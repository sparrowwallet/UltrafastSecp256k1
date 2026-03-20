/* ============================================================================
 * UltrafastSecp256k1 -- OpenCL Backend Bridge
 * ============================================================================
 * Implements gpu::GpuBackend for OpenCL.
 * Wraps the existing secp256k1::opencl::Context class.
 *
 * Supports all 6 GPU C ABI operations:
 *   - generator_mul_batch  (via batch_scalar_mul_generator + batch_jacobian_to_affine)
 *   - hash160_pubkey_batch (CPU-side SIMD hash160 -- GPU hash kernel not yet wired)
 *   - ecdh_batch           (GPU batch_scalar_mul + CPU SHA-256 finalization)
 *   - msm                  (GPU batch_scalar_mul + CPU-side affine summation)
 *   - ecdsa_verify_batch   (GPU via secp256k1_extended.cl kernel)
 *   - schnorr_verify_batch (GPU via secp256k1_extended.cl kernel)
 *
 * Compiled ONLY when SECP256K1_HAVE_OPENCL is set (via CMake).
 * ============================================================================ */

#include "../include/gpu_backend.hpp"

#include <cstring>
#include <cstdio>
#include <vector>
#include <string>
#include <fstream>
#include <filesystem>

/* -- OpenCL Context (Layer 1) ---------------------------------------------- */
#include "secp256k1_opencl.hpp"

/* -- Raw OpenCL API for extended kernel loading ----------------------------- */
#ifdef __APPLE__
    #include <OpenCL/cl.h>
#else
    #include <CL/cl.h>
#endif

/* -- CPU FieldElement for host-side point compression ---------------------- */
#include "secp256k1/field.hpp"

/* -- CPU SHA-256 for ECDH finalization ------------------------------------- */
#include "secp256k1/sha256.hpp"

/* -- CPU Hash160 for pubkey hashing ---------------------------------------- */
#include "secp256k1/hash_accel.hpp"

/* -- Helpers --------------------------------------------------------------- */
namespace {

/** Load a file to string, or empty on failure. */
std::string load_file_to_string(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return {std::istreambuf_iterator<char>(f), {}};
}

} // anonymous namespace

namespace secp256k1 {
namespace gpu {

class OpenCLBackend final : public GpuBackend {
public:
    OpenCLBackend() = default;
    ~OpenCLBackend() override { shutdown(); }

    /* -- Backend identity -------------------------------------------------- */
    uint32_t backend_id() const override { return 2; /* OpenCL */ }
    const char* backend_name() const override { return "OpenCL"; }

    /* -- Device enumeration ------------------------------------------------ */
    uint32_t device_count() const override {
        auto platforms = secp256k1::opencl::enumerate_devices();
        uint32_t total = 0;
        for (auto& [pname, devs] : platforms)
            total += static_cast<uint32_t>(devs.size());
        return total;
    }

    GpuError device_info(uint32_t device_index, DeviceInfo& out) const override {
        auto platforms = secp256k1::opencl::enumerate_devices();
        uint32_t idx = 0;
        for (auto& [pname, devs] : platforms) {
            for (auto& d : devs) {
                if (idx == device_index) {
                    std::memset(&out, 0, sizeof(out));
                    std::snprintf(out.name, sizeof(out.name), "%s", d.name.c_str());
                    out.global_mem_bytes      = d.global_mem_size;
                    out.compute_units         = d.compute_units;
                    out.max_clock_mhz         = d.max_clock_freq;
                    out.max_threads_per_block = static_cast<uint32_t>(d.max_work_group_size);
                    out.backend_id            = 2;
                    out.device_index          = device_index;
                    return GpuError::Ok;
                }
                ++idx;
            }
        }
        return GpuError::Device;
    }

    /* -- Context lifecycle ------------------------------------------------- */
    GpuError init(uint32_t device_index) override {
        if (ctx_) return GpuError::Ok;

        /* Map flat device_index to (platform_id, device_id) */
        auto platforms = secp256k1::opencl::enumerate_devices();
        uint32_t idx = 0;
        int plat = -1, dev = -1;
        for (int p = 0; p < static_cast<int>(platforms.size()); ++p) {
            for (int d = 0; d < static_cast<int>(platforms[p].second.size()); ++d) {
                if (idx == device_index) { plat = p; dev = d; }
                ++idx;
            }
        }
        if (plat < 0) return set_error(GpuError::Device, "OpenCL device not found");

        secp256k1::opencl::DeviceConfig cfg;
        cfg.platform_id = plat;
        cfg.device_id   = dev;
        cfg.verbose      = false;

        ctx_ = secp256k1::opencl::Context::create(cfg);
        if (!ctx_ || !ctx_->is_valid()) {
            std::string msg = ctx_ ? ctx_->last_error() : "Context creation failed";
            ctx_.reset();
            return set_error(GpuError::Device, msg.c_str());
        }

        clear_error();
        return GpuError::Ok;
    }

    void shutdown() override {
        if (ext_ecdsa_verify_)   { clReleaseKernel(ext_ecdsa_verify_);   ext_ecdsa_verify_   = nullptr; }
        if (ext_schnorr_verify_) { clReleaseKernel(ext_schnorr_verify_); ext_schnorr_verify_ = nullptr; }
        if (ext_program_)        { clReleaseProgram(ext_program_);       ext_program_        = nullptr; }
        ext_init_attempted_ = false;
        ctx_.reset();
    }

    bool is_ready() const override { return ctx_ && ctx_->is_valid(); }

    /* -- Error tracking ---------------------------------------------------- */
    GpuError last_error() const override { return last_err_; }
    const char* last_error_msg() const override { return last_msg_; }

    /* -- First-wave ops ---------------------------------------------------- */

    GpuError generator_mul_batch(
        const uint8_t* scalars32, size_t count,
        uint8_t* out_pubkeys33) override
    {
        if (!is_ready()) return set_error(GpuError::Device, "context not initialised");
        if (count == 0) { clear_error(); return GpuError::Ok; }
        if (!scalars32 || !out_pubkeys33) return set_error(GpuError::NullArg, "NULL buffer");

        /* Convert big-endian bytes → OpenCL Scalar (4×uint64 LE limbs) */
        std::vector<secp256k1::opencl::Scalar> h_scalars(count);
        for (size_t i = 0; i < count; ++i) {
            bytes_to_scalar(scalars32 + i * 32, &h_scalars[i]);
        }

        /* Run batch k*G on GPU → Jacobian results */
        std::vector<secp256k1::opencl::JacobianPoint> h_jac(count);
        ctx_->batch_scalar_mul_generator(h_scalars.data(), h_jac.data(), count);

        /* Convert Jacobian → Affine on GPU */
        std::vector<secp256k1::opencl::AffinePoint> h_aff(count);
        ctx_->batch_jacobian_to_affine(h_jac.data(), h_aff.data(), count);

        /* Compress affine → 33-byte pubkeys on host */
        for (size_t i = 0; i < count; ++i) {
            affine_to_compressed(&h_aff[i], out_pubkeys33 + i * 33);
        }

        clear_error();
        return GpuError::Ok;
    }

    GpuError ecdsa_verify_batch(
        const uint8_t* msg_hashes32, const uint8_t* pubkeys33,
        const uint8_t* sigs64, size_t count,
        uint8_t* out_results) override
    {
        if (!is_ready()) return set_error(GpuError::Device, "context not initialised");
        if (count == 0) { clear_error(); return GpuError::Ok; }
        if (!msg_hashes32 || !pubkeys33 || !sigs64 || !out_results)
            return set_error(GpuError::NullArg, "NULL buffer");

        auto err = ensure_extended_kernels();
        if (err != GpuError::Ok) return err;

        auto* cl_ctx = static_cast<cl_context>(ctx_->native_context());
        auto* queue   = static_cast<cl_command_queue>(ctx_->native_queue());
        cl_int clerr;

        /* Prepare GPU-side buffers ----------------------------------------- */

        /* msg_hashes: 32 bytes each, passed flat */
        cl_mem d_msgs = clCreateBuffer(cl_ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                       32 * count, const_cast<uint8_t*>(msg_hashes32), &clerr);
        if (clerr != CL_SUCCESS) return set_error(GpuError::Memory, "msg buffer alloc");

        /* pubkeys: decompress 33-byte → JacobianPoint (3×FieldElement = 96 bytes) */
        struct JacPoint { uint64_t x[4]; uint64_t y[4]; uint64_t z[4]; };
        std::vector<JacPoint> h_pubs(count);
        for (size_t i = 0; i < count; ++i) {
            secp256k1::opencl::AffinePoint aff;
            if (!pubkey33_to_affine(pubkeys33 + i * 33, &aff)) {
                clReleaseMemObject(d_msgs);
                return set_error(GpuError::BadKey, "invalid pubkey");
            }
            std::memcpy(h_pubs[i].x, aff.x.limbs, 32);
            std::memcpy(h_pubs[i].y, aff.y.limbs, 32);
            std::memset(h_pubs[i].z, 0, 32);
            h_pubs[i].z[0] = 1; /* Z = 1 (affine → Jacobian) */
        }
        cl_mem d_pubs = clCreateBuffer(cl_ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                       sizeof(JacPoint) * count, h_pubs.data(), &clerr);

        /* sigs: 64 bytes (r[32] | s[32]) → ECDSASig (r:Scalar, s:Scalar = 64 bytes LE limbs) */
        struct ECDSASig { uint64_t r[4]; uint64_t s[4]; };
        std::vector<ECDSASig> h_sigs(count);
        for (size_t i = 0; i < count; ++i) {
            be32_to_le_limbs(sigs64 + i * 64,      h_sigs[i].r);
            be32_to_le_limbs(sigs64 + i * 64 + 32, h_sigs[i].s);
        }
        cl_mem d_sigs = clCreateBuffer(cl_ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                       sizeof(ECDSASig) * count, h_sigs.data(), &clerr);

        /* results: int per item */
        cl_mem d_res = clCreateBuffer(cl_ctx, CL_MEM_WRITE_ONLY,
                                      sizeof(int) * count, nullptr, &clerr);

        cl_uint cl_count = static_cast<cl_uint>(count);
        clSetKernelArg(ext_ecdsa_verify_, 0, sizeof(cl_mem), &d_msgs);
        clSetKernelArg(ext_ecdsa_verify_, 1, sizeof(cl_mem), &d_pubs);
        clSetKernelArg(ext_ecdsa_verify_, 2, sizeof(cl_mem), &d_sigs);
        clSetKernelArg(ext_ecdsa_verify_, 3, sizeof(cl_mem), &d_res);
        clSetKernelArg(ext_ecdsa_verify_, 4, sizeof(cl_uint), &cl_count);

        size_t global = count;
        clEnqueueNDRangeKernel(queue, ext_ecdsa_verify_, 1, nullptr,
                               &global, nullptr, 0, nullptr, nullptr);
        clFinish(queue);

        /* Read results */
        std::vector<int> h_res(count);
        clEnqueueReadBuffer(queue, d_res, CL_TRUE, 0,
                            sizeof(int) * count, h_res.data(), 0, nullptr, nullptr);

        for (size_t i = 0; i < count; ++i)
            out_results[i] = h_res[i] ? 1 : 0;

        clReleaseMemObject(d_msgs);
        clReleaseMemObject(d_pubs);
        clReleaseMemObject(d_sigs);
        clReleaseMemObject(d_res);

        clear_error();
        return GpuError::Ok;
    }

    GpuError schnorr_verify_batch(
        const uint8_t* msg_hashes32, const uint8_t* pubkeys_x32,
        const uint8_t* sigs64, size_t count,
        uint8_t* out_results) override
    {
        if (!is_ready()) return set_error(GpuError::Device, "context not initialised");
        if (count == 0) { clear_error(); return GpuError::Ok; }
        if (!msg_hashes32 || !pubkeys_x32 || !sigs64 || !out_results)
            return set_error(GpuError::NullArg, "NULL buffer");

        auto err = ensure_extended_kernels();
        if (err != GpuError::Ok) return err;

        auto* cl_ctx = static_cast<cl_context>(ctx_->native_context());
        auto* queue   = static_cast<cl_command_queue>(ctx_->native_queue());
        cl_int clerr;

        /* pubkeys_x: 32 bytes each, passed flat */
        cl_mem d_pks = clCreateBuffer(cl_ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                      32 * count, const_cast<uint8_t*>(pubkeys_x32), &clerr);

        /* messages: 32 bytes each, passed flat */
        cl_mem d_msgs = clCreateBuffer(cl_ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                       32 * count, const_cast<uint8_t*>(msg_hashes32), &clerr);

        /* sigs: 64 bytes (r[32] | s[32]) → SchnorrSig (r:uint8_t[32], s:Scalar = 64 bytes) */
        struct SchnorrSig { uint8_t r[32]; uint64_t s[4]; };
        std::vector<SchnorrSig> h_sigs(count);
        for (size_t i = 0; i < count; ++i) {
            std::memcpy(h_sigs[i].r, sigs64 + i * 64, 32);
            be32_to_le_limbs(sigs64 + i * 64 + 32, h_sigs[i].s);
        }
        cl_mem d_sigs = clCreateBuffer(cl_ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                       sizeof(SchnorrSig) * count, h_sigs.data(), &clerr);

        /* results: int per item */
        cl_mem d_res = clCreateBuffer(cl_ctx, CL_MEM_WRITE_ONLY,
                                      sizeof(int) * count, nullptr, &clerr);

        cl_uint cl_count = static_cast<cl_uint>(count);
        clSetKernelArg(ext_schnorr_verify_, 0, sizeof(cl_mem), &d_pks);
        clSetKernelArg(ext_schnorr_verify_, 1, sizeof(cl_mem), &d_msgs);
        clSetKernelArg(ext_schnorr_verify_, 2, sizeof(cl_mem), &d_sigs);
        clSetKernelArg(ext_schnorr_verify_, 3, sizeof(cl_mem), &d_res);
        clSetKernelArg(ext_schnorr_verify_, 4, sizeof(cl_uint), &cl_count);

        size_t global = count;
        clEnqueueNDRangeKernel(queue, ext_schnorr_verify_, 1, nullptr,
                               &global, nullptr, 0, nullptr, nullptr);
        clFinish(queue);

        /* Read results */
        std::vector<int> h_res(count);
        clEnqueueReadBuffer(queue, d_res, CL_TRUE, 0,
                            sizeof(int) * count, h_res.data(), 0, nullptr, nullptr);

        for (size_t i = 0; i < count; ++i)
            out_results[i] = h_res[i] ? 1 : 0;

        clReleaseMemObject(d_pks);
        clReleaseMemObject(d_msgs);
        clReleaseMemObject(d_sigs);
        clReleaseMemObject(d_res);

        clear_error();
        return GpuError::Ok;
    }

    GpuError ecdh_batch(
        const uint8_t* privkeys32, const uint8_t* peer_pubkeys33,
        size_t count, uint8_t* out_secrets32) override
    {
        if (!is_ready()) return set_error(GpuError::Device, "context not initialised");
        if (count == 0) { clear_error(); return GpuError::Ok; }
        if (!privkeys32 || !peer_pubkeys33 || !out_secrets32)
            return set_error(GpuError::NullArg, "NULL buffer");

        /* Convert private keys → Scalar, peer pubkeys → AffinePoint */
        std::vector<secp256k1::opencl::Scalar> h_scalars(count);
        std::vector<secp256k1::opencl::AffinePoint> h_peers(count);

        for (size_t i = 0; i < count; ++i) {
            bytes_to_scalar(privkeys32 + i * 32, &h_scalars[i]);
            const uint8_t* pub = peer_pubkeys33 + i * 33;
            if (!pubkey33_to_affine(pub, &h_peers[i]))
                return set_error(GpuError::BadKey, "invalid peer pubkey");
        }

        /* GPU: batch scalar_mul(priv[i], peer[i]) → Jacobian */
        std::vector<secp256k1::opencl::JacobianPoint> h_jac(count);
        ctx_->batch_scalar_mul(h_scalars.data(), h_peers.data(),
                               h_jac.data(), count);

        /* GPU: Jacobian → Affine */
        std::vector<secp256k1::opencl::AffinePoint> h_aff(count);
        ctx_->batch_jacobian_to_affine(h_jac.data(), h_aff.data(), count);

        /* CPU: SHA-256(compressed shared point) to match ufsecp_ecdh/CUDA. */
        for (size_t i = 0; i < count; ++i) {
            uint8_t compressed[33];
            affine_to_compressed(&h_aff[i], compressed);
            auto digest = secp256k1::SHA256::hash(compressed, sizeof(compressed));
            std::memcpy(out_secrets32 + i * 32, digest.data(), 32);
        }

        clear_error();
        return GpuError::Ok;
    }

    GpuError hash160_pubkey_batch(
        const uint8_t* pubkeys33, size_t count,
        uint8_t* out_hash160) override
    {
        if (!is_ready()) return set_error(GpuError::Device, "context not initialised");
        if (count == 0) { clear_error(); return GpuError::Ok; }
        if (!pubkeys33 || !out_hash160)
            return set_error(GpuError::NullArg, "NULL buffer");

        /* CPU-side SIMD-accelerated Hash160 */
        for (size_t i = 0; i < count; ++i) {
            secp256k1::hash::hash160_33(pubkeys33 + i * 33,
                                        out_hash160 + i * 20);
        }

        clear_error();
        return GpuError::Ok;
    }

    GpuError msm(
        const uint8_t* scalars32, const uint8_t* points33,
        size_t n, uint8_t* out_result33) override
    {
        if (!is_ready()) return set_error(GpuError::Device, "context not initialised");
        if (n == 0) { clear_error(); return GpuError::Ok; }
        if (!scalars32 || !points33 || !out_result33)
            return set_error(GpuError::NullArg, "NULL buffer");

        /* Convert inputs */
        std::vector<secp256k1::opencl::Scalar> h_scalars(n);
        std::vector<secp256k1::opencl::AffinePoint> h_points(n);
        for (size_t i = 0; i < n; ++i) {
            bytes_to_scalar(scalars32 + i * 32, &h_scalars[i]);
            if (!pubkey33_to_affine(points33 + i * 33, &h_points[i]))
                return set_error(GpuError::BadKey, "invalid MSM point");
        }

        /* GPU: batch scalar_mul(s[i], P[i]) */
        std::vector<secp256k1::opencl::JacobianPoint> h_jac(n);
        ctx_->batch_scalar_mul(h_scalars.data(), h_points.data(),
                               h_jac.data(), n);

        /* GPU: Jacobian → Affine */
        std::vector<secp256k1::opencl::AffinePoint> h_aff(n);
        ctx_->batch_jacobian_to_affine(h_jac.data(), h_aff.data(), n);

        /* CPU: sum affine points */
        bool have_acc = false;
        secp256k1::fast::FieldElement acc_x, acc_y;

        for (size_t i = 0; i < n; ++i) {
            std::array<uint64_t, 4> xl, yl;
            std::memcpy(xl.data(), h_aff[i].x.limbs, 32);
            std::memcpy(yl.data(), h_aff[i].y.limbs, 32);
            auto px = secp256k1::fast::FieldElement::from_limbs(xl);
            auto py = secp256k1::fast::FieldElement::from_limbs(yl);

            /* Skip point at infinity (zero x and y) */
            auto pxb = px.to_bytes();
            auto pyb = py.to_bytes();
            bool is_zero = true;
            for (int k = 0; k < 32 && is_zero; ++k)
                if (pxb[k] || pyb[k]) is_zero = false;
            if (is_zero) continue;

            if (!have_acc) {
                acc_x = px; acc_y = py;
                have_acc = true;
                continue;
            }

            /* Affine point addition: acc += (px, py) */
            auto dx = px - acc_x;
            auto dy = py - acc_y;
            auto dxb = dx.to_bytes();
            bool dx_zero = true;
            for (int k = 0; k < 32 && dx_zero; ++k)
                if (dxb[k]) dx_zero = false;

            if (dx_zero) {
                auto dyb = dy.to_bytes();
                bool dy_zero = true;
                for (int k = 0; k < 32 && dy_zero; ++k)
                    if (dyb[k]) dy_zero = false;
                if (!dy_zero) {
                    /* Inverse points → result is infinity */
                    have_acc = false;
                    continue;
                }
                /* Doubling: lambda = 3*x^2 / (2*y) */
                auto x2 = acc_x * acc_x;
                auto num = x2 + x2 + x2;
                auto den = acc_y + acc_y;
                auto lam = num * den.inverse();
                auto rx = lam * lam - acc_x - acc_x;
                auto ry = lam * (acc_x - rx) - acc_y;
                acc_x = rx; acc_y = ry;
            } else {
                auto lam = dy * dx.inverse();
                auto rx = lam * lam - acc_x - px;
                auto ry = lam * (acc_x - rx) - acc_y;
                acc_x = rx; acc_y = ry;
            }
        }

        if (!have_acc)
            return set_error(GpuError::Arith, "MSM result is point at infinity");

        /* Serialize result */
        auto yb = acc_y.to_bytes();
        out_result33[0] = (yb[31] & 1) ? 0x03 : 0x02;
        auto xb = acc_x.to_bytes();
        std::memcpy(out_result33 + 1, xb.data(), 32);

        clear_error();
        return GpuError::Ok;
    }

private:
    std::unique_ptr<secp256k1::opencl::Context> ctx_;
    GpuError last_err_ = GpuError::Ok;
    char     last_msg_[256] = {};

    /* Extended kernel handles (lazy-loaded for verify ops) */
    cl_program ext_program_         = nullptr;
    cl_kernel  ext_ecdsa_verify_    = nullptr;
    cl_kernel  ext_schnorr_verify_  = nullptr;
    bool       ext_init_attempted_  = false;

    GpuError set_error(GpuError err, const char* msg) {
        last_err_ = err;
        if (msg) {
            size_t i = 0;
            for (; i < sizeof(last_msg_) - 1 && msg[i]; ++i)
                last_msg_[i] = msg[i];
            last_msg_[i] = '\0';
        } else {
            last_msg_[0] = '\0';
        }
        return err;
    }

    void clear_error() {
        last_err_ = GpuError::Ok;
        last_msg_[0] = '\0';
    }

    /* -- Big-endian 32 bytes → 4×uint64 LE limbs -------------------------- */
    static void be32_to_le_limbs(const uint8_t be[32], uint64_t out[4]) {
        for (int limb = 0; limb < 4; ++limb) {
            uint64_t v = 0;
            int base = (3 - limb) * 8;
            for (int b = 0; b < 8; ++b)
                v = (v << 8) | be[base + b];
            out[limb] = v;
        }
    }

    /* -- Lazy-load extended OpenCL program for verify kernels -------------- */
    GpuError ensure_extended_kernels() {
        if (ext_ecdsa_verify_ && ext_schnorr_verify_) return GpuError::Ok;
        if (ext_init_attempted_)
            return set_error(GpuError::Launch, "extended kernel init previously failed");
        ext_init_attempted_ = true;

        auto* cl_ctx = static_cast<cl_context>(ctx_->native_context());

        /* Get device from context */
        cl_device_id device = nullptr;
        clGetContextInfo(cl_ctx, CL_CONTEXT_DEVICES, sizeof(device), &device, nullptr);

        /* Search for secp256k1_extended.cl */
        const char* search_paths[] = {
            "kernels/secp256k1_extended.cl",
            "../kernels/secp256k1_extended.cl",
            "../../opencl/kernels/secp256k1_extended.cl",
            "../../../opencl/kernels/secp256k1_extended.cl",
            "opencl/kernels/secp256k1_extended.cl",
        };

        std::string src;
        std::string kernel_dir;
        for (auto* p : search_paths) {
            src = load_file_to_string(p);
            if (!src.empty()) {
                std::filesystem::path fp(p);
                kernel_dir = fp.parent_path().string();
                break;
            }
        }
        if (src.empty())
            return set_error(GpuError::Launch, "secp256k1_extended.cl not found");

        /* Compile */
        const char* src_ptr = src.c_str();
        size_t src_len = src.size();
        cl_int err;
        ext_program_ = clCreateProgramWithSource(cl_ctx, 1, &src_ptr, &src_len, &err);
        if (err != CL_SUCCESS)
            return set_error(GpuError::Launch, "clCreateProgramWithSource failed");

        std::string opts = "-cl-std=CL1.2 -cl-fast-relaxed-math -cl-mad-enable";
        if (!kernel_dir.empty())
            opts += " -I " + kernel_dir;

        err = clBuildProgram(ext_program_, 1, &device, opts.c_str(), nullptr, nullptr);
        if (err != CL_SUCCESS) {
            /* Grab build log for diagnostics */
            size_t log_len = 0;
            clGetProgramBuildInfo(ext_program_, device, CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_len);
            std::string log(log_len, '\0');
            clGetProgramBuildInfo(ext_program_, device, CL_PROGRAM_BUILD_LOG, log_len, log.data(), nullptr);
            clReleaseProgram(ext_program_);
            ext_program_ = nullptr;
            std::string msg = "extended.cl build failed: " + log.substr(0, 200);
            return set_error(GpuError::Launch, msg.c_str());
        }

        ext_ecdsa_verify_  = clCreateKernel(ext_program_, "ecdsa_verify", &err);
        if (err != CL_SUCCESS) {
            clReleaseProgram(ext_program_); ext_program_ = nullptr;
            return set_error(GpuError::Launch, "ecdsa_verify kernel not found");
        }

        ext_schnorr_verify_ = clCreateKernel(ext_program_, "schnorr_verify", &err);
        if (err != CL_SUCCESS) {
            clReleaseKernel(ext_ecdsa_verify_); ext_ecdsa_verify_ = nullptr;
            clReleaseProgram(ext_program_); ext_program_ = nullptr;
            return set_error(GpuError::Launch, "schnorr_verify kernel not found");
        }

        return GpuError::Ok;
    }

    /* -- Type conversion helpers ------------------------------------------- */

    static void bytes_to_scalar(const uint8_t be[32],
                                secp256k1::opencl::Scalar* out) {
        for (int limb = 0; limb < 4; ++limb) {
            uint64_t v = 0;
            int base = (3 - limb) * 8; /* big-endian: limb 0 → bytes[24..31] */
            for (int b = 0; b < 8; ++b) {
                v = (v << 8) | be[base + b];
            }
            out->limbs[limb] = v;
        }
    }

    static void affine_to_compressed(const secp256k1::opencl::AffinePoint* p,
                                     uint8_t out[33]) {
        /* Convert OpenCL limbs → CPU FieldElement for safe serialisation */
        std::array<uint64_t, 4> xl, yl;
        std::memcpy(xl.data(), p->x.limbs, 32);
        std::memcpy(yl.data(), p->y.limbs, 32);
        auto cx = secp256k1::fast::FieldElement::from_limbs(xl);
        auto cy = secp256k1::fast::FieldElement::from_limbs(yl);

        auto ybytes = cy.to_bytes();
        out[0] = (ybytes[31] & 1) ? 0x03 : 0x02;
        auto xbytes = cx.to_bytes();
        std::memcpy(out + 1, xbytes.data(), 32);
    }

    /** Decompress a 33-byte compressed pubkey to OpenCL AffinePoint.
     *  Returns false if prefix is invalid.                               */
    static bool pubkey33_to_affine(const uint8_t pub[33],
                                   secp256k1::opencl::AffinePoint* out) {
        uint8_t prefix = pub[0];
        if (prefix != 0x02 && prefix != 0x03) return false;

        /* x from big-endian bytes */
        secp256k1::fast::FieldElement fe_x;
        if (!secp256k1::fast::FieldElement::parse_bytes_strict(pub + 1, fe_x))
            return false;

        /* y^2 = x^3 + 7 */
        auto x2 = fe_x * fe_x;
        auto x3 = x2 * fe_x;
        auto y2 = x3 + secp256k1::fast::FieldElement::from_uint64(7);
        auto fe_y = y2.sqrt();

        /* Choose correct parity */
        auto yb = fe_y.to_bytes();
        if ((yb[31] & 1) != (prefix & 1))
            fe_y = fe_y.negate();

        /* Store as LE limbs into OpenCL AffinePoint */
        const auto& xl = fe_x.limbs();
        const auto& yl = fe_y.limbs();
        std::memcpy(out->x.limbs, xl.data(), 32);
        std::memcpy(out->y.limbs, yl.data(), 32);
        return true;
    }
};

/* -- Factory --------------------------------------------------------------- */
std::unique_ptr<GpuBackend> create_opencl_backend() {
    return std::make_unique<OpenCLBackend>();
}

} // namespace gpu
} // namespace secp256k1
