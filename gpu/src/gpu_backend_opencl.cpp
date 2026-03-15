/* ============================================================================
 * UltrafastSecp256k1 -- OpenCL Backend Bridge
 * ============================================================================
 * Implements gpu::GpuBackend for OpenCL.
 * Wraps the existing secp256k1::opencl::Context class.
 *
 * Currently supports:
 *   - generator_mul_batch  (via batch_scalar_mul_generator + batch_jacobian_to_affine)
 *   - ECDSA / Schnorr verify, ECDH, hash160, MSM → UNSUPPORTED (no OpenCL kernels yet)
 *
 * Compiled ONLY when SECP256K1_HAVE_OPENCL is set (via CMake).
 * ============================================================================ */

#include "../include/gpu_backend.hpp"

#include <cstring>
#include <cstdio>
#include <vector>

/* -- OpenCL Context (Layer 1) ---------------------------------------------- */
#include "secp256k1_opencl.hpp"

/* -- CPU FieldElement for host-side point compression ---------------------- */
#include "secp256k1/field.hpp"

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
        const uint8_t*, const uint8_t*, const uint8_t*,
        size_t, uint8_t*) override
    {
        return set_error(GpuError::Unsupported,
                         "ECDSA verify batch not yet available on OpenCL");
    }

    GpuError schnorr_verify_batch(
        const uint8_t*, const uint8_t*, const uint8_t*,
        size_t, uint8_t*) override
    {
        return set_error(GpuError::Unsupported,
                         "Schnorr verify batch not yet available on OpenCL");
    }

    GpuError ecdh_batch(
        const uint8_t*, const uint8_t*,
        size_t, uint8_t*) override
    {
        return set_error(GpuError::Unsupported,
                         "ECDH batch not yet available on OpenCL");
    }

    GpuError hash160_pubkey_batch(
        const uint8_t*, size_t, uint8_t*) override
    {
        return set_error(GpuError::Unsupported,
                         "Hash160 batch not yet available on OpenCL");
    }

    GpuError msm(
        const uint8_t*, const uint8_t*,
        size_t, uint8_t*) override
    {
        return set_error(GpuError::Unsupported,
                         "MSM not yet available on OpenCL");
    }

private:
    std::unique_ptr<secp256k1::opencl::Context> ctx_;
    GpuError last_err_ = GpuError::Ok;
    char     last_msg_[256] = {};

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
};

/* -- Factory --------------------------------------------------------------- */
std::unique_ptr<GpuBackend> create_opencl_backend() {
    return std::make_unique<OpenCLBackend>();
}

} // namespace gpu
} // namespace secp256k1
