/* ============================================================================
 * UltrafastSecp256k1 -- CUDA Backend Bridge
 * ============================================================================
 * Implements gpu::GpuBackend for CUDA/HIP.
 * Converts between flat uint8_t[] C ABI buffers and CUDA internal types,
 * manages device memory, and launches existing kernels.
 *
 * Compiled ONLY when SECP256K1_HAVE_CUDA is set (via CMake).
 * ============================================================================ */

#include "../include/gpu_backend.hpp"

#include <cstring>
#include <cstdio>
#include <vector>

/* -- CUDA runtime ---------------------------------------------------------- */
#include <cuda_runtime.h>

/* -- Existing CUDA headers (Layer 1) --------------------------------------- */
#include "secp256k1.cuh"
#include "ecdh.cuh"
#include "msm.cuh"
#include "gpu_compat.h"

/* ============================================================================
 * Internal helpers
 * ============================================================================ */

#define CUDA_TRY(expr)                                                         \
    do {                                                                       \
        cudaError_t _err = (expr);                                             \
        if (_err != cudaSuccess) {                                             \
            set_error(GpuError::Launch, cudaGetErrorString(_err));              \
            return last_error();                                               \
        }                                                                      \
    } while (0)

namespace secp256k1 {
namespace gpu {

/* ============================================================================
 * CudaBackend implementation
 * ============================================================================ */

class CudaBackend final : public GpuBackend {
public:
    CudaBackend() = default;
    ~CudaBackend() override { shutdown(); }

    /* -- Backend identity -------------------------------------------------- */
    uint32_t backend_id() const override { return 1; /* CUDA */ }
    const char* backend_name() const override { return "CUDA"; }

    /* -- Device enumeration ------------------------------------------------ */
    uint32_t device_count() const override {
        int count = 0;
        if (cudaGetDeviceCount(&count) != cudaSuccess) return 0;
        return static_cast<uint32_t>(count);
    }

    GpuError device_info(uint32_t device_index, DeviceInfo& out) const override {
        int count = 0;
        if (cudaGetDeviceCount(&count) != cudaSuccess || device_index >= static_cast<uint32_t>(count))
            return GpuError::Device;

        cudaDeviceProp prop{};
        if (cudaGetDeviceProperties(&prop, static_cast<int>(device_index)) != cudaSuccess)
            return GpuError::Device;

        std::memset(&out, 0, sizeof(out));
        std::snprintf(out.name, sizeof(out.name), "%s", prop.name);
        out.global_mem_bytes       = prop.totalGlobalMem;
        out.compute_units          = static_cast<uint32_t>(prop.multiProcessorCount);
        out.max_clock_mhz          = static_cast<uint32_t>(prop.clockRate / 1000);
        out.max_threads_per_block  = static_cast<uint32_t>(prop.maxThreadsPerBlock);
        out.backend_id             = 1;
        out.device_index           = device_index;
        return GpuError::Ok;
    }

    /* -- Context lifecycle ------------------------------------------------- */
    GpuError init(uint32_t device_index) override {
        if (ready_) return GpuError::Ok;
        int count = 0;
        if (cudaGetDeviceCount(&count) != cudaSuccess || device_index >= static_cast<uint32_t>(count)) {
            set_error(GpuError::Device, "CUDA device not found");
            return last_error();
        }
        auto err = cudaSetDevice(static_cast<int>(device_index));
        if (err != cudaSuccess) {
            set_error(GpuError::Device, cudaGetErrorString(err));
            return last_error();
        }
        device_idx_ = device_index;
        ready_ = true;
        clear_error();
        return GpuError::Ok;
    }

    void shutdown() override {
        ready_ = false;
    }

    bool is_ready() const override { return ready_; }

    /* -- Error tracking ---------------------------------------------------- */
    GpuError last_error() const override { return last_err_; }
    const char* last_error_msg() const override { return last_msg_; }

    /* -- First-wave ops ---------------------------------------------------- */

    GpuError generator_mul_batch(
        const uint8_t* scalars32, size_t count,
        uint8_t* out_pubkeys33) override
    {
        if (!ready_) return set_error(GpuError::Device, "context not initialised");
        if (!scalars32 || !out_pubkeys33) return set_error(GpuError::NullArg, "NULL buffer");
        if (count == 0) { clear_error(); return GpuError::Ok; }

        /* Allocate device memory */
        Scalar* d_scalars = nullptr;
        JacobianPoint* d_results = nullptr;
        CUDA_TRY(cudaMalloc(&d_scalars, count * sizeof(Scalar)));
        CUDA_TRY(cudaMalloc(&d_results, count * sizeof(JacobianPoint)));

        /* Convert big-endian bytes → Scalar on host, then upload */
        std::vector<Scalar> h_scalars(count);
        for (size_t i = 0; i < count; ++i) {
            bytes_to_scalar(scalars32 + i * 32, &h_scalars[i]);
        }
        CUDA_TRY(cudaMemcpy(d_scalars, h_scalars.data(),
                             count * sizeof(Scalar), cudaMemcpyHostToDevice));

        /* Launch kernel */
        int threads = 128;
        int blocks  = (static_cast<int>(count) + threads - 1) / threads;
        generator_mul_windowed_batch_kernel<<<blocks, threads>>>(
            d_scalars, d_results, static_cast<int>(count));
        CUDA_TRY(cudaGetLastError());
        CUDA_TRY(cudaDeviceSynchronize());

        /* Download results and convert Jacobian → compressed */
        std::vector<JacobianPoint> h_results(count);
        CUDA_TRY(cudaMemcpy(h_results.data(), d_results,
                             count * sizeof(JacobianPoint), cudaMemcpyDeviceToHost));

        for (size_t i = 0; i < count; ++i) {
            jacobian_to_compressed_host(&h_results[i], out_pubkeys33 + i * 33);
        }

        cudaFree(d_results);
        cudaFree(d_scalars);
        clear_error();
        return GpuError::Ok;
    }

    GpuError ecdsa_verify_batch(
        const uint8_t* msg_hashes32, const uint8_t* pubkeys33,
        const uint8_t* sigs64, size_t count,
        uint8_t* out_results) override
    {
        if (!ready_) return set_error(GpuError::Device, "context not initialised");
        if (!msg_hashes32 || !pubkeys33 || !sigs64 || !out_results)
            return set_error(GpuError::NullArg, "NULL buffer");
        if (count == 0) { clear_error(); return GpuError::Ok; }

        /* Prepare host arrays in CUDA internal types */
        std::vector<JacobianPoint> h_pubs(count);
        std::vector<ECDSASignatureGPU> h_sigs(count);
        for (size_t i = 0; i < count; ++i) {
            if (!compressed_to_jacobian_host(pubkeys33 + i * 33, &h_pubs[i]))
                h_pubs[i].infinity = true; /* mark invalid, verify will fail */
            bytes_to_ecdsa_sig(sigs64 + i * 64, &h_sigs[i]);
        }

        /* Allocate device memory */
        uint8_t*            d_msgs = nullptr;
        JacobianPoint*      d_pubs = nullptr;
        ECDSASignatureGPU*  d_sigs = nullptr;
        bool*               d_res  = nullptr;

        CUDA_TRY(cudaMalloc(&d_msgs, count * 32));
        CUDA_TRY(cudaMalloc(&d_pubs, count * sizeof(JacobianPoint)));
        CUDA_TRY(cudaMalloc(&d_sigs, count * sizeof(ECDSASignatureGPU)));
        CUDA_TRY(cudaMalloc(&d_res, count * sizeof(bool)));

        CUDA_TRY(cudaMemcpy(d_msgs, msg_hashes32, count * 32, cudaMemcpyHostToDevice));
        CUDA_TRY(cudaMemcpy(d_pubs, h_pubs.data(), count * sizeof(JacobianPoint), cudaMemcpyHostToDevice));
        CUDA_TRY(cudaMemcpy(d_sigs, h_sigs.data(), count * sizeof(ECDSASignatureGPU), cudaMemcpyHostToDevice));

        /* Launch */
        int threads = 128;
        int blocks  = (static_cast<int>(count) + threads - 1) / threads;
        ecdsa_verify_batch_kernel<<<blocks, threads>>>(
            d_msgs, d_pubs, d_sigs, d_res, static_cast<int>(count));
        CUDA_TRY(cudaGetLastError());
        CUDA_TRY(cudaDeviceSynchronize());

        /* Download results */
        std::vector<bool> h_res_vec(count);
        {
            /* cudaMemcpy doesn't work with std::vector<bool>, use raw array */
            bool* h_res_raw = new bool[count];
            CUDA_TRY(cudaMemcpy(h_res_raw, d_res, count * sizeof(bool), cudaMemcpyDeviceToHost));
            for (size_t i = 0; i < count; ++i)
                out_results[i] = h_res_raw[i] ? 1 : 0;
            delete[] h_res_raw;
        }

        cudaFree(d_res);
        cudaFree(d_sigs);
        cudaFree(d_pubs);
        cudaFree(d_msgs);
        clear_error();
        return GpuError::Ok;
    }

    GpuError schnorr_verify_batch(
        const uint8_t* msg_hashes32, const uint8_t* pubkeys_x32,
        const uint8_t* sigs64, size_t count,
        uint8_t* out_results) override
    {
        if (!ready_) return set_error(GpuError::Device, "context not initialised");
        if (!msg_hashes32 || !pubkeys_x32 || !sigs64 || !out_results)
            return set_error(GpuError::NullArg, "NULL buffer");
        if (count == 0) { clear_error(); return GpuError::Ok; }

        /* Prepare Schnorr sigs in CUDA type */
        std::vector<SchnorrSignatureGPU> h_sigs(count);
        for (size_t i = 0; i < count; ++i) {
            bytes_to_schnorr_sig(sigs64 + i * 64, &h_sigs[i]);
        }

        /* Allocate device memory */
        uint8_t*             d_pks  = nullptr;
        uint8_t*             d_msgs = nullptr;
        SchnorrSignatureGPU* d_sigs = nullptr;
        bool*                d_res  = nullptr;

        CUDA_TRY(cudaMalloc(&d_pks, count * 32));
        CUDA_TRY(cudaMalloc(&d_msgs, count * 32));
        CUDA_TRY(cudaMalloc(&d_sigs, count * sizeof(SchnorrSignatureGPU)));
        CUDA_TRY(cudaMalloc(&d_res, count * sizeof(bool)));

        CUDA_TRY(cudaMemcpy(d_pks, pubkeys_x32, count * 32, cudaMemcpyHostToDevice));
        CUDA_TRY(cudaMemcpy(d_msgs, msg_hashes32, count * 32, cudaMemcpyHostToDevice));
        CUDA_TRY(cudaMemcpy(d_sigs, h_sigs.data(), count * sizeof(SchnorrSignatureGPU), cudaMemcpyHostToDevice));

        /* Launch */
        int threads = 128;
        int blocks  = (static_cast<int>(count) + threads - 1) / threads;
        schnorr_verify_batch_kernel<<<blocks, threads>>>(
            d_pks, d_msgs, d_sigs, d_res, static_cast<int>(count));
        CUDA_TRY(cudaGetLastError());
        CUDA_TRY(cudaDeviceSynchronize());

        /* Download results */
        {
            bool* h_res_raw = new bool[count];
            CUDA_TRY(cudaMemcpy(h_res_raw, d_res, count * sizeof(bool), cudaMemcpyDeviceToHost));
            for (size_t i = 0; i < count; ++i)
                out_results[i] = h_res_raw[i] ? 1 : 0;
            delete[] h_res_raw;
        }

        cudaFree(d_res);
        cudaFree(d_sigs);
        cudaFree(d_msgs);
        cudaFree(d_pks);
        clear_error();
        return GpuError::Ok;
    }

    GpuError ecdh_batch(
        const uint8_t* privkeys32, const uint8_t* peer_pubkeys33,
        size_t count, uint8_t* out_secrets32) override
    {
        /* ECDH has device functions but no batch kernel. We need a thin
           wrapper kernel. For now, return UNSUPPORTED until the kernel
           is added in a follow-up (or we add an inline kernel here). */
        return set_error(GpuError::Unsupported,
                         "ECDH batch kernel not yet available on CUDA");
    }

    GpuError hash160_pubkey_batch(
        const uint8_t* pubkeys33, size_t count,
        uint8_t* out_hash160) override
    {
        if (!ready_) return set_error(GpuError::Device, "context not initialised");
        if (!pubkeys33 || !out_hash160)
            return set_error(GpuError::NullArg, "NULL buffer");
        if (count == 0) { clear_error(); return GpuError::Ok; }

        uint8_t* d_pubs = nullptr;
        uint8_t* d_hash = nullptr;

        CUDA_TRY(cudaMalloc(&d_pubs, count * 33));
        CUDA_TRY(cudaMalloc(&d_hash, count * 20));
        CUDA_TRY(cudaMemcpy(d_pubs, pubkeys33, count * 33, cudaMemcpyHostToDevice));

        int threads = 256;
        int blocks  = (static_cast<int>(count) + threads - 1) / threads;
        hash160_pubkey_kernel<<<blocks, threads>>>(
            d_pubs, 33, d_hash, static_cast<int>(count));
        CUDA_TRY(cudaGetLastError());
        CUDA_TRY(cudaDeviceSynchronize());

        CUDA_TRY(cudaMemcpy(out_hash160, d_hash, count * 20, cudaMemcpyDeviceToHost));

        cudaFree(d_hash);
        cudaFree(d_pubs);
        clear_error();
        return GpuError::Ok;
    }

    GpuError msm(
        const uint8_t* scalars32, const uint8_t* points33,
        size_t n, uint8_t* out_result33) override
    {
        /* MSM exists as device functions (msm_naive, msm_pippenger) but not
           as a standalone kernel with host launch. Return UNSUPPORTED. */
        return set_error(GpuError::Unsupported,
                         "MSM batch kernel not yet available on CUDA");
    }

private:
    bool       ready_      = false;
    uint32_t   device_idx_ = 0;
    GpuError   last_err_   = GpuError::Ok;
    char       last_msg_[256] = {};

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

    /* -- Type conversion helpers (host-side) ------------------------------- */

    /** Big-endian 32 bytes → Scalar (4x uint64_t LE limbs) */
    static void bytes_to_scalar(const uint8_t be[32], Scalar* out) {
        for (int limb = 0; limb < 4; ++limb) {
            uint64_t v = 0;
            for (int b = 0; b < 8; ++b) {
                v = (v << 8) | be[31 - limb * 8 - b];
            }
            out->limbs[limb] = v;
        }
    }

    /** Scalar (4x uint64_t LE limbs) → big-endian 32 bytes */
    static void scalar_to_bytes(const Scalar* s, uint8_t be[32]) {
        for (int limb = 0; limb < 4; ++limb) {
            uint64_t v = s->limbs[limb];
            for (int b = 0; b < 8; ++b) {
                be[31 - limb * 8 - b] = static_cast<uint8_t>(v >> (b * 8));
            }
        }
    }

    /** Big-endian 32 bytes → FieldElement (4x uint64_t LE limbs) */
    static void bytes_to_field(const uint8_t be[32], FieldElement* out) {
        /* Same layout as Scalar */
        for (int limb = 0; limb < 4; ++limb) {
            uint64_t v = 0;
            for (int b = 0; b < 8; ++b) {
                v = (v << 8) | be[31 - limb * 8 - b];
            }
            out->limbs[limb] = v;
        }
    }

    static void field_to_bytes(const FieldElement* fe, uint8_t be[32]) {
        for (int limb = 0; limb < 4; ++limb) {
            uint64_t v = fe->limbs[limb];
            for (int b = 0; b < 8; ++b) {
                be[31 - limb * 8 - b] = static_cast<uint8_t>(v >> (b * 8));
            }
        }
    }

    /** Compact ECDSA sig (64 bytes: R[32] || S[32], big-endian) → ECDSASignatureGPU */
    static void bytes_to_ecdsa_sig(const uint8_t compact[64], ECDSASignatureGPU* out) {
        bytes_to_scalar(compact, &out->r);
        bytes_to_scalar(compact + 32, &out->s);
    }

    /** Schnorr sig (64 bytes: r[32] || s[32], big-endian) → SchnorrSignatureGPU */
    static void bytes_to_schnorr_sig(const uint8_t sig[64], SchnorrSignatureGPU* out) {
        /* r is raw bytes (x-coordinate), s is a scalar */
        std::memcpy(out->r, sig, 32);
        bytes_to_scalar(sig + 32, &out->s);
    }

    /** Compressed pubkey (33 bytes: prefix || x) → JacobianPoint on host.
     *  Uses secp256k1 curve equation y^2 = x^3 + 7 to recover y. */
    static bool compressed_to_jacobian_host(const uint8_t pub[33], JacobianPoint* out) {
        uint8_t prefix = pub[0];
        if (prefix != 0x02 && prefix != 0x03) return false;

        /* Parse x from big-endian bytes */
        FieldElement x;
        bytes_to_field(pub + 1, &x);

        /* For host-side decompression we set z=1 (affine→Jacobian trivially).
           Full y recovery is done by the device kernel. For ECDSA verify,
           the kernel needs the full JacobianPoint. We store x and the parity
           bit, and mark z=1 so the verify kernel can decompress on-device.

           However, the existing verify kernel expects a fully-formed point.
           We do the square root on host using the CPU library. */

        /* Use the CPU decompression path */
        secp256k1::fast::FieldElement cpux;
        std::array<uint8_t, 32> xbytes;
        std::memcpy(xbytes.data(), pub + 1, 32);
        if (!secp256k1::fast::FieldElement::parse_bytes_strict(xbytes.data(), cpux))
            return false;

        auto x2 = cpux * cpux;
        auto x3 = x2 * cpux;
        auto y2 = x3 + secp256k1::fast::FieldElement::from_uint64(7);

        secp256k1::fast::FieldElement y;
        if (!secp256k1::fast::FieldElement::sqrt(y2, y))
            return false;

        /* Check parity */
        auto ybytes = y.to_bytes();
        bool y_is_odd = (ybytes[31] & 1) != 0;
        bool want_odd = (prefix == 0x03);
        if (y_is_odd != want_odd) y = y.negate();

        /* Convert CPU FieldElement → CUDA FieldElement (same layout: 4×uint64 LE) */
        auto xarr = cpux.to_limbs();
        auto yarr = y.to_limbs();
        for (int i = 0; i < 4; ++i) {
            out->x.limbs[i] = xarr[i];
            out->y.limbs[i] = yarr[i];
        }
        out->z.limbs[0] = 1;
        out->z.limbs[1] = 0;
        out->z.limbs[2] = 0;
        out->z.limbs[3] = 0;
        out->infinity = false;
        return true;
    }

    /** JacobianPoint → compressed 33 bytes on host.
     *  Requires one field inversion (expensive but done on host). */
    static void jacobian_to_compressed_host(const JacobianPoint* p, uint8_t out[33]) {
        if (p->infinity) {
            std::memset(out, 0, 33);
            return;
        }

        /* Convert CUDA limbs → CPU FieldElement for inversion */
        secp256k1::fast::FieldElement cx, cy, cz;
        cx = secp256k1::fast::FieldElement::from_limbs(p->x.limbs);
        cy = secp256k1::fast::FieldElement::from_limbs(p->y.limbs);
        cz = secp256k1::fast::FieldElement::from_limbs(p->z.limbs);

        auto zinv  = cz.inverse();
        auto zinv2 = zinv * zinv;
        auto zinv3 = zinv2 * zinv;

        auto ax = cx * zinv2;
        auto ay = cy * zinv3;

        auto ybytes = ay.to_bytes();
        out[0] = (ybytes[31] & 1) ? 0x03 : 0x02;
        auto xbytes = ax.to_bytes();
        std::memcpy(out + 1, xbytes.data(), 32);
    }
};

/* -- Factory function ------------------------------------------------------ */
std::unique_ptr<GpuBackend> create_cuda_backend() {
    return std::make_unique<CudaBackend>();
}

} // namespace gpu
} // namespace secp256k1
