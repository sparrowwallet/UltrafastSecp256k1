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
#include "schnorr.cuh"
#include "gpu_compat.h"

/* -- Host helpers (compiled as C++ by the host compiler) ------------------- */
#include "../include/gpu_cuda_host_helpers.h"

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

/* Kernels defined in cuda/src/secp256k1.cu (namespace secp256k1::cuda).
   Must be declared in the same namespace so the linker finds them. */
namespace cuda {
extern __global__ void ecdsa_verify_batch_kernel(
    const uint8_t* __restrict__ msg_hashes,
    const JacobianPoint* __restrict__ public_keys,
    const ECDSASignatureGPU* __restrict__ sigs,
    bool*          __restrict__ results,
    int count);

extern __global__ void schnorr_verify_batch_kernel(
    const uint8_t* __restrict__ pubkeys_x,
    const uint8_t* __restrict__ msgs,
    const SchnorrSignatureGPU* __restrict__ sigs,
    bool*          __restrict__ results,
    int count);
} // namespace cuda

namespace gpu {

/* Import CUDA types (FieldElement, Scalar, JacobianPoint, etc.) and kernels
   from the secp256k1::cuda namespace into secp256k1::gpu. */
using namespace cuda;

/* ============================================================================
 * Thin wrapper kernels for device functions without __global__ entry points
 * ============================================================================ */

/** ECDH batch kernel: each thread computes SHA-256(0x02 || x) where
 *  x = x-coordinate of privkey[i] * pubkey[i]. */
__global__ void ecdh_batch_kernel(
    const Scalar* privkeys,
    const JacobianPoint* peer_pubs,
    uint8_t* out_secrets,      /* count * 32 bytes */
    bool* out_ok,
    int count)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    out_ok[idx] = secp256k1::cuda::ecdh_compute(
        &privkeys[idx], &peer_pubs[idx], out_secrets + idx * 32);
}

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
        if (count == 0) { clear_error(); return GpuError::Ok; }
        if (!scalars32 || !out_pubkeys33) return set_error(GpuError::NullArg, "NULL buffer");

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
        if (count == 0) { clear_error(); return GpuError::Ok; }
        if (!msg_hashes32 || !pubkeys33 || !sigs64 || !out_results)
            return set_error(GpuError::NullArg, "NULL buffer");

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
        if (count == 0) { clear_error(); return GpuError::Ok; }
        if (!msg_hashes32 || !pubkeys_x32 || !sigs64 || !out_results)
            return set_error(GpuError::NullArg, "NULL buffer");

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
        if (!ready_) return set_error(GpuError::Device, "context not initialised");
        if (count == 0) { clear_error(); return GpuError::Ok; }
        if (!privkeys32 || !peer_pubkeys33 || !out_secrets32)
            return set_error(GpuError::NullArg, "NULL buffer");

        /* Convert host bytes → CUDA types */
        std::vector<Scalar> h_keys(count);
        std::vector<JacobianPoint> h_pubs(count);
        for (size_t i = 0; i < count; ++i) {
            bytes_to_scalar(privkeys32 + i * 32, &h_keys[i]);
            if (!compressed_to_jacobian_host(peer_pubkeys33 + i * 33, &h_pubs[i]))
                h_pubs[i].infinity = true;
        }

        /* Allocate device memory */
        Scalar*        d_keys = nullptr;
        JacobianPoint* d_pubs = nullptr;
        uint8_t*       d_out  = nullptr;
        bool*          d_ok   = nullptr;

        CUDA_TRY(cudaMalloc(&d_keys, count * sizeof(Scalar)));
        CUDA_TRY(cudaMalloc(&d_pubs, count * sizeof(JacobianPoint)));
        CUDA_TRY(cudaMalloc(&d_out, count * 32));
        CUDA_TRY(cudaMalloc(&d_ok, count * sizeof(bool)));

        CUDA_TRY(cudaMemcpy(d_keys, h_keys.data(), count * sizeof(Scalar), cudaMemcpyHostToDevice));
        CUDA_TRY(cudaMemcpy(d_pubs, h_pubs.data(), count * sizeof(JacobianPoint), cudaMemcpyHostToDevice));

        /* Launch */
        int threads = 128;
        int blocks  = (static_cast<int>(count) + threads - 1) / threads;
        ecdh_batch_kernel<<<blocks, threads>>>(d_keys, d_pubs, d_out, d_ok, static_cast<int>(count));
        CUDA_TRY(cudaGetLastError());
        CUDA_TRY(cudaDeviceSynchronize());

        /* Download results */
        CUDA_TRY(cudaMemcpy(out_secrets32, d_out, count * 32, cudaMemcpyDeviceToHost));

        /* Check for failures (peer at infinity → zero shared secret) */
        bool* h_ok = new bool[count];
        CUDA_TRY(cudaMemcpy(h_ok, d_ok, count * sizeof(bool), cudaMemcpyDeviceToHost));
        for (size_t i = 0; i < count; ++i) {
            if (!h_ok[i]) std::memset(out_secrets32 + i * 32, 0, 32);
        }
        delete[] h_ok;

        cudaFree(d_ok);
        cudaFree(d_out);
        cudaFree(d_pubs);
        cudaFree(d_keys);
        clear_error();
        return GpuError::Ok;
    }

    GpuError hash160_pubkey_batch(
        const uint8_t* pubkeys33, size_t count,
        uint8_t* out_hash160) override
    {
        if (!ready_) return set_error(GpuError::Device, "context not initialised");
        if (count == 0) { clear_error(); return GpuError::Ok; }
        if (!pubkeys33 || !out_hash160)
            return set_error(GpuError::NullArg, "NULL buffer");

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
        if (!ready_) return set_error(GpuError::Device, "context not initialised");
        if (n == 0) { clear_error(); return GpuError::Ok; }
        if (!scalars32 || !points33 || !out_result33)
            return set_error(GpuError::NullArg, "NULL buffer");

        /* Convert host bytes → CUDA types */
        std::vector<Scalar> h_scalars(n);
        std::vector<JacobianPoint> h_points(n);
        for (size_t i = 0; i < n; ++i) {
            bytes_to_scalar(scalars32 + i * 32, &h_scalars[i]);
            if (!compressed_to_jacobian_host(points33 + i * 33, &h_points[i]))
                h_points[i].infinity = true;
        }

        /* Allocate device memory for scatter phase */
        Scalar*        d_scalars  = nullptr;
        JacobianPoint* d_points   = nullptr;
        JacobianPoint* d_partials = nullptr;

        CUDA_TRY(cudaMalloc(&d_scalars, n * sizeof(Scalar)));
        CUDA_TRY(cudaMalloc(&d_points, n * sizeof(JacobianPoint)));
        CUDA_TRY(cudaMalloc(&d_partials, n * sizeof(JacobianPoint)));

        CUDA_TRY(cudaMemcpy(d_scalars, h_scalars.data(), n * sizeof(Scalar), cudaMemcpyHostToDevice));
        CUDA_TRY(cudaMemcpy(d_points, h_points.data(), n * sizeof(JacobianPoint), cudaMemcpyHostToDevice));

        /* Phase 1: each thread computes scalars[i] * points[i] */
        int threads = 128;
        int blocks  = (static_cast<int>(n) + threads - 1) / threads;
        msm_scatter_kernel<<<blocks, threads>>>(d_scalars, d_points, d_partials, static_cast<int>(n));
        CUDA_TRY(cudaGetLastError());
        CUDA_TRY(cudaDeviceSynchronize());

        /* Phase 2: download partial results and sum on host via C++ helper. */
        std::vector<JacobianPoint> h_partials(n);
        CUDA_TRY(cudaMemcpy(h_partials.data(), d_partials, n * sizeof(JacobianPoint), cudaMemcpyDeviceToHost));

        cudaFree(d_partials);
        cudaFree(d_points);
        cudaFree(d_scalars);

        /* Marshal limbs into flat arrays for the host helper */
        std::vector<uint64_t> jx(n * 4), jy(n * 4), jz(n * 4);
        bool* jinf = new bool[n];
        for (size_t i = 0; i < n; ++i) {
            for (int j = 0; j < 4; ++j) {
                jx[i * 4 + j] = h_partials[i].x.limbs[j];
                jy[i * 4 + j] = h_partials[i].y.limbs[j];
                jz[i * 4 + j] = h_partials[i].z.limbs[j];
            }
            jinf[i] = h_partials[i].infinity;
        }

        bool ok = cuda_host::msm_accumulate(
            jx.data(), jy.data(), jz.data(), jinf, n, out_result33);
        delete[] jinf;

        if (!ok) {
            std::memset(out_result33, 0, 33);
            return set_error(GpuError::Arith, "MSM result is point at infinity");
        }

        clear_error();
        return GpuError::Ok;
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
     *  Uses secp256k1 curve equation y^2 = x^3 + 7 to recover y.
     *  Delegates to gpu_backend_cuda_host.cpp (compiled by host C++ compiler). */
    static bool compressed_to_jacobian_host(const uint8_t pub[33], JacobianPoint* out) {
        if (!cuda_host::decompress_pubkey(pub, out->x.limbs, out->y.limbs, out->z.limbs))
            return false;
        out->infinity = false;
        return true;
    }

    /** JacobianPoint → compressed 33 bytes on host.
     *  Delegates to gpu_backend_cuda_host.cpp (compiled by host C++ compiler). */
    static void jacobian_to_compressed_host(const JacobianPoint* p, uint8_t out[33]) {
        cuda_host::jacobian_to_compressed(p->x.limbs, p->y.limbs, p->z.limbs, p->infinity, out);
    }
};

/* -- Factory function ------------------------------------------------------ */
std::unique_ptr<GpuBackend> create_cuda_backend() {
    return std::make_unique<CudaBackend>();
}

} // namespace gpu
} // namespace secp256k1
