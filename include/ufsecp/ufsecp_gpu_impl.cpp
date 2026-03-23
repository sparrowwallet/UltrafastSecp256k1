/* ============================================================================
 * UltrafastSecp256k1 -- GPU C ABI Implementation
 * ============================================================================
 * Implements the ufsecp_gpu_* functions declared in ufsecp_gpu.h.
 * Delegates all work to gpu::GpuBackend instances from gpu_backend.hpp.
 *
 * Build with: -DUFSECP_BUILDING (sets dllexport on Windows)
 * ============================================================================ */

#ifndef UFSECP_BUILDING
#define UFSECP_BUILDING
#endif

#include "ufsecp_gpu.h"
#include "../../gpu/include/gpu_backend.hpp"

#include <cstring>
#include <cstdlib>
#include <memory>
#include <mutex>

using namespace secp256k1::gpu;

/* ===========================================================================
 * Opaque GPU context definition
 * =========================================================================== */

struct ufsecp_gpu_ctx {
    std::unique_ptr<GpuBackend> backend;
    uint32_t backend_id;
    uint32_t device_index;
};

/* ===========================================================================
 * Internal helpers
 * =========================================================================== */

static inline ufsecp_error_t to_abi_error(GpuError e) {
    return static_cast<ufsecp_error_t>(static_cast<int>(e));
}

/* ===========================================================================
 * Backend & device discovery
 * =========================================================================== */

uint32_t ufsecp_gpu_backend_count(uint32_t* backend_ids_out, uint32_t max_ids) {
    const uint32_t count = backend_count();
    if (backend_ids_out && max_ids > 0) {
        backend_ids(backend_ids_out, max_ids);
    }
    return count;
}

const char* ufsecp_gpu_backend_name(uint32_t bid) {
    switch (bid) {
    case 1: return "CUDA";
    case 2: return "OpenCL";
    case 3: return "Metal";
    default: return "none";
    }
}

int ufsecp_gpu_is_available(uint32_t bid) {
    return is_available(bid) ? 1 : 0;
}

uint32_t ufsecp_gpu_device_count(uint32_t bid) {
    auto b = create_backend(bid);
    if (!b) return 0;
    return b->device_count();
}

ufsecp_error_t ufsecp_gpu_device_info(
    uint32_t bid, uint32_t device_index,
    ufsecp_gpu_device_info_t* info_out)
{
    if (!info_out) return UFSECP_ERR_NULL_ARG;

    auto b = create_backend(bid);
    if (!b) return UFSECP_ERR_GPU_UNAVAILABLE;

    DeviceInfo di;
    auto err = b->device_info(device_index, di);
    if (err != GpuError::Ok) return to_abi_error(err);

    std::memcpy(info_out->name, di.name, sizeof(info_out->name));
    info_out->global_mem_bytes      = di.global_mem_bytes;
    info_out->compute_units         = di.compute_units;
    info_out->max_clock_mhz         = di.max_clock_mhz;
    info_out->max_threads_per_block = di.max_threads_per_block;
    info_out->backend_id            = di.backend_id;
    info_out->device_index          = di.device_index;
    return UFSECP_OK;
}

/* ===========================================================================
 * GPU context lifecycle
 * =========================================================================== */

ufsecp_error_t ufsecp_gpu_ctx_create(
    ufsecp_gpu_ctx** ctx_out,
    uint32_t bid,
    uint32_t device_index)
{
    if (!ctx_out) return UFSECP_ERR_NULL_ARG;
    *ctx_out = nullptr;

    auto backend = create_backend(bid);
    if (!backend) return UFSECP_ERR_GPU_UNAVAILABLE;

    auto err = backend->init(device_index);
    if (err != GpuError::Ok) return to_abi_error(err);

    auto* ctx = new (std::nothrow) ufsecp_gpu_ctx;
    if (!ctx) return UFSECP_ERR_INTERNAL;

    ctx->backend      = std::move(backend);
    ctx->backend_id   = bid;
    ctx->device_index = device_index;
    *ctx_out = ctx;
    return UFSECP_OK;
}

void ufsecp_gpu_ctx_destroy(ufsecp_gpu_ctx* ctx) {
    if (ctx) {
        ctx->backend.reset();
        delete ctx;
    }
}

ufsecp_error_t ufsecp_gpu_last_error(const ufsecp_gpu_ctx* ctx) {
    if (!ctx) return UFSECP_ERR_NULL_ARG;
    return to_abi_error(ctx->backend->last_error());
}

const char* ufsecp_gpu_last_error_msg(const ufsecp_gpu_ctx* ctx) {
    if (!ctx) return "NULL GPU context";
    return ctx->backend->last_error_msg();
}

/* ===========================================================================
 * First-wave GPU batch operations
 * =========================================================================== */

ufsecp_error_t ufsecp_gpu_generator_mul_batch(
    ufsecp_gpu_ctx* ctx,
    const uint8_t* scalars32,
    size_t count,
    uint8_t* out_pubkeys33)
{
    if (!ctx) return UFSECP_ERR_NULL_ARG;
    if (count == 0) return UFSECP_OK;
    if (!scalars32 || !out_pubkeys33) return UFSECP_ERR_NULL_ARG;
    return to_abi_error(
        ctx->backend->generator_mul_batch(scalars32, count, out_pubkeys33));
}

ufsecp_error_t ufsecp_gpu_ecdsa_verify_batch(
    ufsecp_gpu_ctx* ctx,
    const uint8_t* msg_hashes32,
    const uint8_t* pubkeys33,
    const uint8_t* sigs64,
    size_t count,
    uint8_t* out_results)
{
    if (!ctx) return UFSECP_ERR_NULL_ARG;
    if (count == 0) return UFSECP_OK;
    if (!msg_hashes32 || !pubkeys33 || !sigs64 || !out_results) {
        return UFSECP_ERR_NULL_ARG;
    }
    return to_abi_error(
        ctx->backend->ecdsa_verify_batch(
            msg_hashes32, pubkeys33, sigs64, count, out_results));
}

ufsecp_error_t ufsecp_gpu_schnorr_verify_batch(
    ufsecp_gpu_ctx* ctx,
    const uint8_t* msg_hashes32,
    const uint8_t* pubkeys_x32,
    const uint8_t* sigs64,
    size_t count,
    uint8_t* out_results)
{
    if (!ctx) return UFSECP_ERR_NULL_ARG;
    if (count == 0) return UFSECP_OK;
    if (!msg_hashes32 || !pubkeys_x32 || !sigs64 || !out_results) {
        return UFSECP_ERR_NULL_ARG;
    }
    return to_abi_error(
        ctx->backend->schnorr_verify_batch(
            msg_hashes32, pubkeys_x32, sigs64, count, out_results));
}

ufsecp_error_t ufsecp_gpu_ecdh_batch(
    ufsecp_gpu_ctx* ctx,
    const uint8_t* privkeys32,
    const uint8_t* peer_pubkeys33,
    size_t count,
    uint8_t* out_secrets32)
{
    if (!ctx) return UFSECP_ERR_NULL_ARG;
    if (count == 0) return UFSECP_OK;
    if (!privkeys32 || !peer_pubkeys33 || !out_secrets32) {
        return UFSECP_ERR_NULL_ARG;
    }
    return to_abi_error(
        ctx->backend->ecdh_batch(
            privkeys32, peer_pubkeys33, count, out_secrets32));
}

ufsecp_error_t ufsecp_gpu_hash160_pubkey_batch(
    ufsecp_gpu_ctx* ctx,
    const uint8_t* pubkeys33,
    size_t count,
    uint8_t* out_hash160)
{
    if (!ctx) return UFSECP_ERR_NULL_ARG;
    if (count == 0) return UFSECP_OK;
    if (!pubkeys33 || !out_hash160) return UFSECP_ERR_NULL_ARG;
    return to_abi_error(
        ctx->backend->hash160_pubkey_batch(pubkeys33, count, out_hash160));
}

ufsecp_error_t ufsecp_gpu_msm(
    ufsecp_gpu_ctx* ctx,
    const uint8_t* scalars32,
    const uint8_t* points33,
    size_t n,
    uint8_t* out_result33)
{
    if (!ctx) return UFSECP_ERR_NULL_ARG;
    if (n == 0) return UFSECP_OK;
    if (!scalars32 || !points33 || !out_result33) return UFSECP_ERR_NULL_ARG;
    return to_abi_error(
        ctx->backend->msm(scalars32, points33, n, out_result33));
}

ufsecp_error_t ufsecp_gpu_frost_verify_partial_batch(
    ufsecp_gpu_ctx* ctx,
    const uint8_t* z_i32,
    const uint8_t* D_i33,
    const uint8_t* E_i33,
    const uint8_t* Y_i33,
    const uint8_t* rho_i32,
    const uint8_t* lambda_ie32,
    const uint8_t* negate_R,
    const uint8_t* negate_key,
    size_t count,
    uint8_t* out_results)
{
    if (!ctx) return UFSECP_ERR_NULL_ARG;
    if (count == 0) return UFSECP_OK;
    if (!z_i32 || !D_i33 || !E_i33 || !Y_i33 || !rho_i32 ||
        !lambda_ie32 || !negate_R || !negate_key || !out_results) {
        return UFSECP_ERR_NULL_ARG;
    }
    return to_abi_error(
        ctx->backend->frost_verify_partial_batch(
            z_i32, D_i33, E_i33, Y_i33, rho_i32, lambda_ie32,
            negate_R, negate_key, count, out_results));
}

ufsecp_error_t ufsecp_gpu_ecrecover_batch(
    ufsecp_gpu_ctx* ctx,
    const uint8_t* msg_hashes32,
    const uint8_t* sigs64,
    const int*     recids,
    size_t count,
    uint8_t* out_pubkeys33,
    uint8_t* out_valid)
{
    if (!ctx) return UFSECP_ERR_NULL_ARG;
    if (count == 0) return UFSECP_OK;
    if (!msg_hashes32 || !sigs64 || !recids || !out_pubkeys33 || !out_valid) {
        return UFSECP_ERR_NULL_ARG;
    }
    return to_abi_error(
        ctx->backend->ecrecover_batch(
            msg_hashes32, sigs64, recids, count, out_pubkeys33, out_valid));
}

/* ===========================================================================
 * GPU error string
 * =========================================================================== */

const char* ufsecp_gpu_error_str(ufsecp_error_t err) {
    switch (err) {
    case UFSECP_OK:                   return "OK";
    case UFSECP_ERR_NULL_ARG:         return "NULL argument";
    case UFSECP_ERR_BAD_KEY:          return "invalid private key";
    case UFSECP_ERR_BAD_PUBKEY:       return "invalid public key";
    case UFSECP_ERR_BAD_SIG:          return "invalid signature";
    case UFSECP_ERR_BAD_INPUT:        return "malformed input";
    case UFSECP_ERR_VERIFY_FAIL:      return "verification failed";
    case UFSECP_ERR_ARITH:            return "arithmetic error";
    case UFSECP_ERR_SELFTEST:         return "self-test failed";
    case UFSECP_ERR_INTERNAL:         return "internal error";
    case UFSECP_ERR_BUF_TOO_SMALL:    return "buffer too small";
    case UFSECP_ERR_GPU_UNAVAILABLE:  return "GPU backend unavailable";
    case UFSECP_ERR_GPU_DEVICE:       return "GPU device error";
    case UFSECP_ERR_GPU_LAUNCH:       return "GPU kernel launch failed";
    case UFSECP_ERR_GPU_MEMORY:       return "GPU memory error";
    case UFSECP_ERR_GPU_UNSUPPORTED:  return "operation not supported on this GPU backend";
    case UFSECP_ERR_GPU_BACKEND:      return "GPU backend driver error";
    case UFSECP_ERR_GPU_QUEUE:        return "GPU command queue error";
    default:                          return "unknown error";
    }
}
