/* ============================================================================
 * UltrafastSecp256k1 -- GPU Host Operations Layer (Internal)
 * ============================================================================
 * Abstract interface for GPU backends. Each backend (CUDA, OpenCL, Metal)
 * implements GpuBackend. The C ABI (ufsecp_gpu.h) dispatches through this.
 *
 * NOT part of the public API. Internal use only.
 * ============================================================================ */
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

namespace secp256k1 {
namespace gpu {

/* -- Error codes (mirrors ufsecp_error_t + GPU codes) ---------------------- */
enum class GpuError : int {
    Ok              = 0,
    NullArg         = 1,
    BadKey          = 2,
    BadPubkey       = 3,
    BadSig          = 4,
    BadInput        = 5,
    VerifyFail      = 6,
    Arith           = 7,
    Internal        = 9,
    BufTooSmall     = 10,
    Unavailable     = 100,
    Device          = 101,
    Launch          = 102,
    Memory          = 103,
    Unsupported     = 104,
    Backend         = 105,
    Queue           = 106,
};

/* -- Device info ----------------------------------------------------------- */
struct DeviceInfo {
    char     name[128]           = {};
    uint64_t global_mem_bytes    = 0;
    uint32_t compute_units       = 0;
    uint32_t max_clock_mhz       = 0;
    uint32_t max_threads_per_block = 0;
    uint32_t backend_id          = 0;
    uint32_t device_index        = 0;
};

/* -- Abstract backend interface -------------------------------------------- */
class GpuBackend {
public:
    virtual ~GpuBackend() = default;

    /* Backend identity */
    virtual uint32_t backend_id() const = 0;
    virtual const char* backend_name() const = 0;

    /* Device enumeration */
    virtual uint32_t device_count() const = 0;
    virtual GpuError device_info(uint32_t device_index, DeviceInfo& out) const = 0;

    /* Context init / teardown for selected device */
    virtual GpuError init(uint32_t device_index) = 0;
    virtual void shutdown() = 0;
    virtual bool is_ready() const = 0;

    /* Error tracking */
    virtual GpuError last_error() const = 0;
    virtual const char* last_error_msg() const = 0;

    /* First-wave batch ops */
    virtual GpuError generator_mul_batch(
        const uint8_t* scalars32, size_t count,
        uint8_t* out_pubkeys33) = 0;

    virtual GpuError ecdsa_verify_batch(
        const uint8_t* msg_hashes32, const uint8_t* pubkeys33,
        const uint8_t* sigs64, size_t count,
        uint8_t* out_results) = 0;

    virtual GpuError schnorr_verify_batch(
        const uint8_t* msg_hashes32, const uint8_t* pubkeys_x32,
        const uint8_t* sigs64, size_t count,
        uint8_t* out_results) = 0;

    virtual GpuError ecdh_batch(
        const uint8_t* privkeys32, const uint8_t* peer_pubkeys33,
        size_t count, uint8_t* out_secrets32) = 0;

    virtual GpuError hash160_pubkey_batch(
        const uint8_t* pubkeys33, size_t count,
        uint8_t* out_hash160) = 0;

    virtual GpuError msm(
        const uint8_t* scalars32, const uint8_t* points33,
        size_t n, uint8_t* out_result33) = 0;
};

/* -- Backend registry ------------------------------------------------------ */

/** Return number of compiled backends. */
uint32_t backend_count();

/** Get backend IDs. Returns count written. */
uint32_t backend_ids(uint32_t* ids, uint32_t max_ids);

/** Create a backend instance by ID. Returns nullptr if not compiled. */
std::unique_ptr<GpuBackend> create_backend(uint32_t backend_id);

/** Check if a backend is compiled and has at least one device. */
bool is_available(uint32_t backend_id);

} // namespace gpu
} // namespace secp256k1
