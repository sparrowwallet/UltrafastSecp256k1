// =============================================================================
// UltrafastSecp256k1 Metal — GPU Compute Kernels (Accelerated)
// =============================================================================
// Metal compute shaders for secp256k1 batch operations on Apple Silicon.
//
// ACCELERATION TECHNIQUES:
//   - Comba product scanning in field_mul/field_sqr (see secp256k1_field.h)
//   - 4-bit windowed scalar_mul (see secp256k1_point.h)
//   - Proper O(1) per-thread offset via scalar multiplication
//   - Chunked batch inverse — one threadgroup per chunk
//   - Branchless bloom check with coalesced memory access
//
// Kernels:
//   1.  search_kernel          — Batch ECC search (O(1) offset + bloom check)
//   2.  scalar_mul_batch       — Batch scalar multiplication
//   3.  generator_mul_batch    — Batch G×k multiplication
//   4.  field_mul_bench        — Field multiplication benchmark
//   5.  field_sqr_bench        — Field squaring benchmark
//   5b. field_add_bench        — Field addition benchmark
//   5c. field_sub_bench        — Field subtraction benchmark
//   5d. field_inv_bench        — Field inversion benchmark
//   6.  batch_inverse          — Chunked Montgomery batch inverse
//   7.  point_add_kernel       — Point addition (testing)
//   8.  point_double_kernel    — Point doubling (testing)
// =============================================================================

#include <metal_stdlib>
#include "secp256k1_field.h"
#include "secp256k1_point.h"
#include "secp256k1_bloom.h"
#include "secp256k1_extended.h"
#include "secp256k1_hash160.h"
#include "secp256k1_zk.h"

using namespace metal;

// =============================================================================
// Search Result — 40 bytes, matching CUDA layout
// =============================================================================

struct SearchResult {
    uint x[8];       // 32 bytes: affine X coordinate
    uint index_lo;   // iteration index (low 32)
    uint index_hi;   // iteration index (high 32)
};

// =============================================================================
// Kernel Parameters — passed as uniforms (constant buffer)
// =============================================================================

struct SearchParams {
    uint batch_size;
    uint batch_offset_lo;
    uint batch_offset_hi;
    uint max_results;
};

// =============================================================================
// Kernel 1: ECC Search — O(1) per-thread offset + bloom filter
// =============================================================================
// ACCELERATION: Instead of O(tid) incremental additions, each thread
// computes its scalar offset k = batch_start + tid and does a single
// scalar_mul(G, k). The 4-bit windowed scalar_mul makes this fast.
//
// For SUBTRACTION search (Q - kG = target?), host pre-computes:
//   Q_start = target point
//   KQ_start_scalar = base scalar offset
// Thread tid checks: k = KQ_start_scalar + tid
// =============================================================================

kernel void search_kernel(
    constant JacobianPoint &Q_start    [[buffer(0)]],
    constant AffinePoint &G_affine     [[buffer(1)]],
    constant JacobianPoint &KQ_start   [[buffer(2)]],
    constant AffinePoint &KG_affine    [[buffer(3)]],
    device const uint *bloom_bitwords  [[buffer(4)]],
    constant BloomParams &bloom_params [[buffer(5)]],
    device SearchResult *results       [[buffer(6)]],
    device atomic_uint *result_count   [[buffer(7)]],
    constant SearchParams &params      [[buffer(8)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= params.batch_size) return;

    // Compute scalar offset: k = tid as Scalar256
    Scalar256 k_offset;
    k_offset.limbs[0] = tid;
    for (int i = 1; i < 8; i++) k_offset.limbs[i] = 0;

    // Copy constant-address-space args to thread-local (MSL address space requirement)
    AffinePoint kg_local = KG_affine;
    JacobianPoint kq_local = KQ_start;

    // Compute tid*KG via scalar_mul (4-bit windowed, efficient for small scalars)
    JacobianPoint offset_point = scalar_mul(kg_local, k_offset);

    // KQ = KQ_start + tid*KG
    JacobianPoint KQ = jacobian_add(kq_local, offset_point);

    // Convert to affine X
    AffinePoint kq_aff = jacobian_to_affine(KQ);

    // Convert X to little-endian bytes for bloom test
    uint8_t x_bytes[32];
    for (int i = 0; i < 8; i++) {
        uint limb = kq_aff.x.limbs[i];
        x_bytes[i * 4 + 0] = uint8_t(limb & 0xFFu);
        x_bytes[i * 4 + 1] = uint8_t((limb >> 8) & 0xFFu);
        x_bytes[i * 4 + 2] = uint8_t((limb >> 16) & 0xFFu);
        x_bytes[i * 4 + 3] = uint8_t((limb >> 24) & 0xFFu);
    }

    // Bloom filter check — branchless
    if (bloom_test(bloom_bitwords, bloom_params, x_bytes, 32)) {
        uint idx = atomic_fetch_add_explicit(result_count, 1u, memory_order_relaxed);
        if (idx < params.max_results) {
            for (int i = 0; i < 8; i++) results[idx].x[i] = kq_aff.x.limbs[i];

            // 64-bit index = batch_offset + tid
            ulong full_idx = (ulong(params.batch_offset_hi) << 32) | ulong(params.batch_offset_lo);
            full_idx += tid;
            results[idx].index_lo = uint(full_idx);
            results[idx].index_hi = uint(full_idx >> 32);
        }
    }
}

// =============================================================================
// Kernel 2: Batch Scalar Multiplication — P × k for N points
// =============================================================================

kernel void scalar_mul_batch(
    device const AffinePoint *bases    [[buffer(0)]],
    device const Scalar256 *scalars    [[buffer(1)]],
    device AffinePoint *results        [[buffer(2)]],
    constant uint &count               [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;

    AffinePoint base = bases[tid];
    Scalar256 k = scalars[tid];

    JacobianPoint jac = scalar_mul_glv(base, k);
    results[tid] = jacobian_to_affine(jac);
}

// =============================================================================
// Kernel 3: Batch Generator Multiplication — G × k for N scalars
// =============================================================================

kernel void generator_mul_batch(
    device const Scalar256 *scalars    [[buffer(0)]],
    device AffinePoint *results        [[buffer(1)]],
    constant uint &count               [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;

    AffinePoint gen = generator_affine();
    Scalar256 k = scalars[tid];

    JacobianPoint jac = scalar_mul(gen, k);
    results[tid] = jacobian_to_affine(jac);
}

// =============================================================================
// Kernel 4: Field Multiplication Benchmark
// =============================================================================

kernel void field_mul_bench(
    device const FieldElement *a_arr  [[buffer(0)]],
    device const FieldElement *b_arr  [[buffer(1)]],
    device FieldElement *r_arr        [[buffer(2)]],
    constant uint &count              [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;
    FieldElement a = a_arr[tid];
    FieldElement b = b_arr[tid];
    r_arr[tid] = field_mul(a, b);
}

// =============================================================================
// Kernel 5: Field Squaring Benchmark
// =============================================================================

kernel void field_sqr_bench(
    device const FieldElement *a_arr  [[buffer(0)]],
    device FieldElement *r_arr        [[buffer(1)]],
    constant uint &count              [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;
    FieldElement a = a_arr[tid];
    r_arr[tid] = field_sqr(a);
}

// =============================================================================
// Kernel 5b: Field Addition Benchmark
// =============================================================================

kernel void field_add_bench(
    device const FieldElement *a_arr  [[buffer(0)]],
    device const FieldElement *b_arr  [[buffer(1)]],
    device FieldElement *r_arr        [[buffer(2)]],
    constant uint &count              [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;
    FieldElement a = a_arr[tid];
    FieldElement b = b_arr[tid];
    r_arr[tid] = field_add(a, b);
}

// =============================================================================
// Kernel 5c: Field Subtraction Benchmark
// =============================================================================

kernel void field_sub_bench(
    device const FieldElement *a_arr  [[buffer(0)]],
    device const FieldElement *b_arr  [[buffer(1)]],
    device FieldElement *r_arr        [[buffer(2)]],
    constant uint &count              [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;
    FieldElement a = a_arr[tid];
    FieldElement b = b_arr[tid];
    r_arr[tid] = field_sub(a, b);
}

// =============================================================================
// Kernel 5d: Field Inversion Benchmark
// =============================================================================

kernel void field_inv_bench(
    device const FieldElement *a_arr  [[buffer(0)]],
    device FieldElement *r_arr        [[buffer(1)]],
    constant uint &count              [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;
    FieldElement a = a_arr[tid];
    r_arr[tid] = field_inv(a);
}

// =============================================================================
// Kernel 6: Chunked Batch Field Inverse
// =============================================================================
// ACCELERATION: Each threadgroup handles one chunk of the array.
// The chunk_size is passed as uniform — each threadgroup uses Montgomery's
// trick internally (1 inversion per chunk).
//
// For N elements with chunk_size C:
//   - Launch N/C threadgroups, each with 1 thread
//   - Total inversions: N/C instead of 1 (slightly more, but parallel!)
//
// With 256 chunks on Apple Silicon (256 threadgroups), this saturates the
// GPU while keeping inversion count manageable.
// =============================================================================

struct BatchInvParams {
    uint total_count;
    uint chunk_size;
};

kernel void batch_inverse(
    device FieldElement *elements     [[buffer(0)]],
    device FieldElement *scratch      [[buffer(1)]],
    constant BatchInvParams &params   [[buffer(2)]],
    uint tgid [[threadgroup_position_in_grid]]
) {
    uint start = tgid * params.chunk_size;
    uint end = min(start + params.chunk_size, params.total_count);
    if (start >= end) return;
    uint count = end - start;

    // Forward pass: prefix products (copy device→thread for field_mul)
    FieldElement acc = elements[start];
    scratch[start] = acc;
    for (uint i = 1; i < count; i++) {
        FieldElement el = elements[start + i];
        acc = field_mul(acc, el);
        scratch[start + i] = acc;
    }

    // Single inversion of the chunk product
    FieldElement s_last = scratch[start + count - 1];
    FieldElement inv = field_inv(s_last);

    // Backward pass: recover individual inverses
    for (uint i = count - 1; i > 0; i--) {
        FieldElement s_prev = scratch[start + i - 1];
        FieldElement el_i = elements[start + i];
        FieldElement tmp = field_mul(inv, s_prev);
        inv = field_mul(inv, el_i);
        elements[start + i] = tmp;
    }
    elements[start] = inv;
}

// =============================================================================
// Kernel 7: Point Addition Kernel (for testing)
// =============================================================================

kernel void point_add_kernel(
    device const JacobianPoint *a_arr  [[buffer(0)]],
    device const JacobianPoint *b_arr  [[buffer(1)]],
    device JacobianPoint *r_arr        [[buffer(2)]],
    constant uint &count               [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;
    // Copy device→thread for address space compatibility
    JacobianPoint a_local = a_arr[tid];
    JacobianPoint b_local = b_arr[tid];
    r_arr[tid] = jacobian_add(a_local, b_local);
}

// =============================================================================
// Kernel 8: Point Doubling Kernel (for testing)
// =============================================================================

kernel void point_double_kernel(
    device const JacobianPoint *a_arr  [[buffer(0)]],
    device JacobianPoint *r_arr        [[buffer(1)]],
    constant uint &count               [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;
    JacobianPoint a_local = a_arr[tid];
    r_arr[tid] = jacobian_double(a_local);
}

// =============================================================================
// Kernel 9: Batch ECDSA Sign
// =============================================================================

kernel void ecdsa_sign_batch(
    device const uchar *msg_hashes     [[buffer(0)]],   // N × 32 bytes
    device const uchar *privkeys       [[buffer(1)]],   // N × 32 bytes
    device uchar *signatures           [[buffer(2)]],   // N × 64 bytes (r ∥ s)
    constant uint &count               [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;

    Scalar256 msg, sec;
    for (int i = 0; i < 8; i++) {
        uint idx = tid * 32 + i * 4;
        msg.limbs[7 - i] = ((uint)msg_hashes[idx] << 24) |
                            ((uint)msg_hashes[idx+1] << 16) |
                            ((uint)msg_hashes[idx+2] << 8) |
                            ((uint)msg_hashes[idx+3]);
        sec.limbs[7 - i] = ((uint)privkeys[idx] << 24) |
                            ((uint)privkeys[idx+1] << 16) |
                            ((uint)privkeys[idx+2] << 8) |
                            ((uint)privkeys[idx+3]);
    }

    Scalar256 r_sig, s_sig;
    ecdsa_sign(msg, sec, r_sig, s_sig);

    // Write r ∥ s as big-endian
    uint out_off = tid * 64;
    for (int i = 0; i < 8; i++) {
        uint rv = r_sig.limbs[7 - i];
        signatures[out_off + i*4 + 0] = (uchar)(rv >> 24);
        signatures[out_off + i*4 + 1] = (uchar)(rv >> 16);
        signatures[out_off + i*4 + 2] = (uchar)(rv >> 8);
        signatures[out_off + i*4 + 3] = (uchar)(rv);
    }
    for (int i = 0; i < 8; i++) {
        uint sv = s_sig.limbs[7 - i];
        signatures[out_off + 32 + i*4 + 0] = (uchar)(sv >> 24);
        signatures[out_off + 32 + i*4 + 1] = (uchar)(sv >> 16);
        signatures[out_off + 32 + i*4 + 2] = (uchar)(sv >> 8);
        signatures[out_off + 32 + i*4 + 3] = (uchar)(sv);
    }
}

// =============================================================================
// Kernel 10: Batch ECDSA Verify
// =============================================================================

kernel void ecdsa_verify_batch(
    device const uchar *msg_hashes     [[buffer(0)]],   // N × 32
    device const uchar *pubkeys        [[buffer(1)]],   // N × 64 (x ∥ y, uncompressed coords)
    device const uchar *signatures     [[buffer(2)]],   // N × 64 (r ∥ s)
    device uint *results               [[buffer(3)]],   // N × 1 (0=invalid, 1=valid)
    constant uint &count               [[buffer(4)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;

    Scalar256 msg, r_sig, s_sig;
    AffinePoint pub;

    uint base_msg = tid * 32;
    uint base_pub = tid * 64;
    uint base_sig = tid * 64;

    for (int i = 0; i < 8; i++) {
        msg.limbs[7 - i] = ((uint)msg_hashes[base_msg + i*4] << 24) |
                            ((uint)msg_hashes[base_msg + i*4+1] << 16) |
                            ((uint)msg_hashes[base_msg + i*4+2] << 8) |
                            ((uint)msg_hashes[base_msg + i*4+3]);

        pub.x.limbs[7 - i] = ((uint)pubkeys[base_pub + i*4] << 24) |
                              ((uint)pubkeys[base_pub + i*4+1] << 16) |
                              ((uint)pubkeys[base_pub + i*4+2] << 8) |
                              ((uint)pubkeys[base_pub + i*4+3]);
        pub.y.limbs[7 - i] = ((uint)pubkeys[base_pub + 32 + i*4] << 24) |
                              ((uint)pubkeys[base_pub + 32 + i*4+1] << 16) |
                              ((uint)pubkeys[base_pub + 32 + i*4+2] << 8) |
                              ((uint)pubkeys[base_pub + 32 + i*4+3]);

        r_sig.limbs[7 - i] = ((uint)signatures[base_sig + i*4] << 24) |
                              ((uint)signatures[base_sig + i*4+1] << 16) |
                              ((uint)signatures[base_sig + i*4+2] << 8) |
                              ((uint)signatures[base_sig + i*4+3]);
        s_sig.limbs[7 - i] = ((uint)signatures[base_sig + 32 + i*4] << 24) |
                              ((uint)signatures[base_sig + 32 + i*4+1] << 16) |
                              ((uint)signatures[base_sig + 32 + i*4+2] << 8) |
                              ((uint)signatures[base_sig + 32 + i*4+3]);
    }

    results[tid] = ecdsa_verify(msg, pub, r_sig, s_sig) ? 1u : 0u;
}

// =============================================================================
// Kernel 11: Batch Schnorr Sign (BIP-340)
// =============================================================================

kernel void schnorr_sign_batch(
    device const uchar *msg_hashes     [[buffer(0)]],   // N × 32
    device const uchar *privkeys       [[buffer(1)]],   // N × 32
    device uchar *signatures           [[buffer(2)]],   // N × 64 (R.x ∥ s)
    constant uint &count               [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;

    Scalar256 msg, sec;
    for (int i = 0; i < 8; i++) {
        uint idx = tid * 32 + i * 4;
        msg.limbs[7 - i] = ((uint)msg_hashes[idx] << 24) |
                            ((uint)msg_hashes[idx+1] << 16) |
                            ((uint)msg_hashes[idx+2] << 8) |
                            ((uint)msg_hashes[idx+3]);
        sec.limbs[7 - i] = ((uint)privkeys[idx] << 24) |
                            ((uint)privkeys[idx+1] << 16) |
                            ((uint)privkeys[idx+2] << 8) |
                            ((uint)privkeys[idx+3]);
    }

    Scalar256 sig_rx, sig_s;
    schnorr_sign(msg, sec, sig_rx, sig_s);

    uint out_off = tid * 64;
    for (int i = 0; i < 8; i++) {
        uint rv = sig_rx.limbs[7 - i];
        signatures[out_off + i*4 + 0] = (uchar)(rv >> 24);
        signatures[out_off + i*4 + 1] = (uchar)(rv >> 16);
        signatures[out_off + i*4 + 2] = (uchar)(rv >> 8);
        signatures[out_off + i*4 + 3] = (uchar)(rv);
    }
    for (int i = 0; i < 8; i++) {
        uint sv = sig_s.limbs[7 - i];
        signatures[out_off + 32 + i*4 + 0] = (uchar)(sv >> 24);
        signatures[out_off + 32 + i*4 + 1] = (uchar)(sv >> 16);
        signatures[out_off + 32 + i*4 + 2] = (uchar)(sv >> 8);
        signatures[out_off + 32 + i*4 + 3] = (uchar)(sv);
    }
}

// =============================================================================
// Kernel 12: Batch Schnorr Verify (BIP-340)
// =============================================================================

kernel void schnorr_verify_batch(
    device const uchar *msg_hashes     [[buffer(0)]],   // N × 32
    device const uchar *pubkeys_x      [[buffer(1)]],   // N × 32 (x-only)
    device const uchar *signatures     [[buffer(2)]],   // N × 64 (R.x ∥ s)
    device uint *results               [[buffer(3)]],
    constant uint &count               [[buffer(4)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;

    Scalar256 msg, pub_x, sig_rx, sig_s;
    for (int i = 0; i < 8; i++) {
        uint mi = tid * 32 + i * 4;
        msg.limbs[7 - i] = ((uint)msg_hashes[mi] << 24) |
                            ((uint)msg_hashes[mi+1] << 16) |
                            ((uint)msg_hashes[mi+2] << 8) |
                            ((uint)msg_hashes[mi+3]);

        pub_x.limbs[7 - i] = ((uint)pubkeys_x[mi] << 24) |
                              ((uint)pubkeys_x[mi+1] << 16) |
                              ((uint)pubkeys_x[mi+2] << 8) |
                              ((uint)pubkeys_x[mi+3]);

        uint si = tid * 64 + i * 4;
        sig_rx.limbs[7 - i] = ((uint)signatures[si] << 24) |
                               ((uint)signatures[si+1] << 16) |
                               ((uint)signatures[si+2] << 8) |
                               ((uint)signatures[si+3]);
        sig_s.limbs[7 - i] = ((uint)signatures[si + 32] << 24) |
                              ((uint)signatures[si + 32 +1] << 16) |
                              ((uint)signatures[si + 32 +2] << 8) |
                              ((uint)signatures[si + 32 +3]);
    }

    // Convert pub_x to FieldElement for schnorr_verify
    FieldElement px;
    for (int i = 0; i < 8; i++) px.limbs[i] = pub_x.limbs[i];

    results[tid] = schnorr_verify(msg, px, sig_rx, sig_s) ? 1u : 0u;
}

// =============================================================================
// Kernel 13: Batch ECDH Shared Secret
// =============================================================================

kernel void ecdh_batch(
    device const uchar *privkeys       [[buffer(0)]],   // N × 32
    device const uchar *pubkeys        [[buffer(1)]],   // N × 64 (x ∥ y)
    device uchar *shared_secrets       [[buffer(2)]],   // N × 32 (x-only)
    constant uint &count               [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;

    Scalar256 sec;
    AffinePoint pub;
    for (int i = 0; i < 8; i++) {
        uint ki = tid * 32 + i * 4;
        sec.limbs[7 - i] = ((uint)privkeys[ki] << 24) |
                            ((uint)privkeys[ki+1] << 16) |
                            ((uint)privkeys[ki+2] << 8) |
                            ((uint)privkeys[ki+3]);

        uint pi = tid * 64 + i * 4;
        pub.x.limbs[7 - i] = ((uint)pubkeys[pi] << 24) |
                              ((uint)pubkeys[pi+1] << 16) |
                              ((uint)pubkeys[pi+2] << 8) |
                              ((uint)pubkeys[pi+3]);
        uint yi = tid * 64 + 32 + i * 4;
        pub.y.limbs[7 - i] = ((uint)pubkeys[yi] << 24) |
                              ((uint)pubkeys[yi+1] << 16) |
                              ((uint)pubkeys[yi+2] << 8) |
                              ((uint)pubkeys[yi+3]);
    }

    FieldElement shared_x = ecdh_shared_secret_xonly(sec, pub);

    // Output x as big-endian
    uint out_off = tid * 32;
    for (int i = 0; i < 8; i++) {
        uint v = shared_x.limbs[7 - i];
        shared_secrets[out_off + i*4 + 0] = (uchar)(v >> 24);
        shared_secrets[out_off + i*4 + 1] = (uchar)(v >> 16);
        shared_secrets[out_off + i*4 + 2] = (uchar)(v >> 8);
        shared_secrets[out_off + i*4 + 3] = (uchar)(v);
    }
}

// =============================================================================
// Kernel 14: Batch Hash160 of public keys
// =============================================================================

kernel void hash160_batch(
    device const uchar *pubkeys        [[buffer(0)]],
    device uchar *hashes               [[buffer(1)]],   // N × 20
    constant uint &stride              [[buffer(2)]],   // 33 or 65
    constant uint &count               [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;

    uchar pk[65];
    const uint pk_len = (stride <= 65u) ? stride : 65u;
    for (uint i = 0; i < pk_len; ++i) {
        pk[i] = pubkeys[tid * stride + i];
    }

    uchar h160[20];
    hash160_pubkey(pk, pk_len, h160);

    for (int i = 0; i < 20; ++i) {
        hashes[tid * 20 + i] = h160[i];
    }
}

// =============================================================================
// Kernel 15: Batch Key Recovery
// =============================================================================

kernel void ecrecover_batch(
    device const uchar *msg_hashes     [[buffer(0)]],   // N × 32
    device const uchar *signatures     [[buffer(1)]],   // N × 64 (r ∥ s)
    device const uint *recids          [[buffer(2)]],    // N × 1 (recovery id 0-3)
    device uchar *pubkeys              [[buffer(3)]],    // N × 64 (x ∥ y)
    device uint *valid                 [[buffer(4)]],    // N × 1 (0=fail, 1=ok)
    constant uint &count               [[buffer(5)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;

    Scalar256 msg, r_sig, s_sig;
    for (int i = 0; i < 8; i++) {
        uint mi = tid * 32 + i * 4;
        msg.limbs[7 - i] = ((uint)msg_hashes[mi] << 24) |
                            ((uint)msg_hashes[mi+1] << 16) |
                            ((uint)msg_hashes[mi+2] << 8) |
                            ((uint)msg_hashes[mi+3]);

        uint si = tid * 64 + i * 4;
        r_sig.limbs[7 - i] = ((uint)signatures[si] << 24) |
                              ((uint)signatures[si+1] << 16) |
                              ((uint)signatures[si+2] << 8) |
                              ((uint)signatures[si+3]);
        s_sig.limbs[7 - i] = ((uint)signatures[si + 32] << 24) |
                              ((uint)signatures[si + 32 +1] << 16) |
                              ((uint)signatures[si + 32 +2] << 8) |
                              ((uint)signatures[si + 32 +3]);
    }

    AffinePoint recovered;
    bool ok = ecdsa_recover(msg, r_sig, s_sig, recids[tid], recovered);
    valid[tid] = ok ? 1u : 0u;

    if (ok) {
        uint out_off = tid * 64;
        for (int i = 0; i < 8; i++) {
            uint xv = recovered.x.limbs[7 - i];
            pubkeys[out_off + i*4 + 0] = (uchar)(xv >> 24);
            pubkeys[out_off + i*4 + 1] = (uchar)(xv >> 16);
            pubkeys[out_off + i*4 + 2] = (uchar)(xv >> 8);
            pubkeys[out_off + i*4 + 3] = (uchar)(xv);
        }
        for (int i = 0; i < 8; i++) {
            uint yv = recovered.y.limbs[7 - i];
            pubkeys[out_off + 32 + i*4 + 0] = (uchar)(yv >> 24);
            pubkeys[out_off + 32 + i*4 + 1] = (uchar)(yv >> 16);
            pubkeys[out_off + 32 + i*4 + 2] = (uchar)(yv >> 8);
            pubkeys[out_off + 32 + i*4 + 3] = (uchar)(yv);
        }
    }
}

// =============================================================================
// Kernel 16: SHA-256 Benchmark
// =============================================================================

kernel void sha256_bench(
    device const uchar *inputs         [[buffer(0)]],   // N × 64 bytes
    device uchar *outputs              [[buffer(1)]],   // N × 32 bytes
    constant uint &count               [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;

    uchar data[64];
    for (int i = 0; i < 64; i++) data[i] = inputs[tid * 64 + i];

    uchar hash[32];
    sha256_oneshot(data, 64, hash);

    for (int i = 0; i < 32; i++) outputs[tid * 32 + i] = hash[i];
}

// =============================================================================
// Kernel 17: Hash160 Benchmark
// =============================================================================

kernel void hash160_bench(
    device const uchar *inputs         [[buffer(0)]],   // N × 33 bytes (compressed pubkeys)
    device uchar *outputs              [[buffer(1)]],   // N × 20 bytes
    constant uint &count               [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;

    uchar pk[33];
    for (int i = 0; i < 33; i++) pk[i] = inputs[tid * 33 + i];

    uchar h160[20];
    hash160_pubkey(pk, 33, h160);

    for (int i = 0; i < 20; i++) outputs[tid * 20 + i] = h160[i];
}

// =============================================================================
// Kernel 18: ECDSA Sign Benchmark (sign + verify round-trip)
// =============================================================================

kernel void ecdsa_bench(
    device const uchar *msg_hashes     [[buffer(0)]],
    device const uchar *privkeys       [[buffer(1)]],
    device uint *results               [[buffer(2)]],
    constant uint &count               [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;

    Scalar256 msg, sec;
    for (int i = 0; i < 8; i++) {
        uint idx = tid * 32 + i * 4;
        msg.limbs[7 - i] = ((uint)msg_hashes[idx] << 24) |
                            ((uint)msg_hashes[idx+1] << 16) |
                            ((uint)msg_hashes[idx+2] << 8) |
                            ((uint)msg_hashes[idx+3]);
        sec.limbs[7 - i] = ((uint)privkeys[idx] << 24) |
                            ((uint)privkeys[idx+1] << 16) |
                            ((uint)privkeys[idx+2] << 8) |
                            ((uint)privkeys[idx+3]);
    }

    // Sign
    Scalar256 r_sig, s_sig;
    ecdsa_sign(msg, sec, r_sig, s_sig);

    // Derive public key
    AffinePoint gen = generator_affine();
    JacobianPoint pub_jac = scalar_mul(gen, sec);
    AffinePoint pub_aff = jacobian_to_affine(pub_jac);

    // Verify
    results[tid] = ecdsa_verify(msg, pub_aff, r_sig, s_sig) ? 1u : 0u;
}

// =============================================================================
// Kernel 19: ZK Knowledge Proof -- Batch Prove
// =============================================================================

kernel void zk_knowledge_prove_batch(
    device const uchar *secrets        [[buffer(0)]],
    device const uchar *pubkeys        [[buffer(1)]],
    device const uchar *messages       [[buffer(2)]],
    device const uchar *aux_rands      [[buffer(3)]],
    device uchar *proof_rx_out         [[buffer(4)]],
    device uchar *proof_s_out          [[buffer(5)]],
    device uint *results               [[buffer(6)]],
    constant uint &count               [[buffer(7)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;

    Scalar256 sec = scalar_from_bytes(secrets + tid * 32);
    JacobianPoint pk = scalar_mul_generator_windowed(sec);

    uchar msg[32], aux[32];
    for (int i = 0; i < 32; ++i) { msg[i] = messages[tid * 32 + i]; aux[i] = aux_rands[tid * 32 + i]; }

    AffinePoint G = generator_affine();
    ZKKnowledgeProof proof;
    bool ok = zk_knowledge_prove(sec, pk, G, msg, aux, proof);

    for (int i = 0; i < 32; ++i) proof_rx_out[tid * 32 + i] = proof.rx[i];
    uchar s_bytes[32];
    scalar_to_bytes(proof.s, s_bytes);
    for (int i = 0; i < 32; ++i) proof_s_out[tid * 32 + i] = s_bytes[i];
    results[tid] = ok ? 1u : 0u;
}

// =============================================================================
// Kernel 20: ZK Knowledge Proof -- Batch Verify
// =============================================================================

kernel void zk_knowledge_verify_batch(
    device const uchar *proof_rx_in    [[buffer(0)]],
    device const uchar *proof_s_in     [[buffer(1)]],
    device const uchar *pubkeys        [[buffer(2)]],
    device const uchar *messages       [[buffer(3)]],
    device uint *results               [[buffer(4)]],
    constant uint &count               [[buffer(5)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;

    ZKKnowledgeProof proof;
    for (int i = 0; i < 32; ++i) proof.rx[i] = proof_rx_in[tid * 32 + i];
    uchar s_bytes[32];
    for (int i = 0; i < 32; ++i) s_bytes[i] = proof_s_in[tid * 32 + i];
    proof.s = scalar_from_bytes(s_bytes);

    Scalar256 pk_scalar = scalar_from_bytes(pubkeys + tid * 32);
    JacobianPoint pk = scalar_mul_generator_windowed(pk_scalar);

    uchar msg[32];
    for (int i = 0; i < 32; ++i) msg[i] = messages[tid * 32 + i];

    AffinePoint G = generator_affine();
    results[tid] = zk_knowledge_verify(proof, pk, G, msg) ? 1u : 0u;
}

// =============================================================================
// Kernel 21: ZK DLEQ Proof -- Batch Prove
// =============================================================================

kernel void zk_dleq_prove_batch(
    device const uchar *secrets        [[buffer(0)]],
    device const uchar *aux_rands      [[buffer(1)]],
    device uchar *proof_e_out          [[buffer(2)]],
    device uchar *proof_s_out          [[buffer(3)]],
    device uint *results               [[buffer(4)]],
    constant uint &count               [[buffer(5)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;

    Scalar256 sec = scalar_from_bytes(secrets + tid * 32);
    uchar aux[32];
    for (int i = 0; i < 32; ++i) aux[i] = aux_rands[tid * 32 + i];

    AffinePoint G = generator_affine();
    // H = second generator (deterministic derivation)
    uchar h_tag[] = {'Z','K','/','d','l','e','q','/','H'};
    uchar h_hash[32];
    tagged_hash(h_tag, 9, h_tag, 9, h_hash);
    JacobianPoint H_jac;
    lift_x(h_hash, H_jac);
    AffinePoint H = jacobian_to_affine(H_jac);

    JacobianPoint P = scalar_mul(G, sec);
    JacobianPoint Q = scalar_mul(H, sec);

    ZKDLEQProof proof;
    bool ok = zk_dleq_prove(sec, G, H, P, Q, aux, proof);

    uchar e_bytes[32], s_bytes[32];
    scalar_to_bytes(proof.e, e_bytes);
    scalar_to_bytes(proof.s, s_bytes);
    for (int i = 0; i < 32; ++i) { proof_e_out[tid * 32 + i] = e_bytes[i]; proof_s_out[tid * 32 + i] = s_bytes[i]; }
    results[tid] = ok ? 1u : 0u;
}

// =============================================================================
// Kernel 22: ZK DLEQ Proof -- Batch Verify
// =============================================================================

kernel void zk_dleq_verify_batch(
    device const uchar *proof_e_in     [[buffer(0)]],
    device const uchar *proof_s_in     [[buffer(1)]],
    device const uchar *pubkeys_P      [[buffer(2)]],
    device const uchar *pubkeys_Q      [[buffer(3)]],
    device uint *results               [[buffer(4)]],
    constant uint &count               [[buffer(5)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;

    ZKDLEQProof proof;
    uchar e_bytes[32], s_bytes[32];
    for (int i = 0; i < 32; ++i) { e_bytes[i] = proof_e_in[tid * 32 + i]; s_bytes[i] = proof_s_in[tid * 32 + i]; }
    proof.e = scalar_from_bytes(e_bytes);
    proof.s = scalar_from_bytes(s_bytes);

    AffinePoint G = generator_affine();
    uchar h_tag[] = {'Z','K','/','d','l','e','q','/','H'};
    uchar h_hash[32];
    tagged_hash(h_tag, 9, h_tag, 9, h_hash);
    JacobianPoint H_jac;
    lift_x(h_hash, H_jac);
    AffinePoint H = jacobian_to_affine(H_jac);

    // Reconstruct P and Q from pubkey bytes
    JacobianPoint P, Q;
    lift_x(pubkeys_P + tid * 32, P);
    lift_x(pubkeys_Q + tid * 32, Q);

    results[tid] = zk_dleq_verify(proof, G, H, P, Q) ? 1u : 0u;
}

// =============================================================================
// Kernel 23: Bulletproof Init (generator computation)
// =============================================================================

kernel void bulletproof_init_kernel(
    device AffinePoint *bp_G           [[buffer(0)]],
    device AffinePoint *bp_H           [[buffer(1)]],
    device ZKTagMidstate *bp_ip_midstate [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid != 0) return;

    // Compute "Bulletproof/ip" midstate
    {
        uchar tag[14] = {'B','u','l','l','e','t','p','r','o','o','f','/','i','p'};
        uchar tag_hash[32];
        SHA256Ctx ctx; sha256_init(ctx);
        sha256_update(ctx, tag, 14);
        sha256_final(ctx, tag_hash);
        sha256_init(ctx);
        sha256_update(ctx, tag_hash, 32);
        sha256_update(ctx, tag_hash, 32);
        for (int i = 0; i < 8; i++) bp_ip_midstate[0].h[i] = ctx.h[i];
    }

    // Compute "Bulletproof/gen" midstate
    ZKTagMidstate gen_midstate;
    {
        uchar tag[15] = {'B','u','l','l','e','t','p','r','o','o','f','/','g','e','n'};
        uchar tag_hash[32];
        SHA256Ctx ctx; sha256_init(ctx);
        sha256_update(ctx, tag, 15);
        sha256_final(ctx, tag_hash);
        sha256_init(ctx);
        sha256_update(ctx, tag_hash, 32);
        sha256_update(ctx, tag_hash, 32);
        for (int i = 0; i < 8; i++) gen_midstate.h[i] = ctx.h[i];
    }

    // Generate 64 G_i and 64 H_i
    for (int i = 0; i < 64; i++) {
        uchar buf[5];
        buf[1] = (uchar)(i & 0xFF);
        buf[2] = (uchar)((i >> 8) & 0xFF);
        buf[3] = (uchar)((i >> 16) & 0xFF);
        buf[4] = (uchar)((i >> 24) & 0xFF);

        uchar hash[32];

        // G_i
        buf[0] = 'G';
        zk_tagged_hash_midstate(gen_midstate, buf, 5, hash);
        FieldElement gx = field_from_bytes(hash);
        bp_G[i] = hash_to_point_increment(gx);

        // H_i
        buf[0] = 'H';
        zk_tagged_hash_midstate(gen_midstate, buf, 5, hash);
        FieldElement hx = field_from_bytes(hash);
        bp_H[i] = hash_to_point_increment(hx);
    }
}

// =============================================================================
// Kernel 24: Bulletproof Batch Verify
// =============================================================================

kernel void bulletproof_verify_batch(
    device const RangeProofGPU *proofs     [[buffer(0)]],
    device const AffinePoint *commitments  [[buffer(1)]],
    device const AffinePoint *H_gen        [[buffer(2)]],
    device const AffinePoint *bp_G         [[buffer(3)]],
    device const AffinePoint *bp_H         [[buffer(4)]],
    device const ZKTagMidstate *bp_ip_midstate [[buffer(5)]],
    device uint *results                   [[buffer(6)]],
    constant uint &count                   [[buffer(7)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;

    RangeProofGPU proof = proofs[tid];
    AffinePoint commit = commitments[tid];
    AffinePoint h_ped = H_gen[0];
    ZKTagMidstate ip_mid = bp_ip_midstate[0];

    results[tid] = range_verify_full(proof, commit, h_ped,
                                      bp_G, bp_H, ip_mid) ? 1u : 0u;
}

// =============================================================================
// Kernel 25: Range Proof Polynomial Check (batch)
// =============================================================================

kernel void range_proof_poly_batch(
    device const RangeProofPolyGPU *proofs   [[buffer(0)]],
    device const AffinePoint *commitments    [[buffer(1)]],
    device const AffinePoint *H_gen          [[buffer(2)]],
    device uint *results                     [[buffer(3)]],
    constant uint &count                     [[buffer(4)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;

    RangeProofPolyGPU proof = proofs[tid];
    AffinePoint commit = commitments[tid];
    AffinePoint h_ped = H_gen[0];

    results[tid] = range_proof_poly_check(proof, commit, h_ped) ? 1u : 0u;
}

// =============================================================================
// Kernel 26: Pedersen Commit Batch
// =============================================================================

kernel void pedersen_commit_batch(
    device const uchar *values_in          [[buffer(0)]],
    device const uchar *blindings_in       [[buffer(1)]],
    device const AffinePoint *H_gen        [[buffer(2)]],
    device uchar *commitments_out          [[buffer(3)]],
    constant uint &count                   [[buffer(4)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= count) return;

    Scalar256 val = scalar_from_bytes(values_in + tid * 32);
    Scalar256 blind = scalar_from_bytes(blindings_in + tid * 32);
    AffinePoint h_ped = H_gen[0];

    JacobianPoint result = pedersen_commit(val, blind, h_ped);

    // Convert Jacobian to affine and output as bytes (x || y, 64 bytes)
    AffinePoint aff = jacobian_to_affine(result);
    field_to_bytes(aff.x, commitments_out + tid * 64);
    field_to_bytes(aff.y, commitments_out + tid * 64 + 32);
}

// =============================================================================
// Kernel 27: Pedersen Verify Sum (homomorphic)
// =============================================================================

kernel void pedersen_verify_sum(
    device const AffinePoint *pos          [[buffer(0)]],
    constant uint &n_pos                   [[buffer(1)]],
    device const AffinePoint *neg          [[buffer(2)]],
    constant uint &n_neg                   [[buffer(3)]],
    device uint *result                    [[buffer(4)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid != 0) return;

    JacobianPoint sum = point_at_infinity();

    for (uint i = 0; i < n_pos; ++i) {
        sum = jacobian_add_mixed(sum, pos[i]);
    }

    for (uint i = 0; i < n_neg; ++i) {
        AffinePoint neg_pt = neg[i];
        neg_pt.y = field_negate(neg_pt.y);
        sum = jacobian_add_mixed(sum, neg_pt);
    }

    // Check if sum is infinity (Z == 0)
    if (sum.infinity) { result[0] = 1u; return; }

    uchar z_bytes[32];
    field_to_bytes(sum.z, z_bytes);
    uint z_zero = 1u;
    for (int i = 0; i < 32; i++)
        if (z_bytes[i] != 0) z_zero = 0u;
    result[0] = z_zero;
}

