// =============================================================================
// UltrafastSecp256k1 OpenCL Kernels - Field Arithmetic
// =============================================================================
// secp256k1 field: F_p where p = 2^256 - 2^32 - 977
// Little-endian 256-bit integers using 4x64-bit limbs
// =============================================================================

// Field prime p = 2^256 - 0x1000003D1
// In 64-bit limbs (little-endian):
// p = {0xFFFFFFFEFFFFFC2F, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}

// Constants
#define SECP256K1_P0 0xFFFFFFFEFFFFFC2FUL
#define SECP256K1_P1 0xFFFFFFFFFFFFFFFFUL
#define SECP256K1_P2 0xFFFFFFFFFFFFFFFFUL
#define SECP256K1_P3 0xFFFFFFFFFFFFFFFFUL

// K = 2^32 + 977 = 0x1000003D1 (for fast reduction)
#define SECP256K1_K 0x1000003D1UL

// =============================================================================
// 64-bit Multiplication Helpers
// =============================================================================

// Multiply two 64-bit numbers, get 128-bit result as (hi, lo)
inline ulong2 mul64_full(ulong a, ulong b) {
    // Use OpenCL's mul_hi for high part
    ulong lo = a * b;
    ulong hi = mul_hi(a, b);
    return (ulong2)(lo, hi);
}

// Add with carry: result = a + b + carry_in, returns new carry
inline ulong add_with_carry(ulong a, ulong b, ulong carry_in, ulong* carry_out) {
    ulong sum = a + b;
    ulong c1 = (sum < a) ? 1UL : 0UL;
    sum += carry_in;
    ulong c2 = (sum < carry_in) ? 1UL : 0UL;
    *carry_out = c1 + c2;
    return sum;
}

// Subtract with borrow: result = a - b - borrow_in, returns new borrow
inline ulong sub_with_borrow(ulong a, ulong b, ulong borrow_in, ulong* borrow_out) {
    ulong diff = a - b;
    ulong b1 = (a < b) ? 1UL : 0UL;
    ulong temp = diff;
    diff -= borrow_in;
    ulong b2 = (temp < borrow_in) ? 1UL : 0UL;
    *borrow_out = b1 + b2;
    return diff;
}

// =============================================================================
// Field Element Type (256-bit)
// =============================================================================

typedef struct {
    ulong limbs[4];  // Little-endian: limbs[0] is LSB
} FieldElement;

// =============================================================================
// Field Reduction: r = a mod p
// Uses the fact that p = 2^256 - K where K = 0x1000003D1
// So 2^256 ≡ K (mod p), meaning we can reduce by replacing high bits with K*high
// =============================================================================

inline void field_reduce(FieldElement* r, const ulong* a8) {
    // a8 is 512-bit number (8 limbs), reduce to 256-bit mod p
    // Since p = 2^256 - K, we have: a mod p = a_low + K * a_high (mod p)

    ulong carry = 0;
    ulong temp[5];

    // First reduction: fold a[4..7] into a[0..3] using K
    // temp = a[0..3] + K * a[4..7]

    // Process each high limb
    ulong2 prod;

    // limb 0: a[0] + K * a[4]
    prod = mul64_full(SECP256K1_K, a8[4]);
    temp[0] = a8[0] + prod.x;
    carry = (temp[0] < a8[0]) ? 1UL : 0UL;
    carry += prod.y;

    // limb 1: a[1] + K * a[5] + carry
    prod = mul64_full(SECP256K1_K, a8[5]);
    temp[1] = a8[1] + carry;
    ulong c1 = (temp[1] < carry) ? 1UL : 0UL;
    temp[1] += prod.x;
    c1 += (temp[1] < prod.x) ? 1UL : 0UL;
    carry = c1 + prod.y;

    // limb 2: a[2] + K * a[6] + carry
    prod = mul64_full(SECP256K1_K, a8[6]);
    temp[2] = a8[2] + carry;
    c1 = (temp[2] < carry) ? 1UL : 0UL;
    temp[2] += prod.x;
    c1 += (temp[2] < prod.x) ? 1UL : 0UL;
    carry = c1 + prod.y;

    // limb 3: a[3] + K * a[7] + carry
    prod = mul64_full(SECP256K1_K, a8[7]);
    temp[3] = a8[3] + carry;
    c1 = (temp[3] < carry) ? 1UL : 0UL;
    temp[3] += prod.x;
    c1 += (temp[3] < prod.x) ? 1UL : 0UL;
    temp[4] = c1 + prod.y;

    // Second reduction: if temp[4] > 0, fold it in
    if (temp[4] != 0) {
        prod = mul64_full(SECP256K1_K, temp[4]);
        temp[0] += prod.x;
        carry = (temp[0] < prod.x) ? 1UL : 0UL;
        carry += prod.y;

        temp[1] += carry;
        carry = (temp[1] < carry) ? 1UL : 0UL;

        temp[2] += carry;
        carry = (temp[2] < carry) ? 1UL : 0UL;

        temp[3] += carry;
        // At this point result fits in 256 bits (plus possible 1-bit overflow)
    }

    // Final reduction: if result >= p, subtract p
    // Check if result >= p by comparing limbs
    ulong borrow = 0;
    ulong diff[4];

    diff[0] = sub_with_borrow(temp[0], SECP256K1_P0, 0, &borrow);
    diff[1] = sub_with_borrow(temp[1], SECP256K1_P1, borrow, &borrow);
    diff[2] = sub_with_borrow(temp[2], SECP256K1_P2, borrow, &borrow);
    diff[3] = sub_with_borrow(temp[3], SECP256K1_P3, borrow, &borrow);

    // If no borrow, result >= p, use subtracted value
    // Otherwise, use original value
    // Branchless selection
    ulong mask = (borrow == 0) ? ~0UL : 0UL;

    r->limbs[0] = (diff[0] & mask) | (temp[0] & ~mask);
    r->limbs[1] = (diff[1] & mask) | (temp[1] & ~mask);
    r->limbs[2] = (diff[2] & mask) | (temp[2] & ~mask);
    r->limbs[3] = (diff[3] & mask) | (temp[3] & ~mask);
}

// =============================================================================
// Field Addition: r = (a + b) mod p
// =============================================================================

inline void field_add_impl(FieldElement* r, const FieldElement* a, const FieldElement* b) {
    ulong carry = 0;
    ulong sum[4];

    // Add with carry chain
    sum[0] = add_with_carry(a->limbs[0], b->limbs[0], 0, &carry);
    sum[1] = add_with_carry(a->limbs[1], b->limbs[1], carry, &carry);
    sum[2] = add_with_carry(a->limbs[2], b->limbs[2], carry, &carry);
    sum[3] = add_with_carry(a->limbs[3], b->limbs[3], carry, &carry);

    // Reduce: if carry or sum >= p, subtract p
    ulong borrow = 0;
    ulong diff[4];

    diff[0] = sub_with_borrow(sum[0], SECP256K1_P0, 0, &borrow);
    diff[1] = sub_with_borrow(sum[1], SECP256K1_P1, borrow, &borrow);
    diff[2] = sub_with_borrow(sum[2], SECP256K1_P2, borrow, &borrow);
    diff[3] = sub_with_borrow(sum[3], SECP256K1_P3, borrow, &borrow);

    // If carry from addition or no borrow from subtraction, use diff
    ulong use_diff = (carry != 0) | (borrow == 0);
    ulong mask = use_diff ? ~0UL : 0UL;

    r->limbs[0] = (diff[0] & mask) | (sum[0] & ~mask);
    r->limbs[1] = (diff[1] & mask) | (sum[1] & ~mask);
    r->limbs[2] = (diff[2] & mask) | (sum[2] & ~mask);
    r->limbs[3] = (diff[3] & mask) | (sum[3] & ~mask);
}

// =============================================================================
// Field Subtraction: r = (a - b) mod p
// =============================================================================

inline void field_sub_impl(FieldElement* r, const FieldElement* a, const FieldElement* b) {
    ulong borrow = 0;
    ulong diff[4];

    // Subtract with borrow chain
    diff[0] = sub_with_borrow(a->limbs[0], b->limbs[0], 0, &borrow);
    diff[1] = sub_with_borrow(a->limbs[1], b->limbs[1], borrow, &borrow);
    diff[2] = sub_with_borrow(a->limbs[2], b->limbs[2], borrow, &borrow);
    diff[3] = sub_with_borrow(a->limbs[3], b->limbs[3], borrow, &borrow);

    // If borrow, add p (result was negative)
    ulong mask = borrow ? ~0UL : 0UL;

    ulong carry = 0;
    ulong adj[4];
    adj[0] = add_with_carry(diff[0], SECP256K1_P0 & mask, 0, &carry);
    adj[1] = add_with_carry(diff[1], SECP256K1_P1 & mask, carry, &carry);
    adj[2] = add_with_carry(diff[2], SECP256K1_P2 & mask, carry, &carry);
    adj[3] = add_with_carry(diff[3], SECP256K1_P3 & mask, carry, &carry);

    r->limbs[0] = adj[0];
    r->limbs[1] = adj[1];
    r->limbs[2] = adj[2];
    r->limbs[3] = adj[3];
}

// =============================================================================
// Field Multiplication: r = (a * b) mod p
// =============================================================================

// Helper: add 128-bit product (hi:lo) into 3-register accumulator (c2:c1:c0)
inline void muladd(ulong lo, ulong hi, ulong* c0, ulong* c1, ulong* c2) {
    ulong carry;
    *c0 = add_with_carry(*c0, lo, 0, &carry);
    *c1 = add_with_carry(*c1, hi, carry, &carry);
    *c2 += carry;
}

// Helper: add 128-bit product (hi:lo) doubled into accumulator
inline void muladd2(ulong lo, ulong hi, ulong* c0, ulong* c1, ulong* c2) {
    muladd(lo, hi, c0, c1, c2);
    muladd(lo, hi, c0, c1, c2);
}

inline void field_mul_impl(FieldElement* r, const FieldElement* a, const FieldElement* b) {
    ulong a0 = a->limbs[0], a1 = a->limbs[1], a2 = a->limbs[2], a3 = a->limbs[3];
    ulong b0 = b->limbs[0], b1 = b->limbs[1], b2 = b->limbs[2], b3 = b->limbs[3];
    ulong product[8];
    ulong c0, c1, c2;
    ulong2 m;

    // Column 0: a0*b0
    c0 = 0; c1 = 0; c2 = 0;
    m = mul64_full(a0, b0); muladd(m.x, m.y, &c0, &c1, &c2);
    product[0] = c0; c0 = c1; c1 = c2; c2 = 0;

    // Column 1: a0*b1 + a1*b0
    m = mul64_full(a0, b1); muladd(m.x, m.y, &c0, &c1, &c2);
    m = mul64_full(a1, b0); muladd(m.x, m.y, &c0, &c1, &c2);
    product[1] = c0; c0 = c1; c1 = c2; c2 = 0;

    // Column 2: a0*b2 + a1*b1 + a2*b0
    m = mul64_full(a0, b2); muladd(m.x, m.y, &c0, &c1, &c2);
    m = mul64_full(a1, b1); muladd(m.x, m.y, &c0, &c1, &c2);
    m = mul64_full(a2, b0); muladd(m.x, m.y, &c0, &c1, &c2);
    product[2] = c0; c0 = c1; c1 = c2; c2 = 0;

    // Column 3: a0*b3 + a1*b2 + a2*b1 + a3*b0
    m = mul64_full(a0, b3); muladd(m.x, m.y, &c0, &c1, &c2);
    m = mul64_full(a1, b2); muladd(m.x, m.y, &c0, &c1, &c2);
    m = mul64_full(a2, b1); muladd(m.x, m.y, &c0, &c1, &c2);
    m = mul64_full(a3, b0); muladd(m.x, m.y, &c0, &c1, &c2);
    product[3] = c0; c0 = c1; c1 = c2; c2 = 0;

    // Column 4: a1*b3 + a2*b2 + a3*b1
    m = mul64_full(a1, b3); muladd(m.x, m.y, &c0, &c1, &c2);
    m = mul64_full(a2, b2); muladd(m.x, m.y, &c0, &c1, &c2);
    m = mul64_full(a3, b1); muladd(m.x, m.y, &c0, &c1, &c2);
    product[4] = c0; c0 = c1; c1 = c2; c2 = 0;

    // Column 5: a2*b3 + a3*b2
    m = mul64_full(a2, b3); muladd(m.x, m.y, &c0, &c1, &c2);
    m = mul64_full(a3, b2); muladd(m.x, m.y, &c0, &c1, &c2);
    product[5] = c0; c0 = c1; c1 = c2; c2 = 0;

    // Column 6: a3*b3
    m = mul64_full(a3, b3); muladd(m.x, m.y, &c0, &c1, &c2);
    product[6] = c0;
    product[7] = c1;

    field_reduce(r, product);
}

// =============================================================================
// Field Squaring: r = a² mod p
// Optimized: only need upper triangle of multiplication
// =============================================================================

// Forward declaration for field_sqr_n_impl
inline void field_sqr_impl(FieldElement* r, const FieldElement* a);

// Repeated squaring helper: r = r^(2^n) — in-place
inline void field_sqr_n_impl(FieldElement* r, int n) {
    for (int i = 0; i < n; i++) {
        FieldElement tmp = *r;
        field_sqr_impl(r, &tmp);
    }
}

inline void field_sqr_impl(FieldElement* r, const FieldElement* a) {
    ulong a0 = a->limbs[0], a1 = a->limbs[1], a2 = a->limbs[2], a3 = a->limbs[3];
    ulong product[8];
    ulong c0, c1, c2;
    ulong2 m;

    // Column 0: a0*a0
    c0 = 0; c1 = 0; c2 = 0;
    m = mul64_full(a0, a0); muladd(m.x, m.y, &c0, &c1, &c2);
    product[0] = c0; c0 = c1; c1 = c2; c2 = 0;

    // Column 1: 2*a0*a1
    m = mul64_full(a0, a1); muladd2(m.x, m.y, &c0, &c1, &c2);
    product[1] = c0; c0 = c1; c1 = c2; c2 = 0;

    // Column 2: 2*a0*a2 + a1*a1
    m = mul64_full(a0, a2); muladd2(m.x, m.y, &c0, &c1, &c2);
    m = mul64_full(a1, a1); muladd(m.x, m.y, &c0, &c1, &c2);
    product[2] = c0; c0 = c1; c1 = c2; c2 = 0;

    // Column 3: 2*a0*a3 + 2*a1*a2
    m = mul64_full(a0, a3); muladd2(m.x, m.y, &c0, &c1, &c2);
    m = mul64_full(a1, a2); muladd2(m.x, m.y, &c0, &c1, &c2);
    product[3] = c0; c0 = c1; c1 = c2; c2 = 0;

    // Column 4: 2*a1*a3 + a2*a2
    m = mul64_full(a1, a3); muladd2(m.x, m.y, &c0, &c1, &c2);
    m = mul64_full(a2, a2); muladd(m.x, m.y, &c0, &c1, &c2);
    product[4] = c0; c0 = c1; c1 = c2; c2 = 0;

    // Column 5: 2*a2*a3
    m = mul64_full(a2, a3); muladd2(m.x, m.y, &c0, &c1, &c2);
    product[5] = c0; c0 = c1; c1 = c2; c2 = 0;

    // Column 6: a3*a3
    m = mul64_full(a3, a3); muladd(m.x, m.y, &c0, &c1, &c2);
    product[6] = c0;
    product[7] = c1;

    field_reduce(r, product);
}

// =============================================================================
// Field Negation: r = -a mod p = p - a
// =============================================================================

inline void field_neg_impl(FieldElement* r, const FieldElement* a) {
    // Check if a is zero
    ulong is_zero = ((a->limbs[0] | a->limbs[1] | a->limbs[2] | a->limbs[3]) == 0) ? 1UL : 0UL;

    ulong borrow = 0;
    r->limbs[0] = sub_with_borrow(SECP256K1_P0, a->limbs[0], 0, &borrow);
    r->limbs[1] = sub_with_borrow(SECP256K1_P1, a->limbs[1], borrow, &borrow);
    r->limbs[2] = sub_with_borrow(SECP256K1_P2, a->limbs[2], borrow, &borrow);
    r->limbs[3] = sub_with_borrow(SECP256K1_P3, a->limbs[3], borrow, &borrow);

    // If a was zero, result should be zero
    ulong mask = is_zero ? 0UL : ~0UL;
    r->limbs[0] &= mask;
    r->limbs[1] &= mask;
    r->limbs[2] &= mask;
    r->limbs[3] &= mask;
}

// =============================================================================
// Field Inversion: r = a^(-1) mod p
// Using Fermat's little theorem with optimized addition chain
// Matches CUDA's field_inv_fermat_chain for minimal mul+sqr count
// p-2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
// =============================================================================

inline void field_inv_impl(FieldElement* r, const FieldElement* a) {
    FieldElement x2, x3, x6, x12, x24, x48, x96, x192, x7, x31, x223;
    FieldElement x5, x11, x22;
    FieldElement t;

    // 1. x2 = a^2 * a  (2 consecutive ones)
    field_sqr_impl(&x2, a);
    field_mul_impl(&x2, &x2, a);

    // 2. x3 = x2^2 * a  (3 consecutive ones)
    field_sqr_impl(&x3, &x2);
    field_mul_impl(&x3, &x3, a);

    // 3. x6 = x3^(2^3) * x3  (6 consecutive ones)
    field_sqr_impl(&x6, &x3);
    field_sqr_n_impl(&x6, 2);
    field_mul_impl(&x6, &x6, &x3);

    // 4. x12 = x6^(2^6) * x6  (12 consecutive ones)
    t = x6;
    field_sqr_n_impl(&t, 6);
    field_mul_impl(&x12, &t, &x6);

    // 5. x24 = x12^(2^12) * x12  (24 consecutive ones)
    t = x12;
    field_sqr_n_impl(&t, 12);
    field_mul_impl(&x24, &t, &x12);

    // 6. x48 = x24^(2^24) * x24  (48 consecutive ones)
    t = x24;
    field_sqr_n_impl(&t, 24);
    field_mul_impl(&x48, &t, &x24);

    // 7. x96 = x48^(2^48) * x48  (96 consecutive ones)
    t = x48;
    field_sqr_n_impl(&t, 48);
    field_mul_impl(&x96, &t, &x48);

    // 8. x192 = x96^(2^96) * x96  (192 consecutive ones)
    t = x96;
    field_sqr_n_impl(&t, 96);
    field_mul_impl(&x192, &t, &x96);

    // 9. x7 = x6^2 * a  (7 consecutive ones)
    field_sqr_impl(&x7, &x6);
    field_mul_impl(&x7, &x7, a);

    // 10. x31 = x24^(2^7) * x7  (31 consecutive ones)
    t = x24;
    field_sqr_n_impl(&t, 7);
    field_mul_impl(&x31, &t, &x7);

    // 11. x223 = x192^(2^31) * x31  (223 consecutive ones)
    t = x192;
    field_sqr_n_impl(&t, 31);
    field_mul_impl(&x223, &t, &x31);

    // 12. x5 = x3^(2^2) * x2  (5 consecutive ones)
    t = x3;
    field_sqr_n_impl(&t, 2);
    field_mul_impl(&x5, &t, &x2);

    // 13. x11 = x6^(2^5) * x5  (11 consecutive ones)
    t = x6;
    field_sqr_n_impl(&t, 5);
    field_mul_impl(&x11, &t, &x5);

    // 14. x22 = x11^(2^11) * x11  (22 consecutive ones)
    t = x11;
    field_sqr_n_impl(&t, 11);
    field_mul_impl(&x22, &t, &x11);

    // 15. t = x223^2  (bit 32 is 0)
    field_sqr_impl(&t, &x223);

    // 16. t = t^(2^22) * x22  (append 22 ones)
    field_sqr_n_impl(&t, 22);
    field_mul_impl(&t, &t, &x22);

    // 17. t = t^(2^4)  (bits 9,8,7,6 are 0)
    field_sqr_n_impl(&t, 4);

    // 18. Process remaining 6 bits: 101101
    // bit 5: 1
    field_sqr_impl(&t, &t);
    field_mul_impl(&t, &t, a);
    // bit 4: 0
    field_sqr_impl(&t, &t);
    // bit 3: 1
    field_sqr_impl(&t, &t);
    field_mul_impl(&t, &t, a);
    // bit 2: 1
    field_sqr_impl(&t, &t);
    field_mul_impl(&t, &t, a);
    // bit 1: 0
    field_sqr_impl(&t, &t);
    // bit 0: 1
    field_sqr_impl(&t, &t);
    field_mul_impl(r, &t, a);
}

// =============================================================================
// OpenCL Kernels
// =============================================================================

__kernel void field_add(
    __global const FieldElement* a,
    __global const FieldElement* b,
    __global FieldElement* result,
    const uint count
) {
    uint gid = get_global_id(0);
    if (gid >= count) return;

    // Copy from global to private memory
    FieldElement a_local = a[gid];
    FieldElement b_local = b[gid];
    FieldElement r;
    field_add_impl(&r, &a_local, &b_local);
    result[gid] = r;
}

__kernel void field_sub(
    __global const FieldElement* a,
    __global const FieldElement* b,
    __global FieldElement* result,
    const uint count
) {
    uint gid = get_global_id(0);
    if (gid >= count) return;

    // Copy from global to private memory
    FieldElement a_local = a[gid];
    FieldElement b_local = b[gid];
    FieldElement r;
    field_sub_impl(&r, &a_local, &b_local);
    result[gid] = r;
}

__kernel void field_mul(
    __global const FieldElement* a,
    __global const FieldElement* b,
    __global FieldElement* result,
    const uint count
) {
    uint gid = get_global_id(0);
    if (gid >= count) return;

    // Copy from global to private memory
    FieldElement a_local = a[gid];
    FieldElement b_local = b[gid];
    FieldElement r;
    field_mul_impl(&r, &a_local, &b_local);
    result[gid] = r;
}

__kernel void field_sqr(
    __global const FieldElement* a,
    __global FieldElement* result,
    const uint count
) {
    uint gid = get_global_id(0);
    if (gid >= count) return;

    // Copy from global to private memory
    FieldElement a_local = a[gid];
    FieldElement r;
    field_sqr_impl(&r, &a_local);
    result[gid] = r;
}

__kernel void field_inv(
    __global const FieldElement* a,
    __global FieldElement* result,
    const uint count
) {
    uint gid = get_global_id(0);
    if (gid >= count) return;

    // Copy from global to private memory
    FieldElement a_local = a[gid];
    FieldElement r;
    field_inv_impl(&r, &a_local);
    result[gid] = r;
}

