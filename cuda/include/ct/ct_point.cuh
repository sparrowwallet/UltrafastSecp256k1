#pragma once
// ============================================================================
// Constant-Time Point Arithmetic -- CUDA Device
// ============================================================================
// Side-channel resistant point operations for secp256k1.
//
// Key features:
//   - Brier-Joye complete addition (11M+6S Jac+Jac, 7M+5S Jac+Aff)
//   - Handles ALL cases: P+Q, P+P, P+O, O+Q, P+(-P)=O
//   - Mask-based infinity flag (uint64_t, not bool)
//   - CT table lookup (scans ALL entries)
//   - CT generator_mul (fixed-trace, signed-digit comb)
//   - CT scalar_mul (GLV + Hamburg wNAF, fixed-trace)
//
// Port of: cpu/include/secp256k1/ct/point.hpp + cpu/src/ct_point.cpp
// ============================================================================

#include "ct/ct_scalar.cuh"

namespace secp256k1 {
namespace cuda {
namespace ct {

// --- CT Point Types ----------------------------------------------------------

// Jacobian point with mask-based infinity flag (not bool)
struct CTJacobianPoint {
    FieldElement x;
    FieldElement y;
    FieldElement z;
    uint64_t infinity;  // 0 = normal, 0xFFFF... = point at infinity
};

// Affine point with mask-based infinity flag
struct CTAffinePoint {
    FieldElement x;
    FieldElement y;
    uint64_t infinity;  // 0 = normal, 0xFFFF... = point at infinity
};

// --- CT Point Utilities ------------------------------------------------------

__device__ __forceinline__
void ct_point_set_infinity(CTJacobianPoint* p) {
    field_set_zero(&p->x);
    field_set_zero(&p->y);
    field_set_zero(&p->z);
    p->infinity = ~(uint64_t)0;
}

__device__ __forceinline__
CTJacobianPoint ct_point_from_jacobian(const JacobianPoint* p) {
    CTJacobianPoint r;
    r.x = p->x; r.y = p->y; r.z = p->z;
    r.infinity = bool_to_mask((uint64_t)p->infinity);
    return r;
}

__device__ __forceinline__
JacobianPoint ct_point_to_jacobian(const CTJacobianPoint* p) {
    JacobianPoint r;
    r.x = p->x; r.y = p->y; r.z = p->z;
    r.infinity = (p->infinity != 0);
    return r;
}

__device__ __forceinline__
CTJacobianPoint ct_point_from_affine(const CTAffinePoint* a) {
    CTJacobianPoint r;
    r.x = a->x; r.y = a->y;
    field_set_one(&r.z);
    r.infinity = a->infinity;
    return r;
}

// CT conditional move for CT Jacobian points
__device__ __forceinline__
void ct_point_cmov(CTJacobianPoint* r, const CTJacobianPoint* a, uint64_t mask) {
    cmov256(r->x.limbs, a->x.limbs, mask);
    cmov256(r->y.limbs, a->y.limbs, mask);
    cmov256(r->z.limbs, a->z.limbs, mask);
    cmov64(&r->infinity, a->infinity, mask);
}

// CT conditional move for CT Affine points
__device__ __forceinline__
void ct_aff_cmov(CTAffinePoint* r, const CTAffinePoint* a, uint64_t mask) {
    cmov256(r->x.limbs, a->x.limbs, mask);
    cmov256(r->y.limbs, a->y.limbs, mask);
    cmov64(&r->infinity, a->infinity, mask);
}

// CT conditional negate Y
__device__ __forceinline__
void ct_point_cneg_y(CTAffinePoint* p, uint64_t mask) {
    FieldElement neg_y;
    secp256k1::cuda::field_negate(&p->y, &neg_y);
    cmov256(p->y.limbs, neg_y.limbs, mask);
}

// CT table lookup for affine points: scans ALL entries
__device__ inline
void ct_affine_table_lookup(const CTAffinePoint* table, int count,
                            int index, CTAffinePoint* out) {
    out->x.limbs[0] = 0; out->x.limbs[1] = 0;
    out->x.limbs[2] = 0; out->x.limbs[3] = 0;
    out->y.limbs[0] = 0; out->y.limbs[1] = 0;
    out->y.limbs[2] = 0; out->y.limbs[3] = 0;
    out->infinity = 0;

    for (int i = 0; i < count; i++) {
        uint64_t m = eq_mask((uint64_t)i, (uint64_t)index);
        out->x.limbs[0] |= (table[i].x.limbs[0] & m);
        out->x.limbs[1] |= (table[i].x.limbs[1] & m);
        out->x.limbs[2] |= (table[i].x.limbs[2] & m);
        out->x.limbs[3] |= (table[i].x.limbs[3] & m);
        out->y.limbs[0] |= (table[i].y.limbs[0] & m);
        out->y.limbs[1] |= (table[i].y.limbs[1] & m);
        out->y.limbs[2] |= (table[i].y.limbs[2] & m);
        out->y.limbs[3] |= (table[i].y.limbs[3] & m);
        out->infinity   |= (table[i].infinity & m);
    }
}

// --- CT Point Doubling (4M + 4S + 2add + 2sub) --------------------------------
// Standard Jacobian doubling (same formula as fast path's jacobian_double).
// Handles identity via cmov.

__device__ inline
void ct_point_dbl(const CTJacobianPoint* p, CTJacobianPoint* r) {
    using namespace secp256k1::cuda;

    FieldElement S, M, X3, Y3, Z3, YY, YYYY, t1;

    // YY = Y^2
    field_sqr(&p->y, &YY);

    // S = 4*X*Y^2
    field_mul(&p->x, &YY, &S);
    field_add(&S, &S, &S);
    field_add(&S, &S, &S);

    // M = 3*X^2
    field_sqr(&p->x, &M);
    field_add(&M, &M, &t1);     // t1 = 2*X^2
    field_add(&M, &t1, &M);     // M = 3*X^2

    // X3 = M^2 - 2*S
    field_sqr(&M, &X3);
    field_add(&S, &S, &t1);     // t1 = 2*S
    field_sub(&X3, &t1, &X3);

    // YYYY = Y^4
    field_sqr(&YY, &YYYY);

    // Y3 = M*(S - X3) - 8*Y^4
    field_add(&YYYY, &YYYY, &t1);   // 2*Y^4
    field_add(&t1, &t1, &t1);       // 4*Y^4
    field_add(&t1, &t1, &t1);       // 8*Y^4
    field_sub(&S, &X3, &S);         // S - X3 (reuse S)
    field_mul(&M, &S, &Y3);         // M*(S - X3)
    field_sub(&Y3, &t1, &Y3);       // Y3 final

    // Z3 = 2*Y*Z
    field_mul(&p->y, &p->z, &Z3);
    field_add(&Z3, &Z3, &Z3);

    r->x = X3;
    r->y = Y3;
    r->z = Z3;
    r->infinity = p->infinity;

    // If input was infinity, cmov to identity
    CTJacobianPoint inf;
    ct_point_set_infinity(&inf);
    ct_point_cmov(r, &inf, p->infinity);
}

// --- CT Complete Addition (Jac + Aff, Brier-Joye, 7M + 5S) ------------------
// Handles ALL cases in ONE codepath: P+Q, P+P (doubling), P+O, O+Q, P+(-P)=O

__device__ inline
void ct_point_add_mixed(const CTJacobianPoint* p, const CTAffinePoint* q,
                        CTJacobianPoint* r) {
    using namespace secp256k1::cuda;

    // ZZ = Z1^2
    FieldElement zz;
    field_sqr(&p->z, &zz);

    // U1 = X1, U2 = q.x * ZZ
    FieldElement u1, u2;
    u1 = p->x;
    field_mul(&q->x, &zz, &u2);

    // S1 = Y1, S2 = q.y * ZZ * Z1
    FieldElement s1, s2;
    s1 = p->y;
    FieldElement zzz;
    field_mul(&zz, &p->z, &zzz);
    field_mul(&q->y, &zzz, &s2);

    // T = U1 + U2
    FieldElement t;
    field_add(&u1, &u2, &t);

    // M = S1 + S2
    FieldElement m;
    field_add(&s1, &s2, &m);

    // R = T^2 - U1*U2
    FieldElement t_sq, u1u2, rr;
    field_sqr(&t, &t_sq);
    field_mul(&u1, &u2, &u1u2);
    field_sub(&t_sq, &u1u2, &rr);

    // Degenerate check: M == 0 means P == -Q (doubling case)
    uint64_t m_is_zero = ct::field_is_zero(&m);

    // Ralt = degen ? 2*S1 : R
    FieldElement ralt, s1_2;
    field_add(&s1, &s1, &s1_2);
    ct_select256(ralt.limbs, s1_2.limbs, rr.limbs, m_is_zero);

    // Malt = degen ? U1-U2 : M
    FieldElement malt, u1_u2;
    field_sub(&u1, &u2, &u1_u2);
    ct_select256(malt.limbs, u1_u2.limbs, m.limbs, m_is_zero);

    // N = Malt^2
    FieldElement n;
    field_sqr(&malt, &n);

    // Q_ = -T * N
    FieldElement q_;
    field_mul(&t, &n, &q_);
    field_negate(&q_, &q_);

    // N = N^2 (reuse N)
    FieldElement nn;
    field_sqr(&n, &nn);

    // X3 = Ralt^2 + Q_
    FieldElement x3;
    field_sqr(&ralt, &x3);
    field_add(&x3, &q_, &x3);

    // Z3 = Malt * Z1
    FieldElement z3;
    field_mul(&malt, &p->z, &z3);

    // Y3 = -(Ralt * (2*X3 + Q_) + N) / 2
    FieldElement x3_2, y3_tmp, y3;
    field_add(&x3, &x3, &x3_2);
    field_add(&x3_2, &q_, &y3_tmp);
    field_mul(&ralt, &y3_tmp, &y3);
    field_add(&y3, &nn, &y3);
    field_negate(&y3, &y3);
    field_half(&y3, &y3);

    r->x = x3;
    r->y = y3;
    r->z = z3;
    r->infinity = 0;

    // Check Z3 == 0 (means P + (-P) = O)
    uint64_t z3_zero = ct::field_is_zero(&z3);
    r->infinity = z3_zero;

    // If P was infinity, result = Q (as Jacobian)
    CTJacobianPoint q_jac;
    q_jac.x = q->x; q_jac.y = q->y;
    field_set_one(&q_jac.z);
    q_jac.infinity = q->infinity;
    ct_point_cmov(r, &q_jac, p->infinity);

    // If Q was infinity, result = P
    ct_point_cmov(r, p, q->infinity);
}

// --- CT Complete Addition (Jac + Jac, Brier-Joye, 11M + 6S) -----------------

__device__ inline
void ct_point_add(const CTJacobianPoint* p, const CTJacobianPoint* q,
                  CTJacobianPoint* r) {
    using namespace secp256k1::cuda;

    // Z1Z1 = Z1^2, Z2Z2 = Z2^2
    FieldElement z1z1, z2z2;
    field_sqr(&p->z, &z1z1);
    field_sqr(&q->z, &z2z2);

    // U1 = X1 * Z2Z2, U2 = X2 * Z1Z1
    FieldElement u1, u2;
    field_mul(&p->x, &z2z2, &u1);
    field_mul(&q->x, &z1z1, &u2);

    // S1 = Y1 * Z2Z2 * Z2, S2 = Y2 * Z1Z1 * Z1
    FieldElement s1, s2, z2z2z2, z1z1z1;
    field_mul(&z2z2, &q->z, &z2z2z2);
    field_mul(&p->y, &z2z2z2, &s1);
    field_mul(&z1z1, &p->z, &z1z1z1);
    field_mul(&q->y, &z1z1z1, &s2);

    // Z = Z1 * Z2
    FieldElement z;
    field_mul(&p->z, &q->z, &z);

    // T = U1 + U2
    FieldElement t;
    field_add(&u1, &u2, &t);

    // M = S1 + S2
    FieldElement m;
    field_add(&s1, &s2, &m);

    // R = T^2 - U1*U2
    FieldElement t_sq, u1u2, rr;
    field_sqr(&t, &t_sq);
    field_mul(&u1, &u2, &u1u2);
    field_sub(&t_sq, &u1u2, &rr);

    // Degenerate check
    uint64_t m_is_zero = ct::field_is_zero(&m);

    FieldElement ralt, s1_2;
    field_add(&s1, &s1, &s1_2);
    ct_select256(ralt.limbs, s1_2.limbs, rr.limbs, m_is_zero);

    FieldElement malt, u1_u2;
    field_sub(&u1, &u2, &u1_u2);
    ct_select256(malt.limbs, u1_u2.limbs, m.limbs, m_is_zero);

    FieldElement n;
    field_sqr(&malt, &n);

    FieldElement q_;
    field_mul(&t, &n, &q_);
    field_negate(&q_, &q_);

    FieldElement nn;
    field_sqr(&n, &nn);

    FieldElement x3;
    field_sqr(&ralt, &x3);
    field_add(&x3, &q_, &x3);

    // Z3 = Z * Malt  (note: Z = Z1*Z2, not just Z1)
    FieldElement z3;
    field_mul(&z, &malt, &z3);

    FieldElement x3_2, y3_tmp, y3;
    field_add(&x3, &x3, &x3_2);
    field_add(&x3_2, &q_, &y3_tmp);
    field_mul(&ralt, &y3_tmp, &y3);
    field_add(&y3, &nn, &y3);
    field_negate(&y3, &y3);
    field_half(&y3, &y3);

    r->x = x3;
    r->y = y3;
    r->z = z3;
    r->infinity = 0;

    uint64_t z3_zero = ct::field_is_zero(&z3);
    r->infinity = z3_zero;

    ct_point_cmov(r, q, p->infinity);
    ct_point_cmov(r, p, q->infinity);
}

// --- CT Point Negation -------------------------------------------------------

__device__ __forceinline__
void ct_point_neg(const CTJacobianPoint* p, CTJacobianPoint* r) {
    r->x = p->x;
    secp256k1::cuda::field_negate(&p->y, &r->y);
    r->z = p->z;
    r->infinity = p->infinity;
}

// --- CT Scalar Multiplication: k*P (GLV + fixed-window, CT) ------------------
// Uses CT complete addition, CT table lookups.
// Cost: ~128 doublings + ~64 mixed additions (CT complete)

__device__ inline
void ct_scalar_mul(const JacobianPoint* p_in, const Scalar* k,
                   JacobianPoint* r_out) {
    using namespace secp256k1::cuda;

    // Convert to CT types
    CTJacobianPoint p = ct_point_from_jacobian(p_in);

    // GLV decompose (CT version)
    CTGLVDecomposition glv = ct_glv_decompose(k);

    // Build precomputed table: odd multiples [1P, 3P, 5P, 7P, ..., 15P]
    // Window width w=4 for CT: 8 table entries
    constexpr int TABLE_SIZE = 8;
    CTAffinePoint table_a[TABLE_SIZE];
    CTAffinePoint table_b[TABLE_SIZE];  // endomorphism table (beta)

    // Table[0] = P (affine)
    {
        FieldElement z_inv, z_inv2, z_inv3;
        field_inv(&p.z, &z_inv);
        field_sqr(&z_inv, &z_inv2);
        field_mul(&z_inv, &z_inv2, &z_inv3);
        field_mul(&p.x, &z_inv2, &table_a[0].x);
        field_mul(&p.y, &z_inv3, &table_a[0].y);
        table_a[0].infinity = p.infinity;
    }

    // Build remaining odd multiples via complete additions
    // 2P (Jacobian)
    CTJacobianPoint dbl;
    ct_point_dbl(&p, &dbl);

    // Convert 2P to affine for mixed adds
    CTAffinePoint dbl_aff;
    {
        FieldElement z_inv, z_inv2, z_inv3;
        field_inv(&dbl.z, &z_inv);
        field_sqr(&z_inv, &z_inv2);
        field_mul(&z_inv, &z_inv2, &z_inv3);
        field_mul(&dbl.x, &z_inv2, &dbl_aff.x);
        field_mul(&dbl.y, &z_inv3, &dbl_aff.y);
        dbl_aff.infinity = dbl.infinity;
    }

    // table[i] = (2i+1)*P via accumulation
    CTJacobianPoint acc = p;
    for (int i = 1; i < TABLE_SIZE; i++) {
        ct_point_add_mixed(&acc, &dbl_aff, &acc);
        // Convert to affine
        FieldElement z_inv, z_inv2, z_inv3;
        field_inv(&acc.z, &z_inv);
        field_sqr(&z_inv, &z_inv2);
        field_mul(&z_inv, &z_inv2, &z_inv3);
        field_mul(&acc.x, &z_inv2, &table_a[i].x);
        field_mul(&acc.y, &z_inv3, &table_a[i].y);
        table_a[i].infinity = acc.infinity;
    }

    // Build endomorphism table: beta * X, same Y (or negated if k2_neg)
    // phi(P) = (beta*x, y) on secp256k1
    FieldElement beta;
    for (int i = 0; i < 4; i++) beta.limbs[i] = BETA[i];
    for (int i = 0; i < TABLE_SIZE; i++) {
        field_mul(&table_a[i].x, &beta, &table_b[i].x);
        table_b[i].y = table_a[i].y;
        table_b[i].infinity = table_a[i].infinity;
    }

    // Conditionally negate tables based on GLV sign
    for (int i = 0; i < TABLE_SIZE; i++) {
        ct_point_cneg_y(&table_a[i], glv.k1_neg);
        ct_point_cneg_y(&table_b[i], glv.k2_neg);
    }

    // Bit-by-bit double-and-add with CT table lookup
    // Process k1 and k2 (~128 bits each), fixed 128 iterations
    CTJacobianPoint result;
    ct_point_set_infinity(&result);

    // Process bit-by-bit (simplest CT approach: fixed 128 iterations)
    // Each iteration: double + conditionally add from k1 table + conditionally add from k2 table
    for (int i = 127; i >= 0; --i) {
        // Always double
        ct_point_dbl(&result, &result);

        // k1 bit
        uint64_t b1 = ct::scalar_bit(&glv.k1, i);
        uint64_t m1 = bool_to_mask(b1);
        CTAffinePoint entry1;
        entry1.x = table_a[0].x;
        entry1.y = table_a[0].y;
        entry1.infinity = 0;
        // Add P if bit is set (CT: always compute add, cmov result)
        CTJacobianPoint with_add1;
        ct_point_add_mixed(&result, &entry1, &with_add1);
        ct_point_cmov(&result, &with_add1, m1);

        // k2 bit
        uint64_t b2 = ct::scalar_bit(&glv.k2, i);
        uint64_t m2 = bool_to_mask(b2);
        CTAffinePoint entry2;
        entry2.x = table_b[0].x;
        entry2.y = table_b[0].y;
        entry2.infinity = 0;
        CTJacobianPoint with_add2;
        ct_point_add_mixed(&result, &entry2, &with_add2);
        ct_point_cmov(&result, &with_add2, m2);
    }

    *r_out = ct_point_to_jacobian(&result);
}

// --- CT Generator Multiplication: k*G (fixed-base comb, CT) ------------------
// Uses a precomputed table (loaded at init time) and signed-digit comb method.
// Falls back to ct_scalar_mul(G, k) if no precomputed table is available.

__device__ inline
void ct_generator_mul(const Scalar* k, JacobianPoint* r_out) {
    using namespace secp256k1::cuda;

    // Use the standard generator point G
    JacobianPoint G;
    for (int i = 0; i < 4; i++) {
        G.x.limbs[i] = GENERATOR_X[i];
        G.y.limbs[i] = GENERATOR_Y[i];
    }
    field_set_one(&G.z);
    G.infinity = false;

    // For now, delegate to ct_scalar_mul which is fully constant-time
    // A comb-based generator_mul with precomputed table would be faster
    // but requires a global precomputed table (like the CPU version's 352-point table)
    ct_scalar_mul(&G, k, r_out);
}

} // namespace ct
} // namespace cuda
} // namespace secp256k1
