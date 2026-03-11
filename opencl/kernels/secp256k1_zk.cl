// =============================================================================
// UltrafastSecp256k1 OpenCL -- Zero-Knowledge Proof Kernels
// =============================================================================
// ZK proof primitives for OpenCL:
//   1. Knowledge proof (Schnorr sigma protocol) -- prove + verify
//   2. DLEQ proof (discrete log equality) -- prove + verify
//
// Depends on: secp256k1_extended.cl (which includes field, point, scalar, SHA-256)
// Uses 4x64-bit limbs (ulong) -- matching existing OpenCL convention.
// =============================================================================

#include "secp256k1_extended.cl"

// =============================================================================
// ZK Proof Structures
// =============================================================================

typedef struct {
    uchar rx[32];  // R.x (x-coordinate of nonce point, even Y)
    Scalar s;       // response scalar
} ZKKnowledgeProof;

typedef struct {
    Scalar e;  // challenge
    Scalar s;  // response
} ZKDLEQProof;

// =============================================================================
// Helper: Jacobian to Affine (inline)
// =============================================================================

inline void jacobian_to_affine_impl(const JacobianPoint* p,
                                     FieldElement* ax, FieldElement* ay) {
    FieldElement z_inv, z_inv2, z_inv3;
    field_inv_impl(&z_inv, &p->z);
    field_sqr_impl(&z_inv2, &z_inv);
    field_mul_impl(&z_inv3, &z_inv2, &z_inv);
    field_mul_impl(ax, &p->x, &z_inv2);
    field_mul_impl(ay, &p->y, &z_inv3);
}

// =============================================================================
// Helper: Point to Compressed (33 bytes: prefix || x)
// =============================================================================

inline void point_to_compressed_impl(const JacobianPoint* p,
                                      uchar out[33]) {
    if (point_is_infinity(p)) {
        for (int i = 0; i < 33; ++i) out[i] = 0;
        return;
    }
    FieldElement ax, ay;
    jacobian_to_affine_impl(p, &ax, &ay);

    uchar y_bytes[32];
    field_to_bytes_impl(&ay, y_bytes);
    out[0] = (y_bytes[31] & 1) ? 0x03 : 0x02;
    field_to_bytes_impl(&ax, out + 1);
}

// =============================================================================
// ZK Tagged Hash
// =============================================================================

inline void zk_tagged_hash_impl(const uchar* tag, uint tag_len,
                                 const uchar* data, uint data_len,
                                 uchar out[32]) {
    tagged_hash_impl(tag, tag_len, data, data_len, out);
}

// =============================================================================
// ZK Nonce Derivation
// =============================================================================
// k = H("ZK/nonce" || (secret XOR H(aux)) || point_compressed || msg || aux)

inline void zk_derive_nonce_impl(const Scalar* secret,
                                  const JacobianPoint* point,
                                  const uchar msg[32],
                                  const uchar aux[32],
                                  Scalar* k_out) {
    // Hash aux for XOR hedging
    uchar aux_hash[32];
    SHA256Ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, aux, 32);
    sha256_final(&ctx, aux_hash);

    // masked = secret_bytes XOR aux_hash
    uchar sec_bytes[32];
    scalar_to_bytes_impl(secret, sec_bytes);
    uchar masked[32];
    for (int i = 0; i < 32; ++i) masked[i] = sec_bytes[i] ^ aux_hash[i];

    // Compress point
    uchar pt_comp[33];
    JacobianPoint pt_copy = *point;
    point_to_compressed_impl(&pt_copy, pt_comp);

    // buf = masked[32] || pt_comp[33] || msg[32] || aux[32] = 129 bytes
    uchar buf[32 + 33 + 32 + 32];
    for (int i = 0; i < 32; ++i) buf[i] = masked[i];
    for (int i = 0; i < 33; ++i) buf[32 + i] = pt_comp[i];
    for (int i = 0; i < 32; ++i) buf[65 + i] = msg[i];
    for (int i = 0; i < 32; ++i) buf[97 + i] = aux[i];

    uchar hash[32];
    uchar tag[] = {'Z','K','/','n','o','n','c','e'};
    zk_tagged_hash_impl(tag, 8, buf, sizeof(buf), hash);
    scalar_from_bytes_impl(hash, k_out);
}

// =============================================================================
// 1a. Knowledge Proof -- Proving
// =============================================================================
// Proves knowledge of secret s such that P = s * B for arbitrary base B.

inline int zk_knowledge_prove_impl(
    const Scalar* secret,
    const JacobianPoint* pubkey,
    const JacobianPoint* base,
    const uchar msg[32],
    const uchar aux[32],
    ZKKnowledgeProof* proof)
{
    // k = deterministic nonce
    Scalar k;
    zk_derive_nonce_impl(secret, pubkey, msg, aux, &k);
    if (scalar_is_zero(&k)) return 0;

    // R = k * base
    JacobianPoint R;
    JacobianPoint base_copy = *base;
    scalar_mul_impl(&R, &base_copy, &k);

    // Convert R to affine
    FieldElement rx_fe, ry_fe;
    jacobian_to_affine_impl(&R, &rx_fe, &ry_fe);

    // Ensure even Y: if Y is odd, negate k
    uchar ry_bytes[32];
    field_to_bytes_impl(&ry_fe, ry_bytes);
    Scalar k_eff;
    if (ry_bytes[31] & 1) {
        scalar_negate_impl(&k, &k_eff);
        field_neg_impl(&ry_fe, &ry_fe);
    } else {
        k_eff = k;
    }

    // Store R.x
    field_to_bytes_impl(&rx_fe, proof->rx);

    // e = H("ZK/knowledge" || R.x || P_comp || B_comp || msg)
    uchar p_comp[33], b_comp[33];
    JacobianPoint pk_copy = *pubkey;
    JacobianPoint base_copy2 = *base;
    point_to_compressed_impl(&pk_copy, p_comp);
    point_to_compressed_impl(&base_copy2, b_comp);

    uchar buf[32 + 33 + 33 + 32];
    for (int i = 0; i < 32; ++i) buf[i] = proof->rx[i];
    for (int i = 0; i < 33; ++i) buf[32 + i] = p_comp[i];
    for (int i = 0; i < 33; ++i) buf[65 + i] = b_comp[i];
    for (int i = 0; i < 32; ++i) buf[98 + i] = msg[i];

    uchar e_hash[32];
    uchar tag[] = {'Z','K','/','k','n','o','w','l','e','d','g','e'};
    zk_tagged_hash_impl(tag, 12, buf, sizeof(buf), e_hash);

    Scalar e;
    scalar_from_bytes_impl(e_hash, &e);

    // s = k_eff + e * secret
    Scalar e_sec;
    scalar_mul_mod_n_impl(&e, secret, &e_sec);
    scalar_add_mod_n_impl(&k_eff, &e_sec, &proof->s);

    return 1;
}

// =============================================================================
// 1b. Knowledge Proof -- Verification
// =============================================================================

inline int zk_knowledge_verify_impl(
    const ZKKnowledgeProof* proof,
    const JacobianPoint* pubkey,
    const JacobianPoint* base,
    const uchar msg[32])
{
    // Reconstruct challenge e
    uchar p_comp[33], b_comp[33];
    JacobianPoint pk_copy = *pubkey;
    JacobianPoint base_copy = *base;
    point_to_compressed_impl(&pk_copy, p_comp);
    point_to_compressed_impl(&base_copy, b_comp);

    uchar buf[32 + 33 + 33 + 32];
    for (int i = 0; i < 32; ++i) buf[i] = proof->rx[i];
    for (int i = 0; i < 33; ++i) buf[32 + i] = p_comp[i];
    for (int i = 0; i < 33; ++i) buf[65 + i] = b_comp[i];
    for (int i = 0; i < 32; ++i) buf[98 + i] = msg[i];

    uchar e_hash[32];
    uchar tag[] = {'Z','K','/','k','n','o','w','l','e','d','g','e'};
    zk_tagged_hash_impl(tag, 12, buf, sizeof(buf), e_hash);

    Scalar e;
    scalar_from_bytes_impl(e_hash, &e);

    // Verify: s*B == R + e*P
    JacobianPoint sB;
    JacobianPoint base_copy2 = *base;
    scalar_mul_impl(&sB, &base_copy2, &proof->s);

    JacobianPoint eP;
    JacobianPoint pk_copy2 = *pubkey;
    scalar_mul_impl(&eP, &pk_copy2, &e);

    // R = lift_x(proof->rx) with even Y
    JacobianPoint R_pt;
    if (!lift_x_impl(proof->rx, &R_pt)) return 0;

    // R + e*P
    JacobianPoint R_plus_eP;
    jacobian_add_impl(&R_plus_eP, &R_pt, &eP);

    // Compare s*B == R + e*P via compressed form
    uchar comp1[33], comp2[33];
    point_to_compressed_impl(&sB, comp1);
    point_to_compressed_impl(&R_plus_eP, comp2);

    for (int i = 0; i < 33; ++i)
        if (comp1[i] != comp2[i]) return 0;
    return 1;
}

// =============================================================================
// 2a. DLEQ Proof -- Proving
// =============================================================================
// Proves log_G(P) == log_H(Q) without revealing the discrete log.

inline int zk_dleq_prove_impl(
    const Scalar* secret,
    const JacobianPoint* G_pt,
    const JacobianPoint* H_pt,
    const JacobianPoint* P_pt,
    const JacobianPoint* Q_pt,
    const uchar aux[32],
    ZKDLEQProof* proof)
{
    // Derive nonce using Q_compressed as msg
    uchar q_comp[33];
    JacobianPoint q_copy = *Q_pt;
    point_to_compressed_impl(&q_copy, q_comp);

    Scalar k;
    zk_derive_nonce_impl(secret, P_pt, q_comp, aux, &k);
    if (scalar_is_zero(&k)) return 0;

    // R1 = k * G, R2 = k * H
    JacobianPoint R1, R2;
    JacobianPoint g_copy = *G_pt, h_copy = *H_pt;
    scalar_mul_impl(&R1, &g_copy, &k);
    scalar_mul_impl(&R2, &h_copy, &k);

    // Serialize all 6 points
    uchar g_comp[33], h_comp[33], p_comp[33];
    uchar r1_comp[33], r2_comp[33];
    JacobianPoint g_copy2 = *G_pt, h_copy2 = *H_pt, p_copy = *P_pt;
    point_to_compressed_impl(&g_copy2, g_comp);
    point_to_compressed_impl(&h_copy2, h_comp);
    point_to_compressed_impl(&p_copy, p_comp);
    point_to_compressed_impl(&R1, r1_comp);
    point_to_compressed_impl(&R2, r2_comp);

    // e = H("ZK/dleq" || G || H || P || Q || R1 || R2)
    uchar buf[33 * 6];
    for (int i = 0; i < 33; ++i) {
        buf[i]       = g_comp[i];
        buf[33 + i]  = h_comp[i];
        buf[66 + i]  = p_comp[i];
        buf[99 + i]  = q_comp[i];
        buf[132 + i] = r1_comp[i];
        buf[165 + i] = r2_comp[i];
    }

    uchar e_hash[32];
    uchar tag[] = {'Z','K','/','d','l','e','q'};
    zk_tagged_hash_impl(tag, 7, buf, sizeof(buf), e_hash);
    scalar_from_bytes_impl(e_hash, &proof->e);

    // s = k + e * secret
    Scalar e_sec;
    scalar_mul_mod_n_impl(&proof->e, secret, &e_sec);
    scalar_add_mod_n_impl(&k, &e_sec, &proof->s);

    return 1;
}

// =============================================================================
// 2b. DLEQ Proof -- Verification
// =============================================================================

inline int zk_dleq_verify_impl(
    const ZKDLEQProof* proof,
    const JacobianPoint* G_pt,
    const JacobianPoint* H_pt,
    const JacobianPoint* P_pt,
    const JacobianPoint* Q_pt)
{
    // R1 = s*G - e*P, R2 = s*H - e*Q
    JacobianPoint sG, eP, sH, eQ;
    JacobianPoint g_copy = *G_pt, h_copy = *H_pt;
    JacobianPoint p_copy = *P_pt, q_copy = *Q_pt;
    scalar_mul_impl(&sG, &g_copy, &proof->s);
    scalar_mul_impl(&eP, &p_copy, &proof->e);
    scalar_mul_impl(&sH, &h_copy, &proof->s);
    scalar_mul_impl(&eQ, &q_copy, &proof->e);

    // Negate eP and eQ
    field_neg_impl(&eP.y, &eP.y);
    field_neg_impl(&eQ.y, &eQ.y);

    JacobianPoint R1, R2;
    jacobian_add_impl(&R1, &sG, &eP);
    jacobian_add_impl(&R2, &sH, &eQ);

    // Serialize all 6 points for challenge recomputation
    uchar g_comp[33], h_comp[33], p_comp[33], q_comp[33];
    uchar r1_comp[33], r2_comp[33];
    JacobianPoint g_copy2 = *G_pt, h_copy2 = *H_pt;
    JacobianPoint p_copy2 = *P_pt, q_copy2 = *Q_pt;
    point_to_compressed_impl(&g_copy2, g_comp);
    point_to_compressed_impl(&h_copy2, h_comp);
    point_to_compressed_impl(&p_copy2, p_comp);
    point_to_compressed_impl(&q_copy2, q_comp);
    point_to_compressed_impl(&R1, r1_comp);
    point_to_compressed_impl(&R2, r2_comp);

    uchar buf[33 * 6];
    for (int i = 0; i < 33; ++i) {
        buf[i]       = g_comp[i];
        buf[33 + i]  = h_comp[i];
        buf[66 + i]  = p_comp[i];
        buf[99 + i]  = q_comp[i];
        buf[132 + i] = r1_comp[i];
        buf[165 + i] = r2_comp[i];
    }

    uchar e_hash[32];
    uchar tag[] = {'Z','K','/','d','l','e','q'};
    zk_tagged_hash_impl(tag, 7, buf, sizeof(buf), e_hash);

    Scalar e_check;
    scalar_from_bytes_impl(e_hash, &e_check);

    // e must match
    return scalar_eq_impl(&proof->e, &e_check);
}

// =============================================================================
// Batch Kernel Entry Points
// =============================================================================

__kernel void zk_knowledge_prove_batch(
    __global const Scalar* secrets,
    __global const JacobianPoint* pubkeys,
    __global const JacobianPoint* bases,
    __global const uchar* messages,
    __global const uchar* aux_rands,
    __global ZKKnowledgeProof* proofs,
    __global int* results,
    const uint count)
{
    uint gid = get_global_id(0);
    if (gid >= count) return;

    Scalar sec = secrets[gid];
    JacobianPoint pk = pubkeys[gid];
    JacobianPoint base = bases[gid];

    uchar msg[32], aux[32];
    for (int i = 0; i < 32; ++i) { msg[i] = messages[gid * 32 + i]; aux[i] = aux_rands[gid * 32 + i]; }

    ZKKnowledgeProof proof;
    results[gid] = zk_knowledge_prove_impl(&sec, &pk, &base, msg, aux, &proof);
    proofs[gid] = proof;
}

__kernel void zk_knowledge_verify_batch(
    __global const ZKKnowledgeProof* proofs,
    __global const JacobianPoint* pubkeys,
    __global const JacobianPoint* bases,
    __global const uchar* messages,
    __global int* results,
    const uint count)
{
    uint gid = get_global_id(0);
    if (gid >= count) return;

    ZKKnowledgeProof proof = proofs[gid];
    JacobianPoint pk = pubkeys[gid];
    JacobianPoint base = bases[gid];

    uchar msg[32];
    for (int i = 0; i < 32; ++i) msg[i] = messages[gid * 32 + i];

    results[gid] = zk_knowledge_verify_impl(&proof, &pk, &base, msg);
}

__kernel void zk_dleq_prove_batch(
    __global const Scalar* secrets,
    __global const JacobianPoint* G_pts,
    __global const JacobianPoint* H_pts,
    __global const JacobianPoint* P_pts,
    __global const JacobianPoint* Q_pts,
    __global const uchar* aux_rands,
    __global ZKDLEQProof* proofs,
    __global int* results,
    const uint count)
{
    uint gid = get_global_id(0);
    if (gid >= count) return;

    Scalar sec = secrets[gid];
    JacobianPoint G = G_pts[gid], H = H_pts[gid];
    JacobianPoint P = P_pts[gid], Q = Q_pts[gid];

    uchar aux[32];
    for (int i = 0; i < 32; ++i) aux[i] = aux_rands[gid * 32 + i];

    ZKDLEQProof proof;
    results[gid] = zk_dleq_prove_impl(&sec, &G, &H, &P, &Q, aux, &proof);
    proofs[gid] = proof;
}

__kernel void zk_dleq_verify_batch(
    __global const ZKDLEQProof* proofs,
    __global const JacobianPoint* G_pts,
    __global const JacobianPoint* H_pts,
    __global const JacobianPoint* P_pts,
    __global const JacobianPoint* Q_pts,
    __global int* results,
    const uint count)
{
    uint gid = get_global_id(0);
    if (gid >= count) return;

    ZKDLEQProof proof = proofs[gid];
    JacobianPoint G = G_pts[gid], H = H_pts[gid];
    JacobianPoint P = P_pts[gid], Q = Q_pts[gid];

    results[gid] = zk_dleq_verify_impl(&proof, &G, &H, &P, &Q);
}
