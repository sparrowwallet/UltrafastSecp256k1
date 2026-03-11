#pragma once
// =============================================================================
// UltrafastSecp256k1 Metal -- Zero-Knowledge Proof Operations
// =============================================================================
// ZK proof primitives for Metal (Apple Silicon GPU):
//   1. Knowledge proof (Schnorr sigma protocol) -- prove + verify
//   2. DLEQ proof (discrete log equality) -- prove + verify
//
// Depends on: secp256k1_extended.h (includes field, point, scalar, SHA-256)
// Uses 8x32-bit limbs (uint) -- matching existing Metal convention.
// =============================================================================

#include "secp256k1_extended.h"

// =============================================================================
// ZK Proof Structures
// =============================================================================

struct ZKKnowledgeProof {
    uchar rx[32];    // R.x (x-coordinate of nonce point, even Y)
    Scalar256 s;     // response scalar
};

struct ZKDLEQProof {
    Scalar256 e;     // challenge
    Scalar256 s;     // response
};

// =============================================================================
// Helper: Point to Compressed (33 bytes: prefix || x)
// =============================================================================

inline void point_to_compressed(thread const JacobianPoint &p,
                                 thread uchar out[33]) {
    if (p.infinity != 0) {
        for (int i = 0; i < 33; ++i) out[i] = 0;
        return;
    }
    AffinePoint aff = jacobian_to_affine(p);

    uchar y_bytes[32];
    field_to_bytes(aff.y, y_bytes);
    out[0] = (y_bytes[31] & 1) ? 0x03 : 0x02;
    field_to_bytes(aff.x, out + 1);
}

// =============================================================================
// ZK Nonce Derivation
// =============================================================================
// k = H("ZK/nonce" || (secret XOR H(aux)) || point_compressed || msg || aux)

inline Scalar256 zk_derive_nonce(thread const Scalar256 &secret,
                                  thread const JacobianPoint &point,
                                  thread const uchar msg[32],
                                  thread const uchar aux[32]) {
    // Hash aux for XOR hedging
    uchar aux_hash[32];
    SHA256Ctx ctx; sha256_init(ctx);
    sha256_update(ctx, aux, 32);
    sha256_final(ctx, aux_hash);

    // masked = secret_bytes XOR aux_hash
    uchar sec_bytes[32];
    scalar_to_bytes(secret, sec_bytes);
    uchar masked[32];
    for (int i = 0; i < 32; ++i) masked[i] = sec_bytes[i] ^ aux_hash[i];

    // Compress point
    uchar pt_comp[33];
    point_to_compressed(point, pt_comp);

    // buf = masked[32] || pt_comp[33] || msg[32] || aux[32] = 129 bytes
    uchar buf[129];
    for (int i = 0; i < 32; ++i) buf[i] = masked[i];
    for (int i = 0; i < 33; ++i) buf[32 + i] = pt_comp[i];
    for (int i = 0; i < 32; ++i) buf[65 + i] = msg[i];
    for (int i = 0; i < 32; ++i) buf[97 + i] = aux[i];

    uchar hash[32];
    uchar tag[] = {'Z','K','/','n','o','n','c','e'};
    tagged_hash(tag, 8, buf, 129, hash);
    return scalar_from_bytes(hash);
}

// =============================================================================
// 1a. Knowledge Proof -- Proving
// =============================================================================
// Proves knowledge of secret s such that P = s * B for arbitrary base B.

inline bool zk_knowledge_prove(thread const Scalar256 &secret,
                                thread const JacobianPoint &pubkey,
                                thread const AffinePoint &base,
                                thread const uchar msg[32],
                                thread const uchar aux[32],
                                thread ZKKnowledgeProof &proof) {
    // k = deterministic nonce
    Scalar256 k = zk_derive_nonce(secret, pubkey, msg, aux);
    if (scalar256_is_zero(k)) return false;

    // R = k * base
    JacobianPoint R = scalar_mul(base, k);

    // Convert R to affine
    AffinePoint R_aff = jacobian_to_affine(R);

    // Ensure even Y: if Y is odd, negate k
    uchar ry_bytes[32];
    field_to_bytes(R_aff.y, ry_bytes);
    Scalar256 k_eff;
    if (ry_bytes[31] & 1) {
        k_eff = scalar_negate(k);
        R_aff.y = field_neg(R_aff.y);
    } else {
        k_eff = k;
    }

    // Store R.x
    field_to_bytes(R_aff.x, proof.rx);

    // e = H("ZK/knowledge" || R.x || P_comp || B_comp || msg)
    uchar p_comp[33], b_comp[33];
    point_to_compressed(pubkey, p_comp);
    JacobianPoint base_jac;
    base_jac.x = base.x; base_jac.y = base.y; base_jac.z = field_one(); base_jac.infinity = 0;
    point_to_compressed(base_jac, b_comp);

    uchar buf[130]; // 32 + 33 + 33 + 32
    for (int i = 0; i < 32; ++i) buf[i] = proof.rx[i];
    for (int i = 0; i < 33; ++i) buf[32 + i] = p_comp[i];
    for (int i = 0; i < 33; ++i) buf[65 + i] = b_comp[i];
    for (int i = 0; i < 32; ++i) buf[98 + i] = msg[i];

    uchar e_hash[32];
    uchar tag[] = {'Z','K','/','k','n','o','w','l','e','d','g','e'};
    tagged_hash(tag, 12, buf, 130, e_hash);

    Scalar256 e = scalar_from_bytes(e_hash);

    // s = k_eff + e * secret
    Scalar256 e_sec = scalar_mul_mod_n(e, secret);
    proof.s = scalar_add_mod_n(k_eff, e_sec);

    return true;
}

// Convenience: prove with generator G
inline bool zk_knowledge_prove_generator(thread const Scalar256 &secret,
                                          thread const JacobianPoint &pubkey,
                                          thread const uchar msg[32],
                                          thread const uchar aux[32],
                                          thread ZKKnowledgeProof &proof) {
    AffinePoint G = generator_affine();
    return zk_knowledge_prove(secret, pubkey, G, msg, aux, proof);
}

// =============================================================================
// 1b. Knowledge Proof -- Verification
// =============================================================================

inline bool zk_knowledge_verify(thread const ZKKnowledgeProof &proof,
                                 thread const JacobianPoint &pubkey,
                                 thread const AffinePoint &base,
                                 thread const uchar msg[32]) {
    // Reconstruct challenge e
    uchar p_comp[33], b_comp[33];
    point_to_compressed(pubkey, p_comp);
    JacobianPoint base_jac;
    base_jac.x = base.x; base_jac.y = base.y; base_jac.z = field_one(); base_jac.infinity = 0;
    point_to_compressed(base_jac, b_comp);

    uchar buf[130];
    for (int i = 0; i < 32; ++i) buf[i] = proof.rx[i];
    for (int i = 0; i < 33; ++i) buf[32 + i] = p_comp[i];
    for (int i = 0; i < 33; ++i) buf[65 + i] = b_comp[i];
    for (int i = 0; i < 32; ++i) buf[98 + i] = msg[i];

    uchar e_hash[32];
    uchar tag[] = {'Z','K','/','k','n','o','w','l','e','d','g','e'};
    tagged_hash(tag, 12, buf, 130, e_hash);

    Scalar256 e = scalar_from_bytes(e_hash);

    // Verify: s*B == R + e*P
    JacobianPoint sB = scalar_mul(base, proof.s);

    AffinePoint pk_aff = jacobian_to_affine(pubkey);
    JacobianPoint eP = scalar_mul(pk_aff, e);

    // R = lift_x(proof.rx) with even Y
    JacobianPoint R_pt;
    if (!lift_x(proof.rx, R_pt)) return false;

    // R + e*P
    AffinePoint eP_aff = jacobian_to_affine(eP);
    AffinePoint R_aff = jacobian_to_affine(R_pt);
    JacobianPoint R_jac;
    R_jac.x = R_aff.x; R_jac.y = R_aff.y; R_jac.z = field_one(); R_jac.infinity = 0;
    JacobianPoint R_plus_eP = jacobian_add_mixed(R_jac, eP_aff);

    // Compare s*B == R + e*P via compressed form
    uchar comp1[33], comp2[33];
    point_to_compressed(sB, comp1);
    point_to_compressed(R_plus_eP, comp2);

    for (int i = 0; i < 33; ++i)
        if (comp1[i] != comp2[i]) return false;
    return true;
}

// =============================================================================
// 2a. DLEQ Proof -- Proving
// =============================================================================
// Proves log_G(P) == log_H(Q) without revealing the discrete log.

inline bool zk_dleq_prove(thread const Scalar256 &secret,
                            thread const AffinePoint &G,
                            thread const AffinePoint &H,
                            thread const JacobianPoint &P,
                            thread const JacobianPoint &Q,
                            thread const uchar aux[32],
                            thread ZKDLEQProof &proof) {
    // Derive nonce using Q_compressed as msg
    uchar q_comp[33];
    point_to_compressed(Q, q_comp);

    Scalar256 k = zk_derive_nonce(secret, P, q_comp, aux);
    if (scalar256_is_zero(k)) return false;

    // R1 = k * G, R2 = k * H
    JacobianPoint R1 = scalar_mul(G, k);
    JacobianPoint R2 = scalar_mul(H, k);

    // Serialize all 6 points
    uchar g_comp[33], h_comp[33], p_comp[33];
    uchar r1_comp[33], r2_comp[33];
    JacobianPoint G_jac, H_jac;
    G_jac.x = G.x; G_jac.y = G.y; G_jac.z = field_one(); G_jac.infinity = 0;
    H_jac.x = H.x; H_jac.y = H.y; H_jac.z = field_one(); H_jac.infinity = 0;
    point_to_compressed(G_jac, g_comp);
    point_to_compressed(H_jac, h_comp);
    point_to_compressed(P, p_comp);
    point_to_compressed(R1, r1_comp);
    point_to_compressed(R2, r2_comp);

    // e = H("ZK/dleq" || G || H || P || Q || R1 || R2)
    uchar buf[198]; // 33 * 6
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
    tagged_hash(tag, 7, buf, 198, e_hash);
    proof.e = scalar_from_bytes(e_hash);

    // s = k + e * secret
    Scalar256 e_sec = scalar_mul_mod_n(proof.e, secret);
    proof.s = scalar_add_mod_n(k, e_sec);

    return true;
}

// =============================================================================
// 2b. DLEQ Proof -- Verification
// =============================================================================

inline bool zk_dleq_verify(thread const ZKDLEQProof &proof,
                             thread const AffinePoint &G,
                             thread const AffinePoint &H,
                             thread const JacobianPoint &P,
                             thread const JacobianPoint &Q) {
    // R1 = s*G - e*P, R2 = s*H - e*Q
    JacobianPoint sG = scalar_mul(G, proof.s);
    AffinePoint P_aff = jacobian_to_affine(P);
    JacobianPoint eP = scalar_mul(P_aff, proof.e);

    JacobianPoint sH = scalar_mul(H, proof.s);
    AffinePoint Q_aff = jacobian_to_affine(Q);
    JacobianPoint eQ = scalar_mul(Q_aff, proof.e);

    // Negate eP and eQ
    eP.y = field_neg(eP.y);
    eQ.y = field_neg(eQ.y);

    AffinePoint eP_aff = jacobian_to_affine(eP);
    AffinePoint eQ_aff = jacobian_to_affine(eQ);
    JacobianPoint R1 = jacobian_add_mixed(sG, eP_aff);
    JacobianPoint R2 = jacobian_add_mixed(sH, eQ_aff);

    // Serialize all 6 points for challenge recomputation
    uchar g_comp[33], h_comp[33], p_comp[33], q_comp[33];
    uchar r1_comp[33], r2_comp[33];
    JacobianPoint G_jac, H_jac;
    G_jac.x = G.x; G_jac.y = G.y; G_jac.z = field_one(); G_jac.infinity = 0;
    H_jac.x = H.x; H_jac.y = H.y; H_jac.z = field_one(); H_jac.infinity = 0;
    point_to_compressed(G_jac, g_comp);
    point_to_compressed(H_jac, h_comp);
    point_to_compressed(P, p_comp);
    point_to_compressed(Q, q_comp);
    point_to_compressed(R1, r1_comp);
    point_to_compressed(R2, r2_comp);

    uchar buf[198];
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
    tagged_hash(tag, 7, buf, 198, e_hash);

    Scalar256 e_check = scalar_from_bytes(e_hash);
    return scalar256_eq(proof.e, e_check);
}
