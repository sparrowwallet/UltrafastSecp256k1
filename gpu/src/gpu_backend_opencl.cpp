/* ============================================================================
 * UltrafastSecp256k1 -- OpenCL Backend Bridge
 * ============================================================================
 * Implements gpu::GpuBackend for OpenCL.
 * Wraps the existing secp256k1::opencl::Context class.
 *
 * Currently supports:
 *   - generator_mul_batch  (via batch_scalar_mul_generator + batch_jacobian_to_affine)
 *   - hash160_pubkey_batch (CPU-side SIMD hash160 -- GPU hash kernel not yet wired)
 *   - ecdh_batch           (GPU batch_scalar_mul + CPU SHA-256 finalization)
 *   - msm                  (GPU batch_scalar_mul + CPU-side affine summation)
 *   - ECDSA / Schnorr verify → UNSUPPORTED (needs extended kernel compilation)
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

/* -- CPU SHA-256 for ECDH finalization ------------------------------------- */
#include "secp256k1/sha256.hpp"

/* -- CPU Hash160 for pubkey hashing ---------------------------------------- */
#include "secp256k1/hash_accel.hpp"

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
        if (!is_ready()) return set_error(GpuError::Device, "context not initialised");
        return set_error(GpuError::Unsupported,
                         "ECDSA verify batch not yet available on OpenCL");
    }

    GpuError schnorr_verify_batch(
        const uint8_t*, const uint8_t*, const uint8_t*,
        size_t, uint8_t*) override
    {
        if (!is_ready()) return set_error(GpuError::Device, "context not initialised");
        return set_error(GpuError::Unsupported,
                         "Schnorr verify batch not yet available on OpenCL");
    }

    GpuError ecdh_batch(
        const uint8_t* privkeys32, const uint8_t* peer_pubkeys33,
        size_t count, uint8_t* out_secrets32) override
    {
        if (!is_ready()) return set_error(GpuError::Device, "context not initialised");
        if (count == 0) { clear_error(); return GpuError::Ok; }
        if (!privkeys32 || !peer_pubkeys33 || !out_secrets32)
            return set_error(GpuError::NullArg, "NULL buffer");

        /* Convert private keys → Scalar, peer pubkeys → AffinePoint */
        std::vector<secp256k1::opencl::Scalar> h_scalars(count);
        std::vector<secp256k1::opencl::AffinePoint> h_peers(count);

        for (size_t i = 0; i < count; ++i) {
            bytes_to_scalar(privkeys32 + i * 32, &h_scalars[i]);
            const uint8_t* pub = peer_pubkeys33 + i * 33;
            if (!pubkey33_to_affine(pub, &h_peers[i]))
                return set_error(GpuError::BadKey, "invalid peer pubkey");
        }

        /* GPU: batch scalar_mul(priv[i], peer[i]) → Jacobian */
        std::vector<secp256k1::opencl::JacobianPoint> h_jac(count);
        ctx_->batch_scalar_mul(h_scalars.data(), h_peers.data(),
                               h_jac.data(), count);

        /* GPU: Jacobian → Affine */
        std::vector<secp256k1::opencl::AffinePoint> h_aff(count);
        ctx_->batch_jacobian_to_affine(h_jac.data(), h_aff.data(), count);

        /* CPU: SHA-256(compressed shared point) to match ufsecp_ecdh/CUDA. */
        for (size_t i = 0; i < count; ++i) {
            uint8_t compressed[33];
            affine_to_compressed(&h_aff[i], compressed);
            auto digest = secp256k1::SHA256::hash(compressed, sizeof(compressed));
            std::memcpy(out_secrets32 + i * 32, digest.data(), 32);
        }

        clear_error();
        return GpuError::Ok;
    }

    GpuError hash160_pubkey_batch(
        const uint8_t* pubkeys33, size_t count,
        uint8_t* out_hash160) override
    {
        if (!is_ready()) return set_error(GpuError::Device, "context not initialised");
        if (count == 0) { clear_error(); return GpuError::Ok; }
        if (!pubkeys33 || !out_hash160)
            return set_error(GpuError::NullArg, "NULL buffer");

        /* CPU-side SIMD-accelerated Hash160 */
        for (size_t i = 0; i < count; ++i) {
            secp256k1::hash::hash160_33(pubkeys33 + i * 33,
                                        out_hash160 + i * 20);
        }

        clear_error();
        return GpuError::Ok;
    }

    GpuError msm(
        const uint8_t* scalars32, const uint8_t* points33,
        size_t n, uint8_t* out_result33) override
    {
        if (!is_ready()) return set_error(GpuError::Device, "context not initialised");
        if (n == 0) { clear_error(); return GpuError::Ok; }
        if (!scalars32 || !points33 || !out_result33)
            return set_error(GpuError::NullArg, "NULL buffer");

        /* Convert inputs */
        std::vector<secp256k1::opencl::Scalar> h_scalars(n);
        std::vector<secp256k1::opencl::AffinePoint> h_points(n);
        for (size_t i = 0; i < n; ++i) {
            bytes_to_scalar(scalars32 + i * 32, &h_scalars[i]);
            if (!pubkey33_to_affine(points33 + i * 33, &h_points[i]))
                return set_error(GpuError::BadKey, "invalid MSM point");
        }

        /* GPU: batch scalar_mul(s[i], P[i]) */
        std::vector<secp256k1::opencl::JacobianPoint> h_jac(n);
        ctx_->batch_scalar_mul(h_scalars.data(), h_points.data(),
                               h_jac.data(), n);

        /* GPU: Jacobian → Affine */
        std::vector<secp256k1::opencl::AffinePoint> h_aff(n);
        ctx_->batch_jacobian_to_affine(h_jac.data(), h_aff.data(), n);

        /* CPU: sum affine points */
        bool have_acc = false;
        secp256k1::fast::FieldElement acc_x, acc_y;

        for (size_t i = 0; i < n; ++i) {
            std::array<uint64_t, 4> xl, yl;
            std::memcpy(xl.data(), h_aff[i].x.limbs, 32);
            std::memcpy(yl.data(), h_aff[i].y.limbs, 32);
            auto px = secp256k1::fast::FieldElement::from_limbs(xl);
            auto py = secp256k1::fast::FieldElement::from_limbs(yl);

            /* Skip point at infinity (zero x and y) */
            auto pxb = px.to_bytes();
            auto pyb = py.to_bytes();
            bool is_zero = true;
            for (int k = 0; k < 32 && is_zero; ++k)
                if (pxb[k] || pyb[k]) is_zero = false;
            if (is_zero) continue;

            if (!have_acc) {
                acc_x = px; acc_y = py;
                have_acc = true;
                continue;
            }

            /* Affine point addition: acc += (px, py) */
            auto dx = px - acc_x;
            auto dy = py - acc_y;
            auto dxb = dx.to_bytes();
            bool dx_zero = true;
            for (int k = 0; k < 32 && dx_zero; ++k)
                if (dxb[k]) dx_zero = false;

            if (dx_zero) {
                auto dyb = dy.to_bytes();
                bool dy_zero = true;
                for (int k = 0; k < 32 && dy_zero; ++k)
                    if (dyb[k]) dy_zero = false;
                if (!dy_zero) {
                    /* Inverse points → result is infinity */
                    have_acc = false;
                    continue;
                }
                /* Doubling: lambda = 3*x^2 / (2*y) */
                auto x2 = acc_x * acc_x;
                auto num = x2 + x2 + x2;
                auto den = acc_y + acc_y;
                auto lam = num * den.inverse();
                auto rx = lam * lam - acc_x - acc_x;
                auto ry = lam * (acc_x - rx) - acc_y;
                acc_x = rx; acc_y = ry;
            } else {
                auto lam = dy * dx.inverse();
                auto rx = lam * lam - acc_x - px;
                auto ry = lam * (acc_x - rx) - acc_y;
                acc_x = rx; acc_y = ry;
            }
        }

        if (!have_acc)
            return set_error(GpuError::Arith, "MSM result is point at infinity");

        /* Serialize result */
        auto yb = acc_y.to_bytes();
        out_result33[0] = (yb[31] & 1) ? 0x03 : 0x02;
        auto xb = acc_x.to_bytes();
        std::memcpy(out_result33 + 1, xb.data(), 32);

        clear_error();
        return GpuError::Ok;
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

    /** Decompress a 33-byte compressed pubkey to OpenCL AffinePoint.
     *  Returns false if prefix is invalid.                               */
    static bool pubkey33_to_affine(const uint8_t pub[33],
                                   secp256k1::opencl::AffinePoint* out) {
        uint8_t prefix = pub[0];
        if (prefix != 0x02 && prefix != 0x03) return false;

        /* x from big-endian bytes */
        secp256k1::fast::FieldElement fe_x;
        if (!secp256k1::fast::FieldElement::parse_bytes_strict(pub + 1, fe_x))
            return false;

        /* y^2 = x^3 + 7 */
        auto x2 = fe_x * fe_x;
        auto x3 = x2 * fe_x;
        auto y2 = x3 + secp256k1::fast::FieldElement::from_uint64(7);
        auto fe_y = y2.sqrt();

        /* Choose correct parity */
        auto yb = fe_y.to_bytes();
        if ((yb[31] & 1) != (prefix & 1))
            fe_y = fe_y.negate();

        /* Store as LE limbs into OpenCL AffinePoint */
        const auto& xl = fe_x.limbs();
        const auto& yl = fe_y.limbs();
        std::memcpy(out->x.limbs, xl.data(), 32);
        std::memcpy(out->y.limbs, yl.data(), 32);
        return true;
    }
};

/* -- Factory --------------------------------------------------------------- */
std::unique_ptr<GpuBackend> create_opencl_backend() {
    return std::make_unique<OpenCLBackend>();
}

} // namespace gpu
} // namespace secp256k1
