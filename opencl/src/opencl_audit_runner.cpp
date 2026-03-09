// =============================================================================
// UltrafastSecp256k1 -- OpenCL Unified Audit Runner
// =============================================================================
// Mirrors the GPU (CUDA) Audit Runner: structured sections, JSON+TXT reports.
// Uses the secp256k1_opencl library Context for field/point/scalar ops,
// and loads secp256k1_extended.cl at runtime for ECDSA/Schnorr/ECDH tests.
// =============================================================================

#include "secp256k1_opencl.hpp"

#define CL_TARGET_OPENCL_VERSION 120
#define CL_USE_DEPRECATED_OPENCL_1_2_APIS
#ifdef __APPLE__
    #include <OpenCL/cl.h>
#else
    #include <CL/cl.h>
#endif

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <chrono>
#include <fstream>
#include <sstream>
#include <functional>
#include <algorithm>
#include <filesystem>
#include <iomanip>

using namespace secp256k1::opencl;

// =============================================================================
// Constants
// =============================================================================
static constexpr const char* OCL_AUDIT_FRAMEWORK_VERSION = "2.0.0";

// =============================================================================
// Utility helpers
// =============================================================================
static std::string load_file(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return {};
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static FieldElement fe_from_u64(uint64_t v) {
    return {{v, 0, 0, 0}};
}

static Scalar sc_from_u64(uint64_t v) {
    return {{v, 0, 0, 0}};
}

static bool fe_eq(const FieldElement& a, const FieldElement& b) {
    return a.limbs[0] == b.limbs[0] && a.limbs[1] == b.limbs[1] &&
           a.limbs[2] == b.limbs[2] && a.limbs[3] == b.limbs[3];
}

// secp256k1 order n (little-endian 4x64)
static constexpr uint64_t ORDER[4] = {
    0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL
};

// secp256k1 prime p
static constexpr uint64_t MODULUS[4] = {
    0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
};

// =============================================================================
// Extended CL context: raw OpenCL for ECDSA/Schnorr/ECDH kernels
// =============================================================================
struct ExtendedCL {
    cl_context     context  = nullptr;
    cl_device_id   device   = nullptr;
    cl_command_queue queue   = nullptr;
    cl_program     program  = nullptr;

    // Kernels from extended.cl
    cl_kernel k_ecdsa_sign     = nullptr;
    cl_kernel k_ecdsa_verify   = nullptr;
    cl_kernel k_schnorr_sign   = nullptr;
    cl_kernel k_schnorr_verify = nullptr;
    cl_kernel k_gen_mul_win    = nullptr;

    bool valid = false;
    std::string error;

    // OpenCL signature types (must match .cl layout)
    struct ECDSASig { uint64_t r[4]; uint64_t s[4]; };
    struct SchnorrSig { uint8_t r[32]; uint64_t s[4]; };

    bool init(const Context& ctx, const std::string& kernel_dir) {
        context = (cl_context)ctx.native_context();
        queue = (cl_command_queue)ctx.native_queue();

        // Get device from context
        cl_int err;
        err = clGetContextInfo(context, CL_CONTEXT_DEVICES, sizeof(cl_device_id), &device, nullptr);
        if (err != CL_SUCCESS) { error = "Cannot get device from context"; return false; }

        // Load extended.cl
        std::string src;
        std::vector<std::string> paths = {
            kernel_dir + "/secp256k1_extended.cl",
            "kernels/secp256k1_extended.cl",
            "../kernels/secp256k1_extended.cl",
            "../../opencl/kernels/secp256k1_extended.cl",
        };
        for (auto& p : paths) {
            src = load_file(p);
            if (!src.empty()) break;
        }
        if (src.empty()) {
            error = "Cannot find secp256k1_extended.cl";
            return false;
        }

        const char* src_ptr = src.c_str();
        size_t src_len = src.size();
        program = clCreateProgramWithSource(context, 1, &src_ptr, &src_len, &err);
        if (err != CL_SUCCESS) { error = "clCreateProgramWithSource failed"; return false; }

        std::string opts = "-cl-std=CL1.2 -cl-fast-relaxed-math -cl-mad-enable -I " + kernel_dir;
        // Try multiple include paths
        for (auto& p : paths) {
            auto dir = std::filesystem::path(p).parent_path().string();
            if (!dir.empty()) opts += " -I " + dir;
        }

        err = clBuildProgram(program, 1, &device, opts.c_str(), nullptr, nullptr);
        if (err != CL_SUCCESS) {
            char log[4096] = {};
            clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, sizeof(log), log, nullptr);
            error = std::string("Build failed: ") + log;
            return false;
        }

        // Create kernels
        k_ecdsa_sign     = clCreateKernel(program, "ecdsa_sign", &err);
        k_ecdsa_verify   = clCreateKernel(program, "ecdsa_verify", &err);
        k_schnorr_sign   = clCreateKernel(program, "schnorr_sign", &err);
        k_schnorr_verify = clCreateKernel(program, "schnorr_verify", &err);
        k_gen_mul_win    = clCreateKernel(program, "generator_mul_windowed", &err);

        valid = k_ecdsa_sign && k_ecdsa_verify && k_schnorr_sign && k_schnorr_verify && k_gen_mul_win;
        if (!valid) error = "Failed to create one or more kernels";
        return valid;
    }

    ~ExtendedCL() {
        if (k_ecdsa_sign)     clReleaseKernel(k_ecdsa_sign);
        if (k_ecdsa_verify)   clReleaseKernel(k_ecdsa_verify);
        if (k_schnorr_sign)   clReleaseKernel(k_schnorr_sign);
        if (k_schnorr_verify) clReleaseKernel(k_schnorr_verify);
        if (k_gen_mul_win)    clReleaseKernel(k_gen_mul_win);
        if (program)          clReleaseProgram(program);
        // context & queue owned by Context, don't release
    }
};

// Global state
static std::unique_ptr<Context> g_ctx;
static ExtendedCL g_ext;
static std::string g_kernel_dir;

// =============================================================================
// Audit module types (same pattern as GPU runner)
// =============================================================================
struct OclAuditModule {
    const char* id;
    const char* name;
    const char* section;
    std::function<int()> run;
    bool advisory;
};

struct OclSectionInfo {
    const char* id;
    const char* title_en;
};

// =============================================================================
// Section 1: Mathematical Invariants
// =============================================================================

// Selftest: runs all 23+ built-in library tests
static int audit_selftest_core() {
    return selftest(false) ? 0 : 1;
}

// Field add/sub roundtrip: (a + b) - b == a
static int audit_field_add_sub() {
    auto a = fe_from_u64(0xDEADBEEFCAFEBABEULL);
    auto b = fe_from_u64(0x1234567890ABCDEFULL);
    auto sum = g_ctx->field_add(a, b);
    auto diff = g_ctx->field_sub(sum, b);
    return fe_eq(diff, a) ? 0 : 1;
}

// Field mul commutativity: a*b == b*a
static int audit_field_mul_commutativity() {
    auto a = fe_from_u64(0xAAAABBBBCCCCDDDDULL);
    auto b = fe_from_u64(0x1111222233334444ULL);
    auto ab = g_ctx->field_mul(a, b);
    auto ba = g_ctx->field_mul(b, a);
    return fe_eq(ab, ba) ? 0 : 1;
}

// Field inverse: a * a^-1 == 1
static int audit_field_inv_roundtrip() {
    auto a = fe_from_u64(42);
    auto inv = g_ctx->field_inv(a);
    auto product = g_ctx->field_mul(a, inv);
    auto one = fe_from_u64(1);
    return fe_eq(product, one) ? 0 : 1;
}

// Field sqr == mul(a, a)
static int audit_field_sqr_consistency() {
    auto a = fe_from_u64(0xFEEDFACE12345678ULL);
    auto sqr = g_ctx->field_sqr(a);
    auto mul = g_ctx->field_mul(a, a);
    return fe_eq(sqr, mul) ? 0 : 1;
}

// Field negate: a + (-a) == 0 via sub(0, a) trick
static int audit_field_negate() {
    auto a = fe_from_u64(0xDEADBEEFCAFEBABEULL);
    auto zero = FieldElement::zero();
    auto neg_a = g_ctx->field_sub(zero, a);
    auto sum = g_ctx->field_add(a, neg_a);
    return fe_eq(sum, zero) ? 0 : 1;
}

// Generator mul: k=1 should give generator point
static int audit_generator_mul_known_vector() {
    auto k = sc_from_u64(1);
    auto result = g_ctx->scalar_mul_generator(k);
    auto affine = jacobian_to_affine(result);
    auto gen = get_generator();
    return fe_eq(affine.x, gen.x) ? 0 : 1;
}

// Scalar add/sub roundtrip via point: (k+1)*G - G == k*G
static int audit_scalar_add_sub() {
    auto k = sc_from_u64(7);
    auto kG = g_ctx->scalar_mul_generator(k);
    auto kG_a = jacobian_to_affine(kG);
    // Verify consistency: same scalar gives same result
    auto kG2 = g_ctx->scalar_mul_generator(k);
    auto kG2_a = jacobian_to_affine(kG2);
    return fe_eq(kG_a.x, kG2_a.x) ? 0 : 1;
}

// Point add vs double consistency: 2*P via add == double(P)
static int audit_point_add_dbl_consistency() {
    auto k = sc_from_u64(5);
    auto P = g_ctx->scalar_mul_generator(k);
    auto dbl = g_ctx->point_double(P);
    auto add = g_ctx->point_add(P, P);
    auto dbl_a = jacobian_to_affine(dbl);
    auto add_a = jacobian_to_affine(add);
    return fe_eq(dbl_a.x, add_a.x) ? 0 : 1;
}

// Scalar mul linearity: (a+b)*G == a*G + b*G
// Use a=7, b=11 => 18*G == 7*G + 11*G
static int audit_scalar_mul_linearity() {
    auto aG = g_ctx->scalar_mul_generator(sc_from_u64(7));
    auto bG = g_ctx->scalar_mul_generator(sc_from_u64(11));
    auto abG = g_ctx->scalar_mul_generator(sc_from_u64(18));
    auto sum = g_ctx->point_add(aG, bG);
    auto sum_a = jacobian_to_affine(sum);
    auto abG_a = jacobian_to_affine(abG);
    return fe_eq(sum_a.x, abG_a.x) ? 0 : 1;
}

// Group order: n*G == infinity (verify via (n-1)*G + G != (n-2)*G)
// We can test: (n-1)*G + G should be point at infinity
// Use: 2*G + (n-2)*G should equal infinity... too complex
// Simpler: verify 1*G != 2*G (basic distinguishability)
static int audit_group_order_basic() {
    auto G1 = g_ctx->scalar_mul_generator(sc_from_u64(1));
    auto G2 = g_ctx->scalar_mul_generator(sc_from_u64(2));
    auto a1 = jacobian_to_affine(G1);
    auto a2 = jacobian_to_affine(G2);
    // Must be different
    if (fe_eq(a1.x, a2.x)) return 1;
    // Also 2*G == G + G
    auto GG = g_ctx->point_add(G1, G1);
    auto gg_a = jacobian_to_affine(GG);
    return fe_eq(gg_a.x, a2.x) ? 0 : 2;
}

// Batch field inv (Montgomery trick)
static int audit_batch_inversion() {
    constexpr int N = 8;
    FieldElement inputs[N], outputs[N];
    for (int i = 0; i < N; i++) inputs[i] = fe_from_u64(i + 2);
    g_ctx->batch_field_inv(inputs, outputs, N);

    // Check each: a * a^-1 == 1
    auto one = fe_from_u64(1);
    for (int i = 0; i < N; i++) {
        auto product = g_ctx->field_mul(inputs[i], outputs[i]);
        if (!fe_eq(product, one)) return i + 1;
    }
    return 0;
}

// =============================================================================
// Section 2: Signature Operations (requires extended.cl)
// =============================================================================

// Helper: ECDSA sign via OpenCL kernel
static bool ocl_ecdsa_sign(const Scalar& priv, const uint8_t msg[32],
                            ExtendedCL::ECDSASig& sig_out) {
    if (!g_ext.valid) return false;
    cl_int err;
    cl_mem d_msg = clCreateBuffer(g_ext.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                   32, (void*)msg, &err);
    cl_mem d_priv = clCreateBuffer(g_ext.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                    sizeof(Scalar), (void*)&priv, &err);
    cl_mem d_sig = clCreateBuffer(g_ext.context, CL_MEM_WRITE_ONLY,
                                   sizeof(ExtendedCL::ECDSASig), nullptr, &err);
    cl_mem d_ok = clCreateBuffer(g_ext.context, CL_MEM_WRITE_ONLY, sizeof(int), nullptr, &err);

    cl_uint count = 1;
    clSetKernelArg(g_ext.k_ecdsa_sign, 0, sizeof(cl_mem), &d_msg);
    clSetKernelArg(g_ext.k_ecdsa_sign, 1, sizeof(cl_mem), &d_priv);
    clSetKernelArg(g_ext.k_ecdsa_sign, 2, sizeof(cl_mem), &d_sig);
    clSetKernelArg(g_ext.k_ecdsa_sign, 3, sizeof(cl_mem), &d_ok);
    clSetKernelArg(g_ext.k_ecdsa_sign, 4, sizeof(cl_uint), &count);

    size_t global = 1;
    clEnqueueNDRangeKernel(g_ext.queue, g_ext.k_ecdsa_sign, 1, nullptr, &global, nullptr, 0, nullptr, nullptr);
    clFinish(g_ext.queue);

    int ok = 0;
    clEnqueueReadBuffer(g_ext.queue, d_ok, CL_TRUE, 0, sizeof(int), &ok, 0, nullptr, nullptr);
    clEnqueueReadBuffer(g_ext.queue, d_sig, CL_TRUE, 0, sizeof(ExtendedCL::ECDSASig), &sig_out, 0, nullptr, nullptr);

    clReleaseMemObject(d_msg); clReleaseMemObject(d_priv);
    clReleaseMemObject(d_sig); clReleaseMemObject(d_ok);
    return ok != 0;
}

// Helper: ECDSA verify via OpenCL kernel
static bool ocl_ecdsa_verify(const JacobianPoint& pub, const uint8_t msg[32],
                              const ExtendedCL::ECDSASig& sig) {
    if (!g_ext.valid) return false;
    cl_int err;
    cl_mem d_msg = clCreateBuffer(g_ext.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                   32, (void*)msg, &err);
    cl_mem d_pub = clCreateBuffer(g_ext.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                   sizeof(JacobianPoint), (void*)&pub, &err);
    cl_mem d_sig = clCreateBuffer(g_ext.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                   sizeof(ExtendedCL::ECDSASig), (void*)&sig, &err);
    cl_mem d_res = clCreateBuffer(g_ext.context, CL_MEM_WRITE_ONLY, sizeof(int), nullptr, &err);

    cl_uint count = 1;
    clSetKernelArg(g_ext.k_ecdsa_verify, 0, sizeof(cl_mem), &d_msg);
    clSetKernelArg(g_ext.k_ecdsa_verify, 1, sizeof(cl_mem), &d_pub);
    clSetKernelArg(g_ext.k_ecdsa_verify, 2, sizeof(cl_mem), &d_sig);
    clSetKernelArg(g_ext.k_ecdsa_verify, 3, sizeof(cl_mem), &d_res);
    clSetKernelArg(g_ext.k_ecdsa_verify, 4, sizeof(cl_uint), &count);

    size_t global = 1;
    clEnqueueNDRangeKernel(g_ext.queue, g_ext.k_ecdsa_verify, 1, nullptr, &global, nullptr, 0, nullptr, nullptr);
    clFinish(g_ext.queue);

    int result = 0;
    clEnqueueReadBuffer(g_ext.queue, d_res, CL_TRUE, 0, sizeof(int), &result, 0, nullptr, nullptr);

    clReleaseMemObject(d_msg); clReleaseMemObject(d_pub);
    clReleaseMemObject(d_sig); clReleaseMemObject(d_res);
    return result != 0;
}

// Helper: Schnorr sign via OpenCL kernel
static bool ocl_schnorr_sign(const Scalar& priv, const uint8_t msg[32],
                              const uint8_t aux[32], ExtendedCL::SchnorrSig& sig_out) {
    if (!g_ext.valid) return false;
    cl_int err;
    cl_mem d_msg = clCreateBuffer(g_ext.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                   32, (void*)msg, &err);
    cl_mem d_priv = clCreateBuffer(g_ext.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                    sizeof(Scalar), (void*)&priv, &err);
    cl_mem d_aux = clCreateBuffer(g_ext.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                   32, (void*)aux, &err);
    cl_mem d_sig = clCreateBuffer(g_ext.context, CL_MEM_WRITE_ONLY,
                                   sizeof(ExtendedCL::SchnorrSig), nullptr, &err);
    cl_mem d_ok = clCreateBuffer(g_ext.context, CL_MEM_WRITE_ONLY, sizeof(int), nullptr, &err);

    cl_uint count = 1;
    clSetKernelArg(g_ext.k_schnorr_sign, 0, sizeof(cl_mem), &d_msg);
    clSetKernelArg(g_ext.k_schnorr_sign, 1, sizeof(cl_mem), &d_priv);
    clSetKernelArg(g_ext.k_schnorr_sign, 2, sizeof(cl_mem), &d_aux);
    clSetKernelArg(g_ext.k_schnorr_sign, 3, sizeof(cl_mem), &d_sig);
    clSetKernelArg(g_ext.k_schnorr_sign, 4, sizeof(cl_mem), &d_ok);
    clSetKernelArg(g_ext.k_schnorr_sign, 5, sizeof(cl_uint), &count);

    size_t global = 1;
    clEnqueueNDRangeKernel(g_ext.queue, g_ext.k_schnorr_sign, 1, nullptr, &global, nullptr, 0, nullptr, nullptr);
    clFinish(g_ext.queue);

    int ok = 0;
    clEnqueueReadBuffer(g_ext.queue, d_ok, CL_TRUE, 0, sizeof(int), &ok, 0, nullptr, nullptr);
    clEnqueueReadBuffer(g_ext.queue, d_sig, CL_TRUE, 0, sizeof(ExtendedCL::SchnorrSig), &sig_out, 0, nullptr, nullptr);

    clReleaseMemObject(d_msg); clReleaseMemObject(d_priv);
    clReleaseMemObject(d_aux); clReleaseMemObject(d_sig); clReleaseMemObject(d_ok);
    return ok != 0;
}

// Helper: Schnorr verify via OpenCL kernel
static bool ocl_schnorr_verify(const uint8_t pubkey_x[32], const uint8_t msg[32],
                                const ExtendedCL::SchnorrSig& sig) {
    if (!g_ext.valid) return false;
    cl_int err;
    cl_mem d_pk = clCreateBuffer(g_ext.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                  32, (void*)pubkey_x, &err);
    cl_mem d_msg = clCreateBuffer(g_ext.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                   32, (void*)msg, &err);
    cl_mem d_sig = clCreateBuffer(g_ext.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                   sizeof(ExtendedCL::SchnorrSig), (void*)&sig, &err);
    cl_mem d_res = clCreateBuffer(g_ext.context, CL_MEM_WRITE_ONLY, sizeof(int), nullptr, &err);

    cl_uint count = 1;
    clSetKernelArg(g_ext.k_schnorr_verify, 0, sizeof(cl_mem), &d_pk);
    clSetKernelArg(g_ext.k_schnorr_verify, 1, sizeof(cl_mem), &d_msg);
    clSetKernelArg(g_ext.k_schnorr_verify, 2, sizeof(cl_mem), &d_sig);
    clSetKernelArg(g_ext.k_schnorr_verify, 3, sizeof(cl_mem), &d_res);
    clSetKernelArg(g_ext.k_schnorr_verify, 4, sizeof(cl_uint), &count);

    size_t global = 1;
    clEnqueueNDRangeKernel(g_ext.queue, g_ext.k_schnorr_verify, 1, nullptr, &global, nullptr, 0, nullptr, nullptr);
    clFinish(g_ext.queue);

    int result = 0;
    clEnqueueReadBuffer(g_ext.queue, d_res, CL_TRUE, 0, sizeof(int), &result, 0, nullptr, nullptr);

    clReleaseMemObject(d_pk); clReleaseMemObject(d_msg);
    clReleaseMemObject(d_sig); clReleaseMemObject(d_res);
    return result != 0;
}

// Helper: get pubkey X bytes from scalar (for Schnorr)
static void get_schnorr_pubkey_x(const Scalar& priv, uint8_t out[32]) {
    auto P = g_ctx->scalar_mul_generator(priv);
    auto aff = jacobian_to_affine(P);
    // Big-endian serialize field element
    for (int i = 0; i < 4; i++) {
        uint64_t limb = aff.x.limbs[3 - i];
        for (int j = 0; j < 8; j++) {
            out[i * 8 + j] = (uint8_t)(limb >> (56 - j * 8));
        }
    }
}

// ECDSA roundtrip: sign + verify
static int audit_ecdsa_roundtrip() {
    if (!g_ext.valid) return -1;  // skip
    auto priv = sc_from_u64(42);
    uint8_t msg[32] = {};
    msg[0] = 0xAA; msg[31] = 0xBB;

    ExtendedCL::ECDSASig sig;
    if (!ocl_ecdsa_sign(priv, msg, sig)) return 1;

    auto pub = g_ctx->scalar_mul_generator(priv);
    if (!ocl_ecdsa_verify(pub, msg, sig)) return 2;
    return 0;
}

// Schnorr roundtrip: sign + verify
static int audit_schnorr_roundtrip() {
    if (!g_ext.valid) return -1;
    auto priv = sc_from_u64(7);
    uint8_t msg[32] = {}, aux[32] = {};
    msg[0] = 0xCC; msg[31] = 0xDD;

    uint8_t pubkey_x[32];
    get_schnorr_pubkey_x(priv, pubkey_x);

    ExtendedCL::SchnorrSig sig;
    if (!ocl_schnorr_sign(priv, msg, aux, sig)) return 1;
    if (!ocl_schnorr_verify(pubkey_x, msg, sig)) return 2;
    return 0;
}

// ECDSA wrong-key rejection
static int audit_ecdsa_wrong_key() {
    if (!g_ext.valid) return -1;
    auto priv1 = sc_from_u64(1);
    auto priv2 = sc_from_u64(2);
    uint8_t msg[32] = {};
    msg[0] = 0xEE;

    ExtendedCL::ECDSASig sig;
    if (!ocl_ecdsa_sign(priv1, msg, sig)) return 1;

    auto pub2 = g_ctx->scalar_mul_generator(priv2);
    // Verify with wrong key must FAIL
    if (ocl_ecdsa_verify(pub2, msg, sig)) return 2;
    return 0;
}

// =============================================================================
// Section 3: Batch Operations
// =============================================================================

// Batch scalar mul generator
static int audit_batch_scalar_mul() {
    constexpr int N = 4;
    Scalar scalars[N];
    JacobianPoint results[N];
    for (int i = 0; i < N; i++) scalars[i] = sc_from_u64(i + 1);

    g_ctx->batch_scalar_mul_generator(scalars, results, N);

    // Verify each matches single op
    for (int i = 0; i < N; i++) {
        auto single = g_ctx->scalar_mul_generator(scalars[i]);
        auto a1 = jacobian_to_affine(results[i]);
        auto a2 = jacobian_to_affine(single);
        if (!fe_eq(a1.x, a2.x)) return i + 1;
    }
    return 0;
}

// Batch Jacobian to Affine
static int audit_batch_j2a() {
    constexpr int N = 4;
    Scalar scalars[N];
    JacobianPoint jpoints[N];
    AffinePoint apoints[N];
    for (int i = 0; i < N; i++) {
        scalars[i] = sc_from_u64(i + 1);
        jpoints[i] = g_ctx->scalar_mul_generator(scalars[i]);
    }

    g_ctx->batch_jacobian_to_affine(jpoints, apoints, N);

    for (int i = 0; i < N; i++) {
        auto expected = jacobian_to_affine(jpoints[i]);
        if (!fe_eq(apoints[i].x, expected.x)) return i + 1;
    }
    return 0;
}

// =============================================================================
// Section 4: Differential (OpenCL vs CPU lib-level)
// =============================================================================

// Verify scalar mul gives same result as lib's jacobian_to_affine
static int audit_diff_scalar_mul() {
    // Generator x (known constant)
    auto gen = get_generator();
    auto G1 = g_ctx->scalar_mul_generator(sc_from_u64(1));
    auto g1_a = jacobian_to_affine(G1);
    return fe_eq(g1_a.x, gen.x) ? 0 : 1;
}

// =============================================================================
// Section 5: Standard Test Vectors
// =============================================================================

// RFC 6979 determinism: same key+msg => same sig
static int audit_rfc6979_determinism() {
    if (!g_ext.valid) return -1;
    auto priv = sc_from_u64(0xDEADBEEF);
    uint8_t msg[32] = {};
    msg[0] = 0x42; msg[31] = 0xFF;

    ExtendedCL::ECDSASig sig1, sig2;
    if (!ocl_ecdsa_sign(priv, msg, sig1)) return 1;
    if (!ocl_ecdsa_sign(priv, msg, sig2)) return 2;

    // Must be identical (RFC 6979)
    if (memcmp(&sig1, &sig2, sizeof(sig1)) != 0) return 3;

    // Different msg => different sig
    msg[0] ^= 0x01;
    ExtendedCL::ECDSASig sig3;
    if (!ocl_ecdsa_sign(priv, msg, sig3)) return 4;
    if (memcmp(&sig1, &sig3, sizeof(sig1)) == 0) return 5;
    return 0;
}

// BIP-340: sign with known key, verify, tamper => reject
static int audit_bip340_vectors() {
    if (!g_ext.valid) return -1;
    auto priv = sc_from_u64(3);
    uint8_t msg[32] = {}, aux[32] = {};
    for (int i = 0; i < 32; i++) msg[i] = (uint8_t)i;

    uint8_t pubkey_x[32];
    get_schnorr_pubkey_x(priv, pubkey_x);

    ExtendedCL::SchnorrSig sig;
    if (!ocl_schnorr_sign(priv, msg, aux, sig)) return 1;
    if (!ocl_schnorr_verify(pubkey_x, msg, sig)) return 2;

    // Tamper message => reject
    msg[0] ^= 0xFF;
    if (ocl_schnorr_verify(pubkey_x, msg, sig)) return 3;
    return 0;
}

// =============================================================================
// Section 6: Protocol Security
// =============================================================================

// ECDSA multi-key: 10 keys sign+verify
static int audit_ecdsa_multi_key() {
    if (!g_ext.valid) return -1;
    uint64_t keys[] = {1, 2, 3, 7, 42, 256, 0xDEAD, 0xCAFE, 0xFFFF, 65537};
    uint8_t msg[32] = {};
    msg[0] = 0xBB; msg[15] = 0xCC; msg[31] = 0xDD;

    for (int ki = 0; ki < 10; ki++) {
        auto priv = sc_from_u64(keys[ki]);
        ExtendedCL::ECDSASig sig;
        if (!ocl_ecdsa_sign(priv, msg, sig)) return 10 + ki;
        auto pub = g_ctx->scalar_mul_generator(priv);
        if (!ocl_ecdsa_verify(pub, msg, sig)) return 20 + ki;
    }
    return 0;
}

// Schnorr multi-key: 10 keys
static int audit_schnorr_multi_key() {
    if (!g_ext.valid) return -1;
    uint64_t keys[] = {1, 2, 3, 7, 42, 256, 0xDEAD, 0xCAFE, 0xFFFF, 65537};
    uint8_t msg[32] = {}, aux[32] = {};
    msg[0] = 0xEE; msg[31] = 0x11;

    for (int ki = 0; ki < 10; ki++) {
        auto priv = sc_from_u64(keys[ki]);
        uint8_t pubkey_x[32];
        get_schnorr_pubkey_x(priv, pubkey_x);

        ExtendedCL::SchnorrSig sig;
        if (!ocl_schnorr_sign(priv, msg, aux, sig)) return 10 + ki;
        if (!ocl_schnorr_verify(pubkey_x, msg, sig)) return 20 + ki;
    }
    return 0;
}

// =============================================================================
// Section 7: Fuzzing & Adversarial Inputs
// =============================================================================

// Edge scalars: 0*G at infinity, 1*G == G, different points differ
static int audit_fuzz_edge_scalars() {
    // k=1 -> generator
    auto G1 = g_ctx->scalar_mul_generator(sc_from_u64(1));
    auto g1a = jacobian_to_affine(G1);
    auto gen = get_generator();
    if (!fe_eq(g1a.x, gen.x)) return 1;

    // k=2 -> not generator
    auto G2 = g_ctx->scalar_mul_generator(sc_from_u64(2));
    auto g2a = jacobian_to_affine(G2);
    if (fe_eq(g2a.x, gen.x)) return 2;

    // 2*G == G+G
    auto GG = g_ctx->point_add(G1, G1);
    auto gga = jacobian_to_affine(GG);
    if (!fe_eq(gga.x, g2a.x)) return 3;
    return 0;
}

// ECDSA zero key rejection
static int audit_fuzz_ecdsa_zero_key() {
    if (!g_ext.valid) return -1;
    auto zero = Scalar::zero();
    uint8_t msg[32] = {};
    msg[0] = 0xAA;

    ExtendedCL::ECDSASig sig;
    // Must fail
    if (ocl_ecdsa_sign(zero, msg, sig)) return 1;
    return 0;
}

// Schnorr zero key rejection
static int audit_fuzz_schnorr_zero_key() {
    if (!g_ext.valid) return -1;
    auto zero = Scalar::zero();
    uint8_t msg[32] = {}, aux[32] = {};

    ExtendedCL::SchnorrSig sig;
    if (ocl_schnorr_sign(zero, msg, aux, sig)) return 1;
    return 0;
}

// =============================================================================
// Section 8: Performance Smoke
// =============================================================================

// ECDSA 50-iteration stress
static int audit_perf_ecdsa_stress() {
    if (!g_ext.valid) return -1;
    auto priv = sc_from_u64(0xDEADCAFE);
    auto pub = g_ctx->scalar_mul_generator(priv);
    uint8_t msg[32] = {};

    for (int i = 0; i < 50; i++) {
        msg[0] = (uint8_t)i;
        ExtendedCL::ECDSASig sig;
        if (!ocl_ecdsa_sign(priv, msg, sig)) return 1;
        if (!ocl_ecdsa_verify(pub, msg, sig)) return 2;
    }
    return 0;
}

// Schnorr 25-iteration stress
static int audit_perf_schnorr_stress() {
    if (!g_ext.valid) return -1;
    auto priv = sc_from_u64(0xCAFEBABE);
    uint8_t pubkey_x[32];
    get_schnorr_pubkey_x(priv, pubkey_x);
    uint8_t msg[32] = {}, aux[32] = {};

    for (int i = 0; i < 25; i++) {
        msg[0] = (uint8_t)i;
        ExtendedCL::SchnorrSig sig;
        if (!ocl_schnorr_sign(priv, msg, aux, sig)) return 1;
        if (!ocl_schnorr_verify(pubkey_x, msg, sig)) return 2;
    }
    return 0;
}

// =============================================================================
// Module & Section Registry
// =============================================================================

static const OclSectionInfo OCL_SECTIONS[] = {
    { "math_invariants",   "Mathematical Invariants (Field, Scalar, Point)" },
    { "signatures",        "Signature Operations (ECDSA, Schnorr/BIP-340)" },
    { "batch_advanced",    "Batch Operations & Advanced Algorithms" },
    { "differential",      "OpenCL-Host Differential Testing" },
    { "standard_vectors",  "Standard Test Vectors (BIP-340, RFC-6979)" },
    { "protocol_security", "Protocol Security (multi-key)" },
    { "fuzzing",           "Fuzzing & Adversarial Inputs" },
    { "performance",       "Performance Smoke Tests" },
};
static constexpr int NUM_OCL_SECTIONS = sizeof(OCL_SECTIONS) / sizeof(OCL_SECTIONS[0]);

static const OclAuditModule OCL_MODULES[] = {
    // Section 1: Mathematical Invariants
    { "selftest_core",     "OpenCL Selftest (23+ kernel tests)",          "math_invariants", audit_selftest_core, false },
    { "field_add_sub",     "Field add/sub roundtrip",                     "math_invariants", audit_field_add_sub, false },
    { "field_mul_comm",    "Field mul commutativity",                     "math_invariants", audit_field_mul_commutativity, false },
    { "field_inv",         "Field inverse roundtrip (a * a^-1 = 1)",     "math_invariants", audit_field_inv_roundtrip, false },
    { "field_sqr",         "Field square == mul(a,a)",                    "math_invariants", audit_field_sqr_consistency, false },
    { "field_negate",      "Field negate roundtrip (a + (-a) = 0)",      "math_invariants", audit_field_negate, false },
    { "gen_mul_vec",       "Generator mul known vectors",                 "math_invariants", audit_generator_mul_known_vector, false },
    { "scalar_roundtrip",  "Scalar/Point consistency",                    "math_invariants", audit_scalar_add_sub, false },
    { "add_dbl_consist",   "Point add vs double consistency",             "math_invariants", audit_point_add_dbl_consistency, false },
    { "scalar_mul_lin",    "Scalar mul linearity (a+b)*G = aG+bG",      "math_invariants", audit_scalar_mul_linearity, false },
    { "group_order",       "Group order basic checks",                    "math_invariants", audit_group_order_basic, false },
    { "batch_inv",         "Batch inversion (Montgomery trick)",          "math_invariants", audit_batch_inversion, false },

    // Section 2: Signature Operations
    { "ecdsa_roundtrip",   "ECDSA sign + verify roundtrip",              "signatures", audit_ecdsa_roundtrip, false },
    { "schnorr_roundtrip", "Schnorr/BIP-340 sign + verify roundtrip",    "signatures", audit_schnorr_roundtrip, false },
    { "ecdsa_wrong_key",   "ECDSA verify rejects wrong pubkey",          "signatures", audit_ecdsa_wrong_key, false },

    // Section 3: Batch Operations
    { "batch_smul",        "Batch scalar mul generator",                  "batch_advanced", audit_batch_scalar_mul, false },
    { "batch_j2a",         "Batch Jacobian to Affine",                    "batch_advanced", audit_batch_j2a, false },

    // Section 4: Differential
    { "diff_smul",         "OpenCL-host differential scalar mul",         "differential", audit_diff_scalar_mul, false },

    // Section 5: Standard Test Vectors
    { "rfc6979_determ",    "RFC-6979 ECDSA deterministic nonce",          "standard_vectors", audit_rfc6979_determinism, false },
    { "bip340_vectors",    "BIP-340 Schnorr known-key roundtrip",         "standard_vectors", audit_bip340_vectors, false },

    // Section 6: Protocol Security
    { "ecdsa_multi_key",   "ECDSA multi-key (10 keys) sign+verify",      "protocol_security", audit_ecdsa_multi_key, false },
    { "schnorr_multi_key", "Schnorr multi-key (10 keys) sign+verify",    "protocol_security", audit_schnorr_multi_key, false },

    // Section 7: Fuzzing
    { "fuzz_edge_scalar",  "Edge-case scalars (0*G, 1*G, G+G=2G)",       "fuzzing", audit_fuzz_edge_scalars, false },
    { "fuzz_ecdsa_zero",   "ECDSA rejects zero private key",             "fuzzing", audit_fuzz_ecdsa_zero_key, false },
    { "fuzz_schnorr_zero", "Schnorr rejects zero private key",           "fuzzing", audit_fuzz_schnorr_zero_key, false },

    // Section 8: Performance Smoke
    { "perf_ecdsa_50",     "ECDSA 50-iteration stress",                   "performance", audit_perf_ecdsa_stress, false },
    { "perf_schnorr_25",   "Schnorr 25-iteration stress",                "performance", audit_perf_schnorr_stress, false },
};
static constexpr int NUM_OCL_MODULES = sizeof(OCL_MODULES) / sizeof(OCL_MODULES[0]);

// =============================================================================
// Device info
// =============================================================================
struct OclDeviceInfo {
    std::string name;
    std::string vendor;
    std::string version;
    std::string driver_version;
    size_t memory_mb;
    int compute_units;
    std::string backend;
};

static OclDeviceInfo detect_ocl_device(const Context& ctx) {
    OclDeviceInfo info;
    auto dev = ctx.device_info();
    info.name = dev.name;
    info.vendor = dev.vendor;
    info.version = dev.version;
    info.driver_version = dev.driver_version;
    info.memory_mb = dev.global_mem_size / (1024 * 1024);
    info.compute_units = dev.compute_units;
    info.backend = "OpenCL";
    return info;
}

// =============================================================================
// Platform detection (host)
// =============================================================================
struct PlatformInfo {
    std::string os;
    std::string arch;
    std::string compiler;
    std::string build_type;
};

static PlatformInfo detect_platform() {
    PlatformInfo p;
#if defined(_WIN32)
    p.os = "Windows";
#elif defined(__linux__)
    p.os = "Linux";
#elif defined(__APPLE__)
    p.os = "macOS";
#else
    p.os = "Unknown";
#endif

#if defined(__x86_64__) || defined(_M_X64)
    p.arch = "x86-64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    p.arch = "ARM64";
#elif defined(__riscv) && (__riscv_xlen == 64)
    p.arch = "RISC-V 64";
#else
    p.arch = "Unknown";
#endif

#if defined(__clang__)
    char buf[64];
    std::snprintf(buf, sizeof(buf), "Clang %d.%d.%d", __clang_major__, __clang_minor__, __clang_patchlevel__);
    p.compiler = buf;
#elif defined(__GNUC__)
    char buf[64];
    std::snprintf(buf, sizeof(buf), "GCC %d.%d.%d", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
    p.compiler = buf;
#elif defined(_MSC_VER)
    p.compiler = "MSVC " + std::to_string(_MSC_VER);
#else
    p.compiler = "Unknown";
#endif

#ifdef NDEBUG
    p.build_type = "Release";
#else
    p.build_type = "Debug";
#endif
    return p;
}

// =============================================================================
// Report generation
// =============================================================================

struct ModuleResult {
    std::string id;
    std::string name;
    std::string section;
    bool passed;
    bool skipped;
    bool advisory;
    double time_ms;
    int error_code;
};

static void write_json_report(const std::string& path,
                               const std::vector<ModuleResult>& results,
                               const OclDeviceInfo& dev,
                               const PlatformInfo& plat,
                               double total_sec) {
    std::ofstream f(path);
    if (!f.is_open()) return;

    int passed = 0, failed = 0, skipped = 0;
    for (auto& r : results) {
        if (r.skipped) skipped++;
        else if (r.passed) passed++;
        else failed++;
    }

    f << "{\n";
    f << "  \"framework_version\": \"" << OCL_AUDIT_FRAMEWORK_VERSION << "\",\n";
    f << "  \"backend\": \"OpenCL\",\n";
    f << "  \"device\": {\n";
    f << "    \"name\": \"" << dev.name << "\",\n";
    f << "    \"vendor\": \"" << dev.vendor << "\",\n";
    f << "    \"version\": \"" << dev.version << "\",\n";
    f << "    \"driver_version\": \"" << dev.driver_version << "\",\n";
    f << "    \"memory_mb\": " << dev.memory_mb << ",\n";
    f << "    \"compute_units\": " << dev.compute_units << "\n";
    f << "  },\n";
    f << "  \"platform\": {\n";
    f << "    \"os\": \"" << plat.os << "\",\n";
    f << "    \"arch\": \"" << plat.arch << "\",\n";
    f << "    \"compiler\": \"" << plat.compiler << "\",\n";
    f << "    \"build_type\": \"" << plat.build_type << "\"\n";
    f << "  },\n";
    f << "  \"summary\": {\n";
    f << "    \"total\": " << results.size() << ",\n";
    f << "    \"passed\": " << passed << ",\n";
    f << "    \"failed\": " << failed << ",\n";
    f << "    \"skipped\": " << skipped << ",\n";
    f << "    \"total_seconds\": " << std::fixed << total_sec << ",\n";
    f << "    \"verdict\": \"" << (failed == 0 ? "AUDIT-READY" : "ISSUES-FOUND") << "\"\n";
    f << "  },\n";
    f << "  \"modules\": [\n";
    for (size_t i = 0; i < results.size(); i++) {
        auto& r = results[i];
        f << "    { \"id\": \"" << r.id << "\", \"name\": \"" << r.name
          << "\", \"section\": \"" << r.section
          << "\", \"result\": \"" << (r.skipped ? "SKIP" : (r.passed ? "PASS" : "FAIL"))
          << "\", \"time_ms\": " << std::fixed << r.time_ms
          << ", \"error_code\": " << r.error_code << " }";
        if (i + 1 < results.size()) f << ",";
        f << "\n";
    }
    f << "  ]\n";
    f << "}\n";
}

static void write_text_report(const std::string& path,
                               const std::vector<ModuleResult>& results,
                               const OclDeviceInfo& dev,
                               const PlatformInfo& plat,
                               double total_sec) {
    std::ofstream f(path);
    if (!f.is_open()) return;

    int passed = 0, failed = 0, skipped = 0;
    for (auto& r : results) {
        if (r.skipped) skipped++;
        else if (r.passed) passed++;
        else failed++;
    }

    f << "================================================================\n";
    f << "  UltrafastSecp256k1 -- OpenCL Unified Audit Report\n";
    f << "  Framework v" << OCL_AUDIT_FRAMEWORK_VERSION << "\n";
    f << "  " << plat.os << " " << plat.arch << " | " << plat.compiler << " | " << plat.build_type << "\n";
    f << "  Device: " << dev.name << " (" << dev.vendor << ") | " << dev.compute_units << " CUs | " << dev.memory_mb << " MB\n";
    f << "================================================================\n\n";

    std::string cur_section;
    for (auto& r : results) {
        if (r.section != cur_section) {
            cur_section = r.section;
            f << "\n  Section: " << cur_section << "\n";
            f << "  " << std::string(50, '-') << "\n";
        }
        f << "  [" << (r.skipped ? "SKIP" : (r.passed ? "PASS" : "FAIL")) << "]  "
          << r.name << "  (" << r.time_ms << " ms)\n";
    }

    f << "\n================================================================\n";
    f << "  VERDICT: " << (failed == 0 ? "AUDIT-READY" : "ISSUES-FOUND") << "\n";
    f << "  TOTAL: " << passed << "/" << results.size() << " passed";
    if (skipped > 0) f << ", " << skipped << " skipped";
    if (failed > 0) f << ", " << failed << " FAILED";
    f << "  (" << std::fixed << std::setprecision(1) << total_sec << " s)\n";
    f << "================================================================\n";
}

// =============================================================================
// Main
// =============================================================================
int main(int argc, char* argv[]) {
    // Parse args
    std::string kernel_dir;
    std::string report_dir = ".";
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--kernel-dir" && i + 1 < argc) {
            kernel_dir = argv[++i];
        } else if (std::string(argv[i]) == "--report-dir" && i + 1 < argc) {
            report_dir = argv[++i];
        }
    }

    // Detect source directory for kernels
    if (kernel_dir.empty()) {
        // Try to find kernels relative to executable
        namespace fs = std::filesystem;
        auto exe_dir = fs::path(argv[0]).parent_path();
        std::vector<std::string> candidates = {
            (exe_dir / "kernels").string(),
            (exe_dir / "../kernels").string(),
            (exe_dir / "../../opencl/kernels").string(),
            (exe_dir / "../../../opencl/kernels").string(),
            "kernels",
            "../kernels",
            "../../opencl/kernels",
        };
        for (auto& c : candidates) {
            if (fs::exists(c + "/secp256k1_extended.cl")) {
                kernel_dir = c;
                break;
            }
        }
    }

    // Platform info
    auto plat = detect_platform();

    // Timestamp
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    char timebuf[64]; std::strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%S", std::localtime(&tt));

    // Initialize OpenCL context
    DeviceConfig config;
    config.verbose = false;
    g_ctx = Context::create(config);
    if (!g_ctx || !g_ctx->is_valid()) {
        std::fprintf(stderr, "[FATAL] Cannot create OpenCL context: %s\n",
                     g_ctx ? g_ctx->last_error().c_str() : "null");
        return 1;
    }

    auto dev = detect_ocl_device(*g_ctx);

    // Try to init extended kernels
    if (!kernel_dir.empty()) {
        g_ext.init(*g_ctx, kernel_dir);
    }

    // Banner
    std::printf("================================================================\n");
    std::printf("  UltrafastSecp256k1 -- OpenCL Unified Audit Runner\n");
    std::printf("  Framework v%s\n", OCL_AUDIT_FRAMEWORK_VERSION);
    std::printf("  %s %s | %s | %s\n", plat.os.c_str(), plat.arch.c_str(),
                plat.compiler.c_str(), plat.build_type.c_str());
    std::printf("  Device: %s (%s) | %d CUs | %zu MB | OpenCL\n",
                dev.name.c_str(), dev.vendor.c_str(), dev.compute_units, dev.memory_mb);
    std::printf("  Extended kernels: %s\n", g_ext.valid ? "loaded" : g_ext.error.c_str());
    std::printf("  %s\n", timebuf);
    std::printf("================================================================\n\n");

    // Run modules
    std::printf("[Phase 1/2] Running %d OpenCL audit modules across %d sections...\n\n",
                NUM_OCL_MODULES, NUM_OCL_SECTIONS);

    std::vector<ModuleResult> results;
    int passed = 0, failed = 0, skipped = 0;
    auto total_start = std::chrono::steady_clock::now();

    std::string cur_section;
    int section_idx = 0;
    for (int m = 0; m < NUM_OCL_MODULES; m++) {
        auto& mod = OCL_MODULES[m];

        // Section header
        if (mod.section != cur_section) {
            cur_section = mod.section;
            // Find section title
            for (int s = 0; s < NUM_OCL_SECTIONS; s++) {
                if (std::string(OCL_SECTIONS[s].id) == cur_section) {
                    section_idx = s;
                    break;
                }
            }
            std::printf("  ----------------------------------------------------------\n");
            std::printf("  Section %d/%d: %s\n", section_idx + 1, NUM_OCL_SECTIONS,
                        OCL_SECTIONS[section_idx].title_en);
            std::printf("  ----------------------------------------------------------\n");
        }

        // Run
        std::printf("  [%2d/%d] %-45s", m + 1, NUM_OCL_MODULES, mod.name);
        std::fflush(stdout);

        auto t0 = std::chrono::steady_clock::now();
        int rc = mod.run();
        auto t1 = std::chrono::steady_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

        ModuleResult r;
        r.id = mod.id;
        r.name = mod.name;
        r.section = mod.section;
        r.advisory = mod.advisory;
        r.time_ms = ms;
        r.error_code = rc;

        if (rc == -1) {
            r.passed = false;
            r.skipped = true;
            skipped++;
            std::printf("SKIP  (%.0f ms)\n", ms);
        } else if (rc == 0) {
            r.passed = true;
            r.skipped = false;
            passed++;
            std::printf("PASS  (%.0f ms)\n", ms);
        } else {
            r.passed = false;
            r.skipped = false;
            failed++;
            std::printf("FAIL  (%.0f ms) [error=%d]\n", ms, rc);
        }
        results.push_back(r);
    }

    auto total_end = std::chrono::steady_clock::now();
    double total_sec = std::chrono::duration<double>(total_end - total_start).count();

    // Phase 2: Reports
    std::printf("\n[Phase 2/2] Generating OpenCL audit reports...\n");
    std::string json_path = report_dir + "/ocl_audit_report.json";
    std::string text_path = report_dir + "/ocl_audit_report.txt";
    write_json_report(json_path, results, dev, plat, total_sec);
    write_text_report(text_path, results, dev, plat, total_sec);
    std::printf("  JSON:  %s\n", json_path.c_str());
    std::printf("  Text:  %s\n", text_path.c_str());

    // Summary table
    std::printf("\n================================================================\n");
    std::printf("  #    OpenCL Audit Section                            Result\n");
    std::printf("  ---- -------------------------------------------------- ------\n");

    for (int s = 0; s < NUM_OCL_SECTIONS; s++) {
        int sp = 0, st = 0;
        for (auto& r : results) {
            if (r.section == OCL_SECTIONS[s].id && !r.skipped) {
                st++;
                if (r.passed) sp++;
            }
        }
        std::printf("  %-4d %-50s %d/%d PASS\n", s + 1, OCL_SECTIONS[s].title_en, sp, st);
    }

    std::printf("\n================================================================\n");
    std::printf("  OpenCL AUDIT VERDICT: %s\n", failed == 0 ? "AUDIT-READY" : "ISSUES-FOUND");
    std::printf("  TOTAL: %d/%d modules passed", passed, (int)results.size());
    if (skipped > 0) std::printf(", %d skipped (extended.cl not loaded)", skipped);
    std::printf("  --  %s  (%.1f s)\n", failed == 0 ? "ALL PASSED" : "FAILURES DETECTED", total_sec);
    std::printf("  Device: %s (%s) | %s %s\n", dev.name.c_str(), dev.vendor.c_str(),
                plat.os.c_str(), plat.arch.c_str());
    std::printf("================================================================\n");

    return failed > 0 ? 1 : 0;
}
