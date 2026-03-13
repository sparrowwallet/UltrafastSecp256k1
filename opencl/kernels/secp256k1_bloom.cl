// =============================================================================
// secp256k1_bloom.cl -- Bloom Filter for OpenCL
// =============================================================================
// GPU-side bloom filter for candidate matching.
// Matches CUDA DeviceBloom semantics using FNV-1a + SplitMix64 hashing.
// =============================================================================

#ifndef SECP256K1_BLOOM_CL
#define SECP256K1_BLOOM_CL

// -- fast_reduce64: ((uint128)x * range) >> 64 equivalent ---------------------
inline ulong bloom_fast_reduce64(ulong x, ulong range) {
    // Emulate mul_hi(x, range) without __int128
    ulong x_lo = x & 0xFFFFFFFFUL;
    ulong x_hi = x >> 32;
    ulong r_lo = range & 0xFFFFFFFFUL;
    ulong r_hi = range >> 32;

    ulong t0 = x_lo * r_lo;
    ulong t1 = x_hi * r_lo;
    ulong t2 = x_lo * r_hi;
    ulong t3 = x_hi * r_hi;

    ulong mid = (t0 >> 32) + (t1 & 0xFFFFFFFFUL) + (t2 & 0xFFFFFFFFUL);
    ulong hi = t3 + (t1 >> 32) + (t2 >> 32) + (mid >> 32);
    return hi;
}

// -- FNV-1a 64-bit hash -------------------------------------------------------
inline ulong bloom_fnv1a64(const uchar* data, int len) {
    ulong h = 1469598103934665603UL;
    for (int i = 0; i < len; ++i) {
        h ^= (ulong)data[i];
        h *= 1099511628211UL;
    }
    return h;
}

// -- SplitMix64 ---------------------------------------------------------------
inline ulong bloom_splitmix64(ulong x) {
    x += 0x9e3779b97f4a7c15UL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9UL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebUL;
    x = x ^ (x >> 31);
    return x;
}

// -- Bloom filter test --------------------------------------------------------
inline int bloom_test_impl(__global const ulong* bitwords,
                            ulong m_bits, uint k, ulong salt,
                            const uchar* data, int len) {
    ulong h1 = bloom_fnv1a64(data, len);
    ulong h2 = bloom_splitmix64(h1 ^ salt) | 1UL;

    for (uint i = 0; i < k; ++i) {
        ulong idx = bloom_fast_reduce64(h1 + (ulong)i * h2, m_bits);
        ulong w = idx >> 6;
        ulong mask = 1UL << (idx & 63UL);
        if ((bitwords[w] & mask) == 0UL) return 0;
    }
    return 1;
}

// -- Bloom filter add (no atomics -- use for init only) -----------------------
inline void bloom_add_impl(__global ulong* bitwords,
                            ulong m_bits, uint k, ulong salt,
                            const uchar* data, int len) {
    ulong h1 = bloom_fnv1a64(data, len);
    ulong h2 = bloom_splitmix64(h1 ^ salt) | 1UL;

    for (uint i = 0; i < k; ++i) {
        ulong idx = bloom_fast_reduce64(h1 + (ulong)i * h2, m_bits);
        ulong w = idx >> 6;
        ulong mask = 1UL << (idx & 63UL);
        bitwords[w] |= mask;
    }
}

// -- Batch check kernel -------------------------------------------------------
__kernel void bloom_check_kernel(
    __global const ulong* bitwords,
    ulong m_bits,
    uint k,
    ulong salt,
    __global const uchar* data,
    int item_len,
    int count,
    __global uchar* results)
{
    int idx = get_global_id(0);
    if (idx >= count) return;

    uchar local_data[64]; // max item size
    int len = (item_len < 64) ? item_len : 64;
    for (int i = 0; i < len; ++i)
        local_data[i] = data[idx * item_len + i];

    results[idx] = (uchar)bloom_test_impl(bitwords, m_bits, k, salt, local_data, len);
}

// -- Batch add kernel ---------------------------------------------------------
__kernel void bloom_add_kernel(
    __global ulong* bitwords,
    ulong m_bits,
    uint k,
    ulong salt,
    __global const uchar* data,
    int item_len,
    int count)
{
    int idx = get_global_id(0);
    if (idx >= count) return;

    uchar local_data[64];
    int len = (item_len < 64) ? item_len : 64;
    for (int i = 0; i < len; ++i)
        local_data[i] = data[idx * item_len + i];

    bloom_add_impl(bitwords, m_bits, k, salt, local_data, len);
}

#endif // SECP256K1_BLOOM_CL
