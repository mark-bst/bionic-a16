#pragma once

#ifndef __ORDER_LITTLE_ENDIAN__
    #error "Not little endian"
#endif

#define ATTR_HIDDEN       __attribute__((visibility("hidden")))

#define OBS_OBJ_TEXT(s)  ([] () __always_inline { constexpr auto obj = OBS_MAKE_OBJ(s); return obj.get_decrypt_data();}())
#define OBS_TMP_STR(s)   (OBS_OBJ_TEXT(s).str())
#define OBS_GLOB_STR(s)  ([] () __always_inline { constexpr auto obj = OBS_MAKE_OBJ(s); static auto obj1 = obj; \
    static auto obj2 = obj1.get_decrypt_data();  return obj2.str(); }())

// internal use:
#define OBS_MAKE_OBJ(s)  (obs_str::make_encrypt_data<__COUNTER__, __LINE__>(s))

namespace obs_str {

static inline constexpr uint32_t gnu_hash(const char* str)
{
    uint32_t r = 0x1505;
    while (*str) r += (r << 5) + static_cast<unsigned char>(*str++);
    return r;
}

static inline constexpr uint32_t get_default_seed(bool use_day = false)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdate-time"
    const char* str = use_day ? __DATE__ : __TIME__;
    constexpr auto seed = 131;
    uint32_t r = 0x1357;
    while (*str) r = r * seed + static_cast<unsigned char>(*str++);
    return r;
#pragma GCC diagnostic pop
}

template<unsigned N, uint32_t seed>
struct RandomNumber {
    static inline constexpr uint32_t xor_shift(uint32_t value) {
        constexpr uint32_t a = 15, b = 19;
        value ^= value << a;
        value ^= value >> b;
        return value;
    }
    static constexpr uint32_t value = xor_shift(RandomNumber<N - 1, seed>::value);
};

template<uint32_t seed>
struct RandomNumber<0, seed> {
    static constexpr uint32_t value = seed;
};

template<unsigned N, unsigned seed1, unsigned seed2, uint32_t default_seed = get_default_seed()>
class ATTR_HIDDEN  Encryptor {
    static_assert(N >= 2, "");
    static constexpr uint32_t s0 = default_seed  + seed2 * 9973u + seed1 * 37u;

    template<unsigned M>
    static constexpr uint32_t r = RandomNumber<M, s0>::value;

    static constexpr uint32_t key1 = r<5> | 1, key2 = r<2>, key3 = r<4>, key4 = (r<1> >> 2) | 1;

    static inline constexpr uint32_t act(uint32_t a, uint32_t b, uint32_t idx, const uint32_t(&keys)[2]) {
        constexpr auto f  = ((key1 ^ key3) >> 3);
        const auto key    = keys[(idx ^ f) & 1];
        return  key ^ (a + b);
    }
public:
    static constexpr void encrypt(uint32_t* data) {
        constexpr uint32_t keys[] = { key1, key2};
        uint32_t a = 0, b = data[N - 1];
        for (unsigned i = 0; i < N; ++i) {
            const unsigned idx = i + 1 < N ? i + 1 : 0;
            a        = data[idx];
            data[i] += act(a, b, i, keys);
            b        = data[i];
        }
    }

    static inline __always_inline void decrypt(uint32_t* data) {
        static_assert((key1  & 1) != 0, "");
        static_assert(((key1 ^ key4) & 1) == 0, "");

        static uint32_t k1 asm("k1") = key1 ^ key4;
        if ((k1 & 1) == 0) k1 ^= key4;

        const uint32_t keys[] = { k1, k1 ^ (key1 ^ key2) };
        uint32_t a = data[0], b = 0;
        for (unsigned i = N; i-- != 0; ) {
            const unsigned idx = i > 0 ? i - 1: N - 1;
            b        = data[idx];
            data[i] -= act(a, b, i, keys);
            a        = data[i];
        }
    }
};

template<unsigned dstlen, unsigned srclen>
static inline constexpr void copy_and_pad_to(uint32_t* dst, const char* src) {
    static_assert(4 * dstlen >= srclen && dstlen > 0, "");
    constexpr auto r = srclen % 4u;
    constexpr auto n = srclen / 4u;

    const char* p = src;
    for (unsigned i = 0; i < n; ++i, p += 4) {
        const unsigned char p0 = p[0], p1 = p[1], p2 = p[2], p3 = p[3];
        const uint32_t v = (p3 << 24) + (p2 << 16) + (p1 << 8) + p0;
        dst[i] = v;
    }

    if (r > 0) {
        uint32_t v = 0;
        for (unsigned i = 0; i < r; ++i) {
            const unsigned char ch = *p++;
            v += (ch << (i * 8));
        }
        dst[n]  = v;
    }
}

template<unsigned N, unsigned seed1, unsigned seed2>
class ATTR_HIDDEN DecryptData {
    unsigned    m_data[N];
public:
    DecryptData(const unsigned (&data)[N]) {
        for (unsigned i = 0; i < N; ++i) m_data[i] = data[i];
        Encryptor<N, seed1, seed2>::decrypt(m_data);
    }
    // ~DecryptData() { for (unsigned i = 0; i < N; ++i) m_data[i] = 0; }
    const char* str()  const { return data();}
    const char* data() const { return reinterpret_cast<const char*>(m_data);}
};

template<unsigned M, unsigned seed1, unsigned seed2, unsigned align = 16>
class ATTR_HIDDEN EryptData {
    static_assert(align == 4 || align == 8 || align == 16, "");
    enum        { N = (M + align- 1) / align * align / 4 };
    uint32_t    m_data[N] = {};
public:
    constexpr EryptData(const char(&arr)[M]) {
        copy_and_pad_to<N, M>(m_data, arr);
        Encryptor<N, seed1, seed2>::encrypt(m_data);
    }
    auto __always_inline get_decrypt_data() const { return DecryptData<N, seed1, seed2>(m_data);}
};

template<unsigned seed1, unsigned seed2, unsigned N>
static inline constexpr auto make_encrypt_data(const char(&arr)[N]) {
    return EryptData<N, seed1, seed2>(arr);
};

}
