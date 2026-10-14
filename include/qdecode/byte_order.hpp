#pragma once

// qdecode - byte_order.hpp
// ---------------------------------------------------------------------------
// Compile-time endianness detection and allocation-free byte-order helpers.
//
// IMPORTANT PRODUCTION CORRECTNESS NOTE:
// The SBE wire format is BIG-ENDIAN, regardless of the host architecture.
// Simply `reinterpret_cast<const uint64_t*>` (as a mock/toy parser would) reads
// in *host* byte order and produces garbage on the x86/ARM little-endian hosts
// that dominate HFT. Every raw scalar field must be byte-swapped when the host
// is little-endian. Doing so here as `constexpr`/`[[likely]]` free functions
// lets the optimizer fold the swaps away on big-endian hosts and inline them
// entirely on little-endian hosts.
//
// Zero allocation: no heap, no exception-driven paths in the hot path.

#include <cstddef>
#include <cstdint>

#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) &&                \
    (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define QDECODE_HOST_BIG_ENDIAN 1
#else
#define QDECODE_HOST_BIG_ENDIAN 0
#endif

namespace qdecode {

namespace detail {
// Compile-time reversible 16/32/64-bit swaps. Written unconditionally so the
// compiler can fold them to a single BSWAP instruction or zero on big-endian.
constexpr std::uint16_t bswap16(std::uint16_t v) noexcept {
    return static_cast<std::uint16_t>((v >> 8U) | (v << 8U));
}
constexpr std::uint32_t bswap32(std::uint32_t v) noexcept {
    return ((v & 0x000000FFU) << 24U) | ((v & 0x0000FF00U) << 8U) |
           ((v & 0x00FF0000U) >> 8U) | ((v & 0xFF000000U) >> 24U);
}
constexpr std::uint64_t bswap64(std::uint64_t v) noexcept {
    return ((v & 0x00000000000000FFULL) << 56U) |
           ((v & 0x000000000000FF00ULL) << 40U) |
           ((v & 0x0000000000FF0000ULL) << 24U) |
           ((v & 0x00000000FF000000ULL) << 8U) |
           ((v & 0x000000FF00000000ULL) >> 8U) |
           ((v & 0x0000FF0000000000ULL) >> 24U) |
           ((v & 0x00FF000000000000ULL) >> 40U) |
           ((v & 0xFF00000000000000ULL) >> 56U);
}
}  // namespace detail

// ---------------------------------------------------------------------------
// Big-endian loaded from a possibly-unaligned pointer.
// Reads via memcpy to remain safe on ARM (no unaligned load guarantees) yet
// noexcept and allocation-free; the compiler emits a single unaligned load.
// ---------------------------------------------------------------------------
inline std::uint16_t load_be16(const std::uint8_t* p) noexcept {
    std::uint16_t v;
    __builtin_memcpy(&v, p, sizeof(v));
#if QDECODE_HOST_BIG_ENDIAN
    return v;
#else
    return detail::bswap16(v);
#endif
}

inline std::uint32_t load_be32(const std::uint8_t* p) noexcept {
    std::uint32_t v;
    __builtin_memcpy(&v, p, sizeof(v));
#if QDECODE_HOST_BIG_ENDIAN
    return v;
#else
    return detail::bswap32(v);
#endif
}

inline std::uint64_t load_be64(const std::uint8_t* p) noexcept {
    std::uint64_t v;
    __builtin_memcpy(&v, p, sizeof(v));
#if QDECODE_HOST_BIG_ENDIAN
    return v;
#else
    return detail::bswap64(v);
#endif
}

// Signed big-endian loads (sign-extend as the stored host value).
inline std::int16_t load_be_i16(const std::uint8_t* p) noexcept {
    return static_cast<std::int16_t>(load_be16(p));
}
inline std::int32_t load_be_i32(const std::uint8_t* p) noexcept {
    return static_cast<std::int32_t>(load_be32(p));
}
inline std::int64_t load_be_i64(const std::uint8_t* p) noexcept {
    return static_cast<std::int64_t>(load_be64(p));
}

// ---------------------------------------------------------------------------
// Little-endian loads from a possibly-unaligned pointer. Used for container
// formats (e.g. a little-endian pcap) that store fields in LE byte order.
// Always safe on any host; no allocation, noexcept, folds to a single load.
// ---------------------------------------------------------------------------
inline std::uint16_t load_le16(const std::uint8_t* p) noexcept {
    std::uint16_t v;
    __builtin_memcpy(&v, p, sizeof(v));
#if QDECODE_HOST_BIG_ENDIAN
    return detail::bswap16(v);
#else
    return v;
#endif
}

inline std::uint32_t load_le32(const std::uint8_t* p) noexcept {
    std::uint32_t v;
    __builtin_memcpy(&v, p, sizeof(v));
#if QDECODE_HOST_BIG_ENDIAN
    return detail::bswap32(v);
#else
    return v;
#endif
}

inline std::uint64_t load_le64(const std::uint8_t* p) noexcept {
    std::uint64_t v;
    __builtin_memcpy(&v, p, sizeof(v));
#if QDECODE_HOST_BIG_ENDIAN
    return detail::bswap64(v);
#else
    return v;
#endif
}

// ---------------------------------------------------------------------------
// Big-endian store into a possibly-unaligned destination.
// ---------------------------------------------------------------------------
inline void store_be16(std::uint8_t* p, std::uint16_t v) noexcept {
    std::uint16_t s = v;
#if !QDECODE_HOST_BIG_ENDIAN
    s = detail::bswap16(s);
#endif
    __builtin_memcpy(p, &s, sizeof(s));
}
inline void store_be32(std::uint8_t* p, std::uint32_t v) noexcept {
    std::uint32_t s = v;
#if !QDECODE_HOST_BIG_ENDIAN
    s = detail::bswap32(s);
#endif
    __builtin_memcpy(p, &s, sizeof(s));
}
inline void store_be64(std::uint8_t* p, std::uint64_t v) noexcept {
    std::uint64_t s = v;
#if !QDECODE_HOST_BIG_ENDIAN
    s = detail::bswap64(s);
#endif
    __builtin_memcpy(p, &s, sizeof(s));
}

}  // namespace qdecode