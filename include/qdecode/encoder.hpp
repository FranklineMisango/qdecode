#pragma once

// qdecode - encoder.hpp
// ---------------------------------------------------------------------------
// Allocation-free big-endian SBE encoder. Used to build self-validating wire
// fixtures and, in production, to encode outbound SBE messages into a reusable
// ring buffer. It does NOT own the buffer: the caller provides a writable span
// and the encoder advances a cursor with pointer arithmetic.
//
// The decoder/test harness relies on this encoder to prove the wire format
// round-trips exactly (byte-for-byte) through the zero-copy view decoders.

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "qdecode/byte_order.hpp"

namespace qdecode {

/// Zero-allocation big-endian writer over a caller-owned writable buffer.
class SbeEncoder {
public:
    explicit SbeEncoder(std::uint8_t* buf, std::size_t capacity) noexcept
        : buf_(buf), cap_(capacity), pos_(0) {}

    /// Reset the cursor for a fresh message.
    void reset() noexcept { pos_ = 0; }
    [[nodiscard]] std::size_t size() const noexcept { return pos_; }
    [[nodiscard]] bool can_write(std::size_t n) const noexcept { return pos_ + n <= cap_; }

    // --- big-endian scalar stores ------------------------------------------
    [[nodiscard]] bool u16(std::uint16_t v) noexcept { return store(0, v); }
    [[nodiscard]] bool u32(std::uint32_t v) noexcept { return store(0, v); }
    [[nodiscard]] bool u64(std::uint64_t v) noexcept { return store(0, v); }
    [[nodiscard]] bool i16(std::int16_t v) noexcept { return u16(static_cast<std::uint16_t>(v)); }
    [[nodiscard]] bool i32(std::int32_t v) noexcept { return u32(static_cast<std::uint32_t>(v)); }
    [[nodiscard]] bool i64(std::int64_t v) noexcept { return u64(static_cast<std::uint64_t>(v)); }
    [[nodiscard]] bool u8(std::uint8_t v) noexcept {
        return store_bytes(&v, 1);
    }

    /// Write `n` raw bytes (padding, fixed arrays).
    [[nodiscard]] bool raw(const std::uint8_t* src, std::size_t n) noexcept {
        return store_bytes(src, n);
    }
    /// Zero-fill `n` bytes (padding fields).
    [[nodiscard]] bool pad(std::size_t n) noexcept {
        static const std::uint8_t zero = 0;
        for (std::size_t i = 0; i < n; ++i)
            if (!store_bytes(&zero, 1)) return false;
        return true;
    }

private:
    template <typename T>
    [[nodiscard]] bool store(std::size_t, T v) noexcept {
        if (!can_write(sizeof(T))) [[unlikely]]
            return false;
        store_be(&buf_[pos_], v);
        pos_ += sizeof(T);
        return true;
    }

    template <typename T>
    void store_be(std::uint8_t* p, T v) noexcept {
        if constexpr (sizeof(T) == 1) {
            *p = static_cast<std::uint8_t>(v);
        } else if constexpr (sizeof(T) == 2) {
            store_be16(p, static_cast<std::uint16_t>(v));
        } else if constexpr (sizeof(T) == 4) {
            store_be32(p, static_cast<std::uint32_t>(v));
        } else {
            store_be64(p, static_cast<std::uint64_t>(v));
        }
    }

    [[nodiscard]] bool store_bytes(const std::uint8_t* src, std::size_t n) noexcept {
        if (!can_write(n)) [[unlikely]]
            return false;
        if (n != 0) __builtin_memcpy(buf_ + pos_, src, n);
        pos_ += n;
        return true;
    }

    std::uint8_t* buf_;
    std::size_t cap_;
    std::size_t pos_;
};

}  // namespace qdecode