#pragma once

// qdecode - buffer_view.hpp
// ---------------------------------------------------------------------------
// A zero-copy, optionally bounds-checked view over the raw wire buffer.
//
// This is the foundation of the view pattern: the class holds ONLY a raw
// pointer and a length. No copies, no heap. All field readers walk the buffer
// via pointer arithmetic and explicit big-endian byte loads.
//
// Bounds checking is compiled out entirely unless QDECODE_ENABLE_BOUNDS_CHECK
// is defined (a correctness/debug mode). In the hot production path the checks
// are zero-cost. Every checked reader is marked [[likely]]/[[unlikely]] so the
// CPU branch predictor does not stall on the (rare) overrun paths.

#include <cstddef>
#include <cstdint>

#include "qdecode/byte_order.hpp"

namespace qdecode {

/// Controls whether bounds checks are emitted. Define QDECODE_ENABLE_BOUNDS_CHECK
/// to turn them on; keep undefined for the zero-overhead production build.
#ifndef QDECODE_ENABLE_BOUNDS_CHECK
#define QDECODE_ENABLE_BOUNDS_CHECK 0
#endif

class BufferView {
public:
    constexpr BufferView() noexcept : data_(nullptr), size_(0) {}
    constexpr BufferView(const std::uint8_t* data, std::size_t size) noexcept
        : data_(data), size_(size) {}

    constexpr const std::uint8_t* data() const noexcept { return data_; }
    constexpr std::size_t size() const noexcept { return size_; }
    constexpr bool empty() const noexcept { return size_ == 0; }

    /// Raw element pointer retrieval with optional bounds enforcement.
    constexpr const std::uint8_t* at(std::size_t offset) const noexcept {
#if QDECODE_ENABLE_BOUNDS_CHECK
        if (offset >= size_)
            return data_;  // pinned to base when OOB (defensive/debug only)
#endif
        return data_ + offset;
    }

    /// Advance the view origin. Returns true on success.
    [[nodiscard]] constexpr bool seek(std::size_t offset) noexcept {
        if (offset > size_)
            return false;
        data_ += offset;
        size_ -= offset;
        return true;
    }

    /// Advance the view origin by the given offset while the view is already
    /// positioned; requires the sub-view to fit. Returns true on success.
    [[nodiscard]] constexpr bool skip(std::size_t n) noexcept {
#if QDECODE_ENABLE_BOUNDS_CHECK
        if (n > size_)
            return false;
#else
        if (n > size_) [[unlikely]]
            return false;
#endif
        data_ += n;
        size_ -= n;
        return true;
    }

    /// Return a sub-view of `n` bytes starting at offset 0 of the current view.
    [[nodiscard]] constexpr BufferView subview(std::size_t n) const noexcept {
        BufferView out = *this;
        out.size_ = (n <= size_) ? n : size_;
        return out;
    }

    // --- Typed big-endian scalar readers, zero-allocation -------------------
    std::uint16_t u16(std::size_t off) const noexcept {
        return load_be16(at(off));
    }
    std::uint32_t u32(std::size_t off) const noexcept {
        return load_be32(at(off));
    }
    std::uint64_t u64(std::size_t off) const noexcept {
        return load_be64(at(off));
    }
    std::int16_t i16(std::size_t off) const noexcept {
        return load_be_i16(at(off));
    }
    std::int32_t i32(std::size_t off) const noexcept {
        return load_be_i32(at(off));
    }
    std::int64_t i64(std::size_t off) const noexcept {
        return load_be_i64(at(off));
    }
    std::uint8_t u8(std::size_t off) const noexcept { return at(off)[0]; }

    // --- Contiguous byte range accessors ------------------------------------
    /// Fixed-array reader; returns a view into the raw bytes (rename view).
    [[nodiscard]] constexpr BufferView bytes(std::size_t off,
                                             std::size_t n) const noexcept {
        BufferView v;
        v.data_ = at(off);
        v.size_ = (off + n <= size_) ? n : (size_ > off ? size_ - off : 0);
        return v;
    }

private:
    const std::uint8_t* data_;
    std::size_t size_;
};

}  // namespace qdecode