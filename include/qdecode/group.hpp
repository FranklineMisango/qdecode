#pragma once

// qdecode - group.hpp
// ---------------------------------------------------------------------------
// Repeating-group iteration, the "hard part" of SBE. A group cannot use static
// offsets: the decoder must read the group header (blockLength + numInGroup),
// then stride through `numInGroup` occurrences each `blockLength` bytes, and
// finally skip the trailing variable-length data blocks.
//
// Zero allocation: the iterator holds only a pointer + length + remaining count
// and advances via pointer arithmetic. No vector, no heap, no linking with the
// standard library's containers.

#include <cstddef>
#include <cstdint>

#include "qdecode/buffer_view.hpp"
#include "qdecode/byte_order.hpp"

namespace qdecode {

// ---------------------------------------------------------------------------
// Standard SBE group header layout (big-endian):
//   offset  size  field
//   0       2     blockLength
//   2       2     numInGroup
//
// NOTE (CME MDP 3.0 divergence): MDP 3.0 uses a compact group header where the
// count is a single byte. That encoder is a thin layer on top of this class;
// the group iteration logic below is identical either way.
// ---------------------------------------------------------------------------
struct GroupHeader {
    std::uint16_t blockLength;
    std::uint16_t numInGroup;
};

/// Forward-only zero-copy iterator over the fixed entries of a repeating group.
template <typename EntryDecoder>
class GroupIterator {
public:
    GroupIterator() noexcept : remaining_(0) {}

    /// `entries` points at the first fixed entry (past the group header),
    /// `block_length` is the per-entry fixed block size, `num` is the count.
    GroupIterator(BufferView entries, std::uint16_t block_length,
                  std::uint16_t num) noexcept
        : cur_(entries), remaining_(num), block_length_(block_length) {}

    /// Parse the group header and position `input` right after it.
    /// Returns false if the header does not fit or claims more fixed bytes than
    /// `input` can hold.
    [[nodiscard]] static bool read_header(BufferView& input, GroupHeader& out) noexcept {
        if (input.size() < 4U) [[unlikely]]
            return false;
        out.blockLength = input.u16(0);
        out.numInGroup = input.u16(2);
        const std::size_t fixed = static_cast<std::size_t>(out.blockLength) *
                                  static_cast<std::size_t>(out.numInGroup);
        if (input.size() - 4U < fixed) [[unlikely]]
            return false;
        (void)input.skip(4U);
        return true;
    }

    [[nodiscard]] bool hasNext() const noexcept { return remaining_ > 0U; }
    [[nodiscard]] std::uint16_t remaining() const noexcept { return remaining_; }

    /// Build the next entry's decoder view (cheap: pointer arithmetic only).
    /// Must only be called when hasNext() is true.
    [[nodiscard]] EntryDecoder next() noexcept {
        EntryDecoder e(cur_);
        (void)cur_.skip(block_length_);
        if (remaining_ > 0U) [[likely]]
            --remaining_;
        return e;
    }

private:
    BufferView cur_;
    std::uint16_t remaining_;
    std::uint16_t block_length_;
};

/// Read a VarData block header (length)(2 bytes big-endian) and return a view
/// to the raw bytes that follow. Advances `input` past header + data.
/// Returns an empty view on malformed input (no allocation, no throw).
[[nodiscard]] inline BufferView read_var_data(BufferView& input) noexcept {
    if (input.size() < 2U) [[unlikely]]
        return BufferView();
    const std::uint16_t len = input.u16(0);
    if (static_cast<std::size_t>(len) > input.size() - 2U) [[unlikely]]
        return BufferView();
    BufferView bytes(input.data() + 2, len);
    (void)input.skip(2U + len);
    return bytes;
}

}  // namespace qdecode