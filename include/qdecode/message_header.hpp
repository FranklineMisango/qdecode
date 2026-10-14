#pragma once

// qdecode - message_header.hpp
// ---------------------------------------------------------------------------
// The standardized 8-byte SBE message header:
//
//   offset  size  field
//   0       2     blockLength  (root block length, big-endian)
//   2       2     templateId   (message type selector, big-endian)
//   4       2     schemaId     (schema selector, big-endian)
//   6       2     version      (schema version, big-endian)
//
// The decoder is a view: it does not own the buffer and allocates nothing.
//
// CME MDP 3.0 flattens this slightly (blockLength is the total block length and
// a compact numInGroup is used in group headers), but the 8-byte layout above is
// the canonical SBE preamble produced by all standard SBE generators, so we pin
// to it and document the MDP-3 divergence at the group layer.

#include <cstddef>
#include <cstdint>

#include "qdecode/buffer_view.hpp"
#include "qdecode/byte_order.hpp"

namespace qdecode {

/// Zero-copy view over an 8-byte SBE message header. sizeof == 8.
struct MessageHeaderWire {
    std::uint16_t blockLength;  ///< root block length in bytes
    std::uint16_t templateId;   ///< message template selector
    std::uint16_t schemaId;     ///< schema (namespace) selector
    std::uint16_t version;      ///< schema version
};

class MessageHeaderDecoder {
public:
    explicit MessageHeaderDecoder(BufferView msg) noexcept : msg_(msg) {}

    /// Decode the header and consume it, returning whether a full header fit.
    [[nodiscard]] bool decode(MessageHeaderWire& out) noexcept {
        if (msg_.size() < kSize) [[unlikely]]
            return false;
        out.blockLength = msg_.u16(kBlockLengthOffset);
        out.templateId = msg_.u16(kTemplateIdOffset);
        out.schemaId = msg_.u16(kSchemaIdOffset);
        out.version = msg_.u16(kVersionOffset);
        (void)msg_.skip(kSize);
        return true;
    }

    /// Zero-copy unaligned read of blockLength (no allocation, no memcpy of the
    /// whole header). Use `decode()` when you want all four fields at once.
    [[nodiscard]] std::uint16_t blockLength() const noexcept {
        return msg_.u16(kBlockLengthOffset);
    }
    [[nodiscard]] std::uint16_t templateId() const noexcept {
        return msg_.u16(kTemplateIdOffset);
    }
    [[nodiscard]] std::uint16_t schemaId() const noexcept {
        return msg_.u16(kSchemaIdOffset);
    }
    [[nodiscard]] std::uint16_t version() const noexcept {
        return msg_.u16(kVersionOffset);
    }

    /// The view positioned immediately after the header (start of root block).
    /// `decode()` has already advanced past the 8-byte header, so this simply
    /// returns the current view; no additional offset is applied.
    [[nodiscard]] BufferView root() const noexcept {
        return msg_;
    }

    static constexpr std::size_t kSize = 8U;
    static constexpr std::size_t kBlockLengthOffset = 0U;
    static constexpr std::size_t kTemplateIdOffset = 2U;
    static constexpr std::size_t kSchemaIdOffset = 4U;
    static constexpr std::size_t kVersionOffset = 6U;

private:
    BufferView msg_;
};

}  // namespace qdecode