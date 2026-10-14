#pragma once

// qdecode - mdp3_packet.hpp
// ---------------------------------------------------------------------------
// CME MDP 3.0 "Binary Packet Header" + per-message framing, byte-order aware.
//
// This is the framing layer that turns a UDP payload into a stream of SBE
// messages. The earlier `decode_pcap`/`scan_pcap` tools assumed an incorrect
// packet header (MsgSeqNum + MsgSize + flags then SBE at +8). The real CME
// MDP 3.0 wire layout is:
//
//   Binary Packet Header (12 bytes):
//     offset  size  field
//     0       4     MsgSeqNum       (uint32)
//     4       2     MsgSize         (uint16, length of this packet's message(s))
//     6       2     flags           (IsLast | IsFragmented bitmap, uint16)
//     8       4     SendingTime     (uint32, seconds since epoch)
//
//   then zero or more messages, each:
//     offset  size  field
//     0       2     MsgSize  (uint16, total length of the message INCLUDING
//                             this 2-byte preamble and the 8-byte SBE header)
//     2       8     SBE message header (blockLength/templateId/schemaId/version)
//     10      -     root block + groups (the SBE body)
//
// All fields above are stored in the feed's native byte order. Standard CME
// MDP 3.0 is big-endian; some redistributed captures (e.g. Databento's) are
// little-endian. The callers here detect the byte order from the wire and pass
// it down, so the same framing code serves both.
//
// The iteration helpers are zero-allocation: they hold only a pointer + a
// remaining length and advance with pointer arithmetic, mirroring qdecode's
// BufferView philosophy.

#include <cstddef>
#include <cstdint>

#include "qdecode/byte_order.hpp"

namespace qdecode {

/// One MDP 3.0 binary packet header (fixed 12 bytes on the wire).
struct Mdp3PacketHeaderWire {
    std::uint32_t msgSeqNum;
    std::uint16_t msgSize;      ///< total payload length in this packet
    std::uint16_t flags;        ///< IsLast | IsFragmented bitmap
    std::uint32_t sendingTime;  ///< seconds since epoch
};

/// Endianness of the MDP 3.0 feed (independent of the pcap container).
enum class ByteOrder { BigEndian, LittleEndian };

namespace detail {
// Read 16/32-bit using the feed's byte order.
inline std::uint16_t load_u16(const std::uint8_t* p, ByteOrder bo) noexcept {
    return bo == ByteOrder::BigEndian ? load_be16(p) : load_le16(p);
}
inline std::uint32_t load_u32(const std::uint8_t* p, ByteOrder bo) noexcept {
    return bo == ByteOrder::BigEndian ? load_be32(p) : load_le32(p);
}
inline std::uint64_t load_u64(const std::uint8_t* p, ByteOrder bo) noexcept {
    return bo == ByteOrder::BigEndian ? load_be64(p) : load_le64(p);
}
}  // namespace detail

/// Decode the 12-byte MDP 3.0 binary packet header. Returns false if the input
/// is shorter than the fixed header.
[[nodiscard]] inline bool decode_mdp3_packet_header(const std::uint8_t* data,
                                                     std::size_t size,
                                                     ByteOrder bo,
                                                     Mdp3PacketHeaderWire& out) noexcept {
    if (size < 12U) [[unlikely]]
        return false;
    out.msgSeqNum = detail::load_u32(data + 0, bo);
    out.msgSize = detail::load_u16(data + 4, bo);
    out.flags = detail::load_u16(data + 6, bo);
    out.sendingTime = detail::load_u32(data + 8, bo);
    return true;
}

/// A zero-copy iterator over the SBE messages inside one MDP 3.0 packet.
///
/// `payload` must point at the first message (i.e. just past the 12-byte packet
/// header), `size` is the number of bytes available after the header.
///
/// Each yielded message's `msg` view points at the 2-byte MsgSize preamble; the
/// 8-byte SBE header follows at +2. `message_size()` is the full length
/// (preamble + SBE header + body) and the iterator advances by exactly that,
/// mirroring CME MDP 3.0 and the reference decoder.
class Mdp3MessageIterator {
public:
    Mdp3MessageIterator() noexcept : cur_(nullptr), rem_(0), bo_(ByteOrder::BigEndian) {}

    Mdp3MessageIterator(const std::uint8_t* payload, std::size_t size,
                        ByteOrder bo) noexcept
        : cur_(payload), rem_(size), bo_(bo) {}

    [[nodiscard]] bool hasNext() const noexcept { return rem_ >= 10U; }

    /// Advance to the next message. Only valid when hasNext() is true; a
    /// malformed length stops iteration (hasNext() becomes false).
    void next() noexcept {
        const std::uint16_t sz = detail::load_u16(cur_, bo_);
        if (sz < 10U || static_cast<std::size_t>(sz) > rem_) {
            rem_ = 0;  // malformed; stop iterating
            return;
        }
        cur_ += sz;
        rem_ -= sz;
    }

    /// Total length of the current message (preamble + SBE header + body).
    [[nodiscard]] std::uint16_t message_size() const noexcept {
        return detail::load_u16(cur_, bo_);
    }
    /// 8-byte SBE header (blockLength/templateId/schemaId/version).
    [[nodiscard]] const std::uint8_t* sbe_header() const noexcept { return cur_ + 2U; }
    /// Point at the start of the current message (the MsgSize preamble).
    [[nodiscard]] const std::uint8_t* msg() const noexcept { return cur_; }

    /// Bytes remaining (preamble of the current message onward).
    [[nodiscard]] std::size_t remaining() const noexcept { return rem_; }

private:
    const std::uint8_t* cur_;
    std::size_t rem_;
    ByteOrder bo_;
};

}  // namespace qdecode