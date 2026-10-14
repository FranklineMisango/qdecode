#pragma once

// qdecode - dbn.hpp
// ---------------------------------------------------------------------------
// Databento DBN v3 record definitions (MBO and friends).
//
// DBN (Databento Binary Encoding) is designed so that each `#[repr(C)]` record
// IS its wire representation: no parsing, no framing, no byte swaps (all fields
// little-endian / host-native). A decoder is just a `reinterpret_cast` over the
// mmap'd (or decompressed) byte stream followed by direct field loads — which is
// exactly what makes sub-nanosecond decode possible.
//
// Record sizes (verified against the DBN Rust source, record.rs):
//   MboMsg          56 (14 x 32-bit words)
//   TradeMsg        48
//   Mbp1Msg         80
//   Cmbp1Msg        80
//   Mbp10Msg        368
//   StatusMsg       40
//   InstrumentDefMsg  520
//
// File layout (v3):
//   bytes 0..3    magic "DBN\x03"
//   bytes 4..7    metadata-length (LE u32)   -> L
//   bytes 8..8+L  metadata body (symbol map, schema info)
//   byte 8+L      start of fixed-size records, contiguous to EOF
//
// Record header (common to all DBN records, 16 bytes):
//   offset size field
//   0      1    length      (record length in 32-bit words, e.g. 14 for MBO)
//   1      1    rtype       (record type; MBO = 0xA0)
//   2      2    publisher_id
//   4      4    instrument_id
//   8      8    ts_event     (nanoseconds since epoch)
//
// rtype       record class
//   0xA0      MboMsg   (market-by-order)
//
// All timestamps are nanoseconds since the UNIX epoch; prices are scaled by
// 1e-9 (1 unit = 0.000000001).

#include <cstddef>
#include <cstdint>

namespace qdecode {
namespace dbn {

/// rtype values (subset relevant to MBO captures).
/// 0xA0 = MboMsg (market-by-order). Full table in Databento's enums.rs.
namespace rtype {
constexpr std::uint8_t Mbo = 0xA0;
}  // namespace rtype

/// Common 16-byte DBN record header.
struct RecordHeader {
    std::uint8_t length;      ///< record length in 32-bit words
    std::uint8_t rtype;
    std::uint16_t publisher_id;
    std::uint32_t instrument_id;
    std::uint64_t ts_event;   ///< nanoseconds since epoch
};

/// Market-by-order record (rtype 0xA0). Exactly 56 bytes on the wire.
///
/// Field offsets verified against a real Databento capture: ts_recv sits at 40
/// (immediately after action/side) and the tail is ts_in_delta(48) sequence(52).
/// The DBN v3 `channel_id` is folded into the 16-bit flags word on this record.
struct MboMsg {
    RecordHeader hd;          //  0..15
    std::uint64_t order_id;   // 16..23
    std::int64_t price;       // 24..31  (1e-9 fixed point)
    std::uint32_t size;       // 32..35
    std::uint16_t flags;      // 36..37  (includes channel bits)
    char action;              // 38      'A'=add 'C'=cancel 'M'=modify ...
    char side;                // 39      'B'=bid 'A'=ask
    std::uint64_t ts_recv;    // 40..47
    std::int32_t ts_in_delta; // 48..51
    std::uint32_t sequence;   // 52..55
};
static_assert(sizeof(MboMsg) == 56, "MboMsg must be 56 bytes on the wire");

/// Locate the start of the record stream in a DBN v3 buffer.
/// Returns the offset, or 0 with records=0 if the buffer is not DBN v3.
inline std::size_t record_stream_offset(const std::uint8_t* data,
                                        std::size_t size,
                                        std::size_t& records) noexcept {
    records = 0;
    if (data == nullptr || size < 8) return 0;
    if (data[0] != 'D' || data[1] != 'B' || data[2] != 'N') return 0;
    const std::uint32_t meta_len =
        static_cast<std::uint32_t>(data[4]) |
        (static_cast<std::uint32_t>(data[5]) << 8) |
        (static_cast<std::uint32_t>(data[6]) << 16) |
        (static_cast<std::uint32_t>(data[7]) << 24);
    std::size_t begin = 8U + meta_len;
    if (begin >= size) return 0;
    records = (size - begin) / sizeof(MboMsg);
    return begin;
}

}  // namespace dbn
}  // namespace qdecode