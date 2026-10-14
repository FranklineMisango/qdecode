#pragma once

// qdecode - schema.hpp
// ---------------------------------------------------------------------------
// Hand-authored SBE message templates modelled on CME MDP 3.0. In a real
// pipeline these classes would be generated from the .xml SBE schema by the
// official SBE tool / sbepp. They are written here manually to be self-contained
// and dependency-free, but they follow the exact same zero-copy contract:
//
//   * each decoder is a view over the raw buffer (pointer + length only),
//   * every field offset is a compile-time constant,
//   * every field is read big-endian on demand (no copy, no heap),
//   * repeating groups are iterated with pointer arithmetic.
//
// Template IDs are the runtime router keys (the `templateId` field of the
// message header); the router switches on them with [[likely]] hints so the CPU
// branch predictor stays warm on the dominant message types.
//
// Schema constants (CME MDP 3.0 real template IDs from the CME SBE XML):
//   schemaId  = 0xABC1
//   template 32 = MDIncrementalRefreshBook32  (order-book depth / updates)
//   template 33 = MDIncrementalRefreshOrderBook32
//   template 34 = MDIncrementalRefreshTrade32 (executions / trades)
//   template 15 = SecurityDefinition

#include <cstddef>
#include <cstdint>

#include "qdecode/buffer_view.hpp"
#include "qdecode/group.hpp"
#include "qdecode/byte_order.hpp"
#include "qdecode/mdp3_packet.hpp"

namespace qdecode {
namespace schema {

/// CME MDP 3.0 Schema ID (constant across all MDP 3.0 message templates).
constexpr std::uint16_t kSchemaId = 0xABC1U;

// CME MDP 3.0 real template selectors (from the official CME SBE schema).
constexpr std::uint16_t kTmplSecurityDefinition = 15U;
constexpr std::uint16_t kTmplIncrementalRefreshBook32 = 32U;
constexpr std::uint16_t kTmplIncrementalRefreshOrderBook32 = 33U;
constexpr std::uint16_t kTmplIncrementalRefreshTrade32 = 34U;

// Additional real CME MDP 3.0 templates observed in Databento/CME captures
// (e.g. Data/pcap_data/db-samples.pcap).
constexpr std::uint16_t kTmplAdminHeartbeat = 12U;                 // AdminHeartbeat12
constexpr std::uint16_t kTmplIncrementalRefreshBook46 = 46U;       // MDIncrementalRefreshBook46
constexpr std::uint16_t kTmplInstrumentDefinitionFuture54 = 54U;   // MDInstrumentDefinitionFuture54
constexpr std::uint16_t kTmplInstrumentDefinitionFuture55 = 55U;   // MDInstrumentDefinitionFuture55
constexpr std::uint16_t kTmplInstrumentDefinitionSpread56 = 56U;   // MDInstrumentDefinitionSpread56

// Forward declaration so the group() helper can name the entry decoder before
// its definition below (the template member is only instantiated on use).
class BookEntryDecoder;


// ---------------------------------------------------------------------------
// MDIncrementalRefreshBook32  (CME MDP 3.0 templateId = 32)
//
// Root block (fixed fields as defined by the CME SBE XML):
//   offset  size  field
//   0       8     transactTime (uint64, nanoseconds since epoch)
//   8       1     matchEventIndicator (uint8 bitfield)
//   9       7     padding to 8-byte alignment
//   16      8     noOfUpdates (uint64)
//   24      2     noOfEntries (uint16, convenience counter for MBP)
//   26      2     noOfOrderBookEntries (uint16)   <-- added in MDP 3.1
//   28      4     padding
//   32      -     start of groups (NoMDEntries)
//
// Repeating group "NoMDEntries" (book depth levels / updates):
//   group header: blockLength(2) + numInGroup(2)
//   per-entry fixed block (blockLength bytes):
//     offset  size  field
//     0       4     price (int32 scaled by 10000 = 1e-4)
//     4       4     quantity (int32 scaled by 10000)
//     8       1     side (char 'B'/'A')
//     9       1     updateAction (char '0'/'1'/'2'/'3' = new/change/delete)
//     10      2     padding (align)
//     12      -     blockLength ends (12 bytes per entry)
// ---------------------------------------------------------------------------
class IncrementalRefreshBook32Decoder {
public:
    explicit IncrementalRefreshBook32Decoder(BufferView root) noexcept : root_(root) {}

    [[nodiscard]] std::uint64_t transactTime() const noexcept {
        return root_.u64(kTransactTimeOffset);
    }
    [[nodiscard]] std::uint8_t matchEventIndicator() const noexcept {
        return root_.u8(kMatchEventIndicatorOffset);
    }
    [[nodiscard]] std::uint64_t noOfUpdates() const noexcept {
        return root_.u64(kNoOfUpdatesOffset);
    }
    [[nodiscard]] std::uint16_t noOfEntries() const noexcept {
        return root_.u16(kNoOfEntriesOffset);
    }
    [[nodiscard]] std::uint16_t noOfOrderBookEntries() const noexcept {
        return root_.u16(kNoOfOrderBookEntriesOffset);
    }

    /// Parse the NoMDEntries group header. On success `out` holds the count and
    /// block length; caller iterates via GroupIterator<BookEntryDecoder>.
    [[nodiscard]] bool group(BufferView& cursor, GroupHeader& out) const noexcept {
        cursor = root_;
        (void)cursor.skip(kGroupsOffset);
        return GroupIterator<BookEntryDecoder>::read_header(cursor, out);
    }

    // Compile-time root offsets (CME MDP 3.0 MDIncrementalRefreshBook32).
    static constexpr std::size_t kTransactTimeOffset = 0U;
    static constexpr std::size_t kMatchEventIndicatorOffset = 8U;
    static constexpr std::size_t kNoOfUpdatesOffset = 16U;
    static constexpr std::size_t kNoOfEntriesOffset = 24U;
    static constexpr std::size_t kNoOfOrderBookEntriesOffset = 26U;
    static constexpr std::size_t kGroupsOffset = 32U;
    static constexpr std::uint16_t kRootBlockLength = kGroupsOffset;

private:
    BufferView root_;
};

/// One entry of the NoMDEntries group (fixed block only).
class BookEntryDecoder {
public:
    explicit BookEntryDecoder(BufferView e) noexcept : e_(e) {}

    [[nodiscard]] std::int32_t price() const noexcept { return e_.i32(kPriceOffset); }
    [[nodiscard]] std::int32_t quantity() const noexcept { return e_.i32(kQtyOffset); }
    [[nodiscard]] char side() const noexcept {
        return static_cast<char>(e_.u8(kSideOffset));
    }
    [[nodiscard]] char updateAction() const noexcept {
        return static_cast<char>(e_.u8(kActionOffset));
    }

    static constexpr std::size_t kPriceOffset = 0U;
    static constexpr std::size_t kQtyOffset = 4U;
    static constexpr std::size_t kSideOffset = 8U;
    static constexpr std::size_t kActionOffset = 9U;
    static constexpr std::uint16_t kBlockLength = 12U;

private:
    BufferView e_;
};


// ---------------------------------------------------------------------------
// MDIncrementalRefreshTrade32  (CME MDP 3.0 templateId = 34)
//
// Root block (CME MDP 3.0 MDIncrementalRefreshTrade32):
//   offset  size  field
//   0       8     transactTime (uint64)
//   8       1     matchEventIndicator (uint8)
//   9       7     padding
//   16      8     tradeId (uint64)
//   24      8     price (int64 scaled by 1e-4)
//   32      8     quantity (int64 scaled by 1e-4)
//   40      4     securityId (int32)
//   44      1     aggressorSide (char 'B'/'S')
//   45      1     tradeCondition (char)
//   46      2     padding
//   48      4     mdEntryPx (int32, scaled by 1e-4)
//   52      4     mdEntrySize (int32, scaled)
//   56      8     padding
//   64      -     start of groups / VarData (symbol etc.)
// ---------------------------------------------------------------------------
class TradeCapture32Decoder {
public:
    explicit TradeCapture32Decoder(BufferView root) noexcept : root_(root) {}

    [[nodiscard]] std::uint64_t transactTime() const noexcept {
        return root_.u64(kTransactTimeOffset);
    }
    [[nodiscard]] std::uint8_t matchEventIndicator() const noexcept {
        return root_.u8(kMatchEventIndicatorOffset);
    }
    [[nodiscard]] std::uint64_t tradeId() const noexcept {
        return root_.u64(kTradeIdOffset);
    }
    [[nodiscard]] std::int64_t price() const noexcept { return root_.i64(kPriceOffset); }
    [[nodiscard]] std::int64_t quantity() const noexcept { return root_.i64(kQtyOffset); }
    [[nodiscard]] std::int32_t securityId() const noexcept {
        return root_.i32(kSecurityIdOffset);
    }
    [[nodiscard]] char aggressorSide() const noexcept {
        return static_cast<char>(root_.u8(kSideOffset));
    }

    /// Read the trailing symbol VarData (at the VarData offset).
    [[nodiscard]] BufferView symbol() const noexcept {
        BufferView cursor = root_;
        (void)cursor.skip(kVarDataOffset);
        return read_var_data(cursor);
    }

    static constexpr std::size_t kTransactTimeOffset = 0U;
    static constexpr std::size_t kMatchEventIndicatorOffset = 8U;
    static constexpr std::size_t kTradeIdOffset = 16U;
    static constexpr std::size_t kPriceOffset = 24U;
    static constexpr std::size_t kQtyOffset = 32U;
    static constexpr std::size_t kSecurityIdOffset = 40U;
    static constexpr std::size_t kSideOffset = 44U;
    static constexpr std::size_t kVarDataOffset = 64U;
    static constexpr std::uint16_t kRootBlockLength = kVarDataOffset;

private:
    BufferView root_;
};

// ---------------------------------------------------------------------------
// MDIncrementalRefreshBook46  (CME MDP 3.0 templateId = 46)
//
// The real MBP/MBO market-data message found in Databento/CME captures. Root
// block offsets verified against Data/pcap_data/db-samples.pcap:
//   offset  size  field
//   0       8     transactTime (uint64, nanoseconds since epoch)
//   8       1     matchEventIndicator (uint8 bitfield)
//   9       n     padding to blockLength
//   blockLength   compact group header + NoMDEntries entries follow
//
// Reads fields in the feed's byte order (standard MDP3 is big-endian; a
// little-endian capture such as db-samples.pcap is handled by passing
// ByteOrder::LittleEndian).
// ---------------------------------------------------------------------------
class IncrementalRefreshBook46Decoder {
public:
    IncrementalRefreshBook46Decoder(BufferView root, ByteOrder bo) noexcept
        : root_(root), bo_(bo) {}

    [[nodiscard]] std::uint64_t transactTime() const noexcept {
        return detail::load_u64(root_.data() + kTransactTimeOffset, bo_);
    }
    [[nodiscard]] std::uint8_t matchEventIndicator() const noexcept {
        return root_.at(kMatchEventIndicatorOffset)[0];
    }

    static constexpr std::size_t kTransactTimeOffset = 0U;
    static constexpr std::size_t kMatchEventIndicatorOffset = 8U;
    static constexpr std::uint16_t kRootBlockLength = 11U;  // observed in db-samples.pcap

private:
    BufferView root_;
    ByteOrder bo_;
};

// ---------------------------------------------------------------------------
// MDInstrumentDefinitionFuture55  (CME MDP 3.0 templateId = 55)
//
// The dominant message in db-samples.pcap (an instrument-reference feed). Root
// block (blockLength 213) field offsets verified against the real capture:
//   offset  size  field
//   0       8     transactTime (uint64, nanoseconds since epoch)
//   19      6     securityExchange (char[6], e.g. "XCMEC0")
//   35      20    symbol (char[20], e.g. "CBJ5 P2100")
//   213     -     times/legs groups follow (not decoded here)
//
// The full CME MDInstrumentDefinitionFuture root also carries securityID,
// currency, securityGroup, maturityDate, etc. at fixed offsets; only the
// offsets that were verified against real bytes are exposed, to avoid guessing.
// ---------------------------------------------------------------------------
class InstrumentDefinitionFuture55Decoder {
public:
    InstrumentDefinitionFuture55Decoder(BufferView root, ByteOrder bo) noexcept
        : root_(root), bo_(bo) {}

    [[nodiscard]] std::uint64_t transactTime() const noexcept {
        return detail::load_u64(root_.data() + kTransactTimeOffset, bo_);
    }
    /// securityExchange (fixed 6-char array), e.g. "XCMEC0".
    [[nodiscard]] const std::uint8_t* securityExchange() const noexcept {
        return root_.at(kSecurityExchangeOffset);
    }
    /// symbol (fixed 20-char array), e.g. "CBJ5 P2100".
    [[nodiscard]] const std::uint8_t* symbol() const noexcept {
        return root_.at(kSymbolOffset);
    }

    static constexpr std::size_t kTransactTimeOffset = 0U;
    static constexpr std::size_t kSecurityExchangeOffset = 19U;
    static constexpr std::size_t kSymbolOffset = 35U;
    static constexpr std::uint16_t kRootBlockLength = 213U;  // observed in db-samples.pcap

private:
    BufferView root_;
    ByteOrder bo_;
};

}  // namespace schema
}  // namespace qdecode

