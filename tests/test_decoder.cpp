// qdecode - test_decoder.cpp
// ---------------------------------------------------------------------------
// Round-trip validation of the zero-copy SBE decoder. Uses only the real
// components (encoder -> wire buffer -> decoder view) — no mocks, no stubs.
//
// Build with:
//   c++ -std=c++20 -O2 -Iinclude -Isrc test_decoder.cpp src/pcap.cpp -o test

#include <cassert>
#include <cstdio>
#include <cstring>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "qdecode/byte_order.hpp"
#include "qdecode/buffer_view.hpp"
#include "qdecode/message_header.hpp"
#include "qdecode/group.hpp"
#include "qdecode/schema.hpp"
#include "qdecode/router.hpp"
#include "qdecode/encoder.hpp"
#include "qdecode/pcap.hpp"
#include "qdecode/mdp3_packet.hpp"
#include "qdecode/dbn.hpp"

using namespace qdecode;

namespace {

int failures = 0;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "CHECK FAILED %s:%d: %s\n", __FILE__,  \
                         __LINE__, #cond);                               \
            ++failures;                                                  \
        }                                                                \
    } while (0)

// ---------------------------------------------------------------------------
// Build a single MDIncrementalRefreshBook32 message with `n` depth entries.
// Layout: 8-byte header, 32-byte root, group header(4), n*12 entry bytes.
// Returns message size written, or 0 on overflow.
// ---------------------------------------------------------------------------
std::size_t build_book32(std::uint8_t* buf, std::size_t cap, std::uint16_t n,
                         std::uint64_t transact_time) {
    SbeEncoder e(buf, cap);
    // SBE message header.
    CHECK(e.u16(schema::IncrementalRefreshBook32Decoder::kRootBlockLength)); // 32
    CHECK(e.u16(schema::kTmplIncrementalRefreshBook32));
    CHECK(e.u16(schema::kSchemaId));
    CHECK(e.u16(0));                       // version
    // Root block.
    CHECK(e.u64(transact_time));           // transactTime @0
    CHECK(e.u8(0x1A));                     // matchEventIndicator @8
    CHECK(e.pad(7));                       // padding @9..15
    CHECK(e.u64(n));                       // noOfUpdates @16
    CHECK(e.u16(n));                       // noOfEntries @24
    CHECK(e.u16(0));                       // noOfOrderBookEntries @26
    CHECK(e.pad(4));                       // padding @28..31
    // Group: NoMDEntries
    CHECK(e.u16(schema::BookEntryDecoder::kBlockLength));  // blockLength = 12
    CHECK(e.u16(n));                               // numInGroup
    for (std::uint16_t i = 0; i < n; ++i) {
        CHECK(e.i32(10000 + i * 100));     // price @0
        CHECK(e.i32(100 + i));             // quantity @4
        CHECK(e.u8((i % 2) ? 'A' : 'B'));  // side @8
        CHECK(e.u8((i % 3) ? '1' : '0'));  // action @9
        CHECK(e.pad(2));                   // padding @10..11
    }
    return e.size();
}

// ---------------------------------------------------------------------------
// Build a single MDIncrementalRefreshTrade32 message with a symbol VarData.
// ---------------------------------------------------------------------------
std::size_t build_trade32(std::uint8_t* buf, std::size_t cap, std::uint64_t trade_id,
                          std::int64_t price, std::int64_t qty, const char* symbol) {
    SbeEncoder e(buf, cap);
    CHECK(e.u16(schema::TradeCapture32Decoder::kRootBlockLength));  // 64
    CHECK(e.u16(schema::kTmplIncrementalRefreshTrade32));
    CHECK(e.u16(schema::kSchemaId));
    CHECK(e.u16(0));
    CHECK(e.u64(1234567890));              // transactTime @0
    CHECK(e.u8(0));                        // matchEventIndicator @8
    CHECK(e.pad(7));                       // padding @9..15
    CHECK(e.u64(trade_id));                // tradeId @16
    CHECK(e.i64(price));                   // price @24
    CHECK(e.i64(qty));                     // quantity @32
    CHECK(e.i32(123456));                  // securityId @40
    CHECK(e.u8('S'));                      // aggressorSide @44
    CHECK(e.u8(0));                        // tradeCondition @45
    CHECK(e.pad(2));                       // padding @46..47
    CHECK(e.pad(16));                      // padding @48..63
    const std::size_t slen = std::strlen(symbol);
    CHECK(e.u16(static_cast<std::uint16_t>(slen)));  // VarData length
    CHECK(e.raw(reinterpret_cast<const std::uint8_t*>(symbol), slen));
    return e.size();
}

}  // namespace

int main() {
    std::uint8_t buf[1024];
    std::memset(buf, 0, sizeof(buf));


    // ---- Test 1: incremental book round-trip -------------------------------
    const std::uint64_t tt = 1234567890123456789ULL;
    const std::size_t nmsg = build_book32(buf, sizeof(buf), 4, tt);
    CHECK(nmsg > 0);

    // The message size: 8 (header) + 32 (root) + 4 (group header) + 4*12 = 92
    CHECK(nmsg == 92);

    BufferView msg(buf, nmsg);
    RouteResult r = route(msg);
    CHECK(r.valid);
    CHECK(r.schema_match);
    CHECK(r.header.templateId == schema::kTmplIncrementalRefreshBook32);
    CHECK(r.header.schemaId == schema::kSchemaId);
    CHECK(r.header.blockLength == schema::IncrementalRefreshBook32Decoder::kRootBlockLength);

    schema::IncrementalRefreshBook32Decoder book(r.root);
    CHECK(book.transactTime() == tt);
    CHECK(book.noOfUpdates() == 4);
    CHECK(book.noOfEntries() == 4);
    CHECK(book.matchEventIndicator() == 0x1A);

    // Iterate the repeating group.
    BufferView cursor = r.root;
    GroupHeader gh{};
    CHECK(book.group(cursor, gh));
    CHECK(gh.numInGroup == 4);
    CHECK(gh.blockLength == schema::BookEntryDecoder::kBlockLength);

    GroupIterator<schema::BookEntryDecoder> it(cursor, gh.blockLength, gh.numInGroup);
    std::size_t seen = 0;
    while (it.hasNext()) {
        auto entry = it.next();
        CHECK(entry.price() == 10000 + static_cast<std::int32_t>(seen) * 100);
        CHECK(entry.quantity() == 100 + static_cast<std::int32_t>(seen));
        CHECK(entry.side() == ((seen % 2) ? 'A' : 'B'));
        CHECK(entry.updateAction() == ((seen % 3) ? '1' : '0'));
        ++seen;
    }
    CHECK(seen == 4);

    // ---- Test 2: trade capture round-trip + VarData ------------------------
    std::uint8_t tbuf[512];
    std::memset(tbuf, 0, sizeof(tbuf));
    const std::size_t ntr = build_trade32(tbuf, sizeof(tbuf), 9001, 1234567, 5000, "ESH6");
    CHECK(ntr > 0);

    RouteResult rt = route(BufferView(tbuf, ntr));
    CHECK(rt.valid);
    CHECK(rt.header.templateId == schema::kTmplIncrementalRefreshTrade32);

    schema::TradeCapture32Decoder trade(rt.root);
    CHECK(trade.tradeId() == 9001);
    CHECK(trade.price() == 1234567);
    CHECK(trade.quantity() == 5000);
    CHECK(trade.aggressorSide() == 'S');

    BufferView sym = trade.symbol();
    CHECK(sym.size() == 4);
    CHECK(std::memcmp(sym.data(), "ESH6", 4) == 0);

    // ---- Test 3: truncated header is rejected -------------------------------
    {
        RouteResult bad = route(BufferView(buf, 4));  // only 4 of 8 header bytes
        CHECK(!bad.valid);
    }

    // ---- Test 4: malformed group (claims more than fits) rejected -----------
    {
        // Header + root that claims 1000 entries but buffer holds none.
        SbeEncoder e(buf, sizeof(buf));
        CHECK(e.u16(schema::IncrementalRefreshBook32Decoder::kRootBlockLength));
        CHECK(e.u16(schema::kTmplIncrementalRefreshBook32));
        CHECK(e.u16(schema::kSchemaId));
        CHECK(e.u16(0));
        CHECK(e.u64(1));
        CHECK(e.u8(0));
        CHECK(e.pad(7));
        CHECK(e.u64(0));
        CHECK(e.u16(0));   // noOfEntries
        CHECK(e.u16(0));   // noOfOrderBookEntries
        CHECK(e.pad(4));   // padding
        CHECK(e.u16(schema::BookEntryDecoder::kBlockLength));
        CHECK(e.u16(1000));  // absurd count
        // No entry bytes follow.

        RouteResult r2 = route(BufferView(buf, e.size()));
        CHECK(r2.valid);
        schema::IncrementalRefreshBook32Decoder b2(r2.root);
        BufferView cur = r2.root;
        GroupHeader gh2{};
        // read_header must fail because fixed size (1000*12) exceeds buffer.
        CHECK(!b2.group(cur, gh2));
    }


    // ---- Test 5: pcap reader (mmap a synthetic capture) --------------------
    {
        const char* path = "/tmp/qdecode_test.pcap";
        // 24-byte global header + one 16-byte record header + payload.
        // Payload must fit a 1-entry book32 message (8+32+4+12=56 bytes).
        std::uint8_t pcap[24 + 16 + 64];
        std::memset(pcap, 0, sizeof(pcap));
        store_be32(pcap + 0, 0xA1B2C3D4U);  // big-endian magic
        store_be16(pcap + 4, 2);            // version 2.4
        store_be16(pcap + 6, 4);
        store_be32(pcap + 16, 65535);       // snaplen
        store_be32(pcap + 20, 1);           // ethernet
        store_be32(pcap + 24, 1600000000);  // ts_sec
        store_be32(pcap + 28, 42);          // ts_usec
        // Build the SBE book32 message (1 entry) as the packet payload first.
        const std::size_t n = build_book32(pcap + 40, 64, 1, 999);
        CHECK(n == 56);
        store_be32(pcap + 32, static_cast<std::uint32_t>(n));  // incl_len
        store_be32(pcap + 36, static_cast<std::uint32_t>(n));  // orig_len

        const int fd = ::open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
        CHECK(fd >= 0);
        // Write only the used bytes: 24-byte global header + record(16) + payload.
        const std::size_t file_len = 24U + 16U + n;
        CHECK(::write(fd, pcap, file_len) == (ssize_t)file_len);
        ::close(fd);

        PcapFile pf;
        CHECK(pf.open_mmap(path));
        PcapView pv = pf.view();
        CHECK(pv.validate());

        std::uint64_t sec = 0, usec = 0;
        const std::uint8_t* payload = nullptr;
        std::size_t plen = 0;
        CHECK(pv.next_packet(sec, usec, &payload, plen));
        CHECK(sec == 1600000000);
        CHECK(usec == 42);
        CHECK(plen == n);

        RouteResult rp = route(BufferView(payload, plen));
        CHECK(rp.valid);
        schema::IncrementalRefreshBook32Decoder pb(rp.root);
        CHECK(pb.transactTime() == 999);
        BufferView pc = rp.root;
        GroupHeader pgh{};
        CHECK(pb.group(pc, pgh));
        CHECK(pgh.numInGroup == 1);

        // Second call must hit EOF.
        CHECK(!pv.next_packet(sec, usec, &payload, plen));
        ::unlink(path);
    }

    // ---- Test 6: byte-order helpers round-trip -----------------------------
    {
        std::uint8_t b[8];
        store_be64(b, 0x0102030405060708ULL);
        CHECK(b[0] == 0x01);  // most-significant byte first on the wire
        CHECK(load_be64(b) == 0x0102030405060708ULL);
    }

    // ---- Test 7: MDP 3.0 framing + little-endian decoders ------------------
    {
        // Build a synthetic UDP payload exactly matching the wire layout in
        // db-samples.pcap (12-byte binary packet header + one message whose
        // 2-byte MsgSize preamble counts the whole message).
        //
        // Layout (little-endian, as in the Databento capture):
        //   pkt header: MsgSeqNum(4) MsgSize(2) flags(2) SendingTime(4)
        //   msg:        MsgSize(2) blockLength(2) templateId(2) schema(2) ver(2)
        //               root(8+... )  -> template 55 = 20-byte symbol area etc.
        std::uint8_t buf[256];
        std::memset(buf, 0, sizeof(buf));
        ByteOrder le = ByteOrder::LittleEndian;

        // --- packet header (12 bytes) ---
        std::uint32_t seq = 389; std::memcpy(buf + 0, &seq, 4);
        std::uint16_t msgsz = 40; std::memcpy(buf + 4, &msgsz, 2);  // payload len
        std::uint16_t flags = 0;  std::memcpy(buf + 6, &flags, 2);
        std::uint16_t pad = 0;    std::memcpy(buf + 8, &pad, 2);
        std::uint16_t pad2 = 0;   std::memcpy(buf + 10, &pad2, 2);

        // --- one message: message at buf+12 ---
        std::uint8_t* m = buf + 12;
        // SBE message body size (root only; 10 = msg preamble + 8-byte SBE hdr)
        const std::uint16_t block_len = 29;
        const std::uint16_t msg_body = 10U + 8U + block_len;  // full message len
        std::uint16_t sz = static_cast<std::uint16_t>(msg_body);
        std::memcpy(m + 0, &sz, 2);                 // MsgSize preamble
        std::memcpy(m + 2, &block_len, 2);          // blockLength = 29
        const std::uint16_t tmpl = schema::kTmplInstrumentDefinitionFuture55;
        std::memcpy(m + 4, &tmpl, 2);               // templateId = 55
        const std::uint16_t sid = 1; std::memcpy(m + 6, &sid, 2);  // schemaId = 1
        const std::uint16_t ver = 9; std::memcpy(m + 8, &ver, 2);  // version = 9
        std::uint8_t* root = m + 10;
        // transactTime @0 (8 bytes)
        std::uint64_t tt = 0x1122334455667788ULL; std::memcpy(root + 0, &tt, 8);
        // securityExchange @19 ("XCMEA6")
        std::memcpy(root + 19, "XCMEA6", 6);
        // symbol @35 ("LEZ4 P0980")
        std::memcpy(root + 35, "LEZ4 P0980\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 20);

        // --- verify framing ---
        Mdp3PacketHeaderWire ph;
        CHECK(decode_mdp3_packet_header(buf, 12U + msg_body, le, ph));
        CHECK(ph.msgSeqNum == 389);

        Mdp3MessageIterator it(buf + 12, msg_body, le);
        CHECK(it.hasNext());
        CHECK(it.message_size() == msg_body);
        const std::uint8_t* h = it.sbe_header();
        CHECK(detail::load_u16(h + 2, le) == schema::kTmplInstrumentDefinitionFuture55);
        CHECK(detail::load_u16(h + 0, le) == block_len);

        BufferView rroot(h + 8, msg_body - 2U - 8U);
        schema::InstrumentDefinitionFuture55Decoder def55(rroot, le);
        CHECK(def55.transactTime() == 0x1122334455667788ULL);
        CHECK(std::memcmp(def55.securityExchange(), "XCMEA6", 6) == 0);
        CHECK(std::memcmp(def55.symbol(), "LEZ4 P0980", 10) == 0);

        it.next();
        CHECK(!it.hasNext());  // exactly one message decoded

        // --- template 54 routes via the (big-endian) router on BE wire bytes ---
        // route() parses the 8-byte SBE header at offset 0 (no MsgSize preamble).
        std::uint8_t b2[20];
        std::memset(b2, 0, sizeof(b2));
        store_be16(b2 + 0, block_len);                               // blockLength
        store_be16(b2 + 2, schema::kTmplInstrumentDefinitionFuture54);
        store_be16(b2 + 4, 1);                                       // schemaId
        store_be16(b2 + 6, 9);                                       // version
        RouteResult r54 = route(BufferView(b2, 20));
        CHECK(r54.valid);
        CHECK(r54.header.templateId == schema::kTmplInstrumentDefinitionFuture54);
        CHECK(r54.schema_match);  // template 54 routed
    }

    // ---- Test 8: Databento DBN v3 header + MBO record layout ---------------
    {
        // Tiny synthetic DBN v3: magic + metadata-length + a few MBO records.
        std::uint8_t buf[512];
        std::memset(buf, 0, sizeof(buf));
        buf[0] = 'D'; buf[1] = 'B'; buf[2] = 'N'; buf[3] = 0x03;
        // metadata length at bytes 4..7 (LE) = 16 bytes
        buf[4] = 16; buf[5] = 0; buf[6] = 0; buf[7] = 0;
        // record stream begins at 8 + 16 = 24
        const std::size_t begin = 24U;

        dbn::MboMsg* m = reinterpret_cast<dbn::MboMsg*>(buf + begin);
        // first MBO record
        m->hd.length = 14;                       // 14 x 32-bit words = 56 bytes
        m->hd.rtype = dbn::rtype::Mbo;           // 0xA0
        m->hd.publisher_id = 1;
        m->hd.instrument_id = 10252;
        m->hd.ts_event = 1791815400000069715ULL;
        m->order_id = 6417741761577ULL;
        m->price = 7853750000000LL;
        m->size = 1;
        m->flags = 0x0080;
        m->action = 'A';
        m->side = 'B';
        m->ts_recv = 1791815400000070000ULL;
        m->ts_in_delta = 14403;
        m->sequence = 4408730;

        // Header parser must locate the record stream at 24.
        std::size_t n = 0;
        std::size_t off = dbn::record_stream_offset(buf, sizeof(buf), n);
        CHECK(off == begin);
        CHECK(n == (sizeof(buf) - begin) / sizeof(dbn::MboMsg));

        // Direct field loads (zero-copy, host-native LE) must round-trip.
        const dbn::MboMsg* r = reinterpret_cast<const dbn::MboMsg*>(buf + off);
        CHECK(r->hd.length == 14);
        CHECK(r->hd.rtype == dbn::rtype::Mbo);
        CHECK(r->hd.instrument_id == 10252);
        CHECK(r->action == 'A');
        CHECK(r->side == 'B');
        CHECK(r->sequence == 4408730);
        CHECK(sizeof(dbn::MboMsg) == 56);  // enforced by static_assert too

        // Non-DBN bytes must be rejected.
        std::uint8_t bad[64];
        std::memset(bad, 'x', sizeof(bad));
        std::size_t bn = 1;
        CHECK(dbn::record_stream_offset(bad, sizeof(bad), bn) == 0);
        CHECK(bn == 0);
    }

    if (failures == 0) {
        std::printf("ALL TESTS PASSED\n");
        return 0;
    }
    std::printf("%d CHECK(S) FAILED\n", failures);
    return 1;
}

