// qdecode - tools/decode_pcap.cpp
// ---------------------------------------------------------------------------
// Tool that mmaps a PCAP capture file and decodes SBE messages found in
// UDP payloads. Strips Ethernet/IP/UDP headers and routes each payload
// through the SBE decoder.
//
// Build:
//   c++ -std=c++20 -O2 -Iinclude src/pcap.cpp tools/decode_pcap.cpp \
//       -o build/decode_pcap
//
// Usage:
//   ./build/decode_pcap Data/pcap_data/market-data-sample.pcap

#include <cstdio>
#include <cstring>

#include "qdecode/buffer_view.hpp"
#include "qdecode/message_header.hpp"
#include "qdecode/router.hpp"
#include "qdecode/schema.hpp"
#include "qdecode/group.hpp"
#include "qdecode/mdp3_packet.hpp"
#include "qdecode/pcap.hpp"
#include "qdecode/byte_order.hpp"

using namespace qdecode;

BufferView extract_udp_payload(const std::uint8_t* pkt, std::size_t len) {
    if (len < 14) return BufferView{};
    std::uint16_t ethertype = load_be16(pkt + 12);
    std::size_t ip_offset = 14;
    if (ethertype == 0x8100) {
        if (len < 18) return BufferView{};
        ethertype = load_be16(pkt + 16);
        ip_offset = 18;
    }
    if (ethertype != 0x0800 || len < ip_offset + 20)
        return BufferView{};
    const std::uint8_t* ip = pkt + ip_offset;
    if ((ip[0] >> 4) != 4) return BufferView{};
    std::size_t ip_hdr_len = (ip[0] & 0x0F) * 4U;
    if (ip_hdr_len < 20 || ip_hdr_len > len - ip_offset) return BufferView{};
    if (ip[9] != 17) return BufferView{};
    std::size_t udp_off = ip_offset + ip_hdr_len;
    std::uint16_t udp_len = load_be16(pkt + udp_off + 4);
    if (udp_len < 8) return BufferView{};
    std::size_t pl_off = udp_off + 8;
    std::size_t avail = len - pl_off;
    std::size_t pl_len = (udp_len - 8U < avail) ? (udp_len - 8U) : avail;
    if (pl_len == 0) return BufferView{};
    return BufferView(pkt + pl_off, pl_len);
}
// ---------------------------------------------------------------------------
// CME MDP 3.0 Binary Packet Header (12 bytes) + per-message framing. See
// qdecode/mdp3_packet.hpp for the layout. Byte order is auto-detected from the
// first message's templateId: standard MDP3 is big-endian, but redistributed
// captures (e.g. Databento) may be little-endian.
// ---------------------------------------------------------------------------
ByteOrder detect_mdp3_byte_order(const std::uint8_t* messages, std::size_t size) {
    // First message: [MsgSize(2)][blockLength(2)][templateId(2)][schemaId(2)][version(2)].
    // Peek at the templateId (bytes 4-5 of the message) in both byte orders and
    // pick the one that is a known real template.
    if (size >= 10U) {
        const std::uint8_t* m = messages;
        const std::uint16_t tmpl_be = load_be16(m + 4);
        const std::uint16_t tmpl_le = load_le16(m + 4);
        auto known = [](std::uint16_t t) {
            return t == schema::kTmplAdminHeartbeat ||
                   t == schema::kTmplIncrementalRefreshBook46 ||
                   t == schema::kTmplInstrumentDefinitionFuture54 ||
                   t == schema::kTmplInstrumentDefinitionFuture55 ||
                   t == schema::kTmplInstrumentDefinitionSpread56;
        };
        if (known(tmpl_le)) return ByteOrder::LittleEndian;
        if (known(tmpl_be)) return ByteOrder::BigEndian;
    }
    return ByteOrder::BigEndian;  // default to the standard
}

std::size_t decode_mdp3_payload(BufferView udp, std::uint64_t pkt_ts_sec,
                                std::uint64_t pkt_ts_usec, unsigned pkt_no,
                                ByteOrder bo) {
    if (udp.size() < 12U)
        return 0;

    Mdp3PacketHeaderWire ph;
    if (!decode_mdp3_packet_header(udp.data(), udp.size(), bo, ph))
        return 0;

    // Messages start right after the 12-byte packet header.
    const std::uint8_t* first = udp.data() + 12U;
    std::size_t avail = udp.size() - 12U;

    std::size_t count = 0;
    Mdp3MessageIterator it(first, avail, bo);
    while (it.hasNext()) {
        const std::uint16_t msg_size = it.message_size();
        // 8-byte SBE header honors the feed's byte order (this capture is LE).
        const std::uint8_t* h = it.sbe_header();
        const std::uint16_t bl = detail::load_u16(h + 0, bo);
        const std::uint16_t tmpl = detail::load_u16(h + 2, bo);
        const std::uint16_t schemaid = detail::load_u16(h + 4, bo);
        const std::uint16_t ver = detail::load_u16(h + 6, bo);
        BufferView root(h + 8, msg_size - 2U - 8U);

        ++count;
        std::printf("[packet %u] ts=%llu.%06llu  tmpl=%u  bl=%u  msgSize=%u  "
                    "schema=%u ver=%u  seq=%u sendt=%u\n",
                    pkt_no,
                    (unsigned long long)pkt_ts_sec,
                    (unsigned long long)pkt_ts_usec,
                    tmpl, bl, msg_size, schemaid, ver,
                    ph.msgSeqNum, ph.sendingTime);

        if (tmpl == schema::kTmplIncrementalRefreshBook46) {
            schema::IncrementalRefreshBook46Decoder book(root, bo);
            std::printf("  -> MDIncrementalRefreshBook46: "
                        "transactTime=%llu  matchEventIndicator=0x%02x\n",
                        (unsigned long long)book.transactTime(),
                        (unsigned)book.matchEventIndicator());
        } else if (tmpl == schema::kTmplInstrumentDefinitionFuture55) {
            schema::InstrumentDefinitionFuture55Decoder def(root, bo);
            char exch[7] = {0};
            char sym[21] = {0};
            std::memcpy(exch, def.securityExchange(), 6);
            std::memcpy(sym, def.symbol(), 20);
            std::printf("  -> MDInstrumentDefinitionFuture55: "
                        "transactTime=%llu  exchange=%-6s  symbol=%s\n",
                        (unsigned long long)def.transactTime(),
                        exch, sym);
        }
        it.next();
    }
    return count;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "Usage: %s <pcap-file>\n", argv[0]);
        return 1;
    }

    PcapFile pf;
    if (!pf.open_mmap(argv[1])) {
        std::fprintf(stderr, "Error: could not open '%s'\n", argv[1]);
        return 1;
    }

    PcapView pv = pf.view();
    if (!pv.validate()) {
        std::fprintf(stderr, "Error: invalid PCAP (bad magic)\n");
        return 1;
    }

    std::printf("PCAP byte order: %s\n",
                pv.big_endian() ? "big-endian" : "little-endian");

    std::uint64_t sec = 0, usec = 0;
    const std::uint8_t* payload = nullptr;
    std::size_t plen = 0;
    unsigned pkt_no = 0, sbe_cnt = 0;

    while (pv.next_packet(sec, usec, &payload, plen)) {
        ++pkt_no;
        BufferView udp = extract_udp_payload(payload, plen);
        if (udp.empty() || udp.size() < 12U) continue;

        // MDP 3.0 byte order is detected from the first message's templateId.
        ByteOrder bo = detect_mdp3_byte_order(udp.data() + 12U, udp.size() - 12U);
        sbe_cnt += decode_mdp3_payload(udp, sec, usec, pkt_no, bo);
    }

    std::printf("\n=== SUMMARY ===\n");
    std::printf("Packets : %u\nSBE msgs: %u\n", pkt_no, sbe_cnt);
    return 0;
}