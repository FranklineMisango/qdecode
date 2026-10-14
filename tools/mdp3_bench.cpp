// qdecode - tools/mdp3_bench.cpp
// ---------------------------------------------------------------------------
// Decode-throughput benchmark over a real CME MDP 3.0 pcap (e.g. Databento's
// db-samples.pcap). Uses the corrected MDP 3.0 framing (12-byte packet header +
// per-message MsgSize preamble), detects the feed's byte order, decodes each
// SBE message header and (for known templates) the root fields, and reports
// nanoseconds per message plus aggregate message counts.
//
// Build:
//   c++ -std=c++20 -O3 -march=native -flto -Iinclude src/pcap.cpp \
//       tools/mdp3_bench.cpp -o build/mdp3_bench
//
// Usage:
//   ./build/mdp3_bench Data/pcap_data/db-samples.pcap

#include <chrono>
#include <cstdio>
#include <cstring>
#include <map>

#include "qdecode/buffer_view.hpp"
#include "qdecode/message_header.hpp"
#include "qdecode/schema.hpp"
#include "qdecode/group.hpp"
#include "qdecode/mdp3_packet.hpp"
#include "qdecode/pcap.hpp"
#include "qdecode/byte_order.hpp"

using namespace qdecode;
using clk = std::chrono::steady_clock;

namespace {

/// Strip Ethernet/VLAN/IPv4/UDP and return the UDP payload as a view.
BufferView extract_udp_payload(const std::uint8_t* pkt, std::size_t len) {
    if (len < 14) return BufferView{};
    std::uint16_t ethertype = load_be16(pkt + 12);
    std::size_t ip_offset = 14;
    if (ethertype == 0x8100) {
        if (len < 18) return BufferView{};
        ethertype = load_be16(pkt + 16);
        ip_offset = 18;
    }
    if (ethertype != 0x0800 || len < ip_offset + 20) return BufferView{};
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

/// Detect MDP 3.0 feed byte order from the first message's templateId.
ByteOrder detect_mdp3_byte_order(const std::uint8_t* messages, std::size_t size) {
    if (size >= 10U) {
        const std::uint16_t t_be = load_be16(messages + 4);
        const std::uint16_t t_le = load_le16(messages + 4);
        auto known = [](std::uint16_t t) {
            return t == schema::kTmplAdminHeartbeat ||
                   t == schema::kTmplIncrementalRefreshBook46 ||
                   t == schema::kTmplInstrumentDefinitionFuture54 ||
                   t == schema::kTmplInstrumentDefinitionFuture55 ||
                   t == schema::kTmplInstrumentDefinitionSpread56;
        };
        if (known(t_le)) return ByteOrder::LittleEndian;
        if (known(t_be)) return ByteOrder::BigEndian;
    }
    return ByteOrder::BigEndian;
}

/// Counters accumulated over one full pass over the capture.
struct Stats {
    std::uint64_t packets = 0;
    std::uint64_t packets_with_udp = 0;
    std::uint64_t messages = 0;
    std::map<std::uint16_t, std::uint64_t> by_template;
};

/// Decode a whole capture. `checksum` folds decoded-field values into a sink so
/// the optimizer cannot eliminate the decode work.
void scan_capture(PcapFile& pf, Stats& s, std::uint64_t& checksum) {
    PcapView pv = pf.view();
    if (!pv.validate()) return;
    std::uint64_t sec = 0, usec = 0;
    const std::uint8_t* payload = nullptr;
    std::size_t plen = 0;

    while (pv.next_packet(sec, usec, &payload, plen)) {
        ++s.packets;
        BufferView udp = extract_udp_payload(payload, plen);
        if (udp.empty() || udp.size() < 12U) continue;
        ++s.packets_with_udp;

        const std::uint8_t* first = udp.data() + 12U;
        std::size_t avail = udp.size() - 12U;
        ByteOrder bo = detect_mdp3_byte_order(first, avail);

        Mdp3MessageIterator it(first, avail, bo);
        while (it.hasNext()) {
            const std::uint16_t msg_size = it.message_size();
            const std::uint8_t* h = it.sbe_header();
            const std::uint16_t bl = detail::load_u16(h + 0, bo);
            const std::uint16_t tmpl = detail::load_u16(h + 2, bo);
            const std::uint16_t schemaid = detail::load_u16(h + 4, bo);
            const std::uint16_t ver = detail::load_u16(h + 6, bo);
            BufferView root(h + 8, msg_size - 2U - 8U);

            ++s.messages;
            ++s.by_template[tmpl];

            // Solidify the decode work so it is not dead-code eliminated.
            checksum += tmpl;
            checksum ^= (static_cast<std::uint64_t>(bl) << 16) ^
                        (static_cast<std::uint64_t>(schemaid) << 32) ^ ver;
            if (tmpl == schema::kTmplIncrementalRefreshBook46) {
                schema::IncrementalRefreshBook46Decoder book(root, bo);
                checksum ^= book.transactTime() ^ book.matchEventIndicator();
            } else if (tmpl == schema::kTmplInstrumentDefinitionFuture55) {
                schema::InstrumentDefinitionFuture55Decoder def(root, bo);
                std::uint64_t tt = def.transactTime();
                const std::uint8_t* sx = def.securityExchange();
                const std::uint8_t* sy = def.symbol();
                std::uint64_t s_val = 0;
                for (int i = 0; i < 6; ++i) s_val = s_val * 31u + sx[i];
                for (int i = 0; i < 20; ++i) s_val = s_val * 31u + sy[i];
                checksum ^= tt ^ s_val;
            }
            it.next();
        }
    }
}

}  // namespace

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

    // Warm-up pass: fault in pages + prime the decode path.
    std::uint64_t checksum = 0;
    {
        Stats warm;
        scan_capture(pf, warm, checksum);
        std::printf("warm-up: packets=%llu messages=%llu checksum=%llu\n",
                    (unsigned long long)warm.packets,
                    (unsigned long long)warm.messages,
                    (unsigned long long)checksum);
    }

    // Steady-state timed passes (best of R).
    const int R = 7;
    double best_ns = 1e18;
    Stats best;
    for (int r = 0; r < R; ++r) {
        Stats s;
        std::uint64_t ck = checksum;
        auto t0 = clk::now();
        scan_capture(pf, s, ck);
        auto t1 = clk::now();
        double ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
        if (ns < best_ns) {
            best_ns = ns;
            best = std::move(s);
        }
        checksum ^= ck;  // keep the sink live across passes
    }

    std::printf("\n=== MDP 3.0 decode benchmark ===\n");
    std::printf("packets            : %llu\n", (unsigned long long)best.packets);
    std::printf("UDP packets        : %llu\n", (unsigned long long)best.packets_with_udp);
    std::printf("SBE messages       : %llu\n", (unsigned long long)best.messages);
    std::printf("best pass time     : %.2f ms\n", best_ns / 1e6);
    if (best.messages) {
        std::printf("ns/message         : %.3f\n", best_ns / (double)best.messages);
        std::printf("M msg/s            : %.2f\n",
                    (double)best.messages / (best_ns / 1e9) / 1e6);
    }
    std::printf("template distribution:\n");
    std::uint64_t msgs = best.messages;
    for (auto& kv : best.by_template) {
        std::printf("  tmpl=%u : %llu (%.1f%%)\n", kv.first,
                    (unsigned long long)kv.second,
                    msgs ? 100.0 * (double)kv.second / (double)msgs : 0.0);
    }
    std::printf("checksum           : %llu\n", (unsigned long long)checksum);
    return 0;
}