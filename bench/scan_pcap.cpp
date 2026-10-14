// qdecode - scan_pcap.cpp
// ---------------------------------------------------------------------------
// Inspector for the real market-data-sample.pcap: walks records with the mmap
// PcapView reader, extracts the UDP payload, and prints the first SBE message
// header (blockLength/templateId/schemaId/version) from each packet that looks
// like CME MDP 3.0, plus the MDP packet-header fields. Used only to learn the
// real on-wire template IDs before writing the concrete schema decoders.

#include <cstdio>
#include <cstdint>
#include <cstring>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "qdecode/pcap.hpp"
#include "qdecode/byte_order.hpp"

using namespace qdecode;

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <file.pcap>\n", argv[0]);
        return 2;
    }
    const int fd = ::open(argv[1], O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }
    struct stat st;
    if (::fstat(fd, &st) != 0) { perror("fstat"); return 1; }
    void* base = ::mmap(nullptr, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (base == MAP_FAILED) { perror("mmap"); return 1; }
    const std::uint8_t* data = static_cast<const std::uint8_t*>(base);
    const std::size_t size = (std::size_t)st.st_size;

    // Global header (24 bytes). Detect CONTAINER endianness from the 4 magic
    // bytes. Classic pcap magic: {a1 b2 c3 d4} big-endian, {4d 3c b2 a1} little.
    const std::uint8_t* g = data;
    const bool be = (g[0] == 0xA1 && g[1] == 0xB2 && g[2] == 0xC3 && g[3] == 0xD4);
    const bool le = (g[0] == 0x4D && g[1] == 0x3C && g[2] == 0xB2 && g[3] == 0xA1);
    std::printf("magic bytes: %02x%02x%02x%02x -> %s pcap\n", g[0], g[1], g[2], g[3],
                le ? "little-endian" : (be ? "big-endian" : "unknown"));
    if (!le && !be) { std::fprintf(stderr, "not a classic pcap\n"); return 1; }

    // Record-header fields use container byte order.
    auto r32 = [&](const std::uint8_t* p) -> std::uint32_t {
        std::uint32_t v; std::memcpy(&v, p, 4);
        return le ? v : load_be32(p);
    };
    // SBE message fields are ALWAYS big-endian, independent of pcap container.
    auto be16 = [](const std::uint8_t* p) -> std::uint16_t { return load_be16(p); };
    auto be32 = [](const std::uint8_t* p) -> std::uint32_t { return load_be32(p); };

    std::size_t off = 24;
    std::uint64_t pkt = 0, udp = 0, sbe = 0;
    int printed = 0;
    while (off + 16 <= size) {
        const std::uint8_t* h = data + off;
        const std::uint32_t incl = r32(h + 8);
        if (off + 16 + incl > size) break;
        const std::uint8_t* d = data + off + 16;
        const std::size_t plen = incl;
        (void)r32(h);  // ts_sec
        pkt++;

        // Ethernet(14) + IPv4 + UDP.
        if (plen >= 14 + 20 + 8 && d[12] == 0x08 && d[13] == 0x00) {
            const std::uint8_t ihl = d[14] & 0x0F;
            const std::size_t ip_off = 14;
            if (d[ip_off + 9] == 17) {  // UDP
                const std::size_t udp_off = ip_off + (std::size_t)ihl * 4;
                if (udp_off + 8 <= plen) {
                    const std::uint16_t udp_len = be16(d + udp_off + 4);
                    if (udp_len >= 8 && udp_off + udp_len <= plen) {
                        const std::uint8_t* pay = d + udp_off + 8;
                        const std::size_t pay_len = udp_len - 8;
                        udp++;
                        // CME MDP 3.0 packet header: MsgSeqNum(4) + MsgSize(2)
                        // + IsLast|Fragmented(2). SBE message(s) follow.
                        if (pay_len >= 12) {
                            const std::uint8_t* m = pay + 8;
                            const std::size_t mlen = pay_len - 8;
                            if (mlen >= 8) {
                                const std::uint16_t block_len = be16(m);
                                const std::uint16_t template_id = be16(m + 2);
                                const std::uint16_t schema_id = be16(m + 4);
                                const uint16_t ver = be16(m + 6);
                                sbe++;
                                if (printed < 20) {
                                    std::printf("pkt#%llu udp_dst=%u seq=%u blockLen=%u templateId=%u schemaId=%u version=%u\n",
                                        (unsigned long long)pkt,
                                        (unsigned)be16(d + udp_off + 2),
                                        (unsigned)be32(pay),
                                        block_len, template_id, schema_id, ver);
                                    printed++;
                                }
                            }
                        }
                    }
                }
            }
        }
        off += 16 + incl;
    }
    ::munmap(base, size);
    ::close(fd);
    std::printf("total packets=%llu udp=%llu sbe-like=%llu\n",
                (unsigned long long)pkt, (unsigned long long)udp, (unsigned long long)sbe);
    return 0;
}