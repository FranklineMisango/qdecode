// qdecode - dump_pkt.cpp
// Dump full Ethernet/IP/UDP payload hex for the first N packets of a pcap so we
// can inspect the exact MDP 3.0 / SBE structure byte-by-byte.

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "qdecode/byte_order.hpp"

using namespace qdecode;

static void hexdump(const std::uint8_t* p, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        std::printf("%02x ", p[i]);
        if ((i + 1) % 16 == 0) std::printf("\n");
    }
    if (n % 16) std::printf("\n");
}

int main(int argc, char** argv) {
    const int fd = ::open(argv[1], O_RDONLY);
    struct stat st;
    ::fstat(fd, &st);
    void* base = ::mmap(nullptr, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    const std::uint8_t* data = static_cast<const std::uint8_t*>(base);
    const std::size_t size = (std::size_t)st.st_size;

    const bool le = (data[0]==0x4D && data[1]==0x3C && data[2]==0xB2 && data[3]==0xA1);
    auto r32 = [&](const std::uint8_t* p){ std::uint32_t v; std::memcpy(&v,p,4); return le?v:load_be32(p); };

    std::size_t off = 24;
    for (int n = 0; n < 3 && off + 16 <= size; ) {
        const std::uint32_t incl = r32(data + off + 8);
        const std::uint8_t* d = data + off + 16;
        const std::size_t plen = incl;
        // Ethernet + IPv4 + UDP
        if (plen >= 14+20+8 && d[12]==0x08 && d[13]==0x00 && d[14+9]==17) {
            const std::size_t ihl = d[14] & 0x0F;
            const std::size_t uo = 14 + ihl*4;
            const std::uint16_t ulen = load_be16(d+uo+4);
            const std::uint8_t* pay = d + uo + 8;
            const std::size_t pl = ulen - 8;
            std::printf("=== packet %d incl=%zu udp_len=%u payload_len=%zu ===\n",
                        n+1, plen, (unsigned)ulen, pl);
            hexdump(pay, pl);
            n++;
        }
        off += 16 + incl;
    }
    ::munmap(base, size);
    ::close(fd);
    return 0;
}