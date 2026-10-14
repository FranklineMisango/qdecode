// qdecode - size_dist.cpp
// Histogram of UDP payload sizes across a pcap, to understand message types.
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "qdecode/byte_order.hpp"
using namespace qdecode;
int main(int argc, char** argv) {
    const int fd = ::open(argv[1], O_RDONLY);
    struct stat st; ::fstat(fd, &st);
    void* base = ::mmap(nullptr, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    const std::uint8_t* data = static_cast<const std::uint8_t*>(base);
    const std::size_t size = (std::size_t)st.st_size;
    const bool le = (data[0]==0x4D);
    auto r32 = [&](const std::uint8_t* p){ std::uint32_t v; std::memcpy(&v,p,4); return le?v:load_be32(p); };
    auto r16 = [&](const std::uint8_t* p){ std::uint16_t v; std::memcpy(&v,p,2); return le?v:load_be16(p); };

    std::size_t off = 24;
    // Count payload sizes in log-ish buckets and total.
    long histo[4096] = {0};
    long total=0, over=0;
    long template_histo[1024] = {0};
    while (off + 16 <= size) {
        const std::uint32_t incl = r32(data+off+8);
        const std::uint8_t* d = data+off+16;
        const std::size_t plen = incl;
        if (plen >= 14+20+8 && d[12]==0x08 && d[13]==0x00 && d[14+9]==17) {
            const std::size_t uo = 14 + (d[14]&0x0F)*4;
            const std::uint16_t ulen = load_be16(d+uo+4);
            if (ulen >= 8) {
                const std::size_t pl = ulen - 8;
                total++;
                if (pl >= 4096) over++; else histo[pl]++;
                // SBE message header: assume big-endian after a 7-byte MDP header.
                if (pl >= 7+8) {
                    const std::uint8_t* m = d+uo+8+7;
                    std::uint32_t t = load_be16(m+2);
                    if (t < 1024) template_histo[t]++;
                }
            }
        }
        off += 16 + incl;
    }
    std::printf("total UDP payloads=%ld, >=4096=%ld\n", total, over);
    std::printf("payload-size histogram (nonzero buckets):\n");
    for (std::size_t i=0;i<4096;i++) if (histo[i]) std::printf("  size=%zu count=%ld\n", i, histo[i]);
    std::printf("templateId (big-endian read) histogram:\n");
    for (std::size_t i=0;i<1024;i++) if (template_histo[i]) std::printf("  tmpl=%zu count=%ld\n", i, template_histo[i]);
    ::munmap(base,size); ::close(fd);
    return 0;
}