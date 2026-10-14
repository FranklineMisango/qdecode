#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "qdecode/byte_order.hpp"
using namespace qdecode;
static void h(const std::uint8_t* p, std::size_t n) {
    for (std::size_t i = 0; i < n; i++) { std::printf("%02x ", p[i]); if ((i + 1) % 16 == 0) std::printf("\n"); }
    if (n % 16) std::printf("\n");
}
int main(int argc, char** argv) {
    const int fd = ::open(argv[1], O_RDONLY); struct stat st; ::fstat(fd, &st);
    void* base = ::mmap(nullptr, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    const std::uint8_t* data = (const std::uint8_t*)base; const std::size_t size = (std::size_t)st.st_size;
    const bool le = (data[0] == 0x4D);
    auto r32 = [&](const std::uint8_t* p) { std::uint32_t v; std::memcpy(&v, p, 4); return le ? v : load_be32(p); };
    std::size_t off = 24; int shown = 0;
    for (int target = 294; target <= 303 && shown < 1; target++) {
        off = 24;
        while (off + 16 <= size) {
            const std::uint32_t incl = r32(data + off + 8);
            const std::uint8_t* d = data + off + 16; const std::size_t plen = incl;
            if (plen >= 14 + 20 + 8 && d[12] == 0x08 && d[13] == 0x00 && d[14 + 9] == 17) {
                const std::size_t uo = 14 + (d[14] & 0x0F) * 4;
                const std::uint16_t ulen = load_be16(d + uo + 4);
                if (ulen >= 8) { std::size_t pl = ulen - 8; if ((int)pl == target) {
                    const std::uint8_t* pay = d + uo + 8;
                    std::printf("=== payload size %zu (target %d) ===\n", pl, target); h(pay, pl); shown = 1; break; } }
            }
            off += 16 + incl;
        }
    }
    ::munmap(base, size); ::close(fd); return 0;
}