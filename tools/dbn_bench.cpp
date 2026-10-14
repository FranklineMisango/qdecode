// qdecode - tools/dbn_bench.cpp
// ---------------------------------------------------------------------------
// Decode-throughput benchmark over a Databento DBN (`.zst` or raw `.dbn`) MBO
// capture. Because DBN records are fixed `repr(C)` structs on the wire, decode
// is a straight mmap + pointer-stride + direct field loads — the path that
// reaches sub-10ns per record.
//
// Accepts either a raw `.dbn` file or a `.dbn.zst` (decompressed into memory
// first via zstd). Reports nanoseconds per record.
//
// Build:
//   c++ -std=c++20 -O3 -march=native -flto -lzstd tools/dbn_bench.cpp -o build/dbn_bench
//
// Usage:
//   ./build/dbn_bench Data/pcap_data/glbx-mdp3-20261012.mbo.dbn.zst

#include <chrono>
#include <cstdio>
#include <cstring>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <zstd.h>

#include "qdecode/dbn.hpp"

using namespace qdecode;
using clk = std::chrono::steady_clock;

namespace {

/// Flag which records were decoded and fold their values so the optimizer can't
/// eliminate the decode loop.
struct Handle {
    std::uint64_t seen = 0;
    std::uint64_t adds = 0;
    std::uint64_t cancels = 0;
    std::uint64_t price_sum = 0;
    std::uint64_t size_sum = 0;
    void on_mbo(const dbn::MboMsg* m) {
        ++seen;
        price_sum += static_cast<std::uint64_t>(m->price);
        size_sum += m->size;
        if (m->action == 'A') ++adds;
        else if (m->action == 'C') ++cancels;
    }
};

std::size_t load_bytes(const char* path, std::vector<std::uint8_t>& out,
                       const std::uint8_t** ptr) {
    // Read the whole file into memory: handles .dbn and .dbn.zst transparently.
    int fd = ::open(path, O_RDONLY);
    if (fd < 0) { std::fprintf(stderr, "open failed\n"); return 0; }
    struct stat st; ::fstat(fd, &st);
    std::size_t fsz = static_cast<std::size_t>(st.st_size);
    std::vector<std::uint8_t> comp(fsz);
    if (fsz && ::read(fd, comp.data(), fsz) != static_cast<ssize_t>(fsz)) {
        ::close(fd); std::fprintf(stderr, "read failed\n"); return 0;
    }
    ::close(fd);

    bool is_zst = fsz >= 4 && comp[0] == 0x28 && comp[1] == 0xB5 &&
                  comp[2] == 0x2F && comp[3] == 0xFD;
    if (!is_zst) {  // raw DBN; hand out the buffer directly
        out.swap(comp);
        *ptr = out.data();
        return out.size();
    }
    // zstd decompress in one shot.
    unsigned long long dlen = ZSTD_getFrameContentSize(comp.data(), comp.size());
    if (dlen == ZSTD_CONTENTSIZE_UNKNOWN || dlen == ZSTD_CONTENTSIZE_ERROR)
        return 0;
    out.resize(dlen);
    size_t got = ZSTD_decompress(out.data(), dlen, comp.data(), comp.size());
    if (ZSTD_isError(got) || got != dlen) {
        std::fprintf(stderr, "zstd decompress error\n");
        return 0;
    }
    *ptr = out.data();
    return out.size();
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "Usage: %s <file.dbn|file.dbn.zst>\n", argv[0]);
        return 1;
    }

    std::vector<std::uint8_t> storage;
    const std::uint8_t* data = nullptr;
    std::size_t size = load_bytes(argv[1], storage, &data);
    if (!size) { std::fprintf(stderr, "could not load '%s'\n", argv[1]); return 1; }

    std::size_t n_records = 0;
    std::size_t begin = dbn::record_stream_offset(data, size, n_records);
    if (n_records == 0) { std::fprintf(stderr, "not DBN v3 or no records\n"); return 1; }

    std::printf("DBN file        : %s\n", argv[1]);
    std::printf("metadata len    : %zu bytes, records begin at %zu\n",
                begin - 8U, begin);
    std::printf("records         : %llu (%.2f MiB of data)\n",
                (unsigned long long)n_records,
                (double)(n_records * sizeof(dbn::MboMsg)) / (1024.0 * 1024.0));

    // --- function that decodes all records (stride-56 pointer walk) ---

    // Warm up (populate page cache + OOO window).
    Handle warm;
    std::size_t wb = dbn::record_stream_offset(data, size, n_records);
    {
        const dbn::MboMsg* m = reinterpret_cast<const dbn::MboMsg*>(data + wb);
        for (std::size_t i = 0; i < n_records; ++i) { warm.on_mbo(m); ++m; }
    }

    // Steady-state timed passes (best of R).
    const int R = 9;
    double best_ms = 1e18;
    Handle best;
    std::uint64_t checksum = warm.seen;
    for (int r = 0; r < R; ++r) {
        std::size_t b2 = dbn::record_stream_offset(data, size, n_records);
        Handle h;
        auto t0 = clk::now();
        const dbn::MboMsg* m = reinterpret_cast<const dbn::MboMsg*>(data + b2);
        for (std::size_t i = 0; i < n_records; ++i) { h.on_mbo(m); ++m; }
        auto t1 = clk::now();
        double ms = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count() / 1e6;
        checksum ^= h.price_sum ^ h.size_sum;
        if (ms < best_ms) { best_ms = ms; best = h; }
    }

    std::printf("\n=== DBN MBO decode benchmark ===\n");
    std::printf("records          : %llu\n", (unsigned long long)best.seen);
    std::printf("adds             : %llu\n", (unsigned long long)best.adds);
    std::printf("cancels          : %llu\n", (unsigned long long)best.cancels);
    std::printf("best pass time   : %.3f ms\n", best_ms);
    if (best.seen) {
        std::printf("ns/record        : %.3f\n", best_ms * 1e6 / (double)best.seen);
        std::printf("M records/s      : %.2f\n", (double)best.seen / (best_ms / 1e3) / 1e6);
    }
    std::printf("checksum         : %llu (prevent DCE)\n", (unsigned long long)checksum);
    return 0;
}