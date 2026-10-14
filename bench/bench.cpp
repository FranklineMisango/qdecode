// qdecode - bench.cpp
// ---------------------------------------------------------------------------
// Microbenchmark of the zero-copy decode path. Decodes N identical
// MDIncrementalRefreshBook messages (with 5 depth entries each) straight from
// a prebuilt wire buffer, verifying each field, and reports ns/message.
//
// Build (production flags):
//   c++ -std=c++20 -O3 -march=native -flto -Iinclude bench.cpp -o bench

#include <chrono>
#include <cstdio>
#include <cstring>

#include "qdecode/encoder.hpp"
#include "qdecode/buffer_view.hpp"
#include "qdecode/message_header.hpp"
#include "qdecode/router.hpp"
#include "qdecode/schema.hpp"
#include "qdecode/group.hpp"

using namespace qdecode;
using clk = std::chrono::steady_clock;

int main() {
    constexpr std::uint16_t kEntries = 5;
    constexpr std::uint64_t kIters = 5'000'000ULL;

    std::uint8_t buf[512];
    std::memset(buf, 0, sizeof(buf));
    SbeEncoder e(buf, sizeof(buf));
    // Setup writes are trusted (buffer is oversized); discard the nodiscard
    // returns explicitly.
    (void)e.u16(schema::IncrementalRefreshBook32Decoder::kRootBlockLength);
    (void)e.u16(schema::kTmplIncrementalRefreshBook32);
    (void)e.u16(schema::kSchemaId);
    (void)e.u16(0);
    (void)e.u64(1234567890123456789ULL);
    (void)e.u8(0x1A);
    (void)e.pad(7);
    (void)e.u64(kEntries);
    (void)e.u16(kEntries);   // noOfEntries
    (void)e.u16(0);          // noOfOrderBookEntries
    (void)e.pad(4);          // padding @28..31
    (void)e.u16(schema::BookEntryDecoder::kBlockLength);
    (void)e.u16(kEntries);
    for (std::uint16_t i = 0; i < kEntries; ++i) {
        (void)e.i32(10000 + i * 100);
        (void)e.i32(100 + i);
        (void)e.u8((i % 2) ? 'A' : 'B');
        (void)e.u8((i % 3) ? '1' : '0');
        (void)e.pad(2);
    }
    const std::size_t msglen = e.size();

    // Warm-up.
    volatile std::uint64_t sink = 0;
    for (int w = 0; w < 1000; ++w) {
        RouteResult r = route(BufferView(buf, msglen));
        sink += r.header.templateId;
    }

    const auto t0 = clk::now();
    for (std::uint64_t iter = 0; iter < kIters; ++iter) {
        RouteResult r = route(BufferView(buf, msglen));
        schema::IncrementalRefreshBook32Decoder book(r.root);
        BufferView cursor = r.root;
        GroupHeader gh{};
        (void)book.group(cursor, gh);
        GroupIterator<schema::BookEntryDecoder> it(cursor, gh.blockLength, gh.numInGroup);
        std::uint64_t sum = 0;
        while (it.hasNext()) {
            auto entry = it.next();
            sum += static_cast<std::uint64_t>(entry.price());
        }
        sink += sum;
    }
    const auto t1 = clk::now();

    const double ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
    const double per_msg = ns / static_cast<double>(kIters);
    const double msgs_per_sec = 1e9 / per_msg;

    std::printf("messages      : %llu\n", (unsigned long long)kIters);
    std::printf("message size  : %zu bytes\n", msglen);
    std::printf("total time    : %.2f ms\n", ns / 1e6);
    std::printf("per-message   : %.3f ns\n", per_msg);
    std::printf("throughput    : %.2f M msg/s\n", msgs_per_sec / 1e6);
    std::printf("sink          : %llu (prevent DCE)\n", (unsigned long long)sink);
    return 0;
}