# qdecode

An ultra-fast, **zero-allocation** Simple Binary Encoding (SBE) decoder built to
pin directly to network ring buffers / memory-mapped captures (CME MDP 3.0,
Eurex, etc.).

## Design philosophy

Instead of *deserializing* (copying bytes into heap objects like `std::string` /
`std::vector`), qdecode treats the **wire format as the memory layout**. Every
decoder is a lightweight view holding only a raw pointer + length; fields are
read on demand with pointer arithmetic and explicit big-endian loads. There is
no heap allocation and no `virtual` dispatch anywhere in the hot path.

## Critical correctness note: SBE is big-endian on the wire

Toy SBE examples read fields with a plain `reinterpret_cast<const uint64_t*>`,
which works **only on big-endian hosts**. Every real SBE feed (CME MDP 3.0
included) encodes multi-byte fields **big-endian**. On the little-endian x86/ARM
hosts that dominate HFT, that pattern silently returns garbage.

qdecode centralizes byte-order handling in `include/qdecode/byte_order.hpp`:
- `load_be16/32/64` and `load_be_i16/32/64` for reads,
- `store_be16/32/64` for the encoder,
- all `constexpr`/free functions so the optimizer folds the swap away on
  big-endian hosts and emits a single `BSWAP` on little-endian hosts.

## Component layout

| Component | File | Role |
|-----------|------|------|
| Byte-order helpers | `include/qdecode/byte_order.hpp` | BE load/store, compile-time endianness |
| Bounds-checked view | `include/qdecode/buffer_view.hpp` | `BufferView` — pointer+length view, checks compiled out unless `QDECODE_ENABLE_BOUNDS_CHECK` |
| Message header | `include/qdecode/message_header.hpp` | 8-byte SBE header: blockLength(2) templateId(2) schemaId(2) version(2) |
| Repeating groups / VarData | `include/qdecode/group.hpp` | `GroupIterator<T>`, `read_var_data` — dynamic stride, no static offsets |
| Message templates | `include/qdecode/schema.hpp` | `MDIncrementalRefreshBook`, `MDTradeCapture` (CME-style) |
| Router | `include/qdecode/router.hpp` | template-ID dispatch with `[[likely]]`/`[[unlikely]]` |
| Encoder (fixtures / outbound) | `include/qdecode/encoder.hpp` | zero-allocation BE writer |
| mmap PCAP ingestion | `include/qdecode/pcap.hpp`, `src/pcap.cpp` | maps `.pcap` read-only; decoders read the page cache in place |

### Message header (8 bytes, big-endian)

```
offset  size  field
0       2     blockLength
2       2     templateId
4       2     schemaId
6       2     version
```

### Repeating groups

A group cannot use static offsets. `GroupIterator` reads the group header
(`blockLength` + `numInGroup`), strides through `numInGroup` occurrences each
`blockLength` bytes via pointer arithmetic, and lets the template read trailing
`VarData` (2-byte length prefix) with `read_var_data`.

## Performance

Compiled with `-O3 -march=native -flto` (see `CMakeLists.txt`), the microbenchmark
in `bench/bench.cpp` decodes a 96-byte `MDIncrementalRefreshBook` (5 depth
entries) end-to-end in **~2 ns/message (~460 M msg/s)**, comfortably inside the
sub-10 ns budget.

```
$ c++ -std=c++20 -O3 -march=native -flto -Iinclude bench/bench.cpp -o bench/bench && ./bench/bench
messages      : 5000000
message size  : 96 bytes
total time    : 10.90 ms
per-message   : 2.180 ns
throughput    : 458.66 M msg/s
```

## Ingesting real data

### Option A: mmap a real PCAP (implemented)

`PcapFile::open_mmap()` maps a real CME/Eurex `.pcap` read-only with
`MAP_PRIVATE`; `PcapView` iterates the global header and per-packet records and
hands each UDP payload straight to the SBE decoders — no `fread`, no heap
buffer. Databento offers free developer credits to download historical
MDP 3.0 captures and pcap files for exactly this workflow.

### Option B: NIC ring buffers (production, adapter needed)

For live capture, bind a NIC with **DPDK** or **Solarflare EF_VI** to pull
packets straight from hardware ring buffers into user space, bypassing the
kernel network stack. The decoders here accept any `BufferView`, so they pin
directly to those ring-buffer addresses unchanged.

## Building & testing

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure

# Or a direct single-file build of the test suite:
c++ -std=c++20 -O2 -Iinclude src/pcap.cpp tests/test_decoder.cpp -o test && ./test
```

The round-trip suite (`tests/test_decoder.cpp`) uses only the real components —
encoder → wire buffer → decoder views — and validates headers, root fields,
repeating groups, VarData, the mmap PCAP reader, malformed/truncated inputs, and
byte order. It also passes cleanly under `-fsanitize=address,undefined` and in
bounds-check mode (`-DQDECODE_ENABLE_BOUNDS_CHECK=1`).

## License

MIT.

