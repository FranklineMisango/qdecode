#pragma once

// qdecode - pcap.hpp
// ---------------------------------------------------------------------------
// mmap-based, zero-allocation ingestion of real PCAP capture files
// (CME MDP 3.0, Eurex, etc.). Instead of reading a file into a heap buffer via
// fread, the entire file is mapped into the process's virtual address space and
// the decoder views read the wire bytes straight out of the page cache.
//
// PCAP container format (big-endian fields, 24-byte global header):
//   offset  size  field
//   0       4     magic            (0xa1b2c3d4 big-endian variant)
//   4       2     version_major
//   6       2     version_minor
//   8       4     thiszone
//   12      4     sigfigs
//   16      4     snaplen
//   20      4     network          (1 = ethernet, 113 = Linux SLL)
// then per packet, a 16-byte record header:
//   offset  size  field
//   0       4     ts_sec
//   4       4     ts_usec
//   8       4     incl_len        (bytes of the captured packet in this file)
//   12      4     orig_len        (bytes of the original packet on the wire)
// followed by `incl_len` bytes of packet data.

#include <cstddef>
#include <cstdint>

namespace qdecode {

class PcapView;  // forward declaration (defined below)

/// RAII owner of an mmap'd PCAP file. Maps the file read-only (MAP_PRIVATE) so
/// the SBE decoders read wire bytes straight out of the page cache with no heap
/// buffer and no fread. Unmaps on destruction.
class PcapFile {
public:
    PcapFile() noexcept;
    ~PcapFile();
    PcapFile(const PcapFile&) = delete;
    PcapFile& operator=(const PcapFile&) = delete;

    /// Open `path` and map it. Returns false (with errno set) on failure.
    [[nodiscard]] bool open_mmap(const char* path) noexcept;

    /// Return a zero-copy view over the mapped capture.
    [[nodiscard]] PcapView view() const noexcept;

    /// Unmap and close (idempotent).
    void close() noexcept;

private:
    int fd_;
    std::uint8_t* base_;
    std::size_t len_;
};

/// Zero-copy view over one mmap'd PCAP: the global header plus the packet
/// stream. No allocation; owns nothing (the mapping is held by PcapFile).
class PcapView {
public:
    constexpr PcapView() noexcept
        : data_(nullptr), size_(0), cursor_(0), is_big_endian_(true) {}
    constexpr PcapView(const std::uint8_t* data, std::size_t size) noexcept
        : data_(data), size_(size), cursor_(0), is_big_endian_(true) {}

    /// Validate the 24-byte global header and detect container byte order
    /// (classic pcap magic 0xA1B2C3D4 big-endian, or 0xA1B23C4D little-endian).
    /// Returns false on malformed input. On success cursor_ sits at the first
    /// packet record header.
    [[nodiscard]] bool validate() noexcept;

    /// True if the record-header fields (incl_len/orig_len/timestamps) use
    /// big-endian byte order. Always true for a big-endian pcap; false for the
    /// common little-endian pcap written by tcpdump/libpcap on x86/ARM hosts.
    [[nodiscard]] bool big_endian() const noexcept { return is_big_endian_; }

    /// Decode the next 16-byte packet record header using the detected byte
    /// order. Returns false at EOF or on a truncated record. On success
    /// `payload`/`payload_len` point into the mapping (the captured packet
    /// bytes) and cursor_ advances past the record.
    [[nodiscard]] bool next_packet(std::uint64_t& ts_sec, std::uint64_t& ts_usec,
                                   const std::uint8_t** payload,
                                   std::size_t& payload_len) noexcept;

private:
    /// Read a 32-bit record-header field honoring container byte order.
    [[nodiscard]] std::uint32_t record_u32(std::size_t off) const noexcept;
    /// Read the canonical magic value (numeric, byte-order-invariant layout).
    [[nodiscard]] std::uint32_t magic() const noexcept;

    const std::uint8_t* data_;
    std::size_t size_;
    std::size_t cursor_;
    bool is_big_endian_;
};

}  // namespace qdecode