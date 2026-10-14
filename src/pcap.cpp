// qdecode - pcap.cpp
// ---------------------------------------------------------------------------
// Implementation of the mmap-based PCAP reader (see pcap.hpp for the layout).
// The PCAP file is mapped read-only with MAP_PRIVATE so we never dirty the
// page cache; the SBE decoders then read the wire bytes in place.

#include <cerrno>
#include <cstring>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "qdecode/byte_order.hpp"
#include "qdecode/pcap.hpp"

namespace qdecode {

// PCAP layout constants.
namespace {
constexpr std::size_t kGlobalHeaderLen = 24U;
constexpr std::size_t kRecordHeaderLen = 16U;
// Byte patterns of the classic pcap magic as it appears on disk.
constexpr std::uint8_t kMagBe[4] = {0xA1, 0xB2, 0xC3, 0xD4};  // big-endian
constexpr std::uint8_t kMagLe[4] = {0x4D, 0x3C, 0xB2, 0xA1};  // little-endian
}  // namespace

bool PcapView::validate() noexcept {
    if (size_ < kGlobalHeaderLen) [[unlikely]]
        return false;
    // Detect container byte order from the raw magic byte pattern.
    const std::uint8_t* g = data_;
    if (g[0] == kMagBe[0] && g[1] == kMagBe[1] && g[2] == kMagBe[2] &&
        g[3] == kMagBe[3]) {
        is_big_endian_ = true;  // classic big-endian pcap
    } else if (g[0] == kMagLe[0] && g[1] == kMagLe[1] && g[2] == kMagLe[2] &&
               g[3] == kMagLe[3]) {
        is_big_endian_ = false;  // classic little-endian pcap
    } else {
        return false;
    }
    cursor_ = kGlobalHeaderLen;
    return true;
}

std::uint32_t PcapView::record_u32(std::size_t rel) const noexcept {
    const std::uint8_t* p = data_ + cursor_ + rel;
    return is_big_endian_ ? load_be32(p) : load_le32(p);
}

bool PcapView::next_packet(std::uint64_t& ts_sec, std::uint64_t& ts_usec,
                           const std::uint8_t** payload,
                           std::size_t& payload_len) noexcept {
    if (cursor_ > size_) [[unlikely]]
        return false;
    if (size_ - cursor_ < kRecordHeaderLen) [[unlikely]]
        return false;

    ts_sec = record_u32(0);
    ts_usec = record_u32(4);
    const std::uint32_t incl_len = record_u32(8);
    (void)record_u32(12);  // orig_len

    const std::size_t record_end = cursor_ + kRecordHeaderLen + incl_len;
    if (record_end > size_) [[unlikely]]
        return false;  // truncated capture

    *payload = data_ + cursor_ + kRecordHeaderLen;
    payload_len = incl_len;
    cursor_ = record_end;
    return true;
}

// ---------------------------------------------------------------------------
// PcapFile: owns an mmap'd capture. RAII closes the fd and unmaps on destroy.
// (Declaration lives in qdecode/pcap.hpp.)
// ---------------------------------------------------------------------------
PcapFile::PcapFile() noexcept : fd_(-1), base_(nullptr), len_(0) {}
PcapFile::~PcapFile() { close(); }

/// Open `path` and map it read-only. Returns false and leaves errno set on
/// failure. This is the zero-copy ingest path: no fread, no heap buffer.
bool PcapFile::open_mmap(const char* path) noexcept {
    close();
    const int fd = ::open(path, O_RDONLY);
    if (fd < 0) [[unlikely]]
        return false;
    struct stat st;
    if (::fstat(fd, &st) != 0) [[unlikely]] {
        ::close(fd);
        return false;
    }
    if (st.st_size == 0) [[unlikely]] {
        ::close(fd);
        errno = EINVAL;
        return false;
    }
    void* base = ::mmap(nullptr, static_cast<std::size_t>(st.st_size),
                        PROT_READ, MAP_PRIVATE, fd, 0);
    if (base == MAP_FAILED) [[unlikely]] {
        const int saved = errno;
        ::close(fd);
        errno = saved;
        return false;
    }
    // fd may be closed immediately; the mapping remains valid.
    ::close(fd);
    fd_ = -1;
    base_ = static_cast<std::uint8_t*>(base);
    len_ = static_cast<std::size_t>(st.st_size);
    return true;
}

PcapView PcapFile::view() const noexcept {
    return PcapView(base_, len_);
}

void PcapFile::close() noexcept {
    if (base_ != nullptr) {
        ::munmap(base_, len_);
        base_ = nullptr;
        len_ = 0;
    }
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

}  // namespace qdecode