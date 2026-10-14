// qdecode - decode_le.cpp
// Probe: decode a Databento MDP3 payload assuming LITTLE-ENDIAN SBE, to test
// whether Databento's pcap replays are little-endian. Reads the SBE message
// header and attempts to decode an MDIncrementalRefreshBook group.
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "qdecode/byte_order.hpp"
using namespace qdecode;
static std::uint16_t le16(const std::uint8_t* p){std::uint16_t v;std::memcpy(&v,p,2);return v;}
static std::uint32_t le32(const std::uint8_t* p){std::uint32_t v;std::memcpy(&v,p,4);return v;}
static std::uint64_t le64(const std::uint8_t* p){std::uint64_t v;std::memcpy(&v,p,8);return v;}
int main(int argc,char**argv){
  const int fd=::open(argv[1],O_RDONLY);struct stat st;::fstat(fd,&st);
  void* base=::mmap(nullptr,(size_t)st.st_size,PROT_READ,MAP_PRIVATE,fd,0);
  const std::uint8_t* data=(const std::uint8_t*)base;const std::size_t size=(std::size_t)st.st_size;
  const bool lec=(data[0]==0x4D);
  auto cr32=[&](const std::uint8_t*p){std::uint32_t v;std::memcpy(&v,p,4);return lec?v:load_be32(p);};
  std::size_t off=24; int done=0;
  while(off+16<=size && !done){
    const std::uint32_t incl=cr32(data+off+8);
    const std::uint8_t* d=data+off+16; const std::size_t plen=incl;
    if(plen>=14+20+8&&d[12]==0x08&&d[13]==0x00&&d[14+9]==17){
      const std::size_t uo=14+(d[14]&0x0F)*4;
      const std::uint16_t ulen=load_be16(d+uo+4);
      if(ulen>=8){ const std::uint8_t* pay=d+uo+8; const std::size_t pl=ulen-8;
        // Try MDP header at 8 bytes, SBE at pay+8, all LE.
        if(pl>=16){
          const std::uint8_t* m=pay+8;
          std::uint16_t bl=le16(m),tid=le16(m+2),sid=le16(m+4),ver=le16(m+6);
          std::printf("seq(LE)=%u SBE@pay+8: blockLen=%u templateId=%u schemaId=%u version=%u\n",(unsigned)le32(pay),bl,tid,sid,ver);
          // Also try big-endian SBE fields.
          std::printf("  SBE fields BE: blockLen=%u templateId=%u\n",(unsigned)load_be16(m),(unsigned)load_be16(m+2));
          done=1;
        }
      }
    }
    off+=16+incl;
  }
  ::munmap(base,size);::close(fd);return 0;
}