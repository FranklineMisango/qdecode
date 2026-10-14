// qdecode - find_sbe.cpp
// Scan a payload for the SBE message header position/byte-order such that the
// templateId is a known CME MDP 3.0 message type and blockLength is sane.
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
// Known MDP3 template ids of interest.
static bool known_tid(std::uint16_t t){
  switch(t){case 5:case 9:case 12:case 14:case 21:case 23:case 27:case 31:case 33:
    case 34:case 35:case 36:case 37:case 38:case 46:case 50:case 54: return true;}
  return false;
}
int main(int argc,char**argv){
  const int fd=::open(argv[1],O_RDONLY);struct stat st;::fstat(fd,&st);
  void* base=::mmap(nullptr,(size_t)st.st_size,PROT_READ,MAP_PRIVATE,fd,0);
  const std::uint8_t* data=(const std::uint8_t*)base;const std::size_t size=(std::size_t)st.st_size;
  const bool lec=(data[0]==0x4D);
  auto cr32=[&](const std::uint8_t*p){std::uint32_t v;std::memcpy(&v,p,4);return lec?v:load_be32(p);};
  std::size_t off=24; int n=0;
  while(off+16<=size && n<6){
    const std::uint32_t incl=cr32(data+off+8);
    const std::uint8_t* d=data+off+16; const std::size_t plen=incl;
    if(plen>=14+20+8&&d[12]==0x08&&d[13]==0x00&&d[14+9]==17){
      const std::size_t uo=14+(d[14]&0x0F)*4;
      const std::uint16_t ulen=load_be16(d+uo+4);
      if(ulen>=8){ const std::uint8_t* pay=d+uo+8; const std::size_t pl=ulen-8;
        std::printf("payload=%zu seq(LE)=%u\n",pl,(unsigned)le32(pay));
        // Candidate: SBE header somewhere from pay+3..pay+11
        for (std::size_t s=3;s<=11 && pl>=s+8;s++){
          const std::uint8_t* m=pay+s;
          std::uint16_t bl_le=le16(m), tid_le=le16(m+2);
          std::uint16_t bl_be=load_be16(m), tid_be=load_be16(m+2);
          if (known_tid(tid_le)) std::printf("  off=%zu LE: blockLen=%u templateId=%u schemaId=%u\n",s,bl_le,tid_le,le16(m+4));
          if (known_tid(tid_be)) std::printf("  off=%zu BE: blockLen=%u templateId=%u schemaId=%u\n",s,bl_be,tid_be,load_be16(m+4));
        }
        n++;
      }
    }
    off+=16+incl;
  }
  ::munmap(base,size);::close(fd);return 0;
}