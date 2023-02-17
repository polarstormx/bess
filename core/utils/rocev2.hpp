#ifndef BESS_UTILS_ROCEV2_H_
#define BESS_UTILS_ROCEV2_H_

#include "endian.h"

#define ROCEV2_ICRC_BYTES 4
#define ROCEV2_UDP_PORT 4791

namespace bess {
namespace utils {
  
  /*
   * RoCEv2 header. Should also have 4 bytes ICRC at the end of the packet.
   */
  struct [[gnu::packed]] RoCEv2 { // 12 bytes
	enum Opcode : uint8_t {
	  SEND_First = 0,
	  SEND_Middle = 1,
	  SEND_Last = 2,
	  Ack = 0x11,
	};
	
	Opcode opcode;
	uint8_t omit;
	be16_t p_key; // partition key
	uint8_t fb_reserve;
	struct [[gnu::packed]] QP { uint8_t data[3]; } dest_qp; // Destination Queue Pair
	uint8_t ackreq; // Acknowledge Request (1 bit) and reserved 7 bits
	struct [[gnu::packed]] PSN { uint8_t data[3]; } psn; // Packet Sequence Number

	RoCEv2() = default;
  }; // struct RoCEv2

  static_assert(std::is_pod<RoCEv2>::value, "RoCEv2 not a POD type");
  static_assert(sizeof(RoCEv2) == 12, "struct RoCEv2 size is not 12");
  
} // namepsace utils
} // names bess

#endif // BESS_UTILS_ROCEV2_H_
