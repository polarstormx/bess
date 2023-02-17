/*
 * Here defines packet header that is used in our project.
 * The `FocusPacketHeader` packs all headers together to be used easily.
 */
#ifndef BESS_UTILS_FLOODGATE_SWITCH_H_
#define BESS_UTILS_FLOODGATE_SWITCH_H_

#include <cstring>
#include "endian.h"
#include "ether.h"
#include "ip.h"
#include "udp.h"
#include "rocev2.hpp"
#include "../utils/checksum.h"

#define FG_UDP_PORT 702
#define MIN_FRAME_SIZE 64

namespace bess {
namespace utils {
  struct [[gnu::packed]] FocusPacketHeader {
	struct [[gnu::packed]] FloodgateHeader {
	  enum Type: uint16_t {
		Data = 0,
		Ack = 1,
		SwitchAck = 2
	  };
	  be16_t type;
	  be16_t length;
	  be32_t seq_num;
	  be32_t credit;
	  FloodgateHeader() = default;
	}; // struct FloodgateHeader
	
	Ethernet eth;         // 14 B
	Ipv4 ip;              // 20 B
	Udp udp;              // 8 B
	union [[gnu::packed]] { // 12 B
	  RoCEv2 roce;
	  FloodgateHeader fgh;
	};

	enum PacketType {
	  Irrelevant,
	  Data,
	  Ack,
	  SwitchAck
	};

	inline bool isIpv4() const {
	  return eth.ether_type.value() == Ethernet::Type::kIpv4;
	}

	inline PacketType CheckProto() const {
	  if (ip.protocol != Ipv4::Proto::kUdp) {
		return PacketType::Irrelevant; // Irrelevant packet, e.g. TCP
	  } else if (udp.dst_port.value() == ROCEV2_UDP_PORT
				 && udp.checksum == 0) { // RoCEv2
		switch(roce.opcode) {
		case RoCEv2::Opcode::Ack: return PacketType::Ack;
		default: return PacketType::Data;
		}
	  } else if (udp.dst_port.value() == FG_UDP_PORT) { // Floodgate
		switch(fgh.type.value()) {
		case FloodgateHeader::Type::Data: return PacketType::Data;
		case FloodgateHeader::Type::Ack: return PacketType::Ack;
		case FloodgateHeader::Type::SwitchAck: return PacketType::SwitchAck;
		default:;
		}
	  }
	  return PacketType::Irrelevant;
	}

	inline uint16_t getDataLength() {
	  return udp.length.value() - sizeof(RoCEv2) - ROCEV2_ICRC_BYTES;
	}
  }; // struct FocusPacketHeader

  static_assert(std::is_pod<FocusPacketHeader::FloodgateHeader>::value, "FloodagteHeader not a POD type");
  static_assert(std::is_pod<FocusPacketHeader>::value, "FocusPacketHeader not a POD type");
  static_assert(sizeof(FocusPacketHeader::FloodgateHeader) == sizeof(RoCEv2),
				"Floodgate header should be the same size of RoCEv2 heder");
  static_assert(sizeof(FocusPacketHeader) == 54, "struct FocusPacketHeader size is not correct");

  /*
   * Generate switch ACK from packet
   */
  inline bess::Packet*
  generate_switch_ack(unsigned char* templ, be32_t pkt_src, be32_t pkt_dst, uint32_t credit) {
	bess::Packet* ack;
	uint32_t total_size = MIN_FRAME_SIZE;
	uint32_t payload_size = total_size - sizeof(FocusPacketHeader);

	if (unlikely(!(ack = current_worker.packet_pool()->Alloc(total_size)))) {
	  LOG(ERROR) << "Cannot allocate packet when generating switch-ACk";
	  return nullptr;
	}
	ack->set_data_off(SNBUF_HEADROOM);
	ack->set_total_len(total_size);
	ack->set_data_len(total_size);

	char *dst = ack->buffer<char *>() + SNBUF_HEADROOM;
	bess::utils::CopyInlined(dst, templ, total_size, false);

	FocusPacketHeader *header = ack->head_data<FocusPacketHeader *>();
	header->eth.ether_type = be16_t(Ethernet::Type::kIpv4);
	// packet src should be ACK's dst, and packet dst should be ACK's src
	header->ip.src = pkt_dst;
	header->ip.dst = pkt_src;
	header->ip.protocol = Ipv4::Proto::kUdp;
	header->fgh.type = be16_t(FocusPacketHeader::FloodgateHeader::Type::SwitchAck);
	header->fgh.credit = bess::utils::be32_t(credit); // used to update inflights
	header->udp.length = be16_t(sizeof(FocusPacketHeader::FloodgateHeader) + payload_size);
	header->udp.dst_port = be16_t(FG_UDP_PORT);
	header->ip.length = be16_t(sizeof(Udp) + header->udp.length.value());
	// header->last_pkt = 0;
	// header->voq = nullptr;

	header->udp.checksum = bess::utils::CalculateIpv4UdpChecksum(header->ip, header->udp);
	// header->ip.checksum = bess::utils::CalculateIpv4Checksum(*ip);
	return ack;
  } // generate_switch_ack()

  inline void markECN(bess::Packet *packet) {
	FocusPacketHeader *header = packet->head_data<FocusPacketHeader*>();
#if __BYTE_ORDER == __LITTLE_ENDIAN
	header->ip.type_of_service |= 0b11000000; // mark ECN two bits as 0b11
#elif __BYTE_ORDER == __BIG_ENDIAN
	header->ip.type_of_service |= 0b11;
#else
#error __BYTE_ORDER must be defined.
#endif
  }

  /*
   * Bind metadata to packet
   */
  class PacketMeta {
  public:
	class Metadata {
	public:
	  enum Type : uint16_t {
		Data = 0,
		Ack = 1,
		SwitchAck = 2,
		Others = 3
	  };
	  Type type;
	  bess::gate_idx_t inport;
	  void *voq;
	  
	  Metadata(): type(Type::Data), inport(0), voq(nullptr) {}
	  Metadata(Type t, bess::gate_idx_t p, void* v):
		type(t), inport(p), voq(v) {}
	};
	
	Metadata meta;
	bess::Packet *packet;

	PacketMeta() = default;
	PacketMeta(bess::Packet *pk): meta(), packet(pk) {}
	PacketMeta(Metadata::Type t, bess::Packet *pk):
	  meta(Metadata(t, 0, nullptr)), packet(pk) {}
	PacketMeta(Metadata::Type t, bess::gate_idx_t p, void* v, bess::Packet *pk):
	  meta(Metadata(t, p, v)), packet(pk) {}
  }; // class PacketMeta
  
}  // namespace utils
}  // namespace bess


#endif  // BESS_UTILS_FLOODGATE_SWITCH_H_
