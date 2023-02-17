#ifndef BESS_MODULES_ENDHOST_H_
#define BESS_MODULES_ENDHOST_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/udp.h"

#include "../utils/floodgate_header.hpp"
#include "../utils/network_utils.h"
#include "../utils/format.h"
#include <fstream>
#include <unordered_map>

#define MAX_TEMPLATE_SIZE 1536
// #define MAX_PAYLOAD_SIZE 1000
#define PKT_OVERHEAD 24

class Endhost final: public Module {
  // struct FlowInfo {
  // 	enum Status {Sleep = 0, Sending, Tail, Finished}; // Tail means waiting for last ACK
  // 	uint32_t id;
  // 	uint32_t inflight; // # of packets that are in-flight
  // 	uint32_t inflight_limit; // window size
  // 	enum Status status;
  // 	uint64_t finish_time; // time when receives the last ACK
  // 	FlowInfo() = default;
  // 	FlowInfo(uint32_t i,  uint32_t limit): id(i), inflight(), inflight_limit(limit),
  // 								  status(), finish_time() {}
  // 	inline bool win_full() { return inflight >= inflight_limit; }
  // };

public:
  Endhost() :
	Module(),
	burst_(),
	endhost_id_(),
	flow_events_(),
	templ_(),
	templ_size_(),
	eid2ips_(),
	stat_() { max_allowed_workers_ = 2; }

  /*
   * Commands of this module.
   * config_sender -- CommandConfigSender
   * dump_fcts -- CommandDumpFcts
   */
  static const Commands cmds;
  
  /* 
   * Init() is called when starting
   */
  CommandResponse Init(const bess::pb::EndhostArg &arg);

  /*
   * Configure sender
   */
  CommandResponse CommandConfigSender(const bess::pb::EndhostCommandConfigSenderArg &arg);

  /*
   * Dump flow info to a file
   */
  CommandResponse CommandDumpFcts(const bess::pb::EmptyArg &);
  
  /*
   * Called when a batch of packets arrives at Endhost which should be data packets or ACKs.
   */
  void ProcessBatch(Context * ctx, bess::PacketBatch *batch) override;

  /*
   * Called when scheduled, send out a batch of packets to downstream.
   */
  struct task_result RunTask(Context *ctx, bess::PacketBatch *batch, void *) override;

  /*
   * Description message showed in pipeline
   */
  std::string GetDesc() const override;

private:
  /*
   * For statistics
   */
  struct Stat {
	std::atomic<uint64_t> out_cnt, ack_cnt, reply_cnt;
	Stat() = default;
  };

  uint32_t burst_; // how many packet sent in one batch
  uint32_t endhost_id_; // ID of this Endhost
  bess::utils::FlowEvents flow_events_;
  unsigned char templ_[MAX_TEMPLATE_SIZE] = {};  // template to generate packet
  uint32_t templ_size_; // size of template
  std::unordered_map<uint32_t, bess::utils::be32_t> eid2ips_; // map of Endhost ID to IP address

  struct Stat stat_;  // statistics

  /*
   * Used by ProcessBatch() to deal with two kinds of packets
   */
  inline void processPktData(Context * ctx, bess::Packet *packet);
  inline void processPktAck(Context *ctx, bess::Packet *packet);

  /*
   * Used by RunTask() to genrate a packet according to shot info
   */
  inline bess::Packet* generateFgPacket(bess::utils::FlowEvents::FlowOneShot shot);
}; // class Endhost


#endif // BESS_MODULES_ENDHOST_H_
