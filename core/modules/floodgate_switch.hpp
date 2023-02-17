#ifndef BESS_MODULES_FLOODGATE_SWITCH_H_
#define BESS_MODULES_FLOODGATE_SWITCH_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../kmod/llring.h"
#include "../utils/endian.h"
#include <arpa/inet.h>
#include <atomic>
#include <vector>
#include <unordered_map>
#include <random>

#include "../utils/floodgate_header.hpp"
#include "../utils/network_utils.h"  // StaticRoutingTable is defined here
#include "../utils/format.h"
#include "../utils/yarray.h"

#define PKT_OVERHEAD 24
#define SWITCH_ACK_TEMPLATE_SIZE 88  // 64 + PKT_OVERHEAD(24)
#define BUF_ENQUEUE_SUCCESS 0
#define BUF_ENQUEUE_MARK_ECN 1

/* Custom hash function for faster IP hashing */
struct IpHash {
  std::size_t operator()(bess::utils::be32_t const& v) const noexcept {
	return (v.value() & 0xff) - 1;	
  }
};

/*
 * Initialize a llring queue.
 * sp means single producer, sc means single consumer.
 */
struct llring* newQueue(uint32_t size, bool sp = false, bool sc = true);

struct Voq {
  // bess::utils::be32_t ip_addr;  // ip destination this VOQ sends to. Only used by log now. May remove.
  std::atomic<uint32_t> inflight;  // # of packets in-flight, i.e. per-dst sending window
  uint32_t inflight_limit; // limit # of in-flight packets
  std::atomic<uint64_t> qcnt; // how many elements is in queue
  uint64_t maxLen;
  struct llring *queue;

  Voq() = default;
  bool Preallocate(uint32_t queue_size);
  inline void set_limit(uint32_t inflight_lim) { inflight_limit = inflight_lim; }
  inline bool empty() { return qcnt.load() == 0; }
  inline bool hit_limit() {
	const uint32_t inf = inflight;
	return inf < 0xffffff && inf >= inflight_limit;
  }
  inline uint64_t length() { const uint32_t l = qcnt.load(); return l < 0xffff ? l : 0; }
  inline int enqueue(bess::utils::PacketMeta *pmeta) {
	// multiple producers enqueue
	int err = llring_mp_enqueue(queue, pmeta);
	if (!err) {
	  qcnt.fetch_add(1, std::memory_order_relaxed);
	  const uint64_t len = length();
	  if (len > maxLen) maxLen = len;
	}
	return err;
  }
  inline bess::utils::PacketMeta* dequeue() {
	bess::utils::PacketMeta* pmeta;
	if (!llring_sc_dequeue(queue, (void**)(&pmeta))) {
	  qcnt.fetch_sub(1, std::memory_order_relaxed);
	  return pmeta;
	}
	return nullptr;
  }
	
}; // struct Voq

/*
 * Used to accumulate packets credits to send switch_ACK.
 * A CreditAccumulator should accumulate credits according to packet's mibo length.
 * Also store how many packets are not sent which are in queue.
 * If the packets-in-queue is zero or credit_ hit limit, send one switch_ACK.
 */
class CreditAccumulator {
public:
  const gate_idx_t port; // port bound to this accumulator
  const bess::utils::be32_t src;
  const bess::utils::be32_t dst;
  CreditAccumulator(uint32_t credit_limit, uint64_t timeout, gate_idx_t p,
					bess::utils::be32_t s, bess::utils::be32_t d):
	port(p), src(s), dst(d),
    credit_(0),
	credit_limit_(credit_limit),
	timestamp_(),
	timeout_(timeout) {
	timestamp_ = rdtsc();
  }
  inline bool credit_hit_limit() {
	return credit_ >= credit_limit_;
  }
  inline bool should_fire(uint64_t current_ns) {
	const uint64_t credit = credit_;
	return credit >= credit_limit_
	  || (credit > 0 && current_ns >= timestamp_ + timeout_);
  }
  inline uint32_t credit() { return credit_; }
  inline void incr_credit(uint32_t credit) {
    credit_.fetch_add(credit, std::memory_order_relaxed);
  }
  inline void reset(uint64_t current_ns, uint64_t old_credit) {
	credit_.fetch_sub(old_credit, std::memory_order_relaxed);
	timestamp_ = current_ns;
  }

private:
  std::atomic<uint64_t> credit_;
  const uint32_t credit_limit_;
  std::atomic<uint64_t> timestamp_;
  const uint64_t timeout_;
}; // class CreditAccumulator

/*
 * Configuration of output port
 */
class OPort {
public:
  uint32_t m;  // a parameter of Floodgate
  uint32_t bdpi; // BDP of this output gate
  uint32_t bound_voqs_idx; // index of `bound_voqs`, used in RunTask() to send out packets by round-robin
  std::unordered_map<bess::utils::be32_t, CreditAccumulator*, IpHash> bound_cas; // bound CreditAccumulators, mapped from ip_dst to CreditAccumulator*
  uint8_t omac[bess::utils::Ethernet::Address::kSize]; // MAC address on the other end of this port
  bool edge;  // whether this port is the edge of FloodgateSwitch cluster, e.g. connected to a host
  OPort() = default;
  OPort(uint32_t mm, uint32_t b, bool e, uint32_t cap):
	m(mm), bdpi(b), bound_voqs_idx(0), bound_cas(),
	edge(e), bound_voqs_(), buf_(), cnt_(0),
	kmax_(), kmin_(), randGen_() {
	bound_voqs_.reserve(cap);
	bound_cas.reserve(cap);
  }
  inline void Config(uint32_t mm, uint32_t b, uint32_t kmax, uint32_t kmin,
					 bool e, uint32_t cap) {
	m = mm; bdpi = b; bound_voqs_idx = 0; edge = e; cnt_ = 0;
	bound_voqs_.reserve(cap);
	bound_cas.reserve(cap);
	kmax_ = kmax;
	kmin_ = kmin;
	llring_set_water_mark(buf_, kmax);
  }
  bool Preallocate(uint32_t buffer_size); 
  inline void bindVoq(struct Voq* voq) { bound_voqs_.push_back(voq); }
  inline struct Voq* getVoq(uint32_t idx) { return bound_voqs_[idx]; }
  inline uint32_t voqsNum() { return bound_voqs_.size(); }
  inline int bufEnq(bess::utils::PacketMeta *pmeta) {
    int err = llring_mp_enqueue(buf_, pmeta);
	if (err == -LLRING_ERR_NOBUF) {
	  return -LLRING_ERR_NOBUF; // negative number -1
	}
	cnt_.fetch_add(1, std::memory_order_relaxed);
	// if (err == -LLRING_ERR_QUOT || shouldEcn((struct Voq*)pmeta->meta.voq)) {
	if (err == -LLRING_ERR_QUOT || shouldEcn()) {
	  return BUF_ENQUEUE_MARK_ECN; // 1
	}
	return BUF_ENQUEUE_SUCCESS;
  }
  inline uint32_t bufDeq(bess::utils::PacketMeta** pktbatch, uint32_t burst) {
	uint32_t c = llring_sc_dequeue_burst(buf_, (void**)(pktbatch), burst);
	cnt_.fetch_sub(c, std::memory_order_relaxed);
	return c;
  }
  inline int bufSize() const { const int c = cnt_.load(); return c >=0 ? c : 0; }
  inline uint32_t length() const { return llring_count(buf_); }
  inline bool shouldEcn() {
	const int cnt = cnt_;
	return cnt > (int)kmin_ && randGen_() % 100 < (cnt - (int)kmin_) * 20 / (kmax_ - kmin_);
  }

  bess::utils::Yarray<struct Voq*> bound_voqs_; // indices of voqs that send packets through this port
  struct llring *buf_;
  std::atomic<int> cnt_; // how many elements is in buffer
  uint32_t kmax_, kmin_;  // for ECN
  std::mt19937 randGen_; // random number generator
}; // class OPort

class FloodgateSwitch final: public Module {
 public:
  FloodgateSwitch():
	Module(),
	burst_(),
	prefetch_(),
	queue_size_(),
	credit_limit_(),
	templ_(),
	routing_table_(),
	oports_(),
	voqs_(),
	voqs_last_idx_(),
	ip2voq_(),
	enable_floodgate_(),
	stat_() {
	is_task_ = true;
	propagate_workers_ = false;
	max_allowed_workers_ = Worker::kMaxWorkers; // support multiple workers
  }
  static const gate_idx_t kNumIGates = MAX_GATES; // s.t. can have multiple input gates
  static const gate_idx_t kNumOGates = MAX_GATES; // s.t. can have multiple output gates
  
  /*
   * Commands of this module.
   * add_routes -- CommandAddRoutes
   * config_oport -- CommandConfigOPort
   */
  static const Commands cmds;
  
  /* 
   * Init() is called when starting
   */
  CommandResponse Init(const bess::pb::FloodgateSwitchArg &arg);
  
  /*
   * Add routes to routing table
   */
  CommandResponse CommandAddRoutes(const bess::pb::FloodgateSwitchCommandAddRoutesArg &arg);

  /*
   * Configure one output port
   */
  CommandResponse CommandConfigOPort(const bess::pb::FloodgateSwitchCommandConfigOPortArg &arg);

  /*
   * Called when a batch of packets from upstream arrives at FloodgateSwitch.
   */
  void ProcessBatch(Context * ctx, bess::PacketBatch *batch) override;

  /*
   * Called when scheduled, send out a batch of packets to downstream.
   */
  struct task_result RunTask(Context *ctx, bess::PacketBatch *batch, void *portId) override;

  /*
   * Description message showed in pipeline
   */
  std::string GetDesc() const override;
 
 private:
  /*
   * For statistics
   */
  struct Stat {
	std::atomic<uint64_t> out_cnt, drop_cnt, ack_cnt, qecn_cnt, vecn_cnt;
	std::vector<uint64_t> buf_sizes;
	Stat(): out_cnt(0), drop_cnt(0), ack_cnt(0), qecn_cnt(0), vecn_cnt(0), buf_sizes() {}
  };
  
  uint32_t burst_; // how many packets the switch sends out as a batch
  bool prefetch_; // DPDK prefetch first 64B of each packet to L1 cache
  uint32_t queue_size_; // queue size of VOQ and egress buffer
  uint32_t credit_limit_; // credit limit of CreditAccumulator
  uint64_t ca_timeout_; // credit accumulator timeout
  uint32_t voq_resume_lim_; // VOQ length limitation to resume sending credit ACk
  unsigned char templ_[SWITCH_ACK_TEMPLATE_SIZE] = {};  // template to generate switch-ACK
  bess::utils::StaticRoutingTable routing_table_;
  std::vector<struct OPort*> oports_;  // output ports
  std::vector<struct Voq*> voqs_; // VOQs
  uint16_t voqs_last_idx_; // point to the index after lastly used VOQs
  std::unordered_map<bess::utils::be32_t, struct Voq*, IpHash> ip2voq_;

  bool enable_floodgate_;
  struct Stat stat_;  // statistics

  /*
   * Update complicated arguments.
   * Typically stores packet template.
   */
  CommandResponse ProcessUpdatableArguments(const bess::pb::FloodgateSwitchArg &arg);

  inline bool send(bess::utils::PacketMeta *packet, bess::gate_idx_t port);

  /*
   * Corresponds to 3 FloodgateHeader type
   */
  inline void processPktData(Context *ctx, bess::Packet *packet, bess::gate_idx_t port);
  inline void processPktAck(Context *ctx, bess::Packet *packet, bess::gate_idx_t port);
  inline void processPktSwitchAck(Context *ctx, bess::Packet *packet);

  /*
   * Accumulate the CreditAccumulator of the <inport, ip_dst>, if should fire a switch-ACK,
   */
  inline void creditAccumulate(bess::utils::FocusPacketHeader *header, bess::gate_idx_t inport);

  /*
   * Corresponds to 2 task types.
   */
  inline void runQueue(bess::PacketBatch *batch, bess::gate_idx_t port);
  inline void runCore(Context *ctx, bess::gate_idx_t port);

}; // class FloodgateSwitch


#endif  // BESS_MODULES_FLOODGATE_SWITCH_H_
