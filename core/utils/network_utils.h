#ifndef BESS_UTILS_NETWORK_UTILS_H_
#define BESS_UTILS_NETWORK_UTILS_H_

#include <arpa/inet.h>
#include <string>
#include <vector>
#include <sstream>
#include <atomic>
#include "cuckoo_map.h"
#include "endian.h"
#include "../gate.h"

namespace bess {
namespace utils {

std::string ip2str(be32_t ip_addr);
be32_t str2ip(std::string ip_str);
  
struct NetworkAddress {
  be32_t addr;
  be32_t mask;

  NetworkAddress(be32_t a, be32_t m): addr(a), mask(m) {}

  /*
   * construct networkaddress with a string e.g. 172.16.0.0/24
   */
  NetworkAddress(const std::string net_str) {
	std::size_t slash_idx = net_str.find('/');
	if (slash_idx != std::string::npos) {
	  std::string addr_str = net_str.substr(0, slash_idx);
	  std::string mask_str = net_str.substr(slash_idx+1);
	  uint32_t a;
	  if (inet_pton(AF_INET, addr_str.c_str(), &a)) {
		uint32_t shift = 32 - std::stoi(mask_str);
		mask = be32_t(0xffffffff >> shift << shift);
		addr = be32_t::raw_load(a) & mask; // a is big-endian
		return;
	  }
	}
	// wrong string format;
	addr = be32_t(0);
	mask = be32_t(0);
  }
}; // struct networkaddress

class StaticRoutingTable {
public:
  StaticRoutingTable(gate_idx_t default_gate = LookupFailed):
	table_tuples_(),
	default_gate_(default_gate) {}
  ~StaticRoutingTable() {
	for (auto tuple: table_tuples_) {
	  delete tuple.ht;
	}
  }
  static const gate_idx_t LookupFailed = 0xffff; // indicates entry not found
  bool AddRoute(const std::string net_str, const gate_idx_t gate); // inefficient because uses vector::insert
  
  /*
   * Look up entry according to ip address in RoutingTable, return gate_idx if found, else -1.
   */
  inline bess::gate_idx_t LookupEntry(be32_t ip_addr)  {
	for (auto tuple : table_tuples_) {
	  be32_t net_addr = ip_addr & tuple.mask;
	  std::pair<be32_t, gate_idx_t> *result = tuple.ht->Find(net_addr);
	  if(result != nullptr) {
		return result->second;
	  }
	}
	return default_gate_; // if default_gate_ not set, it will be LookupFailed.
  }

private:
  /*
   * StaticRoutingTable tuple, tables with different masks store in different tuples.
   */
  struct SrtTuple {
	CuckooMap<be32_t, gate_idx_t> *ht;  // hash table
	be32_t mask;
	SrtTuple() =  default;
	SrtTuple(be32_t m):
	  ht(new CuckooMap<be32_t, gate_idx_t>()),
	  mask(m) {}
  };
  
  /*
   * Tuples are sorted by mask length from large to small, so that traverse the tuples will
   * do the max-prefix matching of CIDR.
   */
  std::vector<struct SrtTuple> table_tuples_;
  gate_idx_t default_gate_;

}; // class StaticRoutingTable

class FlowEvents {

  struct FlowEvent {
	enum Status {Sleep = 0, Sending, Tail, Finished}; // Tail means waiting for last ACK
	const uint32_t id; // flow ID
	const uint64_t arrive_time; // microseconds
	const uint32_t dst; // dst sender_id
	uint64_t size; // size of this flow
	
	uint64_t real_start_time; // real start time
	uint64_t real_finish_time; // time when receives the last ACK
	const uint32_t win_inc; // windows increase rate *10
	enum Status status;
	
	struct FlowEvent *prev; // previous FlowEvent that is activated but has not finished
	struct FlowEvent *next; // next FlowEvent that is activated but has not finished

	FlowEvent(uint32_t i, uint64_t t, uint32_t d, uint64_t sz,uint32_t inc):
	  id(i), arrive_time(t), dst(d), size(sz),
	  real_start_time(), real_finish_time(),win_inc(inc), status(), prev(), next() {}
	inline bool win_full() { return inflight >= inflight_limit; }
  };

public:
	static std::atomic<uint32_t> inflight; // # of packets that are in-flight
	static uint32_t inflight_limit; // window size	
  // used to pass flow information to other class
  struct FlowOneShot {
	const uint32_t id; // flow ID
	const uint32_t dst; // dst sender_id
	const uint32_t size; // size of this shot
	const uint32_t seq; // sequence number. Only indicates whether this is the last packet for now.
  FlowOneShot(uint32_t i, uint32_t d, uint32_t s, uint32_t sq): id(i), dst(d), size(s), seq(sq) {}
  };

  FlowEvents() = default;

  /*
   * Initiate the FlowEvents from a stream which has lines that are in format of:
   * "flow_id src dst size arrive_time"
   * Return how many flows to send
   */
  uint32_t Init(std::istream &flow_raw_input, uint32_t sender_id,
							 uint32_t inflight_limit,uint32_t win_inc, uint32_t max_shot_bytes = 1000);

  /*
   * Record the start time
   */
  inline void Start(uint64_t start_time) {
	start_time_ = start_time;
  }

  /*
   * According to current time in nanoseconds, put events that should be activated into
   * the double linked list.
   */
  inline bool RefreshNewEvents(uint64_t current_ns) {
	uint64_t elapsed = current_ns - start_time_;
	if (boundary_idx_ >= flow_events_.size()) return false;
	if (flow_events_[boundary_idx_]->arrive_time <= elapsed) {
	  if (act_head_->next == nullptr) {
		flow_events_[boundary_idx_]->real_start_time = current_ns;
		flow_events_[boundary_idx_]->status = FlowEvent::Status::Sending;
		// Add to the first of double linked list
		act_head_->next = flow_events_[boundary_idx_];
		act_tail_ = act_head_->next;
		act_ptr_ = act_head_->next;
		act_ptr_->prev = act_head_;
		boundary_idx_ ++;
	  }
	} else return false;
	
	for (; boundary_idx_ < flow_events_.size(); boundary_idx_++) {
	  if (flow_events_[boundary_idx_]->arrive_time <= elapsed) {
		struct FlowEvent *tmp = flow_events_[boundary_idx_];
		tmp->real_start_time = current_ns;
		tmp->status = FlowEvent::Status::Sending;
		// Add to double linked list
		act_tail_->next = tmp;
		tmp->prev = act_tail_;
		act_tail_ = tmp;
	  } else {
		break;
	  }
	}
	return true;
  }

  /*
   * Find one event that is ready (is actived and window is not full).
   * Return the flow_id, destination_id, bytes should send
   */
  inline FlowOneShot GetFlowShot() {
	FlowEvent *tmp = getNextEvent(), *event = tmp;
	do {
	  if (event != nullptr) {
		if (!event->win_full()) {
		  std::pair<uint32_t, uint32_t> datap = pullCurrentEventData();  
		  FlowEvents::inflight += 10;
		  return FlowOneShot(event->id, event->dst, datap.first, datap.second);
		}
		event = getNextEvent();
	  }
	} while(event && event != tmp); // if all events are blocked, exit the loop

	// no event is ready
	return FlowOneShot(0xffffffff, 0xffffffff, 0, false);
  }

  /*
   * Ack one packet of the flow_id.
   * Return whether successfully acked.
   */
  inline bool Ack(uint32_t flow_id, uint64_t current_ns, uint32_t seq) {
	std::pair<uint32_t, uint32_t> *idx = fid2idx_.Find(flow_id);
	if (idx == nullptr) return false;
	FlowEvents::inflight -= flow_events_[idx->second]->win_inc;
	// if (flow_events_[idx->second].status == FlowEvent::Status::Tail) {
	if (seq == 0xffffffff) {
	  // the last ACK
	  flow_events_[idx->second]->status = FlowEvent::Status::Finished;
	  flow_events_[idx->second]->real_finish_time = current_ns;
	}
	return true;
  }
  
  /*
   * After all the events finished, return a stream s.t. can be used to output.
   */
  std::stringstream GetFlowTime();

private:
  uint32_t max_shot_bytes_; // max bytes sent in one shot
  std::vector<struct FlowEvent*> flow_events_;
  uint64_t start_time_; // start time (ns)
  uint32_t boundary_idx_; // boundary in flow_events_ where indices small than it are activated
  struct FlowEvent *act_head_; // the empty head of FlowEvent that is sending
  struct FlowEvent *act_tail_; // the tail of FlowEvent that is sending
  struct FlowEvent *act_ptr_; // a pointer moving in a ring points to all activated events

  bess::utils::CuckooMap<uint32_t, uint32_t>  fid2idx_; // map from flow ID to flows_events_ index

  /*
   * Get next event pointer (to do some check)
   */
  inline FlowEvent* getNextEvent() {
	if (act_ptr_ == nullptr) return nullptr; // no event is ready
	act_ptr_ = act_ptr_->next ? act_ptr_->next : act_head_->next;
	return act_ptr_;
  }

  /*
   * Get current event data for one packet, max length is max_shot_bytes.
   * Return: <payload length to be sent, whether remains data to be sent>
   */
  inline std::pair<uint32_t, uint32_t> pullCurrentEventData() {
	uint32_t data, seq = 0;
	if (act_ptr_->size > max_shot_bytes_) {
	  data = max_shot_bytes_;
	  act_ptr_->size -= max_shot_bytes_;
	} else {
	  data = act_ptr_->size;
	  act_ptr_->status = FlowEvent::Status::Tail;
	  seq = 0xffffffff;
	  // Remove from double linked list
	  act_ptr_->prev->next = act_ptr_->next;
	  if (act_ptr_ != act_tail_) {
		act_ptr_->next->prev = act_ptr_->prev;
	  } else {
		act_tail_ = act_tail_->prev;
	  }
	  // we don't move act_ptr_ here since when call getNextEvent() later, things go right.
	}
	return std::make_pair(data, seq);
  }

}; // class FlowEvents
  
} // namepsace utils
} // namespace bess

#endif // BESS_UTILS_NETWORK_UTILS_H_
