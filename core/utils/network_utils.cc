#include "network_utils.h"
#include "../gate.h"
#include <stdint.h>

using bess::utils::FlowEvents;
using bess::utils::StaticRoutingTable;

std::string bess::utils::ip2str(bess::utils::be32_t ip_addr) {
  char ipStr[16];
  uint32_t ipa = ip_addr.raw_value();
  inet_ntop(AF_INET, &ipa, ipStr, 16);
  return std::string(ipStr);
}

bess::utils::be32_t bess::utils::str2ip(std::string ip_str) {
  uint32_t ip;
  if (inet_pton(AF_INET, ip_str.c_str(), &ip)) {
    return bess::utils::be32_t::raw_load(ip);  // ip is already big endian
  }
  return bess::utils::be32_t(0);
}

bool StaticRoutingTable::AddRoute(const std::string net_str,
                                  const gate_idx_t gate) {
  bess::utils::NetworkAddress net_addr(net_str);
  if (net_addr.addr.value() == 0) {
    // wrong network address string
    return false;
  }
  if (!table_tuples_.empty()) {
    for (auto tuple = table_tuples_.begin(); tuple != table_tuples_.end();
         tuple++) {
      if (net_addr.mask == tuple->mask) {
        tuple->ht->Insert(net_addr.addr, gate);
        return true;
      } else if (net_addr.mask > tuple->mask) {
        // Add a new tuple since no mask matches
        auto nt = table_tuples_.insert(
            tuple, StaticRoutingTable::SrtTuple(net_addr.mask));
        nt->ht->Insert(net_addr.addr, gate);
        return true;
      }
    }
  }
  // the new mask is smaller than those in tuples, append the mask.
  StaticRoutingTable::SrtTuple st(net_addr.mask);
  st.ht->Insert(net_addr.addr, gate);
  table_tuples_.push_back(st);
  return true;
}

/*
 * Initiate the FlowEvents from a stream which has lines that are in format of:
 * "flow_id src dst size arrive_time"
 * Return how many flows to send
 */
uint32_t FlowEvents::Init(std::istream &flow_raw_input, uint32_t sender_id,
                          uint32_t _inflight_limit, uint32_t win_inc,
                          uint32_t max_shot_bytes)
                          {
  uint32_t flow_id, src;
  uint16_t dst;
  uint64_t size;
  double arrive_time;
  FlowEvents::inflight_limit=_inflight_limit;
  while (flow_raw_input >> flow_id >> src >> dst >> size >> arrive_time) {
    if (src == sender_id) {
      FlowEvents::FlowEvent *fe = new FlowEvents::FlowEvent(
          flow_id,
          (uint64_t)(arrive_time * 1e9),  // nanoseconds
          dst, size, win_inc);
      flow_events_.push_back(fe);
      fid2idx_.Emplace(flow_id, flow_events_.size() - 1);
    }
  }

  boundary_idx_ = 0;
  max_shot_bytes_ = max_shot_bytes;
  act_ptr_ = nullptr;
  act_head_ = new struct FlowEvent(0, 0, 0, 0, 0);
  act_tail_ = nullptr;

  return flow_events_.size();
}

/*
 * After all the events finished, return a stream s.t. can be used to output.
 */
std::stringstream FlowEvents::GetFlowTime() {
  std::stringstream ss;
  for (auto event : flow_events_) {
    ss << event->id << ' ' << event->real_start_time - start_time_ << ' '
       << event->real_finish_time - start_time_ << ' '
       << (event->real_finish_time == 0
               ? 0
               : event->real_finish_time - event->real_start_time)
       << '\n';
  }
  return ss;
}

std::atomic<uint32_t> FlowEvents::inflight;
uint32_t FlowEvents::inflight_limit;