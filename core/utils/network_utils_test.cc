#include "network_utils.h"
#include <sstream>

#include <gtest/gtest.h>

using bess::utils::NetworkAddress;
using bess::utils::StaticRoutingTable;
using bess::utils::FlowEvents;

TEST(NetworkAddressTest, Constructor) {
  NetworkAddress addr("192.168.0.0/24");
  bess::utils::be32_t ad, ma;
  ad = bess::utils::be32_t(0xc0a80000);
  ma = bess::utils::be32_t(0xffffff00);
  ASSERT_EQ(ad, addr.addr);
  ASSERT_EQ(ma, addr.mask);
}

TEST(SrtTableTest, AddRoute) {
  StaticRoutingTable st;
  bess::gate_idx_t ret;
  bess::utils::be32_t ip_addr;
  uint32_t ip;
  bool added;
  added = st.AddRoute("192.168.0.0/24", 0);
  ASSERT_TRUE(added);
  added = st.AddRoute("172.16.0.0/24", 1);
  ASSERT_TRUE(added);
  added = st.AddRoute("192.168.0.0/16", 8);
  ASSERT_TRUE(added);
  
  inet_pton(AF_INET, "192.168.0.1", &ip);
  ip_addr = bess::utils::be32_t::raw_load(ip);
  ret = st.LookupEntry(ip_addr);
  ASSERT_EQ(0, ret);

  inet_pton(AF_INET, "172.16.0.200", &ip);
  ip_addr = bess::utils::be32_t::raw_load(ip);
  ret = st.LookupEntry(ip_addr);
  ASSERT_EQ(1, ret);

  inet_pton(AF_INET, "192.168.2.100", &ip);
  ip_addr = bess::utils::be32_t::raw_load(ip);
  ret = st.LookupEntry(ip_addr);
  ASSERT_EQ(8, ret);
}

TEST(SrTableTest, NotFound) {
  StaticRoutingTable st;
  bess::gate_idx_t ret;
  bess::utils::be32_t ip_addr;
  uint32_t ip;
  
  inet_pton(AF_INET, "172.16.0.1", &ip);
  ip_addr = bess::utils::be32_t(ip);
  ret = st.LookupEntry(ip_addr);
  // ASSERT_EQ(StaticRoutingTable::LookupFailed, ret);
  ASSERT_EQ(0xffff, ret);
}

TEST(SrTableTest, DefaultGate) {  
  bess::gate_idx_t ret, default_gate = 1;
  StaticRoutingTable st(default_gate);
  bess::utils::be32_t ip_addr;
  uint32_t ip;
  
  inet_pton(AF_INET, "172.16.0.1", &ip);
  ip_addr = bess::utils::be32_t(ip);
  ret = st.LookupEntry(ip_addr);
  ASSERT_EQ(default_gate, ret);
}

// bool flowShotAssert(struct FlowEvents::FlowOneShot shot, uint32_t id, uint32_t size) {
//   return shot.id == id && shot.size == size;
// }

// TEST(FlowEventsTest, GetBurst) {
//   FlowEvents events;
//   std::stringstream ss;
//   ss << "0 0 4 3666 2.000001031\n" // 1 us
// 	"1 0 5 50 2.000002092\n" // 2 us
// 	"2 0 2 60 2.000002095\n" //  2 us
// 	"3 0 5 800 2.000003114\n" // 3 us
// 	"4 0 4 1600 2.000004182\n" // 4 us
// 	"5 0 5 2000 2.000005182\n"; // 5 us

//   uint32_t max_shot_bytes = 1000;
  
//   bool suc = events.Init(ss, 0, max_shot_bytes);
//   ASSERT_TRUE(suc);

//   events.Start(2e9);

//   uint64_t tick = 4e9 + 1000;
//   ASSERT_FALSE(events.RefreshNewEvents(tick));
//   auto event = events.GetNextEvent();
//   ASSERT_EQ(event, nullptr);
  
//   tick += 1000; // 2 us
//   ASSERT_TRUE(events.RefreshNewEvents(tick));
//   event = events.GetNextEvent();
//   ASSERT_EQ(event->id, 0);
  
	
//   tick += 1000; // 3 us
//   ASSERT_TRUE(events.RefreshNewEvents(tick));
//   shots = events.GetBurst(burst);
//   ASSERT_TRUE(flowShotAssert(shots[0], 1, 50));
//   ASSERT_TRUE(flowShotAssert(shots[1], 2, 60));

//   tick += 1000; // 4 us
//   ASSERT_TRUE(events.RefreshNewEvents(tick));
//   shots = events.GetBurst(burst);
//   ASSERT_TRUE(flowShotAssert(shots[0], 0, max_shot_bytes));
//   ASSERT_TRUE(flowShotAssert(shots[1], 3, 800));

//   tick += 1000; // 5 us
//   ASSERT_TRUE(events.RefreshNewEvents(tick));
//   shots = events.GetBurst(burst);
//   ASSERT_TRUE(flowShotAssert(shots[0], 0, 666));
//   ASSERT_TRUE(flowShotAssert(shots[1], 4, max_shot_bytes));

//   tick += 1000; // 6 us
//   ASSERT_TRUE(events.RefreshNewEvents(tick));
//   shots = events.GetBurst(burst);
//   ASSERT_TRUE(flowShotAssert(shots[0], 5, max_shot_bytes));
//   ASSERT_TRUE(flowShotAssert(shots[1], 4, 600));

//   tick += 1000; // 7 us
//   ASSERT_TRUE(events.RefreshNewEvents(tick));
//   shots = events.GetBurst(burst);
//   ASSERT_TRUE(flowShotAssert(shots[0], 5, max_shot_bytes));
//   ASSERT_EQ(shots.size(), 1);
// }
