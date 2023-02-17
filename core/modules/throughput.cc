#include "throughput.hpp"

void Throughput::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
	bess::Packet *packet = batch->pkts()[i];
	acc_bytes_ += packet->total_len();
  }
  bess::Packet::Free(batch);
  pkt_cnt_ += cnt;

  cycle_cnt_++;
  if (cycle_cnt_ % trigger_cycle_ == 0) {
  	throughput_ = double(acc_bytes_) / (ctx->current_ns - stime_) * 1e9;
  	cycle_cnt_ = 0;
  	acc_bytes_ = 0;
  	stime_ = ctx->current_ns;
  }
}

std::string Throughput::GetDesc() const {
  std::string desc = bess::utils::Format("Throughput: %lf, tot_pkt: %ld", throughput_, pkt_cnt_);
  return desc;
}

ADD_MODULE(Throughput, "Throughput", "Monitor throughput.");
