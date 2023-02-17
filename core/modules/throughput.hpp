#ifndef BESS_MODULES_THROUGHPUT_H_
#define BESS_MODULES_THROUGHPUT_H_

#include "../module.h"
#include "../utils/format.h"
#include <atomic>

#define TRIGGER_CYCLE 1000

class Throughput final: public Module {
public:
  Throughput():
	pkt_cnt_(),
	cycle_cnt_(),
	trigger_cycle_(TRIGGER_CYCLE),
	acc_bytes_(),
	stime_(),
	throughput_() {
	  max_allowed_workers_ = Worker::kMaxWorkers;
  }
  
  static const gate_idx_t kNumOGates = 0;
  
  void ProcessBatch(Context * ctx, bess::PacketBatch *batch) override;
  std::string GetDesc() const override;

private:
  uint64_t pkt_cnt_;
  uint32_t cycle_cnt_;
  const uint32_t trigger_cycle_;
  std::atomic<uint64_t> acc_bytes_;
  uint64_t stime_;
  double throughput_;
};

#endif // BESS_MODULES_THROUGHPUT_H_
