#include "floodgate_switch.hpp"

// #define FGS_DEBUG  // If defined, log info. Turn it off when ready.
#ifdef FGS_DEBUG
#define DEBUG_INFO LOG(INFO) << "<" << name() << "> "
#endif

using bess::utils::FocusPacketHeader;  // the packet header we defined
using bess::utils::PacketMeta; // Packet with metadata
/*
 * Initialize a llring queue.
 * sp means single producer, sc means single consumer.
 */
struct llring* newQueue(uint32_t size, bool sp, bool sc) {
  int bytes = llring_bytes_with_slots(size);
  struct llring *queue = reinterpret_cast<llring *>(std::aligned_alloc(alignof(llring), bytes));
  if (queue != nullptr) {
	// In llring_init():
	// 3rd parameter 0 means false, indicating multiple producers.
	// 4th parameter 1 means true, indicating single consumer.
	if(!llring_init(queue, size, sp, sc))
	  return queue;
	else LOG(ERROR) << "Failed to initialize llring";
  }
  std::free(queue);
  return nullptr;
}

inline std::pair<bess::gate_idx_t, uint32_t> tid2port(void *tid) {
  uint16_t t = (uint16_t)(uintptr_t)tid;
  return std::make_pair(t / 2, t % 2);
}

inline std::pair<bess::gate_idx_t, uint32_t> tid2port(bess::gate_idx_t gate) {
  return std::make_pair(gate / 2, gate % 2);
}

inline std::pair<void*, void*> port2tids(gate_idx_t port) {
  return std::make_pair((void *)(uintptr_t)(2 * port), (void *)(uintptr_t)(2 * port + 1));
} 

bool Voq::Preallocate(uint32_t queue_size) {
  queue = newQueue(queue_size);
  return queue != nullptr;
}

bool OPort::Preallocate(uint32_t buffer_size) {
  buf_ = newQueue(buffer_size);
  return buf_ != nullptr;
}

const Commands FloodgateSwitch::cmds = {
  {"add_routes", "FloodgateSwitchCommandAddRoutesArg",
   MODULE_CMD_FUNC(&FloodgateSwitch::CommandAddRoutes), Command::THREAD_UNSAFE},
  {"config_oport", "FloodgateSwitchCommandConfigOPortArg",
   MODULE_CMD_FUNC(&FloodgateSwitch::CommandConfigOPort), Command::THREAD_UNSAFE}
};

/*
 * Init is called when starting
 */
CommandResponse FloodgateSwitch::Init(const bess::pb::FloodgateSwitchArg &arg) {
  voqs_.resize(arg.voqs_num());  // pre-allocate VOQ struct
  oports_.resize(arg.ports_num()); // pre-allocate OPort
  ip2voq_.reserve(arg.voqs_num());
  credit_limit_ = arg.credit_limit(); // credit limit of CreditAccumulator
  ca_timeout_ = arg.ca_timeout(); // credit accumulator timeout
  voq_resume_lim_ = arg.voq_resume_lim(); // VOQ length limitation to resume sending credit ACk
  prefetch_ = arg.prefetch();  // whether to prefetch L1 cache
  burst_ = arg.burst();  // # of pkts per batch
  enable_floodgate_ = arg.enable_floodgate(); // whether enable Floodgate

  LOG(INFO) << "Starting Floodgate Switch -- " << name();

  voqs_last_idx_ = 0;

  // Check queue_size value
  uint32_t queue_size_ = arg.queue_size();
  if (queue_size_ < 4 || queue_size_ > 0x4000) {
	return CommandFailure(-EINVAL, "queue_size must be in [4, 16384]");
  }
  if (queue_size_ & (queue_size_ - 1)) {
	return CommandFailure(-EINVAL, "queue_size must be a power of 2");
  }
  // if (queue_size < credit_limit_ * 2) {
  // 	return CommandFailure(-EINVAL, "queue_size is too small comparing to credit_limit");
  // }
  for (uint32_t i = 0; i < voqs_.size(); i++) {
	voqs_[i] = new struct Voq();
	bool suc = voqs_[i]->Preallocate(queue_size_);
	if (!suc) {
	  CommandFailure(-ENOMEM, "Cannot initiate VOQ with llring_init");
	}
  }
  for (uint32_t i = 0; i < oports_.size(); i++) {
	oports_[i] = new OPort();
	bool suc = oports_[i]->Preallocate(queue_size_);
	if (!suc) {
	  CommandFailure(-ENOMEM, "Cannot initiate port buffer with llring_init");
	}
  }
  return ProcessUpdatableArguments(arg);
}

/*
 * Update complicated arguments.
 * Typically stores packet template.
 */
CommandResponse
FloodgateSwitch::ProcessUpdatableArguments(const bess::pb::FloodgateSwitchArg &arg) {

  if (arg.templ().length() == 0) {
    if (strnlen(reinterpret_cast<const char*>(templ_), SWITCH_ACK_TEMPLATE_SIZE) == 0) {
      return CommandFailure(-EINVAL, "must specify 'template'");
    }
  } else {
    // update template
    if (arg.templ().length() != SWITCH_ACK_TEMPLATE_SIZE - PKT_OVERHEAD) {
      return CommandFailure(-EINVAL, "'template' size should be %d not %lu", SWITCH_ACK_TEMPLATE_SIZE - PKT_OVERHEAD, arg.templ().length());
    }

    const char *tmpl = arg.templ().c_str();
	const FocusPacketHeader *header = reinterpret_cast<const FocusPacketHeader *>(tmpl);
    // const Ethernet *eth = reinterpret_cast<const Ethernet *>(tmpl);
    if (header->eth.ether_type.value() != bess::utils::Ethernet::Type::kIpv4) {
      return CommandFailure(-EINVAL, "'template' is not IPv4");
    }

    if (header->ip.protocol != bess::utils::Ipv4::Proto::kUdp) {
      return CommandFailure(-EINVAL, "'template' is not UDP");
    }

    uint32_t template_size = arg.templ().length();

    memset(templ_, 0, SWITCH_ACK_TEMPLATE_SIZE);
    bess::utils::Copy(templ_, tmpl, template_size);
  }
  return CommandSuccess();
}

/*
 * Add routes to routing table
 */
CommandResponse
FloodgateSwitch::CommandAddRoutes(const bess::pb::FloodgateSwitchCommandAddRoutesArg &arg) {
  for (auto i = 0; i < arg.routes_size(); i++) {
	const std::string network = arg.routes(i).network();
	const bess::gate_idx_t port = arg.routes(i).port();
	if (!routing_table_.AddRoute(network, port)) {
	  return CommandFailure(-EINVAL, "Cannot add route");
	}
  }
  return CommandSuccess();
}

/*
 * Configure one output port
 */
CommandResponse
FloodgateSwitch::CommandConfigOPort(const bess::pb::FloodgateSwitchCommandConfigOPortArg &arg) {
  bess::gate_idx_t port = (bess::gate_idx_t)arg.port();
  if (port > MAX_GATES) {
	return CommandFailure(EINVAL, "Too big of port number.");
  }
  if (port < oports_.size() && oports_[port]->m > 0) {
	return CommandFailure(-EINVAL, "Overwiting an existed output port.");
  }
  if (arg.m() == 0 || arg.bdpi() == 0)
	return CommandFailure(-EINVAL, "Parameter 'm' and 'bdpi' should be a non-zero number.");
  if (port >= oports_.size()) {
	return CommandFailure(-EINVAL, "Port number %u is too big. Total ports num is %lu", port, oports_.size());
  }
  // Parse Ethernet MAC address
  uint8_t *bytes = oports_[port]->omac;
  int ret = bess::utils::Parse(arg.mac(), "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", &bytes[0],
                  &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]);
  if (ret != bess::utils::Ethernet::Address::kSize) {
	return CommandFailure(-EINVAL, "Invalid MAC address %s", arg.mac().c_str());
  }

  oports_[port]->Config(arg.m(), arg.bdpi(), arg.ecn_kmax(), arg.ecn_kmin(),
						arg.edge(), voqs_.size());
  auto [tid1, tid2] = port2tids(port);
  task_id_t t1 = RegisterTask(tid1); // for egress buffer
  task_id_t t2 = RegisterTask(tid2); // for core function
  if (t1 == INVALID_TASK_ID || t2 == INVALID_TASK_ID) {
	return CommandFailure(-ENOMEM, "Create task for ports failed");
  }

  stat_.buf_sizes.resize(port+1); stat_.buf_sizes[port] = 0;
#ifdef FGS_DEBUG
  LOG(INFO) << "Configed OPort " << port; 
#endif
  return CommandSuccess();
}

inline bool FloodgateSwitch::send(bess::utils::PacketMeta *pmeta, bess::gate_idx_t port) {
  int res = oports_[port]->bufEnq(pmeta);
  if (unlikely(res == -LLRING_ERR_NOBUF)) {
	LOG(ERROR) << "Cannot enqueue to buffer of port" << port
	  		   << " with buffer length=" << oports_[port]->bufSize()
	  		   << " err: " << res;
	return false;
  } else if (res == BUF_ENQUEUE_MARK_ECN) {
	stat_.qecn_cnt ++;
	bess::utils::markECN(pmeta->packet); // set ECN to 0b11
  }
  const int bsz = oports_[port]->bufSize();
  if (bsz > (int)stat_.buf_sizes[port])
  	stat_.buf_sizes[port] = bsz;
  return true;
}

/*
 *    
 * Called by ProcessBatch() when incoming a data packet.
 *
 *    +-----------------+         No
 *    | ip.dst recorded +-------------+
 *    +---------+-------+             |
 *          Yes |                     |
 *              |                     v
 *              |            +----------------+
 *              |            |allocate window |
 *              +------------+    & VOQ       |
 *              v            +----------------+
 *     +----------------+
 *     | Sending Window |         No
 *     |    is full     +-------------+
 *     +--------+-------+             |
 *          Yes |                     |
 *              |                     |
 *              v                     v
 *     +----------------+       +-----------+
 *     | enqueue to VOQ |       |  send out |
 *     +----------------+       +-----------+
 *
 *
 */
inline void
FloodgateSwitch::processPktData(Context * ctx, bess::Packet *packet, const bess::gate_idx_t port) {
  if (!enable_floodgate_) {
	// stat_.out_cnt ++;
#ifdef FGS_DEBUG
	  DEBUG_INFO << "Receive a data packet to " << port;
#endif
	  send(new PacketMeta(packet), port);
	  return;
  }
  // get VOQ idx of ip_dst, if cannot find, emplace it
  FocusPacketHeader *header = packet->head_data<FocusPacketHeader*>();
#ifdef FGS_DEBUG
  DEBUG_INFO << "[IN]: Receiving a data packet "
			 << bess::utils::ip2str(header->ip.src) << "->"
			 << bess::utils::ip2str(header->ip.dst);
#endif
  bess::gate_idx_t inport = tid2port(ctx->current_igate).first;
  PacketMeta *pmeta = new PacketMeta(PacketMeta::Metadata::Type::Data,
									 inport, nullptr, packet); // metadata

  // create CreditAccumulator if does not exist
  if (unlikely(!oports_[inport]->edge
			   && oports_[inport]->bound_cas.find(header->ip.dst) == oports_[inport]->bound_cas.end())) {
	// create a CreditAccumulator for this <inport, ip_dst>
	oports_[inport]->bound_cas
	  .emplace(header->ip.dst,
			   new CreditAccumulator(credit_limit_, ca_timeout_, inport, header->ip.src, header->ip.dst));
#ifdef FGS_DEBUG
	DEBUG_INFO << "Creating a CreditAccumulator for inport=" << (int)inport << " ip="
			   << bess::utils::ip2str(header->ip.dst);
#endif
  }

  OPort *oport = oports_[port];
  if (!oport->edge) {
	struct Voq *voq;
	auto voq_p = ip2voq_.find(header->ip.dst); // find the VOQ of this IP dst
	if (unlikely(voq_p == ip2voq_.end())) { // ip dst is not added to VOQ map
	  // initate a VOQ for IP dst
	  // if (unlikely(voqs_last_idx_ >= voqs_.size())) {
	  // 	// Maybe use push_back instead
	  // 	LOG(ERROR) << "Not enough VOQs pre-allocated. May cause fatal error.";
	  // }
	  voq = voqs_[voqs_last_idx_++];
	  voq->set_limit(oport->m * oport->bdpi);
	  ip2voq_.emplace(header->ip.dst, voq);
	  oport->bindVoq(voq); // bind VOQ to output port
	} else {
	  voq = voq_p->second;
	}

	pmeta->meta.voq = voq; // metadata
	if (!voq->empty() || voq->hit_limit()) {  // VOQ is not empty or window is full
	  // push pakcet to VOQ
	  int err = voq->enqueue(pmeta);
	  if (unlikely(err)) {
		bess::Packet::Free(packet); stat_.drop_cnt.fetch_add(1, std::memory_order_relaxed);
		LOG(ERROR) << "VOQ is full. Drop packet from " << bess::utils::ip2str(header->ip.src);
	  }
	  const uint32_t vlen = voq->length(), kmax = oport->kmax_ * 2, kmin = oport->kmin_ * 2;
	  if (vlen >= kmax || (vlen > kmin && oport->randGen_() % 100 < (vlen - kmin) * 30 / (kmax - kmin))) {
	  	stat_.vecn_cnt.fetch_add(1, std::memory_order_relaxed);
	  	bess::utils::markECN(packet); // set ECN to 0b11
	  }
#ifdef FGS_DEBUG
	  DEBUG_INFO << "Push packet to VOQ which destines to "
				 << bess::utils::ip2str(header->ip.dst)
				 << " becasue empty=" << voq->empty()
				 << " hit_limit=" << voq->hit_limit()
				 << " VOQ queue size = " << voq->length();
#endif
	  return;
	}
	// voq is empty && window is not full, send the packet directly
  }
  // (oport is last hop || voq is empty && window is not full) send the packet directly

#ifdef FGS_DEBUG
  DEBUG_INFO << "[OUT] Send packet destined to " << bess::utils::ip2str(header->ip.dst)
			 << " directly to port: " << port;
#endif
  // stat_.out_cnt ++;
  send(pmeta, port);
}

/*
 * Called when incoming a normal ACK. Send it out.
 */
inline void
FloodgateSwitch::processPktAck(Context *, bess::Packet *packet, bess::gate_idx_t port) {
  PacketMeta *pmeta = new PacketMeta(PacketMeta::Metadata::Type::Ack, packet); // metadata
#ifdef FGS_DEBUG
  FocusPacketHeader *header = packet->head_data<FocusPacketHeader*>();
  DEBUG_INFO << "Forwarding an ACK from " << bess::utils::ip2str(header->ip.src)
			 << " to " << bess::utils::ip2str(header->ip.dst) << " to port" << port;
#endif
  send(pmeta, port);
}

/*
 * Called when incoming a switch-ACK.
 */
inline void
FloodgateSwitch::processPktSwitchAck(Context *, bess::Packet *packet) {
  FocusPacketHeader *header = packet->head_data<FocusPacketHeader*>();
  auto voq_p = ip2voq_.find(header->ip.src);
  if (unlikely(voq_p == ip2voq_.end())) {
	LOG(ERROR) << "<" << name() << "> Cannot find IP " << header->ip.src << " in VOQs, which should not happen in switch-ACK processing.";
  }

  struct Voq *voq = voq_p->second;
  uint32_t credit = header->fgh.credit.value();
#ifdef FGS_DEBUG
  DEBUG_INFO << "[IN] Receiving a switch-ACK of " << bess::utils::ip2str(header->ip.src)
			 << " inflight = " << voq->inflight << " - " << credit;
#endif
  // voq->inflight = voq->inflight >= credit ? voq->inflight - credit : 0;
  voq->inflight.fetch_sub(credit, std::memory_order_relaxed);
  // stat_.ack_cnt ++;
  bess::Packet::Free(packet);
}

/*
 * Called when a batch of packets from upstream arrives at FloodgateSwitch.
 */
void FloodgateSwitch::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
	bess::Packet *packet = batch->pkts()[i];
	const FocusPacketHeader *header = packet->head_data<const FocusPacketHeader*>();
	if (likely(header->isIpv4())) {
	  bess::gate_idx_t port = routing_table_.LookupEntry(header->ip.dst);
	  // routing, get output port
	  // if (unlikely(port == bess::utils::StaticRoutingTable::LookupFailed)) {
	  // 	LOG(ERROR) << "Cannot find route to " << bess::utils::ip2str(header->ip.dst);
	  // 	bess::Packet::Free(packet);
	  // 	continue;
	  // }
	  switch(header->CheckProto()) {
	  case FocusPacketHeader::PacketType::Irrelevant:
#ifdef FGS_DEBUG
		if (header->ip.protocol == bess::utils::Ipv4::Proto::kIcmp) {
		  DEBUG_INFO << "ICMP " << bess::utils::ip2str(header->ip.src)
					 << "->" << bess::utils::ip2str(header->ip.dst);
		} else {
		  DEBUG_INFO << "Irrelevant pkt to " << port << " udp dst_port: "
					 << header->udp.dst_port.value() << " fgh type " << header->fgh.type.value();
		}
#endif
		send(new PacketMeta(PacketMeta::Metadata::Type::Others, packet), port); break;
	  case FocusPacketHeader::PacketType::Data:
		processPktData(ctx, packet, port); break;
	  case FocusPacketHeader::PacketType::Ack:
		processPktAck(ctx, packet, port); break;
	  case FocusPacketHeader::PacketType::SwitchAck:
		processPktSwitchAck(ctx, packet); break;
	  }
	} else { // not IPv4
#ifdef FGS_DEBUG
	  DEBUG_INFO << "Not an IPv4 packet but: ether_type=" << header->eth.ether_type.value();
#endif
	  // LOG(ERROR) << "Not an IPv4 packet but: ether_type="  << header->eth.ether_type.value(); // TBR
	  // stat_.drop_cnt ++;
	  bess::Packet::Free(packet);
	}
  }
}

/*
 * Accumulate the CreditAccumulator of the <inport, ip_dst>, if should fire a switch-ACK,
 */
inline void FloodgateSwitch::creditAccumulate(FocusPacketHeader *header, bess::gate_idx_t inport) {
  OPort *oport = oports_[inport];
  if (!oport->edge) {
	CreditAccumulator *ca = oport->bound_cas.find(header->ip.dst)->second;
	ca->incr_credit(header->getDataLength());
#ifdef FGS_DEBUG
	DEBUG_INFO << "Accumulate credit of " << bess::utils::ip2str(header->ip.dst)
			   << " by " << header->getDataLength() << " to " << ca->credit();
#endif
  }
}

/*
 * Dequeue from queue and put to batch.
 */
inline void FloodgateSwitch::runQueue(bess::PacketBatch *batch, bess::gate_idx_t port) {
  OPort *oport = oports_[port];
  // const int bsz = oport->bufSize();
  // if (bsz > (int)stat_.buf_sizes[port] && bsz <= (int)queue_size_)
  // 	stat_.buf_sizes[port] = bsz; // record max buffer size
  
  bess::utils::PacketMeta* pmetaBatch[bess::PacketBatch::kMaxBurst];
  uint32_t cnt = oport->bufDeq(pmetaBatch, 2 * burst_);
  if (enable_floodgate_) {
	// update window and CreditAccumulator
	for (uint32_t i = 0; i < cnt; i++) {
	  PacketMeta *pmeta = pmetaBatch[i];
	  FocusPacketHeader *header = pmeta->packet->head_data<FocusPacketHeader*>();
	  header->eth.dst_addr.fromBytes(oport->omac); // set dest MAC
	  batch->add(pmeta->packet);
	  if (pmeta->meta.type == PacketMeta::Metadata::Type::Data) {
		if (pmeta->meta.voq != nullptr) { // if is edge, meta.voq will always be nullptr
		  struct Voq *voq = reinterpret_cast<struct Voq*>(pmeta->meta.voq);
		  voq->inflight.fetch_add(header->getDataLength(), std::memory_order_relaxed);
		}
		creditAccumulate(header, pmeta->meta.inport);
	  }
	  delete pmeta;
	}
  } else {
	for (uint32_t i = 0; i < cnt; i++) {
	  FocusPacketHeader *header = pmetaBatch[i]->packet->head_data<FocusPacketHeader*>();
	  header->eth.dst_addr.fromBytes(oport->omac); // set dest MAC
	  batch->add(pmetaBatch[i]->packet);
	  delete pmetaBatch[i];
	}
  }
  
}

/*
 * Push a batch of packets to egress buffer if VOQs has packets.
 * This method will be called in a round robin fashion on every output port.
 * If the VOQs bound to this port has packets, send them out.
 * `batch` should be filled with packets
 */
inline void FloodgateSwitch::runCore(Context *ctx, bess::gate_idx_t port) {    
  if (!enable_floodgate_) {
  	// children_overload_ > 0 indicates downstream queue is full or nearly full
  	return;
  }
  
  OPort *oport = oports_[port];
  
  // Check if should fire switch-ACK
  for (auto ca_p: oport->bound_cas) {
	CreditAccumulator *ca = ca_p.second;
	auto voq_p = ip2voq_.find(ca_p.first);
	if (ca->should_fire(ctx->current_ns)) {
	  if (voq_p == ip2voq_.end() || voq_p->second->qcnt < voq_resume_lim_) {
		// send a switch ACK
		const uint64_t credit = ca->credit();
		bess::Packet *packet = bess::utils::generate_switch_ack(templ_, ca->src, ca->dst, credit);
		if (likely(packet != nullptr)) {
		  PacketMeta *pmeta = new PacketMeta(PacketMeta::Metadata::Type::SwitchAck, packet); // metadata
#ifdef FGS_DEBUG
		  DEBUG_INFO << "[OUT] Send sAck to port: " << ca->port  << " of "
					 << bess::utils::ip2str(ca->dst) << " with credit " << credit;
#endif
		  send(pmeta, port);
		} else {
		  LOG(ERROR) << "Cannot generate switch ACK";
		}
		ca->reset(ctx->current_ns, credit);
	  }
	}
  }
  
  // Check if should send pakets from VOQs
  const uint32_t bvoq_size = oport->voqsNum();
  uint32_t dataNum = 0;
  if (bvoq_size > 0) {
	uint32_t per_burst = burst_ / bvoq_size > 0 ? burst_ / bvoq_size : 1;
	// uint32_t per_burst = 2;
	uint32_t bidx = oport->bound_voqs_idx;
	do {
	  // for each VOQ bound to this port, check if it has packet to sent
	  struct Voq *voq = oport->getVoq(bidx);
	  if (!voq->empty() && !voq->hit_limit()) {
		// get packets from VOQ and push to egress buffer
		for (uint32_t i = 0; i < per_burst; i++) {
		  bess::utils::PacketMeta* pmeta = voq->dequeue();
		  if (pmeta) {
#ifdef FGS_DEBUG
			LOG(INFO) << "Core: dequeue packet to port " << port;
#endif
			send(pmeta, port);
			dataNum ++;
		  } else break;
		}
	  }
	  bidx = (bidx + 1) % bvoq_size;
	} while (dataNum < burst_ && bidx != oport->bound_voqs_idx);
    oport->bound_voqs_idx = bidx;
	// stat_.out_cnt += dataNum;
  }
}

/*
 * Called when scheduled.
 */
struct task_result
FloodgateSwitch::RunTask(Context *ctx, bess::PacketBatch *batch, void *tid) {
  batch->clear();
  auto[port, tcase] = tid2port(tid);
  switch(tcase) {
  case 0: runQueue(batch, port); break;
  case 1: runCore(ctx, port);  break;
  }

  uint32_t cnt = batch->cnt(), total_bytes = 0;
  if (cnt == 0) {
	return {.block = true, .packets = 0, .bits = 0};
	// runCore ends here
  }
  
  for (uint32_t i = 0; i < cnt; i++) {
	total_bytes += batch->pkts()[i]->total_len() + PKT_OVERHEAD;
	// if (likely(prefetch_)) {
	rte_prefetch0(batch->pkts()[i]->head_data());
	// }
  }
#ifdef FGS_DEBUG
  DEBUG_INFO << "[OUT] RunTask port " << port << " sends " << cnt << " packets";
#endif
  // batch has packets from queue
  RunChooseModule(ctx, (bess::gate_idx_t)(uintptr_t)tid, batch);
  return {.block = false,
		  .packets = cnt,
		  .bits = total_bytes * 8};
}

/*
 * Description message showed in pipeline
 */
std::string FloodgateSwitch::GetDesc() const {
  // std::string desc = bess::utils::Format("Forward %lu, sAck %lu, Drop %lu, ECN %lu, Queues ",
  // 										 stat_.out_cnt.load(),
  // 										 stat_.ack_cnt.load(),
  // 										 stat_.drop_cnt.load(),
  // 										 stat_.ecn_cnt.load());
  std::string desc = bess::utils::Format("Drop %lu, qECN %lu, vECN %lu, Queues ",
  										 stat_.drop_cnt.load(),
  										 stat_.qecn_cnt.load(),
										 stat_.vecn_cnt.load());
  for (auto i: stat_.buf_sizes) {
	desc += bess::utils::Format("%lu ", i);
  }
  // print VOQ max length
  const std::string myname = name();
  int idx = -1;
  if (enable_floodgate_) {
	switch(myname[myname.length()-1]) {
	case '2': break;
	case '6': idx = 0; break;
	case '3': [[fallthrough]]
	case '8': idx = 2; break;
	}
	if (idx >= 0) {
	  desc += "VOQ ";
	  for (uint32_t i = 0; i < oports_[idx]->bound_voqs_.size(); i++) {
		desc += bess::utils::Format("%lu ", oports_[idx]->getVoq(i)->maxLen);
	  }
	}
  }
  return desc;
}

ADD_MODULE(FloodgateSwitch, "FloodgateSwitch", "Floodgate Switch core function.");
