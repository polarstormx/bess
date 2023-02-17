#include "endhost.hpp"

// #define EH_DEBUG  // If defined, log info. Turn it off when ready.
#ifdef EH_DEBUG
#define DEBUG_INFO LOG(INFO) << "<" << name() << "> "
#endif

using bess::utils::FocusPacketHeader;  // the packet header we defined
using bess::utils::FlowEvents;

const Commands Endhost::cmds = {
  {"config_sender", "EndhostCommandConfigSenderArg",
   MODULE_CMD_FUNC(&Endhost::CommandConfigSender), Command::THREAD_SAFE},
  {"dump_fcts", "EmptyArg", MODULE_CMD_FUNC(&Endhost::CommandDumpFcts), Command::THREAD_SAFE}
};

/* 
 * Init() is called when starting
 */
CommandResponse Endhost::Init(const bess::pb::EndhostArg &arg) {
  is_task_ = arg.is_sender();
  LOG(INFO) << "Starting Endhost -- " << this->name();
  return CommandSuccess();
}

/*
 * Configure sender
 */
CommandResponse
Endhost::CommandConfigSender(const bess::pb::EndhostCommandConfigSenderArg &arg) {
  endhost_id_ = arg.sender_id();
  templ_size_ = arg.templ().length();
  uint32_t max_payload_size = templ_size_ - sizeof(FocusPacketHeader);
  // Read flow file
  std::ifstream flowfile(arg.flowfile());
  if (!flowfile.is_open()) {
	LOG(ERROR) << "Failed to open flow file" << arg.flowfile();
  }
  uint32_t flows_cnt = flow_events_.Init(flowfile, endhost_id_, arg.inflight_limit(),arg.window_increase_rate(), max_payload_size);
  if (flows_cnt == 0) {
	// there are no flows to be sent
	LOG(INFO) << "<" << name() << "> Configured as sender but has no flows to send.";
	// return CommandSuccess();
  } else {
	LOG(INFO) << "<" << name() << "> sender has " << flows_cnt << " flows to send.";
  }
  task_id_t tid = RegisterTask(nullptr);
  if (tid == INVALID_TASK_ID)
	return CommandFailure(-ENOMEM, "Failed to create BESS task.");
  
  burst_ = arg.burst();

  // initiate ID to IP map
  for (int i = 0; i < arg.eid2ips_size(); i++) {
	uint32_t eid = arg.eid2ips(i).eid();
	bess::utils::be32_t ip_addr = bess::utils::str2ip(arg.eid2ips(i).ip());
	if (ip_addr.value() > 0) {
	  eid2ips_.emplace(eid, ip_addr);
	} else {
	  return CommandFailure(-EINVAL,
							"Cannot convert %s to IP address", arg.eid2ips(i).ip().c_str());
	}
  }
	  
  // initiate packet template
  if (arg.templ().length() == 0) {
	if (strnlen(reinterpret_cast<const char*>(templ_), MAX_TEMPLATE_SIZE) == 0) {
	  return CommandFailure(EINVAL, "must specify template 'templ'");
	}
  } else {
	// update template
	if (arg.templ().length() > MAX_TEMPLATE_SIZE) {
	  return CommandFailure(EINVAL, "'template' is too big");
	}
	
	const char *tmpl = arg.templ().c_str();
	const FocusPacketHeader *header = reinterpret_cast<const FocusPacketHeader *>(tmpl);
	// const Ethernet *eth = reinterpret_cast<const Ethernet *>(tmpl);
	if (header->eth.ether_type.value() != bess::utils::Ethernet::Type::kIpv4) {
	  return CommandFailure(EINVAL, "'template' is not IPv4");
	}
	
	if (header->ip.protocol != bess::utils::Ipv4::Proto::kUdp) {
	  return CommandFailure(EINVAL, "'template' is not UDP");
	}

	memset(templ_, 0, MAX_TEMPLATE_SIZE);
	bess::utils::Copy(templ_, tmpl, templ_size_);
  }

  flow_events_.Start(tsc_to_ns(rdtsc()));
  return CommandSuccess();
}


/*
 * Dump flow info to a file
 */
CommandResponse Endhost::CommandDumpFcts(const bess::pb::EmptyArg &) {
  std::string filename = "fct/fcts_" + std::to_string(endhost_id_) + ".txt";
  LOG(INFO) << "Saver result to file " << filename;
  std::ofstream outfile(filename);
  if (unlikely(outfile.fail())) {
	LOG(ERROR) << "Cannot open file " << filename;
	return CommandFailure(-EINVAL, "Cannot open file %s", filename.c_str());
  }
  outfile << flow_events_.GetFlowTime().rdbuf();
  return CommandSuccess();
}

/*
 * Used by ProcessBatch() to deal with data packets.
 * Generate an ACK and send back.
 */
inline void Endhost::processPktData(Context * ctx, bess::Packet *packet) {
  bess::Packet* ack;
  uint32_t total_size = 64;
  if (unlikely(!(ack = current_worker.packet_pool()->Alloc(total_size)))) {
	LOG(ERROR) << "Cannot allocate packet when generating ACK";
	return;
  }
  
  ack->set_data_off(SNBUF_HEADROOM);
  ack->set_total_len(total_size);
  ack->set_data_len(total_size);

  char *to = ack->buffer<char *>() + SNBUF_HEADROOM;
  char *from = packet->buffer<char *>() + SNBUF_HEADROOM;
  bess::utils::CopyInlined(to, from, total_size, false);

  FocusPacketHeader *header = ack->head_data<FocusPacketHeader *>();
  std::swap(header->eth.src_addr, header->eth.dst_addr);
  std::swap(header->ip.src, header->ip.dst);
  // header->udp.length = bess::utils::be16_t(sizeof(FocusPacketHeader::FloodgateHeader) + payload_size);
  // header->ip.length = bess::utils::be16_t(sizeof(bess::utils::Udp) + header->udp.length.value());
  header->fgh.type = bess::utils::be16_t(FocusPacketHeader::FloodgateHeader::Type::Ack);
#ifdef EH_DEBUG
  DEBUG_INFO << "[IN] Receiving a data packet " << bess::utils::ip2str(header->ip.dst)
			 << "->" << bess::utils::ip2str(header->ip.src) << " Ack it back.";
#endif
  stat_.reply_cnt ++;
  EmitPacket(ctx, ack);
  bess::Packet::Free(packet);
}

/*
 * Used by ProcessBatch() to deal with ACKs.
 */
inline void Endhost::processPktAck(Context *ctx, bess::Packet *packet) {
  const FocusPacketHeader *header = packet->head_data<const FocusPacketHeader*>();
  if (unlikely(header->ip.dst != eid2ips_[endhost_id_]))
	LOG(ERROR) << "Receive an Ack not for me, but for " << bess::utils::ip2str(header->ip.dst);
  uint32_t flow_id = header->udp.src_port.value();
  bool suc = flow_events_.Ack(flow_id, ctx->current_ns, header->fgh.seq_num.value());
  if (unlikely(!suc)) LOG(ERROR) << "<" << this->name() << "> Failed to find flow ID " << flow_id;
  else stat_.ack_cnt ++;
#ifdef EH_DEBUG
  DEBUG_INFO << "[IN] Receives an ACK from " << bess::utils::ip2str(header->ip.src);
#endif
  bess::Packet::Free(packet);
}

/*
 * Called when a batch of packets arrives at Endhost which should be data packets or ACKs.
 */
void Endhost::ProcessBatch(Context * ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
	bess::Packet *packet = batch->pkts()[i];
	const FocusPacketHeader *header = packet->head_data<const FocusPacketHeader*>();
	// check if IPv4 and UDP
	if (header->isIpv4()) {
	  switch (header->CheckProto()) {
	  case FocusPacketHeader::PacketType::Data :
		processPktData(ctx, packet); continue;
	  case FocusPacketHeader::PacketType::Ack :
		processPktAck(ctx, packet); continue;
	  default:
		LOG(WARNING) << "Receives a non-data non-ack type " << header->fgh.type.value()
					 << " with UDP dst_port=" << header->udp.dst_port.value();
	  }
	}
	//LOG(WARNING) << "<" << this->name() << "> Receives packet with type that shouldn't receive";
	bess::Packet::Free(packet);
  }
}

/*
 * Used by RunTask() to generate a packet according to event and payload length
 */
inline bess::Packet*
Endhost::generateFgPacket(FlowEvents::FlowOneShot shot) {
  uint32_t total_size = sizeof(FocusPacketHeader) + shot.size;

  bess::Packet *packet;
  if (!(packet = current_worker.packet_pool()->Alloc())) {
	LOG(ERROR) << "Cannot allocate memory when generate data packet.";
    return nullptr;
  }
  
  FocusPacketHeader *header = packet->head_data<FocusPacketHeader *>();
  packet->set_data_off(SNBUF_HEADROOM);
  packet->set_total_len(total_size);
  packet->set_data_len(total_size);

  char *p = packet->buffer<char *>() + SNBUF_HEADROOM;
  bess::utils::CopyInlined(p, templ_, total_size, false);

  header->ip.src = eid2ips_[endhost_id_];
  header->ip.dst = eid2ips_[shot.dst]; // !ATTENTION!: no check here, should make sure flow file and eid2ips_ map is correct.
  header->udp.src_port = bess::utils::be16_t(shot.id);
  header->udp.dst_port = bess::utils::be16_t(FG_UDP_PORT);

  header->fgh.type = bess::utils::be16_t(FocusPacketHeader::FloodgateHeader::Type::Data);
  header->fgh.length = bess::utils::be16_t(shot.size);
  header->fgh.seq_num = bess::utils::be32_t(shot.seq);

  return packet;
}

/*
 * Called when scheduled, send out a batch of packets to downstream.
 */
struct task_result Endhost::RunTask(Context *ctx, bess::PacketBatch *batch, void *) {
  if (unlikely(children_overload_ > 0)) {
	return {.block = true, .packets = 0, .bits = 0};
  }
  
  flow_events_.RefreshNewEvents(ctx->current_ns);
  
  uint64_t total_bytes = 0;
  batch->clear();
  for (uint32_t i = 0; i < burst_; i++) {
	FlowEvents::FlowOneShot shot = flow_events_.GetFlowShot();
	if (shot.id == 0xffffffff && shot.size == 0) break; // no event is ready
	bess::Packet *packet = generateFgPacket(shot);
	if (packet) {
	  batch->add(packet);
	  total_bytes += packet->total_len();
	}
  }

  uint32_t sent_cnt = batch->cnt();
  if (sent_cnt == 0) {
	return {.block = true, .packets = 0, .bits = 0};
  }
  
  const int pkt_overhead = PKT_OVERHEAD;  // 24
  for (uint32_t i = 0; i < sent_cnt; i++) { // prefetch
	rte_prefetch0(batch->pkts()[i]->head_data());
  }
  stat_.out_cnt += sent_cnt;
#ifdef EH_DEBUG
  DEBUG_INFO << "[OUT] RunTask sends " << sent_cnt << " packets" ;
#endif
  RunNextModule(ctx, batch);
  return {.block = false,
		  .packets = sent_cnt,
		  .bits = (total_bytes + sent_cnt * pkt_overhead) * 8};
}

/*
 * Description message showed in pipeline
 */
std::string Endhost::GetDesc() const {
  std::string desc;
  if (burst_ == 0 && templ_size_ == 0) { // This is a receiver
	desc = bess::utils::Format("Replied %lu", stat_.reply_cnt.load());
  } else {
	desc = bess::utils::Format("Sent %lu, Acked %lu Replied %lu", stat_.out_cnt.load(), stat_.ack_cnt.load(), stat_.reply_cnt.load());
  }
  return desc;
}

ADD_MODULE(Endhost, "endhost", "An endhost as a receiver and sender.");
