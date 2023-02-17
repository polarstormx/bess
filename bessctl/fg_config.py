from scapy.all import *


class Floodgate(Packet):
    name = "Floodgate"
    fields_desc = [ShortField("type", 0),
                   ShortField("length", 0),
                   IntField("seq_num", 0),
                   IntField("credit", 0)]


HEADER_LEN = 54
ACK_PACKET_LEN = 64
ACK_PAY_LEN = ACK_PACKET_LEN - HEADER_LEN
# DATA_PAY_LEN = 1000
DATA_PAY_LEN = 1460 - HEADER_LEN
# Craft a packet with the specified IP addresses


def gen_template(payload_len):
    eth = Ether(src='ec:0d:9a:bf:dc:b5', dst='ec:0d:9a:bf:d9:2c')
    ip = IP(src='172.16.100.7', dst='172.16.100.20')
    udp = UDP(sport=10001, dport=10001)
    fg = Floodgate(type=0, length=payload_len, seq_num=0, credit=0)
    payload = 'a' * payload_len
    pkt = eth/ip/udp/fg/payload
    return bytes(pkt)


def add_bw_limit(bess, mod, bw, wid, coreid, mod_tid=0):
    bess.add_worker(wid, coreid)
    tcName = "%dGbps%d" % (bw, wid)
    # ceilPktSize = ((HEADER_LEN + DATA_PAY_LEN) // 100 + 1) * 100
    ceilPktSize = (1024 // 100 + 1) * 100
    bess.add_tc(tcName, wid=wid, policy='rate_limit',
                # resource='packet', limit={'packet': int(bw * 1e9 / ceilPktSize / 8)})
                resource='bit', limit={'bit': int(bw * 1e9)})
    mod.attach_task(parent=tcName, module_taskid=mod_tid)


fgs_queue_size = 2**13  # an upper bound # of packets stored in VOQ
fgs_voqs_num = 6
fgs_credit_limit = int(1e4)  # bytes
fgs_ca_timeout = 20000  # nanoseconds
fgs_template = gen_template(ACK_PAY_LEN)
fgs_prefetch = True
fgs_burst = 16
fgs_enable_floodgate = True
fgs_voq_win20 = 65000  # 75000 # 285000
fgs_10g_kmin = 70  # 30
fgs_10g_kmax = 155  # 115
fgs_20g_kmin = 80  # 60
fgs_20g_kmax = 250  # 230
fgs_voq_resume_limit = 100

sender_win_size = 200  # of packets
sender_win_increase = 10  # 11 means window increase rate is 1.1
sender_burst = 8
sender_template = gen_template(DATA_PAY_LEN)
sender_eid2ips = [
    {"eid": 0, "ip": "172.16.100.6"},
    {"eid": 1, "ip": "172.16.100.19"},
]
#sender_flowfile = "./fct/const_incast.txt"
# sender_flowfile = "./fct/testbed/config-testbed-cdf4.txt"
sender_flowfile = ["./fct/mytest8.txt",
                   "./fct/mytest13.txt"
                   ]

# flowfile = "./fct/flow-incastmix-testbed-cdf4.txt"
# flowfile = "./fct/flow-incastmix-testbed-cdf13.txt"
# flowfile = "./fct/flow-incastmix-testbed-cdf7.txt"
# flowfile = "./fct/flow-incastmix-testbed-cdf8.txt"
# flowfile = "./fct/testbed-flowinfo-30wMTU-incast/config-testbed-cdf4.txt"
