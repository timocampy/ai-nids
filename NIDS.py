from scapy.all import IP, UDP, sniff, TCP, Raw
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import TCP, UDP
import time
import pandas as pd
import itertools
import random
from collections import deque, defaultdict
import re
import joblib
import numpy as np
import tensorflow as tf
import pickle
import tkinter as tk
from tkinter import ttk
import threading
from collections import defaultdict

PROTO_MAP = {
    17: "udp",
    6: "tcp",
    2: "igmp",
    89: "ospf",
    132: "sctp",
    47: "gre",
    3: "ggp",
    4: "ipnip",
    5: "st2",
    13: "argus",
    16: "chaos",
    8: "egp",
    14: "emcon",
    11: "nvp",
    12: "pup",
    15: "xnet",
    18: "mux",
    19: "dcn",
    20: "hmp",
    21: "prm",
    23: "trunk-1",
    24: "trunk-2",
    22: "xns-idp",
    25: "leaf-1",
    26: "leaf2",
    28: "irtp",
    27: "rdp",
    30: "netblt",
    31: "mfe-nsp",
    32: "merit-inp",
    34: "3pc",
    35: "idpr",
    37: "ddp",
    38: "idpr-cmtp",
    39: "tp++",
    41: "ipv6",
    42: "sdrp",
    44: "ipv6-frag",
    43: "ipv6-route",
    45: "idpr",
    48: "mhrp",
    52: "i-nlsp",
    66: "rvd",
    55: "mobile",
    54: "narp",
    57: "skip",
    56: "tlsp",
    59: "ipv6-no",
    255: "any",
    60: "ipv6-opts",
    62: "cftp",
    64: "sat-expak",
    67: "ippc",
    65: "kryptolan",
    69: "sat-mon",
    72: "cpnx",
    74: "wsn",
    75: "pvp",
    76: "br-sat-mon",
    77: "sun-nd",
    78: "wb-mon",
    81: "vmtp",
    83: "vines",
    85: "nsfnet-igp",
    86: "dgp",
    88: "eigrp",
    87: "tcf",
    90: "sprite-rpc",
    91: "larp",
    92: "mtp",
    93: "ax.25",
    94: "ipip",
    95: "micp",
    98: "encap",
    100: "gmtp",
    101: "ifmp",
    102: "pnni",
    106: "qnx",
    105: "scps",
    7: "cbt",
    10: "bbn-rcc",
    9: "igp",
    49: "bna",
    53: "swipe",
    70: "visa",
    71: "ipcv",
    73: "cphb",
    29: "iso-tp4",
    79: "wb-expak",
    82: "secure-vmtp",
    36: "xtp",
    40: "il",
    46: "rsvp",
    133: "fc",
    80: "iso-ip",
    97: "etherip",
    103: "pim",
    104: "aris",
    107: "a/n",
    108: "ipcomp",
    109: "snp",
    110: "compaq-peer",
    111: "ipx-n-ip",
    113: "pgm",
    112: "vrrp",
    115: "l2tp",
    116: "ddx",
    117: "iatp",
    118: "stp",
    119: "srp",
    120: "uti",
    122: "sm",
    121: "smp", 
    124: "isis",
    123: "ptp",
    125: "fire",
    126: "crtp",
    127: "crudp",
    128: "sccopmce",
    129: "iplt",
    131: "pipe",
    130: "sps",
    1: "icmp",
}

SERVICE_MAP = {
    53: "dns",
    80: "http",
    8080: "http",
    25: "smtp",
    20: "ftp-data",
    21: "ftp",
    110: "pop3",
    22: "ssh",
    67: "dhcp",
    68: "dhcp",
    161: "snmp",
    162: "snmp",
    443: "ssl",
    194: "irc",
    529: "irc",
    6665: "irc",
    6666: "irc",
    6667: "irc",
    6668: "irc",
    6669: "irc",
    6697: "irc", #tested using pcap file used to make dataset, it had protocol irc in these ranges as well
    1812: "radius",
    1813: "radius",
    }
TCP_STATE_MAP = {
    "0x01": "FIN",    #FIN
    "0x11": "FIN",    #FIN + ACK
    "0x14": "INT",    #RST + ACK
    "0x12": "CON",    #SYN + ACK
    "0x02": "REQ",    #SYN
    "0x04": "RST",    #RST
    "0x40": "ECO",    #ECE
    "0x10": "ACC",    #ACK
    "0x18": "PAR",    #PSH + ACK
}

encoder = joblib.load("encoder.pkl")
scaler = joblib.load("scaler.pkl")
model = tf.keras.models.load_model("687584.keras")
with open('index_to_label_map.pkl', 'rb') as f:
    index_to_label = pickle.load(f)

cat_col = ['proto', 'service', 'state']
num_col = ["djit","dur", "is_ftp_login","ct_flw_http_mthd","dbytes","dwin","sload", "stcpb",
           "ct_src_dport_ltm", "ct_ftp_cmd", "smean", "spkts", "sjit", "dload", "synack", "ct_dst_sport_ltm",
           "rate", "dmean", "sinpkt",  "swin",  "tcprtt", "ackdat", "is_sm_ips_ports", "dloss",
           "trans_depth", "sloss", "response_body_len", "dpkts",  "dinpkt", "sbytes", "dtcpb",
            ]
required_labels = ["proto", "service", "state", "djit","dur", "is_ftp_login","ct_flw_http_mthd","dbytes","dwin","sload", "stcpb",
           "ct_src_dport_ltm", "ct_ftp_cmd", "smean", "spkts", "sjit", "dload", "synack", "ct_dst_sport_ltm",
           "rate", "dmean", "sinpkt",  "swin",  "tcprtt", "ackdat", "is_sm_ips_ports", "dloss",
           "trans_depth", "sloss", "response_body_len", "dpkts",  "dinpkt", "sbytes", "dtcpb",]

alt_flag_cycle = itertools.cycle(["INT", "FIN"])
flows = {}
flow_logs = []
recent_connections = deque(maxlen=100) #might need to increase depending on environment
src_dport_tracker = defaultdict(set)
dest_sport_tracker = defaultdict(set)
FTP_COMMAND_REGEX = re.compile(rb"^[a-z]{3,4}( .*)?\r\n", re.IGNORECASE)
detected_attacks = []

prediction_counts = defaultdict(int)
service_label_counts = defaultdict(lambda: defaultdict(int))

def get_protocol(packet):
    if packet.haslayer(ARP):
        return "arp"
    #elif packet.haslayer(Ether) and not packet.haslayer(IP) and not packet.haslayer(IPv6):
        #eth_type = packet[Ether].type
        #if eth_type == 0x010b:
            #return "SEP"
    elif packet.haslayer(IP):
        proto_num = packet[IP].proto
        if proto_num == 17 and packet.haslayer(UDP):
            udp_dst_port = packet[UDP].dport
            udp_src_port = packet[UDP].sport
            if udp_dst_port in [5004, 5005] or udp_src_port in [5004, 5005]:
                return "rtp"

        return PROTO_MAP.get(proto_num, "unas")
    
    return "unas"

def get_service(packet):
    if packet.haslayer(TCP):  
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):  
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    else:
        return "None"
    
    if dst_port in SERVICE_MAP:
        return SERVICE_MAP[dst_port]

    if src_port in SERVICE_MAP:
        return SERVICE_MAP[src_port]

    return "None"

def get_tcp_state(packet):   
    if packet.haslayer(TCP):  
        flags = packet[TCP].flags.value
        flags_hex = hex(flags)
        state = TCP_STATE_MAP.get(flags_hex, None)
        if state is None:
            state = next(alt_flag_cycle)
        
        return state
    
    elif packet.haslayer(UDP):
        return "INT" if random.random() < 0.8 else "CON"
    
    else:
        state = next(alt_flag_cycle)
        return state

def update_flow_counters(flow_data, direction, packet_size, timestamp):
    flow_data['rate'] = calculate_flow_rate(flow_data)
    flow_data['dur'] = timestamp - flow_data['start_time']
    
    duration = flow_data['dur']
    if duration < 1:
        duration = 1
    int(duration)
    
    if direction == 'forward':
        flow_data['spkts'] += 1
        flow_data['sbytes'] += packet_size
        flow_data['sload'] = (flow_data['sbytes'] * 8) / duration

        if flow_data['last_src_pkt_time'] != 0:
            sinpkt = (timestamp - flow_data['last_src_pkt_time']) * 1000 #miliseconds
            flow_data['sinpkt'] = sinpkt

            flow_data['sjit'] = abs(sinpkt - flow_data['s_prev_inpkt']) * 1000
            flow_data['s_prev_inpkt'] = sinpkt
            
        else:
            flow_data['sinpkt'] = 0
            flow_data['sjit'] = 0
            
        flow_data['last_src_pkt_time'] = timestamp
        flow_data['smean'] = flow_data['sbytes'] / flow_data['spkts']

    elif direction == 'reverse':
        flow_data['dpkts'] += 1
        flow_data['dbytes'] += packet_size
        flow_data['dload'] = (flow_data['dbytes'] * 8) / duration

        if flow_data['last_dst_pkt_time'] != 0:
            dinpkt = (timestamp - flow_data['last_dst_pkt_time']) * 1000
            flow_data['dinpkt'] = dinpkt

            flow_data['djit'] = abs(dinpkt - flow_data['d_prev_inpkt']) * 1000
            flow_data['d_prev_inpkt'] = dinpkt
        else:
            flow_data['dinpkt'] = 0
            flow_data['djit'] = 0
        flow_data['last_dst_pkt_time'] = timestamp
        flow_data['dmean'] = flow_data['dbytes'] / flow_data['dpkts']

def calculate_flow_rate(flow_data):
    total_pkts = flow_data['spkts'] + flow_data['dpkts']
    duration = flow_data['dur']
    return (total_pkts / duration) if duration > 0 else 0

def calculate_lost_packets(flow_data, direction, sequence_number, has_data):
    if not has_data:
        return
    
    if direction == 'forward':
        if sequence_number == flow_data['last_src_seq']:
            flow_data['sloss'] += 1
        elif sequence_number > flow_data['last_src_seq']:
            flow_data['last_src_seq'] = sequence_number
            
    elif direction == 'reverse':
        if sequence_number == flow_data['last_dst_seq']:
            flow_data['dloss'] += 1
        elif sequence_number > flow_data['last_dst_seq']:
            flow_data['last_dst_seq'] = sequence_number

def update_tcp_fields(flow_data, direction, packet):
    if not packet.haslayer(TCP):
        return
    
    tcp = packet[TCP]
    win = tcp.window
    seq = tcp.seq
    ack = tcp.ack
    flags = tcp.flags
    ts = packet.time

    if direction == 'forward':
        flow_data['swin'] = win
        flow_data['stcpb'] = seq
        if len(tcp.payload) > 0:
            flow_data['seq_times'][seq + len(tcp.payload)] = ts
        
    elif direction == 'reverse':
        flow_data['dwin'] = win
        flow_data['dtcpb'] = seq
        
        acked_seq = ack
        if acked_seq in flow_data['seq_times']:
            sent_time = flow_data['seq_times'][acked_seq]
            rtt = ts - sent_time
            flow_data['tcprtt'] = round(rtt, 6)
            del flow_data['seq_times'][acked_seq]

    if flags & 0x02 and not flags & 0x10:  #SYN without ACK
        flow_data['syn_time'] = ts

    elif flags & 0x12:  #SYN + ACK
        if 'syn_time' in flow_data:
            flow_data['synack'] = round(ts - flow_data['syn_time'], 6)
            flow_data['synack_time'] = ts

    elif flags & 0x10 and not (flags & 0x02 or len(tcp.payload) > 0):  #pure ACK
        if 'synack_time' in flow_data and flow_data['synack_time'] is not None:
            if 'ack_time' not in flow_data or flow_data['ack_time'] is None:
                flow_data['ack_time'] = ts

    elif len(tcp.payload) > 0 and 'ack_time' in flow_data and flow_data['ack_time'] is not None and 'ackdat' not in flow_data:
        flow_data['ackdat'] = round(ts - flow_data['ack_time'], 6)
        
    if packet[TCP].sport in [80, 443]:
        flow_data['response_body_len'] = len(packet[TCP].payload)
    else:
        flow_data['response_body_len'] = 0

def ct_features(packet, src_port, dst_port, flow_data, recent_connections, src_dport_tracker, dest_sport_tracker):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    recent_connections.append((src_ip, dst_ip, src_port, dst_port))
    src_dport_tracker[src_ip].add(dst_port)
    dest_sport_tracker[dst_ip].add(src_port)

    ct_src_dport_ltm = sum(
        1 for s, d, sp, dp in recent_connections if s == src_ip and dp in src_dport_tracker[src_ip]
    )

    ct_dest_sport_ltm = sum(
        1 for s, d, sp, dp in recent_connections if d == dst_ip and sp in dest_sport_tracker[dst_ip]
    )

    flow_data['ct_src_dport_ltm'] = ct_src_dport_ltm
    flow_data['ct_dst_sport_ltm'] = ct_dest_sport_ltm

def ftp_features(packet, flow_data):
    if Raw not in packet:
        return

    payload = packet[Raw].load.lower()
    if b'user ' in payload and b'pass ' in payload: #logins
        flow_data['is_ftp_login'] = 1

    lines = payload.split(b'\r\n')
    for line in lines:
        if FTP_COMMAND_REGEX.match(line.strip()):
            flow_data['ct_ftp_cmd'] = 1
            break

def cleanup_idle_udp_flows(current_time, timeout=20):
    to_delete = []

    for flow_key, flow_data in flows.items():
        if flow_data['proto'] == 'udp':
            if current_time - flow_data['timestamp'] > timeout:
                print(f"[DEBUG] Closing idle UDP flow: {flow_key} after {timeout}s of inactivity.")
                to_delete.append(flow_key)

    for flow_key in to_delete:
        del flows[flow_key]
        
def initialize_flow(timestamp, proto, service, state):
    return {
        'start_time': timestamp,
        'timestamp': timestamp,
        'dur': 0,
        'proto': proto,
        'service': service,
        'state': state,
        'closed': False,
        'spkts': 0,
        'dpkts': 0,
        'sbytes': 0,
        'dbytes': 0,
        'rate': 0,
        'sload': 0,
        'dload': 0,
        'sloss': 0,
        'dloss': 0,
        'last_src_seq': 0,
        'last_dst_seq': 0,
        'last_src_pkt_time': 0,
        'last_dst_pkt_time': 0,
        'sinpkt': 0,
        'dinpkt': 0,
        'sjit': 0,
        'djit': 0,
        's_prev_inpkt': 0,
        'd_prev_inpkt': 0,
        'swin': 0,
        'dwin': 0,
        'stcpb': 0,
        'dtcpb': 0,
        'tcprtt': 0,
        'seq_times': {},
        'synack': 0,
        'ackdat': 0,
        'synack_time': None,
        'ack_time': None,
        'smean': 0,
        'dmean': 0,
        'trans_depth': 0,
        'response_body_len': 0,
        'ct_src_dport_ltm': 0,
        'ct_dst_sport_ltm': 0,
        'is_ftp_login': 0,
        'ct_ftp_cmd': 0,
        'ct_flw_http_mthd': 0,
        'is_sm_ips_ports': 0
        }

def update_flow(packet, packet_size, timestamp, src_ip, dst_ip, proto, service, state):
    global flows, flow_logs

    src_port = packet[TCP].sport if packet.haslayer(TCP) else (packet[UDP].sport if packet.haslayer(UDP) else 0)
    dst_port = packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else 0)

    flow_key = (src_ip, dst_ip, proto, src_port, dst_port)
    reverse_key = (dst_ip, src_ip, proto, dst_port, src_port)
    
    #check if part of existing flow if not make new
    if flow_key not in flows and reverse_key not in flows:
        flows[flow_key] = initialize_flow(timestamp, proto, service, state)
    
    if packet.haslayer(TCP):
        sequence_number = packet[TCP].seq
    else:
        sequence_number = 0   
    if packet.haslayer(TCP):
        has_data = len(packet[TCP].payload) > 0
        
    #update flow date back or forth   
    if reverse_key in flows:
        flow_data = flows[reverse_key]
        update_flow_counters(flow_data, 'reverse', packet_size, timestamp)
        update_tcp_fields(flow_data, 'reverse', packet)
        if packet.haslayer(TCP):
            calculate_lost_packets(flow_data, 'reverse', sequence_number, has_data)
    else:
        flow_data = flows[flow_key]
        update_flow_counters(flow_data, 'forward', packet_size, timestamp)
        update_tcp_fields(flow_data, 'forward', packet)
        if packet.haslayer(TCP):
            calculate_lost_packets(flow_data, 'forward', sequence_number, has_data)
    
    #dummy values for trans_depth and http mthd because I wont get non ssl 
    #http traffic in my testing environment, and even in other cases the model would
    #barely know this information so not much meaning to building it out
    if packet.haslayer(TCP):
        service = flow_data['service']
        if service in ('http', 'ssl'):
            if random.random() < 0.93:
                flow_data['trans_depth'] = 1
            else:
                flow_data['trans_depth'] = 0
            if random.random() < 0.92:
                flow_data['ct_flw_http_mthd'] = 1
            else:
                flow_data['ct_flw_http_mthd'] = 0
        else:
            flow_data['trans_depth'] = 0
            flow_data['ct_flw_http_mthd'] = 0
    
    ct_features(packet, src_port, dst_port, flow_data, recent_connections, src_dport_tracker, dest_sport_tracker)

    if flow_data['service'] == 'ftp':
        ftp_features(packet, flow_data)
    
    if src_ip == dst_ip and src_port == dst_port:
        flow_data['is_sm_ips_ports'] = 1
    else:
        flow_data['is_sm_ips_ports'] = 0
    
    flow_logs.append({
        'timestamp': timestamp,
        'flow_id': f"{flow_key}",
        'dur': flow_data['dur'],
        'proto': proto,
        'service': service,
        'state': state,
        'spkts': flow_data['spkts'],
        'dpkts': flow_data['dpkts'],
        'sbytes': flow_data['sbytes'],
        'dbytes': flow_data['dbytes'],
        'rate': flow_data['rate'],
        'sload':flow_data['sload'],
        'dload':flow_data['dload'],
        'sloss': flow_data['sloss'],
        'dloss': flow_data['dloss'],
        'sinpkt': flow_data['sinpkt'],
        'dinpkt': flow_data['dinpkt'],
        'sjit': flow_data['sjit'],
        'djit': flow_data['djit'],
        's_prev_inpkt': flow_data['s_prev_inpkt'],
        'd_prev_inpkt': flow_data['d_prev_inpkt'],
        'swin': flow_data['swin'],
        'dwin': flow_data['dwin'],
        'stcpb': flow_data['stcpb'],
        'dtcpb': flow_data['dtcpb'],
        'tcprtt': flow_data['tcprtt'],
        'synack': flow_data['synack'],
        'synack_time': flow_data['synack_time'],
        'ack_time': flow_data['ack_time'],
        'ackdat': flow_data['ackdat'],
        'smean': flow_data['smean'],
        'dmean': flow_data['dmean'],
        'trans_depth': flow_data['trans_depth'],
        'response_body_len': flow_data['response_body_len'],
        'ct_src_dport_ltm': flow_data['ct_src_dport_ltm'],
        'ct_dst_sport_ltm': flow_data['ct_dst_sport_ltm'],
        'is_ftp_login': flow_data['is_ftp_login'],
        'ct_ftp_cmd': flow_data['ct_ftp_cmd'],
        'ct_flw_http_mthd': flow_data['ct_flw_http_mthd'],
        'is_sm_ips_ports': flow_data['is_sm_ips_ports'],
        })

    #flow closure based on TCP states (FIN or RST)
    tcp_state = get_tcp_state(packet)

    if tcp_state in ("FIN", "RST"):
        
        if packet.haslayer(TCP):
            has_data = len(packet[TCP].payload) > 0
            
        if reverse_key in flows:
            flow_data = flows[reverse_key]
            update_flow_counters(flow_data, 'reverse', packet_size, timestamp)
            update_tcp_fields(flow_data, 'reverse', packet)
            if packet.haslayer(TCP):
                calculate_lost_packets(flow_data, 'reverse', sequence_number, has_data)
                
        else:
            flow_data = flows[flow_key]
            update_flow_counters(flow_data, 'forward', packet_size, timestamp)
            update_tcp_fields(flow_data, 'forward', packet)
            if packet.haslayer(TCP):
                calculate_lost_packets(flow_data, 'forward', sequence_number, has_data)
        
        if packet.haslayer(TCP):
            service = flow_data['service']
            if service in ('http', 'ssl'):
                if random.random() < 0.93:
                    flow_data['trans_depth'] = 1
                else:
                    flow_data['trans_depth'] = 0
        else:
            flow_data['trans_depth'] = 0
            
        ct_features(packet, src_port, dst_port, flow_data, recent_connections, src_dport_tracker, dest_sport_tracker)

        if flow_data['service'] == 'ftp':
            ftp_features(packet, flow_data)
            
        if src_ip == dst_ip and src_port == dst_port:
            flow_data['is_sm_ips_ports'] = 1
        else:
            flow_data['is_sm_ips_ports'] = 0

        if flow_key in flows:
            flows[flow_key]['closed'] = True
        if reverse_key in flows:
            flows[reverse_key]['closed'] = True
            
        timestamp = time.time()

        flow_logs.append({
            'timestamp': timestamp,
            'flow_id': f"{flow_key}",
            'dur': flow_data['dur'],
            'proto': proto,
            'service': service,
            'state': state,
            'spkts': flow_data['spkts'],
            'dpkts': flow_data['dpkts'],
            'sbytes': flow_data['sbytes'],
            'dbytes': flow_data['dbytes'],
            'rate': flow_data['rate'],
            'sload':flow_data['sload'],
            'dload':flow_data['dload'],
            'sloss': flow_data['sloss'],
            'dloss': flow_data['dloss'],
            'sinpkt': flow_data['sinpkt'],
            'dinpkt': flow_data['dinpkt'],
            'swin': flow_data['swin'],
            'dwin': flow_data['dwin'],
            'stcpb': flow_data['stcpb'],
            'dtcpb': flow_data['dtcpb'],
            'tcprtt': flow_data['tcprtt'],
            'synack': flow_data['synack'],
            'synack_time': flow_data['synack_time'],
            'ack_time': flow_data['ack_time'],
            'ackdat': flow_data['ackdat'],
            'smean': flow_data['smean'],
            'dmean': flow_data['dmean'],
            'trans_depth': flow_data['trans_depth'],
            'response_body_len': flow_data['response_body_len'],
            'ct_src_dport_ltm': flow_data['ct_src_dport_ltm'],
            'ct_dst_sport_ltm': flow_data['ct_dst_sport_ltm'],
            'is_ftp_login': flow_data['is_ftp_login'],
            'ct_ftp_cmd': flow_data['ct_ftp_cmd'],
            'ct_flw_http_mthd': flow_data['ct_flw_http_mthd'],
            'is_sm_ips_ports': flow_data['is_sm_ips_ports'],
            })

        #remove flow from the flows dictionary after logging
        print(f"Flow {flow_key} closed at {timestamp} due to {tcp_state}. Deleting flow from memory.")
        del flows[flow_key]
        if reverse_key in flows:
            del flows[reverse_key]

    return flow_key

def print_flow(flow_key, flow_data):
    """Print flow details for debugging."""
    total_spkts = flow_data['spkts']
    total_dpkts = flow_data['dpkts']
    total_sbytes = flow_data['sbytes']
    total_dbytes = flow_data['dbytes']

    print(f"Flow captured: {flow_key} Duration: {flow_data['dur']:.2f}s "
          f"Protocol: {flow_data['proto']} Service: {flow_data['service']} "
          f"Src Bytes: {total_sbytes} Dst Bytes: {total_dbytes} "
          f"Total Packets: {total_spkts} Total ACK Packets: {total_dpkts}")
    
def process_packet(packet):
    global flows

    try:
        if not packet.haslayer(IP):
            return
        timestamp = time.time()
        proto = get_protocol(packet)
        service = get_service(packet)
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        packet_size = len(packet)
        state = get_tcp_state(packet)
        cleanup_idle_udp_flows(time.time())

        flow_key = update_flow(packet, packet_size, timestamp, src_ip, dst_ip, proto, service, state)

        flow_data = flows.get(flow_key)
        if not flow_data:
            return

        cat_features = encoder.feature_names_in_
        num_features = scaler.feature_names_in_

        temp_flow_data = {}
        for col in cat_features:
            temp_flow_data[col] = [flow_data.get(col, 0)]
        for col in num_features:
            temp_flow_data[col] = [flow_data.get(col, 0.0)]
            
        # Create DataFrame with correct column order
        flow_df = pd.DataFrame(temp_flow_data)

        try:
            #pre-process
            encoded = encoder.transform(flow_df[cat_features])
            scaled = scaler.transform(flow_df[num_features])
            X_input = np.concatenate([encoded, scaled], axis=1)
            
            #predict
            prediction = model.predict(X_input)
            predicted_index = np.argmax(prediction)
            predicted_label = index_to_label[predicted_index]
            confidence = prediction[0][predicted_index]

            print(f"Predicted class: {predicted_label} (confidence: {prediction[0][predicted_index]:.2f})")
            print_flow(flow_key, flow_data)
            
            if predicted_label != "Normal" and confidence > 0.8:
                attack_time = time.strftime('%H:%M:%S', time.localtime(timestamp))
                src_port = flow_key[3] if len(flow_key) > 3 else 0
                dst_port = flow_key[4] if len(flow_key) > 4 else 0

                msg = (
                    f"{attack_time:<20} "
                    f"{src_ip:<15}: {src_port:<5} -> "
                    f"{dst_ip:<15}: {dst_port:<5} "
                    f"{proto:<6} "
                    f"{predicted_label}"
                )

                log_attack_to_gui(msg)
                detected_attacks.append({
                "time": attack_time,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": proto,
                "attack_type": predicted_label
                })
            prediction_counts[predicted_label] += 1
            service_label_counts[service][predicted_label] += 1
            
        except ValueError as ve:
            print(f"Encoding/Scaling error: {ve}")
            print("Problematic values:")
            print("Categorical:", flow_df[cat_features].to_dict())
            print("Numerical:", flow_df[num_features].to_dict())

    except Exception as e:
        print(f"Error processing packet: {e}")

def start_capture():
    prediction_counts.clear()
    service_label_counts.clear()
    try:
        duration = int(timeout_entry.get())
    except ValueError:
        log_text.insert(tk.END, "Invalid input. Enter a number.\n")
        return

    log_text.insert(tk.END, f"Starting capture for {duration} seconds...\n")
    log_text.see(tk.END)

    thread = threading.Thread(target=run_sniffer, args=(duration,), daemon=True)
    thread.start()
    
def run_sniffer(duration):
    try:
        sniff(iface="WiFi", prn=process_packet, store=False, timeout=duration)
        log_text.insert(tk.END, f"Capture finished after {duration} seconds.\n")
    except Exception as e:
        log_text.insert(tk.END, f"Error: {e}\n")
    log_text.see(tk.END)
    
    if detected_attacks:
        df = pd.DataFrame(detected_attacks)
        filename = f"detected_attacks_{int(time.time())}.csv"
        df.to_csv(filename, index=False)
        log_attack_to_gui(f"Exported {len(detected_attacks)} attacks to {filename}")
    else:
        log_attack_to_gui("No attacks detected, no CSV exported.")
    
root = tk.Tk()
root.title("NIDS")

#timeout
frame = ttk.Frame(root, padding="10")
frame.pack(fill=tk.BOTH, expand=True)

input_frame = ttk.Frame(frame)
input_frame.pack(anchor=tk.W, pady=5)

#set time
ttk.Label(input_frame, text="Capture Duration (seconds):").pack(side=tk.LEFT, padx=(0, 5))
timeout_entry = ttk.Entry(input_frame, width=10)
timeout_entry.insert(0, "30")
timeout_entry.pack(side=tk.LEFT)

#start capture button
start_button = ttk.Button(input_frame, text="Start Capture", command=start_capture)
start_button.pack(side=tk.LEFT, padx=5)

#log to interface
log_text = tk.Text(frame, height=10, wrap=tk.WORD)
log_text.pack(fill=tk.BOTH, expand=True)

def log_attack_to_gui(msg):
    log_text.insert(tk.END, msg + "\n")
    log_text.see(tk.END)
    
def show_prediction_stats():
    stats_window = tk.Toplevel()
    stats_window.title("Prediction Stats")
    stats_window.geometry("500x400")

    text_widget = tk.Text(stats_window, wrap=tk.WORD)
    text_widget.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

    #Total counts
    tpckets = sum(prediction_counts.values())
    text_widget.insert(tk.END, f"--- Total Predictions of {tpckets}---\n")
    for label, count in prediction_counts.items():
        text_widget.insert(tk.END, f"{label:<15}: {count}\n")

    #Service-wise counts
    text_widget.insert(tk.END, "\n--- Service-wise Breakdown ---\n")
    for service, label_dict in service_label_counts.items():
        text_widget.insert(tk.END, f"\nService: {service}\n")
        for label, count in label_dict.items():
            text_widget.insert(tk.END, f"  {label:<15}: {count}\n")

    text_widget.config(state=tk.DISABLED)

stats_button = ttk.Button(input_frame, text="Show Stats", command=show_prediction_stats)
stats_button.pack(side=tk.LEFT, padx=5)
 
#GUI loop
root.mainloop()

#to see what complete records look like captured from this program, close program after capture to see
try:
    df = pd.DataFrame.from_dict(flow_logs)

    print("\nFlow data captured:")
    print(df)

    required_labels = ["dur", "proto", "service", "state", "spkts", "dpkts", "sbytes",
                       "dbytes", "rate", "sload", "dload", "sloss", "dloss", "sinpkt",
                       "dinpkt", "sjit", "djit", "swin", "dwin", "stcpb", "dtcpb", "tcprtt",
                       "synack", "ackdat", "smean", "dmean", "trans_depth", "response_body_len",
                       "ct_src_dport_ltm", "ct_dest_sport_ltm", "is_ftp_login", "ct_ftp_cmd",
                       "ct_flw_http_mthd", "is_sm_ips_ports"]
    for col in required_labels:
        if col not in df.columns:
            df[col] = 0

    df = df[required_labels]

    df.to_csv("captured_traffic.csv", index=False)
    print("\nData saved to captured_traffic.csv")

except Exception as e:
    print(f"Error converting flows to DataFrame: {e}") 