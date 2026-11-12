import time
import pandas as pd
from scapy.all import rdpcap, sniff, IP, TCP, UDP
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config

def process_pcap_file(pcap_path: str) -> pd.DataFrame:
    """Đọc file PCAP (từ Wireshark) và chuyển thành dữ liệu Flow tương thích Random Forest."""
    packets = rdpcap(pcap_path)
    flows = {}
    
    for packet in packets:
        if IP not in packet:
            continue
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        sport = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else 0)
        dport = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else 0)
        
        flow_key = (src_ip, dst_ip, sport, dport, proto)
        pkt_len = len(packet)
        now = time.time()
        
        if flow_key not in flows:
            flows[flow_key] = {
                'start_time': now, 'last_time': now,
                'fwd_pkts': 1, 'bwd_pkts': 0,
                'fwd_len': [pkt_len], 'bwd_len': [0],
                'dport': dport
            }
        else:
            f = flows[flow_key]
            f['last_time'] = now
            f['fwd_pkts'] += 1
            f['fwd_len'].append(pkt_len)

    data = []
    for key, f in flows.items():
        data.append({
            'Destination Port': f['dport'],
            'Flow Duration': (f['last_time'] - f['start_time']) * 1e6,
            'Total Fwd Packets': f['fwd_pkts'],
            'Total Backward Packets': f['bwd_pkts'],
            'Total Length of Fwd Packets': sum(f['fwd_len']),
            'Total Length of Bwd Packets': sum(f['bwd_len']),
            'Fwd Packet Length Max': max(f['fwd_len']),
            'Fwd Packet Length Min': min(f['fwd_len']),
            'Bwd Packet Length Max': max(f['bwd_len']),
            'Bwd Packet Length Min': min(f['bwd_len'])
        })
    return pd.DataFrame(data)