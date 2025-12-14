from scapy.all import *
import model
import json

def analyze_session(packet):
    """Анализ TCP сессии из пакета"""
    if packet.haslayer(TCP) and packet.haslayer(IP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        
        session_data = {
            'protocol': ip_layer.proto,
            'source_ip': ip_layer.src,
            'dest_ip': ip_layer.dst,
            'source_port': tcp_layer.sport,
            'dest_port': tcp_layer.dport,
            'window_size': tcp_layer.window,
        }
        
        return session_data

# Захват пакетов
packets = sniff(count=10, filter="tcp")  # захватываем 10 TCP пакетов

# Анализ каждого пакета
for packet in packets:
    data = analyze_session(packet)
    if data:
        print(json.dumps(data, indent=2))
loaded_object = joblib.load('my_sklearn_model.pkl')