from scapy.all import *
from model import group_dst_port, group_src_port
import json
import joblib
import pandas as pd
import numpy as np

def extract_session_info(pcap_file):
        packets = []
        """Извлечение информации о сессиях из PCAP"""
        try:
            packets = rdpcap(pcap_file)
            print(f"Загружено пакетов: {len(packets)}")
        except Exception as e:
            print(f"Ошибка загрузки PCAP: {e}")
            return

        if not packets:
            print("Сначала загрузите PCAP файл!")
            return
        
        print("Извлечение информации о сессиях...")
        session_data = []
        
        # Словарь для отслеживания начальных размеров окон
        init_fwd_windows = {}  # (src_ip, src_port, dst_ip, dst_port) -> window
        init_bwd_windows = {}  # (dst_ip, dst_port, src_ip, src_port) -> window
        
        for i, packet in enumerate(packets):
            # Инициализация данных пакета
            packet_info = {
                'packet_id': i,
                'Protocol': 'Unknown',
                'Src_IP': None,
                'Dst_IP': None,
                'Src_Port': None,
                'Dst_Port': None,
                'Window_Size': None,
                'Init Fwd Win Byts': None,
                'Init Bwd Win Byts': None
            }
            
            # Извлечение IP информации
            if IP in packet:
                ip_layer = packet[IP]
                packet_info['Src_IP'] = ip_layer.src
                packet_info['Dst_IP'] = ip_layer.dst
                packet_info['Protocol'] = ip_layer.proto
                
                # Извлечение портов для TCP/UDP
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    packet_info['Src_Port'] = tcp_layer.sport
                    packet_info['Dst_Port'] = tcp_layer.dport
                    packet_info['Window_Size'] = tcp_layer.window
                    
                    # Определение направления (Forward/Backward)
                    # Forward: от клиента к серверу (обычно меньший порт -> больший порт)
                    is_forward = packet_info['Src_Port'] < packet_info['Dst_Port'] if packet_info['Src_Port'] and packet_info['Dst_Port'] else True
                    
                    # Создаем ключи для сессии
                    forward_key = (ip_layer.src, tcp_layer.sport, 
                                 ip_layer.dst, tcp_layer.dport)
                    backward_key = (ip_layer.dst, tcp_layer.dport,
                                  ip_layer.src, tcp_layer.sport)
                    
                    # Проверяем SYN флаг для определения начального размера окна
                    if tcp_layer.flags & 0x02:  # SYN флаг
                        if is_forward and forward_key not in init_fwd_windows:
                            init_fwd_windows[forward_key] = tcp_layer.window
                        elif not is_forward and backward_key not in init_bwd_windows:
                            init_bwd_windows[backward_key] = tcp_layer.window
                    
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    packet_info['Src_Port'] = group_src_port(udp_layer.sport)
                    packet_info['Dst_Port'] = group_dst_port(udp_layer.dport)
                    packet_info['Window_Size'] = 0  # UDP не имеет окна
            
            # Добавляем пакет в данные сессии
            session_data.append(packet_info)
            
            # Группируем пакеты по сессиям
            if packet_info['Src_IP'] and packet_info['Dst_IP'] and packet_info['Src_Port'] and packet_info['Dst_Port']:
                session_key = tuple(sorted([
                    f"{packet_info['Src_IP']}:{packet_info['Src_Port']}",
                    f"{packet_info['Dst_IP']}:{packet_info['Dst_Port']}"
                ]))
        
        # Создаем DataFrame
        df = pd.DataFrame(session_data)
        
        # Добавляем начальные размеры окон к каждому пакету
        print("Добавление начальных размеров окон...")
        for idx, row in df.iterrows():
            if row['Protocol'] == 'TCP' and row['Src_Port'] and row['Dst_Port']:
                forward_key = (row['Src_IP'], row['Src_Port'], 
                             row['Dst_IP'], row['Dst_Port'])
                backward_key = (row['Dst_IP'], row['Dst_Port'],
                              row['Src_IP'], row['Src_Port'])
                
                if forward_key in init_fwd_windows:
                    df.at[idx, 'Init Fwd Win Byts'] = init_fwd_windows[forward_key]
                if backward_key in init_bwd_windows:
                    df.at[idx, 'Init Bwd Win Byts'] = init_bwd_windows[backward_key]
        
        print(f"Извлечено записей: {len(df)}")
        
        return df

def preprocess_frame(df:pd.DataFrame):
    df_processed = df.copy()
    df_processed = df_processed[['Protocol', 'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Dst_Port', 'Src_Port']]

    df_processed['Dst Port Group'] = df['Dst_Port'].apply(group_dst_port)
    df_processed['Src Port Group'] = df['Src_Port'].apply(group_src_port)
    df_processed = df_processed.drop(['Dst_Port', 'Src_Port'], axis=1)

    return df_processed
