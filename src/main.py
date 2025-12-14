import joblib
import numpy as np
from sniffer import preprocess_frame, extract_session_info

def main():

    pcap_file = input("Введите имя pcap файла: ")
    loaded_model = joblib.load("my_sklearn_model.pkl")
    session_info = extract_session_info(pcap_file)
    print(session_info["Src_IP"][1])
    prep_data = preprocess_frame(session_info)
    predictions = loaded_model.predict(prep_data)

    print("DDoS атака была произведена с данных ip-адресов:")
    set_ip_adr = set()
    for i in range(len(predictions)):
        if predictions[i] != 0 and session_info["Src_IP"][i] not in set_ip_adr:
            print(f"C ip-адреса {session_info["Src_IP"][i]} на порт {session_info["Src_Port"][i]}")
            set_ip_adr.add(session_info["Src_IP"][i])

if __name__ == "__main__":
    main()
