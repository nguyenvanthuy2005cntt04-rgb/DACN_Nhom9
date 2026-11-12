import streamlit as st
import pandas as pd
import requests, os, sys, threading, queue, socket
import time

sys.path.append(os.path.abspath(os.path.dirname(__file__)))
import config
from src.utils import load_artifact, load_json
from database.db_manager import save_log
from src.capture_demo import process_pcap_file
from scapy.all import sniff, IP, TCP, UDP

st.set_page_config(page_title="IDS Dashboard", layout="wide")
st.title("🛡️ HỆ THỐNG PHÁT HIỆN XÂM NHẬP MẠNG")

BACKEND_URL = "http://127.0.0.1:8000"

menu = st.sidebar.selectbox("Chức năng hệ thống:", [
    "1. Dashboard & Kết quả huấn luyện",
    "2. Phân tích File PCAP / CSV",
    "3. Nhật ký CSDL (Database Logs)"
])

# Hàm dịch IP sang tên miền (Domain)
def resolve_ip(ip):
    if ip.startswith("192.168.") or ip.startswith("10.") or ip == "127.0.0.1":
        return "Mạng nội bộ (Local)"
    try:
        socket.setdefaulttimeout(0.2) # Chờ tối đa 0.2s để tránh treo app
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Không xác định (Unknown IP)"

@st.cache_resource
def load_assets():
    # Load mô hình, bộ chuẩn hóa và danh sách đặc trưng đã lưu
    clf = load_artifact(config.MODEL_PATH)
    scaler = load_artifact(config.PREPROCESSOR_PATH)
    features = load_json(config.FEATURE_COLUMNS_PATH)
    return clf, scaler, features

clf, scaler, features = load_assets()


@st.cache_resource
def get_shared_state():
    # Hàng đợi, Event dừng, Dictionary lưu Flow, Khóa luồng (Lock)
    return queue.Queue(), threading.Event(), {}, threading.Lock()

packet_queue, stop_sniff_event, flow_sessions, flow_lock = get_shared_state()

if 'live_packets' not in st.session_state:
    st.session_state.live_packets = []
if 'sniffing' not in st.session_state:
    st.session_state.sniffing = False

def process_live_packet(packet):
    """
    Xử lý Packet thành Bidirectional Flow và tính toán đặc trưng CICFlowMeter
    """
    if IP not in packet:
        return
        
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = packet[IP].proto
    pkt_len = len(packet)
    pkt_time = float(packet.time) 
    
    sport = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else 0)
    dport = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else 0)
    
    if sport == 0 and dport == 0:
        return # Bỏ qua các giao thức không phải TCP/UDP

    # 1. CƠ CHẾ BIDIRECTIONAL FLOW
    forward_key = f"{src_ip}-{dst_ip}-{sport}-{dport}-{protocol}"
    backward_key = f"{dst_ip}-{src_ip}-{dport}-{sport}-{protocol}"
    
    # KHOÁ LUỒNG LẠI KHI CẬP NHẬT DICTIONARY (Chống Race Condition)
    with flow_lock:
        if forward_key in flow_sessions:
            flow_key = forward_key
            direction = "fwd"
        elif backward_key in flow_sessions:
            flow_key = backward_key
            direction = "bwd"
        else:
            # Khởi tạo luồng mới
            flow_key = forward_key
            direction = "fwd"
            
            flow_sessions[flow_key] = {
                'Source IP': src_ip, 'Destination IP': dst_ip,
                'Destination Port': dport, 'Protocol': protocol,
                'start_time': pkt_time, 'last_time': pkt_time,
                'Total Fwd Packets': 0, 'Total Backward Packets': 0, 
                'Total Length of Fwd Packets': 0, 'Total Length of Bwd Packets': 0,
                'Fwd Packet Length Max': 0, 'Fwd Packet Length Min': 999999,
                'Bwd Packet Length Max': 0, 'Bwd Packet Length Min': 999999,
                'FIN Flag Count': 0, 'SYN Flag Count': 0, 'RST Flag Count': 0,
                'PSH Flag Count': 0, 'ACK Flag Count': 0, 'URG Flag Count': 0
            }

        flow = flow_sessions[flow_key]
        flow['last_time'] = pkt_time
        
        # Đếm cờ TCP (Top feature importance trong hệ thống IDS)
        if TCP in packet:
            flags = packet[TCP].flags
            if 'F' in flags: flow['FIN Flag Count'] += 1
            if 'S' in flags: flow['SYN Flag Count'] += 1
            if 'R' in flags: flow['RST Flag Count'] += 1
            if 'P' in flags: flow['PSH Flag Count'] += 1
            if 'A' in flags: flow['ACK Flag Count'] += 1
            if 'U' in flags: flow['URG Flag Count'] += 1
        
        # Cập nhật số liệu kích thước gói tin
        if direction == "fwd":
            flow['Total Fwd Packets'] += 1
            flow['Total Length of Fwd Packets'] += pkt_len
            if pkt_len > flow['Fwd Packet Length Max']: flow['Fwd Packet Length Max'] = pkt_len
            if pkt_len < flow['Fwd Packet Length Min']: flow['Fwd Packet Length Min'] = pkt_len
        else:
            flow['Total Backward Packets'] += 1
            flow['Total Length of Bwd Packets'] += pkt_len
            if pkt_len > flow['Bwd Packet Length Max']: flow['Bwd Packet Length Max'] = pkt_len
            if pkt_len < flow['Bwd Packet Length Min']: flow['Bwd Packet Length Min'] = pkt_len

def start_sniffing():
    try:
        with flow_lock:
            flow_sessions.clear() # Xóa rác phiên bắt cũ an toàn
            
        sniff(
            prn=process_live_packet,
            stop_filter=lambda p: stop_sniff_event.is_set(),
            store=False
        )
        
        # 3. CHỐT SỔ VÀ ĐẨY FLOW VÀO QUEUE
        with flow_lock:
            for key, flow in list(flow_sessions.items()):
                if flow['Fwd Packet Length Min'] == 999999: flow['Fwd Packet Length Min'] = 0
                if flow['Bwd Packet Length Min'] == 999999: flow['Bwd Packet Length Min'] = 0
                
                # KHẮC PHỤC LỖI 4: TÍNH TOÁN RATE VÀ MEAN ĐỂ MÔ HÌNH HỌC MÁY KHÔNG BỊ SAI LỆCH
                duration_sec = flow['last_time'] - flow['start_time']
                if duration_sec <= 0: duration_sec = 0.000001 # Tránh chia cho 0
                
                flow['Flow Duration'] = duration_sec * 1_000_000 # Chuẩn Microseconds
                
                flow['Flow Bytes/s'] = (flow['Total Length of Fwd Packets'] + flow['Total Length of Bwd Packets']) / duration_sec
                flow['Flow Packets/s'] = (flow['Total Fwd Packets'] + flow['Total Backward Packets']) / duration_sec
                
                flow['Fwd Packet Length Mean'] = flow['Total Length of Fwd Packets'] / flow['Total Fwd Packets'] if flow['Total Fwd Packets'] > 0 else 0
                flow['Bwd Packet Length Mean'] = flow['Total Length of Bwd Packets'] / flow['Total Backward Packets'] if flow['Total Backward Packets'] > 0 else 0
                
                packet_queue.put(flow)
                
    except Exception as e:
        print(f"Lỗi Sniffing: {e}")


# ================= GIAO DIỆN STREAMLIT =================

with st.expander("📡 **KHỐI GIÁM SÁT TRAFFIC MẠNG THỰC TẾ )**", expanded=True):
    st.info("Hãy lướt web để tạo traffic!")
    
    col_btn1, col_btn2, col_btn3 = st.columns(3)
    
    if col_btn1.button("▶ Bắt đầu bắt Traffic Thực tế"):
        st.session_state.live_packets = []
        st.session_state.sniffing = True
        stop_sniff_event.clear()
        
        while not packet_queue.empty(): 
            packet_queue.get()
            
        t = threading.Thread(target=start_sniffing, daemon=True)
        t.start()
        st.success("🟢 Đang chạy luồng ngầm an toàn ... Hãy lướt web để tạo traffic!")

    if col_btn2.button("⏹ Dừng & Xử lý ML"):
        st.session_state.sniffing = False
        stop_sniff_event.set()
        
        time.sleep(1) # Đợi luồng ngầm xả dữ liệu vào Queue
        
        while not packet_queue.empty():
            st.session_state.live_packets.append(packet_queue.get())
            
        if len(st.session_state.live_packets) > 0:
            df_captured = pd.DataFrame(st.session_state.live_packets)
            
            os.makedirs("data/uploads", exist_ok=True)
            csv_path = "data/uploads/live_captured_internet.csv"
            df_captured.to_csv(csv_path, index=False)
            
            # Khớp đặc trưng với Model, điền 0 cho cột thiếu
            # Nhờ đã tự tính các cột quan trọng (Means/Rates/Flags) nên tỷ lệ nhiễu cực thấp
            X_live = df_captured.reindex(columns=features, fill_value=0)
            X_live_scaled = scaler.transform(X_live)
            X_scaled_df = pd.DataFrame(X_live_scaled, columns=features)
            
            preds = clf.predict(X_scaled_df)
            probs = clf.predict_proba(X_scaled_df)[:, 1] if hasattr(clf, "predict_proba") else [0.0]*len(preds)
            
            
            df_captured['Prediction'] = ['ATTACK' if str(p).upper() in ['1', 'ATTACK', 'ANOMALY'] else 'BENIGN' for p in preds]
            df_captured['Attack_Probability'] = probs
            
            # Tối ưu: Chỉ phân giải Domain cho luồng ATTACK
            with st.spinner('Đang phân giải IP... (Chỉ tra cứu tên miền cho các luồng Tấn công)'):
                df_captured['Website / Domain'] = df_captured.apply(
                    lambda row: resolve_ip(row['Destination IP']) if row['Prediction'] == 'ATTACK' else "An toàn (Bỏ qua)", 
                    axis=1
                )
            
            attack_count = 0
            for idx, row in df_captured[df_captured['Prediction'] == 'ATTACK'].iterrows():
                save_log(int(row['Destination Port']), float(row['Flow Duration']), 'ATTACK', float(row['Attack_Probability']), source_type="LIVE_INTERNET")
                attack_count += 1
                
            m1, m2, m3 = st.columns(3)
            m1.metric("Tổng luồng (Flows) bắt được", len(df_captured))
            m2.metric("An toàn (BENIGN)", len(df_captured) - attack_count)
            m3.metric("Phát hiện Tấn công (ATTACK)", attack_count, delta_color="inverse")
            
            st.write("### 📋 Bảng Phân Tích Chi Tiết IP, Tên miền & Kết Quả Từ Mô Hình ML")
            # Hiển thị các cột quan trọng nếu có
            display_cols = [c for c in ['Source IP', 'Destination IP', 'Website / Domain', 'Destination Port', 'Flow Bytes/s', 'Prediction', 'Attack_Probability'] if c in df_captured.columns]
            st.dataframe(df_captured[display_cols])
        else:
            st.warning("Chưa có luồng mạng nào! Hãy lướt web vài giây rồi thử lại.")

    if col_btn3.button("🗑 Xóa dữ liệu tạm"):
        st.session_state.live_packets = []
        st.session_state.sniffing = False
        stop_sniff_event.set()
        while not packet_queue.empty(): 
            packet_queue.get()
        st.rerun()

    if st.session_state.sniffing:
        st.caption("⚡ Hệ thống đang lắng nghe gói tin mạng ngầm...")

st.divider()

if menu == "1. Dashboard & Kết quả huấn luyện":
    st.subheader("📊 Kết quả Đánh giá Mô hình")
    if os.path.exists(config.METRICS_PATH):
        metrics = load_json(config.METRICS_PATH)
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Accuracy", f"{metrics.get('accuracy', 0)*100:.2f}%")
        m2.metric("Precision", f"{metrics.get('precision', 0)*100:.2f}%")
        m3.metric("Recall", f"{metrics.get('recall', 0)*100:.2f}%")
        m4.metric("F1-Score", f"{metrics.get('f1_score', 0)*100:.2f}%")

    st.divider()
    c1, c2 = st.columns(2)
    with c1:
        st.write("**Ma trận nhầm lẫn**")
        if os.path.exists(config.CONFUSION_MATRIX_PATH):
            st.image(config.CONFUSION_MATRIX_PATH)
    with c2:
        st.write("**Độ quan trọng đặc trưng**")
        if os.path.exists(config.FEATURE_IMPORTANCE_PATH):
            st.image(config.FEATURE_IMPORTANCE_PATH)

elif menu == "2. Phân tích File PCAP / CSV":
    st.subheader("📁 Upload File Lưu Lượng Mạng")
    file_type = st.radio("Chọn loại file:", ["CSV", "PCAP (Wireshark)"])
    uploaded_file = st.file_uploader("Chọn file:", type=["csv"] if file_type == "CSV" else ["pcap"])
    
    if uploaded_file:
        save_path = os.path.join("data", "uploads", uploaded_file.name)
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
            
        if st.button("Tiến hành phân tích"):
            if file_type == "CSV":
                df = pd.read_csv(save_path)
                df.columns = df.columns.str.strip()
            else:
                df = process_pcap_file(save_path)
                
            X = df.reindex(columns=features, fill_value=0)
            X_scaled = scaler.transform(X)
            X_scaled_df = pd.DataFrame(X_scaled, columns=features)
            
            preds = clf.predict(X_scaled_df)
            probs = clf.predict_proba(X_scaled_df)[:, 1] if hasattr(clf, "predict_proba") else [0.0]*len(preds)
            
            # Sửa lỗi ép kiểu nhãn ở chức năng Upload
            df['Prediction'] = ['ATTACK' if str(p).upper() in ['1', 'ATTACK', 'ANOMALY'] else 'BENIGN' for p in preds]
            df['Attack_Probability'] = probs
            
            for idx, row in df[df['Prediction'] == 'ATTACK'].iterrows():
                save_log(int(row.get('Destination Port', 0)), float(row.get('Flow Duration', 0)), 'ATTACK', float(row['Attack_Probability']), source_type="FILE_UPLOAD")
            
            total = len(df)
            attacks = (df['Prediction'] == 'ATTACK').sum()
            normals = total - attacks
            
            k1, k2, k3 = st.columns(3)
            k1.metric("Tổng kết nối", total)
            k2.metric("An toàn (BENIGN)", normals)
            k3.metric("Phát hiện Tấn công (ATTACK)", attacks, delta_color="inverse")
            
            display_cols = [c for c in ['Destination Port', 'Flow Duration', 'Prediction', 'Attack_Probability'] if c in df.columns]
            st.dataframe(df[display_cols])

elif menu == "3. Nhật ký CSDL (Database Logs)":
    st.subheader("🗄️ Nhật ký Lưu trữ Tấn công")
    try:
        res = requests.get(f"{BACKEND_URL}/api/logs")
        if res.status_code == 200 and res.json():
            st.dataframe(pd.DataFrame(res.json()))
        else:
            st.info("Chưa có ghi nhận tấn công.")
    except:
        st.error("Không thể kết nối Server FastAPI Backend!")