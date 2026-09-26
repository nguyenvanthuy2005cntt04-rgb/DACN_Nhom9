import streamlit as st
import pandas as pd
import requests, os, sys, threading, queue

sys.path.append(os.path.abspath(os.path.dirname(__file__)))
import config
from src.utils import load_artifact, load_json
from database.db_manager import save_log
from src.capture_demo import process_pcap_file
from scapy.all import sniff, IP, TCP, UDP

st.set_page_config(page_title="IDS Dashboard - Random Forest", layout="wide")
st.title("🛡️ HỆ THỐNG PHÁT HIỆN XÂM NHẬP MẠNG (IDS) - RANDOM FOREST")

BACKEND_URL = "http://127.0.0.1:8000"

menu = st.sidebar.selectbox("Chức năng hệ thống:", [
    "1. Dashboard & Kết quả huấn luyện",
    "2. Phân tích File PCAP / CSV",
    "3. Nhật ký CSDL (Database Logs)"
])

@st.cache_resource
def load_assets():
    clf = load_artifact(config.MODEL_PATH)
    scaler = load_artifact(config.PREPROCESSOR_PATH)
    features = load_json(config.FEATURE_COLUMNS_PATH)
    return clf, scaler, features

clf, scaler, features = load_assets()

# --- GIẢI PHÁP TỐI ƯU CHO ĐA LUỒNG ---
# Dùng cache_resource để tạo Queue và Event tĩnh, không bị ảnh hưởng bởi session_state
@st.cache_resource
def get_shared_state():
    return queue.Queue(), threading.Event()

packet_queue, stop_sniff_event = get_shared_state()

if 'live_packets' not in st.session_state:
    st.session_state.live_packets = []
if 'sniffing' not in st.session_state:
    st.session_state.sniffing = False

def process_live_packet(packet):
    # Hàm này chạy ở luồng ngầm, truy cập trực tiếp vào biến tĩnh packet_queue
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        sport = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else 0)
        dport = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else 0)
        pkt_len = len(packet)
        
        packet_queue.put({
            'Source IP': src_ip,
            'Destination IP': dst_ip,
            'Destination Port': dport,
            'Flow Duration': 100.0,
            'Total Fwd Packets': 1,
            'Total Backward Packets': 0,
            'Total Length of Fwd Packets': pkt_len,
            'Total Length of Bwd Packets': 0,
            'Fwd Packet Length Max': pkt_len,
            'Fwd Packet Length Min': pkt_len,
            'Bwd Packet Length Max': 0,
            'Bwd Packet Length Min': 0
        })

def start_sniffing():
    try:
        sniff(
            prn=process_live_packet,
            stop_filter=lambda p: stop_sniff_event.is_set(),
            store=False
        )
    except Exception as e:
        print(f"Lỗi Sniffing: {e}")

with st.expander("📡 **KHỐI GIÁM SÁT TRAFFIC MẠNG THỰC TẾ (REAL-TIME INTERNET SNIFFING)**", expanded=True):
    st.info("Nhấn 'Bắt đầu', sau đó mở trình duyệt lướt web. Hệ thống sẽ bắt IP thực tế, tự xuất file CSV và đưa qua ML phân loại.")
    
    col_btn1, col_btn2, col_btn3 = st.columns(3)
    
    if col_btn1.button("▶ Bắt đầu bắt Traffic Thực tế"):
        st.session_state.live_packets = []
        st.session_state.sniffing = True
        stop_sniff_event.clear()
        
        # Xóa sạch Queue cũ
        while not packet_queue.empty():
            packet_queue.get()
            
        t = threading.Thread(target=start_sniffing, daemon=True)
        t.start()
        st.success("🟢 Đang bắt gói tin internet thực tế... Hãy lướt web để tạo traffic!")

    if col_btn2.button("⏹ Dừng & Xuất File CSV & Đưa vào ML"):
        st.session_state.sniffing = False
        stop_sniff_event.set()
        
        # Rút dữ liệu từ Queue ra session list
        while not packet_queue.empty():
            st.session_state.live_packets.append(packet_queue.get())
            
        if len(st.session_state.live_packets) > 0:
            df_captured = pd.DataFrame(st.session_state.live_packets)
            
            os.makedirs("data/uploads", exist_ok=True)
            csv_path = "data/uploads/live_captured_internet.csv"
            df_captured.to_csv(csv_path, index=False)
            st.success(f"✅ Đã tạo thành công file CSV thực tế tại: `{csv_path}` ({len(df_captured)} gói tin)")
            
            X_live = df_captured[features].fillna(0)
            X_live_scaled = scaler.transform(X_live)
            preds = clf.predict(X_live_scaled)
            probs = clf.predict_proba(X_live_scaled)[:, 1]
            
            df_captured['Prediction'] = ['ATTACK' if p == 1 else 'BENIGN' for p in preds]
            df_captured['Attack_Probability'] = probs
            
            attack_count = 0
            for idx, row in df_captured[df_captured['Prediction'] == 'ATTACK'].iterrows():
                save_log(int(row['Destination Port']), float(row['Flow Duration']), 'ATTACK', float(row['Attack_Probability']), source_type="LIVE_INTERNET")
                attack_count += 1
                
            m1, m2, m3 = st.columns(3)
            m1.metric("Tổng gói tin bắt được", len(df_captured))
            m2.metric("An toàn (BENIGN)", len(df_captured) - attack_count)
            m3.metric("Phát hiện Tấn công (ATTACK)", attack_count, delta_color="inverse")
            
            st.write("### 📋 Bảng Phân Tích Chi Tiết IP & Kết Quả Từ Mô Hình ML")
            st.dataframe(df_captured[['Source IP', 'Destination IP', 'Destination Port', 'Prediction', 'Attack_Probability']])
        else:
            st.warning("Chưa bắt được gói tin nào! Hãy bấm 'Bắt đầu' và lướt web vài giây rồi thử lại.")

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
    st.subheader("📊 Kết quả Đánh giá Mô hình Random Forest")
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
        st.write("**Ma trận nhầm lẫn (Confusion Matrix)**")
        if os.path.exists(config.CONFUSION_MATRIX_PATH):
            st.image(config.CONFUSION_MATRIX_PATH)
    with c2:
        st.write("**Độ quan trọng đặc trưng (Feature Importance)**")
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
                
            X = df[features].fillna(0)
            X_scaled = scaler.transform(X)
            preds = clf.predict(X_scaled)
            probs = clf.predict_proba(X_scaled)[:, 1]
            
            df['Prediction'] = ['ATTACK' if p == 1 else 'BENIGN' for p in preds]
            df['Attack_Probability'] = probs
            
            for idx, row in df[df['Prediction'] == 'ATTACK'].iterrows():
                save_log(int(row['Destination Port']), float(row['Flow Duration']), 'ATTACK', float(row['Attack_Probability']), source_type="FILE_UPLOAD")
            
            total = len(df)
            attacks = (df['Prediction'] == 'ATTACK').sum()
            normals = total - attacks
            
            k1, k2, k3 = st.columns(3)
            k1.metric("Tổng kết nối", total)
            k2.metric("An toàn (BENIGN)", normals)
            k3.metric("Phát hiện Tấn công (ATTACK)", attacks, delta_color="inverse")
            
            st.dataframe(df[['Destination Port', 'Flow Duration', 'Prediction', 'Attack_Probability']])

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
        