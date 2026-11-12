import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "ids_logs.db")

def init_db():
    """Khởi tạo bảng lưu trữ lịch sử phát hiện xâm nhập."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            dst_port INTEGER,
            flow_duration REAL,
            prediction TEXT,
            attack_prob REAL,
            source_type TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_log(dst_port, flow_duration, prediction, attack_prob, source_type="LIVE"):
    """Lưu 1 dòng log kết quả vào Database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO attack_logs (dst_port, flow_duration, prediction, attack_prob, source_type)
        VALUES (?, ?, ?, ?, ?)
    ''', (dst_port, flow_duration, prediction, attack_prob, source_type))
    conn.commit()
    conn.close()

def get_recent_logs(limit=100):
    """Lấy danh sách các log gần nhất để hiển thị lên Web."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT timestamp, dst_port, flow_duration, prediction, attack_prob, source_type FROM attack_logs ORDER BY id DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows