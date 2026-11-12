from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import pandas as pd
import joblib
import sys
import os

sys.path.append(os.path.abspath(os.path.dirname(__file__)))
import config
from src.utils import load_artifact, load_json
from database.db_manager import init_db, save_log, get_recent_logs

app = FastAPI(title="IDS Random Forest Backend API", version="1.0")

# Khởi tạo DB khi ứng dụng chạy
init_db()

# Load Model Random Forest
clf = load_artifact(config.MODEL_PATH)
scaler = load_artifact(config.PREPROCESSOR_PATH)
features = load_json(config.FEATURE_COLUMNS_PATH)

class FlowData(BaseModel):
    dst_port: int
    flow_duration: float
    total_fwd_pkts: int
    total_bwd_pkts: int
    total_fwd_len: float
    total_bwd_len: float
    fwd_len_max: float
    fwd_len_min: float
    bwd_len_max: float
    bwd_len_min: float

@app.get("/")
def home():
    return {"message": "IDS Random Forest API Server đang chạy thành công!"}

@app.post("/api/predict")
def predict_flow(data: FlowData):
    """API dự đoán 1 luồng kết nối mạng theo mô hình Random Forest."""
    raw_data = [[
        data.dst_port, data.flow_duration, data.total_fwd_pkts,
        data.total_bwd_pkts, data.total_fwd_len, data.total_bwd_len,
        data.fwd_len_max, data.fwd_len_min, data.bwd_len_max, data.bwd_len_min
    ]]
    
    df_input = pd.DataFrame(raw_data, columns=features)
    X_scaled = scaler.transform(df_input)
    
    pred = clf.predict(X_scaled)[0]
    prob = clf.predict_proba(X_scaled)[0][1]
    
    label = "ATTACK" if pred == 1 else "BENIGN"
    
    # Lưu kết quả vào CSDL
    save_log(data.dst_port, data.flow_duration, label, float(prob), source_type="API_DETECT")
    
    return {
        "prediction": label,
        "attack_probability": round(float(prob), 4),
        "status": "ALERT" if pred == 1 else "NORMAL"
    }

@app.get("/api/logs")
def fetch_logs():
    """API cho phép Web Frontend lấy nhật ký lưu trữ."""
    logs = get_recent_logs()
    return [{"timestamp": r[0], "dst_port": r[1], "duration": r[2], "result": r[3], "probability": r[4], "source": r[5]} for r in logs]