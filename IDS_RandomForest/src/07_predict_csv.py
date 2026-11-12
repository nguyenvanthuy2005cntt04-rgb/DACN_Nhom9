import pandas as pd
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config
from src.utils import load_artifact, clean_column_names

def predict_csv(input_csv_path: str):
    print(f"--- 07. DỰ ĐOÁN DỮ LIỆU TỪ FILE CSV: {input_csv_path} ---")
    clf = load_artifact(config.MODEL_PATH)
    scaler = load_artifact(config.PREPROCESSOR_PATH)
    
    df = pd.read_csv(input_csv_path)
    df_clean = clean_column_names(df)
    
    X = df_clean[config.FEATURE_COLUMNS].fillna(0)
    X_scaled = scaler.transform(X)
    
    preds = clf.predict(X_scaled)
    probs = clf.predict_proba(X_scaled)[:, 1]
    
    df_clean['Prediction'] = ['ATTACK' if p == 1 else 'NORMAL' for p in preds]
    df_clean['Attack_Probability'] = probs
    
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    df_clean.to_csv(config.PREDICTIONS_PATH, index=False)
    print(f"✅ Đã lưu kết quả dự đoán tại: {config.PREDICTIONS_PATH}")
    return df_clean

if __name__ == "__main__":
    if len(sys.argv) > 1:
        predict_csv(sys.argv[1])
    else:
        print("Sử dụng: python src/07_predict_csv.py <đường_dẫn_file_csv>")