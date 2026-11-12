import pandas as pd
import os
import sys
from sklearn.preprocessing import StandardScaler

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config
from src.utils import clean_column_names, save_artifact, save_json

def preprocess():
    print("--- 02. TIỀN XỬ LÝ DỮ LIỆU ---")
    df = pd.read_csv(config.RAW_DATA_PATH)
    df = clean_column_names(df)
    
    # Mã hóa nhãn nhị phân: BENIGN = 0, Tất cả Tấn công = 1
    df['Label'] = df['Label'].apply(lambda x: 0 if str(x).strip() == 'BENIGN' else 1)
    
    # Chọn lọc cột
    X = df[config.FEATURE_COLUMNS]
    y = df['Label']
    
    # Fit Scaler
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    df_processed = pd.DataFrame(X_scaled, columns=config.FEATURE_COLUMNS)
    df_processed['Label'] = y.values
    
    # Lưu kết quả
    os.makedirs(os.path.dirname(config.PROCESSED_DATA_PATH), exist_ok=True)
    df_processed.to_parquet(config.PROCESSED_DATA_PATH, index=False)
    
    save_artifact(scaler, config.PREPROCESSOR_PATH)
    save_json(config.FEATURE_COLUMNS, config.FEATURE_COLUMNS_PATH)
    
    print(f" Đã lưu dữ liệu xử lý tại: {config.PROCESSED_DATA_PATH}")
    print(f" Đã lưu Preprocessor tại: {config.PREPROCESSOR_PATH}")

if __name__ == "__main__":
    preprocess()