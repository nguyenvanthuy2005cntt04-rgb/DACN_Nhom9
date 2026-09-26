import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Đường dẫn dữ liệu
RAW_DATA_PATH = os.path.join(BASE_DIR, "data", "raw", "CIC-IDS2017.csv")
PROCESSED_DATA_PATH = os.path.join(BASE_DIR, "data", "processed", "cleaned_data.parquet")

# Đường dẫn lưu Model & Preprocessor
MODEL_PATH = os.path.join(BASE_DIR, "models", "random_forest.joblib")
PREPROCESSOR_PATH = os.path.join(BASE_DIR, "models", "preprocessor.joblib")
FEATURE_COLUMNS_PATH = os.path.join(BASE_DIR, "models", "feature_columns.json")

# Đường dẫn Kết quả & Đánh giá
RESULTS_DIR = os.path.join(BASE_DIR, "results")
CONFUSION_MATRIX_PATH = os.path.join(RESULTS_DIR, "confusion_matrix.png")
FEATURE_IMPORTANCE_PATH = os.path.join(RESULTS_DIR, "feature_importance.png")
METRICS_PATH = os.path.join(RESULTS_DIR, "metrics.json")
PREDICTIONS_PATH = os.path.join(RESULTS_DIR, "predictions.csv")

# Danh sách 10 đặc trưng chính (Cốt lõi để tương thích giữa CIC-IDS2017 và Scapy Live Flow)
FEATURE_COLUMNS = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 
    'Total Backward Packets', 'Total Length of Fwd Packets', 
    'Total Length of Bwd Packets', 'Fwd Packet Length Max', 
    'Fwd Packet Length Min', 'Bwd Packet Length Max', 'Bwd Packet Length Min'
]

# Tham số Random Forest mặc định
RF_PARAMS = {
    'n_estimators': 100,
    'max_depth': 15,
    'random_state': 42,
    'n_jobs': -1
}