import pandas as pd
import sys
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config
from src.utils import save_artifact

def train():
    print("--- 03. HUẤN LUYỆN MÔ HÌNH RANDOM FOREST ---")
    df = pd.read_parquet(config.PROCESSED_DATA_PATH)
    
    X = df[config.FEATURE_COLUMNS]
    y = df['Label']
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    clf = RandomForestClassifier(**config.RF_PARAMS)
    clf.fit(X_train, y_train)
    
    save_artifact(clf, config.MODEL_PATH)
    print(f"✅ Đã huấn luyện xong và lưu mô hình tại: {config.MODEL_PATH}")

if __name__ == "__main__":
    train()