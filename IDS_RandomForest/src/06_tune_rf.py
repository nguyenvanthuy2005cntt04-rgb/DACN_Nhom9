import pandas as pd
import sys
import os
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.ensemble import RandomForestClassifier

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config
from src.utils import save_artifact

def tune():
    print("--- 06. TỐI ƯU SIÊU THAM SỐ (GRID SEARCH) ---")
    df = pd.read_parquet(config.PROCESSED_DATA_PATH)
    X = df[config.FEATURE_COLUMNS]
    y = df['Label']
    
    X_train, _, y_train, _ = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    param_grid = {
        'n_estimators': [50, 100],
        'max_depth': [10, 15, 20],
        'min_samples_split': [2, 5]
    }
    
    rf = RandomForestClassifier(random_state=42)
    grid_search = GridSearchCV(estimator=rf, param_grid=param_grid, cv=3, scoring='f1', n_jobs=-1)
    grid_search.fit(X_train, y_train)
    
    print("Bộ tham số tốt nhất:", grid_search.best_params_)
    best_model = grid_search.best_estimator_
    save_artifact(best_model, config.MODEL_PATH)
    print(f"✅ Đã cập nhật mô hình tối ưu vào: {config.MODEL_PATH}")

if __name__ == "__main__":
    tune()