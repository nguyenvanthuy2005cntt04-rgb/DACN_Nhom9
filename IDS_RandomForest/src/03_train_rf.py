import pandas as pd
import sys
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config
from src.utils import save_artifact

def train_and_select_best():
    print("--- 03. HUẤN LUYỆN, SO SÁNH VÀ CHỌN MÔ HÌNH TỐT NHẤT ---")
    df = pd.read_parquet(config.PROCESSED_DATA_PATH)
    
    X = df[config.FEATURE_COLUMNS]
    y = df['Label']
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Khai báo các mô hình cần so sánh
    models = {
        "Random Forest": RandomForestClassifier(**config.RF_PARAMS),
        "Decision Tree": DecisionTreeClassifier(random_state=42),
        "K-Nearest Neighbors": KNeighborsClassifier(n_neighbors=5),
        "Logistic Regression": LogisticRegression(max_iter=1000)
    }
    
    best_model_name = ""
    best_model = None
    best_f1 = 0.0
    
    print(f"\nĐang tiến hành huấn luyện và đánh giá {len(models)} thuật toán...")
    print(f"{'Thuật toán':<22} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10}")
    print("-" * 75)

    for name, model in models.items():
        # Huấn luyện
        model.fit(X_train, y_train)
        
        # Dự đoán
        y_pred = model.predict(X_test)
        
        # Tính toán các chỉ số
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        
        print(f"{name:<22} | {acc*100:>8.2f}% | {prec*100:>8.2f}% | {rec*100:>8.2f}% | {f1*100:>8.2f}%")
        
        # Cập nhật mô hình tốt nhất (dựa trên F1-Score vì nó cân bằng tốt nhất cho bài toán IDS)
        if f1 > best_f1:
            best_f1 = f1
            best_model = model
            best_model_name = name

    print("-" * 75)
    print(f"🏆 THUẬT TOÁN TỐT NHẤT: {best_model_name} (F1-Score: {best_f1*100:.2f}%)")
    
    # Lưu duy nhất mô hình tốt nhất để app.py sử dụng
    save_artifact(best_model, config.MODEL_PATH)
    print(f"✅ Đã lưu mô hình {best_model_name} tại: {config.MODEL_PATH}")

if __name__ == "__main__":
    train_and_select_best()