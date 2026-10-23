import pandas as pd
import sys
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config
from src.utils import save_artifact

def train_and_compare():
    print("--- 03. HUẤN LUYỆN VÀ SO SÁNH CÁC MÔ HÌNH MACHINE LEARNING ---")
    df = pd.read_parquet(config.PROCESSED_DATA_PATH)
    
    X = df[config.FEATURE_COLUMNS]
    y = df['Label']
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    models = {
        "Random Forest": RandomForestClassifier(**config.RF_PARAMS),
        "Decision Tree": DecisionTreeClassifier(random_state=42),
        "K-Nearest Neighbors": KNeighborsClassifier(n_neighbors=5),
        "Logistic Regression": LogisticRegression(max_iter=1000)
    }
    
    print("\nTiến hành huấn luyện, đánh giá và xuất file...")
    model_dir = os.path.dirname(config.MODEL_PATH)
    os.makedirs(model_dir, exist_ok=True)

    for name, model in models.items():
        print(f"Đang huấn luyện {name}...")
        model.fit(X_train, y_train)
        
        y_pred = model.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        print(f"-> Độ chính xác của {name}: {acc * 100:.2f}%")
        
        file_name = f"{name.lower().replace(' ', '_').replace('-', '_')}_model.pkl"
        save_path = os.path.join(model_dir, file_name)
        
        save_artifact(model, save_path)
        print(f"✅ Đã lưu {name} tại: {save_path}\n")

if __name__ == "__main__":
    train_and_compare()