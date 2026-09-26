import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import sys
import os
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config
from src.utils import load_artifact, save_json

def evaluate():
    print("--- 04. ĐÁNH GIÁ MÔ HÌNH ---")
    df = pd.read_parquet(config.PROCESSED_DATA_PATH)
    clf = load_artifact(config.MODEL_PATH)
    
    X = df[config.FEATURE_COLUMNS]
    y = df['Label']
    
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    y_pred = clf.predict(X_test)
    
    # Tính các chỉ số
    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall": recall_score(y_test, y_pred),
        "f1_score": f1_score(y_test, y_pred)
    }
    
    save_json(metrics, config.METRICS_PATH)
    print("Chỉ số đánh giá:", metrics)
    
    # Vẽ Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['NORMAL', 'ATTACK'], yticklabels=['NORMAL', 'ATTACK'])
    plt.title('Confusion Matrix')
    plt.ylabel('Thực tế')
    plt.xlabel('Dự đoán')
    plt.tight_layout()
    
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    plt.savefig(config.CONFUSION_MATRIX_PATH)
    plt.close()
    print(f"✅ Đã lưu Confusion Matrix tại: {config.CONFUSION_MATRIX_PATH}")

if __name__ == "__main__":
    evaluate()