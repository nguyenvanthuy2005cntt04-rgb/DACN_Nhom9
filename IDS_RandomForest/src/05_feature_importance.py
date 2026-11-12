import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config
from src.utils import load_artifact

def plot_importance():
    print("--- 05. TRÍCH XUẤT FEATURE IMPORTANCE ---")
    clf = load_artifact(config.MODEL_PATH)
    
    importance = clf.feature_importances_
    df_imp = pd.DataFrame({'Feature': config.FEATURE_COLUMNS, 'Importance': importance})
    df_imp = df_imp.sort_values(by='Importance', ascending=False)
    
    plt.figure(figsize=(10, 6))
    sns.barplot(x='Importance', y='Feature', data=df_imp, palette='viridis')
    plt.title('Feature Importance - Random Forest IDS')
    plt.tight_layout()
    
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    plt.savefig(config.FEATURE_IMPORTANCE_PATH)
    plt.close()
    print(f"✅ Đã lưu đồ thị Feature Importance tại: {config.FEATURE_IMPORTANCE_PATH}")

if __name__ == "__main__":
    plot_importance()