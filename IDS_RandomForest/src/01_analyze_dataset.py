import pandas as pd
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config
from src.utils import clean_column_names

def analyze():
    print(f"--- 01. PHÂN TÍCH TẬP DỮ LIỆU: {config.RAW_DATA_PATH} ---")
    if not os.path.exists(config.RAW_DATA_PATH):
        print(f"Lỗi: File {config.RAW_DATA_PATH} không tồn tại!")
        return

    df = pd.read_csv(config.RAW_DATA_PATH)
    print(f"Kích thước ban đầu: {df.shape[0]} dòng, {df.shape[1]} cột")
    
    df = clean_column_names(df)
    print(f"Kích thước sau khi làm sạch ban đầu: {df.shape[0]} dòng")
    
    if 'Label' in df.columns:
        print("\nPhân bố các lớp nhãn (Label):")
        print(df['Label'].value_counts())
    else:
        print("Cảnh báo: Không tìm thấy cột 'Label'")

if __name__ == "__main__":
    analyze()