import pandas as pd
import os
def load_logs(file_name="siem_ueba_log_small.csv"):

    base_dir =os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.join(base_dir,"..")
    file_path = os.path.join(project_root, "data", file_name)

    #Print which file is being loaded
    print("Loading logs from: ",file_path)

    df = pd.read_csv(file_path, encoding ="utf-8")
    
    print("Total rows before:", len(df))
    print("Duplicate rows:", df.duplicated().sum())
    print("Rows:", len(df))
    print(df.head())
    return df



if __name__ == "__main__":
    load_logs()
