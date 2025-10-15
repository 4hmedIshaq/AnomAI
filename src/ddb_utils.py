import duckdb
import os
from load_data import load_logs
from preprocess import clean_logs


# Build full path for database file
db_path = os.path.join(os.path.dirname(__file__), "..", "data", "logs.duckdb")

# Making sure that folder exists
os.makedirs(os.path.dirname(db_path), exist_ok=True)

def save_logs_to_duckdb():
    df = load_logs()
    df_clean = clean_logs(df)

    # Open and close connection inside the function (prevents locking)
    with duckdb.connect(db_path) as con:
        con.register("logs_df", df_clean)
        con.execute("CREATE OR REPLACE TABLE logs AS SELECT * FROM logs_df")

    print("✅ Logs saved into DuckDB successfully")

if __name__ == "__main__":
    save_logs_to_duckdb()