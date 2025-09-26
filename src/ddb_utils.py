import duckdb
import os
from load_data import load_logs
from preprocess import clean_logs


# Build full path for database file
db_path = os.path.join(os.path.dirname(__file__), "..", "data", "logs.duckdb")

# Making sure that folder exists
os.makedirs(os.path.dirname(db_path), exist_ok=True)

connection = duckdb.connect("../data/logs.duckdb")

df= load_logs()
df_clean= clean_logs(df)

#register dataframe
connection.register("logs_df", df_clean)
#save data as table in duckdb
connection.execute("CREATE OR REPLACE TABLE logs AS SELECT * FROM logs_df")

print("Logs saved into DuckDb successfully")