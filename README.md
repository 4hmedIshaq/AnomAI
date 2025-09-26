Mini-SOC Log Analysis Project

This project processes raw logs, cleans them, and stores them in a DuckDB database for analysis. Security detection rules are written in security_rules.py and can be executed via a Python script or a Jupyter notebook.



- Workflow

Load & Clean Logs

Run load_data.py and preprocess.py together via ddb_utils.py.

This will save logs into data/logs.duckdb.

    cd src
    python ddb_utils.py


Expected output:

    Loading logs from: ../data/siem_ueba_log_git.csv
    Rows: XXXXX
    Logs saved into DuckDb successfull


Security Rules

All rules live in security_rules.py.

Each rule is a function that:

Accepts a DuckDB connection.

Runs a SQL query against the logs table.

Returns the result as a pandas DataFrame.

Example rule (security_rules.py):

    def failed_logins(connection):
        query = """
        SELECT entity_id, COUNT(*) AS attempts
        FROM logs
        WHERE Content LIKE '%failed%'
        GROUP BY entity_id
        HAVING attempts > 5
        """
        return connection.execute(query).fetchdf()




How to Run Rules
Option 1: Run via Script (test.py)

Inside test.py you can import and run rules:

import duckdb
from security_rules import failed_logins

    if __name__ == "__main__":
        connection = duckdb.connect("../data/logs.duckdb")

        print("Failed login attempts:")
        print(failed_logins(connection))

Run it from terminal:

    cd src
    python test.py
