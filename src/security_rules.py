import duckdb

# connect to DuckDB file
con = duckdb.connect("../data/logs.duckdb")

# Example rule: Failed logins (Event ID 4625 for Windows)
rule_failed_logins = """
SELECT *
FROM logs
WHERE Content LIKE '%4625%'
OR Content LIKE '%Failed password%'
"""
results = con.execute(rule_failed_logins).fetchdf()

print("Failed login attempts:")
print(results.head())   # show first 10 rows

# Count total failed logins
rule_failed_count = """
SELECT COUNT(*) AS failed_attempts
FROM logs
WHERE Content LIKE '%4625%'
"""
count_result = con.execute(rule_failed_count).fetchdf()
print("Total failed login attempts:", count_result.iloc[0,0])


# Count failed logins per source IP

rule_failed_by_ip = """
SELECT src_ip, COUNT(*) AS attempts
FROM logs
WHERE Content LIKE '%4625%'
GROUP BY src_ip
ORDER BY attempts DESC
"""
ip_result = con.execute(rule_failed_by_ip).fetchdf()
print("Failed login attempts by source IP:")
print(ip_result.head(10))

row_count = con.execute("SELECT COUNT(*) FROM LOGS").fetchone()[0]
print(f"Total rows in logs table: {row_count}")



def failed_logins_by_ip(connection):
    query = """
    SELECT src_ip, COUNT(*) AS attempts
    FROM logs
    WHERE Content LIKE '%4625%' OR Content LIKE '%Failed password%'
    GROUP BY src_ip
    ORDER BY attempts DESC
    """
    return connection.execute(query).fetchdf()



def total_failed_logins(connection):
    query = """
    SELECT COUNT(*) AS total_failed
    FROM logs
    WHERE Content LIKE '%4625%' OR Content LIKE '%Failed password%'
    """
    return connection.execute(query).fetchdf()