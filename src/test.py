import duckdb
from security_rules import failed_logins_by_ip, total_failed_logins

con = duckdb.connect("../data/logs.duckdb")

print(total_failed_logins(con))
print(failed_logins_by_ip(con).head(10))