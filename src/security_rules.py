import os
import duckdb
import pandas as pd
from typing import Dict, Tuple

base_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(base_dir, "../data/logs.duckdb")


# Normalize path (handles .. cleanly)
db_path = os.path.normpath(db_path)

# Connect to the databse
connection = duckdb.connect(db_path)
print(f" Connected to database: {db_path}")

# Failed logins
def failed_logins(connection):
    query = """
    SELECT *
    FROM logs 
    WHERE Content LIKE '%4625%'          --Windows failed login
    OR Content LIKE '%Failed password%'  --Linux Failed authentication
    """
    return connection.execute(query).fetchdf()

#failed_logins_results = failed_logins(connection)
#print("Failed login attempts:")
#print(failed_logins_results)   # show first 10 rows


# Count total failed logins on windoes with %4625$
def failed_count_windows(connection):
    query = """
    SELECT COUNT(*) AS failed_attempts
    FROM logs
    WHERE Content LIKE '%4625%'
    """
    return connection.execute(query).fetchdf()

#failed_login_count = failed_count_windows(connection)
#print("Total failed login attempts:", failed_login_count.iloc[0, 0])


# Count failed logins per source IP
def failed_logins_by_ip(connection):
    query = """
    SELECT src_ip, COUNT(*) AS attempts
    FROM logs
    WHERE Content LIKE '%4625%'
    GROUP BY src_ip
    ORDER BY attempts DESC
    """
    return connection.execute(query).fetchdf()

#failed_by_ip_results = failed_logins_by_ip(connection)
#print("Failed login attempts by source IP:")
#print(failed_by_ip_results.head(10))


# Count total rows in logs table
#row_count = connection.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
#print("Total rows in logs table:", row_count)


# Brute force detection (many failed logins before a success)
def brute_force_candidates(connection):
    query = """
    SELECT f.src_ip, f.entity_id, COUNT(*) AS failed_attempts
    FROM logs f
    JOIN logs s
      ON f.src_ip = s.src_ip
     AND f.entity_id = s.entity_id
    WHERE (f.Content LIKE '%4625%' OR f.Content LIKE '%Failed password%')
      AND (s.Content LIKE '%4624%' OR s.Content LIKE '%Accepted password%')
    GROUP BY f.src_ip, f.entity_id
    HAVING COUNT(*) > 3
    ORDER BY failed_attempts DESC
    """
    return connection.execute(query).fetchdf()

#brute_force_results = brute_force_candidates(connection)
#print("Brute force candidates:")
#print(brute_force_results.head(10))


# Privilege escalation
def privilege_escalations(connection):
    query = """
    SELECT *
    FROM logs
    WHERE (AGENT_NAME = 'WINDOWS_AGENT' AND Content LIKE '%4672%')
       OR (AGENT_NAME = 'UBUNTU_AGENT' AND Content LIKE '%sudo%')
       OR (AGENT_NAME = 'UBUNTU_AGENT' AND Content LIKE '%pam_unix(cron:session): session opened for user root%')
    """
    return connection.execute(query).fetchdf()

#priv_escalations_results = privilege_escalations(connection)
#print("Privilege escalation events:")
#print(priv_escalations_results.head(10))


# Account lockouts (for Windows)
def account_lockouts(connection):
    query = """
    SELECT *
    FROM logs
    WHERE AGENT_NAME = 'WINDOWS_AGENT'
      AND Content LIKE '%4740%'
    """
    return connection.execute(query).fetchdf()

#lockout_results = account_lockouts(connection)
#print("Account lockout events:")
#print(lockout_results.head(10))


# Log clearing/tampering
def log_cleared(connection):
    query = """
    SELECT *
    FROM logs
    WHERE (AGENT_NAME = 'WINDOWS_AGENT' AND Content LIKE '%1102%')
       OR (AGENT_NAME = 'UBUNTU_AGENT' AND Content LIKE '%log cleared%')
    """
    return connection.execute(query).fetchdf()

#log_clears_results = log_cleared(connection)
#print("Log clearing events:")
#print(log_clears_results.head(10))


# Suspicious new processes (Linux)
def suspicious_linux_process(connection):
    query = """
    SELECT *
    FROM logs
    WHERE AGENT_NAME = 'UBUNTU_AGENT'
      AND Content LIKE '%exec%'
      AND (Content LIKE '%python%' OR Content LIKE '%nc%' OR Content LIKE '%bash%')
    """
    return connection.execute(query).fetchdf()

#suspicious_linux_results = suspicious_linux_process(connection)
#print("Suspicious new processes (Linux):")
#print(suspicious_linux_results.head(10))


# Suspicious new processes (Windows)
def suspicious_windows_process(connection):
    query = """
    SELECT *
    FROM logs
    WHERE AGENT_NAME = 'WINDOWS_AGENT'
      AND Content LIKE '%4688%'
      AND (Content LIKE '%powershell%' OR Content LIKE '%cmd.exe%' OR Content LIKE '%wscript.exe%' OR Content LIKE '%cscript.exe%')
    """
    return connection.execute(query).fetchdf()

#suspicious_win_results = suspicious_windows_process(connection)
#print("Suspicious new processes (Windows):")
#print(suspicious_win_results.head(10))


# Windows remote login events (RDP)
def rdp_logins(connection):
    query = """
    SELECT *
    FROM logs
    WHERE AGENT_NAME = 'WINDOWS_AGENT'
      AND Content LIKE '%4624%'
      AND Content LIKE '%Logon Type: 10%'
    """
    return connection.execute(query).fetchdf()

#rdp_logins_results = rdp_logins(connection)
#print("RDP login events:")
#print(rdp_logins_results.head(10))


# Linux SSH Root logins
def ssh_root_logins(connection):
    query = """
    SELECT *
    FROM logs
    WHERE AGENT_NAME = 'UBUNTU_AGENT'
      AND Content LIKE '%sshd%'
      AND Content LIKE '%root%'
    """
    return connection.execute(query).fetchdf()

#ssh_root_logins_results = ssh_root_logins(connection)
#print("Linux SSH Root login events:")
#print(ssh_root_logins_results.head(10))


