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


#Brute force detection (many failed logins before a success)
rule_brute_force = """
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
brute_force = con.execute(rule_brute_force).fetchdf()
print("Brute force candidates:")
print(brute_force.head(10))

#Privilege escalation
rule_privilege_escalation = """
SELECT *
FROM logs
WHERE (AGENT_NAME = 'WINDOWS_AGENT' AND Content LIKE '%4672%')
   OR (AGENT_NAME = 'UBUNTU_AGENT' AND Content LIKE '%sudo%')
   OR (AGENT_NAME = 'UBUNTU_AGENT' AND Content LIKE '%pam_unix(cron:session): session opened for user root%')
"""
priv_escalations = con.execute(rule_privilege_escalation).fetchdf()
print("Privilege escalation events:")
print(priv_escalations.head(10))

#Account lockouts (for Windows)
rule_account_lockouts = """
SELECT *
FROM logs
WHERE AGENT_NAME = 'WINDOWS_AGENT'
  AND Content LIKE '%4740%'
"""
lockouts = con.execute(rule_account_lockouts).fetchdf()
print("Account lockout events:")
print(lockouts.head(10))

#Log clearing/tampering
rule_log_cleared = """
SELECT *
FROM logs
WHERE (AGENT_NAME = 'WINDOWS_AGENT' AND Content LIKE '%1102%')
   OR (AGENT_NAME = 'UBUNTU_AGENT' AND Content LIKE '%log cleared%')
"""
log_clears = con.execute(rule_log_cleared).fetchdf()
print("Log clearing events:")
print(log_clears.head(10))

#Suspicious new processes (Linux)
rule_suspicious_Linux_process = """
SELECT *
FROM logs
WHERE AGENT_NAME = 'UBUNTU_AGENT'
  AND Content LIKE '%exec%'
  AND (Content LIKE '%python%' OR Content LIKE '%nc%' OR Content LIKE '%bash%')
"""
suspicious_processes_linux = con.execute(rule_suspicious_Linux_process).fetchdf()
print("Suspicious new processes (Linux):")
print(suspicious_processes_linux.head(10))

#Suspicious new processes (Windows)
rule_suspicious_Windows_process = """
SELECT *
FROM logs
WHERE AGENT_NAME = 'WINDOWS_AGENT'
  AND Content LIKE '%4688%'
  AND (Content LIKE '%powershell%' OR Content LIKE '%cmd.exe%' OR Content LIKE '%wscript.exe%' OR Content LIKE '%cscript.exe%')
"""
suspicious_processes_win = con.execute(rule_suspicious_Windows_process).fetchdf()
print("Suspicious new processes (Windows):")
print(suspicious_processes_win.head(10))

#Windows remote login events (RDP)
rule_rdp_logins = """
SELECT *
FROM logs
WHERE AGENT_NAME = 'WINDOWS_AGENT'
  AND Content LIKE '%4624%'
  AND Content LIKE '%Logon Type: 10%'
"""
rdp_logins = con.execute(rule_rdp_logins).fetchdf()
print("RDP login events:")
print(rdp_logins.head(10))

#Linux SSH Root logins
rule_ssh_root_logins = """
SELECT *
FROM logs
WHERE AGENT_NAME = 'UBUNTU_AGENT'
  AND Content LIKE '%sshd%'
  AND Content LIKE '%root%'
"""
ssh_root_logins = con.execute(rule_ssh_root_logins).fetchdf()
print("Linux SSH Root login events:")
print(ssh_root_logins.head(10))
