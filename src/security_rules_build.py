# can also use .security_rules import * as a relative import meaning saying that its from the same package so take it from this package i am in. 
from src.security_rules import *  
import duckdb
import pandas as pd
from typing import Dict, Tuple


# connect to DuckDB file
connection = duckdb.connect(db_path)

# Run all the rules and store it in a dictionary. 
def combined_rules(connection) -> Dict[str, pd.DataFrame]:
    """Run all detection rules and return a dict of DataFrames."""
    return {
        "failed_logins": failed_logins(connection),
        "failed_by_ip": failed_logins_by_ip(connection),
        "brute_force": brute_force_candidates(connection),
        "priv_esc": privilege_escalations(connection),
        "account_lockout": account_lockouts(connection),
        "log_cleared": log_cleared(connection),
        "susp_linux": suspicious_linux_process(connection),
        "susp_win": suspicious_windows_process(connection),
        "rdp_logins": rdp_logins(connection),
        "ssh_root_logins": ssh_root_logins(connection),
        "failed_count_windows": failed_count_windows(connection),  
    }

#print(run_all_rules(connection))
results = combined_rules(connection)
print(results)


'''def build_llm_context(results, examples=3):
    """
    Create a simple text summary for all detection results.
    Includes rule names, total records, OS (Windows/Linux) breakdown,
    and a few sample log entries.
    """
    lines = []
    lines.append("=== Security Detection Summary ===\n")

    for name, df in results.items():
        # Skip invalid or empty data
        if not isinstance(df, pd.DataFrame) or df.empty:
            lines.append("\n🔹 " + name.upper() + ": No records detected.")
            continue

        # Check if the data has OS info
        os_breakdown = ""
        if "AGENT_NAME" in df.columns:
            win_count = len(df[df["AGENT_NAME"] == "WINDOWS_AGENT"])
            lin_count = len(df[df["AGENT_NAME"] == "UBUNTU_AGENT"])
            os_breakdown = " (Windows: " + str(win_count) + ", Ubuntu: " + str(lin_count) + ")"

        # Add rule name and total
        lines.append("\n🔹 Rule: " + name.upper() + os_breakdown)
        lines.append("Total records: " + str(len(df)))

        # Add sample log entries
        sample_text = df.head(examples).to_string(index=False)
        lines.append("Sample entries:\n" + sample_text)

    # Footer info
    lines.append("\nSource: SIEM detections from Windows and Ubuntu agents.")
    lines.append("Each rule represents a specific type of security event.\n")

    return "\n".join(lines)

print(build_llm_context(results, examples=3))'''

def build_llm_context(results, examples=2):
    """
    Generate a short, readable context summary for the LLM.
    Includes each rule name, OS type counts, total events, and brief samples.
    """
    lines = ["=== Security Detection Summary ==="]

    for name, df in results.items():
        if not isinstance(df, pd.DataFrame) or df.empty:
            lines.append(f"\n * {name.upper()}: No records found.")
            continue

        # OS summary (if applicable)
        if "AGENT_NAME" in df.columns:
            win = (df["AGENT_NAME"] == "WINDOWS_AGENT").sum()
            lin = (df["AGENT_NAME"] == "UBUNTU_AGENT").sum()
            os_info = f" (Windows: {win}, Ubuntu: {lin})"
        else:
            os_info = ""

        lines.append(f"\n * {name.upper()}{os_info}")
        lines.append(f"Total: {len(df)} events")

        # Short preview
        preview = df.head(examples).astype(str)
        if "Content" in preview.columns:
            preview["Content"] = preview["Content"].str[:100] + "..."
        lines.append(preview.to_string(index=False))

    lines.append("\nSource: Aggregated detections from Windows and Ubuntu systems.")
    return "\n".join(lines)



import pandas as pd
from src.security_rules import (
    failed_logins,
    failed_logins_by_ip,
    brute_force_candidates,
    privilege_escalations,
    account_lockouts,
    log_cleared,
    suspicious_linux_process,
    suspicious_windows_process,
    rdp_logins,
    ssh_root_logins,
    failed_count_windows
)

def run_all_detections(connection):
    """
    Run all detection queries on the provided DuckDB connection
    and return them as individual variables (not a dictionary).
    """
    failed_logins_df           = failed_logins(connection)
    failed_logins_ip_df        = failed_logins_by_ip(connection)
    brute_force_df         = brute_force_candidates(connection)
    priv_esc_df                = privilege_escalations(connection)
    acc_lockout_df             = account_lockouts(connection)
    log_cleared_df           = log_cleared(connection)
    susp_linux_df          = suspicious_linux_process(connection)
    susp_win_df            = suspicious_windows_process(connection)
    rdp_logins_df                 = rdp_logins(connection)
    ssh_root_logins_df            = ssh_root_logins(connection)
    failed_login_win_df        = failed_count_windows(connection)

    return(
    failed_logins_df, 
    failed_logins_ip_df,
    brute_force_df,  
    priv_esc_df,    
    acc_lockout_df,     
    log_cleared_df,    
    susp_linux_df,    
    susp_win_df,     
    rdp_logins_df,      
    ssh_root_logins_df,
    failed_login_win_df,
    )
    