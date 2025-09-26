import pandas as pd

def clean_logs(df):

    df2 = df.copy(deep=True)

    # Fill in NaNs
    df2 = df2.fillna("Unknown")

    # Parse timestamp
    if "date" in df2.columns:
        df2.loc[:, "timestamp"] = pd.to_datetime(df2["date"], errors="coerce")

    # Normalize IPs
    if "src_ip" in df2.columns:
        df2.loc[:, "src_ip"] = df2["src_ip"].astype(str).str.strip()
    if "dst_ip" in df2.columns:
        df2.loc[:, "dst_ip"] = df2["dst_ip"].astype(str).str.strip()

    return df2
