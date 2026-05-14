import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

def detect_insider_threats(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # 1. Feature Engineering
    df['hour'] = df['timestamp'].dt.hour
    df['is_after_hours'] = df['hour'].apply(lambda x: 1 if x < 6 or x > 21 else 0)
    df['file_access_drift'] = df['file_access'] / (df['avg_file_access_30d'] + 1)
    
    # 2. NLP Content Inspection Logic (The "Inspector")
    patterns = {
        "Credentials": r"(?i)(password|login|key|secret)",
        "Sensitive": r"(?i)(ssn|salary|confidential|backup)",
        "System": r"(?i)(export|root|admin|cmd)"
    }
    def inspect_content(text):
        found = []
        for name, reg in patterns.items():
            if pd.Series(text).str.contains(reg, na=False).any():
                found.append(name)
        return ", ".join(found) if found else "None"

    df['patterns_found'] = df['email_subject'].apply(inspect_content)

    # 3. ML Anomaly Detection (Isolation Forest)
    features = ['file_access', 'network_traffic_mb', 'is_after_hours']
    model = IsolationForest(contamination=0.1, random_state=42)
    df['ml_score'] = model.fit_predict(df[features])

    # 4. Hybrid Weighted Risk Engine (Logic + ML)
    def calculate_risk(row):
        score = 0
        factors = []
        if row['ml_score'] == -1: 
            score += 25
            factors.append("Statistical Anomaly (AI)")
        if row['patterns_found'] != "None": 
            score += 35
            factors.append(f"DLP Hit: {row['patterns_found']}")
        if row['network_traffic_mb'] > 15: 
            score += 25
            factors.append("Data Exfiltration")
        if row['is_after_hours'] == 1: 
            score += 20
            factors.append("Temporal Anomaly (After-Hours)")
        if row['file_access_drift'] > 3:
            score += 20
            factors.append("High File Drift")
            
        return pd.Series([min(score, 100), " | ".join(factors) if factors else "Normal Activity"])

    df[['risk_score', 'risk_factors']] = df.apply(calculate_risk, axis=1)
    df['threat_level'] = df['risk_score'].apply(lambda s: "CRITICAL" if s >= 70 else ("MEDIUM" if s >= 40 else "LOW"))
    
    return df