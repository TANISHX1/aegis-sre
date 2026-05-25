import os
import pandas as pd
from datetime import datetime, timedelta

def generate_telemetry():
    # Make sure logs directory exists
    os.makedirs("logs", exist_ok=True)
    
    # Compile realistic telemetry records matching SRE Graph nodes
    data = {
        "timestamp": [
            (datetime.now() - timedelta(minutes=i)).strftime("%Y-%m-%d %H:%M:%S")
            for i in range(10)
        ],
        "service": [
            "api-gateway", "auth-service", "payment-service", "database",
            "api-gateway", "auth-service", "payment-service", "database",
            "api-gateway", "auth-service"
        ],
        "ip": [
            "10.0.1.1", "10.0.1.2", "10.0.1.3", "10.0.1.4",
            "10.0.1.1", "10.0.1.2", "10.0.1.3", "10.0.1.4",
            "10.0.1.1", "10.0.1.2"
        ],
        "request_count": [1200, 850, 430, 2200, 1150, 890, 420, 2150, 1310, 910],
        "error_count": [150, 8, 2, 0, 180, 12, 1, 0, 240, 9], # High error counts on api-gateway
        "vulnerable_package": [
            "urllib3==1.26.15", "None", "None", "None",
            "urllib3==1.26.15", "None", "None", "None",
            "urllib3==1.26.15", "None"
        ]
    }
    
    df = pd.DataFrame(data)
    target_path = "logs/server_telemetry.parquet"
    df.to_parquet(target_path, engine="pyarrow", index=False)
    print(f"[*] Successfully generated mock telemetry log: {target_path}")
    print(df.head(5))

if __name__ == "__main__":
    generate_telemetry()
