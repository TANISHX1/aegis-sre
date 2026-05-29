import os
import requests
import pandas as pd
from datetime import datetime, timedelta

def generate():
    print("Fetching latest commit from Harshit7623/aegis-sre...")
    resp = requests.get("https://api.github.com/repos/Harshit7623/aegis-sre/commits")
    if resp.status_code != 200:
        print("Failed to fetch commits. Using fallback mock data.")
        author = "Harshit7623"
        sha = "unknown"
    else:
        commits = resp.json()
        latest = commits[0]
        author = latest['commit']['author']['name']
        sha = latest['sha']
        print(f"Latest commit: {sha} by {author}")

    # Generate recent logs
    now = datetime.utcnow()
    
    logs = []
    # 5 normal logs
    for i in range(5):
        logs.append({
            "timestamp": now - timedelta(minutes=10-i),
            "level": "INFO",
            "service": "api-gateway",
            "message": "Processed request normally.",
            "ip": "192.168.1.1",
            "request_path": "/v1/health",
            "response_code": 200
        })
        
    # 5 crash logs
    for i in range(5):
        logs.append({
            "timestamp": now - timedelta(minutes=5-i),
            "level": "ERROR",
            "service": "api-gateway",
            # We explicitly mention 'requests' here because our OSV table has package_name='requests'
            "message": f"Fatal exception in requests. Commit {sha} (author: {author}) might be related.",
            "ip": "10.0.0.5",
            "request_path": "/v1/api/data",
            "response_code": 500
        })
        
    df = pd.DataFrame(logs)
    os.makedirs("logs", exist_ok=True)
    df.to_parquet("logs/api_gateway_telemetry.parquet")
    # Duplicate for auth_service_logs just in case the LLM picks it
    df.to_parquet("logs/auth_service_telemetry.parquet")
    print("✅ Live telemetry generated successfully!")

if __name__ == "__main__":
    generate()
