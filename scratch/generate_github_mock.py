import os
import pandas as pd
from datetime import datetime, timedelta

def generate_commits():
    # Make sure logs directory exists
    os.makedirs("logs", exist_ok=True)
    
    data = {
        "commit_hash": ["a5d89f3", "b2e91c2", "c7f02d4", "d9e83f1", "e2d3f4a"],
        "author": ["TANISHX1", "TANISHX1", "alice_dev", "bob_ops", "TANISHX1"],
        "commit_date": [
            (datetime.now() - timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S"),
            (datetime.now() - timedelta(days=5)).strftime("%Y-%m-%d %H:%M:%S"),
            (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S"),
            (datetime.now() - timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S"),
            (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
        ],
        "message": [
            "chore: bump urllib3 to 1.26.15",
            "feat: add payment gateway",
            "fix: UI layout on mobile",
            "ops: update k8s configs",
            "fix: urgent patch for urllib3 session leak"
        ],
        "changed_files": [
            "requirements.txt, api_gateway/main.py",
            "payment_service/core.py",
            "frontend/assets/main.css",
            "infra/k8s/deployment.yaml",
            "requirements.txt"
        ]
    }
    
    df = pd.DataFrame(data)
    target_path = "logs/github_commits.parquet"
    df.to_parquet(target_path, engine="pyarrow", index=False)
    print(f"[*] Successfully generated mock git commits: {target_path}")

if __name__ == "__main__":
    generate_commits()
