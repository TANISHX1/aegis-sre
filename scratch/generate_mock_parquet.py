import os
import pandas as pd
from datetime import datetime, timedelta

def generate_telemetry():
    os.makedirs("logs", exist_ok=True)
    
    # 1. API Gateway Telemetry (500 Errors caused by urllib3 leak)
    api_gw_data = {
        "timestamp": [(datetime.now() - timedelta(minutes=i)).strftime("%Y-%m-%d %H:%M:%S") for i in range(10)],
        "level": ["ERROR", "CRITICAL", "INFO", "WARN", "ERROR", "INFO", "WARN", "INFO", "ERROR", "CRITICAL"],
        "service": ["api-gateway"] * 10,
        "message": [
            "Failed to authenticate request. urllib3 error.", 
            "Vulnerability alert triggered. Deprecated package dependency.",
            "Transaction successful.", "High latency observed.",
            "Connection dropped due to urllib3 exception.", "Session renewed.", 
            "Rate limit approaching.", "Backup complete.",
            "KeyExpired error.", "urllib3 Cookie leak in cross-identity HTTP redirect."
        ],
        "ip": ["10.0.1.1", "10.0.1.2", "10.0.1.3", "10.0.1.4"] * 2 + ["10.0.1.1", "10.0.1.2"],
        "request_path": ["/v1/transactions", "/auth/token", "/v1/checkout", "/db/query"] * 2 + ["/v1/transactions", "/auth/token"],
        "response_code": [500, 500, 200, 429, 500, 200, 429, 200, 500, 500]
    }
    
    # 2. Auth Service Telemetry (JWT Expirations & Brute Force)
    auth_data = {
        "timestamp": [(datetime.now() - timedelta(minutes=i*2)).strftime("%Y-%m-%d %H:%M:%S") for i in range(5)],
        "level": ["WARN", "ERROR", "ERROR", "ERROR", "CRITICAL"],
        "service": ["auth-service"] * 5,
        "message": [
            "Invalid JWT signature.", "Rate limit exceeded for IP.",
            "Malformed authentication token.", "Multiple failed login attempts.",
            "Database connection timeout. Fatal error in cryptography package during AES decryption."
        ],
        "ip": ["192.168.1.10", "192.168.1.11", "192.168.1.10", "192.168.1.10", "10.0.5.5"],
        "request_path": ["/v1/auth/verify"] * 5,
        "response_code": [401, 429, 400, 403, 500]
    }

    # 3. Payment Gateway Telemetry (Timeouts & API Failures)
    payment_data = {
        "timestamp": [(datetime.now() - timedelta(minutes=i*5)).strftime("%Y-%m-%d %H:%M:%S") for i in range(5)],
        "level": ["INFO", "WARN", "ERROR", "ERROR", "CRITICAL"],
        "service": ["payment-gateway"] * 5,
        "message": [
            "Processing payload.", "Upstream Stripe API slow response.",
            "Timeout waiting for Stripe.", "Payment processing failed.",
            "Circuit breaker OPEN for stripe_api. Uncaught Template syntax error in django rendering engine."
        ],
        "ip": ["172.16.0.5"] * 5,
        "request_path": ["/v1/checkout/process"] * 5,
        "response_code": [200, 200, 504, 500, 500]
    }

    def save_parquet(data_dict, filename):
        df = pd.DataFrame(data_dict)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        path = f"logs/{filename}"
        df.to_parquet(path, engine="pyarrow", index=False)
        print(f"[*] Successfully generated mock telemetry: {path}")

    save_parquet(api_gw_data, "api_gateway_telemetry.parquet")
    save_parquet(auth_data, "auth_service_telemetry.parquet")
    save_parquet(payment_data, "payment_gateway_telemetry.parquet")

    # Generate OSV packages mock data
    osv_data = {
        "package_name": ["cryptography", "urllib3", "django"],
        "installed_version": ["3.4.7", "1.26.5", "3.2.0"],
        "vulnerable_version_range": ["<38.0.0", "<1.26.18", "<4.0.0"],
        "cve": ["CVE-2023-49083", "CVE-2023-43804", "CVE-2022-22818"],
        "severity": ["HIGH", "MEDIUM", "LOW"],
        "summary": ["NULL pointer dereference", "urllib3 Cookie leak", "Template syntax error"]
    }
    osv_df = pd.DataFrame(osv_data)
    osv_path = "logs/osv_packages.parquet"
    osv_df.to_parquet(osv_path, engine="pyarrow", index=False)
    print(f"[*] Successfully generated OSV mock data: {osv_path}")

    # Generate GitHub commits mock data
    github_data = {
        "commit_hash": ["a5d89f3", "b72c91a", "c83d10b"],
        "author": ["charlie", "alice", "bob"],
        "commit_date": [
            "2026-05-25 15:20:00",
            "2026-05-24 10:10:00",
            "2026-05-23 09:05:00"
        ],
        "message": ["Refactor auth-service logic and update dependencies (urllib3)", "Fix typo in readme", "Add metrics dashboard"],
        "changed_files": ["requirements.txt (urllib3), auth_service/jwt.py", "README.md", "metrics.py"]
    }
    github_df = pd.DataFrame(github_data)
    github_df['commit_date'] = pd.to_datetime(github_df['commit_date'])
    github_path = "logs/github_commits.parquet"
    github_df.to_parquet(github_path, engine="pyarrow", index=False)
    print(f"[*] Successfully generated GitHub mock data: {github_path}")

if __name__ == "__main__":
    generate_telemetry()
