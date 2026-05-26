#!/usr/bin/env python3
"""
Aegis-SRE: Source Registration Setup Script
--------------------------------------------
Generates Coral source YAML manifests with correct absolute paths
for the current machine, then registers them. This eliminates the 
hardcoded path problem when cloning onto different systems.

Usage:
    python3 setup_sources.py
"""

import os
import subprocess
import shutil

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")


def generate_parquet_source():
    yaml_content = f"""name: local_file
version: 0.1.0
dsl_version: 3
backend: parquet
tables:
  - name: api_gateway_logs
    description: "API Gateway 500 error telemetry"
    source:
      location: "file://{LOGS_DIR}/api_gateway_telemetry.parquet"
  - name: auth_service_logs
    description: "Auth Service JWT telemetry"
    source:
      location: "file://{LOGS_DIR}/auth_service_telemetry.parquet"
  - name: payment_gateway_logs
    description: "Payment Gateway Stripe telemetry"
    source:
      location: "file://{LOGS_DIR}/payment_gateway_telemetry.parquet"
"""
    path = os.path.join(PROJECT_ROOT, "parquet-source.yaml")
    with open(path, "w") as f:
        f.write(yaml_content)
    print(f"[✓] Generated {path}")
    return path


def generate_osv_source():
    yaml_content = f"""name: osv
version: 0.1.0
dsl_version: 3
backend: parquet
tables:
  - name: packages
    description: "Google OSV API mock"
    source:
      location: "file://{LOGS_DIR}/osv_packages.parquet"
"""
    path = os.path.join(PROJECT_ROOT, "osv-source.yaml")
    with open(path, "w") as f:
        f.write(yaml_content)
    print(f"[✓] Generated {path}")
    return path


def generate_github_source():
    yaml_content = f"""name: github
version: 0.1.0
dsl_version: 3
backend: parquet
tables:
  - name: commits
    description: "GitHub commits mock"
    source:
      location: "file://{LOGS_DIR}/github_commits.parquet"
"""
    path = os.path.join(PROJECT_ROOT, "github-source.yaml")
    with open(path, "w") as f:
        f.write(yaml_content)
    print(f"[✓] Generated {path}")
    return path


def register_sources():
    coral = shutil.which("coral")
    if not coral:
        print("[!] Coral CLI not found in PATH. Skipping registration.")
        print("    Install it: curl -fsSL https://withcoral.com/install.sh | sh")
        return

    sources = {
        "local_file": os.path.join(PROJECT_ROOT, "parquet-source.yaml"),
        "osv": os.path.join(PROJECT_ROOT, "osv-source.yaml"),
    }
    
    # Check which sources are already registered
    result = subprocess.run([coral, "source", "list"], capture_output=True, text=True)
    existing = result.stdout if result.returncode == 0 else ""

    for name, yaml_path in sources.items():
        if name in existing:
            # Remove and re-add to update paths
            subprocess.run([coral, "source", "remove", name], capture_output=True)
        subprocess.run([coral, "source", "add", "--file", yaml_path], capture_output=True)
        print(f"[✓] Registered Coral source: {name}")

    # GitHub source: prefer real token, fall back to parquet mock
    github_token = os.environ.get("GITHUB_TOKEN", "")
    if github_token and "your_github" not in github_token:
        if "github" in existing:
            subprocess.run([coral, "source", "remove", "github"], capture_output=True)
        env = {**os.environ, "GITHUB_TOKEN": github_token}
        subprocess.run([coral, "source", "add", "github"], capture_output=True, env=env)
        print("[✓] Registered Coral source: github (LIVE API)")
    else:
        github_yaml = os.path.join(PROJECT_ROOT, "github-source.yaml")
        if "github" in existing:
            subprocess.run([coral, "source", "remove", "github"], capture_output=True)
        subprocess.run([coral, "source", "add", "--file", github_yaml], capture_output=True)
        print("[✓] Registered Coral source: github (offline mock)")


if __name__ == "__main__":
    print("=" * 50)
    print("  Aegis-SRE: Source Registration Setup")
    print("=" * 50)
    
    # 1. Generate mock data if not present
    if not os.path.exists(os.path.join(LOGS_DIR, "api_gateway_telemetry.parquet")):
        print("\n[*] Generating mock telemetry data...")
        subprocess.run(["python3", os.path.join(PROJECT_ROOT, "scratch", "generate_mock_parquet.py")], 
                       cwd=PROJECT_ROOT)
    
    # 2. Generate YAML manifests with correct paths
    print("\n[*] Generating source manifests...")
    generate_parquet_source()
    generate_osv_source()
    generate_github_source()
    
    # 3. Register with Coral
    print("\n[*] Registering sources with Coral CLI...")
    register_sources()
    
    print("\n[✓] Setup complete! Run `reflex run` to start the application.")
