"""
Aegis-Antigravity: Coral Query Executor Engine
---------------------------------------------------
This module implements the execution wrapper for Coral, using the Model Context
Protocol (MCP) as the primary data access layer.

CRITICAL ARCHITECTURAL DESIGN CHOICES & RATIONALE (THE "WHY"):
1. MCP-First Architecture:
   Instead of shelling out to `coral sql` via subprocess on every query, we maintain
   a persistent MCP connection to `coral mcp-stdio`. This gives us structured responses,
   typed errors, and access to Coral's full tool suite (catalog, schema discovery, SQL)
   through a single persistent process — eliminating ~300ms cold-start per query.

2. Graceful Degradation Chain:
   The executor follows a three-tier fallback: MCP → subprocess → mock.
   If the MCP connection fails, it falls back to raw subprocess execution.
   If Coral isn't installed at all, it falls back to the mock engine.

3. Strict Resource and Execution Timeouts:
   Network failures or inefficient joins could freeze execution. The MCP client
   enforces timeouts internally, preventing thread starvation in the web server.

4. Structured Error Diagnostics for SRE Brain:
   LLM agents need descriptive error contexts for self-correction. Both MCP and
   subprocess paths return structured JSON with status, data, and error messages.
"""

import json
import logging
import os
import shutil
import subprocess
from typing import Dict, Any, Union

# Set up logging for audit trails - crucial for SRE forensics
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CoralExecutor")


class CoralExecutorError(Exception):
    """Custom exception for Coral Execution flow. Used to separate database errors from agent bugs."""
    pass


# MCP Client import — the primary execution path
try:
    from tools.mcp_client import get_mcp_client
    HAS_MCP = True
except ImportError:
    HAS_MCP = False
    logger.warning("MCP client not available. Falling back to subprocess execution.")


def _is_source_registered(coral_binary: str, source_name: str) -> bool:
    """Check if a named source is already registered in Coral."""
    try:
        result = subprocess.run(
            [coral_binary, "source", "list"],
            capture_output=True, text=True, timeout=5.0
        )
        return source_name in result.stdout
    except Exception:
        return False


def _init_coral_sources(coral_binary: str):
    """
    Dynamically configure Coral data sources based on available credentials.
    """
    github_token = os.environ.get("GITHUB_TOKEN")
    has_real_token = github_token and github_token.strip() and "your_github" not in github_token
    
    github_registered = _is_source_registered(coral_binary, "github")
    
    if has_real_token and not github_registered:
        logger.info("✅ Real GITHUB_TOKEN detected! Configuring live GitHub API source in Coral.")
        env = {**os.environ, "GITHUB_TOKEN": github_token}
        subprocess.run([coral_binary, "source", "add", "github"], capture_output=True, env=env)
    elif not has_real_token and not github_registered:
        logger.info("No GITHUB_TOKEN detected. Registering offline Parquet mock for GitHub.")
        subprocess.run([coral_binary, "source", "add", "--file", "github-source.yaml"], capture_output=True)


def _subprocess_coral_execution(coral_binary: str, query: str, timeout: float) -> Dict[str, Any]:
    """Helper to run coral via subprocess."""
    cleaned_query = query.strip()
    if not cleaned_query:
        return {"status": "error", "message": "Empty query."}

    cmd = [coral_binary, "sql", cleaned_query, "--format", "json"]
    coral_env = {**os.environ}
    if os.getenv("GITHUB_TOKEN"):
        coral_env["GITHUB_TOKEN"] = os.getenv("GITHUB_TOKEN")

    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=timeout, shell=False, env=coral_env
        )
        if result.returncode != 0:
            return {"status": "error", "message": result.stderr.strip()}
        return {"status": "success", "data": json.loads(result.stdout), "count": len(json.loads(result.stdout))}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def execute_coral_query(query: str, timeout: float = 30.0) -> Dict[str, Any]:
    """
    Executes a federated Coral SQL query using the best available method.
    
    Execution priority:
    1. MCP Client (persistent connection to coral mcp-stdio) — preferred
    2. Subprocess (coral sql "<query>" --format json) — fallback
    3. Mock engine — if Coral is not installed
    
    Args:
        query (str): The raw SQL query formulated by the SRE Brain.
        timeout (float): Max execution time before termination.
        
    Returns:
        Dict[str, Any]: Structured output with 'status', 'data', and 'count'.
    """
    # 1. TRY MCP (preferred path)
    if HAS_MCP:
        try:
            logger.info(f"[MCP] Executing Coral SQL via MCP: {query[:120]}...")
            client = get_mcp_client()
            result = client.sql(query)
            if result.get("status") == "success":
                logger.info(f"[MCP] Query returned {result.get('count', 0)} rows.")
                return result
            else:
                logger.warning(f"[MCP] Query returned error: {result.get('message')}. Falling back to subprocess.")
        except Exception as e:
            logger.warning(f"[MCP] MCP execution failed: {e}. Falling back to subprocess.")
    
    # 2. FALLBACK: Subprocess execution
    coral_binary = shutil.which("coral")
    
    if coral_binary:
        _init_coral_sources(coral_binary)
        return _subprocess_coral_execution(coral_binary, query, timeout)
    
    # 3. LAST RESORT: Mock engine
    logger.warning("Coral CLI not found. Engaging mock dry-run mode.")
    return _mock_coral_execution(query)


def _mock_coral_execution(query: str) -> Dict[str, Any]:
    """
    Mock runner for local hackathon testing in environments where the Coral CLI is not installed.
    Simulates database behavior and handles queries related to logs, vulnerability checks, and git metadata.
    
    Why: In hackathons, agents are frequently developed and evaluated in environments without complete CLI footprints.
    This mock mimics the schema of Coral returns so the agent logic runs seamlessly.
    """
    import re
    query_upper = query.upper()
    logger.info("Mock Execution Triggered")

    # Mock response for Parquet Log files query
    if "READ(" in query_upper and "PARQUET" in query_upper:
        return {
            "status": "success",
            "data": [
                {
                    "timestamp": "2026-05-25T19:45:10Z",
                    "level": "ERROR",
                    "service": "api-gateway",
                    "message": "Failed to authenticate request. KeyExpired.",
                    "ip": "192.168.1.42",
                    "request_path": "/v1/transactions",
                    "response_code": 500
                },
                {
                    "timestamp": "2026-05-25T19:46:12Z",
                    "level": "CRITICAL",
                    "service": "auth-service",
                    "message": "Vulnerability alert triggered. Deprecated package dependency.",
                    "ip": "192.168.1.15",
                    "request_path": "/auth/token",
                    "response_code": 500
                }
            ],
            "count": 2
        }

    # Mock response for Google OSV packages joins
    elif "OSV.PACKAGES" in query_upper:
        return {
            "status": "success",
            "data": [
                {
                    "package_name": "cryptography",
                    "installed_version": "3.4.7",
                    "vulnerable_version_range": "<38.0.0",
                    "cve": "CVE-2023-49083",
                    "severity": "HIGH",
                    "summary": "NULL pointer dereference in cryptography package"
                },
                {
                    "package_name": "urllib3",
                    "installed_version": "1.26.5",
                    "vulnerable_version_range": "<1.26.18",
                    "cve": "CVE-2023-43804",
                    "severity": "MEDIUM",
                    "summary": "urllib3 Cookie leak in cross-identity HTTP redirect"
                }
            ],
            "count": 2
        }

    # Mock response for GitHub handle TANISHX1 commits
    elif "TANISHX1" in query_upper or "GITHUB" in query_upper:
        try:
            import subprocess
            git_cmd = ["git", "log", "-n", "5", "--pretty=format:%H||%an||%ad||%s", "--date=iso"]
            result = subprocess.run(git_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            commits = []
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                parts = line.split("||")
                if len(parts) == 4:
                    h, author, date, msg = parts
                    # Fetch modified files for this commit
                    files_cmd = ["git", "show", "--name-only", "--pretty=format:", h]
                    files_res = subprocess.run(files_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    changed_files = ", ".join(filter(None, files_res.stdout.strip().split("\n")))
                    commits.append({
                        "commit_hash": h[:7],
                        "author": author,
                        "commit_date": date,
                        "message": msg,
                        "changed_files": changed_files or "None"
                    })
            if commits:
                return {
                    "status": "success",
                    "data": commits,
                    "count": len(commits)
                }
        except Exception as e:
            logger.warning(f"Failed to query real git commits, falling back to mock: {e}")

        # Fallback if git command fails or is not a git repo
        return {
            "status": "success",
            "data": [
                {
                    "commit_hash": "a5d89f3",
                    "author": "TANISHX1",
                    "commit_date": "2026-05-25T15:20:00Z",
                    "message": "Refactor auth-service logic and update dependencies",
                    "changed_files": "requirements.txt, auth_service/jwt.py"
                }
            ],
            "count": 1
        }

    # Generic schema matching query request
    return {
        "status": "success",
        "data": [
            {
                "sys_log_id": 1001,
                "environment": "production",
                "health_status": "Degraded",
                "details": f"Mock result for: {query[:60]}..."
            }
        ],
        "count": 1
    }
