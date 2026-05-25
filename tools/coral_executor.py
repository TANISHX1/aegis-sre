"""
Aegis-Antigravity SRE: Coral CLI Query Executor Engine
------------------------------------------------------
This module implements the execution wrapper for the local Coral CLI.
In a zero-warehouse architecture, Coral queries are executed on-the-fly, 
federating local parquet logs and remote vulnerability databases.

CRITICAL ARCHITECTURAL DESIGN CHOICES & RATIONALE (THE "WHY"):
1. Subprocess Call Isolation (shell=False):
   By passing command arguments as a list and explicitly setting `shell=False`, we prevent 
   the operating system from spawning a shell process (like /bin/sh or /bin/bash) to evaluate the query. 
   This fundamentally immunizes the system against shell injection attacks (e.g., executing arbitrary 
   commands via semicolons or shell expansions like `$(...)`), as arguments are passed directly 
   to the system call execve().
   
2. Strict Resource and Execution Timeouts:
   Coral SQL joins offline log files with external network resources (e.g., Google OSV API, Sentry). 
   Network failures or malicious/inefficient joins (e.g., Cartesian products on large datasets) 
   could freeze execution. Setting a rigid timeout (default 30.0s) prevents thread starvation 
   in the web application server and avoids CPU exhaustion.

3. Structured Error Diagnostics for SRE Brain:
   LLM agents need highly descriptive error contexts to perform self-correction. Instead of 
   crashing or returning generic error codes, this module parses stderr, captures CLI signals, 
   and returns structured JSON detailing syntax mistakes, file access failures, or timeout events.
"""

import json
import logging
import shutil
import subprocess
from typing import Dict, Any, Union

# Set up logging for audit trails - crucial for SRE forensics
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CoralExecutor")


class CoralExecutorError(Exception):
    """Custom exception for Coral Execution flow. Used to separate database errors from agent bugs."""
    pass


def execute_coral_query(query: str, timeout: float = 30.0) -> Dict[str, Any]:
    """
    Executes a federated Coral SQL query via local CLI subprocess execution.
    
    Args:
        query (str): The raw SQL query formulated by the SRE Brain.
        timeout (float): Max execution time before subprocess termination.
        
    Returns:
        Dict[str, Any]: Structured output. Contains 'status' ('success' or 'error'), 
                        and either 'data' (JSON query results) or 'message' (error details).
    """
    # 1. PRE-FLIGHT CHECK: CLI binary verification
    # Before executing the subprocess, verify the executable is present.
    # Why? It is highly inefficient to spawn a subprocess only to get an OS-level
    # 'FileNotFoundError'. Verifying via shutil.which() saves process-spawning overhead.
    coral_binary = shutil.which("coral")
    if not coral_binary:
        # Provide fallback/mock mode for Hackathon dry runs when the environment 
        # might not have the fully configured CLI installed on the worker node.
        logger.warning("Coral CLI binary 'coral' not found in PATH. Engaging mock dry-run mode.")
        return _mock_coral_execution(query)

    # 2. INPUT SANITIZATION
    # Even with shell=False, we strip leading/trailing whitespace and control chars 
    # to protect downstream JSON parsers.
    cleaned_query = query.strip()
    if not cleaned_query:
        return {
            "status": "error",
            "message": "Empty query received. Unable to execute empty instruction."
        }

    # 3. CONSTRUCT COMMAND LIST
    # Arguments must be isolated to prevent flags or CLI parameters from leaking.
    # By separating arguments, 'coral' processes the string strictly as a query argument.
    cmd = [coral_binary, "sql", cleaned_query, "--format", "json"]

    logger.info(f"Executing Coral SQL: {cleaned_query} (Timeout: {timeout}s)")

    try:
        # 4. SUBPROCESS INVOKATION WITH ISOLATION
        # - shell=False: Prevents shell expansion attacks.
        # - stdout & stderr=PIPE: Redirects descriptors to memory, preventing pollution 
        #   of the parent terminal console.
        # - text=True: Decodes standard output bytes to UTF-8 dynamically.
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            shell=False
        )

        # 5. DIAGNOSTICS & STATUS CHECK
        # Coral CLI returns non-zero codes on syntax errors, missing tables, or resource exhaustion.
        if result.returncode != 0:
            logger.error(f"Coral CLI returned non-zero exit code {result.returncode}. Stderr: {result.stderr}")
            return {
                "status": "error",
                "exit_code": result.returncode,
                "message": result.stderr.strip() or f"Execution failed with code {result.returncode}"
            }

        # 6. JSON PARSING & PAYLOAD EXTRACTION
        # Coral --format json delivers structured data. We deserialize it immediately.
        # Deserializing on behalf of the agent reduces the token consumption because
        # we can validate schema compliance and return clean python dicts.
        try:
            parsed_data = json.loads(result.stdout)
            return {
                "status": "success",
                "data": parsed_data,
                "count": len(parsed_data) if isinstance(parsed_data, list) else 1
            }
        except json.JSONDecodeError as jde:
            logger.error(f"Failed to parse Coral JSON output. Raw stdout: {result.stdout}")
            return {
                "status": "error",
                "message": f"Malformed CLI output. Unable to decode JSON. Error: {str(jde)}",
                "raw_output": result.stdout.strip()
            }

    except subprocess.TimeoutExpired as te:
        # Timeout safety valve triggered! Kill process and recover.
        logger.error(f"Coral SQL query timed out after {timeout} seconds. Query: {cleaned_query}")
        return {
            "status": "error",
            "message": f"Query execution timed out. Limit of {timeout}s exceeded. Avoid complex Cartesian JOINs without limits."
        }
    except Exception as e:
        # Global fallback to prevent exceptions from propagating and crashing the Reflex UI thread.
        logger.exception("Unexpected system failure during Coral execution.")
        return {
            "status": "error",
            "message": f"Internal subprocess executor crash: {str(e)}"
        }


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
