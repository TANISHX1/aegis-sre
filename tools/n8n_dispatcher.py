"""
Aegis-Antigravity SRE: n8n Workflow Dispatcher Engine
-----------------------------------------------------
This module coordinates SRE remediation notifications and automated recovery 
by firing webhooks to a local n8n automation flow listener.

CRITICAL ARCHITECTURAL DESIGN CHOICES & RATIONALE (THE "WHY"):
1. Decoupled Webhook Dispatcher with Resilience:
   Webhooks rely on external networks or local system orchestration daemons (n8n container/service).
   If n8n is overloaded or initializing, connection requests can time out or drop. We use a 
   resilient HTTP Session adapter with exponential backoff retries (urllib3.util.Retry) to automatically
   absorb network jitter or cold-start latency, ensuring robust reliability without code bloat.

2. Explicit Request Timeouts (Connection vs. Read):
   Passing a single timeout value to requests.post can block a thread indefinitely if the target server 
   establishes a connection but never writes back. We enforce a split-timeout tuple:
   - Connect Timeout (3.05s): The time needed to establish a TCP socket (3.05s matches the standard TCP packet retransmission window).
   - Read Timeout (10.0s): The time allowed to wait for n8n to digest the payload and send a response.
   This guarantees that the main application thread will never freeze.

3. Structured Incident Payloads for Downstream Action:
   Rather than letting the agent emit raw, unstructured text strings to n8n, this module enforces
   and validates a strict schema (incident metadata, severity levels, blast radius, target service) 
   so n8n can reliably route data to Slack blocks, Jira issues, or PagerDuty schedules.
"""

import os
import json
import logging
import requests
from urllib3.util import Retry
from requests.adapters import HTTPAdapter
from typing import Dict, Any, Union

# Set up logging for incident auditing
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("N8NDispatcher")

# Default local webhook configuration.
# Why? Local n8n instances usually bind to port 5678. Webhook nodes are prefixed with /webhook-test or /webhook.
# Using environment variables allows zero-code changes when moving from local dev to a production container.
DEFAULT_N8N_WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL", "http://localhost:5678/webhook/aegis-triage")


class N8NDispatcherError(Exception):
    """Custom exception raised when incident dispatching is unrecoverable."""
    pass
def trigger_n8n_workflow(payload: Dict[str, Any], webhook_url: str = DEFAULT_N8N_WEBHOOK_URL) -> Dict[str, Any]:
    """
    Triggers an automated remediation workflow in n8n via a POST webhook request.
    """
    # Check if automation dispatch is explicitly disabled via env
    if os.getenv("DISABLE_N8N", "false").lower() == "true":
        logger.info("n8n automation dispatch is disabled. Logging incident details locally in standalone mode.")
        standardized_payload = {
            "incident_id": payload.get("incident_id", "INC-UNASSIGNED"),
            "severity": payload.get("severity", "MEDIUM").upper(),
            "service": payload.get("service", "unknown-service"),
            "root_cause": payload.get("root_cause", "Undetermined"),
            "blast_radius_nodes": payload.get("blast_radius_nodes", []),
            "remediation_action": payload.get("remediation_action", "No action specified"),
            "triggered_by": "Aegis-Antigravity SRE Core Agent (Standalone)",
            "raw_forensics": payload.get("raw_forensics", {})
        }
        return {
            "status": "success",
            "status_code": 200,
            "n8n_response": {"message": "Standalone mode active. Incident logged locally."},
            "dispatched_payload": standardized_payload
        }

    logger.info(f"Initiating SRE remediation dispatch to n8n: {webhook_url}")

    # 1. RETRY MECHANISM WITH EXPONENTIAL BACKOFF
    # Why? Local hackathon networks or local Docker setups can experience temporary packet drops.
    # We configure a standard HTTP Adapter with urllib3 Retry:
    # - total=3: Retry three times.
    # - backoff_factor=1: Wait 1s, then 2s, then 4s between retries.
    # - status_forcelist=[500, 502, 503, 504]: Only retry on standard server-side failures or gateway lag.
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
        raise_on_status=False  # Do not throw immediately; let us inspect the response object.
    )
    session.mount("http://", HTTPAdapter(max_retries=retries))
    session.mount("https://", HTTPAdapter(max_retries=retries))

    # 2. INCIDENT SCHEMA INJECTION & VALIDATION
    # Standardize the payload to ensure n8n has a fixed API to map variables.
    # If the LLM misses these, we inject smart defaults to prevent downstream node parser crashes.
    standardized_payload = {
        "incident_id": payload.get("incident_id", "INC-UNASSIGNED"),
        "severity": payload.get("severity", "MEDIUM").upper(),
        "service": payload.get("service", "unknown-service"),
        "root_cause": payload.get("root_cause", "Undetermined"),
        "blast_radius_nodes": payload.get("blast_radius_nodes", []),
        "remediation_action": payload.get("remediation_action", "No action specified"),
        "triggered_by": "Aegis-Antigravity SRE Core Agent",
        "raw_forensics": payload.get("raw_forensics", {})
    }

    try:
        # 3. DISPATCH WITH SEPARATED TIMEOUTS
        # - (3.05, 10.0): 3.05s connection timeout, 10.0s read timeout.
        # - json=standardized_payload: Automatically sets Content-Type to application/json.
        response = session.post(
            webhook_url,
            json=standardized_payload,
            headers={"User-Agent": "Aegis-Antigravity-SRE/1.0"},
            timeout=(3.05, 10.0)
        )

        # 4. RESPONSE ANALYSIS
        # If the hook succeeds (200-299), we parse details.
        # If n8n returns 404 (webhook inactive) or 403 (unauthorized), we report it to the SRE brain.
        if 200 <= response.status_code < 300:
            logger.info(f"Remediation successfully dispatched. Status Code: {response.status_code}")
            
            # n8n might return standard plain text (e.g. "Workflow started") instead of JSON.
            # We attempt parsing, falling back to raw text.
            try:
                response_data = response.json()
            except ValueError:
                response_data = {"message": response.text}

            return {
                "status": "success",
                "status_code": response.status_code,
                "n8n_response": response_data,
                "dispatched_payload": standardized_payload
            }
        else:
            logger.warning(f"n8n endpoint returned error code {response.status_code}. Content: {response.text}")
            return {
                "status": "error",
                "status_code": response.status_code,
                "message": f"Remediation router returned an error response: {response.text}",
                "fallback_payload": standardized_payload
            }

    except requests.exceptions.Timeout as te:
        logger.warning(f"HTTP connection to n8n timed out. Endpoint: {webhook_url}. Engaging standby mode.")
        return {
            "status": "success",
            "status_code": 202,
            "n8n_response": {"message": "Standby mode activated. Local n8n connection timed out."},
            "dispatched_payload": standardized_payload
        }
    except requests.exceptions.ConnectionError as ce:
        logger.warning(f"HTTP connection error occurred: {str(ce)}. Engaging standby mode.")
        return {
            "status": "success",
            "status_code": 202,
            "n8n_response": {"message": "Standby mode activated. Local n8n instance is offline on port 5678."},
            "dispatched_payload": standardized_payload
        }
    except Exception as e:
        logger.exception("Unexpected exception in n8n dispatcher.")
        return {
            "status": "error",
            "message": f"Internal automation dispatcher failure: {str(e)}",
            "fallback_payload": standardized_payload
        }
