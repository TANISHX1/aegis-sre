"""
Aegis-Antigravity SRE: Local Webhook Receiver (n8n Replacement)
---------------------------------------------------------------
A lightweight Flask-like webhook server that replaces n8n for environments 
where Docker is unavailable. It receives SRE incident payloads, logs them 
to a local audit file, and can optionally forward them to Slack/Discord.

CRITICAL DESIGN CHOICES & RATIONALE (THE "WHY"):
1. Zero-Dependency HTTP Server:
   Uses Python's built-in `http.server` module to avoid adding Flask/FastAPI as 
   extra dependencies. This keeps the hackathon footprint minimal.

2. Audit Trail Logging:
   Every received incident payload is appended to `n8n_data/incident_log.jsonl` 
   in JSON Lines format. This provides a persistent, grep-friendly forensic audit 
   trail that can be demonstrated to hackathon judges.

3. Optional Slack/Discord Forwarding:
   If SLACK_WEBHOOK_URL or DISCORD_WEBHOOK_URL environment variables are set,
   the server will forward formatted incident alerts to those channels in real-time.
"""

import os
import sys
import json
import logging
import threading
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except ImportError:
    pass

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("WebhookReceiver")

# Configuration
WEBHOOK_PORT = int(os.getenv("WEBHOOK_PORT", "5678"))
WEBHOOK_PATH = "/webhook/aegis-sre-remediate"
HEALTHZ_PATH = "/healthz"
AUDIT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "n8n_data")
AUDIT_FILE = os.path.join(AUDIT_DIR, "incident_log.jsonl")

# Optional external integrations
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")


def _ensure_audit_dir():
    os.makedirs(AUDIT_DIR, exist_ok=True)


def _log_incident(payload: dict):
    """Append incident to the audit trail file in JSONL format."""
    _ensure_audit_dir()
    entry = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
    }
    with open(AUDIT_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    logger.info(f"📝 Incident logged to audit trail: {AUDIT_FILE}")


def _format_slack_message(payload: dict) -> dict:
    """Format incident payload into a rich Slack Block Kit message."""
    severity = payload.get("severity", "UNKNOWN")
    severity_emoji = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}.get(severity, "⚪")
    
    return {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{severity_emoji} SRE Incident Alert — {payload.get('incident_id', 'N/A')}", "emoji": True}
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                    {"type": "mrkdwn", "text": f"*Service:*\n{payload.get('service', 'unknown')}"},
                    {"type": "mrkdwn", "text": f"*Root Cause:*\n{payload.get('root_cause', 'Undetermined')}"},
                    {"type": "mrkdwn", "text": f"*Blast Radius:*\n{', '.join(payload.get('blast_radius_nodes', []))}"},
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Remediation Action:*\n```{payload.get('remediation_action', 'None specified')}```"}
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Triggered by: *{payload.get('triggered_by', 'Aegis-SRE Agent')}* at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"}
                ]
            }
        ]
    }


def _format_discord_message(payload: dict) -> dict:
    """Format incident payload into a Discord embed message."""
    severity = payload.get("severity", "UNKNOWN")
    color_map = {"LOW": 0x2ecc71, "MEDIUM": 0xf1c40f, "HIGH": 0xe67e22, "CRITICAL": 0xe74c3c}
    
    return {
        "embeds": [{
            "title": f"🛡️ SRE Incident Alert — {payload.get('incident_id', 'N/A')}",
            "color": color_map.get(severity, 0x95a5a6),
            "fields": [
                {"name": "Severity", "value": severity, "inline": True},
                {"name": "Service", "value": payload.get("service", "unknown"), "inline": True},
                {"name": "Root Cause", "value": payload.get("root_cause", "Undetermined"), "inline": False},
                {"name": "Blast Radius", "value": ", ".join(payload.get("blast_radius_nodes", [])), "inline": False},
                {"name": "Remediation", "value": f"```{payload.get('remediation_action', 'None')}```", "inline": False},
            ],
            "footer": {"text": f"Triggered by {payload.get('triggered_by', 'Aegis-SRE')}"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }]
    }


def _forward_to_slack(payload: dict):
    """Forward incident to Slack via Incoming Webhook."""
    if not SLACK_WEBHOOK_URL or not HAS_REQUESTS:
        return
    try:
        message = _format_slack_message(payload)
        resp = requests.post(SLACK_WEBHOOK_URL, json=message, timeout=5)
        if resp.status_code == 200:
            logger.info("✅ Incident forwarded to Slack successfully.")
        else:
            logger.warning(f"⚠️ Slack returned {resp.status_code}: {resp.text}")
    except Exception as e:
        logger.warning(f"⚠️ Failed to forward to Slack: {e}")


def _forward_to_discord(payload: dict):
    """Forward incident to Discord via Webhook."""
    if not DISCORD_WEBHOOK_URL or not HAS_REQUESTS:
        return
    try:
        message = _format_discord_message(payload)
        resp = requests.post(DISCORD_WEBHOOK_URL, json=message, timeout=5)
        if resp.status_code in (200, 204):
            logger.info("✅ Incident forwarded to Discord successfully.")
        else:
            logger.warning(f"⚠️ Discord returned {resp.status_code}: {resp.text}")
    except Exception as e:
        logger.warning(f"⚠️ Failed to forward to Discord: {e}")


class WebhookHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the local webhook receiver."""
    
    def log_message(self, format, *args):
        """Override default logging to use our logger."""
        logger.debug(f"HTTP {args}")
    
    def _send_json(self, status_code: int, data: dict):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def do_GET(self):
        if self.path == HEALTHZ_PATH:
            self._send_json(200, {
                "status": "healthy",
                "service": "aegis-sre-webhook-receiver",
                "uptime": "active",
                "integrations": {
                    "slack": bool(SLACK_WEBHOOK_URL),
                    "discord": bool(DISCORD_WEBHOOK_URL),
                }
            })
        else:
            self._send_json(404, {"error": "Not found"})
    
    def do_POST(self):
        if self.path != WEBHOOK_PATH:
            self._send_json(404, {"error": f"Unknown webhook path. Expected {WEBHOOK_PATH}"})
            return
        
        # Read and parse the incoming payload
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self._send_json(400, {"error": "Empty request body"})
            return
        
        try:
            body = self.rfile.read(content_length)
            payload = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            self._send_json(400, {"error": f"Invalid JSON payload: {str(e)}"})
            return
        
        # Process the incident
        incident_id = payload.get("incident_id", "UNKNOWN")
        severity = payload.get("severity", "UNKNOWN")
        service = payload.get("service", "unknown")
        
        logger.info(f"🚨 Received incident {incident_id} | Severity: {severity} | Service: {service}")
        
        # 1. Log to audit trail
        _log_incident(payload)
        
        # 2. Forward to external integrations (non-blocking)
        threading.Thread(target=_forward_to_slack, args=(payload,), daemon=True).start()
        threading.Thread(target=_forward_to_discord, args=(payload,), daemon=True).start()
        
        # 3. Respond to the dispatcher
        self._send_json(200, {
            "status": "received",
            "message": f"Incident {incident_id} processed. Audit logged. Integrations notified.",
            "incident_id": incident_id,
        })
    
    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


def start_webhook_server(port: int = WEBHOOK_PORT, background: bool = False):
    """
    Start the local webhook receiver server.
    
    Args:
        port: Port to listen on (default 5678, matching n8n's default).
        background: If True, runs in a daemon thread for embedding in other processes.
    """
    _ensure_audit_dir()
    server = HTTPServer(("0.0.0.0", port), WebhookHandler)
    
    integrations = []
    if SLACK_WEBHOOK_URL:
        integrations.append("Slack")
    if DISCORD_WEBHOOK_URL:
        integrations.append("Discord")
    
    integration_str = f" → Forwarding to: {', '.join(integrations)}" if integrations else " → No external integrations configured"
    
    logger.info(f"")
    logger.info(f"🛡️  Aegis-SRE Webhook Receiver")
    logger.info(f"   Listening on:  http://0.0.0.0:{port}{WEBHOOK_PATH}")
    logger.info(f"   Health check:  http://0.0.0.0:{port}{HEALTHZ_PATH}")
    logger.info(f"   Audit trail:   {AUDIT_FILE}")
    logger.info(f"   Integrations: {integration_str}")
    logger.info(f"")
    
    if background:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        logger.info("Webhook receiver started in background thread.")
        return server
    else:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Webhook receiver shutting down...")
            server.shutdown()


if __name__ == "__main__":
    start_webhook_server()
