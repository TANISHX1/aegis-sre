"""
Aegis SRE: Pure Python Reactive Command Dashboard
-------------------------------------------------------------
This is the core Reflex UI module. It binds the state management, the SVG visual 
node threat graph, file upload forensic workflows, and the cognitive brain 
into a unified, glassmorphic dark-themed command panel.

CRITICAL ARCHITECTURAL DESIGN CHOICES & RATIONALE (THE "WHY"):
1. Dynamic UI Generator State Flow (yield):
   Reflex compiles down to Next.js on the client and runs a FastAPI server on the backend.
   Standard HTTP request-response patterns are blocking. If the agent loop executed 
   synchronously, the server would lock up, and the client browser would drop the connection due to timeouts.
   Using `async def` coupled with generator `yield` signals allows Reflex to push real-time 
   state updates to the client DOM via standard WebSockets. Every time `yield` is called, the current 
   state delta is compiled, serialized to JSON, and flashed to the client instantly.

2. Sandboxed File Upload Forensic Validation:
   Hackathon uploads must protect the server host. If a user uploads a file with path traversal characters
   (e.g., ../../../etc/cron.d/malicious), they could overwrite system configuration files. 
   We enforce strict sandboxing using `os.path.basename()` to strip directory paths, forcing 
   all uploads to write exclusively into the isolated `/logs` folder.

3. Lightweight Native SVG Graph vs Heavy NPM Canvas Libraries:
   Directly loading heavy Javascript canvas or D3 graphs inside React frequently introduces bundle bloating,
   React lifecycle hydration errors, and cross-origin resource blockages. By representing the 
   "Blast Radius" threat topology as a native SVG generated reactively from python lists (`blast_radius_nodes`),
   we achieve ultra-high performance (60fps rendering) with absolute styling control and zero third-party
   NPM packaging complexity.

4. UI State Isolation to Avoid Memory Bloat:
   Large Parquet files can contain millions of log rows. In a zero-warehouse model, we do NOT load log rows 
   into the Reflex state (which would cause massive WebSocket serialization delay and browser tab crashes). 
   Instead, we keep logs strictly in system memory during Coral execution, transferring only the 
   summarized aggregates and alerts back to the Reflex UI state.
"""

import os
import sys
import asyncio
import reflex as rx
from typing import Dict, Any, List

# Ensure our local subpackages (tools, agent) are discoverable in Python's pathing table.
# Crucial for dynamic hackathon runs where virtualenvs are created on-the-fly.
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.sre_brain import SREBrain

# CSS Theme definitions (Premium Glassmorphic Cyberpunk design)
THEME_BG = "radial-gradient(circle at 50% 10%, rgba(0, 242, 254, 0.05) 0%, transparent 50%), radial-gradient(circle at 80% 60%, rgba(157, 78, 221, 0.03) 0%, transparent 40%), radial-gradient(circle at 20% 80%, rgba(255, 107, 107, 0.03) 0%, transparent 40%), #050508"
ACCENT_CORAL = "#ff6b6b"
ACCENT_CYAN = "#00f2fe"
ACCENT_PURPLE = "#9d4edd"


GLASS_BOX = {
    "background": "rgba(9, 9, 13, 0.65)",
    "backdrop_filter": "blur(16px)",
    "-webkit-backdrop-filter": "blur(16px)",
    "border": "1px solid rgba(0, 242, 254, 0.08)",
    "border_radius": "14px",
    "box_shadow": "0 8px 32px 0 rgba(0, 0, 0, 0.4)",
}


class State(rx.State):
    """
    Core Application State. Manages active sessions, uploaded forensic log manifests,
    cognitive logs from the agent brain, and the dynamic reactive SVG topology calculations.
    """
    
    # 0. Landing Page Gate
    show_landing: bool = True
    landing_exiting: bool = False

    # 1. Chat Logs Container
    chat_history: List[Dict[str, str]] = [
        {
            "role": "assistant",
            "content": "**Aegis SRE Core Online**. I am your Zero-Warehouse Autonomous Agent. Drop `.parquet` files in the sidebar and trigger an investigation. I will join local telemetry logs with vulnerability databases and GitHub records to isolate root causes."
        }
    ]
    
    # 2. Reactive UI Control flags
    current_question: str = ""
    is_investigating: bool = False
    
    # 3. Agent Cognitive Thought Logs (Displayed as real-time terminal output)
    agent_thought_log: List[str] = [
        "System: Initializing Aegis Brain context...",
        "System: Awaiting telemetry logs upload or manual forensic instruction."
    ]
    
    # 4. Forensic Log Store
    uploaded_logs: List[str] = []
    
    # 5. Native Reactive SVG Graph States
    demo_mode: bool = os.environ.get("DEMO_MODE", "true").lower() == "true"

    blast_radius_nodes: List[Dict[str, Any]] = [
        {"id": "api-gateway", "label": "API Gateway", "x": 170, "y": 50, "status": "Healthy", "vulnerable": "None", "remediation": "No current action required."},
        {"id": "auth-service", "label": "Auth Service", "x": 80, "y": 150, "status": "Healthy", "vulnerable": "None", "remediation": "No current action required."},
        {"id": "db-primary", "label": "Primary DB", "x": 80, "y": 250, "status": "Healthy", "vulnerable": "None", "remediation": "No current action required."},
        {"id": "payment-sys", "label": "Payment Sys", "x": 260, "y": 150, "status": "Healthy", "vulnerable": "None", "remediation": "No current action required."},
        {"id": "worker-queue", "label": "Celery Workers", "x": 260, "y": 250, "status": "Healthy", "vulnerable": "None", "remediation": "No current action required."},
    ] if os.environ.get("DEMO_MODE", "true").lower() == "true" else [
        {"id": "core-hub", "label": "Scanning Architecture...", "x": 170, "y": 150, "status": "Healthy", "vulnerable": "None", "remediation": "Awaiting Aegis Agent analysis."}
    ]

    blast_radius_edges: List[Dict[str, str]] = [
        {"source": "api-gateway", "target": "auth-service"},
        {"source": "api-gateway", "target": "payment-sys"},
        {"source": "auth-service", "target": "db-primary"},
        {"source": "payment-sys", "target": "worker-queue"},
    ] if os.environ.get("DEMO_MODE", "true").lower() == "true" else []

    @rx.var
    def computed_edges(self) -> List[Dict[str, Any]]:
        coord_map = {node["id"]: {"x": node["x"], "y": node["y"]} for node in self.blast_radius_nodes}
        edges_with_coords = []
        for edge in self.blast_radius_edges:
            if edge["source"] in coord_map and edge["target"] in coord_map:
                edges_with_coords.append({
                    "x1": str(coord_map[edge["source"]]["x"]),
                    "y1": str(coord_map[edge["source"]]["y"]),
                    "x2": str(coord_map[edge["target"]]["x"]),
                    "y2": str(coord_map[edge["target"]]["y"])
                })
        return edges_with_coords

    # Details of node clicked in the Threat panel
    selected_node_info: Dict[str, str] = {
        "id": "none",
        "name": "No Service Selected",
        "status": "Healthy",
        "ip": "-",
        "vulnerable": "None",
        "remediation": "Awaiting analysis. Tap a node to inspect."
    }
    
    # 6. Integrations State
    github_token: str = os.environ.get("GITHUB_TOKEN", "")
    github_owner: str = os.environ.get("GITHUB_REPO", "Harshit7623/Aegis_demo_repo").split("/")[0] if "/" in os.environ.get("GITHUB_REPO", "Harshit7623/Aegis_demo_repo") else "Harshit7623"
    github_repo_name: str = os.environ.get("GITHUB_REPO", "Harshit7623/Aegis_demo_repo").split("/")[1] if "/" in os.environ.get("GITHUB_REPO", "Harshit7623/Aegis_demo_repo") else "Aegis_demo_repo"
    github_connection_status: str = "Checking..."
    osv_connection_status: str = "Checking..."
    show_github_token_input: bool = False
    
    notion_connection_status: str = "Checking..."
    show_notion_token_input: bool = False
    notion_token: str = ""

    jira_connection_status: str = "Checking..."
    show_jira_token_input: bool = False
    jira_token: str = ""

    slack_connection_status: str = "Checking..."
    show_slack_token_input: bool = False
    slack_token: str = ""

    show_playbooks: bool = False
    
    def toggle_playbooks(self):
        self.show_playbooks = not self.show_playbooks

    async def enter_dashboard(self):
        """Animated transition: fade out landing, then reveal the main dashboard."""
        self.landing_exiting = True
        yield
        await asyncio.sleep(0.6)  # Wait for CSS exit animation
        self.show_landing = False
        self.landing_exiting = False

    # 6. ASYNC CORE INVESTIGATION LOOP
    @rx.event(background=True)
    async def trigger_investigation(self):
        """
        Launches Aegis Brain async reasoning.
        Iterates over the agent's thoughts and tool actions, yielding them continuously to 
        prevent Next.js socket timeouts and keep the UI reactive.
        """
        async with self:
            if not self.current_question.strip():
                return
            
            self.is_investigating = True
            # Clear logs to focus on current trace session
            self.agent_thought_log = [f"System: Starting investigation sequence for: '{self.current_question}'"]
            # Capture question and history before releasing the lock
            current_q = self.current_question
            history_buffer = []
            for turn in self.chat_history[-6:]:
                history_buffer.append({"role": turn["role"], "content": turn["content"]})
        yield  # Force UI refresh to render loading states

        # Instantiating SREBrain. Done inside the method so it refreshes environmental variables (e.g. keys) dynamically.
        brain = SREBrain()
            
        # Run Aegis agent generator loop
        try:
            # We fetch thoughts via generator to print intermediate diagnostics to the operator.
            for step in brain.run_investigation_loop(current_q, history_buffer):
                step_type = step.get("type")
                
                async with self:
                    if step_type == "status":
                        self.agent_thought_log.append(f"[STATUS] {step.get('content')}")
                    elif step_type == "thought":
                        self.agent_thought_log.append(f"[COGNITION] {step.get('content')}")
                    elif step_type == "tool_call":
                        tool_name = step.get("tool_name")
                        args = step.get("arguments", {})
                        self.agent_thought_log.append(f"[TOOL_INVOCATION] {tool_name} with params -> {args}")
                    elif step_type == "tool_result":
                        tool_name = step.get("tool_name")
                        result = step.get("result", {})
                        self.agent_thought_log.append(f"[TOOL_RESULT] {tool_name} returned status: {result.get('status')}")
                        
                        # Dynamically update the blast radius or SVG topology based on Coral execution outputs!
                        if tool_name == "execute_coral_query" and result.get("status") == "success":
                            self._parse_query_impact(result.get("data", []))
                        elif tool_name == "update_threat_topology" and result.get("status") == "success":
                            nodes = result.get("nodes", [])
                            edges = result.get("edges", [])
                            if nodes:
                                # Normalize status values for frontend color matching
                                for n in nodes:
                                    s = n.get("status", "").strip().lower()
                                    n["status"] = "Healthy" if s in ("healthy", "stable", "ok", "operational", "normal", "running", "active", "up") else "Degraded"
                                self.blast_radius_nodes = nodes
                                self.blast_radius_edges = edges
                                self.agent_thought_log.append("[ALERT] Agent has dynamically redrawn the Threat Topology graph!")
                    elif step_type == "final":
                        self.chat_history.append({"role": "user", "content": current_q})
                        self.chat_history.append({"role": "assistant", "content": step.get("content", "")})
                        self.current_question = ""
                    elif step_type == "error":
                        self.agent_thought_log.append(f"[ERROR] {step.get('content')}")
                        self.chat_history.append({"role": "assistant", "content": f"[WARNING] Aegis Brain encountered an execution block: {step.get('content')}"})
                
                # Push state delta updates to the Reflex websocket immediately
                yield
                
        except Exception as e:
            async with self:
                self.agent_thought_log.append(f"[FATAL_CRASH] Aegis brain loop: {str(e)}")
            yield
            
        async with self:
            self.is_investigating = False
        yield

    def select_node(self, node_id: str):
        """
        Interactive Node Click Handler. Updates details pane when a visual node is tapped.
        """
        for n in self.blast_radius_nodes:
            if n["id"] == node_id:
                # Use the dynamic remediation string provided by the AI agent's topology update
                remediation = n.get("remediation", "None needed. Service is stable.")
                
                ip_map = {
                    "api-gateway": "192.168.1.42",
                    "auth-service": "192.168.1.105",
                    "db-primary": "192.168.1.220",
                    "payment-sys": "192.168.1.118",
                    "worker-queue": "192.168.1.199",
                    "primary-db": "192.168.1.220",
                    "celery-workers": "192.168.1.199"
                }
                ip_addr = ip_map.get(n["id"], "192.168.1.50")
                
                self.selected_node_info = {
                    "id": n["id"],
                    "name": n["label"],
                    "status": n["status"],
                    "ip": ip_addr,
                    "vulnerable": n["vulnerable"],
                    "remediation": remediation
                }
                break

    # 7. FORENSIC FILE DROPZONE HANDLER
    async def handle_upload(self, files: List[rx.UploadFile]):
        """
        Secures and saves uploaded Parquet files to the local /logs directory.
        Allows the Zero-Warehouse Coral engine to read and analyze them instantly.
        """
        # Resolve target directory relative to current directory
        project_root = os.getcwd()
        logs_dir = os.path.join(project_root, "logs")
        
        # Safe directory initialization
        if not os.path.exists(logs_dir):
            os.makedirs(logs_dir)
            
        for file in files:
            file_bytes = await file.read()
            # DEFENSE IN DEPTH: Use basename to prevent path traversal attempts
            safe_name = os.path.basename(file.filename)
            
            # Enforce .parquet files for CLI standard compatibility
            if not safe_name.endswith('.parquet') and not safe_name.endswith('.log'):
                self.agent_thought_log.append(f"⚠️ Blocked upload of {safe_name}. System accepts Parquet (.parquet) logs exclusively.")
                continue

            target_path = os.path.join(logs_dir, safe_name)
            
            # Secure file IO operation
            with open(target_path, "wb") as f:
                f.write(file_bytes)
                
            if safe_name not in self.uploaded_logs:
                self.uploaded_logs.append(safe_name)
                
            self.agent_thought_log.append(f"📁 Forensic Log mounted: {safe_name} -> Available inside Coral as local_file.read('/logs/{safe_name}')")

    def remove_log(self, filename: str):
        """Removes a log file from the state and the file system."""
        if filename in self.uploaded_logs:
            self.uploaded_logs.remove(filename)
        
        filepath = os.path.join("logs", filename)
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
                self.agent_thought_log.append(f"🗑️ Log unmounted: {filename}")
            except Exception as e:
                self.agent_thought_log.append(f"⚠️ Failed to remove {filename}: {str(e)}")

    @rx.event(background=True)
    async def run_predefined_playbook(self, prompt: str):
        """
        Loads quick playbooks directly into the user input and executes them immediately.
        """
        async with self:
            self.current_question = prompt
        return State.trigger_investigation

    def set_current_question(self, question: str):
        """
        Explicitly sets the current question state variable.
        Why? In Python 3.14, dynamic runtime class method generation behaves differently.
        Declaring this explicitly guarantees compatibility and avoids AttributeError exceptions.
        """
        self.current_question = question

    def set_github_token(self, val: str):
        self.github_token = val
        
    def set_github_owner(self, val: str):
        self.github_owner = val
        
    def set_github_repo_name(self, val: str):
        self.github_repo_name = val

    def toggle_github_token_input(self):
        self.show_github_token_input = True

    def set_notion_token(self, val: str):
        self.notion_token = val
    def toggle_notion_token_input(self):
        self.show_notion_token_input = True

    def set_jira_token(self, val: str):
        self.jira_token = val
    def toggle_jira_token_input(self):
        self.show_jira_token_input = True

    def set_slack_token(self, val: str):
        self.slack_token = val
    def toggle_slack_token_input(self):
        self.show_slack_token_input = True

    @rx.event(background=True)
    async def update_github_scope(self):
        """
        Updates the target repository scope in the environment and .env file independently of the API token connection.
        """
        import os, dotenv
        async with self:
            full_repo = f"{self.github_owner}/{self.github_repo_name}" if self.github_owner and self.github_repo_name else "Harshit7623/aegis-sre"
            os.environ["GITHUB_REPO"] = full_repo
            
            env_file = os.path.join(os.getcwd(), ".env")
            if not os.path.exists(env_file):
                open(env_file, 'a').close()
            dotenv.set_key(env_file, "GITHUB_REPO", full_repo)
            
            self.agent_thought_log.append(f"🔄 Updated target repository scope to: {full_repo}")

    @rx.event(background=True)
    async def connect_github(self):
        """
        Dynamically connects the GitHub API via Coral MCP based on user GUI input.
        """
        import subprocess, os
        import dotenv
        async with self:
            if not self.github_token:
                self.github_connection_status = "Error: Missing token"
                return
            self.github_connection_status = "Connecting..."
            token = self.github_token
            # Build full repo name
            full_repo = f"{self.github_owner}/{self.github_repo_name}" if self.github_owner and self.github_repo_name else "Harshit7623/aegis-sre"
            os.environ["GITHUB_REPO"] = full_repo
            os.environ["GITHUB_TOKEN"] = token
            
            # Permanently sync to .env file to survive restarts
            env_file = os.path.join(os.getcwd(), ".env")
            if not os.path.exists(env_file):
                open(env_file, 'a').close()
            dotenv.set_key(env_file, "GITHUB_TOKEN", token)
            dotenv.set_key(env_file, "GITHUB_REPO", full_repo)
            
        env = os.environ.copy()
        
        # Remove and re-add GitHub source via Coral CLI
        subprocess.run(["coral", "source", "remove", "github"], capture_output=True)
        res = subprocess.run(["coral", "source", "add", "github"], env=env, capture_output=True, text=True)
        
        async with self:
            if res.returncode == 0:
                self.github_connection_status = "Connected (Live)"
                self.show_github_token_input = False
                self.agent_thought_log.append(f"🔗 Connected live GitHub API (Target Repo: {full_repo})")
            else:
                self.github_connection_status = "Connection Failed"
                self.agent_thought_log.append(f"❌ Failed to connect GitHub: {res.stderr}")

    @rx.event(background=True)
    async def connect_notion(self):
        import subprocess, os, dotenv
        async with self:
            if not self.notion_token:
                self.notion_connection_status = "Error: Missing token"
                return
            self.notion_connection_status = "Connecting..."
            token = self.notion_token
            os.environ["NOTION_TOKEN"] = token
            env_file = os.path.join(os.getcwd(), ".env")
            if not os.path.exists(env_file): open(env_file, 'a').close()
            dotenv.set_key(env_file, "NOTION_TOKEN", token)
        env = os.environ.copy()
        subprocess.run(["coral", "source", "remove", "notion"], capture_output=True)
        res = subprocess.run(["coral", "source", "add", "notion"], env=env, capture_output=True, text=True)
        async with self:
            if res.returncode == 0:
                self.notion_connection_status = "Connected (Live)"
                self.show_notion_token_input = False
                self.agent_thought_log.append("🔗 Connected live Notion API")
            else:
                self.notion_connection_status = "Connection Failed"
                self.agent_thought_log.append(f"❌ Failed to connect Notion: {res.stderr}")

    @rx.event(background=True)
    async def connect_jira(self):
        import subprocess, os, dotenv
        async with self:
            if not self.jira_token:
                self.jira_connection_status = "Error: Missing token"
                return
            self.jira_connection_status = "Connecting..."
            token = self.jira_token
            os.environ["JIRA_API_TOKEN"] = token
            env_file = os.path.join(os.getcwd(), ".env")
            if not os.path.exists(env_file): open(env_file, 'a').close()
            dotenv.set_key(env_file, "JIRA_API_TOKEN", token)
        env = os.environ.copy()
        subprocess.run(["coral", "source", "remove", "jira"], capture_output=True)
        res = subprocess.run(["coral", "source", "add", "jira"], env=env, capture_output=True, text=True)
        async with self:
            if res.returncode == 0:
                self.jira_connection_status = "Connected (Live)"
                self.show_jira_token_input = False
                self.agent_thought_log.append("🔗 Connected live Jira API")
            else:
                self.jira_connection_status = "Connection Failed"
                self.agent_thought_log.append(f"❌ Failed to connect Jira: {res.stderr}")

    @rx.event(background=True)
    async def connect_slack(self):
        import subprocess, os, dotenv
        async with self:
            if not self.slack_token:
                self.slack_connection_status = "Error: Missing token"
                return
            self.slack_connection_status = "Connecting..."
            token = self.slack_token
            os.environ["SLACK_BOT_TOKEN"] = token
            env_file = os.path.join(os.getcwd(), ".env")
            if not os.path.exists(env_file): open(env_file, 'a').close()
            dotenv.set_key(env_file, "SLACK_BOT_TOKEN", token)
        env = os.environ.copy()
        subprocess.run(["coral", "source", "remove", "slack"], capture_output=True)
        res = subprocess.run(["coral", "source", "add", "slack"], env=env, capture_output=True, text=True)
        async with self:
            if res.returncode == 0:
                self.slack_connection_status = "Connected (Live)"
                self.show_slack_token_input = False
                self.agent_thought_log.append("🔗 Connected live Slack API")
            else:
                self.slack_connection_status = "Connection Failed"
                self.agent_thought_log.append(f"❌ Failed to connect Slack: {res.stderr}")

    @rx.event(background=True)
    async def check_coral_connections(self):
        """
        Dynamically queries Coral CLI to determine exactly which APIs are mounted.
        This provides a true source of truth rather than blindly relying on environment files.
        """
        import subprocess
        try:
            res = subprocess.run(["coral", "source", "list"], capture_output=True, text=True)
            output = res.stdout
            
            async with self:
                if "\ngithub " in output or "^github " in output or "github " in output:
                    self.github_connection_status = "Connected (Live)"
                    self.show_github_token_input = False
                else:
                    self.github_connection_status = "Not Connected"
                    self.show_github_token_input = True
                    
                if "\nosv " in output or "^osv " in output or "osv " in output:
                    self.osv_connection_status = "Connected (Mock Parquet)"
                else:
                    self.osv_connection_status = "Not Connected"

                if "\nnotion " in output or "^notion " in output or "notion " in output:
                    self.notion_connection_status = "Connected (Live)"
                    self.show_notion_token_input = False
                else:
                    self.notion_connection_status = "Not Connected"
                    self.show_notion_token_input = True

                if "\njira " in output or "^jira " in output or "jira " in output:
                    self.jira_connection_status = "Connected (Live)"
                    self.show_jira_token_input = False
                else:
                    self.jira_connection_status = "Not Connected"
                    self.show_jira_token_input = True

                if "\nslack " in output or "^slack " in output or "slack " in output:
                    self.slack_connection_status = "Connected (Live)"
                    self.show_slack_token_input = False
                else:
                    self.slack_connection_status = "Not Connected"
                    self.show_slack_token_input = True
        except Exception:
            async with self:
                self.github_connection_status = "Connection Error"
                self.osv_connection_status = "Connection Error"
                self.notion_connection_status = "Connection Error"
                self.jira_connection_status = "Connection Error"
                self.slack_connection_status = "Connection Error"

    def handle_key_down(self, key: str):
        """
        Handles keyboard entries inside the triage console.
        If 'Enter' is typed, it delegates to the core investigation background task.
        """
        if key == "Enter" and not self.is_investigating:
            return State.trigger_investigation

    def _parse_query_impact(self, dataset: List[Dict[str, Any]]):
        """
        Mock logic for demo: Scans the raw SQL query results for vulnerability references.
        If found, mutates specific connected nodes to "Degraded" statuses inside the Reflex memory model.
        """
        if not dataset or not self.demo_mode:
            return
            
        self.agent_thought_log.append(f"[ANALYSIS] Analyzing {len(dataset)} query records to calculate blast radius topology...")
        
        # Simple threat matching logic
        has_vulnerability = False
        vulnerable_pkg = ""
        cve_id = ""
        
        for row in dataset:
            # Check if dataset contains vulnerability reports
            if "cve" in row or "vulnerable_version_range" in row:
                has_vulnerability = True
                vulnerable_pkg = row.get("package_name", "unknown")
                cve_id = row.get("cve", "CVE-UNKNOWN")
                break
                
        if has_vulnerability:
            # Dynamic topology mutation: Flag Auth Service and API gateway as degraded due to package mismatch
            mutated_nodes = []
            for node in self.blast_radius_nodes:
                mutated = node.copy()
                if node["id"] == "api-gateway":
                    mutated["status"] = "Degraded"
                    mutated["vulnerable"] = f"{vulnerable_pkg} ({cve_id})"
                elif node["id"] == "auth-service":
                    mutated["status"] = "Degraded"
                    mutated["vulnerable"] = f"{vulnerable_pkg} ({cve_id})"
                mutated_nodes.append(mutated)
                
            self.blast_radius_nodes = mutated_nodes
            self.agent_thought_log.append("[ALERT] Threat Topology updated. API Gateway and Auth Service flag vulnerability alert!")


# ==========================================
# UI COMPONENTS (VIBRANT CYBERPUNK GLASSMORPHISM)
# ==========================================

def header() -> rx.Component:
    """
    Top Navigation Dashboard Header. Shows platform online status indicators.
    """
    return rx.flex(
        rx.hstack(
            # Premium glowing emblem
            rx.box(
                rx.image(src="/aegis_logo.png", width="30px", height="30px"),
                style={"filter": "drop-shadow(0 0 8px #FF6F61)"}
            ),
            rx.vstack(
                rx.heading("AEGIS SRE", size="5", color="white", font_family="Inter", font_weight="700"),
                rx.text("Zero-Warehouse Federated Forensics", size="1", color="rgba(255, 255, 255, 0.5)", font_family="Inter"),
                spacing="0"
            ),
            align="center",
            spacing="3"
        ),
        rx.spacer(),
        rx.hstack(
            # Platform state badge
            rx.box(
                rx.hstack(
                    rx.box(
                        style={
                            "width": "8px",
                            "height": "8px",
                            "background_color": "#00F2FE",
                            "border_radius": "50%",
                            "animation": "pulse 2s infinite"
                        }
                    ),
                    rx.text("AEGIS CORE ACTIVE", font_size="10px", color="#00F2FE", font_weight="600", font_family="JetBrains Mono"),
                    align="center",
                    spacing="2"
                ),
                padding="4px 10px",
                border="1px solid rgba(0, 242, 254, 0.2)",
                background_color="rgba(0, 242, 254, 0.05)",
                border_radius="20px",
            ),
            # Latency metric
            rx.text("LATENCY: <120ms", font_size="10px", color="rgba(255, 255, 255, 0.4)", font_family="JetBrains Mono"),
            align="center",
            spacing="4"
        ),
        position="fixed",
        top="0",
        left="0",
        right="0",
        z_index="10",
        width="100%",
        padding="15px 25px 30px 25px",
        background="linear-gradient(to bottom, #050508 0%, rgba(5, 5, 8, 0.95) 45%, rgba(5, 5, 8, 0.7) 70%, rgba(5, 5, 8, 0) 100%)",
        backdrop_filter="blur(12px)",
        align="center"
    )


def integrations_dialog() -> rx.Component:
    return rx.dialog.root(
        rx.dialog.trigger(
            rx.button("🔌 Manage Data Integrations", width="100%", size="2", variant="outline", color_scheme="teal")
        ),
        rx.dialog.content(
            rx.dialog.title("Data Integrations"),
            rx.dialog.description("Manage connections to external Zero-Warehouse sources."),
            rx.vstack(
                # GitHub Integration Card
                rx.card(
                    rx.vstack(
                        rx.hstack(
                            rx.text("GitHub API", weight="bold"),
                            rx.badge(State.github_connection_status, color_scheme=rx.cond(State.github_connection_status == "Connected (Live)", "green", "orange")),
                            justify="between", width="100%"
                        ),
                        rx.cond(
                            State.show_github_token_input,
                            rx.vstack(
                                rx.text("1. Authenticate with a Personal Access Token (One-time connection).", size="1", color="gray"),
                                rx.input(placeholder="GitHub Token (ghp_...)", on_change=State.set_github_token, type="password", width="100%"),
                                rx.button("Connect API", on_click=State.connect_github, color_scheme="ruby", variant="soft", width="100%"),
                                width="100%",
                                spacing="2"
                            ),
                            rx.button("Update Token", on_click=State.toggle_github_token_input, color_scheme="gray", variant="outline", size="1", width="100%")
                        ),
                        
                        rx.divider(margin_y="10px"),
                        rx.text("2. Target Repository Scope:", size="2", font_weight="bold"),
                        rx.text("All workings will use this default repository unless overridden in the prompt.", size="1", color="gray"),
                        rx.hstack(
                            rx.input(placeholder="Username (e.g. dev-user)", on_change=State.set_github_owner, width="50%"),
                            rx.input(placeholder="Repository (e.g. seat-allocation-sys)", on_change=State.set_github_repo_name, width="50%"),
                            width="100%"
                        ),
                        rx.button("Update Scope", on_click=State.update_github_scope, color_scheme="indigo", variant="soft", size="1", width="100%"),
                        spacing="3",
                        width="100%"
                    ),
                    width="100%"
                ),
                # OSV Database Card
                rx.card(
                    rx.hstack(
                        rx.text("OSV Vulnerabilities", weight="bold"),
                        rx.badge(State.osv_connection_status, color_scheme="green"),
                        justify="between", width="100%"
                    ),
                    width="100%"
                ),
                # Notion Card
                rx.card(
                    rx.vstack(
                        rx.hstack(
                            rx.text("Notion Workspace", weight="bold"),
                            rx.badge(State.notion_connection_status, color_scheme=rx.cond(State.notion_connection_status == "Connected (Live)", "green", "orange")),
                            justify="between", width="100%"
                        ),
                        rx.cond(
                            State.show_notion_token_input,
                            rx.vstack(
                                rx.text("Authenticate with an Internal Integration Token.", size="1", color="gray"),
                                rx.input(placeholder="Notion Secret (secret_...)", on_change=State.set_notion_token, type="password", width="100%"),
                                rx.button("Connect API", on_click=State.connect_notion, color_scheme="ruby", variant="soft", width="100%"),
                                width="100%", spacing="2"
                            ),
                            rx.button("Update Token", on_click=State.toggle_notion_token_input, color_scheme="gray", variant="outline", size="1", width="100%")
                        ),
                    ),
                    width="100%"
                ),
                # Jira Card
                rx.card(
                    rx.vstack(
                        rx.hstack(
                            rx.text("Atlassian Jira", weight="bold"),
                            rx.badge(State.jira_connection_status, color_scheme=rx.cond(State.jira_connection_status == "Connected (Live)", "green", "orange")),
                            justify="between", width="100%"
                        ),
                        rx.cond(
                            State.show_jira_token_input,
                            rx.vstack(
                                rx.text("Authenticate with an Atlassian API Token.", size="1", color="gray"),
                                rx.input(placeholder="Jira Token", on_change=State.set_jira_token, type="password", width="100%"),
                                rx.button("Connect API", on_click=State.connect_jira, color_scheme="ruby", variant="soft", width="100%"),
                                width="100%", spacing="2"
                            ),
                            rx.button("Update Token", on_click=State.toggle_jira_token_input, color_scheme="gray", variant="outline", size="1", width="100%")
                        ),
                    ),
                    width="100%"
                ),
                # Slack Card
                rx.card(
                    rx.vstack(
                        rx.hstack(
                            rx.text("Slack Enterprise", weight="bold"),
                            rx.badge(State.slack_connection_status, color_scheme=rx.cond(State.slack_connection_status == "Connected (Live)", "green", "orange")),
                            justify="between", width="100%"
                        ),
                        rx.cond(
                            State.show_slack_token_input,
                            rx.vstack(
                                rx.text("Authenticate with a Slack Bot Token.", size="1", color="gray"),
                                rx.input(placeholder="Slack Token (xoxb-...)", on_change=State.set_slack_token, type="password", width="100%"),
                                rx.button("Connect API", on_click=State.connect_slack, color_scheme="ruby", variant="soft", width="100%"),
                                width="100%", spacing="2"
                            ),
                            rx.button("Update Token", on_click=State.toggle_slack_token_input, color_scheme="gray", variant="outline", size="1", width="100%")
                        ),
                    ),
                    width="100%"
                ),
                spacing="4",
                width="100%",
                margin_top="15px"
            ),
            rx.dialog.close(
                rx.button("Done", margin_top="20px", width="100%", variant="soft")
            ),
            max_width="600px"
        )
    )

def how_to_use_dialog() -> rx.Component:
    """
    Interactive floating guide modal helping new operators understand how to use Aegis SRE.
    """
    return rx.dialog.root(
        rx.dialog.trigger(
            rx.button(
                "❓ How to Use Guide",
                position="fixed",
                bottom="20px",
                right="20px",
                z_index="1000",
                background_color="rgba(153, 84, 222, 0.2)",
                border="1px solid #9954de",
                color="white",
                font_family="JetBrains Mono",
                font_size="11px",
                padding="10px 16px",
                border_radius="30px",
                backdrop_filter="blur(8px)",
                _hover={
                    "background_color": "rgba(153, 84, 222, 0.4)",
                    "box_shadow": "0 0 15px rgba(153, 84, 222, 0.4)",
                    "cursor": "pointer"
                }
            )
        ),
        rx.dialog.content(
            rx.dialog.title(
                rx.hstack(
                    rx.image(src="/aegis_logo.png", width="24px", height="24px"),
                    rx.text("AEGIS SRE OPERATOR PLAYBOOK", font_family="JetBrains Mono", letter_spacing="0.1em"),
                    align="center",
                    spacing="2"
                )
            ),
            rx.dialog.description(
                "Follow this exact step-by-step operational sequence to run Zero-Warehouse forensics and patch microservices successfully."
            ),
            rx.vstack(
                rx.divider(margin_y="10px", border_color="rgba(255,255,255,0.08)"),
                
                # Step 1
                rx.hstack(
                    rx.badge("01", color_scheme="purple", font_family="JetBrains Mono"),
                    rx.vstack(
                        rx.text("Mount Log Source (Required)", font_weight="bold", size="2"),
                        rx.text("Vulnerability scans require active system data. Drag and drop your '.parquet' log database into the FORENSIC CONTROL dropzone in the left panel.", size="1", color="rgba(255,255,255,0.6)"),
                        align="start",
                        spacing="0"
                    ),
                    spacing="3",
                    align="start",
                    width="100%"
                ),
                
                # Step 2
                rx.hstack(
                    rx.badge("02", color_scheme="purple", font_family="JetBrains Mono"),
                    rx.vstack(
                        rx.text("Select SRE Playbook", font_weight="bold", size="2"),
                        rx.text("Click any diagnostic script in the left panel (e.g., 'Zero-Warehouse RCA') to let the agent compile multi-hop joins across OSV logs and GitHub commits.", size="1", color="rgba(255,255,255,0.6)"),
                        align="start",
                        spacing="0"
                    ),
                    spacing="3",
                    align="start",
                    width="100%"
                ),
                
                # Step 3
                rx.hstack(
                    rx.badge("03", color_scheme="purple", font_family="JetBrains Mono"),
                    rx.vstack(
                        rx.text("Conversational Triage", font_weight="bold", size="2"),
                        rx.text("Use the natural language Chat Console in the middle column to ask questions. Read the 'Agent Cognitive Log Stream' (terminal panel) to audit its live query reasoning.", size="1", color="rgba(255,255,255,0.6)"),
                        align="start",
                        spacing="0"
                    ),
                    spacing="3",
                    align="start",
                    width="100%"
                ),
                
                # Step 4
                rx.hstack(
                    rx.badge("04", color_scheme="purple", font_family="JetBrains Mono"),
                    rx.vstack(
                        rx.text("Analyze Blast Radius Topology", font_weight="bold", size="2"),
                        rx.text("Observe the right-side dependency graph. SRE color-codes nodes instantly: Green (Healthy), Red (Degraded), or Purple (Source of the incident).", size="1", color="rgba(255,255,255,0.6)"),
                        align="start",
                        spacing="0"
                    ),
                    spacing="3",
                    align="start",
                    width="100%"
                ),
                
                # Step 5
                rx.hstack(
                    rx.badge("05", color_scheme="purple", font_family="JetBrains Mono"),
                    rx.vstack(
                        rx.text("Audit Service Node Details", font_weight="bold", size="2"),
                        rx.text("Tap any node in the SVG topology map to view active CVE vulnerabilities, system state parameters, and the recommended patch playbook in the Inspector Details sidebar.", size="1", color="rgba(255,255,255,0.6)"),
                        align="start",
                        spacing="0"
                    ),
                    spacing="3",
                    align="start",
                    width="100%"
                ),
                
                # Step 6
                rx.hstack(
                    rx.badge("06", color_scheme="purple", font_family="JetBrains Mono"),
                    rx.vstack(
                        rx.text("Dispatch Automated Hot-Patch", font_weight="bold", size="2"),
                        rx.text("Click the deep-purple 'Investigate' button inside the Chat Console to dispatch hot-patch workflows (e.g. n8n workflow triggers) to automatically isolate and resolve the issue.", size="1", color="rgba(255,255,255,0.6)"),
                        align="start",
                        spacing="0"
                    ),
                    spacing="3",
                    align="start",
                    width="100%"
                ),
                
                rx.divider(margin_y="10px", border_color="rgba(255,255,255,0.08)"),
                
                rx.dialog.close(
                    rx.button(
                        "Understood, Start Operations", 
                        width="100%", 
                        color_scheme="purple",
                        font_family="Inter",
                        font_weight="600"
                    )
                ),
                spacing="4",
                align="stretch",
                width="100%"
            ),
            style={
                "background_color": "#09090d",
                "border": "1px solid rgba(153, 84, 222, 0.2)",
                "color": "white",
                "max_width": "500px",
                "font_family": "Inter"
            }
        )
    )


def sidebar_forensics() -> rx.Component:
    """
    Left Sidebar: Drag & Drop zone for Parquet files and incident response playbook shortcuts.
    """
    return rx.vstack(
        rx.heading("FORENSIC CONTROL", size="3", color="white", font_family="Inter", font_weight="600"),
        rx.text("Ingest local database Parquet chunks dynamically into memory paths.", size="1", color="rgba(255,255,255,0.4)", margin_bottom="15px"),

        # 1. DASHDROPZONE COMPONENT
        rx.upload(
            rx.vstack(
                rx.text("📥 Drag Parquet Logs Here", font_size="12px", font_weight="600", color="rgba(255, 255, 255, 0.8)", font_family="Inter"),
                rx.text("Supports (.parquet) formats", font_size="10px", color="rgba(255,255,255,0.4)", font_family="Inter"),
                padding="25px 15px",
                align="center",
                spacing="1"
            ),
            id="parquet_upload",
            border="2px dashed rgba(255, 255, 255, 0.1)",
            border_radius="10px",
            background_color="rgba(255,255,255,0.02)",
            on_drop=State.handle_upload(rx.upload_files(upload_id="parquet_upload")),
            width="100%",
            cursor="pointer",
            _hover={"border_color": ACCENT_CORAL, "background_color": "rgba(255, 111, 97, 0.02)"}
        ),

        # 2. UPLOADED MANIFESTS
        rx.text("MOUNTED LOG SOURCES", font_size="10px", font_weight="600", color="rgba(255,255,255,0.6)", margin_top="15px", font_family="JetBrains Mono"),
        rx.cond(
            State.uploaded_logs.length() > 0,
            rx.vstack(
                rx.foreach(
                    State.uploaded_logs,
                    lambda log_name: rx.hstack(
                        rx.text("📄", font_size="12px"),
                        rx.text(log_name, font_size="11px", color="rgba(255,255,255,0.8)", overflow="hidden", text_overflow="ellipsis", font_family="JetBrains Mono"),
                        rx.spacer(),
                        rx.icon(
                            "trash",
                            size=14,
                            color="rgba(255, 111, 97, 0.8)",
                            cursor="pointer",
                            on_click=lambda: State.remove_log(log_name),
                            _hover={"color": "red"}
                        ),
                        width="100%",
                        padding="6px 10px",
                        align="center",
                        background_color="rgba(255,255,255,0.03)",
                        border_radius="6px",
                        border="1px solid rgba(255,255,255,0.05)"
                    )
                ),
                width="100%",
                spacing="2"
            ),
            rx.text("No active server logs mounted in /logs path.", font_size="11px", color="rgba(255,255,255,0.3)", font_style="italic")
        ),

        rx.divider(border_color="rgba(255,255,255,0.05)", margin_y="15px"),

        # 3. FORENSIC PLAYBOOKS
        rx.button(
            rx.hstack(
                rx.heading("FORENSIC PLAYBOOKS", size="2", color="white", font_family="Inter", font_weight="600"),
                rx.spacer(),
                rx.icon(rx.cond(State.show_playbooks, "chevron-up", "chevron-down"), color="rgba(255,255,255,0.4)"),
                width="100%", align="center"
            ),
            on_click=State.toggle_playbooks,
            variant="ghost", width="100%", padding="0", _hover={"background_color": "transparent"},
            cursor="pointer"
        ),
        rx.text("Automated multi-hop preloaded query scripts.", size="1", color="rgba(255,255,255,0.4)", margin_bottom="10px"),
        
        rx.cond(
            State.show_playbooks,
            rx.vstack(
                rx.button(
                    "🔍 Infrastructure Vulnerability Scan",
                    on_click=State.run_predefined_playbook("Scan all mounted .parquet logs and identify matching package vulnerabilities from the osv.packages database."),
                    width="100%",
                    variant="outline",
                    color_scheme="teal",
                    size="1",
                    font_family="Inter",
                    justify="start",
                    opacity=rx.cond(State.uploaded_logs.length() > 0, "1.0", "0.4"),
                    cursor=rx.cond(State.uploaded_logs.length() > 0, "pointer", "not-allowed"),
                    disabled=rx.cond(State.uploaded_logs.length() > 0, False, True)
                ),
                rx.button(
                    "🐙 Commit Anomaly Check",
                    on_click=State.run_predefined_playbook(f"Audit recent commits from author {State.github_owner} in the {State.github_repo_name} repository. Identify recent code velocity and flag any abnormal patterns."),
                    width="100%",
                    variant="outline",
                    color_scheme="indigo",
                    size="1",
                    font_family="Inter",
                    justify="start"
                ),
                rx.button(
                    "⚡ Zero-Warehouse RCA",
                    on_click=State.run_predefined_playbook(f"Execute multi-hop SQL JOIN between server logs, OSV vulnerabilities, and {State.github_owner}'s GitHub commits to find the exact root cause."),
                    width="100%",
                    variant="outline",
                    color_scheme="orange",
                    size="1",
                    font_family="Inter",
                    justify="start",
                    opacity=rx.cond(State.uploaded_logs.length() > 0, "1.0", "0.4"),
                    cursor=rx.cond(State.uploaded_logs.length() > 0, "pointer", "not-allowed"),
                    disabled=rx.cond(State.uploaded_logs.length() > 0, False, True)
                ),
                rx.cond(
                    State.uploaded_logs.length() == 0,
                    rx.text("⚠️ Ingestion required for active playbook scripts.", size="1", color="#ffbd2e", font_style="italic", margin_top="5px")
                ),
                width="100%",
                spacing="3",
            )
        ),
        
        rx.divider(border_color="rgba(255,255,255,0.05)", margin_y="15px"),

        # 4. API INTEGRATIONS
        integrations_dialog(),

        width="100%",
        padding="95px 20px 20px 20px",
        height="100vh",
        background_color="rgba(14, 13, 18, 0.5)",
        border_right="1px solid rgba(255,255,255,0.05)",
        overflow_y="auto"
    )


def chat_console() -> rx.Component:
    """
    Middle Panel: Natural Language Chat Console for incident triage.
    Includes the collapsible Agent Thought Stream panel.
    """
    return rx.vstack(
        # 1. ACTIVE CONVERSATION SHELF
        rx.box(
            rx.vstack(
                rx.foreach(
                    State.chat_history,
                    lambda msg: rx.box(
                        rx.vstack(
                            rx.hstack(
                                rx.cond(
                                    msg["role"] == "user",
                                    rx.text("OPERATOR", font_size="10px", font_weight="700", font_family="JetBrains Mono", color=ACCENT_CYAN),
                                    rx.hstack(
                                        rx.image(src="/aegis_logo.png", width="14px", height="14px"),
                                        rx.text("AEGIS AGENT", font_size="10px", font_weight="700", font_family="JetBrains Mono", color="#9954de"),
                                        align="center",
                                        spacing="2"
                                    )
                                ),
                                rx.spacer(),
                                align="center",
                                width="100%"
                            ),
                            rx.markdown(
                                msg["content"],
                                style={
                                    "font_family": "Inter",
                                    "font_size": "13px",
                                    "color": "rgba(255, 255, 255, 0.95)",
                                    "line_height": "1.6"
                                }
                            ),
                            spacing="2",
                            align="start"
                        ),
                        padding="15px",
                        border_radius="10px",
                        border="1px solid",
                        border_color=rx.cond(msg["role"] == "user", "rgba(0, 242, 254, 0.1)", "rgba(255, 111, 97, 0.1)"),
                        background=rx.cond(msg["role"] == "user", "rgba(0, 242, 254, 0.02)", "rgba(255, 111, 97, 0.02)"),
                        width="100%"
                    )
                ),
                spacing="4",
                width="100%"
            ),
            flex="1",
            width="100%",
            overflow_y="auto",
            padding="20px",
            height="calc(100vh - 350px)",
        ),

        # 2. AGENT COGNITIVE THOUGHT LOG (Terminal-style scrolling box)
        rx.vstack(
            rx.hstack(
                rx.box(
                    style={
                        "width": "6px",
                        "height": "6px",
                        "background_color": ACCENT_CYAN,
                        "border_radius": "50%",
                        "animation": rx.cond(State.is_investigating, "pulse 1.5s infinite", "none")
                    }
                ),
                rx.text("AGENT COGNITIVE LOG STREAM (REAL-TIME)", font_size="10px", font_weight="700", color=ACCENT_CYAN, font_family="JetBrains Mono"),
                rx.spacer(),
                rx.cond(
                    State.is_investigating,
                    rx.text("Reasoning and Joining...", font_size="10px", color="rgba(255,255,255,0.4)", font_style="italic"),
                    rx.text("Idle", font_size="10px", color="rgba(255,255,255,0.3)")
                ),
                align="center",
                width="100%",
                padding="6px 12px",
                border_bottom="1px solid rgba(255, 183, 3, 0.1)",
                background_color="rgba(255, 183, 3, 0.03)"
            ),
            rx.box(
                rx.vstack(
                    rx.foreach(
                        State.agent_thought_log,
                        lambda log_line: rx.text(
                            log_line,
                            font_size="11px",
                            color="#ECEFF1",
                            font_family="JetBrains Mono",
                            white_space="pre-wrap",
                            margin_bottom="4px"
                        )
                    ),
                    spacing="0",
                    width="100%"
                ),
                padding="12px",
                height="130px",
                overflow_y="auto",
                width="100%"
            ),
            width="100%",
            background_color="#050508",
            border="1px solid rgba(0, 242, 254, 0.15)",
            border_radius="8px",
            margin_bottom="15px"
        ),

        # 3. CHAT INPUT SHELF
        rx.hstack(
            rx.input(
                placeholder="Describe incident or request a forensic investigation...",
                value=State.current_question,
                on_change=State.set_current_question,
                on_key_down=State.handle_key_down,
                style={
                    "background_color": "rgba(255,255,255,0.03)",
                    "border": "1px solid rgba(255,255,255,0.1)",
                    "color": "white",
                    "border_radius": "8px",
                    "font_family": "Inter",
                    "font_size": "13px",
                    "padding_left": "15px",
                    "padding_right": "15px",
                    "height": "45px",
                    "box_sizing": "border-box"
                },
                flex="1",
                width="100%",
                disabled=State.is_investigating
            ),
            rx.button(
                rx.cond(State.is_investigating, rx.spinner(size="1"), "Investigate"),
                on_click=State.trigger_investigation(),
                background_color="#9954de",
                color="white",
                font_family="Inter",
                font_weight="600",
                border_radius="8px",
                padding="10px 20px",
                _hover={"background_color": "#b073f4"},
                disabled=State.is_investigating
            ),
            width="100%",
            spacing="3",
            padding_top="10px",
            border_top="1px solid rgba(255,255,255,0.05)"
        ),
        width="100%",
        padding="95px 20px 20px 20px",
        height="100vh",
        align="stretch"
    )


def threat_intelligence() -> rx.Component:
    """
    Right Panel: Blast Radius dynamic SVG Graph and detailed node inspection.
    """
    return rx.vstack(
        # Client-side 120Hz High-Fidelity SVG zoom & pan controller script
        rx.script("""
            function initSVGZoomPan() {
                const svg = document.querySelector('.zoom-svg-container');
                if (!svg || svg.dataset.zoomBound) return;
                svg.dataset.zoomBound = 'true';

                const g = svg.querySelector('.zoom-g-container');
                if (!g) return;

                let scale = 1;
                let translateX = 0;
                let translateY = 0;
                let isDragging = false;
                let startX = 0;
                let startY = 0;

                g.style.transformOrigin = '150px 150px';
                g.style.transition = 'transform 0.05s ease-out';

                svg.addEventListener('wheel', e => {
                    e.preventDefault();
                    const zoomIntensity = 0.04;
                    const delta = e.deltaY < 0 ? 1 : -1;
                    const nextScale = scale + delta * zoomIntensity;
                    
                    if (nextScale >= 0.6 && nextScale <= 3.5) {
                        scale = nextScale;
                        g.style.transform = `translate(${translateX}px, ${translateY}px) scale(${scale})`;
                    }
                }, { passive: false });

                svg.addEventListener('mousedown', e => {
                    // Only start drag if clicking background, not interactive node
                    if (e.target.closest('g') && e.target.closest('g').style.cursor === 'pointer') return;
                    isDragging = true;
                    startX = e.clientX - translateX;
                    startY = e.clientY - translateY;
                    svg.style.cursor = 'grabbing';
                });

                window.addEventListener('mousemove', e => {
                    if (!isDragging) return;
                    translateX = e.clientX - startX;
                    translateY = e.clientY - startY;
                    g.style.transform = `translate(${translateX}px, ${translateY}px) scale(${scale})`;
                });

                window.addEventListener('mouseup', () => {
                    if (isDragging) {
                        isDragging = false;
                        svg.style.cursor = 'grab';
                    }
                });

                svg.style.cursor = 'grab';
                svg.style.userSelect = 'none';
            }

            document.addEventListener('DOMContentLoaded', initSVGZoomPan);
            setInterval(initSVGZoomPan, 500);
        """),
        rx.heading("BLAST RADIUS TOPOLOGY", size="3", color="white", font_family="Inter", font_weight="600"),
        rx.text("Real-time telemetry dependencies and isolated network compromised paths.", size="1", color="rgba(255,255,255,0.4)", margin_bottom="15px"),

        # 1. NATIVE SVG REACTIVE GRAPH NODE CONTAINER
        # SVG coordinates map directly to reactive coordinate values from State.blast_radius_nodes.
        # Renders interactive glowing vectors at 60fps.
        rx.box(
            rx.el.svg(
                rx.el.g(
                    # A. DRAW EDGES / NETWORKING CHANNELS
                    rx.foreach(
                        State.computed_edges,
                        lambda edge: rx.el.line(
                            x1=edge["x1"],
                            y1=edge["y1"],
                            x2=edge["x2"],
                            y2=edge["y2"],
                            stroke="rgba(255, 255, 255, 0.15)",
                            stroke_width="1.5",
                            stroke_dasharray="4,4"
                        )
                    ),
                    
                    # B. DRAW NODE GLOWS & LABELS
                    rx.foreach(
                        State.blast_radius_nodes,
                        lambda node: rx.el.g(
                            # Outer neon glow circle with direct CSS filter drop-shadow
                            rx.el.circle(
                                cx=node["x"],
                                cy=node["y"],
                                r=12,
                                fill=rx.cond(node["status"] == "Healthy", "rgba(39, 201, 63, 0.15)", rx.cond(node["status"] == "Source", "rgba(157, 78, 221, 0.15)", "rgba(255, 107, 107, 0.15)")),
                                stroke=rx.cond(node["status"] == "Healthy", "#27c93f", rx.cond(node["status"] == "Source", ACCENT_PURPLE, ACCENT_CORAL)),
                                stroke_width="2",
                                style={
                                    "filter": rx.cond(
                                        node["status"] == "Healthy",
                                        "drop-shadow(0 0 5px #27c93f)",
                                        rx.cond(node["status"] == "Source", "none", "drop-shadow(0 0 5px #ff6b6b)")
                                    )
                                }
                            ),
                            # Inner core circle
                            rx.el.circle(
                                cx=node["x"],
                                cy=node["y"],
                                r=5,
                                fill="white"
                            ),
                            # Text Labels
                            rx.el.text(
                                node["label"],
                                x=node["x"],
                                y=node["y"],
                                dy="-18",
                                text_anchor="middle",
                                fill="rgba(255,255,255,0.8)",
                                font_size="9px",
                                font_family="JetBrains Mono",
                                font_weight="600"
                            ),
                            # Status pill subtext
                            rx.el.text(
                                node["status"],
                                x=node["x"],
                                y=node["y"],
                                dy="22",
                                text_anchor="middle",
                                fill=rx.cond(node["status"] == "Healthy", "#27c93f", rx.cond(node["status"] == "Source", ACCENT_PURPLE, ACCENT_CORAL)),
                                font_size="7px",
                                font_family="JetBrains Mono",
                                font_weight="700"
                            ),
                            # Clicking a node updates the focus details panels in real-time
                            on_click=lambda: State.select_node(node["id"]),
                            style={"cursor": "pointer"}
                        )
                    ),
                    class_name="zoom-g-container"
                ),
                class_name="zoom-svg-container",
                width="100%",
                height="100%",
                view_box="0 0 300 300"
            ),
            width="100%",
            height="260px",
            border="1px solid rgba(255, 255, 255, 0.05)",
            border_radius="10px",
            background_color="rgba(10, 10, 12, 0.5)",
            margin_bottom="20px",
            overflow="hidden"
        ),

        # 2. INTEL NODE INSPECTOR DETAILS SHELF
        rx.heading("INSPECTOR DETAILS", size="2", color="white", font_family="Inter", font_weight="600"),
        rx.box(
            rx.cond(
                State.selected_node_info.keys().length() > 0,
                rx.vstack(
                    rx.hstack(
                        rx.text("Service Name:", font_size="11px", color="rgba(255,255,255,0.4)", font_family="Inter", width="90px"),
                        rx.text(State.selected_node_info["name"], font_size="12px", color="white", font_weight="600", font_family="Inter"),
                        align="center"
                    ),
                    rx.hstack(
                        rx.text("Cluster IP:", font_size="11px", color="rgba(255,255,255,0.4)", font_family="Inter", width="90px"),
                        rx.text(State.selected_node_info["ip"], font_size="11px", color="#ECEFF1", font_family="JetBrains Mono"),
                        align="center"
                    ),
                    rx.hstack(
                        rx.text("Health status:", font_size="11px", color="rgba(255,255,255,0.4)", font_family="Inter", width="90px"),
                        rx.badge(
                            State.selected_node_info["status"],
                            color_scheme=rx.cond(State.selected_node_info["status"] == "Healthy", "green", rx.cond(State.selected_node_info["status"] == "Source", "purple", "red")),
                            variant="soft"
                        ),
                        align="center"
                    ),
                    rx.hstack(
                        rx.text("Detected Bug:", font_size="11px", color="rgba(255,255,255,0.4)", font_family="Inter", width="90px"),
                        rx.text(State.selected_node_info["vulnerable"], font_size="11px", color=rx.cond(State.selected_node_info["vulnerable"] == "None", "rgba(255,255,255,0.6)", ACCENT_CORAL), font_weight="500", font_family="JetBrains Mono"),
                        align="center"
                    ),
                    rx.divider(border_color="rgba(255,255,255,0.05)", margin_y="5px"),
                    rx.vstack(
                        rx.text("Remediation playbook:", font_size="10px", color="rgba(255,255,255,0.4)", font_weight="700", font_family="JetBrains Mono"),
                        rx.text(State.selected_node_info["remediation"], font_size="11px", color="#A2E3C4", font_family="Inter", line_height="1.5"),
                        align="start",
                        spacing="1"
                    ),
                    align="stretch",
                    spacing="2",
                    width="100%"
                ),
                rx.text("Tap a dynamic topology node above to audit telemetry details.", font_size="11px", color="rgba(255,255,255,0.3)", font_style="italic")
            ),
            padding="15px",
            border="1px solid rgba(255,255,255,0.05)",
            border_radius="10px",
            background_color="rgba(255, 255, 255, 0.02)",
            width="100%"
        ),
        
        width="100%",
        padding="95px 20px 20px 20px",
        height="100vh",
        background_color="rgba(14, 13, 18, 0.5)",
        border_left="1px solid rgba(255,255,255,0.05)",
        overflow_y="auto"
    )


# ==========================================
# LANDING PAGE (FUI Gate)
# ==========================================

def landing_data_stream() -> rx.Component:
    """Decorative scrolling code text for the landing page sides."""
    code_lines = (
        "import aegis.core.forensics\n"
        "from sre_brain import SREBrain\n"
        "coral.execute(query='SELECT * FROM github.commits')\n"
        "topology.update_nodes(scan_repo=True)\n"
        "brain.run_investigation_loop(prompt, history)\n"
        "for step in brain.run_gemini_native_loop(q):\n"
        "    yield {'type': 'tool_result', ...}\n"
        "blast_radius.compute_edges(node_map)\n"
        "n8n.trigger_workflow(payload={'service': 'api'})\n"
        "osv.scan_dependencies(lockfile='poetry.lock')\n"
        "forensics.upload_parquet(sandbox='/logs')\n"
        "graph.render_svg(viewbox=state.svg_view_box)\n"
        "state.agent_thought_log.append('[SYSTEM] Scan complete')\n"
        "telemetry.stream(protocol='websocket', fps=60)\n"
    )
    return rx.el.div(
        rx.text(code_lines * 4, white_space="pre", font_size="10px", line_height="1.7"),
        class_name="data-stream",
        position="absolute",
        height="200%",
        width="200px",
        overflow="hidden",
        pointer_events="none",
        user_select="none"
    )


def landing_data_stream() -> rx.Component:
    """Decorative scrolling code text for the landing page sides."""
    code_lines = (
        "import aegis.core.forensics\n"
        "from sre_brain import SREBrain\n"
        "coral.execute(query='SELECT * FROM github.commits')\n"
        "topology.update_nodes(scan_repo=True)\n"
        "brain.run_investigation_loop(prompt, history)\n"
        "for step in brain.run_gemini_native_loop(q):\n"
        "    yield {'type': 'tool_result', ...}\n"
        "blast_radius.compute_edges(node_map)\n"
        "n8n.trigger_workflow(payload={'service': 'api'})\n"
        "osv.scan_dependencies(lockfile='poetry.lock')\n"
        "forensics.upload_parquet(sandbox='/logs')\n"
        "graph.render_svg(viewbox=state.svg_view_box)\n"
        "state.agent_thought_log.append('[SYSTEM] Scan complete')\n"
        "telemetry.stream(protocol='websocket', fps=60)\n"
    )
    return rx.el.div(
        rx.text(code_lines * 4, white_space="pre", font_size="10px", line_height="1.7"),
        class_name="data-stream",
        position="absolute",
        height="200%",
        width="200px",
        overflow="hidden",
        pointer_events="none",
        user_select="none"
    )


def parquet_visual_mock() -> rx.Component:
    """Mock terminal visual displaying Parquet log schema loading."""
    return rx.box(
        rx.vstack(
            rx.hstack(
                rx.box(width="8px", height="8px", border_radius="50%", background_color="#ff5f56"),
                rx.box(width="8px", height="8px", border_radius="50%", background_color="#ffbd2e"),
                rx.box(width="8px", height="8px", border_radius="50%", background_color="#27c93f"),
                rx.spacer(),
                rx.text("forensics_sandbox.sh", font_family="JetBrains Mono", font_size="10px", color="rgba(255,255,255,0.4)"),
                width="100%",
                margin_bottom="10px"
            ),
            rx.vstack(
                rx.hstack(
                    rx.text("aegis-sre ~ %", color="#00f2fe", font_family="JetBrains Mono", font_size="11px"),
                    rx.text("parquet-inspect telemetry_dump.parquet", color="white", font_family="JetBrains Mono", font_size="11px"),
                    align="center"
                ),
                rx.text("Ingesting local schema mapping catalog...", font_family="JetBrains Mono", font_size="11px", color="rgba(255,255,255,0.4)"),
                rx.text("├── timestamp  : INT64 (NANOSECONDS)", font_family="JetBrains Mono", font_size="11px", color="#ff6b6b"),
                rx.text("├── service_id : UTF8 (API-GATEWAY)", font_family="JetBrains Mono", font_size="11px", color="white"),
                rx.text("├── payload    : JSON (OSV-DEPENDENCY)", font_family="JetBrains Mono", font_size="11px", color="rgba(255,255,255,0.7)"),
                rx.text("└── trace_id   : UTF8 (TX-a5d89f3)", font_family="JetBrains Mono", font_size="11px", color="#9d4edd"),
                rx.hstack(
                    rx.text("[===================================]", color="#00f2fe", font_family="JetBrains Mono", font_size="11px"),
                    rx.text("100% SECURE", color="#27c93f", font_family="JetBrains Mono", font_size="10px", font_weight="700"),
                    align="center",
                    margin_top="10px"
                ),
                align="start",
                spacing="1",
                width="100%"
            ),
            width="100%",
            spacing="1"
        ),
        class_name="fui-visual-panel mock-terminal"
    )


def thought_log_visual_mock() -> rx.Component:
    """Mock agent thoughts stream running in real-time."""
    return rx.box(
        rx.vstack(
            rx.hstack(
                rx.text("● Aegis Cognitive Pipeline", font_family="JetBrains Mono", font_size="11px", color="#00f2fe", font_weight="700"),
                rx.spacer(),
                rx.text("SYS_LEVEL_5", font_family="JetBrains Mono", font_size="9px", color="rgba(255,255,255,0.3)"),
                width="100%",
                margin_bottom="10px"
            ),
            rx.vstack(
                rx.text("● [01:42:09] Initializing Aegis SRE Core context...", font_family="JetBrains Mono", font_size="11px", color="rgba(255,255,255,0.5)"),
                rx.text("● [01:42:10] Ingesting sandboxed Parquet forensics schema...", font_family="JetBrains Mono", font_size="11px", color="rgba(255,255,255,0.7)"),
                rx.text("● [01:42:11] OSV database connection isolated. Scanning lockfiles...", font_family="JetBrains Mono", font_size="11px", color="#ff6b6b"),
                rx.text("● [01:42:12] CVE vulnerability isolated: urllib3 (CVE-2023-43804)", font_family="JetBrains Mono", font_size="11px", color="#ff6b6b", font_weight="700"),
                rx.text("● [01:42:13] Running automated remediation playbook dispatch...", font_family="JetBrains Mono", font_size="11px", color="#9d4edd"),
                rx.hstack(
                    rx.text("● [01:42:14] Core dispatch complete. Awaiting validation", font_family="JetBrains Mono", font_size="11px", color="#27c93f"),
                    rx.box(class_name="mock-terminal-cursor"),
                    align="center"
                ),
                align="start",
                spacing="2"
            ),
            width="100%",
            spacing="1"
        ),
        class_name="fui-visual-panel"
    )


def topology_visual_mock() -> rx.Component:
    """A beautiful mock SVG node map topology."""
    return rx.box(
        rx.vstack(
            rx.hstack(
                rx.hstack(
                    rx.image(src="/aegis_logo.png", width="16px", height="16px"),
                    rx.text("Active Threat Topology Map", font_family="JetBrains Mono", font_size="11px", color="white"),
                    align="center",
                    spacing="2"
                ),
                rx.spacer(),
                rx.text("60 FPS", font_family="JetBrains Mono", font_size="9px", color="#00f2fe"),
                width="100%",
                margin_bottom="15px"
            ),
            # Beautiful mock vector SVG graphics
            rx.box(
                rx.el.svg(
                    # Edges lines
                    rx.el.line(x1="70", y1="120", x2="220", y2="60", stroke="rgba(255, 255, 255, 0.1)", stroke_width="2"),
                    rx.el.line(x1="70", y1="120", x2="220", y2="180", stroke="rgba(255, 255, 255, 0.1)", stroke_width="2"),
                    rx.el.line(x1="220", y1="60", x2="370", y2="120", stroke="rgba(255, 255, 255, 0.1)", stroke_width="2"),
                    rx.el.line(x1="220", y1="180", x2="370", y2="120", stroke="rgba(255, 255, 255, 0.1)", stroke_width="2"),
                    
                    # Glowing pulsing circle
                    rx.el.circle(cx="220", cy="180", r="12", fill="none", stroke="#ff6b6b", stroke_width="2", class_name="mock-node-pulse"),
                    
                    # Nodes circles
                    rx.el.circle(cx="70", cy="120", r="8", fill="#27c93f"),
                    rx.el.circle(cx="220", cy="60", r="8", fill="#27c93f"),
                    rx.el.circle(cx="220", cy="180", r="8", fill="#ff6b6b"),
                    rx.el.circle(cx="370", cy="120", r="8", fill="#9d4edd"),
                    
                    # Texts labels
                    rx.el.text("API Gateway", x="70", y="105", fill="rgba(255,255,255,0.7)", font_family="JetBrains Mono", font_size="9px", text_anchor="middle"),
                    rx.el.text("Auth Service", x="220", y="45", fill="rgba(255,255,255,0.7)", font_family="JetBrains Mono", font_size="9px", text_anchor="middle"),
                    rx.el.text("DB Primary", x="220", y="205", fill="#ff6b6b", font_family="JetBrains Mono", font_size="9px", font_weight="700", text_anchor="middle"),
                    rx.el.text("Celery Worker", x="370", y="105", fill="rgba(255,255,255,0.7)", font_family="JetBrains Mono", font_size="9px", text_anchor="middle"),
                    
                    view_box="0 0 440 240",
                    width="100%",
                    height="180px"
                ),
                width="100%"
            ),
            width="100%"
        ),
        class_name="fui-visual-panel"
    )


def integration_visual_mock() -> rx.Component:
    """Mock visual panel for MCP Integrations connections status."""
    return rx.box(
        rx.vstack(
            rx.hstack(
                rx.text("⚙️ MCP Action Hub Status", font_family="JetBrains Mono", font_size="11px", color="white"),
                rx.spacer(),
                rx.text("4 / 4 ACTIVE", font_family="JetBrains Mono", font_size="9px", color="#27c93f", font_weight="700"),
                width="100%",
                margin_bottom="15px"
            ),
            rx.vstack(
                rx.hstack(
                    rx.text("🟢 Slack Integration", font_family="JetBrains Mono", font_size="11px", color="rgba(255,255,255,0.75)", width="160px"),
                    rx.spacer(),
                    rx.text("CONNECTED // #aegis-alerts", font_family="JetBrains Mono", font_size="11px", color="#00f2fe")
                ),
                rx.el.div(class_name="data-bar", style={"width": "100%", "opacity": "0.1"}),
                rx.hstack(
                    rx.text("🟢 Notion Workbook", font_family="JetBrains Mono", font_size="11px", color="rgba(255,255,255,0.75)", width="160px"),
                    rx.spacer(),
                    rx.text("CONNECTED // db_playbooks", font_family="JetBrains Mono", font_size="11px", color="#00f2fe")
                ),
                rx.el.div(class_name="data-bar", style={"width": "100%", "opacity": "0.1"}),
                rx.hstack(
                    rx.text("🟢 GitHub Commit-Log", font_family="JetBrains Mono", font_size="11px", color="rgba(255,255,255,0.75)", width="160px"),
                    rx.spacer(),
                    rx.text("CONNECTED // aegis-sre", font_family="JetBrains Mono", font_size="11px", color="#00f2fe")
                ),
                rx.el.div(class_name="data-bar", style={"width": "100%", "opacity": "0.1"}),
                rx.hstack(
                    rx.text("🟢 Jira Issue-Tracker", font_family="JetBrains Mono", font_size="11px", color="rgba(255,255,255,0.75)", width="160px"),
                    rx.spacer(),
                    rx.text("CONNECTED // secure_api", font_family="JetBrains Mono", font_size="11px", color="#9d4edd")
                ),
                width="100%",
                spacing="3",
                align="stretch"
            ),
            width="100%"
        ),
        class_name="fui-visual-panel"
    )


def n8n_visual_mock() -> rx.Component:
    """Mock visual panel for n8n Automated Workflow Trigger."""
    return rx.box(
        rx.vstack(
            rx.hstack(
                rx.text("⚡ n8n Workflow Dispatcher", font_family="JetBrains Mono", font_size="11px", color="white"),
                rx.spacer(),
                rx.badge("RUNNING", color_scheme="green"),
                width="100%",
                margin_bottom="15px"
            ),
            rx.vstack(
                # Node 1: Webhook Trigger
                rx.hstack(
                    rx.box(
                        style={
                            "width": "8px",
                            "height": "8px",
                            "background_color": "#27c93f",
                            "border_radius": "50%",
                            "box_shadow": "0 0 6px #27c93f"
                        }
                    ),
                    rx.text("[1] Webhook Trigger", font_family="JetBrains Mono", font_weight="700", font_size="11px", color="white"),
                    rx.spacer(),
                    rx.text("HTTP POST 200 OK", font_family="JetBrains Mono", font_size="10px", color="rgba(255,255,255,0.4)")
                ),
                # Connecting spine
                rx.hstack(
                    rx.box(width="2px", height="15px", background="rgba(255,255,255,0.1)", margin_left="3px"),
                    width="100%"
                ),
                # Node 2: SRE Threat Vector Analyzer
                rx.hstack(
                    rx.box(
                        style={
                            "width": "8px",
                            "height": "8px",
                            "background_color": "#9d4edd",
                            "border_radius": "50%",
                            "box_shadow": "0 0 6px #9d4edd"
                        }
                    ),
                    rx.text("[2] Aegis Brain Parser", font_family="JetBrains Mono", font_weight="700", font_size="11px", color="white"),
                    rx.spacer(),
                    rx.text("Isolated CVE-2023", font_family="JetBrains Mono", font_size="10px", color="rgba(255,255,255,0.4)")
                ),
                # Connecting spine
                rx.hstack(
                    rx.box(width="2px", height="15px", background="rgba(255,255,255,0.1)", margin_left="3px"),
                    width="100%"
                ),
                # Node 3: Automated Actions Dispatch
                rx.hstack(
                    rx.box(
                        style={
                            "width": "8px",
                            "height": "8px",
                            "background_color": "#ff6b6b",
                            "border_radius": "50%",
                            "box_shadow": "0 0 6px #ff6b6b"
                        }
                    ),
                    rx.text("[3] Production Hot-Patch", font_family="JetBrains Mono", font_weight="700", font_size="11px", color="white"),
                    rx.spacer(),
                    rx.badge("DISPATCHED", color_scheme="red")
                ),
                width="100%",
                spacing="1",
                align="stretch"
            ),
            width="100%"
        ),
        class_name="fui-visual-panel"
    )


def showcase_feature_text(heading: str, label: str, title: str, description: str, color_accent: str) -> rx.Component:
    """GitHub-style bold left aligned feature descriptions."""
    return rx.vstack(
        rx.text(heading, font_family="JetBrains Mono", font_size="11px", color="rgba(255,255,255,0.3)", letter_spacing="0.2em", margin_bottom="5px"),
        rx.hstack(
            rx.text(label, font_family="JetBrains Mono", font_size="10px", color=color_accent, font_weight="700", padding="2px 8px", background=f"rgba(255, 255, 255, 0.04)", border_radius="4px", border=f"1px solid rgba(255,255,255,0.06)"),
            align="center",
            margin_bottom="10px"
        ),
        rx.el.h2(title, font_size="26px", font_weight="800", color="white", line_height="1.3", margin_bottom="12px"),
        rx.text(description, font_size="14px", color="rgba(255, 255, 255, 0.5)", line_height="1.6"),
        align="start",
        spacing="1",
        class_name="showcase-text-col"
    )


def landing_page() -> rx.Component:
    """Premium GitHub-inspired alternating showcase scrolling landing page."""
    return rx.el.div(
        # Sticky navbar at the top
        rx.hstack(
            rx.hstack(
                rx.image(src="/aegis_logo.png", width="24px", height="24px"),
                rx.text("AEGIS // SRE", font_family="JetBrains Mono", font_weight="700", font_size="14px", letter_spacing="0.15em", color="white"),
                align="center",
                spacing="2"
            ),
            rx.spacer(),
            rx.hstack(
                rx.text("FIELD-STATION-01 //", font_size="10px", font_family="JetBrains Mono", color="rgba(255,255,255,0.3)"),
                rx.text("ONLINE", font_size="10px", font_family="JetBrains Mono", color="#27c93f", font_weight="700"),
                rx.el.span(class_name="status-blink"),
                align="center",
                spacing="2"
            ),
            rx.spacer(),
            rx.el.button(
                "[ LAUNCH CORE ]",
                class_name="gate-btn",
                on_click=State.enter_dashboard,
                style={"padding": "8px 24px", "fontSize": "11px"}
            ),
            class_name="cyber-nav",
            width="100%",
            align="center",
            justify="between"
        ),

        # SECTION 1: HERO VIEWPORT
        rx.vstack(
            # Shield pulsing logo
            rx.box(
                rx.el.div(class_name="pulse-ring", style={"left": "50%", "top": "50%"}),
                rx.el.div(class_name="pulse-ring", style={"left": "50%", "top": "50%"}),
                rx.vstack(
                    rx.image(src="/aegis_logo.png", width="74px", height="74px", class_name="fade-up fade-up-d1"),
                    align="center",
                    justify="center"
                ),
                position="relative",
                width="180px",
                height="180px",
                display="flex",
                align_items="center",
                justify_content="center"
            ),

            # Glitch Title
            rx.el.h1(
                "AEGIS",
                class_name="glitch-text fade-up fade-up-d2",
                data_text="AEGIS",
                font_size="clamp(44px, 8vw, 80px)",
                margin_top="-5px",
                margin_bottom="0"
            ),

            # Subtitle
            rx.text(
                "SRE ENGINE",
                font_family="JetBrains Mono",
                font_size="15px",
                font_weight="300",
                letter_spacing="0.65em",
                color="rgba(255, 255, 255, 0.4)",
                margin_top="-4px",
                class_name="fade-up fade-up-d3"
            ),

            rx.el.div(
                class_name="data-bar fade-up fade-up-d3",
                style={"width": "220px", "marginTop": "20px", "marginBottom": "16px"}
            ),

            # Tagline
            rx.text(
                "Autonomous Zero-Warehouse Forensic & Blast Radius Orchestration",
                font_family="Inter",
                font_size="14px",
                color="rgba(255, 255, 255, 0.5)",
                text_align="center",
                max_width="600px",
                class_name="fade-up fade-up-d3"
            ),

            # Metadata reticle
            rx.box(
                rx.vstack(
                    rx.hstack(
                        rx.text("PLATFORM", font_size="9px", color="rgba(255,255,255,0.3)", font_family="JetBrains Mono", letter_spacing="0.1em", width="90px"),
                        rx.text("ACTIVE / FORWARD DEPLOYED", font_size="9px", color="#27c93f", font_family="JetBrains Mono", font_weight="700"),
                        align="center"
                    ),
                    rx.hstack(
                        rx.text("REMEDIATION", font_size="9px", color="rgba(255,255,255,0.3)", font_family="JetBrains Mono", letter_spacing="0.1em", width="90px"),
                        rx.text("AUTOMATED FORENSICS", font_size="9px", color="rgba(255,255,255,0.6)", font_family="JetBrains Mono"),
                        align="center"
                    ),
                    rx.hstack(
                        rx.text("TELEMETRY", font_size="9px", color="rgba(255,255,255,0.3)", font_family="JetBrains Mono", letter_spacing="0.1em", width="90px"),
                        rx.text("PARQUET / LOCAL DATABASE", font_size="9px", color="rgba(255,255,255,0.6)", font_family="JetBrains Mono"),
                        align="center"
                    ),
                    spacing="2",
                    padding="14px 20px"
                ),
                class_name="reticle-box fade-up fade-up-d4",
                margin_top="25px",
                width="300px"
            ),

            # Scroll indicator pointing down
            rx.el.div(
                rx.el.div(
                    rx.text("SCROLL TO AUDIT SYSTEM FEATURES", font_size="8px", font_family="JetBrains Mono", color="rgba(255,255,255,0.3)", letter_spacing="0.2em"),
                    class_name="scroll-indicator"
                ),
                class_name="fade-up fade-up-d4",
                width="100%",
                position="absolute",
                bottom="0",
                left="0",
                right="0"
            ),

            align="center",
            justify="center",
            height="calc(100vh - 70px)",
            width="100%",
            position="relative"
        ),

        # SECTION 2: GITHUB-STYLE CONNECTING SPINE TIMELINE SHOWCASE
        rx.box(
            # The Vertical spine line running down behind all content
            rx.el.div(class_name="github-spine"),

            # SECTION 2A: FEATURE 1 (Ingestion)
            rx.el.div(
                # Glowing node — sits outside the grid, positioned absolutely
                rx.el.div(class_name="spine-node", style={"top": "100px"}),
                # The actual 2-column grid
                rx.el.div(
                    showcase_feature_text(
                        "INGESTION PIPELINE",
                        "ZERO-WAREHOUSE",
                        "Ingest Massive Parquet Telemetry Logs Instantly",
                        "Directly stream multi-gigabyte .parquet forensic records sandboxed securely on your local file systems. Perform automated SQL schema extraction, parsing local data lakes with near-zero warehousing latency or expensive ingestion pipelines.",
                        "#00f2fe"
                    ),
                    rx.box(parquet_visual_mock(), class_name="showcase-visual-col"),
                    class_name="showcase-row"
                ),
                style={"position": "relative"},
            ),

            # SECTION 2B: FEATURE 2 (Cognitive Brain)
            rx.el.div(
                rx.el.div(class_name="spine-node spine-node-purple", style={"top": "100px"}),
                rx.el.div(
                    rx.box(thought_log_visual_mock(), class_name="showcase-visual-col"),
                    showcase_feature_text(
                        "COGNITIVE LOGIC",
                        "AUTONOMOUS TRIAGE",
                        "AI Cognitive Agent Reasoning Chain",
                        "Leverages Gemini 3.1 Flash for deep-reasoning investigations. Resolves constraints by executing tool-call loops synchronously, directly joining raw logs, vulnerabilities catalogs, and commit tables to identify core root causes.",
                        "#9d4edd"
                    ),
                    class_name="showcase-row"
                ),
                style={"position": "relative"},
            ),

            # SECTION 2C: FEATURE 3 (Blast Radius Map)
            rx.el.div(
                rx.el.div(class_name="spine-node", style={"top": "100px"}),
                rx.el.div(
                    showcase_feature_text(
                        "TOPOLOGY VECTORING",
                        "INTERACTIVE SVG",
                        "60FPS Vector Mapping of Dependency Blast Radius",
                        "Hardware-accelerated reactive SVG graph tracing critical microservices paths. Designed with seamless touchpad trackpad and wheel event zooming, precise coordinate mapping, and sticky floating inspector overlays.",
                        "#00f2fe"
                    ),
                    rx.box(topology_visual_mock(), class_name="showcase-visual-col"),
                    class_name="showcase-row"
                ),
                style={"position": "relative"},
            ),

            # SECTION 2D: FEATURE 4 (MCP Actions Connectors)
            rx.el.div(
                rx.el.div(class_name="spine-node spine-node-coral", style={"top": "100px"}),
                rx.el.div(
                    rx.box(integration_visual_mock(), class_name="showcase-visual-col"),
                    showcase_feature_text(
                        "REMEDIATION PLUGINS",
                        "CONNECTIONS STACK",
                        "Automated Resolution & Integrations",
                        "Bridge local telemetry and workspaces seamlessly using MCP connections. Run secure Coral queries to rollback commits on GitHub, log forensic playbooks in Notion, generate Jira tickets, or dispatch alert streams to Slack.",
                        "#ff6b6b"
                    ),
                    class_name="showcase-row"
                ),
                style={"position": "relative"},
            ),

            # SECTION 2E: FEATURE 5 (n8n Workflow Remediation)
            rx.el.div(
                rx.el.div(class_name="spine-node", style={"top": "100px"}),
                rx.el.div(
                    showcase_feature_text(
                        "AUTOMATED REMEDIATION",
                        "N8N WORKFLOWS",
                        "Instant Multi-Service Outage Resolution & Patching",
                        "Trigger fast n8n workflow pipelines on isolated SRE telemetry detections. Securely lock down failing gateways, rollback broken builds on GitHub, log forensic playbooks in Notion, and notify teams on Slack—remediating incident threats in seconds.",
                        "#27c93f"
                    ),
                    rx.box(n8n_visual_mock(), class_name="showcase-visual-col"),
                    class_name="showcase-row"
                ),
                style={"position": "relative"},
            ),

            class_name="github-spine-container"
        ),

        # SECTION 3: CALL TO ACTION SYSTEM LAUNCH
        rx.vstack(
            rx.el.div(class_name="data-bar", style={"width": "100px", "opacity": "0.2", "marginBottom": "20px"}),
            rx.box(
                rx.el.div(class_name="pulse-ring", style={"left": "50%", "top": "50%"}),
                rx.el.div(class_name="pulse-ring", style={"left": "50%", "top": "50%"}),
                rx.vstack(
                    rx.image(src="/aegis_logo.png", width="56px", height="56px"),
                    align="center",
                    justify="center"
                ),
                position="relative",
                width="120px",
                height="120px",
                display="flex",
                align_items="center",
                justify_content="center"
            ),
            rx.el.h2("INITIALIZE SYSTEM REMEDIATION PIPELINE", font_size="28px", font_weight="800", color="white", letter_spacing="0.05em", text_align="center", margin_top="25px"),
            rx.text("Access live microservices nodes map, sandboxed logs analytics workspace, and cognitive thoughts audit log.", font_size="13px", color="rgba(255,255,255,0.4)", text_align="center", max_width="500px"),
            
            rx.el.button(
                "[ LAUNCH FORENSIC DASHBOARD ]",
                class_name="gate-btn",
                on_click=State.enter_dashboard,
                style={"marginTop": "35px", "padding": "16px 48px", "fontSize": "13px"}
            ),
            
            rx.text("v2.1.0 // LEVEL 5 CLASSIFIED ACCESS", font_size="9px", font_family="JetBrains Mono", color="rgba(255,255,255,0.15)", letter_spacing="0.15em", margin_top="45px"),
            
            padding="120px 20px 160px 20px",
            width="100%",
            align="center",
            justify="center"
        ),

        # Viewport L-shaped tech corner markers
        rx.el.div(class_name="corner-tl", style={"position": "fixed", "top": "20px", "left": "20px"}),
        rx.el.div(class_name="corner-tr", style={"position": "fixed", "top": "20px", "right": "20px"}),
        rx.el.div(class_name="corner-bl", style={"position": "fixed", "bottom": "20px", "left": "20px"}),
        rx.el.div(class_name="corner-br", style={"position": "fixed", "bottom": "20px", "right": "20px"}),

        class_name=rx.cond(State.landing_exiting, "landing-exit landing-container", "landing-container"),
        position="fixed",
        inset="0",
        z_index="9999",
        overflow_y="auto"
    )


def dashboard() -> rx.Component:
    """
    Main Dashboard. The 3-column forensics command grid.
    """
    return rx.box(
        rx.vstack(
            header(),
            rx.grid(
                sidebar_forensics(),
                chat_console(),
                threat_intelligence(),
                grid_template_columns="280px 1fr 340px",
                width="100%",
                height="100vh",
                spacing="0"
            ),
            spacing="0",
            width="100%",
            height="100vh",
            overflow="hidden"
        ),
        how_to_use_dialog(),
        background=THEME_BG,
        width="100%",
        height="100vh",
        color="white"
    )


def index() -> rx.Component:
    """
    Root page. Shows the FUI landing gate on first load, transitions to the dashboard on enter.
    """
    return rx.box(
        rx.cond(
            State.show_landing,
            landing_page(),
            rx.fragment()
        ),
        rx.cond(
            State.show_landing,
            rx.fragment(),
            dashboard()
        ),
        width="100%",
        height="100vh",
        background="#050508"
    )


# Configure the Reflex compiler application instances
app = rx.App(
    theme=rx.theme(appearance="dark", accent_color="cyan", radius="large"),
    style={
        "font_family": "Inter",
        "background_color": "#050508",
        "::placeholder": {
            "color": "#a1a1aa !important",
            "opacity": "1 !important",
        }
    },
    stylesheets=[
        "https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap",
        "/landing.css",
    ]
)

# Bind index page route to compilation target
app.add_page(index, route="/", title="Aegis SRE | Zero-Warehouse Forensics", on_load=State.check_coral_connections)
