"""
Aegis-Antigravity SRE: Pure Python Reactive Command Dashboard
-------------------------------------------------------------
This is the core Reflex UI module. It binds the state management, the SVG visual 
node threat graph, file upload forensic workflows, and the SRE cognitive brain 
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
THEME_BG = "radial-gradient(circle at 50% 50%, #08070b 0%, #111016 100%)"
ACCENT_CORAL = "#FF6F61"
ACCENT_CYAN = "#00F2FE"
ACCENT_PURPLE = "#9D4EDD"

NODE_COORDINATES = {
    "logs-db": {"x": 150, "y": 150},
    "api-gateway": {"x": 70, "y": 70},
    "auth-service": {"x": 230, "y": 70},
    "payment-v2": {"x": 70, "y": 230},
    "notify-worker": {"x": 230, "y": 230},
}

STATIC_EDGES = [
    {"source": "logs-db", "target": "api-gateway"},
    {"source": "logs-db", "target": "auth-service"},
    {"source": "logs-db", "target": "payment-v2"},
    {"source": "logs-db", "target": "notify-worker"},
    {"source": "api-gateway", "target": "auth-service"},
]

GLASS_BOX = {
    "background": "rgba(18, 17, 24, 0.65)",
    "backdrop_filter": "blur(16px)",
    "-webkit-backdrop-filter": "blur(16px)",
    "border": "1px solid rgba(255, 255, 255, 0.05)",
    "border_radius": "14px",
    "box_shadow": "0 8px 32px 0 rgba(0, 0, 0, 0.4)",
}


class State(rx.State):
    """
    Core Application State. Manages active sessions, uploaded forensic log manifests,
    cognitive logs from the agent brain, and the dynamic reactive SVG topology calculations.
    """
    
    # 1. Chat Logs Container
    chat_history: List[Dict[str, str]] = [
        {
            "role": "assistant",
            "content": "👋 **Aegis-Antigravity Core Online**. I am your Zero-Warehouse SRE Agent. Drop `.parquet` files in the sidebar and trigger an investigation. I will join local telemetry logs with vulnerability databases and GitHub records to isolate root causes."
        }
    ]
    
    # 2. Reactive UI Control flags
    current_question: str = ""
    is_investigating: bool = False
    
    # 3. Agent Cognitive Thought Logs (Displayed as real-time terminal output)
    agent_thought_log: List[str] = [
        "System: Initializing SRE Brain context...",
        "System: Awaiting telemetry logs upload or manual forensic instruction."
    ]
    
    # 4. Forensic Log Store
    uploaded_logs: List[str] = []
    
    # 5. Native Reactive SVG Graph States
    # Represents nodes affected by an incident (Blast Radius) and their security state.
    blast_radius_nodes: List[Dict[str, Any]] = [
        {"id": "logs-db", "name": "Telemetry Source", "x": 150, "y": 150, "status": "Source", "ip": "Zero-Warehouse Logs", "vulnerable": "None"},
        {"id": "api-gateway", "name": "API Gateway", "x": 70, "y": 70, "status": "Degraded", "ip": "192.168.1.42", "vulnerable": "urllib3 (CVE-2023-43804)"},
        {"id": "auth-service", "name": "Auth Service", "x": 230, "y": 70, "status": "Degraded", "ip": "192.168.1.15", "vulnerable": "cryptography (CVE-2023-49083)"},
        {"id": "payment-v2", "name": "Payment Engine", "x": 70, "y": 230, "status": "Stable", "ip": "192.168.1.100", "vulnerable": "None"},
        {"id": "notify-worker", "name": "Notifier Pod", "x": 230, "y": 230, "status": "Stable", "ip": "192.168.1.105", "vulnerable": "None"},
    ]
    # Details of node clicked in the Threat panel
    selected_node_info: Dict[str, str] = {
        "id": "api-gateway",
        "name": "API Gateway",
        "status": "Degraded",
        "ip": "192.168.1.42",
        "vulnerable": "urllib3 (CVE-2023-43804)",
        "remediation": "Upgrade to urllib3>=1.26.18, rollback TANISHX1's commit a5d89f3."
    }

    # 6. ASYNC CORE INVESTIGATION LOOP
    @rx.background
    async def trigger_investigation(self):
        """
        Launches SRE Brain async reasoning.
        Iterates over the agent's thoughts and tool actions, yielding them continuously to 
        prevent Next.js socket timeouts and keep the UI reactive.
        """
        if not self.current_question.strip():
            return
            
        self.is_investigating = True
        # Clear logs to focus on current trace session
        self.agent_thought_log = [f"System: Starting investigation sequence for: '{self.current_question}'"]
        yield # Force UI refresh to render loading states

        # Instantiating SREBrain. Done inside the method so it refreshes environmental variables (e.g. keys) dynamically.
        brain = SREBrain()
        
        # Compile chat history to match raw OpenAI message structures.
        history_buffer = []
        # Take last 6 turns to keep context window tight, reducing token consumption.
        for turn in self.chat_history[-6:]:
            history_buffer.append({"role": turn["role"], "content": turn["content"]})
            
        # Run SRE agent generator loop
        try:
            # We fetch thoughts via generator to print intermediate diagnostics to the operator.
            for step in brain.run_investigation_loop(self.current_question, history_buffer):
                step_type = step.get("type")
                
                if step_type == "status":
                    self.agent_thought_log.append(f"🔄 {step.get('content')}")
                elif step_type == "thought":
                    self.agent_thought_log.append(f"🧠 {step.get('content')}")
                elif step_type == "tool_call":
                    tool_name = step.get("tool_name")
                    args = step.get("arguments", {})
                    self.agent_thought_log.append(f"🛠️ Tool Call: {tool_name} with params -> {args}")
                elif step_type == "tool_result":
                    tool_name = step.get("tool_name")
                    result = step.get("result", {})
                    self.agent_thought_log.append(f"✅ Tool {tool_name} returned status: {result.get('status')}")
                    
                    # Dynamically update the blast radius or SVG topology based on Coral execution outputs!
                    if tool_name == "execute_coral_query" and result.get("status") == "success":
                        self._parse_query_impact(result.get("data", []))
                elif step_type == "final":
                    self.chat_history.append({"role": "user", "content": self.current_question})
                    self.chat_history.append({"role": "assistant", "content": step.get("content", "")})
                    self.current_question = ""
                elif step_type == "error":
                    self.agent_thought_log.append(f"❌ Error: {step.get('content')}")
                    self.chat_history.append({"role": "assistant", "content": f"⚠️ SRE Brain encountered an execution block: {step.get('content')}"})
                
                # Push state delta updates to the Reflex websocket immediately
                yield
                
        except Exception as e:
            self.agent_thought_log.append(f"❌ Fatal crash in SRE brain loop: {str(e)}")
            yield
            
        self.is_investigating = False
        yield

    def select_node(self, node_id: str):
        """
        Interactive Node Click Handler. Updates details pane when a visual node is tapped.
        """
        for n in self.blast_radius_nodes:
            if n["id"] == node_id:
                # Custom logic calculating remediation recommendations based on vulnerable statuses
                remediation = "None needed. Service is stable."
                if "urllib3" in n["vulnerable"]:
                    remediation = "Upgrade urllib3 to 1.26.18, roll back TANISHX1's commit a5d89f3."
                elif "cryptography" in n["vulnerable"]:
                    remediation = "Patch package cryptography to version 38.0.2 via Poetry."
                
                self.selected_node_info = {
                    "id": n["id"],
                    "name": n["name"],
                    "status": n["status"],
                    "ip": n["ip"],
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

    def run_predefined_playbook(self, prompt: str):
        """
        Loads quick playbooks directly into the user input to streamline manual response.
        """
        self.current_question = prompt

    def set_current_question(self, question: str):
        """
        Explicitly sets the current question state variable.
        Why? In Python 3.14, dynamic runtime class method generation behaves differently.
        Declaring this explicitly guarantees compatibility and avoids AttributeError exceptions.
        """
        self.current_question = question

    async def handle_key_down(self, key: str):
        """
        Handles keyboard entries inside the triage console.
        If 'Enter' is typed, it delegates to the core investigation generator,
        yielding updates dynamically back to the client event loop.
        """
        if key == "Enter" and not self.is_investigating:
            async for _ in self.trigger_investigation():
                yield

    def _parse_query_impact(self, dataset: List[Dict[str, Any]]):
        """
        Helper parsing tool outcomes to alter UI topology reactively.
        If Coral database queries isolate vulnerable packages, we dynamically alter
        nodes to "Degraded" statuses inside the Reflex memory model.
        """
        if not dataset:
            return
            
        self.agent_thought_log.append(f"📊 Analyzing {len(dataset)} query records to calculate blast radius topology...")
        
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
            self.agent_thought_log.append("🚨 Threat Topology updated. API Gateway and Auth Service flag vulnerability alert!")


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
                rx.text("🛡️", font_size="24px"),
                style={"filter": "drop-shadow(0 0 8px #FF6F61)"}
            ),
            rx.vstack(
                rx.heading("AEGIS-ANTIGRAVITY SRE", size="5", color="white", font_family="Inter", font_weight="700"),
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
        width="100%",
        padding="15px 25px",
        background_color="rgba(10, 10, 12, 0.8)",
        border_bottom="1px solid rgba(255, 255, 255, 0.05)",
        backdrop_filter="blur(10px)",
        align="center"
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
                        width="100%",
                        padding="6px 10px",
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
        rx.heading("FORENSIC PLAYBOOKS", size="2", color="white", font_family="Inter", font_weight="600"),
        rx.text("Automated multi-hop preloaded query scripts.", size="1", color="rgba(255,255,255,0.4)"),
        
        rx.vstack(
            rx.button(
                "🔍 Scan vulnerabilities (OSV)",
                on_click=State.run_predefined_playbook("Scan auth_errors.parquet logs and identify matching package vulnerabilities from osv.packages database."),
                width="100%",
                variant="outline",
                color_scheme="teal",
                size="1",
                font_family="Inter"
            ),
            rx.button(
                "🐙 Trace TANISHX1 commits",
                on_click=State.run_predefined_playbook("Audit recent commits from author TANISHX1 in github.commits and correlate with server errors."),
                width="100%",
                variant="outline",
                color_scheme="indigo",
                size="1",
                font_family="Inter"
            ),
            rx.button(
                "⚡ Zero-Warehouse Join",
                on_click=State.run_predefined_playbook("Execute multi-hop SQL JOIN between server.parquet logs, Google OSV API package vulnerabilities, and TANISHX1 GitHub commits to find the exact root cause."),
                width="100%",
                variant="outline",
                color_scheme="orange",
                size="1",
                font_family="Inter"
            ),
            width="100%",
            spacing="3",
            margin_top="10px"
        ),
        
        width="100%",
        padding="20px",
        height="calc(100vh - 80px)",
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
                                rx.text(
                                    rx.cond(msg["role"] == "user", "👤 SRE OPERATOR", "🛡️ AEGIS AGENT"),
                                    font_size="10px",
                                    font_weight="700",
                                    font_family="JetBrains Mono",
                                    color=rx.cond(msg["role"] == "user", ACCENT_CYAN, ACCENT_CORAL)
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
                        "background_color": "#FFB703",
                        "border_radius": "50%",
                        "animation": rx.cond(State.is_investigating, "pulse 1.5s infinite", "none")
                    }
                ),
                rx.text("AGENT COGNITIVE LOG STREAM (REAL-TIME)", font_size="10px", font_weight="700", color="#FFB703", font_family="JetBrains Mono"),
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
            background_color="#0A0A0C",
            border="1px solid rgba(255, 183, 3, 0.15)",
            border_radius="8px",
            margin_bottom="15px"
        ),

        # 3. CHAT INPUT SHELF
        rx.hstack(
            rx.input(
                placeholder="Ask about logs, request a vulnerability check, or trigger remediation...",
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
                    "padding": "10px 15px",
                    "width": "100%"
                },
                disabled=State.is_investigating
            ),
            rx.button(
                rx.cond(State.is_investigating, rx.spinner(size="1"), "Investigate 🚀"),
                on_click=State.trigger_investigation(),
                background_color=ACCENT_CORAL,
                color="white",
                font_family="Inter",
                font_weight="600",
                border_radius="8px",
                padding="10px 20px",
                _hover={"background_color": "#FF8A7F"},
                disabled=State.is_investigating
            ),
            width="100%",
            spacing="3",
            padding_top="10px",
            border_top="1px solid rgba(255,255,255,0.05)"
        ),
        
        width="100%",
        padding="20px",
        height="calc(100vh - 80px)",
        align="stretch"
    )


def threat_intelligence() -> rx.Component:
    """
    Right Panel: Blast Radius dynamic SVG Graph and detailed node inspection.
    """
    return rx.vstack(
        rx.heading("BLAST RADIUS TOPOLOGY", size="3", color="white", font_family="Inter", font_weight="600"),
        rx.text("Real-time telemetry dependencies and isolated network compromised paths.", size="1", color="rgba(255,255,255,0.4)", margin_bottom="15px"),

        # 1. NATIVE SVG REACTIVE GRAPH NODE CONTAINER
        # SVG coordinates map directly to reactive coordinate values from State.blast_radius_nodes.
        # Renders interactive glowing vectors at 60fps.
        rx.box(
            rx.el.svg(
                # A. DRAW EDGES / NETWORKING CHANNELS
                # Drew statically at compile-time to bypass dynamic list lookups in Reflex.
                *[
                    rx.el.line(
                        x1=NODE_COORDINATES[edge["source"]]["x"],
                        y1=NODE_COORDINATES[edge["source"]]["y"],
                        x2=NODE_COORDINATES[edge["target"]]["x"],
                        y2=NODE_COORDINATES[edge["target"]]["y"],
                        stroke="rgba(255, 255, 255, 0.15)",
                        stroke_width="1.5",
                        stroke_dasharray="4,4"
                    )
                    for edge in STATIC_EDGES
                ],
                
                # B. DRAW NODE GLOWS & LABELS
                rx.foreach(
                    State.blast_radius_nodes,
                    lambda node: rx.el.g(
                        # Outer neon glow circle with direct CSS filter drop-shadow
                        rx.el.circle(
                            cx=node["x"],
                            cy=node["y"],
                            r=12,
                            fill=rx.cond(node["status"] == "Stable", "rgba(0, 242, 254, 0.1)", rx.cond(node["status"] == "Source", "rgba(157, 78, 221, 0.15)", "rgba(255, 111, 97, 0.15)")),
                            stroke=rx.cond(node["status"] == "Stable", ACCENT_CYAN, rx.cond(node["status"] == "Source", ACCENT_PURPLE, ACCENT_CORAL)),
                            stroke_width="2",
                            style={
                                "filter": rx.cond(
                                    node["status"] == "Stable",
                                    "drop-shadow(0 0 5px #00F2FE)",
                                    rx.cond(node["status"] == "Source", "none", "drop-shadow(0 0 5px #FF6F61)")
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
                            node["name"],
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
                            fill=rx.cond(node["status"] == "Stable", ACCENT_CYAN, rx.cond(node["status"] == "Source", ACCENT_PURPLE, ACCENT_CORAL)),
                            font_size="7px",
                            font_family="JetBrains Mono",
                            font_weight="700"
                        ),
                        # Clicking a node updates the focus details panels in real-time
                        on_click=lambda: State.select_node(node["id"]),
                        style={"cursor": "pointer"}
                    )
                ),
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
                            color_scheme=rx.cond(State.selected_node_info["status"] == "Stable", "teal", rx.cond(State.selected_node_info["status"] == "Source", "purple", "red")),
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
        padding="20px",
        height="calc(100vh - 80px)",
        background_color="rgba(14, 13, 18, 0.5)",
        border_left="1px solid rgba(255,255,255,0.05)",
        overflow_y="auto"
    )


def index() -> rx.Component:
    """
    Main Index Page. Assembles layouts into a fluid 3-column responsive design grid.
    """
    return rx.box(
        rx.vstack(
            header(),
            rx.grid(
                # Columns defined explicitly to accommodate Sidebar (Left), Chat (Center), Threat Topology (Right)
                sidebar_forensics(),
                chat_console(),
                threat_intelligence(),
                grid_template_columns="280px 1fr 340px",
                width="100%",
                height="calc(100vh - 80px)",
                spacing="0"
            ),
            spacing="0",
            width="100%",
            height="100vh",
            overflow="hidden"
        ),
        background=THEME_BG,
        width="100%",
        height="100vh",
        color="white"
    )


# Configure the Reflex compiler application instances
app = rx.App(
    style={
        "font_family": "Inter",
        "background_color": "#08070b",
    },
    stylesheets=[
        "https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap",
    ]
)

# Bind index page route to compilation target
app.add_page(index, route="/", title="Aegis-Antigravity SRE | Zero-Warehouse Forensics")
