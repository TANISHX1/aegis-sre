"""
Aegis-Antigravity SRE: CLI Diagnostic Test Runner
-------------------------------------------------
This utility verifies the agent's core reasoning engine and mock tool suite
directly from the terminal.

CRITICAL DESIGN CHOICES & RATIONALE (THE "WHY"):
1. Decoupled CLI Diagnostics:
   Relying purely on the web UI to audit agent loops makes debugging extremely slow and 
   difficult to integrate into CI/CD pipelines. This standalone script bootstraps the 
   complete execution loop, mock-injects environments, and logs steps sequentially.
   
2. Safe Async Generator Ingestion:
   SREBrain.run_investigation_loop is an asynchronous-style generator (streams data in turns).
   We iterate through the yielded steps, formatting them in high-visibility ANSI colors 
   to provide a pristine visual output of what the agent is reasoning and executing.
"""

import sys
import os

# Ensure the root package directories are fully discoverable in sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from agent.sre_brain import SREBrain

# ANSI Terminal formatting codes for gorgeous CLI reporting
C_GREEN = "\033[92m"
C_CYAN = "\033[96m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_BOLD = "\033[1m"
C_END = "\033[0m"

def run_test():
    print(f"{C_BOLD}{C_CYAN}=== AEGIS-ANTIGRAVITY SRE COGNITIVE DIAGNOSTIC RUN ==={C_END}\n")
    
    # Initialize our brain instance
    print(f"[*] Bootstrapping SRE Brain...")
    brain = SREBrain()
    
    # Formulate a complex, multi-hop SRE question matching our schemas
    telemetry_query = (
        "We are seeing a massive spike in 500 errors in our production api-gateway. "
        "Can you scan our server log 'auth_errors.parquet', find if there are package vulnerabilities "
        "causing this, check if TANISHX1 has made any recent commits related to those packages, "
        "and if so, trigger a remediation alert immediately?"
    )
    
    print(f"\n{C_BOLD}[Operator Prompt]{C_END}: {telemetry_query}\n")
    print(f"{C_BOLD}[Executing Agent Reasoning Loop...]{C_END}")
    print("-" * 60)
    
    # Process generator turns
    try:
        for turn in brain.run_investigation_loop(telemetry_query):
            turn_type = turn.get("type")
            
            if turn_type == "status":
                print(f"{C_CYAN}[Status]{C_END} {turn.get('content')}")
            elif turn_type == "thought":
                print(f"\n{C_YELLOW}[Agent Thoughts]{C_END}\n{turn.get('content')}\n")
            elif turn_type == "tool_call":
                print(f"{C_GREEN}[Tool Invocation]{C_END} Call '{turn.get('tool_name')}' with arguments: {turn.get('arguments')}")
            elif turn_type == "tool_result":
                result = turn.get("result", {})
                print(f"{C_GREEN}[Tool Outcome]{C_END} '{turn.get('tool_name')}' returned status: {result.get('status')} (records: {result.get('count', 0)})")
            elif turn_type == "final":
                print(f"\n{C_BOLD}{C_GREEN}[Final SRE Incident Report]{C_END}\n{turn.get('content')}\n")
            elif turn_type == "error":
                print(f"{C_RED}[Fatal Error]{C_END} {turn.get('content')}", file=sys.stderr)
                
    except Exception as ex:
        print(f"{C_RED}[Execution Failure]{C_END} Runner crashed: {str(ex)}", file=sys.stderr)
        
    print("-" * 60)
    print(f"\n{C_BOLD}{C_CYAN}=== DIAGNOSTIC RUN COMPLETE ==={C_END}")

if __name__ == "__main__":
    run_test()
