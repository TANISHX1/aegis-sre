#!/bin/bash
# setup_aegis.sh: Sandboxed Environment Initializer for Aegis SRE

# 1. Enforce Local Configuration Isolation
# This keeps all Coral configurations, credentials, and source links 
# isolated within the project directory to prevent system-wide contamination.
export CORAL_CONFIG_DIR="$(pwd)/.aegis_sandbox"
mkdir -p "$CORAL_CONFIG_DIR"

echo "🛡️ Aegis Sandbox Initialized at: $CORAL_CONFIG_DIR"

# Check if Coral CLI is installed (Adding Windows local bin support)
CORAL_BIN=$(command -v coral)
if [ -z "$CORAL_BIN" ]; then
    # Check common Windows installation path from Bash/MSYS2 context
    WINDOWS_CORAL="/c/Users/$USER/.local/bin/coral.exe"
    if [ -f "$WINDOWS_CORAL" ]; then
        CORAL_BIN="$WINDOWS_CORAL"
    fi
fi

if [ -z "$CORAL_BIN" ]; then
    echo "⚠️ Warning: 'coral' CLI not found. The project will run in MOCK MODE."
    echo "👉 To run in REAL MODE, install Coral from: https://github.com/withcoral/coral"
    exit 0
fi

echo "✅ Found Coral CLI: $CORAL_BIN"

# 2. Register Custom Bounty Sources
# We register OSV, Logs, and GitHub history for the federated engine.
for spec in "osv.yaml" "logs.yaml" "github.yaml"; do
    if [ -f "backend/specs/$spec" ]; then
        echo "Registering $spec..."
        "$CORAL_BIN" source add --file "backend/specs/$spec"
    else
        echo "⚠️ Warning: backend/specs/$spec not found."
    fi
done

# 3. Register Aegis Diagnostic Skill (best-effort, non-fatal)
echo "Registering Aegis diagnostic skill..."
"$CORAL_BIN" skill add \
  --name "aegis_diagnostic_playbook" \
  --description "Aegis SRE diagnostic heuristics for root-cause isolation, cross-silo join patterns, and remediation playbooks." \
  >/dev/null 2>&1 || echo "⚠️ Warning: coral skill registration is not supported in this CLI version."

echo "🚀 Aegis SRE Backend Ready."

