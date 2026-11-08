# Settings for the remote (ssh) mode described in README, "How we recorded it".
# Not needed for the tutorial (local mode: REA_LOCAL_BIN + REA_BACKEND_CMD).
# Copy to config.sh, adjust, and load it with: source config.sh

# --- local mode (the tutorial) ---
# export REA_LOCAL_BIN="$PWD/target/syncd"                        # difftest runs the binary on this machine (Linux/WSL)
# export REA_BACKEND_CMD='["npx","-y","rea-agents@6.8.0","mcp"]'  # REA start command (JSON array); also the default
# export SECRETS_FILE="$HOME/rea-secrets/secrets.json"            # required by the proxy; outside the repo and the agent's folder

# --- remote mode (how we recorded) ---
export REA_SSH_TARGET="user@analysis-host"          # ssh target that runs REA
# A script YOU write on that host (not in this repo): it exports GHIDRA_INSTALL_DIR
# and JAVA_HOME, then runs: exec npx -y rea-agents@6.8.0 mcp
export REA_REMOTE_LAUNCHER="/opt/rea-demo/rea-mcp-launch.sh"
export REA_REMOTE_BIN="/opt/rea-demo/target/syncd"  # path of the binary on that host, used by the check
