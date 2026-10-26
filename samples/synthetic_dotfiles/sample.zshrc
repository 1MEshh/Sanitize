# ==============================================================================
# Synthetic ZSH Configuration (Unsanitized Fixture for Sanitize Guard)
# Contains synthetic machine paths, private LAN IPs, and mock secret tokens.
# ==============================================================================

export ZSH="/home/synthuser/.oh-my-zsh"
export PATH="/home/synthuser/bin:/home/synthuser/.local/bin:$PATH"

# Development cluster endpoints
export CLUSTER_LEADER="192.168.1.105"
export BACKUP_HOST="10.0.0.45"
export ROUTER_MAC="a4:c3:f0:8e:12:44"

# Synthetic API Credentials
export CLOUD_API_KEY="api_key_synthetic99887766554433221100aa"
export REPO_AUTH_TOKEN="auth_token_synthtesttoken1234567890abcdef"

# Shell customizations
ZSH_THEME="agnoster"
plugins=(git docker python rust)

source $ZSH/oh-my-zsh.sh

# Aliases
alias ll="ls -lah"
alias devcluster="ssh admin@$CLUSTER_LEADER"
