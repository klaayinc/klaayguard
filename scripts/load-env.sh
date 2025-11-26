#!/usr/bin/env bash
# Load environment variables from .env files
# Usage: source scripts/load-env.sh <environment>
#   environment: development, staging, or production

# Determine the environment
ENV_NAME="${1:-${KLAAY_ENV:-production}}"

# Get script directory and project root
if [ -n "$BASH_SOURCE" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    # Fallback for when sourced in a way that doesn't set BASH_SOURCE
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
fi
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Function to load env file
load_env_file() {
    local env_file="$1"
    if [ -f "$env_file" ]; then
        # Read and export variables, ignoring comments and empty lines
        while IFS= read -r line || [ -n "$line" ]; do
            # Skip comments and empty lines
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "$line" ]] && continue
            # Export the variable
            if [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
                export "${BASH_REMATCH[1]}=${BASH_REMATCH[2]}"
            fi
        done < "$env_file"
        return 0
    fi
    return 1
}

# Load in priority order (later overrides earlier)
# 1. Load defaults
if load_env_file "$PROJECT_ROOT/.env.defaults"; then
    : # Silently continue
fi

# 2. Load environment-specific file
ENV_FILE="$PROJECT_ROOT/.env.$ENV_NAME"
if ! load_env_file "$ENV_FILE"; then
    echo "Warning: Environment file not found: $ENV_FILE" >&2
    echo "Run: scripts/setup-env.sh to create it" >&2
fi

# 3. Load local overrides (optional)
LOCAL_ENV_FILE="$PROJECT_ROOT/.env.$ENV_NAME.local"
if load_env_file "$LOCAL_ENV_FILE"; then
    : # Silently continue
fi

# Export KLAAY_ENV
export KLAAY_ENV="$ENV_NAME"

# Validate required variables
REQUIRED_VARS=("VITE_API_BASE_URL" "VITE_EARTHENWARE_URL")
MISSING_VARS=()

for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        MISSING_VARS+=("$var")
    fi
done

if [ ${#MISSING_VARS[@]} -gt 0 ]; then
    echo "Error: Required environment variables are not set:" >&2
    for var in "${MISSING_VARS[@]}"; do
        echo "  - $var" >&2
    done
    echo "" >&2
    echo "Please ensure your .env.$ENV_NAME file defines these variables." >&2
    echo "Run: scripts/setup-env.sh to create template files." >&2
    return 1 2>/dev/null || exit 1
fi
