#!/usr/bin/env fish
# Load environment variables from .env files (Fish shell version)
# Usage: source scripts/load-env.fish <environment>
#   environment: development, staging, or production

# Determine the environment
set -l env_name (test (count $argv) -gt 0; and echo $argv[1]; or echo $KLAAY_ENV; or echo "production")

# Get project root (assuming this script is in scripts/)
set -l project_root (dirname (status --current-filename))/..
set -l project_root (cd $project_root; and pwd)

# Function to load env file
function load_env_file
    set -l env_file $argv[1]
    if test -f $env_file
        # Read each line, skip comments and empty lines
        for line in (cat $env_file | grep -v '^#' | grep -v '^$')
            # Parse key=value
            set -l parts (string split -m 1 = $line)
            if test (count $parts) -eq 2
                set -gx $parts[1] $parts[2]
            end
        end
        return 0
    end
    return 1
end

# Load in priority order (later overrides earlier)
# 1. Load defaults
if load_env_file "$project_root/.env.defaults"
    # Silently continue
end

# 2. Load environment-specific file
set -l env_file "$project_root/.env.$env_name"
if not load_env_file $env_file
    echo "Warning: Environment file not found: $env_file" >&2
    echo "Run: scripts/setup-env.sh to create it" >&2
end

# 3. Load local overrides (optional)
set -l local_env_file "$project_root/.env.$env_name.local"
if load_env_file $local_env_file
    # Silently continue
end

# Export KLAAY_ENV
set -gx KLAAY_ENV $env_name

# Validate required variables
set -l required_vars VITE_API_BASE_URL VITE_EARTHENWARE_URL
set -l missing_vars

for var in $required_vars
    if not set -q $var
        set -a missing_vars $var
    end
end

if test (count $missing_vars) -gt 0
    echo "Error: Required environment variables are not set:" >&2
    for var in $missing_vars
        echo "  - $var" >&2
    end
    echo "" >&2
    echo "Please ensure your .env.$env_name file defines these variables." >&2
    echo "Run: scripts/setup-env.sh to create template files." >&2
    return 1
end



