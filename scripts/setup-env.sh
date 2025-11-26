#!/usr/bin/env bash
# Setup environment files for KlaayGuard
# This script copies template files from config/ to the project root

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_DIR="$PROJECT_ROOT/config"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  KlaayGuard Environment Setup${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Function to copy env file
copy_env_file() {
    local src="$1"
    local dest="$2"
    local env_name="$3"

    if [ -f "$dest" ]; then
        echo -e "${YELLOW}⚠${NC}  $env_name already exists, skipping"
    else
        cp "$src" "$dest"
        echo -e "${GREEN}✓${NC}  Created $env_name"
    fi
}

# Check if config directory exists
if [ ! -d "$CONFIG_DIR" ]; then
    echo -e "${RED}✗${NC}  Config directory not found: $CONFIG_DIR"
    exit 1
fi

# Copy environment files
copy_env_file "$CONFIG_DIR/env.defaults" "$PROJECT_ROOT/.env.defaults" ".env.defaults"
copy_env_file "$CONFIG_DIR/env.development" "$PROJECT_ROOT/.env.development" ".env.development"
copy_env_file "$CONFIG_DIR/env.staging" "$PROJECT_ROOT/.env.staging" ".env.staging"
copy_env_file "$CONFIG_DIR/env.production" "$PROJECT_ROOT/.env.production" ".env.production"

echo ""
echo -e "${GREEN}✓${NC}  Environment setup complete!"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "  1. Review the created .env.* files"
echo "  2. Customize values if needed (especially for .env.development.local)"
echo "  3. Run: bin/build development"
echo ""
echo -e "${BLUE}Documentation:${NC}"
echo "  See docs/ENVIRONMENT.md for detailed usage instructions"
echo ""
