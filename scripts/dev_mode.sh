#!/usr/bin/env bash
set -euo pipefail

# ScanGuard AI - Local Development Mode Helper
# ⚠️ WARNING: This script configures development-only settings that DISABLE AUTHENTICATION.
# NEVER use these settings in production, staging, or any publicly accessible environment.

echo "========================================="
echo "ScanGuard AI - Dev Mode Setup"
echo "========================================="
echo ""
echo "⚠️  WARNING: This configures DEV-ONLY settings that DISABLE authentication."
echo "   NEVER use in production or publicly accessible environments!"
echo ""

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="$REPO_ROOT/backend"
FRONTEND_DIR="$REPO_ROOT/frontend"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running in CI or production-like environment
if [[ "${CI:-false}" == "true" ]] || [[ "${PROD:-false}" == "true" ]] || [[ "${PRODUCTION:-false}" == "true" ]]; then
  echo -e "${RED}ERROR: This script is for local development only.${NC}"
  echo "It appears you're running in CI or production environment."
  echo "Refusing to continue."
  exit 1
fi

echo "Repository root: $REPO_ROOT"
echo ""

# Function to create or update .env file
create_or_update_backend_env() {
  local env_file="$BACKEND_DIR/.env"
  local env_example="$BACKEND_DIR/.env.example"

  if [[ -f "$env_file" ]]; then
    echo -e "${YELLOW}Backend .env already exists.${NC}"
    echo "Add these lines manually if not already present:"
    echo ""
    echo "  # ⚠️ DEV-ONLY: DO NOT USE IN PRODUCTION"
    echo "  DEV_AUTH_BYPASS=true"
    echo "  DEV_AUTH_USER_ID=00000000-0000-0000-0000-000000000001"
    echo "  DEV_AUTH_EMAIL=dev@example.com"
    echo "  SKIP_PINECONE=true"
    echo ""
  else
    echo -e "${GREEN}Creating backend/.env from .env.example...${NC}"
    if [[ -f "$env_example" ]]; then
      cp "$env_example" "$env_file"
      echo "Created $env_file"
    else
      echo "Warning: backend/.env.example not found. Creating minimal .env"
      touch "$env_file"
    fi

    # Append dev-only settings
    cat >> "$env_file" << 'EOF'

# ⚠️ DEV-ONLY: DO NOT USE IN PRODUCTION
DEV_AUTH_BYPASS=true
DEV_AUTH_USER_ID=00000000-0000-0000-0000-000000000001
DEV_AUTH_EMAIL=dev@example.com
SKIP_PINECONE=true

# Minimal local database
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/scanguard
EOF
    echo -e "${GREEN}Added dev-only settings to backend/.env${NC}"
  fi
}

create_or_update_frontend_env() {
  local env_file="$FRONTEND_DIR/.env"
  local env_example="$FRONTEND_DIR/.env.example"

  if [[ -f "$env_file" ]]; then
    echo -e "${YELLOW}Frontend .env already exists.${NC}"
    echo "Add these lines manually if not already present:"
    echo ""
    echo "  # ⚠️ DEV-ONLY: DO NOT USE IN PRODUCTION"
    echo "  VITE_DEV_AUTH_BYPASS=true"
    echo "  VITE_API_URL=http://localhost:8000"
    echo ""
  else
    echo -e "${GREEN}Creating frontend/.env from .env.example...${NC}"
    if [[ -f "$env_example" ]]; then
      cp "$env_example" "$env_file"
      echo "Created $env_file"
    else
      echo "Warning: frontend/.env.example not found. Creating minimal .env"
      touch "$env_file"
    fi

    # Append dev-only settings
    cat >> "$env_file" << 'EOF'

# ⚠️ DEV-ONLY: DO NOT USE IN PRODUCTION
VITE_DEV_AUTH_BYPASS=true
VITE_API_URL=http://localhost:8000
EOF
    echo -e "${GREEN}Added dev-only settings to frontend/.env${NC}"
  fi
}

# Main execution
echo "Step 1: Backend environment setup"
echo "-----------------------------------"
create_or_update_backend_env
echo ""

echo "Step 2: Frontend environment setup"
echo "-----------------------------------"
create_or_update_frontend_env
echo ""

echo "========================================="
echo "Dev Mode Setup Complete!"
echo "========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Start backend:"
echo "   cd backend && uvicorn src.main:asgi_app --reload --port 8000"
echo ""
echo "2. Start frontend (in separate terminal):"
echo "   cd frontend && npm run dev"
echo ""
echo "3. Access UI (no login required):"
echo "   http://localhost:5173"
echo ""
echo -e "${RED}⚠️  REMINDER: These settings are for LOCAL DEVELOPMENT ONLY.${NC}"
echo -e "${RED}   NEVER commit .env files or use DEV_AUTH_BYPASS in production!${NC}"
echo ""
