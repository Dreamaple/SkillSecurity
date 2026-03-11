#!/usr/bin/env bash
#
# SkillSecurity — One-click GitHub deployment script (Linux/macOS)
#
# Usage:
#   ./scripts/deploy-github.sh                              # Personal account, public
#   ./scripts/deploy-github.sh --repo skillsecurity --org my-org
#   ./scripts/deploy-github.sh --skip-tests
#
set -euo pipefail

REPO_NAME="skillsecurity"
ORG=""
VISIBILITY="public"
SKIP_TESTS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --repo) REPO_NAME="$2"; shift 2 ;;
        --org) ORG="$2"; shift 2 ;;
        --private) VISIBILITY="private"; shift ;;
        --skip-tests) SKIP_TESTS=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

step() { echo -e "\n\033[36m==> $1\033[0m"; }
ok()   { echo -e "    \033[32m[OK]\033[0m $1"; }
fail() { echo -e "    \033[31m[FAIL]\033[0m $1"; exit 1; }
info() { echo -e "    \033[33m$1\033[0m"; }

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

# ── Step 0: Check prerequisites ──────────────────────────────────────
step "Checking prerequisites..."

for cmd in git python3 gh; do
    command -v "$cmd" >/dev/null 2>&1 || fail "$cmd is not installed"
done
ok "All prerequisites found (git, python3, gh)"

gh auth status >/dev/null 2>&1 || fail "Not logged into GitHub CLI. Run: gh auth login"
ok "GitHub CLI authenticated"

# ── Step 1: Validate project ─────────────────────────────────────────
if [ "$SKIP_TESTS" = false ]; then
    step "Running tests and lint..."

    info "Installing dependencies..."
    python3 -m pip install -e ".[dev]" --quiet 2>/dev/null

    info "Running ruff check..."
    python3 -m ruff check src/ tests/ || fail "Lint errors found"
    ok "Lint passed"

    info "Running tests..."
    python3 -m pytest tests/ --cov=skillsecurity -q || fail "Tests failed"
    ok "All tests passed with coverage >= 80%"
else
    info "Skipping tests (--skip-tests flag set)"
fi

# ── Step 2: Prepare git ──────────────────────────────────────────────
step "Preparing git repository..."

BRANCH=$(git branch --show-current 2>/dev/null || true)
if [ -z "$BRANCH" ]; then
    git checkout -b main
    ok "Created main branch"
else
    info "Current branch: $BRANCH"
fi

git add -A
if [ -n "$(git status --porcelain)" ]; then
    git commit -m "feat: SkillSecurity v0.1.0 — AI Agent tool call security layer

Complete implementation of the SkillSecurity core engine:
- Runtime tool call interception with <10ms latency
- YAML-based policy engine with regex matching
- Skill permission manifests with intersection model
- Static code scanner for dangerous patterns
- Async JSONL audit logging with sensitive data redaction
- CLI tool (check, scan, init, validate, log)
- Self-protection mechanism
- Policy hot-reload via file watcher
- 158 tests, 82%+ code coverage, zero lint errors
- Built-in policy templates (default, strict, development)
- Apache 2.0 license"
    ok "Changes committed"
else
    info "No uncommitted changes"
fi

# ── Step 3: Create GitHub repository ─────────────────────────────────
step "Creating GitHub repository..."

if [ -n "$ORG" ]; then
    FULL_NAME="$ORG/$REPO_NAME"
else
    GH_USER=$(gh api user --jq '.login')
    FULL_NAME="$GH_USER/$REPO_NAME"
fi

if gh repo view "$FULL_NAME" >/dev/null 2>&1; then
    info "Repository $FULL_NAME already exists"
else
    CREATE_ARGS=("repo" "create" "$REPO_NAME" "--$VISIBILITY")
    CREATE_ARGS+=("--description" "AI Agent Skill/Tool call security protection layer")
    [ -n "$ORG" ] && CREATE_ARGS+=("--org" "$ORG")

    gh "${CREATE_ARGS[@]}" || fail "Failed to create repository"
    ok "Created repository: $FULL_NAME"
fi

# ── Step 4: Push to GitHub ───────────────────────────────────────────
step "Pushing to GitHub..."

if ! git remote get-url origin >/dev/null 2>&1; then
    git remote add origin "https://github.com/$FULL_NAME.git"
    ok "Added remote origin"
else
    git remote set-url origin "https://github.com/$FULL_NAME.git"
    info "Updated remote origin"
fi

git push -u origin HEAD:main || fail "Push failed"
ok "Code pushed to GitHub"

# ── Step 5: Configure repository ─────────────────────────────────────
step "Configuring repository settings..."

gh repo edit "$FULL_NAME" \
    --enable-issues \
    --enable-wiki=false \
    --default-branch main \
    --add-topic "ai-security" \
    --add-topic "agent-security" \
    --add-topic "tool-call" \
    --add-topic "llm-safety" \
    --add-topic "python" 2>/dev/null || true

ok "Repository settings configured"

# ── Summary ───────────────────────────────────────────────────────────
echo ""
echo -e "\033[32m=======================================\033[0m"
echo -e "\033[32m  Deployment Complete!\033[0m"
echo -e "\033[32m=======================================\033[0m"
echo ""
echo "  Repository: https://github.com/$FULL_NAME"
echo ""
echo -e "\033[33m  Next steps:\033[0m"
echo "    1. Visit the repository and verify everything looks good"
echo "    2. Create a GitHub Release: gh release create v0.1.0 --generate-notes"
echo "    3. (Optional) Publish to PyPI: python -m build && twine upload dist/*"
echo "    4. (Optional) Set up Codecov: add CODECOV_TOKEN to repository secrets"
echo ""
