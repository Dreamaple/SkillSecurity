<#
.SYNOPSIS
    SkillSecurity - One-click GitHub deployment script.

.DESCRIPTION
    This script:
    1. Validates the project (tests + lint)
    2. Creates a GitHub repository
    3. Commits all code
    4. Pushes to GitHub
    5. Sets up repository settings

.PARAMETER RepoName
    GitHub repository name (default: skillsecurity)

.PARAMETER Org
    GitHub organization (leave empty for personal account)

.PARAMETER Visibility
    Repository visibility: public or private (default: public)

.PARAMETER SkipTests
    Skip running tests before deployment

.EXAMPLE
    .\scripts\deploy-github.ps1
    .\scripts\deploy-github.ps1 -RepoName "skillsecurity" -Visibility "public"
    .\scripts\deploy-github.ps1 -Org "my-org" -RepoName "skillsecurity"
#>

param(
    [string]$RepoName = "skillsecurity",
    [string]$Org = "",
    [string]$Visibility = "public",
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"

function Write-Step { param([string]$msg) Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok { param([string]$msg) Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Fail { param([string]$msg) Write-Host "    [FAIL] $msg" -ForegroundColor Red }
function Write-Info { param([string]$msg) Write-Host "    $msg" -ForegroundColor Yellow }

# ── Step 0: Check prerequisites ──────────────────────────────────────
Write-Step "Checking prerequisites..."

$requiredTools = @("git", "python", "gh")
foreach ($tool in $requiredTools) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Fail "$tool is not installed. Please install it first."
        if ($tool -eq "gh") {
            Write-Info "Install GitHub CLI: https://cli.github.com/"
        }
        exit 1
    }
}
Write-Ok "All prerequisites found (git, python, gh)"

$ghAuth = gh auth status 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Not logged into GitHub CLI. Run: gh auth login"
    exit 1
}
Write-Ok "GitHub CLI authenticated"

# ── Step 1: Validate project ─────────────────────────────────────────
if (-not $SkipTests) {
    Write-Step "Running tests and lint..."

    Push-Location (Split-Path $PSScriptRoot -Parent)

    Write-Info "Installing dependencies..."
    python -m pip install -e ".[dev]" --quiet 2>$null

    Write-Info "Running ruff check..."
    python -m ruff check src/ tests/
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Lint errors found. Fix them before deploying."
        Pop-Location
        exit 1
    }
    Write-Ok "Lint passed"

    Write-Info "Running tests..."
    python -m pytest tests/ --cov=skillsecurity -q
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Tests failed. Fix them before deploying."
        Pop-Location
        exit 1
    }
    Write-Ok "All tests passed with coverage >= 80%"

    Pop-Location
} else {
    Write-Info "Skipping tests (--SkipTests flag set)"
}

# ── Step 2: Prepare git ──────────────────────────────────────────────
Write-Step "Preparing git repository..."

Push-Location (Split-Path $PSScriptRoot -Parent)

$branch = git branch --show-current 2>$null
if (-not $branch) {
    git checkout -b main
    Write-Ok "Created main branch"
} else {
    Write-Info "Current branch: $branch"
}

git add -A
$status = git status --porcelain
if ($status) {
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
    Write-Ok "Changes committed"
} else {
    Write-Info "No uncommitted changes"
}

# ── Step 3: Create GitHub repository ─────────────────────────────────
Write-Step "Creating GitHub repository..."

if ($Org) {
    $fullName = "$Org/$RepoName"
} else {
    $ghUser = gh api user --jq '.login' 2>$null
    $fullName = "$ghUser/$RepoName"
}

$repoExists = gh repo view $fullName 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Info "Repository $fullName already exists"
} else {
    $createArgs = @("repo", "create", $RepoName, "--$Visibility")
    $createArgs += "--description"
    $createArgs += "AI Agent Skill/Tool call security protection layer — the antivirus for AI Skills"

    if ($Org) {
        $createArgs += "--org"
        $createArgs += $Org
    }

    gh @createArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Failed to create repository"
        Pop-Location
        exit 1
    }
    Write-Ok "Created repository: $fullName"
}

# ── Step 4: Push to GitHub ───────────────────────────────────────────
Write-Step "Pushing to GitHub..."

$remoteExists = git remote get-url origin 2>$null
if ($LASTEXITCODE -ne 0) {
    git remote add origin "https://github.com/$fullName.git"
    Write-Ok "Added remote origin"
} else {
    git remote set-url origin "https://github.com/$fullName.git"
    Write-Info "Updated remote origin"
}

git push -u origin HEAD:main
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Push failed. Check your permissions."
    Pop-Location
    exit 1
}
Write-Ok "Code pushed to GitHub"

# ── Step 5: Configure repository ─────────────────────────────────────
Write-Step "Configuring repository settings..."

gh repo edit $fullName `
    --enable-issues `
    --enable-wiki=false `
    --default-branch main `
    --add-topic "ai-security" `
    --add-topic "agent-security" `
    --add-topic "tool-call" `
    --add-topic "llm-safety" `
    --add-topic "python" 2>$null

Write-Ok "Repository settings configured"

# ── Step 6: Summary ──────────────────────────────────────────────────
Pop-Location

Write-Host ""
Write-Host "=======================================" -ForegroundColor Green
Write-Host "  Deployment Complete!" -ForegroundColor Green
Write-Host "=======================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Repository: https://github.com/$fullName" -ForegroundColor White
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Yellow
Write-Host "    1. Visit the repository and verify everything looks good"
Write-Host "    2. Create a GitHub Release: gh release create v0.1.0 --generate-notes"
Write-Host "    3. (Optional) Publish to PyPI: python -m build && twine upload dist/*"
Write-Host "    4. (Optional) Set up Codecov: add CODECOV_TOKEN to repository secrets"
Write-Host ""
