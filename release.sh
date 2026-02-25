#!/bin/bash
#
# kwebdavfs Release Script
#
# Bumps the version, updates all version files, commits, tags, and pushes.
# A GitHub Actions workflow then builds and publishes the .deb package.
#
# Usage:
#   ./release.sh                  # Patch bump  (0.1.0 -> 0.1.1) [default]
#   ./release.sh --minor          # Minor bump  (0.1.0 -> 0.2.0)
#   ./release.sh --major          # Major bump  (0.1.0 -> 1.0.0)
#   ./release.sh --version 1.2.3  # Specific version
#   ./release.sh --dry-run        # Preview without making changes

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Helpers ──────────────────────────────────────────────────────────────────

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log()  { echo -e "$(date +%H:%M:%S) ${CYAN}INFO${RESET}  $*"; }
warn() { echo -e "$(date +%H:%M:%S) ${YELLOW}WARN${RESET}  $*"; }
err()  { echo -e "$(date +%H:%M:%S) ${RED}ERROR${RESET} $*" >&2; }
ok()   { echo -e "$(date +%H:%M:%S) ${GREEN}OK${RESET}    $*"; }

DRY_RUN=false

run() {
    log "Running: $*"
    if $DRY_RUN; then
        log "[DRY-RUN] Not executing."
        return 0
    fi
    "$@"
}

# ── Argument parsing ──────────────────────────────────────────────────────────

INCREMENT="patch"
TARGET_VERSION=""

for arg in "$@"; do
    case "$arg" in
        --major)      INCREMENT="major" ;;
        --minor)      INCREMENT="minor" ;;
        --patch)      INCREMENT="patch" ;;
        --dry-run)    DRY_RUN=true ;;
        --version=*)  TARGET_VERSION="${arg#*=}" ;;
        --version)    ;;   # handled below with shift
        -*)           err "Unknown option: $arg"; exit 1 ;;
    esac
done
# Support `--version X.Y.Z` (space-separated)
for i in "$@"; do
    if [[ "$i" == "--version" ]]; then
        NEXT=true
    elif [[ "${NEXT:-false}" == "true" ]]; then
        TARGET_VERSION="$i"
        NEXT=false
    fi
done

# ── Version helpers ────────────────────────────────────────────────────────────

validate_semver() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { err "Invalid version: $1"; exit 1; }
}

bump_version() {
    local ver="$1" type="$2"
    local major minor patch
    IFS='.' read -r major minor patch <<< "$ver"
    case "$type" in
        major) echo "$((major+1)).0.0" ;;
        minor) echo "${major}.$((minor+1)).0" ;;
        patch) echo "${major}.${minor}.$((patch+1))" ;;
    esac
}

# ── Read current version ───────────────────────────────────────────────────────

CURRENT_VERSION="$(cat VERSION | tr -d '[:space:]')"
validate_semver "$CURRENT_VERSION"
log "Current version: ${BOLD}${CURRENT_VERSION}${RESET}"

if [[ -n "$TARGET_VERSION" ]]; then
    validate_semver "$TARGET_VERSION"
    NEW_VERSION="$TARGET_VERSION"
else
    NEW_VERSION="$(bump_version "$CURRENT_VERSION" "$INCREMENT")"
fi
log "Target version:  ${BOLD}${NEW_VERSION}${RESET}"

# ── Pre-flight checks ─────────────────────────────────────────────────────────

log "Checking git status..."
if ! git diff --quiet || ! git diff --cached --quiet; then
    err "Working tree is not clean. Commit or stash changes first."
    git status --short
    exit 1
fi
ok "Working tree is clean."

BRANCH="$(git branch --show-current)"
if [[ "$BRANCH" != "main" ]]; then
    warn "Not on 'main' branch (currently on: ${BRANCH})."
    read -r -p "Continue anyway? (y/N): " CONFIRM
    [[ "${CONFIRM,,}" == "y" ]] || { log "Aborted."; exit 0; }
fi

log "Fetching from origin..."
$DRY_RUN || git fetch origin --quiet

BEHIND=$(git rev-list --count HEAD..origin/"$BRANCH" 2>/dev/null || echo 0)
if [[ "$BEHIND" -gt 0 ]]; then
    err "Local branch is ${BEHIND} commit(s) behind origin/${BRANCH}. Pull first."
    exit 1
fi

if git tag -l "v${NEW_VERSION}" | grep -q .; then
    err "Tag v${NEW_VERSION} already exists."
    exit 1
fi

ok "Pre-flight checks passed."

# ── Confirm ───────────────────────────────────────────────────────────────────

echo
echo -e "  ${BOLD}Release summary${RESET}"
echo -e "  Current : ${CURRENT_VERSION}"
echo -e "  New     : ${BOLD}${NEW_VERSION}${RESET}"
echo -e "  Tag     : v${NEW_VERSION}"
echo -e "  Dry-run : ${DRY_RUN}"
echo

if ! $DRY_RUN; then
    read -r -p "Proceed with release? (y/N): " CONFIRM
    [[ "${CONFIRM,,}" == "y" ]] || { log "Aborted."; exit 0; }
fi

# ── Update files ──────────────────────────────────────────────────────────────

log "Updating VERSION..."
if ! $DRY_RUN; then
    echo "$NEW_VERSION" > VERSION
fi

log "Updating dkms.conf..."
if ! $DRY_RUN; then
    sed -i "s/^PACKAGE_VERSION=.*/PACKAGE_VERSION=\"${NEW_VERSION}\"/" dkms.conf
fi

log "Updating debian/changelog..."
if ! $DRY_RUN; then
    TIMESTAMP="$(date -R)"
    TMP_CL="$(mktemp)"
    {
        echo "kwebdavfs (${NEW_VERSION}) unstable; urgency=medium"
        echo
        echo "  * Release v${NEW_VERSION}."
        echo
        echo " -- MrMEEE <noreply@github.com>  ${TIMESTAMP}"
        echo
        cat debian/changelog
    } > "$TMP_CL"
    mv "$TMP_CL" debian/changelog
fi

# ── Commit, tag, push ─────────────────────────────────────────────────────────

run git add VERSION dkms.conf debian/changelog
run git commit -m "Release v${NEW_VERSION}"
run git tag "v${NEW_VERSION}" -m "Release v${NEW_VERSION}"
run git push origin "$BRANCH"
run git push origin "v${NEW_VERSION}"

# ── Summary ───────────────────────────────────────────────────────────────────

echo
echo -e "══════════════════════════════════════════════════"
if $DRY_RUN; then
    echo -e "  ${YELLOW}DRY RUN COMPLETE — no changes made${RESET}"
else
    echo -e "  ${GREEN}${BOLD}RELEASE v${NEW_VERSION} COMPLETE${RESET}"
    echo
    echo -e "  GitHub Actions will now build and publish:"
    echo -e "  ${CYAN}kwebdavfs-dkms_${NEW_VERSION}_all.deb${RESET}"
    echo
    echo -e "  Track progress:"
    echo -e "  ${CYAN}https://github.com/MrMEEE/kwebdavfs/actions${RESET}"
fi
echo -e "══════════════════════════════════════════════════"
