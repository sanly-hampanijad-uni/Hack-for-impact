#!/usr/bin/env bash
# ==========================================================
set -Eeuo pipefail
source $".env"

# Coloured logging functions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# check if required dependencies are installed
check_dependencies() {
    command -v python3 >/dev/null 2>&1 || {
        error "Python 3 is not installed."
        return 1
    }
    command -v curl >/dev/null 2>&1 || {
        error "curl is not installed."
        return 1
    }
}

# Setup - create venv and install dependencies
setup() {
    info "Setting up..."

    check_dependencies

    if [[ ! -d "$PROJECT_DIR/.venv" ]]; then
        python3 -m venv ".venv"
    fi

    if [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "cygwin"* ]]; then
        ./.venv/Scripts/activate.bat
    else
        source .venv/bin/activate
    fi

    if [[ -f "${PROJECT_DIR}/pyproject.toml" ]]; then
        python -m pip install -e .
        python -m pip install -e ".[dev]"
    fi
    success "setup complete."
}

# Vulnerability scan
scan() {
    local CVE=""
    local REPO=""
    local output_file=""
    local artifact_dir=""
    local status=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --repo)
                if [[ $# -lt 2 ]]; then
                    error "--repo requires a directory path."
                    return 1
                fi
                REPO="$2"
                shift 2
                ;;

            --cve)
                if [[ $# -lt 2 ]]; then
                    error "--cve requires a CVE identifier."
                    return 1
                fi
                CVE="$2"
                shift 2
                ;;

            *)
                error "Unknown scan argument: $1"
                return 1
                ;;
        esac
    done

    if [[ -z "$REPO" || ! -d "$REPO" ]]; then
        error "Invalid repository. Please provide a valid directory path using --repo."
        return 1
    fi

    local command_args=(
        -m
        spark_cve
        scan
        "$REPO"
        --allow-execution
        --allow-downloads
    )

    if [[ -n "$CVE" ]]; then
        command_args+=(
            --cve "$CVE")
    fi

    output_file="$(mktemp)"
    trap 'rm -f "$output_file"' RETURN

    info "Starting vulnerability scan..."
    info "Repository: $REPO"

    if [[ -n "$CVE" ]]; then
        info "CVE: $CVE"
    else
        info "CVE: most recent qualifying CVE"
    fi

    if python3 "${command_args[@]}" 2>&1 | tee "$output_file"; then
        status=0
    else
        status=$?
    fi

    if [[ $status -ne 0 ]]; then
        error "Scan failed with exit code $status."
        return "$status"
    fi

    artifact_dir="$(
        sed -n 's/^JSON and tool events: //p' "$output_file" |
        tail -n 1
    )"

    success "Scan completed."
    info "Artifacts: $artifact_dir"
}

main() {
    setup
    scan "$@"
}

main "$@"

# Run the script with the following commands:
# ./scripts/Execute.sh --repo {$REPO}
# ./scripts/Execute.sh  --repo {$REPO} --cve CVE-2026-12345