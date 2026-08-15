#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

shopt -s extglob

if [[ ! "$BASH_VERSION" ]] ; then
    exec /bin/bash "$0" "$@"
fi

# === Terminal UI helpers =====================================================

NC="\033[0m"
BOLD="\033[1m"
DIM="\033[2m"
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
WHITE="\033[1;37m"

SYMBOL_OK="✓"
SYMBOL_WARN="⚠"
SYMBOL_ERR="✗"
SYMBOL_INFO="›"
SYMBOL_ARROW="→"

TERM_WIDTH=$(tput cols 2>/dev/null || echo 80)

function realpath() {
    [[ $1 = /* ]] && echo "$1" || echo "$PWD/${1#./}"
}

draw_line() {
    local char="${1:-=}"
    local width="${2:-$TERM_WIDTH}"
    printf '%*s' "$width" '' | tr ' ' "$char"
}

draw_box() {
    local title="$1"
    shift
    local lines=("$@")
    local width=$((TERM_WIDTH - 4))

    echo -e "${CYAN}┌=$(draw_line '=' $((width - 2)))=┐${NC}"
    if [[ -n "$title" ]]; then
        local title_plain
        title_plain=$(echo -e "$title" | sed 's/\x1b\[[0-9;]*m//g')
        local padding=$(( (width - ${#title_plain}) / 2 ))
        echo -e "${CYAN}│${NC}$(printf '%*s' "$padding" '')${title}$(printf '%*s' $((width - padding - ${#title_plain})) '')${CYAN}│${NC}"
        echo -e "${CYAN}├=$(draw_line '=' $((width - 2)))=┤${NC}"
    fi
    for line in "${lines[@]}"; do
        local line_plain
        line_plain=$(echo -e "$line" | sed 's/\x1b\[[0-9;]*m//g')
        local right_pad=$((width - ${#line_plain}))
        [[ $right_pad -lt 0 ]] && right_pad=0
        echo -e "${CYAN}│${NC} ${line}$(printf '%*s' "$right_pad" '')${CYAN}│${NC}"
    done
    echo -e "${CYAN}└=$(draw_line '=' $((width - 2)))=┘${NC}"
}

log_step() { echo -e "  ${GREEN}${SYMBOL_OK}${NC} $1"; }
log_warn() { echo -e "  ${YELLOW}${SYMBOL_WARN}${NC} $1"; }
log_fail() { echo -e "  ${RED}${SYMBOL_ERR}${NC} $1"; }
log_info() { echo -e "  ${DIM}${SYMBOL_INFO}${NC} $1"; }

spinner() {
    local pid=$1
    local msg="${2:-Working}"
    local frames=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${CYAN}%s${NC} %s" "${frames[$((i % 10))]}" "$msg"
        i=$((i + 1))
        sleep 0.08
    done
    printf "\r"
}

confirm() {
    local prompt="$1"
    local default="${2:-yes}"
    local hint
    if [[ "$default" == "yes" ]]; then
        hint="[Y/n]"
    else
        hint="[y/N]"
    fi
    while true; do
        echo -ne "  ${CYAN}?${NC} ${prompt} ${DIM}${hint}${NC} "
        read -r answer
        answer="${answer:-$default}"
        case "${answer,,}" in
            y|yes) return 0 ;;
            n|no) return 1 ;;
            *) echo -e "    ${DIM}Please answer yes or no${NC}" ;;
        esac
    done
}

run_cmd() {
    local msg="$1"
    shift
    if [[ "$EDH_DEBUG" == "1" ]]; then
        log_info "${msg}"
        "$@"
    else
        "$@" >/dev/null 2>&1 &
        spinner $! "$msg"
        wait $!
    fi
}

# Portable sha256 of a file (sha256sum on Linux/CloudShell, shasum on macOS).
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

run_cmd_piped() {
    local msg="$1"
    local cmd="$2"
    if [[ "$EDH_DEBUG" == "1" ]]; then
        log_info "${msg}"
        eval "$cmd"
    else
        eval "$cmd" >/dev/null 2>&1 &
        spinner $! "$msg"
        wait $!
    fi
}

show_banner() {
    echo ""
    echo -e "  ${BOLD}${WHITE}Engineering Development Hub (EDH)${NC}"
    echo -e "  ${CYAN}$(draw_line '=' 40)${NC}"
    echo -e "  ${DIM}Source Code${NC}      https://github.com/awslabs/engineering-development-hub"
    echo -e "  ${DIM}Documentation${NC}   https://awslabs.github.io/engineering-development-hub-documentation/"
    echo -e "  ${DIM}Silent Mode${NC}     Use ${WHITE}--help${NC} for CLI options"
    echo -e "  ${DIM}Debug Mode${NC}      Set ${WHITE}EDH_DEBUG=1${NC} for verbose output"
    echo -e "  ${DIM}Exit${NC}            Press ${WHITE}Ctrl+C${NC} at any time"
    if [[ "$EDH_DEBUG" == "1" ]]; then
        echo ""
        echo -e "  ${YELLOW}${SYMBOL_WARN} Debug mode enabled${NC}"
    fi
    echo ""
}

section_header() {
    local title="$1"
    echo ""
    echo -e "  ${CYAN}$(draw_line '=' 40)${NC}"
    echo -e "  ${BOLD}${WHITE}${title}${NC}"
    echo -e "  ${CYAN}$(draw_line '=' 40)${NC}"
    echo ""
}

# === Configuration ===========================================================

EDH_DEBUG="${EDH_DEBUG:-${SOCA_DEBUG:-0}}"

SOCA_PYTHON=${SOCA_PYTHON:-$(command -v python3)}
SOCA_PYTHON_SKIP_VENV=${SOCA_PYTHON_SKIP_VENV:-"false"}
SOCA_PYTHON_VERSION=${SOCA_PYTHON_VERSION:-"3.13"}
export SOCA_PYTHON_VERSION

PYENV_URL="https://pyenv.run"
INSTALLER_DIRECTORY=$(dirname $(realpath "$0"))
PYTHON_VENV="$INSTALLER_DIRECTORY/resources/src/envs/venv-py-installer"
NODEJS_BIN="https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh"
export NVM_DIR="$INSTALLER_DIRECTORY/resources/src/envs/.nvm"

# shellcheck disable=SC2164
cd "$INSTALLER_DIRECTORY"

show_banner

section_header "System Pre-requisites"

SYSTEM=$(uname -s)
CHECK_GLIBC=false

case $SYSTEM in
    "Linux")
        log_step "Platform: Linux"
        CHECK_GLIBC=true
        ;;
    "Darwin")
        log_step "Platform: macOS"
        CHECK_GLIBC=false
        SOCA_NODE_VERSION=24
        ;;
    *)
        log_fail "Unsupported OS: ${SYSTEM}"
        exit 1
        ;;
esac

if [[ "$CHECK_GLIBC" = true ]]; then
    SYSTEM_GETCONF_BIN=$(command -v getconf)

    if [[ -z "$SYSTEM_GETCONF_BIN" ]]; then
        log_fail "getconf is not installed (required for GLIBC detection)"
        exit 1
    fi

    SYSTEM_GLIBC_VERSION=$($SYSTEM_GETCONF_BIN GNU_LIBC_VERSION | head -n 1 | awk '{print $NF}')

    if [[ -z "$SYSTEM_GLIBC_VERSION" ]]; then
        log_fail "Unable to determine GLIBC version"
        exit 1
    fi

    case $SYSTEM_GLIBC_VERSION in
        2.2[0-7])
            SOCA_NODE_VERSION=16
            ;;
        2.2[8-9]|2.[3-9][0-9])
            SOCA_NODE_VERSION=24
            ;;
        *)
            log_warn "Unknown GLIBC ${SYSTEM_GLIBC_VERSION}, defaulting to Node 16"
            SOCA_NODE_VERSION=16
            ;;
    esac
    log_step "GLIBC ${SYSTEM_GLIBC_VERSION} ${SYMBOL_ARROW} Node.js ${SOCA_NODE_VERSION}"
fi

# === Python verification =====================================================

section_header "Python Environment"

PYENV=$(command -v pyenv)
if [[ -z "${PYENV}" ]]; then
    PYENV_AVAILABLE=false
else
    PYENV_AVAILABLE=true
    log_info "PyEnv detected"
fi

if [[ -z "$SOCA_PYTHON" ]]; then
    log_fail "Python3 not found. Install from https://www.python.org/downloads/"
    exit 1
fi

PYTHON_VERSION=$($SOCA_PYTHON -c "import sys;print(f'{sys.version_info.major}.{sys.version_info.minor}')")

if [[ "$PYTHON_VERSION" != "$SOCA_PYTHON_VERSION" ]]; then
    log_warn "Python ${PYTHON_VERSION} detected, but ${SOCA_PYTHON_VERSION} is required"

    if [[ "${PYENV_AVAILABLE}" == true ]]; then
        PYENV_VERSIONS=$($PYENV versions | grep "${SOCA_PYTHON_VERSION}")
        if [[ -z "$PYENV_VERSIONS" ]]; then
            if confirm "Install Python ${SOCA_PYTHON_VERSION} via PyEnv?"; then
                $PYENV install "${SOCA_PYTHON_VERSION}"
            else
                exit 1
            fi
        fi
        $PYENV versions | grep "${SOCA_PYTHON_VERSION}"
        echo -ne "  ${CYAN}?${NC} Which version to use? "
        read -r PYENV_INSTALLED_VERSION
        if ! $PYENV local "${PYENV_INSTALLED_VERSION}"; then
            log_fail "Invalid version selected"
            exit 1
        fi
        SOCA_PYTHON=$($PYENV which python3)
    else
        if confirm "Install PyEnv and Python ${SOCA_PYTHON_VERSION}?"; then
            if ! curl --silent $PYENV_URL | bash; then
                log_fail "PyEnv installation failed"
                # flush  $HOME/.pyenv for the next install to avoid the following error:
                # WARNING: Can not proceed with installation. Kindly remove the '$HOME/.pyenv' directory first.
                rm -rf "$HOME/.pyenv"
                exit 1
            fi
            export PYENV_ROOT="$HOME/.pyenv"
            command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"
            eval "$(pyenv init -)"
            PYENV=$(command -v pyenv)
            log_info "Installing Python ${SOCA_PYTHON_VERSION}..."
            if ! $PYENV install "${SOCA_PYTHON_VERSION}"; then
                log_fail "Python installation failed"
                exit 1
            fi
            $PYENV local "${SOCA_PYTHON_VERSION}"
            SOCA_PYTHON=$($PYENV which python)
        else
            log_fail "Python ${SOCA_PYTHON_VERSION} is required"
            exit 1
        fi
    fi
fi

log_step "Python ${SOCA_PYTHON_VERSION} ${SYMBOL_ARROW} $($SOCA_PYTHON --version 2>&1 | awk '{print $2}')"

# === Virtual environment =====================================================

USING_SOCA_VENV=true
if [[ -n $VIRTUAL_ENV ]]; then
    log_warn "Existing virtual environment detected: ${VIRTUAL_ENV}"
    log_info "It's recommended to exit your venv and re-launch the installer"
    if [[ $SOCA_PYTHON_SKIP_VENV == "false" ]]; then
        if ! confirm "Continue with existing virtual environment?" "no"; then
            exit 1
        fi
    fi
    USING_SOCA_VENV=false
else
    if [[ ! -e $PYTHON_VENV/bin/activate ]]; then
        log_info "Creating Python virtual environment..."
        rm -rf "$PYTHON_VENV"
        $SOCA_PYTHON -m venv "$PYTHON_VENV"
        # shellcheck disable=SC1090
        . "$PYTHON_VENV/bin/activate"
    else
        # Rebuild venv if requirements.txt changed since last install (stale deps) or EDH_FORCE_VENV_REBUILD=1; else reuse.
        _req_hash="$(sha256_of resources/src/requirements.txt)"
        _stored_req_hash=""
        [[ -f "$PYTHON_VENV/.edh_req_hash" ]] && _stored_req_hash="$(cat "$PYTHON_VENV/.edh_req_hash")"
        if [[ "${EDH_FORCE_VENV_REBUILD:-0}" == "1" || "$_req_hash" != "$_stored_req_hash" ]]; then
            if [[ "${EDH_FORCE_VENV_REBUILD:-0}" == "1" ]]; then
                log_warn "EDH_FORCE_VENV_REBUILD set ${SYMBOL_ARROW} rebuilding virtual environment"
            else
                log_warn "requirements.txt changed ${SYMBOL_ARROW} rebuilding virtual environment"
            fi
            rm -rf "$PYTHON_VENV"
            $SOCA_PYTHON -m venv "$PYTHON_VENV"
            # shellcheck disable=SC1090
            . "$PYTHON_VENV/bin/activate"
        else
            log_step "Loading virtual environment"
            source "$PYTHON_VENV/bin/activate"
        fi
    fi
fi

# === Venv sanity check =======================================================
# After activation, confirm that VIRTUAL_ENV, python3, and pip3 all resolve
# to the intended venv. Catches:
#   - pyenv/conda/homebrew shims ahead of the venv in PATH
#   - stale venvs where bin/python is a broken symlink
#   - activate script that partially failed
#   - a different VIRTUAL_ENV leaking in via the parent shell
#
# When the user opted to keep their own venv (USING_SOCA_VENV=false), we
# log what they're running in but do NOT enforce -- that is their call.
ACTIVE_VENV="${VIRTUAL_ENV:-}"
ACTIVE_PY="$(command -v python3 || true)"
ACTIVE_PIP="$(command -v pip3 || true)"


if [[ "${AWS_EXECUTION_ENV:-}" == "CloudShell" ]];
then
    log_step "Detected AWS CloudShell"
    USE_CLOUDSHELL=1
else
    USE_CLOUDSHELL=0
fi  

if [[ $USING_SOCA_VENV == "true" ]]; then
    EXPECTED_PY="$PYTHON_VENV/bin/python3"
    EXPECTED_PIP="$PYTHON_VENV/bin/pip3"
    if [[ $ACTIVE_VENV != "$PYTHON_VENV" ]]; then
        log_fail "Venv activation mismatch: VIRTUAL_ENV=${ACTIVE_VENV:-<unset>}, expected ${PYTHON_VENV}"
        log_info "This usually means a shim (pyenv, conda, homebrew) took precedence. Unset or deactivate it, then re-run."
        exit 1
    fi
    if [[ $ACTIVE_PY != "$EXPECTED_PY" ]]; then
        log_fail "python3 resolves to ${ACTIVE_PY:-<not found>}, expected ${EXPECTED_PY}"
        log_info "Check PATH ordering -- something ahead of the venv is winning."
        exit 1
    fi
    if [[ $ACTIVE_PIP != "$EXPECTED_PIP" ]]; then
        log_fail "pip3 resolves to ${ACTIVE_PIP:-<not found>}, expected ${EXPECTED_PIP}"
        log_info "Check PATH ordering -- something ahead of the venv is winning."
        exit 1
    fi
    log_step "Venv sanity: $ACTIVE_VENV"
else
    log_warn "Using caller-provided venv (not sanity-checked against SOCA expectations):"
    log_info "  VIRTUAL_ENV = ${ACTIVE_VENV:-<unset>}"
    log_info "  python3     = ${ACTIVE_PY:-<not found>}"
    log_info "  pip3        = ${ACTIVE_PIP:-<not found>}"
fi

# === Python dependencies =====================================================

if run_cmd_piped "Installing Python dependencies" "pip3 install --upgrade pip && pip3 install -r resources/src/requirements.txt"; then
    log_step "Python dependencies installed"
    # Record the requirements fingerprint so the next run can detect drift.
    sha256_of resources/src/requirements.txt > "$PYTHON_VENV/.edh_req_hash" 2>/dev/null || true
else
    log_fail "Failed to install Python dependencies"
    exit 1
fi

# === Node.js environment =====================================================

section_header "Node.js Environment"

if [[ ! -d $NVM_DIR ]]; then
    mkdir -p "$NVM_DIR"
    run_cmd_piped "Installing NVM" "curl --silent -o- '$NODEJS_BIN' | bash"
    source "$NVM_DIR/nvm.sh"
    # shellcheck disable=SC1090
    source "$NVM_DIR/bash_completion"

    run_cmd "Installing Node.js ${SOCA_NODE_VERSION}" nvm install "${SOCA_NODE_VERSION}"
    log_step "Node.js ${SOCA_NODE_VERSION} installed"

    run_cmd "Installing AWS CDK" npm install -g aws-cdk
    log_step "AWS CDK installed"
else
    source "$NVM_DIR/nvm.sh"
    source "$NVM_DIR/bash_completion"
    log_step "NVM loaded (Node.js $(node --version 2>/dev/null || echo 'unknown'))"
fi

# === AWS CLI =================================================================

section_header "AWS Configuration"

PIP3=$(command -v pip3)
if ! command -v aws > /dev/null 2>&1; then
    log_warn "AWS CLI not detected"
    if confirm "Install AWS CLI and configure credentials?"; then
        run_cmd "Installing AWS CLI" "$PIP3" install awscli
        log_step "AWS CLI installed"
        log_info "Running 'aws configure'..."
        aws configure
    else
        exit 1
    fi
else
    log_step "AWS CLI $(aws --version 2>&1 | awk '{print $1}' | cut -d/ -f2)"
fi

export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-$(grep region <"${HOME}/.aws/config" 2>/dev/null | head -n 1 | awk '{print $3}')}
if [[ -z "$AWS_DEFAULT_REGION" ]]; then
    if [[ "$USE_CLOUDSHELL" -eq 0  ]]; then
        # default to use-east-1 for non-cloudshell deployment, just to init awscli
        export AWS_DEFAULT_REGION="us-east-1"
    else
        # when using cloudshell, we must determine the region of the CloudShell environment as we will have to send a hearthbeat to avoid disconnect
        # There is one final check if AWS_DEFAULT_REGION / .aws/config is not available, which is to read the content of /etc/dnf/vars/awsregion
        DETECT_AWSREGION="$(cat /etc/dnf/vars/awsregion)"
        export AWS_DEFAULT_REGION=${DETECT_AWSREGION}
        if [[ -z "$AWS_DEFAULT_REGION" ]]; then
            log_fail "Unable to determine CloudShell region, run export AWS_DEFAULT_REGION=<region_name> and try again"
            exit 1
        fi
    fi
fi
log_info "Region: ${AWS_DEFAULT_REGION}"

# === Compile translation catalogs (.po → .mo) ================================
# .mo files are derived artifacts (gitignored) and must be compiled before the
# installer can load translations via gettext.translation(). Silently falls
# back to English if compilation fails (non-fatal — English is always bundled).
#
# Uses the venv's pybabel CLI entry point explicitly, rather than a PATH
# lookup or a programmatic call to compile_catalog().run() — the latter has
# a bug path in Babel 2.17 when locale=None (iterate-all mode) that raises
# TypeError on os.path.join.
LOCALE_DIR="$INSTALLER_DIRECTORY/resources/src/locale"
if [[ -x "$PYTHON_VENV/bin/pybabel" ]]; then
    VENV_PYBABEL="$PYTHON_VENV/bin/pybabel"
elif [[ -n $VIRTUAL_ENV && -x "$VIRTUAL_ENV/bin/pybabel" ]]; then
    VENV_PYBABEL="$VIRTUAL_ENV/bin/pybabel"
else
    VENV_PYBABEL="$(command -v pybabel || true)"
fi

if [[ -d $LOCALE_DIR && -n $VENV_PYBABEL ]]; then
    if "$VENV_PYBABEL" compile -d "$LOCALE_DIR" -D installer >/dev/null 2>&1; then
        log_step "Translation catalogs compiled"
    else
        log_warn "Translation catalog compile failed — installer will run in English"
        log_info "To diagnose: $VENV_PYBABEL compile -d $LOCALE_DIR -D installer"
    fi
elif [[ -d $LOCALE_DIR ]]; then
    log_warn "pybabel not found — installer will run in English (install: pip install Babel)"
fi


# === AWS CloudShell: session-manager-plugin ==================================
# AWS_EXECUTION_ENV is set to "CloudShell" inside CloudShell environments.
if [[ ${USE_CLOUDSHELL} -eq 1 ]]; then
    if ! command -v session-manager-plugin &>/dev/null; then
        ARCH=$(uname -m)
        case "$ARCH" in
            x86_64)
                SSM_RPM="https://s3.amazonaws.com/session-manager-downloads/plugin/latest/linux_64bit/session-manager-plugin.rpm"
                ;;
            aarch64|arm64)
                SSM_RPM="https://s3.amazonaws.com/session-manager-downloads/plugin/latest/linux_arm64/session-manager-plugin.rpm"
                ;;
            *)
                log_warn "CloudShell: unknown architecture '${ARCH}', skipping session-manager-plugin install"
                SSM_RPM=""
                ;;
        esac
        if [[ -n "$SSM_RPM" ]]; then
            log_step "CloudShell detected — installing session-manager-plugin (${ARCH})"
            sudo dnf install -y "$SSM_RPM"
        fi
    else
        log_step "CloudShell detected — session-manager-plugin already installed"
    fi

    log_step "Launching CloudShell Keep Alive"
    python3 -u resources/src/cloudshell_keepalive.py --region "${AWS_DEFAULT_REGION}" >> resources/src/cloudshell_keepalive.log 2>&1 &
fi



# === Launch installer ========================================================

echo ""
echo -e "  ${GREEN}$(draw_line '=' 40)${NC}"
echo -e "  ${BOLD}${GREEN}${SYMBOL_OK} All pre-requisites validated${NC}"
echo -e "  ${GREEN}$(draw_line '=' 40)${NC}"
echo ""

# Always start from a clean synth (installs are rare; never risk stale cdk.out from a prior/failed run).
rm -rf resources/src/cdk.out

if [[ ${EDH_INSTALLER_LEGACY:-"false"} == "true" ]]; then
    resources/src/install_soca_legacy.py "$@"
else
    resources/src/install_soca.py "$@"
fi
