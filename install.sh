#!/bin/sh
# ─────────────────────────────────────────────────────────────────
# LeakScan Installer — Linux & macOS
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/zeexz/secret-leak-scanner/main/install.sh | bash
#
# Environment variables:
#   LEAKSCAN_INSTALL_DIR  Override install directory (default: ~/.leakscan/bin)
#   GITHUB_TOKEN          Authenticate with GitHub API (for private repos / rate limits)
# ─────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────
REPO="zeexz/secret-leak-scanner"
BINARY_NAME="leakscan"
INSTALL_DIR="${LEAKSCAN_INSTALL_DIR:-$HOME/.leakscan/bin}"
GITHUB_API="https://api.github.com/repos/$REPO/releases/latest"
# ──────────────────────────────────────────────────────────────────

# ── Colors ────────────────────────────────────────────────────────
PURPLE='\033[35m'
CYAN='\033[36m'
GREEN='\033[32m'
YELLOW='\033[33m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

banner() {
    echo ""
    echo "  ${BOLD}${PURPLE}⚡ LEAKSCAN INSTALLER ⚡${RESET}"
    echo "  ${CYAN}Secrets & Credential Leak Scanner${RESET}"
    echo "  ${DIM}────────────────────────────────────${RESET}"
    echo ""
}

info()  { echo "  ${CYAN}● $1${RESET}"; }
step()  { echo "  ${DIM}→ $1${RESET}"; }
ok()    { echo "  ${GREEN}✅ $1${RESET}"; }
warn()  { echo "  ${YELLOW}⚠ $1${RESET}"; }
fail()  { echo "  ${PURPLE}✖ $1${RESET}" >&2; exit 1; }

# ── Detect OS & Architecture ─────────────────────────────────────
detect_platform() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"

    case "$OS" in
        linux)  OS="linux" ;;
        darwin) OS="darwin" ;;
        *)      fail "Unsupported OS: $OS" ;;
    esac

    case "$ARCH" in
        x86_64|amd64)   ARCH="amd64" ;;
        aarch64|arm64)  ARCH="arm64" ;;
        armv7l)         ARCH="armv7" ;;
        i386|i686)      ARCH="386" ;;
        *)              fail "Unsupported architecture: $ARCH" ;;
    esac
}

# ── Check for required commands ───────────────────────────────────
check_deps() {
    for cmd in curl tar; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            fail "Required command '$cmd' is not installed. Please install it and try again."
        fi
    done
}

# ── Fetch latest release info ────────────────────────────────────
fetch_release() {
    step "Fetching latest release from GitHub..."

    CURL_AUTH=""
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        CURL_AUTH="-H \"Authorization: Bearer $GITHUB_TOKEN\""
    fi

    RELEASE_JSON=$(curl -fsSL -H "Accept: application/vnd.github.v3+json" \
        ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
        "$GITHUB_API") || fail "Failed to fetch release info from $GITHUB_API"

    VERSION=$(echo "$RELEASE_JSON" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')

    if [ -z "$VERSION" ]; then
        fail "Could not determine latest version."
    fi
}

# ── Find download URL for our platform ───────────────────────────
find_asset_url() {
    # Try common naming patterns:
    #   leakscan_v1.0.0_linux_amd64.tar.gz
    #   leakscan-linux-amd64.tar.gz
    #   leakscan_linux_amd64.tar.gz

    DOWNLOAD_URL=""

    # Extract all browser_download_url values
    ASSET_URLS=$(echo "$RELEASE_JSON" | grep '"browser_download_url"' | sed 's/.*"browser_download_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')

    for url in $ASSET_URLS; do
        case "$url" in
            *"${OS}"*"${ARCH}"*.tar.gz)
                DOWNLOAD_URL="$url"
                break
                ;;
            *"${OS}"*"${ARCH}"*.zip)
                DOWNLOAD_URL="$url"
                break
                ;;
            *"${OS}"*"${ARCH}"*)
                DOWNLOAD_URL="$url"
                break
                ;;
        esac
    done

    if [ -z "$DOWNLOAD_URL" ]; then
        fail "No compatible asset found for ${OS}/${ARCH} in release ${VERSION}.
Available assets:
$(echo "$ASSET_URLS" | sed 's/^/  - /')"
    fi
}

# ── Download and install ─────────────────────────────────────────
install_binary() {
    step "Downloading $(basename "$DOWNLOAD_URL")..."

    TEMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TEMP_DIR"' EXIT

    ASSET_NAME=$(basename "$DOWNLOAD_URL")
    TEMP_FILE="$TEMP_DIR/$ASSET_NAME"

    curl -fsSL ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
        -o "$TEMP_FILE" "$DOWNLOAD_URL" || fail "Download failed."

    # Create install directory
    mkdir -p "$INSTALL_DIR"

    # Extract or copy
    case "$ASSET_NAME" in
        *.tar.gz)
            step "Extracting archive..."
            tar -xzf "$TEMP_FILE" -C "$TEMP_DIR"
            # Find the binary
            EXTRACTED=$(find "$TEMP_DIR" -name "$BINARY_NAME" -type f | head -1)
            if [ -z "$EXTRACTED" ]; then
                # Try without exact name match
                EXTRACTED=$(find "$TEMP_DIR" -name "leakscan*" -type f -not -name "*.tar.gz" | head -1)
            fi
            if [ -z "$EXTRACTED" ]; then
                fail "Could not find leakscan binary in the archive."
            fi
            cp "$EXTRACTED" "$INSTALL_DIR/$BINARY_NAME"
            ;;
        *.zip)
            step "Extracting archive..."
            unzip -qo "$TEMP_FILE" -d "$TEMP_DIR"
            EXTRACTED=$(find "$TEMP_DIR" -name "$BINARY_NAME" -type f | head -1)
            if [ -z "$EXTRACTED" ]; then
                EXTRACTED=$(find "$TEMP_DIR" -name "leakscan*" -type f -not -name "*.zip" | head -1)
            fi
            if [ -z "$EXTRACTED" ]; then
                fail "Could not find leakscan binary in the archive."
            fi
            cp "$EXTRACTED" "$INSTALL_DIR/$BINARY_NAME"
            ;;
        *)
            # Direct binary download
            cp "$TEMP_FILE" "$INSTALL_DIR/$BINARY_NAME"
            ;;
    esac

    chmod +x "$INSTALL_DIR/$BINARY_NAME"
}

# ── Update shell profile PATH ────────────────────────────────────
setup_path() {
    # Check if already on PATH
    case ":$PATH:" in
        *":$INSTALL_DIR:"*)
            return
            ;;
    esac

    step "Adding $INSTALL_DIR to PATH..."

    PATH_LINE="export PATH=\"$INSTALL_DIR:\$PATH\""

    # Detect shell and config file
    SHELL_NAME=$(basename "${SHELL:-/bin/sh}")
    case "$SHELL_NAME" in
        zsh)   PROFILE="$HOME/.zshrc" ;;
        bash)
            if [ -f "$HOME/.bashrc" ]; then
                PROFILE="$HOME/.bashrc"
            else
                PROFILE="$HOME/.bash_profile"
            fi
            ;;
        fish)
            PROFILE="$HOME/.config/fish/config.fish"
            PATH_LINE="fish_add_path $INSTALL_DIR"
            ;;
        *)     PROFILE="$HOME/.profile" ;;
    esac

    # Only add if not already present
    if [ -f "$PROFILE" ] && grep -q "$INSTALL_DIR" "$PROFILE" 2>/dev/null; then
        return
    fi

    echo "" >> "$PROFILE"
    echo "# LeakScan CLI" >> "$PROFILE"
    echo "$PATH_LINE" >> "$PROFILE"

    info "Added to $PROFILE"
}

# ── Main ──────────────────────────────────────────────────────────
main() {
    banner
    check_deps
    detect_platform

    info "Platform:     $OS/$ARCH"
    info "Install Dir:  $INSTALL_DIR"
    echo ""

    fetch_release
    info "Version:      $VERSION"
    echo ""

    find_asset_url
    install_binary
    setup_path

    echo ""
    ok "leakscan $VERSION installed successfully!"
    echo ""
    info "Binary:  $INSTALL_DIR/$BINARY_NAME"
    echo ""

    # Quick verify
    if "$INSTALL_DIR/$BINARY_NAME" --version >/dev/null 2>&1; then
        INSTALLED_VERSION=$("$INSTALL_DIR/$BINARY_NAME" --version 2>&1 || true)
        info "Verify:  $INSTALLED_VERSION"
    else
        warn "Restart your terminal for PATH changes to take effect."
    fi

    echo ""
    echo "  ${DIM}┌─────────────────────────────────────────────────┐${RESET}"
    echo "  ${DIM}│  Restart your terminal, then run:               │${RESET}"
    echo "  ${DIM}│                                                 │${RESET}"
    echo "  ${DIM}│    ${CYAN}leakscan scan .${DIM}                              │${RESET}"
    echo "  ${DIM}│    ${CYAN}leakscan tui${DIM}                                 │${RESET}"
    echo "  ${DIM}│                                                 │${RESET}"
    echo "  ${DIM}└─────────────────────────────────────────────────┘${RESET}"
    echo ""
}

main
