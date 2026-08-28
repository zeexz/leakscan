#!/usr/bin/env sh
# LeakScan Installer — Linux & macOS (improved)
#
# Features:
# - Pin a release tag or use 'latest'
# - Verify SHA256 checksum if a .sha256 asset is attached to the release
# - Optional cosign verification when signature + certificate assets are attached and `cosign` is installed
# - Supports --dry-run and --uninstall modes
# - Installs to $LEAKSCAN_INSTALL_DIR or ~/.leakscan/bin by default
#
# Usage examples:
#   ./install.sh                    # install latest
#   ./install.sh --tag v1.2.3       # install specific tag
#   ./install.sh --dry-run          # show actions but don't install
#   ./install.sh --uninstall        # remove installed binary
#
set -euo pipefail

# Defaults (change these only if you know what you're doing)
REPO="zeexz/leakscan"
BINARY_NAME="leakscan"
INSTALL_DIR_DEFAULT="$HOME/.leakscan/bin"
GITHUB_API_BASE="https://api.github.com/repos"

# CLI options
TAG="latest"
INSTALL_DIR=""
DRY_RUN=0
UNINSTALL=0
NO_PATH=0
VERIFY_COSIGN=0
QUIET=0

print_usage() {
  cat <<EOF
Usage: $0 [--tag <tag>] [--install-dir <path>] [--dry-run] [--uninstall] [--no-path] [--verify-cosign]

Options:
  --tag <tag>         Install a specific release tag (e.g. v1.2.3). Default: latest
  --install-dir PATH  Install directory. Default: $INSTALL_DIR_DEFAULT
  --dry-run           Print actions without performing them
  --uninstall         Remove installed binary and exit
  --no-path           Do not attempt to add install dir to PATH/profile
  --verify-cosign     Attempt cosign verification if signature assets exist (requires cosign installed)
  --quiet             Minimize output
  --help              Show this help
EOF
}

# Simple logging helpers
info()  { [ "$QUIET" -eq 0 ] && printf "[info] %s\n" "$1"; }
step()  { [ "$QUIET" -eq 0 ] && printf "  → %s\n" "$1"; }
ok()    { [ "$QUIET" -eq 0 ] && printf "[ok] %s\n" "$1"; }
warn()  { printf "[warn] %s\n" "$1"; }
fail()  { printf "[error] %s\n" "$1" >&2; exit 1; }

# Parse args
while [ "$#" -gt 0 ]; do
  case "$1" in
    --tag)
      TAG="$2"; shift 2;;
    --install-dir)
      INSTALL_DIR="$2"; shift 2;;
    --dry-run)
      DRY_RUN=1; shift;;
    --uninstall)
      UNINSTALL=1; shift;;
    --no-path)
      NO_PATH=1; shift;;
    --verify-cosign)
      VERIFY_COSIGN=1; shift;;
    --quiet)
      QUIET=1; shift;;
    --help|-h)
      print_usage; exit 0;;
    *)
      echo "Unknown arg: $1"; print_usage; exit 2;;
  esac
done

INSTALL_DIR="${INSTALL_DIR:-${LEAKSCAN_INSTALL_DIR:-$INSTALL_DIR_DEFAULT}}"

# platform detection
detect_platform() {
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')
  ARCH=$(uname -m)
  case "$OS" in
    linux) OS=linux ;; darwin) OS=darwin ;; *) fail "Unsupported OS: $OS";;
  esac
  case "$ARCH" in
    x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; armv7l) ARCH=armv7 ;; i386|i686) ARCH=386 ;; *) fail "Unsupported arch: $ARCH";;
  esac
}

check_deps() {
  for cmd in curl tar mktemp grep sed awk; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      fail "Required command '$cmd' not found. Please install it and re-run."
    fi
  done
}

# Uninstall flow
uninstall() {
  if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
      info "Would remove $INSTALL_DIR/$BINARY_NAME"
    else
      rm -f "$INSTALL_DIR/$BINARY_NAME" && ok "Removed $INSTALL_DIR/$BINARY_NAME"
    fi
  else
    warn "No installation found at $INSTALL_DIR/$BINARY_NAME"
  fi

  # Optionally remove PATH lines from common shells (best-effort; we don't edit aggressively)
  if [ "$NO_PATH" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    info "If you added a PATH entry to your shell profile, you may wish to remove it manually."
  fi
  exit 0
}

# Fetch release metadata
fetch_release_json() {
  API_URL="$GITHUB_API_BASE/$REPO/releases"
  if [ "$TAG" = "latest" ]; then
    API_URL="$API_URL/latest"
  else
    API_URL="$API_URL/tags/$TAG"
  fi
  step "Fetching release metadata from $API_URL"
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    RELEASE_JSON=$(curl -fsSL -H "Accept: application/vnd.github.v3+json" -H "Authorization: Bearer $GITHUB_TOKEN" "$API_URL") || fail "Failed to fetch release info"
  else
    RELEASE_JSON=$(curl -fsSL -H "Accept: application/vnd.github.v3+json" "$API_URL") || fail "Failed to fetch release info"
  fi
}

# Find asset URL matching platform
find_asset_for_platform() {
  ASSET_URLS=$(printf "%s" "$RELEASE_JSON" | grep '"browser_download_url"' | sed -E 's/.*"browser_download_url"[[:space:]]*:[[:space:]]*"([^\"]*)".*/\1/')
  DOWNLOAD_URL=""
  for url in $ASSET_URLS; do
    case "$url" in
      *"$OS"*"$ARCH"*.tar.gz|*"$OS"*"$ARCH"*.zip|*"$OS"*"$ARCH"*) DOWNLOAD_URL="$url"; break;;
      *) ;;
    esac
  done
  if [ -z "$DOWNLOAD_URL" ]; then
    # fallback to any asset with the binary name
    for url in $ASSET_URLS; do
      case "$url" in
        *"$BINARY_NAME"*.tar.gz|*"$BINARY_NAME"*.zip|*"$BINARY_NAME"*) DOWNLOAD_URL="$url"; break;;
      esac
    done
  fi
  if [ -z "$DOWNLOAD_URL" ]; then
    fail "No compatible release asset found for $OS/$ARCH. Available:\n$ASSET_URLS"
  fi
}

# Try to find checksum and signature assets related to the chosen asset
find_verification_assets() {
  ASSET_NAME=$(basename "$DOWNLOAD_URL")
  ASSET_URLS=$(printf "%s" "$RELEASE_JSON" | grep '"browser_download_url"' | sed -E 's/.*"browser_download_url"[[:space:]]*:[[:space:]]*"([^\"]*)".*/\1/')
  CHECKSUM_URL=""
  SIG_URL=""
  CERT_URL=""

  # Common checksum names: <asset>.sha256, <basename>.sha256, checksums.txt
  for url in $ASSET_URLS; do
    case "$url" in
      *"$ASSET_NAME"*.sha256|*"$ASSET_NAME"*.sha256sum) CHECKSUM_URL="$url"; break;;
    esac
  done
  # Try basename.sha256
  BASENAME=$(printf "%s" "$ASSET_NAME" | sed 's/\.[^.]*$//')
  for url in $ASSET_URLS; do
    case "$url" in
      *"$BASENAME"*.sha256|*"$BASENAME"*.sha256sum) CHECKSUM_URL="$url"; break;;
    esac
  done

  # Try common cosign pair names: <asset>.sig and <asset>.pem (or .crt)
  for url in $ASSET_URLS; do
    case "$url" in
      *"$ASSET_NAME"*.sig) SIG_URL="$url";;
      *"$ASSET_NAME"*.pem|*"$ASSET_NAME"*.crt) CERT_URL="$url";;
    esac
  done
}

verify_checksum() {
  if [ -z "$CHECKSUM_URL" ]; then
    warn "No checksum asset found for automatic verification"
    return 1
  fi
  step "Downloading checksum: $CHECKSUM_URL"
  curl -fsSL ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} -o "$TEMP_DIR/$ASSET_NAME.sha256" "$CHECKSUM_URL" || fail "Failed to download checksum"

  # Normalize the checksum file (may contain 'sha256  filename' or 'checksum  -')
  CHKSUM_LINE=$(awk 'NF{print $1}' "$TEMP_DIR/$ASSET_NAME.sha256" | head -n1)
  if [ -z "$CHKSUM_LINE" ]; then
    warn "Checksum file appears empty"
    return 1
  fi

  step "Computing local SHA256 of downloaded asset"
  SHA_LOCAL=$(sha256sum "$TEMP_FILE" | awk '{print $1}')
  if [ "$SHA_LOCAL" = "$CHKSUM_LINE" ]; then
    ok "Checksum OK"
    return 0
  else
    fail "Checksum mismatch: expected $CHKSUM_LINE, got $SHA_LOCAL"
  fi
}

verify_cosign() {
  if [ "$VERIFY_COSIGN" -ne 1 ]; then
    return 2
  fi
  if [ -z "$SIG_URL" -o -z "$CERT_URL" ]; then
    warn "Cosign assets not found; skipping cosign verification"
    return 1
  fi
  if ! command -v cosign >/dev/null 2>&1; then
    warn "cosign not installed; install cosign or run without --verify-cosign"
    return 1
  fi

  step "Downloading cosign signature and certificate"
  curl -fsSL ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} -o "$TEMP_DIR/$ASSET_NAME.sig" "$SIG_URL" || fail "Failed to download signature"
  curl -fsSL ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} -o "$TEMP_DIR/$ASSET_NAME.pem" "$CERT_URL" || fail "Failed to download certificate"

  step "Running cosign verify-blob"
  if cosign verify-blob --signature "$TEMP_DIR/$ASSET_NAME.sig" --certificate "$TEMP_DIR/$ASSET_NAME.pem" "$TEMP_FILE"; then
    ok "cosign verification OK"
    return 0
  else
    fail "cosign verification failed"
  fi
}

# Add install dir to common shell profile (best-effort)
setup_path() {
  [ "$NO_PATH" -eq 1 ] && return
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) return;;
  esac
  step "Adding $INSTALL_DIR to PATH in shell profile (best-effort)"
  SHELL_NAME=$(basename "${SHELL:-/bin/sh}")
  case "$SHELL_NAME" in
    zsh) PROFILE="$HOME/.zshrc" ;; 
    bash)
      if [ -f "$HOME/.bashrc" ]; then PROFILE="$HOME/.bashrc"; else PROFILE="$HOME/.bash_profile"; fi ;; 
    fish) PROFILE="$HOME/.config/fish/config.fish" ;; 
    *) PROFILE="$HOME/.profile" ;;
  esac
  [ -f "$PROFILE" ] || touch "$PROFILE"
  if grep -q "$INSTALL_DIR" "$PROFILE" 2>/dev/null; then
    return
  fi
  echo "\n# LeakScan CLI" >> "$PROFILE"
  echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$PROFILE"
  ok "Appended PATH entry to $PROFILE"
}

# MAIN
if [ "$UNINSTALL" -eq 1 ]; then
  detect_platform
  uninstall
fi

check_deps
detect_platform

info "Platform: $OS/$ARCH"
info "Install dir: $INSTALL_DIR"
info "Release tag: $TAG"

fetch_release_json
find_asset_for_platform
find_verification_assets

TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT
ASSET_NAME=$(basename "$DOWNLOAD_URL")
TEMP_FILE="$TEMP_DIR/$ASSET_NAME"

step "Downloading asset: $DOWNLOAD_URL"
if [ "$DRY_RUN" -eq 1 ]; then
  info "DRY-RUN: would download to $TEMP_FILE"
else
  curl -fsSL ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} -o "$TEMP_FILE" "$DOWNLOAD_URL" || fail "Asset download failed"
fi

# Try verification (checksum first, then cosign if requested)
if [ "$DRY_RUN" -eq 0 ]; then
  if verify_checksum; then
    :
  else
    # checksum failed or not present; try cosign if requested
    if [ "$VERIFY_COSIGN" -eq 1 ]; then
      verify_cosign || warn "Verification did not succeed"
    else
      warn "No verification performed (attach .sha256 or use --verify-cosign)"
    fi
  fi
fi

# Extract and install
if [ "$DRY_RUN" -eq 1 ]; then
  info "DRY-RUN: would extract and install $BINARY_NAME into $INSTALL_DIR"
  exit 0
fi

mkdir -p "$INSTALL_DIR"
case "$ASSET_NAME" in
  *.tar.gz)
    step "Extracting tar.gz"
    tar -xzf "$TEMP_FILE" -C "$TEMP_DIR"
    EXTRACTED=$(find "$TEMP_DIR" -type f -name "$BINARY_NAME" -perm -111 | head -n1 || true)
    if [ -z "$EXTRACTED" ]; then
      EXTRACTED=$(find "$TEMP_DIR" -type f -name "${BINARY_NAME}*" | head -n1 || true)
    fi
    if [ -z "$EXTRACTED" ]; then fail "Could not find binary inside archive"; fi
    cp "$EXTRACTED" "$INSTALL_DIR/$BINARY_NAME"
    ;;
  *.zip)
    step "Extracting zip"
    if command -v unzip >/dev/null 2>&1; then
      unzip -qo "$TEMP_FILE" -d "$TEMP_DIR"
    else
      fail "zip archive requires 'unzip' command"
    fi
    EXTRACTED=$(find "$TEMP_DIR" -type f -name "$BINARY_NAME" -perm -111 | head -n1 || true)
    if [ -z "$EXTRACTED" ]; then
      EXTRACTED=$(find "$TEMP_DIR" -type f -name "${BINARY_NAME}*" | head -n1 || true)
    fi
    if [ -z "$EXTRACTED" ]; then fail "Could not find binary inside zip"; fi
    cp "$EXTRACTED" "$INSTALL_DIR/$BINARY_NAME"
    ;;
  *)
    step "Installing direct binary"
    cp "$TEMP_FILE" "$INSTALL_DIR/$BINARY_NAME"
    ;;
esac

chmod +x "$INSTALL_DIR/$BINARY_NAME"
ok "Installed $BINARY_NAME to $INSTALL_DIR/$BINARY_NAME"

# Add to PATH/profile if desired
setup_path

# Quick verify
if "$INSTALL_DIR/$BINARY_NAME" --version >/dev/null 2>&1; then
  INSTALLED_VERSION=$("$INSTALL_DIR/$BINARY_NAME" --version 2>&1 || true)
  info "Verify: $INSTALLED_VERSION"
else
  warn "Could not run $INSTALL_DIR/$BINARY_NAME --version; restart shell if PATH updated"
fi

info "Done. Run '$BINARY_NAME --help' to get started."