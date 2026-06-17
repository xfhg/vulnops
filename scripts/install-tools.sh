#!/usr/bin/env bash
# install-tools.sh — Download Ghost Security tool binaries to bins/
# Jailed: installs to bins/ relative to harness root, never to ~/.ghost/bin/
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_DIR="${HARNESS_ROOT}/bins"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[install]${NC} $*"; }
warn() { echo -e "${YELLOW}[install]${NC} $*"; }
err()  { echo -e "${RED}[install]${NC} $*" >&2; }

detect_platform() {
    local os arch
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"

    case "$os" in
        linux)  os="linux" ;;
        darwin) os="darwin" ;;
        *)      err "Unsupported OS: $os"; exit 1 ;;
    esac

    case "$arch" in
        x86_64|amd64)  arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *)             err "Unsupported arch: $arch"; exit 1 ;;
    esac

    echo "${os}_${arch}"
}

get_latest_version() {
    local repo="$1"
    local version=""

    # Try gh CLI first (more reliable, handles auth/rate limits)
    if command -v gh &>/dev/null; then
        version="$(gh release view --repo "$repo" --json tagName -q '.tagName' 2>/dev/null || true)"
    fi

    # Fallback to GitHub API
    if [ -z "$version" ]; then
        version="$(curl -sfL "https://api.github.com/repos/${repo}/releases/latest" \
            | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\(.*\)".*/\1/' 2>/dev/null || true)"
    fi

    # Last resort: scrape the releases page
    if [ -z "$version" ]; then
        version="$(curl -sfL "https://github.com/${repo}/releases/latest" 2>/dev/null \
            | grep -oP '(?<=/releases/tag/)[^"]+' | head -1 || true)"
    fi

    echo "$version"
}

download_and_extract() {
    local repo="$1"
    local binary="$2"
    local version="$3"

    local platform
    platform="$(detect_platform)"
    local os="${platform%_*}"
    local arch="${platform#*_}"

    mkdir -p "$INSTALL_DIR"

    if [ "$version" = "latest" ]; then
        log "Fetching latest version for ${repo}..."
        version="$(get_latest_version "$repo")"
        if [ -z "$version" ]; then
            err "Failed to determine latest version for $repo"
            err "Try: $0 --version <tag> $binary"
            return 1
        fi
    fi

    log "Installing ${binary} ${version} for ${platform}..."

    local tmpdir
    tmpdir="$(mktemp -d)"
    trap "rm -rf '$tmpdir'" RETURN

    # Try download patterns in order:
    # 1. <binary>_<os>_<arch>.tar.gz (ghostsecurity convention)
    # 2. <binary>-<os>-<arch>.tar.gz (alternative)
    # 3. <binary>_<os>_<arch> (bare binary, some repos)
    # 4. <binary>-<os>-<arch> (bare binary alt)
    local patterns=(
        "${binary}_${os}_${arch}.tar.gz"
        "${binary}-${os}-${arch}.tar.gz"
        "${binary}_${os}_${arch}"
        "${binary}-${os}-${arch}"
    )

    local downloaded=false
    for asset in "${patterns[@]}"; do
        local url="https://github.com/${repo}/releases/download/${version}/${asset}"
        log "  Trying: ${asset}"

        if curl -sfL -o "${tmpdir}/${asset}" "$url"; then
            downloaded=true

            if [[ "$asset" == *.tar.gz ]]; then
                # Extract binary from tarball
                log "  Extracting..."
                tar -xzf "${tmpdir}/${asset}" -C "$tmpdir" 2>/dev/null || true

                # Find the binary (may be at top level or in a subdirectory)
                local found=false
                for candidate in "${tmpdir}/${binary}" "${tmpdir}"/*/ "${tmpdir}/${binary}"*; do
                    if [ -f "$candidate" ] && [ -x "$candidate" ]; then
                        cp "$candidate" "${INSTALL_DIR}/${binary}"
                        chmod +x "${INSTALL_DIR}/${binary}"
                        found=true
                        break
                    fi
                done

                # Broader search: find any executable that isn't a script
                if [ "$found" = false ]; then
                    while IFS= read -r -d '' f; do
                        if file "$f" 2>/dev/null | grep -q "Mach-O\|ELF"; then
                            cp "$f" "${INSTALL_DIR}/${binary}"
                            chmod +x "${INSTALL_DIR}/${binary}"
                            found=true
                            break
                        fi
                    done < <(find "$tmpdir" -type f -executable -print0 2>/dev/null)
                fi

                if [ "$found" = false ]; then
                    err "  Downloaded tarball but could not find binary inside"
                    downloaded=false
                fi
            else
                # Bare binary
                cp "${tmpdir}/${asset}" "${INSTALL_DIR}/${binary}"
                chmod +x "${INSTALL_DIR}/${binary}"
            fi

            break
        fi
    done

    if [ "$downloaded" = false ]; then
        err "Failed to download ${binary} ${version} for ${platform}"
        err "Checked URLs:"
        for asset in "${patterns[@]}"; do
            err "  https://github.com/${repo}/releases/download/${version}/${asset}"
        done
        err ""
        err "Manually check: https://github.com/${repo}/releases"
        return 1
    fi

    # Verify installation
    if command -v "$binary" &>/dev/null || [ -x "${INSTALL_DIR}/${binary}" ]; then
        fix_binary "${INSTALL_DIR}/${binary}"
        log "  Installed: ${INSTALL_DIR}/${binary}"
        echo "$version" > "${INSTALL_DIR}/.${binary}.version"
        return 0
    else
        err "  Binary installed but not executable: ${INSTALL_DIR}/${binary}"
        return 1
    fi
}

version_for_tool() {
    local tool="$1"
    local default_version="$2"
    local var_name value
    case "$tool" in
        wraith) var_name="WRAITH_VERSION" ;;
        poltergeist) var_name="POLTERGEIST_VERSION" ;;
        omp) var_name="OMP_VERSION" ;;
        osv-scanner) var_name="OSV_SCANNER_VERSION" ;;
        *) var_name="" ;;
    esac
    if [ -n "$var_name" ]; then
        value="${!var_name:-}"
        if [ -n "$value" ]; then
            echo "$value"
            return
        fi
    fi
    echo "$default_version"
}

download_omp() {
    local version="$1"
    local platform
    platform="$(detect_platform)"

    mkdir -p "$INSTALL_DIR"

    # Check if already up to date
    local version_file="${INSTALL_DIR}/.omp.version"
    if [ -f "${INSTALL_DIR}/omp" ] && [ -f "$version_file" ]; then
        local installed_version
        installed_version="$(cat "$version_file")"
        if [ "$version" = "latest" ] || [ "$installed_version" = "$version" ]; then
            log "  omp: already installed (${installed_version})"
            return 0
        fi
    fi

    # Resolve version
    if [ "$version" = "latest" ]; then
        log "Fetching latest OMP version..."
        version="$(get_latest_version "can1357/oh-my-pi")"
        if [ -z "$version" ]; then
            err "Failed to determine latest OMP version"
            return 1
        fi
    fi

    # Map platform to OMP binary name. OMP's release assets use x64 for
    # Intel/AMD 64-bit builds, while Ghost Security tools use amd64.
    local os="${platform%_*}"
    local arch="${platform#*_}"
    local omp_arch="$arch"
    case "$arch" in
        amd64) omp_arch="x64" ;;
    esac
    local ext=""
    if [ "$os" = "windows" ]; then
        ext=".exe"
    fi

    log "Installing omp ${version} for ${platform}..."

    local assets=(
        "omp-${os}-${omp_arch}${ext}"
        "omp-${os}-${arch}${ext}"
    )
    local downloaded=false
    local asset
    for asset in "${assets[@]}"; do
        local url="https://github.com/can1357/oh-my-pi/releases/download/${version}/${asset}"
        log "  Trying: ${asset}"
        if curl -sfL -o "${INSTALL_DIR}/omp" "$url"; then
            downloaded=true
            break
        fi
    done

    if [ "$downloaded" = false ]; then
        err "Failed to download omp ${version} for ${platform}"
        err "Checked URLs:"
        for asset in "${assets[@]}"; do
            err "  https://github.com/can1357/oh-my-pi/releases/download/${version}/${asset}"
        done
        err "Check: https://github.com/can1357/oh-my-pi/releases"
        return 1
    fi

    chmod +x "${INSTALL_DIR}/omp"
    fix_binary "${INSTALL_DIR}/omp"
    echo "$version" > "$version_file"
    log "  Installed: ${INSTALL_DIR}/omp"
    return 0
}

download_osv_scanner() {
    local version="${1:-latest}"
    local platform
    platform="$(detect_platform)"

    mkdir -p "$INSTALL_DIR"

    local version_file="${INSTALL_DIR}/.osv-scanner.version"
    if [ -x "${INSTALL_DIR}/osv-scanner" ] && [ -f "$version_file" ]; then
        local installed_version
        installed_version="$(cat "$version_file")"
        log "  osv-scanner: already installed (${installed_version})"
        return 0
    fi

    if [ "$version" = "latest" ]; then
        log "Fetching latest OSV-Scanner version..."
        version="$(get_latest_version "google/osv-scanner")"
        if [ -z "$version" ]; then
            err "Failed to determine latest OSV-Scanner version"
            return 1
        fi
    fi

    local os="${platform%_*}"
    local arch="${platform#*_}"
    local version_no_v="${version#v}"
    local ext=""
    if [ "$os" = "windows" ]; then
        ext=".exe"
    fi

    log "Installing osv-scanner ${version} for ${platform}..."

    local tmpdir
    tmpdir="$(mktemp -d)"
    trap "rm -rf '$tmpdir'" RETURN

    local assets=(
        "osv-scanner_${os}_${arch}${ext}"
        "osv-scanner_${version_no_v}_${os}_${arch}${ext}"
        "osv-scanner-${os}-${arch}${ext}"
        "osv-scanner_${os}_${arch}.tar.gz"
        "osv-scanner_${version_no_v}_${os}_${arch}.tar.gz"
        "osv-scanner-${os}-${arch}.tar.gz"
    )

    local downloaded=false
    local asset
    for asset in "${assets[@]}"; do
        local url="https://github.com/google/osv-scanner/releases/download/${version}/${asset}"
        log "  Trying: ${asset}"
        if curl -sfL -o "${tmpdir}/${asset}" "$url"; then
            downloaded=true
            if [[ "$asset" == *.tar.gz ]]; then
                log "  Extracting..."
                tar -xzf "${tmpdir}/${asset}" -C "$tmpdir" 2>/dev/null || true
                local found=false
                while IFS= read -r -d '' f; do
                    if [ "$(basename "$f")" = "osv-scanner" ] || file "$f" 2>/dev/null | grep -q "Mach-O\|ELF"; then
                        cp "$f" "${INSTALL_DIR}/osv-scanner"
                        chmod +x "${INSTALL_DIR}/osv-scanner"
                        found=true
                        break
                    fi
                done < <(find "$tmpdir" -type f -print0 2>/dev/null)
                if [ "$found" = false ]; then
                    err "  Downloaded tarball but could not find osv-scanner inside"
                    downloaded=false
                    continue
                fi
            else
                cp "${tmpdir}/${asset}" "${INSTALL_DIR}/osv-scanner"
                chmod +x "${INSTALL_DIR}/osv-scanner"
            fi
            break
        fi
    done

    if [ "$downloaded" = false ]; then
        err "Failed to download osv-scanner ${version} for ${platform}"
        err "Checked URLs:"
        for asset in "${assets[@]}"; do
            err "  https://github.com/google/osv-scanner/releases/download/${version}/${asset}"
        done
        err "Check: https://github.com/google/osv-scanner/releases"
        return 1
    fi

    fix_binary "${INSTALL_DIR}/osv-scanner"
    echo "$version" > "$version_file"
    log "  Installed: ${INSTALL_DIR}/osv-scanner"
    return 0
}

fix_binary() {
    local binary_path="$1"
    # Strip macOS quarantine attribute (set by browser/curl downloads)
    if command -v xattr &>/dev/null; then
        xattr -d com.apple.provenance "$binary_path" 2>/dev/null || true
    fi
    # Ad-hoc code sign for macOS Gatekeeper
    if command -v codesign &>/dev/null; then
        codesign --force --sign - "$binary_path" 2>/dev/null || true
    fi
}

ensure_osv_scanner() {
    local requested_version="${1:-latest}"
    # wraith shells out to osv-scanner — it must be next to wraith in bins/
    local target="${INSTALL_DIR}/osv-scanner"
    local version_file="${INSTALL_DIR}/.osv-scanner.version"
    if [ -x "$target" ] && [ -f "$version_file" ]; then
        local installed_version
        installed_version="$(cat "$version_file")"
        if [ "$requested_version" = "latest" ] || [ "$installed_version" = "$requested_version" ]; then
            log "  osv-scanner: already in ${INSTALL_DIR} (${installed_version})"
            return 0
        fi
    elif [ -x "$target" ] && [ "$requested_version" = "latest" ]; then
        log "  osv-scanner: already in ${INSTALL_DIR}"
        return 0
    else
        rm -f "$target"
    fi
    # Check PATH
    local sys_bin
    sys_bin="$(command -v osv-scanner 2>/dev/null || true)"
    if [ -n "$sys_bin" ] && [ -x "$sys_bin" ] && [ "$requested_version" = "latest" ]; then
        cp "$sys_bin" "$target"
        chmod +x "$target"
        fix_binary "$target"
        log "  osv-scanner: copied from ${sys_bin}"
        return 0
    fi
    download_osv_scanner "$requested_version"
}

usage() {
    cat <<EOF
Usage: $0 [tool...]

Install Ghost Security tool binaries to bins/.

Tools:
  wraith        SCA dependency vulnerability scanner
  poltergeist   Secrets/credentials scanner
  osv-scanner   OSV database scanner used by wraith
  omp           Oh My Pi orchestrator
  all           Install all tools (default)

Options:
  --version TAG   Specific version to install (default: latest)
  --help          Show this help

Examples:
  $0                  # Install all tools (latest)
  $0 wraith           # Install only wraith
  $0 --version v1.0.0 wraith   # Install specific version
EOF
}

main() {
    local tools=()
    local version="latest"

    while [ $# -gt 0 ]; do
        case "$1" in
            --version) version="$2"; shift 2 ;;
            --help)    usage; exit 0 ;;
            wraith|poltergeist|osv-scanner|omp|all) tools+=("$1"); shift ;;
            *)         err "Unknown tool: $1"; usage; exit 1 ;;
        esac
    done

    if [ ${#tools[@]} -eq 0 ]; then
        tools=("all")
    fi

    log "Install directory: ${INSTALL_DIR}"
    log "Platform: $(detect_platform)"
    log ""

    local failures=0
    for tool in "${tools[@]}"; do
        case "$tool" in
            wraith)
                download_and_extract "ghostsecurity/wraith" "wraith" "$(version_for_tool wraith "$version")" || ((failures++))
                ;;
            poltergeist)
                download_and_extract "ghostsecurity/poltergeist" "poltergeist" "$(version_for_tool poltergeist "$version")" || ((failures++))
                ;;
            osv-scanner)
                download_osv_scanner "$(version_for_tool osv-scanner "$version")" || ((failures++))
                ;;
            omp)
                download_omp "$(version_for_tool omp "$version")" || ((failures++))
                ;;
            all)
                download_and_extract "ghostsecurity/wraith" "wraith" "$(version_for_tool wraith "$version")" || ((failures++))
                download_and_extract "ghostsecurity/poltergeist" "poltergeist" "$(version_for_tool poltergeist "$version")" || ((failures++))
                download_omp "$(version_for_tool omp "$version")" || ((failures++))
                ;;
        esac
    done

    # ── osv-scanner (wraith dependency) ──
    ensure_osv_scanner "$(version_for_tool osv-scanner latest)" || ((failures++))
    # ── Graphify (required — graph-guided intrusion analysis) ──
    local VENV_DIR="${HARNESS_ROOT}/.venv"
    local graphify_failed=false
    if [ "${SKIP_GRAPHIFY_INSTALL:-0}" = "1" ]; then
        log "  graphify: skipped by SKIP_GRAPHIFY_INSTALL=1"
    elif [ -x "${VENV_DIR}/bin/graphify" ]; then
        log "  graphify: already installed (${VENV_DIR}/bin/graphify)"
    elif command -v python3 &>/dev/null; then
        log "  graphify: installing into ${VENV_DIR}..."
        if ! python3 -m venv "${VENV_DIR}" 2>/dev/null; then
            warn "  graphify: venv creation failed"
            graphify_failed=true
        fi
        if [ -x "${VENV_DIR}/bin/pip" ]; then
            local graphify_log="${HARNESS_ROOT}/.harness/logs/graphify-pip-install.log"
            mkdir -p "$(dirname "$graphify_log")"
            "${VENV_DIR}/bin/pip" install -q "graphifyy[openai]" >"$graphify_log" 2>&1 \
                && log "  graphify: installed (${VENV_DIR}/bin/graphify)" \
                || { warn "  graphify: pip install failed"; warn "  see: ${graphify_log}"; graphify_failed=true; }
        else
            graphify_failed=true
        fi
    else
        warn "python3 not found — graphify not installed"
        graphify_failed=true
    fi

    if [ "$graphify_failed" = true ]; then
        warn "  graphify is required by validate-config; fix the bootstrap error before audit runtime"
        ((failures++))
    fi

    log ""
    if [ $failures -gt 0 ]; then
        warn "${failures} tool(s) failed to install"
        exit 1
    fi

    log "Installation complete. Binaries in: ${INSTALL_DIR}"
    log "Add to PATH: export PATH=\"${INSTALL_DIR}:\$PATH\""
}

main "$@"
