#!/bin/bash
# Custosa - One-Click Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/uditanshutomar/CustosaXopenclaw/main/install.sh | bash

set -e

echo ""
echo "  ██████╗██╗   ██╗███████╗████████╗ ██████╗ ███████╗ █████╗ "
echo " ██╔════╝██║   ██║██╔════╝╚══██╔══╝██╔═══██╗██╔════╝██╔══██╗"
echo " ██║     ██║   ██║███████╗   ██║   ██║   ██║███████╗███████║"
echo " ██║     ██║   ██║╚════██║   ██║   ██║   ██║╚════██║██╔══██║"
echo " ╚██████╗╚██████╔╝███████║   ██║   ╚██████╔╝███████║██║  ██║"
echo "  ╚═════╝ ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚══════╝╚═╝  ╚═╝"
echo ""
echo "  Prompt Injection Protection for OpenClaw/Moltbot"
echo "  ================================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Darwin*) OS="macos" ;;
        Linux*)  OS="linux" ;;
        *)       error "Unsupported operating system" ;;
    esac
    info "Detected OS: $OS"
}

# Check if Homebrew is available
has_brew() {
    command -v brew &> /dev/null
}

# Check Python version
check_python() {
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
        MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 10 ]; then
            success "Python $PYTHON_VERSION found"
            return 0
        fi
    fi
    return 1
}

# Install via Homebrew (preferred)
install_with_brew() {
    info "Installing via Homebrew..."

    # Add tap if not already added
    if ! brew tap | grep -q "uditanshutomar/custosaxopenclaw"; then
        brew tap uditanshutomar/custosaxopenclaw
    fi

    # Install custosa
    brew install custosa
    success "Installed via Homebrew"
}

# Install via pip (fallback)
install_with_pip() {
    info "Installing via pip..."

    if ! check_python; then
        error "Python 3.10+ required. Install with: brew install python@3.12"
    fi

    pip3 install --user git+https://github.com/uditanshutomar/CustosaXopenclaw.git
    success "Installed via pip"

    # Ensure ~/.local/bin is in PATH
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        warn "Add ~/.local/bin to your PATH:"
        echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
}

# Main installation flow
main() {
    detect_os

    # Check if already installed
    if command -v custosa &> /dev/null; then
        warn "Custosa is already installed"
        custosa --version 2>/dev/null || true
        echo ""
        read -p "Reinstall? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 0
        fi
    fi

    echo ""

    # Install: prefer Homebrew on macOS, pip elsewhere
    if [ "$OS" = "macos" ] && has_brew; then
        install_with_brew
    elif has_brew; then
        install_with_brew
    else
        install_with_pip
    fi

    echo ""
    echo "================================================"
    success "Installation Complete!"
    echo "================================================"
    echo ""
    echo "Next steps:"
    echo "  ${GREEN}custosa install${NC}  - Run setup wizard"
    echo ""
    echo "Commands:"
    echo "  custosa status  - Check protection status"
    echo "  custosa logs    - View security logs"
    echo "  custosa stop    - Stop protection"
    echo ""
}

main "$@"
