#!/bin/bash
# Custosa V1 - One-Click Installer
# Usage: curl -fsSL https://install.custosa.dev | bash
#    Or: ./scripts/install.sh

set -e

echo ""
echo "🦞 Custosa V1 Installer"
echo "   Prompt Injection Protection for Moltbot"
echo "================================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
check_python() {
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
        MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
        
        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 10 ]; then
            echo -e "${GREEN}✓${NC} Python $PYTHON_VERSION found"
            return 0
        fi
    fi
    
    echo -e "${RED}✗${NC} Python 3.10+ required"
    echo "  Install with: brew install python@3.11"
    exit 1
}

# Check for Moltbot
check_moltbot() {
    if [ -f "$HOME/.clawdbot/moltbot.json" ]; then
        echo -e "${GREEN}✓${NC} Moltbot installation found"
        return 0
    fi
    
    echo -e "${YELLOW}⚠${NC} Moltbot not found at ~/.clawdbot/moltbot.json"
    echo "  Install Moltbot first: https://docs.molt.bot/"
    echo ""
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
}

# Install Custosa
install_custosa() {
    echo ""
    echo "Installing Custosa..."
    
    # Try pip install
    if pip3 install --user custosa 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Installed via pip"
    else
        # Fall back to local install
        echo "Installing from local source..."
        pip3 install --user -e . 2>/dev/null || pip3 install -e .
        echo -e "${GREEN}✓${NC} Installed from source"
    fi
}

# Run setup wizard
run_setup() {
    echo ""
    echo "Running setup wizard..."
    echo ""
    
    # Find custosa in PATH or local
    if command -v custosa &> /dev/null; then
        custosa install
    elif [ -f "./custosa/main.py" ]; then
        python3 -m custosa.main install
    else
        echo -e "${RED}✗${NC} Could not find custosa command"
        exit 1
    fi
}

# Main installation flow
main() {
    check_python
    check_moltbot
    install_custosa
    run_setup
    
    echo ""
    echo "================================================"
    echo -e "${GREEN}🎉 Installation Complete!${NC}"
    echo "================================================"
    echo ""
    echo "Custosa is now protecting your Moltbot."
    echo ""
    echo "Commands:"
    echo "  custosa status  - Check protection status"
    echo "  custosa logs    - View security logs"
    echo "  custosa stop    - Stop protection"
    echo ""
}

main "$@"
