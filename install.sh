#!/bin/bash

# CacheShadow Installation Script
# This script installs CacheShadow and its dependencies

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' 

echo -e "${BLUE}"
cat << "EOF"
    ╔═══════════════════════════════════════════════════════════════╗
    ║              🕷️  CacheShadow Installer  🕷️                    ║
    ║         Advanced Web Cache Poisoning Scanner                  ║
    ╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${YELLOW}[*]${NC} Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[-]${NC} Python 3 is not installed. Please install Python 3.7 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo -e "${GREEN}[+]${NC} Found Python $PYTHON_VERSION"

REQUIRED_VERSION="3.7"
if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${RED}[-]${NC} Python 3.7 or higher is required. You have Python $PYTHON_VERSION"
    exit 1
fi

echo -e "${YELLOW}[*]${NC} Checking pip installation..."
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}[-]${NC} pip3 is not installed. Installing pip..."
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
    python3 get-pip.py
    rm get-pip.py
fi
echo -e "${GREEN}[+]${NC} pip3 is installed"

echo -e "${YELLOW}[*]${NC} Installing dependencies from requirements.txt..."
pip3 install -r requirements.txt

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+]${NC} Dependencies installed successfully"
else
    echo -e "${RED}[-]${NC} Failed to install dependencies"
    exit 1
fi

echo -e "${YELLOW}[*]${NC} Making cache_poison_scanner.py executable..."
chmod +x cache_poison_scanner.py
echo -e "${GREEN}[+]${NC} Script is now executable"

echo -e "${YELLOW}[*]${NC} Do you want to create a symbolic link to run 'cacheshadow' from anywhere? (y/n)"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    SCRIPT_PATH="$(pwd)/cache_poison_scanner.py"
    
    if [ -w "/usr/local/bin" ]; then
        ln -sf "$SCRIPT_PATH" /usr/local/bin/cacheshadow
        echo -e "${GREEN}[+]${NC} Symbolic link created: /usr/local/bin/cacheshadow"
    else
        echo -e "${YELLOW}[!]${NC} Need sudo access to create symlink in /usr/local/bin"
        sudo ln -sf "$SCRIPT_PATH" /usr/local/bin/cacheshadow
        echo -e "${GREEN}[+]${NC} Symbolic link created: /usr/local/bin/cacheshadow"
    fi
    
    echo -e "${GREEN}[+]${NC} You can now run 'cacheshadow' from anywhere!"
else
    echo -e "${YELLOW}[!]${NC} Skipping symbolic link creation"
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}[+] Installation Complete!${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Quick Start:${NC}"
echo -e "  ${GREEN}python3 cache_poison_scanner.py -u https://example.com${NC}"
echo ""
echo -e "${YELLOW}Optional: Add alias to your shell profile (.bashrc or .zshrc):${NC}"
echo -e "  ${BLUE}alias cacheshadow='python3 $(pwd)/cache_poison_scanner.py'${NC}"
echo ""
echo -e "${YELLOW}Examples:${NC}"
echo -e "  ${GREEN}cacheshadow -u https://example.com -v${NC}"
echo -e "  ${GREEN}cacheshadow -u https://example.com --crawl --threads 5${NC}"
echo -e "  ${GREEN}cacheshadow -u https://example.com --inspect-only${NC}"
echo ""
echo -e "${RED}⚠️  WARNING: Use only on authorized targets!${NC}"
echo ""