#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "========================================="
echo "      Zedas Network Utility Installer     "
echo "========================================="

# 1. Ensure the installation script is run with root privileges
if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: Please run this installer with sudo:"
    echo "    sudo ./install.sh"
    exit 1
fi

# 2. Detect the system package manager and install dependencies
echo "[*] Detecting system architecture and installing prerequisites..."
if [ -x "$(command -v apt-get)" ]; then
    # Debian / Ubuntu / Mint
    apt-get update -y
    apt-get install -y python3 python3-venv python3-pip
elif [ -x "$(command -v dnf)" ]; then
    # Fedora / RHEL / CentOS
    dnf install -y python3 python3-pip
elif [ -x "$(command -v pacman)" ]; then
    # Arch Linux / Manjaro
    pacman -Sy --noconfirm python python-pip
else
    echo "[-] Warning: Unknown package manager. Ensuring python3 is available..."
    if ! [ -x "$(command -v python3)" ]; then
        echo "[-] Error: python3 is required but not found. Please install it manually."
        exit 1
    fi
fi

# 3. Define installation locations
INSTALL_DIR="/opt/zedas"
BIN_LINK="/usr/local/bin/zedas"

echo "[*] Creating deployment directory at $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

# 4. Create an isolated virtual environment to prevent system conflicts
echo "[*] Setting up isolated Python environment..."
python3 -m venv "$INSTALL_DIR/venv"

# 5. Upgrade pip and install the application from the current directory
echo "[*] Installing Zedas and its dependencies..."
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install .

# 6. Create a global symbolic link in the trusted system path
echo "[*] Configuring global execution paths..."
if [ -L "$BIN_LINK" ] || [ -f "$BIN_LINK" ]; then
    rm -f "$BIN_LINK"
fi
ln -s "$INSTALL_DIR/venv/bin/zedas" "$BIN_LINK"

# 7. Finalize installation and show usage
echo "========================================="
echo "[+] Zedas successfully installed globally!"
echo "========================================="
echo "You and any other system users can now run the tool directly:"
echo ""
echo "    sudo zedas listen"
echo "    sudo zedas show"
echo "========================================="
