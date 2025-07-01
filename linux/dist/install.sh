#!/bin/bash

# VibeTunnel Linux Installer

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

INSTALL_DIR="/opt/vibetunnel"
BIN_DIR="/usr/local/bin"

log() {
    echo -e "${BLUE}[INSTALL]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    log "Installing system-wide to $INSTALL_DIR..."
    SYSTEM_INSTALL=true
else
    log "Installing to user directory..."
    INSTALL_DIR="$HOME/.local/share/vibetunnel"
    BIN_DIR="$HOME/.local/bin"
    SYSTEM_INSTALL=false
fi

# Create directories
log "Creating directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$BIN_DIR"

# Copy files
log "Copying files..."
cp -r * "$INSTALL_DIR/" 2>/dev/null || true

# Create symlinks
log "Creating symlinks..."
ln -sf "$INSTALL_DIR/vibetunnel-server" "$BIN_DIR/vibetunnel-server"
ln -sf "$INSTALL_DIR/vibetunnel-linux" "$BIN_DIR/vibetunnel"
ln -sf "$INSTALL_DIR/vt" "$BIN_DIR/vt"

# Make scripts executable
chmod +x "$INSTALL_DIR/vibetunnel-server"
chmod +x "$INSTALL_DIR/vibetunnel-linux"
chmod +x "$INSTALL_DIR/vt"

if [[ "$SYSTEM_INSTALL" == false ]]; then
    # Add to PATH if not already there
    if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
        log "Adding $BIN_DIR to PATH..."
        echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$HOME/.bashrc"
        echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$HOME/.zshrc" 2>/dev/null || true
        log_success "Added to PATH. Restart your shell or run: source ~/.bashrc"
    fi
fi

log_success "VibeTunnel installed successfully!"
echo ""
echo "Usage:"
echo "  vibetunnel start        # Start the server"
echo "  vibetunnel status       # Check status"
echo "  vt --shell             # Create terminal session"
echo ""
echo "Dashboard: http://localhost:4020"
