#!/bin/bash

# VibeTunnel Linux Build Script
# This script builds VibeTunnel for Linux systems

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$SCRIPT_DIR/build"
DIST_DIR="$SCRIPT_DIR/dist"
WEB_DIR="$PROJECT_ROOT/web"

log() {
    echo -e "${BLUE}[BUILD]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check dependencies
check_dependencies() {
    log "Checking dependencies..."
    
    local missing_deps=()
    
    # Check Node.js
    if ! command -v node >/dev/null 2>&1; then
        missing_deps+=("nodejs")
    else
        local node_version=$(node --version | sed 's/v//')
        local required_major=18
        local current_major=$(echo "$node_version" | cut -d. -f1)
        if [[ $current_major -lt $required_major ]]; then
            log_error "Node.js version $node_version found, but version $required_major+ is required"
            missing_deps+=("nodejs (version $required_major+)")
        fi
    fi
    
    # Check pnpm
    if ! command -v pnpm >/dev/null 2>&1; then
        missing_deps+=("pnpm")
    fi
    
    # Check optional: Bun (for better performance)
    if ! command -v bun >/dev/null 2>&1; then
        log_warning "Bun not found - will use Node.js (consider installing Bun for better performance)"
    fi
    
    # Check system dependencies
    if ! command -v curl >/dev/null 2>&1; then
        missing_deps+=("curl")
    fi
    
    if ! command -v jq >/dev/null 2>&1; then
        missing_deps+=("jq")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        echo ""
        echo "Install with:"
        echo "  Ubuntu/Debian: sudo apt install nodejs npm curl jq && npm install -g pnpm"
        echo "  Fedora/RHEL:   sudo dnf install nodejs npm curl jq && npm install -g pnpm"
        echo "  Arch Linux:    sudo pacman -S nodejs npm curl jq && npm install -g pnpm"
        echo ""
        echo "Optional (for better performance):"
        echo "  Bun: curl -fsSL https://bun.sh/install | bash"
        exit 1
    fi
    
    log_success "All dependencies found"
}

# Clean previous builds
clean_build() {
    log "Cleaning previous builds..."
    rm -rf "$BUILD_DIR" "$DIST_DIR"
    mkdir -p "$BUILD_DIR" "$DIST_DIR"
}

# Build web server
build_web() {
    log "Building web server..."
    
    cd "$WEB_DIR"
    
    # Install dependencies
    log "Installing web dependencies..."
    pnpm install
    
    # Run build
    log "Building web components..."
    pnpm run build
    
    # Copy server files to build directory
    log "Copying server files..."
    cp -r dist/* "$BUILD_DIR/"
    cp -r public "$BUILD_DIR/"
    cp package.json "$BUILD_DIR/"
    
    # Copy native modules if they exist
    if [[ -d node_modules/node-pty ]]; then
        log "Copying native modules..."
        mkdir -p "$BUILD_DIR/node_modules"
        cp -r node_modules/node-pty "$BUILD_DIR/node_modules/"
        cp -r node_modules/authenticate-pam "$BUILD_DIR/node_modules/" 2>/dev/null || true
    fi
    
    cd - >/dev/null
    log_success "Web server built"
}

# Create standalone executable
create_executable() {
    log "Creating standalone executable..."
    
    local server_script="$DIST_DIR/vibetunnel-server"
    
    # Create wrapper script
    cat > "$server_script" << 'EOF'
#!/usr/bin/env bash

# VibeTunnel Server Executable
# This script finds and runs the VibeTunnel server with the right runtime

set -euo pipefail

# Find the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$SCRIPT_DIR"

# Configuration
DEFAULT_PORT=4020
DEFAULT_HOST="127.0.0.1"

# Parse command line arguments
PORT="$DEFAULT_PORT"
HOST="$DEFAULT_HOST"
CONFIG_FILE=""
DEBUG=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --port|-p)
            PORT="$2"
            shift 2
            ;;
        --host|-h)
            HOST="$2"
            shift 2
            ;;
        --config|-c)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --debug|-d)
            DEBUG=true
            shift
            ;;
        --help)
            cat << HELP
VibeTunnel Server

Usage: vibetunnel-server [OPTIONS]

Options:
    --port, -p PORT         Port to listen on (default: 4020)
    --host, -h HOST         Host to bind to (default: 127.0.0.1)
    --config, -c FILE       Configuration file path
    --debug, -d             Enable debug logging
    --help                  Show this help message

Environment Variables:
    VIBETUNNEL_PORT         Default port
    VIBETUNNEL_HOST         Default host
    VIBETUNNEL_DEBUG        Enable debug mode
HELP
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Override with environment variables
PORT="${VIBETUNNEL_PORT:-$PORT}"
HOST="${VIBETUNNEL_HOST:-$HOST}"
if [[ "${VIBETUNNEL_DEBUG:-}" == "1" ]] || [[ "${VIBETUNNEL_DEBUG:-}" == "true" ]]; then
    DEBUG=true
fi

# Export environment variables
export VIBETUNNEL_PORT="$PORT"
export VIBETUNNEL_HOST="$HOST"
export VIBETUNNEL_STATIC_DIR="$SERVER_DIR/public"

if [[ "$DEBUG" == true ]]; then
    export VIBETUNNEL_DEBUG=1
    echo "Debug mode enabled"
    echo "Port: $PORT"
    echo "Host: $HOST"
    echo "Server dir: $SERVER_DIR"
    echo "Static dir: $VIBETUNNEL_STATIC_DIR"
fi

# Try to run with Bun first (if available), then fall back to Node.js
if command -v bun >/dev/null 2>&1; then
    if [[ "$DEBUG" == true ]]; then
        echo "Using Bun runtime"
    fi
    exec bun "$SERVER_DIR/server.js" "$@"
elif command -v node >/dev/null 2>&1; then
    if [[ "$DEBUG" == true ]]; then
        echo "Using Node.js runtime"
    fi
    exec node "$SERVER_DIR/server.js" "$@"
else
    echo "Error: Neither Bun nor Node.js found"
    echo "Please install Node.js or Bun to run VibeTunnel"
    exit 1
fi
EOF
    
    chmod +x "$server_script"
    log_success "Standalone executable created"
}

# Copy Linux-specific files
copy_linux_files() {
    log "Copying Linux-specific files..."
    
    # Copy server files from build
    cp -r "$BUILD_DIR"/* "$DIST_DIR/"
    
    # Copy Linux launcher and vt command
    cp "$SCRIPT_DIR/vibetunnel-linux" "$DIST_DIR/"
    cp "$SCRIPT_DIR/vt" "$DIST_DIR/"
    
    # Copy documentation
    if [[ -f "$PROJECT_ROOT/README.md" ]]; then
        cp "$PROJECT_ROOT/README.md" "$DIST_DIR/"
    fi
    
    if [[ -f "$PROJECT_ROOT/LICENSE" ]]; then
        cp "$PROJECT_ROOT/LICENSE" "$DIST_DIR/"
    fi
    
    log_success "Linux files copied"
}

# Create installation script
create_installer() {
    log "Creating installation script..."
    
    local installer="$DIST_DIR/install.sh"
    
    cat > "$installer" << 'EOF'
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
EOF
    
    chmod +x "$installer"
    log_success "Installation script created"
}

# Create package
create_package() {
    log "Creating package..."
    
    local package_name="vibetunnel-linux-$(date +%Y%m%d).tar.gz"
    local package_path="linux/$package_name"
    
    cd linux
    tar -czf "$package_name" -C dist .
    cd - >/dev/null
    
    log_success "Package created: $package_path"
    echo ""
    echo "Installation:"
    echo "  tar -xzf $package_path"
    echo "  cd vibetunnel-linux-*"
    echo "  sudo ./install.sh    # System-wide install"
    echo "  ./install.sh         # User install"
}

# Main build process
main() {
    echo "VibeTunnel Linux Build Script"
    echo "============================="
    echo ""
    
    check_dependencies
    clean_build
    build_web
    create_executable
    copy_linux_files
    create_installer
    create_package
    
    echo ""
    log_success "Build completed successfully!"
    echo ""
    echo "Test locally:"
    echo "  cd linux/dist"
    echo "  ./vibetunnel-linux start"
    echo "  ./vt --shell"
}

# Handle Ctrl+C
trap 'log_error "Build interrupted"; exit 1' INT

# Run main function
main "$@"