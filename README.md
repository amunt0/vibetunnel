<!-- Generated: 2025-06-21 18:45:00 UTC -->
![VibeTunnel Banner](assets/banner.png)

# VibeTunnel

**Turn any browser into your terminal.** VibeTunnel proxies your terminals right into the browser, so you can vibe-code anywhere from any device.

[![Download](https://img.shields.io/badge/Download-macOS-blue)](https://github.com/amantus-ai/vibetunnel/releases/latest)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![macOS 14.0+](https://img.shields.io/badge/macOS-14.0+-red)](https://www.apple.com/macos/)
[![Linux](https://img.shields.io/badge/Linux-Ubuntu%2020.04%2B-orange)](https://ubuntu.com/)
[![Apple Silicon](https://img.shields.io/badge/Apple%20Silicon-Required-orange)](https://support.apple.com/en-us/HT211814)
[![Support us on Polar](https://img.shields.io/badge/Support%20us-on%20Polar-purple)](https://vibetunnel.sh/#support)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/amantus-ai/vibetunnel)

## Why VibeTunnel?

Ever wanted to check on your AI agents while you're away? Need to monitor that long-running build from your phone? Want to share a terminal session with a colleague without complex SSH setups? VibeTunnel makes it happen with zero friction.

## Quick Start

### Platform Support

VibeTunnel works on both macOS and Linux systems:

- **macOS**: Requires Apple Silicon Mac (M1+). Intel Macs are not supported.
- **Linux**: Ubuntu 20.04+, Fedora 35+, Arch Linux, or similar distributions

## macOS Installation

### 1. Download & Install

[Download VibeTunnel](https://github.com/amantus-ai/vibetunnel/releases/latest) and drag it to your Applications folder.

### 2. Launch VibeTunnel

VibeTunnel lives in your menu bar. Click the icon to start the server.

### 3. Use the `vt` Command

```bash
# Run any command in the browser
vt pnpm run dev

# Monitor AI agents (with automatic activity tracking)
vt claude --dangerously-skip-permissions

# Control terminal titles
vt --title-mode static npm run dev    # Shows path and command
vt --title-mode dynamic python app.py  # Shows path, command, and activity
vt --title-mode filter vim            # Blocks vim from changing title

# Shell aliases work automatically!
vt claude-danger  # Your custom aliases are resolved

# Open an interactive shell
vt --shell
```

### 4. Open Your Dashboard

Visit [http://localhost:4020](http://localhost:4020) to see all your terminal sessions.

## Linux Installation

### Prerequisites

- **Linux Distribution**: Ubuntu 20.04+, Fedora 35+, Arch Linux, or similar
- **Node.js**: Version 18 or higher
- **pnpm**: Package manager
- **System packages**: `curl`, `jq` (for CLI functionality)

### Option 1: Build from Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/amantus-ai/vibetunnel.git
cd vibetunnel

# Install dependencies
sudo apt update
sudo apt install nodejs npm curl jq build-essential libpam0g-dev  # Ubuntu/Debian
# OR
sudo dnf install nodejs npm curl jq gcc-c++ make pam-devel        # Fedora
# OR  
sudo pacman -S nodejs npm curl jq base-devel pam                  # Arch Linux

# Install pnpm
npm install -g pnpm

# Optional: Install Bun for better performance
curl -fsSL https://bun.sh/install | bash

# Build for Linux
cd linux
./build-linux.sh

# Install
cd dist
sudo ./install.sh    # System-wide install
# OR
./install.sh         # User install to ~/.local
```

### Option 2: Quick Setup (Development)

```bash
# Install system dependencies
sudo apt install nodejs npm curl jq libpam0g-dev  # Ubuntu/Debian

# Install pnpm and build web components
npm install -g pnpm
cd web
pnpm install
pnpm run build

# Use development launcher
cd ../linux
./vibetunnel-linux start
```

### Linux Usage

#### Basic Commands

```bash
# Start VibeTunnel server
vibetunnel-linux start                    # With authentication (secure)
vibetunnel-linux --no-auth start          # Without authentication (development)

# Check status
vibetunnel-linux status

# Stop server
vibetunnel-linux stop

# Restart server
vibetunnel-linux restart

# View logs
vibetunnel-linux logs           # Recent logs
vibetunnel-linux logs -f        # Follow logs in real-time
```

#### Create Terminal Sessions

```bash
# Interactive shell
vt --shell

# Run specific commands
vt npm run dev               # Run development server
vt python app.py             # Run Python application
vt htop                      # System monitor
vt --title-mode static vim file.txt   # Edit file with static title

# Control terminal titles (same as macOS)
vt --title-mode dynamic python app.py  # Shows path, command, and activity
vt --title-mode static npm run dev     # Shows path and command only
vt --title-mode filter vim             # Blocks application title changes
```

#### Auto-Start on Boot (systemd)

```bash
# Install systemd service
vibetunnel-linux install-service

# Enable auto-start on boot
systemctl --user enable vibetunnel.service

# Start service immediately
systemctl --user start vibetunnel.service

# Check service status
systemctl --user status vibetunnel.service

# View service logs
journalctl --user -u vibetunnel.service -f

# Stop service
systemctl --user stop vibetunnel.service

# Disable auto-start
systemctl --user disable vibetunnel.service
```

#### Configuration Management

```bash
# View current configuration
vibetunnel-linux config

# Or use the config manager directly
./config-manager.js show

# Change settings
./config-manager.js set port 8080
./config-manager.js set auth.type password

# Manage encrypted secrets
./config-manager.js set-secret dashboardPassword mypassword
./config-manager.js set-secret ngrokAuthToken your-token

# Reset configuration
./config-manager.js reset
./config-manager.js init
```

#### Authentication Options

**System Authentication (Default - Recommended)**:
```bash
vibetunnel-linux start
# Uses your Linux username/password via PAM
```

**No Authentication (Development/Testing)**:
```bash
vibetunnel-linux --no-auth start
# Anyone on localhost can access (NOT for production)
```

**Dashboard Password**:
```bash
./config-manager.js set auth.type password
./config-manager.js set-secret dashboardPassword your-secure-password
vibetunnel-linux restart
```

**SSH Key Authentication**:
```bash
./config-manager.js set auth.type ssh-key
vibetunnel-linux restart
# Uses your ~/.ssh/authorized_keys
```

### Linux Dashboard Access

Visit [http://localhost:4020](http://localhost:4020) to access your terminal sessions.

- **With Authentication**: Login with your credentials
- **Without Authentication** (`--no-auth`): Direct access

## Features

- **🌐 Browser-Based Access** - Control your terminal from any device with a web browser
- **🚀 Zero Configuration** - No SSH keys, no port forwarding, no complexity
- **🤖 AI Agent Friendly** - Perfect for monitoring Claude Code, ChatGPT, or any terminal-based AI tools
- **📊 Dynamic Terminal Titles** - Real-time activity tracking shows what's happening in each session
- **🔒 Secure by Design** - Multiple authentication options: PAM, SSH keys, passwords, or no-auth for development
- **📱 Mobile Ready** - Native iOS app and responsive web interface for phones and tablets
- **🎬 Session Recording** - All sessions recorded in asciinema format for later playback
- **⚡ High Performance** - Powered by Bun runtime for blazing-fast JavaScript execution
- **🍎 Apple Silicon Native** - Optimized for M1/M2/M3 Macs with ARM64-only binaries
- **🐧 Linux Support** - Full Linux port with systemd integration and CLI management
- **🐚 Shell Alias Support** - Your custom aliases and shell functions work automatically
- **🔄 Cross-Platform** - Same core functionality across macOS and Linux

> **Note**: The iOS app and Tauri-based components are still work in progress and not recommended for production use yet.

## Architecture

VibeTunnel is designed as a cross-platform system with shared core components:

### Core Components (Shared)
1. **Node.js/Bun Server** - High-performance TypeScript server handling terminal sessions
2. **Web Frontend** - Modern web interface using Lit components and xterm.js
3. **Terminal Engine** - PTY management and session multiplexing

### Platform-Specific Components
- **macOS**: Native Swift menu bar application (`mac/`)
- **Linux**: CLI launcher with systemd integration (`linux/`)

The server runs as a standalone executable with embedded Node.js modules, providing excellent performance and minimal resource usage across both platforms.

## Remote Access Options

All remote access options work on both macOS and Linux systems.

### Option 1: Tailscale (Recommended)

[Tailscale](https://tailscale.com) creates a secure peer-to-peer VPN network between your devices. It's the most secure option as traffic stays within your private network without exposing VibeTunnel to the public internet.

**How it works**: Tailscale creates an encrypted WireGuard tunnel between your devices, allowing them to communicate as if they were on the same local network, regardless of their physical location.

**Setup Guide**:
1. Install Tailscale on your server machine:
   - **macOS**: [Download from Mac App Store](https://apps.apple.com/us/app/tailscale/id1475387142) or [Direct Download](https://tailscale.com/download/macos)
   - **Linux**: `curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up`
2. Install Tailscale on your remote device:
   - **iOS**: [Download from App Store](https://apps.apple.com/us/app/tailscale/id1470499037)
   - **Android**: [Download from Google Play](https://play.google.com/store/apps/details?id=com.tailscale.ipn)
   - **Other platforms**: [All Downloads](https://tailscale.com/download)
3. Sign in to both devices with the same account
4. Find your server's Tailscale hostname:
   - **macOS**: Check the Tailscale menu bar app
   - **Linux**: Run `tailscale ip -4` or check `tailscale status`
5. Access VibeTunnel at `http://[your-tailscale-hostname]:4020`

**Benefits**:
- End-to-end encrypted traffic
- No public internet exposure
- Works behind NAT and firewalls
- Zero configuration after initial setup

### Option 2: ngrok

[ngrok](https://ngrok.com) creates secure tunnels to your localhost, making VibeTunnel accessible via a public URL. Perfect for quick sharing or temporary access.

**How it works**: ngrok establishes a secure tunnel from a public endpoint to your local VibeTunnel server, handling SSL/TLS encryption and providing a unique URL for access.

**Setup Guide**:
1. Create a free ngrok account: [Sign up for ngrok](https://dashboard.ngrok.com/signup)
2. Copy your auth token from the [ngrok dashboard](https://dashboard.ngrok.com/get-started/your-authtoken)
3. Configure the token in VibeTunnel:
   - **macOS**: Add in VibeTunnel settings (Settings → Remote Access → ngrok)
   - **Linux**: `./config-manager.js set-secret ngrokAuthToken your-token`
4. Enable ngrok tunneling:
   - **macOS**: Toggle in VibeTunnel settings
   - **Linux**: `./config-manager.js set tunneling.ngrok.enabled true`
5. Restart VibeTunnel to get your `https://[random].ngrok-free.app` URL

**Benefits**:
- Public HTTPS URL with SSL certificate
- No firewall configuration needed
- Built-in request inspection and replay
- Custom domains available (paid plans)

**Note**: Free ngrok URLs change each time you restart the tunnel. Consider a paid plan for persistent URLs.

### Option 3: Local Network
1. Set a dashboard password:
   - **macOS**: Configure in VibeTunnel settings
   - **Linux**: `./config-manager.js set-secret dashboardPassword yourpassword`
2. Enable network access:
   - **macOS**: Switch to "Network" mode in settings
   - **Linux**: `./config-manager.js set host 0.0.0.0`
3. Access via `http://[your-server-ip]:4020`

### Option 4: Cloudflare Quick Tunnel
1. Install [cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)
2. Run `cloudflared tunnel --url http://localhost:4020`
3. Access via the generated `*.trycloudflare.com` URL

## Terminal Title Management

VibeTunnel provides intelligent terminal title management to help you track what's happening in each session:

### Title Modes

- **Dynamic Mode** (default for web UI): Shows working directory, command, and real-time activity
  - Generic activity: `~/projects — npm — •`
  - Claude status: `~/projects — claude — ✻ Crafting (45s, ↑2.1k)`
  
- **Static Mode**: Shows working directory and command
  - Example: `~/projects/app — npm run dev`
  
- **Filter Mode**: Blocks all title changes from applications
  - Useful when you have your own terminal management system
  
- **None Mode**: No title management - applications control their own titles

### Activity Detection

Dynamic mode includes real-time activity detection:
- Shows `•` when there's terminal output within 5 seconds
- Claude commands show specific status (Crafting, Transitioning, etc.)
- Extensible system for future app-specific detectors

## Linux-Specific Features

VibeTunnel's Linux port provides equivalent functionality to the macOS version with Linux-native integrations:

### Linux vs macOS Feature Comparison

| Feature | macOS | Linux |
|---------|--------|--------|
| **GUI** | Native SwiftUI menu bar app | CLI-based launcher |
| **Authentication** | Keychain + PAM | PAM + SSH keys + encrypted file storage |
| **Auto-start** | LaunchAgent | systemd user service |
| **Configuration** | macOS preferences | JSON files in `~/.config/vibetunnel/` |
| **System Integration** | Menu bar, notifications | Command-line interface |
| **Process Management** | macOS APIs | systemd integration |
| **Remote Access** | ✅ Tailscale, ngrok, local network | ✅ Tailscale, ngrok, local network |
| **Terminal Engine** | ✅ Same Node.js/Bun server | ✅ Same Node.js/Bun server |
| **Web Interface** | ✅ Identical browser experience | ✅ Identical browser experience |

### Linux File Structure

```
~/.config/vibetunnel/          # User configuration
├── config.json               # Main configuration  
├── secrets.json              # Encrypted secrets (passwords, tokens)
├── vibetunnel.log            # Server logs
└── recordings/               # Session recordings

/opt/vibetunnel/              # System installation (optional)
├── vibetunnel-server         # Server executable wrapper
├── vibetunnel-linux         # Linux launcher
├── vt                       # VT command
├── config-manager.js        # Configuration manager
└── public/                  # Web frontend assets
```

### Linux Authentication Methods

1. **System PAM Authentication** (Default - Most Secure)
   - Uses your Linux user account credentials
   - Integrates with system authentication (LDAP, Active Directory, etc.)
   - Works with existing user management

2. **SSH Key Authentication**
   - Uses your `~/.ssh/authorized_keys`
   - Perfect for teams with existing SSH key infrastructure
   - No password required

3. **Dashboard Password**
   - Simple password-based authentication
   - Stored encrypted in `secrets.json`
   - Good for shared systems

4. **No Authentication** (Development only)
   - Use `--no-auth` flag for testing
   - **Warning**: Never use in production or on networks

### Troubleshooting Linux

**Common Issues**:

```bash
# Port already in use
sudo netstat -tlnp | grep 4020
vibetunnel-linux config set port 8080

# Permission denied
chmod 700 ~/.config/vibetunnel/
chmod 600 ~/.config/vibetunnel/*.json

# Authentication not working
pamtester login $(whoami) authenticate  # Test PAM
cat ~/.ssh/authorized_keys              # Check SSH keys

# Native modules missing
sudo apt install build-essential python3-dev libpam0g-dev
cd web && pnpm run postinstall

# Reset configuration
./config-manager.js reset
./config-manager.js init
```

**Debug Mode**:
```bash
export VIBETUNNEL_DEBUG=1
vibetunnel-linux start
tail -f ~/.config/vibetunnel/vibetunnel.log
```

## Building from Source

### Prerequisites

**For macOS**:
- macOS 14.0+ (Sonoma) on Apple Silicon (M1/M2/M3)
- Xcode 16.0+
- Node.js 20+
- Bun runtime

**For Linux**:
- Ubuntu 20.04+, Fedora 35+, Arch Linux, or similar
- Node.js 18+
- pnpm package manager
- Build tools: `build-essential`, `libpam0g-dev`

### Build Steps

```bash
# Clone the repository
git clone https://github.com/amantus-ai/vibetunnel.git
cd vibetunnel

# Build the web server (required for both platforms)
cd web
pnpm install
pnpm run build
cd ..
```

#### For macOS App

```bash
# Set up code signing (required for macOS/iOS development)
# Create Local.xcconfig files with your Apple Developer Team ID
cat > mac/VibeTunnel/Local.xcconfig << EOF
// Local Development Configuration
// DO NOT commit this file to version control
DEVELOPMENT_TEAM = YOUR_TEAM_ID
CODE_SIGN_STYLE = Automatic
EOF

cat > ios/VibeTunnel/Local.xcconfig << EOF
// Local Development Configuration  
// DO NOT commit this file to version control
DEVELOPMENT_TEAM = YOUR_TEAM_ID
CODE_SIGN_STYLE = Automatic
EOF

# Build the macOS app
cd mac
./scripts/build.sh --configuration Release
```

#### For Linux Package

```bash
# Install Linux dependencies
sudo apt install build-essential libpam0g-dev  # Ubuntu/Debian
# OR
sudo dnf install gcc-c++ make pam-devel       # Fedora
# OR
sudo pacman -S base-devel pam                  # Arch Linux

# Build Linux package
cd linux
./build-linux.sh

# Install
cd dist
sudo ./install.sh    # System-wide install
# OR
./install.sh         # User install to ~/.local
```

### Custom Node.js Builds

VibeTunnel supports building with a custom Node.js for a 46% smaller executable (61MB vs 107MB):

```bash
# Build custom Node.js (one-time, ~20 minutes)
node build-custom-node.js

# Use environment variable for all builds
export VIBETUNNEL_USE_CUSTOM_NODE=YES

# Or use in Xcode Build Settings
# Add User-Defined Setting: VIBETUNNEL_USE_CUSTOM_NODE = YES
```

See [Custom Node Build Flags](docs/custom-node-build-flags.md) for detailed optimization information.

## Development

For development setup and contribution guidelines, see [CONTRIBUTING.md](docs/CONTRIBUTING.md).

### Key Files
- **macOS App**: `mac/VibeTunnel/VibeTunnelApp.swift`
- **Linux Launcher**: `linux/vibetunnel-linux`
- **Linux VT Command**: `linux/vt`
- **Linux Config Manager**: `linux/config-manager.js`
- **Server**: `web/src/server/` (TypeScript/Node.js)
- **Web UI**: `web/src/client/` (Lit/TypeScript)
- **iOS App**: `ios/VibeTunnel/`

### Testing & Code Coverage

VibeTunnel has comprehensive test suites with code coverage enabled for all projects:

```bash
# Run all tests with coverage
./scripts/test-all-coverage.sh

# macOS tests with coverage (Swift Testing)
cd mac && swift test --enable-code-coverage

# iOS tests with coverage (using xcodebuild)
cd ios && ./scripts/test-with-coverage.sh

# Web tests with coverage (Vitest)
cd web && ./scripts/coverage-report.sh
```

**Coverage Requirements**:
- macOS/iOS: 75% minimum (enforced in CI)
- Web: 80% minimum for lines, functions, branches, and statements

### Debug Logging

Enable debug logging for troubleshooting:

```bash
# Enable debug mode
export VIBETUNNEL_DEBUG=1

# Or use inline
VIBETUNNEL_DEBUG=1 vt your-command
```

Debug logs are written to `~/.vibetunnel/log.txt`.

## Documentation

- [Technical Specification](docs/spec.md) - Detailed architecture and implementation
- [Contributing Guide](docs/CONTRIBUTING.md) - Development setup and guidelines
- [Architecture](docs/architecture.md) - System design overview
- [Build System](docs/build-system.md) - Build process details
- [Push Notifications](docs/push-notification.md) - How web push notifications work
- [Linux README](linux/README-LINUX.md) - Comprehensive Linux-specific documentation

## macOS Permissions

macOS is finicky when it comes to permissions. The system will only remember the first path from where an app requests permissions. If subsequently the app starts somewhere else, it will silently fail. Fix: Delete the entry and restart settings, restart app and next time the permission is requested, there should be an entry in Settings again.

Important: You need to set your Developer ID in Local.xcconfig. If apps are signed Ad-Hoc, each new signing will count as a new app for macOS and the permissions have to be (deleted and) requested again.

**Debug vs Release Bundle IDs**: The Debug configuration uses a different bundle identifier (`sh.vibetunnel.vibetunnel.debug`) than Release (`sh.vibetunnel.vibetunnel`). This allows you to have both versions installed simultaneously, but macOS treats them as separate apps for permissions. You'll need to grant permissions separately for each version.

If that fails, use the terminal to reset:

```
# This removes Accessibility permission for a specific bundle ID:
sudo tccutil reset Accessibility sh.vibetunnel.vibetunnel
sudo tccutil reset Accessibility sh.vibetunnel.vibetunnel.debug  # For debug builds

sudo tccutil reset ScreenCapture sh.vibetunnel.vibetunnel
sudo tccutil reset ScreenCapture sh.vibetunnel.vibetunnel.debug  # For debug builds

# This removes all Automation permissions system-wide (cannot target specific apps):
sudo tccutil reset AppleEvents
```

## Support VibeTunnel

Love VibeTunnel? Help us keep the terminal vibes flowing! Your support helps us buy pizza and drinks while we keep hacking on your favorite AI agent orchestration platform.

All donations go directly to the development team. Choose your own amount - one-time or monthly! Visit our [Polar page](https://vibetunnel.sh/#support) to support us.

## Credits

Created with ❤️ by:
- [@badlogic](https://mariozechner.at/) - Mario Zechner
- [@mitsuhiko](https://lucumr.pocoo.org/) - Armin Ronacher  
- [@steipete](https://steipete.com/) - Peter Steinberger
- [@hjanuschka](https://x.com/hjanuschka) - Helmut Januschka
- [@manuelmaly](https://x.com/manuelmaly) - Manuel Maly

## License

VibeTunnel is open source software licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

**Ready to vibe?** 

- **macOS**: [Download VibeTunnel](https://github.com/amantus-ai/vibetunnel/releases/latest) and start tunneling!
- **Linux**: Clone the repo and run `./linux/build-linux.sh` to get started!
