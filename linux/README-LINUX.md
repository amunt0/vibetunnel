# VibeTunnel for Linux

**Turn any browser into your Linux terminal.** VibeTunnel proxies your terminals right into the browser, so you can vibe-code anywhere from any device.

This is the Linux port of VibeTunnel, providing the same powerful terminal multiplexing functionality that was originally macOS-only.

## Quick Start

### Prerequisites

- **Linux Distribution**: Ubuntu 20.04+, Fedora 35+, Arch Linux, or similar
- **Node.js**: Version 18 or higher
- **pnpm**: Package manager
- **System packages**: `curl`, `jq` (for CLI functionality)

### Installation Options

#### Option 1: Build from Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/amantus-ai/vibetunnel.git
cd vibetunnel

# Install dependencies
sudo apt update
sudo apt install nodejs npm curl jq build-essential  # Ubuntu/Debian
# OR
sudo dnf install nodejs npm curl jq gcc-c++ make     # Fedora
# OR  
sudo pacman -S nodejs npm curl jq base-devel        # Arch Linux

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

#### Option 2: Quick Setup (Development)

```bash
# Install system dependencies
sudo apt install nodejs npm curl jq  # Ubuntu/Debian

# Install pnpm and build web components
npm install -g pnpm
cd web
pnpm install
pnpm run build

# Use development launcher
cd ../linux
./vibetunnel-linux start
```

### Basic Usage

```bash
# Start VibeTunnel server
vibetunnel start

# Check status
vibetunnel status

# Create terminal sessions
vt --shell                    # Interactive shell
vt npm run dev               # Run command in browser
vt python app.py             # Run Python app
vt htop                      # System monitor

# View dashboard at http://localhost:4020
```

## Features

### Core Functionality
- **🌐 Browser-Based Terminals** - Access your Linux terminal from any device with a web browser
- **🚀 Zero SSH Setup** - No SSH keys, no port forwarding, no complexity
- **🤖 Perfect for Development** - Monitor builds, AI agents, and long-running processes
- **📊 Real-Time Activity** - Dynamic terminal titles show what's happening
- **🔒 Secure by Default** - PAM authentication, SSH key support, localhost-only mode
- **📱 Mobile Friendly** - Responsive web interface works great on phones and tablets
- **🎬 Session Recording** - All sessions recorded in asciinema format
- **⚡ High Performance** - Optional Bun runtime for 3x faster JavaScript execution

### Linux-Specific Features
- **🐧 Native PAM Authentication** - Uses your system user accounts
- **🔑 SSH Key Authentication** - Works with your existing ~/.ssh/authorized_keys
- **🔧 Systemd Integration** - Easy service management and autostart
- **📦 Multiple Installation Options** - System packages, user install, or run from source
- **🎨 Desktop Integration** - System tray support (coming soon)

## Configuration

### Configuration Files

VibeTunnel stores configuration in `~/.config/vibetunnel/`:

```
~/.config/vibetunnel/
├── config.json          # Main configuration
├── secrets.json         # Encrypted secrets (passwords, tokens)
├── vibetunnel.log       # Server logs
└── recordings/          # Session recordings
```

### Configuration Management

```bash
# Initialize default configuration
vibetunnel config init

# View current configuration
vibetunnel config show

# Set configuration values
vibetunnel config set port 8080
vibetunnel config set auth.type password

# Manage secrets (encrypted storage)
vibetunnel config set-secret dashboardPassword mypassword
vibetunnel config set-secret ngrokAuthToken your-token

# Edit configuration file directly
vibetunnel config
```

### Authentication Options

#### 1. System Authentication (Default)
Uses your Linux user account via PAM:

```json
{
  "auth": {
    "enabled": true,
    "type": "system"
  }
}
```

#### 2. SSH Key Authentication
Uses your `~/.ssh/authorized_keys`:

```json
{
  "auth": {
    "enabled": true,
    "type": "ssh-key"
  }
}
```

#### 3. Dashboard Password
Simple password protection:

```json
{
  "auth": {
    "enabled": true,
    "type": "password"
  }
}
```

```bash
vibetunnel config set-secret dashboardPassword your-secure-password
```

#### 4. No Authentication (Local Only)
**Warning**: Only use on trusted networks:

```json
{
  "auth": {
    "enabled": false
  }
}
```

## Remote Access

### Option 1: Tailscale (Recommended)

1. Install [Tailscale](https://tailscale.com/download/linux):
   ```bash
   curl -fsSL https://tailscale.com/install.sh | sh
   sudo tailscale up
   ```

2. Configure VibeTunnel:
   ```bash
   vibetunnel config set host 0.0.0.0
   vibetunnel config set auth.enabled true
   ```

3. Access from any device on your Tailscale network:
   ```
   http://[your-tailscale-hostname]:4020
   ```

### Option 2: ngrok

1. Get [ngrok auth token](https://dashboard.ngrok.com/get-started/your-authtoken)

2. Configure VibeTunnel:
   ```bash
   vibetunnel config set-secret ngrokAuthToken your-auth-token
   vibetunnel config set tunneling.ngrok.enabled true
   ```

3. Restart VibeTunnel - you'll get a public HTTPS URL

### Option 3: Local Network

1. Configure for network access:
   ```bash
   vibetunnel config set host 0.0.0.0
   vibetunnel config set auth.enabled true
   vibetunnel config set-secret dashboardPassword your-password
   ```

2. Find your IP address:
   ```bash
   ip addr show | grep inet
   ```

3. Access from other devices:
   ```
   http://[your-ip]:4020
   ```

## Service Management

### Systemd Service (Recommended)

```bash
# Install systemd service
vibetunnel install-service

# Enable autostart
systemctl --user enable vibetunnel.service

# Start service
systemctl --user start vibetunnel.service

# Check status
systemctl --user status vibetunnel.service

# View logs
journalctl --user -u vibetunnel.service -f
```

### Manual Service Management

```bash
# Start server
vibetunnel start

# Stop server
vibetunnel stop

# Restart server
vibetunnel restart

# Check status
vibetunnel status

# View logs
vibetunnel logs        # Recent logs
vibetunnel logs -f     # Follow logs
```

## Advanced Usage

### Environment Variables

```bash
# Override default settings
export VIBETUNNEL_PORT=8080
export VIBETUNNEL_HOST=0.0.0.0
export VIBETUNNEL_DEBUG=1

# Start with environment override
VIBETUNNEL_PORT=8080 vibetunnel start
```

### Command Line Arguments

```bash
# VibeTunnel server
vibetunnel-server --port 8080 --host 0.0.0.0 --debug

# VT command options
vt --title-mode static vim file.txt
vt --title-mode dynamic npm run dev
vt --title-mode filter htop
```

### Terminal Title Modes

- **Dynamic** (default): Shows directory, command, and real-time activity
- **Static**: Shows directory and command only  
- **Filter**: Blocks application title changes
- **None**: No title management

### Session Recording

All sessions are automatically recorded in asciinema format:

```bash
# List recordings
ls ~/.config/vibetunnel/recordings/

# Play recording
asciinema play ~/.config/vibetunnel/recordings/session-20240101-120000.cast

# Convert to GIF (requires agg)
agg ~/.config/vibetunnel/recordings/session-20240101-120000.cast output.gif
```

## Development

### Building from Source

```bash
# Install build dependencies
sudo apt install build-essential python3-dev

# Clone and build
git clone https://github.com/amantus-ai/vibetunnel.git
cd vibetunnel

# Install web dependencies
cd web
pnpm install

# Build web components
pnpm run build

# Build Linux package
cd ../linux
./build-linux.sh
```

### Development Mode

```bash
# Terminal 1: Start web development server
cd web
pnpm run dev

# Terminal 2: Use development launcher
cd linux
./vibetunnel-linux start

# Terminal 3: Create test sessions
./vt --shell
```

### Testing

```bash
# Run web tests
cd web
pnpm run test

# Test Linux components
cd linux
./vibetunnel-linux start
./vt --list
./vt echo "Hello World"
```

## Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Check what's using port 4020
sudo netstat -tlnp | grep 4020
# OR
sudo ss -tlnp | grep 4020

# Kill the process or change port
vibetunnel config set port 8080
```

#### Permission Denied
```bash
# Check file permissions
ls -la ~/.config/vibetunnel/

# Fix permissions
chmod 700 ~/.config/vibetunnel/
chmod 600 ~/.config/vibetunnel/*.json
```

#### Authentication Not Working
```bash
# Check PAM configuration
pamtester login $(whoami) authenticate

# Check SSH keys
cat ~/.ssh/authorized_keys

# Debug authentication
VIBETUNNEL_DEBUG=1 vibetunnel start
```

#### Native Modules Missing
```bash
# Install build tools
sudo apt install build-essential python3-dev

# Rebuild native modules
cd web
pnpm run postinstall
```

### Debug Mode

```bash
# Enable debug logging
export VIBETUNNEL_DEBUG=1
vibetunnel start

# View debug logs
tail -f ~/.config/vibetunnel/vibetunnel.log
```

### Reset Configuration

```bash
# Reset all configuration
vibetunnel config reset

# Reinitialize
vibetunnel config init
```

## Architecture

VibeTunnel Linux consists of:

1. **Web Server** (`vibetunnel-server`) - Node.js/Bun server handling terminals
2. **Linux Launcher** (`vibetunnel-linux`) - Process manager and configuration
3. **VT Command** (`vt`) - CLI for creating terminal sessions
4. **Config Manager** - Secure configuration and secrets storage

### File Structure

```
/opt/vibetunnel/              # System installation
├── vibetunnel-server         # Main server executable
├── vibetunnel-linux         # Linux launcher
├── vt                       # VT command
├── config-manager.js        # Configuration manager
├── public/                  # Web frontend assets
└── node_modules/            # Node.js dependencies

~/.config/vibetunnel/        # User configuration
├── config.json             # Main configuration
├── secrets.json            # Encrypted secrets
├── vibetunnel.log          # Server logs
└── recordings/             # Session recordings
```

## Differences from macOS Version

| Feature | macOS | Linux |
|---------|-------|--------|
| **GUI App** | Native SwiftUI menu bar app | CLI-based launcher |
| **Authentication** | Keychain + PAM | PAM + SSH keys + encrypted file storage |
| **Autostart** | LaunchAgent | systemd user service |
| **Configuration** | macOS preferences | JSON files in ~/.config |
| **System Integration** | Menu bar, notifications | System tray (planned) |
| **Process Management** | macOS APIs | systemd integration |

## Contributing

The Linux port welcomes contributions! Areas where help is needed:

- **System Tray Integration** - GTK/Qt system tray support
- **Package Managers** - .deb, .rpm, AUR packages  
- **Desktop Integration** - .desktop files, file associations
- **Container Support** - Docker, Podman containers
- **ARM64 Support** - Raspberry Pi, ARM servers

## Support

- **Documentation**: See `docs/` directory
- **Issues**: [GitHub Issues](https://github.com/amantus-ai/vibetunnel/issues)
- **Discussions**: [GitHub Discussions](https://github.com/amantus-ai/vibetunnel/discussions)

## License

VibeTunnel is open source software licensed under the MIT License. See [LICENSE](../LICENSE) for details.

---

**Ready to vibe on Linux?** 🐧🚀

```bash
git clone https://github.com/amantus-ai/vibetunnel.git
cd vibetunnel/linux
./build-linux.sh
```