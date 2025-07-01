# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VibeTunnel is a cross-platform application that allows users to access their terminal sessions through any web browser. It consists of:
- **Cross-platform web server** (TypeScript/Node.js/Bun) in `web/` - Core terminal multiplexing functionality
- **Native macOS app** (Swift/SwiftUI) in `mac/` - macOS menu bar interface and system integration
- **Linux port** in `linux/` - CLI-based launcher and Linux-specific components  
- **iOS companion app** in `ios/` - Mobile terminal access (work in progress)

**Platform Support:**
- **macOS**: Full native app with menu bar integration (Apple Silicon M1+ required)
- **Linux**: CLI launcher with systemd integration (Ubuntu 20.04+, Fedora 35+, Arch Linux)
- **iOS**: Mobile companion app (work in progress)

## Critical Development Rules

- **Never commit and/or push before the user has tested your changes!**
- **ABSOLUTELY SUPER IMPORTANT & CRITICAL**: NEVER USE git rebase --skip EVER
- **Never create a new branch/PR automatically when you are already on a branch**, even if the changes do not seem to fit into the existing PR. Only do that when explicitly asked. Our workflow is always start from main, make branch, make PR, merge. Then we go back to main and start something else. PRs sometimes contain different features and that's okay.
- **IMPORTANT**: When refactoring or improving code, directly modify the existing files. DO NOT create new versions with different file names. Users hate having to manually clean up duplicate files.

## Web Development Commands

**IMPORTANT**: The user has `pnpm run dev` running - DO NOT manually build the web project!

In the `web/` directory:

```bash
# Development (user already has this running)
pnpm run dev

# Code quality (MUST run before commit)
pnpm run lint          # Check for linting errors
pnpm run lint:fix      # Auto-fix linting errors
pnpm run format        # Format with Prettier
pnpm run typecheck     # Check TypeScript types

# Testing (only when requested)
pnpm run test
pnpm run test:coverage
pnpm run test:e2e
```

## macOS Development Commands

In the `mac/` directory:

```bash
# Build commands
./scripts/build.sh                    # Build release
./scripts/build.sh --configuration Debug  # Build debug
./scripts/build.sh --sign            # Build with code signing

# Other scripts
./scripts/clean.sh                   # Clean build artifacts
./scripts/lint.sh                    # Run linting
./scripts/create-dmg.sh             # Create installer
```

## Linux Development Commands

In the `linux/` directory:

```bash
# Build Linux package
./build-linux.sh                     # Build complete Linux package

# Development and testing
./vibetunnel-linux start            # Start server
./vibetunnel-linux status           # Check status
./vibetunnel-linux stop             # Stop server
./vt --shell                        # Create terminal session

# Configuration management
./config-manager.js init            # Initialize configuration
./config-manager.js show            # Show configuration
./config-manager.js set port 8080   # Set configuration values
```

## Architecture Overview

### Terminal Sharing Protocol
1. **Session Creation**: `POST /api/sessions` spawns new terminal
2. **Input**: `POST /api/sessions/:id/input` sends keyboard/mouse input
3. **Output**:
   - SSE stream at `/api/sessions/:id/stream` (text)
   - WebSocket at `/buffers` (binary, efficient rendering)
4. **Resize**: `POST /api/sessions/:id/resize` (missing in some implementations)

### Key Entry Points
- **Cross-platform Web Server**: `web/src/server/server.ts`
- **Web Frontend**: `web/src/client/app.ts`
- **Process spawning and forwarding tool**: `web/src/server/fwd.ts`
- **Mac App**: `mac/VibeTunnel/VibeTunnelApp.swift`
- **macOS Server Management**: `mac/VibeTunnel/Core/Services/ServerManager.swift`
- **Linux Launcher**: `linux/vibetunnel-linux`
- **Linux VT Command**: `linux/vt`
- **Linux Configuration**: `linux/config-manager.js`

## Testing

- **Never run tests unless explicitly asked**
- **Web tests**: Vitest in `web/src/test/` (cross-platform)
- **Mac tests**: Swift Testing framework in `VibeTunnelTests/`
- **Linux testing**: Manual testing using `linux/vibetunnel-linux` and `linux/vt`

## Key Files Quick Reference

- **Architecture Details**: `docs/ARCHITECTURE.md`
- **API Specifications**: `docs/spec.md`
- **Server Implementation Guide**: `web/spec.md`
- **Linux Documentation**: `linux/README-LINUX.md`
- **Build Configuration**: `web/package.json`, `mac/Package.swift`, `linux/build-linux.sh`

## Platform-Specific Notes

### macOS Development
- Requires Apple Silicon (M1+) and macOS 14.0+
- Uses Swift 6.0 with SwiftUI for native interface
- Keychain integration for secure storage
- Menu bar application with system integration

### Linux Development  
- Supports Ubuntu 20.04+, Fedora 35+, Arch Linux
- CLI-based launcher replaces macOS menu bar app
- PAM authentication for system user accounts
- Systemd integration for service management
- Encrypted file storage replaces Keychain functionality
