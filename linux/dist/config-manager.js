#!/usr/bin/env node

/**
 * VibeTunnel Linux Configuration Manager
 * Replaces macOS Keychain functionality with secure Linux storage
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

class LinuxConfigManager {
    constructor() {
        this.configDir = path.join(os.homedir(), '.config', 'vibetunnel');
        this.configFile = path.join(this.configDir, 'config.json');
        this.secretsFile = path.join(this.configDir, 'secrets.json');
        this.keyFile = path.join(this.configDir, '.key');
        
        this.ensureConfigDir();
        this.ensureEncryptionKey();
    }

    ensureConfigDir() {
        if (!fs.existsSync(this.configDir)) {
            fs.mkdirSync(this.configDir, { recursive: true, mode: 0o700 });
        }
        
        // Ensure proper permissions
        fs.chmodSync(this.configDir, 0o700);
    }

    ensureEncryptionKey() {
        if (!fs.existsSync(this.keyFile)) {
            const key = crypto.randomBytes(32);
            fs.writeFileSync(this.keyFile, key);
            fs.chmodSync(this.keyFile, 0o600);
        }
    }

    getEncryptionKey() {
        return fs.readFileSync(this.keyFile);
    }

    encrypt(text) {
        const key = this.getEncryptionKey();
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        return iv.toString('hex') + ':' + encrypted;
    }

    decrypt(encryptedText) {
        const key = this.getEncryptionKey();
        const parts = encryptedText.split(':');
        const iv = Buffer.from(parts[0], 'hex');
        const encrypted = parts[1];
        
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    }

    getDefaultConfig() {
        return {
            port: 4020,
            host: "127.0.0.1",
            auth: {
                enabled: true,
                type: "system", // system, password, ssh-key, none
                allowedUsers: [],
                dashboardPassword: null
            },
            tunneling: {
                tailscale: {
                    enabled: false,
                    hostname: null
                },
                ngrok: {
                    enabled: false,
                    authToken: null,
                    domain: null
                }
            },
            logging: {
                level: "info",
                file: path.join(this.configDir, 'vibetunnel.log')
            },
            server: {
                maxSessions: 50,
                sessionTimeout: 3600000, // 1 hour
                enableRecording: true,
                recordingDir: path.join(this.configDir, 'recordings')
            },
            ui: {
                theme: "auto", // auto, light, dark
                terminalTheme: "default",
                showWelcomeMessage: true
            }
        };
    }


    getDefaultSecrets() {
        return {
            ngrokAuthToken: null,
            dashboardPassword: null,
            jwtSecret: crypto.randomBytes(64).toString('hex'),
            sshKeys: []
        };
    }

    // Public configuration (non-sensitive)
    loadConfig() {
        try {
            if (fs.existsSync(this.configFile)) {
                const config = JSON.parse(fs.readFileSync(this.configFile, 'utf8'));
                // Merge with defaults to ensure all fields exist
                return { ...this.getDefaultConfig(), ...config };
            }
        } catch (error) {
            console.error('Error loading config:', error.message);
        }
        
        return this.getDefaultConfig();
    }

    saveConfig(config) {
        try {
            // Ensure the config directory exists
            this.ensureConfigDir();
            
            // Write config with proper formatting
            fs.writeFileSync(this.configFile, JSON.stringify(config, null, 2));
            fs.chmodSync(this.configFile, 0o600);
            
            return true;
        } catch (error) {
            console.error('Error saving config:', error.message);
            return false;
        }
    }

    // Encrypted secrets
    loadSecrets() {
        try {
            if (fs.existsSync(this.secretsFile)) {
                const encryptedSecrets = JSON.parse(fs.readFileSync(this.secretsFile, 'utf8'));
                const secrets = {};
                
                // Decrypt each secret
                for (const [key, encryptedValue] of Object.entries(encryptedSecrets)) {
                    if (encryptedValue && typeof encryptedValue === 'string') {
                        try {
                            secrets[key] = this.decrypt(encryptedValue);
                        } catch (decryptError) {
                            console.warn(`Failed to decrypt secret '${key}':`, decryptError.message);
                            secrets[key] = null;
                        }
                    } else {
                        secrets[key] = encryptedValue;
                    }
                }
                
                return { ...this.getDefaultSecrets(), ...secrets };
            }
        } catch (error) {
            console.error('Error loading secrets:', error.message);
        }
        
        return this.getDefaultSecrets();
    }

    saveSecrets(secrets) {
        try {
            this.ensureConfigDir();
            
            const encryptedSecrets = {};
            
            // Encrypt each secret
            for (const [key, value] of Object.entries(secrets)) {
                if (value && typeof value === 'string') {
                    encryptedSecrets[key] = this.encrypt(value);
                } else {
                    encryptedSecrets[key] = value;
                }
            }
            
            fs.writeFileSync(this.secretsFile, JSON.stringify(encryptedSecrets, null, 2));
            fs.chmodSync(this.secretsFile, 0o600);
            
            return true;
        } catch (error) {
            console.error('Error saving secrets:', error.message);
            return false;
        }
    }

    // High-level API methods
    get(key) {
        const config = this.loadConfig();
        return this.getNestedValue(config, key);
    }

    set(key, value) {
        const config = this.loadConfig();
        this.setNestedValue(config, key, value);
        return this.saveConfig(config);
    }

    getSecret(key) {
        const secrets = this.loadSecrets();
        return secrets[key];
    }

    setSecret(key, value) {
        const secrets = this.loadSecrets();
        secrets[key] = value;
        return this.saveSecrets(secrets);
    }

    // Helper methods for nested object access
    getNestedValue(obj, path) {
        return path.split('.').reduce((current, key) => {
            return current && current[key] !== undefined ? current[key] : null;
        }, obj);
    }

    setNestedValue(obj, path, value) {
        const keys = path.split('.');
        const lastKey = keys.pop();
        const target = keys.reduce((current, key) => {
            if (!current[key] || typeof current[key] !== 'object') {
                current[key] = {};
            }
            return current[key];
        }, obj);
        target[lastKey] = value;
    }

    // CLI commands
    handleCommand(args) {
        const command = args[0];
        
        switch (command) {
            case 'get':
                if (args.length < 2) {
                    console.error('Usage: get <key>');
                    process.exit(1);
                }
                const value = this.get(args[1]);
                console.log(value !== null ? JSON.stringify(value, null, 2) : 'null');
                break;
                
            case 'set':
                if (args.length < 3) {
                    console.error('Usage: set <key> <value>');
                    process.exit(1);
                }
                let setValue = args[2];
                // Try to parse as JSON, fall back to string
                try {
                    setValue = JSON.parse(setValue);
                } catch (e) {
                    // Keep as string
                }
                const success = this.set(args[1], setValue);
                console.log(success ? 'Configuration updated' : 'Failed to update configuration');
                break;
                
            case 'get-secret':
                if (args.length < 2) {
                    console.error('Usage: get-secret <key>');
                    process.exit(1);
                }
                const secret = this.getSecret(args[1]);
                console.log(secret || 'null');
                break;
                
            case 'set-secret':
                if (args.length < 3) {
                    console.error('Usage: set-secret <key> <value>');
                    process.exit(1);
                }
                const secretSuccess = this.setSecret(args[1], args[2]);
                console.log(secretSuccess ? 'Secret stored' : 'Failed to store secret');
                break;
                
            case 'show':
                console.log('Configuration:');
                console.log(JSON.stringify(this.loadConfig(), null, 2));
                break;
                
            case 'init':
                console.log('Initializing VibeTunnel configuration...');
                this.saveConfig(this.getDefaultConfig());
                this.saveSecrets(this.getDefaultSecrets());
                console.log(`Configuration initialized at: ${this.configDir}`);
                break;
                
            case 'reset':
                console.log('Resetting VibeTunnel configuration...');
                if (fs.existsSync(this.configFile)) fs.unlinkSync(this.configFile);
                if (fs.existsSync(this.secretsFile)) fs.unlinkSync(this.secretsFile);
                if (fs.existsSync(this.keyFile)) fs.unlinkSync(this.keyFile);
                console.log('Configuration reset');
                break;
                
            default:
                console.log(`VibeTunnel Linux Configuration Manager

Usage: config-manager.js <command> [args...]

Commands:
  init                    Initialize default configuration
  show                    Show current configuration
  get <key>              Get configuration value
  set <key> <value>      Set configuration value
  get-secret <key>       Get encrypted secret
  set-secret <key> <val> Set encrypted secret
  reset                  Reset all configuration

Examples:
  config-manager.js set port 8080
  config-manager.js set auth.type password
  config-manager.js set-secret ngrokAuthToken your-token
  config-manager.js get-secret dashboardPassword

Configuration location: ${this.configDir}`);
        }
    }
}

// CLI interface
if (require.main === module) {
    const manager = new LinuxConfigManager();
    const args = process.argv.slice(2);
    
    if (args.length === 0) {
        args.push('help');
    }
    
    manager.handleCommand(args);
}

module.exports = LinuxConfigManager;