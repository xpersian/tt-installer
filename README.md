# TrustTunnel VPN Installer

TrustTunnel VPN Installer allows users to effortlessly set up the TrustTunnel VPN service. Use a simple command to initiate a secure and fast VPN connection on your system.

## Features

- 🚀 Quick installation using a single command
- 🔒 Secure connection setup with TLS certificates
- 🖥️ Supports multiple platforms (x86_64, aarch64)
- 🔧 Built-in management menu for easy administration
- 👥 Multi-user support

## Prerequisites

- Supported Operating Systems: Linux
- `curl` must be installed on your system
- Internet connection
- Root privileges

## Installation

1. **Download and Run the Installer Script**

   ```bash
   bash <(curl -fsSL https://raw.githubusercontent.com/deathline94/tt-installer/main/installer.sh)
   ```

## Usage

After installation, run the script again to access the management menu:

```bash
bash /root/trusttunnel-manager.sh
```

### Management Options

- Start/Stop/Restart Service
- View Logs
- Edit Configuration
- Add Users
- Show Client Config
- Reinstall/Uninstall

## Certificate Options

The installer supports three certificate options:

| Option | Works With | Notes |
|--------|------------|-------|
| **Self-signed** | CLI Client only | Quick setup for testing, does not work with Flutter Client |
| **Let's Encrypt** | All clients | Requires a valid domain pointing to your server |
| **Existing certificate** | All clients | Use your own CA-signed certificate |

> ⚠️ **Note:** Self-signed certificates only work with the TrustTunnel CLI client. The Flutter Client requires a valid CA-signed certificate (Let's Encrypt or your own).

## Credits

This installer is built for [TrustTunnel](https://github.com/TrustTunnel/TrustTunnel) - a secure VPN solution that provides encrypted tunneling for your network traffic.
