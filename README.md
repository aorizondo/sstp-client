# SSTP Client with lwIP

Python SSTP client using lwIP for PPP frame handling, with port binding to expose VPN resources locally without creating system network interfaces.

## Features

- ✅ Complete SSTP client (SSL/TLS + HTTP + SSTP handshake)
- ✅ lwIP integration with full PPP support
- ✅ Port binding for local resource exposure
- ✅ Cross-platform (Linux/Windows/Android)
- ✅ No system network interface required
- ✅ Pure Python with stdlib only

## Architecture

```
┌──────────────┐
│ Local App    │
└──────┬───────┘
       │ TCP
       ↓
┌──────────────┐    ┌──────────┐    ┌─────────────┐
│ Port Binding │ ←→ │  lwIP    │ ←→ │ SSTP Client │
│ localhost:P  │    │  (PPP)   │    │  SSL/TLS    │
└──────────────┘    └──────────┘    └──────┬──────┘
                                           │
                                           ↓
                                    ┌──────────────┐
                                    │  VPN Server  │
                                    └──────────────┘
```

## Quick Start

### 1. Compile lwIP

```bash
cd py-lwip
make lwip_lib
```

### 2. Run Client

```bash
python3 main.py \
  --server vpn.example.com \
  --user username \
  --pass password \
  --bind-port 8080 \
  --target 192.168.1.100:80 \
  --verbose
```

This exposes `localhost:8080` which connects to `192.168.1.100:80` inside the VPN.

## Project Structure

```
sstp/
├── lwip_bindings/        # Python bindings for lwIP (ctypes)
├── sstp/                 # SSTP client implementation
│   ├── protocol.py       # SSTP protocol (MS-SSTP spec)
│   ├── handshake.py      # SSL/TLS + HTTP + SSTP handshake
│   ├── client.py         # Main SSTP client
│   └── ppp_handler.py    # PPP frame handling with lwIP
├── port_binding.py       # Local port binding
├── main.py               # CLI entry point
├── py-lwip/              # lwIP submodule
└── scripts/
    └── build_lwip.sh     # lwIP compilation script
```

## Requirements

- Python 3.7+
- CMake (for lwIP compilation)
- GCC/Clang (for lwIP compilation)
- No external Python dependencies (stdlib only)

## Cross-Platform Support

### Linux
Works out of the box after compiling lwIP.

### Windows
1. Compile lwIP with MSVC or MinGW
2. Use PyInstaller for standalone executable:
   ```bash
   pyinstaller --onefile main.py
   ```

### Android
1. Compile lwIP with Android NDK
2. Use Chaquopy for APK packaging

## How It Works

### SSTP Handshake
1. TCP connection to server:443
2. SSL/TLS handshake
3. HTTP CONNECT request/response
4. SSTP negotiation (CALL_CONNECT_REQUEST → ACK → CONNECTED)

### PPP Integration
- SSTP receives PPP frames → feeds to lwIP via `pppos_input()`
- lwIP generates PPP frames → callback → sends via SSTP tunnel
- lwIP handles PPP negotiation, authentication (PAP/CHAP/MSCHAP)

### Port Binding
- Listens on `localhost:PORT`
- Accepts connections → creates lwIP socket to VPN target
- Bidirectional relay: local app ↔ lwIP ↔ VPN resource

## Configuration

All configuration via CLI arguments:

```bash
python3 main.py --help
```

Options:
- `--server`: SSTP server hostname/IP
- `--port`: Server port (default: 443)
- `--user`: Authentication username
- `--pass`: Authentication password
- `--bind-port`: Local port to bind
- `--target`: Target IP:PORT inside VPN
- `--verbose`: Enable debug logging

## Development

### Testing
```bash
# Compile Python modules
python3 -m py_compile main.py sstp/*.py

# Run with verbose logging
python3 main.py --verbose ...
```

### Debugging
Enable verbose logging to see:
- SSTP handshake details
- PPP frame exchanges
- lwIP status changes
- Port binding connections

## License

MIT License - See LICENSE file

## Credits

- lwIP: https://savannah.nongnu.org/projects/lwip/
- py-lwip: https://github.com/vvish/py-lwip
- SSTP Protocol: Microsoft MS-SSTP specification

## Author

Antonio Orizondo (@aorizondo)
