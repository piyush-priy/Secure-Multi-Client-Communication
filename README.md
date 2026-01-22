# Secure Multi-Client Communication System

## SNS Lab Assignment 1: Stateful Symmetric-Key Based Secure Communication Protocol

This project implements a secure client–server protocol for coordinating communication with multiple clients in a hostile network setting. Messages use AES-128-CBC encryption (PKCS#7 padding) and HMAC-SHA256 authentication (verified before decryption). The protocol is stateful and round-based to prevent replay/reordering, includes direction checks to mitigate reflection, and ratchets keys forward after successful exchanges for forward secrecy. An included attack/demo tool exercises common network attacks (replay, tampering, reordering, reflection, desync) and shows how the protocol responds.

## Features

- **AES-128-CBC Encryption** with manual PKCS#7 padding
- **HMAC-SHA256 Authentication** (verify before decrypt)
- **Key Ratcheting** for forward secrecy
- **Round-based Synchronization** for replay protection
- **Multi-client Support** with per-client sessions
- **Data Aggregation** across clients per round

## Requirements

- C++17 compatible compiler (g++ 7+ or clang++ 5+)
- OpenSSL development library
- POSIX-compliant OS (Linux, macOS)

### Installing Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install build-essential libssl-dev
```

**Arch Linux:**
```bash
sudo pacman -S base-devel openssl
```

**macOS:**
```bash
brew install openssl
# May need: export LDFLAGS="-L/usr/local/opt/openssl/lib"
```

## Building

```bash
make all
```

This builds three executables:
- `server` - The multi-client server
- `client` - The client application
- `attacks` - Attack demonstration tool

## Quick Start

### 1. Start the Server
```bash
./server -k keys.txt -n 3
```

Options:
- `-p PORT` - Port to listen on (default: 8443)
- `-k KEYFILE` - Key file path (default: keys.txt)
- `-n CLIENTS` - Expected number of clients per round (default: 3)

### 2. Run Clients (in separate terminals)
```bash
# Terminal 2
./client -i 1 -k 0123456789abcdef0123456789abcdef -r 5

# Terminal 3
./client -i 2 -k fedcba9876543210fedcba9876543210 -r 5

# Terminal 4
./client -i 3 -k abcdef0123456789abcdef0123456789 -r 5
```

Options:
- `-s HOST` - Server hostname (default: localhost)
- `-p PORT` - Server port (default: 8443)
- `-i ID` - Client ID (1-255, required)
- `-k KEY` - Master key (hex string or file path)
- `-r ROUNDS` - Number of rounds (default: 5)
- `-d VALUE` - Data value to send (default: random)

### 3. Run Demo
```bash
make demo
```

## Key File Format

The `keys.txt` file contains pre-shared master keys:
```
# client_id:hex_encoded_master_key
1:0123456789abcdef0123456789abcdef
2:fedcba9876543210fedcba9876543210
3:abcdef0123456789abcdef0123456789
```

## Protocol Overview

### Message Format
```
| Opcode (1) | Client ID (1) | Round (4) | Direction (1) | IV (16) |
| Ciphertext (variable) | HMAC (32) |
```

### Protocol Opcodes
| Opcode | Name | Description |
|--------|------|-------------|
| 10 | CLIENT_HELLO | Client initiates session |
| 20 | SERVER_CHALLENGE | Server sends challenge |
| 30 | CLIENT_DATA | Client sends data |
| 40 | SERVER_AGGR_RESPONSE | Server sends aggregated result |
| 50 | KEY_DESYNC_ERROR | Key synchronization error |
| 60 | TERMINATE | Session termination |

### Protocol Flow
```
Client                                  Server
  |                                       |
  |-------- CLIENT_HELLO (R=0) --------->|
  |                                       |
  |<------- SERVER_CHALLENGE (R=0) ------|
  |                                       |
  |-------- CLIENT_DATA (R=1) ---------->|
  |                                       |
  |<----- SERVER_AGGR_RESPONSE (R=1) ----|
  |                                       |
  |            ... repeat ...             |
  |                                       |
  |---------- TERMINATE ----------------->|
```

## Attack Demonstrations

Run local cryptographic tests:
```bash
./attacks -l
```

Run full attack demonstration (requires server):
```bash
make run-attacks
```

Specific attack tests:
- `-a 1` - Replay attack
- `-a 2` - HMAC tampering
- `-a 3` - Message reordering
- `-a 4` - Reflection attack
- `-a 5` - Invalid opcode attack

## File Structure

| File | Description |
|------|-------------|
| `common.hpp` | Shared types, constants, message format |
| `crypto_utils.hpp/cpp` | Cryptographic primitives |
| `protocol_fsm.hpp/cpp` | Protocol state machine |
| `server.cpp` | Server implementation |
| `client.cpp` | Client implementation |
| `attacks.cpp` | Attack demonstration |
| `keys.txt` | Pre-shared master keys |
| `Makefile` | Build system |

## Security Features

1. **HMAC Verification Before Decryption** - Prevents padding oracle attacks
2. **Round Numbers** - Prevents replay and reordering attacks
3. **Direction Field** - Prevents reflection attacks
4. **Key Ratcheting** - Provides forward secrecy
5. **State Machine** - Validates opcodes for current state

See `SECURITY.md` for detailed security analysis.

## Troubleshooting

### "Failed to bind to port"
Another process is using the port. Either kill it or use a different port:
```bash
./server -p 9000
```

### "Unknown client ID"
The client ID must be configured in `keys.txt` on the server.

### "HMAC verification failed"
Keys don't match between client and server. Verify both are using the same master key.
