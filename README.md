# QASP - Quantum-Aware Secure Protocol

A quantum-safe communication protocol designed for AI agent-to-agent interactions.

## Overview

QASP (Quantum-Aware Secure Protocol) provides post-quantum cryptographic security for AI agent communication. It combines NIST-standardized post-quantum algorithms with hybrid classical cryptography to ensure long-term security against both current and future quantum threats.

### Key Features

- **Post-Quantum Security**: ML-KEM-768 and ML-DSA-65 for quantum-resistant key exchange and signatures
- **Hybrid Cryptography**: X25519 + ML-KEM-768 for defense in depth
- **Capability-Based Access**: Fine-grained permission tokens for resource access
- **Trust Scoring**: Bayesian reputation and behavioral verification
- **Protocol Bridges**: Interoperability with MCP and A2A protocols

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
├─────────────────────────────────────────────────────────────┤
│  Identity (did:qasp)  │  Trust Scoring  │  Capability Mgmt  │
├─────────────────────────────────────────────────────────────┤
│              Protocol Layer (QASP-Shake Handshake)           │
├─────────────────────────────────────────────────────────────┤
│          Crypto Layer (ML-KEM, ML-DSA, AES-256-GCM)          │
├─────────────────────────────────────────────────────────────┤
│              Transport Layer (TCP/QUIC)                      │
└─────────────────────────────────────────────────────────────┘
```

## Installation

### Requirements

- Python 3.12 or later
- liboqs system library (for post-quantum cryptography)

### Install from source

```bash
# Clone the repository
git clone https://github.com/QASP/qasp.git
cd qasp

# Install in development mode
pip install -e ".[dev]"
```

### Install dependencies only

```bash
pip install -e .
```

## Quick Start

```python
from qasp.crypto import kem, signatures, hybrid
from qasp.protocol import QASPConnection

# Generate hybrid keypair
keypair = hybrid.generate_keypair()

# Create a connection (sans-I/O design)
conn = QASPConnection(keypair)

# Process protocol events
events = conn.receive_data(incoming_bytes)
for event in events:
    match event:
        case HandshakeComplete():
            print("Secure connection established")
        case DataReceived(data):
            print(f"Received: {data}")
```

## Development

### Setup

```bash
# Install with development dependencies
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=qasp

# Run specific test file
pytest tests/crypto/test_kem.py
```

### Code Quality

```bash
# Lint
ruff check src/ tests/

# Type check
mypy src/

# Security scan
bandit -r src/
```

## Project Structure

```
src/qasp/
├── crypto/          # Post-quantum cryptography primitives
├── protocol/        # QASP protocol implementation
├── framing/         # CBOR message encoding
├── identity/        # DID-based identity
├── trust/           # Trust scoring and verification
├── transport/       # Network transport (TCP/QUIC)
└── bridges/         # Protocol interoperability (MCP, A2A)
```

## Documentation

- [Build Plan](docs/build-plan.md) - Development roadmap
- [QASP Proposal](docs/qasp-proposal.pdf) - Technical specification

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## Security

See [SECURITY.md](SECURITY.md) for security policy and vulnerability reporting.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.
