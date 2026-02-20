# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in QASP, please report it responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to the maintainers or through GitHub's private vulnerability reporting feature.

When reporting, please include:

1. **Description**: A clear description of the vulnerability
2. **Steps to reproduce**: Detailed steps to reproduce the issue
3. **Impact**: The potential impact of the vulnerability
4. **Affected versions**: Which versions are affected
5. **Suggested fix**: If you have a suggested fix, please include it

### What to Expect

- **Acknowledgment**: We will acknowledge receipt within 48 hours
- **Initial assessment**: We will provide an initial assessment within 7 days
- **Updates**: We will keep you informed of our progress
- **Credit**: We will credit you in the security advisory (unless you prefer to remain anonymous)

### Scope

The following are in scope for security reports:

- Cryptographic vulnerabilities in the QASP protocol
- Authentication or authorization bypasses
- Information disclosure
- Injection vulnerabilities
- Denial of service vulnerabilities with significant impact

### Out of Scope

- Issues in dependencies (please report to the respective projects)
- Issues requiring physical access to user's device
- Social engineering attacks
- Issues in third-party applications using QASP

## Security Best Practices

When using QASP:

1. **Keep dependencies updated**: Regularly update to the latest version
2. **Use strong entropy**: Ensure your system has adequate entropy for key generation
3. **Protect private keys**: Store private keys securely
4. **Validate certificates**: Always verify X.509-PQ certificates
5. **Monitor for anomalies**: Implement logging and monitoring

## Cryptographic Algorithms

QASP uses the following NIST-standardized algorithms:

- **ML-KEM-768** (FIPS 203): Key encapsulation
- **ML-DSA-65** (FIPS 204): Digital signatures
- **AES-256-GCM**: Authenticated encryption
- **HKDF-SHA-384**: Key derivation

These algorithms were selected based on NIST's post-quantum cryptography standardization process.

## Audit Status

This project is currently in development. A formal security audit is planned before the 1.0 release.

## PGP Key

For sensitive communications, you may encrypt your message using our PGP key (to be published).
