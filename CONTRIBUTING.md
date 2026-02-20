# Contributing to QASP

Thank you for your interest in contributing to QASP! This document provides guidelines for contributing to the project.

## Development Setup

### Prerequisites

- Python 3.12 or later
- liboqs system library
- Git

### Setting Up Your Environment

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/qasp.git
   cd qasp
   ```

2. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

## Code Style

We use automated tools to maintain consistent code style:

- **Ruff**: For linting and import sorting
- **mypy**: For static type checking
- **bandit**: For security scanning

### Running Code Quality Checks

```bash
# Lint code
ruff check src/ tests/

# Format code (auto-fix)
ruff check --fix src/ tests/

# Type check
mypy src/

# Security scan
bandit -r src/
```

### Style Guidelines

- Use type hints for all function signatures
- Follow PEP 8 conventions
- Maximum line length: 100 characters
- Use descriptive variable and function names
- Write docstrings for public APIs

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/crypto/test_kem.py

# Run with coverage
pytest --cov=qasp --cov-report=html
```

### Writing Tests

- Place tests in the `tests/` directory, mirroring the source structure
- Use descriptive test function names: `test_<function>_<scenario>_<expected>`
- Use pytest fixtures for common setup
- Include both positive and negative test cases
- Use `hypothesis` for property-based testing where appropriate

Example:
```python
import pytest
from qasp.crypto import kem

def test_kem_keygen_produces_valid_keypair():
    public_key, secret_key = kem.generate_keypair()
    assert public_key is not None
    assert secret_key is not None
    assert len(public_key) > 0

def test_kem_encapsulate_with_invalid_key_raises():
    with pytest.raises(ValueError):
        kem.encapsulate(b"invalid_key")
```

## Pull Request Process

1. **Create a branch**: Use descriptive branch names
   ```bash
   git checkout -b feature/add-hybrid-encryption
   git checkout -b fix/handshake-timeout
   ```

2. **Make your changes**: Follow the code style guidelines

3. **Write tests**: Ensure your changes are tested

4. **Run quality checks**:
   ```bash
   ruff check src/ tests/
   mypy src/
   pytest
   bandit -r src/
   ```

5. **Commit your changes**: Use clear commit messages
   ```bash
   git commit -m "Add hybrid X25519+ML-KEM key exchange"
   ```

6. **Push and create PR**: Push to your fork and open a pull request

### PR Requirements

- All CI checks must pass
- Include tests for new functionality
- Update documentation if needed
- Keep changes focused and atomic

## Reporting Issues

When reporting bugs, please include:

- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Relevant error messages or logs

## Security Issues

For security vulnerabilities, please see [SECURITY.md](SECURITY.md) for our security policy and responsible disclosure process.

## Questions?

Feel free to open a discussion or issue for questions about contributing.
