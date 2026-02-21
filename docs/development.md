# Development Guide

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.12+ | Runtime (3.12 and 3.13 supported) |
| git | any | Source control |
| cmake | any | Build liboqs from source |
| ninja | any | Build liboqs from source |
| Podman + podman-compose | any | Containerized workflow (optional) |

## Quick Start (Podman/Docker)

The fastest path — no need to build liboqs locally:

```bash
git clone <repo-url> && cd QASP
podman-compose up --build dev
```

```bash
 # One-time: start the machine
  podman machine start

  # Build the image (only needed when Dockerfile changes)
  podman build --target dev -t qasp:dev .

  # Run the dev shell
  podman run -it --rm -v ./src:/app/src:Z -v ./tests:/app/tests:Z -w /app qasp:dev

  # Run all tests (using dev image)
  podman run --rm -v ./src:/app/src:Z -v ./tests:/app/tests:Z -w /app qasp:dev -c "pytest -v"                                                                                                              
  
  # Run all tests (using the dedicated test image)
  podman run --rm -v ./src:/app/src:Z -v ./tests:/app/tests:Z qasp:test
```


```bash
  │ Stage │      Target       │               Purpose               │                  Command                  │                                                                                            ├───────┼───────────────────┼─────────────────────────────────────┼───────────────────────────────────────────┤                                                                                          
  │ dev   │ Development shell │ Full dev environment with all tools │ docker build --target dev -t qasp-dev .   │                                                                                          
  ├───────┼───────────────────┼─────────────────────────────────────┼───────────────────────────────────────────┤
  │ test  │ Test runner       │ Runs pytest                         │ docker build --target test -t qasp-test . │
  ├───────┼───────────────────┼─────────────────────────────────────┼───────────────────────────────────────────┤
  │ lint  │ Static analysis   │ Runs ruff, mypy, bandit             │ docker build --target lint -t qasp-lint . │
  └───────┴───────────────────┴─────────────────────────────────────┴───────────────────────────────────────────┘

  How to use it:

  # Build and run tests
  docker build --target test -t qasp-test .
  docker run --rm qasp-test

  # Build and run linters
  docker build --target lint -t qasp-lint .
  docker run --rm qasp-lint

  # Interactive dev shell
  docker build --target dev -t qasp-dev .
  docker run --rm -it qasp-dev
```

This drops you into a shell with liboqs pre-built, all Python deps installed, and `src/` + `tests/` bind-mounted so edits on the host are reflected immediately.

## Native Setup

### 1. Clone the repository

```bash
git clone <repo-url> && cd QASP
```

### 2. Build and install liboqs

```bash
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DBUILD_SHARED_LIBS=ON ..
ninja
sudo ninja install
sudo ldconfig
cd ../..
```

### 3. Create a virtualenv and install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest              # run all tests
pytest -v           # verbose output
pytest -m "not slow"  # skip slow tests
```

### Markers

Defined in `pyproject.toml`:

| Marker | Description |
|--------|-------------|
| `slow` | Long-running tests (deselect with `-m "not slow"`) |
| `integration` | Integration tests |
| `property` | Property-based tests (Hypothesis) |
| `fuzz` | Tests requiring Atheris (Linux only) |

### Hypothesis Profiles

Set via the `HYPOTHESIS_PROFILE` environment variable (configured in `tests/conftest.py`):

| Profile | `max_examples` | Use case |
|---------|----------------|----------|
| `default` | 100 | Local development |
| `ci` | 500 | CI pipelines (more thorough) |
| `quick` | 10 | Fast iteration |
| `debug` | 10 | Verbose output for debugging |

```bash
HYPOTHESIS_PROFILE=quick pytest -m property
```

## Linting & Type Checking

```bash
ruff check src/ tests/   # lint (pycodestyle, pyflakes, isort, bugbear, bandit rules, etc.)
mypy src/                 # type check (strict mode)
bandit -r src/            # security analysis
```

Ruff is configured in `pyproject.toml` with `line-length = 100` and `target-version = "py312"`.

## Project Layout

```
src/qasp/
  __init__.py        Top-level package
  py.typed           PEP 561 marker
  bridges/           Protocol bridges for MCP and A2A interoperability
  crypto/            Post-quantum primitives (KEM, signatures, AEAD)
  framing/           CBOR-based message framing and serialization
  identity/          did:qasp decentralized identifiers and X.509-PQ certificates
  protocol/          Sans-I/O connection management and PQ handshake
  transport/         TCP transport with length-prefixed framing and discovery
  trust/             Bayesian trust scoring, audit certification, and verification
```

## Container Targets

All services are defined in `compose.yaml` and run with `podman-compose up <service>`.

| Service | Base stage | Entrypoint | Description |
|---------|-----------|------------|-------------|
| `dev` | `dev` | `/bin/bash` | Interactive development shell |
| `test` | `test` | `pytest` | Run tests (`-v --tb=short` by default) |
| `lint` | `lint` | `run-lint.sh` | Run all linters (ruff + mypy + bandit) |
| `typecheck` | `lint` | `mypy src/` | Type checking only |
| `security` | `lint` | `bandit -r src/` | Security analysis only |

`dev`, `test`, and `lint` mount both `src/` and `tests/`. `typecheck` and `security` mount only `src/`.
