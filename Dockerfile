# QASP Multi-Stage Dockerfile
# Podman-compatible containerization for quantum-safe protocol library

# =============================================================================
# Stage 1: liboqs-builder
# Build liboqs C library from source
# =============================================================================
FROM ubuntu:24.04 AS liboqs-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    ninja-build \
    git \
    gcc \
    g++ \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Clone and build liboqs
WORKDIR /build
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && \
    cd build && \
    cmake -GNinja \
        -DCMAKE_INSTALL_PREFIX=/liboqs-install \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        .. && \
    ninja && \
    ninja install

# =============================================================================
# Stage 2: python-base
# Base Python image with liboqs libraries
# =============================================================================
FROM python:3.12-slim-bookworm AS python-base

# Copy liboqs libraries from builder
COPY --from=liboqs-builder /liboqs-install/lib /usr/local/lib
COPY --from=liboqs-builder /liboqs-install/include /usr/local/include

# Register shared libraries
RUN ldconfig

# Python environment configuration
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# =============================================================================
# Stage 3: authority (QASP Authority Server - production runtime)
# FastAPI + Uvicorn server with CapFlow relay baked in
# =============================================================================
FROM python-base AS authority

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY README.md .
COPY src/ src/
COPY scripts/ scripts/
COPY docs/ docs/

RUN pip install -e "." && \
    pip install fastapi uvicorn httpx prometheus-client

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8080/ || exit 1

ENTRYPOINT ["python", "scripts/qasp_server.py"]
CMD ["--host", "0.0.0.0", "--port", "8080", "--db", "/data/qasp_authority.db"]

# =============================================================================
# Stage 4: dev (Development Shell)
# Full development environment with all tools
# =============================================================================
FROM python-base AS dev

# Install git for development workflows
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml .
COPY README.md .
COPY src/ src/
COPY tests/ tests/
COPY scripts/ scripts/

# Install all dependencies including dev tools + server deps
RUN pip install -e ".[dev]" && pip install fastapi uvicorn httpx

# Default to interactive bash shell
ENTRYPOINT ["/bin/bash"]

# =============================================================================
# Stage 5: test (Test Runner)
# Minimal image for running tests
# =============================================================================
FROM python-base AS test

# Copy project files
COPY pyproject.toml .
COPY README.md .
COPY src/ src/
COPY tests/ tests/

# Install runtime dependencies and test tools only (no linters)
RUN pip install pytest pytest-asyncio hypothesis && \
    pip install -e .

ENTRYPOINT ["pytest"]
CMD ["-v", "--tb=short"]

# =============================================================================
# Stage 6: lint (Static Analysis)
# Linting and type checking tools
# =============================================================================
FROM python-base AS lint

# Copy project files
COPY pyproject.toml .
COPY README.md .
COPY src/ src/
COPY tests/ tests/

# Install only linting tools and minimal dependencies for type checking
RUN pip install ruff mypy bandit && \
    pip install -e .

# Default: run all linters
COPY <<'EOF' /app/run-lint.sh
#!/bin/bash
set -e
echo "=== Running ruff ==="
ruff check src/ tests/
echo ""
echo "=== Running mypy ==="
mypy src/
echo ""
echo "=== Running bandit ==="
bandit -r src/
echo ""
echo "All checks passed!"
EOF

RUN chmod +x /app/run-lint.sh

ENTRYPOINT ["/bin/bash", "/app/run-lint.sh"]
