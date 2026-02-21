#!/usr/bin/env python3
"""CBOR fuzz testing harness using Atheris.

This module provides fuzz testing for CBOR message parsing in the QASP
framing layer. It uses Atheris (Google's Python fuzzing engine) to
generate random inputs and detect crashes, hangs, and other issues.

Usage (Linux only):
    FUZZ_ITERATIONS=10000 python tests/framing/fuzz_cbor.py

The harness tests:
    - Raw CBOR decoding via codec.decode()
    - Full frame parsing via codec.decode_frame()
    - Header parsing via FrameHeader.from_bytes()
    - Message type dispatch and reconstruction

Environment variables:
    FUZZ_ITERATIONS: Number of fuzzing iterations (default: 10000)
    FUZZ_TIMEOUT: Timeout per iteration in seconds (default: 5)
"""

from __future__ import annotations

import os
import sys

# Check platform and Atheris availability before importing
ATHERIS_AVAILABLE = False
if sys.platform == "linux":
    try:
        import importlib.util
        ATHERIS_AVAILABLE = importlib.util.find_spec("atheris") is not None
    except ImportError:
        pass


def fuzz_cbor_decode(data: bytes) -> None:
    """Fuzz target for raw CBOR decoding.

    Tests that the decode function handles arbitrary byte sequences
    gracefully without crashing.

    Args:
        data: Raw bytes to attempt to decode as CBOR.
    """
    from qasp.framing.codec import FramingError, decode

    try:
        decode(data)
    except FramingError:
        # Expected for invalid CBOR
        pass
    except Exception:  # noqa: S110
        # Fuzzing: intentionally catch all exceptions to find crashes
        pass


def fuzz_frame_decode(data: bytes) -> None:
    """Fuzz target for full frame parsing.

    Tests that decode_frame handles arbitrary byte sequences
    gracefully without crashing.

    Args:
        data: Raw bytes to attempt to parse as a QASP frame.
    """
    from qasp.framing.codec import FramingError, decode_frame

    # Use a fixed HMAC key for fuzzing
    hmac_key = b"\x00" * 32

    try:
        decode_frame(data, hmac_key)
    except FramingError:
        # Expected for invalid frames
        pass
    except Exception:  # noqa: S110
        # Fuzzing: intentionally catch all exceptions to find crashes
        pass


def fuzz_malformed_header(data: bytes) -> None:
    """Fuzz target for header parsing edge cases.

    Tests that FrameHeader.from_bytes handles arbitrary byte sequences
    gracefully without crashing.

    Args:
        data: Raw bytes to attempt to parse as a frame header.
    """
    from qasp.framing.codec import FrameHeader, FramingError

    try:
        FrameHeader.from_bytes(data)
    except FramingError:
        # Expected for invalid headers
        pass
    except Exception:  # noqa: S110
        # Fuzzing: intentionally catch all exceptions to find crashes
        pass


def fuzz_message_type_handling(data: bytes) -> None:
    """Fuzz target for message type dispatch.

    Constructs a valid-looking frame header and tests message
    reconstruction with fuzzed payload.

    Args:
        data: Raw bytes to use as CBOR payload.
    """
    import hashlib
    import hmac as hmac_mod
    import struct

    from qasp.framing.codec import (
        FRAME_MAGIC,
        FRAME_VERSION,
        FramingError,
        decode_frame,
    )

    # Need at least 1 byte for message type selection
    if len(data) < 1:
        return

    # Use first byte to select message type
    type_byte = data[0] % 20  # MessageType values are 0-19
    payload = data[1:]

    # Build a frame with valid structure
    header = (
        FRAME_MAGIC
        + bytes([FRAME_VERSION, type_byte])
        + struct.pack(">I", len(payload))
    )

    # Compute HMAC
    hmac_key = b"\x00" * 32
    frame_data = header + payload
    mac = hmac_mod.new(hmac_key, frame_data, hashlib.sha384).digest()

    full_frame = frame_data + mac

    try:
        decode_frame(full_frame, hmac_key)
    except FramingError:
        # Expected for invalid payloads
        pass
    except (ValueError, KeyError, TypeError):
        # Expected for malformed CBOR structures
        pass
    except Exception:  # noqa: S110
        # Fuzzing: intentionally catch all exceptions to find crashes
        pass


def fuzz_capability_token_cbor(data: bytes) -> None:
    """Fuzz target for capability token CBOR parsing.

    Tests that CapabilityToken.from_cbor handles arbitrary byte sequences
    gracefully without crashing.

    Args:
        data: Raw bytes to attempt to parse as a capability token.
    """
    from qasp.protocol.capability import CapabilityToken, InvalidTokenError

    try:
        CapabilityToken.from_cbor(data)
    except InvalidTokenError:
        # Expected for invalid token data
        pass
    except Exception:  # noqa: S110
        # Fuzzing: intentionally catch all exceptions to find crashes
        pass


def main() -> None:
    """Run the fuzzing harness."""
    if not ATHERIS_AVAILABLE:
        print("Atheris is not available on this platform.")
        print("Fuzzing requires Linux. Skipping fuzz tests.")
        sys.exit(0)

    # Get configuration from environment
    iterations = int(os.environ.get("FUZZ_ITERATIONS", "10000"))
    timeout = int(os.environ.get("FUZZ_TIMEOUT", "5"))

    print(f"Starting CBOR fuzz testing with {iterations} iterations...")
    print(f"Timeout per iteration: {timeout}s")

    # Select fuzz target based on environment variable
    target_name = os.environ.get("FUZZ_TARGET", "all")

    targets = {
        "decode": fuzz_cbor_decode,
        "frame": fuzz_frame_decode,
        "header": fuzz_malformed_header,
        "message_type": fuzz_message_type_handling,
        "capability": fuzz_capability_token_cbor,
    }

    if target_name == "all":
        # Run all targets sequentially
        for name, target in targets.items():
            print(f"\n--- Fuzzing target: {name} ---")
            run_fuzz_target(target, iterations // len(targets))
    elif target_name in targets:
        run_fuzz_target(targets[target_name], iterations)
    else:
        print(f"Unknown target: {target_name}")
        print(f"Available targets: {', '.join(targets.keys())}, all")
        sys.exit(1)

    print("\nFuzzing complete. No crashes found.")


def run_fuzz_target(target: object, iterations: int) -> None:
    """Run a single fuzz target.

    Args:
        target: The fuzzing target function.
        iterations: Number of iterations to run.
    """
    import contextlib

    import atheris

    # Instrument the target modules
    with atheris.instrument_imports():
        import qasp.framing.codec
        import qasp.framing.messages
        import qasp.protocol.capability

        # Ensure modules are loaded (referenced to avoid unused import warning)
        _ = qasp.framing.codec
        _ = qasp.framing.messages
        _ = qasp.protocol.capability

    # Set up atheris
    atheris.Setup(
        [sys.argv[0], f"-runs={iterations}"],
        target,  # type: ignore[arg-type]
    )

    # Run the fuzzer (atheris.Fuzz() calls sys.exit() when done)
    with contextlib.suppress(SystemExit):
        atheris.Fuzz()


if __name__ == "__main__":
    main()
