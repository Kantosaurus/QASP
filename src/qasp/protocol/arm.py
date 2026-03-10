"""ARM Resource URI algebra for QASP capability tokens.

This module implements URI parsing, wildcard matching, prefix-based
attenuation validation, and URI intersection for ARM-style resource URIs
of the form ``qasp://provider/resource/subresource``.

The URI algebra underpins token attenuation (child scope ⊆ parent scope)
and token aggregation (URI intersection for combined permissions).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "ARMUri",
    "InvalidARMUriError",
    "intersect_uris",
    "is_attenuation",
    "parse_uri",
    "uri_matches",
]

# ABNF-derived regex for qasp:// URIs.
# Scheme:   qasp
# Provider: 1*(ALPHA / DIGIT / "-" / ".")
# Segments: *("/" segment)  where segment = 1*(ALPHA / DIGIT / "-" / "_" / "." / "*")
_SEGMENT_CHARS = r"[A-Za-z0-9\-_.*]+"
_PROVIDER_CHARS = r"[A-Za-z0-9\-.]+"
_URI_RE = re.compile(
    rf"^qasp://({_PROVIDER_CHARS})((?:/{_SEGMENT_CHARS})*)$"
)


# =============================================================================
# Exceptions
# =============================================================================


class InvalidARMUriError(Exception):
    """Raised when an ARM URI fails validation against the ABNF grammar."""


# =============================================================================
# Data Structures
# =============================================================================


@dataclass(frozen=True)
class ARMUri:
    """Parsed ARM-style resource URI.

    Attributes:
        scheme: Always ``"qasp"``.
        provider: The provider/authority segment (e.g. ``"acme"``).
        segments: Path segments after the provider (e.g. ``("gpu", "a100")``).
        raw: The original URI string.
    """

    scheme: str
    provider: str
    segments: tuple[str, ...]
    raw: str

    def __str__(self) -> str:
        """Reconstruct the canonical URI string."""
        path = "/".join(self.segments)
        if path:
            return f"{self.scheme}://{self.provider}/{path}"
        return f"{self.scheme}://{self.provider}"


# =============================================================================
# URI Parsing
# =============================================================================


def parse_uri(uri: str) -> ARMUri:
    """Parse a ``qasp://`` URI into structured components.

    Args:
        uri: A URI string matching ``qasp://provider[/seg1[/seg2[...]]]``.

    Returns:
        An :class:`ARMUri` with validated components.

    Raises:
        InvalidARMUriError: If the URI does not match the ABNF grammar.
    """
    if not uri:
        raise InvalidARMUriError("URI must not be empty")

    m = _URI_RE.match(uri)
    if m is None:
        raise InvalidARMUriError(f"Invalid ARM URI: {uri!r}")

    provider = m.group(1)
    path_part = m.group(2)  # e.g. "/gpu/a100" or ""

    if path_part:
        # Strip leading "/" and split
        segments = tuple(path_part[1:].split("/"))
    else:
        segments = ()

    # Wildcards may only appear as the last segment
    for i, seg in enumerate(segments):
        if seg == "*" and i != len(segments) - 1:
            raise InvalidARMUriError(
                f"Wildcard '*' may only appear as the last segment: {uri!r}"
            )

    return ARMUri(scheme="qasp", provider=provider, segments=segments, raw=uri)


# =============================================================================
# URI Matching
# =============================================================================


def uri_matches(pattern: str, target: str) -> bool:
    """Check whether *pattern* matches *target*.

    Matching rules (evaluated in order):
    1. **Exact match**: identical URIs.
    2. **Wildcard match**: ``qasp://acme/gpu/*`` matches
       ``qasp://acme/gpu/a100`` (wildcard covers exactly one segment).
    3. **Prefix match**: ``qasp://acme/gpu`` is a parent of
       ``qasp://acme/gpu/a100`` (shorter path is a prefix of longer path).

    Args:
        pattern: The URI pattern (may contain a trailing ``*`` segment).
        target: The concrete URI to test.

    Returns:
        ``True`` if *pattern* covers *target*.

    Raises:
        InvalidARMUriError: If either URI fails parsing.
    """
    p = parse_uri(pattern)
    t = parse_uri(target)

    # Providers must match
    if p.provider != t.provider:
        return False

    # Exact match (no wildcards, same segments)
    if p.segments == t.segments:
        return True

    # Wildcard match: pattern ends with "*"
    if p.segments and p.segments[-1] == "*":
        prefix = p.segments[:-1]
        # Target must have exactly one more segment beyond the prefix
        if len(t.segments) == len(prefix) + 1:
            return t.segments[:len(prefix)] == prefix
        # Also match if target has exactly the prefix length (wildcard optional)
        # e.g. qasp://acme/* matches qasp://acme/gpu
        if len(t.segments) >= 1 and len(prefix) == 0:
            return len(t.segments) == 1
        if t.segments[:len(prefix)] == prefix and len(t.segments) > len(prefix):
            return len(t.segments) == len(prefix) + 1
        return False

    # Prefix match: pattern is a strict prefix of target
    if len(p.segments) < len(t.segments):
        return t.segments[:len(p.segments)] == p.segments

    return False


# =============================================================================
# Attenuation Validation
# =============================================================================


def is_attenuation(parent_uri: str, child_uri: str) -> bool:
    """Check that *child_uri* is the same scope or narrower than *parent_uri*.

    Valid attenuations:
    - Same URI: ``qasp://acme/gpu/a100`` → ``qasp://acme/gpu/a100``
    - Narrowing: ``qasp://acme/gpu/*`` → ``qasp://acme/gpu/a100``
    - Sub-resource: ``qasp://acme/gpu`` → ``qasp://acme/gpu/a100``

    Invalid (escalation):
    - Widening: ``qasp://acme/gpu/a100`` → ``qasp://acme/gpu/*``
    - Moving up: ``qasp://acme/gpu/a100`` → ``qasp://acme/gpu``

    Args:
        parent_uri: The parent token's resource URI.
        child_uri: The proposed child token's resource URI.

    Returns:
        ``True`` if the child is a valid attenuation of the parent.

    Raises:
        InvalidARMUriError: If either URI fails parsing.
    """
    # Child must be covered by parent's scope
    return uri_matches(parent_uri, child_uri)


# =============================================================================
# URI Intersection
# =============================================================================


def intersect_uris(uri_a: str, uri_b: str) -> str | None:
    """Compute the most specific common scope of two URIs.

    Used by token aggregation algebra to find the effective resource scope
    when combining permissions from multiple tokens.

    Rules:
    - If one URI covers the other, return the more specific one.
    - If URIs are identical, return that URI.
    - If URIs have no overlap, return ``None``.

    Args:
        uri_a: First resource URI.
        uri_b: Second resource URI.

    Returns:
        The most specific common URI, or ``None`` if no overlap.

    Raises:
        InvalidARMUriError: If either URI fails parsing.
    """
    a = parse_uri(uri_a)
    b = parse_uri(uri_b)

    # Different providers => no overlap
    if a.provider != b.provider:
        return None

    # If a covers b, b is more specific
    if uri_matches(uri_a, uri_b):
        return uri_b

    # If b covers a, a is more specific
    if uri_matches(uri_b, uri_a):
        return uri_a

    # Both have wildcards at same level — compute prefix intersection
    a_segs = a.segments
    b_segs = b.segments

    # Strip trailing wildcards for prefix comparison
    a_concrete = a_segs[:-1] if (a_segs and a_segs[-1] == "*") else a_segs
    b_concrete = b_segs[:-1] if (b_segs and b_segs[-1] == "*") else b_segs

    # Find common prefix
    common_len = 0
    for i in range(min(len(a_concrete), len(b_concrete))):
        if a_concrete[i] == b_concrete[i]:
            common_len = i + 1
        else:
            break

    if common_len == 0:
        return None

    # If both had concrete segments that diverge after the common prefix,
    # there's no intersection at a more specific level
    if common_len < len(a_concrete) and common_len < len(b_concrete):
        return None

    # If one is a prefix of the other in concrete segments, the longer is more specific
    if a_concrete[:common_len] == b_concrete[:common_len]:
        # Return the longer concrete path (more specific)
        if len(a_concrete) >= len(b_concrete):
            return str(a)
        return str(b)

    return None
