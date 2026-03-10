"""Tests for ARM Resource URI algebra."""

from __future__ import annotations

import pytest

from qasp.protocol.arm import (
    ARMUri,
    InvalidARMUriError,
    intersect_uris,
    is_attenuation,
    parse_uri,
    uri_matches,
)


# =============================================================================
# Parsing Tests
# =============================================================================


class TestParseUri:
    """Test URI parsing against the ABNF grammar."""

    def test_simple_uri(self):
        uri = parse_uri("qasp://acme/gpu/a100")
        assert uri.scheme == "qasp"
        assert uri.provider == "acme"
        assert uri.segments == ("gpu", "a100")
        assert uri.raw == "qasp://acme/gpu/a100"

    def test_provider_only(self):
        uri = parse_uri("qasp://acme")
        assert uri.provider == "acme"
        assert uri.segments == ()

    def test_single_segment(self):
        uri = parse_uri("qasp://acme/gpu")
        assert uri.segments == ("gpu",)

    def test_deep_path(self):
        uri = parse_uri("qasp://acme/gpu/cluster/rack/a100")
        assert uri.segments == ("gpu", "cluster", "rack", "a100")

    def test_wildcard_segment(self):
        uri = parse_uri("qasp://acme/gpu/*")
        assert uri.segments == ("gpu", "*")

    def test_provider_with_dots(self):
        uri = parse_uri("qasp://cloud.acme.com/gpu")
        assert uri.provider == "cloud.acme.com"
        assert uri.segments == ("gpu",)

    def test_provider_with_hyphens(self):
        uri = parse_uri("qasp://my-provider/resource")
        assert uri.provider == "my-provider"

    def test_segment_with_hyphens_underscores_dots(self):
        uri = parse_uri("qasp://acme/gpu-v2/model_a100.v3")
        assert uri.segments == ("gpu-v2", "model_a100.v3")

    def test_str_roundtrip(self):
        original = "qasp://acme/gpu/a100"
        uri = parse_uri(original)
        assert str(uri) == original

    def test_str_roundtrip_provider_only(self):
        original = "qasp://acme"
        uri = parse_uri(original)
        assert str(uri) == original

    # --- Invalid URIs ---

    def test_empty_string(self):
        with pytest.raises(InvalidARMUriError, match="must not be empty"):
            parse_uri("")

    def test_wrong_scheme(self):
        with pytest.raises(InvalidARMUriError, match="Invalid ARM URI"):
            parse_uri("https://acme/gpu")

    def test_no_scheme(self):
        with pytest.raises(InvalidARMUriError):
            parse_uri("acme/gpu")

    def test_missing_provider(self):
        with pytest.raises(InvalidARMUriError):
            parse_uri("qasp:///gpu")

    def test_wildcard_not_last_segment(self):
        with pytest.raises(InvalidARMUriError, match="last segment"):
            parse_uri("qasp://acme/*/gpu")

    def test_trailing_slash(self):
        # "qasp://acme/gpu/" has an empty segment after the slash
        with pytest.raises(InvalidARMUriError):
            parse_uri("qasp://acme/gpu/")


# =============================================================================
# Matching Tests
# =============================================================================


class TestUriMatches:
    """Test URI pattern matching."""

    # --- Exact matches ---

    def test_exact_match_same(self):
        assert uri_matches("qasp://acme/gpu/a100", "qasp://acme/gpu/a100")

    def test_exact_match_provider_only(self):
        assert uri_matches("qasp://acme", "qasp://acme")

    # --- Wildcard matches ---

    def test_wildcard_matches_single_segment(self):
        assert uri_matches("qasp://acme/gpu/*", "qasp://acme/gpu/a100")

    def test_wildcard_matches_any_value(self):
        assert uri_matches("qasp://acme/gpu/*", "qasp://acme/gpu/v100")

    def test_wildcard_does_not_match_deeper(self):
        # Wildcard covers exactly one segment
        assert not uri_matches("qasp://acme/gpu/*", "qasp://acme/gpu/a100/mem")

    def test_wildcard_does_not_match_parent(self):
        assert not uri_matches("qasp://acme/gpu/*", "qasp://acme/gpu")

    def test_root_wildcard(self):
        assert uri_matches("qasp://acme/*", "qasp://acme/gpu")

    def test_root_wildcard_does_not_match_deep(self):
        assert not uri_matches("qasp://acme/*", "qasp://acme/gpu/a100")

    # --- Prefix matches ---

    def test_prefix_matches_child(self):
        assert uri_matches("qasp://acme/gpu", "qasp://acme/gpu/a100")

    def test_prefix_matches_deep_child(self):
        assert uri_matches("qasp://acme/gpu", "qasp://acme/gpu/a100/mem")

    def test_provider_prefix_matches_any_resource(self):
        assert uri_matches("qasp://acme", "qasp://acme/gpu")

    def test_provider_prefix_matches_deep(self):
        assert uri_matches("qasp://acme", "qasp://acme/gpu/a100")

    # --- Negative matches ---

    def test_different_provider(self):
        assert not uri_matches("qasp://acme/gpu", "qasp://other/gpu")

    def test_different_resource(self):
        assert not uri_matches("qasp://acme/gpu", "qasp://acme/cpu")

    def test_child_does_not_match_parent(self):
        # A more specific URI does NOT match a more general target
        assert not uri_matches("qasp://acme/gpu/a100", "qasp://acme/gpu")

    def test_sibling_no_match(self):
        assert not uri_matches("qasp://acme/gpu/a100", "qasp://acme/gpu/v100")


# =============================================================================
# Attenuation Tests
# =============================================================================


class TestIsAttenuation:
    """Test attenuation (scope narrowing) validation."""

    # --- Valid attenuations ---

    def test_same_uri_is_valid(self):
        assert is_attenuation("qasp://acme/gpu/a100", "qasp://acme/gpu/a100")

    def test_narrowing_wildcard_to_concrete(self):
        assert is_attenuation("qasp://acme/gpu/*", "qasp://acme/gpu/a100")

    def test_narrowing_prefix_to_sub(self):
        assert is_attenuation("qasp://acme/gpu", "qasp://acme/gpu/a100")

    def test_narrowing_provider_to_resource(self):
        assert is_attenuation("qasp://acme", "qasp://acme/gpu")

    # --- Rejected escalations ---

    def test_escalation_concrete_to_wildcard(self):
        assert not is_attenuation("qasp://acme/gpu/a100", "qasp://acme/gpu/*")

    def test_escalation_child_to_parent(self):
        assert not is_attenuation("qasp://acme/gpu/a100", "qasp://acme/gpu")

    def test_escalation_different_provider(self):
        assert not is_attenuation("qasp://acme/gpu", "qasp://other/gpu")

    def test_escalation_sibling(self):
        assert not is_attenuation("qasp://acme/gpu/a100", "qasp://acme/gpu/v100")


# =============================================================================
# Intersection Tests
# =============================================================================


class TestIntersectUris:
    """Test URI intersection for token aggregation."""

    def test_identical_uris(self):
        assert intersect_uris("qasp://acme/gpu/a100", "qasp://acme/gpu/a100") == "qasp://acme/gpu/a100"

    def test_parent_child_returns_child(self):
        result = intersect_uris("qasp://acme/gpu", "qasp://acme/gpu/a100")
        assert result == "qasp://acme/gpu/a100"

    def test_child_parent_returns_child(self):
        result = intersect_uris("qasp://acme/gpu/a100", "qasp://acme/gpu")
        assert result == "qasp://acme/gpu/a100"

    def test_wildcard_and_concrete(self):
        result = intersect_uris("qasp://acme/gpu/*", "qasp://acme/gpu/a100")
        assert result == "qasp://acme/gpu/a100"

    def test_no_overlap_different_providers(self):
        assert intersect_uris("qasp://acme/gpu", "qasp://other/gpu") is None

    def test_no_overlap_sibling_resources(self):
        assert intersect_uris("qasp://acme/gpu/a100", "qasp://acme/cpu/x86") is None

    def test_provider_and_resource(self):
        result = intersect_uris("qasp://acme", "qasp://acme/gpu")
        assert result == "qasp://acme/gpu"


# =============================================================================
# Property-Based Tests
# =============================================================================


class TestProperties:
    """Property-based invariants for URI algebra."""

    URIS = [
        "qasp://acme",
        "qasp://acme/gpu",
        "qasp://acme/gpu/a100",
        "qasp://acme/gpu/*",
        "qasp://acme/cpu",
        "qasp://other/gpu",
    ]

    def test_attenuation_implies_matching(self):
        """If child is a valid attenuation of parent, then parent matches child."""
        for parent in self.URIS:
            for child in self.URIS:
                try:
                    if is_attenuation(parent, child):
                        assert uri_matches(parent, child), (
                            f"is_attenuation({parent}, {child}) == True "
                            f"but uri_matches({parent}, {child}) == False"
                        )
                except InvalidARMUriError:
                    pass

    def test_matching_reflexive(self):
        """Every URI matches itself."""
        for uri in self.URIS:
            try:
                assert uri_matches(uri, uri)
            except InvalidARMUriError:
                pass

    def test_attenuation_reflexive(self):
        """Same URI is always a valid attenuation."""
        for uri in self.URIS:
            try:
                assert is_attenuation(uri, uri)
            except InvalidARMUriError:
                pass

    def test_intersection_symmetric_provider(self):
        """Intersection within same provider should be symmetric in effect."""
        for a in self.URIS:
            for b in self.URIS:
                try:
                    r1 = intersect_uris(a, b)
                    r2 = intersect_uris(b, a)
                    # Both should be None or both non-None
                    assert (r1 is None) == (r2 is None), (
                        f"intersect_uris asymmetry: ({a}, {b}) => {r1}, ({b}, {a}) => {r2}"
                    )
                except InvalidARMUriError:
                    pass
