#!/usr/bin/env python3
"""Download and transform NIST ACVP test vectors for ML-KEM-768 and ML-DSA-65.

NIST publishes ACVP vectors in a split format (prompt.json + expectedResults.json)
with all parameter sets combined.  This script:

  1. Downloads the 10 source files from the ACVP-Server GitHub repo.
  2. Merges prompt + expectedResults by matching (tgId, tcId).
  3. Filters to ML-KEM-768 and ML-DSA-65 parameter sets only.
  4. Splits ML-KEM encapDecap into separate encaps.json / decaps.json.
  5. Writes 6 output files under tests/crypto/vectors/.

Usage:
    python scripts/download_acvp_vectors.py
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

BASE_URL = (
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server"
    "/master/gen-val/json-files"
)

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_DIR = REPO_ROOT / "tests" / "crypto" / "vectors"

# ── helpers ──────────────────────────────────────────────────────────────────


def fetch_json(url: str) -> dict:
    """Download a JSON file and return parsed data."""
    print(f"  GET {url.split('/json-files/')[1]}")
    req = urllib.request.Request(url, headers={"User-Agent": "QASP-ACVP/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())


def download_pair(directory: str) -> tuple[dict, dict]:
    """Download the prompt.json and expectedResults.json for a NIST directory."""
    prompt = fetch_json(f"{BASE_URL}/{directory}/prompt.json")
    expected = fetch_json(f"{BASE_URL}/{directory}/expectedResults.json")
    return prompt, expected


def merge_vectors(prompt: dict, expected: dict) -> dict:
    """Merge expectedResults fields into the prompt test cases by (tgId, tcId).

    Returns a new dict with the same top-level metadata and merged testGroups.
    """
    # Build lookup: (tgId, tcId) -> expected fields
    exp_lookup: dict[tuple[int, int], dict] = {}
    for group in expected.get("testGroups", []):
        tg_id = group["tgId"]
        for test in group.get("tests", []):
            tc_id = test["tcId"]
            # Everything except tcId is an expected-result field
            exp_fields = {k: v for k, v in test.items() if k != "tcId"}
            exp_lookup[(tg_id, tc_id)] = exp_fields

    # Merge into prompt
    merged_groups = []
    for group in prompt.get("testGroups", []):
        tg_id = group["tgId"]
        merged_tests = []
        for test in group.get("tests", []):
            tc_id = test["tcId"]
            merged = dict(test)
            merged.update(exp_lookup.get((tg_id, tc_id), {}))
            merged_tests.append(merged)
        merged_group = dict(group)
        merged_group["tests"] = merged_tests
        merged_groups.append(merged_group)

    result = dict(prompt)
    result["testGroups"] = merged_groups
    return result


def filter_groups(data: dict, parameter_set: str) -> list[dict]:
    """Return only testGroups matching the given parameterSet."""
    return [
        g for g in data.get("testGroups", [])
        if g.get("parameterSet") == parameter_set
    ]


def filter_dsa_signing_groups(groups: list[dict]) -> list[dict]:
    """Keep only external/pure groups (the only mode liboqs-python can verify)."""
    return [
        g for g in groups
        if g.get("signatureInterface") == "external"
        and g.get("preHash") == "pure"
    ]


def write_vectors(path: Path, groups: list[dict]) -> None:
    """Write filtered testGroups to a JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump({"testGroups": groups}, f, indent=2)
    count = sum(len(g.get("tests", [])) for g in groups)
    print(f"  -> {path.relative_to(REPO_ROOT)}  ({count} vectors, {len(groups)} groups)")


# ── main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    print("Downloading NIST ACVP test vectors...\n")

    # ── ML-KEM-768 ───────────────────────────────────────────────────────
    print("[ML-KEM keyGen]")
    prompt, expected = download_pair("ML-KEM-keyGen-FIPS203")
    merged = merge_vectors(prompt, expected)
    groups = filter_groups(merged, "ML-KEM-768")
    write_vectors(VECTORS_DIR / "ml_kem_768" / "keygen.json", groups)

    print("\n[ML-KEM encapDecap]")
    prompt, expected = download_pair("ML-KEM-encapDecap-FIPS203")
    merged = merge_vectors(prompt, expected)
    kem768_groups = filter_groups(merged, "ML-KEM-768")

    encaps_groups = [g for g in kem768_groups if g.get("function") == "encapsulation"]
    decaps_groups = [g for g in kem768_groups if g.get("function") == "decapsulation"]
    write_vectors(VECTORS_DIR / "ml_kem_768" / "encaps.json", encaps_groups)
    write_vectors(VECTORS_DIR / "ml_kem_768" / "decaps.json", decaps_groups)

    # ── ML-DSA-65 ────────────────────────────────────────────────────────
    print("\n[ML-DSA keyGen]")
    prompt, expected = download_pair("ML-DSA-keyGen-FIPS204")
    merged = merge_vectors(prompt, expected)
    groups = filter_groups(merged, "ML-DSA-65")
    write_vectors(VECTORS_DIR / "ml_dsa_65" / "keygen.json", groups)

    print("\n[ML-DSA sigGen]")
    prompt, expected = download_pair("ML-DSA-sigGen-FIPS204")
    merged = merge_vectors(prompt, expected)
    groups = filter_groups(merged, "ML-DSA-65")
    groups = filter_dsa_signing_groups(groups)
    write_vectors(VECTORS_DIR / "ml_dsa_65" / "siggen.json", groups)

    print("\n[ML-DSA sigVer]")
    prompt, expected = download_pair("ML-DSA-sigVer-FIPS204")
    merged = merge_vectors(prompt, expected)
    groups = filter_groups(merged, "ML-DSA-65")
    groups = filter_dsa_signing_groups(groups)
    write_vectors(VECTORS_DIR / "ml_dsa_65" / "sigver.json", groups)

    print("\nDone.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)
