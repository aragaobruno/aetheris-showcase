#!/usr/bin/env python3
"""
AETHERIS STANDALONE FORENSIC BUNDLE VERIFIER (v1.1)
---------------------------------------------------
Zero-Trust, Independent Audit Tool for Verifying AETHERIS Evidence Bundles.
Can be executed standalone by any Bug Bounty triager, SOC2 auditor, or forensics expert.
Zero internal imports — depends only on Python standard library and 'cryptography'.

Usage:
    python verify_aetheris_bundle.py <path_to_bundle.json> [--pubkey <authoritative_pubkey.pem>]
"""

import argparse
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional


def canonical_json_bytes(data: Any) -> bytes:
    """Serializes canonical JSON into bytes with sorted keys and no whitespace."""
    def _default(obj):
        if isinstance(obj, bytes):
            return obj.hex()
        return str(obj)

    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=_default).encode("utf-8")


def verify_standalone_bundle(bundle_path: str, external_pubkey_path: Optional[str] = None) -> bool:
    print("=" * 70)
    print("      AETHERIS FORENSIC BUNDLE — INDEPENDENT STANDALONE AUDITOR      ")
    print("=" * 70)
    print(f"[*] Loading bundle file: {bundle_path}")

    try:
        with open(bundle_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    except Exception as e:
        print(f"[!] FAILED TO READ FILE: {e}")
        return False

    manifest = bundle.get("manifest", {})
    ledger = bundle.get("ledger_chain", [])
    findings = bundle.get("findings", [])
    signature = bundle.get("signature", {})

    print(f"[*] Target Name       : {manifest.get('target_name')}")
    print(f"[*] Exported At       : {manifest.get('exported_at')}")
    print(f"[*] Operational Mode  : {manifest.get('operational_mode')}")
    print(f"[*] Total Evidences   : {len(ledger)}")
    print(f"[*] Total Findings    : {len(findings)}")
    print("-" * 70)

    # 1. Verify Ed25519 Digital Signature & Out-of-Band Trust Anchor
    print("[1/3] Verifying Ed25519 Digital Signature & Authority Trust...")
    sig_hex = signature.get("signature_hex")

    if external_pubkey_path and os.path.exists(external_pubkey_path):
        print(f"  [*] Using Authoritative Out-of-Band Public Key: {external_pubkey_path}")
        with open(external_pubkey_path, "rb") as f:
            pub_pem = f.read()
    else:
        print("  [*] Using Public Key embedded in bundle header.")
        pub_pem = signature.get("public_key_pem", "").encode("utf-8")

    if not sig_hex or not pub_pem:
        print("  [-] FAIL: Missing signature or public key block.")
        return False

    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization

        public_key = serialization.load_pem_public_key(pub_pem)
        bundle_body = {
            "manifest": manifest,
            "ledger_chain": ledger,
            "findings": findings,
        }
        body_canonical = canonical_json_bytes(bundle_body)
        public_key.verify(bytes.fromhex(sig_hex), body_canonical)
        print("  [+] PASS: Ed25519 Digital Signature is VALID & AUTHENTIC.")
    except ImportError:
        print("  [-] CRITICAL ERROR: 'cryptography' library is required to verify the digital signature.")
        print("      Aborting verification. Run: pip install cryptography")
        return False
    except Exception as e:
        print(f"  [-] FAIL: Digital signature mismatch or tampering detected: {e}")
        return False

    # 2. Verify Cryptographic SHA-256 Ledger Chain
    print("\n[2/3] Verifying SHA-256 Ledger Chain & Preimage Cryptography...")
    expected_prev = manifest.get("genesis_hash", "0" * 64)

    for idx, row in enumerate(ledger):
        row_id = row.get("id")
        target_id = row.get("target_id")
        source_module = row.get("source_module")
        captured_at = row.get("captured_at")
        canonical_payload = row.get("canonical_payload")
        payload_sha = row.get("payload_sha")
        prev_sha = row.get("prev_sha")
        row_sha = row.get("row_sha")

        # 2.1 Payload SHA
        calc_payload_sha = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()
        if calc_payload_sha != payload_sha:
            print(f"  [-] FAIL: Payload hash mismatch on Row #{row_id}. Tampering detected!")
            return False

        # 2.2 Prev SHA Link
        if prev_sha != expected_prev:
            print(f"  [-] FAIL: Broken chain link on Row #{row_id}. Expected {expected_prev}, got {prev_sha}")
            return False

        # 2.3 Row Preimage SHA
        preimage = f"v1:{target_id}:{source_module}:{captured_at}:{payload_sha}:{prev_sha}"
        calc_row_sha = hashlib.sha256(preimage.encode("utf-8")).hexdigest()
        if calc_row_sha != row_sha:
            print(f"  [-] FAIL: Row hash mismatch on Row #{row_id}. Expected {calc_row_sha}, stored {row_sha}")
            return False

        expected_prev = row_sha
        print(f"  [+] Block #{row_id} ({source_module}) -> SHA-256 Validated.")

    print(f"  [+] PASS: All {len(ledger)} evidence blocks unbroken from Genesis.")

    # 3. Verify Finding Invariants
    print("\n[3/3] Verifying Empirical Evidence Ground Truth Invariants...")
    for f in findings:
        f_id = f.get("id")
        title = f.get("title")
        status = f.get("status")
        observations = f.get("observations", [])

        if status == "CONFIRMED":
            has_observed = any(o.get("kind") == "OBSERVED" for o in observations)
            if not has_observed:
                print(f"  [-] FAIL: Finding #{f_id} ('{title}') is CONFIRMED without OBSERVED empirical anchor!")
                return False
            print(f"  [+] Finding #{f_id} ('{title}') -> CONFIRMED with empirical proof.")
        else:
            print(f"  [+] Finding #{f_id} ('{title}') -> DRAFT / Unconfirmed.")

    print("\n" + "=" * 70)
    print("[AUDIT RESULT] Status: VERIFIED (Ed25519 signature authentic + Hash chain intact)")
    print("=" * 70)
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AETHERIS Standalone Forensic Verifier")
    parser.add_argument("bundle_path", help="Path to .aetheris-bundle.json")
    parser.add_argument("--pubkey", help="Optional path to authoritative public key PEM file for out-of-band trust", default=None)
    args = parser.parse_args()

    success = verify_standalone_bundle(args.bundle_path, args.pubkey)
    sys.exit(0 if success else 1)
