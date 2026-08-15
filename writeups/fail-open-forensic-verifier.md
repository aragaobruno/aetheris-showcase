# A fail-open in a forensic verifier

*Engineering note — AETHERIS*

The most important component in AETHERIS is not the scanner or the ledger. It is the
standalone verifier: a small script whose entire job is to answer one question for a
hostile third party — *is this evidence bundle authentic and unaltered?* Everything else
in the system exists to produce evidence; the verifier exists to make that evidence
trustworthy to someone who does not trust me. A verifier that gives a wrong "yes" is worse
than no verifier at all, because it manufactures false confidence.

So it was uncomfortable to find that mine had a fail-open.

## The bug

The verifier checks an Ed25519 signature before it will vouch for a bundle. That check was
wrapped like this:

```python
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    public_key = serialization.load_pem_public_key(pub_pem)
    public_key.verify(bytes.fromhex(sig_hex), body_canonical)
    print("  [+] PASS: Ed25519 Digital Signature is VALID.")
except ImportError:
    print("  [~] WARNING: 'cryptography' not installed. Skipping signature validation.")
```

The intent was defensive: don't crash if an auditor is missing a dependency. The effect
was the opposite of defensive. If the `cryptography` library was not present, the `except
ImportError` branch swallowed the *entire* signature check, printed a warning, and let
execution fall through to the hash-chain checks — which then passed and produced the final
verdict: `VERIFIED`.

In other words: on any machine without one library installed, the tool built to prove
authenticity would happily approve a **forged, unsigned bundle**. The single most sensitive
check in the system was optional, and it opted out silently.

## Why this is the wrong failure mode

Security and forensic tooling has a non-negotiable rule that ordinary software does not:
**when in doubt, fail closed.** A missing dependency is not a reason to skip a security
check and continue — it is a reason to stop. The cost of a false negative here (a real
tampering that slips through) is total: it destroys the one property the tool exists to
guarantee. Convenience for the auditor is not worth that trade, ever.

A general test I now apply to any verifier: *is there any code path that reaches a "valid"
verdict without every security-critical check having actually run and passed?* If yes, the
verdict is a lie waiting to happen.

## The fix

Fail closed. A missing crypto library is a fatal condition, not a warning:

```python
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("  [-] FATAL: 'cryptography' is required to verify signatures. Aborting.")
    return False  # never reach a verdict without a completed signature check
```

The guarantee is structural, not cosmetic: there is now no control-flow path from "start"
to "VERIFIED" that bypasses the signature check. The check either runs and passes, or the
program stops. That property is the actual fix — the message text is incidental.

## How it was found

This was caught during an adversarial review of the verifier, where the guiding question
was not "does it verify a good bundle?" but "under what conditions does it approve a bad
one?" That reframing — hunting for the rejection paths, not the happy path — is what surfaced
it. Building the system was the easy half. Submitting it to a hostile read and acting on
what came back is where the engineering actually lives.
