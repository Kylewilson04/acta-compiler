# `acta-sdk` (Python)

Official Python client, offline RFC 8785 JCS ([`serde_jcs`](https://docs.rs/serde_jcs/latest/src/serde_jcs/lib.rs.html)) + BLAKE3 + strict Ed25519 ([`ed25519-dalek`](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.VerifyingKey.html)) verifier, and [`google-genai`](https://github.com/googleapis/python-genai) pre-prompt circuit-breaker for [Acta Compiler](https://acta-server-998422936041.us-west1.run.app/).

## Install

```bash
pip install -e .
# Optional extras:
pip install -e ".[all]"
```

## Run Unit & Production Vector Parity Tests

```bash
python3 -m unittest discover -s tests -v
```
