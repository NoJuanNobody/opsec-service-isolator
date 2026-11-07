# opsec-service-isolator

Decouple volatile services (`lead-scraping`, `identity-sentinel`) from core applications (`tulio`/`peers`/`eloy`) into isolated microservices and Module Federation micro-frontends with an atomic **Master Kill Switch**.

## Features

- **Coupling & OpSec Liability Auditor**: Detects shared database schemas, direct code imports, shared egress IPs, and legal-entity co-mingling.
- **Container & Micro-Frontend Blueprint Generator**: Emits Docker Compose manifests, API gateway boundary specs, and Module Federation remote-entry fallback configs.
- **Master Kill Switch State Machine**: Instantaneously trips or restores `lead-scraping`, `identity-sentinel`, or `all` volatile services with audit logging and HMAC verification.
- **Principal Systems Architect Master Prompt**: Produces structured refactoring prompts for autonomous coding agents.

## Installation

```bash
pip install -e .
```

## Verification

```bash
python3 -m unittest discover -v -s tests
```
