---
name: opsec-service-isolator
description: Decouple volatile services (lead scraping, identity sentinel, OSINT) from core applications into isolated microservices and Module Federation micro-frontends with a Master Kill Switch and separate legal-entity boundaries. Use when isolating high-risk scraping/automation features, configuring micro-frontend fallbacks, or operating an emergency OpSec kill switch.
---

# OpSec Service & Micro-Frontend Isolator (`opsec-service-isolator`)

Principal Systems Architecture toolkit and agent skill for decoupling volatile, high-liability features—such as **Lead Scraping** and **Identity Sentinel**—from a core business application (e.g., `tulio` / `peers` / `eloy`). Enforces strict containerization, zero-shared-database API boundaries, Module Federation micro-frontend fault isolation, separate legal-entity deployment topologies, and an atomic **Master Kill Switch**.

---

## When to Use This Skill

1. **Volatile Service Decoupling**: Moving scraping, OSINT, automated outreach, or identity-sentinel modules out of a core monolith so operational hiccups or third-party blocks never impact the primary business.
2. **Micro-Frontend + Microservice Pairing**: Wrapping an existing micro-frontend and its associated backend workers into a self-contained deployable unit with graceful UI degradation when disabled.
3. **Master Kill Switch Operations**: Arming, tripping, or restoring an instantaneous circuit breaker that severs API gateway routing, halts scraper containers, and swaps the micro-frontend remote entry to an inert fallback component.
4. **Master Prompt Generation**: Generating ready-to-execute Principal Systems Architect prompts for coding agents to refactor coupled codebases.

---

## Quick Start & CLI Usage

### 1. Audit Coupling & Operational Exposure (`audit`)

```bash
python3 -m opsec_service_isolator.cli audit \
  --host-app "tulio-core" \
  --services "lead-scraping,identity-sentinel" \
  --shared-db \
  --direct-imports
```

### 2. Generate Master Kill Switch & Isolation Blueprint (`blueprint`)

```bash
python3 -m opsec_service_isolator.cli blueprint \
  --host-app "tulio-core" \
  --entity-name "Sentinel Ops LLC" \
  --services "lead-scraping,identity-sentinel"
```

### 3. Operate the Master Kill Switch (`killswitch`)

```bash
# Trip the kill switch (isolates volatile services immediately)
python3 -m opsec_service_isolator.cli killswitch \
  --action trip \
  --target all \
  --reason "Upstream rate-limit / OpSec containment drill"

# Check status
python3 -m opsec_service_isolator.cli killswitch --action status

# Restore services
python3 -m opsec_service_isolator.cli killswitch --action restore --target all
```

### 4. Generate Coding-Agent Master Prompt (`master-prompt`)

```bash
python3 -m opsec_service_isolator.cli master-prompt \
  --host-app "tulio/peers/eloy" \
  --services "lead-scraping,identity-sentinel"
```

---

## Architectural Principles

1. **Zero Shared Persistence**: Volatile services own dedicated datastores and communicate with the host application strictly over versioned, token-scoped webhook/REST boundaries.
2. **Micro-Frontend Circuit Boundary**: Host shell loads remote bundles (`leadScrapingRemote`, `identitySentinelRemote`) inside an ErrorBoundary + Kill-Switch gate; when tripped, the shell renders an inert status placeholder with zero network requests to the isolated origin.
3. **Separate Entity Topology**: Infrastructure manifests tag volatile services for independent cloud accounts/projects, distinct egress IPs, and separate billing/legal entities.
4. **Deterministic Master Kill Switch**: Single state transition (`ARMED` -> `TRIPPED`) halts background queues, revokes ingress tokens, and disables micro-frontend remote manifests in `<100ms`.
