import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def audit_service_coupling(
    host_app: str,
    services: List[str],
    shared_db: bool = True,
    direct_imports: bool = True,
    shared_egress_ip: bool = True,
    same_legal_entity: bool = True,
) -> Dict[str, Any]:
    """
    Evaluates operational security (OpSec) and liability coupling between a core host
    application and volatile services (e.g. lead-scraping, identity-sentinel).
    """
    risk_score = 0
    findings: List[Dict[str, str]] = []

    if shared_db:
        risk_score += 35
        findings.append({
            "vector": "SHARED_DATABASE",
            "severity": "CRITICAL",
            "remediation": "Provision dedicated datastore per volatile service; exchange data strictly via signed webhooks or REST DTOs.",
        })

    if direct_imports:
        risk_score += 25
        findings.append({
            "vector": "DIRECT_MONOLITH_IMPORTS",
            "severity": "HIGH",
            "remediation": "Extract UI into Module Federation remote entries with ErrorBoundary fallbacks and move backend workers into standalone containers.",
        })

    if shared_egress_ip:
        risk_score += 20
        findings.append({
            "vector": "SHARED_EGRESS_IP_AND_DOMAIN",
            "severity": "HIGH",
            "remediation": "Route scraper and sentinel traffic through isolated egress proxies and separate subdomain/ASN.",
        })

    if same_legal_entity:
        risk_score += 20
        findings.append({
            "vector": "SHARED_ENTITY_LIABILITY",
            "severity": "MEDIUM",
            "remediation": "Deploy volatile services under a separate subsidiary/operating entity with independent cloud billing and API SLA contracts.",
        })

    tier = (
        "CRITICAL_EXPOSURE"
        if risk_score >= 70
        else "MODERATE_EXPOSURE"
        if risk_score >= 35
        else "ISOLATED_COMPLIANT"
    )

    return {
        "host_app": host_app,
        "volatile_services": services,
        "risk_score": risk_score,
        "exposure_tier": tier,
        "findings": findings,
        "recommended_controls": [
            "Embed Master Kill Switch at API Gateway and Micro-Frontend Remote Loader",
            "Containerize each volatile service with independent health/circuit state",
            "Enforce short-lived HMAC service-to-service tokens that revoke on kill-switch trip",
        ],
    }


def generate_isolation_blueprint(
    host_app: str,
    services: List[str],
    entity_name: str = "Isolated Ops LLC",
    base_port: int = 4100,
) -> Dict[str, Any]:
    """
    Generates a complete Microservice + Micro-Frontend (Module Federation)
    decoupling blueprint with Docker Compose service definitions and kill-switch gates.
    """
    service_specs: List[Dict[str, Any]] = []
    remotes_map: Dict[str, str] = {}

    for idx, svc in enumerate(services):
        slug = svc.strip().lower().replace("_", "-")
        camel = "".join(word.capitalize() for word in slug.split("-"))
        remote_name = f"{camel[0].lower() + camel[1:]}Remote"
        api_port = base_port + (idx * 10) + 1
        mfe_port = base_port + (idx * 10) + 2

        remotes_map[remote_name] = f"{remote_name}@https://{slug}.isolated-ops.internal:{mfe_port}/remoteEntry.js"

        service_specs.append({
            "service_id": slug,
            "operating_entity": entity_name,
            "container_name": f"isolated-{slug}-svc",
            "api_port": api_port,
            "mfe_port": mfe_port,
            "mfe_remote_name": remote_name,
            "database_uri_env": f"{slug.upper().replace('-', '_')}_ISOLATED_DB_URL",
            "killswitch_env": f"KILLSWITCH_{slug.upper().replace('-', '_')}_ENABLED",
            "api_boundary": {
                "ingress_prefix": f"/api/v1/isolated/{slug}",
                "auth_scheme": "HMAC-SHA256 + Scoped Bearer",
                "circuit_breaker_header": "X-OpSec-KillSwitch-State",
            },
            "mfe_fallback_component": f"<{camel}OfflineFallback reason='Service isolated by Master Kill Switch' />",
        })

    return {
        "host_app": host_app,
        "operating_entity": entity_name,
        "isolation_mode": "MICROSERVICE_PLUS_MFE_REMOTE",
        "master_kill_switch_endpoint": "/api/v1/opsec/killswitch",
        "module_federation_remotes": remotes_map,
        "services": service_specs,
    }


class KillSwitchController:
    """
    Deterministic Master Kill Switch controller for volatile microservices and micro-frontends.
    Supports global ('all') or per-service ('lead-scraping', 'identity-sentinel') tripping,
    HMAC token signing, and audit trail persistence.
    """

    def __init__(
        self,
        services: Optional[List[str]] = None,
        state_path: Optional[str] = None,
        secret_key: str = "opsec-default-hmac-key",
    ):
        self.services = services or ["lead-scraping", "identity-sentinel"]
        self.state_path = state_path
        self.secret_key = secret_key
        self._state: Dict[str, Any] = {
            "global_killswitch_tripped": False,
            "services": {
                svc: {
                    "state": "ARMED_ACTIVE",
                    "api_gateway_enabled": True,
                    "mfe_remote_enabled": True,
                    "containers_running": True,
                    "last_reason": "Initial armed state",
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
                for svc in self.services
            },
            "audit_log": [],
        }
        if self.state_path and os.path.exists(self.state_path):
            try:
                with open(self.state_path, "r") as f:
                    self._state = json.load(f)
            except Exception:
                pass

    def _save(self) -> None:
        if self.state_path:
            with open(self.state_path, "w") as f:
                json.dump(self._state, f, indent=2)

    def sign_action(self, action: str, target: str, reason: str) -> str:
        payload = f"{action}:{target}:{reason}"
        return hmac.new(
            self.secret_key.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def trip(self, target: str = "all", reason: str = "Manual OpSec isolation trigger") -> Dict[str, Any]:
        """Trips the kill switch for 'all' or a specific volatile service."""
        targets = list(self._state["services"].keys()) if target == "all" else [target]
        now = datetime.now(timezone.utc).isoformat()
        sig = self.sign_action("TRIP", target, reason)

        for svc in targets:
            if svc not in self._state["services"]:
                self._state["services"][svc] = {}
            self._state["services"][svc].update({
                "state": "KILLED_ISOLATED",
                "api_gateway_enabled": False,
                "mfe_remote_enabled": False,
                "containers_running": False,
                "last_reason": reason,
                "updated_at": now,
            })

        self._state["global_killswitch_tripped"] = all(
            s["state"] == "KILLED_ISOLATED" for s in self._state["services"].values()
        )
        self._state["audit_log"].append({
            "timestamp": now,
            "action": "TRIP",
            "target": target,
            "reason": reason,
            "hmac_signature": sig,
        })
        self._save()
        return self.status()

    def restore(self, target: str = "all", reason: str = "Authorized restoration") -> Dict[str, Any]:
        """Restores 'all' or a specific volatile service back to ARMED_ACTIVE."""
        targets = list(self._state["services"].keys()) if target == "all" else [target]
        now = datetime.now(timezone.utc).isoformat()
        sig = self.sign_action("RESTORE", target, reason)

        for svc in targets:
            if svc in self._state["services"]:
                self._state["services"][svc].update({
                    "state": "ARMED_ACTIVE",
                    "api_gateway_enabled": True,
                    "mfe_remote_enabled": True,
                    "containers_running": True,
                    "last_reason": reason,
                    "updated_at": now,
                })

        self._state["global_killswitch_tripped"] = all(
            s["state"] == "KILLED_ISOLATED" for s in self._state["services"].values()
        )
        self._state["audit_log"].append({
            "timestamp": now,
            "action": "RESTORE",
            "target": target,
            "reason": reason,
            "hmac_signature": sig,
        })
        self._save()
        return self.status()

    def status(self) -> Dict[str, Any]:
        return {
            "global_killswitch_tripped": self._state["global_killswitch_tripped"],
            "services": self._state["services"],
            "audit_events_count": len(self._state["audit_log"]),
            "latest_event": self._state["audit_log"][-1] if self._state["audit_log"] else None,
        }


def build_architect_master_prompt(
    host_app: str = "tulio/peers/eloy",
    services: Optional[List[str]] = None,
    separate_entity: bool = True,
) -> str:
    """
    Synthesizes the Principal Systems Architect Master Prompt for decoupling
    lead scraping and identity sentinel services with a Master Kill Switch.
    """
    svc_list = services or ["lead-scraping", "identity-sentinel"]
    svc_str = ", ".join(f"`{s}`" for s in svc_list)
    entity_clause = (
        "5. **Separate Legal Entity & Infrastructure Boundary**: Parameterize all deployment manifests "
        "(Docker Compose, Railway/Terraform, egress proxies, and signing keys) so these services can be "
        "hosted and billed under an independent operating company with zero shared cloud IAM roles.\n"
        if separate_entity
        else ""
    )

    return (
        f"Act as a Principal Systems Architect and OpSec Lead. Refactor and decouple our volatile services "
        f"({svc_str}) from the primary `{host_app}` application so they operate as strictly isolated "
        f"microservices and micro-frontends with an instantaneous **Master Kill Switch**.\n\n"
        f"### Architectural Requirements\n"
        f"1. **Full Backend Microservice Extraction**: Package each volatile service ({svc_str}) and its background "
        f"workers/queues into standalone Dockerized microservices with dedicated databases. Remove all direct ORM/schema "
        f"sharing with `{host_app}`.\n"
        f"2. **Micro-Frontend (Module Federation) Isolation**: Expose each service's UI as an independent micro-frontend "
        f"remote bundle. Wrap host-side remote mounts in a circuit-breaker boundary that renders a clean, zero-request "
        f"fallback component whenever the service is disabled or unreachable.\n"
        f"3. **Strict API Gateway Contract**: Route all communication between `{host_app}` and {svc_str} exclusively "
        f"through versioned REST/webhook contracts authenticated via revocable HMAC-SHA256 service tokens.\n"
        f"4. **Embedded Master Kill Switch**: Implement a global and per-service Kill Switch (`ARMED_ACTIVE` vs `KILLED_ISOLATED`) "
        f"that atomically:\n"
        f"   - Severs API gateway routes and returns `503 Service Isolated` with zero upstream leakage,\n"
        f"   - Revokes active service-to-service tokens and halts background scraping/sentinel jobs, and\n"
        f"   - Disables the micro-frontend remote manifest in `{host_app}` so the UI cleanly disappears or shows an inert stub.\n"
        f"{entity_clause}"
        f"### Deliverables\n"
        f"- Decoupled directory structure and `docker-compose.isolated.yml` for {svc_str}\n"
        f"- Module Federation host loader with Kill-Switch circuit-breaker gate\n"
        f"- Master Kill Switch CLI & webhook controller with HMAC signature verification and pytest coverage"
    )
