import argparse
import json
from .core import (
    audit_service_coupling,
    generate_isolation_blueprint,
    KillSwitchController,
    build_architect_master_prompt,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OpSec Service & Micro-Frontend Isolator CLI"
    )
    subparsers = parser.add_subparsers(dest="subcommand")

    # audit
    audit_p = subparsers.add_parser("audit", help="Audit OpSec coupling & liability risks")
    audit_p.add_argument("--host-app", default="tulio-core", help="Core application name")
    audit_p.add_argument(
        "--services",
        default="lead-scraping,identity-sentinel",
        help="Comma-separated volatile services",
    )
    audit_p.add_argument("--shared-db", action="store_true", default=True)
    audit_p.add_argument("--direct-imports", action="store_true", default=True)

    # blueprint
    bp_p = subparsers.add_parser("blueprint", help="Generate isolation & Module Federation blueprint")
    bp_p.add_argument("--host-app", default="tulio-core", help="Core application name")
    bp_p.add_argument("--entity-name", default="Sentinel Ops LLC", help="Separate legal entity name")
    bp_p.add_argument(
        "--services",
        default="lead-scraping,identity-sentinel",
        help="Comma-separated volatile services",
    )

    # killswitch
    ks_p = subparsers.add_parser("killswitch", help="Operate Master Kill Switch")
    ks_p.add_argument(
        "--action",
        choices=["trip", "restore", "status"],
        default="status",
        help="Kill switch action",
    )
    ks_p.add_argument(
        "--target",
        default="all",
        help="Target service ('all', 'lead-scraping', 'identity-sentinel')",
    )
    ks_p.add_argument(
        "--reason",
        default="Manual OpSec isolation trigger",
        help="Audit reason for state transition",
    )
    ks_p.add_argument(
        "--state-file",
        default=".killswitch_state.json",
        help="Path to persist kill-switch state",
    )

    # master-prompt
    mp_p = subparsers.add_parser("master-prompt", help="Generate Principal Systems Architect Master Prompt")
    mp_p.add_argument("--host-app", default="tulio/peers/eloy", help="Core application name")
    mp_p.add_argument(
        "--services",
        default="lead-scraping,identity-sentinel",
        help="Comma-separated volatile services",
    )

    args = parser.parse_args()

    if args.subcommand == "audit":
        svcs = [s.strip() for s in args.services.split(",") if s.strip()]
        res = audit_service_coupling(
            host_app=args.host_app,
            services=svcs,
            shared_db=args.shared_db,
            direct_imports=args.direct_imports,
        )
        print(json.dumps(res, indent=2))

    elif args.subcommand == "blueprint":
        svcs = [s.strip() for s in args.services.split(",") if s.strip()]
        res = generate_isolation_blueprint(
            host_app=args.host_app,
            services=svcs,
            entity_name=args.entity_name,
        )
        print(json.dumps(res, indent=2))

    elif args.subcommand == "killswitch":
        ctrl = KillSwitchController(state_path=args.state_file)
        if args.action == "trip":
            res = ctrl.trip(target=args.target, reason=args.reason)
        elif args.action == "restore":
            res = ctrl.restore(target=args.target, reason=args.reason)
        else:
            res = ctrl.status()
        print(json.dumps(res, indent=2))

    elif args.subcommand == "master-prompt":
        svcs = [s.strip() for s in args.services.split(",") if s.strip()]
        print(build_architect_master_prompt(host_app=args.host_app, services=svcs))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
