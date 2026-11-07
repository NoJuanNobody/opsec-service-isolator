import os
import tempfile
import unittest
from opsec_service_isolator.core import (
    audit_service_coupling,
    generate_isolation_blueprint,
    KillSwitchController,
    build_architect_master_prompt,
)


class TestOpSecServiceIsolator(unittest.TestCase):
    def test_audit_service_coupling_critical(self):
        res = audit_service_coupling(
            host_app="tulio-core",
            services=["lead-scraping", "identity-sentinel"],
            shared_db=True,
            direct_imports=True,
            shared_egress_ip=True,
            same_legal_entity=True,
        )
        self.assertEqual(res["risk_score"], 100)
        self.assertEqual(res["exposure_tier"], "CRITICAL_EXPOSURE")
        self.assertEqual(len(res["findings"]), 4)

    def test_audit_service_coupling_isolated(self):
        res = audit_service_coupling(
            host_app="tulio-core",
            services=["lead-scraping", "identity-sentinel"],
            shared_db=False,
            direct_imports=False,
            shared_egress_ip=False,
            same_legal_entity=False,
        )
        self.assertEqual(res["risk_score"], 0)
        self.assertEqual(res["exposure_tier"], "ISOLATED_COMPLIANT")

    def test_generate_isolation_blueprint(self):
        bp = generate_isolation_blueprint(
            host_app="tulio-core",
            services=["lead-scraping", "identity-sentinel"],
            entity_name="Sentinel Ops LLC",
        )
        self.assertEqual(bp["operating_entity"], "Sentinel Ops LLC")
        self.assertIn("leadScrapingRemote", bp["module_federation_remotes"])
        self.assertIn("identitySentinelRemote", bp["module_federation_remotes"])
        self.assertEqual(len(bp["services"]), 2)
        self.assertEqual(bp["services"][0]["container_name"], "isolated-lead-scraping-svc")

    def test_killswitch_trip_and_restore(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            state_path = tmp.name
        try:
            os.remove(state_path)
            ctrl = KillSwitchController(
                services=["lead-scraping", "identity-sentinel"],
                state_path=state_path,
            )
            initial = ctrl.status()
            self.assertFalse(initial["global_killswitch_tripped"])

            # Trip single service
            partial = ctrl.trip(target="lead-scraping", reason="Rate limit spike")
            self.assertFalse(partial["global_killswitch_tripped"])
            self.assertEqual(partial["services"]["lead-scraping"]["state"], "KILLED_ISOLATED")
            self.assertFalse(partial["services"]["lead-scraping"]["mfe_remote_enabled"])
            self.assertEqual(partial["services"]["identity-sentinel"]["state"], "ARMED_ACTIVE")

            # Trip all
            tripped = ctrl.trip(target="all", reason="Full OpSec isolation")
            self.assertTrue(tripped["global_killswitch_tripped"])
            self.assertEqual(tripped["services"]["identity-sentinel"]["state"], "KILLED_ISOLATED")

            # Restore all
            restored = ctrl.restore(target="all", reason="All clear")
            self.assertFalse(restored["global_killswitch_tripped"])
            self.assertTrue(restored["services"]["lead-scraping"]["api_gateway_enabled"])
            self.assertEqual(restored["audit_events_count"], 3)
        finally:
            if os.path.exists(state_path):
                os.remove(state_path)

    def test_build_architect_master_prompt(self):
        prompt = build_architect_master_prompt(
            host_app="tulio/peers/eloy",
            services=["lead-scraping", "identity-sentinel"],
            separate_entity=True,
        )
        self.assertIn("Master Kill Switch", prompt)
        self.assertIn("lead-scraping", prompt)
        self.assertIn("identity-sentinel", prompt)
        self.assertIn("Module Federation", prompt)


if __name__ == "__main__":
    unittest.main()
