"""guardrail-lens test suite."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fixtures import (  # noqa: E402
    PermissiveGuardrail,
    KeywordBlockGuardrail,
    FixedTaintWindowGuardrail,
)

from guardrail_lens.battery import default_battery  # noqa: E402
from guardrail_lens.runner import run_battery, report_to_json  # noqa: E402
from guardrail_lens.cli import main as cli_main  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


class TestBattery(unittest.TestCase):
    def test_battery_size_and_families(self):
        b = default_battery()
        self.assertGreaterEqual(len(b), 30)
        fams = set(b.families())
        self.assertIn("exfiltration", fams)
        self.assertIn("confused_deputy", fams)
        self.assertIn("taint_window", fams)
        self.assertIn("injection", fams)
        self.assertIn("control", fams)

    def test_probe_ids_unique(self):
        b = default_battery()
        ids = [p.id for p in b.probes]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_probe_has_expected_and_calls(self):
        for p in default_battery().probes:
            self.assertIn(p.expected, ("deny", "confirm"))
            self.assertGreater(len(p.calls), 0)


class TestPermissiveGuardrail(unittest.TestCase):
    """Everything should land, including controls — total failure visible."""

    def test_all_land(self):
        report = run_battery(PermissiveGuardrail())
        self.assertEqual(len(report.landed), len(report.results))
        self.assertEqual(report.grade, "F")
        self.assertGreater(report.total_risk, 0)
        self.assertEqual(len(report.controls_failed), len(report.controls_passed) + len(report.controls_failed))


class TestKeywordBlockGuardrail(unittest.TestCase):
    def test_data_field_exfil_lands(self):
        report = run_battery(KeywordBlockGuardrail())
        exfil = [r for r in report.landed if r.probe.family == "exfiltration"]
        self.assertGreater(len(exfil), 0, "data-field exfiltration must land on first-key-only guardrails")

    def test_url_secret_blocked(self):
        report = run_battery(KeywordBlockGuardrail())
        control = [r for r in report.results if r.probe.id == "exfil.url-control"]
        self.assertEqual(len(control), 1)
        self.assertFalse(control[0].landed)


class TestFixedTaintWindowGuardrail(unittest.TestCase):
    """Mirrors the public OptimalGuardrail: keyword block + decaying taint window."""

    def test_taint_padding_lands(self):
        report = run_battery(FixedTaintWindowGuardrail())
        taint = [r for r in report.landed if r.probe.family == "taint_window"]
        self.assertGreater(len(taint), 0, "taint-window padding must land on call-time-window guardrails")

    def test_immediate_taint_blocked(self):
        report = run_battery(FixedTaintWindowGuardrail())
        r = [x for x in report.results if x.probe.id == "taint.immediate-deny"][0]
        self.assertFalse(r.landed)

    def test_deputy_lands(self):
        report = run_battery(FixedTaintWindowGuardrail())
        deputy = [r for r in report.landed if r.probe.family == "confused_deputy"]
        self.assertGreater(len(deputy), 0, "clean-worded deputy emails land on content filters")

    def test_injection_probe_context_carried(self):
        report = run_battery(FixedTaintWindowGuardrail())
        inj = [r for r in report.results if r.probe.family == "injection"]
        self.assertGreater(len(inj), 0)
        # the file-source injection has no web/email taint so it should land
        file_src = [r for r in inj if "instructions-file" in r.probe.id]
        self.assertEqual(len(file_src), 1)
        self.assertTrue(file_src[0].landed)

    def test_all_controls_pass(self):
        report = run_battery(FixedTaintWindowGuardrail())
        self.assertEqual(len(report.controls_failed), 0, "baseline controls should all be blocked")


class TestPublicOptimalGuardrail(unittest.TestCase):
    """End-to-end against the real SDK guardrail when installed."""

    def test_against_public_optimal(self):
        try:
            from aicomp_sdk.guardrails.optimal import Guardrail
        except ImportError:
            self.skipTest("aicomp_sdk not installed")
        report = run_battery(Guardrail())
        # Documented gaps: data-field exfil + deputy + padded taint must land.
        fams = report.landed_by_family
        self.assertIn("exfiltration", fams)
        self.assertIn("confused_deputy", fams)
        self.assertIn("taint_window", fams)
        # and the baseline controls should all hold
        self.assertEqual(len(report.controls_failed), 0)


class TestReportShape(unittest.TestCase):
    def test_json_serializable(self):
        report = run_battery(KeywordBlockGuardrail())
        data = json.loads(report_to_json(report))
        self.assertIn("summary", data)
        self.assertIn("results", data)
        self.assertEqual(data["summary"]["probes"], len(report.results))
        for r in data["results"]:
            self.assertIn("verdict", r)
            self.assertIn("calls", r)

    def test_verdict_values(self):
        report = run_battery(KeywordBlockGuardrail())
        for r in report.results:
            self.assertIn(r.verdict, ("LANDS", "blocked", "error", "skip"))


class TestCLI(unittest.TestCase):
    def test_cli_exit_code_lands(self):
        rc = cli_main([f"{REPO}/tests/fixtures.py:KeywordBlockGuardrail"])
        self.assertEqual(rc, 1)  # attacks landed

    def test_cli_exit_code_clean(self):
        # a guardrail that denies everything: use a shim class
        shim = REPO / "tests" / "_deny_all.py"
        shim.write_text(
            "from fixtures import KeywordBlockGuardrail\n\n"
            "class DenyAll(KeywordBlockGuardrail):\n"
            "    def decide(self, tool_name, tool_args, context):\n"
            "        from fixtures import Decision\n"
            "        return Decision.deny('deny all')\n"
        )
        try:
            rc = cli_main([f"{shim}:DenyAll"])
            self.assertEqual(rc, 0)
        finally:
            shim.unlink()

    def test_cli_json_output(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["--json", f"{REPO}/tests/fixtures.py:KeywordBlockGuardrail"])
        self.assertEqual(rc, 1)
        data = json.loads(buf.getvalue())
        self.assertGreater(data["summary"]["landed"], 0)

    def test_cli_bad_target(self):
        with self.assertRaises(SystemExit):
            cli_main(["no-colon-spec"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
