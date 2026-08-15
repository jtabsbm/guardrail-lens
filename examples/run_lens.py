"""Example: run the lens from Python instead of the CLI."""
from aicomp_sdk.guardrails.optimal import Guardrail

from guardrail_lens import default_battery, run_battery

report = run_battery(Guardrail(), default_battery())

print(f"grade {report.grade} — {len(report.landed)}/{len(report.results)} probes landed")
for r in report.landed[:3]:
    print(f"  {r.probe.id}: {r.probe.description}")
