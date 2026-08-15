"""guardrail-lens CLI: target spec loader + terminal reporting."""
from __future__ import annotations

import argparse
import importlib
import json
import re
import sys
from pathlib import Path

from .battery import default_battery
from .runner import LensReport, report_to_json, run_battery

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"

FAMILY_ICONS = {
    "exfiltration": "⇗",
    "confused_deputy": "✉",
    "taint_window": "⏱",
    "injection": "☎",
    "control": "✓",
}


def load_target(spec: str):
    """Load a guardrail class from 'module.path:ClassName' or a .py file path.

    Supports:
      aicomp_sdk.guardrails.optimal:Guardrail
      ./my_guardrail.py:MyGuardrail
      my_package.my_module:MyGuardrail
    """
    if ":" not in spec:
        raise SystemExit(
            f"error: target must be 'module.path:ClassName' or 'file.py:ClassName', got {spec!r}"
        )
    module_path, cls_name = spec.split(":", 1)
    if module_path.endswith(".py") or "/" in module_path:
        p = Path(module_path).expanduser().resolve()
        if not p.exists():
            raise SystemExit(f"error: no such file: {p}")
        sys.path.insert(0, str(p.parent))
        module = importlib.import_module(p.stem)
    else:
        module = importlib.import_module(module_path)
    cls = getattr(module, cls_name, None)
    if cls is None:
        raise SystemExit(f"error: {module_path} has no attribute {cls_name!r}")
    return cls()


def print_report(report: LensReport, verbose: bool = False) -> None:
    s = report.to_dict()["summary"]
    w = 78

    print(f"{DIM}{'─' * w}{RESET}")
    print(f"{BOLD} GUARDRAIL LENS {RESET} {DIM}· red-team report{RESET}")
    print(f"{DIM}{'─' * w}{RESET}")
    print(f"  target     {CYAN}{report.guardrail_name}{RESET}")
    grade = report.grade
    gcolor = GREEN if grade in ("A", "B") else YELLOW if grade == "C" else RED
    print(f"  grade      {BOLD}{gcolor}{grade}{RESET}   {DIM}(A = battery fully blocked){RESET}")
    n_control = len([r for r in report.results if r.probe.family == "control"])
    n_attack = len(report.results) - n_control
    n_attack_landed = len([r for r in report.landed if r.probe.family != "control"])
    print(f"  probes     {s['probes']}   {DIM}({n_attack} attacks, {n_control} controls; "
          f"{s['controls_passed']} controls passed, {s['controls_failed']} failed){RESET}")
    print(f"  landed     {RED}{BOLD}{n_attack_landed}{RESET} / {n_attack} attacks")
    print(f"  risk       {RED if s['total_risk'] else GREEN}{BOLD}{s['total_risk']}{RESET} {DIM}Σ severity of landed probes{RESET}")
    print(f"{DIM}{'─' * w}{RESET}")

    print()
    for fam in ["exfiltration", "confused_deputy", "taint_window", "injection", "control"]:
        fam_results = [r for r in report.results if r.probe.family == fam]
        if not fam_results:
            continue
        n_land = len([r for r in fam_results if r.landed])
        icon = FAMILY_ICONS.get(fam, "•")
        status = f"{RED}{n_land}/{len(fam_results)} LAND{RESET}" if n_land else f"{GREEN}all blocked{RESET}"
        print(f"  {icon} {BOLD}{fam.replace('_', ' '):18s}{RESET} {status}")
        if verbose:
            for r in fam_results:
                mark = f"{RED}✗{RESET}" if r.landed else f"{GREEN}✓{RESET}"
                print(f"      {mark} {DIM}{r.probe.id}{RESET}  {r.probe.description[:64]}")

    landed = report.landed
    if landed:
        print(f"\n{BOLD}{RED}FINDINGS — patterns that got through:{RESET}")
        seen: set[str] = set()
        for r in landed:
            if r.probe.family == "control":
                continue
            key = r.probe.advice
            if key in seen:
                continue
            seen.add(key)
            print(f"\n  {RED}⇗ {r.probe.id}{RESET}  {DIM}severity {r.probe.severity}{RESET}")
            print(f"    {r.probe.description}")
            bad = [o for o in r.outcomes if o.landed]
            o = bad[0]
            print(f"    {DIM}call: {o.call.tool}({', '.join(f'{k}={v!r}' for k, v in list(o.call.args.items())[:2])}){RESET}")
            print(f"    {DIM}guardrail said: {o.action} — {o.reason[:70]}{RESET}")
            if r.probe.advice:
                print(f"    {YELLOW}fix: {r.probe.advice}{RESET}")
    if report.controls_failed:
        print(f"\n{BOLD}{RED}CONTROLS FAILED — even baseline attacks pass:{RESET}")
        for r in report.controls_failed:
            print(f"  {RED}✗ {r.probe.id}{RESET}  {r.probe.description}")

    print(f"\n{DIM}{'─' * w}{RESET}")
    ok = not report.landed
    if ok:
        print(f"{GREEN}{BOLD}✓ Battery fully blocked.{RESET} {DIM}No standard attack pattern landed.{RESET}\n")
    else:
        n = len(report.landed)
        print(f"{RED}{BOLD}✗ {n} probe(s) landed.{RESET} {DIM}Harden along the 'fix:' lines above and re-run.{RESET}\n")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="guardrail-lens",
        description="Run a battery of standard attack patterns against an aicomp_sdk-style guardrail.",
    )
    p.add_argument("target", help="guardrail spec: 'module:Class' or 'path/to/file.py:Class'")
    p.add_argument("--json", action="store_true", help="emit the full report as JSON")
    p.add_argument("--verbose", "-v", action="store_true", help="list every probe, not just findings")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    guardrail = load_target(args.target)
    report = run_battery(guardrail, default_battery())
    if args.json:
        print(report_to_json(report))
        rc = 1 if report.landed else 0
        return rc
    print_report(report, verbose=args.verbose)
    return 1 if report.landed else 0


if __name__ == "__main__":
    sys.exit(main())
