# Guardrail Lens

Guardrail Lens is a read-only OpenSearch Agent Skill for security and AI-agent observability.
It converts exported events into an evidence-linked triage report instead of a vague risk score.

## What it catches

- unblocked high or critical activity
- authorization and tenant-isolation gaps
- secret or sensitive-data exposure signals
- agent-tool and SSRF surface signals
- low prevention rate
- repeated activity concentrated on one asset

## Run locally

From this directory:

```bash
node scripts/analyze-export.mjs sample-security-events.json
node scripts/evaluate.mjs
node scripts/analyze-opensearch-export.mjs sample-opensearch-export.json
```

The package includes its own dependency-free analyzer in `scripts/security-signal-analyzer.mjs`, so
the folder can be archived or copied without the parent project.

## OpenSearch adaptation

The skill accepts an exported event set first so the demo is deterministic. A live adapter can map
an authorized read-only OpenSearch index to the same event fields and add links to event IDs. Keep
write actions out of the initial version.

See `opensearch-readonly-adapter.md` for a field mapping and a read-only query body.
The offline adapter accepts an OpenSearch response export, preserves hit IDs as evidence references,
and does not contact a live cluster.
Reports also include a minimal `evidence_refs` index with IDs, timestamps, categories, actions, and
source URLs when available; sensitive evidence text is not copied into the report.

## Hackathon fit

The August 2026 OpenSearch Agent Skills Hackathon is for legal U.S. residents aged 18+, solo or in
teams of up to two. Entries are due August 17, 2026 at 11:59 p.m. PST. The package is designed to
address security analytics and observability while staying vendor-neutral and free of proprietary
dependencies.

## Safety

This is defensive triage, not a scanner, penetration test, exploit kit, or authorization-bypass
tool. Use only data and indexes the operator is authorized to inspect. Redact secrets and personal
data before sharing output.
