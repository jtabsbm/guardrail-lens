# Guardrail Lens evaluation

## Baseline

The package includes three deterministic cases in `evaluation-cases.json`:

1. Critical cross-tenant exposure.
2. Benign blocked control path.
3. Unblocked authorization gap with tool and secret signals.

Run:

```bash
node scripts/evaluate.mjs
```

All three cases must pass before packaging.

Standalone smoke test:

```bash
node scripts/analyze-export.mjs sample-security-events.json
```

## OpenSearch-specific acceptance checks

- The skill works with an exported event set without a network connection.
- A read-only index adapter preserves event IDs and timestamps.
- Findings link back to evidence, not only a score.
- OpenSearch export adapter preserves hit IDs in each finding's `event_ids` list.
- Common boolean encodings such as `true`, `"true"`, and `"denied"` normalize to blocked.
- Sensitive values are redacted.
- No write action or live probe is performed.
- The README explains installation, input mapping, output, and limitations.
- The demo fits in five minutes.
