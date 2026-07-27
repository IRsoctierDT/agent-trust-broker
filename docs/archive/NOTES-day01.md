# NOTES — Day 01 · Spine & Substrate (Phase 1)

**Date:** 2026-07-08
**Charter component:** Secure repo scaffold + threat model + DESIGN.md; define the inline
interception architecture.
**Checkpoint target:** CP-1 (Day 7).

## What was built
- Scaffolded the secure-by-default repository for **MCP Sentinel — Agent Trust Broker™**
  (slug `agent-trust-broker`, owner `IRsoctierDT`).
- Generated governance + gates: `AGENTS.md`/`CLAUDE.md` charter, quality gates
  (`pyproject.toml`: ruff, mypy, pytest+coverage≥85, bandit), `.pre-commit-config.yaml`,
  and GitHub CI (`ci.yml` fail-fast, `codeql.yml`, `dependabot.yml`, `CODEOWNERS`, templates).
- Replaced the generic `DESIGN.md` with a **Broker-specific, threat-informed** design:
  interception architecture (both pipelines), six trust boundaries (B1–B6), a seven-entry
  threat model (T1–T7) mapped to controls and charter days, data flows, and a decision log.

## How this extends the Broker
This is the foundation every later day builds on. DESIGN.md §3 defines the interception point
that Day 3's passthrough proxy implements; §5 (threat model) is the spec that Phase 2 (inbound)
and Phase 3 (outbound) defend against, day by day. The trust-boundary table names B3 (untrusted
tool response) as the critical surface — that is the Agentjacking/tool-poisoning lane.

## Key decisions (see DESIGN.md §7)
- **D1** Bidirectional gate, not inbound-only — the two hottest 2026 threats sit on opposite
  sides of the same boundary.
- **D2** HITL enforcement is architectural, not a config flag.
- **D3** Intent verifier scoped to allowlist + divergence MVP (semantic intent = Future Work).
- **D4** Framework substrate deferred to CP-1 — decide on evidence after Days 4–5.

## Verification
- `python -m compileall .` → OK
- `python -m pytest` → 4 passed, 100% coverage (path-traversal security suite green).

## Dead ends / notes
- Scaffold's default `pytest` invocation needs `pytest-cov` present (CI dependency); noted so a
  clean environment installs dev extras before the first local run.

## Assumptions vs facts
- **Fact:** repo scaffolds green; gates enforce coverage and security scanning on commit #1.
- **Assumption:** the reasoning model is not itself adversarial (DESIGN §5) — the Broker defends
  against hostile inputs and hijack, not a maliciously trained model.

## Addendum — Portfolio intake wired (event-driven staging)
- Added `scripts/portfolio_intake.py`: emits a per-day JSON manifest (artifact hashes,
  phase/checkpoint, auto-checked checklist items, `requires_human_approval_before_publish`).
  Typed (mypy --strict clean), ruff-clean, no subprocess (reads git refs from disk).
- Added `tests/unit/test_portfolio_intake.py` (30 tests; module at 94% coverage).
- Added a `portfolio-intake` CI job: fires on push, **only after tests pass**, auto-detects
  the day, and uploads the manifest as a staging artifact. It never publishes (decision D6).
- Verified end-to-end: `python scripts/portfolio_intake.py --day 1 --include DESIGN.md`
  produced `portfolio/intake/day-01.json` with all checklist items green.

## Portfolio Agent handoff
Artifacts filed for Day 01: `DESIGN.md` (threat model + architecture), scaffold tree,
this NOTES file. Tag: `ddsys-agent-charter-day01`. Flagship report #1 (Architecture +
Framework Fitness) lands at CP-1 / Day 7 and will incorporate this design.
