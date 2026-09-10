# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(0.x minors may include additive security features).

## [Unreleased]

### Documentation

- Add `docs/ROADMAP.md`: living residual → build spawn map (P0 identity revocation, keyed-seal posture, Milestone 6 keys; P1 screener corpus / quarantine flood / evidence masks).

## [0.2.0] — 2026-09-10

### Added

- Outbound plan-declaration / divergence MVP (`atb.plan`, `atb/declare_plan`,
  catalog scope `atb:plan.override`): once a subject declares a tool allowlist,
  divergence escalates to HITL; optional `ATB_REQUIRE_PLAN=1` refuses calls
  until a plan is declared.
- Exclusive non-blocking `fcntl` file lock on JSONL audit writers
  (`JsonlAuditStore` when `for_append=True`); readers stay lock-free; release
  via `close()`.
- Lab mint gate: gateway `atb/mint` is off by default; enable only with
  `demo_mint=True` / `ATB_DEMO_MINT=1`.

### Changed

- Operator CLI opens the audit chain read-only (`for_append=False`) for
  pending/show/verify/stats/purge paths; approve/deny/detach still take the
  writer lock and release it when finished.
- Rotation self-test opens the successor read-only after releasing the
  sealer's writer lock.

### Security

- Demo identity minting can no longer be invoked on a production-default
  gateway.
- Concurrent second writers fail closed with `AuditIntegrityError` rather than
  forking the hash chain.