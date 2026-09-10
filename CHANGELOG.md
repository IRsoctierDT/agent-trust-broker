# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(0.x minors may include additive security features).

## [0.3.0](https://github.com/IRsoctierDT/agent-trust-broker/compare/ianua-atb-v0.2.0...ianua-atb-v0.3.0) (2026-09-10)


### Features

* ATB-03 Milestone 3 — runtime enforcement point (PEP) ([4a1e21d](https://github.com/IRsoctierDT/agent-trust-broker/commit/4a1e21d65c663205c5f66c2dba0911d7c22ec251))
* **atb-04:** Milestone 4 — tool-response screening & quarantine ([89b683d](https://github.com/IRsoctierDT/agent-trust-broker/commit/89b683ddfbb89a0ae85ec855f92e105cf26cb24d))
* **atb-04:** Milestone 4 — tool-response screening & quarantine ([5efcde4](https://github.com/IRsoctierDT/agent-trust-broker/commit/5efcde423a8153bb039e15017ec60c3c0015ae12))
* **atb-05:** Milestone 5 — audit-chain lifecycle (rotation, checkpoints, chained time) ([9472c3a](https://github.com/IRsoctierDT/agent-trust-broker/commit/9472c3a00c0257b4903785ab5444a7493e52d5cb))
* CI quality gates + durable hash-chained audit persistence ([957e970](https://github.com/IRsoctierDT/agent-trust-broker/commit/957e970b3329a2e4e39626e6ea423cddd5ca847b))
* end-to-end demo + AuditSink protocol for pluggable persistence ([f55ce56](https://github.com/IRsoctierDT/agent-trust-broker/commit/f55ce56d00a37f1236fcca6292575a588d6f89fa))
* Milestone 1 — identity authority, policy engine, hash-chained audit (T1-T12 green) ([d9ef64d](https://github.com/IRsoctierDT/agent-trust-broker/commit/d9ef64de5bf22110214161d46f6e8b7060995c3e))
* Milestone 2 — escalation queue with chained human approve/deny ([9d34f6d](https://github.com/IRsoctierDT/agent-trust-broker/commit/9d34f6de6e5d2319c0bd7c975c84a74a10103456))
* Milestone 3 — ATB-03 runtime enforcement point (PEP) ([2fec222](https://github.com/IRsoctierDT/agent-trust-broker/commit/2fec222467dcc895b29b3f1d4fb05c37549590ee))
* operator CLI — atb pending / approve / deny / verify ([27bfa79](https://github.com/IRsoctierDT/agent-trust-broker/commit/27bfa795ce862f7e87c90a54caeda7f152db8e4a))


### Bug Fixes

* harden PEP + gateway per multi-lens adversarial review (22 findings) ([d192b35](https://github.com/IRsoctierDT/agent-trust-broker/commit/d192b35ddb5fee41b987b6a0e9505ef55377784e))
* **security:** stop the signing key rendering in repr; close the identity reason vocabulary ([59ecf5c](https://github.com/IRsoctierDT/agent-trust-broker/commit/59ecf5c0a47a8a3830670cf6deb3590398438fae))


### Documentation

* add ATB-02 — scope catalog, role-spec bindings & delegation model ([05a660b](https://github.com/IRsoctierDT/agent-trust-broker/commit/05a660b98c6ff350bbb3c99000205802716aee7b))
* add ATB-03/M3 to README; reconcile charter with actual repo layout ([4d0a6f6](https://github.com/IRsoctierDT/agent-trust-broker/commit/4d0a6f6bd550e6af73e3c64f52a23b33bd57a44f))
* add IANUA-ATB v0.1 identity & policy broker design volume ([ce1cfa3](https://github.com/IRsoctierDT/agent-trust-broker/commit/ce1cfa32c0bbb854b81bdde4fe12454fcaa5d19e))
* add residual→spawn ROADMAP from volume tables ([81342c3](https://github.com/IRsoctierDT/agent-trust-broker/commit/81342c3e85c89671634223d5638f420d38337671))
* **atb-03:** review gate passed — status Draft → Authoritative ([bf4ec75](https://github.com/IRsoctierDT/agent-trust-broker/commit/bf4ec75afaf78ccb12bbfb4274a3cbdbd1aead4f))
* **atb-04:** add design volume — tool-response screening & quarantin… ([67bae9a](https://github.com/IRsoctierDT/agent-trust-broker/commit/67bae9a0aaf73df6fa61312e0ade89439abf1722))
* **atb-04:** add design volume — tool-response screening & quarantine (draft) ([606a469](https://github.com/IRsoctierDT/agent-trust-broker/commit/606a469363682ec1947aeb738c3a4352f45fae2d))
* **atb-04:** format catalog snippet per ruff format ([e4e20d7](https://github.com/IRsoctierDT/agent-trust-broker/commit/e4e20d7dbec587dc5b892de48bd993d95d1bf760))
* **atb-04:** review gate passed — Draft → Authoritative; reconcile with impl review ([6d4c9b6](https://github.com/IRsoctierDT/agent-trust-broker/commit/6d4c9b6a67d579e1e5604aec332aca4d49b73006))
* **atb-05:** add design volume — audit-chain lifecycle (draft) ([0ea14f4](https://github.com/IRsoctierDT/agent-trust-broker/commit/0ea14f4791c0d3b6d83d7774e00606c5d724cac8))
* **atb-06:** add design volume — key lifecycle & cryptographic agility (draft) ([68fe922](https://github.com/IRsoctierDT/agent-trust-broker/commit/68fe92275dd9143b4e4a2105206cfc5923d74df0))
* **atb-06:** fix 11 confirmed findings from adversarial review ([dfe4466](https://github.com/IRsoctierDT/agent-trust-broker/commit/dfe44665589a4e0c39915001162eaf2abbc7f690))
* residual→spawn ROADMAP for future ATB builds ([4af3277](https://github.com/IRsoctierDT/agent-trust-broker/commit/4af32770bbb49c34392de30e254c734adc99baf3))

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
