# ATB build spawn roadmap

Living map from design-volume **Known Residuals**, **Non-Goals**, and
**Recommended Next** sections into buildable amendment slices. Feature PRs
should cut from a row here — not from ad-hoc issue prose.

Pattern proven in [PR #11](https://github.com/IRsoctierDT/agent-trust-broker/pull/11):
residual / former non-goal → catalog scope (if needed) → wire MVP →
`tests/security` conformance rows → volume amendment + CHANGELOG + semver.

## How to spawn a build

1. Pick a row ID below (or promote a new residual into a row first).
2. Write a short **amendment slice** in the owning volume (or a new volume if
   the residual names one): purpose, wire contract, non-goals restated.
3. Add catalog scopes / tool-map entries only when the closed world must grow.
4. Ship `tests/security` rows that assert a **fail-closed outcome** (deny /
   escalate / refuse / startup refusal) — never merely a happy path.
5. Update CHANGELOG; bump semver (patch for hardening, minor for capability).
6. Leave Non-Goals in the [Fenced non-goals](#fenced-non-goals-do-not-spawn)
   section alone unless the volume itself is amended to graduate them.

## Shipped (do not re-open as gaps)

| ID | Source | Shipped | Notes |
|---|---|---|---|
| `R-ATB03-MINT` | ATB-03 demo `atb/mint` | v0.2.0 / PR #11 | Off unless `ATB_DEMO_MINT=1` |
| `R-ATB03-PLAN` | ATB-03 former non-goal (plan-vs-action) | v0.2.0 / PR #11 | Allowlist MVP: `atb/declare_plan`, `atb:plan.override` HITL; not semantic intent |
| `R-ATB05-LOCK` | ATB-05 writer-lock residual / non-goal note | v0.2.0 / PR #11 | Exclusive non-blocking `fcntl.flock` on append opens; readers unlocked |

## Spawn queue

| ID | Pri | Source | Vehicle | MVP acceptance | Min conformance | Bump |
|---|---|---|---|---|---|---|
| `R-ATB06-IDREV` | P0 | ATB-06 Known Residual 7 | ATB-06 amendment or ATB-07 slice | `revoke` appends a chained record; survives restart; CLI verb; delegated cascade still matches T10 | IR1 restart survival; IR2 cascade; IR3 no silent in-memory-only path | minor |
| `R-ATB05-SEALDEF` | P0 | ATB-05 Known Residual 2 | ATB-05 ops amendment | Durable/prod posture requires `ATB_CHAIN_SEAL_KEY`; unset fails closed when posture enabled; lab default documented | L-seal-required refuses unkeyed durable open; forged lifecycle record still exit 4 | patch |
| `R-ATB06-M6` | P0 | ATB-06 Recommended Next (Milestone 6) | Implementation milestone | `atb/keys.py` + epoch registry carried in ATB-05 checkpoint; v2 token profile; `atb key` / `atb anchor`; K1–K17 suite | Full K-matrix green; no `atb/keys.py` on main today | minor |
| `R-ATB04-EVADE` | P1 | ATB-04 Known Residual 1 | ATB-04 ruleset / golden-vector amendment | Homoglyph, chunk-split, short-encoding vectors in `tests/security`; still no ML classifier | S-evade-* rows: withhold or clean with zero authority either way | patch |
| `R-ATB04-FLOOD` | P1 | ATB-04 Known Residual 7 | ATB-04 amendment | Per-tool quarantine sub-budgets and/or bulk deny-by-digest CLI; exhausted budget stays fail-closed | S-flood budget partition; bulk deny leaves digests unreleasable | minor |
| `R-ATB04-MASK` | P1 | ATB-04 Known Residual 2 | Governed catalog/PEP change | Per-tool evidence masks so `audit_read` cannot cheaply oracle rule ids | Masked fields absent from agent-visible audit payloads | minor |
| `R-ATB05-ANCHOR` | P2 | ATB-05 Known Residual 3 | Ops helpers / CLI | Tip recording helpers after rotation, restore, sensitive resolve — **not** automatic rotation | Anchor helper dry-run appends 0; execute records expected tip | patch |
| `R-ATB01-SIGNALS` | P2 | ATB-01 Trust Signals future; ATB-06 Residual 6 | New volume (candidate ATB-07+) | Key-use anomaly signalling; session-level accumulation stays out of ATB-04 | Volume + conformance skeleton before code | minor (new volume) |
| `R-ATB03-PLAN-SEM` | P2 | ATB-03 (beyond allowlist MVP) | Deferred amendment | Semantic / intent plan verifier — only after allowlist MVP proves insufficient; stdlib + deterministic or explicit AGENTS.md exception | TBD; must not weaken `atb:plan.override` HITL | minor |

Priority legend: **P0** next code/PRs; **P1** hardening that closes documented levers; **P2** new volume or deferred research.

## Fenced non-goals (do not spawn)

These stay closed unless a volume is rewritten to graduate them:

| Fence | Source | Why it stays fenced |
|---|---|---|
| Automatic rotation (size/schedule) | ATB-05 / ATB-06 Non-Goals | Violates human gate; can move evidence mid-incident |
| Compaction / summarization / Merkle / skip-lists | ATB-05 Non-Goals | Extra audit surface; linear anchor covers the single-writer model |
| Sidecar manifest | ATB-05 Non-Goals | Second editable source of truth |
| ML / probabilistic semantic screener | ATB-04 Non-Goals | Non-deterministic, non-stdlib, network-dependent |
| Request-side screening as authority | ATB-04 Non-Goals | Scope model remains the primary control |
| Auto-release of previously approved digests | ATB-04 Non-Goals | Each occurrence costs one approval |
| Asymmetric signatures / `cryptography` | ATB-06 Non-Goals | Requires explicit AGENTS.md §5.1 dependency decision |
| Key escrow / KDF-at-rest / material distribution | ATB-06 Non-Goals | Deployment policy, not broker behavior in v0.1 |

## Amendment template

Copy into a volume PR description and the volume itself:

```text
### Amendment: <ID> — <title>
Source residual: <volume> § Known Residuals #<n>
MVP wire contract:
  - ...
Fail-closed behaviors:
  - ...
Conformance rows to add:
  - <ID>: <assert deny/escalate/refuse/startup failure>
Non-goals preserved:
  - ...
Version: <patch|minor> — CHANGELOG entry required
```

## Volume index

| Volume | File |
|---|---|
| ATB-01 | `docs/IANUA-ATB-v0.1-Identity-and-Policy-Broker.md` |
| ATB-02 | `docs/IANUA-ATB-v0.1-Scope-Catalog-and-Delegation-Model.md` |
| ATB-03 | `docs/IANUA-ATB-v0.1-Runtime-Enforcement-Point.md` |
| ATB-04 | `docs/IANUA-ATB-v0.1-Response-Screening-and-Quarantine.md` |
| ATB-05 | `docs/IANUA-ATB-v0.1-Audit-Chain-Lifecycle.md` |
| ATB-06 | `docs/IANUA-ATB-v0.1-Key-Lifecycle-and-Agility.md` |