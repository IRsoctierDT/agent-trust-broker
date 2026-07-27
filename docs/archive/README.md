# docs/archive — superseded design material

Historical documents retained for provenance. **Not authoritative.** The current
design of record is the ATB volume series in `docs/`:

- `IANUA-ATB-v0.1-Identity-and-Policy-Broker.md` (ATB-01)
- `IANUA-ATB-v0.1-Scope-Catalog-and-Delegation-Model.md` (ATB-02)
- `IANUA-ATB-v0.1-Runtime-Enforcement-Point.md` (ATB-03)

## Contents

| File | Origin | Why archived |
|---|---|---|
| `DESIGN-day01-interception.md` | Day-01 scaffold, 2026-07-08 | Describes the earlier *runtime tool-output interception* conception of the Agent Trust Broker (trust boundaries B1–B6, threat entries T1–T7). Superseded by the identity/policy architecture in ATB-01/02 and the enforcement model in ATB-03, which addresses the same injection threat (THR-0002) by constraining authority rather than screening tool text. |
| `NOTES-day01.md` | Day-01 scaffold, 2026-07-08 | Build log for the original scaffold. |

## Provenance note

These files were recovered on 2026-07-26 from an untracked working-tree copy at
`IANUA-Broker/agent-trust-broker/` — a stale scaffold that had never been committed to
any repository. The salvage also brought across the `AGENTS.md` / `CLAUDE.md` operating
charter and the repository governance configuration (CodeQL, Dependabot, CODEOWNERS,
issue/PR templates, pre-commit), all of which now live at their canonical locations in
this repository. The scaffold was removed after salvage; a full archive of it was retained
outside the repository.
