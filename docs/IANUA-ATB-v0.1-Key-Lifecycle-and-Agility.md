---
title: "IANUA-ATB v0.1 — Volume ATB-06: Key Lifecycle & Cryptographic Agility"
series: "IANUA Engineering Reference"
volume: "ATB-06"
status: "Draft — pending human review gate"
supersedes: "None (extends ATB-01 through ATB-05)"
companion_docs:
  - "IANUA-ATB v0.1 — Volume ATB-01: Identity Issuance & Zero-Trust Policy Enforcement"
  - "IANUA-ATB v0.1 — Volume ATB-02: Scope Catalog, Role-Spec Bindings & Delegation Model"
  - "IANUA-ATB v0.1 — Volume ATB-03: Runtime Enforcement Point & Tool-Call Mediation"
  - "IANUA-ATB v0.1 — Volume ATB-04: Tool-Response Screening & Quarantine"
  - "IANUA-ATB v0.1 — Volume ATB-05: Audit-Chain Lifecycle"
  - "IANUA — AGENTS.md Operating Charter"
eaods_traceability:
  reference_implementation_of:
    - "PAT-0001 — Zero Trust Service Identity"
    - "EAODS-CTRL-000184 — Service Identity Verification"
  mitigates:
    - "THR-0001 — Compromised Service Identity"
  emits_evidence_to:
    - "PAT-0003 — Continuous Assurance Evidence Pipeline"
  governed_by:
    - "STD-0001 — Canonical Terminology & Object Identifiers"
    - "STD-0002 — Cross-Artifact Traceability & Knowledge Graph"
purpose: >
  Specifies the key lifecycle the series has assumed but never defined: how the
  identity signing key and the chain seal key are introduced, rotated, retired,
  and revoked without invalidating outstanding identities or making a single
  historical record unverifiable; how key material is referenced without the
  broker ever persisting, chaining, or logging it; and how the series gains
  cryptographic agility over a decade-long evidence lifetime, given that every
  record hash is frozen the instant it is written.
owner: "Repository maintainer (human)"
review_cadence: "Re-read on session start; revise on any key, algorithm, or token-format change"
---

# IANUA Agent Trust Broker (ATB)

## Volume ATB-06 — Key Lifecycle & Cryptographic Agility

---

## Purpose

Five volumes have leaned on two secrets without ever specifying their lives.
`IdentityAuthority` takes **one** HMAC key at construction; replacing it
instantly invalidates every outstanding identity, and no token minted under a
previous key can ever be verified again. ATB-05 added a **second** key
(`ATB_CHAIN_SEAL_KEY`) with the same gap: rotating it would strand verification
of every segment already sealed. ATB-01 listed `rotate` as an Identity
Authority operation and referenced `kms://` key material; neither was ever
designed. And every digest in the series is hard-coded `sha256:` — in record
hashes, ATB-04 quarantine digests, ATB-05 segment digests, and an ATB-02
catalog resource pattern — while the evidence those digests protect is meant
to outlive any particular primitive.

This volume closes all four gaps under one model: a **key epoch** whose status
history is chained (tamper-evident, travels with the evidence) while its
material lives only behind a non-secret reference resolved from operator
configuration. Two facts make the whole design tractable:

> **No key compromise ever makes a record unverifiable.** The record hash chain
> is unkeyed sha256 and stays that way, so the *evidence* survives every key
> event — nothing is ever re-signed, because nothing may ever be re-written.
> But the split is sharper than "keys are only about attribution": an unkeyed
> chain is fully recomputable, so on-box integrity against an adversary with
> write access to the volume rests entirely on the keyed seals (ATB-05's own
> truncate-and-forge residual). Therefore **losing an `identity_sign` key is an
> attribution event; losing a `chain_seal` key is an integrity event for the
> on-box copy** — the off-box anchor and archive digests are what bound it.

> **HMAC is symmetric, so a verifier can forge.** With stdlib-only crypto there
> is no third-party non-repudiation: anyone who can *check* a seal can *mint*
> one. Seals prove "someone holding the operator's key sealed this", never
> "the operator sealed this, and no one else could have". Stated here plainly
> because the series' evidence claims must not quietly overreach.

---

## Strategic Objectives

- **Rotation without loss.** Outstanding short-lived identities stay verifiable
  through a bounded overlap; historical seals stay verifiable **forever**.
  Nothing is ever re-signed, because nothing may ever be re-written.
- **No secret anywhere it must not be.** Key bytes never enter the chain, a
  log, an error message, a `repr`, or an exported artifact. Only non-secret
  identifiers and commitments are chained.
- **No silent acceptance.** An unknown epoch, absent material, a revoked key,
  or an unimplemented algorithm refuses. Verification distinguishes *"I cannot
  check this here"* from *"this is wrong"* — and never conflates either with
  success.
- **Compromise is a designed path.** Emergency revocation is distinct from
  routine rotation, chained, and bounded by an accounting of exactly what it
  invalidates versus what it merely de-attributes.
- **Agility without retro-editing.** New algorithms apply to **new values
  only**, declared in a closed registry, adopted at ATB-05 segment boundaries.
  Frozen archives gain protection under a stronger primitive by *appending* a
  re-anchor commitment, never by touching a byte.
- **Zero migration.** A deployment with today's single `ATB_SIGNING_KEY` and no
  epoch records keeps working unchanged, forever.

---

## Trust & Engineering Principles

1. **The chain says *what*; configuration says *where*.** Epoch identity,
   status, and commitments are chained. Material location and availability are
   operator configuration. Neither authority may substitute for the other, and
   the broker **never resolves a chained reference to read a file** — doing so
   would hand a chain-writer an arbitrary-file-read primitive and collapse the
   two-party control into one.
2. **Domain separation is total.** Every keyed construction carries a distinct,
   frozen label. A seal tag can never be replayed as a token MAC even if the
   same bytes were misconfigured into both keys — and that misconfiguration is
   independently refused at startup by fingerprint equality.
3. **The key id is inside the MAC.** Binding it costs nothing and makes each
   tag self-describing evidence of which epoch minted it, removing any
   dependence on the lookup path being honest.
4. **Position, not wall clock, bounds seal epochs.** Epoch windows for chained
   artifacts are enforced by **chain position** — ATB-05 principle 5 (time is
   telemetry, position is authority) applies here without exception.
5. **A revocation is never authenticated by the key it revokes.** `revoke`
   refuses on an active epoch: rotate first, so the successor seals the
   revocation.
6. **Algorithms are a closed world.** Like scopes and tools: an algorithm the
   binary does not implement is unrepresentable, not "assume the best".

---

## The Key Epoch Model

**Purposes** — exactly two, closed: `identity_sign` and `chain_seal`. One key ⇒
one purpose ⇒ one algorithm ⇒ one epoch. No key is ever used for two
constructions.

**Identifier** — `kid = f"{tag}-{epoch:06d}"`, tag ∈ {`idsign`, `seal`};
non-secret, monotonic per purpose, **never reused**, matching `[a-z0-9-]{1,32}`.
Epoch `000000` is reserved for the adopted legacy key.

**Fingerprint** — the non-secret binding commitment:

```
fpr = "fpr-sha256-128:" + sha256(b"atb-key-fingerprint-v1\n" + key).hexdigest()[:32]
```

Domain-separated (never collides with or doubles as a content digest) and
truncated to 128 bits. It is deliberately **purpose-independent**: purpose
binding belongs to the per-construction domain labels, and folding it in here
would make the same bytes fingerprint differently under each purpose — which
would hide exactly the misconfiguration the guard exists to catch (the same key
installed as both the identity and the seal key). Comparison is therefore
across **all** epochs of **both** purposes: a repeat fingerprint is refused as
key reuse. It exists so wrong material is a **named startup
refusal** ("material for `idsign-000002` does not match the chained
commitment") instead of undiagnosable mass denial, and so an auditor in 2036
can prove they hold the right key before concluding "chain broken". Honest
cost: it is a public commitment to a secret, i.e. an offline guessing oracle —
acceptable **only** because keys are ≥ 32 bytes of CSPRNG output, a property
the broker enforces by length and can never enforce by entropy (Residual 4).

**States** — `active → verify_only → expired`, with `revoked` reachable from
any state:

| State | Mint / seal? | Verify? | Derived from |
|---|---|---|---|
| `active` | yes (newest active per purpose only) | yes | an activation record with no successor |
| `verify_only` | **no** | yes | a successor's `supersedes` field |
| `expired` | no | no | `verify_until` elapsed (identity only) — computed, never a record |
| `revoked` | no | see revocation semantics | a chained revocation record |

`verify_only` for `identity_sign` is bounded by `verify_until = superseded_at +
ATB_KEY_OVERLAP_SECONDS` (default 960 s = the 900 s identity TTL + 60 s skew),
so outstanding tokens survive exactly their natural lifetime and no longer. For
`chain_seal` there is **no** `verify_until`: historical seals must verify
forever. Retirement only stops *new* sealing.

**Chained records** — ordinary records (one ATB-DEC id each, carrying `at`,
ignored by the queue's unknown-type forward compatibility; payload hygiene
unchanged — ids, fingerprints, counts, closed vocabularies only):

```yaml
# Routine rotation is exactly ONE atomic append. The predecessor's
# verify_only status is DERIVED from `supersedes`, so there is no window in
# which two epochs are simultaneously active.
type: key_epoch_activated
purpose: identity_sign
kid: idsign-000002
epoch: 2
alg: hmac-sha256
profile: atb-identity-token-v2
key_fpr: "fpr-sha256-128:…"
key_ref: "file:idsign-000002.key"   # ADVISORY provenance; never resolved
supersedes: idsign-000001            # null for the first epoch of a purpose
activated_by: ivan
auth_kid: seal-000001                # see "no format break", below
auth: "hmac-sha256:…"
```

```yaml
type: key_epoch_adopted        # retroactively DESCRIBES the pre-ATB-06 key
purpose: identity_sign
kid: idsign-000000
epoch: 0
alg: hmac-sha256
profile: atb-identity-token-v1
key_fpr: "fpr-sha256-128:…"
kidless: true                  # at most ONE kidless epoch per purpose, ever
adopted_by: ivan
```

```yaml
type: key_epoch_revoked
purpose: identity_sign
kid: idsign-000001
reason_code: key_compromise    # closed: key_compromise | material_lost
                               #       | operator_error | algorithm_withdrawn
revoked_by: ivan
evidence_ref: ATB-DEC-004871   # optional chained pointer; never free text
```

### Epoch state across a chain rotation

**The registry is checkpoint-carried state, not archive history.** ATB-05's
runtime reads only the active segment — archives are stat-only and may be
legitimately detached — so a chained epoch record becomes invisible to the
running broker the moment the chain rotates past it. Left unaddressed, one
routine `atb rotate --execute` would silently un-enforce a chained
`key_epoch_revoked`: the registry would replay empty, empty means *legacy
single-key mode* (K17), and the broker would go back to accepting the very
material the operator revoked. This is the identical failure ATB-05 fixed for
detach authorizations, and it gets the identical treatment.

The `chain_checkpoint` therefore carries a `key_epochs` list — one entry per
epoch ever chained, for **both** purposes — seeded from the predecessor
checkpoint's list plus every `key_epoch_adopted` / `key_epoch_activated` /
`key_epoch_revoked` appended since:

```yaml
key_epochs:
  - {purpose: identity_sign, kid: idsign-000001, epoch: 1, alg: hmac-sha256,
     profile: atb-identity-token-v2, key_fpr: "fpr-sha256-128:…", kidless: false,
     state: revoked, supersedes: idsign-000000,
     activated_ref: ATB-DEC-004120, activated_seq: 4120,   # position bounds
     superseded_ref: ATB-DEC-004890, revoked_ref: ATB-DEC-004901,
     reason_code: key_compromise}
```

Entries are **state, not events**: they are never dropped (a `chain_seal` epoch
must stay verifiable forever, and a revocation must stay in force forever), and
positions are carried because containment is bound by chain position. Deep
verification re-derives the list from the predecessor archive and byte-compares
it, exactly as it already does for `pending` / `approvals` / `detached` — so a
checkpoint that quietly drops a revocation fails verification. The record
*count* for a rotation is unchanged at two; the checkpoint *payload* grows.

Describing the legacy key is **not** retro-editing: the legacy tokens and
records are untouched. The single-`kidless`-epoch rule is load-bearing — a
second would force trial verification of kid-less tokens against multiple keys,
which is precisely the oracle this design forbids.

---

## No Format Break: `auth_kid` as a Sibling Field

ATB-05 shipped seals as `auth: "hmac-sha256:<hex>"` under the domain prefix
`atb-chain-seal-v1\n`, with `seal_tag()` hashing **the canonical payload minus
`auth`**. That last detail is the whole migration story: adding a sibling field
`auth_kid` makes the key id **MAC-covered for free**, with zero change to
`seal_tag`/`verify_seal_tag`, zero change to the tag format, and full backward
compatibility with every seal already written.

Verified against the shipped implementation: adding `auth_kid` changes the tag,
and substituting a different `auth_kid` invalidates it. A seal with no
`auth_kid` is, by definition, from the kidless epoch.

> **Rejected:** a `mac:<alg>:<kid>:<hex>` v2 seal format under a new domain
> prefix. It would break every seal Milestone 5 has already written, for a
> property the sibling field delivers at zero cost.

**The authenticated-record set grows.** ATB-05 ships
`LIFECYCLE_TYPES = {chain_rotated, chain_checkpoint, segment_detached}`, and
both the tag check and the keyed-chain downgrade guard key off that set — so
ATB-06's own records would be *unauthenticated by default*, and a chain-writer
could forge a `key_epoch_revoked` or a `key_epoch_activated` naming their own
material. ATB-06 therefore extends it to
`AUTHENTICATED_TYPES = LIFECYCLE_TYPES | {key_epoch_adopted,
key_epoch_activated, key_epoch_revoked, family_reanchored}`. Every record of
those types **must** carry `auth_kid` + `auth` on a keyed chain, and
verification **must** FAIL (exit 4) on any such record whose tag is absent or
invalid under material present here. "Ordinary records" in the model above
means only *one ATB-DEC id, an `at`, and no special handling in the queue's
replay* — never "outside the tag demand".

**Verification must reach the active segment.** ATB-05's keyed tag check runs
inside the deep-verify archive loop only, so records in the *active* segment —
where every freshly appended key record lives until the next rotation — are
never tag-checked, and `--active-only` performs no tag verification at all
while printing "PROVEN: no record in the active segment has been added,
edited, removed, or reordered". ATB-06 lifts the check into a helper applied to
**every** segment including the active one, and applies the unkeyed-downgrade
guard there too, so an unkeyed run over a keyed chain cannot pass silently when
the only keyed records are the recent ones. `--active-only`'s PROVEN sentence
is amended to name what its tag check did and did not cover.

---

## Identity Token Profiles

**v1 (legacy, frozen forever).** `<identity_id>.<mac_hex>`; message is today's
`"|".join((identity_id, subject, not_after.isoformat(), ",".join(sorted(scopes))))`
with no domain prefix. Never changed, never extended — it is what existing
tokens are.

**v2 (`atb-identity-token-v2`).** `ATB2.<kid>.<identity_id>.<mac_hex>`, MAC over
`b"atb-identity-token-v2\n" + canonical_json({...})` covering the kid, the
algorithm id, and **all seven identity fields** — `identity_id`, `subject`,
`issued_at`, `not_after`, `scopes`, `delegatable`, `delegated_by`.

This closes two latent defects in one format change:

- **Coverage.** v1's MAC omits `issued_at`, `delegatable`, and `delegated_by`.
  Not exploitable today — `verify()` re-MACs against the server-side `_store`,
  so those fields are authenticated by *state*, not by the tag — but the
  moment the identity store becomes durable, shared, or multi-process, the tag
  becomes load-bearing and the omission becomes a real forgery surface.
- **Separator ambiguity.** The `|`/`,` joins are injection-shaped in the same
  class as the coverage gap (not exploitable today: subjects come from
  `ROLE_BINDINGS` and scopes from the closed `CATALOG`). Canonical JSON removes
  the class.

**Selection is by exact `kid` lookup — never trial verification**, and the
algorithm comes from the **chained epoch**, never from a field the caller
supplies. There is no algorithm field in a token an attacker can rewrite, so
algorithm downgrade by input manipulation is structurally impossible. A v1
(kid-less) token resolves to the single `kidless` epoch or is refused
(`unversioned_token_refused`) once `ATB_REQUIRE_KID=on`.

---

## Rotation & Revocation

**Routine rotation** — `atb key rotate <purpose>`, dry-run by default, gateway
stopped, §5.1-gated:

1. **Preflight.** Deep-verify the family; confirm the new material is loadable
   and its fingerprint is *not* equal to any existing epoch's (key reuse and
   the both-keys-same-bytes misconfiguration are refused here).
2. **Append one record** — `key_epoch_activated` with `supersedes`. The
   predecessor becomes `verify_only` **by derivation**; there is no
   two-active-epochs window to explain away, and a crash leaves either the old
   epoch active (record absent) or the new one active (record present).
3. **Report** the new kid, its fingerprint, and — for `identity_sign` — the
   instant the overlap lapses.

For `chain_seal`, activation is **dual-sealed**, specified exactly:

1. Build the activation payload with `auth_kid` set to the **outgoing** kid and
   compute `auth_prev = seal_tag(payload_without_auth_and_auth_prev, old_key)`.
2. Insert `auth_prev`, set `auth_kid` to the **new** kid, and compute
   `auth = seal_tag(payload_without_auth, new_key)` — so the outer tag covers
   `auth_prev` (it is an ordinary sibling field, exactly like `auth_kid`),
   while the inner tag does not cover the outer one. Order matters and is
   normative: computing them the other way makes neither tag cover the other.
3. Both keys must be loadable at that moment, or the rotation refuses.

A verifier holding **either** key can validate its half: the new key checks
`auth`, the old key re-derives `auth_prev` over the payload minus both fields.
Neither key alone can forge a lineage change, because a forger holding only the
old key cannot produce `auth`, and one holding only the new key cannot produce
`auth_prev`. Verification of `auth_prev` is a distinct code path from
`verify_seal_tag` (which reads only `auth`) and is part of Milestone 6.

**Emergency revocation** — `atb key revoke <kid> --reason-code …`:

- **Refuses on an active epoch**: rotate first. A revocation must never be
  authenticated by the key it revokes.
- `identity_sign` revoked ⇒ every token under that kid fails verification
  **immediately** (`key_epoch_revoked`), not at overlap expiry. Blast radius is
  bounded and countable: short TTLs mean the outstanding set is small, and the
  per-record `key_epoch` attribution (below) makes "which decisions were
  authenticated under this epoch" an exact query rather than a narrative.
- `chain_seal` revoked ⇒ **new** seals under that kid are refused, and seals
  written **before** the revocation's chain position still verify, reported as
  `SEALED-BY-REVOKED-EPOCH`. Making them FAIL would turn one key compromise
  into permanent verification failure for all history it ever touched — the
  integrity/attribution asymmetry stated in the Purpose. What the operator
  loses is attribution confidence for that window, not the evidence.

**Position-only containment.** A seal is accepted from epoch *k* only when its
chain position lies within *k*'s activation-to-supersession interval. Wall
clock is never consulted: a stepped-back host clock must not widen an epoch's
acceptance window.

**Per-record attribution.** Decision records where identity verification
succeeded carry an additive `key_epoch` field (absent on unverified denials,
never back-filled). `atb key show <kid>` then reports exactly how many
decisions an epoch authenticated — requirement 6's accounting, delivered as a
count rather than a story.

---

## Cryptographic Agility

The `<alg>:<hex>` grammar is already load-bearing everywhere (`sha256:` record
hashes, quarantine digests, segment digests, `hmac-sha256:` tags), so agility
is a **closed algorithm registry** over the grammar the series already speaks:

| Rule | Consequence |
|---|---|
| Registry is closed and validated at import | An algorithm the binary does not implement is refused, never assumed |
| Algorithm applies to **new values only** | Not one historical byte is rewritten |
| Changes adopt at an **ATB-05 segment boundary** | The checkpoint declares the segment's algorithms; mixed-algorithm families verify per segment |
| Every digest carries its prefix | Parsers dispatch on the declared algorithm; an unknown prefix fails closed |

**The frozen-archive problem, honestly.** Agility cannot retroactively
strengthen a hash already written: if sha256 were broken tomorrow, every
existing archive digest is exactly as strong as sha256 was. The one real
mitigation is to *append* new evidence — `atb anchor --alg <new> --execute`
writes a single `family_reanchored` record committing to every archived
segment's whole-file digest under the stronger algorithm plus the current tip.
It edits nothing and it cannot repair a break that already happened, but from
that record forward the family is bound under both primitives.

**Coupling to watch:** ATB-02's catalog hard-codes the resource pattern
`quarantine:sha256:*`, and ATB-04's release deriver full-matches
`sha256:[0-9a-f]{64}`. A new quarantine digest algorithm would therefore
produce resource strings **no scope authorizes** — release would fail closed,
which is safe but silently unusable. Any digest-algorithm migration must extend
that catalog pattern and deriver in the same governed change.

---

## Key Material Handling

- **Location** — `ATB_KEY_DIR` (0700, one 0400 file per kid, named by kid) or
  the legacy `ATB_SIGNING_KEY` / `ATB_CHAIN_SEAL_KEY` env vars. The directory
  **must not** be the chain volume: keys beside the evidence they authenticate
  defeats the separation, and the check is a startup refusal.
- **Never** persisted by the broker, chained, logged, printed, or rendered in a
  `repr`. (Milestone 5's companion fix made `IdentityAuthority.signing_key`
  `repr=False` — "never logged" must be structural, not a matter of caller
  care.)
- **`key_ref` is advisory provenance only.** It is chained so an auditor can
  see where material was *said* to live — including the literal ATB-01
  `kms://` URI, validated as a URI with no userinfo, query, or fragment — and
  it is **never resolved by the broker**.
- **Startup consistency guard**, scoped to material the broker must actually
  *use*. For the **active** epoch of each purpose, and for every non-expired
  `verify_only` **`identity_sign`** epoch, material must resolve and its
  fingerprint must equal the chained commitment, or the broker refuses to
  start. Superseded **`chain_seal`** epochs are checked *opportunistically*:
  present material must match its fingerprint (a mismatch is the named refusal
  of K2), but absent material is **not** a startup condition — it is an
  `UNVERIFIED` tag at verify time (exit 3, INCOMPLETE). Demanding otherwise
  would make a broker unstartable years later merely because an old seal key
  was retired to cold storage, which is the normal end state, not a fault.
  Missing material for an *expired* identity epoch is likewise normal — that is
  how old keys get deleted.

---

## Three-Valued Verification

`atb verify` gains a third outcome, because "I do not hold this key" and "this
tag is wrong" are different facts and must never share an exit code:

| Exit | Meaning |
|---|---|
| **0 — PASS** | Hash chain verifies and every seal tag checked under material present here |
| **3 — INCOMPLETE** | Hash chain verifies; one or more epochs' material is absent here, so those tags are `UNVERIFIED` — printed with the NOT-PROVEN text, never counted as pass |
| **4 — FAIL** | Tamper: a hash mismatch, or a tag invalid **under a key that is present** |

`--allow-unkeyed` promotes 3 → 0 while printing what it waived; it can never
touch 4. This is what lets a forensic workstation without the escrowed seal key
report honestly instead of choosing between a false pass and a false alarm.

---

## Record Accounting

| Operation | Records | Count |
|---|---|---|
| `atb key adopt <purpose>` (legacy description) | `key_epoch_adopted` | **1** |
| `atb key rotate <purpose> --execute` | `key_epoch_activated` (with `supersedes`) | **1** |
| `atb key revoke <kid> --execute` | `key_epoch_revoked` | **1** |
| `atb anchor --alg <new> --execute` | `family_reanchored` | **1** |
| `atb key list / show`, any verify | — | **0** |
| Identity mint/verify, policy decisions | unchanged (decisions gain an additive `key_epoch` field) | unchanged |

Every ATB-01/03/04/05 count table is unchanged; the engine stays zero-diff.

---

## CLI & Configuration

| Verb | Function |
|---|---|
| `atb key list` | Epochs per purpose with state, fingerprint, and material-present flag |
| `atb key show <kid>` | One epoch's chained history plus the count of decisions it authenticated |
| `atb key adopt <purpose>` | Describe the pre-ATB-06 key as epoch 0 (once per purpose, ever) |
| `atb key rotate <purpose>` | Dry-run default; `--execute` appends one activation record |
| `atb key revoke <kid>` | Refuses on an active epoch; requires a closed `--reason-code` |
| `atb anchor --alg <new>` | Append a cross-algorithm commitment over the whole family |

| Key | Default | Meaning |
|---|---|---|
| `ATB_KEY_DIR` | unset | Directory of per-kid material (0700; files 0400); must not be the chain volume |
| `ATB_KEY_OVERLAP_SECONDS` | `960` | Identity verify-only overlap: TTL + skew |
| `ATB_REQUIRE_KID` | `off` | When `on`, kid-less (v1) tokens are refused |

All parsed fail-closed. `ATB_SIGNING_KEY` and `ATB_CHAIN_SEAL_KEY` keep working
as the epoch-0 material source, so an existing deployment needs no change.

---

## Non-Goals

- **No asymmetric signatures.** Stdlib-only rules out Ed25519, so there is no
  third-party non-repudiation; adopting `cryptography` is an AGENTS.md §5.1
  dependency decision this volume does not make for the maintainer.
- **No automatic rotation.** No schedule, no size trigger — a human verb only.
- **No key escrow, wrapping, or KDF-at-rest** in v0.1: material is plaintext
  hex protected by filesystem mode (Residual 3).
- **No key-material distribution mechanism.** How an operator gets bytes onto
  the host is deployment policy, not broker behavior.

---

## Known Residuals (accepted, documented)

1. **A verifier can forge.** HMAC is symmetric: anyone who can validate a seal
   can mint one. Seals bound *who could have* sealed something to the set of
   key holders, and no further.
2. **Truncation can un-revoke.** Epoch status is chained, and ATB-05's
   documented active-tail residual means a truncated prefix still verifies — so
   truncating past a `key_epoch_revoked` restores the epoch's apparent
   validity. Bounded by the same mitigation: anchor cadence plus off-box copies.
3. **Material is plaintext at rest**, protected by filesystem mode (and a tmpfs
   mount where the deployment provides one). No stdlib-only wrapping story
   would add real strength on a single-host lab where the broker must read the
   key unattended.
4. **The fingerprint assumes entropy the broker cannot verify.** It checks
   length; it cannot check randomness. A low-entropy key makes the chained
   fingerprint an offline guessing oracle.
5. **The bootstrap epoch is self-attested.** Adopting epoch 0 on a legacy chain
   is authorized by the operator's say-so; there is no prior key to sign it.
6. **Compromise detection is assumed.** Every response path starts "the
   operator notices". Per-epoch attribution counts make *investigation* exact,
   but nothing here raises the alarm — key-use anomaly signalling is a
   candidate for the trust-signals volume.
7. **Identity revocation remains unchained.** `IdentityAuthority.revoke()`
   mutates an in-memory set, appends no record, and has no CLI verb — so it
   does not survive a restart and leaves no evidence. Named here because this
   volume makes *key* revocation durable and tamper-evident while identity
   revocation is neither; closing that gap is a candidate for the next volume.

---

## Conformance Test Matrix (key-lifecycle extension)

| # | Property | Test asserts |
|---|---|---|
| K1 | Epoch identity | `kid` is monotonic per purpose, never reused; a second `kidless` epoch is refused |
| K2 | Fingerprint binds material | Wrong material for a chained epoch is a **named** startup refusal, not mass denial; the **same** bytes installed under both purposes is refused as key reuse |
| K3 | Rotation is one atomic record | `key rotate --execute` appends exactly one `key_epoch_activated`; the predecessor is `verify_only` by derivation; no state has two active epochs |
| K4 | Overlap is bounded | A token minted under the previous identity epoch verifies until `verify_until` and is refused after; a stepped-back clock does not widen the window |
| K5 | Seals verify forever | A segment sealed under a superseded seal epoch still verifies after any number of rotations |
| K5b | Epoch state survives rotation | After N rotations following a `key_epoch_revoked`, the revocation is still in force (its material is refused) and the registry is unchanged; a checkpoint that drops an epoch fails deep verification |
| K5c | Key records are authenticated | On a keyed chain every `key_epoch_*` / `family_reanchored` record carries a valid tag; a forged or untagged one FAILS (exit 4), in the **active** segment as well as archives — including under `--active-only` |
| K5d | Dual-sealed handover | A seal-epoch activation validates under either key; stripping or altering `auth_prev` invalidates `auth`; rotation refuses when either key is unloadable |
| K6 | Kid is MAC-covered | Substituting `auth_kid` invalidates the tag; a seal written before ATB-06 (no `auth_kid`) still verifies |
| K7 | No downgrade | A token/seal declaring an algorithm other than its epoch's is refused; an unimplemented algorithm is refused |
| K8 | No secret leaks | No key byte appears in any `repr`, log line, error message, chained payload, or exported artifact (pinned for both key types) |
| K9 | Revocation ordering | `key revoke` refuses on an active epoch; after rotation the revocation is sealed by the successor |
| K10 | Revocation semantics | Revoked identity epoch ⇒ its tokens fail immediately; revoked seal epoch ⇒ new seals refused, prior seals verify and report `SEALED-BY-REVOKED-EPOCH` |
| K11 | Position containment | A seal whose chain position lies outside its epoch's interval is refused, regardless of timestamps |
| K12 | Three-valued verify | Absent material ⇒ exit 3 with UNVERIFIED tags and the NOT-PROVEN text; a bad tag under present material ⇒ exit 4; `--allow-unkeyed` promotes 3→0 and never 4 |
| K13 | v2 coverage | Altering any of the seven identity fields invalidates a v2 MAC; v1 tokens keep verifying under the frozen v1 message |
| K14 | Re-anchoring | `atb anchor --alg` appends exactly one record committing to every archived segment under the new algorithm, editing nothing |
| K15 | Key/chain separation | `ATB_KEY_DIR` inside the chain volume is a startup refusal; a chained `key_ref` is never opened by the broker |
| K16 | Attribution | Decisions carry `key_epoch` when identity verification succeeded and never when it failed; `key show` counts them exactly |
| K17 | Zero migration | A single-key deployment with no epoch records mints, verifies, seals, and rotates its chain exactly as before |

A conformance run that skips any row is a failed run.

---

## QA Checklist

- [x] YAML front matter validated.
- [x] Epoch model: purposes, identifiers, fingerprints, states, and the chained
      record vocabulary defined; legacy adoption bounded to one kidless epoch.
- [x] `auth_kid` sibling-field migration verified against the shipped
      `seal_tag`; no seal-format break.
- [x] Authenticated-record set extended to ATB-06's own record types; tag
      verification extended to the active segment and to `--active-only`.
- [x] Key-epoch registry carried across rotation so a chained revocation cannot
      be un-enforced by a routine rotation.
- [x] Token profiles v1 (frozen) and v2 (full coverage, canonical JSON,
      kid-in-MAC, no caller-supplied algorithm) specified.
- [x] Rotation is one atomic append; revocation refuses on an active epoch;
      dual-sealed seal-key handover.
- [x] Position-only epoch containment; no wall-clock authority anywhere.
- [x] Compromise semantics separated into integrity vs attribution, with
      per-epoch accounting.
- [x] Agility: closed registry, new-values-only, segment-boundary adoption,
      re-anchoring for frozen archives, ATB-02/04 digest coupling flagged.
- [x] Key material: location, separation from the chain volume, never
      resolved from the chain, startup consistency guard.
- [x] Three-valued verification with an explicit downgrade that cannot mask
      tamper.
- [x] Record accounting; engine and all prior conformance counts unchanged.
- [x] CLI and configuration documented; nothing automatic.
- [x] Residuals stated, including the symmetric-crypto limit and the unchained
      identity revocation gap.
- [x] Conformance matrix (K1–K17, plus K5b–K5d) defined.
- [ ] Human review gate completed.

---

## Human Review Gate

Maintainer approval of the key-lifecycle design is required before any
implementing code is written. The review shall verify: no key compromise makes
a historical record unverifiable; key bytes never reach the chain, a log, or a
`repr`; rotation is one atomic, crash-safe append and revocation is never
authenticated by the key it revokes; epoch windows are bound by chain position,
never wall clock; algorithm and kid are taken from the chained epoch, never
from caller-supplied input; verification distinguishes absent material from
tamper and the downgrade cannot mask tamper; the seal format is unchanged;
existing single-key deployments need zero migration; and the residuals —
symmetric-crypto forgeability, truncation un-revocation, plaintext material at
rest, entropy assumptions, self-attested bootstrap, undetected compromise, and
unchained identity revocation — are accepted as documented.

**Reviewer:** ____________________   **Date:** __________   **Decision:** approve / revise

---

## Recommended Next Logical Deliverable

**IANUA-ATB v0.1 — Reference Implementation, Milestone 6:** a stdlib-only
`atb/keys.py` (epoch registry replayed from the chain **and carried in the
ATB-05 checkpoint**, fingerprints, resolver with the scoped startup consistency
guard, closed algorithm registry), the v2 token profile alongside the frozen v1
path, `auth_kid` + `auth_prev` on lifecycle records, the extended
`AUTHENTICATED_TYPES` set with tag verification reaching the active segment,
position-containment and three-valued outcomes in ATB-05 verification, the
`atb key` verb group and `atb anchor`, per-record epoch attribution, and
`.env.example` / `infra/README.md` updates — shipping the K1–K17 (plus K5b–K5d) suite under
`tests/security` and passing the full IANUA gate set from the first commit.
