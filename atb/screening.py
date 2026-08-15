"""Tool-response content screening (ATB-04): deterministic trust signal.

A ``ResponseScreener`` classifies the value a downstream tool returned —
textualize, digest, count invisible characters, normalize, then evaluate a
versioned closed-world ruleset. The screener is a *sensor*: it never
authorizes, never denies, and never enqueues. The authority question a flag
raises ("may this content reach the agent?") is answered exclusively by
``PolicyEngine.authorize`` on the cataloged ``atb:response.release`` scope;
the PEP orchestrates that in ``atb.enforcement``.

Security considerations (fail-closed by construction):

- **Deterministic and stdlib-only.** Same response bytes + same
  ``RULESET_VERSION`` (on the same interpreter build) => identical verdict.
  The ruleset is code, not config: a frozen tuple validated at import,
  changed only by reviewed PR with a version bump. ``rules_digest``
  incorporates the Unicode data version so provenance survives upgrades.
- **Verdicts only tighten.** ``cause == "clean"`` carries no authority and
  is deliberately unadvertised downstream; every non-clean cause withholds.
- **No payload in evidence.** ``ScreenVerdict`` carries rule ids, version,
  digest, and counts. The canonical payload bytes ride only on
  ``ScreenVerdict.payload`` for the PEP to quarantine — they must never be
  chained, logged, or placed in any agent-facing surface.
- **Bounded cost.** Size gates run before hashing: beyond the per-blob cap
  nothing is hashed or stored; between the scan cap and the blob cap the
  content is digested and quarantined unscanned (releasable ``oversize``).
- **Quarantine stores are content-addressed and read-verified.** ``get``
  re-hashes on every read, so a torn or tampered blob is indistinguishable
  from an absent one and is never served. ``FileQuarantineStore`` writes via
  temp-file + fsync + atomic rename (a file existing under a digest name is
  complete by construction) and self-heals a corrupt blob on the next put.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Protocol, runtime_checkable

RULESET_VERSION = "0.1.0"
SCREENING_REFUSAL = "screening_refusal"
RELEASE_ACTION = "atb:response.release"

DEFAULT_SCREEN_MAX_BYTES = 1_048_576
DEFAULT_QUARANTINE_MAX_BYTES = 16_777_216
DEFAULT_QUARANTINE_BUDGET_BYTES = 268_435_456

_DIGEST_HEX = re.compile(r"sha256:[0-9a-f]{64}\Z")

#: Verdict causes that keep a human release path open (content quarantined).
RELEASABLE_CAUSES = frozenset({"rules", "oversize", "undecodable"})

_ZERO_WIDTH_THRESHOLD = 8
_BIDI_CONTROLS = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
_ALLOWED_CONTROLS = frozenset("\t\n\r")


class Plane(Enum):
    """Which text plane a rule scans (ATB-04 normalization pipeline)."""

    NORMALIZED = "normalized"
    RAW = "raw"
    COUNTERS = "counters"


@dataclass(frozen=True)
class ScreenRule:
    """One closed-world screening rule; ``pattern`` is None only for COUNTERS."""

    rule_id: str
    name: str
    plane: Plane
    pattern: re.Pattern[str] | None
    description: str


def _norm(pattern: str) -> re.Pattern[str]:
    """Compile a NORMALIZED-plane pattern; DOTALL so bounded gaps cross newlines."""
    return re.compile(pattern, re.DOTALL)


RULESET: tuple[ScreenRule, ...] = (
    ScreenRule(
        "ATB-R001",
        "instruction_override",
        Plane.NORMALIZED,
        _norm(
            r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|earlier|above)\b"
            r".{0,40}\b(instructions?|prompts?|rules|context)\b"
        ),
        "canonical injection preamble overriding prior instructions",
    ),
    ScreenRule(
        "ATB-R002",
        "system_prompt_disclosure",
        Plane.NORMALIZED,
        _norm(
            r"\b(reveal|show|print|repeat|leak|output)\b.{0,40}"
            r"\b(system|developer|hidden)\b\s+(prompt|instructions?|message)\b"
        ),
        "steering the agent to disclose its own instructions",
    ),
    ScreenRule(
        "ATB-R003",
        "role_reassignment",
        Plane.NORMALIZED,
        _norm(
            r"\byou\s+are\s+(now|no\s+longer)\b|\bnew\s+persona\b"
            r"|\bact\s+as\s+(?:an?\s+)?(unrestricted|jailbroken|dan)\b"
        ),
        "persona-hijack framing",
    ),
    ScreenRule(
        "ATB-R004",
        "tool_steering_exfiltration",
        Plane.NORMALIZED,
        _norm(
            r"\b(call|invoke|use)\s+(?:the\s+)?(http_fetch|mint_sub_identity|corpus_ingest)\b"
            r"|\b(send|post|upload|exfiltrate)\b.{0,40}\bhttps?://"
        ),
        "steering toward high-risk mediated tools or URL exfiltration",
    ),
    ScreenRule(
        "ATB-R005",
        "protocol_marker_smuggling",
        Plane.NORMALIZED,
        _norm(
            r"</?(system|assistant|tool_result|function_call)\b[^>]{0,80}>"
            r"|\"jsonrpc\"\s*:|\batb_token\b"
        ),
        "forged conversation/protocol frames or token fishing",
    ),
    ScreenRule(
        "ATB-R006",
        "invisible_text_obfuscation",
        Plane.COUNTERS,
        None,
        "zero-width flooding, bidi overrides, or stray control characters",
    ),
    ScreenRule(
        "ATB-R007",
        "encoded_payload_blob",
        Plane.RAW,
        re.compile(r"[A-Za-z0-9+/=]{200,8192}"),
        "large base64-like block (flagged as ciphertext; never decoded)",
    ),
    ScreenRule(
        "ATB-R008",
        "approval_steering",
        Plane.NORMALIZED,
        _norm(
            r"\b(use|pass|set|include|supply)\b.{0,30}\bapproval_ref\b"
            r"|\batb-dec-\d{6}\b.{0,40}\bapprove\b"
        ),
        "coaching the agent to spend or solicit approvals",
    ),
    ScreenRule(
        "ATB-R009",
        "secret_material",
        Plane.RAW,
        re.compile(
            # Bounded repeats plus a run-start guard on the JWT alternative
            # (its two runs straddle a mandatory ``.``): the negative
            # lookbehind makes only run-initial ``eyJ`` a candidate start, so
            # the worst case is linear in the scan cap, not quadratic. Bounds
            # alone are insufficient here — the lookbehind is load-bearing.
            r"AKIA[0-9A-Z]{16}"
            r"|-----BEGIN[A-Z ]{0,30}PRIVATE KEY-----"
            r"|xox[baprs]-[0-9A-Za-z-]{10,4096}"
            r"|(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,4096}\.eyJ[A-Za-z0-9_-]{10,8192}"
        ),
        "credential material transiting into agent context",
    ),
)


def validate_ruleset(rules: tuple[ScreenRule, ...]) -> None:
    """Fail closed on duplicate ids or missing patterns (mirrors T11)."""
    seen: set[str] = set()
    for rule in rules:
        if rule.rule_id in seen:
            raise ValueError(f"duplicate screening rule id: {rule.rule_id}")
        seen.add(rule.rule_id)
        if rule.plane is Plane.COUNTERS:
            if rule.pattern is not None:
                raise ValueError(f"COUNTERS rule {rule.rule_id} must not carry a pattern")
        elif rule.pattern is None:
            raise ValueError(f"rule {rule.rule_id} has no pattern")


# Fail closed at import time: a malformed ruleset is a defect.
validate_ruleset(RULESET)


def rules_digest(rules: tuple[ScreenRule, ...] = RULESET) -> str:
    """Provenance digest over the canonical ruleset + Unicode data version.

    COUNTERS rules carry no regex, so their operative parameters (the
    zero-width threshold, the bidi-override set, the allowed controls) are
    folded in explicitly — otherwise a threshold change would leave the
    digest unchanged and the provenance claim would be false.
    """
    canonical = json.dumps(
        {
            "rules": [
                {
                    "id": rule.rule_id,
                    "name": rule.name,
                    "plane": rule.plane.value,
                    "pattern": rule.pattern.pattern if rule.pattern else "",
                }
                for rule in rules
            ],
            "counters": {
                "zero_width_threshold": _ZERO_WIDTH_THRESHOLD,
                "bidi_controls": sorted(f"U+{ord(c):04X}" for c in _BIDI_CONTROLS),
                "allowed_controls": sorted(f"U+{ord(c):04X}" for c in _ALLOWED_CONTROLS),
            },
            "unicodedata": unicodedata.unidata_version,
            "version": RULESET_VERSION,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


RULES_DIGEST = rules_digest()


@dataclass(frozen=True)
class ScreenVerdict:
    """Deterministic screening outcome. Evidence only — never response text.

    ``payload`` carries the canonical bytes solely so the PEP can quarantine
    them; it must never be chained, logged, or placed on an agent-facing
    surface, and is None when nothing storable exists.
    """

    # clean | rules | oversize | undecodable | response_oversized | textualization_failed
    cause: str
    rule_ids: tuple[str, ...]
    ruleset_version: str
    rules_digest: str
    digest: str  # "sha256:<hex>", or "" when nothing was hashed
    size_bytes: int
    invisible_count: int
    payload: bytes | None

    @property
    def releasable(self) -> bool:
        """True when the content is quarantined and a human may release it."""
        return self.cause in RELEASABLE_CAUSES


def _sha256(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _textualize(result: object) -> tuple[bytes | None, str | None, str]:
    """Canonicalize a downstream result to (bytes, text, cause).

    ``repr`` is never used as a fallback: it is not canonical and may embed
    addresses, which would break verdict determinism and digest stability.
    """
    if isinstance(result, str):
        return result.encode("utf-8"), result, "ok"
    if isinstance(result, (bytes, bytearray)):
        raw = bytes(result)
        try:
            return raw, raw.decode("utf-8"), "ok"
        except UnicodeDecodeError:
            return raw, None, "undecodable"
    try:
        text = json.dumps(
            result, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        )
    except (TypeError, ValueError, RecursionError):
        return None, None, "textualization_failed"
    return text.encode("utf-8"), text, "ok"


def _census(text: str) -> tuple[int, bool, bool]:
    """Count Cf characters; detect bidi overrides and stray C0/C1 controls."""
    cf_count = 0
    bidi = False
    stray_control = False
    for ch in text:
        category = unicodedata.category(ch)
        if category == "Cf":
            cf_count += 1
            if ch in _BIDI_CONTROLS:
                bidi = True
        elif category == "Cc" and ch not in _ALLOWED_CONTROLS:
            stray_control = True
    return cf_count, bidi, stray_control


def _normalize(text: str) -> str:
    """Scan-plane normalization: strip Cf, NFKC-fold, casefold."""
    stripped = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return unicodedata.normalize("NFKC", stripped).casefold()


@dataclass(frozen=True)
class ResponseScreener:
    """Pure, deterministic classifier over downstream results (ATB-04)."""

    rules: tuple[ScreenRule, ...] = RULESET
    version: str = RULESET_VERSION
    max_scan_bytes: int = DEFAULT_SCREEN_MAX_BYTES
    max_blob_bytes: int = DEFAULT_QUARANTINE_MAX_BYTES

    def __post_init__(self) -> None:
        # A custom ruleset meets the same import-time bar (T11 mirror).
        validate_ruleset(self.rules)
        if self.max_scan_bytes <= 0 or self.max_blob_bytes < self.max_scan_bytes:
            raise ValueError("screening caps must be positive and blob cap >= scan cap")

    @property
    def rules_digest(self) -> str:
        """Provenance digest for this screener's ruleset."""
        return rules_digest(self.rules)

    def _verdict(
        self,
        cause: str,
        rule_ids: tuple[str, ...] = (),
        digest: str = "",
        size_bytes: int = 0,
        invisible_count: int = 0,
        payload: bytes | None = None,
    ) -> ScreenVerdict:
        return ScreenVerdict(
            cause=cause,
            rule_ids=rule_ids,
            ruleset_version=self.version,
            rules_digest=self.rules_digest,
            digest=digest,
            size_bytes=size_bytes,
            invisible_count=invisible_count,
            payload=payload,
        )

    def screen(self, result: object) -> ScreenVerdict:
        """Classify one downstream result; pure and deterministic."""
        raw, text, cause = _textualize(result)
        if cause == "textualization_failed" or raw is None:
            return self._verdict("textualization_failed")
        size = len(raw)
        if size > self.max_blob_bytes:
            # Nothing is hashed or stored beyond the blob cap (bounded cost).
            return self._verdict("response_oversized", size_bytes=size)
        digest = _sha256(raw)
        if cause == "undecodable":
            return self._verdict("undecodable", digest=digest, size_bytes=size, payload=raw)
        if size > self.max_scan_bytes:
            return self._verdict("oversize", digest=digest, size_bytes=size, payload=raw)
        if text is None:  # unreachable by construction; fail closed regardless
            return self._verdict("textualization_failed")
        cf_count, bidi, stray_control = _census(text)
        normalized = _normalize(text)
        matched: list[str] = []
        for rule in self.rules:
            if rule.plane is Plane.COUNTERS:
                if cf_count >= _ZERO_WIDTH_THRESHOLD or bidi or stray_control:
                    matched.append(rule.rule_id)
            elif rule.pattern is not None:
                plane_text = normalized if rule.plane is Plane.NORMALIZED else text
                if rule.pattern.search(plane_text):
                    matched.append(rule.rule_id)
        if matched:
            return self._verdict(
                "rules",
                rule_ids=tuple(matched),
                digest=digest,
                size_bytes=size,
                invisible_count=cf_count,
                payload=raw,
            )
        return self._verdict(
            "clean", digest=digest, size_bytes=size, invisible_count=cf_count, payload=None
        )


class QuarantineError(Exception):
    """Quarantined content cannot be stored (budget, cap, or I/O failure)."""


@runtime_checkable
class QuarantineStore(Protocol):
    """Content-addressed holding store for withheld response payloads."""

    def put(self, content: bytes) -> str:
        """Store content; return its ``sha256:<hex>`` digest. Idempotent."""
        ...  # pragma: no cover - protocol definition

    def get(self, digest: str) -> bytes | None:
        """Return verified content, or None when absent or corrupt."""
        ...  # pragma: no cover - protocol definition

    def total_bytes(self) -> int:
        """Aggregate stored size, for budget enforcement."""
        ...  # pragma: no cover - protocol definition


@dataclass
class MemoryQuarantineStore:
    """In-memory store: demo parity with the in-memory audit chain."""

    budget_bytes: int = DEFAULT_QUARANTINE_BUDGET_BYTES
    _blobs: dict[str, bytes] = field(default_factory=dict)

    def put(self, content: bytes) -> str:
        digest = _sha256(content)
        if digest in self._blobs:
            return digest
        if self.total_bytes() + len(content) > self.budget_bytes:
            raise QuarantineError("quarantine budget exceeded")
        self._blobs[digest] = bytes(content)
        return digest

    def get(self, digest: str) -> bytes | None:
        content = self._blobs.get(digest)
        if content is None or _sha256(content) != digest:
            return None
        return content

    def total_bytes(self) -> int:
        return sum(len(content) for content in self._blobs.values())


@dataclass
class FileQuarantineStore:
    """Durable content-addressed store: 0o700 dir, 0o600 write-once blobs.

    Filenames are the hex digest, so attacker-controlled bytes never
    influence the path. Writes are temp-file + fsync + atomic rename; a
    file existing under a digest name is therefore complete by
    construction, and a corrupt blob self-heals on the next put.
    """

    root: Path
    budget_bytes: int = DEFAULT_QUARANTINE_BUDGET_BYTES

    def __post_init__(self) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.root.chmod(0o700)

    def _path(self, digest: str) -> Path:
        if not _DIGEST_HEX.fullmatch(digest):
            raise QuarantineError(f"malformed digest: {digest!r}")
        return self.root / digest.removeprefix("sha256:")

    def put(self, content: bytes) -> str:
        digest = _sha256(content)
        path = self._path(digest)
        try:
            existing_ok = path.is_file() and _sha256(path.read_bytes()) == digest
        except OSError:
            # An unreadable existing blob is treated as corrupt: fall through
            # and rewrite it. Any store fault stays inside QuarantineError so
            # the PEP can never confuse it with a downstream transport failure.
            existing_ok = False
        if existing_ok:
            return digest  # idempotent: identical bytes by construction
        if self.total_bytes() + len(content) > self.budget_bytes:
            raise QuarantineError("quarantine budget exceeded")
        temp = self.root / f".tmp-{digest.removeprefix('sha256:')}"
        try:
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, content)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(temp, path)
        except OSError as exc:
            temp.unlink(missing_ok=True)
            raise QuarantineError(f"quarantine write failed: {exc.__class__.__name__}") from exc
        return digest

    def get(self, digest: str) -> bytes | None:
        try:
            path = self._path(digest)
        except QuarantineError:
            return None
        try:
            content = path.read_bytes()
        except OSError:
            return None
        if _sha256(content) != digest:
            return None  # torn or tampered: never served
        return content

    def total_bytes(self) -> int:
        total = 0
        try:
            entries = list(self.root.iterdir())
        except OSError as exc:
            raise QuarantineError(f"quarantine scan failed: {exc.__class__.__name__}") from exc
        for entry in entries:
            if entry.name.startswith(".tmp-"):
                continue
            try:
                if entry.is_file():
                    total += entry.stat().st_size
            except FileNotFoundError:
                continue  # vanished mid-scan (e.g. concurrent purge): skip
            except OSError as exc:
                raise QuarantineError(f"quarantine scan failed: {exc.__class__.__name__}") from exc
        return total
