"""Identity Authority (ATB-01/ATB-02): mint, verify, revoke, delegate.

Credentials are short-lived, scoped, and signed (HMAC over the identity
record) with a key supplied at construction — never hard-coded, never logged.
Verification fails closed: unknown, expired, revoked, or tampered credentials
all verify as invalid. Delegation only attenuates (subset of the *target
role's* binding), is depth-1, and revocation cascades to delegated identities.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from atb.bindings import ROLE_BINDINGS

DEFAULT_TTL_SECONDS = 900  # 15 minutes — long lifetimes require a documented exception


class VerificationError(Exception):
    """Presented credential is invalid; callers must fail closed."""


class DelegationError(Exception):
    """Delegation request violates the ATB-02 delegation rules."""


@dataclass(frozen=True)
class Identity:
    """One issued identity. The signature lives in the token, not the record."""

    identity_id: str
    subject: str
    issued_at: datetime
    not_after: datetime
    scopes: frozenset[str]
    delegatable: bool
    delegated_by: str | None = None


@dataclass
class IdentityAuthority:
    """Issues and verifies scoped, short-lived agent identities."""

    signing_key: bytes
    now: Callable[[], datetime] = lambda: datetime.now(UTC)
    _store: dict[str, Identity] = field(default_factory=dict)
    _revoked: set[str] = field(default_factory=set)
    _sequence: int = 0

    def _sign(self, identity: Identity) -> str:
        message = "|".join(
            (
                identity.identity_id,
                identity.subject,
                identity.not_after.isoformat(),
                ",".join(sorted(identity.scopes)),
            )
        )
        return hmac.new(self.signing_key, message.encode("utf-8"), hashlib.sha256).hexdigest()

    def _issue(
        self,
        subject: str,
        scopes: frozenset[str],
        ttl_seconds: int,
        delegatable: bool,
        delegated_by: str | None,
    ) -> tuple[Identity, str]:
        self._sequence += 1
        issued_at = self.now()
        identity = Identity(
            identity_id=f"ATB-ID-{self._sequence:06d}",
            subject=subject,
            issued_at=issued_at,
            not_after=issued_at + timedelta(seconds=ttl_seconds),
            scopes=scopes,
            delegatable=delegatable,
            delegated_by=delegated_by,
        )
        self._store[identity.identity_id] = identity
        token = f"{identity.identity_id}.{self._sign(identity)}"
        return identity, token

    def mint(self, role: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> tuple[Identity, str]:
        """Mint an identity for a registered role, scoped to its binding."""
        binding = ROLE_BINDINGS.get(role)
        if binding is None:
            raise VerificationError(f"unknown role: {role!r}")
        return self._issue(role, binding.scopes, ttl_seconds, binding.delegatable, None)

    def mint_delegated(
        self,
        delegator_token: str,
        role: str,
        scopes: frozenset[str],
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> tuple[Identity, str]:
        """Mint a depth-1, attenuated identity on behalf of a delegator."""
        delegator = self.verify(delegator_token)
        if not delegator.delegatable:
            raise DelegationError("delegator is not delegatable (depth-1 rule)")
        binding = ROLE_BINDINGS.get(role)
        if binding is None:
            raise DelegationError(f"unknown target role: {role!r}")
        if not scopes <= binding.scopes:
            raise DelegationError("delegated scopes must be a subset of the target role's binding")
        if self.now() + timedelta(seconds=ttl_seconds) > delegator.not_after:
            raise DelegationError("delegated lifetime may not exceed the delegator's")
        return self._issue(
            role, scopes, ttl_seconds, delegatable=False, delegated_by=delegator.identity_id
        )

    def verify(self, token: str) -> Identity:
        """Validate a presented token; raise VerificationError on any defect."""
        identity_id, _, signature = token.partition(".")
        identity = self._store.get(identity_id)
        if identity is None:
            raise VerificationError("unknown identity")
        if not hmac.compare_digest(signature, self._sign(identity)):
            raise VerificationError("signature mismatch")
        if identity.identity_id in self._revoked:
            raise VerificationError("identity revoked")
        if self.now() >= identity.not_after:
            raise VerificationError("identity expired")
        return identity

    def revoke(self, identity_id: str) -> None:
        """Revoke an identity and cascade to every identity it delegated."""
        self._revoked.add(identity_id)
        for candidate in self._store.values():
            if candidate.delegated_by == identity_id:
                self._revoked.add(candidate.identity_id)
