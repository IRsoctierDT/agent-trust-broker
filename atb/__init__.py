"""IANUA Agent Trust Broker (ATB).

Identity issuance and Zero-Trust policy enforcement for the IANUA agent fleet.
Reference implementation of PAT-0001 / EAODS-CTRL-000184 (see docs/).
"""

from atb.audit import AuditLog
from atb.bindings import ROLE_BINDINGS, RoleBinding
from atb.catalog import CATALOG, ScopeSpec, validate_bindings
from atb.identity import DelegationError, Identity, IdentityAuthority, VerificationError
from atb.policy import Decision, PolicyEngine

__all__ = [
    "CATALOG",
    "ROLE_BINDINGS",
    "AuditLog",
    "Decision",
    "DelegationError",
    "Identity",
    "IdentityAuthority",
    "PolicyEngine",
    "RoleBinding",
    "ScopeSpec",
    "VerificationError",
    "validate_bindings",
]
