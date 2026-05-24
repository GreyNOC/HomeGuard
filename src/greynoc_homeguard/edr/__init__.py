"""HomeGuard EDR foundation - Phase 1.

This package is the *foundation* for a defensive endpoint-detection-and-response
layer. Phase 1 is intentionally narrow: an evidence + assessment data model
plus a function that maps existing HomeGuard endpoint findings into a single
:class:`EndpointAssessment` with a careful compromise-level call.

Later phases will add process trees, event collection, YARA, correlation,
response, and continuous monitoring. None of that lives here yet.

Defensive-only contract (do not change without security review):
  * No exploit / credential-dumping / bypass / payload code.
  * No process killing, file quarantining, or firewall mutation.
  * No outbound telemetry. Evidence stays on the host.

HomeGuard does not guess. It builds an evidence chain.
"""

from .assessment import (
    ALL_LEVELS,
    LEVEL_CLEAN,
    LEVEL_CONFIRMED_COMPROMISE,
    LEVEL_LIKELY_COMPROMISE,
    LEVEL_NOT_RUN,
    LEVEL_REVIEW_INDICATOR,
    LEVEL_SUSPICIOUS_ACTIVITY,
    assess_endpoint_findings,
    level_rank,
    normalize_level,
)
from .models import EndpointAssessment, EvidenceChain, EvidenceItem

__all__ = [
    "ALL_LEVELS",
    "LEVEL_CLEAN",
    "LEVEL_CONFIRMED_COMPROMISE",
    "LEVEL_LIKELY_COMPROMISE",
    "LEVEL_NOT_RUN",
    "LEVEL_REVIEW_INDICATOR",
    "LEVEL_SUSPICIOUS_ACTIVITY",
    "EndpointAssessment",
    "EvidenceChain",
    "EvidenceItem",
    "assess_endpoint_findings",
    "level_rank",
    "normalize_level",
]
