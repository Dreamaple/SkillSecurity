"""Privacy protection layer — data classification, outbound inspection, financial detection, chat protection."""

from __future__ import annotations

from skillsecurity.privacy.chat import ChatDetector, ChatMatch
from skillsecurity.privacy.classifier import DataClassifier, SensitiveMatch
from skillsecurity.privacy.domains import DomainIntelligence, TrustLevel
from skillsecurity.privacy.financial import FinancialDetector, FinancialMatch
from skillsecurity.privacy.outbound import InspectionResult, OutboundInspector

__all__ = [
    "ChatDetector",
    "ChatMatch",
    "DataClassifier",
    "DomainIntelligence",
    "FinancialDetector",
    "FinancialMatch",
    "InspectionResult",
    "OutboundInspector",
    "SensitiveMatch",
    "TrustLevel",
]
