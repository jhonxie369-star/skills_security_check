"""
Prompt Guard - AI prompt injection detection library (v3.2.0)

577+ attack patterns | 11 SHIELD categories | 10 languages

Standalone Mode (default — no API, no internet required):
    from skills_security_check import SkillsSecurityCheck
    guard = SkillsSecurityCheck()
    result = guard.analyze("user message")

API-Enhanced Mode (optional — latest patterns + threat intelligence):
    # Pull newest patterns, report anonymized threats

v3.2.0: Skill Weaponization Defense
- 27 new patterns: reverse shell, SSH injection, exfiltration, cognitive rootkit, semantic worm
- Optional API client for live pattern updates + anonymized threat reporting

v3.1.0: Token Optimization
- Tiered pattern loading (70% reduction)
- Message hash cache (90% reduction for repeats)
"""

__version__ = "3.2.0"

from skills_security_check.models import Severity, Action, DetectionResult, SanitizeResult
from skills_security_check.engine import SkillsSecurityCheck
from skills_security_check.cache import MessageCache, get_cache
from skills_security_check.pattern_loader import TieredPatternLoader, LoadTier, get_loader

# The API client is optional. Import it explicitly when needed:

__all__ = [
    # Core (always available, no network required)
    "SkillsSecurityCheck",
    "Severity",
    "Action",
    "DetectionResult",
    "SanitizeResult",
    "MessageCache",
    "get_cache",
    "TieredPatternLoader",
    "LoadTier",
    "get_loader",
    "__version__",
]
