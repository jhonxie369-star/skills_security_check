"""
Prompt Guard - Pattern scanner.

v4.0.0: Single scan entry point. All patterns loaded from YAML via TieredPatternLoader.
No more hardcoded patterns in this file.
"""

import re
import logging
from typing import Tuple, List, Dict

from skills_security_check.models import Severity
from skills_security_check.pattern_loader import TieredPatternLoader, LoadTier, get_loader

logger = logging.getLogger("skills_security_check")

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


def scan_text_for_patterns(text: str) -> Tuple[List[str], List[str], Severity]:
    """
    Run all loaded YAML patterns against text.
    Returns (reasons, patterns_matched, max_severity).
    """
    reasons, patterns_matched, max_severity, _ = scan_text_with_context(text)
    return reasons, patterns_matched, max_severity


def scan_text_with_context(text: str, context_lines: int = 5) -> Tuple[List[str], List[str], Severity, List[Dict]]:
    """
    Run all loaded YAML patterns against text with match context capture.
    Returns (reasons, patterns_matched, max_severity, match_contexts).
    """
    reasons = []
    patterns_matched = []
    match_contexts = []
    max_severity = Severity.SAFE
    text_lower = text.lower()
    text_lines = text.splitlines()

    loader = get_loader()
    if not loader.tiers[LoadTier.CRITICAL].loaded:
        loader.load_tier(LoadTier.HIGH)

    for entry in loader.get_patterns():
        if not entry.compiled:
            continue
        try:
            match = entry.compiled.search(text_lower)
            if not match:
                continue

            sev = _SEVERITY_MAP.get(entry.severity, Severity.MEDIUM)
            if sev.value > max_severity.value:
                max_severity = sev

            cat_key = f"{entry.category}_{entry.lang}" if entry.lang != "en" else entry.category
            if cat_key not in reasons:
                reasons.append(cat_key)
            patterns_matched.append(f"{entry.lang}:{entry.category}:{entry.pattern[:40]}")

            # Capture context
            start_pos = match.start()
            line_num = text[:start_pos].count('\n')
            start_line = max(0, line_num - context_lines)
            end_line = min(len(text_lines), line_num + context_lines + 1)
            match_contexts.append({
                "pattern": entry.pattern[:100],
                "category": cat_key,
                "matched_text": match.group(0),
                "line_number": line_num + 1,
                "context": text_lines[start_line:end_line],
                "context_range": f"{start_line + 1}-{end_line}",
            })
        except re.error as e:
            logger.warning("Regex error in %s: %s", entry.category, e)

    return reasons, patterns_matched, max_severity, match_contexts
