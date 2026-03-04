"""
Prompt Guard - Pattern scanner.

Runs all pattern sets against a single text string.
Used for scanning both original and decoded text.

SECURITY FIX (HIGH-002): All pattern sets from the engine are now included
here so the decode-then-scan pipeline has full coverage.
"""

import re
import logging
from typing import Tuple, List, Dict

from skills_security_check.models import Severity
from skills_security_check.patterns import (
    CRITICAL_PATTERNS,
    SECRET_PATTERNS,
    PATTERNS_EN, PATTERNS_KO, PATTERNS_JA, PATTERNS_ZH,
    PATTERNS_RU, PATTERNS_ES, PATTERNS_DE, PATTERNS_FR,
    PATTERNS_PT, PATTERNS_VI,
    SCENARIO_JAILBREAK, EMOTIONAL_MANIPULATION, AUTHORITY_RECON,
    COGNITIVE_MANIPULATION, PHISHING_SOCIAL_ENG, SYSTEM_FILE_ACCESS,
    MALWARE_DESCRIPTION, INDIRECT_INJECTION, CONTEXT_HIJACKING,
    SAFETY_BYPASS,
    # v2.5.0 patterns previously missing
    MULTI_TURN_MANIPULATION, TOKEN_SMUGGLING, PROMPT_EXTRACTION,
    URGENCY_MANIPULATION, SYSTEM_PROMPT_MIMICRY, REPETITION_ATTACK,
    # v2.5.2 patterns previously missing
    JSON_INJECTION_MOLTBOOK, GUARDRAIL_BYPASS_EXTENDED,
    AGENT_SOVEREIGNTY_MANIPULATION, EXPLICIT_CALL_TO_ACTION,
    # v2.6.1 patterns previously missing
    ALLOWLIST_BYPASS, HOOKS_HIJACKING, SUBAGENT_EXPLOITATION,
    HIDDEN_TEXT_INJECTION, GITIGNORE_BYPASS,
    # v2.7.0 patterns previously missing
    AUTO_APPROVE_EXPLOIT, LOG_CONTEXT_EXPLOIT, MCP_ABUSE,
    PREFILLED_URL, UNICODE_TAG_DETECTION, BROWSER_AGENT_INJECTION,
    HIDDEN_TEXT_HINTS,
    # v3.0.1 patterns (HiveFence Scout Round 3)
    OUTPUT_PREFIX_INJECTION, BENIGN_FINETUNING_ATTACK, PROMPTWARE_KILLCHAIN,
    # v3.1.0 patterns (HiveFence Scout Round 4 - 2026-02-08)
    CAUSAL_MECHANISTIC_ATTACKS, AGENT_TOOL_ATTACKS, TEMPLATE_CHAT_ATTACKS,
    EVASION_STEALTH_ATTACKS, MULTIMODAL_PHYSICAL_ATTACKS, DEFENSE_BYPASS_ANALYSIS,
    INFRASTRUCTURE_PROTOCOL_ATTACKS,
    # v3.2.0 patterns - Skill Weaponization Defense (Min Hong Analysis)
    SKILL_REVERSE_SHELL, SKILL_SSH_INJECTION, SKILL_EXFILTRATION_PIPELINE,
    SKILL_COGNITIVE_ROOTKIT, SKILL_SEMANTIC_WORM, SKILL_OBFUSCATED_PAYLOAD,
)

logger = logging.getLogger("skills_security_check")


def scan_text_for_patterns(text: str) -> Tuple[List[str], List[str], Severity]:
    """
    Run all pattern sets against a single text string.
    Returns (reasons, patterns_matched, max_severity).
    Used for scanning both original and decoded text.
    """
    reasons, patterns_matched, max_severity, _ = scan_text_with_context(text)
    return reasons, patterns_matched, max_severity


def scan_text_with_context(text: str, context_lines: int = 5) -> Tuple[List[str], List[str], Severity, List[Dict]]:
    """
    Run all pattern sets against a single text string with context capture.
    Returns (reasons, patterns_matched, max_severity, match_contexts).
    """
    reasons = []
    patterns_matched = []
    match_contexts = []
    max_severity = Severity.SAFE
    text_lower = text.lower()
    text_lines = text.splitlines()

    def add_match_context(pattern: str, match_obj, category: str):
        """Helper to capture context around a match."""
        if not match_obj:
            return
        start_pos = match_obj.start()
        # Find line number
        line_num = text[:start_pos].count('\n')
        start_line = max(0, line_num - context_lines)
        end_line = min(len(text_lines), line_num + context_lines + 1)
        
        match_contexts.append({
            "pattern": pattern[:100],
            "category": category,
            "matched_text": match_obj.group(0),
            "line_number": line_num + 1,
            "context": text_lines[start_line:end_line],
            "context_range": f"{start_line + 1}-{end_line}"
        })

    # Critical patterns
    for pattern in CRITICAL_PATTERNS:
        try:
            match = re.search(pattern, text_lower, re.IGNORECASE)
            if match:
                reasons.append("critical_pattern")
                patterns_matched.append(pattern)
                max_severity = Severity.CRITICAL
                add_match_context(pattern, match, "critical_pattern")
        except re.error as e:
            logger.warning("Regex error in CRITICAL_PATTERNS: %s", e)

    # Secret patterns
    for lang, patterns in SECRET_PATTERNS.items():
        for pattern in patterns:
            try:
                match = re.search(pattern, text_lower, re.IGNORECASE)
                if match:
                    max_severity = Severity.CRITICAL
                    reasons.append(f"secret_request_{lang}")
                    patterns_matched.append(f"{lang}:secret:{pattern[:40]}")
                    add_match_context(pattern, match, f"secret_request_{lang}")
            except re.error as e:
                logger.warning("Regex error in SECRET_PATTERNS[%s]: %s", lang, e)

    # Language-specific patterns
    all_lang_patterns = [
        (PATTERNS_EN, "en"), (PATTERNS_KO, "ko"), (PATTERNS_JA, "ja"),
        (PATTERNS_ZH, "zh"), (PATTERNS_RU, "ru"), (PATTERNS_ES, "es"),
        (PATTERNS_DE, "de"), (PATTERNS_FR, "fr"), (PATTERNS_PT, "pt"),
        (PATTERNS_VI, "vi"),
    ]
    severity_map = {
        "instruction_override": Severity.HIGH,
        "role_manipulation": Severity.MEDIUM,
        "system_impersonation": Severity.HIGH,
        "jailbreak": Severity.HIGH,
        "output_manipulation": Severity.LOW,
        "data_exfiltration": Severity.CRITICAL,
        "social_engineering": Severity.HIGH,
    }
    for pattern_set, lang in all_lang_patterns:
        for category, patterns in pattern_set.items():
            for pattern in patterns:
                try:
                    match = re.search(pattern, text_lower, re.IGNORECASE)
                    if match:
                        cat_severity = severity_map.get(category, Severity.MEDIUM)
                        if cat_severity.value > max_severity.value:
                            max_severity = cat_severity
                        reasons.append(f"{category}_{lang}")
                        patterns_matched.append(f"{lang}:{pattern[:50]}")
                        add_match_context(pattern, match, f"{category}_{lang}")
                except re.error as e:
                    logger.warning("Regex error in PATTERNS_%s[%s]: %s", lang, category, e)

    # ALL versioned pattern sets (SECURITY FIX: complete set)
    versioned_sets = [
        # v2.4.0
        (SCENARIO_JAILBREAK, "scenario_jailbreak", Severity.HIGH),
        (EMOTIONAL_MANIPULATION, "emotional_manipulation", Severity.HIGH),
        (AUTHORITY_RECON, "authority_recon", Severity.MEDIUM),
        (COGNITIVE_MANIPULATION, "cognitive_manipulation", Severity.MEDIUM),
        (PHISHING_SOCIAL_ENG, "phishing_social_eng", Severity.CRITICAL),
        (SYSTEM_FILE_ACCESS, "system_file_access", Severity.CRITICAL),
        (MALWARE_DESCRIPTION, "malware_description", Severity.HIGH),
        (REPETITION_ATTACK, "repetition_attack", Severity.HIGH),
        # v2.5.0
        (INDIRECT_INJECTION, "indirect_injection", Severity.HIGH),
        (CONTEXT_HIJACKING, "context_hijacking", Severity.MEDIUM),
        (MULTI_TURN_MANIPULATION, "multi_turn_manipulation", Severity.MEDIUM),
        (TOKEN_SMUGGLING, "token_smuggling", Severity.HIGH),
        (PROMPT_EXTRACTION, "prompt_extraction", Severity.CRITICAL),
        (SAFETY_BYPASS, "safety_bypass", Severity.HIGH),
        (URGENCY_MANIPULATION, "urgency_manipulation", Severity.MEDIUM),
        (SYSTEM_PROMPT_MIMICRY, "system_prompt_mimicry", Severity.CRITICAL),
        # v2.5.2
        (JSON_INJECTION_MOLTBOOK, "json_injection_moltbook", Severity.HIGH),
        (GUARDRAIL_BYPASS_EXTENDED, "guardrail_bypass_extended", Severity.CRITICAL),
        (AGENT_SOVEREIGNTY_MANIPULATION, "agent_sovereignty_manipulation", Severity.HIGH),
        (EXPLICIT_CALL_TO_ACTION, "explicit_call_to_action", Severity.CRITICAL),
        # v2.6.1
        (ALLOWLIST_BYPASS, "allowlist_bypass", Severity.CRITICAL),
        (HOOKS_HIJACKING, "hooks_hijacking", Severity.CRITICAL),
        (SUBAGENT_EXPLOITATION, "subagent_exploitation", Severity.CRITICAL),
        (HIDDEN_TEXT_INJECTION, "hidden_text_injection", Severity.HIGH),
        (GITIGNORE_BYPASS, "gitignore_bypass", Severity.HIGH),
        # v2.7.0
        (AUTO_APPROVE_EXPLOIT, "auto_approve_exploit", Severity.CRITICAL),
        (LOG_CONTEXT_EXPLOIT, "log_context_exploit", Severity.HIGH),
        (MCP_ABUSE, "mcp_abuse", Severity.CRITICAL),
        (PREFILLED_URL, "prefilled_url_exfiltration", Severity.CRITICAL),
        (UNICODE_TAG_DETECTION, "unicode_tag_injection", Severity.CRITICAL),
        (BROWSER_AGENT_INJECTION, "browser_agent_injection", Severity.HIGH),
        (HIDDEN_TEXT_HINTS, "hidden_text_hints", Severity.HIGH),
        # v3.0.1 - HiveFence Scout Round 3
        (OUTPUT_PREFIX_INJECTION, "output_prefix_injection", Severity.HIGH),
        (BENIGN_FINETUNING_ATTACK, "benign_finetuning_attack", Severity.HIGH),
        (PROMPTWARE_KILLCHAIN, "promptware_killchain", Severity.CRITICAL),
        # v3.1.0 - HiveFence Scout Round 4 (2026-02-08)
        (CAUSAL_MECHANISTIC_ATTACKS, "causal_mechanistic_attack", Severity.HIGH),
        (AGENT_TOOL_ATTACKS, "agent_tool_attack", Severity.CRITICAL),
        (TEMPLATE_CHAT_ATTACKS, "template_chat_attack", Severity.HIGH),
        (EVASION_STEALTH_ATTACKS, "evasion_stealth_attack", Severity.HIGH),
        (MULTIMODAL_PHYSICAL_ATTACKS, "multimodal_physical_attack", Severity.HIGH),
        (DEFENSE_BYPASS_ANALYSIS, "defense_bypass_analysis", Severity.HIGH),
        (INFRASTRUCTURE_PROTOCOL_ATTACKS, "infrastructure_protocol_attack", Severity.CRITICAL),
        # v3.2.0 - Skill Weaponization Defense (Min Hong Analysis - 2026-02-11)
        (SKILL_REVERSE_SHELL, "skill_reverse_shell", Severity.CRITICAL),
        (SKILL_SSH_INJECTION, "skill_ssh_injection", Severity.CRITICAL),
        (SKILL_EXFILTRATION_PIPELINE, "skill_exfiltration_pipeline", Severity.CRITICAL),
        (SKILL_COGNITIVE_ROOTKIT, "skill_cognitive_rootkit", Severity.CRITICAL),
        (SKILL_SEMANTIC_WORM, "skill_semantic_worm", Severity.HIGH),
        (SKILL_OBFUSCATED_PAYLOAD, "skill_obfuscated_payload", Severity.HIGH),
    ]
    for patterns, category, severity in versioned_sets:
        for pattern in patterns:
            try:
                match = re.search(pattern, text_lower, re.IGNORECASE)
                if match:
                    if severity.value > max_severity.value:
                        max_severity = severity
                    if category not in reasons:
                        reasons.append(category)
                    patterns_matched.append(f"versioned:{category}:{pattern[:40]}")
                    add_match_context(pattern, match, category)
            except re.error as e:
                logger.warning("Regex error in %s: %s", category, e)

    return reasons, patterns_matched, max_severity, match_contexts
    """
    Run all pattern sets against a single text string.
    Returns (reasons, patterns_matched, max_severity).
    Used for scanning both original and decoded text.
    """
    reasons = []
    patterns_matched = []
    max_severity = Severity.SAFE
    text_lower = text.lower()

    # Critical patterns
    for pattern in CRITICAL_PATTERNS:
        try:
            if re.search(pattern, text_lower, re.IGNORECASE):
                reasons.append("critical_pattern")
                patterns_matched.append(pattern)
                max_severity = Severity.CRITICAL
        except re.error as e:
            logger.warning("Regex error in CRITICAL_PATTERNS: %s", e)

    # Secret patterns
    for lang, patterns in SECRET_PATTERNS.items():
        for pattern in patterns:
            try:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    max_severity = Severity.CRITICAL
                    reasons.append(f"secret_request_{lang}")
                    patterns_matched.append(f"{lang}:secret:{pattern[:40]}")
            except re.error as e:
                logger.warning("Regex error in SECRET_PATTERNS[%s]: %s", lang, e)

    # Language-specific patterns
    all_lang_patterns = [
        (PATTERNS_EN, "en"), (PATTERNS_KO, "ko"), (PATTERNS_JA, "ja"),
        (PATTERNS_ZH, "zh"), (PATTERNS_RU, "ru"), (PATTERNS_ES, "es"),
        (PATTERNS_DE, "de"), (PATTERNS_FR, "fr"), (PATTERNS_PT, "pt"),
        (PATTERNS_VI, "vi"),
    ]
    severity_map = {
        "instruction_override": Severity.HIGH,
        "role_manipulation": Severity.MEDIUM,
        "system_impersonation": Severity.HIGH,
        "jailbreak": Severity.HIGH,
        "output_manipulation": Severity.LOW,
        "data_exfiltration": Severity.CRITICAL,
        "social_engineering": Severity.HIGH,
    }
    for pattern_set, lang in all_lang_patterns:
        for category, patterns in pattern_set.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, text_lower, re.IGNORECASE):
                        cat_severity = severity_map.get(category, Severity.MEDIUM)
                        if cat_severity.value > max_severity.value:
                            max_severity = cat_severity
                        reasons.append(f"{category}_{lang}")
                        patterns_matched.append(f"{lang}:{pattern[:50]}")
                except re.error as e:
                    logger.warning("Regex error in PATTERNS_%s[%s]: %s", lang, category, e)

    # ALL versioned pattern sets (SECURITY FIX: complete set)
    versioned_sets = [
        # v2.4.0
        (SCENARIO_JAILBREAK, "scenario_jailbreak", Severity.HIGH),
        (EMOTIONAL_MANIPULATION, "emotional_manipulation", Severity.HIGH),
        (AUTHORITY_RECON, "authority_recon", Severity.MEDIUM),
        (COGNITIVE_MANIPULATION, "cognitive_manipulation", Severity.MEDIUM),
        (PHISHING_SOCIAL_ENG, "phishing_social_eng", Severity.CRITICAL),
        (SYSTEM_FILE_ACCESS, "system_file_access", Severity.CRITICAL),
        (MALWARE_DESCRIPTION, "malware_description", Severity.HIGH),
        (REPETITION_ATTACK, "repetition_attack", Severity.HIGH),
        # v2.5.0
        (INDIRECT_INJECTION, "indirect_injection", Severity.HIGH),
        (CONTEXT_HIJACKING, "context_hijacking", Severity.MEDIUM),
        (MULTI_TURN_MANIPULATION, "multi_turn_manipulation", Severity.MEDIUM),
        (TOKEN_SMUGGLING, "token_smuggling", Severity.HIGH),
        (PROMPT_EXTRACTION, "prompt_extraction", Severity.CRITICAL),
        (SAFETY_BYPASS, "safety_bypass", Severity.HIGH),
        (URGENCY_MANIPULATION, "urgency_manipulation", Severity.MEDIUM),
        (SYSTEM_PROMPT_MIMICRY, "system_prompt_mimicry", Severity.CRITICAL),
        # v2.5.2
        (JSON_INJECTION_MOLTBOOK, "json_injection_moltbook", Severity.HIGH),
        (GUARDRAIL_BYPASS_EXTENDED, "guardrail_bypass_extended", Severity.CRITICAL),
        (AGENT_SOVEREIGNTY_MANIPULATION, "agent_sovereignty_manipulation", Severity.HIGH),
        (EXPLICIT_CALL_TO_ACTION, "explicit_call_to_action", Severity.CRITICAL),
        # v2.6.1
        (ALLOWLIST_BYPASS, "allowlist_bypass", Severity.CRITICAL),
        (HOOKS_HIJACKING, "hooks_hijacking", Severity.CRITICAL),
        (SUBAGENT_EXPLOITATION, "subagent_exploitation", Severity.CRITICAL),
        (HIDDEN_TEXT_INJECTION, "hidden_text_injection", Severity.HIGH),
        (GITIGNORE_BYPASS, "gitignore_bypass", Severity.HIGH),
        # v2.7.0
        (AUTO_APPROVE_EXPLOIT, "auto_approve_exploit", Severity.CRITICAL),
        (LOG_CONTEXT_EXPLOIT, "log_context_exploit", Severity.HIGH),
        (MCP_ABUSE, "mcp_abuse", Severity.CRITICAL),
        (PREFILLED_URL, "prefilled_url_exfiltration", Severity.CRITICAL),
        (UNICODE_TAG_DETECTION, "unicode_tag_injection", Severity.CRITICAL),
        (BROWSER_AGENT_INJECTION, "browser_agent_injection", Severity.HIGH),
        (HIDDEN_TEXT_HINTS, "hidden_text_hints", Severity.HIGH),
        # v3.0.1 - HiveFence Scout Round 3
        (OUTPUT_PREFIX_INJECTION, "output_prefix_injection", Severity.HIGH),
        (BENIGN_FINETUNING_ATTACK, "benign_finetuning_attack", Severity.HIGH),
        (PROMPTWARE_KILLCHAIN, "promptware_killchain", Severity.CRITICAL),
        # v3.1.0 - HiveFence Scout Round 4 (2026-02-08)
        (CAUSAL_MECHANISTIC_ATTACKS, "causal_mechanistic_attack", Severity.HIGH),
        (AGENT_TOOL_ATTACKS, "agent_tool_attack", Severity.CRITICAL),
        (TEMPLATE_CHAT_ATTACKS, "template_chat_attack", Severity.HIGH),
        (EVASION_STEALTH_ATTACKS, "evasion_stealth_attack", Severity.HIGH),
        (MULTIMODAL_PHYSICAL_ATTACKS, "multimodal_physical_attack", Severity.HIGH),
        (DEFENSE_BYPASS_ANALYSIS, "defense_bypass_analysis", Severity.HIGH),
        (INFRASTRUCTURE_PROTOCOL_ATTACKS, "infrastructure_protocol_attack", Severity.CRITICAL),
        # v3.2.0 - Skill Weaponization Defense (Min Hong Analysis - 2026-02-11)
        (SKILL_REVERSE_SHELL, "skill_reverse_shell", Severity.CRITICAL),
        (SKILL_SSH_INJECTION, "skill_ssh_injection", Severity.CRITICAL),
        (SKILL_EXFILTRATION_PIPELINE, "skill_exfiltration_pipeline", Severity.CRITICAL),
        (SKILL_COGNITIVE_ROOTKIT, "skill_cognitive_rootkit", Severity.CRITICAL),
        (SKILL_SEMANTIC_WORM, "skill_semantic_worm", Severity.HIGH),
        (SKILL_OBFUSCATED_PAYLOAD, "skill_obfuscated_payload", Severity.HIGH),
    ]
    for patterns, category, severity in versioned_sets:
        for pattern in patterns:
            try:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    if severity.value > max_severity.value:
                        max_severity = severity
                    if category not in reasons:
                        reasons.append(category)
                    patterns_matched.append(f"versioned:{category}:{pattern[:40]}")
            except re.error as e:
                logger.warning("Regex error in %s: %s", category, e)

    return reasons, patterns_matched, max_severity
