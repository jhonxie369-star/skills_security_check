"""
Prompt Guard - Logging utilities.

Markdown and JSONL logging with optional SHA-256 hash chain,

"""

import json
import hashlib
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Dict

from skills_security_check.models import Severity, DetectionResult


def log_detection(config: Dict, result: DetectionResult, message: str, context: Dict):
    """Log detection to security log file (Markdown format)."""
    if not config.get("logging", {}).get("enabled", True):
        return

    log_path = Path(
        config.get("logging", {}).get("path", "memory/security-log.md")
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%H:%M:%S")

    # SECURITY FIX (MED-006): Sanitize user-controlled data for log injection
    user_id = str(context.get("user_id", "unknown")).replace("|", "_").replace("\n", " ")[:50]
    chat_name = str(context.get("chat_name", "unknown")).replace("|", "_").replace("\n", " ")[:50]

    # Check if we need to add date header
    add_date_header = True
    if log_path.exists():
        content = log_path.read_text()
        if f"## {date_str}" in content:
            add_date_header = False

    entry = []
    if add_date_header:
        entry.append(f"\n## {date_str}\n")

    entry.append(
        f"### {time_str} | {result.severity.name} | user:{user_id} | {chat_name}"
    )
    entry.append(f"- Patterns: {', '.join(result.reasons)}")
    if config.get("logging", {}).get("include_message", False):
        safe_msg = message[:100].replace("\n", " ")
        entry.append(
            f'- Message: "{safe_msg}{"..." if len(message) > 100 else ""}"'
        )
    entry.append(f"- Action: {result.action.value}")
    entry.append(f"- Fingerprint: {result.fingerprint}")
    entry.append("")

    with open(log_path, "a") as f:
        f.write("\n".join(entry))


def log_detection_json(config: Dict, result: DetectionResult, message: str, context: Dict):
    """Log detection in structured JSONL format with optional hash chain.

    Note: The hash chain is NOT thread-safe. In concurrent environments,
    use external locking or a database-backed log instead.
    """
    if not config.get("logging", {}).get("enabled", True):
        return

    log_config = config.get("logging", {})
    if log_config.get("format", "markdown") != "json":
        return

    json_path = Path(log_config.get("json_path", "memory/security-log.jsonl"))
    json_path.parent.mkdir(parents=True, exist_ok=True)
    use_hash_chain = log_config.get("hash_chain", False)

    now = datetime.now()
    user_id = context.get("user_id", "unknown")
    chat_name = context.get("chat_name", "unknown")

    entry = {
        "timestamp": now.isoformat(),
        "severity": result.severity.name,
        "action": result.action.value,
        "user_id": str(user_id),
        "chat_name": chat_name,
        "reasons": result.reasons,
        "pattern_count": len(result.patterns_matched),
        "fingerprint": result.fingerprint,
        "scan_type": result.scan_type,
    }

    if result.decoded_findings:
        entry["decoded_encodings"] = [
            d["encoding"] for d in result.decoded_findings
        ]

    if result.canary_matches:
        entry["canary_matches"] = result.canary_matches

    if log_config.get("include_message", False):
        entry["message_preview"] = message[:100]

    # Hash chain for tamper detection
    if use_hash_chain:
        prev_hash = "genesis"
        if json_path.exists():
            try:
                lines = json_path.read_text().strip().split("\n")
                if lines and lines[-1]:
                    last_entry = json.loads(lines[-1])
                    prev_hash = last_entry.get("entry_hash", "genesis")
            except Exception:
                pass
        entry["prev_hash"] = prev_hash
        entry_str = json.dumps(entry, sort_keys=True, ensure_ascii=False)
        # SECURITY FIX (CRIT-005): Use full SHA-256 hash for tamper detection
        entry["entry_hash"] = hashlib.sha256(entry_str.encode()).hexdigest()

    with open(json_path, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
