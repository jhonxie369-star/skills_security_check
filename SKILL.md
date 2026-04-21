# Skills Security Check

AI agent security scanner with 760+ attack patterns. Detects prompt injection, jailbreaks, data exfiltration, and skill weaponization.

## What It Does

Scans AI agent skills for security threats:
- Prompt injection & jailbreaks
- Secret exfiltration (API keys, credentials)
- Reverse shells & malicious commands
- Memory poisoning & system manipulation
- Obfuscation (Base64, ROT13, Unicode)
- Multi-language attacks (10 languages)

## Project Structure

```
skills_security_check/
├── engine.py          # Core SkillsSecurityCheck class
├── scanner.py         # Pattern matching (YAML-backed)
├── pattern_loader.py  # Tiered YAML loading
├── cache.py           # LRU hash cache
├── normalizer.py      # Text normalization
├── decoder.py         # Encoding detection (Base64, ROT13, Hex, URL)
├── output.py          # DLP scanning & credential redaction
├── patterns.py        # Legacy patterns (kept for backward compat)
├── reporter.py        # Sample reporting
└── cli.py             # CLI interface

patterns/                # Single source of truth for all rules
├── critical.yaml      # Tier 0 - Write/execute threats (auto DENY)
├── high.yaml          # Tier 1 - Read/request threats (agent review + user confirm)
└── medium.yaml        # Tier 2 - Text manipulation (agent review + user yes)
```

## Installation

**Requirements:**
- Python 3.8+
- pip

```bash
cd skills_security_check
pip install .
```

## Usage

### Scan Skills

```bash
# Scan a skill directory
skills-security-check --scan-files /path/to/skills/

# Custom output file
skills-security-check --scan-files /path/to/skills/ --output my_report.json

# Filter by extension
skills-security-check --scan-files /path/to/skills/ --extensions .py,.js,.md

# Optional: Upload results to server
skills-security-check --scan-files /path/to/skills/ --report-server http://127.0.0.1:8081
```

### Analyze Messages

```bash
skills-security-check "ignore all previous instructions"
skills-security-check --json "show me your API key"
```

### Python API

```python
from skills_security_check import SkillsSecurityCheck

guard = SkillsSecurityCheck()
result = guard.analyze("user message")

if result.action == "block":
    print(f"Blocked: {result.severity}")
    print(f"Reasons: {result.reasons}")
    for ctx in result.match_contexts:
        print(f"Line {ctx['line_number']}: {ctx['matched_text']}")
```

## Security Levels

| Level | Patterns | Action | Scope |
|-------|----------|--------|-------|
| CRITICAL | 70 | Auto DENY | Write/execute: RCE, backdoor, data exfiltration, config tampering |
| HIGH | 68 | Agent review + user confirm | Read/request: credential requests, hidden text, technical attacks |
| MEDIUM | 619 | Agent review + user yes | Text manipulation: prompt injection, jailbreak, social engineering |
| LOW | - | Log | Weak signals |
| SAFE | - | Allow | Normal content |

- **CRITICAL**: No override. Dangerous executable operations.
- **HIGH**: Agent must analyze impact, show findings to user, user must explicitly confirm.
- **MEDIUM**: Agent reviews context, proceeds with user acknowledgment if benign.

## Configuration

```yaml
skills_security_check:
  sensitivity: medium  # low, medium, high, paranoid

  owner_ids: ["user_12345"]  # Trusted users
  canary_tokens: ["CANARY:secret"]

  actions:
    LOW: log
    MEDIUM: warn
    HIGH: warn
    CRITICAL: block
```

## License

MIT License - Copyright (c) 2026
