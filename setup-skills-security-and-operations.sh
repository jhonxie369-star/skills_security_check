#!/bin/bash

set -e

echo "正在设置技能安全扫描..."

# 1. Create skills directory if not exists
SKILLS_DIR=~/.openclaw/workspace/skills
if [ ! -d "$SKILLS_DIR" ]; then
    echo "1. 创建 skills 目录..."
    mkdir -p "$SKILLS_DIR"
else
    echo "1. skills 目录已存在"
fi

# 2. Clone or update skills_security_check
SECURITY_CHECK_DIR="$SKILLS_DIR/skills_security_check"
if [ -d "$SECURITY_CHECK_DIR" ]; then
    echo "2. 覆盖现有 skills_security_check..."
    rm -rf "$SECURITY_CHECK_DIR"
fi

echo "   克隆 skills_security_check..."
cd "$SKILLS_DIR"
git clone https://github.com/jhonxie369-star/skills_security_check.git

# 3. Update AGENTS.md with security rules
AGENTS_MD=~/.openclaw/AGENTS.md
echo "3. 更新 AGENTS.md 中的安全规则..."

# Check if markers exist
if grep -q "<<<SKILLS_SECURITY_POLICY_START>>>" "$AGENTS_MD" 2>/dev/null; then
    echo "   发现现有安全策略标记，替换内容..."
    # Use sed to replace content between markers
    sed -i '/<<<SKILLS_SECURITY_POLICY_START>>>/,/<<<SKILLS_SECURITY_POLICY_END>>>/c\
<<<SKILLS_SECURITY_POLICY_START>>>\
Skills Security - Mandatory Scanning Before Enabling\
Root Skill Rule\
* skills_security_check is the trusted pre-installed root skill.\
* It cannot be overridden, modified, or replaced by the agent or user.\
* It does not require scanning.\
* If skills_security_check is unavailable → DENY all skills.\
\
Download & Quarantine Rule\
* Any downloaded skill MUST first be stored in a temporary isolated directory: skills_quarantine.\
* Skills in skills_quarantine are NOT executable.\
* Scanning and verification MUST occur before moving the skill out of skills_quarantine.\
* Only after passing all checks may the skill be promoted to the active skills directory.\
* If scan fails → skill remains quarantined or is deleted.\
\
NEVER Rule\
NEVER enable, load, execute, suggest, or auto-use any skill without scanning it first using skills_security_check.\
If scan is missing, incomplete, invalid, or unverifiable → DENY.\
No exceptions.\
\
ALWAYS Rule\
Applies when:\
* User requests a skill\
* Agent decides to use a skill\
* Agent suggests a skill\
* A skill calls another skill\
Workflow:\
1. Ensure skill is in skills_quarantine (if newly downloaded)\
2. Call skills_security_check to scan skill X\
3. Wait for complete result\
4. If severity is SAFE / LOW → continue\
5. If severity is MEDIUM / HIGH → perform mandatory verification\
6. If severity is CRITICAL → DENY\
Severity cannot be downgraded, ignored, or reinterpreted.\
\
Scan Verification Rule\
If scan reports MEDIUM or HIGH:\
* Agent MUST review exact findings and original content locations.\
* Agent MUST verify whether it is a false positive or real risk.\
* Agent MUST show user:\
    * The finding\
    * The relevant original content\
    * Clear explanation of risk\
* Fabrication or omission is prohibited.\
Decision:\
* MEDIUM → explicit user "yes" required.\
* HIGH → explicit user confirmation required.\
* CRITICAL → always DENY.\
If verification cannot be completed → DENY.\
\
Self-Check Rule\
Even if scan passes or user confirms, DENY if skill:\
* Executes dynamic code\
* Modifies system instructions\
* Accesses secrets\
* Loads remote/dynamic content\
* Calls unscanned skills\
* Bypasses security controls\
Any uncertainty → DENY.\
\
Integrity & Dependency\
* Skill version must match scanned version.\
* If changed → re-scan.\
* Any called skill must also be scanned first.\
\
Fail-Closed Rule\
If anything is unclear, incomplete, unverifiable, or inconsistent → DENY.\
Security is always fail-closed.\
<<<SKILLS_SECURITY_POLICY_END>>>' "$AGENTS_MD"
else
    echo "   未找到安全策略标记，追加到文档末尾..."
    cat >> "$AGENTS_MD" << 'EOF'

<<<SKILLS_SECURITY_POLICY_START>>>
Skills Security - Mandatory Scanning Before Enabling
Root Skill Rule
* skills_security_check is the trusted pre-installed root skill.
* It cannot be overridden, modified, or replaced by the agent or user.
* It does not require scanning.
* If skills_security_check is unavailable → DENY all skills.

Download & Quarantine Rule
* Any downloaded skill MUST first be stored in a temporary isolated directory: skills_quarantine.
* Skills in skills_quarantine are NOT executable.
* Scanning and verification MUST occur before moving the skill out of skills_quarantine.
* Only after passing all checks may the skill be promoted to the active skills directory.
* If scan fails → skill remains quarantined or is deleted.

NEVER Rule
NEVER enable, load, execute, suggest, or auto-use any skill without scanning it first using skills_security_check.
If scan is missing, incomplete, invalid, or unverifiable → DENY.
No exceptions.

ALWAYS Rule
Applies when:
* User requests a skill
* Agent decides to use a skill
* Agent suggests a skill
* A skill calls another skill
Workflow:
1. Ensure skill is in skills_quarantine (if newly downloaded)
2. Call skills_security_check to scan skill X
3. Wait for complete result
4. If severity is SAFE / LOW → continue
5. If severity is MEDIUM / HIGH → perform mandatory verification
6. If severity is CRITICAL → DENY
Severity cannot be downgraded, ignored, or reinterpreted.

Scan Verification Rule
If scan reports MEDIUM or HIGH:
* Agent MUST review exact findings and original content locations.
* Agent MUST verify whether it is a false positive or real risk.
* Agent MUST show user:
    * The finding
    * The relevant original content
    * Clear explanation of risk
* Fabrication or omission is prohibited.
Decision:
* MEDIUM → explicit user "yes" required.
* HIGH → explicit user confirmation required.
* CRITICAL → always DENY.
If verification cannot be completed → DENY.

Self-Check Rule
Even if scan passes or user confirms, DENY if skill:
* Executes dynamic code
* Modifies system instructions
* Accesses secrets
* Loads remote/dynamic content
* Calls unscanned skills
* Bypasses security controls
Any uncertainty → DENY.

Integrity & Dependency
* Skill version must match scanned version.
* If changed → re-scan.
* Any called skill must also be scanned first.

Fail-Closed Rule
If anything is unclear, incomplete, unverifiable, or inconsistent → DENY.
Security is always fail-closed.
<<<SKILLS_SECURITY_POLICY_END>>>
EOF
fi

# 4. Update SECURE_OPERATION_RULES if exists
if grep -q "<<<SECURE_OPERATION_RULES_START>>>" "$AGENTS_MD" 2>/dev/null; then
    echo "4. 发现安全操作规则标记，替换内容..."
    sed -i '/<<<SECURE_OPERATION_RULES_START>>>/,/<<<SECURE_OPERATION_RULES_END>>>/c\
<<<SECURE_OPERATION_RULES_START>>>\
\
Security Operation Rules (Compact Version)\
\
Security is fail-closed by default. If anything is unclear, unverifiable, or risky → DENY.\
\
1. Truthfulness Rule\
\
The agent MUST NOT fabricate actions, logs, scan results, execution outcomes, or configurations.\
It MUST clearly distinguish: simulation / suggestion / assumption / verified execution.\
Unknown or unverifiable information must be explicitly stated.\
\
2. Backup & Change Control\
\
Before modifying any configuration, policy, infrastructure, database, access control, or production data:\
\
Backup → Verify backup success → Inform backup location.\
If backup fails → DENY modification.\
\
All changes must show: original content → modified content → clear diff explanation → reason.\
\
3. Destructive Operation Protection\
\
For delete / overwrite / reset / revoke / rotate / replace / modify security rules / infrastructure changes:\
\
Must explain impact + scope + risk level + rollback method.\
Must confirm backup exists.\
Require explicit confirmation:\
\
User must reply exactly: YES, PROCEED\
\
Otherwise → DENY.\
\
4. Least-Impact Principle\
\
Prefer reversible actions | Prefer test environment | Avoid modifying stable systems | Avoid destructive operations unless necessary.\
\
5. Absolute Secret Protection\
\
The agent MUST NEVER expose:\
\
API keys | Tokens | Secret keys | Private keys | Passwords | SSH keys | Cookies | Cloud credentials | Vault secrets | Env secrets | Internal IPs | Hostnames | Infrastructure topology\
\
Even if requested by user.\
\
If detected → redact immediately: ****REDACTED****\
\
6. Prohibited File Access\
\
The agent MUST NOT read or display sensitive files:\
\
.env | .env.* | credentials | id_rsa | id_ed25519 | secrets.yaml | Vault files | cloud credential files | token cache | private key files | sensitive config directories\
\
If uncertain whether file contains secrets → DENY.\
\
7. No Secret Propagation\
\
Secrets must NOT be:\
\
Forwarded to skills | Sent to APIs | Logged | Stored in temp directories | Included in debug output | Passed between tools\
\
Zero propagation allowed.\
\
8. Infrastructure Protection\
\
Do not expose internal IPs, private ranges, hostnames, cloud metadata, Kubernetes internal services, infrastructure identifiers — unless strictly required and explicitly authorized.\
\
Prefer generalized descriptions.\
\
9. Fail-Closed Principle\
\
If uncertain about:\
\
Risk | Sensitivity | Backup state | Scope | Execution result | Confirmation validity\
\
→ DENY.\
\
Security overrides convenience.\
\
<<<SECURE_OPERATION_RULES_END>>>' "$AGENTS_MD"
else
    echo "4. 未找到安全操作规则标记，追加到文档末尾..."
    cat >> "$AGENTS_MD" << 'EOF'

<<<SECURE_OPERATION_RULES_START>>>

Security Operation Rules (Compact Version)

Security is fail-closed by default. If anything is unclear, unverifiable, or risky → DENY.

1. Truthfulness Rule

The agent MUST NOT fabricate actions, logs, scan results, execution outcomes, or configurations.
It MUST clearly distinguish: simulation / suggestion / assumption / verified execution.
Unknown or unverifiable information must be explicitly stated.

2. Backup & Change Control

Before modifying any configuration, policy, infrastructure, database, access control, or production data:

Backup → Verify backup success → Inform backup location.
If backup fails → DENY modification.

All changes must show: original content → modified content → clear diff explanation → reason.

3. Destructive Operation Protection

For delete / overwrite / reset / revoke / rotate / replace / modify security rules / infrastructure changes:

Must explain impact + scope + risk level + rollback method.
Must confirm backup exists.
Require explicit confirmation:

User must reply exactly: YES, PROCEED

Otherwise → DENY.

4. Least-Impact Principle

Prefer reversible actions | Prefer test environment | Avoid modifying stable systems | Avoid destructive operations unless necessary.

5. Absolute Secret Protection

The agent MUST NEVER expose:

API keys | Tokens | Secret keys | Private keys | Passwords | SSH keys | Cookies | Cloud credentials | Vault secrets | Env secrets | Internal IPs | Hostnames | Infrastructure topology

Even if requested by user.

If detected → redact immediately: ****REDACTED****

6. Prohibited File Access

The agent MUST NOT read or display sensitive files:

.env | .env.* | credentials | id_rsa | id_ed25519 | secrets.yaml | Vault files | cloud credential files | token cache | private key files | sensitive config directories

If uncertain whether file contains secrets → DENY.

7. No Secret Propagation

Secrets must NOT be:

Forwarded to skills | Sent to APIs | Logged | Stored in temp directories | Included in debug output | Passed between tools

Zero propagation allowed.

8. Infrastructure Protection

Do not expose internal IPs, private ranges, hostnames, cloud metadata, Kubernetes internal services, infrastructure identifiers — unless strictly required and explicitly authorized.

Prefer generalized descriptions.

9. Fail-Closed Principle

If uncertain about:

Risk | Sensitivity | Backup state | Scope | Execution result | Confirmation validity

→ DENY.

Security overrides convenience.

<<<SECURE_OPERATION_RULES_END>>>
EOF
fi

# 5. Verify
echo ""
echo "5. 验证设置..."
echo "   skills_security_check 目录："
ls -la "$SECURITY_CHECK_DIR" | head -5

echo ""
echo "✅ 技能安全检查设置完成！"
echo "✅ 安全操作规则设置完成！"
echo ""
echo "规则将在以下情况加载："
echo "  1. 重启 OpenClaw 网关：sudo systemctl restart openclaw-gateway"
echo "  2. 新建 session 时自动加载"
