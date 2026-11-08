"""Cryptographic misuse rules: ECB, fixed IV, weak hashes, literal keys."""

from __future__ import annotations

import re

from backend.analyzer.rules.base import (
    MAX_FINDINGS_PER_RULE,
    Finding,
    ScanContext,
    is_code_line,
    register,
)

ECB_RE = re.compile(r'Cipher\.getInstance\(\s*"(AES/ECB/[^"]*|DES/ECB/[^"]*|AES|DES)"')
WEAK_HASH_RE = re.compile(r'MessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"\s*\)', re.IGNORECASE)
FIXED_IV_RE = re.compile(
    r"IvParameterSpec\s*\(\s*(new\s+byte\[\]\s*\{[^}]+\}|[A-Z_]{4,}\.getBytes\(\)|\"[^\"]{8,}\"\.getBytes\(\))"
)
LITERAL_KEY_RE = re.compile(
    r'new\s+SecretKeySpec\s*\(\s*("([^"]{8,})"|([A-Z_]{4,}))\.getBytes\(\)'
)


@register
class EcbCipherRule:
    rule_id = "CRYPTO-001"
    category = "crypto"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for file in ctx.files:
            for i, line in enumerate(file.lines):
                if not is_code_line(line):
                    continue
                match = ECB_RE.search(line)
                if match:
                    mode = match.group(1)
                    implicit = mode.upper() in ("AES", "DES")
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            category=self.category,
                            severity="HIGH",
                            cwe="CWE-327",
                            title=f"使用 ECB 模式加密 ({'Cipher.getInstance 未指定模式' if implicit else mode})",
                            description=(
                                "ECB 模式对相同明文块输出相同密文块，无法抵抗块重放与"
                                "模式分析（经典企鹅图漏洞）。AES 不指定模式时默认即 ECB。"
                            ),
                            file=file.path,
                            line=i + 1,
                            snippet=line.strip(),
                            suggestion="改用 AES/GCM/NoPadding 或 AES/CBC/PKCS5Padding 并配合随机 IV 与完整性校验 (MAC)。",
                        )
                    )
                    if len(findings) >= MAX_FINDINGS_PER_RULE:
                        return findings
        return findings


@register
class FixedIvRule:
    rule_id = "CRYPTO-002"
    category = "crypto"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for file in ctx.files:
            for i, line in enumerate(file.lines):
                if not is_code_line(line):
                    continue
                match = FIXED_IV_RE.search(line)
                if match:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            category=self.category,
                            severity="MEDIUM",
                            cwe="CWE-329",
                            title="使用固定初始化向量 (IV)",
                            description=(
                                "IV 由字面量/常量生成并复用于多次加密，相同明文前缀"
                                "产生相同密文前缀，泄露分组级信息且削弱 CBC 安全性。"
                            ),
                            file=file.path,
                            line=i + 1,
                            snippet=line.strip(),
                            suggestion="每次加密使用 SecureRandom 生成新 IV，随密文一起传输。",
                        )
                    )
                    if len(findings) >= MAX_FINDINGS_PER_RULE:
                        return findings
        return findings


@register
class WeakHashRule:
    rule_id = "CRYPTO-003"
    category = "crypto"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for file in ctx.files:
            for i, line in enumerate(file.lines):
                if not is_code_line(line):
                    continue
                match = WEAK_HASH_RE.search(line)
                if match:
                    algo = match.group(1).upper()
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            category=self.category,
                            severity="MEDIUM",
                            cwe="CWE-327",
                            title=f"使用弱哈希算法 {algo}",
                            description=(
                                f"{algo} 已被证实存在碰撞攻击（如 shattered.io），"
                                "用于签名/完整性校验时可被构造碰撞绕过。"
                            ),
                            file=file.path,
                            line=i + 1,
                            snippet=line.strip(),
                            suggestion="完整性校验改用 SHA-256 及以上；口令存储使用 bcrypt/PBKDF2/scrypt 等慢哈希。",
                        )
                    )
                    if len(findings) >= MAX_FINDINGS_PER_RULE:
                        return findings
        return findings


@register
class LiteralKeyRule:
    rule_id = "CRYPTO-004"
    category = "crypto"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for file in ctx.files:
            for i, line in enumerate(file.lines):
                if not is_code_line(line):
                    continue
                match = LITERAL_KEY_RE.search(line)
                if match:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            category=self.category,
                            severity="HIGH",
                            cwe="CWE-321",
                            title="加密密钥以硬编码字面量构造 SecretKeySpec",
                            description=(
                                "对称密钥直接来自字符串常量，与 APK 一起分发，"
                                "反编译后可解密所有相关流量或本地数据。"
                            ),
                            file=file.path,
                            line=i + 1,
                            snippet=line.strip(),
                            suggestion="密钥通过 Android Keystore 生成与保管，或由服务端按设备下发并走安全通道。",
                        )
                    )
                    if len(findings) >= MAX_FINDINGS_PER_RULE:
                        return findings
        return findings
