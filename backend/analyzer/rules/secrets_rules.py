"""Hardcoded secret rules: AK/SK, JWT secrets, private keys, high-entropy."""

from __future__ import annotations

import re

from backend.analyzer.rules.base import (
    MAX_FINDINGS_PER_RULE,
    Finding,
    ScanContext,
    is_code_line,
    register,
    shannon_entropy,
)

AK_SK_RE = re.compile(
    r"""(?i)\b(access[_-]?key(?:[_-]?id)?|secret[_-]?key|secret[_-]?id|ak|sk)\b\s*[:=]\s*["']([A-Za-z0-9+/=_\-]{12,64})["']"""
)
JWT_SECRET_RE = re.compile(
    r"""(?i)\b(jwt[_-]?(secret|key)|signing[_-]?key|sign[_-]?key|token[_-]?secret)\b\s*[:=]\s*["']([^"']{8,128})["']"""
)
JWT_BUILDER_RE = re.compile(
    r"""(?i)signWith\s*\(\s*SignatureAlgorithm\.(?:HS256|HS384|HS512)\s*,\s*["']([^"']{8,128})["']"""
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE\s+KEY-----")
ENTROPY_STRING_RE = re.compile(r"""["']([A-Za-z0-9+/=_\-]{20,80})["']""")

_ENTROPY_EXCLUDE = re.compile(
    r"""(?i)^(https?://|/|com\.|org\.|android\.|java\.|javax\.|kotlin\.|Lcom/|java/|utf-?8|sha-?(1|256|512)|md5|aes|rsa|ecb|cbc|ctr|gcm)$"""
)
_ENTROPY_MIN_LEN = 20
_ENTROPY_THRESHOLD = 4.5


def _looks_like_secret(value: str) -> bool:
    lowered = value.lower()
    if _ENTROPY_EXCLUDE.match(lowered):
        return False
    if lowered in {"false", "true", "null", "none"}:
        return False
    # paths and dotted identifiers are not secrets
    if value.count("/") >= 2 or value.count(".") >= 3:
        return False
    return shannon_entropy(value) >= _ENTROPY_THRESHOLD


@register
class AccessKeyRule:
    rule_id = "SECRETS-001"
    category = "secrets"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for file in ctx.files:
            for i, line in enumerate(file.lines):
                if not is_code_line(line):
                    continue
                for match in AK_SK_RE.finditer(line):
                    value = match.group(2)
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            category=self.category,
                            severity="HIGH",
                            cwe="CWE-798",
                            title=f"硬编码云访问凭证 ({match.group(1)})",
                            description=(
                                f"代码中以字面量形式存储访问密钥 `{match.group(1)}`，"
                                "反编译即可提取并冒用身份调用云端 API。"
                            ),
                            file=file.path,
                            line=i + 1,
                            snippet=line.strip(),
                            suggestion="将 AK/SK 迁移到服务端下发或安全存储（Android Keystore/加密 SharedPreferences），并对已泄露凭证轮换。",
                        )
                    )
                    break
                if len(findings) >= MAX_FINDINGS_PER_RULE:
                    return findings
        return findings


@register
class JwtSecretRule:
    rule_id = "SECRETS-002"
    category = "secrets"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for file in ctx.files:
            for i, line in enumerate(file.lines):
                if not is_code_line(line):
                    continue
                match = JWT_SECRET_RE.search(line) or JWT_BUILDER_RE.search(line)
                if match:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            category=self.category,
                            severity="HIGH",
                            cwe="CWE-798",
                            title="硬编码 JWT 签名密钥",
                            description=(
                                "客户端内置 JWT 签名密钥，攻击者可离线伪造任意用户 token，"
                                "完全绕过服务端会话认证。"
                            ),
                            file=file.path,
                            line=i + 1,
                            snippet=line.strip(),
                            suggestion="JWT 必须由服务端签发与校验，客户端仅保存短期 token；已泄露密钥立即轮换。",
                        )
                    )
                    if len(findings) >= MAX_FINDINGS_PER_RULE:
                        return findings
        return findings


@register
class PrivateKeyRule:
    rule_id = "SECRETS-003"
    category = "secrets"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for file in ctx.files:
            for i, line in enumerate(file.lines):
                if PRIVATE_KEY_RE.search(line):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            category=self.category,
                            severity="CRITICAL",
                            cwe="CWE-321",
                            title="应用内嵌私钥文件",
                            description=(
                                "源码或资源中出现 PEM 私钥块，攻击者可解密通信、"
                                "伪造签名或冒充服务端身份。"
                            ),
                            file=file.path,
                            line=i + 1,
                            snippet=line.strip(),
                            suggestion="私钥仅保存在服务端 HSM/密钥管理系统中，客户端只用公钥加密或证书校验。",
                        )
                    )
                    if len(findings) >= MAX_FINDINGS_PER_RULE:
                        return findings
        return findings


@register
class HighEntropyStringRule:
    rule_id = "SECRETS-004"
    category = "secrets"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for file in ctx.files:
            for i, line in enumerate(file.lines):
                if not is_code_line(line):
                    continue
                for match in ENTROPY_STRING_RE.finditer(line):
                    value = match.group(1)
                    key = (file.path, value)
                    if key in seen or not _looks_like_secret(value):
                        continue
                    seen.add(key)
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            category=self.category,
                            severity="MEDIUM",
                            cwe="CWE-798",
                            title=f"高熵疑似密钥字符串 (熵 {shannon_entropy(value):.2f})",
                            description=(
                                "字符串字面量具有接近随机密钥的熵值，可能是硬编码的"
                                "加密密钥、token 或签名盐值。"
                            ),
                            file=file.path,
                            line=i + 1,
                            snippet=line.strip(),
                            suggestion="确认字符串用途；若为密钥则迁移到服务端或 Android Keystore，避免以常量形式打包。",
                        )
                    )
                    if len(findings) >= MAX_FINDINGS_PER_RULE:
                        return findings
        return findings
