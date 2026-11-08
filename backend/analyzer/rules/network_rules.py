"""Network security rules: cleartext HTTP, trust-all certificate verifiers."""

from __future__ import annotations

import re

from backend.analyzer.rules.base import (
    MAX_FINDINGS_PER_RULE,
    Finding,
    ScanContext,
    SourceFile,
    is_code_line,
    register,
)

HTTP_URL_RE = re.compile(r"""["'](http://(?!localhost|127\.0\.0\.1|10\.|192\.168\.)[^"'\s]{4,200})["']""")

TRUST_MANAGER_RE = re.compile(r"implements\s+X509TrustManager")
EMPTY_METHOD_RE = re.compile(
    r"public\s+void\s+check(?:Client|Server)Trusted\s*\([^)]*\)\s*(?:throws\s+[\w.,\s]+)?\{\s*(?:/\*.*?\*/|//.*)?\}",
    re.DOTALL,
)
HOSTNAME_VERIFIER_RE = re.compile(r"implements\s+HostnameVerifier")
VERIFY_TRUE_RE = re.compile(r"public\s+boolean\s+verify\s*\([^)]*\)\s*\{\s*return\s+true\s*;\s*\}")


class _Collector:
    def __init__(self, rule_id: str) -> None:
        self.rule_id = rule_id
        self.findings: list[Finding] = []

    def add(self, finding: Finding) -> None:
        if len(self.findings) < MAX_FINDINGS_PER_RULE:
            self.findings.append(finding)


@register
class CleartextHttpRule:
    rule_id = "NETWORK-002"
    category = "network"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        collector = _Collector(self.rule_id)
        seen_hosts: set[str] = set()
        for file in ctx.files:
            for i, line in enumerate(file.lines):
                if not is_code_line(line):
                    continue
                for match in HTTP_URL_RE.finditer(line):
                    url = match.group(1)
                    host = url.split("/")[2] if "/" in url[7:] else url
                    if host in seen_hosts:
                        continue
                    seen_hosts.add(host)
                    collector.add(
                        Finding(
                            rule_id=self.rule_id,
                            category=self.category,
                            severity="MEDIUM",
                            cwe="CWE-319",
                            title=f"使用明文 HTTP 传输: {host}",
                            description=(
                                f"代码中请求了明文 HTTP 地址 {url}，传输内容可被嗅探、"
                                "篡改或重定向，属于传输层敏感数据明文暴露。"
                            ),
                            file=file.path,
                            line=i + 1,
                            snippet=line.strip(),
                            suggestion="统一使用 HTTPS 并启用证书校验；确需 HTTP 时在 network_security_config 中显式声明白名单域名。",
                        )
                    )
                    if len(collector.findings) >= MAX_FINDINGS_PER_RULE:
                        return collector.findings
        return collector.findings


@register
class TrustAllManagerRule:
    rule_id = "NETWORK-003"
    category = "network"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        collector = _Collector(self.rule_id)
        for file in ctx.files:
            text = file.text
            if "X509TrustManager" in text and EMPTY_METHOD_RE.search(text):
                line = file.find_line("X509TrustManager")
                collector.add(
                    Finding(
                        rule_id=self.rule_id,
                        category=self.category,
                        severity="CRITICAL",
                        cwe="CWE-295",
                        title="自定义 TrustManager 未校验服务端证书",
                        description=(
                            f"`{file.path}` 实现了空的 checkClientTrusted/checkServerTrusted，"
                            "等于接受任意证书，中间人可用自签名证书截获全部 HTTPS 流量。"
                        ),
                        file=file.path,
                        line=line,
                        snippet=text.splitlines()[line - 1].strip() if line - 1 < len(text.splitlines()) else "",
                        suggestion="移除空实现的 TrustManager，使用系统默认证书链校验，必要时实施证书锁定 (Certificate Pinning)。",
                    )
                )
            if "HostnameVerifier" in text and VERIFY_TRUE_RE.search(text):
                line = file.find_line("HostnameVerifier")
                collector.add(
                    Finding(
                        rule_id=self.rule_id,
                        category=self.category,
                        severity="HIGH",
                        cwe="CWE-295",
                        title="HostnameVerifier 对任意主机名返回 true",
                        description=(
                            f"`{file.path}` 的 verify 方法恒返回 true，域名不匹配的"
                            "证书也会被接受，配合钓鱼 Wi-Fi 即可劫持会话。"
                        ),
                        file=file.path,
                        line=line,
                        snippet="public boolean verify(...) { return true; }",
                        suggestion="删除恒真的 HostnameVerifier，使用默认校验或 HttpsURLConnection.setDefaultHostnameVerifier 白名单。",
                    )
                )
        return collector.findings
