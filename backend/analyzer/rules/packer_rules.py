"""Packer / hardening detection via .so signatures and stub entry classes."""

from __future__ import annotations

import re

from backend.analyzer.rules.base import Finding, ScanContext, register

# vendor: (so filename patterns, application-class / dex stub patterns)
PACKER_SIGNATURES: list[dict] = [
    {
        "name": "360加固 (Jiagu)",
        "so": (re.compile(r"libjiagu(_art|_x86)?\.so"),),
        "classes": (re.compile(r"(?i)\bcom\.stub\.StubApp\b|\bcom\.qihoo\w*\.StubApplication\b"),),
    },
    {
        "name": "梆梆安全 (SecNeo)",
        "so": (re.compile(r"libDexHelper(-x86)?\.so|libSecShell(-x86|-S)?\.(so|apk)"),),
        "classes": (re.compile(r"(?i)\bcom\.secneo\.(SApplication|apkprotect\w*)\b|\bcom\.secshell\w*"),),
    },
    {
        "name": "爱加密 (Ijiami)",
        "so": (re.compile(r"libexec(main|\.so)?\.so|libijiami(-x86)?\.(so|data)"),),
        "classes": (re.compile(r"(?i)\bcom\.shell\.SuperApplication\b|\bijiami\b"),),
    },
    {
        "name": "腾讯乐固 (Legu)",
        "so": (re.compile(r"libshella(-[\d.]+)?\.so|libtup\.so|libtospro\.so"),),
        "classes": (re.compile(r"(?i)\bcom\.tencent\.StubShell\.(TxAppEntry|TxReceiver)\b"),),
    },
    {
        "name": "网易易盾 (Neseo)",
        "so": (re.compile(r"libnesec\.so|libMobisec(python)?\.so"),),
        "classes": (re.compile(r"(?i)\bcom\.netease\.mobisec\w*"),),
    },
]


@register
class PackerDetectionRule:
    rule_id = "PACKER-001"
    category = "packer"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        evidence_sources: list[str] = list(ctx.raw_entries)
        if ctx.manifest is not None and ctx.manifest.application_class:
            evidence_sources.append(ctx.manifest.application_class)
        evidence_sources.extend(f.path for f in ctx.files)
        text_pool = "\n".join(f.text for f in ctx.files)

        findings: list[Finding] = []
        for vendor in PACKER_SIGNATURES:
            evidence: list[str] = []
            for pattern in vendor["so"]:
                for name in ctx.raw_entries:
                    if pattern.search(name):
                        evidence.append(name)
            class_match = None
            for pattern in vendor["classes"]:
                if ctx.manifest is not None and ctx.manifest.application_class and pattern.search(
                    ctx.manifest.application_class
                ):
                    class_match = ctx.manifest.application_class
                if class_match is None:
                    m = pattern.search(text_pool)
                    if m:
                        class_match = m.group(0)
            if evidence or class_match:
                if class_match:
                    evidence.append(f"入口/存根类 {class_match}")
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        category=self.category,
                        severity="LOW",
                        cwe="CWE-693",
                        title=f"检测到加固保护: {vendor['name']}",
                        description=(
                            f"识别到 {vendor['name']} 特征。加固会加壳 DEX、隐藏真实入口类，"
                            "静态反编译只能看到存根，深度审计需要脱壳或动态分析配合。"
                        ),
                        file=evidence[0] if evidence else "AndroidManifest.xml",
                        line=1,
                        snippet="; ".join(evidence[:3]),
                        suggestion="如需审计真实代码，使用对应脱壳方案或 Frida 壳检测后 dump DEX 再导入分析。",
                    )
                )
        return findings
