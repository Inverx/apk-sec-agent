"""WebView risk rules: JS bridge exposure."""

from __future__ import annotations

import re

from backend.analyzer.rules.base import (
    MAX_FINDINGS_PER_RULE,
    Finding,
    ScanContext,
    is_code_line,
    register,
)

JS_ENABLED_RE = re.compile(r"setJavaScriptEnabled\s*\(\s*true\s*\)")
JS_INTERFACE_RE = re.compile(r"addJavascriptInterface\s*\(")
FILE_ACCESS_RE = re.compile(r"setAllowFileAccess\s*\(\s*true\s*\)")


@register
class WebViewJsBridgeRule:
    rule_id = "WEBVIEW-001"
    category = "webview"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for file in ctx.files:
            text = file.text
            if JS_ENABLED_RE.search(text) and JS_INTERFACE_RE.search(text):
                line = 1
                for i, ln in enumerate(file.lines):
                    if JS_INTERFACE_RE.search(ln):
                        line = i + 1
                        break
                has_file_access = bool(FILE_ACCESS_RE.search(text))
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        category=self.category,
                        severity="HIGH",
                        cwe="CWE-749",
                        title="WebView 开启 JS 并注入本地 Java 桥接对象",
                        description=(
                            "setJavaScriptEnabled(true) 与 addJavascriptInterface 同时出现，"
                            "加载的页面（含被劫持的 HTTP 页面）可通过反射调用桥接对象，"
                            f"在 API<17 存在远程代码执行风险；"
                            + ("且允许文件访问，可放大为本地文件读取。" if has_file_access else "")
                        ),
                        file=file.path,
                        line=line,
                        snippet=file.lines[line - 1].strip() if line - 1 < len(file.lines) else "",
                        suggestion="仅对可信域名开启 JS；桥接对象使用 @JavascriptInterface 显式白名单方法（API17+），避免暴露敏感能力；关闭 setAllowFileAccess。",
                    )
                )
                if len(findings) >= MAX_FINDINGS_PER_RULE:
                    break
        return findings
