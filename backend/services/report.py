"""Markdown / JSON audit report rendering."""

from __future__ import annotations

import html
from typing import Any

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _result(task) -> dict[str, Any]:
    return task.result_json or {}


def findings_sorted(task) -> list[dict[str, Any]]:
    findings = _result(task).get("findings", [])
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "LOW"), 9))


def build_json_report(task, apk) -> dict[str, Any]:
    result = _result(task)
    return {
        "report_version": 1,
        "task_id": task.id,
        "status": task.status,
        "apk": {
            "id": apk.id,
            "filename": apk.filename,
            "sha256": apk.sha256,
            "size": apk.size,
        },
        "duration_ms": task.duration_ms,
        "summary": result.get("summary", {}),
        "manifest": result.get("manifest"),
        "packers": result.get("packers", []),
        "findings": findings_sorted(task),
        "generated_from": "APK-SecAgent static analysis pipeline",
    }


def build_markdown_report(task, apk) -> str:
    result = _result(task)
    summary = result.get("summary", {})
    manifest = result.get("manifest") or {}
    packers = result.get("packers", [])
    lines: list[str] = []
    lines.append(f"# APK 安全审计报告 — {html.escape(apk.filename)}")
    lines.append("")
    lines.append(f"- 任务 ID：`{task.id}`")
    lines.append(f"- 状态：`{task.status}`")
    lines.append(f"- SHA256：`{apk.sha256}`")
    lines.append(f"- 大小：{apk.size} 字节")
    if task.duration_ms is not None:
        lines.append(f"- 分析耗时：{task.duration_ms} ms")
    lines.append("")

    lines.append("## 风险统计")
    lines.append("")
    lines.append(f"共发现 **{summary.get('total', 0)}** 个风险项，扫描文件 "
                 f"{result.get('scanned_files', 0)} 个。")
    by_sev = summary.get("by_severity", {})
    if by_sev:
        lines.append("")
        lines.append("| 严重等级 | 数量 |")
        lines.append("|---|---|")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if by_sev.get(sev):
                lines.append(f"| {sev} | {by_sev[sev]} |")

    lines.append("")
    lines.append("## 风险清单")
    lines.append("")
    findings = findings_sorted(task)
    if not findings:
        lines.append("未发现风险项。")
    else:
        lines.append("| ID | 等级 | CWE | 风险 | 位置 |")
        lines.append("|---|---|---|---|---|")
        for f in findings:
            lines.append(
                f"| {f.get('id')} | {f.get('severity')} | {f.get('cwe') or 'N/A'} "
                f"| {html.escape(f.get('title', ''))} "
                f"| `{html.escape(f.get('file', ''))}:{f.get('line')}` |"
            )
    lines.append("")
    lines.append("### 修复建议")
    lines.append("")
    for f in findings:
        lines.append(f"#### [{f.get('severity')}] {f.get('id')} {html.escape(f.get('title', ''))}")
        lines.append("")
        lines.append(f"- 位置：`{f.get('file')}:{f.get('line')}`（CWE: {f.get('cwe') or 'N/A'}）")
        lines.append(f"- 说明：{html.escape(f.get('description', ''))}")
        lines.append(f"- 建议：{html.escape(f.get('suggestion', ''))}")
        lines.append("")

    if manifest:
        lines.append("## Manifest 概要")
        lines.append("")
        lines.append(f"- 包名：`{manifest.get('package', 'N/A')}`")
        lines.append(f"- Application：`{manifest.get('application_class', 'N/A')}`")
        perms = manifest.get("permissions", [])
        lines.append(f"- 权限（{len(perms)}）：{'、'.join(f'`{p}`' for p in perms) or '无'}")
        comps = manifest.get("exported_components", [])
        lines.append(f"- 导出组件（{len(comps)}）：")
        for c in comps:
            lines.append(f"  - `{c.get('type')}` {c.get('name')}"
                         f"{'（无权限保护）' if not c.get('permission') else ''}")
        lines.append("")

    if packers:
        lines.append("## 加固识别")
        lines.append("")
        for p in packers:
            lines.append(f"- **{p.get('name')}**：置信度 {p.get('confidence')}，"
                         f"特征 {', '.join(p.get('evidence', []))}")
        lines.append("")

    lines.append("---")
    lines.append("*由 APK-SecAgent 静态分析流水线自动生成*")
    return "\n".join(lines)
