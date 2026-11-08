"""Static analysis scanner orchestration."""

from __future__ import annotations

import logging
from pathlib import Path

from backend.analyzer import rules  # noqa: F401  (registers rules on import)
from backend.analyzer.manifest import ManifestInfo, parse_manifest
from backend.analyzer.rules.base import (
    SEVERITY_ORDER,
    Finding,
    ScanContext,
    SourceFile,
    all_rules,
)
from backend.analyzer.decompiler import MAX_SOURCE_BYTES, SOURCE_EXTENSIONS

logger = logging.getLogger("app.analyzer")


def load_manifest(workspace: Path) -> ManifestInfo | None:
    manifest_path = workspace / "AndroidManifest.xml"
    if not manifest_path.exists():
        return None
    try:
        return parse_manifest(manifest_path.read_text(encoding="utf-8", errors="replace"))
    except ValueError as exc:
        logger.warning("manifest parse failed: %s", exc)
        return None


def load_source_files(workspace: Path) -> list[SourceFile]:
    sources_root = workspace / "sources"
    if not sources_root.exists():
        return []
    files: list[SourceFile] = []
    for ext in SOURCE_EXTENSIONS:
        for path in sorted(sources_root.rglob(f"*{ext}")):
            try:
                if path.stat().st_size > MAX_SOURCE_BYTES:
                    logger.info("skip oversized source %s", path)
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                logger.warning("cannot read %s: %s", path, exc)
                continue
            rel = path.relative_to(workspace).as_posix()
            files.append(SourceFile(path=rel, text=text))
    return files


def collect_raw_entries(workspace: Path) -> list[str]:
    raw_root = workspace / "raw"
    if not raw_root.exists():
        return []
    return [p.relative_to(raw_root).as_posix() for p in raw_root.rglob("*") if p.is_file()]


def scan_workspace(workspace: Path) -> dict:
    """Run all registered rules over a decompiled workspace."""
    manifest = load_manifest(workspace)
    files = load_source_files(workspace)
    raw_entries = collect_raw_entries(workspace)
    ctx = ScanContext(manifest=manifest, files=files, raw_entries=raw_entries, workspace=workspace)

    findings: list[Finding] = []
    for rule in all_rules():
        try:
            findings.extend(rule.scan(ctx))
        except Exception:  # noqa: BLE001 - a broken rule must not kill the scan
            logger.exception("rule %s crashed", getattr(rule, "rule_id", rule))

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line))
    for i, finding in enumerate(findings, start=1):
        finding.id = f"F-{i:03d}"

    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_category: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_category[finding.category] = by_category.get(finding.category, 0) + 1

    return {
        "findings": [f.to_dict() for f in findings],
        "summary": {
            "total": len(findings),
            "by_severity": by_severity,
            "by_category": by_category,
        },
        "scanned_files": len(files),
        "manifest": manifest.to_dict() if manifest else None,
    }
