"""Static scan rule base: Finding model, ScanContext, registry."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Protocol

from backend.analyzer.manifest import ManifestInfo

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SEVERITY_ORDER = {name: i for i, name in enumerate(SEVERITIES)}

CATEGORIES = (
    "manifest",
    "network",
    "secrets",
    "crypto",
    "packer",
    "webview",
)

MAX_FINDINGS_PER_RULE = 20


@dataclass
class SourceFile:
    path: str  # workspace-relative, e.g. sources/com/demo/Foo.java
    text: str
    lines: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.lines:
            self.lines = self.text.splitlines()

    def find_line(self, needle: str, start: int = 0) -> int:
        """1-based line number of the first line containing ``needle``."""
        for i in range(start, len(self.lines)):
            if needle in self.lines[i]:
                return i + 1
        return 1


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    cwe: str | None
    title: str
    description: str
    file: str
    line: int
    snippet: str = ""
    suggestion: str = ""
    id: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "cwe": self.cwe,
            "title": self.title,
            "description": self.description,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet[:240],
            "suggestion": self.suggestion,
        }


@dataclass
class ScanContext:
    manifest: ManifestInfo | None
    files: list[SourceFile]
    raw_entries: list[str] = field(default_factory=list)  # original zip entry names
    workspace: "Path | None" = None  # Path when available


class Rule(Protocol):
    rule_id: str
    category: str

    def scan(self, ctx: ScanContext) -> list[Finding]: ...


_REGISTRY: list[Rule] = []


def register(rule_class: Callable[[], Rule]) -> Callable[[], Rule]:
    _REGISTRY.append(rule_class())
    return rule_class


def all_rules() -> list[Rule]:
    return list(_REGISTRY)


def snippet_of(file: SourceFile, line: int, width: int = 160) -> str:
    if 1 <= line <= len(file.lines):
        return file.lines[line - 1].strip()[:width]
    return ""


_ENTROPY_CACHE: dict[str, float] = {}


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    if value in _ENTROPY_CACHE:
        return _ENTROPY_CACHE[value]
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    import math

    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
    if len(_ENTROPY_CACHE) > 4096:
        _ENTROPY_CACHE.clear()
    _ENTROPY_CACHE[value] = entropy
    return entropy


COMMENT_RE = re.compile(r"^\s*(//|/\*|\*|#)")


def is_code_line(line: str) -> bool:
    return not COMMENT_RE.match(line)
