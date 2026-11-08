"""Rule registry bootstrap: importing this package registers all rules."""

from __future__ import annotations

from backend.analyzer.rules import (  # noqa: F401
    crypto_rules,
    manifest_rules,
    network_rules,
    packer_rules,
    secrets_rules,
    webview_rules,
)
from backend.analyzer.rules.base import all_rules, register  # noqa: F401
