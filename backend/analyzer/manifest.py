"""AndroidManifest.xml (plain-text XML) parsing.

Binary AXML manifests produced by aapt are converted to text by
JADX/Apktool before reaching this parser; the lightweight builtin pipeline
consumes zips whose manifest is already text (synthetic test APKs).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
COMPONENT_TAGS = {
    "activity": "activity",
    "activity-alias": "activity-alias",
    "service": "service",
    "receiver": "receiver",
    "provider": "provider",
}


def _attr(element: ET.Element, name: str) -> str | None:
    value = element.get(f"{ANDROID_NS}{name}")
    return value if value not in (None, "") else element.get(name)


@dataclass
class ComponentInfo:
    type: str
    name: str
    exported_attr: bool | None = None
    has_intent_filter: bool = False
    permission: str | None = None
    intent_actions: list[str] = field(default_factory=list)
    intent_categories: list[str] = field(default_factory=list)

    @property
    def exported_effective(self) -> bool:
        # Pre-API-31 semantics: intent-filter present => exported defaults true.
        if self.exported_attr is not None:
            return self.exported_attr
        return self.has_intent_filter

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "name": self.name,
            "exported": self.exported_effective,
            "exported_attr": self.exported_attr,
            "permission": self.permission,
            "intent_actions": self.intent_actions,
            "intent_categories": self.intent_categories,
        }


@dataclass
class ManifestInfo:
    package: str = ""
    version_name: str = ""
    application_class: str = ""
    debuggable: bool = False
    allow_backup: bool = True
    uses_cleartext_traffic: bool = False
    permissions: list[str] = field(default_factory=list)
    components: list[ComponentInfo] = field(default_factory=list)
    main_activity: str = ""

    @property
    def exported_components(self) -> list[dict]:
        return [c.to_dict() for c in self.components if c.exported_effective]

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "version_name": self.version_name,
            "application_class": self.application_class,
            "debuggable": self.debuggable,
            "allow_backup": self.allow_backup,
            "uses_cleartext_traffic": self.uses_cleartext_traffic,
            "permissions": list(self.permissions),
            "components": [c.to_dict() for c in self.components],
            "main_activity": self.main_activity,
            "exported_components": self.exported_components,
        }


def parse_manifest(xml_text: str) -> ManifestInfo:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"AndroidManifest.xml 解析失败: {exc}") from exc

    info = ManifestInfo()
    info.package = root.get("package", "") or ""
    info.version_name = _attr(root, "versionName") or ""

    application = root.find("application")
    if application is None:
        return info

    info.application_class = _attr(application, "name") or ""
    info.debuggable = (_attr(application, "debuggable") or "false").lower() == "true"
    info.allow_backup = (_attr(application, "allowBackup") or "false").lower() == "true"
    info.uses_cleartext_traffic = (
        (_attr(application, "usesCleartextTraffic") or "false").lower() == "true"
    )

    for perm in root.findall("uses-permission"):
        name = _attr(perm, "name")
        if name:
            info.permissions.append(name)

    for tag, comp_type in COMPONENT_TAGS.items():
        for element in application.findall(tag):
            component = ComponentInfo(
                type=comp_type,
                name=_attr(element, "name") or "(anonymous)",
                permission=_attr(element, "permission"),
            )
            exported_attr = _attr(element, "exported")
            if exported_attr is not None:
                component.exported_attr = exported_attr.lower() == "true"
            filters = element.findall("intent-filter")
            component.has_intent_filter = bool(filters)
            for f in filters:
                for action in f.findall("action"):
                    action_name = _attr(action, "name")
                    if action_name:
                        component.intent_actions.append(action_name)
                for category in f.findall("category"):
                    category_name = _attr(category, "name")
                    if category_name:
                        component.intent_categories.append(category_name)
                if (
                    "android.intent.action.MAIN" in component.intent_actions
                    and "android.intent.category.LAUNCHER" in component.intent_categories
                ):
                    info.main_activity = component.name
            info.components.append(component)

    return info
