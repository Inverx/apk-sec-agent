"""Manifest risk rules: debuggable / allowBackup / unprotected exports."""

from __future__ import annotations

from backend.analyzer.manifest import ComponentInfo
from backend.analyzer.rules.base import Finding, ScanContext, register


@register
class DebuggableRule:
    rule_id = "MANIFEST-001"
    category = "manifest"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        if ctx.manifest is None or not ctx.manifest.debuggable:
            return []
        return [
            Finding(
                rule_id=self.rule_id,
                category=self.category,
                severity="HIGH",
                cwe="CWE-489",
                title="应用开启 debuggable 调试标记",
                description=(
                    "android:debuggable=\"true\" 允许任意调试器附着到生产应用，"
                    "攻击者可借此读取内存、注入代码、绕过 Root 检测。"
                ),
                file="AndroidManifest.xml",
                line=1,
                snippet='<application android:debuggable="true">',
                suggestion="移除 android:debuggable=\"true\"，依赖构建类型的默认值（release 为 false）。",
            )
        ]


@register
class AllowBackupRule:
    rule_id = "MANIFEST-002"
    category = "manifest"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        if ctx.manifest is None or not ctx.manifest.allow_backup:
            return []
        return [
            Finding(
                rule_id=self.rule_id,
                category=self.category,
                severity="MEDIUM",
                cwe="CWE-530",
                title="允许应用数据备份 (allowBackup=true)",
                description=(
                    "开启 allowBackup 后可通过 adb backup 提取私有目录数据"
                    "（SharedPreferences、数据库、缓存），泄露登录态与敏感配置。"
                ),
                file="AndroidManifest.xml",
                line=1,
                snippet='<application android:allowBackup="true">',
                suggestion="设置 android:allowBackup=\"false\"，或配置 backup_rules 排除敏感文件。",
            )
        ]


@register
class ExportedComponentRule:
    rule_id = "MANIFEST-003"
    category = "manifest"

    LAUNCHER_ACTION = "android.intent.action.MAIN"
    LAUNCHER_CATEGORY = "android.intent.category.LAUNCHER"

    def _is_launcher(self, comp: ComponentInfo) -> bool:
        return (
            self.LAUNCHER_ACTION in comp.intent_actions
            and self.LAUNCHER_CATEGORY in comp.intent_categories
        )

    def scan(self, ctx: ScanContext) -> list[Finding]:
        if ctx.manifest is None:
            return []
        findings: list[Finding] = []
        for comp in ctx.manifest.components:
            if not comp.exported_effective or comp.permission:
                continue
            if self._is_launcher(comp):
                continue  # 入口 Activity 导出属于预期行为
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity="HIGH",
                    cwe="CWE-862",
                    title=f"导出组件缺少权限保护: {comp.name}",
                    description=(
                        f"{comp.type} `{comp.name}` 处于导出状态且未声明 permission，"
                        "任意第三方应用可直接拉起或投递 Intent，可能被用于界面劫持、"
                        "越权调用内部逻辑或注入恶意参数。"
                    ),
                    file="AndroidManifest.xml",
                    line=1,
                    snippet=f"<{comp.type} android:name=\"{comp.name}\" android:exported=\"true\">",
                    suggestion=(
                        "为非入口导出组件添加 android:permission（signature 级别），"
                        "或在不需要外部调用时设置 android:exported=\"false\"。"
                    ),
                )
            )
        return findings


@register
class CleartextManifestRule:
    rule_id = "NETWORK-001"
    category = "network"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        if ctx.manifest is None or not ctx.manifest.uses_cleartext_traffic:
            return []
        return [
            Finding(
                rule_id=self.rule_id,
                category=self.category,
                severity="MEDIUM",
                cwe="CWE-319",
                title="Manifest 允许全局明文流量 (usesCleartextTraffic=true)",
                description=(
                    "application 配置 usesCleartextTraffic=\"true\" 后，应用所有 HTTP "
                    "明文请求被系统放行，流量可被中间人窃听与篡改。"
                ),
                file="AndroidManifest.xml",
                line=1,
                snippet='<application android:usesCleartextTraffic="true">',
                suggestion="设置 usesCleartextTraffic=\"false\" 并配置 network_security_config 仅信任 HTTPS。",
            )
        ]
