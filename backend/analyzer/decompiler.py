"""Decompilation dispatcher: JADX CLI -> Apktool CLI -> builtin extractor.

Product layout inside a workspace directory (``data/workspaces/<sha256>/``):

- ``AndroidManifest.xml``  text manifest (converted when a tool is available)
- ``sources/**``           decompiled java sources
- ``raw/**``               all other original zip entries (libs, assets, res)

The builtin path handles zips that already contain a text manifest and
.java sources (synthetic test APKs, CI); real binary APKs route to JADX /
Apktool when configured.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import zipfile
from pathlib import Path

from backend.app.config import settings
from backend.services.storage import is_zip_slip_name, safe_extract

logger = logging.getLogger("app.analyzer")

SOURCE_EXTENSIONS = {".java", ".kt"}
MAX_SOURCE_BYTES = 2 * 1024 * 1024

# Common local installation paths probed when auto_detect_decompilers is enabled
KNOWN_JADX_PATHS = (
    r"C:\Program Files\jadx\bin\jadx.bat",
    "/usr/local/bin/jadx",
    "/usr/bin/jadx",
)
KNOWN_APKTOOL_PATHS = (
    r"C:\Program Files\apktool\apktool.bat",
    "/usr/local/bin/apktool",
    "/usr/bin/apktool",
)


class DecompileError(RuntimeError):
    pass


def _run_cmd(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    logger.info("running decompiler: %s", " ".join(cmd))
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=600,
        shell=False,
        check=False,
    )


def _wrap_cmd(path: str, args: list[str]) -> list[str]:
    """Windows .cmd launchers must run through cmd.exe."""
    if path.lower().endswith((".cmd", ".bat")):
        return ["cmd", "/c", path, *args]
    return [path, *args]


def _find_jadx() -> str:
    if settings.jadx_cli and Path(settings.jadx_cli).exists():
        return settings.jadx_cli
    if settings.auto_detect_decompilers:
        for known in KNOWN_JADX_PATHS:
            if Path(known).exists():
                logger.info("auto-detected JADX CLI: %s", known)
                return known
    which = shutil.which("jadx") or shutil.which("jadx.bat")
    return which or ""


def _find_apktool() -> str:
    if settings.apktool_cmd and Path(settings.apktool_cmd).exists():
        return settings.apktool_cmd
    if settings.auto_detect_decompilers:
        for known in KNOWN_APKTOOL_PATHS:
            if Path(known).exists():
                logger.info("auto-detected Apktool: %s", known)
                return known
    return shutil.which("apktool") or ""


def _looks_like_synthetic(zf: zipfile.ZipFile) -> bool:
    """True when the zip contains a text manifest and java sources."""
    names = zf.namelist()
    has_sources = any(n.endswith(".java") for n in names)
    manifest_entry = next((n for n in names if n == "AndroidManifest.xml"), None)
    if not manifest_entry or not has_sources:
        return False
    try:
        head = zf.open(manifest_entry).read(6)
    except (KeyError, zipfile.BadZipFile):
        return False
    return head.lstrip()[:1] == b"<"


def _builtin_extract(apk_path: Path, workspace: Path) -> dict:
    raw_dir = workspace / "raw"
    extracted = safe_extract(apk_path, raw_dir)

    manifest_src = raw_dir / "AndroidManifest.xml"
    manifest_dest = workspace / "AndroidManifest.xml"
    if manifest_src.exists():
        data = manifest_src.read_bytes()
        if data.lstrip()[:1] != b"<":
            logger.warning("binary AXML manifest requires JADX/Apktool; skipping manifest")
        else:
            manifest_dest.write_bytes(data)

    source_count = 0
    for ext in SOURCE_EXTENSIONS:
        source_count += len(list(raw_dir.rglob(f"*{ext}")))
    for name in extracted:
        if name.startswith(("sources/", "src/", "java/")):
            continue
    # Surface sources at workspace/sources/** when the zip used another root.
    src_root = raw_dir / "sources"
    if not src_root.exists():
        for candidate in ("src", "java"):
            c = raw_dir / candidate
            if c.exists() and any(c.rglob("*.java")):
                src_root = c
                break
    if src_root.exists():
        target_root = workspace / "sources"
        if not target_root.exists():
            shutil.copytree(src_root, target_root)

    return {
        "engine": "builtin",
        "manifest_found": manifest_dest.exists(),
        "source_files": source_count,
        "entries": len(extracted),
    }


def _decompile_jadx(apk_path: Path, workspace: Path) -> dict:
    jadx = _find_jadx()
    if not jadx:
        raise DecompileError("JADX CLI 未配置")
    sources_out = workspace / "_jadx_out"
    result = _run_cmd(_wrap_cmd(jadx, ["-q", "-deobf-min=3", "-d", str(sources_out),
                                       str(apk_path)]))
    if result.returncode != 0:
        raise DecompileError(f"JADX 退出码 {result.returncode}: {result.stderr[:500]}")

    jadx_sources = sources_out / "sources"
    if jadx_sources.exists():
        shutil.move(str(jadx_sources), str(workspace / "sources"))
    jadx_manifest = sources_out / "resources" / "AndroidManifest.xml"
    if jadx_manifest.exists():
        shutil.copy(jadx_manifest, workspace / "AndroidManifest.xml")
    jadx_resources = sources_out / "resources"
    if jadx_resources.exists():
        shutil.move(str(jadx_resources), str(workspace / "raw"))
    shutil.rmtree(sources_out, ignore_errors=True)

    source_files = sum(
        len(list((workspace / "sources").rglob(f"*{ext}")))
        for ext in SOURCE_EXTENSIONS
    ) if (workspace / "sources").exists() else 0
    return {
        "engine": "jadx",
        "manifest_found": (workspace / "AndroidManifest.xml").exists(),
        "source_files": source_files,
        "entries": source_files,
    }


def _decompile_apktool(apk_path: Path, workspace: Path) -> dict:
    apktool = _find_apktool()
    if not apktool:
        raise DecompileError("Apktool 未配置")
    out = workspace / "_apktool_out"
    result = _run_cmd(_wrap_cmd(apktool, ["d", "-f", "-o", str(out), str(apk_path)]))
    if result.returncode != 0:
        raise DecompileError(f"Apktool 退出码 {result.returncode}: {result.stderr[:500]}")

    if (out / "AndroidManifest.xml").exists():
        shutil.copy(out / "AndroidManifest.xml", workspace / "AndroidManifest.xml")
    smali_root = None
    for candidate in ("sources", "smali"):
        c = out / candidate
        if c.exists():
            smali_root = c
            break
    if smali_root is not None:
        shutil.move(str(smali_root), str(workspace / "sources"))
    (workspace / "raw").mkdir(parents=True, exist_ok=True)
    for keep in ("res", "assets", "lib", "unknown", "original"):
        src = out / keep
        if src.exists():
            shutil.move(str(src), str(workspace / "raw" / keep))
    shutil.rmtree(out, ignore_errors=True)

    source_files = sum(
        len(list((workspace / "sources").rglob(f"*{ext}")))
        for ext in SOURCE_EXTENSIONS
    ) if (workspace / "sources").exists() else 0
    return {
        "engine": "apktool",
        "manifest_found": (workspace / "AndroidManifest.xml").exists(),
        "source_files": source_files,
        "entries": source_files,
    }


def decompile(apk_path: Path, workspace: Path) -> dict:
    """Decompile an APK into ``workspace`` with three-level fallback.

    Raises DecompileError when the archive is unreadable or empty.
    """
    workspace.mkdir(parents=True, exist_ok=True)
    if not apk_path.exists():
        raise DecompileError(f"APK 文件不存在: {apk_path}")

    try:
        with zipfile.ZipFile(apk_path) as zf:
            names = [n for n in zf.namelist() if not is_zip_slip_name(n)]
    except zipfile.BadZipFile as exc:
        raise DecompileError(f"无法读取 ZIP: {exc}") from exc

    if not names:
        raise DecompileError("ZIP 内没有任何条目")

    synthetic = False
    try:
        with zipfile.ZipFile(apk_path) as zf:
            synthetic = _looks_like_synthetic(zf)
    except zipfile.BadZipFile:
        synthetic = False

    errors: list[str] = []
    if not synthetic:
        if _find_jadx():
            try:
                return _decompile_jadx(apk_path, workspace)
            except DecompileError as exc:
                errors.append(str(exc))
        if _find_apktool():
            try:
                return _decompile_apktool(apk_path, workspace)
            except DecompileError as exc:
                errors.append(str(exc))
        if errors:
            logger.warning("external decompilers failed, falling back to builtin: %s",
                           "; ".join(errors))

    result = _builtin_extract(apk_path, workspace)
    if result["source_files"] == 0 and not result["manifest_found"]:
        raise DecompileError(
            "内置解析器未找到可用 Manifest/源码；"
            + ("; ".join(errors) if errors else "请配置 JADX 或 Apktool 以分析二进制 APK")
        )
    return result
