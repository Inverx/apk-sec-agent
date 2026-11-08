"""Application settings loaded from environment variables / .env.

All generated artifacts stay inside the project ``data/`` directory so the
workspace containment policy holds. Sensitive values (secret key, LLM key)
are injected via environment variables and are masked in logs.
"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(REPO_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "APK-SecAgent"
    version: str = "1.0.0"
    secret_key: str = "dev-only-secret-change-me-3f9c1bd6a2e7"
    access_token_expire_minutes: int = 720

    database_url: str = f"sqlite:///{(REPO_ROOT / 'data' / 'apksec.db').as_posix()}"
    data_dir: Path = REPO_ROOT / "data"

    # upload limits
    max_upload_size: int = 200 * 1024 * 1024  # 200 MB
    chunk_size: int = 4 * 1024 * 1024  # 4 MB
    allowed_extensions: tuple[str, ...] = (".apk", ".zip")

    # middleware
    rate_limit_per_minute: int = 240

    # task pipeline
    task_timeout_seconds: int = 900
    task_max_retries: int = 2
    task_retry_backoff_seconds: float = 1.5
    worker_concurrency: int = 2
    max_chunks_per_index: int = 3000

    # external decompiler binaries (empty = auto-detect on PATH / fallback to builtin)
    jadx_cli: str = ""
    apktool_cmd: str = ""
    auto_detect_decompilers: bool = True

    # demo accounts seeded on first startup
    seed_demo: bool = True

    # OpenAI-compatible LLM (optional; offline engine used when absent)
    llm_api_key: str = ""
    llm_base_url: str = ""
    llm_model: str = ""


settings = Settings()
