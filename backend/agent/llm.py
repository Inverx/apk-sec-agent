"""OpenAI-compatible chat client (optional; offline engine is the fallback)."""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger("app.agent.llm")


class LLMClient:
    def __init__(self, api_key: str = "", base_url: str = "", model: str = "") -> None:
        self.api_key = api_key.strip()
        self.base_url = base_url.strip().rstrip("/")
        self.model = model.strip()

    @property
    def configured(self) -> bool:
        return bool(self.api_key and self.base_url and self.model)

    async def chat_completion(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.2,
        timeout: float = 90.0,
    ) -> dict[str, Any]:
        """Return the assistant message dict from an OpenAI-compatible API."""
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
            response.raise_for_status()
            data = response.json()
        return data["choices"][0]["message"]
