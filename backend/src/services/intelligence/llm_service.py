from __future__ import annotations

from typing import Optional, Protocol

import httpx

from ...config import Settings


class LLMClient(Protocol):
    provider: str
    model: str

    async def generate(self, prompt: str, system: Optional[str] = None) -> str: ...

    async def is_available(self) -> bool: ...


class OllamaService:
    provider = "ollama"

    def __init__(self, host: str = "http://localhost:11434", model: str = "llama3:8b"):
        self.host = host
        self.model = model

    async def generate(self, prompt: str, system: Optional[str] = None) -> str:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{self.host}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "system": system,
                    "stream": False,
                },
            )
            result = response.json()
            return result.get("response", "")

    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.host}/api/tags")
                return response.status_code == 200
        except Exception:
            return False


class OpenRouterService:
    provider = "openrouter"

    def __init__(
        self,
        api_key: str,
        model: str = "openai/gpt-4o-mini",
        base_url: str = "https://openrouter.ai/api/v1",
        site_url: Optional[str] = None,
        app_name: Optional[str] = None,
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.site_url = site_url
        self.app_name = app_name

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        if self.site_url:
            headers["HTTP-Referer"] = self.site_url
        if self.app_name:
            headers["X-Title"] = self.app_name
        return headers

    async def generate(self, prompt: str, system: Optional[str] = None) -> str:
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers=self._headers(),
                json={
                    "model": self.model,
                    "messages": messages,
                    "temperature": 0.2,
                },
            )
            response.raise_for_status()
            data = response.json()

        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0] if isinstance(choices[0], dict) else {}
            msg = first.get("message")
            if isinstance(msg, dict):
                content = msg.get("content")
                if isinstance(content, str):
                    return content.strip()
            text = first.get("text")
            if isinstance(text, str):
                return text.strip()

        return ""

    async def is_available(self) -> bool:
        return bool(self.api_key)


def get_llm_service(settings: Settings) -> LLMClient:
    provider = (settings.llm_provider or "auto").strip().lower()

    if provider == "ollama":
        return OllamaService(host=settings.ollama_host, model=settings.ollama_model)

    if provider == "openrouter":
        return OpenRouterService(
            api_key=settings.open_router_api_key or "",
            model=settings.open_router_model,
            base_url=settings.open_router_base_url,
            site_url=settings.open_router_site_url,
            app_name=settings.open_router_app_name,
        )

    if settings.open_router_api_key:
        return OpenRouterService(
            api_key=settings.open_router_api_key,
            model=settings.open_router_model,
            base_url=settings.open_router_base_url,
            site_url=settings.open_router_site_url,
            app_name=settings.open_router_app_name,
        )

    return OllamaService(host=settings.ollama_host, model=settings.ollama_model)
