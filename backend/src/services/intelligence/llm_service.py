from __future__ import annotations

from typing import Optional

import httpx


class OllamaService:
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

