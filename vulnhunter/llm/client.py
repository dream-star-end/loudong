"""Unified LLM client with automatic fallback to rule-based analysis.

When an API key is configured, uses the real LLM for reasoning.
Otherwise, falls back to deterministic rule-based analysis so the system
works out-of-the-box without any external API dependency.
"""

import json
import logging
from dataclasses import dataclass

import httpx

from vulnhunter.config import settings

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    content: str
    model: str
    usage_tokens: int = 0
    is_fallback: bool = False


class LLMClient:
    """Unified interface to LLM providers."""

    def __init__(self) -> None:
        self.provider = settings.llm_provider
        self.model = settings.llm_model
        self.api_key = settings.llm_api_key
        self._available = bool(self.api_key and self.api_key != "sk-placeholder")

    @property
    def available(self) -> bool:
        return self._available

    async def chat(
        self,
        system_prompt: str,
        user_message: str,
        temperature: float = 0.2,
    ) -> LLMResponse:
        if not self._available:
            return LLMResponse(
                content="", model="fallback", usage_tokens=0, is_fallback=True
            )

        try:
            if self.provider == "openai":
                return await self._call_openai(system_prompt, user_message, temperature)
            elif self.provider == "anthropic":
                return await self._call_anthropic(system_prompt, user_message, temperature)
            else:
                return await self._call_openai(system_prompt, user_message, temperature)
        except Exception as e:
            logger.warning("LLM call failed, using fallback: %s", e)
            return LLMResponse(
                content="", model="fallback", usage_tokens=0, is_fallback=True
            )

    async def _call_openai(
        self, system_prompt: str, user_message: str, temperature: float
    ) -> LLMResponse:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "temperature": temperature,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message},
                    ],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return LLMResponse(
                content=data["choices"][0]["message"]["content"],
                model=data["model"],
                usage_tokens=data.get("usage", {}).get("total_tokens", 0),
            )

    async def _call_anthropic(
        self, system_prompt: str, user_message: str, temperature: float
    ) -> LLMResponse:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                },
                json={
                    "model": self.model,
                    "max_tokens": 4096,
                    "temperature": temperature,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": user_message}],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return LLMResponse(
                content=data["content"][0]["text"],
                model=data["model"],
                usage_tokens=data.get("usage", {}).get("input_tokens", 0)
                + data.get("usage", {}).get("output_tokens", 0),
            )

    async def analyze_json(
        self, system_prompt: str, user_message: str
    ) -> dict | list:
        """Call LLM and parse response as JSON. Returns empty dict on fallback."""
        resp = await self.chat(system_prompt, user_message)
        if resp.is_fallback:
            return {}
        try:
            text = resp.content.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0]
            return json.loads(text)
        except (json.JSONDecodeError, IndexError):
            logger.warning("Failed to parse LLM JSON response")
            return {}
