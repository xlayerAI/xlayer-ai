"""
XLayer AI - Google Gemini Provider

Auth priority:
  1. Application Default Credentials (gcloud auth application-default login)
     → No API key needed. Uses your Google account / Gemini subscription.
  2. GEMINI_API_KEY environment variable (or settings.llm.api_key)
     → Free tier: gemini-2.0-flash, 15 req/min, 1M tokens/day
     → Get key at: https://aistudio.google.com/apikey

Setup for ADC (one-time):
  pip install google-auth google-generativeai
  gcloud auth application-default login
  → browser opens → sign in with your Google account
  → credentials saved at ~/.config/gcloud/application_default_credentials.json
"""

import asyncio
from typing import Optional
from loguru import logger


class GeminiProvider:
    """
    Google Gemini provider with dual auth: ADC (gcloud OAuth) or API key.
    """

    DEFAULT_MODEL = "gemini-2.0-flash"

    def __init__(
        self,
        model: str = "",
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ):
        self.model = model or self.DEFAULT_MODEL
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._genai = None
        self._auth_method: Optional[str] = None

    async def initialize(self, api_key: Optional[str] = None) -> bool:
        """
        Try ADC first, then API key.
        Returns True if initialized successfully.
        """
        if await self._try_adc():
            return True

        if api_key:
            if await self._try_api_key(api_key):
                return True

        logger.warning(
            "Gemini auth failed. Choose one:\n"
            "  [ADC]     gcloud auth application-default login\n"
            "  [API key] set GEMINI_API_KEY=... in .env  (free at aistudio.google.com)"
        )
        return False

    async def _try_adc(self) -> bool:
        """Try Google Application Default Credentials."""
        try:
            import google.auth
            from google.auth.transport.requests import Request as GoogleRequest
            import google.generativeai as genai

            credentials, _ = google.auth.default(
                scopes=["https://www.googleapis.com/auth/generative-language"]
            )
            if not credentials.valid:
                await asyncio.to_thread(credentials.refresh, GoogleRequest())

            genai.configure(credentials=credentials)
            self._genai = genai
            self._auth_method = "adc"
            logger.info(f"Gemini: ADC auth OK (model={self.model})")
            return True

        except ImportError:
            logger.debug("Gemini ADC: google-auth not installed")
        except Exception as e:
            logger.debug(f"Gemini ADC not available: {e}")

        return False

    async def _try_api_key(self, api_key: str) -> bool:
        """Try direct API key auth."""
        try:
            import google.generativeai as genai

            genai.configure(api_key=api_key)
            self._genai = genai
            self._auth_method = "api_key"
            logger.info(f"Gemini: API key configured (model={self.model})")
            return True

        except ImportError:
            logger.warning("google-generativeai not installed. Run: pip install google-generativeai")
        except Exception as e:
            logger.warning(f"Gemini API key init failed: {e}")

        return False

    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_mode: bool = False,
    ) -> str:
        """Send a completion request."""
        if not self._genai:
            raise RuntimeError("GeminiProvider not initialized")

        gen_config_kwargs = {
            "temperature": self.temperature,
            "max_output_tokens": self.max_tokens,
        }
        if json_mode:
            gen_config_kwargs["response_mime_type"] = "application/json"

        gen_config = self._genai.GenerationConfig(**gen_config_kwargs)

        model_instance = self._genai.GenerativeModel(
            model_name=self.model,
            system_instruction=system_prompt or "You are a security expert.",
            generation_config=gen_config,
        )

        response = await asyncio.to_thread(model_instance.generate_content, prompt)
        return response.text

    @property
    def is_ready(self) -> bool:
        return self._genai is not None

    @property
    def auth_method(self) -> Optional[str]:
        return self._auth_method
