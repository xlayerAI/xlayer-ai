"""
XLayer AI LLM Engine - Language model integration for intelligent analysis

Supports:
- OpenAI (GPT-4, GPT-3.5, etc.)
- Ollama (local models)
- Anthropic (Claude models)
- Google Gemini (gemini-1.5-pro, gemini-2.0-flash, etc.)
- Kimi / Moonshot (OpenAI-compatible)
- MiniMax (abab6.5s, etc.)
"""

import json
from typing import Optional, List, Dict, Any
from loguru import logger

from xlayer_hunter.config.settings import Settings, get_settings


class LLMEngine:
    """
    LLM Engine for intelligent security analysis
    
    Used for:
    - Payload selection optimization
    - Response analysis
    - Report generation enhancement
    - Vulnerability classification
    """
    
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self._client = None
        self._provider = self.settings.llm.provider
        self._minimax_group_id: Optional[str] = None
    
    async def initialize(self):
        """Initialize the LLM client"""
        if self._provider == "openai":
            await self._init_openai()
        elif self._provider == "ollama":
            await self._init_ollama()
        elif self._provider == "anthropic":
            await self._init_anthropic()
        elif self._provider == "gemini":
            await self._init_gemini()
        elif self._provider == "kimi":
            await self._init_kimi()
        elif self._provider == "minimax":
            await self._init_minimax()
        else:
            logger.warning(f"Unknown LLM provider: {self._provider}")
    
    async def _init_openai(self):
        """Initialize OpenAI client"""
        try:
            from openai import AsyncOpenAI
            
            api_key = self.settings.llm.api_key
            if not api_key:
                logger.warning("OpenAI API key not configured")
                return
            
            self._client = AsyncOpenAI(api_key=api_key)
            logger.info("OpenAI client initialized")
            
        except ImportError:
            logger.warning("OpenAI package not installed")
    
    async def _init_ollama(self):
        """Initialize Ollama client"""
        try:
            import httpx
            
            base_url = self.settings.llm.base_url or "http://localhost:11434"
            self._client = httpx.AsyncClient(base_url=base_url)
            logger.info(f"Ollama client initialized at {base_url}")
            
        except ImportError:
            logger.warning("httpx package not installed for Ollama")

    async def _init_anthropic(self):
        """Initialize Anthropic (Claude) client"""
        try:
            from anthropic import AsyncAnthropic
            
            api_key = self.settings.llm.api_key
            if not api_key:
                logger.warning("Anthropic API key not configured")
                return
            self._client = AsyncAnthropic(api_key=api_key)
            logger.info("Anthropic client initialized")
        except ImportError:
            logger.warning("anthropic package not installed: pip install anthropic")

    async def _init_gemini(self):
        """Initialize Google Gemini client"""
        try:
            from google import genai
            from google.genai import types
            
            api_key = self.settings.llm.api_key
            if not api_key:
                logger.warning("Gemini API key not configured")
                return
            self._client = genai.Client(api_key=api_key)
            logger.info("Gemini client initialized")
        except ImportError:
            logger.warning("google-genai package not installed: pip install google-genai")

    async def _init_kimi(self):
        """Initialize Kimi (Moonshot) client - OpenAI-compatible API"""
        try:
            from openai import AsyncOpenAI
            
            api_key = self.settings.llm.api_key
            if not api_key:
                logger.warning("Kimi/Moonshot API key not configured")
                return
            base_url = self.settings.llm.base_url or "https://api.moonshot.ai/v1"
            self._client = AsyncOpenAI(api_key=api_key, base_url=base_url)
            logger.info(f"Kimi client initialized at {base_url}")
        except ImportError:
            logger.warning("openai package not installed")

    async def _init_minimax(self):
        """Initialize MiniMax client (HTTP)"""
        try:
            import httpx
            
            api_key = self.settings.llm.api_key
            if not api_key:
                logger.warning("MiniMax API key not configured")
                return
            base_url = (self.settings.llm.base_url or "https://api.minimax.io").rstrip("/")
            self._client = httpx.AsyncClient(
                base_url=base_url,
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=60.0,
            )
            self._minimax_group_id = self.settings.llm.group_id
            logger.info("MiniMax client initialized")
        except ImportError:
            logger.warning("httpx package not installed for MiniMax")
    
    async def analyze_response(
        self,
        response_body: str,
        vuln_type: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze HTTP response for vulnerability indicators
        
        Args:
            response_body: HTTP response body
            vuln_type: Type of vulnerability being tested
            context: Additional context (endpoint, parameter, etc.)
            
        Returns:
            Analysis result with confidence and indicators
        """
        if not self._client:
            return {"error": "LLM not initialized", "confidence": 0}
        
        prompt = f"""Analyze this HTTP response for {vuln_type} vulnerability indicators.

Context:
- Endpoint: {context.get('endpoint', 'unknown')}
- Parameter: {context.get('parameter', 'unknown')}
- Payload sent: {context.get('payload', 'unknown')}

Response body (truncated):
{response_body[:2000]}

Analyze and respond in JSON format:
{{
    "vulnerable": true/false,
    "confidence": 0.0-1.0,
    "indicators": ["list of specific indicators found"],
    "evidence": "specific text from response proving vulnerability",
    "false_positive_risk": "low/medium/high",
    "recommended_payloads": ["list of payloads to try next"]
}}
"""
        
        try:
            result = await self._complete(prompt)
            return json.loads(result)
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return {"error": str(e), "confidence": 0}
    
    async def generate_payloads(
        self,
        vuln_type: str,
        context: Dict[str, Any],
        previous_attempts: List[str]
    ) -> List[str]:
        """
        Generate context-aware payloads using LLM
        
        Args:
            vuln_type: Type of vulnerability
            context: Target context (tech stack, WAF, etc.)
            previous_attempts: Previously tried payloads
            
        Returns:
            List of suggested payloads
        """
        if not self._client:
            return []
        
        prompt = f"""Generate {vuln_type} payloads for this target.

Target context:
- Technology: {context.get('technology', 'unknown')}
- Database: {context.get('database', 'unknown')}
- WAF detected: {context.get('waf', 'none')}
- Parameter type: {context.get('param_type', 'unknown')}

Previously tried (avoid these):
{json.dumps(previous_attempts[:10])}

Generate 5 new payloads optimized for this context. Consider WAF bypass techniques if WAF is detected.
Respond with JSON array of payload strings only.
"""
        
        try:
            result = await self._complete(prompt)
            return json.loads(result)
        except Exception as e:
            logger.error(f"Payload generation failed: {e}")
            return []
    
    async def enhance_report(
        self,
        finding: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Enhance vulnerability finding with LLM-generated content
        
        Args:
            finding: Raw finding data
            
        Returns:
            Enhanced finding with better descriptions
        """
        if not self._client:
            return finding
        
        prompt = f"""Enhance this security vulnerability finding for a professional penetration test report.

Finding:
{json.dumps(finding, indent=2)}

Provide enhanced content in JSON format:
{{
    "executive_description": "1-2 sentence description for executives",
    "technical_description": "detailed technical explanation",
    "business_impact": "specific business risks and compliance implications",
    "attack_scenario": "realistic attack scenario exploiting this vulnerability",
    "remediation_priority": "immediate/short-term/long-term",
    "remediation_steps": ["detailed step-by-step remediation"]
}}
"""
        
        try:
            result = await self._complete(prompt)
            enhanced = json.loads(result)
            finding.update(enhanced)
            return finding
        except Exception as e:
            logger.error(f"Report enhancement failed: {e}")
            return finding
    
    async def classify_vulnerability(
        self,
        response_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Classify vulnerability type and severity using LLM
        
        Args:
            response_data: Response data to analyze
            
        Returns:
            Classification with type, severity, and confidence
        """
        if not self._client:
            return {"type": "unknown", "severity": "unknown", "confidence": 0}
        
        prompt = f"""Classify this potential security vulnerability.

Data:
{json.dumps(response_data, indent=2)[:3000]}

Classify and respond in JSON format:
{{
    "vulnerability_type": "sqli/xss/auth_bypass/idor/ssrf/lfi/rfi/other",
    "severity": "critical/high/medium/low/info",
    "confidence": 0.0-1.0,
    "cwe_id": "CWE-XXX",
    "owasp_category": "A01-A10",
    "reasoning": "brief explanation of classification"
}}
"""
        
        try:
            result = await self._complete(prompt)
            return json.loads(result)
        except Exception as e:
            logger.error(f"Classification failed: {e}")
            return {"type": "unknown", "severity": "unknown", "confidence": 0}
    
    async def _complete(self, prompt: str) -> str:
        """Send completion request to LLM"""
        if self._provider == "openai":
            return await self._complete_openai(prompt)
        elif self._provider == "ollama":
            return await self._complete_ollama(prompt)
        elif self._provider == "anthropic":
            return await self._complete_anthropic(prompt)
        elif self._provider == "gemini":
            return await self._complete_gemini(prompt)
        elif self._provider == "kimi":
            return await self._complete_openai(prompt)  # OpenAI-compatible
        elif self._provider == "minimax":
            return await self._complete_minimax(prompt)
        else:
            raise ValueError(f"Unknown provider: {self._provider}")
    
    async def _complete_openai(self, prompt: str) -> str:
        """Complete using OpenAI API"""
        response = await self._client.chat.completions.create(
            model=self.settings.llm.model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a security expert analyzing web application vulnerabilities. Always respond in valid JSON format."
                },
                {"role": "user", "content": prompt}
            ],
            temperature=self.settings.llm.temperature,
            max_tokens=self.settings.llm.max_tokens
        )
        
        return response.choices[0].message.content
    
    async def _complete_ollama(self, prompt: str) -> str:
        """Complete using Ollama API"""
        response = await self._client.post(
            "/api/generate",
            json={
                "model": self.settings.llm.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": self.settings.llm.temperature
                }
            }
        )
        
        data = response.json()
        return data.get("response", "")

    async def _complete_anthropic(self, prompt: str) -> str:
        """Complete using Anthropic (Claude) API"""
        system = "You are a security expert analyzing web application vulnerabilities. Always respond in valid JSON format when asked for structured output."
        message = await self._client.messages.create(
            model=self.settings.llm.model,
            max_tokens=self.settings.llm.max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        if not message.content or not message.content[0].text:
            return ""
        return message.content[0].text

    async def _complete_gemini(self, prompt: str) -> str:
        """Complete using Google Gemini API"""
        try:
            from google.genai.types import GenerateContentConfig
            system = "You are a security expert analyzing web application vulnerabilities. Always respond in valid JSON format when asked for structured output."
            response = self._client.models.generate_content(
                model=self.settings.llm.model,
                contents=prompt,
                config=GenerateContentConfig(
                    system_instruction=system,
                    temperature=self.settings.llm.temperature,
                    max_output_tokens=self.settings.llm.max_tokens,
                ),
            )
        except Exception:
            # Fallback: no config, system in contents
            full_prompt = "You are a security expert. Respond in valid JSON when asked.\n\n" + prompt
            response = self._client.models.generate_content(
                model=self.settings.llm.model,
                contents=full_prompt,
            )
        if getattr(response, "text", None) is None:
            return ""
        return response.text

    async def _complete_minimax(self, prompt: str) -> str:
        """Complete using MiniMax chat completion API"""
        payload = {
            "model": self.settings.llm.model,
            "messages": [
                {"role": "system", "content": "You are a security expert. Always respond in valid JSON when asked for structured output."},
                {"role": "user", "content": prompt},
            ],
            "temperature": self.settings.llm.temperature,
            "max_tokens": self.settings.llm.max_tokens,
        }
        if self._minimax_group_id:
            payload["group_id"] = self._minimax_group_id
        response = await self._client.post("/v1/text/chatcompletion_v2", json=payload)
        response.raise_for_status()
        data = response.json()
        reply = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
        return reply or ""
    
    async def close(self):
        """Close LLM client connections"""
        if self._client is None:
            return
        if self._provider == "ollama":
            await self._client.aclose()
        elif self._provider == "minimax":
            await self._client.aclose()


async def get_llm_engine() -> LLMEngine:
    """Get initialized LLM engine instance"""
    engine = LLMEngine()
    await engine.initialize()
    return engine
