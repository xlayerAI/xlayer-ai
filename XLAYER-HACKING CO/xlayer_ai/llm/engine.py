"""
XLayer AI LLM Engine - Language model integration for intelligent analysis

Supports:
- OpenAI API (GPT-4, GPT-3.5)
- Local models via Ollama
- Anthropic Claude (optional)
"""

import re
import json
from typing import Optional, List, Dict, Any
from loguru import logger

from xlayer_ai.config.settings import Settings, get_settings

try:
    from xlayer_ai.prompts.personas import (
        RECONNAISSANCE_PERSONA_PROMPT,
        INITIAL_ACCESS_PERSONA_PROMPT,
        PLANNER_PERSONA_PROMPT,
        SUMMARY_PERSONA_PROMPT,
        SUPERVISOR_PERSONA_PROMPT,
    )
except Exception:
    RECONNAISSANCE_PERSONA_PROMPT = ""
    INITIAL_ACCESS_PERSONA_PROMPT = ""
    PLANNER_PERSONA_PROMPT = ""
    SUMMARY_PERSONA_PROMPT = ""
    SUPERVISOR_PERSONA_PROMPT = ""


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

    def _select_persona_prompt(self, task: str) -> str:
        """Select persona prompt by configured profile or task intent."""
        if not self.settings.llm.persona_enabled:
            return ""

        persona_map = {
            "reconnaissance": RECONNAISSANCE_PERSONA_PROMPT,
            "initial_access": INITIAL_ACCESS_PERSONA_PROMPT,
            "planner": PLANNER_PERSONA_PROMPT,
            "summary": SUMMARY_PERSONA_PROMPT,
            "supervisor": SUPERVISOR_PERSONA_PROMPT,
        }

        profile = (self.settings.llm.persona_profile or "auto").strip().lower()
        if profile != "auto":
            return persona_map.get(profile, "")

        task_map = {
            "analyze_response": "reconnaissance",
            "generate_payloads": "initial_access",
            "enhance_report": "summary",
            "classify_vulnerability": "supervisor",
        }
        return persona_map.get(task_map.get(task, "planner"), "")

    def _compose_system_prompt(self, task: str, fallback: str) -> str:
        """Compose system prompt with optional persona layer."""
        persona_prompt = self._select_persona_prompt(task)
        if not persona_prompt:
            return fallback
        return (
            f"{persona_prompt}\n\n"
            "<operational_guardrails>\n"
            f"{fallback}\n"
            "</operational_guardrails>"
        )
    
    @property
    def is_ready(self) -> bool:
        """Check if LLM is initialized and ready"""
        return self._client is not None

    async def initialize(self):
        """Initialize the LLM client"""
        if self._provider == "openai":
            await self._init_openai()
        elif self._provider == "ollama":
            await self._init_ollama()
        elif self._provider in ("gemini", "gemini_adc"):
            await self._init_gemini()
            return  # GeminiProvider does its own validation
        elif self._provider == "openai_oauth":
            await self._init_openai_oauth()
            return  # OpenAIOAuthProvider does its own validation
        elif self._provider in ("none", "disabled"):
            logger.info("LLM disabled")
            return
        else:
            logger.warning(f"Unknown LLM provider: {self._provider}")
            return

        if self._client:
            try:
                await self._complete('Respond with exactly: {"status": "ok"}')
                logger.info("LLM connection verified")
            except Exception as e:
                logger.warning(f"LLM connection test failed: {e}. LLM features will be disabled.")
                self._client = None
    
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

    async def _init_gemini(self):
        """Initialize Gemini provider (ADC or API key)."""
        from xlayer_ai.llm.gemini_provider import GeminiProvider

        # gemini_adc → ADC only (no API key fallback)
        api_key = None if self._provider == "gemini_adc" else self.settings.llm.api_key

        provider = GeminiProvider(
            model=self.settings.llm.model or "gemini-2.0-flash",
            temperature=self.settings.llm.temperature,
            max_tokens=self.settings.llm.max_tokens,
        )
        ok = await provider.initialize(api_key=api_key)
        if ok:
            self._client = provider
            logger.info(f"Gemini ready via {provider.auth_method}")
        else:
            logger.warning("Gemini initialization failed — LLM features disabled")

    async def _init_openai_oauth(self):
        """Initialize OpenAI via PKCE OAuth (ChatGPT/Codex subscription)."""
        from xlayer_ai.llm.openai_oauth import OpenAIOAuthProvider

        provider = OpenAIOAuthProvider(
            model=self.settings.llm.model or "gpt-4o-mini",
            temperature=self.settings.llm.temperature,
            max_tokens=self.settings.llm.max_tokens,
            client_id=getattr(self.settings.llm, "openai_client_id", None),
        )
        ok = await provider.initialize()
        if ok:
            self._client = provider
            logger.info("OpenAI OAuth ready")
        else:
            logger.warning("OpenAI OAuth initialization failed — LLM features disabled")
    
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
            system_prompt = self._compose_system_prompt(
                "analyze_response",
                "You are a security expert analyzing web application vulnerabilities. Always respond in valid JSON format."
            )
            result = await self._complete(prompt, system_prompt=system_prompt)
            return json.loads(self._extract_json(result))
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
            system_prompt = self._compose_system_prompt(
                "generate_payloads",
                "You generate safe, context-aware security test payload candidates and return strict JSON arrays."
            )
            result = await self._complete(prompt, system_prompt=system_prompt)
            return json.loads(self._extract_json(result))
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
            system_prompt = self._compose_system_prompt(
                "enhance_report",
                "You are a professional security reporting specialist. Return concise, actionable JSON."
            )
            result = await self._complete(prompt, system_prompt=system_prompt)
            enhanced = json.loads(result)
            finding.update(enhanced)
            return finding
        except Exception as e:
            logger.error(f"Report enhancement failed: {e}")
            return finding

    async def get_remediation_snippet(
        self,
        vuln_type: str,
        parameter: str,
        endpoint: str = "",
    ) -> Optional[str]:
        """
        Generate a short safe-code snippet for the report (e.g. parameterized query, encode output).
        Returns one concise code example or None if LLM unavailable.
        """
        if not self._client:
            return None
        prompt = f"""Vulnerability: {vuln_type}, parameter: {parameter}, endpoint: {endpoint or 'N/A'}.
Provide ONE short safe-code fix snippet only (no explanation). Examples:
- SQLi: Use parameterized query: cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
- XSS: Encode output: html.escape(user_input) or use a safe template engine
- SSRF: Validate URL against allowlist; block file:// and internal IPs
Return only the code line or 1-2 line snippet, nothing else."""
        try:
            result = await self._complete(prompt, system_prompt="You are a secure coding expert. Reply with only the code snippet.")
            return (result or "").strip()[:500] or None
        except Exception as e:
            logger.debug(f"Remediation snippet failed: {e}")
            return None
    
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
            system_prompt = self._compose_system_prompt(
                "classify_vulnerability",
                "You are a security triage expert. Classify findings accurately and return strict JSON."
            )
            result = await self._complete(prompt, system_prompt=system_prompt)
            return json.loads(self._extract_json(result))
        except Exception as e:
            logger.error(f"Classification failed: {e}")
            return {"type": "unknown", "severity": "unknown", "confidence": 0}
    
    def _extract_json(self, text: str) -> str:
        """Extract JSON from LLM response, handling markdown code blocks"""
        code_block_match = re.search(r'```(?:json)?\s*([\s\S]*?)```', text)
        if code_block_match:
            return code_block_match.group(1).strip()
        json_match = re.search(r'(\{[\s\S]*\}|\[[\s\S]*\])', text)
        if json_match:
            return json_match.group(1).strip()
        return text.strip()

    async def _complete(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Send completion request to LLM"""
        if self._provider == "openai":
            return await self._complete_openai(prompt, system_prompt=system_prompt)
        elif self._provider == "ollama":
            return await self._complete_ollama(prompt, system_prompt=system_prompt)
        elif self._provider in ("gemini", "gemini_adc", "openai_oauth"):
            return await self._client.complete(prompt, system_prompt=system_prompt)
        else:
            raise ValueError(f"Unknown provider: {self._provider}")

    async def _complete_with_system(self, system_prompt: str, user_prompt: str) -> str:
        """Send completion with explicit system + user messages"""
        if self._provider == "openai":
            response = await self._client.chat.completions.create(
                model=self.settings.llm.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt}
                ],
                temperature=self.settings.llm.temperature,
                max_tokens=self.settings.llm.max_tokens,
                response_format={"type": "json_object"}
            )
            return response.choices[0].message.content
        elif self._provider == "ollama":
            combined = f"SYSTEM:\n{system_prompt}\n\nUSER:\n{user_prompt}"
            return await self._complete_ollama(combined)
        elif self._provider in ("gemini", "gemini_adc"):
            return await self._client.complete(user_prompt, system_prompt=system_prompt, json_mode=True)
        elif self._provider == "openai_oauth":
            return await self._client.complete(user_prompt, system_prompt=system_prompt, json_mode=True)
        else:
            raise ValueError(f"Unknown provider: {self._provider}")
    
    async def _complete_openai(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Complete using OpenAI API"""
        if not system_prompt:
            system_prompt = (
                "You are a security expert analyzing web application vulnerabilities. "
                "Always respond in valid JSON format."
            )
        response = await self._client.chat.completions.create(
            model=self.settings.llm.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            temperature=self.settings.llm.temperature,
            max_tokens=self.settings.llm.max_tokens
        )
        
        return response.choices[0].message.content
    
    async def _complete_ollama(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Complete using Ollama API"""
        full_prompt = prompt
        if system_prompt:
            full_prompt = f"SYSTEM:\n{system_prompt}\n\nUSER:\n{prompt}"
        response = await self._client.post(
            "/api/generate",
            json={
                "model": self.settings.llm.model,
                "prompt": full_prompt,
                "stream": False,
                "options": {
                    "temperature": self.settings.llm.temperature
                }
            }
        )
        
        data = response.json()
        return data.get("response", "")
    
    async def close(self):
        """Close LLM client connections"""
        if not self._client:
            return
        if self._provider == "ollama":
            await self._client.aclose()
        elif self._provider in ("gemini", "gemini_adc"):
            pass  # GeminiProvider has no persistent connection to close
        elif self._provider == "openai_oauth":
            await self._client.close()


async def get_llm_engine() -> LLMEngine:
    """Get initialized LLM engine instance"""
    engine = LLMEngine()
    await engine.initialize()
    return engine
