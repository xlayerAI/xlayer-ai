"""
XLayer AI Settings - Configuration management using Pydantic
"""

from functools import lru_cache
from typing import Optional, List, Literal
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMSettings(BaseSettings):
    """LLM provider configuration"""
    provider: str = Field(
        default="openai",
        description="LLM provider: openai | ollama | gemini | gemini_adc | openai_oauth | none"
    )
    api_key: Optional[str] = Field(default=None, description="API key (OpenAI or Gemini)")
    model: str = Field(default="gpt-4o-mini", description="Model name to use")
    base_url: Optional[str] = Field(default=None, description="Custom API base URL (Ollama)")
    temperature: float = Field(default=0.1, description="Temperature for generation")
    max_tokens: int = Field(default=4096, description="Max tokens for response")
    persona_enabled: bool = Field(default=True, description="Enable persona prompts")
    persona_profile: str = Field(
        default="auto",
        description="Persona profile: auto|planner|reconnaissance|initial_access|summary|supervisor"
    )
    # OpenAI OAuth — required for openai_oauth provider
    openai_client_id: Optional[str] = Field(
        default=None,
        description="OAuth client_id for openai_oauth provider (ChatGPT/Codex subscription)"
    )

    @property
    def is_enabled(self) -> bool:
        """Check if LLM is configured and enabled."""
        if self.provider in ("none", "disabled"):
            return False
        # API-key-only providers
        if self.provider == "openai" and not self.api_key:
            return False
        # OAuth / ADC providers — no API key needed (auth handled at runtime)
        if self.provider in ("gemini", "gemini_adc", "openai_oauth", "ollama"):
            return True
        return True

    def validate_config(self) -> tuple:
        """Validate LLM configuration. Returns (is_valid, message)."""
        if self.provider == "openai":
            if not self.api_key:
                return False, "OpenAI provider requires XLAYER_LLM__API_KEY"
            return True, f"OpenAI → model={self.model}"
        elif self.provider == "ollama":
            base = self.base_url or "http://localhost:11434"
            return True, f"Ollama → {base}, model={self.model}"
        elif self.provider == "gemini":
            if self.api_key:
                return True, f"Gemini → API key, model={self.model or 'gemini-2.0-flash'}"
            return True, f"Gemini → ADC (gcloud), model={self.model or 'gemini-2.0-flash'}"
        elif self.provider == "gemini_adc":
            return True, f"Gemini ADC → gcloud credentials, model={self.model or 'gemini-2.0-flash'}"
        elif self.provider == "openai_oauth":
            if not self.openai_client_id:
                return False, "openai_oauth requires XLAYER_LLM__OPENAI_CLIENT_ID"
            return True, f"OpenAI OAuth → model={self.model or 'gpt-4o-mini'}"
        elif self.provider in ("none", "disabled"):
            return True, "LLM disabled — static-analysis-only mode"
        else:
            return False, f"Unknown LLM provider: {self.provider}"


class AuthSettings(BaseSettings):
    """Authentication configuration for scanning protected targets"""
    enabled: bool = Field(default=False, description="Enable authenticated scanning")

    # Form-based login
    login_url: Optional[str] = Field(default=None, description="Login form URL")
    username: Optional[str] = Field(default=None, description="Login username")
    password: Optional[str] = Field(default=None, description="Login password")
    username_field: str = Field(default="username", description="Username form field name")
    password_field: str = Field(default="password", description="Password form field name")
    success_url_contains: Optional[str] = Field(default=None, description="URL pattern after successful login")
    failure_text: Optional[str] = Field(default=None, description="Text shown on failed login")

    # Token-based
    bearer_token: Optional[str] = Field(default=None, description="Bearer token for Authorization header")
    api_key: Optional[str] = Field(default=None, description="API key value")
    api_key_header: str = Field(default="X-API-Key", description="Header name for API key")

    # Raw cookies
    session_cookie: Optional[str] = Field(default=None, description="Raw session cookie value (name=value)")


class ScanSettings(BaseSettings):
    """Scanning configuration"""
    max_depth: int = Field(default=3, description="Maximum crawl depth")
    max_pages: int = Field(default=100, description="Maximum pages to crawl")
    timeout: int = Field(default=30, description="Request timeout in seconds")
    rate_limit: float = Field(default=0.5, description="Delay between requests in seconds")
    user_agent: str = Field(
        default="XLayer-AI/1.0 (Security Scanner)",
        description="User agent string"
    )
    follow_redirects: bool = Field(default=True, description="Follow HTTP redirects")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")
    js_rendering: bool = Field(default=True, description="Enable JS rendering for SPA sites")
    hunter_concurrency: int = Field(
        default=6,
        description="Maximum hunters to execute concurrently in phase 2 (0 = unbounded)"
    )
    # Request pacing jitter (human-like, WAF evasion)
    pacing_jitter_min_sec: float = Field(default=0.0, description="Min delay between requests (0=disabled)")
    pacing_jitter_max_sec: float = Field(default=0.0, description="Max delay between requests (e.g. 1.5 for human-like)")


class PortScanSettings(BaseSettings):
    """Port scanning configuration"""
    enabled: bool = Field(default=True, description="Enable port scanning")
    top_ports: int = Field(default=100, description="Number of top ports to scan")
    timeout: float = Field(default=2.0, description="Connection timeout per port")
    concurrent: int = Field(default=100, description="Concurrent port scan connections")


class ExploitSettings(BaseSettings):
    """Exploitation configuration"""
    enabled: bool = Field(default=True, description="Enable exploitation phase")
    browser_timeout: int = Field(default=30, description="Browser page timeout")
    screenshot: bool = Field(default=True, description="Capture screenshots as evidence")
    headless_browser_required: Literal[True] = Field(
        default=True,
        description="Hard requirement: headless browser is mandatory and cannot be disabled"
    )
    video: bool = Field(default=False, description="Record video of exploitation")
    max_attempts: int = Field(default=3, description="Max exploitation attempts per vuln")
    use_agentic_exploit: bool = Field(
        default=False,
        description="Use Coordinator + Solver agentic exploit path in phase 3"
    )
    agentic_merge_with_exploit: bool = Field(
        default=True,
        description="When agentic exploit is enabled, merge classic ExploitAgent results"
    )
    strict_validators: bool = Field(
        default=True,
        description="Use stricter deterministic-style validation checks where available"
    )
    memory_learning: bool = Field(
        default=False,
        description="Enable memory-learning hooks for exploit phase (progressive rollout)"
    )


class ReportSettings(BaseSettings):
    """Report generation configuration"""
    output_dir: str = Field(default="./reports", description="Output directory for reports")
    formats: List[str] = Field(default=["json", "html"], description="Report formats to generate")
    include_evidence: bool = Field(default=True, description="Include evidence in report")
    executive_summary: bool = Field(default=True, description="Generate executive summary")


class Settings(BaseSettings):
    """Main XLayer AI settings"""
    model_config = SettingsConfigDict(
        env_prefix="XLAYER_",
        env_file=".env",
        env_nested_delimiter="__",
        extra="ignore"
    )
    
    debug: bool = Field(default=False, description="Enable debug mode")
    verbose: bool = Field(default=True, description="Verbose output")

    llm: LLMSettings = Field(default_factory=LLMSettings)
    scan: ScanSettings = Field(default_factory=ScanSettings)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    port_scan: PortScanSettings = Field(default_factory=PortScanSettings)
    exploit: ExploitSettings = Field(default_factory=ExploitSettings)
    report: ReportSettings = Field(default_factory=ReportSettings)
    
    hunters: List[str] = Field(
        default=[
            # Original 5
            "sqli", "xss", "auth", "ssrf", "lfi",
            # Agentic path — additional hunters
            "ssti", "rce", "xxe", "open_redirect", "cors",
            "csrf", "subdomain_takeover", "graphql",
            "race_condition", "deserialization", "http_smuggling",
        ],
        description="Enabled vulnerability hunters"
    )


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()
