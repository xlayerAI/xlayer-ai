"""
XLayer AI Settings - Configuration management using Pydantic
"""

from functools import lru_cache
from typing import Optional, List
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMSettings(BaseSettings):
    """LLM provider configuration.

    Supported providers: openai, ollama, anthropic, gemini, kimi, minimax.
    - openai: GPT-4, GPT-3.5, etc. (model e.g. gpt-4o-mini)
    - ollama: Local models (model e.g. llama3.2)
    - anthropic: Claude models (model e.g. claude-3-5-sonnet-20241022)
    - gemini: Google Gemini (model e.g. gemini-1.5-pro, gemini-2.0-flash)
    - kimi: Moonshot Kimi (model e.g. moonshot-v1-8k, kimi-k2-turbo-preview). Uses base_url https://api.moonshot.ai/v1 if not set.
    - minimax: MiniMax (model e.g. abab6.5s). Set base_url https://api.minimax.io and group_id if required.
    """
    provider: str = Field(
        default="openai",
        description="LLM provider: openai, ollama, anthropic, gemini, kimi, minimax"
    )
    api_key: Optional[str] = Field(default=None, description="API key for LLM provider")
    model: str = Field(default="gpt-4o-mini", description="Model name to use")
    base_url: Optional[str] = Field(default=None, description="Custom API base URL (Ollama, Kimi, Minimax, etc.)")
    group_id: Optional[str] = Field(default=None, description="MiniMax group_id (required for Minimax)")
    temperature: float = Field(default=0.1, description="Temperature for generation")
    max_tokens: int = Field(default=4096, description="Max tokens for response")


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
    video: bool = Field(default=False, description="Record video of exploitation")
    max_attempts: int = Field(default=3, description="Max exploitation attempts per vuln")


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
    port_scan: PortScanSettings = Field(default_factory=PortScanSettings)
    exploit: ExploitSettings = Field(default_factory=ExploitSettings)
    report: ReportSettings = Field(default_factory=ReportSettings)
    
    hunters: List[str] = Field(
        default=["sqli", "xss", "auth", "ssrf", "lfi"],
        description="Enabled vulnerability hunters"
    )


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()
