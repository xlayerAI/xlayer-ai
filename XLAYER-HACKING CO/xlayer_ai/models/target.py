"""
XLayer AI Target Models - Data structures for targets and attack surface
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, HttpUrl


class HTTPMethod(str, Enum):
    """HTTP methods"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class EndpointType(str, Enum):
    """Types of discovered endpoints"""
    PAGE = "page"
    API = "api"
    FORM = "form"
    AUTH = "auth"
    FILE = "file"
    REDIRECT = "redirect"
    UNKNOWN = "unknown"


class InputType(str, Enum):
    """Types of input parameters"""
    URL_PARAM = "url_param"
    FORM_FIELD = "form_field"
    HEADER = "header"
    COOKIE = "cookie"
    JSON_BODY = "json_body"
    PATH_PARAM = "path_param"


class InputParameter(BaseModel):
    """Represents an input parameter that could be tested"""
    name: str
    input_type: InputType
    sample_value: Optional[str] = None
    required: bool = False
    validation_hints: List[str] = Field(default_factory=list)


class Endpoint(BaseModel):
    """Represents a discovered endpoint"""
    url: str
    method: HTTPMethod = HTTPMethod.GET
    endpoint_type: EndpointType = EndpointType.UNKNOWN
    parameters: List[InputParameter] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)
    auth_required: bool = False
    response_type: Optional[str] = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    
    @property
    def has_inputs(self) -> bool:
        """Check if endpoint has testable inputs"""
        return len(self.parameters) > 0


class ServiceInfo(BaseModel):
    """Information about a discovered service"""
    port: int
    protocol: str = "tcp"
    service: Optional[str] = None
    banner: Optional[str] = None
    version: Optional[str] = None


class TechnologyStack(BaseModel):
    """Detected technology stack"""
    server: Optional[str] = None
    language: Optional[str] = None
    framework: Optional[str] = None
    database: Optional[str] = None
    frontend: Optional[str] = None
    cms: Optional[str] = None
    waf: Optional[str] = None
    cdn: Optional[str] = None
    os: Optional[str] = None
    additional: Dict[str, str] = Field(default_factory=dict)


class Target(BaseModel):
    """Represents a scan target"""
    url: str
    scope: List[str] = Field(default_factory=list)
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    def is_in_scope(self, url: str) -> bool:
        """Check if URL is within scan scope"""
        if not self.scope:
            return url.startswith(self.url)
        return any(url.startswith(s) for s in self.scope)


class AttackSurface(BaseModel):
    """Complete attack surface map from reconnaissance"""
    target: Target
    
    ip_addresses: List[str] = Field(default_factory=list)
    open_ports: List[int] = Field(default_factory=list)
    services: List[ServiceInfo] = Field(default_factory=list)
    
    technology: TechnologyStack = Field(default_factory=TechnologyStack)
    
    endpoints: List[Endpoint] = Field(default_factory=list)
    forms: List[Endpoint] = Field(default_factory=list)
    api_endpoints: List[Endpoint] = Field(default_factory=list)
    auth_endpoints: List[Endpoint] = Field(default_factory=list)
    
    robots_txt: Optional[str] = None
    sitemap_urls: List[str] = Field(default_factory=list)
    
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    scan_duration_seconds: float = 0.0
    
    @property
    def all_endpoints(self) -> List[Endpoint]:
        """Get all discovered endpoints"""
        return self.endpoints + self.forms + self.api_endpoints + self.auth_endpoints
    
    @property
    def testable_endpoints(self) -> List[Endpoint]:
        """Get endpoints with testable inputs"""
        return [e for e in self.all_endpoints if e.has_inputs]
    
    @property
    def attack_surface_score(self) -> str:
        """Calculate attack surface score"""
        score = 0
        score += len(self.testable_endpoints) * 2
        score += len(self.auth_endpoints) * 3
        score += len(self.api_endpoints) * 2
        score += len(self.open_ports)
        
        if score > 50:
            return "critical"
        elif score > 30:
            return "high"
        elif score > 15:
            return "medium"
        else:
            return "low"
    
    def to_summary(self) -> Dict[str, Any]:
        """Generate summary for reporting"""
        return {
            "target": self.target.url,
            "ip_addresses": self.ip_addresses,
            "open_ports": self.open_ports,
            "technology": self.technology.model_dump(exclude_none=True),
            "endpoints_count": len(self.all_endpoints),
            "testable_inputs": len(self.testable_endpoints),
            "auth_endpoints": len(self.auth_endpoints),
            "attack_surface_score": self.attack_surface_score,
            "scan_duration": f"{self.scan_duration_seconds:.2f}s"
        }
