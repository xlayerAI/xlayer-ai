"""
XLayer AI Port Scanner - Async port scanner using native sockets
"""

import asyncio
import socket
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from loguru import logger


TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9090, 27017
]

TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
    2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009,
    5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001,
    6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000,
    32768, 49152, 49153, 49154, 49155, 49156, 49157
]

SERVICE_BANNERS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    27017: "mongodb"
}


@dataclass
class PortResult:
    """Result of a port scan"""
    port: int
    is_open: bool
    service: Optional[str] = None
    banner: Optional[str] = None
    error: Optional[str] = None


@dataclass
class ScanResult:
    """Complete scan result"""
    host: str
    open_ports: List[int]
    services: List[PortResult]
    scan_time_seconds: float


class PortScanner:
    """
    Async port scanner using native Python sockets
    
    No external dependencies (no nmap)
    """
    
    def __init__(
        self,
        timeout: float = 2.0,
        concurrent: int = 100,
        grab_banner: bool = True
    ):
        self.timeout = timeout
        self.concurrent = concurrent
        self.grab_banner = grab_banner
        self._semaphore: Optional[asyncio.Semaphore] = None
    
    async def scan_port(self, host: str, port: int) -> PortResult:
        """
        Scan a single port
        
        Args:
            host: Target hostname or IP
            port: Port number to scan
            
        Returns:
            PortResult with scan results
        """
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.concurrent)
        
        async with self._semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )
                
                banner = None
                service = SERVICE_BANNERS.get(port, "unknown")
                
                if self.grab_banner:
                    try:
                        writer.write(b"\r\n")
                        await writer.drain()
                        banner_data = await asyncio.wait_for(
                            reader.read(1024),
                            timeout=2.0
                        )
                        if banner_data:
                            banner = banner_data.decode("utf-8", errors="ignore").strip()
                    except (asyncio.TimeoutError, Exception):
                        pass
                
                writer.close()
                await writer.wait_closed()
                
                return PortResult(
                    port=port,
                    is_open=True,
                    service=service,
                    banner=banner
                )
                
            except asyncio.TimeoutError:
                return PortResult(port=port, is_open=False, error="timeout")
            except ConnectionRefusedError:
                return PortResult(port=port, is_open=False, error="refused")
            except OSError as e:
                return PortResult(port=port, is_open=False, error=str(e))
    
    async def scan_ports(
        self,
        host: str,
        ports: Optional[List[int]] = None,
        top_n: int = 100
    ) -> ScanResult:
        """
        Scan multiple ports on a host
        
        Args:
            host: Target hostname or IP
            ports: List of ports to scan (optional)
            top_n: Number of top ports to scan if ports not specified
            
        Returns:
            ScanResult with all findings
        """
        import time
        start_time = time.time()
        
        if ports is None:
            if top_n <= 25:
                ports = TOP_PORTS[:top_n]
            else:
                ports = TOP_100_PORTS[:top_n]
        
        logger.info(f"Scanning {len(ports)} ports on {host}")
        
        tasks = [self.scan_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks)
        
        open_ports = []
        services = []
        
        for result in results:
            if result.is_open:
                open_ports.append(result.port)
                services.append(result)
                logger.debug(f"Port {result.port} open: {result.service}")
        
        scan_time = time.time() - start_time
        logger.info(f"Scan complete: {len(open_ports)} open ports found in {scan_time:.2f}s")
        
        return ScanResult(
            host=host,
            open_ports=sorted(open_ports),
            services=services,
            scan_time_seconds=scan_time
        )
    
    async def quick_scan(self, host: str) -> List[int]:
        """Quick scan of common ports"""
        result = await self.scan_ports(host, ports=TOP_PORTS)
        return result.open_ports


async def resolve_hostname(hostname: str) -> Optional[str]:
    """
    Resolve hostname to IP address
    
    Args:
        hostname: Hostname to resolve
        
    Returns:
        IP address or None if resolution fails
    """
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            socket.gethostbyname,
            hostname
        )
        return result
    except socket.gaierror as e:
        logger.warning(f"DNS resolution failed for {hostname}: {e}")
        return None


async def get_dns_records(hostname: str) -> Dict[str, List[str]]:
    """
    Get DNS records for a hostname
    
    Args:
        hostname: Hostname to query
        
    Returns:
        Dictionary of record types to values
    """
    records = {"A": [], "AAAA": []}
    
    try:
        loop = asyncio.get_event_loop()
        
        try:
            ipv4_results = await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(hostname, None, socket.AF_INET)
            )
            records["A"] = list(set(r[4][0] for r in ipv4_results))
        except socket.gaierror:
            pass
        
        try:
            ipv6_results = await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(hostname, None, socket.AF_INET6)
            )
            records["AAAA"] = list(set(r[4][0] for r in ipv6_results))
        except socket.gaierror:
            pass
            
    except Exception as e:
        logger.warning(f"DNS query failed for {hostname}: {e}")
    
    return records
