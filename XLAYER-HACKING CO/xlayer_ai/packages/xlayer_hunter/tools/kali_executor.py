"""
XLayer AI Kali Executor - Run commands and offensive tools inside a Kali Docker container.

Native Python alternative to MCP: agent can use this class directly instead of
calling a separate MCP server. Fits "NATIVE IMPLEMENTATION: All tools are built-in Python code".

Tools exposed:
- run_command: arbitrary shell command in Kali
- hydra: brute-force authentication (SSH, FTP, HTTP, etc.)
- searchsploit: search Exploit-DB for vulnerabilities
"""

import subprocess
from typing import Optional, Union, List


CONTAINER_NAME = "attacker"


def _run_in_kali(command: str, container_name: str = CONTAINER_NAME) -> str:
    """
    Run a single command in the Kali Linux Docker container.
    Returns stdout on success, or an error message string on failure.
    """
    try:
        docker_check = subprocess.run(
            ["docker", "ps"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        if docker_check.returncode != 0:
            return f"[-] Docker is not available: {docker_check.stderr.strip()}"

        container_check = subprocess.run(
            ["docker", "ps", "-a", "--filter", f"name={container_name}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        if container_name not in container_check.stdout:
            return f"[-] Container '{container_name}' does not exist"

        running_check = subprocess.run(
            ["docker", "ps", "--filter", f"name={container_name}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        if container_name not in running_check.stdout:
            start_result = subprocess.run(
                ["docker", "start", container_name],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
            if start_result.returncode != 0:
                return (
                    f"[-] Failed to start container '{container_name}': "
                    f"{start_result.stderr.strip()}"
                )

        result = subprocess.run(
            ["docker", "exec", container_name, "sh", "-c", command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        if result.returncode != 0:
            return f"[-] Command execution error: {result.stderr.strip()}"
        return result.stdout.strip() or "(no output)"

    except FileNotFoundError:
        return "[-] Docker command not found. Is Docker installed and in PATH?"
    except Exception as e:
        return f"[-] Error: {str(e)} (Type: {type(e).__name__})"


class KaliExecutor:
    """
    Execute offensive security tools inside a Kali Linux Docker container.

    Use from ExploitAgent or Initial_Access swarm agent by importing and calling
    methods directly—no MCP server required.

    Example:
        executor = KaliExecutor()
        out = executor.run_command("whoami")
        out = executor.searchsploit("apache 2.4.49")
        out = executor.hydra("192.168.1.1", "-l root -P /root/data/wordlist/password.txt ssh")
    """

    def __init__(self, container_name: str = CONTAINER_NAME):
        self.container_name = container_name

    def run_command(self, command: str) -> str:
        """
        Run one command at a time in the Kali container. Use for nc, curl, msfconsole, etc.

        Args:
            command: Shell command to run (e.g. "nmap -sV 192.168.1.1")

        Returns:
            Command stdout or an error message.
        """
        return _run_in_kali(command, self.container_name)

    def hydra(
        self,
        target: str,
        options: Optional[Union[str, List[str]]] = None,
    ) -> str:
        """
        Run Hydra brute-force authentication attack in Kali.

        Args:
            target: Target IP/host or URL (e.g. "192.168.1.1" or "http://target/login")
            options: Hydra options (e.g. "-l admin -P /root/data/wordlist/password.txt ssh").
                     Can be string or list of args joined by space.

        Returns:
            Hydra output or error message.

        Example:
            hydra("192.168.1.1", "-l root -P /root/data/wordlist/password.txt ssh")
        """
        if options is None:
            args_str = ""
        elif isinstance(options, list):
            args_str = " ".join(str(x) for x in options)
        else:
            args_str = str(options)
        command = f"hydra {args_str.strip()} {target}".strip()
        return _run_in_kali(command, self.container_name)

    def searchsploit(
        self,
        service_name: str,
        options: Optional[Union[str, List[str]]] = None,
    ) -> str:
        """
        Search Exploit-DB (searchsploit) in Kali.

        Args:
            service_name: Service or CVE to search (e.g. "apache 2.4.49" or use with --cve).
            options: Extra options (e.g. "--cve CVE-2021-41773", "-t", "-e"). String or list.

        Returns:
            searchsploit output or error message.

        Example:
            searchsploit("apache 2.4.49")
            searchsploit("ssh", ["--cve", "CVE-2020-15778"])
        """
        if options is None:
            args_str = ""
        elif isinstance(options, list):
            args_str = " ".join(str(x) for x in options)
        else:
            args_str = str(options)
        command = f"searchsploit {args_str.strip()} {service_name}".strip()
        return _run_in_kali(command, self.container_name)
