import socket
import concurrent.futures
from datetime import datetime

RISKY_PORTS = {
    21:    ("FTP",              "HIGH",     "FTP transmits credentials in plaintext"),
    22:    ("SSH",              "LOW",      "SSH open - ensure key-based auth only"),
    23:    ("Telnet",           "CRITICAL", "Telnet is a plaintext protocol - disable immediately"),
    25:    ("SMTP",             "MEDIUM",   "SMTP relay may be exploited for spam"),
    53:    ("DNS",              "MEDIUM",   "DNS exposed - check for zone transfer vulnerability"),
    80:    ("HTTP",             "MEDIUM",   "HTTP serving unencrypted traffic"),
    110:   ("POP3",             "HIGH",     "POP3 may expose email credentials"),
    135:   ("RPC",              "HIGH",     "Windows RPC - commonly exploited"),
    139:   ("NetBIOS",          "HIGH",     "NetBIOS - lateral movement risk"),
    143:   ("IMAP",             "HIGH",     "IMAP may expose email credentials"),
    443:   ("HTTPS",            "LOW",      "HTTPS open - verify certificate validity"),
    445:   ("SMB",              "CRITICAL", "SMB exposed - EternalBlue / ransomware risk"),
    1433:  ("MSSQL",            "CRITICAL", "MSSQL database port exposed to internet"),
    1521:  ("Oracle DB",        "CRITICAL", "Oracle database port exposed to internet"),
    2375:  ("Docker HTTP",      "CRITICAL", "Docker daemon unauthenticated API exposed"),
    2376:  ("Docker TLS",       "HIGH",     "Docker daemon TLS exposed"),
    3000:  ("Dev Server",       "MEDIUM",   "Development server possibly exposed"),
    3306:  ("MySQL",            "CRITICAL", "MySQL database port exposed to internet"),
    3389:  ("RDP",              "CRITICAL", "RDP exposed - brute force and exploit risk"),
    5432:  ("PostgreSQL",       "CRITICAL", "PostgreSQL database port exposed to internet"),
    5900:  ("VNC",              "HIGH",     "VNC remote desktop exposed"),
    6379:  ("Redis",            "CRITICAL", "Redis has no authentication by default"),
    7001:  ("WebLogic",         "HIGH",     "WebLogic commonly has critical CVEs"),
    8080:  ("HTTP Alt",         "MEDIUM",   "Alternate HTTP port - may be dev/staging"),
    8443:  ("HTTPS Alt",        "LOW",      "Alternate HTTPS port open"),
    8888:  ("Jupyter",          "HIGH",     "Jupyter Notebook may allow code execution"),
    9200:  ("Elasticsearch",    "CRITICAL", "Elasticsearch open - no auth by default"),
    9300:  ("Elasticsearch",    "CRITICAL", "Elasticsearch cluster port exposed"),
    11211: ("Memcached",        "HIGH",     "Memcached exposed - data leakage risk"),
    27017: ("MongoDB",          "CRITICAL", "MongoDB exposed - no auth by default"),
    27018: ("MongoDB",          "CRITICAL", "MongoDB shard port exposed"),
    50000: ("SAP",              "HIGH",     "SAP gateway port exposed"),
}

SCAN_TIMEOUT = 1.5
MAX_WORKERS = 100


def _probe_port(host: str, port: int) -> tuple:
    try:
        with socket.create_connection((host, port), timeout=SCAN_TIMEOUT):
            return port, True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return port, False


def _grab_banner(host: str, port: int) -> str:
    try:
        with socket.create_connection((host, port), timeout=2) as s:
            s.settimeout(2)
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            return s.recv(256).decode("utf-8", errors="replace").strip()[:120]
    except Exception:
        return ""


def _resolve_host(target: str) -> str:
    target = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target


def run_port_scan(target: str) -> list:
    findings = []
    host = _resolve_host(target)
    ports_to_scan = list(RISKY_PORTS.keys())

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(_probe_port, host, p): p for p in ports_to_scan}
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)

    for port in sorted(open_ports):
        service, severity, detail = RISKY_PORTS.get(port, ("Unknown", "LOW", f"Port {port} is open"))
        banner = _grab_banner(host, port)
        finding = {
            "type": "open_port",
            "port": port,
            "service": service,
            "severity": severity,
            "detail": detail,
            "host": host,
            "timestamp": datetime.utcnow().isoformat(),
            "recommendation": f"If port {port} ({service}) is not required externally, restrict access via firewall rules.",
        }
        if banner:
            finding["banner"] = banner
        findings.append(finding)

    if not findings:
        findings.append({
            "type": "port_scan_clean",
            "severity": "INFO",
            "detail": f"No high-risk ports found open on {host}",
            "host": host,
            "timestamp": datetime.utcnow().isoformat(),
        })

    return findings