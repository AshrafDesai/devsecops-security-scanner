import ssl
import socket
import datetime
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "ANON"
]

DEPRECATED_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]


def _extract_hostname(target: str) -> str:
    return target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]


def _check_https_redirect(hostname: str) -> list:
    findings = []
    try:
        r = requests.get(
            f"http://{hostname}",
            timeout=8,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "DevSecOps-Scanner/1.0"},
        )
        if not r.url.startswith("https://"):
            findings.append({
                "type": "no_https_redirect",
                "severity": "HIGH",
                "detail": f"HTTP does not redirect to HTTPS. Final URL: {r.url}",
                "recommendation": "Configure server to return 301 redirect from HTTP to HTTPS.",
            })
        else:
            if r.history and r.history[0].status_code not in (301, 308):
                findings.append({
                    "type": "non_permanent_redirect",
                    "severity": "LOW",
                    "detail": f"HTTP redirects to HTTPS with status {r.history[0].status_code} (should be 301 or 308)",
                    "recommendation": "Use a permanent redirect (301) to ensure browsers cache the HTTPS redirect.",
                })
    except requests.exceptions.ConnectionError:
        findings.append({
            "type": "http_port_closed",
            "severity": "INFO",
            "detail": f"Port 80 not reachable on {hostname} - HTTPS-only setup may be fine.",
            "recommendation": "Verify HTTP port 80 is intentionally closed.",
        })
    except Exception as e:
        findings.append({
            "type": "http_check_error",
            "severity": "LOW",
            "detail": str(e),
            "recommendation": "Manually verify HTTP to HTTPS redirect.",
        })
    return findings


def _check_certificate(hostname: str) -> list:
    findings = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, 443), timeout=8) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher_name, _, _ = ssock.cipher()

                exp_str = cert.get("notAfter", "")
                if exp_str:
                    exp_date = datetime.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp_date - datetime.datetime.utcnow()).days
                    if days_left < 0:
                        findings.append({
                            "type": "ssl_cert_expired",
                            "severity": "CRITICAL",
                            "detail": f"SSL certificate expired {abs(days_left)} days ago",
                            "recommendation": "Renew the SSL certificate immediately.",
                        })
                    elif days_left < 14:
                        findings.append({
                            "type": "ssl_cert_expiring_critical",
                            "severity": "CRITICAL",
                            "detail": f"SSL certificate expires in {days_left} days",
                            "recommendation": "Renew SSL certificate urgently.",
                        })
                    elif days_left < 30:
                        findings.append({
                            "type": "ssl_cert_expiring_soon",
                            "severity": "HIGH",
                            "detail": f"SSL certificate expires in {days_left} days",
                            "recommendation": "Plan SSL certificate renewal within the next week.",
                        })
                    elif days_left < 60:
                        findings.append({
                            "type": "ssl_cert_expiring",
                            "severity": "MEDIUM",
                            "detail": f"SSL certificate expires in {days_left} days",
                            "recommendation": "Schedule SSL certificate renewal.",
                        })

                if protocol in DEPRECATED_PROTOCOLS:
                    findings.append({
                        "type": "deprecated_tls_protocol",
                        "severity": "CRITICAL",
                        "detail": f"Server supports deprecated protocol: {protocol}",
                        "recommendation": f"Disable {protocol} and enforce TLS 1.2 or TLS 1.3 only.",
                    })

                for weak in WEAK_CIPHERS:
                    if weak.upper() in cipher_name.upper():
                        findings.append({
                            "type": "weak_cipher_suite",
                            "severity": "HIGH",
                            "detail": f"Weak cipher suite in use: {cipher_name}",
                            "recommendation": "Configure server to use strong cipher suites (AES-GCM, ChaCha20).",
                        })
                        break

                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                if subject == issuer:
                    findings.append({
                        "type": "self_signed_certificate",
                        "severity": "HIGH",
                        "detail": "Certificate is self-signed",
                        "recommendation": "Replace self-signed certificate with one from a trusted CA.",
                    })

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "type": "ssl_cert_invalid",
            "severity": "CRITICAL",
            "detail": f"SSL certificate verification failed: {str(e)}",
            "recommendation": "Investigate and replace the SSL certificate immediately.",
        })
    except ssl.SSLError as e:
        findings.append({
            "type": "ssl_handshake_error",
            "severity": "HIGH",
            "detail": f"SSL handshake failed: {str(e)}",
            "recommendation": "Review SSL/TLS configuration on the server.",
        })
    except ConnectionRefusedError:
        findings.append({
            "type": "https_port_closed",
            "severity": "HIGH",
            "detail": f"Port 443 not open on {hostname}",
            "recommendation": "Enable HTTPS on port 443.",
        })
    except Exception as e:
        findings.append({
            "type": "ssl_check_error",
            "severity": "MEDIUM",
            "detail": f"Could not complete SSL check: {str(e)}",
            "recommendation": "Manually verify SSL configuration.",
        })
    return findings


def _check_hsts(target: str) -> list:
    findings = []
    try:
        r = requests.get(target, timeout=8, verify=False, headers={"User-Agent": "DevSecOps-Scanner/1.0"})
        hsts = r.headers.get("Strict-Transport-Security", "")
        if not hsts:
            findings.append({
                "type": "hsts_missing",
                "severity": "HIGH",
                "detail": "Strict-Transport-Security header not present",
                "recommendation": "Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            })
        else:
            if "max-age" in hsts.lower():
                try:
                    max_age = int(hsts.lower().split("max-age=")[1].split(";")[0].strip())
                    if max_age < 31536000:
                        findings.append({
                            "type": "hsts_short_max_age",
                            "severity": "MEDIUM",
                            "detail": f"HSTS max-age is {max_age}s (recommended: 31536000+)",
                            "recommendation": "Increase HSTS max-age to at least 31536000 (1 year).",
                        })
                except (ValueError, IndexError):
                    pass
            if "includesubdomains" not in hsts.lower():
                findings.append({
                    "type": "hsts_no_subdomains",
                    "severity": "LOW",
                    "detail": "HSTS does not include subdomains",
                    "recommendation": "Add includeSubDomains to HSTS header.",
                })
    except Exception as e:
        findings.append({
            "type": "hsts_check_error",
            "severity": "LOW",
            "detail": str(e),
            "recommendation": "Manually verify HSTS configuration.",
        })
    return findings


def run_ssl_check(target: str) -> list:
    hostname = _extract_hostname(target)
    findings = []
    findings.extend(_check_https_redirect(hostname))
    findings.extend(_check_certificate(hostname))
    findings.extend(_check_hsts(target if target.startswith("https") else f"https://{hostname}"))
    return findings