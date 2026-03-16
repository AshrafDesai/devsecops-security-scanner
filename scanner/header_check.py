import requests
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUIRED_HEADERS = {
    "Content-Security-Policy": {
        "severity": "HIGH",
        "detail": "Missing Content-Security-Policy header - XSS attacks possible",
        "recommendation": "Add CSP header: Content-Security-Policy: default-src 'self'",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "detail": "Missing X-Frame-Options header - clickjacking attacks possible",
        "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "detail": "Missing X-Content-Type-Options header - MIME sniffing attacks possible",
        "recommendation": "Add X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "detail": "Missing Referrer-Policy header - referrer data may leak",
        "recommendation": "Add Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "detail": "Missing Permissions-Policy header - browser features unrestricted",
        "recommendation": "Add Permissions-Policy to restrict camera, microphone, geolocation etc.",
    },
    "Cache-Control": {
        "severity": "LOW",
        "detail": "Missing Cache-Control header - sensitive data may be cached",
        "recommendation": "Add Cache-Control: no-store for sensitive pages",
    },
}

DISCLOSURE_HEADERS = {
    "X-Powered-By": {
        "severity": "MEDIUM",
        "detail_prefix": "Technology stack disclosed via X-Powered-By",
        "recommendation": "Remove X-Powered-By header to reduce information disclosure.",
    },
    "Server": {
        "severity": "LOW",
        "detail_prefix": "Server software disclosed via Server header",
        "recommendation": "Remove or genericize the Server header (e.g., 'Server: webserver').",
    },
    "X-AspNet-Version": {
        "severity": "MEDIUM",
        "detail_prefix": "ASP.NET version disclosed",
        "recommendation": "Remove X-AspNet-Version header in web.config.",
    },
    "X-AspNetMvc-Version": {
        "severity": "MEDIUM",
        "detail_prefix": "ASP.NET MVC version disclosed",
        "recommendation": "Remove X-AspNetMvc-Version header.",
    },
    "X-Generator": {
        "severity": "LOW",
        "detail_prefix": "CMS/framework disclosed via X-Generator",
        "recommendation": "Remove X-Generator header.",
    },
}

INSECURE_CSP_PATTERNS = [
    ("unsafe-inline", "MEDIUM", "CSP allows unsafe-inline - XSS risk remains"),
    ("unsafe-eval",   "MEDIUM", "CSP allows unsafe-eval - code injection risk"),
    ("*",             "HIGH",   "CSP uses wildcard source - effectively disabled"),
]

CORS_ISSUES = {
    "Access-Control-Allow-Origin": "*",
}


def _check_cors(headers: dict) -> list:
    findings = []
    acao = headers.get("access-control-allow-origin", "")
    if acao == "*":
        findings.append({
            "type": "cors_wildcard",
            "severity": "HIGH",
            "detail": "Access-Control-Allow-Origin: * allows any origin to make cross-origin requests",
            "recommendation": "Restrict CORS to specific trusted origins.",
        })
    acac = headers.get("access-control-allow-credentials", "")
    if acac.lower() == "true" and acao == "*":
        findings.append({
            "type": "cors_credentials_wildcard",
            "severity": "CRITICAL",
            "detail": "CORS wildcard combined with Allow-Credentials: true - credential theft possible",
            "recommendation": "Never combine Allow-Credentials: true with wildcard origin.",
        })
    return findings


def _check_csp(headers: dict) -> list:
    findings = []
    csp = headers.get("content-security-policy", "")
    if csp:
        for pattern, severity, detail in INSECURE_CSP_PATTERNS:
            if pattern in csp.lower():
                findings.append({
                    "type": "weak_csp",
                    "severity": severity,
                    "detail": detail,
                    "recommendation": f"Remove '{pattern}' from Content-Security-Policy.",
                })
    return findings


def _check_cookies(response) -> list:
    findings = []
    raw_cookies = response.headers.get("Set-Cookie", "")
    if not raw_cookies:
        return findings
    cookies = response.headers.getlist("Set-Cookie") if hasattr(response.headers, "getlist") else [raw_cookies]

    for cookie in cookies:
        cookie_lower = cookie.lower()
        name = cookie.split("=")[0].strip()
        if "httponly" not in cookie_lower:
            findings.append({
                "type": "cookie_missing_httponly",
                "severity": "MEDIUM",
                "detail": f"Cookie '{name}' missing HttpOnly flag - accessible via JavaScript",
                "recommendation": f"Add HttpOnly flag to cookie '{name}'.",
            })
        if "secure" not in cookie_lower:
            findings.append({
                "type": "cookie_missing_secure",
                "severity": "HIGH",
                "detail": f"Cookie '{name}' missing Secure flag - transmitted over HTTP",
                "recommendation": f"Add Secure flag to cookie '{name}'.",
            })
        if "samesite" not in cookie_lower:
            findings.append({
                "type": "cookie_missing_samesite",
                "severity": "MEDIUM",
                "detail": f"Cookie '{name}' missing SameSite attribute - CSRF risk",
                "recommendation": f"Add SameSite=Strict or SameSite=Lax to cookie '{name}'.",
            })
    return findings


def _check_xss_protection(headers: dict) -> list:
    findings = []
    xss = headers.get("x-xss-protection", "")
    if xss == "0":
        findings.append({
            "type": "xss_protection_disabled",
            "severity": "MEDIUM",
            "detail": "X-XSS-Protection is explicitly disabled",
            "recommendation": "Remove this header or set X-XSS-Protection: 1; mode=block",
        })
    return findings


def run_header_check(target: str) -> list:
    findings = []
    try:
        r = requests.get(
            target,
            timeout=10,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": "DevSecOps-Scanner/1.0"},
        )
        headers_lower = {k.lower(): v for k, v in r.headers.items()}

        for header, meta in REQUIRED_HEADERS.items():
            if header.lower() not in headers_lower:
                findings.append({
                    "type": f"missing_{header.lower().replace('-', '_')}",
                    "severity": meta["severity"],
                    "detail": meta["detail"],
                    "header": header,
                    "recommendation": meta["recommendation"],
                })

        for header, meta in DISCLOSURE_HEADERS.items():
            val = headers_lower.get(header.lower(), "")
            if val:
                findings.append({
                    "type": "information_disclosure",
                    "severity": meta["severity"],
                    "detail": f"{meta['detail_prefix']}: {val}",
                    "header": header,
                    "recommendation": meta["recommendation"],
                })

        findings.extend(_check_csp(headers_lower))
        findings.extend(_check_cors(headers_lower))
        findings.extend(_check_cookies(r))
        findings.extend(_check_xss_protection(headers_lower))

        if r.url.startswith("http://") and not r.url.startswith("https://"):
            findings.append({
                "type": "content_served_over_http",
                "severity": "HIGH",
                "detail": f"Page content is being served over unencrypted HTTP: {r.url}",
                "recommendation": "Serve all content over HTTPS.",
            })

    except requests.exceptions.SSLError as e:
        findings.append({
            "type": "ssl_error_on_request",
            "severity": "HIGH",
            "detail": f"SSL error when connecting: {str(e)[:200]}",
            "recommendation": "Investigate SSL certificate and configuration.",
        })
    except requests.exceptions.ConnectionError as e:
        findings.append({
            "type": "connection_error",
            "severity": "MEDIUM",
            "detail": f"Could not connect to target: {str(e)[:200]}",
            "recommendation": "Verify target URL is reachable.",
        })
    except Exception as e:
        findings.append({
            "type": "header_check_error",
            "severity": "LOW",
            "detail": str(e)[:200],
            "recommendation": "Manually review HTTP security headers.",
        })

    return findings