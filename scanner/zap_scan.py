import subprocess
import json
import os
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ZAP_DOCKER_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
ZAP_REPORT_NAME = "zap_report.json"
ZAP_WORK_DIR = os.path.join(os.environ.get("REPORT_DIR", "/tmp"), "zap_work")

ZAP_RISK_MAP = {
    "3": "CRITICAL",
    "2": "HIGH",
    "1": "MEDIUM",
    "0": "LOW",
    "high":     "CRITICAL",
    "medium":   "HIGH",
    "low":      "MEDIUM",
    "informational": "LOW",
}


def _risk_to_severity(risk_desc: str) -> str:
    risk_desc = str(risk_desc).lower().strip()
    for key, val in ZAP_RISK_MAP.items():
        if key in risk_desc:
            return val
    return "LOW"


def _parse_zap_json(path: str) -> list:
    findings = []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for site in data.get("site", []):
            site_name = site.get("@name", "")
            for alert in site.get("alerts", []):
                severity = _risk_to_severity(alert.get("riskdesc", ""))
                instances = alert.get("instances", [])
                urls = [i.get("uri", "") for i in instances[:3]]
                findings.append({
                    "type": "zap_alert",
                    "name": alert.get("alert", alert.get("name", "Unknown")),
                    "severity": severity,
                    "detail": alert.get("desc", "")[:400],
                    "solution": alert.get("solution", "")[:300],
                    "reference": alert.get("reference", "")[:200],
                    "cweid": alert.get("cweid", ""),
                    "wascid": alert.get("wascid", ""),
                    "site": site_name,
                    "affected_urls": urls,
                    "instance_count": len(instances),
                    "recommendation": alert.get("solution", "Refer to ZAP documentation for remediation.")[:300],
                })
    except Exception as e:
        findings.append({
            "type": "zap_parse_error",
            "severity": "LOW",
            "detail": f"Could not parse ZAP output: {str(e)}",
            "recommendation": "Review raw ZAP output manually.",
        })
    return findings


def run_zap_docker(target: str) -> list:
    findings = []
    os.makedirs(ZAP_WORK_DIR, exist_ok=True)
    report_host_path = os.path.join(ZAP_WORK_DIR, ZAP_REPORT_NAME)

    if os.path.exists(report_host_path):
        os.remove(report_host_path)

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{ZAP_WORK_DIR}:/zap/wrk:rw",
        ZAP_DOCKER_IMAGE,
        "zap-baseline.py",
        "-t", target,
        "-J", ZAP_REPORT_NAME,
        "-l", "WARN",
        "-z", "-config api.disablekey=true",
        "--auto",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
        print(result.stdout[-3000:] if len(result.stdout) > 3000 else result.stdout)

        if os.path.exists(report_host_path):
            findings = _parse_zap_json(report_host_path)
        else:
            findings.append({
                "type": "zap_no_output",
                "severity": "MEDIUM",
                "detail": "ZAP completed but no report file was generated",
                "recommendation": "Check ZAP Docker container permissions and working directory.",
            })

    except subprocess.TimeoutExpired:
        findings.append({
            "type": "zap_timeout",
            "severity": "MEDIUM",
            "detail": "ZAP scan timed out after 600 seconds",
            "recommendation": "Increase timeout or reduce scan scope.",
        })
    except FileNotFoundError:
        findings.append({
            "type": "docker_not_found",
            "severity": "INFO",
            "detail": "Docker is not installed or not in PATH - ZAP scan skipped",
            "recommendation": "Install Docker Desktop and retry with --zap flag.",
        })
    except Exception as e:
        findings.append({
            "type": "zap_error",
            "severity": "LOW",
            "detail": f"ZAP scan failed: {str(e)}",
            "recommendation": "Review Docker and ZAP configuration.",
        })
    return findings


def run_zap_api(target: str, zap_host: str = "http://localhost:8090", api_key: str = "") -> list:
    findings = []
    headers = {}

    def zap(path: str, params: dict = None) -> dict:
        p = params or {}
        if api_key:
            p["apikey"] = api_key
        r = requests.get(f"{zap_host}/JSON/{path}", params=p, timeout=30)
        return r.json()

    try:
        zap("core/action/accessUrl", {"url": target, "followRedirects": "true"})
        time.sleep(2)

        spider_resp = zap("spider/action/scan", {"url": target, "maxChildren": 5})
        scan_id = spider_resp.get("scan", "0")

        for _ in range(30):
            prog = zap("spider/view/status", {"scanId": scan_id})
            if int(prog.get("status", 0)) >= 100:
                break
            time.sleep(3)

        active_resp = zap("ascan/action/scan", {"url": target, "recurse": "true"})
        scan_id = active_resp.get("scan", "0")

        for _ in range(60):
            prog = zap("ascan/view/status", {"scanId": scan_id})
            if int(prog.get("status", 0)) >= 100:
                break
            time.sleep(5)

        alerts_resp = zap("core/view/alerts", {"baseurl": target, "start": 0, "count": 200})
        for alert in alerts_resp.get("alerts", []):
            findings.append({
                "type": "zap_alert",
                "name": alert.get("alert", "Unknown"),
                "severity": _risk_to_severity(alert.get("risk", "")),
                "detail": alert.get("description", "")[:400],
                "solution": alert.get("solution", "")[:300],
                "url": alert.get("url", ""),
                "cweid": alert.get("cweid", ""),
                "recommendation": alert.get("solution", "")[:300],
            })

    except requests.exceptions.ConnectionError:
        findings.append({
            "type": "zap_api_unavailable",
            "severity": "INFO",
            "detail": f"ZAP API not reachable at {zap_host}",
            "recommendation": "Start ZAP in daemon mode: zap.sh -daemon -port 8090",
        })
    except Exception as e:
        findings.append({
            "type": "zap_api_error",
            "severity": "LOW",
            "detail": str(e),
            "recommendation": "Review ZAP API configuration.",
        })
    return findings


def run_zap_scan(target: str, use_api: bool = False, zap_host: str = "http://localhost:8090", api_key: str = "") -> list:
    if use_api:
        return run_zap_api(target, zap_host, api_key)
    return run_zap_docker(target)