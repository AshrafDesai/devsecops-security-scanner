from datetime import datetime

DEFAULT_THRESHOLDS = {
    "CRITICAL": 0,
    "HIGH":     2,
    "MEDIUM":   10,
    "LOW":      999,
}

SEVERITY_WEIGHT = {
    "CRITICAL": 10,
    "HIGH":     5,
    "MEDIUM":   2,
    "LOW":      1,
    "INFO":     0,
}

OWASP_MAPPING = {
    "no_https_redirect":            "A02:2021 - Cryptographic Failures",
    "ssl_cert_expired":             "A02:2021 - Cryptographic Failures",
    "ssl_cert_invalid":             "A02:2021 - Cryptographic Failures",
    "weak_cipher_suite":            "A02:2021 - Cryptographic Failures",
    "deprecated_tls_protocol":      "A02:2021 - Cryptographic Failures",
    "missing_content_security_policy": "A03:2021 - Injection",
    "weak_csp":                     "A03:2021 - Injection",
    "missing_x_frame_options":      "A05:2021 - Security Misconfiguration",
    "missing_x_content_type_options": "A05:2021 - Security Misconfiguration",
    "hsts_missing":                 "A05:2021 - Security Misconfiguration",
    "cors_wildcard":                "A05:2021 - Security Misconfiguration",
    "cors_credentials_wildcard":    "A01:2021 - Broken Access Control",
    "cookie_missing_httponly":      "A07:2021 - Identification and Authentication Failures",
    "cookie_missing_secure":        "A02:2021 - Cryptographic Failures",
    "cookie_missing_samesite":      "A01:2021 - Broken Access Control",
    "information_disclosure":       "A05:2021 - Security Misconfiguration",
    "open_port":                    "A05:2021 - Security Misconfiguration",
    "zap_alert":                    "A03:2021 - Injection",
}


def _count_by_severity(findings: list) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["LOW"] += 1
    return counts


def _compute_risk_score(counts: dict) -> int:
    score = 0
    for sev, count in counts.items():
        score += count * SEVERITY_WEIGHT.get(sev, 0)
    return min(score, 100)


def _risk_rating(score: int) -> str:
    if score >= 50:
        return "CRITICAL"
    elif score >= 25:
        return "HIGH"
    elif score >= 10:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "CLEAN"


def _enrich_with_owasp(findings: list) -> list:
    enriched = []
    for f in findings:
        f_copy = dict(f)
        ftype = f.get("type", "")
        if ftype in OWASP_MAPPING:
            f_copy["owasp_category"] = OWASP_MAPPING[ftype]
        enriched.append(f_copy)
    return enriched


def _group_by_severity(findings: list) -> dict:
    groups = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        groups.setdefault(sev, []).append(f)
    return groups


def evaluate(findings: list, thresholds: dict = None) -> dict:
    thresholds = thresholds or DEFAULT_THRESHOLDS
    counts = _count_by_severity(findings)
    enriched = _enrich_with_owasp(findings)
    grouped = _group_by_severity(enriched)
    risk_score = _compute_risk_score(counts)
    risk_rating = _risk_rating(risk_score)

    passed = True
    failure_reasons = []

    if counts["CRITICAL"] > thresholds.get("CRITICAL", 0):
        passed = False
        failure_reasons.append(
            f"{counts['CRITICAL']} CRITICAL finding(s) detected — threshold is {thresholds['CRITICAL']} (zero tolerance)"
        )

    if counts["HIGH"] > thresholds.get("HIGH", 2):
        passed = False
        failure_reasons.append(
            f"{counts['HIGH']} HIGH finding(s) detected — threshold is {thresholds['HIGH']}"
        )

    if counts["MEDIUM"] > thresholds.get("MEDIUM", 10):
        failure_reasons.append(
            f"{counts['MEDIUM']} MEDIUM finding(s) detected — threshold is {thresholds['MEDIUM']} (warning only)"
        )

    recommendations = list({
        f.get("recommendation", "")
        for f in enriched
        if f.get("severity", "") in ("CRITICAL", "HIGH") and f.get("recommendation")
    })

    return {
        "passed": passed,
        "exit_code": 0 if passed else 1,
        "risk_score": risk_score,
        "risk_rating": risk_rating,
        "severity_counts": counts,
        "total_findings": len(findings),
        "failure_reasons": failure_reasons,
        "thresholds_used": thresholds,
        "findings_by_severity": grouped,
        "top_recommendations": recommendations[:10],
        "evaluated_at": datetime.utcnow().isoformat() + "Z",
    }