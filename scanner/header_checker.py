RECOMMENDED_SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "content-security-policy": None,
    "strict-transport-security": None,
    "referrer-policy": None,
}


def check_security_headers(headers):
    findings = []
    normalized = {k.lower(): v for k, v in headers.items()}
    missing_headers = []

    for header_name, expected_value in RECOMMENDED_SECURITY_HEADERS.items():
        value = normalized.get(header_name)
        if not value:
            missing_headers.append(header_name)
            continue

        if expected_value and expected_value.lower() not in value.lower():
            findings.append({
                "type": "WeakSecurityHeader",
                "severity": "Low",
                "description": f"Unexpected value for {header_name}: {value}",
            })

    if missing_headers:
        findings.insert(0, {
            "type": "MissingSecurityHeaders",
            "name": "Missing Security Headers",
            "severity": "Medium",
            "evidence": {"missing_headers": missing_headers},
            "description": "Missing security headers: " + ", ".join(missing_headers),
        })

    server_header = normalized.get("server", "")
    if server_header:
        findings.append({
            "type": "ServerHeaderExposed",
            "severity": "Low",
            "description": f"Server banner exposed: {server_header}",
        })

    return findings
