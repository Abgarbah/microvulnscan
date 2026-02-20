def analyze_response(status_code, response_text):
    issues = []
    body = (response_text or "").lower()

    if status_code >= 500:
        issues.append({
            "type": "ServerError",
            "severity": "Medium",
            "description": "Endpoint returned a 5xx status code under fuzzing input.",
        })

    sensitive_markers = ["sql", "syntax error", "traceback", "exception", "stack trace", "root:x:"]
    if any(marker in body for marker in sensitive_markers):
        issues.append({
            "type": "InformationDisclosure",
            "severity": "High",
            "description": "Response appears to leak internal implementation details.",
        })

    reflected_markers = ["<script>alert(1)</script>", "onmouseover=alert(1)"]
    if any(marker in body for marker in reflected_markers):
        issues.append({
            "type": "ReflectedXSS",
            "severity": "High",
            "description": "Potential reflected XSS payload detected in response body.",
        })

    return issues
