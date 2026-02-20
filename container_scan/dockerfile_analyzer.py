import re


class DockerfileAnalyzer:
    def __init__(self):
        self.high_risk_base_images = ["latest", "alpine:latest", "ubuntu:latest"]

    def scan(self, dockerfile_path):
        findings = []

        try:
            with open(dockerfile_path, "r", encoding="utf-8") as file:
                lines = file.readlines()
        except FileNotFoundError:
            return [{
                "target": dockerfile_path,
                "category": "container",
                "type": "DockerfileMissing",
                "severity": "High",
                "description": "Dockerfile not found.",
            }]

        content = "".join(lines)

        if re.search(r"^FROM\s+[^\s]+:latest", content, flags=re.IGNORECASE | re.MULTILINE):
            findings.append({
                "target": dockerfile_path,
                "category": "container",
                "type": "MutableBaseImageTag",
                "severity": "Medium",
                "description": "Base image uses mutable ':latest' tag.",
            })

        if "USER" not in content.upper():
            findings.append({
                "target": dockerfile_path,
                "category": "container",
                "type": "RunsAsRoot",
                "severity": "High",
                "description": "No USER directive found; container may run as root.",
            })

        dangerous_patterns = [
            ("curl | sh", "Remote script execution detected (curl | sh)."),
            ("ADD http", "Remote URL used with ADD directive."),
            ("chmod 777", "Overly permissive file permissions found."),
        ]

        lower = content.lower()
        for pattern, desc in dangerous_patterns:
            if pattern in lower:
                findings.append({
                    "target": dockerfile_path,
                    "category": "container",
                    "type": "InsecureInstruction",
                    "severity": "High",
                    "description": desc,
                })

        return findings
