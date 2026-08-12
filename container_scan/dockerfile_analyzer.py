import json
import re
import subprocess


class DockerfileAnalyzer:
    def __init__(self, trivy_enabled=True, trivy_command="trivy", trivy_timeout_seconds=90, trivy_max_findings=100):
        self.high_risk_base_images = ["latest", "alpine:latest", "ubuntu:latest"]
        self.trivy_enabled = trivy_enabled
        self.trivy_command = trivy_command
        self.trivy_timeout_seconds = trivy_timeout_seconds
        self.trivy_max_findings = trivy_max_findings

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

        findings.extend(self._scan_base_images_with_trivy(content, dockerfile_path))
        return findings

    def _scan_base_images_with_trivy(self, dockerfile_content, dockerfile_path):
        findings = []
        if not self.trivy_enabled:
            return findings

        base_images = self._extract_base_images(dockerfile_content)
        if not base_images:
            return findings

        for image in base_images:
            try:
                findings.extend(self._run_trivy_image_scan(image, dockerfile_path))
            except FileNotFoundError:
                findings.append({
                    "target": image,
                    "category": "container",
                    "type": "TrivyUnavailable",
                    "severity": "Low",
                    "description": f"Trivy command '{self.trivy_command}' not found; skipped CVE scan for {dockerfile_path}.",
                })
                break
            except subprocess.TimeoutExpired:
                findings.append({
                    "target": image,
                    "category": "container",
                    "type": "TrivyTimeout",
                    "severity": "Low",
                    "description": f"Trivy timed out after {self.trivy_timeout_seconds}s while scanning base image {image}.",
                })
            except Exception as exc:
                findings.append({
                    "target": image,
                    "category": "container",
                    "type": "TrivyScanError",
                    "severity": "Low",
                    "description": f"Trivy failed for base image {image}: {exc}",
                })

        return findings

    def _extract_base_images(self, dockerfile_content):
        images = []
        for line in dockerfile_content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^FROM\s+(?:--\S+\s+)*([^\s]+)", line, flags=re.IGNORECASE)
            if not match:
                continue
            image = match.group(1)
            if image not in images:
                images.append(image)
        return images

    def _run_trivy_image_scan(self, image, dockerfile_path):
        cmd = [
            self.trivy_command,
            "image",
            "--format",
            "json",
            "--quiet",
            "--scanners",
            "vuln",
            image,
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.trivy_timeout_seconds,
            check=False,
        )

        output = (proc.stdout or "").strip()
        if not output:
            stderr = (proc.stderr or "").strip()
            if proc.returncode != 0 and stderr:
                return [{
                    "target": image,
                    "category": "container",
                    "type": "TrivyScanError",
                    "severity": "Low",
                    "description": f"Trivy returned no JSON output for {image}: {stderr}",
                }]
            return []

        data = json.loads(output)
        vulnerabilities = []
        for result in data.get("Results", []):
            vulnerabilities.extend(result.get("Vulnerabilities", []))

        findings = []
        for vuln in vulnerabilities[: self.trivy_max_findings]:
            severity = self._normalize_severity(vuln.get("Severity"))
            cve = vuln.get("VulnerabilityID", "UnknownCVE")
            package = vuln.get("PkgName", "unknown-package")
            installed = vuln.get("InstalledVersion", "unknown")
            fixed = vuln.get("FixedVersion", "unfixed")
            cvss_score = self._extract_cvss_score(vuln)

            finding = {
                "target": image,
                "category": "container_cve",
                "type": "ContainerCVE",
                "severity": severity,
                "description": (
                    f"{cve} in {package} ({installed})"
                    f" fixed in {fixed}."
                ),
                "payload": dockerfile_path,
                "cve_id": cve,
            }
            if cvss_score is not None:
                finding["cvss_score"] = cvss_score

            findings.append(finding)

        return findings

    def _extract_cvss_score(self, vuln):
        cvss = vuln.get("CVSS") or {}
        scores = []
        for value in cvss.values():
            v3 = value.get("V3Score")
            v2 = value.get("V2Score")
            score = value.get("Score")
            for candidate in (v3, v2, score):
                if isinstance(candidate, (int, float)):
                    scores.append(float(candidate))
        if not scores:
            return None
        return round(max(scores), 1)

    def _normalize_severity(self, raw):
        if not raw:
            return "Low"
        value = str(raw).strip().lower()
        mapping = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "unknown": "Low",
        }
        return mapping.get(value, "Low")
