import time
import requests
from urllib.parse import urljoin

from scanner.payloads import PAYLOADS
from scanner.response_analyzer import analyze_response
from scanner.header_checker import check_security_headers


class APIVulnerabilityScanner:
    def __init__(self, timeout=8, max_scan_seconds=30):
        self.timeout = timeout
        self.max_scan_seconds = max_scan_seconds

    def _scan_endpoint_headers(self, url):
        findings = []
        try:
            response = requests.get(url, timeout=self.timeout)
            for finding in check_security_headers(response.headers):
                findings.append({"target": url, "category": "headers", **finding})
        except requests.RequestException as exc:
            findings.append({
                "target": url,
                "category": "connectivity",
                "type": "EndpointUnavailable",
                "severity": "Low",
                "description": f"Could not connect to endpoint: {exc}",
            })
        return findings

    def _fuzz_endpoint(self, base_url, endpoint, started_at):
        findings = []
        full_url = urljoin(base_url.rstrip("/") + "/", endpoint.lstrip("/"))

        for payload_type, payload_values in PAYLOADS.items():
            for payload in payload_values:
                if time.monotonic() - started_at >= self.max_scan_seconds:
                    findings.append({
                        "target": full_url,
                        "category": "scan_control",
                        "type": "ScanTimeLimitReached",
                        "severity": "Low",
                        "description": f"Stopped payload fuzzing after {self.max_scan_seconds}s limit.",
                    })
                    return findings
                params = {"input": payload}
                try:
                    response = requests.get(full_url, params=params, timeout=self.timeout)
                    issues = analyze_response(response.status_code, response.text)
                    for issue in issues:
                        findings.append({
                            "target": full_url,
                            "category": payload_type,
                            "payload": payload,
                            **issue,
                        })
                except requests.RequestException as exc:
                    findings.append({
                        "target": full_url,
                        "category": payload_type,
                        "type": "RequestError",
                        "severity": "Low",
                        "description": f"Error while testing payload '{payload}': {exc}",
                    })
        return findings

    def scan(self, base_url, endpoints):
        findings = []
        started_at = time.monotonic()
        for endpoint in endpoints:
            if time.monotonic() - started_at >= self.max_scan_seconds:
                findings.append({
                    "target": base_url,
                    "category": "scan_control",
                    "type": "ScanTimeLimitReached",
                    "severity": "Low",
                    "description": f"Stopped endpoint scan after {self.max_scan_seconds}s limit.",
                })
                break
            full_url = urljoin(base_url.rstrip("/") + "/", endpoint.lstrip("/"))
            findings.extend(self._scan_endpoint_headers(full_url))
            findings.extend(self._fuzz_endpoint(base_url, endpoint, started_at))
        return findings
