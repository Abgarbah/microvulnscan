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

    def _status_result(self, endpoint, url, status_code=None, status=None, description=None):
        finding_name = "Endpoint Not Found" if status == "Not Found" else (status or "Connection Error")
        return {
            "target": url,
            "endpoint": endpoint,
            "category": "endpoint_status",
            "type": "endpoint_status",
            "name": finding_name,
            "severity": "Info",
            "status_code": status_code,
            "status": status or "Connection Error",
            "description": description or f"Endpoint status: {status}.",
        }

    def _classify_status(self, status_code):
        if 200 <= status_code <= 299:
            return "Available"
        if status_code in {301, 302, 307, 308}:
            return "Redirect"
        return {
            401: "Authentication Required",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            429: "Too Many Requests",
        }.get(status_code, "Server Error" if 500 <= status_code <= 599 else f"HTTP {status_code}")

    def _scan_endpoint(self, endpoint, url):
        try:
            response = requests.get(url, timeout=self.timeout)
            status = self._classify_status(response.status_code)
            if not 200 <= response.status_code <= 299:
                return [self._status_result(
                    endpoint, url, response.status_code, status,
                    f"The endpoint returned HTTP {response.status_code} ({status}).",
                )], response
            findings = [
                {"target": url, "endpoint": endpoint, "category": "headers", **finding}
                for finding in check_security_headers(response.headers)
            ]
            return [self._status_result(endpoint, url, response.status_code, status,
                                        f"The endpoint returned HTTP {response.status_code} ({status}).")] + findings, response
        except requests.exceptions.Timeout as exc:
            return [self._status_result(endpoint, url, status="Timeout", description=f"The endpoint request timed out: {exc}")], None
        except requests.exceptions.ConnectionError as exc:
            return [self._status_result(endpoint, url, status="Connection Error", description=f"Could not connect to endpoint: {exc}")], None
        except requests.RequestException as exc:
            return [self._status_result(endpoint, url, status="Request Error", description=f"Endpoint request failed: {exc}")], None

    def _deduplicate_findings(self, findings):
        unique = []
        seen = set()
        for finding in findings:
            key = (
                finding.get("target"),
                finding.get("endpoint"),
                finding.get("name") or finding.get("type"),
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique

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
                    if not 200 <= response.status_code <= 299:
                        continue
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
            endpoint_findings, response = self._scan_endpoint(endpoint, full_url)
            findings.extend(endpoint_findings)
            if response is not None and 200 <= response.status_code <= 299:
                findings.extend(self._fuzz_endpoint(base_url, endpoint, started_at))
        return self._deduplicate_findings(findings)
