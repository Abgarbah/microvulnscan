import unittest
import json
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

from risk_engine.risk_calculator import RiskCalculator
from scanner.api_scanner import APIVulnerabilityScanner
from scanner.header_checker import check_security_headers
from reports.report_generator import ReportGenerator


def response(status_code, headers=None, text=""):
    return SimpleNamespace(status_code=status_code, headers=headers or {}, text=text)


class ApiScanningBehaviorTests(unittest.TestCase):
    def test_available_endpoint_runs_security_checks(self):
        scanner = APIVulnerabilityScanner(timeout=1, max_scan_seconds=30)
        with patch("scanner.api_scanner.requests.get", return_value=response(200, {})) as request:
            findings = scanner.scan("https://example.test", ["/products"])

        self.assertTrue(any(item.get("status") == "Available" for item in findings))
        self.assertTrue(any(item.get("type") == "MissingSecurityHeaders" for item in findings))
        self.assertGreater(request.call_count, 1)

    def test_not_found_skips_security_and_fuzz_checks(self):
        scanner = APIVulnerabilityScanner(timeout=1, max_scan_seconds=30)
        with patch("scanner.api_scanner.requests.get", return_value=response(404)) as request:
            findings = scanner.scan("https://example.test", ["/orders"])

        self.assertEqual(request.call_count, 1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "endpoint_status")
        self.assertEqual(findings[0]["status"], "Not Found")
        self.assertEqual(findings[0]["severity"], "Info")
        self.assertEqual(findings[0]["status_code"], 404)

    def test_other_statuses_are_distinguished(self):
        scanner = APIVulnerabilityScanner(timeout=1, max_scan_seconds=30)
        for code, expected in ((401, "Authentication Required"), (403, "Forbidden"), (500, "Server Error")):
            with self.subTest(code=code), patch("scanner.api_scanner.requests.get", return_value=response(code)):
                finding = scanner.scan("https://example.test", ["/resource"])[0]
                self.assertEqual(finding["status"], expected)
                self.assertEqual(finding["type"], "endpoint_status")

    def test_timeout_returns_structured_result(self):
        scanner = APIVulnerabilityScanner(timeout=1, max_scan_seconds=30)
        with patch("scanner.api_scanner.requests.get", side_effect=__import__("requests").exceptions.Timeout("slow")):
            finding = scanner.scan("https://example.test", ["/slow"])[0]
        self.assertEqual(finding["status"], "Timeout")
        self.assertEqual(finding["type"], "endpoint_status")

    def test_missing_headers_are_aggregated(self):
        findings = check_security_headers({})
        missing = [item for item in findings if item["type"] == "MissingSecurityHeaders"]
        self.assertEqual(len(missing), 1)
        self.assertEqual(len(missing[0]["evidence"]["missing_headers"]), 5)

    def test_duplicate_findings_are_removed_by_endpoint_and_type(self):
        scanner = APIVulnerabilityScanner()
        findings = scanner._deduplicate_findings([
            {"target": "/products", "type": "MissingSecurityHeaders"},
            {"target": "/products", "type": "MissingSecurityHeaders"},
            {"target": "/products", "type": "ServerHeaderExposed"},
        ])
        self.assertEqual(len(findings), 2)


class RiskCalculationTests(unittest.TestCase):
    def test_endpoint_status_does_not_affect_risk(self):
        result = RiskCalculator().calculate([
            {"type": "endpoint_status", "category": "endpoint_status", "severity": "Info"},
            {"type": "MissingSecurityHeaders", "category": "headers", "severity": "Medium"},
        ])
        self.assertEqual(result["total_score"], 4)
        self.assertEqual(result["total_findings"], 1)
        self.assertEqual(result["severity_count"]["Medium"], 1)


class ReportGenerationTests(unittest.TestCase):
    def test_reports_separate_endpoint_statuses_from_vulnerabilities(self):
        with tempfile.TemporaryDirectory() as output_dir:
            paths = ReportGenerator(output_dir).generate(
                [{
                    "target": "https://example.test/products",
                    "type": "endpoint_status",
                    "category": "endpoint_status",
                    "status_code": 404,
                    "status": "Not Found",
                    "name": "Endpoint Not Found",
                    "severity": "Info",
                }, {
                    "target": "https://example.test/products",
                    "type": "MissingSecurityHeaders",
                    "category": "headers",
                    "severity": "Medium",
                    "description": "Missing security headers",
                    "evidence": {"missing_headers": [
                        "content-security-policy",
                        "x-frame-options",
                    ]},
                }],
                [],
                RiskCalculator().calculate([
                    {"type": "endpoint_status", "category": "endpoint_status", "severity": "Info"},
                    {"type": "MissingSecurityHeaders", "category": "headers", "severity": "Medium"},
                ]),
            )
            with open(paths["json"], encoding="utf-8") as report_file:
                report = json.load(report_file)
            self.assertEqual(len(report["endpoint_statuses"]), 1)
            self.assertEqual(len(report["vulnerability_findings"]), 1)
            vulnerability = report["vulnerability_findings"][0]
            self.assertEqual(vulnerability["name"], "Missing Security Headers")
            with open(paths["html"], encoding="utf-8") as report_file:
                html = report_file.read()
            self.assertIn("Missing Security Headers", html)
            self.assertIn("content-security-policy", html)
            self.assertIn("x-frame-options", html)
            self.assertEqual(ReportGenerator(output_dir)._endpoint_path("https://example.test/products"), "/products")



if __name__ == "__main__":
    unittest.main()
