import json
import os
from datetime import datetime
from html import escape
from urllib.parse import urlparse

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


class ReportGenerator:
    def __init__(self, output_dir="generated_reports"):
        self.output_dir = os.path.abspath(output_dir)
        os.makedirs(self.output_dir, exist_ok=True)

    def generate(self, api_findings, container_findings, risk_summary, scan_info=None):
        timestamp = datetime.utcnow()
        api_report_findings = self._prepare_findings(api_findings)
        container_report_findings = self._prepare_findings(container_findings)
        report_data = {
            "generated_at": timestamp.isoformat() + "Z",
            "api_findings": api_report_findings,
            "container_findings": container_report_findings,
            "risk_summary": risk_summary,
            "scan_info": scan_info or {},
        }
        all_findings = api_report_findings + container_report_findings
        report_data["endpoint_statuses"] = [
            finding for finding in all_findings
            if finding.get("category") == "endpoint_status" or finding.get("type") == "endpoint_status"
        ]
        report_data["vulnerability_findings"] = [
            finding for finding in all_findings
            if finding.get("category") != "endpoint_status" and finding.get("type") != "endpoint_status"
        ]

        # Include microseconds to prevent collisions for rapid back-to-back scans.
        base_name = f"report_{timestamp.strftime('%Y%m%d_%H%M%S_%f')}"
        json_path = os.path.join(self.output_dir, f"{base_name}.json")
        html_path = os.path.join(self.output_dir, f"{base_name}.html")
        pdf_path = os.path.join(self.output_dir, f"{base_name}.pdf")

        os.makedirs(self.output_dir, exist_ok=True)

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        self._write_html(html_path, report_data)
        self._write_pdf(pdf_path, report_data)

        return {
            "json": json_path,
            "html": html_path,
            "pdf": pdf_path,
        }

    def _write_html(self, output_path, report_data):
        rows = []
        findings = report_data["vulnerability_findings"]
        statuses = report_data["endpoint_statuses"]
        status_rows = []
        for status in statuses:
            status_rows.append(
                "<tr>"
                f"<td>{escape(str(status.get('endpoint') or status.get('target') or 'unknown'))}</td>"
                f"<td>{escape(str(status.get('status_code') or '-'))}</td>"
                f"<td>{escape(str(status.get('status') or status.get('name') or 'Unknown'))}</td>"
                "</tr>"
            )
        for finding in findings:
            missing_headers = self._missing_headers(finding)
            details = escape(str(finding.get("description") or "No description"))
            if missing_headers:
                details += "<br><strong>Missing Headers:</strong><ul>"
                details += "".join(f"<li>{escape(header)}</li>" for header in missing_headers)
                details += "</ul>"
            rows.append(
                (
                    "<tr>"
                    f"<td>{escape(str(finding.get('severity') or 'Low'))}</td>"
                    f"<td>{escape(self._finding_name(finding))}</td>"
                    f"<td>{escape(str(finding.get('category') or 'unknown'))}</td>"
                    f"<td>{escape(self._endpoint_path(finding.get('endpoint') or finding.get('target')))}</td>"
                    f"<td>{details}</td>"
                    "</tr>"
                )
            )

        html = (
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<title>microvulnscan Report</title>"
            "<style>body{font-family:Arial,sans-serif;padding:20px;}"
            "table{border-collapse:collapse;width:100%;}"
            "th,td{border:1px solid #ddd;padding:8px;text-align:left;}"
            "th{background:#f4f4f4;}</style></head><body>"
            "<h1>microvulnscan Report</h1>"
            f"<p>Generated at: {escape(str(report_data['generated_at']))}</p>"
            f"<p>Risk level: <strong>{escape(str(report_data['risk_summary']['risk_level']))}</strong></p>"
            f"<p>Total score: <strong>{report_data['risk_summary']['total_score']}</strong></p>"
            "<h2>Endpoint Status Summary</h2><table><thead><tr>"
            "<th>Endpoint</th><th>HTTP Status</th><th>Status</th>"
            "</tr></thead><tbody>" + "".join(status_rows) + "</tbody></table>"
            "<h2>Vulnerability Findings</h2><table><thead><tr>"
            "<th>Severity</th><th>Type</th><th>Category</th><th>Target</th><th>Description</th>"
            "</tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table></body></html>"
        )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

    def _write_pdf(self, output_path, report_data):
        c = canvas.Canvas(output_path, pagesize=letter)
        width, height = letter
        left = 54
        right = width - 54
        y = height - 54
        risk_summary = report_data["risk_summary"]
        scan_info = report_data.get("scan_info") or {}
        findings = report_data["vulnerability_findings"]
        statuses = report_data["endpoint_statuses"]

        def new_page():
            nonlocal y
            c.showPage()
            y = height - 54
            c.setFont("Courier", 10)

        def ensure_space(points):
            if y < points:
                new_page()

        def divider():
            nonlocal y
            ensure_space(70)
            c.setStrokeColorRGB(0.72, 0.75, 0.8)
            c.line(left, y, right, y)
            y -= 18

        def text(label, value):
            nonlocal y
            ensure_space(58)
            c.setFont("Courier-Bold", 10)
            c.drawString(left, y, f"{label:<14}:")
            c.setFont("Courier", 10)
            c.drawString(left + 102, y, str(value))
            y -= 16

        def section(title):
            nonlocal y
            ensure_space(72)
            divider()
            c.setFont("Courier-Bold", 12)
            c.drawString(left, y, title)
            y -= 18

        c.setTitle("microvulnscan Report")
        c.setFont("Courier-Bold", 16)
        c.rect(left, y - 34, right - left, 34, stroke=1, fill=0)
        c.drawCentredString(width / 2, y - 22, "microvulnscan Report")
        y -= 58

        c.setFont("Courier-Bold", 12)
        c.drawString(left, y, "Scan Information")
        y -= 18
        divider()
        text("Target", scan_info.get("target") or self._target_from_findings(findings))
        text("Scanner", scan_info.get("scanner") or "microvulnscan")
        text("Date", self._pdf_date(report_data["generated_at"]))
        text("Status", scan_info.get("status") or "Completed")
        y -= 8
        text("Overall Risk", str(risk_summary.get("risk_level", "Unknown")).upper())
        text("Risk Score", f"{risk_summary.get('total_score', 0)} / 100")

        section("Vulnerability Summary")
        counts = risk_summary.get("severity_count", {}) or {}
        for severity in ("Critical", "High", "Medium", "Low"):
            c.setFont("Courier", 10)
            c.drawString(left, y, f"{severity:<14}{counts.get(severity, 0)}")
            y -= 16

        section("Endpoint Status Summary")
        if not statuses:
            c.setFont("Courier", 10)
            c.drawString(left, y, "No endpoint status results were captured.")
            y -= 16
        else:
            c.setFont("Courier", 9)
            for status in statuses[:200]:
                ensure_space(42)
                endpoint = self._short_text(status.get("endpoint") or status.get("target") or "unknown", 42)
                code = str(status.get("status_code") or "-")
                label = self._short_text(status.get("status") or status.get("name") or "Unknown", 24)
                c.drawString(left, y, f"{code:<6}{label:<25}{endpoint}")
                y -= 14

        section("Findings")
        if not findings:
            c.setFont("Courier", 10)
            c.drawString(left, y, "No findings were captured.")
            y -= 16
        else:
            c.setFont("Courier", 9)
            for finding in findings[:200]:
                ensure_space(70)
                severity = self._short_text(str(finding.get("severity") or "Low").title(), 9)
                issue_type = self._short_text(self._finding_name(finding), 28)
                target = self._endpoint_path(finding.get("endpoint") or finding.get("target"))
                c.drawString(left, y, f"{severity:<9}{issue_type:<30}{target}")
                y -= 14
                missing_headers = self._missing_headers(finding)
                if missing_headers:
                    ensure_space(30)
                    c.setFont("Courier-Bold", 8)
                    c.drawString(left + 18, y, "Missing headers:")
                    y -= 12
                    c.setFont("Courier", 8)
                    for header in missing_headers:
                        ensure_space(24)
                        c.drawString(left + 30, y, f"- {header}")
                        y -= 12
            if len(findings) > 200:
                c.drawString(left, y, f"... {len(findings) - 200} additional findings omitted")
                y -= 14

        section("Recommendations")
        c.setFont("Courier", 10)
        for item in self._recommendations(findings, risk_summary):
            ensure_space(58)
            c.drawString(left, y, f"- {item}")
            y -= 16

        divider()
        c.setFont("Courier-Bold", 10)
        c.drawString(left, y, "Generated by microvulnscan")
        c.save()

    def _pdf_date(self, generated_at):
        try:
            value = datetime.fromisoformat(str(generated_at).replace("Z", "+00:00"))
            return value.strftime("%d-%m-%Y")
        except ValueError:
            return str(generated_at)[:10]

    def _target_from_findings(self, findings):
        for finding in findings:
            target = finding.get("target")
            if target:
                return target
        return "Not specified"

    def _recommendations(self, findings, risk_summary):
        recommendations = []
        text = " ".join(
            f"{finding.get('type', '')} {finding.get('description', '')}".lower()
            for finding in findings
        )
        if "header" in text:
            recommendations.append("Configure HTTP security headers")
        if "error" in text or "disclosure" in text:
            recommendations.append("Disable verbose error messages")
        if "time limit" in text or "timeout" in text:
            recommendations.append("Increase scan timeout")
        if risk_summary.get("risk_level") in {"Critical", "High", "Medium"}:
            recommendations.append("Prioritize remediation by severity")
        recommendations.append("Re-run assessment")
        return recommendations

    def _short_text(self, value, max_length):
        text = " ".join(str(value).split())
        if len(text) <= max_length:
            return text
        return text[: max_length - 3].rstrip() + "..."

    def _prepare_findings(self, findings):
        prepared = []
        for finding in findings:
            report_finding = dict(finding)
            report_finding.setdefault("name", self._finding_name(report_finding))
            prepared.append(report_finding)
        return prepared

    def _finding_name(self, finding):
        return finding.get("name") or {
            "MissingSecurityHeaders": "Missing Security Headers",
        }.get(finding.get("type") or finding.get("issue_type"), finding.get("type") or finding.get("issue_type") or "UnknownIssue")

    def _missing_headers(self, finding):
        evidence = finding.get("evidence") or {}
        headers = evidence.get("missing_headers") if isinstance(evidence, dict) else None
        return headers or []

    def _endpoint_path(self, target):
        if not target:
            return "unknown"
        value = str(target)
        parsed = urlparse(value)
        if parsed.scheme and parsed.netloc:
            return parsed.path or "/"
        return value
