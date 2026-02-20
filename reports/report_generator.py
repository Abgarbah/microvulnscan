import json
import os
from datetime import datetime
from html import escape

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


class ReportGenerator:
    def __init__(self, output_dir="generated_reports"):
        self.output_dir = os.path.abspath(output_dir)
        os.makedirs(self.output_dir, exist_ok=True)

    def generate(self, api_findings, container_findings, risk_summary):
        timestamp = datetime.utcnow()
        report_data = {
            "generated_at": timestamp.isoformat() + "Z",
            "api_findings": api_findings,
            "container_findings": container_findings,
            "risk_summary": risk_summary,
        }

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
        findings = report_data["api_findings"] + report_data["container_findings"]
        for finding in findings:
            rows.append(
                (
                    "<tr>"
                    f"<td>{escape(str(finding.get('severity') or 'Low'))}</td>"
                    f"<td>{escape(str(finding.get('type') or 'UnknownIssue'))}</td>"
                    f"<td>{escape(str(finding.get('category') or 'unknown'))}</td>"
                    f"<td>{escape(str(finding.get('target') or 'unknown'))}</td>"
                    f"<td>{escape(str(finding.get('description') or 'No description'))}</td>"
                    "</tr>"
                )
            )

        html = (
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<title>VulnMicroScan Report</title>"
            "<style>body{font-family:Arial,sans-serif;padding:20px;}"
            "table{border-collapse:collapse;width:100%;}"
            "th,td{border:1px solid #ddd;padding:8px;text-align:left;}"
            "th{background:#f4f4f4;}</style></head><body>"
            "<h1>VulnMicroScan Report</h1>"
            f"<p>Generated at: {escape(str(report_data['generated_at']))}</p>"
            f"<p>Risk level: <strong>{escape(str(report_data['risk_summary']['risk_level']))}</strong></p>"
            f"<p>Total score: <strong>{report_data['risk_summary']['total_score']}</strong></p>"
            "<h2>Findings</h2><table><thead><tr>"
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
        y = height - 40

        c.setFont("Helvetica-Bold", 14)
        c.drawString(40, y, "VulnMicroScan Report")
        y -= 24

        c.setFont("Helvetica", 10)
        c.drawString(40, y, f"Generated at: {report_data['generated_at']}")
        y -= 14
        c.drawString(40, y, f"Risk level: {report_data['risk_summary']['risk_level']}")
        y -= 14
        c.drawString(40, y, f"Total score: {report_data['risk_summary']['total_score']}")
        y -= 20

        c.setFont("Helvetica-Bold", 11)
        c.drawString(40, y, "Findings")
        y -= 16
        c.setFont("Helvetica", 9)

        findings = report_data["api_findings"] + report_data["container_findings"]
        if not findings:
            c.drawString(40, y, "No findings.")
        else:
            for finding in findings[:200]:
                line = (
                    f"[{finding.get('severity', 'Low')}] "
                    f"{finding.get('type', 'UnknownIssue')} - "
                    f"{finding.get('target', 'unknown')}"
                )
                c.drawString(40, y, line[:110])
                y -= 12
                if y < 40:
                    c.showPage()
                    y = height - 40
                    c.setFont("Helvetica", 9)

        c.save()
