SEVERITY_WEIGHTS = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 1,
}


class RiskCalculator:
    def calculate(self, findings):
        total_score = 0
        severity_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        cvss_weighted_findings = 0

        for finding in findings:
            severity = finding.get("severity", "Low")
            if severity not in SEVERITY_WEIGHTS:
                severity = "Low"
            severity_count[severity] += 1

            severity_score = SEVERITY_WEIGHTS[severity]
            cvss_score = self._parse_cvss_score(finding.get("cvss_score"))
            if cvss_score is not None:
                total_score += max(severity_score, round(cvss_score))
                cvss_weighted_findings += 1
            else:
                total_score += severity_score

        if total_score >= 50:
            risk_level = "Critical"
        elif total_score >= 25:
            risk_level = "High"
        elif total_score >= 10:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        return {
            "total_findings": len(findings),
            "severity_count": severity_count,
            "total_score": total_score,
            "risk_level": risk_level,
            "cvss_weighted_findings": cvss_weighted_findings,
        }

    def _parse_cvss_score(self, value):
        if value is None:
            return None
        try:
            score = float(value)
        except (TypeError, ValueError):
            return None
        if score < 0:
            return 0.0
        if score > 10:
            return 10.0
        return score
