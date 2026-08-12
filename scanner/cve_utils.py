import time

import requests

try:
    from cvss import CVSS2, CVSS3, CVSS4
except Exception:
    CVSS2 = None
    CVSS3 = None
    CVSS4 = None


NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


class CVEEnricher:
    def __init__(self, enabled=True, api_key=None, timeout_seconds=12, min_interval_seconds=0.7):
        self.enabled = enabled
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.min_interval_seconds = min_interval_seconds
        self._cache = {}
        self._last_request_ts = 0.0

    def enrich_findings(self, findings):
        if not self.enabled:
            return findings

        for finding in findings:
            cve_id = (finding.get("cve_id") or "").strip().upper()
            if not cve_id:
                continue
            # Skip external call when we already have CVSS.
            if finding.get("cvss_score") is not None:
                continue

            cvss_info = self.get_cvss_from_nvd(cve_id)
            if not cvss_info:
                continue

            score = cvss_info.get("base_score")
            if score is not None:
                finding["cvss_score"] = score

            nvd_sev = _normalize_severity(cvss_info.get("severity"))
            if nvd_sev:
                current = _normalize_severity(finding.get("severity"))
                if not current or SEVERITY_ORDER[nvd_sev] > SEVERITY_ORDER[current]:
                    finding["severity"] = nvd_sev

        return findings

    def get_cvss_from_nvd(self, cve_id):
        if cve_id in self._cache:
            return self._cache[cve_id]

        self._respect_rate_limit()
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            response = requests.get(
                NVD_API_BASE,
                params={"cveId": cve_id},
                headers=headers,
                timeout=self.timeout_seconds,
            )
        except requests.RequestException:
            self._cache[cve_id] = None
            return None

        self._last_request_ts = time.monotonic()
        if response.status_code != 200:
            self._cache[cve_id] = None
            return None

        try:
            data = response.json()
        except ValueError:
            self._cache[cve_id] = None
            return None

        vuln_list = data.get("vulnerabilities") or []
        if not vuln_list:
            self._cache[cve_id] = None
            return None

        cve_data = vuln_list[0].get("cve") or {}
        metrics = cve_data.get("metrics") or {}
        selected = _pick_cvss_data(metrics)
        if not selected:
            self._cache[cve_id] = None
            return None

        cvss_data, version = selected
        result = {
            "base_score": cvss_data.get("baseScore"),
            "severity": _normalize_severity(cvss_data.get("baseSeverity")) or "Low",
            "vector": cvss_data.get("vectorString"),
            "version": version,
            "source": "NVD",
        }

        calculated = _calculate_from_vector(result.get("vector"), version)
        if calculated is not None:
            result["calculated_score"] = calculated
            if result.get("base_score") is None:
                result["base_score"] = calculated

        self._cache[cve_id] = result
        return result

    def _respect_rate_limit(self):
        if self._last_request_ts <= 0:
            return
        elapsed = time.monotonic() - self._last_request_ts
        if elapsed < self.min_interval_seconds:
            time.sleep(self.min_interval_seconds - elapsed)


def _pick_cvss_data(metrics):
    preferred = [
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ]
    for metric_key, version in preferred:
        entries = metrics.get(metric_key) or []
        if not entries:
            continue
        cvss_data = (entries[0] or {}).get("cvssData") or {}
        if cvss_data:
            return cvss_data, version
    return None


def _calculate_from_vector(vector, version):
    if not vector:
        return None
    try:
        if version.startswith("4") and CVSS4:
            return float(CVSS4(vector).base_score)
        if version.startswith("3") and CVSS3:
            return float(CVSS3(vector).base_score)
        if version.startswith("2") and CVSS2:
            return float(CVSS2(vector).base_score)
    except Exception:
        return None
    return None


def _normalize_severity(raw):
    if not raw:
        return None
    value = str(raw).strip().lower()
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }
    return mapping.get(value)
