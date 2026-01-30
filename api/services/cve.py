"""CVE lookup service using NVD API."""

import httpx
from typing import Optional

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def search_cve(keyword: str) -> list[dict]:
    """Search CVEs by keyword (service name, product, etc)."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(
                NVD_API_URL,
                params={"keywordSearch": keyword, "resultsPerPage": 10},
            )
            response.raise_for_status()
            data = response.json()

            cves = []
            for item in data.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "")

                # Get description
                descriptions = cve_data.get("descriptions", [])
                description = next(
                    (d["value"] for d in descriptions if d["lang"] == "en"),
                    "No description",
                )

                # Get severity
                metrics = cve_data.get("metrics", {})
                cvss = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
                severity = "UNKNOWN"
                score = 0.0
                if cvss:
                    severity = cvss[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                    score = cvss[0].get("cvssData", {}).get("baseScore", 0.0)

                cves.append({
                    "id": cve_id,
                    "description": description[:300] + "..." if len(description) > 300 else description,
                    "severity": severity,
                    "score": score,
                })

            return cves
        except Exception as e:
            return [{"error": str(e)}]


async def get_cve_by_id(cve_id: str) -> Optional[dict]:
    """Get specific CVE by ID."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(
                NVD_API_URL,
                params={"cveId": cve_id},
            )
            response.raise_for_status()
            data = response.json()

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return None

            cve_data = vulnerabilities[0].get("cve", {})

            descriptions = cve_data.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                "No description",
            )

            metrics = cve_data.get("metrics", {})
            cvss = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
            severity = "UNKNOWN"
            score = 0.0
            if cvss:
                severity = cvss[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                score = cvss[0].get("cvssData", {}).get("baseScore", 0.0)

            return {
                "id": cve_data.get("id"),
                "description": description,
                "severity": severity,
                "score": score,
                "published": cve_data.get("published"),
                "lastModified": cve_data.get("lastModified"),
            }
        except Exception:
            return None
