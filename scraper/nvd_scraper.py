"""
Eye of Horus — NVD (NIST) CVE Feed Scraper
Pulls recently published and updated CVE vulnerability records
from the official NIST National Vulnerability Database (NVD) API v2.

Data includes:
    - CVE ID, description, CVSS v3 severity score
    - Affected CPE products (vendors/software)
    - CWE weakness classifications
    - Publication and modification dates

No authentication required.
Rate limit: 5 requests / 30 seconds (unauthenticated)
Docs: https://nvd.nist.gov/developers/vulnerabilities
"""

import sys
import time
import schedule
import requests
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Iterator

from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scraper.base_scraper import BaseScraper
from config.settings import kafka as kafka_cfg

# ══════════════════════════════════════════════════════════════════════════════
#  NVD API Client
# ══════════════════════════════════════════════════════════════════════════════

NVD_BASE_URL    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE_SIZE   = 100   # Max results per page (NVD limit)
NVD_RATE_DELAY  = 6     # Seconds between requests (5 req/30s limit)
DATE_FMT        = "%Y-%m-%dT%H:%M:%S.000"
MIN_YEAR        = 2023  # Hard floor — reject anything published before this year


class NvdApiClient:
    """Lightweight client for the NVD CVE 2.0 REST API."""

    def __init__(self) -> None:
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "EyeOfHorus-OSINT/1.0 (cybersecurity research)"
        })

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=6, max=60))
    def _get(self, params: dict) -> dict:
        response = self._session.get(NVD_BASE_URL, params=params, timeout=30)
        response.raise_for_status()
        return response.json()

    def get_recent_cves(
        self,
        hours_back: int = 24,
        min_cvss: float = 0.0,
    ) -> list[dict]:
        """
        Return CVEs published or modified within the last N hours.
        Optionally filter by minimum CVSS base score.

        Args:
            hours_back: Look-back window in hours.
            min_cvss:   Minimum CVSS v3 score to include (0.0 = all).
        """
        end_dt   = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(hours=hours_back)

        # NVD timestamp format: 2024-01-01T00:00:00.000
        start_str = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
        end_str   = end_dt.strftime("%Y-%m-%dT%H:%M:%S.000")

        all_cves  = []
        params    = {
            "pubStartDate":   start_str,
            "pubEndDate":     end_str,
            "resultsPerPage": NVD_PAGE_SIZE,
            "startIndex":     0,
        }
        if min_cvss > 0:
            params["cvssV3Severity"] = self._cvss_to_severity(min_cvss)

    def _paginate(self, params: dict) -> list[dict]:
        """Fetch all pages for a given set of query params."""
        all_cves: list[dict] = []
        p = dict(params)
        p["startIndex"] = 0

        while True:
            data = self._get(p)
            vulnerabilities = data.get("vulnerabilities", [])
            all_cves.extend(vulnerabilities)

            total_results = data.get("totalResults", 0)
            start_index   = data.get("startIndex", 0)

            logger.debug(
                f"[nvd] Page: startIndex={start_index}, "
                f"fetched={len(vulnerabilities)}, total={total_results}"
            )

            if start_index + len(vulnerabilities) >= total_results:
                break

            p["startIndex"] += NVD_PAGE_SIZE
            time.sleep(NVD_RATE_DELAY)  # Respect rate limit

        return all_cves

    def get_recent_cves(
        self,
        days_back: int = 30,
        min_cvss: float = 0.0,
    ) -> list[dict]:
        """
        Dual-query strategy:
          1. Publication window (last `days_back` days) — catches fresh CVEs.
          2. Last-modified window (48 h) — catches old CVEs upgraded to CRITICAL.
        Results are merged and deduplicated by CVE ID.
        """
        now      = datetime.now(timezone.utc)
        pub_start = now - timedelta(days=days_back)
        mod_start = now - timedelta(hours=48)

        # Query 1: recently published
        pub_params: dict = {
            "pubStartDate":   pub_start.strftime(DATE_FMT),
            "pubEndDate":     now.strftime(DATE_FMT),
            "resultsPerPage": NVD_PAGE_SIZE,
        }
        if min_cvss > 0:
            pub_params["cvssV3Severity"] = self._cvss_to_severity(min_cvss)

        logger.info(f"[nvd] Fetching published CVEs ({days_back}d window)…")
        pub_cves = self._paginate(pub_params)
        logger.info(f"[nvd] Published query returned {len(pub_cves)} CVE(s).")
        time.sleep(NVD_RATE_DELAY)

        # Query 2: recently modified (CVSS upgrades)
        mod_params: dict = {
            "lastModStartDate": mod_start.strftime(DATE_FMT),
            "lastModEndDate":   now.strftime(DATE_FMT),
            "resultsPerPage":   NVD_PAGE_SIZE,
        }
        if min_cvss > 0:
            mod_params["cvssV3Severity"] = self._cvss_to_severity(min_cvss)

        logger.info("[nvd] Fetching recently modified CVEs (48h window)…")
        mod_cves = self._paginate(mod_params)
        logger.info(f"[nvd] Modified query returned {len(mod_cves)} CVE(s).")

        # Merge + deduplicate by CVE ID
        seen: set[str] = set()
        merged: list[dict] = []
        for item in pub_cves + mod_cves:
            cve_id = item.get("cve", {}).get("id", "")
            if cve_id and cve_id not in seen:
                seen.add(cve_id)
                merged.append(item)

        logger.info(f"[nvd] Total unique CVEs after dedup: {len(merged)}.")
        return merged

    @staticmethod
    def _cvss_to_severity(score: float) -> str:
        """Convert numeric CVSS score to NVD severity string."""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        return "LOW"


# ══════════════════════════════════════════════════════════════════════════════
#  NVD CVE Scraper
# ══════════════════════════════════════════════════════════════════════════════

class NvdScraper(BaseScraper):
    """
    Scrapes NIST NVD for recently published CVE vulnerability records.

    Each CVE becomes one OSINT record. The CVSS score is stored in `extra`
    so the PySpark threat processor can use it to boost the threat score
    for high-severity vulnerabilities.
    """

    @property
    def source_name(self) -> str:
        return "nvd_cve"

    def __init__(
        self,
        days_back: int = 30,
        min_cvss: float = 0.0,
    ) -> None:
        self._client    = NvdApiClient()
        self._days_back = days_back
        self._min_cvss  = min_cvss
        logger.info(
            f"[nvd] Initialized. Look-back: {days_back} days, "
            f"min CVSS: {min_cvss}"
        )

    # ── Fetch ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _is_recent_enough(cve_item: dict) -> bool:
        """Hard guard: reject any CVE published before MIN_YEAR."""
        published = cve_item.get("cve", {}).get("published", "")
        try:
            return int(published[:4]) >= MIN_YEAR
        except (ValueError, TypeError):
            return False

    def fetch(self) -> Iterator[dict[str, Any]]:
        """Fetch recent CVEs from NVD (dual-query) and yield raw vulnerability dicts."""
        logger.info(f"[nvd] Fetching CVEs (last {self._days_back} days)…")
        try:
            cves = self._client.get_recent_cves(
                days_back=self._days_back,
                min_cvss=self._min_cvss,
            )
            # Apply publication-year hard filter as a safety net
            recent = [c for c in cves if self._is_recent_enough(c)]
            filtered_out = len(cves) - len(recent)
            if filtered_out:
                logger.warning(
                    f"[nvd] Dropped {filtered_out} CVE(s) published before {MIN_YEAR}."
                )
            logger.info(f"[nvd] {len(recent)} CVE(s) passed year guard.")
            for cve in recent:
                yield cve
        except requests.HTTPError as e:
            logger.error(f"[nvd] API error: {e.response.status_code} — {e}")
        except Exception as exc:
            logger.error(f"[nvd] Unexpected error: {exc}")

    # ── Transform ─────────────────────────────────────────────────────────────

    def _transform(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Map a raw NVD vulnerability dict to the standard OSINT record."""
        cve_data = raw.get("cve", {})
        cve_id   = cve_data.get("id", "UNKNOWN")

        # ── Description ──────────────────────────────────────────────────────
        descriptions = cve_data.get("descriptions", [])
        description  = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            cve_data.get("sourceIdentifier", ""),
        )

        # ── CVSS v3 Score ─────────────────────────────────────────────────────
        metrics         = cve_data.get("metrics", {})
        cvss_v3_data    = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
        cvss_score      = 0.0
        cvss_severity   = "UNKNOWN"
        cvss_vector     = ""

        if cvss_v3_data:
            cvss_data   = cvss_v3_data[0].get("cvssData", {})
            cvss_score  = cvss_data.get("baseScore", 0.0)
            cvss_severity = cvss_data.get("baseSeverity", "UNKNOWN")
            cvss_vector   = cvss_data.get("vectorString", "")

        # ── CWE (weakness type) ───────────────────────────────────────────────
        weaknesses = cve_data.get("weaknesses", [])
        cwes       = [
            desc.get("value", "")
            for w in weaknesses
            for desc in w.get("description", [])
            if desc.get("lang") == "en"
        ]

        # ── Affected CPE products ─────────────────────────────────────────────
        configs          = cve_data.get("configurations", [])
        affected_vendors = set()
        for config in configs:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpe_uri = cpe_match.get("criteria", "")
                    # CPE format: cpe:2.3:type:vendor:product:...
                    parts = cpe_uri.split(":")
                    if len(parts) > 4:
                        affected_vendors.add(parts[3])  # vendor field

        # ── Dates ─────────────────────────────────────────────────────────────
        published_str = cve_data.get("published", "")
        published_at  = datetime.now(timezone.utc)
        if published_str:
            try:
                published_at = datetime.fromisoformat(
                    published_str.replace("Z", "+00:00")
                )
            except Exception:
                pass

        # ── Build full text for NLP ───────────────────────────────────────────
        text_body = (
            f"{cve_id} {description} "
            f"Severity: {cvss_severity}. "
            f"Affected: {' '.join(affected_vendors)}. "
            f"Weaknesses: {' '.join(cwes)}."
        )

        return self.build_record(
            post_id=f"nvd_{cve_id}",
            title=f"{cve_id} — {cvss_severity} (CVSS {cvss_score})",
            text=text_body,
            author="NIST-NVD",
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            published_at=published_at,
            extra={
                "cve_id":           cve_id,
                "cvss_score":       cvss_score,
                "cvss_severity":    cvss_severity,
                "cvss_vector":      cvss_vector,
                "cwes":             cwes,
                "affected_vendors": list(affected_vendors),
                "source_type":      "cve_vulnerability",
            },
        )


# ── Standalone entry point ────────────────────────────────────────────────────
if __name__ == "__main__":
    from broker.producer import OsintProducer

    logger.add("logs/scraper_nvd.log", rotation="10 MB", retention="7 days")

    # Pull CVEs from last 30 days, all severity levels
    scraper = NvdScraper(days_back=30, min_cvss=0.0)

    with OsintProducer() as producer:

        def scrape_and_push():
            logger.info("━" * 60)
            logger.info("🔐 Starting NVD CVE scrape cycle...")
            count = scraper.run(
                callback=lambda record: producer.send(
                    data=record,
                    topic=kafka_cfg.TOPIC_RAW,
                    key="nvd",
                )
            )
            logger.info(f"✅ Cycle complete — {count} CVEs pushed to Kafka.")

        scrape_and_push()
        schedule.every(6).hours.do(scrape_and_push)
        logger.info("⏱  Polling every 6 hours. Press Ctrl+C to stop.")

        while True:
            schedule.run_pending()
            time.sleep(1)
