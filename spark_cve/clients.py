"""Deterministic NVD retrieval and local Ollama transport; no third-party dependencies."""
import json
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen


class ServiceError(RuntimeError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def request_json(url, *, payload=None, headers=None, timeout=120):
    body = None if payload is None else json.dumps(payload).encode()
    req = Request(url, data=body, headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urlopen(req, timeout=timeout) as response:
            return json.load(response)
    except HTTPError as exc:
        # Do not expose response bodies, headers, or credentials in diagnostics.
        raise ServiceError(f"HTTP {exc.code} from {urlparse(url).hostname}", status=exc.code) from None
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        raise ServiceError(f"Request to {urlparse(url).hostname} failed ({type(exc).__name__})") from None


def normalize_cve(record):
    metrics = record.get("metrics", {})
    # Explicit policy: CVSS 4.0, then 3.1, then 3.0; prefer Primary within that version.
    candidates = next((metrics[k] for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30")
                       if metrics.get(k)), [])
    chosen = next((m for m in candidates if m.get("type") == "Primary"), candidates[0] if candidates else {})
    data = chosen.get("cvssData", {})
    return {
        "id": record["id"], "published": record.get("published"),
        "modified": record.get("lastModified"), "nvd_status": record.get("vulnStatus"),
        "description": "\n".join(d["value"] for d in record.get("descriptions", []) if d.get("lang") == "en"),
        "severity": data.get("baseSeverity", chosen.get("baseSeverity", "UNSCORED")).upper(),
        "score": data.get("baseScore"), "score_version": data.get("version"),
        "score_source": chosen.get("source"),
        "cwes": [d["value"] for w in record.get("weaknesses", []) for d in w.get("description", [])
                 if d.get("lang") == "en"],
        "configurations": record.get("configurations", []),
        "references": record.get("references", []),
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
    }


class NVD:
    endpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, key=None, transport=request_json, sleep=time.sleep):
        self.key, self.transport, self.sleep = key, transport, sleep
        self.last_request = None

    def fetch(self, **params):
        interval = 0.7 if self.key else 6.1
        for attempt in range(3):
            if self.last_request is not None:
                self.sleep(max(0, interval - (time.monotonic() - self.last_request)))
            self.last_request = time.monotonic()
            try:
                return self.transport(self.endpoint + "?" + urlencode(params),
                                      headers={"apiKey": self.key} if self.key else {}, timeout=45)
            except ServiceError as exc:
                if exc.status not in {429, 500, 502, 503, 504} or attempt == 2:
                    raise
                self.sleep(2 ** attempt)

    def get(self, cve_id):
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
            raise ValueError("Expected a CVE ID such as CVE-2025-12345")
        rows = self.fetch(cveId=cve_id).get("vulnerabilities", [])
        if not rows:
            raise ServiceError(f"NVD did not return {cve_id}")
        return normalize_cve(rows[0]["cve"])

    def recent(self, count=10, lookback_days=30, now=None):
        """Fully page recent windows; never assume NVD returns newest first.

        Windows progress backwards. If fewer than count are found, return an
        explicitly bounded result instead of claiming global completeness.
        """
        end = now or datetime.now(timezone.utc)
        found = {}
        searched = 0
        while searched < lookback_days:
            days = min(3, lookback_days - searched)
            start = end - timedelta(days=days)
            index = 0
            while True:
                page = self.fetch(pubStartDate=start.isoformat(timespec="milliseconds"),
                                  pubEndDate=end.isoformat(timespec="milliseconds"),
                                  resultsPerPage=2000, startIndex=index)
                rows = page.get("vulnerabilities", [])
                for row in rows:
                    cve = normalize_cve(row["cve"])
                    if cve["severity"] in {"HIGH", "CRITICAL"} and cve["nvd_status"] != "Rejected":
                        found[cve["id"]] = cve
                index += len(rows)
                if index >= page.get("totalResults", 0):
                    break
                if not rows:
                    raise ServiceError("NVD pagination ended before all results were retrieved")
            searched += days
            if len(found) >= count:
                break
            end = start
        return sorted(found.values(), key=lambda c: (c["published"], c["id"]), reverse=True)[:count]


class Ollama:
    def __init__(self, base_url="http://127.0.0.1:11435", model="nemotron-3-nano:30b",
                 transport=request_json, timeout=180):
        parsed = urlparse(base_url)
        if parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or parsed.scheme != "http":
            raise ValueError("Use a loopback HTTP Ollama endpoint through the SSH tunnel")
        if "cloud" in model.lower():
            raise ValueError("Select a locally installed model, not an Ollama cloud model")
        self.url, self.model, self.transport, self.timeout = base_url.rstrip("/"), model, transport, timeout

    def models(self):
        return self.transport(self.url + "/api/tags", timeout=10)

    def chat(self, messages, tools=None, schema=None):
        payload = {"model": self.model, "messages": messages, "stream": False,
                   "think": False, "keep_alive": "30m",
                   "options": {"num_ctx": 8192, "num_predict": 2048, "temperature": 0}}
        if tools:
            payload["tools"] = tools
        if schema:
            payload["format"] = schema
        response = self.transport(self.url + "/api/chat", payload=payload, timeout=self.timeout)
        if not isinstance(response.get("message"), dict):
            raise ServiceError("Ollama returned no message")
        # Only retain public content/tool requests, never hidden thinking traces.
        return {k: v for k, v in response["message"].items() if k in {"role", "content", "tool_calls"}}
