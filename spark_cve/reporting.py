import json
import sys
from datetime import datetime, timezone
from pathlib import Path


class Events:
    def __init__(self, path):
        self.path = Path(path)

    def __call__(self, kind, **data):
        event = {"time": datetime.now(timezone.utc).isoformat(), "event": kind, **data}
        with self.path.open("a") as handle:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
        label = " / ".join(str(data[k]) for k in ("cve", "agent", "tool", "evidence_id", "status") if k in data)
        if kind == "model_response":
            label += f" / {data['phase']} / {data['elapsed_seconds']}s / {data.get('metrics', {}).get('done_reason')}"
        if kind == "nvd_request":
            label += f"attempt {data['attempt']}/{data['max_attempts']} / timeout {data['timeout_seconds']}s / page offset {data['query'].get('startIndex', 0)}"
        if kind == "nvd_response":
            label += f"{data['records']} records / {data['elapsed_seconds']}s"
        if kind == "nvd_retry":
            label += f"retry in {data['delay_seconds']}s"
        if data.get("error"):
            label += " / " + str(data["error"])[:300]
        print(f"[{event['time'][11:19]}] {kind}: {label}", file=sys.stderr, flush=True)


def markdown(results):
    lines = ["# Spark CVE investigation", "", "Local Nemotron inference on DGX Spark; repository tools execute on the laptop.",
             "", "These are evidence-based assessments of a filtered source snapshot, not a security guarantee.",
             "Suggested diffs have not been applied or tested. Reproduction instructions have not been executed.", ""]
    for result in results:
        cve, assessment = result["cve"], result["assessment"]
        lines += [f"## {cve['id']} — {assessment['status']}", "",
                  f"Severity: {cve['severity']} | Score: {cve['score']} | CVSS: {cve['score_version']}",
                  f"Score source: {cve['score_source']} | Published: {cve['published']} | Retrieved: {cve['retrieved_at']}",
                  f"Model: `{result['model']}` | Source snapshot SHA-256: `{result['snapshot']}`", "",
                  "### Assessment", "", assessment["summary"], "", "### Prerequisites", ""]
        if result.get("analysis_error"):
            lines += ["**Analysis failed:** " + result["analysis_error"],
                      "This UNCERTAIN result reflects an execution failure, not a completed security investigation.", ""]
        for condition in assessment["conditions"]:
            lines += [f"- **{condition['name']}: {condition['finding']}** — {condition['explanation']} "
                      f"({', '.join(condition['evidence_ids']) or 'no evidence'})"]
        lines += ["", "### Independent review", "", f"Review state: {result.get('review_state', 'completed')}", "", assessment["review_notes"], "",
                  f"Investigator verdict: {result['investigator']['status']}", "", "### Missing information", ""]
        lines += [f"- {item}" for item in assessment["missing_information"]] or ["- None reported."]
        lines += ["", "### Remediation", "", assessment["remediation"], "", "### Local reproduction", "",
                  f"Status: {assessment['reproduction_status']}", ""]
        lines += [f"{i}. {step}" for i, step in enumerate(assessment["reproduction_steps"], 1)]
        if assessment["suggested_diff"]:
            lines += ["", "### Suggested diff (unverified)", "", "````diff", assessment["suggested_diff"], "````"]
        lines += ["", "### Evidence", ""]
        for item in result["evidence"]:
            lines += [f"#### {item['id']} — {item['agent']}: {item['tool']}", "", "````json",
                      json.dumps({"arguments": item["arguments"], "result": item["result"]}, indent=2, ensure_ascii=False), "````", ""]
        lines += ["### NVD references", "", f"- https://nvd.nist.gov/vuln/detail/{cve['id']}"]
        for ref in cve["references"]:
            if ref.get("url", "").startswith(("https://", "http://")):
                lines.append(f"- {ref['url']}")
        lines.append("")
    return "\n".join(lines)


def write_reports(output, results):
    output = Path(output)
    # Always rewrite after each CVE, preserving completed results if a later run fails.
    (output / "report.json").write_text(json.dumps(results, indent=2, ensure_ascii=False))
    (output / "report.md").write_text(markdown(results))
    for result in results:
        diff = result["assessment"]["suggested_diff"]
        if diff:
            (output / f"{result['cve']['id']}.suggested.diff").write_text(diff)
