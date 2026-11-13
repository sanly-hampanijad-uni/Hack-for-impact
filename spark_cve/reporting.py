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
        if result.get("attack_surface"):
            surface = result["attack_surface"]
            lines += ["", "### Attack-vector analysis context", "",
                      f"The investigator received the **{surface['status']}** attack-vector analysis as "
                      f"unverified leads and was instructed to verify them independently. See "
                      f"`{surface['report']}` (snapshot `{surface['snapshot']}`).", ""]
        for role in ("prover", "disprover"):
            perspective = result.get(role)
            if perspective:
                lines += [f"### {role.title()} perspective", "",
                          f"Draft verdict: **{perspective['status']}** — {perspective['summary']}",
                          f"Full report: `{cve['id']}-{role}.md`", ""]
        for condition in assessment["conditions"]:
            lines += [f"- **{condition['name']}: {condition['finding']}** — {condition['explanation']} "
                      f"({', '.join(condition['evidence_ids']) or 'no evidence'})"]
        lines += ["", "### Independent review", "", assessment["review_notes"], "",
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
        cve_id = result["cve"]["id"]
        for role in ("prover", "disprover"):
            perspective = result.get(role)
            if perspective:
                (output / f"{cve_id}-{role}.md").write_text(perspective_markdown(result, role))
        diff = result["assessment"]["suggested_diff"]
        if diff:
            (output / f"{cve_id}.suggested.diff").write_text(diff)


def perspective_markdown(result, role):
    cve = result["cve"]
    assessment = result[role]
    lines = [f"# {role.title()} report for {cve['id']}", "",
             "This is an evidence-seeking perspective, not the final verdict. The reviewer evaluates it "
             "alongside the investigator and opposing perspective.", "",
             f"Perspective verdict: **{assessment['status']}**", "",
             "## Summary", "", assessment["summary"], "", "## Prerequisites", ""]
    for condition in assessment["conditions"]:
        lines.append(f"- **{condition['name']}: {condition['finding']}** — {condition['explanation']} "
                     f"({', '.join(condition['evidence_ids']) or 'no evidence'})")
    lines += ["", "## Missing information", ""]
    lines += [f"- {item}" for item in assessment["missing_information"]] or ["- None reported."]
    lines += ["", "## Perspective notes", "", assessment["review_notes"], "",
              "Evidence details are included in the main `report.md` file.", ""]
    return "\n".join(lines)


def attack_surface_markdown(result):
    analysis = result["analysis"]
    lines = ["# Attack-surface analysis", "",
             "Defensive, source-based analysis of a filtered repository snapshot. "
             "Potential vectors are not confirmed vulnerabilities.", "",
             f"Status: **{analysis['status']}**", "",
             f"Model: `{result['model']}` | Source snapshot SHA-256: `{result['snapshot']}`", "",
             "## Summary", "", analysis["summary"], "", "## Potential attack vectors", ""]
    if not analysis["attack_vectors"]:
        lines.append("No source-supported vectors were reported.")
    for vector in analysis["attack_vectors"]:
        lines += [f"### {vector['id']}: {vector['entry_point']}", "",
                  f"- Category: {vector['category']}",
                  f"- Confidence: {vector['confidence']}",
                  f"- User-controlled inputs: {', '.join(vector['user_controlled_inputs']) or 'Not identified'}",
                  f"- Data flow: {vector['data_flow']}",
                  f"- Potential risk: {vector['potential_risk']}",
                  f"- Controls observed: {vector['controls_observed']}",
                  f"- Evidence: {', '.join(vector['evidence_ids'])}",
                  f"- Recommendation: {vector['recommendation']}", ""]
    lines += ["## Coverage gaps", ""]
    lines += [f"- {gap}" for gap in analysis["coverage_gaps"]] or ["- None reported."]
    lines += ["", "## Evidence", ""]
    for item in result["evidence"]:
        lines += [f"### {item['id']} — {item['tool']}", "", "````json",
                  json.dumps({"arguments": item["arguments"], "result": item["result"]},
                             indent=2, ensure_ascii=False), "````", ""]
    return "\n".join(lines)


def write_attack_surface_reports(output, result):
    output = Path(output)
    (output / "attack-vector-report.json").write_text(json.dumps(result, indent=2, ensure_ascii=False))
    (output / "attack-vector-report.md").write_text(attack_surface_markdown(result))
