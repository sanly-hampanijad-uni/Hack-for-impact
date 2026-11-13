# Vulnerability Generation Agent

[Hack for Impact Sheffield](https://events.nvidia.com/Hack-for-Impact-Sheffield)

## Challenge Tracks

### Economic Systems

**Focus:** Improving how money flows through businesses, workers, and markets.

**The Goal:** Build agentic systems that help individuals and organisations make better economic decisions, unlock opportunities, or optimise costs.

### Public Services

**Focus:** Enhancing how people access and interact with public services and resources.

**The Goal:** Use data to build tools that simplify navigation of public systems, making essential services more accessible, efficient, and user-friendly.

### Urban Operations

**Focus:** Optimising how cities run, from large-scale infrastructure to everyday life.

**The Goal:** Develop systems that improve how cities function behind the scenes and in real time.

## What We Are Making

Spark CVE is a CLI that investigates whether a **local Go repository** is exposed
to a specific CVE, using Nemotron running on NVIDIA DGX Spark. It retrieves live
NVD records, lets an investigator choose repository tools, has a separate reviewer
evaluate investigator, prover, and disprover findings, and writes Markdown/JSON
reports with captured evidence.

### Quick start

Python 3.11+ is sufficient. Runtime dependencies: Python standard library only.
Run these commands from this repository; installation is optional.

Keep the SSH tunnel open in another terminal (authenticate interactively):

```bash
ssh -N -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:11435:127.0.0.1:11434 user13@spark13.local
```

Check the existing Ollama instance and local model:

```bash
python3 -m spark_cve doctor
```

Default model: `nemotron-3-nano:30b`. Have the Spark operator load that model if
missing. A successful doctor checks connectivity and model listing, not GPU
placement or tool-call correctness. Verify GPU use on Spark with its operator
before making that claim in the demonstration.

Retrieve recent CVEs without analysing source:

```bash
python3 -m spark_cve recent --prompt-key
```

The key prompt does not echo or save the key. Alternatively supply `NVD_API_KEY`
in the process environment. Never commit keys; rotate any key shared in chat.
Requests also work without a key, with slower rate limiting. No offline fallback
is used: service failure stops retrieval with a nonzero exit code.

Investigate the latest 10 scored HIGH/CRITICAL CVEs:

```bash
python3 -m spark_cve scan /absolute/path/to/go-repository --prompt-key
```

Investigate one known CVE, still fetched live from NVD (replace the placeholder):

```bash
python3 -m spark_cve scan /absolute/path/to/go-repository --cve CVE-YYYY-NNNNN --prompt-key
```

Create a separate, source-based attack-surface report without querying NVD:

```bash
python3 -m spark_cve attack-surface /absolute/path/to/application
```

The `attack-vector-analyser` reviews permitted source/configuration files for
HTTP routes, CLI/file inputs, and other user-controlled data flows. It uses
read-only repository tools and does not execute code, send HTTP requests, or
generate payloads or exploit steps. Findings are potential vectors, not confirmed
vulnerabilities; excluded files and deployment/runtime configuration can leave
coverage gaps.

The `scan` command also runs this analysis once before the CVE investigations.
Its findings are passed to each investigator as unverified navigation hints;
the investigator must verify relevant paths with its own evidence before using
them in a CVE assessment.

Useful options:

```bash
python3 -m spark_cve --ollama-url http://127.0.0.1:11435 --model nemotron-3-nano:30b doctor
python3 -m spark_cve scan /absolute/path/to/go-repository --limit 1 --max-turns 6 --prompt-key
python3 -m spark_cve scan --help
python3 -m spark_cve attack-surface --help
```

Global options (`--model`, `--ollama-url`) precede the subcommand. Model transport
accepts loopback HTTP endpoints only. Each agent has a bounded tool-turn budget
and two final JSON attempts. Each HTTP inference call has a 180-second timeout;
batch analysis can take substantially longer than a five-minute presentation.

### Optional Go execution

Source inspection is the default. To allow fixed checks, install/start Docker and
preload a Go image matching the repository's toolchain:

```bash
docker pull golang:1.24
python3 -m spark_cve scan /absolute/path/to/go-repository \
  --allow-execution --go-image golang:1.24 --prompt-key
```

Use `--allow-downloads` as well to permit dependency retrieval. That flag enables
container network access; private module paths can then reach configured module
proxies. It does not forward host credentials. Without it the container has no
network, so dependency-dependent checks may fail. Images are never pulled by an
agent. No host Go installation is needed.

Available checks: `go test`, `go vet`, and `go list -m -json all`. They run in a
disposable filtered source copy with a read-only container root, unprivileged user,
resource limits, no added capabilities, and a timeout. Source is never edited.
The runner excludes hidden files, secrets, vendor trees, binary fixtures, symlinks,
and files larger than 256KB; missing fixtures may cause checks to fail. Docker
is an MVP isolation boundary, not a hardened hostile-code execution service.

### Output and verdicts

Each scan creates a new private `artifacts/<timestamp>/` directory containing:

- `cves.json`: structured live NVD context with retrieval timestamps.
- `events.jsonl`: public agent/tool activity and tool results, not hidden reasoning.
- `report.json`: investigator, prover, disprover, reviewer assessments, evidence, model, and source fingerprint.
- `report.md`: exposure report, prerequisite findings, cited file/line evidence,
  reproduction instructions, missing information, remediation, and suggested diff.
- `<CVE>-prover.md` and `<CVE>-disprover.md`: separate evidence-cited perspective reports.
- `<CVE>.suggested.diff`: emitted when a supported fix can be proposed.

The `attack-surface` command writes `attack-vector-report.md` and
`attack-vector-report.json` alongside `events.jsonl` in its output directory.
`scan` writes the same attack-vector reports in addition to its CVE reports.

Artifacts contain source excerpts; treat them as private. The entire artifacts
directory is ignored by Git. Reports are saved after each completed CVE.

- **AFFECTED:** every prerequisite is marked proven with valid evidence references.
- **NOT AFFECTED:** at least one necessary prerequisite is disproven with evidence.
- **UNCERTAIN:** evidence, supported tooling, model output, or review is insufficient.

The schema gates evidence presence; the reviewer still needs to assess whether
that evidence actually supports each claim. Model assessments can be wrong.
Missing search matches, failed checks, or an installed dependency alone do not
establish a definite verdict. Affected prerequisites are component identity,
affected active version, reachable path, attacker-controlled input, and insufficient
mitigation. Source changes during a CVE investigation force UNCERTAIN.

**Current boundary:** this MVP produces reproduction *instructions*. It does not
generate and execute arbitrary CVE exploit programs, apply patches, or verify
suggested diffs. Generic Go tests cannot be labelled a successful CVE reproduction.

### NVD selection policy

The client fully paginates three-day publication windows, searches backwards up
to 30 days by default, chooses HIGH/CRITICAL records, sorts by publication time
descending, and takes 10. When 10 matches have been found, older windows cannot
displace those matches. If fewer are found, the CLI states the bounded search
interval; `--lookback-days` supports up to 120 days. Unscored and rejected records
are excluded. New disclosures without scores therefore do not appear immediately.

Score policy: CVSS 4.0 first, then 3.1, then 3.0; prefer the Primary source within
that version, otherwise the first available source. Preserve the selected score
source/version in the report. No CPE-to-Go-module identity mapping is assumed.
The agents reason over the supplied configuration data and source evidence.
Linked advisories are listed, not automatically downloaded in this MVP.

### Go support and privacy

The deterministic tools read `go.mod` and `go.work`, expose replacements verbatim,
search source, read numbered ranges, compare simple release versions, and optionally
request checks. Manifest parsing is deliberately conservative: requirements are
declarations, not a resolved build list. Pseudo/prerelease version comparison is
reported as unknown. Local replacements outside the selected repository are not
read. Workspaces, build tags, runtime settings, deployment toolchains and unusual
manifests may require additional evidence and result in UNCERTAIN.

The laptop runs tools and orchestration. Only CVE API parameters go to NVD.
Selected source excerpts go through the SSH tunnel to Ollama on DGX Spark;
there is no hosted LLM provider or source upload to a CVE service. The attack-vector
analyser, investigator, prover, disprover, and reviewer share one model but use
separate conversations. The reviewer must inspect repository content itself.
Tool permissions remain in deterministic application code.
Hidden paths and common secret filenames are excluded, but source files can still
contain embedded credentials; review your repository before sharing excerpts with
the trusted Spark host.

### Tests and team ownership

```bash
python3 -m unittest discover -s tests -v
```

Tests use explicit synthetic CVE/model responses; they are not an offline runtime
fallback or proof of live model quality. They cover pagination, score filtering,
key handling, source boundaries, tool execution controls, evidence gates, and the
two-agent/report pipeline.

Suggested ownership: developer 1 handles `clients.py` (Ollama) and `agents.py`;
developer 2 handles `clients.py` (NVD) and `tools.py`; developer 3 handles `cli.py`,
`reporting.py` and the video. Coordinate edits to the shared client file.
Keep integrating through the existing schemas/tools rather than separate services.

For the video: show doctor, live recent CVEs, one investigation's actual tool events,
the review, and the evidence/report. The latest global CVEs may be unrelated to the
mock repository. Do not invent an exposure for the demo; use live manual CVE
selection once a real matching vulnerability is identified. Dashboard, scheduled
monitoring, automatic reproduction and additional language support remain stretch work.
Proof of concept: When a CVE is discovered. You supply your codebase, and our agent will determine whether your application is vulnerable, explains the evidence, and suggests a fix.
