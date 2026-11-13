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

Spark CVE is a CLI that investigates whether a **local repository, across languages and frameworks,** is exposed
to a specific CVE, using Nemotron running on NVIDIA DGX Spark. It retrieves live
NVD records, lets an investigator choose repository tools, has a separate reviewer
challenge the conclusion, and writes Markdown/JSON reports with captured evidence.

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
missing. Doctor checks connectivity, model listing, and a real synthetic tool-call
request (without sending source). It does not establish GPU placement or evidence
quality. Verify GPU use on Spark with its operator
before making that claim in the demonstration.

Retrieve recent CVEs without analysing source:

```bash
python3 -m spark_cve recent
```

The key prompt does not echo or save the key. Without `--prompt-key`, the CLI
automatically reads `NVD_API_KEY` from this project's `.env` file:

```dotenv
NVD_API_KEY=your-key-here
```

`.env` is ignored by Git. `.env.example` contains only an empty template. The
process environment overrides the file; `--prompt-key` overrides both. Use
`--env-file /path/to/settings.env` for another file. Only `NVD_API_KEY` is read;
the analysed repository's `.env` is never automatically loaded, and the key is
not exported into repository test environments. Never commit keys.
Requests also work without a key, with slower rate limiting. No offline fallback
is used: service failure stops retrieval with a nonzero exit code.

Investigate the latest **2** scored HIGH/CRITICAL CVEs (the testing default):

```bash
python3 -m spark_cve scan /absolute/path/to/go-repository
```

Investigate one known CVE, still fetched live from NVD (replace the placeholder):

```bash
python3 -m spark_cve scan /absolute/path/to/go-repository --cve CVE-YYYY-NNNNN
```

Useful options:

```bash
python3 -m spark_cve --ollama-url http://127.0.0.1:11435 --model nemotron-3-nano:30b doctor
python3 -m spark_cve scan /absolute/path/to/go-repository --limit 1 --max-turns 6 --prompt-key
python3 -m spark_cve scan --help
```

Add `--limit 10` to restore the full ten-CVE batch. Global options (`--model`,
`--ollama-url`) precede the subcommand. Model transport accepts loopback HTTP
endpoints only. Each agent gets eight investigation turns by default, followed by
up to two structured assessment attempts. The verdict schema is supplied only
after evidence collection. Each HTTP inference call has a 180-second timeout;
batch analysis can take substantially longer than a five-minute presentation.

A synthetic tool-call preflight runs once before NVD retrieval. Repeated missing
tool calls before source inspection stop the investigation after two attempts.
Repeated empty application searches redirect the model to source, dependency tools or tests. A failed investigator skips review; an operational analysis failure
stops the remaining batch with a nonzero exit code and preserves its report.
A valid UNCERTAIN assessment still receives review and permits the batch to continue.

### Evidence-driven investigation

The workflow is now:

1. Inspect manifests and available source/checks deterministically.
2. Ask Nemotron to extract CVE-specific prerequisites and proof/disproof criteria.
3. Resolve effective dependency versions with available ecosystem tools.
4. Require the investigator to read actual application source/configuration.
5. Let it trace public API usage, inspect downloaded dependency source, discover
   existing tests and choose targeted checks.
6. Ask it to classify each prerequisite as holding, false, or unknown, citing
   actual evidence identifiers. Backend code derives the verdict using the plan's
   `any`/`all` relationships. Alternative attack vectors do not all need to exist.
7. Require a separate reviewer to read source, challenge contradictions, and
   optionally request one bounded follow-up investigation/review round.

A stable affected dependency alone is insufficient. A passing test is insufficient.
An existing reproduction's assertions, controlled input and trace must be assessed
against the selected CVE. A benign request or a selector that ran zero tests does
not establish absence. Unsupported resolution/tooling is a coverage gap, never
proof of NOT AFFECTED. Plans and model interpretations can still be wrong.

### Language and framework coverage

Source listing, numbered file reads and searching work on UTF-8 text in any
language, including extensionless build/configuration files. This replaces the
Go-only source-extension allowlist. Hidden/secret paths, binary files, generated
or dependency directories, symlinks and files larger than 256KB remain excluded.

| Ecosystem | Dependency evidence | Local checks |
| --- | --- | --- |
| Go | go.mod/go.work; resolved build list and registered downloaded source | Go tests, targeted existing tests, vet, build list |
| Python | requirements.txt, pyproject.toml, Poetry/uv/Pipfile locks; pip inventory after preparing a project venv | unittest, pytest if installed, selected unittest tests |
| JavaScript/TypeScript | package.json, npm lock; Yarn/pnpm metadata retained as raw evidence; npm installed-tree resolution/source where available | npm test or node --test; selected Node test files |
| Rust | Cargo.toml/lock; cargo metadata resolution/source | cargo test and metadata |
| Java/Kotlin | Maven dependencies; Gradle files retained as raw evidence | installed Maven or Gradle test command |
| .NET | project PackageReference and packages.lock.json | dotnet test --no-restore |
| PHP | Composer requirements and lock | composer run-script test |
| Ruby | Gemfile metadata and locked versions | bundle exec rake test |
| Other stacks | generic source/config inspection; explicit coverage limitations | operator-configured argv |

This is not complete semantic dependency resolution for every ecosystem. Maven,
Gradle, .NET, Composer and Bundler currently have partial manifest evidence and
fixed test launchers, not verified active-environment resolvers. Dynamic Python
metadata, Yarn/pnpm resolution, deployment settings, some workspace layouts and
build tags can still require additional evidence. Missing SDKs are reported; the
CLI does not automatically install system runtimes. It does not require Go for a
non-Go repository.

### Optional execution without Docker

```bash
python3 -m spark_cve scan /path/to/repository --allow-execution --allow-downloads
```

The laptop runs checks using installed runtimes; DGX Spark runs Nemotron inference.
A persistent temporary source copy and caches are reused within a scan, so repeated
Go checks do not repeatedly download the same dependencies. The workspace is
cleaned up on completion/error. API keys and host credentials are not forwarded
in the child environment. Local execution has your user's filesystem/network
permissions and is not a sandbox. The download flag controls supported package
manager retrieval, not arbitrary network access by repository code.

Agents may call `prepare_environment` to install Go modules, npm dependencies
(without lifecycle scripts), Cargo dependencies, or Python dependencies in a venv
when both flags are enabled. Missing package managers, Python venv support or
private dependency credentials are recorded as unavailable. Tests may need
excluded binary/hidden fixtures, operating-system libraries or SDK configuration.

For any other test framework or a project-specific reproduction, configure exact
commands yourself. The model can select these checks but cannot invent shell
commands or system installations:

```bash
python3 -m spark_cve scan /path/to/repository --allow-execution --test-command 'python3 -m unittest discover -s tests -v'
python3 -m spark_cve scan VulnerableCodeBase2/ --cve CVE-2026-100353 --allow-execution --allow-downloads --reproduce-command 'go run . -mode reproduce'
```

Commands are split into argv without an outer shell and run from the copied
repository root. `--test-command` and `--reproduce-command` are repeatable. Their
check names are `custom_test_1`, `custom_reproduction_1`, etc. Do not include
credentials in command arguments. A configured reproduction's actual execution is
recorded as `executed_unverified`; its exit code alone never decides the verdict.

`--check-timeout 180` increases the per-operation limit for cold builds (default
90 seconds, maximum 600). `--max-turns` controls each main agent's tool turns;
follow-up passes have at most four turns each.

Docker remains an optional **Go-only** laptop runner via `--runner docker` and
`--go-image IMAGE`. It requires a preloaded image; no automatic image pull occurs.
The richer persistent environment, multi-stack resolution and dependency-source
inspection currently require the default `--runner local`.

### Output and verdicts

Each scan creates a new private `artifacts/<timestamp>/` directory containing:

- `cves.json`: structured live NVD context with retrieval timestamps.
- `events.jsonl`: public agent/tool activity and tool results, not hidden reasoning.
- `report.json`: investigator draft, reviewer assessment, evidence, model, and source fingerprint.
- `report.md`: exposure report, prerequisite findings, cited file/line evidence,
  reproduction instructions, missing information, remediation, and suggested diff.
- `<CVE>.suggested.diff`: emitted when a supported fix can be proposed.

Artifacts contain source excerpts; treat them as private. The entire artifacts
directory is ignored by Git. Reports are saved after each completed CVE.
Model events now include phase, elapsed time, completion reason, token/timing
metrics and a bounded public response preview. Validation errors are visible in
the terminal and event file. `analysis_error` and `review_state` distinguish a
failed run from a completed UNCERTAIN assessment. Private reasoning is excluded.

- **AFFECTED:** common prerequisites hold, with one proven alternative attack path (`any`) or all required conditions (`all`), citing valid evidence.
- **NOT AFFECTED:** a common prerequisite is disproven, or all alternative paths are disproven; for an `all` group a single disproven requirement suffices.
- **UNCERTAIN:** evidence, supported tooling, model output, or review is insufficient.

The schema gates evidence presence; the reviewer still needs to assess whether
that evidence actually supports each claim. Model assessments can be wrong.
Missing search matches, failed checks, or an installed dependency alone do not
establish a definite verdict. The plan names the affected component/version and CVE-specific attack-path conditions,
including reachability, input and mitigations where relevant. Source changes during a CVE investigation force UNCERTAIN.

**Current boundary:** the model may select existing targeted tests or an operator-configured
reproduction command. It cannot generate arbitrary exploit programs, apply patches,
or verify suggested diffs automatically. Generic tests cannot establish successful
CVE reproduction by exit code alone.
Reproduction status is assigned by application code, not generated by the model:
`executed_unverified` when an operator-configured reproduction command actually ran;
otherwise `instructions_only` when steps are provided or `not_run`. A stray model
execution claim is ignored and logged rather than discarding valid source evidence.
The report's `execution` object and project check section list actual check attempts,
captured exit codes, and passed/failed/unavailable/timeout outcomes separately.

### NVD selection policy

The client fully paginates one-day publication windows (up to 2,000 records per request by default), searches backwards up
to 30 days by default, chooses HIGH/CRITICAL records, sorts by publication time
descending, and takes the requested count (2 by default, up to 10). Once enough matches have been found, older windows cannot
displace those matches. If fewer are found, the CLI states the bounded search
interval; `--lookback-days` supports up to 120 days. Unscored and rejected records
are excluded. New disclosures without scores therefore do not appear immediately.

NVD requests retry transient HTTP errors and network timeouts up to three total
attempts, with visible request/retry events. Authentication errors are not retried.
The timeout defaults to 45 seconds per attempt; use `--nvd-timeout 90` if the live
service is slow. Three timed-out attempts at that setting can take over four
minutes including backoff. `--nvd-page-size` can reduce response size on a constrained
connection, but the 2,000-record default usually avoids many sequential requests.
Neither setting can fix an unavailable NVD service. Retrieval still stops without
an offline fallback.

Score policy: CVSS 4.0 first, then 3.1, then 3.0; prefer the Primary source within
that version, otherwise the first available source. Preserve the selected score
source/version in the report. No CPE-to-Go-module identity mapping is assumed.
The agents reason over the supplied configuration data and source evidence.
Linked advisories are listed, not automatically downloaded in this MVP.

### Privacy and analysis scope

The laptop runs repository tools and orchestration. Only CVE API parameters go to
NVD. Selected source excerpts go through the SSH tunnel to Ollama on DGX Spark;
there is no external hosted LLM. Dependency installation may contact package
registries under `--allow-downloads`. Both agent roles share one model but have
separate conversations; reviewer source reads are enforced independently.

Only resolved dependency directories under the prepared workspace/cache are
registered for dependency inspection. Traversal, symlinks and secret/hidden paths
are rejected. Local replacements outside that workspace are not read. Missing
source, unsupported version formats or deployment configuration remain explicit
coverage gaps. The report includes scoped resolution outcomes, source-read counts,
actual checks and errors. Source modifications during a CVE assessment invalidate
its result. Review embedded secrets before sending source to the trusted Spark host.

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
