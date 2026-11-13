# VulnerableCodeBase2: catalog validation demo

A small, deliberately vulnerable Go HTTP API for investigating
**CVE-2026-100353** (GO-2026-6800 / GHSA-vrcc-3ch7-hppw).
This is a real dependency vulnerability, not a hand-written imitation.

The Go vulnerability database added the report on **5 November 2026**. The
maintainer advisory was published on **28 August 2026**. This is a recent Go
database entry, not a promise that the CVE appears in today's latest two global
NVD results. Select its ID explicitly for a reliable investigation.

## Run the API

Use Go 1.25 or later. From this directory:

```bash
go mod download
go run .
```

It listens at `http://127.0.0.1:8082`. `GET /health` and `GET /items` return normal
responses. It is intentionally bound to loopback for a local hackathon demo.

## Reproduce without starting a server

```bash
go run . -mode reproduce
```

This calls the same handler in process with a synthetic request to
`/items?ids=1&ids=2`. On the pinned vulnerable version, it captures a nil-pointer
panic in `openapi3filter`, prints the stack and a reproduction confirmation, and
exits with code 0. An unrelated panic is not counted as a successful reproduction.

```bash
go test -v ./...
```

`TestNormalRoutes` checks the benign paths. **Passing
`TestCVE2026100353Reproduces` means the vulnerability is present**, not that the
application is secure. It deliberately expects the vulnerable dependency to panic.

## Exposure and evidence to investigate

- `go.mod` pins `github.com/getkin/kin-openapi v0.144.0`, a version reproduced by
  the maintainer advisory. `go.sum` provides dependency checksums.
- `catalogSpec` in `main.go` declares an OpenAPI 3.1 array query parameter without
  an `items` schema. Document validation accepts this contract.
- Unauthenticated request input reaches `openapi3filter.ValidateRequest` in the
  HTTP handler. There is no application recovery middleware around validation.
- Supplying array elements reaches a missing nil check inside the dependency's
  query-array decoder. The controlled test demonstrates the resulting panic.
- Recovery inside `reproduce` belongs only to the diagnostic harness. The normal
  serving path does not use that function.

The standard Go HTTP server normally recovers handler panics and terminates the
affected connection. Do not claim this fixture necessarily terminates the entire
server process. The directly demonstrated behavior is a request-validation panic.

## Investigate with Spark CVE

From the parent `Hack-for-impact` directory, with the DGX tunnel running:

```bash
python3 -m spark_cve scan VulnerableCodeBase2/ --cve CVE-2026-100353 --allow-execution --allow-downloads
```

This still retrieves the selected CVE live from NVD. No cached CVE response is
supplied by the demo. Go checks run on the laptop; Nemotron runs on DGX Spark.
The investigator currently treats reproduction-status metadata as application-owned:
generic `go test` execution is listed separately, even when a named fixture test
contains a CVE-specific reproduction. Inspect its output and source as evidence.

## Remediation

The maintainer identifies **v0.149.0** as patched. In a separate copy, run:

```bash
go get github.com/getkin/kin-openapi@v0.149.0
go mod tidy
go run . -mode reproduce
```

With the patched dependency, the request should produce a normal validation error
instead of a panic. The reproduction command then exits with code 1 because it
cannot demonstrate the vulnerability. The test that deliberately expects the
vulnerable panic should also fail; replace it with an assertion of clean rejection
when turning this into a fixed application. Adding an explicit element schema to
the API's `ids` array also removes this particular missing-`items` trigger, but
upgrading the affected library addresses the underlying decoder bug.

## Sources

- Maintainer advisory: https://github.com/getkin/kin-openapi/security/advisories/GHSA-vrcc-3ch7-hppw
- Go vulnerability record: https://pkg.go.dev/vuln/GO-2026-6800
- NVD record: https://nvd.nist.gov/vuln/detail/CVE-2026-100353
- Fix commit: https://github.com/getkin/kin-openapi/commit/9814d1f2b212f3508bf52296aa9e248b2122a5a9
