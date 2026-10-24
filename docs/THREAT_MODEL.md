# Threat model

Status legend: **[done]** implemented and tested in this repository today, **[planned Mn]** scheduled
for milestone n, **[ops]** an operator responsibility that code cannot enforce.

## Assets

| Asset | Why it matters |
|---|---|
| GitHub App private key | Mints tokens for every installed repo, including private ones |
| GitLab bot token | Write access to the destination namespace |
| Webhook secret | Lets an attacker inject events if leaked |
| Database | Registry, ID mappings, audit log |
| Mirror data on disk | Full copies of private source code |

## Trust boundaries

1. GitHub API/webhooks -> engine (untrusted input: payloads, pagination links, repo names)
2. Engine -> GitLab (write path; must be confined to the approved namespace)
3. Engine <-> PostgreSQL (state integrity)
4. CI/CD -> repository (workflow code, dependencies)

## Threats and controls

| # | Threat | Control | Status |
|---|---|---|---|
| T1 | Token or key leaks via logs, errors, audit rows, reports | Central redactor (pattern + key-name) applied in the JSON log formatter, audit writer and error messages; `SecretStr` for all secrets; CLI prints field *names* only on config errors | **[done]** |
| T2 | Token embedded in URLs, argv or git config | No token ever placed in a URL by this codebase; GitHub tokens go only in the `Authorization` header. Git push/clone will use an in-memory `GIT_ASKPASS`-style helper, never argv or `.git/config` | API **[done]**, git **[planned M3]** |
| T3 | Over-privileged GitHub access | GitHub App (no PAT support); discovery tokens are downscoped to `metadata: read`; the app should be granted read-only permissions, which also makes one-way sync a permission-level guarantee | **[done]** (downscoping), **[ops]** (grant minimal permissions) |
| T4 | SSRF via configured URLs or server-provided links | `validate_base_url` rejects non-HTTPS, credentials, loopback/private/link-local/IPv4-mapped/numeric-form hosts; pagination refuses any `Link` off the API origin; redirects are never followed | **[done]**. Residual: no DNS resolution check (DNS rebinding) -> **[ops]** egress allow-list |
| T5 | Forged or replayed webhooks | HMAC-SHA256 constant-time verification, size/schema limits, `X-GitHub-Delivery` dedupe | **[planned M5]** |
| T6 | Overwriting or polluting an unrelated GitLab project | Namespace allow-list, ownership marker required before any write to an existing project, conflicts quarantined | **[planned M2]** |
| T7 | Silent loss of destination data | No project-deletion code path in the default build; branch deletion quarantined; a repo absent from GitHub is only flagged `source_deleted` after N consecutive healthy scans (**[done]**), never acted on automatically | registry **[done]**, git **[planned M3]** |
| T8 | A transient permission/API failure being misread as "repo deleted" | Disappearance counts only for installations that scanned successfully; empty installation list is an anomaly, not mass deletion | **[done]** |
| T9 | Visibility widening (private code exposed) | Config rejects policies that widen; existing repos whose policy would widen are held in `visibility_review_required` and never auto-applied; unknown visibility fails closed to private | **[done]** |
| T10 | Audit log tampering | Append-only triggers (UPDATE/DELETE/TRUNCATE rejected), SHA-256 hash chain, `audit verify` command | **[done]**. Residual: a DB superuser can rewrite the full chain -> export the head hash off-box **[planned M7]** |
| T11 | SQL injection | All values are bound parameters; the few dynamic column lists are built from hard-coded constants | **[done]** |
| T12 | Concurrent runs corrupting counters or state | Session advisory lock on discovery; audit appends serialized by advisory lock; row locks on registry updates | **[done]** |
| T13 | Command injection via repo names/refs | Git invoked with argument lists (never a shell), ref and path validation | **[planned M3]** |
| T14 | Malicious dependency / action update | Hash-pinned lockfile, `pip-audit` in CI, actions pinned to verified commit SHAs, Dependabot with 14-day cooldown, CodeQL, SBOM artifact | **[done]** |
| T15 | Privileged CI abused by PR code | Workflows use `pull_request` (never `pull_request_target`), `contents: read` by default, `persist-credentials: false`, CODEOWNERS on `.github/` | **[done]** (workflows are written but not yet executed on GitHub) |
| T16 | Secrets committed to the repo | `.gitignore`, pre-commit `detect-private-key` + `detect-secrets`, CI secret scan with baseline (verified to reject a planted token) | **[done]** |
| T17 | Data at rest | Database and backups encrypted, `sslmode=require` | **[ops]**; `doctor` check **[planned M7]** |
| T18 | Stolen credentials persisting after rotation | Installation tokens cached in memory only and invalidated on 401; rotation/incident runbook | code **[done]**, runbook **[planned M8]** |

## Out of scope / residual risk

* A compromised host running the worker holds live tokens and mirror data. Run it with least privilege and disk encryption.
* The audit chain proves *tampering* only if the head hash is stored somewhere the DB admin cannot rewrite.
* GitHub and GitLab are trusted to enforce their own authentication.
