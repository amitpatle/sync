# Design: invariants, policies, limitations

## Synchronization invariants

1. **One direction.** Nothing writes to GitHub using GitLab-derived data. GitHub credentials should hold read-only permissions, so this holds at the permission level too.
2. **Identity by ID.** A repository is its immutable GitHub numeric ID. Names are mutable attributes; renames/transfers update the row and write `repository_name_history`.
3. **Ownership marker (M2).** A GitLab project is written only if it maps to our registry *and* carries our marker. Custom attributes are admin-only in GitLab, so the portable marker is a description footer, with a custom attribute added when `GHGL_GITLAB_ADMIN_MODE` is on.
4. **Webhooks are hints (M5).** An event enqueues "reconcile X"; workers re-read GitHub and diff against the mappings.
5. **Idempotency.** Every write is preceded by a mapping lookup; replays converge on the same state. Implemented for the registry: re-scanning an unchanged account produces zero changes and zero writes.
6. **No automatic destruction.** No code path deletes a GitLab project. Absence is recorded, never acted upon.

## Deletion and conflict policies

| Situation | Behaviour | Status |
|---|---|---|
| Repo missing from a scan | Count only if its installation scanned OK; `missing` after 1 miss, `source_deleted` after N (default 3). Reappearance resets. | done |
| Zero installations visible | Anomaly event; nothing evaluated | done |
| Installation failed/suspended | Run marked incomplete (exit code 7); its repos untouched | done |
| Owner not in allow-list | Installation skipped, never given a token | done |
| Rename / transfer | Row updated, history + audit entry | done |
| Name reused by a different repo ID | Separate row, `repo.name_reused` audit event | done |
| Fork | Excluded by default (`GHGL_FORK_POLICY`); dedup across installations by ID. *Parent-based fork dedup is not implemented* because the installation listing does not expose a fork's parent. | done / limited |
| Archived | Synced read-only by default, or skipped | done |
| Visibility narrowed | Applied | done |
| Visibility widened (incl. policy change) | Held for review, never auto-applied | done |
| Branch deleted | Quarantine, optional delayed removal | planned M3 |
| Force push | Mirror and audit old/new SHA | planned M3 |
| GitLab-side edits | Overwritten on next reconcile, drift audited | planned M4/M6 |
| Missing permission | `blocked`, alert, stop retrying | partial (classified now; enforcement M4) |

## Known limitations (so far)

* **Registry cannot yet distinguish "deleted" from "access revoked"** for a repo that vanishes while its installation still scans fine. Both end as `source_deleted`. A probe of `GET /repositories/{id}` (404 vs 403) is planned with the queue (M4).
* **`refs/pull/*`** will be excluded from Git pushes by using explicit `refs/heads/*` and `refs/tags/*` refspecs (never `--mirror`). I could not confirm from GitLab's documentation that GitLab rejects those refs, so this is a design choice, not a documented GitLab restriction.
* **PRs, reviews, reactions, timestamps and authorship** cannot be reproduced faithfully on GitLab (see the migration limits table to be added in M6). Nothing will be reported as synchronized unless it was.
* **Audit `details` must not contain floats** (jsonb round-trip would change the canonical form). Enforced by convention; tests cover the current events.
* **GitHub API version** defaults to `2022-11-28` (supported until March 2028). Version `2026-03-10` contains breaking changes to endpoints this project uses (installation repositories, issues, pulls, access tokens); migration is a tracked task, not yet done.
* **Workflows are unexecuted.** YAML is validated and action SHAs verified against the upstream repositories, but the workflows have not run on GitHub.

## Operational notes

* Discovery exit codes: `0` ok, `2` config, `3` database, `4` migration, `5` already running, `6` GitHub failure, `7` incomplete scan, `8` audit chain broken.
* Dry-run executes the real code path and rolls back, so a preview cannot diverge from a real run. It leaves no audit trace by design.
* Audit `seq` may have gaps (rolled-back dry runs); the `prev_hash` chain is authoritative.
