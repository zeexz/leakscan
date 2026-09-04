# Changelog

All notable changes to **leakscan** are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [2.1.0] — 2026-09-04

### Added
- **Fast Staged Git Scanning (`--staged`)** — Added dedicated `StagedScanner` running `git diff --cached -U0` (with pure Go `go-git` fallback) to inspect only added lines in the Git index in `< 50ms`.
- **High-Speed Pre-Commit Hook** — Updated `leakscan init` to generate a pre-commit hook that invokes `leakscan scan --staged --fail-severity high` instead of full-filesystem scans.
- **Inline Comment Ignores (`leakscan:ignore`)** — Added in-code suppression directives across Regex and Shannon Entropy detectors. Supports same-line and previous-line comments (`//`, `#`, `/* */`, `<!-- -->`) and optional rule targeting (e.g. `leakscan:ignore[aws-access-key-id]`).
- **Cryptographic Baseline Management (`--baseline` & `--record-baseline`)** — Implemented zero-knowledge baseline snapshots using SHA256 fingerprints combining secret type, line-drift-resistant normalized path, and redacted secret preview. Allows teams with legacy codebases to adopt leakscan without breaking CI builds.
- **Remote Webhooks & Central Ingestion (`--webhook-url` & `--upload-url`)** — Added real-time notification dispatch compatible with Slack, MS Teams, Discord, and custom security webhook endpoints, as well as full SARIF/JSON report uploads with bearer authentication.

---

## [2.0.1] — 2026-08-27

### Fixed
- **Entropy threshold flag regression** — the `--entropy-threshold` flag on
  `watch` was not being read from the parent `scan` command's flag set;
  `watch` now declares the flag independently (`cmd/watch.go`)
- **Watch command polling interval** — reduced from 5 s to 3 s for more
  responsive live feedback during development workflows
- **Redaction edge case** — strings shorter than 8 characters are now fully
  redacted as `[REDACTED]` rather than showing `****` which leaked length

### Changed
- `README.md` — added "How to Write a Custom Rule" tutorial section

---

## [2.0.0] — 2026-06-15

> **PR narrative:** _"Add `watch` command, interactive TUI, entropy detector,
> parallel multi-scanner execution, and custom `--rules-file` support"_
>
> This release pivoted leakscan from a one-shot CLI into a live-monitoring
> tool. Key architectural decisions are documented below.

### Added

#### `watch` command (fsnotify-based polling watcher)

A `leakscan watch <path>` command continuously monitors a directory and
re-scans whenever files change. The initial implementation used
[`fsnotify`](https://github.com/fsnotify/fsnotify) event subscriptions, but
**we switched to a polling loop** (3-second ticker) after discovering that
fsnotify on macOS emits duplicate `CHMOD` events on file saves in many editors,
leading to redundant re-scans. The polling approach trades a small latency
penalty for deterministic behaviour across all OSes.

**Lesson:** Event-driven watchers are more efficient but cross-platform edge
cases often push you toward simpler, more predictable polling. Always prototype
both and benchmark on your target platforms.

#### Interactive TUI (`bubbletea`)

`leakscan scan --tui` launches a terminal UI built with
[Bubble Tea](https://github.com/charmbracelet/bubbletea). The Elm-like
message-passing architecture (`Model / Update / View`) made it straightforward
to implement keyboard-navigable finding lists, live severity filtering, and a
remediation detail pane without shared mutable state.

**Architecture decision:** The TUI model is separate from the scan logic — it
receives a `[]Finding` slice via an `InitModel(findings)` call. This keeps
business logic testable independently of the terminal rendering layer.

#### Entropy detector

A second `Detector` implementation (`EntropyDetector`) that flags
high-Shannon-entropy strings assigned to secret-named variables. Uses a
Birnbaum-style false-positive filter (placeholder set + variable name
heuristics) to avoid flagging UUIDs, version strings, and module paths.

**Why not just raise the entropy bar?** Testing on real codebases showed that
a flat threshold of ≥ 4.5 bits/char missed many real secrets (short keys with
low entropy) while a threshold of ≥ 3.5 caused too many false positives on
base64-encoded images. The current implementation uses a *context-aware
threshold*: lower (3.8) for secret-named variables, higher (4.2) for all others.

#### Parallel multi-scanner execution

The `scan` command now runs all enabled scanners concurrently using
`golang.org/x/sync/errgroup`. Each scanner reports its findings via a
mutex-protected slice. Scanner errors are demoted to warnings (logged to
stderr) so that a permissions error on `/proc` doesn't abort a filesystem scan.

#### Custom `--rules-file` flag

Users can supply additional detection rules without modifying the binary:
```bash
leakscan scan . --rules-file ./my-company-rules.yaml
```
Custom rules are *merged* (appended) with the built-in rule set. This enables
org-specific patterns (internal API key formats, secret naming conventions)
without forking the project.

### Changed
- Rule YAML schema: `id` field is now required and must be unique
- Severity values normalised to `critical | high | medium` (removed `low`)

---

## [1.1.0] — 2026-04-02

> **PR narrative:** _"Add git history scanner and shell history scanner"_
>
> The filesystem-only scanner missed a major attack vector: secrets that had
> been committed and then deleted. This release adds deep git history scanning
> using `go-git` (pure Go — no `git` binary required) and shell history
> scanning for credentials accidentally typed into the terminal.

### Added

#### Git history scanner (`go-git`)

`leakscan scan . --include-git-history` iterates every commit in the repo's
history, checks out each blob, and runs the full detector pipeline against it.
Using [`go-git`](https://github.com/go-git/go-git) instead of shelling out to
the `git` binary avoids subprocess overhead and makes the tool self-contained.

**Performance note:** Deep histories (10 k+ commits) can take several minutes.
A future optimization could index only blobs that differ between commits
(delta-only scanning).

#### Shell history scanner

Scans `~/.bash_history`, `~/.zsh_history`, and `~/.fish_history` for
credentials accidentally passed as CLI arguments (e.g.,
`curl -H 'Authorization: Bearer sk_live_...'`). This is a surprisingly common
finding in developer workstation audits.

### Changed
- Binary size reduced by ~12% via `-ldflags="-s -w"` stripping debug info

---

## [1.0.0] — 2026-02-14

> **Initial release:** _"Filesystem secret scanner with regex engine and JSON output"_

### Added
- `leakscan scan <path>` — recursive filesystem scan
- Embedded regex rule set (`rules/default-patterns.yaml`) — 6 built-in rules:
  AWS Access Key ID, AWS Secret Access Key, GitHub PAT, Slack token,
  Private Key headers, Generic environment secret assignment
- `--format json` for machine-readable output (CI integration)
- `--fail-severity <level>` for non-zero exit codes in CI pipelines
- `--ignore-file` support for `.leakscanner-ignore` glob patterns
- Redaction engine: secrets are never printed in plaintext
- Docker image: `ghcr.io/<owner>/leakscan:latest`

---

[Unreleased]: https://github.com/example/leakscan/compare/v2.0.1...HEAD
[2.0.1]: https://github.com/example/leakscan/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/example/leakscan/compare/v1.1.0...v2.0.0
[1.1.0]: https://github.com/example/leakscan/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/example/leakscan/releases/tag/v1.0.0
