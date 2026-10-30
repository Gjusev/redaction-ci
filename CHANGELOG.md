# Changelog

All notable changes to Redaction-CI are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.1] — 2026-10-30

### Changed

- README restructured for the GitHub Marketplace listing: banner, badges,
  demo output, recipes (PR comment, JSON output, strict mode), privacy
  and security section, copy pass for tone and consistency.
- `action.yml` description tightened for marketplace listings.
- Repository topics set (`pdf`, `security`, `github-actions`, …).

## [0.2.0] — 2026-10-29

### Breaking

- **`fail-on` now defaults to `confirmed`** (was `any`). Warnings —
  invisible/camouflaged text, form values, attachments — no longer fail a
  build out of the box; they still appear as annotations and in the job
  summary. Set `fail-on: any` to restore the strict behaviour. Rationale:
  the most common legitimate invisible text in the wild is the OCR layer
  of a searchable scan, and v0.1 failed every such document by default.
- Globs are now matched **case-insensitively**: a repository of `.PDF`
  files (a common scanner output) is no longer silently skipped.

### Added

- **`unapplied-redaction` (confirmed)**: a PDF redaction annotation whose
  underlying text is still extractable — the redaction was marked but
  `apply_redactions()` was never run. This is the single most common
  real-world redaction failure.
- **`incremental-leftover` (confirmed/warning)**: a file saved
  incrementally after "redacting" keeps every earlier revision; each
  recoverable revision is re-scanned and reported when it actually
  contains findings (benign multi-`%%EOF` writers such as linearized PDFs
  stay quiet).
- **`camouflaged-text` (warning)**: text painted the same colour as the
  box behind it (black-on-black, either paint order) or near-white text on
  the white page — invisible to every viewer, extractable by every tool.
- **`off-page-text` (warning)**: text placed entirely outside the visible
  page rectangle: never rendered, recoverable by unclipped extractors.
- **`image-covered-text` (warning)**: extractable text geometrically
  under a placed, opaque image (a screenshot pasted over live text). Paint
  order is not verified, so this is a warning tier; captions drawn over
  photos can trigger it.
- **`form-value` (warning)** and **`attachment` (warning)**: filled
  AcroForm fields and embedded file attachments shipping data inside the
  PDF.
- **OCR-layer discrimination**: invisible render-mode-3 text overlapping a
  placed image is the OCR layer of a searchable scan and is no longer
  flagged. Invisible text with no image under it stays a warning.
- Invisible-text findings are aggregated per page instead of per span (a
  scanned page no longer produces dozens of warnings).
- `!`-prefixed negation lines in `paths` (e.g.
  `contracts/**/*.pdf\n!**/drafts/**`) — the syntax the action.yml example
  advertised in v0.1 but the CLI did not implement.
- `format` action input (`text` | `json`) exposing the CLI's JSON output
  to consumers.

### Fixed

- **Script injection**: action inputs are no longer interpolated into the
  bash `run:` block; they are passed via `env:` (GitHub's documented
  hardening for actions wired to untrusted context).
- `--format json` under `GITHUB_ACTIONS=true` no longer corrupts stdout
  with `::error` annotation lines — annotations go to stderr in JSON mode.
- Scan-error annotations are capped (10) with a trailing "… and N more"
  note; findings were already capped at 50 per level.
- A covered text run that also has a visible copy on top of the box (the
  text → dark panel → white redraw z-order quirk of some generators) is
  no longer a false positive.
- Stacked identical boxes no longer produce duplicate findings.
- `--paths ""` / whitespace-only no longer silently scans nothing; and an
  explicit glob whose matches are all removed by `--exclude` fails closed
  instead of passing green.
- `.git` is never walked when resolving globs.

### Changed

- `actions/checkout` and `actions/setup-python` are pinned to commit SHAs.
- CI runs the unit suite on ubuntu (Python 3.11–3.13), windows and macos,
  adds a `ruff` lint job, `workflow_dispatch`, and new dogfood jobs for
  the `exclude` input, the encrypted-PDF exit-2 path and the step summary.

## [0.1.0] — 2026-10-28

Initial release: `covered-text` (confirmed) and `invisible-text`
(warning) detection, composite action packaging, fixtures + test suite,
dogfooding CI.
