# Redaction-CI

**gitleaks, but for PDFs.** A GitHub Action that fails CI when a committed
PDF still contains recoverable text under its redaction boxes.

Drawing a black rectangle over a paragraph does **not** remove the
paragraph — the text stays in the PDF content stream, one copy-paste away
for anyone who opens the file. Redaction-CI catches exactly that before it
reaches your repository, plus every other classic way a "redacted" PDF
leaks: unapplied redaction annotations, invisible or camouflaged text
layers, text dragged off the page, screenshots pasted over live text,
filled form fields, embedded attachments, and earlier revisions left
behind by incremental saves.

```
[CONFIRMED] contract.pdf p3 — 1 extractable text run(s) still recoverable
            under covering box: 'Internal key: DO-NOT-SHARE-9911'
```

## What it detects

| Finding | Severity | Meaning |
| --- | --- | --- |
| `covered-text` | **confirmed** | Extractable text sits under a later-drawn, opaque, dark filled box. The box hides nothing that matters — the text is still extractable. |
| `unapplied-redaction` | **confirmed** | A redaction annotation is present but the underlying text is still extractable — the redaction was marked, never applied. |
| `incremental-leftover` | **confirmed*** | The file was saved incrementally after "redacting": earlier revisions are still in the file, and re-scanning them finds the leak. |
| `invisible-text` | warning | Text with PDF render mode 3 or fill opacity ≤ 0.05 that does **not** sit on a placed image. Invisible spans overlapping an image are the OCR layer of a searchable scan and are not flagged. |
| `camouflaged-text` | warning | Text painted the same colour as the box behind it (black-on-black, either paint order) or near-white on the white page: invisible to viewers, extractable by tools. |
| `off-page-text` | warning | Text entirely outside the visible page: never rendered, recoverable by unclipped extractors. |
| `image-covered-text` | warning | Extractable text under a placed, opaque image (screenshot over live text). Paint order is not verified, so this stays a warning. |
| `form-value` | warning | AcroForm fields that still carry values. |
| `attachment` | warning | Embedded file attachments shipping whole extra documents inside the PDF. |
| image-only pages | info | Pages with no extractable text at all (scans without OCR). Listed in the job summary; never fails the build. Verifying them needs OCR — see [limitations](#honest-limitations). |

\* `incremental-leftover` is a warning when the earlier revision contains
only warnings.

Detection details:

- **Paint order matters.** A box only "hides" text if it is drawn *after*
  the text in the content stream (`seqno` comparison). Dark text panels
  with light text on top — a common, legitimate design — are not flagged,
  and a covered run that is visibly redrawn on top of the panel is
  suppressed as a benign generator quirk.
- **The box must be redaction-like.** Filled path, fill opacity ≥
  `min-fill-opacity` (default 0.5), perceived luminance ≤ `max-fill-luma`
  (default 0.85). White-outs are not flagged by default; raise
  `max-fill-luma` to 1.0 to include them.
- **Overlap threshold.** A box must cover at least `min-overlap`
  (default 0.5) of a text run's bounding box to count as hiding it.
- **Fail-closed.** Encrypted PDFs, unparseable files, an explicitly empty
  or negation-only `paths` input, an explicit glob that matches nothing,
  and excludes that remove every matched file all fail the step (exit 2)
  — an unverifiable or empty scan is not a clean scan. Repos with no PDFs
  at all pass.

## Quickstart

```yaml
name: Redaction check
on: [push, pull_request]

jobs:
  redaction:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Gjusev/redaction-ci@v0.2.0
        with:
          paths: |
            contracts/**/*.pdf
            !**/drafts/**
```

That's it — no secrets, no token, no Docker image. Findings appear as
file annotations on the commit/PR and as a table in the job summary. The
step fails (exit 1) when findings match the `fail-on` policy — by default
only confirmed leaks; set `fail-on: any` to also fail on warnings.

Pin to the moving major tag `@v0` to receive v0 fixes and features
automatically, or to an exact version for full reproducibility (see
[releases](#releases)).

### Inputs

| Input | Default | Description |
| --- | --- | --- |
| `paths` | `**/*.pdf` | Newline-separated glob(s) relative to the repo root; a line starting with `!` excludes that glob. Matching is case-insensitive (`.PDF` is caught too). An explicit glob that matches nothing fails the scan (typos must not pass silently); the default glob passes on repos with no PDFs. |
| `exclude` | *(empty)* | Newline-separated glob(s) to exclude. Excludes that remove every matched file fail the scan. |
| `fail-on` | `confirmed` | `confirmed` fails only on covered text, unapplied redactions and recoverable earlier revisions. `any` also fails on invisible/camouflaged text, form values, attachments and the other warnings. |
| `max-fill-luma` | `0.85` | Perceived luminance (0..1) a fill may have at most to count as a redaction box. Lower = only dark boxes; `1.0` also flags white-outs. |
| `min-overlap` | `0.5` | Fraction of a text run's bbox a box must cover. |
| `min-fill-opacity` | `0.5` | Minimum fill opacity to count as covering. |
| `format` | `text` | stdout format of the scan step: `text` or `json` (machine-readable; annotations then go to stderr). |

### Outputs

`findings`, `confirmed`, `warnings`, `files`, `pages`,
`files-with-findings`, `matched` — usable via step `id` and
`${{ steps.<id>.outputs.confirmed }}` etc. `matched` is `"true"` when
findings matched the fail-on policy (the step then exits non-zero: 1 on
findings, 2 on scan errors).

## Threat model

**Who this is for:** anyone who commits "redacted" PDFs to a repository —
contracts, invoices, reports, incident write-ups — where the redaction was
done visually (box tool, highlighter, screenshot annotation) or marked but
never applied, rather than with a redaction feature that actually removes
content.

**What an attacker/customer/auditor can do with a fake redaction:** open
the PDF in any viewer or library, select/copy the text under the box, or
run any of a hundred free text extractors. No exploit needed; the data is
*in* the file. Redaction-CI's detection core uses the same primitives
(text extraction + drawing geometry + revision recovery) so what it flags
is what an extractor can recover.

**What Redaction-CI proves:** that a PDF in CI contains *no extractable
text under redaction-like boxes, no unapplied redaction annotations, no
invisible/camouflaged/off-page text, no filled forms or attachments, and
no leaking earlier revisions*. It is a regression gate, not a forensic
certification.

**What it does not protect against** — see limitations below: OCR-less
scans, metadata leakage, and anything outside the text/drawing/revision
model of the PDF.

## Packaging: composite action, not Docker

This is a **composite action** (Python + [PyMuPDF](https://pypi.org/project/pymupdf/),
pinned in `requirements.txt`) rather than a `docker://` container:

- **No image to build, publish, or patch.** A `docker://` action needs a
  registry image that must be rebuilt for every detector fix and
  dependency bump — that is a release pipeline in itself, and it silently
  drifts from the code you can read here.
- **Transparent.** The whole detector is one readable Python file; a
  composite action runs exactly that file in your runner.
- **Fast.** No image pull; `pip install` of the pinned wheel takes
  seconds. `actions/setup-python` is pinned to a commit SHA.
- **No secrets.** Annotations and the job summary use runner primitives
  (`::error` workflow commands, `$GITHUB_STEP_SUMMARY`); the action never
  calls the API and needs no token. Inputs reach the script through
  `env:` — never interpolated into the shell — so wiring `paths` to
  untrusted context (PR changed-file lists, `workflow_dispatch` inputs)
  cannot inject shell code.

Trade-off: the action runs where Python runs. The test suite covers
ubuntu, windows and macos runners.

## Honest limitations

Read this section before trusting a green check with your life.

- **Scanned/image PDFs without an OCR layer are not verified.** If the
  "redacted" page is a bitmap with no text at all, there is nothing to
  check. OCR-based verification is deliberately out of scope — a wrong
  OCR-based "all clear" is worse than an honest "cannot verify". (A scan
  *with* an OCR layer is verified through that layer, which is exactly
  what an attacker would extract.)
- **Image-over-text is a warning tier.** Text under a placed image is
  flagged by geometry only — the PDF content stream does not expose image
  paint order through the extraction API — so a caption drawn over a
  photo can also trigger it. It never fails a build under the default
  `fail-on: confirmed`.
- **Detection is heuristic.** Paint order, fill colour, opacity and
  overlap are strong signals, not proof. Pathological construction orders
  or unusual colour spaces (e.g. spot colours, ICC) can produce false
  negatives; CMYK luminance is approximated without ICC profiles.
  Stacked semi-transparent boxes, each below `min-fill-opacity`, are not
  combined.
- **Opaque stamps over live text** (a black "DRAFT" stamp, a banner) are
  indistinguishable from a fake redaction by geometry alone: the text
  under them really is recoverable. If you stamp documents, expect a
  confirmed finding and exclude or adjust for those files.
- **Other leak vectors are out of scope:** document metadata (there is no
  way to tell "sensitive" from "producer string"), JavaScript/OpenAction,
  and anything outside the text/drawing/revision model of the page.
- **Rotated pages:** coordinates from text and drawings are compared in
  the same (unrotated) page space, which is consistent, but heavily
  transform-nested content has not been battle-tested.
- **A green check is not a redaction certificate.** If the stakes are
  high, render the page to an image and *look at it* (or run a proper
  redaction tool like PyMuPDF's `apply_redactions()`, which actually
  removes content) before publishing.

## Releases

- Exact tags (`v0.2.0`, …) are immutable release points; the quickstart
  pins one for reproducibility.
- A moving major tag (`v0`) is force-updated to the latest release tag by
  the [release workflow](.github/workflows/release.yml); pin it to
  receive fixes automatically.
- Changes — including breaking ones — are documented in
  [CHANGELOG.md](CHANGELOG.md).

## License

Redaction-CI's own code is MIT — see [LICENSE](LICENSE). The detection
dependency **PyMuPDF is AGPL-3.0** and is installed from PyPI at run time,
not vendored or modified; its license terms apply to PyMuPDF itself. If
your project cannot accept an AGPL dependency at run time, please file an
issue — a pdfplumber-based (MIT) fallback is possible but would lose
render-mode detection, the invisible-text check and revision recovery.

## Development

Python **≥ 3.11** is required (the pinned `pymupdf==2.0` wheel is
cp311-abi3; CI runs 3.12):

```sh
python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest ruff
.venv/bin/python -m pytest tests/ -q          # unit + fixture tests
.venv/bin/python tests/make_fixtures.py       # regenerate fixtures/*.pdf
.venv/bin/ruff check .                        # lint
```

The repo's own CI [dogfoods the action](.github/workflows/ci.yml): clean
fixtures (including a legitimate OCR scan and a benign white-redraw
panel) must pass, the fake-redaction fixtures must fail, and the
invisible-text fixture must respect both `fail-on` modes.

---
by @Gjusev — datenmaske.de
