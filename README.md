# Redaction-CI

**gitleaks, but for PDFs.** A GitHub Action that fails CI when a committed
PDF still contains recoverable text under its redaction boxes.

Drawing a black rectangle over a paragraph does **not** remove the
paragraph — the text stays in the PDF content stream, one copy-paste away
for anyone who opens the file. Redaction-CI catches exactly that before it
reaches your repository, plus a second classic failure mode: text that is
present in the file but never rendered (hidden OCR layers, hidden copies
of sensitive strings).

```
[CONFIRMED] contract.pdf p3 — 1 extractable text run(s) still recoverable
            under covering box: 'Internal key: DO-NOT-SHARE-9911'
```

## What it detects

| Finding | Severity | Meaning |
| --- | --- | --- |
| `covered-text` | **confirmed** | Extractable text sits under a later-drawn, opaque, dark filled box. The box hides nothing that matters — the text is still extractable. |
| `invisible-text` | warning | Text with PDF render mode 3 (never rendered) or fill opacity ≤ 0.05: hidden OCR layers, hidden duplicates. Any extractor sees it, no viewer shows it. |
| image-only pages | info | Pages with no extractable text at all (scans). Listed in the job summary; never fails the build. v0.1 cannot verify them — see [limitations](#honest-limitations). |

Detection details:

- **Paint order matters.** A box only "hides" text if it is drawn *after*
  the text in the content stream (`seqno` comparison). Dark text panels
  with light text on top — a common, legitimate design — are not flagged.
- **The box must be redaction-like.** Filled path, fill opacity ≥
  `min-fill-opacity` (default 0.5), perceived luminance ≤ `max-fill-luma`
  (default 0.85). White-outs are not flagged by default; raise
  `max-fill-luma` to 1.0 to include them.
- **Overlap threshold.** A box must cover at least `min-overlap`
  (default 0.5) of a text run's bounding box to count as hiding it, so
  descender-grazing highlights don't trigger findings.
- Encrypted PDFs and unparseable files **fail the step (exit 2)** — an
  unverifiable PDF is not a clean PDF.

## Quickstart

```yaml
name: Redaction check
on: [push, pull_request]

jobs:
  redaction:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Gjusev/redaction-ci@v0.1.0
        with:
          paths: |
            contracts/**/*.pdf
            reports/*.pdf
          fail-on: any
```

That's it — no secrets, no token, no Docker image. Findings appear as
file annotations on the commit/PR and as a table in the job summary.

### Inputs

| Input | Default | Description |
| --- | --- | --- |
| `paths` | `**/*.pdf` | Newline-separated glob(s) relative to the repo root. An explicit glob that matches nothing fails the scan (typos must not pass silently); the default glob passes on repos with no PDFs. |
| `exclude` | *(empty)* | Newline-separated glob(s) to exclude. |
| `fail-on` | `any` | `any` fails on every finding. `confirmed` fails only on `covered-text`; invisible text is then a warning that shows up in annotations and the summary without failing the build. |
| `max-fill-luma` | `0.85` | Perceived luminance (0..1) a fill may have at most to count as a redaction box. Lower = only dark boxes; `1.0` also flags white-outs. |
| `min-overlap` | `0.5` | Fraction of a text run's bbox a box must cover. |
| `min-fill-opacity` | `0.5` | Minimum fill opacity to count as covering. |

### Outputs

`findings`, `confirmed`, `warnings`, `files`, `pages`,
`files-with-findings`, `matched` — usable via step `id` and
`${{ steps.<id>.outputs.confirmed }}` etc.

## Threat model

**Who this is for:** anyone who commits "redacted" PDFs to a repository —
contracts, invoices, reports, incident write-ups — where the redaction was
done visually (box tool, highlighter, screenshot annotation) rather than
with a redaction feature that actually removes content.

**What an attacker/customer/auditor can do with a fake redaction:** open
the PDF in any viewer or library, select/copy the text under the box, or
run any of a hundred free text extractors. No exploit needed; the data is
*in* the file. Redaction-CI's detection core uses the same primitive
(text extraction + drawing geometry) so what it flags is what an
extractor can recover.

**What Redaction-CI proves:** that a PDF in CI contains *no extractable
text under redaction-like boxes and no invisible text layer*. It is a
regression gate, not a forensic certification.

**What it does not protect against** — see limitations below: scans,
image-over-text, metadata/attachment leakage, incremental-save leftovers,
and anything outside the text/drawing model of the PDF.

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
  seconds. ubuntu-latest + `actions/setup-python@v5` is cached.
- **No secrets.** Annotations and the job summary use runner primitives
  (`::error` workflow commands, `$GITHUB_STEP_SUMMARY`); the action never
  calls the API and needs no token.

Trade-off: the action runs where Python runs (ubuntu/macos runners).
Windows runners work in principle (bash is available) but are untested.

## Honest limitations

Read this section before trusting a green check with your life.

- **Scanned/image PDFs are not verified.** If the "redacted" page is a
  bitmap, there is no text layer to check. OCR-based verification is the
  obvious v0.2 feature and is deliberately out of scope here — a wrong
  OCR-based "all clear" is worse than an honest "cannot verify".
- **Text under an image is not detected.** If someone pastes a screenshot
  over live text, the text is still extractable but no filled box is
  involved. (Detecting image-over-text overlaps is planned.)
- **Detection is heuristic.** Paint order, fill colour, opacity and
  overlap are strong signals, not proof. Pathological construction orders
  or unusual colour spaces (e.g. spot colours, ICC) can produce false
  negatives; CMYK luminance is approximated without ICC profiles.
- **Other leak vectors are out of scope:** document metadata, embedded
  attachments, incremental-save leftovers of earlier document versions,
  form fields, and JavaScript. This action looks at page content only.
- **Rotated pages:** coordinates from text and drawings are compared in
  the same (unrotated) page space, which is consistent, but heavily
  transform-nested content has not been battle-tested.
- **A green check is not a redaction certificate.** If the stakes are
  high, render the page to an image and *look at it* (or run a proper
  redaction tool like PyMuPDF's `apply_redactions()`, which actually
  removes content) before publishing.

## License

Redaction-CI's own code is MIT — see [LICENSE](LICENSE). The detection
dependency **PyMuPDF is AGPL-3.0** and is installed from PyPI at run time,
not vendored or modified; its license terms apply to PyMuPDF itself. If
your project cannot accept an AGPL dependency at run time, please file an
issue — a pdfplumber-based (MIT) fallback is possible but would lose
render-mode detection, the invisible-text check.

## Development

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
.venv/bin/python -m pytest tests/ -q          # unit + fixture tests
.venv/bin/python tests/make_fixtures.py       # regenerate fixtures/*.pdf
```

The repo's own CI [dogfoods the action](.github/workflows/ci.yml): clean
fixtures must pass, the fake-redaction fixture must fail, and the
invisible-text fixture must respect both `fail-on` modes.

---
by @Gjusev — datenmaske.de
