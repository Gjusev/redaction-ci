"""Tests for the Redaction-CI detector: unit + fixture integration + CLI."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pymupdf
import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tests"))

import redaction_ci as rci  # noqa: E402
from make_fixtures import FIXTURES, encrypted, fake_redaction, invisible_text  # noqa: E402

OPTS = rci.Options()

#: Expected severity per kind — a severity regression must fail the suite.
KIND_SEVERITY = {
    rci.KIND_COVERED: rci.SEVERITY_CONFIRMED,
    rci.KIND_UNAPPLIED: rci.SEVERITY_CONFIRMED,
    rci.KIND_INCREMENTAL: rci.SEVERITY_CONFIRMED,
    rci.KIND_INVISIBLE: rci.SEVERITY_WARNING,
    rci.KIND_CAMOUFLAGE: rci.SEVERITY_WARNING,
    rci.KIND_OFFPAGE: rci.SEVERITY_WARNING,
    rci.KIND_IMAGE_COVER: rci.SEVERITY_WARNING,
    rci.KIND_FORM_VALUE: rci.SEVERITY_WARNING,
    rci.KIND_ATTACHMENT: rci.SEVERITY_WARNING,
}

#: kind -> count for each fixture, plus the informational image-only pages.
EXPECTATIONS = {
    "benign-redacted.pdf": ({}, 0),
    "fake-redaction.pdf": ({rci.KIND_COVERED: 1}, 0),
    "invisible-text.pdf": ({rci.KIND_INVISIBLE: 1}, 0),
    "image-only.pdf": ({}, 1),
    "ocr-legit.pdf": ({}, 0),  # invisible OCR words over an image = legit
    "black-on-black.pdf": ({rci.KIND_CAMOUFLAGE: 1}, 0),
    "off-page.pdf": ({rci.KIND_OFFPAGE: 1}, 0),
    "unapplied-redact.pdf": ({rci.KIND_UNAPPLIED: 1}, 0),
    "image-over-text.pdf": ({rci.KIND_IMAGE_COVER: 1}, 0),
    "white-redraw.pdf": ({}, 0),  # same text visibly redrawn on the panel
    "stacked-boxes.pdf": ({rci.KIND_COVERED: 1}, 0),  # duplicate boxes deduped
    "form-value.pdf": ({rci.KIND_FORM_VALUE: 1}, 0),
    "attachment.pdf": ({rci.KIND_ATTACHMENT: 1}, 0),
    "incremental-leftover.pdf": ({rci.KIND_INCREMENTAL: 1}, 0),
}

BUILDERS = dict(FIXTURES)


# ---------------------------------------------------------------------------
# Unit: geometry and colour
# ---------------------------------------------------------------------------

def test_overlap_fraction_cases():
    span = (0, 0, 10, 10)
    assert rci.overlap_fraction(span, (0, 0, 10, 10)) == pytest.approx(1.0)
    assert rci.overlap_fraction(span, (20, 20, 30, 30)) == 0.0
    assert rci.overlap_fraction(span, (5, 0, 15, 10)) == pytest.approx(0.5)
    # box only clips a 1pt-tall sliver of the span
    assert rci.overlap_fraction(span, (0, 9, 10, 20)) == pytest.approx(0.1)
    # touching edges do not count
    assert rci.overlap_fraction(span, (10, 10, 20, 20)) == 0.0


def test_fill_luminance():
    assert rci.fill_luminance((0.0, 0.0, 0.0)) == pytest.approx(0.0)
    assert rci.fill_luminance((1.0, 1.0, 1.0)) == pytest.approx(1.0)
    assert rci.fill_luminance((0.5,)) == pytest.approx(0.5)
    # CMYK: full black = (0,0,0,1), paper white = (0,0,0,0)
    assert rci.fill_luminance((0.0, 0.0, 0.0, 1.0)) == pytest.approx(0.0)
    assert rci.fill_luminance((0.0, 0.0, 0.0, 0.0)) == pytest.approx(1.0)


def test_text_color_luminance():
    assert rci.text_color_luminance((0.0, 0.0, 0.0)) == pytest.approx(0.0)
    assert rci.text_color_luminance((1.0, 1.0, 1.0)) == pytest.approx(1.0)
    assert rci.text_color_luminance(0x000000) == pytest.approx(0.0)  # sRGB int form
    assert rci.text_color_luminance(0xFFFFFF) == pytest.approx(1.0)
    assert rci.text_color_luminance(None) == pytest.approx(1.0)


def test_glob_to_regex_is_version_independent():
    # dir/** must match files at any depth below dir (this exact pattern
    # regressed in CI: pathlib's ** semantics changed between 3.12 and 3.13)
    rx = rci.glob_to_regex("skip/**")
    assert rx.match("skip/ignored.pdf")
    assert rx.match("skip/a/b.pdf")
    assert not rx.match("keep.pdf")
    rx = rci.glob_to_regex("**/*.pdf")
    assert rx.match("x.pdf")
    assert rx.match("a/b/c.pdf")
    # case-insensitive: scanners emit .PDF as often as .pdf
    assert rx.match("a/b/c.PDF")
    rx = rci.glob_to_regex("contracts/*.pdf")
    assert rx.match("contracts/a.pdf")
    assert not rx.match("contracts/sub/a.pdf")
    rx = rci.glob_to_regex("a?c.pdf")
    assert rx.match("abc.pdf") and not rx.match("ac.pdf") and not rx.match("a/c.pdf")


def test_is_redaction_like():
    def drawing(type="f", fill=(0, 0, 0), opacity=1.0, rect=(0, 0, 100, 20)):
        return {"type": type, "fill": fill, "fill_opacity": opacity, "rect": pymupdf.Rect(*rect)}

    assert rci.is_redaction_like(drawing(), 0.85, 0.5)
    assert not rci.is_redaction_like(drawing(fill=(1, 1, 1)), 0.85, 0.5)  # white-out
    assert rci.is_redaction_like(drawing(fill=(1, 1, 1)), 1.0, 0.5)  # ...unless asked for
    assert not rci.is_redaction_like(drawing(type="s"), 0.85, 0.5)  # stroke only
    assert not rci.is_redaction_like(drawing(fill=None), 0.85, 0.5)
    assert not rci.is_redaction_like(drawing(opacity=0.2), 0.85, 0.5)
    assert not rci.is_redaction_like(drawing(rect=(0, 0, 1, 1)), 0.85, 0.5)  # decoration


def test_excerpt_truncates_and_normalises():
    assert rci.excerpt("a  b\nc") == "a b c"
    long = "x" * 200
    assert len(rci.excerpt(long)) == 60
    assert rci.excerpt(long).endswith("…")


def test_annotation_escaping():
    f = rci.Finding(
        kind=rci.KIND_COVERED,
        severity=rci.SEVERITY_CONFIRMED,
        file="dir/a,b.pdf",
        page=1,
        rect=(0, 0, 1, 1),
        text="weird%text",
        detail="d\nline2",
    )
    ann = f.annotation()
    assert ann.startswith("::error file=")
    assert "%0A" in ann and "%25" in ann and "%2C" in ann and "%3A" in ann
    assert "\n" not in ann.split("::", 2)[2]


# ---------------------------------------------------------------------------
# Integration: fixtures (freshly generated + the committed copies)
# ---------------------------------------------------------------------------

def _assert_expectation(findings, image_only_pages, name):
    expected_kinds, expected_image_only = EXPECTATIONS[name]
    by_kind: dict[str, int] = {}
    for f in findings:
        assert f.severity == KIND_SEVERITY[f.kind], f"{name}: {f.kind} has severity {f.severity}"
        by_kind[f.kind] = by_kind.get(f.kind, 0) + 1
    assert by_kind == expected_kinds, f"{name}: findings {[(f.kind, f.detail) for f in findings]}"
    assert len(image_only_pages) == expected_image_only, f"{name}: image-only {image_only_pages}"


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_generated_fixtures(tmp_path, name):
    path = tmp_path / name
    BUILDERS[name](path)
    findings, image_only, pages = rci.scan_file(path, name, OPTS)
    assert pages == 1
    _assert_expectation(findings, image_only, name)

    if name == "fake-redaction.pdf":
        assert findings[0].severity == rci.SEVERITY_CONFIRMED
        assert "DO-NOT-SHARE-9911" in findings[0].text
    if name == "incremental-leftover.pdf":
        assert findings[0].severity == rci.SEVERITY_CONFIRMED
    if name == "unapplied-redact.pdf":
        assert findings[0].severity == rci.SEVERITY_CONFIRMED


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_committed_fixtures(name):
    """The committed fixtures must behave exactly like freshly generated ones."""
    path = REPO / "fixtures" / name
    findings, image_only, _ = rci.scan_file(path, name, OPTS)
    _assert_expectation(findings, image_only, name)


def test_fail_on_policy(tmp_path):
    fake = tmp_path / "fake.pdf"
    invis = tmp_path / "invis.pdf"
    fake_redaction(fake)
    invisible_text(invis)
    res_fake = rci.scan_file(fake, "fake.pdf", OPTS)[0]
    res_invis = rci.scan_file(invis, "invis.pdf", OPTS)[0]
    assert rci.ScanResult(findings=res_fake).matched("confirmed")
    assert rci.ScanResult(findings=res_invis).matched("confirmed") is False
    assert rci.ScanResult(findings=res_invis).matched("any")


def test_unencrypted_assumption_on_visible_text_over_box(tmp_path):
    """Text drawn *after* a dark box (white text on black panel) is not a finding."""
    doc = pymupdf.open()
    page = doc.new_page(width=300, height=120)
    page.draw_rect(pymupdf.Rect(40, 40, 260, 80), fill=(0, 0, 0), color=None)
    page.insert_text((50, 60), "white on black is fine", fontsize=12, color=(1, 1, 1))
    path = tmp_path / "panel.pdf"
    doc.save(path)
    doc.close()
    findings, _, _ = rci.scan_file(path, "panel.pdf", OPTS)
    assert findings == []


def test_white_on_white_without_box_is_camouflaged(tmp_path):
    doc = pymupdf.open()
    page = doc.new_page(width=300, height=120)
    page.insert_text((50, 60), "white on white is hidden", fontsize=12, color=(1, 1, 1))
    path = tmp_path / "pale.pdf"
    doc.save(path)
    doc.close()
    findings, _, _ = rci.scan_file(path, "pale.pdf", OPTS)
    assert [f.kind for f in findings] == [rci.KIND_CAMOUFLAGE]


def test_white_on_white_fires_even_with_a_dark_box_elsewhere(tmp_path):
    """A dark header bar on the page must not disable the pale-text check."""
    doc = pymupdf.open()
    page = doc.new_page(width=300, height=400)
    page.draw_rect(pymupdf.Rect(0, 0, 300, 40), fill=(0, 0, 0), color=None)
    page.insert_text((50, 200), "ghost text", fontsize=12, color=(1, 1, 1))
    path = tmp_path / "pale2.pdf"
    doc.save(path)
    doc.close()
    findings, _, _ = rci.scan_file(path, "pale2.pdf", OPTS)
    assert [f.kind for f in findings] == [rci.KIND_CAMOUFLAGE]


def test_double_drawn_text_under_box_is_still_covered(tmp_path):
    """Two identical runs under one box must not suppress each other.

    Double-drawn text (faux bold, overprint) or a decoy copy under the box
    is itself covered -- only a copy painted AFTER the box suppresses.
    """
    doc = pymupdf.open()
    page = doc.new_page(width=595, height=842)
    page.insert_text((72, 200), "Internal key: DO-NOT-SHARE-9911", fontsize=14)
    page.insert_text((72, 200), "Internal key: DO-NOT-SHARE-9911", fontsize=14)
    page.draw_rect(pymupdf.Rect(64, 186, 340, 206), fill=(0, 0, 0), color=None)
    path = tmp_path / "double.pdf"
    doc.save(path)
    doc.close()
    findings, _, _ = rci.scan_file(path, "double.pdf", OPTS)
    assert [f.kind for f in findings] == [rci.KIND_COVERED]
    assert findings[0].severity == rci.SEVERITY_CONFIRMED


def test_invisible_spans_aggregate_per_page(tmp_path):
    doc = pymupdf.open()
    page = doc.new_page(width=595, height=842)
    for i, word in enumerate(["HiddenA", "HiddenB", "HiddenC"]):
        page.insert_text((72, 120 + 20 * i), word, fontsize=12, render_mode=3)
    path = tmp_path / "multi.pdf"
    doc.save(path)
    doc.close()
    findings, _, _ = rci.scan_file(path, "multi.pdf", OPTS)
    assert len(findings) == 1
    assert findings[0].kind == rci.KIND_INVISIBLE
    assert "3 text run(s)" in findings[0].detail


def test_unchecked_checkbox_is_not_a_form_value(tmp_path):
    doc = pymupdf.open()
    page = doc.new_page(width=595, height=842)
    widget = pymupdf.Widget()
    widget.field_name = "consent"
    widget.field_type = pymupdf.PDF_WIDGET_TYPE_CHECKBOX
    widget.field_value = False
    widget.rect = pymupdf.Rect(72, 240, 186, 264)
    page.add_widget(widget)
    path = tmp_path / "cb.pdf"
    doc.save(path)
    doc.close()
    findings, _, _ = rci.scan_file(path, "cb.pdf", OPTS)
    assert findings == []


def test_benign_incremental_save_stays_quiet(tmp_path):
    """Multiple %%EOF markers alone are not a finding: clean revisions stay clean."""
    path = tmp_path / "benign-incr.pdf"
    doc = pymupdf.open()
    page = doc.new_page(width=595, height=842)
    page.insert_text((72, 120), "Quarterly report Q3", fontsize=14)
    doc.save(path)
    doc.close()
    doc = pymupdf.open(path)
    doc[0].insert_text((72, 160), "Customer: ACME GmbH", fontsize=14)
    doc.saveIncr()
    doc.close()
    findings, _, _ = rci.scan_file(path, "benign-incr.pdf", OPTS)
    assert findings == []


def test_leak_in_middle_revision_is_caught(tmp_path):
    """A leak introduced in revision 2 and redacted in revision 3 still leaks."""
    path = tmp_path / "mid.pdf"
    # rev 1: clean
    doc = pymupdf.open()
    page = doc.new_page(width=595, height=842)
    page.insert_text((72, 120), "Quarterly report Q3", fontsize=14)
    doc.save(path)
    doc.close()
    # rev 2: fake redaction appended incrementally
    doc = pymupdf.open(path)
    doc[0].insert_text((72, 200), "Internal key: DO-NOT-SHARE-9911", fontsize=14)
    doc[0].draw_rect(pymupdf.Rect(64, 186, 340, 206), fill=(0, 0, 0), color=None)
    doc.saveIncr()
    doc.close()
    # rev 3: redaction applied properly -- but rev 2 stays in the file
    doc = pymupdf.open(path)
    doc[0].add_redact_annot(pymupdf.Rect(64, 186, 340, 206), fill=(0, 0, 0))
    doc[0].apply_redactions()
    doc.saveIncr()
    doc.close()
    findings, _, _ = rci.scan_file(path, "mid.pdf", OPTS)
    assert [f.kind for f in findings] == [rci.KIND_INCREMENTAL]
    assert findings[0].severity == rci.SEVERITY_CONFIRMED
    assert "DO-NOT-SHARE-9911" in findings[0].text


# ---------------------------------------------------------------------------
# CLI behaviour (subprocess: exit codes, outputs, summary)
# ---------------------------------------------------------------------------

def run_cli(args, cwd, env_extra=None):
    env = dict(os.environ)
    env.pop("GITHUB_ACTIONS", None)
    env.pop("GITHUB_OUTPUT", None)
    env.update(env_extra or {})
    return subprocess.run(
        [sys.executable, str(REPO / "redaction_ci.py"), *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_exit_codes(tmp_path):
    for name, builder in BUILDERS.items():
        builder(tmp_path / name)

    r = run_cli(["--paths", "fake-redaction.pdf"], tmp_path)
    assert r.returncode == 1
    r = run_cli(["--paths", "fake-redaction.pdf", "--fail-on", "confirmed"], tmp_path)
    assert r.returncode == 1
    r = run_cli(["--paths", "benign-redacted.pdf"], tmp_path)
    assert r.returncode == 0
    r = run_cli(["--paths", "image-only.pdf"], tmp_path)
    assert r.returncode == 0
    r = run_cli(["--paths", "ocr-legit.pdf", "--fail-on", "any"], tmp_path)
    assert r.returncode == 0  # legitimate searchable scan passes even on 'any'
    # invisible text is a warning: the DEFAULT policy (confirmed) passes...
    r = run_cli(["--paths", "invisible-text.pdf"], tmp_path)
    assert r.returncode == 0
    # ...and only fails under --fail-on any.
    r = run_cli(["--paths", "invisible-text.pdf", "--fail-on", "any"], tmp_path)
    assert r.returncode == 1
    # unapplied redactions and incremental leftovers are confirmed findings.
    r = run_cli(["--paths", "unapplied-redact.pdf"], tmp_path)
    assert r.returncode == 1
    r = run_cli(["--paths", "incremental-leftover.pdf"], tmp_path)
    assert r.returncode == 1


def test_cli_fails_closed_on_errors(tmp_path):
    r = run_cli(["--paths", "does-not-exist-*.pdf"], tmp_path)
    assert r.returncode == 2
    junk = tmp_path / "broken.pdf"
    junk.write_text("this is not a pdf", encoding="utf-8")
    r = run_cli(["--paths", "broken.pdf"], tmp_path)
    assert r.returncode == 2
    encrypted(tmp_path / "locked.pdf")
    r = run_cli(["--paths", "locked.pdf"], tmp_path)
    assert r.returncode == 2
    assert "encrypted" in r.stdout
    # an explicitly empty --paths must not silently scan nothing
    r = run_cli(["--paths", "   "], tmp_path)
    assert r.returncode == 2


def test_cli_negation_glob(tmp_path):
    """A '!'-prefixed line in --paths is an exclusion (as action.yml documents)."""
    fake_redaction(tmp_path / "keep.pdf")
    (tmp_path / "drafts").mkdir()
    fake_redaction(tmp_path / "drafts" / "ignored.pdf")
    r = run_cli(["--paths", "**/*.pdf\n!drafts/**"], tmp_path)
    assert r.returncode == 1
    assert "ignored.pdf" not in r.stdout
    assert "keep.pdf" in r.stdout


def test_cli_exclude_emptied_corpus_fails_closed(tmp_path):
    fake_redaction(tmp_path / "only.pdf")
    r = run_cli(["--paths", "only.pdf", "--exclude", "only.pdf"], tmp_path)
    assert r.returncode == 2
    assert "excludes removed every file" in r.stdout


def test_cli_default_glob_emptied_by_exclude_fails_closed(tmp_path):
    """The action always passes the default glob; excludes must not empty it."""
    fake_redaction(tmp_path / "leak.pdf")
    r = run_cli(["--exclude", "**/*.pdf"], tmp_path)  # --paths omitted = default
    assert r.returncode == 2
    assert "excludes removed every file" in r.stdout


def test_cli_negation_only_paths_fails_closed(tmp_path):
    fake_redaction(tmp_path / "leak.pdf")
    r = run_cli(["--paths", "!**/*.pdf"], tmp_path)
    assert r.returncode == 2


def test_cli_uppercase_pdf_extension_is_scanned(tmp_path):
    fake_redaction(tmp_path / "REPORT.PDF")
    r = run_cli([], tmp_path)  # default glob must catch the fake redaction
    assert r.returncode == 1


def test_cli_json_and_github_outputs(tmp_path):
    fake_redaction(tmp_path / "fake.pdf")
    out_file = tmp_path / "github-output.txt"
    r = run_cli(
        ["--paths", "fake.pdf", "--format", "json"],
        tmp_path,
        env_extra={"GITHUB_OUTPUT": str(out_file)},
    )
    assert r.returncode == 1
    payload = json.loads(r.stdout)
    assert payload["findings"][0]["kind"] == rci.KIND_COVERED
    assert payload["files_scanned"] == 1
    assert "confirmed=1" in out_file.read_text()
    assert "matched=true" in out_file.read_text()


def test_cli_json_stdout_stays_clean_with_annotations(tmp_path):
    """Annotations must not corrupt the JSON stream when running on GitHub."""
    fake_redaction(tmp_path / "fake.pdf")
    r = run_cli(
        ["--paths", "fake.pdf", "--format", "json", "--annotations", "always"],
        tmp_path,
    )
    assert r.returncode == 1
    payload = json.loads(r.stdout)  # would raise if ::error leaked into stdout
    assert payload["findings"]
    assert "::error" in r.stderr  # the annotations moved to stderr instead


def test_cli_summary_file(tmp_path):
    fake_redaction(tmp_path / "fake.pdf")
    summary = tmp_path / "summary.md"
    r = run_cli(["--paths", "fake.pdf", "--summary-file", str(summary)], tmp_path)
    assert r.returncode == 1
    text = summary.read_text()
    assert "## Redaction-CI report" in text
    assert "fake.pdf" in text
    assert "DO-NOT-SHARE-9911" in text


def test_cli_annotations_auto_off_locally(tmp_path):
    fake_redaction(tmp_path / "fake.pdf")
    r = run_cli(["--paths", "fake.pdf"], tmp_path)
    assert "::error file=" not in r.stdout
    r = run_cli(["--paths", "fake.pdf"], tmp_path, env_extra={"GITHUB_ACTIONS": "true"})
    assert "::error file=fake.pdf" in r.stdout


def test_default_glob_without_pdfs_is_clean(tmp_path):
    """A repo with no PDFs must pass when the default glob is used.

    Covers both the CLI default (no --paths) and the action's behaviour,
    which always passes --paths with the input default value.
    """
    (tmp_path / "note.txt").write_text("no pdfs here")
    r = run_cli([], tmp_path)
    assert r.returncode == 0
    assert "0 file(s)" in r.stdout
    r = run_cli(["--paths", "**/*.pdf"], tmp_path)
    assert r.returncode == 0


def test_exclude_glob(tmp_path):
    fake_redaction(tmp_path / "keep.pdf")
    (tmp_path / "skip").mkdir()
    fake_redaction(tmp_path / "skip" / "ignored.pdf")
    r = run_cli(["--paths", "keep.pdf\nskip/ignored.pdf", "--exclude", "skip/**"], tmp_path)
    assert r.returncode == 1
    assert "ignored.pdf" not in r.stdout


def test_dot_git_is_never_scanned(tmp_path):
    (tmp_path / ".git" / "objects").mkdir(parents=True)
    fake_redaction(tmp_path / ".git" / "objects" / "leak.pdf")
    r = run_cli([], tmp_path)
    assert r.returncode == 0
    assert "0 file(s)" in r.stdout


# ---------------------------------------------------------------------------
# Reporting layer (unit coverage)
# ---------------------------------------------------------------------------

def _finding(kind=rci.KIND_COVERED, severity=rci.SEVERITY_CONFIRMED, page=1):
    return rci.Finding(
        kind=kind, severity=severity, file="a.pdf", page=page,
        rect=(0, 0, 1, 1), text="secret", detail="d",
    )


def test_emit_annotations_caps_findings_and_errors(capsys):
    result = rci.ScanResult(
        findings=[_finding() for _ in range(60)]
        + [_finding(severity=rci.SEVERITY_WARNING) for _ in range(60)],
        errors=[f"broken-{i}.pdf: cannot scan" for i in range(30)],
    )
    rci.emit_annotations(result, "always")
    out = capsys.readouterr().out
    errors = [line for line in out.splitlines() if line.startswith("::error")]
    warnings = [line for line in out.splitlines() if line.startswith("::warning")]
    scan_errors = [line for line in errors if "cannot scan" in line]
    assert len(scan_errors) == rci.MAX_ERROR_ANNOTATIONS  # the rest is findings + 1 trailing note
    assert len(errors) == rci.MAX_ANNOTATIONS_PER_LEVEL + rci.MAX_ERROR_ANNOTATIONS + 1
    assert len(warnings) == rci.MAX_ANNOTATIONS_PER_LEVEL
    assert f"and {30 - rci.MAX_ERROR_ANNOTATIONS} more scan error" in out
    rci.emit_annotations(result, "never")
    assert capsys.readouterr().out == ""


def test_summary_markdown_branches():
    clean = rci.ScanResult()
    assert "No recoverable text" in rci.summary_markdown(clean, "confirmed")
    assert "**Verdict: pass**" in rci.summary_markdown(clean, "confirmed")

    with_errors = rci.ScanResult(errors=["x.pdf: cannot scan (boom)"])
    assert "Scan errors (1)" in rci.summary_markdown(with_errors, "confirmed")

    doc_level = rci.ScanResult(findings=[
        _finding(kind=rci.KIND_ATTACHMENT, severity=rci.SEVERITY_WARNING, page=0)
    ])
    md = rci.summary_markdown(doc_level, "any")
    assert "| — |" in md  # document-level findings show an em dash

    flooded = rci.ScanResult(findings=[_finding() for _ in range(rci.MAX_SUMMARY_ROWS + 5)])
    assert "more finding(s) not listed" in rci.summary_markdown(flooded, "confirmed")

    scanned = rci.ScanResult(image_only_pages=[("scan.pdf", 3)])
    assert "Image-only page(s)" in rci.summary_markdown(scanned, "confirmed")


def test_result_json_shape():
    result = rci.ScanResult(
        findings=[_finding()],
        files_scanned=1,
        pages_scanned=2,
        image_only_pages=[("scan.pdf", 1)],
        errors=["e"],
    )
    payload = json.loads(rci.result_json(result))
    assert set(payload) == {"findings", "files_scanned", "pages_scanned", "image_only_pages", "errors"}
    assert set(payload["findings"][0]) == {"kind", "severity", "file", "page", "rect", "text", "detail"}
    assert payload["image_only_pages"] == [["scan.pdf", 1]]
