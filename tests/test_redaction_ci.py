"""Tests for the Redaction-CI detector: unit + fixture integration + CLI."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import pymupdf

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tests"))

import redaction_ci as rci  # noqa: E402
from make_fixtures import (  # noqa: E402
    FIXTURES,
    benign_redacted,
    fake_redaction,
    image_only,
    invisible_text,
)

OPTS = rci.Options()

EXPECTATIONS = {
    "benign-redacted.pdf": {"covered": 0, "invisible": 0, "image_only": 0},
    "fake-redaction.pdf": {"covered": 1, "invisible": 0, "image_only": 0},
    "invisible-text.pdf": {"covered": 0, "invisible": 1, "image_only": 0},
    "image-only.pdf": {"covered": 0, "invisible": 0, "image_only": 1},
}

BUILDERS = {
    "benign-redacted.pdf": benign_redacted,
    "fake-redaction.pdf": fake_redaction,
    "invisible-text.pdf": invisible_text,
    "image-only.pdf": image_only,
}


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
    assert "%0A" in ann and "%25" in ann and "%2C" in ann
    assert "\n" not in ann.split("::", 2)[2]


# ---------------------------------------------------------------------------
# Integration: fixtures (freshly generated + the committed copies)
# ---------------------------------------------------------------------------

def _assert_expectation(findings, image_only_pages, name):
    exp = EXPECTATIONS[name]
    covered = [f for f in findings if f.kind == rci.KIND_COVERED]
    invisible = [f for f in findings if f.kind == rci.KIND_INVISIBLE]
    assert len(covered) == exp["covered"], f"{name}: covered findings {covered}"
    assert len(invisible) == exp["invisible"], f"{name}: invisible findings {invisible}"
    assert len(image_only_pages) == exp["image_only"], f"{name}: image-only {image_only_pages}"


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
    # invisible text is a warning: only fails under --fail-on any
    r = run_cli(["--paths", "invisible-text.pdf", "--fail-on", "confirmed"], tmp_path)
    assert r.returncode == 0
    r = run_cli(["--paths", "invisible-text.pdf", "--fail-on", "any"], tmp_path)
    assert r.returncode == 1


def test_cli_fails_closed_on_errors(tmp_path):
    r = run_cli(["--paths", "does-not-exist-*.pdf"], tmp_path)
    assert r.returncode == 2
    junk = tmp_path / "broken.pdf"
    junk.write_text("this is not a pdf", encoding="utf-8")
    r = run_cli(["--paths", "broken.pdf"], tmp_path)
    assert r.returncode == 2


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
