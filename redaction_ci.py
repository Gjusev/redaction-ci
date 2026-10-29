#!/usr/bin/env python3
"""Redaction-CI: detect fake PDF redactions.

Two failure modes are detected per page:

1. ``covered-text``  -- extractable text that sits under a later-drawn,
   opaque, dark filled box without being removed (classic "x-ray"
   redaction: the text is still in the content stream, one copy-paste
   away). Reported with severity ``confirmed``.
2. ``invisible-text`` -- text that is never rendered: PDF render mode 3
   (hidden OCR layers, hidden copies of sensitive strings) or text with
   near-zero fill opacity. Reported with severity ``warning``.

Pages that contain no text at all (scans, image-only PDFs) are listed as
informational: verifying them needs OCR, which is out of scope for v0.1.

Exit codes:
    0  no findings matched the --fail-on policy
    1  findings matched the --fail-on policy
    2  scan error (unreadable or encrypted PDF, explicit glob matched
       nothing) -- fail closed: an unverifiable PDF is not a clean PDF.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

import pymupdf

__version__ = "0.1.0"

DEFAULT_PATHS = "**/*.pdf"

KIND_COVERED = "covered-text"
KIND_INVISIBLE = "invisible-text"

SEVERITY_CONFIRMED = "confirmed"
SEVERITY_WARNING = "warning"

RENDER_INVISIBLE = 3

#: A "redaction box" smaller than this (in points per side) is treated as
#: decoration, not as an attempt to hide a text line.
MIN_BOX_SIDE = 2.0

#: Annotation spam guard: GitHub caps annotations per step/job, so the
#: workflow-command stream is truncated while all findings still count.
MAX_ANNOTATIONS_PER_LEVEL = 50
MAX_SUMMARY_ROWS = 100

EXCERPT_LIMIT = 60


# ---------------------------------------------------------------------------
# Geometry and colour helpers
# ---------------------------------------------------------------------------

def overlap_fraction(span_bbox: Sequence[float], box: Sequence[float]) -> float:
    """Fraction of the *span* bbox area that intersects the box.

    The span area is the denominator: a big redaction box grazing a small
    word should not score 1.0, and a box that only clips a descender
    should score close to 0.
    """
    ix0 = max(span_bbox[0], box[0])
    iy0 = max(span_bbox[1], box[1])
    ix1 = min(span_bbox[2], box[2])
    iy1 = min(span_bbox[3], box[3])
    if ix1 <= ix0 or iy1 <= iy0:
        return 0.0
    inter = (ix1 - ix0) * (iy1 - iy0)
    area = max((span_bbox[2] - span_bbox[0]) * (span_bbox[3] - span_bbox[1]), 1e-9)
    return inter / area


def fill_luminance(color: Sequence[float]) -> float:
    """Perceived luminance (0..1) of a PDF fill colour.

    Handles grayscale (1 component), RGB (3) and CMYK (4) tuples; CMYK is
    converted with the simple subtractive approximation ``1 - c`` per
    channel (no ICC profiles -- good enough to tell "dark box" from
    "white-out").
    """
    if color is None or len(color) == 0:
        return 0.0
    if len(color) == 1:
        comps = (color[0], color[0], color[0])
    elif len(color) == 4:
        c, m, y, k = (float(v) for v in color[:4])
        comps = ((1 - c) * (1 - k), (1 - m) * (1 - k), (1 - y) * (1 - k))
    else:
        comps = (float(color[0]), float(color[1]), float(color[2]))
    return 0.299 * comps[0] + 0.587 * comps[1] + 0.114 * comps[2]


def is_redaction_like(
    drawing: dict,
    max_fill_luma: float,
    min_fill_opacity: float,
) -> bool:
    """True if a ``get_drawings()`` item plausibly tries to hide content.

    A filled path (rect or otherwise) with an opaque fill no brighter
    than *max_fill_luma*. Stroke-only paths and faint fills do not hide
    anything, so they are ignored.
    """
    if drawing.get("type") not in ("f", "fs"):
        return False
    fill = drawing.get("fill")
    if fill is None:
        return False
    if float(drawing.get("fill_opacity") or 1.0) < min_fill_opacity:
        return False
    if fill_luminance(fill) > max_fill_luma:
        return False
    rect = drawing.get("rect")
    if rect is None or rect.width < MIN_BOX_SIDE or rect.height < MIN_BOX_SIDE:
        return False
    return True


def excerpt(text: str, limit: int = EXCERPT_LIMIT) -> str:
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TextSpan:
    text: str
    bbox: tuple
    render_mode: int
    opacity: float
    seqno: int


@dataclass(frozen=True)
class FillBox:
    rect: tuple
    seqno: int


@dataclass
class Finding:
    kind: str  # KIND_COVERED | KIND_INVISIBLE
    severity: str  # SEVERITY_CONFIRMED | SEVERITY_WARNING
    file: str
    page: int  # 1-based
    rect: tuple
    text: str  # recoverable excerpt
    detail: str

    @property
    def title(self) -> str:
        if self.kind == KIND_COVERED:
            return "Fake redaction: text recoverable under box"
        return "Invisible text layer (render mode 3 / zero opacity)"

    def annotation(self) -> str:
        """GitHub workflow command for a file-level annotation."""
        level = "error" if self.severity == SEVERITY_CONFIRMED else "warning"
        title = escape_workflow_property(self.title)
        path = escape_workflow_property(self.file)
        message = escape_workflow_data(
            f"p{self.page} {self.detail}: {self.text!r}"
        )
        return f"::{level} file={path},title={title}::{message}"


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    pages_scanned: int = 0
    image_only_pages: list[tuple[str, int]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def confirmed(self) -> int:
        return sum(1 for f in self.findings if f.severity == SEVERITY_CONFIRMED)

    @property
    def warnings(self) -> int:
        return sum(1 for f in self.findings if f.severity == SEVERITY_WARNING)

    @property
    def files_with_findings(self) -> int:
        return len({f.file for f in self.findings})

    def matched(self, fail_on: str) -> bool:
        if fail_on == "confirmed":
            return self.confirmed > 0
        return bool(self.findings)


# ---------------------------------------------------------------------------
# Page-level extraction
# ---------------------------------------------------------------------------

def _collect_spans(page: "pymupdf.Page") -> list[TextSpan]:
    spans = []
    for s in page.get_texttrace():
        text = "".join(chr(c[0]) for c in s.get("chars", ()))
        if not text.strip():
            continue  # whitespace-only spans are layout noise
        spans.append(
            TextSpan(
                text=text,
                bbox=tuple(s["bbox"]),
                render_mode=int(s.get("type", 0)),
                opacity=float(s.get("opacity", 1.0)),
                seqno=int(s.get("seqno", -1)),
            )
        )
    return spans


def _fill_boxes(
    page: "pymupdf.Page",
    max_fill_luma: float,
    min_fill_opacity: float,
) -> list[FillBox]:
    boxes = []
    for d in page.get_drawings() or ():
        if not is_redaction_like(d, max_fill_luma, min_fill_opacity):
            continue
        seqno = d.get("seqno")
        # Missing seqno means unknown paint order; assume the box is drawn
        # last (worst case) so we stay on the recall side.
        seqno = int(seqno) if seqno is not None else sys.maxsize
        r = d["rect"]
        boxes.append(FillBox(rect=(r.x0, r.y0, r.x1, r.y1), seqno=seqno))
    return boxes


def scan_page(doc: "pymupdf.Document", page_number: int, file_label: str, opts: "Options") -> tuple[list[Finding], bool]:
    """Scan one 0-based page. Returns (findings, image_only)."""
    page = doc[page_number]
    spans = _collect_spans(page)
    boxes = _fill_boxes(page, opts.max_fill_luma, opts.min_fill_opacity)
    findings: list[Finding] = []

    for box in boxes:
        covered = [
            s
            for s in spans
            if s.render_mode != RENDER_INVISIBLE
            and s.opacity > 0.05
            and box.seqno > s.seqno
            and overlap_fraction(s.bbox, box.rect) >= opts.min_overlap
        ]
        if not covered:
            continue
        seen: list[str] = []
        for s in covered:
            snippet = excerpt(s.text)
            if snippet not in seen:
                seen.append(snippet)
        sample = " | ".join(seen[:3])
        findings.append(
            Finding(
                kind=KIND_COVERED,
                severity=SEVERITY_CONFIRMED,
                file=file_label,
                page=page_number + 1,
                rect=box.rect,
                text=sample,
                detail=f"{len(covered)} extractable text run(s) still recoverable under covering box",
            )
        )

    for s in spans:
        hidden_mode = s.render_mode == RENDER_INVISIBLE
        hidden_opacity = s.opacity <= 0.05
        if not (hidden_mode or hidden_opacity):
            continue
        why = "PDF render mode 3 (invisible)" if hidden_mode else "fill opacity <= 0.05"
        findings.append(
            Finding(
                kind=KIND_INVISIBLE,
                severity=SEVERITY_WARNING,
                file=file_label,
                page=page_number + 1,
                rect=s.bbox,
                text=excerpt(s.text),
                detail=f"text present but never rendered ({why})",
            )
        )

    image_only = not spans and bool(page.get_images(full=False))
    return findings, image_only


# ---------------------------------------------------------------------------
# File / corpus scanning
# ---------------------------------------------------------------------------

def scan_file(path: Path, file_label: str, opts: "Options") -> tuple[list[Finding], bool, int]:
    """Scan one PDF. Returns (findings, image_only_pages, pages). Raises on unreadable."""
    doc = pymupdf.open(path)
    try:
        if doc.needs_pass:
            raise ValueError("PDF is encrypted (password required); cannot verify redactions")
        findings: list[Finding] = []
        image_only: list[tuple[str, int]] = []
        for pno in range(doc.page_count):
            page_findings, page_image_only = scan_page(doc, pno, file_label, opts)
            findings.extend(page_findings)
            if page_image_only:
                image_only.append((file_label, pno + 1))
        return findings, image_only, doc.page_count
    finally:
        doc.close()


def glob_to_regex(pattern: str) -> "re.Pattern[str]":
    """Translate a path glob to a regex, independent of the Python version.

    pathlib's ``**`` handling changed semantics across 3.12 -> 3.13
    (``dir/**`` matches files on 3.13 but not on 3.12); the action runs on
    whatever Python setup-python provides, so exclusion behaviour must not
    depend on that. Supported: ``**`` (any depth, including none), ``*``
    (within one path segment), ``?`` (one non-separator char).
    """
    i, n = 0, len(pattern)
    out: list[str] = []
    while i < n:
        c = pattern[i]
        if c == "*":
            if pattern[i : i + 3] == "**/":
                out.append("(?:[^/]+/)*")
                i += 3
            elif pattern[i : i + 2] == "**":
                out.append(".*")
                i += 2
            else:
                out.append("[^/]*")
                i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("".join(["^", *out, "$"]))


def resolve_files(
    base: Path,
    patterns: Sequence[str],
    excludes: Sequence[str],
) -> tuple[list[Path], list[str]]:
    """Resolve globs relative to *base*; returns (files, unmatched_patterns)."""
    candidates = [p for p in base.rglob("*") if p.is_file()]

    def match(pattern: str) -> set[Path]:
        rx = glob_to_regex(pattern)
        return {p for p in candidates if rx.match(p.relative_to(base).as_posix())}

    files: set[Path] = set()
    unmatched: list[str] = []
    for pattern in patterns:
        matched = match(pattern)
        if not matched:
            unmatched.append(pattern)
        files |= matched
    for pattern in excludes:
        files -= match(pattern)
    return sorted(files), unmatched


def scan(
    base_dir: Path,
    patterns: Sequence[str],
    excludes: Sequence[str],
    opts: "Options",
    strict_patterns: bool = True,
) -> ScanResult:
    result = ScanResult()
    files, unmatched = resolve_files(base_dir, patterns, excludes)
    if strict_patterns:
        # A typo'd explicit glob would otherwise fail silently open.
        for pattern in unmatched:
            result.errors.append(f"pattern matched no files: {pattern}")
    for path in files:
        label = path.relative_to(base_dir).as_posix() if path.is_relative_to(base_dir) else str(path)
        try:
            findings, image_only, pages = scan_file(path, label, opts)
        except Exception as exc:  # unreadable/corrupt PDFs fail the scan
            result.errors.append(f"{label}: cannot scan ({exc.__class__.__name__}: {exc})")
            continue
        result.files_scanned += 1
        result.pages_scanned += pages
        result.findings.extend(findings)
        result.image_only_pages.extend(image_only)
    return result


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def escape_workflow_property(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace(",", "%2C").replace(":", "%3A")


def escape_workflow_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _md_cell(value: str) -> str:
    return " ".join(value.split()).replace("|", "\\|")


def summary_markdown(result: ScanResult, fail_on: str) -> str:
    lines = ["## Redaction-CI report", ""]
    verdict = "fail" if result.matched(fail_on) else "pass"
    lines.append(
        f"**Verdict: {verdict}** (fail-on: `{fail_on}`) — "
        f"{result.files_scanned} file(s), {result.pages_scanned} page(s), "
        f"{len(result.findings)} finding(s): {result.confirmed} confirmed, {result.warnings} warning(s)."
    )
    if result.errors:
        lines.append("")
        lines.append(f"**Scan errors ({len(result.errors)})** — fail closed:")
        lines.append("")
        for err in result.errors[:MAX_SUMMARY_ROWS]:
            lines.append(f"- ⚠️ {err}")
    if result.findings:
        lines.append("")
        lines.append("| File | Page | Type | Severity | Recoverable text |")
        lines.append("| --- | --- | --- | --- | --- |")
        for f in result.findings[:MAX_SUMMARY_ROWS]:
            lines.append(
                f"| `{_md_cell(f.file)}` | {f.page} | {_md_cell(f.kind)} | {_md_cell(f.severity)} | {_md_cell(f.text)} |"
            )
        if len(result.findings) > MAX_SUMMARY_ROWS:
            lines.append(f"| … | | {len(result.findings) - MAX_SUMMARY_ROWS} more finding(s) not listed | | |")
    if result.image_only_pages:
        shown = ", ".join(f"`{f}` p{p}" for f, p in result.image_only_pages[:MAX_SUMMARY_ROWS])
        lines.append("")
        lines.append(
            f"**Image-only page(s)** (no extractable text): {shown}. "
            "Scanned/image PDFs need OCR to verify — out of scope in v0.1, see README limitations."
        )
    if not result.findings and not result.errors:
        lines.append("")
        lines.append("No recoverable text under redaction boxes, no invisible text layers found.")
    lines.append("")
    lines.append(
        "_Detection is heuristic (content-stream order, fill colour/opacity, overlap). "
        "It cannot prove a redaction is complete — see README limitations._"
    )
    return "\n".join(lines)


def write_summary(summary_file: str, text: str) -> None:
    if not summary_file:
        return
    with open(summary_file, "a", encoding="utf-8") as fh:
        fh.write(text + "\n")


def write_github_outputs(result: ScanResult, fail_on: str) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    if not output_file:
        return
    verdict = "true" if result.matched(fail_on) else "false"
    with open(output_file, "a", encoding="utf-8") as fh:
        fh.write(f"findings={len(result.findings)}\n")
        fh.write(f"confirmed={result.confirmed}\n")
        fh.write(f"warnings={result.warnings}\n")
        fh.write(f"files={result.files_scanned}\n")
        fh.write(f"pages={result.pages_scanned}\n")
        fh.write(f"files-with-findings={result.files_with_findings}\n")
        fh.write(f"matched={verdict}\n")


def emit_annotations(result: ScanResult, annotations: str) -> None:
    if annotations == "never":
        return
    if annotations == "auto" and os.environ.get("GITHUB_ACTIONS") != "true":
        return
    counts = {"error": 0, "warning": 0}
    for f in result.findings:
        level = "error" if f.severity == SEVERITY_CONFIRMED else "warning"
        if counts[level] >= MAX_ANNOTATIONS_PER_LEVEL:
            continue
        counts[level] += 1
        print(f.annotation())
    for err in result.errors:
        print(f"::error title=Redaction-CI scan error::{escape_workflow_data(err)}")


def result_json(result: ScanResult) -> str:
    return json.dumps(
        {
            "findings": [
                {
                    "kind": f.kind,
                    "severity": f.severity,
                    "file": f.file,
                    "page": f.page,
                    "rect": [round(v, 2) for v in f.rect],
                    "text": f.text,
                    "detail": f.detail,
                }
                for f in result.findings
            ],
            "files_scanned": result.files_scanned,
            "pages_scanned": result.pages_scanned,
            "image_only_pages": [list(p) for p in result.image_only_pages],
            "errors": result.errors,
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@dataclass
class Options:
    max_fill_luma: float = 0.85
    min_overlap: float = 0.5
    min_fill_opacity: float = 0.5


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redaction_ci",
        description="Detect fake PDF redactions: extractable text under covering boxes and invisible text layers.",
    )
    parser.add_argument(
        "--paths",
        default=None,
        metavar="GLOB",
        help=f"newline-separated glob(s) of PDFs to scan, relative to cwd (default: {DEFAULT_PATHS!r})",
    )
    parser.add_argument(
        "--exclude",
        default="",
        metavar="GLOB",
        help="newline-separated glob(s) to exclude from the scan (default: none)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("any", "confirmed"),
        default="any",
        help="'any' fails on all findings; 'confirmed' fails only on extractable text under a box (default: any)",
    )
    parser.add_argument(
        "--max-fill-luma",
        type=float,
        default=0.85,
        help="a fill counts as a redaction box if its perceived luminance is <= this (0..1; default 0.85)",
    )
    parser.add_argument(
        "--min-overlap",
        type=float,
        default=0.5,
        help="minimum fraction of a text run's bbox a box must cover to count (default 0.5)",
    )
    parser.add_argument(
        "--min-fill-opacity",
        type=float,
        default=0.5,
        help="minimum fill opacity for a box to count as covering (default 0.5)",
    )
    parser.add_argument("--summary-file", default=None, help="append the markdown report to this file ($GITHUB_STEP_SUMMARY)")
    parser.add_argument(
        "--annotations",
        choices=("auto", "always", "never"),
        default="auto",
        help="emit GitHub workflow-command annotations (default: auto = only when GITHUB_ACTIONS=true)",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text", help="stdout format (default: text)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    opts = Options(
        max_fill_luma=args.max_fill_luma,
        min_overlap=args.min_overlap,
        min_fill_opacity=args.min_fill_opacity,
    )

    patterns = [p.strip() for p in (args.paths if args.paths is not None else DEFAULT_PATHS).splitlines() if p.strip()]
    excludes = [p.strip() for p in args.exclude.splitlines() if p.strip()]

    base = Path.cwd()
    # The action always passes --paths (its input default), so strictness is
    # keyed off the pattern itself: only user-chosen globs fail closed when
    # they match nothing; the default glob is allowed to scan zero PDFs.
    strict_patterns = (args.paths or "").strip() not in (None, "", DEFAULT_PATHS)
    result = scan(base, patterns, excludes, opts, strict_patterns=strict_patterns)

    if args.format == "json":
        print(result_json(result))
    else:
        for f in result.findings:
            loc = f"{f.file} p{f.page}"
            print(f"[{f.severity.upper():9}] {loc} — {f.detail}: {f.text!r}")
        for err in result.errors:
            print(f"[ERROR    ] {err}")
        if not result.findings and not result.errors:
            print("No fake-redaction findings.")
        verdict = "fail" if result.matched(args.fail_on) else "pass"
        print(
            f"Scanned {result.files_scanned} file(s), {result.pages_scanned} page(s); "
            f"{len(result.findings)} finding(s) ({result.confirmed} confirmed, {result.warnings} warnings); "
            f"verdict: {verdict} (fail-on: {args.fail_on})"
        )

    emit_annotations(result, args.annotations)
    write_summary(args.summary_file or "", summary_markdown(result, args.fail_on))
    write_github_outputs(result, args.fail_on)

    if result.errors:
        return 2
    return 1 if result.matched(args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
