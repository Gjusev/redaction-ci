#!/usr/bin/env python3
"""Redaction-CI: detect fake PDF redactions.

Failure modes detected per page:

1. ``covered-text``  -- extractable text that sits under a later-drawn,
   opaque, dark filled box without being removed (classic "x-ray"
   redaction: the text is still in the content stream, one copy-paste
   away). Reported with severity ``confirmed``.
2. ``unapplied-redaction`` -- a PDF redaction annotation whose underlying
   text is still extractable: someone marked the redaction but never
   applied it. Severity ``confirmed``.
3. ``invisible-text`` -- text that is never rendered: PDF render mode 3
   (hidden copies of sensitive strings) or text with near-zero fill
   opacity. Invisible spans that overlap a placed image are treated as a
   legitimate OCR layer of a scan and skipped. Severity ``warning``.
4. ``camouflaged-text`` -- text whose fill colour matches the box (or the
   white page) behind it: black-on-black / white-on-white, invisible to
   every viewer, extractable by every tool. Severity ``warning``.
5. ``off-page-text`` -- text placed entirely outside the visible page
   rectangle: never rendered, recoverable by unclipped extractors.
   Severity ``warning``.
6. ``image-covered-text`` -- extractable text geometrically under a
   placed image (paint order is not verified, so this is a warning, not a
   confirmed leak). Severity ``warning``.
7. ``form-value`` -- AcroForm fields that still carry values.
   Severity ``warning``.
8. ``attachment`` -- embedded file attachments shipping whole extra
   documents inside the PDF. Severity ``warning``.
9. ``incremental-leftover`` -- earlier document revisions recoverable
   before the first ``%%EOF`` of an incrementally saved file; the first
   revision is re-scanned and only reported when it actually contains
   findings. Severity ``confirmed`` when the earlier revision has a
   confirmed finding, else ``warning``.

Pages that contain no text at all (scans, image-only PDFs) are listed as
informational: verifying them needs OCR, which is out of scope.

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
from typing import Sequence

import pymupdf

__version__ = "0.2.0"

DEFAULT_PATHS = "**/*.pdf"

KIND_COVERED = "covered-text"
KIND_UNAPPLIED = "unapplied-redaction"
KIND_INVISIBLE = "invisible-text"
KIND_CAMOUFLAGE = "camouflaged-text"
KIND_OFFPAGE = "off-page-text"
KIND_IMAGE_COVER = "image-covered-text"
KIND_FORM_VALUE = "form-value"
KIND_ATTACHMENT = "attachment"
KIND_INCREMENTAL = "incremental-leftover"

KIND_TITLES = {
    KIND_COVERED: "Fake redaction: text recoverable under box",
    KIND_UNAPPLIED: "Redaction annotation never applied",
    KIND_INVISIBLE: "Invisible text layer (render mode 3 / zero opacity)",
    KIND_CAMOUFLAGE: "Camouflaged text (same colour as its background)",
    KIND_OFFPAGE: "Off-page text (present but never rendered)",
    KIND_IMAGE_COVER: "Text under a covering image",
    KIND_FORM_VALUE: "Form field carries a value",
    KIND_ATTACHMENT: "Embedded attachment",
    KIND_INCREMENTAL: "Earlier document revision recoverable",
}

SEVERITY_CONFIRMED = "confirmed"
SEVERITY_WARNING = "warning"

RENDER_INVISIBLE = 3

#: A "redaction box" smaller than this (in points per side) is treated as
#: decoration, not as an attempt to hide a text line.
MIN_BOX_SIDE = 2.0

#: Annotation spam guard: GitHub caps annotations per step/job, so the
#: workflow-command stream is truncated while all findings still count.
MAX_ANNOTATIONS_PER_LEVEL = 50
MAX_ERROR_ANNOTATIONS = 10
MAX_SUMMARY_ROWS = 100

EXCERPT_LIMIT = 60

#: Text and box fill colours within this luminance distance are
#: "camouflaged": no viewer can separate them.
CAMOUFLAGE_DELTA = 0.12

#: Text at least this bright, with nothing drawn under it, matches the
#: default white PDF page: white-on-white.
PALE_LUMA = 0.9

#: Fraction of an invisible span that must overlap a placed image for the
#: span to count as the OCR layer of a scan.
OCR_OVERLAP = 0.5


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


def text_color_luminance(color: object) -> float:
    """Luminance (0..1) of a text fill colour from ``get_texttrace()``.

    pymupdf >= 1.26 reports ``color`` as an (r, g, b) float tuple; older
    releases used a single sRGB int. Both are handled defensively.
    """
    if color is None:
        return 1.0
    if isinstance(color, (int, float)):
        i = int(color)
        comps = (((i >> 16) & 255) / 255, ((i >> 8) & 255) / 255, (i & 255) / 255)
    else:
        try:
            comps = (float(v) for v in tuple(color)[:3])
        except TypeError:
            return 1.0
        comps = tuple(comps)
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


def _norm(text: str) -> str:
    return " ".join(text.split())


def _sample(texts: Sequence[str], limit: int = 3) -> str:
    seen: list[str] = []
    for t in texts:
        s = excerpt(t)
        if s not in seen:
            seen.append(s)
    return " | ".join(seen[:limit])


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
    luma: float

    @property
    def is_visible(self) -> bool:
        return self.render_mode != RENDER_INVISIBLE and self.opacity > 0.05


@dataclass(frozen=True)
class FillBox:
    rect: tuple
    seqno: int
    luma: float


@dataclass
class Finding:
    kind: str
    severity: str  # SEVERITY_CONFIRMED | SEVERITY_WARNING
    file: str
    page: int  # 1-based; 0 = document-level (no page)
    rect: tuple
    text: str  # recoverable excerpt
    detail: str

    @property
    def title(self) -> str:
        return KIND_TITLES.get(self.kind, self.kind)

    def annotation(self) -> str:
        """GitHub workflow command for a file-level annotation."""
        level = "error" if self.severity == SEVERITY_CONFIRMED else "warning"
        title = escape_workflow_property(self.title)
        path = escape_workflow_property(self.file)
        prefix = f"p{self.page} " if self.page else ""
        message = escape_workflow_data(f"{prefix}{self.detail}: {self.text!r}")
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
                luma=text_color_luminance(s.get("color")),
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
        boxes.append(
            FillBox(
                rect=(r.x0, r.y0, r.x1, r.y1),
                seqno=seqno,
                luma=fill_luminance(d["fill"]),
            )
        )
    # Stacked identical boxes (e.g. a double-painted rect) are one box.
    dedup: dict[tuple, FillBox] = {}
    for b in boxes:
        key = tuple(round(v, 1) for v in b.rect)
        prev = dedup.get(key)
        if prev is None or b.seqno > prev.seqno:
            dedup[key] = b
    return list(dedup.values())


def _page_images(page: "pymupdf.Page") -> list[tuple]:
    """Bounding boxes of opaque placed images large enough to hide text.

    Masked/soft-masked images can be transparent, so they are skipped:
    they cannot be assumed to hide anything.
    """
    rects = []
    for info in page.get_image_info() or ():
        if info.get("has-mask"):
            continue
        r = info.get("bbox")
        if not r or (r[2] - r[0]) < MIN_BOX_SIDE or (r[3] - r[1]) < MIN_BOX_SIDE:
            continue
        rects.append(tuple(r))
    return rects


def _has_visible_copy(span: TextSpan, box: FillBox, visible_index: dict) -> bool:
    """True if the same text is also visibly painted ON TOP of the box.

    Some generators emit text, then a dark backing panel, then the same
    text again in white on top. Nothing is concealed: the covered run has
    a readable copy drawn after the box. A same-text span *under* the box
    (double-drawn text, faux bold, a decoy) is itself covered and must not
    suppress the finding.
    """
    for bbox, seqno in visible_index.get(_norm(span.text), ()):
        if seqno > box.seqno and seqno != span.seqno and overlap_fraction(bbox, box.rect) > 0:
            return True
    return False


def _overlaps_any(bbox: Sequence[float], rects: Sequence[tuple], threshold: float) -> bool:
    # Strict '>' on purpose: the pale-text exclusions pass threshold 0.0,
    # and a zero-overlap rect must NOT count as "something behind it".
    return any(overlap_fraction(bbox, r) > threshold for r in rects)


def scan_page(doc: "pymupdf.Document", page_number: int, file_label: str, opts: "Options") -> tuple[list[Finding], bool]:
    """Scan one 0-based page. Returns (findings, image_only)."""
    page = doc[page_number]
    spans = _collect_spans(page)
    boxes = _fill_boxes(page, opts.max_fill_luma, opts.min_fill_opacity)
    images = _page_images(page)
    findings: list[Finding] = []
    visible = [s for s in spans if s.is_visible]
    visible_index: dict[str, list] = {}
    for s in visible:
        visible_index.setdefault(_norm(s.text), []).append((s.bbox, s.seqno))
    page_rect = (page.rect.x0, page.rect.y0, page.rect.x1, page.rect.y1)

    # 1. Extractable text under a later-drawn covering box (confirmed).
    for box in boxes:
        covered = [
            s
            for s in visible
            if box.seqno > s.seqno
            and overlap_fraction(s.bbox, box.rect) >= opts.min_overlap
            and not _has_visible_copy(s, box, visible_index)
        ]
        if covered:
            findings.append(
                Finding(
                    kind=KIND_COVERED,
                    severity=SEVERITY_CONFIRMED,
                    file=file_label,
                    page=page_number + 1,
                    rect=box.rect,
                    text=_sample(s.text for s in covered),
                    detail=f"{len(covered)} extractable text run(s) still recoverable under covering box",
                )
            )

    # 2. Redaction annotations that were never applied (confirmed).
    for annot in page.annots(types=[pymupdf.PDF_ANNOT_REDACT]) or ():
        covered_text = page.get_text("text", clip=annot.rect).strip()
        if covered_text:
            findings.append(
                Finding(
                    kind=KIND_UNAPPLIED,
                    severity=SEVERITY_CONFIRMED,
                    file=file_label,
                    page=page_number + 1,
                    rect=tuple(annot.rect),
                    text=excerpt(covered_text),
                    detail="redaction annotation present but underlying text still extractable (apply_redactions never run)",
                )
            )

    # 3. Text that is never rendered (warning). Invisible spans that sit
    # on a placed image are the OCR layer of a scan -- legitimate.
    hidden = [s for s in spans if not s.is_visible]
    hidden_suspect = [s for s in hidden if not _overlaps_any(s.bbox, images, OCR_OVERLAP)]
    if hidden_suspect:
        mode3 = sum(1 for s in hidden_suspect if s.render_mode == RENDER_INVISIBLE)
        faint = len(hidden_suspect) - mode3
        why = "render mode 3" if mode3 else ""
        if faint:
            why = f"{why + ' / ' if why else ''}fill opacity <= 0.05"
        findings.append(
            Finding(
                kind=KIND_INVISIBLE,
                severity=SEVERITY_WARNING,
                file=file_label,
                page=page_number + 1,
                rect=tuple(
                    (
                        min(s.bbox[0] for s in hidden_suspect),
                        min(s.bbox[1] for s in hidden_suspect),
                        max(s.bbox[2] for s in hidden_suspect),
                        max(s.bbox[3] for s in hidden_suspect),
                    )
                ),
                text=_sample(s.text for s in hidden_suspect),
                detail=f"{len(hidden_suspect)} text run(s) present but never rendered ({why})",
            )
        )

    # 4a. Camouflaged text: same colour as a box behind/around it,
    # regardless of paint order (warning).
    for box in boxes:
        camouflaged = [
            s
            for s in visible
            if box.seqno <= s.seqno
            and overlap_fraction(s.bbox, box.rect) >= opts.min_overlap
            and abs(s.luma - box.luma) <= CAMOUFLAGE_DELTA
        ]
        if camouflaged:
            findings.append(
                Finding(
                    kind=KIND_CAMOUFLAGE,
                    severity=SEVERITY_WARNING,
                    file=file_label,
                    page=page_number + 1,
                    rect=box.rect,
                    text=_sample(s.text for s in camouflaged),
                    detail=f"{len(camouflaged)} text run(s) painted the same colour as the box behind them (never visible)",
                )
            )

    # 4b. Near-white text with nothing but the white page behind it.
    pale = [
        s
        for s in visible
        if s.luma >= PALE_LUMA
        and not _overlaps_any(s.bbox, [b.rect for b in boxes], 0.0)
        and not _overlaps_any(s.bbox, images, 0.0)
    ]
    if pale:
        findings.append(
            Finding(
                kind=KIND_CAMOUFLAGE,
                severity=SEVERITY_WARNING,
                file=file_label,
                page=page_number + 1,
                rect=pale[0].bbox,
                text=_sample(s.text for s in pale),
                detail=f"{len(pale)} near-white text run(s) on the white page (never visible)",
            )
        )

    # 5. Text entirely outside the visible page: never rendered. Invisible
    # spans are already reported by check 3; this catches the visible-mode
    # ones so a span is never double-reported.
    off_page = [s for s in visible if overlap_fraction(s.bbox, page_rect) == 0.0]
    if off_page:
        findings.append(
            Finding(
                kind=KIND_OFFPAGE,
                severity=SEVERITY_WARNING,
                file=file_label,
                page=page_number + 1,
                rect=off_page[0].bbox,
                text=_sample(s.text for s in off_page),
                detail=f"{len(off_page)} text run(s) entirely outside the visible page (recoverable by unclipped extractors)",
            )
        )

    # 6. Text under a placed image (paint order unverified: warning).
    for image_rect in images:
        under = [
            s
            for s in visible
            if overlap_fraction(s.bbox, image_rect) >= opts.min_overlap
        ]
        if under:
            findings.append(
                Finding(
                    kind=KIND_IMAGE_COVER,
                    severity=SEVERITY_WARNING,
                    file=file_label,
                    page=page_number + 1,
                    rect=image_rect,
                    text=_sample(s.text for s in under),
                    detail=f"{len(under)} text run(s) under a covering image (image paint order not verified)",
                )
            )

    # 7. AcroForm fields that still carry values. Checkboxes and radios
    # carry only their on/off state -- nothing worth a warning.
    for widget in page.widgets() or ():
        if widget.field_type in (
            pymupdf.PDF_WIDGET_TYPE_SIGNATURE,
            pymupdf.PDF_WIDGET_TYPE_CHECKBOX,
            pymupdf.PDF_WIDGET_TYPE_RADIOBUTTON,
        ):
            continue
        value = widget.field_value
        if isinstance(value, (list, tuple)):
            value = ", ".join(str(v) for v in value)
        if value is not None and str(value).strip():
            findings.append(
                Finding(
                    kind=KIND_FORM_VALUE,
                    severity=SEVERITY_WARNING,
                    file=file_label,
                    page=page_number + 1,
                    rect=tuple(widget.rect),
                    text=excerpt(str(value)),
                    detail=f"form field {widget.field_name!r} still carries a value",
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
        for name in doc.embfile_names():
            data = bytes(doc.embfile_get(name))
            findings.append(
                Finding(
                    kind=KIND_ATTACHMENT,
                    severity=SEVERITY_WARNING,
                    file=file_label,
                    page=0,
                    rect=(0, 0, 0, 0),
                    text=excerpt(data.decode("utf-8", "replace")),
                    detail=f"embedded file {name!r} ({len(data)} bytes) recoverable",
                )
            )
        pages = doc.page_count
    finally:
        doc.close()
    findings.extend(_incremental_leftovers(path, file_label, opts))
    return findings, image_only, pages


def _incremental_leftovers(path: Path, file_label: str, opts: "Options") -> list[Finding]:
    """Re-scan every earlier revision of an incrementally saved PDF.

    Saving incrementally after "redacting" keeps every earlier revision in
    the file. The byte prefix ending at each ``%%EOF`` marker is one
    recoverable revision; the final one is the current document, already
    scanned. Only when a recoverable revision actually contains findings
    is anything reported, so writers that benignly emit multiple ``%%EOF``
    markers stay quiet.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return []
    positions: list[int] = []
    start = 0
    while True:
        i = data.find(b"%%EOF", start)
        if i < 0:
            break
        positions.append(i + 5)
        start = i + 5
    rev_findings: list[Finding] = []
    seen: set = set()
    for pos in positions[:-1]:  # the last prefix IS the current document
        try:
            old = pymupdf.open(stream=data[:pos], filetype="pdf")
        except Exception:
            continue  # unparseable prefix (e.g. linearized first body)
        try:
            if old.needs_pass or old.page_count == 0:
                continue
            for pno in range(old.page_count):
                page_findings, _ = scan_page(old, pno, file_label, opts)
                for f in page_findings:
                    key = (f.kind, f.page, f.text)
                    if key not in seen:
                        seen.add(key)
                        rev_findings.append(f)
        except Exception:
            continue
        finally:
            old.close()
    if not rev_findings:
        return []
    has_confirmed = any(f.severity == SEVERITY_CONFIRMED for f in rev_findings)
    first = rev_findings[0]
    return [
        Finding(
            kind=KIND_INCREMENTAL,
            severity=SEVERITY_CONFIRMED if has_confirmed else SEVERITY_WARNING,
            file=file_label,
            page=first.page,
            rect=(0, 0, 0, 0),
            text=first.text,
            detail=f"{len(rev_findings)} issue(s) recoverable from {len(positions) - 1} earlier revision(s) of the file",
        )
    ]


def glob_to_regex(pattern: str) -> "re.Pattern[str]":
    """Translate a path glob to a regex, independent of the Python version.

    pathlib's ``**`` handling changed semantics across 3.12 -> 3.13
    (``dir/**`` matches files on 3.13 but not on 3.12); the action runs on
    whatever Python setup-python provides, so matching behaviour must not
    depend on that. Supported: ``**`` (any depth, including none), ``*``
    (within one path segment), ``?`` (one non-separator char).

    Matching is case-insensitive: scanners produce ``.PDF`` as often as
    ``.pdf``, and a missed file is a missed leak.
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
    return re.compile("".join(["^", *out, "$"]), re.IGNORECASE)


def resolve_files(
    base: Path,
    patterns: Sequence[str],
    excludes: Sequence[str],
) -> tuple[list[Path], list[str], int]:
    """Resolve globs relative to *base*.

    Returns (files, unmatched_patterns, excluded_count). ``.git`` is never
    walked: nothing in it is a scannable document.
    """
    candidates: list[Path] = []
    for root, dirs, file_names in os.walk(base):
        dirs[:] = [d for d in dirs if d != ".git"]
        candidates.extend(Path(root, name) for name in file_names)

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
    excluded = 0
    for pattern in excludes:
        matched = match(pattern)
        excluded += len(files & matched)
        files -= matched
    return sorted(files), unmatched, excluded


def scan(
    base_dir: Path,
    patterns: Sequence[str],
    excludes: Sequence[str],
    opts: "Options",
    strict_patterns: bool = True,
) -> ScanResult:
    result = ScanResult()
    files, unmatched, excluded = resolve_files(base_dir, patterns, excludes)
    if strict_patterns:
        # A typo'd explicit glob would otherwise fail silently open.
        for pattern in unmatched:
            result.errors.append(f"pattern matched no files: {pattern}")
    if excluded and not files:
        # Excludes that empty the whole corpus are a mistake, not a clean
        # scan -- this holds for the default glob too (the action always
        # passes it), so it lives outside the strict_patterns gate.
        result.errors.append("excludes removed every file matched by the patterns")
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
            page = f.page if f.page else "—"
            lines.append(
                f"| `{_md_cell(f.file)}` | {page} | {_md_cell(f.kind)} | {_md_cell(f.severity)} | {_md_cell(f.text)} |"
            )
        if len(result.findings) > MAX_SUMMARY_ROWS:
            lines.append(f"| … | | {len(result.findings) - MAX_SUMMARY_ROWS} more finding(s) not listed | | |")
    if result.image_only_pages:
        shown = ", ".join(f"`{f}` p{p}" for f, p in result.image_only_pages[:MAX_SUMMARY_ROWS])
        lines.append("")
        lines.append(
            f"**Image-only page(s)** (no extractable text): {shown}. "
            "Scanned/image PDFs need OCR to verify — out of scope, see README limitations."
        )
    if not result.findings and not result.errors:
        lines.append("")
        lines.append("No recoverable text under redaction boxes, no invisible or camouflaged text layers found.")
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


def emit_annotations(result: ScanResult, annotations: str, to_stderr: bool = False) -> None:
    """Print GitHub workflow-command annotations.

    With ``to_stderr`` (used for ``--format json``) the commands leave the
    stdout JSON stream unpolluted; GitHub does not parse workflow commands
    from stderr, so no annotations are rendered in that mode -- the JSON
    consumer is expected to surface findings itself.
    """
    if annotations == "never":
        return
    if annotations == "auto" and os.environ.get("GITHUB_ACTIONS") != "true":
        return
    stream = sys.stderr if to_stderr else sys.stdout
    counts = {"error": 0, "warning": 0}
    for f in result.findings:
        level = "error" if f.severity == SEVERITY_CONFIRMED else "warning"
        if counts[level] >= MAX_ANNOTATIONS_PER_LEVEL:
            continue
        counts[level] += 1
        print(f.annotation(), file=stream)
    for err in result.errors[:MAX_ERROR_ANNOTATIONS]:
        print(f"::error title=Redaction-CI scan error::{escape_workflow_data(err)}", file=stream)
    if len(result.errors) > MAX_ERROR_ANNOTATIONS:
        more = len(result.errors) - MAX_ERROR_ANNOTATIONS
        print(f"::error title=Redaction-CI scan error::... and {more} more scan error(s) — see job summary", file=stream)


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
        description="Detect fake PDF redactions: extractable text under covering boxes, unapplied redaction annotations, invisible/camouflaged text layers and more.",
    )
    parser.add_argument(
        "--paths",
        default=None,
        metavar="GLOB",
        help=(
            f"newline-separated glob(s) of PDFs to scan, relative to cwd (default: {DEFAULT_PATHS!r}); "
            "a line starting with '!' is treated as an exclusion"
        ),
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
        default="confirmed",
        help=(
            "'confirmed' fails only on extractable text under a box, unapplied redactions and recoverable "
            "earlier revisions (default); 'any' also fails on invisible/camouflaged text and the other warnings"
        ),
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
        help="emit GitHub workflow-command annotations (default: auto = only when GITHUB_ACTIONS=true; with --format json they go to stderr)",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text", help="stdout format (default: text)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _split_patterns(paths: str | None, exclude: str) -> tuple[list[str], list[str]]:
    """Split --paths/--exclude into (patterns, excludes), honouring '!'."""
    patterns: list[str] = []
    excludes = [p.strip() for p in exclude.splitlines() if p.strip()]
    for line in (paths if paths is not None else DEFAULT_PATHS).splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("!"):
            negated = line[1:].strip()
            if negated:
                excludes.append(negated)
        else:
            patterns.append(line)
    return patterns, excludes


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    opts = Options(
        max_fill_luma=args.max_fill_luma,
        min_overlap=args.min_overlap,
        min_fill_opacity=args.min_fill_opacity,
    )

    if args.paths is not None and not args.paths.strip():
        print("error: --paths was given but is empty; refusing to scan nothing", file=sys.stderr)
        return 2
    patterns, excludes = _split_patterns(args.paths, args.exclude)
    if args.paths is not None and not patterns:
        print("error: --paths contains only negation lines; refusing to scan nothing", file=sys.stderr)
        return 2

    base = Path.cwd()
    # The action always passes --paths (its input default), so strictness is
    # keyed off the pattern itself: only user-chosen globs fail closed when
    # they match nothing; the default glob is allowed to scan zero PDFs.
    strict_patterns = args.paths is not None and args.paths.strip() != DEFAULT_PATHS
    result = scan(base, patterns, excludes, opts, strict_patterns=strict_patterns)

    if args.format == "json":
        print(result_json(result))
    else:
        for f in result.findings:
            loc = f"{f.file} p{f.page}" if f.page else f"{f.file} doc"
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

    emit_annotations(result, args.annotations, to_stderr=args.format == "json")
    write_summary(args.summary_file or "", summary_markdown(result, args.fail_on))
    write_github_outputs(result, args.fail_on)

    if result.errors:
        return 2
    return 1 if result.matched(args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
