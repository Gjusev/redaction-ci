#!/usr/bin/env python3
"""Generate the fixture PDFs in ``fixtures/``.

Each fixture isolates one behaviour of the detector:

- ``benign-redacted.pdf``  text truly removed (PyMuPDF redaction
  annotations applied), black box painted over the gap -> 0 findings.
- ``fake-redaction.pdf``   black box drawn *over* intact text -> 1
  confirmed ``covered-text`` finding.
- ``invisible-text.pdf``   text drawn with PDF render mode 3 (plus a
  black box over it) -> 1 ``invisible-text`` warning.
- ``image-only.pdf``       a scan-like image, no text -> 0 findings,
  one informational image-only page.

Run ``python tests/make_fixtures.py [outdir]`` to regenerate. The
fixtures are committed so the repo's CI can dogfood the action against
its own repository without regenerating first.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pymupdf

SECRET_LINE = "Internal key: DO-NOT-SHARE-9911"
SECRET_RECT = pymupdf.Rect(64, 186, 340, 206)


def _new_page(doc: "pymupdf.Document") -> "pymupdf.Page":
    page = doc.new_page(width=595, height=842)  # A4
    page.insert_text((72, 120), "Quarterly report Q3", fontsize=14)
    page.insert_text((72, 160), "Customer: ACME GmbH", fontsize=14)
    page.insert_text((72, 200), SECRET_LINE, fontsize=14)
    return page


def _save(doc: "pymupdf.Document", out: Path) -> None:
    doc.set_metadata(
        {
            "producer": "redaction-ci fixtures",
            "creator": "tests/make_fixtures.py",
            "creationDate": "D:20261029000000Z",
            "modDate": "D:20261029000000Z",
        }
    )
    doc.save(out)
    doc.close()


def benign_redacted(out: Path) -> None:
    doc = pymupdf.open()
    page = _new_page(doc)
    # The honest way: remove the text, then paint the box.
    page.add_redact_annot(SECRET_RECT, fill=(0, 0, 0))
    page.apply_redactions()
    _save(doc, out)


def fake_redaction(out: Path) -> None:
    doc = pymupdf.open()
    page = _new_page(doc)
    # The dishonest way: draw a box over text that is still in the file.
    page.draw_rect(SECRET_RECT, fill=(0, 0, 0), color=None)
    _save(doc, out)


def invisible_text(out: Path) -> None:
    doc = pymupdf.open()
    page = _new_page(doc)
    # Hidden layer: text that any extractor finds but no viewer renders.
    page.insert_text((72, 240), "Hidden copy: TOPSECRET-4455", fontsize=14, render_mode=3)
    page.draw_rect(pymupdf.Rect(64, 226, 360, 246), fill=(0, 0, 0), color=None)
    _save(doc, out)


def image_only(out: Path) -> None:
    doc = pymupdf.open()
    page = doc.new_page(width=595, height=842)
    pix = pymupdf.Pixmap(pymupdf.csRGB, pymupdf.IRect(0, 0, 300, 120))
    pix.set_rect(pix.irect, (235, 235, 235))
    pix.set_rect(pymupdf.IRect(40, 40, 260, 80), (60, 60, 60))
    page.insert_image(pymupdf.Rect(72, 100, 372, 220), pixmap=pix)
    _save(doc, out)


FIXTURES = {
    "benign-redacted.pdf": benign_redacted,
    "fake-redaction.pdf": fake_redaction,
    "invisible-text.pdf": invisible_text,
    "image-only.pdf": image_only,
}


def generate(outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    for name, builder in FIXTURES.items():
        builder(outdir / name)
        print(f"wrote {outdir / name}")


if __name__ == "__main__":
    outdir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "fixtures"
    generate(outdir)
