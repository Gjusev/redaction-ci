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
- ``ocr-legit.pdf``        scan image + render-mode-3 OCR words on top of
  it (the standard searchable-scan output) -> 0 findings: an invisible
  span overlapping an image is a legitimate OCR layer.
- ``black-on-black.pdf``   dark box, then same-colour text on top ->
  1 ``camouflaged-text`` warning (invisible to viewers, extractable).
- ``off-page.pdf``         text far outside the page -> 1 ``off-page-text``
  warning.
- ``unapplied-redact.pdf`` redaction annotation added but never applied ->
  1 confirmed ``unapplied-redaction`` finding.
- ``image-over-text.pdf``  intact text, screenshot image pasted over it ->
  1 ``image-covered-text`` warning (paint order unverified).
- ``white-redraw.pdf``     text, dark panel over it, same text redrawn in
  white on top (a benign generator z-order quirk) -> 0 findings.
- ``stacked-boxes.pdf``    the same black box drawn twice over text -> 1
  ``covered-text`` finding (duplicates deduplicated).
- ``form-value.pdf``       filled AcroForm text field -> 1 ``form-value``
  warning.
- ``attachment.pdf``       embedded file attachment -> 1 ``attachment``
  warning.
- ``incremental-leftover.pdf`` fake redaction saved, then properly
  redacted and saved *incrementally* -> the current revision is clean but
  revision 1 leaks -> 1 confirmed ``incremental-leftover`` finding.

``encrypted.pdf`` (password "pw") is generated separately: it is not part
of EXPECTATIONS because scanning it must fail (exit 2).

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


def ocr_legit(out: Path) -> None:
    """A searchable scan: image page plus render-mode-3 OCR words on it."""
    doc = pymupdf.open()
    page = doc.new_page(width=595, height=842)
    words = ["Quarterly", "report", "Q3", "Customer:", "ACME", "GmbH", SECRET_LINE]
    pix = pymupdf.Pixmap(pymupdf.csRGB, pymupdf.IRect(0, 0, 450, 60))
    pix.set_rect(pix.irect, (255, 255, 255))
    page.insert_image(pymupdf.Rect(72, 100, 522, 160), pixmap=pix)
    x = 76
    for word in words:
        page.insert_text((x, 136), word, fontsize=12, render_mode=3)  # the OCR layer
        x += 8 * len(word) + 12
    _save(doc, out)


def black_on_black(out: Path) -> None:
    doc = pymupdf.open()
    page = _new_page(doc)
    # Box first, then text in the same colour: invisible, but extractable.
    page.draw_rect(SECRET_RECT, fill=(0, 0, 0), color=None)
    page.insert_text((72, 200), SECRET_LINE, fontsize=14, color=(0, 0, 0))
    _save(doc, out)


def off_page(out: Path) -> None:
    doc = pymupdf.open()
    page = _new_page(doc)
    # Text dragged outside the canvas: no viewer renders it.
    page.insert_text((2400, 2600), SECRET_LINE, fontsize=14)
    _save(doc, out)


def unapplied_redact(out: Path) -> None:
    doc = pymupdf.open()
    page = _new_page(doc)
    # Redaction marked but never applied: the text is fully intact.
    page.add_redact_annot(SECRET_RECT, fill=(0, 0, 0))
    _save(doc, out)


def image_over_text(out: Path) -> None:
    doc = pymupdf.open()
    page = _new_page(doc)
    # A screenshot pasted over the live text.
    pix = pymupdf.Pixmap(pymupdf.csRGB, pymupdf.IRect(0, 0, 300, 40))
    pix.set_rect(pix.irect, (200, 200, 200))
    page.insert_image(SECRET_RECT, pixmap=pix)
    _save(doc, out)


def white_redraw(out: Path) -> None:
    doc = pymupdf.open()
    page = _new_page(doc)
    # Benign generator quirk: text, dark panel over it, same text again
    # in white on top. Nothing is hidden; the detector must stay quiet.
    page.insert_text((72, 200), SECRET_LINE, fontsize=14)
    page.draw_rect(SECRET_RECT, fill=(0.12, 0.12, 0.12), color=None)
    page.insert_text((72, 200), SECRET_LINE, fontsize=14, color=(1, 1, 1))
    _save(doc, out)


def stacked_boxes(out: Path) -> None:
    doc = pymupdf.open()
    page = _new_page(doc)
    # The same box painted twice over the text: still one finding.
    page.draw_rect(SECRET_RECT, fill=(0, 0, 0), color=None)
    page.draw_rect(SECRET_RECT, fill=(0, 0, 0), color=None)
    _save(doc, out)


def form_value(out: Path) -> None:
    doc = pymupdf.open()
    page = _new_page(doc)
    widget = pymupdf.Widget()
    widget.field_name = "tax_id"
    widget.field_type = pymupdf.PDF_WIDGET_TYPE_TEXT
    widget.field_value = "123-45-6789"
    widget.rect = pymupdf.Rect(72, 240, 260, 264)
    page.add_widget(widget)
    _save(doc, out)


def attachment(out: Path) -> None:
    doc = pymupdf.open()
    _new_page(doc)
    doc.embfile_add("hr-salaries.csv", b"name,salary\nalice,120000\nbob,90000\n")
    _save(doc, out)


def incremental_leftover(out: Path) -> None:
    # Revision 1: a fake redaction.
    doc = pymupdf.open()
    page = _new_page(doc)
    page.draw_rect(SECRET_RECT, fill=(0, 0, 0), color=None)
    doc.save(out)
    doc.close()
    # Revision 2 (incremental): the redaction is applied properly, but the
    # earlier revision stays in the file and still contains the secret.
    doc = pymupdf.open(out)
    page = doc[0]
    page.add_redact_annot(SECRET_RECT, fill=(0, 0, 0))
    page.apply_redactions()
    doc.saveIncr()
    doc.close()


def encrypted(out: Path) -> None:
    doc = pymupdf.open()
    _new_page(doc)
    doc.save(out, encryption=pymupdf.PDF_ENCRYPT_AES_256, user_pw="pw", owner_pw="pw")
    doc.close()


FIXTURES = {
    "benign-redacted.pdf": benign_redacted,
    "fake-redaction.pdf": fake_redaction,
    "invisible-text.pdf": invisible_text,
    "image-only.pdf": image_only,
    "ocr-legit.pdf": ocr_legit,
    "black-on-black.pdf": black_on_black,
    "off-page.pdf": off_page,
    "unapplied-redact.pdf": unapplied_redact,
    "image-over-text.pdf": image_over_text,
    "white-redraw.pdf": white_redraw,
    "stacked-boxes.pdf": stacked_boxes,
    "form-value.pdf": form_value,
    "attachment.pdf": attachment,
    "incremental-leftover.pdf": incremental_leftover,
}


def generate(outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    for name, builder in FIXTURES.items():
        builder(outdir / name)
        print(f"wrote {outdir / name}")
    encrypted(outdir / "encrypted.pdf")
    print(f"wrote {outdir / 'encrypted.pdf'}")


if __name__ == "__main__":
    outdir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "fixtures"
    generate(outdir)
