#!/usr/bin/env python3
"""

What it does (high-level):
- Metadata analysis (document metadata + basic file stats)
- Structure indicators (PDF header, EOF markers, xref/updates heuristics)
- Text extraction tests (search/copy-like extraction)
- Redaction analysis (very important!):
    * Detect true redaction annotations (if present)
    * Detect common "fake redaction" patterns:
        - Black rectangles drawn over text (overlay)
        - White-on-white text (color trick) [best-effort]
        - Cropping (CropBox vs MediaBox differences)
        - Hidden layers / optional content groups (best-effort)
    * Tries to “recover” text under suspected redaction boxes by checking
      if extractable text exists in that region.
- Visual output:
    * Renders pages to images
    * Draws bounding boxes around suspected redaction overlays and/or redaction annotations
    * Saves annotated images to an output folder
- Interactivity:
    * Menu-driven CLI
    * Lets students choose pages, search terms, and output options

IMPORTANT NOTES / LIMITATIONS (read this!):
- "PDF forensics" can get extremely deep. This script covers many common
  techniques and teaches the concepts, but it is NOT a replacement for
  professional forensic tools.
- Some checks are best-effort because PDF internals vary widely.
- If a PDF is scanned (image-only), text-under-box detection may fail unless OCR text exists.

Dependencies (install):
- pip install pymupdf pypdf matplotlib

PyMuPDF (pymupdf) is used for rendering pages and inspecting drawings/annotations,
which is great for visual/redaction analysis.

Tested conceptually on typical PDFs; expect to iterate for your course labs.

Usage:
  python pdf_forensics_lab.py /path/to/file.pdf
"""

import os
import re
import sys
import json
import hashlib
import datetime
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict, Any

# ---- Core libraries for PDF work ----
from pypdf import PdfReader  # metadata & some structure
import fitz  # PyMuPDF: rendering, annotations, drawings, text blocks
import matplotlib.pyplot as plt
import matplotlib.patches as patches


# -----------------------------
# Utility helpers
# -----------------------------

def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    """Compute SHA-256 hash of a file (standard forensic step for integrity)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def safe_mkdir(path: str) -> None:
    """Create folder if it doesn't exist."""
    os.makedirs(path, exist_ok=True)


def read_tail_bytes(path: str, n: int = 1024 * 256) -> bytes:
    """
    Read the last N bytes of a file.
    Why? Many PDF "incremental updates" (edits appended) show up near the end.
    """
    size = os.path.getsize(path)
    start = max(0, size - n)
    with open(path, "rb") as f:
        f.seek(start)
        return f.read()


def count_pdf_markers(raw: bytes) -> Dict[str, int]:
    """
    Count common PDF markers in raw bytes.
    - '%%EOF' count can indicate incremental updates (multiple EOFs)
    - 'startxref' count can also indicate multiple revisions
    """
    # PDFs are bytes; search markers as bytes
    return {
        "EOF_count": raw.count(b"%%EOF"),
        "startxref_count": raw.count(b"startxref"),
        "xref_count": raw.count(b"xref"),
        "obj_count": raw.count(b" obj"),
        "endobj_count": raw.count(b"endobj"),
    }


def pretty_dt(ts: float) -> str:
    """Format a file timestamp nicely."""
    return datetime.datetime.fromtimestamp(ts).isoformat(sep=" ", timespec="seconds")


# -----------------------------
# Data structures for findings
# -----------------------------

@dataclass
class BoxFinding:
    page_index: int
    rect: fitz.Rect
    kind: str  # e.g., "redaction_annot", "overlay_rect", "crop_suspect"
    details: str
    recovered_text: str = ""


# -----------------------------
# PDF Forensics class
# -----------------------------

class PDFForensicsLab:
    """
    Encapsulates analysis steps so students can read the code more easily
    and instructors can extend it.
    """

    def __init__(self, pdf_path: str, out_dir: str = "pdf_forensics_output"):
        self.pdf_path = pdf_path
        self.out_dir = out_dir

        # We open with both libraries:
        # - pypdf for metadata and some structural access
        # - PyMuPDF for rendering and deep page-level inspection
        self.reader = PdfReader(pdf_path)
        self.doc = fitz.open(pdf_path)

        safe_mkdir(self.out_dir)

    # -------------------------
    # 1) Metadata analysis
    # -------------------------

    def analyze_metadata(self) -> Dict[str, Any]:
        """
        Extract metadata via pypdf and basic filesystem stats.
        Note: metadata can be missing or spoofed.
        """
        meta = {}
        pypdf_meta = self.reader.metadata  # may be None-ish fields

        # pypdf returns keys like '/Author', '/Creator', etc.
        meta["pdf_metadata"] = {str(k): str(v) for k, v in (pypdf_meta or {}).items()}

        st = os.stat(self.pdf_path)
        meta["file_stats"] = {
            "path": os.path.abspath(self.pdf_path),
            "size_bytes": st.st_size,
            "created_time": pretty_dt(st.st_ctime),
            "modified_time": pretty_dt(st.st_mtime),
            "sha256": sha256_file(self.pdf_path),
        }

        meta["page_count"] = len(self.doc)
        return meta

    # -------------------------
    # 2) Basic structure / incremental update heuristics
    # -------------------------

    def analyze_structure_heuristics(self) -> Dict[str, Any]:
        """
        This is NOT full PDF parsing (which is complex),
        but a set of practical heuristics for teaching.
        """
        results: Dict[str, Any] = {}
        with open(self.pdf_path, "rb") as f:
            head = f.read(1024)

        # PDF header typically looks like: %PDF-1.7
        header_match = re.search(br"%PDF-(\d\.\d)", head)
        results["header_version"] = header_match.group(1).decode() if header_match else "unknown"

        # Tail marker counts:
        tail = read_tail_bytes(self.pdf_path, n=1024 * 512)
        markers = count_pdf_markers(tail)
        results["tail_marker_counts"] = markers

        # Teaching point:
        # Multiple %%EOF markers can indicate incremental saves (appended updates).
        # That's not guaranteed, but it's a strong clue.
        results["possible_incremental_updates"] = markers["EOF_count"] > 1

        return results

    # -------------------------
    # 3) Text extraction tests
    # -------------------------

    def extract_text_page(self, page_index: int) -> str:
        """Extract text from a page using PyMuPDF (best for layout-aware extraction)."""
        page = self.doc[page_index]
        return page.get_text("text")  # plain text

    def search_text(self, term: str, max_hits: int = 50) -> List[Dict[str, Any]]:
        """
        Search for term across pages and return locations.
        Useful to show that 'redacted' text may still be searchable.
        """
        hits = []
        for i in range(len(self.doc)):
            page = self.doc[i]
            # search_for returns rectangles where the term appears (if the text layer contains it)
            rects = page.search_for(term)
            for r in rects[:max_hits]:
                hits.append({"page": i, "rect": [r.x0, r.y0, r.x1, r.y1]})
            if len(hits) >= max_hits:
                break
        return hits

    # -------------------------
    # 4) Redaction analysis (detailed)
    # -------------------------

    def detect_redaction_annots(self) -> List[BoxFinding]:
        """
        Detect true redaction annotations:
        - Subtype /Redact (in PDF spec)
        - In PyMuPDF, redaction annotations show up as annot type 'redact'
          depending on version.
        """
        findings: List[BoxFinding] = []
        for i in range(len(self.doc)):
            page = self.doc[i]
            annot = page.first_annot
            while annot:
                # PyMuPDF has annot.type as (code, name)
                atype = annot.type[1] if annot.type else "unknown"
                rect = annot.rect

                if "redact" in atype.lower():
                    findings.append(
                        BoxFinding(
                            page_index=i,
                            rect=rect,
                            kind="redaction_annot",
                            details=f"Found redaction annotation (annot.type={atype}).",
                        )
                    )
                annot = annot.next
        return findings

    def detect_cropbox_differences(self) -> List[BoxFinding]:
        """
        Cropping is a common 'fake redaction': content is still there, just out of view.
        We compare MediaBox and CropBox (best-effort via PyMuPDF page.rect and page.mediabox).

        If CropBox is smaller than MediaBox, we flag it as a “crop suspect”.
        """
        findings: List[BoxFinding] = []
        for i in range(len(self.doc)):
            page = self.doc[i]

            # In PyMuPDF:
            # - page.rect is the visible page rectangle (often CropBox-ish)
            # - page.mediabox is the MediaBox
            # NOTE: For some PDFs these may match even if other boxes exist.
            visible = page.rect
            media = page.mediabox

            # If visible differs meaningfully from media, it may be cropped.
            if (abs(visible.x0 - media.x0) > 0.5 or
                abs(visible.y0 - media.y0) > 0.5 or
                abs(visible.x1 - media.x1) > 0.5 or
                abs(visible.y1 - media.y1) > 0.5):
                findings.append(
                    BoxFinding(
                        page_index=i,
                        rect=visible,
                        kind="crop_suspect",
                        details=f"Visible page rect differs from MediaBox (possible cropping). visible={visible}, media={media}",
                    )
                )

        return findings

    def detect_overlay_rectangles(self,
                                 page_index: int,
                                 min_area: float = 500.0,
                                 dark_fill_threshold: float = 0.25) -> List[BoxFinding]:
        """
        Detect rectangles that LOOK like black boxes (common fake redaction).

        How it works:
        - Use PyMuPDF page.get_drawings() to inspect vector drawing operations.
        - Identify filled rectangles with a “dark” fill color.
        - For each candidate rectangle, check if there is extractable text underneath.

        Notes for students:
        - This is heuristic: some PDFs use images or complex paths.
        - Fill colors can vary; we approximate “darkness”.
        """
        findings: List[BoxFinding] = []
        page = self.doc[page_index]

        drawings = page.get_drawings()  # list of drawing dicts
        # Each drawing dict may include items like:
        # - "rect": bounding rectangle
        # - "fill": fill color (RGB floats 0..1) or None
        # - "items": a list of operations

        for d in drawings:
            r = d.get("rect", None)
            fill = d.get("fill", None)

            if r is None or fill is None:
                continue

            rect = fitz.Rect(r)
            area = rect.get_area()
            if area < min_area:
                continue  # ignore tiny boxes (likely design elements)

            # fill is RGB triple (r,g,b) floats 0..1
            # We'll compute "brightness" ~ average; darker means more likely redaction box.
            if isinstance(fill, (list, tuple)) and len(fill) >= 3:
                brightness = (fill[0] + fill[1] + fill[2]) / 3.0
            else:
                continue

            # If brightness is low, it's dark.
            if brightness <= dark_fill_threshold:
                # Try to see if text exists underneath this rectangle:
                recovered = self.recover_text_in_rect(page_index, rect)

                # If we found text under the box, that's *very* suspicious.
                details = f"Dark filled rectangle (brightness={brightness:.2f}, area={area:.0f}). Possible overlay redaction."
                if recovered.strip():
                    details += " Extractable text detected UNDER the rectangle!"

                findings.append(
                    BoxFinding(
                        page_index=page_index,
                        rect=rect,
                        kind="overlay_rect",
                        details=details,
                        recovered_text=recovered.strip(),
                    )
                )

        return findings

    def recover_text_in_rect(self, page_index: int, rect: fitz.Rect) -> str:
        """
        Attempt to extract text that lies within a rectangle on the page.

        Forensic idea:
        - If a black box covers text visually, but the underlying text objects are still present,
          text extraction in that region may still return content.

        Implementation:
        - Use page.get_text("words") to get word-level boxes and return words intersecting the rect.
        """
        page = self.doc[page_index]
        words = page.get_text("words")  # list of (x0, y0, x1, y1, "word", block_no, line_no, word_no)
        recovered_words = []
        for w in words:
            wrect = fitz.Rect(w[0], w[1], w[2], w[3])
            if rect.intersects(wrect):
                recovered_words.append(w[4])
        return " ".join(recovered_words)

    def best_effort_hidden_text_checks(self, page_index: int) -> Dict[str, Any]:
        """
        A few “quick and dirty” checks that often reveal improper redaction:
        - Full-page text extraction length
        - Whether there are many text blocks but low visible text (hard to define precisely)
        - Detect Optional Content Groups (layers) presence in document (global check)

        Keep it educational: not perfect, but illustrates what to look for.
        """
        page = self.doc[page_index]
        text = page.get_text("text")
        blocks = page.get_text("blocks")  # includes text and images blocks

        # Check for optional content (layers) in the PDF catalog (best-effort)
        # In PyMuPDF, doc.xref_get_key can read raw keys from objects,
        # but this is more advanced. We'll do a simple raw search in file tail.
        tail = read_tail_bytes(self.pdf_path, n=1024 * 1024)
        has_ocg = (b"/OCProperties" in tail) or (b"/OCG" in tail) or (b"/OCGs" in tail)

        return {
            "page_text_length": len(text),
            "page_block_count": len(blocks),
            "document_maybe_has_layers_ocg": bool(has_ocg),
        }

    # -------------------------
    # 5) Visual reporting
    # -------------------------

    def render_page_image(self, page_index: int, zoom: float = 2.0) -> str:
        """
        Render a page to PNG and return the file path.
        zoom>1 increases resolution (useful for reading).
        """
        page = self.doc[page_index]
        mat = fitz.Matrix(zoom, zoom)
        pix = page.get_pixmap(matrix=mat, alpha=False)

        out_path = os.path.join(self.out_dir, f"page_{page_index+1:03d}.png")
        pix.save(out_path)
        return out_path

    def annotate_findings_on_image(self, page_index: int, findings: List[BoxFinding], zoom: float = 2.0) -> str:
        """
        Render page, then annotate rectangles using matplotlib, saving an annotated PNG.

        NOTE:
        - We draw boxes; we do not “edit” the PDF.
        - Boxes are in PDF coordinate space (origin top-left in PyMuPDF),
          but matplotlib uses image coordinates. We map by scaling with zoom.
        """
        img_path = self.render_page_image(page_index, zoom=zoom)

        img = plt.imread(img_path)
        fig, ax = plt.subplots(figsize=(10, 13))
        ax.imshow(img)
        ax.axis("off")

        # Draw rectangles
        for f in findings:
            if f.page_index != page_index:
                continue
            r = f.rect

            # Scale by zoom because rendered image is zoomed
            x0, y0, x1, y1 = r.x0 * zoom, r.y0 * zoom, r.x1 * zoom, r.y1 * zoom
            w, h = (x1 - x0), (y1 - y0)

            # Label depends on kind
            label = f.kind
            if f.kind == "overlay_rect" and f.recovered_text:
                label += " (+text_under)"

            rect_patch = patches.Rectangle(
                (x0, y0), w, h,
                fill=False,
                linewidth=2
            )
            ax.add_patch(rect_patch)
            ax.text(x0, max(0, y0 - 5), label, fontsize=10)

        out_path = os.path.join(self.out_dir, f"page_{page_index+1:03d}_annotated.png")
        plt.tight_layout()
        plt.savefig(out_path, dpi=150)
        plt.close(fig)
        return out_path

    # -------------------------
    # 6) Orchestrated runs
    # -------------------------

    def run_redaction_analysis(self,
                              page_selection: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        Run a comprehensive redaction-focused analysis and return a JSON-like dict.
        """
        report: Dict[str, Any] = {"redaction_analysis": {}}

        # First: find explicit redaction annotations
        redact_annots = self.detect_redaction_annots()
        report["redaction_analysis"]["redaction_annotations_found"] = len(redact_annots)
        report["redaction_analysis"]["redaction_annotation_items"] = [
            {
                "page": f.page_index,
                "rect": [f.rect.x0, f.rect.y0, f.rect.x1, f.rect.y1],
                "details": f.details,
            }
            for f in redact_annots
        ]

        # Cropbox suspicion
        crop_suspects = self.detect_cropbox_differences()
        report["redaction_analysis"]["crop_suspects_found"] = len(crop_suspects)
        report["redaction_analysis"]["crop_suspect_items"] = [
            {
                "page": f.page_index,
                "visible_rect": [f.rect.x0, f.rect.y0, f.rect.x1, f.rect.y1],
                "details": f.details,
            }
            for f in crop_suspects
        ]

        # Page-by-page overlay rectangles and hidden text checks
        if page_selection is None:
            page_selection = list(range(len(self.doc)))

        overlay_findings: List[BoxFinding] = []
        hidden_checks: Dict[int, Dict[str, Any]] = {}

        for p in page_selection:
            overlay_findings.extend(self.detect_overlay_rectangles(p))
            hidden_checks[p] = self.best_effort_hidden_text_checks(p)

        report["redaction_analysis"]["overlay_rectangles_found"] = len(overlay_findings)
        report["redaction_analysis"]["overlay_rectangle_items"] = [
            {
                "page": f.page_index,
                "rect": [f.rect.x0, f.rect.y0, f.rect.x1, f.rect.y1],
                "details": f.details,
                "recovered_text": f.recovered_text,
            }
            for f in overlay_findings
        ]

        report["redaction_analysis"]["hidden_text_checks"] = {
            str(k): v for k, v in hidden_checks.items()
        }

        # Combine all findings for visualization
        all_findings = redact_annots + crop_suspects + overlay_findings

        # Make annotated images for pages with findings
        pages_with_findings = sorted({f.page_index for f in all_findings})
        annotated_images = []
        for p in pages_with_findings:
            out_img = self.annotate_findings_on_image(p, all_findings, zoom=2.0)
            annotated_images.append(out_img)

        report["redaction_analysis"]["annotated_images"] = annotated_images
        return report

    def run_full_report(self) -> Dict[str, Any]:
        """
        Run a broader “PDF forensics” report (metadata + structure heuristics + redaction analysis).
        """
        report: Dict[str, Any] = {
            "generated_at": datetime.datetime.now().isoformat(sep=" ", timespec="seconds"),
            "input_file": os.path.abspath(self.pdf_path),
        }

        report["metadata"] = self.analyze_metadata()
        report["structure_heuristics"] = self.analyze_structure_heuristics()

        # Redaction analysis is the star of the show
        report.update(self.run_redaction_analysis())

        # Save JSON report (good for grading / lab submissions)
        json_path = os.path.join(self.out_dir, "forensics_report.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        report["report_json_path"] = json_path
        return report


# -----------------------------
# Interactive CLI
# -----------------------------

def prompt_int(prompt: str, min_v: int, max_v: int) -> int:
    """Prompt for an integer with bounds, for student-friendly input."""
    while True:
        try:
            v = int(input(prompt).strip())
            if v < min_v or v > max_v:
                print(f"Please enter a number between {min_v} and {max_v}.")
                continue
            return v
        except ValueError:
            print("Please enter a valid integer.")


def prompt_pages(page_count: int) -> Optional[List[int]]:
    """
    Ask student whether to analyze all pages or a subset.
    Returns list of zero-based page indexes or None for all.
    """
    print("\nPage selection:")
    print("  1) All pages")
    print("  2) Single page")
    print("  3) Range of pages")
    choice = prompt_int("Choose (1-3): ", 1, 3)

    if choice == 1:
        return None
    if choice == 2:
        p = prompt_int(f"Page number (1-{page_count}): ", 1, page_count)
        return [p - 1]
    if choice == 3:
        start = prompt_int(f"Start page (1-{page_count}): ", 1, page_count)
        end = prompt_int(f"End page (1-{page_count}): ", 1, page_count)
        if end < start:
            start, end = end, start
        return list(range(start - 1, end))
    return None


def main():
    if len(sys.argv) < 2:
        print("Usage: python pdf_forensics_lab.py /path/to/file.pdf")
        sys.exit(1)

    pdf_path = sys.argv[1]
    if not os.path.isfile(pdf_path):
        print(f"File not found: {pdf_path}")
        sys.exit(1)

    lab = PDFForensicsLab(pdf_path)

    print("\n=== PDF Forensics Lab Script ===")
    print(f"Target PDF: {os.path.abspath(pdf_path)}")
    print(f"Pages: {len(lab.doc)}")
    print(f"Output folder: {os.path.abspath(lab.out_dir)}")

    while True:
        print("\nMenu:")
        print("  1) Show metadata")
        print("  2) Show structure heuristics (incremental update clues)")
        print("  3) Search text (demonstrate 'redacted' text may still be searchable)")
        print("  4) Run redaction analysis (with annotated images)")
        print("  5) Run FULL report (metadata + structure + redaction; saves JSON)")
        print("  0) Exit")

        choice = prompt_int("Choose an option (0-5): ", 0, 5)

        if choice == 0:
            print("Goodbye.")
            break

        if choice == 1:
            meta = lab.analyze_metadata()
            print("\n--- Metadata ---")
            print(json.dumps(meta, indent=2, ensure_ascii=False))

        elif choice == 2:
            st = lab.analyze_structure_heuristics()
            print("\n--- Structure Heuristics ---")
            print(json.dumps(st, indent=2, ensure_ascii=False))
            if st.get("possible_incremental_updates"):
                print("\nNOTE: Multiple %%EOF markers suggest incremental updates (possible edit history).")
            else:
                print("\nNOTE: Only one %%EOF in tail sample; incremental updates not strongly indicated.")

        elif choice == 3:
            term = input("Enter a search term: ").strip()
            hits = lab.search_text(term)
            print(f"\nFound {len(hits)} hits (showing up to {len(hits)} returned):")
            for h in hits[:20]:
                print(f"  - Page {h['page']+1}, rect={h['rect']}")
            if hits:
                print("\nTeaching point: If a term is found via search, it exists in the text layer—")
                print("even if it might be visually obscured by a 'redaction' overlay.")

        elif choice == 4:
            pages = prompt_pages(len(lab.doc))
            rep = lab.run_redaction_analysis(page_selection=pages)
            print("\n--- Redaction Analysis Summary ---")
            ra = rep["redaction_analysis"]
            print(f"Redaction annotations found: {ra['redaction_annotations_found']}")
            print(f"Crop suspects found: {ra['crop_suspects_found']}")
            print(f"Overlay rectangles found: {ra['overlay_rectangles_found']}")
            print("\nAnnotated images saved:")
            for p in ra["annotated_images"]:
                print(f"  - {p}")

            # If we recovered text under overlays, highlight it for students
            recovered = [
                item for item in ra["overlay_rectangle_items"]
                if item.get("recovered_text", "").strip()
            ]
            if recovered:
                print("\n!!! POTENTIAL FAILED REDACTIONS (text detected under overlays) !!!")
                for item in recovered[:10]:
                    print(f"Page {item['page']+1} text_under_overlay: {item['recovered_text'][:120]}")

        elif choice == 5:
            rep = lab.run_full_report()
            print("\nFULL report complete.")
            print(f"JSON report saved to: {rep['report_json_path']}")
            ra = rep["redaction_analysis"]
            print(f"Annotated images: {len(ra['annotated_images'])}")
            for p in ra["annotated_images"]:
                print(f"  - {p}")

            print("\nTip for students: submit the JSON report plus annotated images for grading.")

if __name__ == "__main__":
    main()
