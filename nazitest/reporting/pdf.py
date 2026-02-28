"""PDF report generation via WeasyPrint."""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def html_to_pdf(html_path: Path, pdf_path: Path | None = None) -> Path:
    """Convert an HTML report to PDF using WeasyPrint."""
    from weasyprint import HTML

    if pdf_path is None:
        pdf_path = html_path.with_suffix(".pdf")

    HTML(filename=str(html_path)).write_pdf(str(pdf_path))
    logger.info("PDF report generated: %s", pdf_path)
    return pdf_path
