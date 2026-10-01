import fitz

from detection.detector import detect_sensitive_data


def protect_pdf(file_bytes: bytes, findings: list):
    """
    Protect sensitive values detected by the
    main PDLR detection engine.

    The PDF is never modified in-place.
    A new protected PDF is returned.
    """

    pdf = fitz.open(
        stream=file_bytes,
        filetype="pdf"
    )

    total_redactions = 0

    # Go through every page
    for page in pdf:

        # Get the text currently present on this page
        page_text = page.get_text()

        if not page_text:
            continue

        # Protect every value detected by
        # the unified PDLR detection engine.
        for finding in findings:

            sensitive_value = finding.get("value")

            if not sensitive_value:
                continue

            # Find the detected value on this page
            areas = page.search_for(
                str(sensitive_value)
            )

            for rect in areas:

                page.add_redact_annot(
                    rect,
                    fill=(0, 0, 0)
                )

                total_redactions += 1

        # Permanently apply the redactions
        page.apply_redactions()

    # Create a new protected PDF
    output = bytearray()

    protected_pdf = pdf.tobytes(
        garbage=4,
        deflate=True
    )

    pdf.close()

    return protected_pdf, total_redactions