import fitz

from detection.detector import detect_sensitive_data


def verify_protected_pdf(file_bytes: bytes):

    pdf = fitz.open(
        stream=file_bytes,
        filetype="pdf"
    )

    extracted_text = ""

    for page in pdf:
        extracted_text += page.get_text()

    pdf.close()

    remaining_findings = detect_sensitive_data(
        extracted_text
    )

    verified = len(remaining_findings) == 0

    return {
        "verified": verified,

        "status":
            "PROTECTION VERIFIED"
            if verified
            else "PROTECTION FAILED",

        "remaining_findings":
            remaining_findings,

        "total_remaining":
            len(remaining_findings)
    }