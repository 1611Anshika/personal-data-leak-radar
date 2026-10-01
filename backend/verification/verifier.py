from detection.detector import detect_sensitive_data
from ocr.extractor import extract_text_from_image
from qr.detector import detect_qr_codes
from metadata.scanner import scan_image_metadata


def verify_protected_image(file_bytes: bytes):
    """
    Re-scan a protected image and determine whether
    sensitive information is still present.
    """

    # -------------------------
    # 1. OCR SECOND SCAN
    # -------------------------
    extracted_text = extract_text_from_image(file_bytes)

    remaining_findings = detect_sensitive_data(
        extracted_text
    )

    # -------------------------
    # 2. QR SECOND SCAN
    # -------------------------
    qr_results = detect_qr_codes(file_bytes)

    for qr in qr_results:
        remaining_findings.append({
            "type": "QR Code",
            "value": qr["data"],
            "severity": "High"
        })

    # -------------------------
    # 3. METADATA SECOND SCAN
    # -------------------------
    metadata_results = scan_image_metadata(file_bytes)

    for metadata in metadata_results:
        remaining_findings.append({
            "type": metadata["type"],
            "value": metadata["value"],
            "metadata": metadata["metadata"],
            "severity": metadata["severity"]
        })

    # -------------------------
    # 4. VERIFICATION RESULT
    # -------------------------
    verified = len(remaining_findings) == 0

    if verified:
        status = "PROTECTION VERIFIED"
    else:
        status = "PROTECTION FAILED"

    return {
        "verified": verified,
        "status": status,
        "remaining_findings": remaining_findings,
        "total_remaining": len(remaining_findings)
    }