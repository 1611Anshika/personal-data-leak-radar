from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from detection.detector import detect_sensitive_data
from ocr.extractor import extract_text_from_image

from detection.detector import detect_sensitive_data
from pdf.extractor import extract_text_from_pdf
from qr.detector import detect_qr_codes
from metadata.scanner import scan_image_metadata
from risk.risk_engine import calculate_risk
import os
import uuid

from fastapi.staticfiles import StaticFiles

from ocr.extractor import extract_words_with_coordinates
from protection.image_protector import protect_sensitive_regions
from verification.verifier import verify_protected_image
from ai.bedrock_analyzer import analyze_findings
from protection.pdf_protector import protect_pdf
from verification.pdf_verifier import verify_protected_pdf
from history.history_manager import (
    load_history,
    create_scan_record
)
from fastapi import Form


app = FastAPI(title="PDLR - Personal Data Leak Radar")
PROTECTED_DIR = "protected_outputs"

os.makedirs(PROTECTED_DIR, exist_ok=True)

app.mount(
    "/protected",
    StaticFiles(directory=PROTECTED_DIR),
    name="protected"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "message": "PDLR backend is running",
        "status": "success"
    }


@app.get("/health")
def health():
    return {
        "service": "PDLR",
        "status": "healthy"
    }


@app.post("/api/upload")
async def upload_file(
    file: UploadFile = File(...),
    sharing_context: str = Form("")
):

    content = await file.read()

        # If the uploaded file is a PDF
    if file.content_type == "application/pdf":

        extracted_text = extract_text_from_pdf(content)

        findings = detect_sensitive_data(extracted_text)

        return {
            "filename": file.filename,
            "content_type": file.content_type,
            "extracted_text": extracted_text,
            "findings": findings,
            "total_findings": len(findings),
            "processing_method": "PDF Text Extraction + PII Detection"
        }

    # If the uploaded file is an image, use OCR
    if file.content_type and file.content_type.startswith("image/"):

        # 1. OCR
        extracted_text = extract_text_from_image(content)

        # 2. Detect sensitive text
        findings = detect_sensitive_data(extracted_text)

        # 3. Detect QR codes
        qr_results = detect_qr_codes(content)

        for qr in qr_results:
            findings.append({
                "type": "QR Code",
                "value": qr["data"],
                "severity": "High"
            })

        # 4. Scan hidden metadata
        metadata_results = scan_image_metadata(content)

        for metadata in metadata_results:
            findings.append({
                "type": metadata["type"],
                "value": metadata["value"],
                "metadata": metadata["metadata"],
                "severity": metadata["severity"]
            })
        risk = calculate_risk(findings,
    sharing_context)
        create_scan_record(
            filename=file.filename,
            findings=findings,
            risk=risk
        )

        ai_analysis = analyze_findings(
            findings,
            file.filename,
            sharing_context
        )

        return {
            "filename": file.filename,
            "content_type": file.content_type,
            "extracted_text": extracted_text,
            "findings": findings,
            "total_findings": len(findings),
            "qr_codes": qr_results,
            "metadata": metadata_results,
            "risk": risk,
            "ai_analysis": ai_analysis,
            "processing_method": "OCR + PII + QR + Metadata Detection + AI Analysis"
        }
    # For text files, use the existing text detection
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        text = ""

    findings = detect_sensitive_data(text)

    return {
        "filename": file.filename,
        "content_type": file.content_type,
        "extracted_text": text,
        "findings": findings,
        "total_findings": len(findings),
        "processing_method": "Text + PII Detection"
    }
@app.post("/api/protect")
async def protect_file(
    file: UploadFile = File(...),
    mode: str = Form("redact")
):
    print("PDLR protection mode:", mode)
    content = await file.read()

    # Currently protection is supported for images
    if not file.content_type or not file.content_type.startswith("image/"):
        return {
            "status": "error",
            "message": "Image protection is currently supported."
        }

    # --------------------------------
    # 1. OCR WITH COORDINATES
    # --------------------------------

    words = extract_words_with_coordinates(content)

    # --------------------------------
    # 2. DETECT SENSITIVE INFORMATION
    # --------------------------------

    extracted_text = " ".join(
        word["text"]
        for word in words
    )

    findings = detect_sensitive_data(extracted_text)

    sensitive_values = [
        finding["value"]
        for finding in findings
    ]
    qr_results = detect_qr_codes(
    content
)

    # --------------------------------
    # 3. CREATE PROTECTED COPY
    # --------------------------------

    protected_bytes = protect_sensitive_regions(
    content,
    words,
    sensitive_values,
    qr_results=qr_results,
    mode=mode
)
    # --------------------------------
    # 4. SAVE PROTECTED COPY
    # --------------------------------

    protected_filename = (
        f"protected_{uuid.uuid4().hex}.png"
    )

    protected_path = os.path.join(
        PROTECTED_DIR,
        protected_filename
    )

    with open(protected_path, "wb") as output_file:
        output_file.write(protected_bytes)

    # --------------------------------
    # 5. SECOND SCAN
    # --------------------------------

    verification = verify_protected_image(
        protected_bytes
    )
    protection_summary = {
    "method": mode,
    "regions_protected": len(sensitive_values),
    "verified": verification["verified"]
}
    create_scan_record(
        filename=file.filename,
        findings=findings,
        risk=calculate_risk(findings),
        verification=verification
    )

    # --------------------------------
    # 6. RETURN RESULT
    # --------------------------------

    return {
        "filename": file.filename,

        "protected_file": protected_filename,

        "protected_url": (
            f"/protected/{protected_filename}"
        ),

        "original_modified": False,

        "initial_findings": findings,

        "initial_total": len(findings),
        "protection_summary": protection_summary,
        "protection_mode": mode,
       

        "verification": verification,
         "verification_evidence": {
                    "initial_findings": len(findings),
                    "protected_regions": len(sensitive_values),
                    "remaining_findings": verification["total_remaining"],
                    "verification_status": verification["status"]
                }
    }
@app.post("/api/clipboard/image/protect")
async def protect_clipboard_image(
    file: UploadFile = File(...),
    mode: str = Form("redact")
):
    content = await file.read()

    if not file.content_type or not file.content_type.startswith("image/"):
        return {
            "status": "error",
            "message": "Clipboard image required."
        }

    # 1. OCR
    words = extract_words_with_coordinates(content)

    extracted_text = " ".join(
        word["text"]
        for word in words
    )

    # 2. Detect sensitive information
    findings = detect_sensitive_data(extracted_text)

    # 3. Detect QR codes
    qr_results = detect_qr_codes(content)

    for qr in qr_results:
        findings.append({
            "type": "QR Code",
            "value": qr["data"],
            "severity": "High"
        })

    # 4. Detect metadata
    metadata_results = scan_image_metadata(content)

    for metadata in metadata_results:
        findings.append({
            "type": metadata["type"],
            "value": metadata["value"],
            "metadata": metadata["metadata"],
            "severity": metadata["severity"]
        })

    # 5. If nothing sensitive was found
    if not findings:
        return {
            "status": "safe",
            "protected": False,
            "verified": True,
            "message": "No sensitive information detected."
        }

    # 6. Extract sensitive values
    sensitive_values = [
        finding["value"]
        for finding in findings
        if finding.get("value")
    ]

    # 7. Protect image
    protected_bytes = protect_sensitive_regions(
    content,
    words,
    sensitive_values,
    qr_results=qr_results,
    mode=mode
)

    # 8. Save protected copy
    protected_filename = (
        f"clipboard_protected_{uuid.uuid4().hex}.png"
    )

    protected_path = os.path.join(
        PROTECTED_DIR,
        protected_filename
    )

    with open(protected_path, "wb") as output_file:
        output_file.write(protected_bytes)

    # 9. SECOND SCAN
    verification = verify_protected_image(
        protected_bytes
    )

    return {
        "status": "success",
        "protected": True,
        "protected_file": protected_filename,
        "protected_url": (
            f"/protected/{protected_filename}"
        ),
        "initial_findings": findings,
        "initial_total": len(findings),
       
        "verification": verification,
         "verification_evidence": {
                    "initial_findings": len(findings),
                    "protected_regions": len(sensitive_values),
                    "remaining_findings": verification["total_remaining"],
                    "verification_status": verification["status"]
                }
    }
@app.post("/api/clipboard/scan")
async def scan_clipboard(data: dict):
    text = data.get("text", "")

    if not text:
        return {
            "status": "error",
            "message": "No clipboard text received."
        }

    findings = detect_sensitive_data(text)
    risk = calculate_risk(findings)

    ai_analysis = analyze_findings(
        findings,
        "Clipboard Content"
    )

    return {
        "status": "success",
        "source": "desktop_clipboard",
        "findings": findings,
        "total_findings": len(findings),
        "risk": risk,
        "ai_analysis": ai_analysis
    }
@app.post("/api/protect/pdf")
async def protect_pdf_file(
    file: UploadFile = File(...),
    sharing_context: str = Form("")
):
    content = await file.read()

    if file.content_type != "application/pdf":
        return {
            "status": "error",
            "message": "PDF file required."
        }

    # --------------------------------
    # 1. EXTRACT TEXT FROM ORIGINAL PDF
    # --------------------------------

    extracted_text = extract_text_from_pdf(content)

    # --------------------------------
    # 2. DETECT SENSITIVE INFORMATION
    # --------------------------------

    findings = detect_sensitive_data(extracted_text)

    # --------------------------------
    # 3. CALCULATE ORIGINAL RISK
    # --------------------------------

    risk = calculate_risk(
        findings,
        sharing_context
    )

    # --------------------------------
    # 4. AI ANALYSIS
    # --------------------------------

    ai_analysis = analyze_findings(
        findings,
        file.filename,
        sharing_context
    )

    # --------------------------------
    # 5. PROTECT THE PDF
    # --------------------------------

    protected_bytes, redaction_count = protect_pdf(
        content,
        findings
    )

    # --------------------------------
    # 6. CREATE SEPARATE PROTECTED COPY
    # --------------------------------

    protected_filename = (
        f"protected_{uuid.uuid4().hex}.pdf"
    )

    protected_path = os.path.join(
        PROTECTED_DIR,
        protected_filename
    )

    with open(
        protected_path,
        "wb"
    ) as output_file:
        output_file.write(protected_bytes)

    # --------------------------------
    # 7. VERIFY PROTECTED PDF
    # --------------------------------

    verification = verify_protected_pdf(
        protected_bytes
    )

    # --------------------------------
    # 8. SAVE TO SCAN HISTORY
    # --------------------------------

    create_scan_record(
        filename=file.filename,
        findings=findings,
        risk=risk,
        verification=verification
    )

    # --------------------------------
    # 9. RETURN COMPLETE RESULT
    # --------------------------------

    return {
        "status": "success",
        "filename": file.filename,

        "protected_file": protected_filename,

        "protected_url":
            f"/protected/{protected_filename}",

        "original_modified": False,

        "extracted_text": extracted_text,

        "initial_findings": findings,

        "initial_total": len(findings),

        "risk": risk,

        "ai_analysis": ai_analysis,

        "redactions": redaction_count,

        "verification": verification,

        "processing_method":
            "PDF Text Extraction + PII Detection + AI Analysis + Protection + Verification"
    }
@app.get("/api/history")
async def get_scan_history():

    history = load_history()

    return {
        "status": "success",
        "total": len(history),
        "history": history
    }
@app.get("/api/dashboard/stats")
async def get_dashboard_stats():

    history = load_history()

    total_scans = len(history)

    total_findings = sum(
        item.get("findings", 0)
        for item in history
    )

    protected_files = sum(
        1
        for item in history
        if item.get("protected")
    )

    verified_files = sum(
        1
        for item in history
        if item.get("verified")
    )

    return {
        "status": "success",

        "total_scans":
            total_scans,

        "total_findings":
            total_findings,

        "protected_files":
            protected_files,

        "verified_files":
            verified_files
    }
from mangum import Mangum

handler = Mangum(app)