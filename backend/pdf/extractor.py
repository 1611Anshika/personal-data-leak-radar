import fitz


def extract_text_from_pdf(file_bytes: bytes) -> str:
    """
    Extract text from all pages of a PDF.
    """

    pdf = fitz.open(stream=file_bytes, filetype="pdf")

    extracted_text = ""

    for page in pdf:
        extracted_text += page.get_text()

    pdf.close()

    return extracted_text