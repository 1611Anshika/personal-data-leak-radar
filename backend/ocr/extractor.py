import pytesseract
import cv2
import numpy as np
from PIL import Image
from io import BytesIO

pytesseract.pytesseract.tesseract_cmd = (
    r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)


def extract_text_from_image(file_bytes: bytes) -> str:
    image = Image.open(BytesIO(file_bytes)).convert("RGB")

    image_array = np.array(image)

    gray = cv2.cvtColor(
        image_array,
        cv2.COLOR_RGB2GRAY
    )

    # Enlarge image for better OCR
    enlarged = cv2.resize(
        gray,
        None,
        fx=2,
        fy=2,
        interpolation=cv2.INTER_CUBIC
    )

    # Improve text/background separation
    thresholded = cv2.threshold(
        enlarged,
        0,
        255,
        cv2.THRESH_BINARY + cv2.THRESH_OTSU
    )[1]

    text = pytesseract.image_to_string(
        thresholded,
        config="--psm 6"
    )

    return text


def extract_words_with_coordinates(file_bytes: bytes):
    image = Image.open(
        BytesIO(file_bytes)
    ).convert("RGB")

    image_array = np.array(image)

    gray = cv2.cvtColor(
        image_array,
        cv2.COLOR_RGB2GRAY
    )

    original_height, original_width = gray.shape

    scale = 2

    enlarged = cv2.resize(
        gray,
        None,
        fx=scale,
        fy=scale,
        interpolation=cv2.INTER_CUBIC
    )

    thresholded = cv2.threshold(
        enlarged,
        0,
        255,
        cv2.THRESH_BINARY + cv2.THRESH_OTSU
    )[1]

    data = pytesseract.image_to_data(
        thresholded,
        output_type=pytesseract.Output.DICT,
        config="--psm 6"
    )

    words = []

    for i in range(len(data["text"])):

        text = data["text"][i].strip()

        if not text:
            continue

        x = int(data["left"][i] / scale)
        y = int(data["top"][i] / scale)
        width = int(data["width"][i] / scale)
        height = int(data["height"][i] / scale)

        words.append({
            "text": text,
            "x": x,
            "y": y,
            "width": width,
            "height": height,
            "confidence": data["conf"][i]
        })

    return words