import cv2
import numpy as np


def detect_qr_codes(file_bytes: bytes):
    """
    Detect and decode QR codes from an image.

    Returns:
        A list containing QR data and the QR bounding box.
    """

    image_array = np.frombuffer(
        file_bytes,
        np.uint8
    )

    image = cv2.imdecode(
        image_array,
        cv2.IMREAD_COLOR
    )

    if image is None:
        return []

    detector = cv2.QRCodeDetector()

    results = []

    data, points, _ = detector.detectAndDecode(image)

    if data and points is not None:

        points = points[0].astype(int)

        x_coordinates = points[:, 0]
        y_coordinates = points[:, 1]

        x1 = int(np.min(x_coordinates))
        y1 = int(np.min(y_coordinates))
        x2 = int(np.max(x_coordinates))
        y2 = int(np.max(y_coordinates))

        results.append({
            "type": "QR Code",
            "data": data,
            "x": x1,
            "y": y1,
            "width": x2 - x1,
            "height": y2 - y1
        })

    return results