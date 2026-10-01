from PIL import Image
from io import BytesIO


def sanitize_image_metadata(file_bytes: bytes):
    """
    Create a clean copy of an image without
    embedded EXIF and other image metadata.
    """

    image = Image.open(
        BytesIO(file_bytes)
    ).convert("RGB")

    output = BytesIO()

    # Re-save the image without copying
    # the original metadata.
    image.save(
        output,
        format="PNG"
    )

    output.seek(0)

    return output.getvalue()