from PIL import Image
from io import BytesIO
import exifread


# Metadata that may expose privacy-sensitive information
SENSITIVE_METADATA = {
    "author",
    "artist",
    "copyright",
    "software",
    "make",
    "model",
    "datetime",
    "datetimeoriginal",
    "datetimedigitized",
    "gpslatitude",
    "gpslongitude",
    "gpslatitude ref",
    "gpslongitude ref",
    "location",
}


def is_sensitive_metadata(metadata_name):
    name = metadata_name.lower()

    return (
        name in SENSITIVE_METADATA
        or "gps" in name
        or "author" in name
        or "artist" in name
        or "location" in name
        or "device" in name
        or "camera" in name
    )


def scan_image_metadata(file_bytes: bytes):
    findings = []

    try:
        image = Image.open(BytesIO(file_bytes))

        # ---------- Image metadata ----------
        if image.info:

            for key, value in image.info.items():

                if isinstance(value, bytes):
                    continue

                if is_sensitive_metadata(key):

                    findings.append({
                        "type": "Sensitive Image Metadata",
                        "metadata": key,
                        "value": str(value),
                        "severity": "Medium"
                    })

        # ---------- EXIF ----------
        exif_data = image.getexif()

        if exif_data:

            for tag_id, value in exif_data.items():

                tag_name = Image.ExifTags.TAGS.get(
                    tag_id,
                    str(tag_id)
                )

                if is_sensitive_metadata(tag_name):

                    findings.append({
                        "type": "Sensitive EXIF Metadata",
                        "metadata": tag_name,
                        "value": str(value),
                        "severity": "Medium"
                    })

    except Exception as error:
        print("Pillow metadata scan error:", error)

    # ---------- Detailed EXIF ----------
    try:

        image_stream = BytesIO(file_bytes)

        tags = exifread.process_file(
            image_stream,
            details=False
        )

        for tag, value in tags.items():

            if is_sensitive_metadata(tag):

                findings.append({
                    "type": "Sensitive EXIF Metadata",
                    "metadata": tag,
                    "value": str(value),
                    "severity": "Medium"
                })

    except Exception as error:
        print("EXIF scan error:", error)

    return findings