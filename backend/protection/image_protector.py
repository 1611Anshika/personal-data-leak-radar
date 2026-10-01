from PIL import Image, ImageDraw, ImageFilter
from io import BytesIO
import re
from protection.metadata_sanitizer import sanitize_image_metadata


# ============================================================
# TEXT NORMALIZATION
# ============================================================

def normalize_text(text):
    """
    Normalize text so OCR variations such as
    spaces, hyphens and punctuation do not prevent matching.
    """
    return re.sub(
        r"[^a-zA-Z0-9]",
        "",
        str(text)
    ).lower()


# ============================================================
# BOX UTILITIES
# ============================================================

def get_word_box(word):
    return (
        word["x"],
        word["y"],
        word["x"] + word["width"],
        word["y"] + word["height"]
    )


def boxes_overlap_or_close(box1, box2, gap=15):
    """
    Check whether two OCR boxes are close enough
    to potentially belong to the same sensitive value.
    """

    x1, y1, x2, y2 = box1
    a1, b1, a2, b2 = box2

    horizontal_gap = max(
        a1 - x2,
        x1 - a2,
        0
    )

    vertical_gap = max(
        b1 - y2,
        y1 - b2,
        0
    )

    return (
        horizontal_gap <= gap
        and
        vertical_gap <= gap
    )


# ============================================================
# FIND SENSITIVE OCR REGIONS
# ============================================================

def find_sensitive_regions(
    words,
    sensitive_values
):
    """
    Find bounding boxes corresponding to sensitive values.

    Handles:
    - exact OCR words
    - OCR split across multiple words
    - spaces
    - hyphens
    - punctuation variations
    """

    regions = []

    normalized_values = []

    for value in sensitive_values:

        normalized = normalize_text(value)

        if normalized:
            normalized_values.append(
                normalized
            )

    if not normalized_values:
        return regions

    # --------------------------------------------------------
    # Build OCR word data
    # --------------------------------------------------------

    word_data = []

    for index, word in enumerate(words):

        text = str(
            word.get("text", "")
        ).strip()

        if not text:
            continue

        normalized = normalize_text(
            text
        )

        if not normalized:
            continue

        word_data.append({
            "index": index,
            "text": text,
            "normalized": normalized,
            "box": get_word_box(word)
        })

    # --------------------------------------------------------
    # Exact single-word matches
    # --------------------------------------------------------

    for item in word_data:

        if item["normalized"] in normalized_values:

            regions.append(
                item["box"]
            )

    # --------------------------------------------------------
    # Multi-word / split OCR matching
    # --------------------------------------------------------

    for target in normalized_values:

        for start in range(
            len(word_data)
        ):

            combined = ""

            selected_boxes = []

            for end in range(
                start,
                min(
                    start + 8,
                    len(word_data)
                )
            ):

                item = word_data[end]

                # Only combine nearby OCR words.
                if selected_boxes:

                    previous_box = selected_boxes[-1]

                    if not boxes_overlap_or_close(
                        previous_box,
                        item["box"],
                        gap=25
                    ):
                        break

                combined += item["normalized"]

                selected_boxes.append(
                    item["box"]
                )

                if combined == target:

                    x1 = min(
                        box[0]
                        for box in selected_boxes
                    )

                    y1 = min(
                        box[1]
                        for box in selected_boxes
                    )

                    x2 = max(
                        box[2]
                        for box in selected_boxes
                    )

                    y2 = max(
                        box[3]
                        for box in selected_boxes
                    )

                    regions.append(
                        (x1, y1, x2, y2)
                    )

                    break

                # Stop if the combined OCR text
                # is already longer than target.
                if len(combined) > len(target):

                    break

    return regions


# ============================================================
# MERGE OVERLAPPING REGIONS
# ============================================================

def merge_regions(
    regions,
    padding=6
):

    expanded = []

    for x1, y1, x2, y2 in regions:

        expanded.append((
            x1 - padding,
            y1 - padding,
            x2 + padding,
            y2 + padding
        ))

    merged = []

    for region in expanded:

        x1, y1, x2, y2 = region

        merged_this = False

        for i, existing in enumerate(
            merged
        ):

            ex1, ey1, ex2, ey2 = existing

            overlap = not (
                x2 < ex1
                or
                x1 > ex2
                or
                y2 < ey1
                or
                y1 > ey2
            )

            if overlap:

                merged[i] = (
                    min(x1, ex1),
                    min(y1, ey1),
                    max(x2, ex2),
                    max(y2, ey2)
                )

                merged_this = True
                break

        if not merged_this:

            merged.append(region)

    return merged

def get_qr_regions(qr_results, padding=20):
    """
    Convert QR detector results into image regions.
    """

    regions = []

    for qr in qr_results:
        if (
            "x" not in qr
            or "y" not in qr
            or "width" not in qr
            or "height" not in qr
        ):
            continue

        x1 = qr["x"] - padding
        y1 = qr["y"] - padding

        x2 = (
            qr["x"]
            + qr["width"]
            + padding
        )

        y2 = (
            qr["y"]
            + qr["height"]
            + padding
        )

        regions.append(
            (x1, y1, x2, y2)
        )

    return regions
# ============================================================
# PROTECTION MODES
# ============================================================

def apply_protection(image, regions, mode="redact"):
    """
    Apply protection to sensitive regions.

    Modes:
        redact -> completely hide the region
        mask   -> partially hide the region
        blur   -> blur the region
    """

    protected = image.copy()
    draw = ImageDraw.Draw(protected)

    for region in regions:

        x1, y1, x2, y2 = map(
            int,
            region
        )

        if mode == "blur":

            crop = protected.crop(
                (x1, y1, x2, y2)
            )

            blurred = crop.filter(
                ImageFilter.GaussianBlur(
                    radius=25
                )
            )

            protected.paste(
                blurred,
                (x1, y1)
            )

        elif mode == "mask":

            # Hide most of the sensitive region
            # while leaving a small portion visible.
            width = x2 - x1

            mask_end = x1 + int(
                width * 0.65
            )

            draw.rectangle(
                (x1, y1, mask_end, y2),
                fill="black"
            )

        else:

            # Complete redaction
            draw.rectangle(
                (x1, y1, x2, y2),
                fill="black"
            )

    return protected


# ============================================================
# MAIN PROTECTION FUNCTION
# ============================================================
def remove_image_metadata(image):
    """
    Create a clean image containing only pixel data.
    This removes EXIF, GPS, author, camera and other
    embedded metadata from the protected output.
    """
    clean_image = Image.new(
        "RGB",
        image.size
    )

    clean_image.putdata(
        list(image.getdata())
    )

    return clean_image
def protect_sensitive_regions(
    file_bytes: bytes,
    words: list,
    sensitive_values: list,
    qr_results=None,
    mode="redact"
):
    image = Image.open(
        BytesIO(file_bytes)
    ).convert("RGB")

    # -----------------------------
    # OCR-sensitive regions
    # -----------------------------

    regions = find_sensitive_regions(
        words,
        sensitive_values
    )

    # -----------------------------
    # QR-sensitive regions
    # -----------------------------

    if qr_results:
        qr_regions = get_qr_regions(
            qr_results
        )

        regions.extend(qr_regions)

    # -----------------------------
    # Merge overlapping regions
    # -----------------------------

    regions = merge_regions(
        regions
    )

    # -----------------------------
    # Apply protection
    # -----------------------------

    protected = apply_protection(
    image,
    regions,
    mode
)

# Remove hidden metadata before creating
# the protected output.
    protected = remove_image_metadata(
        protected
    )

    output = BytesIO()

    protected.save(
        output,
        format="PNG"
    )

    output.seek(0)

    protected_bytes = output.getvalue()

    # Remove embedded metadata from the
    # protected copy.
    protected_bytes = sanitize_image_metadata(
        protected_bytes
    )

    return protected_bytes