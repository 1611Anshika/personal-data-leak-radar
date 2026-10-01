import time
import hashlib
import pyperclip
import requests

from io import BytesIO
from PIL import Image

from clipboard_image import (
    get_clipboard_image,
    set_clipboard_image
)


# ==========================================
# CONFIGURATION
# ==========================================

BACKEND_TEXT_URL = (
    "http://127.0.0.1:8000/api/clipboard/scan"
)

BACKEND_IMAGE_URL = (
    "http://127.0.0.1:8000/api/clipboard/image/protect"
)

BACKEND_BASE_URL = (
    "http://127.0.0.1:8000"
)


# ==========================================
# STARTUP
# ==========================================

print("====================================")
print(" PDLR Desktop Privacy Agent")
print("====================================")
print("Clipboard protection started...")
print("Backend:", BACKEND_TEXT_URL)
print("Press CTRL+C to stop.\n")


# Last processed text clipboard
last_clipboard = ""


# Prevent repeatedly processing the image
# that PDLR itself puts back into clipboard.
last_protected_image_hash = None


# ==========================================
# TEXT PROTECTION
# ==========================================

def mask_sensitive_text(text, findings):
    """
    Replace detected sensitive values with
    safe redaction labels.
    """

    protected_text = text

    for finding in findings:

        value = finding.get("value", "")
        data_type = finding.get("type", "")

        if not value:
            continue

        if data_type == "Email Address":

            replacement = "[REDACTED EMAIL]"

        elif data_type == "Phone Number":

            replacement = "[REDACTED PHONE]"

        elif data_type == "PAN Card":

            replacement = "[REDACTED PAN]"

        elif data_type == "Aadhaar Number":

            replacement = "[REDACTED AADHAAR]"

        elif data_type == "Credit/Debit Card":

            replacement = "[REDACTED CARD]"

        elif data_type == "AWS Access Key":

            replacement = "[REDACTED AWS KEY]"

        else:

            replacement = "[REDACTED]"

        protected_text = protected_text.replace(
            value,
            replacement
        )

    return protected_text


# ==========================================
# TEXT CLIPBOARD SCAN
# ==========================================

def scan_clipboard(text):

    try:

        response = requests.post(
            BACKEND_TEXT_URL,
            json={
                "text": text
            },
            timeout=30
        )

        if response.status_code != 200:

            print(
                "Backend returned:",
                response.status_code
            )

            return

        result = response.json()

        findings = result.get(
            "findings",
            []
        )

        risk = result.get(
            "risk",
            {}
        )

        print("\n===== PDLR SCAN RESULT =====")

        print(
            "Sensitive findings:",
            result.get(
                "total_findings",
                0
            )
        )

        print(
            "Risk:",
            risk.get(
                "level",
                "UNKNOWN"
            ),
            f"({risk.get('score', 0)}/100)"
        )

        # ----------------------------------
        # No sensitive information
        # ----------------------------------

        if not findings:

            print(
                "\n✓ No sensitive information detected."
            )

            print(
                "============================\n"
            )

            return

        # ----------------------------------
        # Display detected types
        # ----------------------------------

        print("\nDetected:")

        for finding in findings:

            print(
                f"- {finding.get('type')} "
                f"[{finding.get('severity')}]"
            )

        print(
            "\n⚠️ Sensitive information detected."
        )

        print(
            "🛡️ Activating Privacy Shield..."
        )

        # ----------------------------------
        # Protect text
        # ----------------------------------

        protected_text = mask_sensitive_text(
            text,
            findings
        )

        # Replace clipboard
        pyperclip.copy(
            protected_text
        )

        print(
            "✓ Sensitive information masked."
        )

        print(
            "✓ Safe copy placed in clipboard."
        )

        # ----------------------------------
        # SECOND SCAN
        # ----------------------------------

        verify_response = requests.post(
            BACKEND_TEXT_URL,
            json={
                "text": protected_text
            },
            timeout=30
        )

        if verify_response.status_code != 200:

            print(
                "Verification failed:",
                verify_response.status_code
            )

            return

        verification = verify_response.json()

        remaining = verification.get(
            "total_findings",
            0
        )

        print(
            "\n===== PROTECTION VERIFICATION ====="
        )

        if remaining == 0:

            print(
                "🛡️ PROTECTION VERIFIED"
            )

            print(
                "Second scan found no unresolved "
                "sensitive information."
            )

        else:

            print(
                "⚠️ PROTECTION FAILED"
            )

            print(
                "Remaining findings:",
                remaining
            )
            print("FULL VERIFICATION RESPONSE:")
            print(result)
        remaining = result.get("verification", {}).get(
            "remaining_findings", []
        )

        for finding in remaining:
            print(
                "🔎 Remaining:",
                finding.get("type"),
                "|",
                finding.get("value", "")
            )

        print(
            "====================================\n"
        )

    except requests.exceptions.ConnectionError:

        print(
            "Could not connect to PDLR backend."
        )

    except Exception as error:

        print(
            "Text clipboard error:",
            error
        )


# ==========================================
# IMAGE → PNG BYTES
# ==========================================

def image_to_png_bytes(image):

    if image is None:

        raise ValueError(
            "Cannot convert None into PNG."
        )

    output = BytesIO()

    image.save(
        output,
        format="PNG"
    )

    output.seek(0)

    return output.read()


# ==========================================
# IMAGE CLIPBOARD PROTECTION
# ==========================================
def get_image_hash(image):
    """
    Create a SHA-256 hash of the clipboard image.
    Used to prevent PDLR from processing its own
    protected image repeatedly.
    """

    image_bytes = image_to_png_bytes(image)

    return hashlib.sha256(
        image_bytes
    ).hexdigest()

def protect_clipboard_image(image):

    try:

        # ----------------------------------
        # Validate image
        # ----------------------------------

        if image is None:

            print(
                "⚠️ Clipboard image is empty."
            )

            return False

        print(
            "🛡️ Sending image to PDLR "
            "Privacy Shield..."
        )

        # ----------------------------------
        # Convert image to PNG
        # ----------------------------------

        image_bytes = image_to_png_bytes(
            image
        )

        # ----------------------------------
        # Send image to backend
        # ----------------------------------

        files = {

            "file": (
                "clipboard.png",
                image_bytes,
                "image/png"
            )

        }

        response = requests.post(

            BACKEND_IMAGE_URL,

            files=files,

            timeout=60

        )

        # ----------------------------------
        # Backend error
        # ----------------------------------

        if response.status_code != 200:

            print(
                "Image protection failed:",
                response.status_code
            )

            print(
                response.text
            )

            return False

        result = response.json()

        # ----------------------------------
        # Nothing sensitive detected
        # ----------------------------------

        if result.get(
            "protected"
        ) is not True:

            print(
                "✓ No sensitive information detected."
            )

            return False

        # ----------------------------------
        # Verification
        # ----------------------------------

        verification = result.get(
            "verification",
            {}
        )

        if not verification.get(
            "verified"
        ):

            print(
                "\n⚠️ PROTECTION FAILED"
            )

            print(
                "Remaining findings:",
                verification.get(
                    "total_remaining",
                    0
                )
            )

            return False

        # ----------------------------------
        # Get protected image URL
        # ----------------------------------

        protected_url = (
            BACKEND_BASE_URL
            + result.get(
                "protected_url",
                ""
            )
        )

        if not protected_url:

            print(
                "Protected image URL missing."
            )

            return False

        # ----------------------------------
        # Download protected image
        # ----------------------------------

        protected_response = requests.get(

            protected_url,

            timeout=30

        )

        if protected_response.status_code != 200:

            print(
                "Could not retrieve protected image."
            )

            return False

        # ----------------------------------
        # Convert response into Pillow image
        # ----------------------------------

        protected_image = Image.open(

            BytesIO(
                protected_response.content
            )

        ).convert("RGB")
                # ----------------------------------
        # Remember this protected image
        # ----------------------------------

        global last_protected_image_hash

        last_protected_image_hash = get_image_hash(
            protected_image
        )
        # ----------------------------------
        # Put safe image into clipboard
        # ----------------------------------

        clipboard_success = set_clipboard_image(
            protected_image
        )

        if not clipboard_success:

            print(
                "⚠️ Could not place safe image "
                "into clipboard."
            )

            return False

        # ----------------------------------
        # SUCCESS
        # ----------------------------------

        print(
            "\n===================================="
        )

        print(
            " 🛡️ PROTECTION VERIFIED"
        )

        print(
            "===================================="
        )

        print(
            "Sensitive regions were protected."
        )

        print(
            "Second scan found no unresolved "
            "sensitive information."
        )

        print(
            "✓ Safe image placed into clipboard."
        )

        print(
            "====================================\n"
        )

        return True

    except requests.exceptions.ConnectionError:

        print(
            "Could not connect to PDLR "
            "image protection service."
        )

        return False

    except Exception as error:

        print(
            "Image protection error:",
            error
        )

        return False


# ==========================================
# IMAGE CLIPBOARD CHECK
# ==========================================

def check_image_clipboard():

    try:

        image = get_clipboard_image()

        if image is not None:

            return image

        return None

    except Exception as error:

        print(
            "Image clipboard check error:",
            error
        )

        return None


# ==========================================
# MAIN CLIPBOARD MONITOR
# ==========================================

while True:

    try:

        # ==================================
        # 1. CHECK IMAGE CLIPBOARD
        # ==================================

        image = check_image_clipboard()

        if image is not None:

            # --------------------------------
            # If this is the image that PDLR
            # itself just placed in clipboard,
            # don't process it again.
            # --------------------------------


            current_image_hash = get_image_hash(
                image
            )

            if (
                last_protected_image_hash
                and current_image_hash == last_protected_image_hash
            ):

                print(
                    "✓ Protected image already verified. "
                    "Skipping re-processing."
                )

                time.sleep(2)

                continue

            # --------------------------------
            # New image detected
            # --------------------------------

            print(
                "\n📸 Image detected in clipboard."
            )

            success = protect_clipboard_image(
                image
            )

            # Give Windows clipboard time
            # to settle.
            time.sleep(2)

            continue


        # ==================================
        # 2. CHECK TEXT CLIPBOARD
        # ==================================

        current_clipboard = pyperclip.paste()

        if (
            current_clipboard
            and current_clipboard != last_clipboard
        ):

            print(
                "\nNew clipboard content detected."
            )

            scan_clipboard(
                current_clipboard
            )

            # Important:
            # Store the CURRENT clipboard after
            # protection so the protected text
            # is not immediately processed again.
            last_clipboard = pyperclip.paste()


        # ==================================
        # 3. WAIT
        # ==================================

        time.sleep(1)


    except KeyboardInterrupt:

        print(
            "\nPDLR Desktop Agent stopped."
        )

        break


    except Exception as error:

        print(
            "Clipboard error:",
            error
        )

        time.sleep(1)