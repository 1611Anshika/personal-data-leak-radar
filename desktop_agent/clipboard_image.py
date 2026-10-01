import win32clipboard
from PIL import Image
from io import BytesIO


def get_clipboard_image():
    try:
        win32clipboard.OpenClipboard()

        if not win32clipboard.IsClipboardFormatAvailable(
            win32clipboard.CF_DIB
        ):
            win32clipboard.CloseClipboard()
            return None

        data = win32clipboard.GetClipboardData(
            win32clipboard.CF_DIB
        )

        win32clipboard.CloseClipboard()

        image = Image.open(
            BytesIO(data)
        )

        return image.copy()

    except Exception as error:

        try:
            win32clipboard.CloseClipboard()
        except:
            pass

        print(
            "Image clipboard read error:",
            error
        )

        return None


def set_clipboard_image(image):
    """
    Put a Pillow image into the Windows clipboard.
    Windows expects DIB data rather than PNG.
    """

    output = BytesIO()

    # Windows clipboard expects RGB data
    image = image.convert("RGB")

    # Save as BMP
    image.save(
        output,
        format="BMP"
    )

    # Remove the 14-byte BMP file header.
    # CF_DIB expects only the DIB data.
    bmp_data = output.getvalue()[14:]

    try:

        win32clipboard.OpenClipboard()

        win32clipboard.EmptyClipboard()

        win32clipboard.SetClipboardData(
            win32clipboard.CF_DIB,
            bmp_data
        )

        return True

    except Exception as error:

        print(
            "Image clipboard write error:",
            error
        )

        return False

    finally:

        try:
            win32clipboard.CloseClipboard()
        except:
            pass