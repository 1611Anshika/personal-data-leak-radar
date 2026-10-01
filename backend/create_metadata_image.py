from PIL import Image
from PIL.PngImagePlugin import PngInfo


# Create a simple image
image = Image.new("RGB", (600, 300), "white")

# Add synthetic metadata
metadata = PngInfo()

metadata.add_text("Author", "Rahul Sharma")
metadata.add_text("Device", "Demo Smartphone")
metadata.add_text("Location", "Mumbai, Maharashtra")
metadata.add_text("Comment", "PDLR Metadata Test")

# Save image
image.save(
    "test_metadata_image.png",
    pnginfo=metadata
)

print("Metadata test image created successfully!")