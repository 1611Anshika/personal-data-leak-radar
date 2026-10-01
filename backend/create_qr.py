import qrcode

data = "https://example.com/pdlr-demo"

img = qrcode.make(data)

img.save("test_qr.png")

print("QR code created successfully!")