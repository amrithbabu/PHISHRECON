from PIL import Image, PngImagePlugin

# Create image
img = Image.new("RGB", (500, 300), "white")

# Add hidden metadata
metadata = PngImagePlugin.PngInfo()
metadata.add_text(
    "HiddenMessage",
    "This is hidden test content for PhishRecon"
)

# Save image
img.save("hidden_test.png", pnginfo=metadata)

print("Created: hidden_test.png")
