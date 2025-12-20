# Adding Custom Images to Peacemaker AI GUI

## Quick Start Guide

### 1. Prepare Your Image
- Create an `assets` folder in your project root: `InfoSec_Project/assets/`
- Save your logo/image there (e.g., `logo.png`, `background.jpg`)
- Recommended formats: PNG (with transparency), JPG, or WEBP
- Recommended logo size: 200x200 pixels or similar square dimensions

### 2. Add Image to Sidebar Logo

Edit `src/gui.py`:

**Add import at the top (around line 1-10):**
```python
from PIL import Image
```

**Replace the logo section (around line 93-103):**
```python
# Brand Header with Image
brand_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
brand_frame.grid(row=0, column=0, padx=20, pady=(30, 10), sticky="ew")

# Load logo image
try:
    logo_path = os.path.join(os.path.dirname(__file__), "..", "assets", "logo.png")
    logo_img = Image.open(logo_path)
    self.logo_image = ctk.CTkImage(
        light_image=logo_img,
        dark_image=logo_img,
        size=(100, 100)  # Adjust size as needed
    )
    
    logo_display = ctk.CTkLabel(
        brand_frame,
        image=self.logo_image,
        text=""
    )
    logo_display.pack(pady=(0, 10))
except Exception as e:
    print(f"[!] Could not load logo image: {e}")

# Text below image
self.logo_label = ctk.CTkLabel(
    brand_frame, 
    text="Peacemaker AI", 
    font=ctk.CTkFont(size=22, weight="bold", family="Roboto"),
    text_color=COLORS["accent"]
)
self.logo_label.pack()
```

### 3. Common Image Locations

**Sidebar Logo:** Lines 93-103 in `setup_sidebar()`
**Dashboard:** Lines 200+ in `setup_dashboard()`
**Scan Page:** Lines 270+ in `setup_scan()`

### 4. Image Properties

**Size:** `size=(width, height)` in pixels
**Position:** Use `.pack()`, `.grid()`, or `.place()`
**Transparency:** PNG files support transparency

### 5. Example: Add Image to Dashboard

```python
# In setup_dashboard(), after the title:
try:
    shield_img = Image.open("assets/shield_icon.png")
    self.shield_image = ctk.CTkImage(
        light_image=shield_img,
        dark_image=shield_img,
        size=(80, 80)
    )
    
    icon_label = ctk.CTkLabel(
        dashboard_header,
        image=self.shield_image,
        text=""
    )
    icon_label.pack(side="left", padx=10)
except:
    pass  # Silently fail if image not found
```

### 6. Tips

- **Keep images small** (< 500KB) for fast loading
- **Use PNG** for logos with transparency
- **Test both light/dark modes** if your app supports theme switching
- **Handle errors gracefully** with try/except blocks
- **Use relative paths** with `os.path.join()` for portability

### 7. Troubleshooting

**Image not showing?**
- Check file path is correct
- Verify image file exists
- Check console for error messages
- Ensure PIL/Pillow is installed: `pip install Pillow`

**Image too large/small?**
- Adjust the `size=(width, height)` parameter
- Maintain aspect ratio for best results

**Image looks blurry?**
- Use higher resolution source image
- Avoid upscaling (size larger than original)
