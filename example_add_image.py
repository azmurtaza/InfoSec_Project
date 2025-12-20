"""
Example: Adding a Custom Logo Image to Peacemaker AI GUI

This file shows the exact code changes needed to add a logo image.
Copy the relevant parts to your gui.py file.
"""

import customtkinter as ctk
from PIL import Image
import os

# ============================================================
# STEP 1: Add this import at the top of gui.py (if not already there)
# ============================================================
# from PIL import Image


# ============================================================
# STEP 2: Modify the setup_sidebar() method around line 93-103
# ============================================================

def setup_sidebar_with_logo(self):
    """Example of sidebar setup with custom logo image"""
    
    # ... existing sidebar setup code ...
    
    # Brand Header with Image
    brand_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
    brand_frame.grid(row=0, column=0, padx=20, pady=(30, 10), sticky="ew")
    
    # ===== ADD LOGO IMAGE HERE =====
    try:
        # Build path to logo image (place your logo.png in assets folder)
        logo_path = os.path.join(
            os.path.dirname(__file__),  # src directory
            "..",                        # go up one level
            "assets",                    # assets folder
            "logo.png"                   # your image file
        )
        
        # Load the image
        logo_img = Image.open(logo_path)
        
        # Create CTkImage with desired size
        self.logo_image = ctk.CTkImage(
            light_image=logo_img,
            dark_image=logo_img,
            size=(100, 100)  # Width x Height in pixels - ADJUST THIS
        )
        
        # Display the image
        logo_display = ctk.CTkLabel(
            brand_frame,
            image=self.logo_image,
            text=""  # Empty text = image only
        )
        logo_display.pack(pady=(0, 10))
        
    except Exception as e:
        # If image fails to load, just print error and continue
        print(f"[!] Could not load logo image: {e}")
        print(f"[*] Make sure logo.png exists in: {os.path.join(os.path.dirname(__file__), '..', 'assets')}")
    
    # ===== EXISTING TEXT LABEL (keep this) =====
    self.logo_label = ctk.CTkLabel(
        brand_frame, 
        text="Peacemaker AI", 
        font=ctk.CTkFont(size=22, weight="bold", family="Roboto"),
        text_color=COLORS["accent"]
    )
    self.logo_label.pack()
    
    self.version_label = ctk.CTkLabel(
        brand_frame, 
        text="v1.0 Pro", 
        font=ctk.CTkFont(size=11),
        text_color=COLORS["text_secondary"]
    )
    self.version_label.pack()


# ============================================================
# ALTERNATIVE: Image with Text Overlay
# ============================================================

def logo_with_text_overlay_example(self):
    """Show image with text on top of it"""
    
    brand_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
    brand_frame.grid(row=0, column=0, padx=20, pady=(30, 10), sticky="ew")
    
    try:
        logo_path = os.path.join(os.path.dirname(__file__), "..", "assets", "logo.png")
        logo_img = Image.open(logo_path)
        
        self.logo_image = ctk.CTkImage(
            light_image=logo_img,
            dark_image=logo_img,
            size=(150, 150)
        )
        
        # Image with text parameter (text appears on image)
        logo_display = ctk.CTkLabel(
            brand_frame,
            image=self.logo_image,
            text="Peacemaker AI",  # Text overlays the image
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="white",
            compound="center"  # center, top, bottom, left, right
        )
        logo_display.pack(pady=10)
        
    except Exception as e:
        print(f"[!] Could not load logo: {e}")


# ============================================================
# EXAMPLE: Add Icon to Dashboard
# ============================================================

def add_dashboard_icon_example(self):
    """Add a shield icon to the dashboard"""
    
    # In setup_dashboard(), after the title label
    try:
        icon_path = os.path.join(os.path.dirname(__file__), "..", "assets", "shield.png")
        icon_img = Image.open(icon_path)
        
        self.shield_icon = ctk.CTkImage(
            light_image=icon_img,
            dark_image=icon_img,
            size=(60, 60)
        )
        
        icon_label = ctk.CTkLabel(
            dashboard_frame,
            image=self.shield_icon,
            text=""
        )
        icon_label.pack(pady=10)
        
    except:
        pass  # Silently skip if icon not found


# ============================================================
# QUICK REFERENCE
# ============================================================
"""
Image Sizes:
- Sidebar Logo: 80-120 pixels
- Dashboard Icons: 40-80 pixels  
- Background Images: 300-600 pixels

Image Formats:
- PNG (recommended for logos with transparency)
- JPG (for photos/backgrounds)
- WEBP (modern format, smaller file size)

Compound Options (text + image):
- "center" - text centered on image
- "top" - image above text
- "bottom" - image below text
- "left" - image to left of text
- "right" - image to right of text

File Structure:
InfoSec_Project/
├── assets/
│   ├── logo.png
│   ├── shield.png
│   └── background.jpg
└── src/
    └── gui.py
"""
