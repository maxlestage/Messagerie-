"""Régénère toutes les icônes PNG des apps et du site à partir de branding/logo.png.

    python3 branding/make_icons.py      (depuis n'importe où, Pillow requis)

Le logo source est carré, sur le fond vert clair de la marque (BG). Quand une
icône demande de la marge (icône adaptative Android, icônes iMessage en 4:3),
le logo est réduit et centré sur ce même fond.
"""
import os
from PIL import Image, ImageDraw, ImageFilter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BG = (231, 251, 218)  # #E7FBDA, le fond du logo — aussi brocolis_icon_bg sur Android

logo = Image.open(os.path.join(ROOT, "branding", "logo.png")).convert("RGB")


def render(w, h, fill=1.0):
    """Logo centré sur BG, son côté valant `fill` du plus petit côté de l'icône.

    Quand il reste de la marge, les bords du logo (fond seul, l'anneau commence
    à ~5 % du bord) sont fondus dans BG pour qu'aucune couture ne se voie.
    """
    side = round(fill * min(w, h))
    img = logo.resize((side, side), Image.LANCZOS)
    if side == w and side == h:
        return img
    out = Image.new("RGB", (w, h), BG)
    feather = max(1, round(side * 0.03))
    mask = Image.new("L", (side, side), 0)
    ImageDraw.Draw(mask).rectangle((feather, feather, side - 1 - feather, side - 1 - feather), fill=255)
    mask = mask.filter(ImageFilter.GaussianBlur(feather / 2))
    out.paste(img, ((w - side) // 2, (h - side) // 2), mask)
    return out


IOS = "Brocolis/Assets.xcassets"
IMSG = "BrocolisiMessage/Assets.xcassets/iMessage App Icon.stickersiconset"
TARGETS = [
    (f"{IOS}/AppIcon.appiconset/AppIcon-1024.png", 1024, 1024, 1.0),
    (f"{IOS}/BrocolisLogo.imageset/BrocolisLogo-1024.png", 1024, 1024, 1.0),
    ("BrocolisWatch/Assets.xcassets/AppIcon.appiconset/AppIcon-1024.png", 1024, 1024, 1.0),
    ("android/app/src/main/res/drawable/brocolis_logo.png", 1024, 1024, 1.0),
    # Icône adaptative : le lanceur peut masquer jusqu'au cercle de 72/108.
    ("android/app/src/main/res/drawable/brocolis_logo_foreground.png", 1024, 1024, 0.64),
    ("site/assets/photo.png", 640, 640, 1.0),
] + [
    (f"{IMSG}/icon-{name}.png", w, h, 1.0)
    for w, h, name in [
        (1024, 768, "1024x768"), (54, 40, "27x20@2x"), (81, 60, "27x20@3x"),
        (58, 58, "29x29@2x"), (87, 87, "29x29@3x"), (64, 48, "32x24@2x"),
        (96, 72, "32x24@3x"), (120, 90, "60x45@2x"), (180, 135, "60x45@3x"),
        (58, 58, "ipad-29x29@2x"), (134, 100, "ipad-67x50@2x"), (148, 110, "ipad-74x55@2x"),
    ]
]

for rel, w, h, fill in TARGETS:
    render(w, h, fill).save(os.path.join(ROOT, rel), optimize=True)
    print(f"{rel} {w}x{h}")
