"""Builds win4tress's icons from the emblem, assets/logo/emblem.svg.

The SVG must stay flat polygons: a square viewBox, and <path>s with a hex fill
and path data of absolute M, L and Z only. Each size is drawn from it at 8x and
averaged down, so edges are anti-aliased without blur. Below 32 px the emblem
fills the square; from there it keeps a margin of a 32nd of the size.

Writes:
- ui/src-tauri/icons/icon.ico (16-256 px; the exe's icon, the window's, the tray's)
- ui/src-tauri/icons/{32x32,128x128,128x128@2x,icon}.png
- ui/src/lib/logo/emblem.svg (the in-app logo, a copy)

    python tools/dev/make-logo.py
"""
import re
import shutil
import struct
import xml.etree.ElementTree as ET
from io import BytesIO
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "assets" / "logo" / "emblem.svg"
ICONS = ROOT / "ui" / "src-tauri" / "icons"
IN_APP = ROOT / "ui" / "src" / "lib" / "logo"

ICO_SIZES = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256]
SUPERSAMPLE = 8

Shape = tuple[str, list[list[tuple[float, float]]]]


def shapes(svg: Path) -> tuple[list[Shape], tuple[float, float, float]]:
    """Each path's fill and polygons, and the viewBox's left, top and side."""
    root = ET.parse(svg).getroot()
    left, top, w, h = (float(v) for v in root.get("viewBox", "").split())
    if w != h:
        raise SystemExit(f"{svg}: the viewBox isn't square")
    out = []
    for path in root.iter("{http://www.w3.org/2000/svg}path"):
        polygons, points = [], []
        tokens = re.findall(r"[A-Za-z]|-?(?:\d+\.?\d*|\.\d+)", path.get("d", ""))
        nums = []
        for t in tokens:
            if t in "ML":
                continue
            if t == "Z":
                points += list(zip(nums[::2], nums[1::2]))
                polygons.append(points)
                points, nums = [], []
            elif t[0].isalpha():
                raise SystemExit(f"{svg}: path command {t} (only M, L and Z)")
            else:
                nums.append(float(t))
        out.append((path.get("fill", "#000"), polygons))
    return out, (left, top, w)


def draw(emblem: list[Shape], box: tuple[float, float, float], size: int) -> Image.Image:
    """The emblem on a transparent `size` px square."""
    left, top, side = box
    margin = size // 32
    inner = size - 2 * margin
    big = inner * SUPERSAMPLE
    scale = big / side
    im = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    pen = ImageDraw.Draw(im)
    for fill, polygons in emblem:
        for points in polygons:
            pen.polygon([((x - left) * scale, (y - top) * scale) for x, y in points], fill=fill)
    # Averaged with premultiplied alpha, so edges don't darken.
    small = im.convert("RGBa").resize((inner, inner), Image.BOX).convert("RGBA")
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    canvas.paste(small, (margin, margin))
    return canvas


def ico(images: list[Image.Image]) -> bytes:
    """An .ico of PNG-compressed entries, smallest first."""
    pngs = []
    for im in images:
        buf = BytesIO()
        im.save(buf, "PNG", optimize=True)
        pngs.append(buf.getvalue())
    out = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    for im, data in zip(images, pngs):
        side = im.width if im.width < 256 else 0
        out += struct.pack("<BBBBHHII", side, side, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    return out + b"".join(pngs)


def main():
    emblem, box = shapes(SOURCE)

    (ICONS / "icon.ico").write_bytes(ico([draw(emblem, box, s) for s in ICO_SIZES]))
    for name, size in [("32x32", 32), ("128x128", 128), ("128x128@2x", 256), ("icon", 512)]:
        draw(emblem, box, size).save(ICONS / f"{name}.png", optimize=True)

    IN_APP.mkdir(exist_ok=True)
    for old in IN_APP.glob("logo-*.png"):
        old.unlink()
    shutil.copyfile(SOURCE, IN_APP / "emblem.svg")
    print(f"icon.ico ({', '.join(map(str, ICO_SIZES))}), 4 PNGs, the in-app emblem.svg")


if __name__ == "__main__":
    main()
