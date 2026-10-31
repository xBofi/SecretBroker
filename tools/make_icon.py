"""Render the SecretBroker icon (flat rounded tile + shield with keyhole) to a multi-size .ico.

Pure Python (zlib only) so it runs without extra dependencies:
    python tools/make_icon.py secretbroker/assets/icon.ico
    python tools/make_icon.py --iconset build/SecretBroker.iconset    (macOS: iconutil -c icns turns it into .icns)
    python tools/make_icon.py --menubar secretbroker/assets/menubar.png
"""

import math
import struct
import sys
import zlib

SIZES = (16, 24, 32, 48, 64, 128, 256)
TOP, BOTTOM = (38, 38, 38), (23, 23, 23)  # Grafito, with a barely visible shade
SHIELD = [(0.50, 0.17), (0.77, 0.27), (0.77, 0.49), (0.73, 0.62), (0.64, 0.73), (0.50, 0.83),
          (0.36, 0.73), (0.27, 0.62), (0.23, 0.49), (0.23, 0.27)]


def inside_polygon(x, y, points):
    inside = False
    for (x1, y1), (x2, y2) in zip(points, points[1:] + points[:1]):
        if (y1 > y) != (y2 > y) and x < x1 + (y - y1) * (x2 - x1) / (y2 - y1):
            inside = not inside
    return inside


def inside_rounded_rect(x, y, margin=0.04, radius=0.22):
    lo, hi = margin, 1 - margin
    if not (lo <= x <= hi and lo <= y <= hi):
        return False
    cx = min(max(x, lo + radius), hi - radius)
    cy = min(max(y, lo + radius), hi - radius)
    return (x - cx) ** 2 + (y - cy) ** 2 <= radius ** 2


def inside_keyhole(x, y):
    if (x - 0.5) ** 2 + (y - 0.45) ** 2 <= 0.075 ** 2:
        return True
    return 0.45 <= y <= 0.64 and abs(x - 0.5) <= 0.03 + (y - 0.45) * 0.12


# macOS icons sit on Apple's grid: the tile is 824 of 1024 px, centred, so it matches the other apps in the Dock.
MAC_INSET = (1024 - 824) / 2 / 1024


def render(size, inset=0.0, template=False):
    """The icon at `size` px. `inset`: empty border around the tile (macOS). `template`: only the shield, black on
    transparent, for the macOS menu bar (which tints it for light and dark bars)."""
    samples = 4 if size >= 48 else 6
    if size >= 512:
        samples = 2
    rows = []
    for py in range(size):
        row = bytearray([0])  # PNG filter: none
        for px in range(size):
            r = g = b = a = 0.0
            for sy in range(samples):
                for sx in range(samples):
                    x = ((px + (sx + 0.5) / samples) / size - inset) / (1 - 2 * inset)
                    y = ((py + (sy + 0.5) / samples) / size - inset) / (1 - 2 * inset)
                    if template:
                        # The shield fills the bar's height; the keyhole is cut out.
                        x, y = 0.5 + (x - 0.5) * 0.75, 0.5 + (y - 0.5) * 0.75
                        if inside_polygon(x, y, SHIELD) and not inside_keyhole(x, y):
                            r, g, b, a = r, g, b, a + 1
                        continue
                    if not (inside_rounded_rect(x, y, margin=0.0, radius=0.225) if inset else inside_rounded_rect(x, y)):
                        continue
                    if inside_polygon(x, y, SHIELD) and not inside_keyhole(x, y):
                        color = (255, 255, 255)
                    else:
                        t = min(max((x + y) / 2, 0), 1)
                        color = tuple(TOP[i] + (BOTTOM[i] - TOP[i]) * t for i in range(3))
                    r, g, b, a = r + color[0], g + color[1], b + color[2], a + 1
            n = samples * samples
            if a:
                row += bytes((round(r / a), round(g / a), round(b / a), round(255 * a / n)))
            else:
                row += bytes(4)
        rows.append(bytes(row))
    return png(size, b"".join(rows))


def png(size, raw):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def ico(images):
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, blobs = b"", b""
    for size, data in images:
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
        blobs += data
    return header + entries + blobs


def iconset(folder):
    """The sizes iconutil expects in an .iconset folder."""
    import os
    os.makedirs(folder, exist_ok=True)
    for points in (16, 32, 128, 256, 512):
        for scale in (1, 2):
            name = f"icon_{points}x{points}{'@2x' if scale == 2 else ''}.png"
            with open(os.path.join(folder, name), "wb") as fh:
                fh.write(render(points * scale, inset=MAC_INSET))
    print("written", folder)


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--iconset":
        iconset(sys.argv[2])
        sys.exit(0)
    if len(sys.argv) > 2 and sys.argv[1] == "--menubar":
        with open(sys.argv[2], "wb") as fh:
            fh.write(render(44, template=True))  # 22 pt at 2x
        print("written", sys.argv[2])
        sys.exit(0)
    target = sys.argv[1] if len(sys.argv) > 1 else "icon.ico"
    with open(target, "wb") as fh:
        fh.write(ico([(s, render(s)) for s in SIZES]))
    with open(target.rsplit(".", 1)[0] + ".png", "wb") as fh:
        fh.write(render(256))
    print("written", target)
