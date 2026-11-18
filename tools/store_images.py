"""Images for the extension's store listings (docs/STORES.md), from the brand in tools/make_icon.py.

    python tools/store_images.py                      dist/store/logo-300x300.png          Edge Add-ons' extension logo
                                                      dist/store/promo-small-440x280.png   Chrome Web Store, Edge Add-ons
                                                      dist/store/promo-marquee-1400x560.png
    python tools/store_images.py --screenshots [DIR]  also dist/store/screenshot-<n>-<what>.png, 1280x800, from the
                                                      screenshots a run of tests/test_browser.py saved (DIR; without it,
                                                      the newest complete run in the temporary folder)
    python tools/store_images.py --out DIR            somewhere else than dist/store/

The promotional images carry no text (the stores show them in every language): the shield on Grafito. A store
screenshot must be exactly 1280x800: the test's are the size of the window or the popup, so each is cut around what it
shows and doubled, or set on a plain background. Pure Python (zlib only), like make_icon.py.
"""

import argparse
import struct
import sys
import tempfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import make_icon  # noqa: E402

LIGHT = (236, 236, 236)   # behind a light popup
BORDER_LIGHT, BORDER_DARK = (208, 208, 208), (64, 64, 64)
# The screenshots of tests/test_browser.py worth showing, in the order of the listing: (the end of its file name,
# the name here, how to fit it). "popup": centred on a plain background and doubled. "page": 640x400 of the page
# from that corner, doubled. "window": the app's window as it is, centred on Grafito.
SCREENSHOTS = (
    ("05-popup-logins-light", "popup", "popup", None),
    ("08-menu-light", "menu", "page", (0, 0)),
    ("10-menu-2fa", "2fa", "page", (0, 0)),
    ("15-save-bar-light", "save", "page", (-640, 0)),
    ("04-app-settings-browser", "app", "window", None),
)


# ---------------------------------------------------------------------------------------------- PNG in and out
# An image here is (width, height, rows): one bytearray of RGB bytes per row.

def write_png(path, image):
    width, height, rows = image

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    raw = b"".join(b"\0" + bytes(row) for row in rows)
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    Path(path).write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def read_png(path):
    """An 8-bit RGB or RGBA PNG without interlacing (what the browser's screenshots are), as RGB rows."""
    data = Path(path).read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError(f"{path} is not a PNG")
    position, packed, header = 8, b"", None
    while position < len(data):
        length, kind = struct.unpack(">I4s", data[position:position + 8])
        body = data[position + 8:position + 8 + length]
        if kind == b"IHDR":
            header = struct.unpack(">IIBBBBB", body)
        elif kind == b"IDAT":
            packed += body
        position += 12 + length
    width, height, depth, colour, _, _, interlace = header
    if depth != 8 or colour not in (2, 6) or interlace:
        raise ValueError(f"{path}: only 8-bit RGB or RGBA PNGs without interlacing can be read")
    size = 4 if colour == 6 else 3
    raw, stride = zlib.decompress(packed), width * size
    rows, previous = [], bytearray(stride)
    for y in range(height):
        start = y * (stride + 1)
        kind, line = raw[start], bytearray(raw[start + 1:start + 1 + stride])
        if kind == 1:
            for i in range(size, stride):
                line[i] = (line[i] + line[i - size]) & 255
        elif kind == 2:
            for i in range(stride):
                line[i] = (line[i] + previous[i]) & 255
        elif kind == 3:
            for i in range(stride):
                line[i] = (line[i] + (((line[i - size] if i >= size else 0) + previous[i]) >> 1)) & 255
        elif kind == 4:
            for i in range(stride):
                a = line[i - size] if i >= size else 0
                b = previous[i]
                c = previous[i - size] if i >= size else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[i] = (line[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        previous = line
        if size == 4:
            rgb = bytearray(width * 3)
            rgb[0::3], rgb[1::3], rgb[2::3] = line[0::4], line[1::4], line[2::4]
            rows.append(rgb)
        else:
            rows.append(line)
    return width, height, rows


# ---------------------------------------------------------------------------------------------- drawing

def grafito(width, height):
    """The icon's tile as a background: Grafito, barely lighter at the top left."""
    rows = []
    for y in range(height):
        row = bytearray(width * 3)
        for x in range(width):
            t = (x / width + y / height) / 2
            row[x * 3:x * 3 + 3] = bytes(round(make_icon.TOP[i] + (make_icon.BOTTOM[i] - make_icon.TOP[i]) * t) for i in range(3))
        rows.append(row)
    return width, height, rows


def plain(width, height, colour):
    return width, height, [bytearray(bytes(colour) * width) for _ in range(height)]


def shield(image, side, samples=4):
    """Draw the icon's shield, white with its keyhole open, in a square of `side` pixels at the centre."""
    width, height, rows = image
    left, top = (width - side) // 2, (height - side) // 2
    for py in range(top, top + side):
        row = rows[py]
        for px in range(left, left + side):
            covered = 0
            for sy in range(samples):
                for sx in range(samples):
                    x = (px - left + (sx + 0.5) / samples) / side
                    y = (py - top + (sy + 0.5) / samples) / side
                    covered += make_icon.inside_polygon(x, y, make_icon.SHIELD) and not make_icon.inside_keyhole(x, y)
            if covered:
                share = covered / (samples * samples)
                for i in range(3):
                    row[px * 3 + i] = round(row[px * 3 + i] + (255 - row[px * 3 + i]) * share)
    return image


def promo(width, height):
    """A promotional image: the shield on Grafito, no text."""
    return shield(grafito(width, height), round(height * 0.92))


def crop(image, x, y, width, height):
    """`width` x `height` of an image from (x, y); a negative x or y counts from the right or the bottom."""
    full_width, full_height, rows = image
    x = full_width + x if x < 0 else x
    y = full_height + y if y < 0 else y
    if x < 0 or y < 0 or x + width > full_width or y + height > full_height:
        raise ValueError(f"a {width}x{height} piece does not fit in a {full_width}x{full_height} screenshot")
    return width, height, [bytearray(row[x * 3:(x + width) * 3]) for row in rows[y:y + height]]


def doubled(image):
    width, height, rows = image
    out = []
    for row in rows:
        wide = bytearray(width * 6)
        for offset in (0, 3):
            wide[offset::6], wide[offset + 1::6], wide[offset + 2::6] = row[0::3], row[1::3], row[2::3]
        out += [wide, bytearray(wide)]
    return width * 2, height * 2, out


def framed(image, background, border, shadow=0.30, spread=18):
    """`image` centred on `background` (changed in place), with a line around it and a soft shadow under it."""
    width, height, rows = image
    full_width, full_height, canvas = background
    if width > full_width or height > full_height:
        raise ValueError(f"a {width}x{height} screenshot does not fit in {full_width}x{full_height}")
    left, top = (full_width - width) // 2, (full_height - height) // 2
    drop = spread // 3  # the shadow falls a little below
    for y in range(max(0, top - spread), min(full_height, top + height + spread + drop)):
        row = canvas[y]
        dy = max(top + drop - y, 0, y - (top + height - 1 + drop))
        for x in range(max(0, left - spread), min(full_width, left + width + spread)):
            dx = max(left - x, 0, x - (left + width - 1))
            distance = (dx * dx + dy * dy) ** 0.5
            if distance < spread:
                dark = shadow * (1 - distance / spread) ** 2
                for i in range(3):
                    row[x * 3 + i] = round(row[x * 3 + i] * (1 - dark))
    line = bytes(border)
    for y in range(top - 1, top + height + 1):
        row = canvas[y]
        if y in (top - 1, top + height):
            row[(left - 1) * 3:(left + width + 1) * 3] = line * (width + 2)
        else:
            row[(left - 1) * 3:left * 3] = line
            row[left * 3:(left + width) * 3] = rows[y - top]
            row[(left + width) * 3:(left + width + 1) * 3] = line
    return background


def store_screenshot(image, how, corner):
    """A test screenshot as the stores want it: 1280x800."""
    if how == "popup":
        return doubled(framed(image, plain(640, 400, LIGHT), BORDER_LIGHT))
    if how == "page":
        return doubled(crop(image, corner[0], corner[1], 640, 400))
    return framed(image, grafito(1280, 800), BORDER_DARK, shadow=0.45, spread=30)


# ---------------------------------------------------------------------------------------------- the files

def find_run(folder=None):
    """{ending: path} of the screenshots to use, from `folder` or the newest run of tests/test_browser.py that has
    them all (it saves them in <temporary folder>/secretbroker-browser-*/screenshots)."""
    folders = [Path(folder)] if folder else sorted(Path(tempfile.gettempdir()).glob("secretbroker-browser-*/screenshots"),
                                                   key=lambda p: p.stat().st_mtime, reverse=True)
    for candidate in folders:
        found = {}
        for ending, *_ in SCREENSHOTS:
            matches = sorted(candidate.glob(f"*-{ending}.png"))
            if matches:
                found[ending] = matches[0]
        if len(found) == len(SCREENSHOTS):
            return found
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Images for the extension's store listings.")
    parser.add_argument("--out", default=str(ROOT / "dist" / "store"), help="folder to write into (default: dist/store/)")
    parser.add_argument("--screenshots", nargs="?", const="", metavar="DIR",
                        help="also fit the screenshots of tests/test_browser.py (its screenshots folder; default: the newest run)")
    args = parser.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    written = []

    logo = out / "logo-300x300.png"
    logo.write_bytes(make_icon.render(300))
    written.append(logo)
    for name, (width, height) in (("promo-small-440x280", (440, 280)), ("promo-marquee-1400x560", (1400, 560))):
        write_png(out / f"{name}.png", promo(width, height))
        written.append(out / f"{name}.png")

    if args.screenshots is not None:
        run = find_run(args.screenshots or None)
        if not run:
            print("No screenshots found: run tests/test_browser.py first (it prints where it saved them) and pass that folder.")
            return 1
        print(f"Screenshots from {next(iter(run.values())).parent}")
        for number, (ending, name, how, corner) in enumerate(SCREENSHOTS, 1):
            target = out / f"screenshot-{number}-{name}.png"
            write_png(target, store_screenshot(read_png(run[ending]), how, corner))
            written.append(target)
    for path in written:
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
