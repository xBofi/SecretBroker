"""Remove the parts of the PyQt6 wheels SecretBroker never loads (used by tools/build_deb.sh).

The wheels carry all of Qt (3D, multimedia, QML controls, Designer...): about 540 MB. The app needs the web
view, widgets, the tray icon and the platform plugins. Everything those load (their ELF NEEDED entries,
followed transitively) is kept; the rest of Qt6/lib, the unused PyQt6 modules and plugin folders go.

    python tools/deb_trim_qt.py <site-packages>
"""

import shutil
import subprocess
import sys
from pathlib import Path

# PyQt6 modules pywebview's Qt backend, the tray (resident.QtTray) and the clipboard import.
MODULES = ["QtCore", "QtGui", "QtWidgets", "QtNetwork", "QtWebChannel", "QtWebEngineCore", "QtWebEngineWidgets",
           "QtPrintSupport", "QtDBus", "QtSvg", "QtOpenGL", "QtOpenGLWidgets"]
PLUGINS = ["platforms", "platformthemes", "platforminputcontexts", "xcbglintegrations", "egldeviceintegrations",
           "wayland-decoration-client", "wayland-graphics-integration-client", "wayland-shell-integration",
           "imageformats", "iconengines", "tls", "networkinformation", "generic", "printsupport"]


def needed(path):
    out = subprocess.run(["readelf", "-d", str(path)], capture_output=True, text=True).stdout
    return [line.split("[", 1)[1].split("]", 1)[0] for line in out.splitlines() if "(NEEDED)" in line]


def main(site):
    pyqt = Path(site) / "PyQt6"
    qt = pyqt / "Qt6"
    libs = {p.name: p for p in (qt / "lib").iterdir() if ".so" in p.name}
    roots = [pyqt / f"{m}.abi3.so" for m in MODULES] + [pyqt / f for f in ("sip.cpython-312-x86_64-linux-gnu.so",)]
    roots += [p for p in (qt / "libexec").iterdir() if p.is_file()]
    for folder in PLUGINS:
        if (qt / "plugins" / folder).is_dir():
            roots += [p for p in (qt / "plugins" / folder).rglob("*.so")]
    keep, todo = set(), [r for r in roots if r.exists()]
    while todo:
        for name in needed(todo.pop()):
            if name in libs and name not in keep:
                keep.add(name)
                todo.append(libs[name])
    before = sum(f.stat().st_size for f in pyqt.rglob("*") if f.is_file())
    for name, path in libs.items():
        if name not in keep:
            path.unlink()
    for module in pyqt.glob("Qt*.abi3.so"):
        if module.name.split(".")[0] not in MODULES:
            module.unlink()
            for stub in pyqt.glob(module.name.split(".")[0] + ".pyi"):
                stub.unlink()
    for folder in (qt / "plugins").iterdir():
        if folder.name not in PLUGINS:
            shutil.rmtree(folder)
    for folder in ("qml", "qsci"):
        shutil.rmtree(qt / folder, ignore_errors=True)
    for translation in (qt / "translations").glob("*.qm"):
        translation.unlink()  # Qt's own dialogs; the web view's locales (qtwebengine_locales) stay
    shutil.rmtree(pyqt / "bindings", ignore_errors=True)
    after = sum(f.stat().st_size for f in pyqt.rglob("*") if f.is_file())
    print(f"PyQt6: {before / 1e6:.0f} MB -> {after / 1e6:.0f} MB ({len(keep)} Qt libraries kept)")


if __name__ == "__main__":
    main(sys.argv[1])
