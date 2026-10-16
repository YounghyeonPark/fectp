"""Puts what a wheel carries where the build expects it.

    python bindings/python/stage.py [path/to/library]

Copies the shared library into ``fectp/_native`` — the one built by
``cargo build -p fectp-ffi --release`` for this platform unless a path is
given, as CI gives one for a library built elsewhere — and the workspace
``LICENSE`` beside ``pyproject.toml``. Both are build output and ignored by git.
"""

import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
NAMES = {"win32": "fectp.dll", "darwin": "libfectp.dylib"}


def main() -> None:
    if len(sys.argv) > 1:
        library = Path(sys.argv[1])
    else:
        library = ROOT / "target" / "release" / NAMES.get(sys.platform, "libfectp.so")
    if not library.is_file():
        raise SystemExit(f"{library} does not exist; build it with cargo first")

    native = HERE / "fectp" / "_native"
    if native.exists():
        shutil.rmtree(native)
    native.mkdir()
    shutil.copy2(library, native / library.name)
    shutil.copy2(ROOT / "LICENSE", HERE / "LICENSE")
    print(f"staged {library.name} ({library.stat().st_size} bytes) and LICENSE")


if __name__ == "__main__":
    main()
