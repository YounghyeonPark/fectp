"""The parts of the build that pyproject.toml cannot say.

**One wheel per platform, any Python 3.** The package is pure Python calling a
shared library through ``ctypes``, so nothing in it depends on the
interpreter's ABI — but the library does depend on the platform. setuptools
calls a wheel either pure (``py3-none-any``) or tied to one interpreter
(``cp313-cp313-...``), and this is neither, so the tag is set here:
``py3-none-<platform>``.

**The platform tag can be named.** ``FECTP_WHEEL_PLATFORM`` overrides it, for
the cases where the machine building is not the one the library targets:
``manylinux_2_28_x86_64`` for a library built in that container, and
``macosx_11_0_universal2`` for one built for both macOS architectures.

**The version is the workspace's.** Read from the root ``Cargo.toml`` so the
binding and the library inside it cannot drift apart.
"""

import os
import re
from pathlib import Path

from setuptools import setup
from setuptools.command.bdist_wheel import bdist_wheel


def workspace_version() -> str:
    root = Path(__file__).resolve().parents[2]
    text = (root / "Cargo.toml").read_text(encoding="utf-8")
    section = text.split("[workspace.package]", 1)[1]
    return re.search(r'^version = "([^"]+)"', section, re.M).group(1)


class PlatformWheel(bdist_wheel):
    def finalize_options(self):
        super().finalize_options()
        # Not pure: it carries a native library.
        self.root_is_pure = False

    def get_tag(self):
        _python, _abi, platform = super().get_tag()
        return "py3", "none", os.environ.get("FECTP_WHEEL_PLATFORM", platform)


def staged_library_present() -> None:
    native = Path(__file__).resolve().parent / "fectp" / "_native"
    if not any(native.glob("*fectp.*")):
        raise SystemExit(
            "no shared library staged in fectp/_native. Build it with "
            "`cargo build -p fectp-ffi --release` and copy it there first; "
            "a wheel without it would install and then fail on import."
        )


staged_library_present()
setup(version=workspace_version(), cmdclass={"bdist_wheel": PlatformWheel})
