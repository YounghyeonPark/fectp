"""Reports what the linked image occupies in flash.

Reads the ELF directly rather than shelling out to `arm-none-eabi-size`, which
is not part of a Rust toolchain and would make this depend on a separate
install.

    python size.py [path-to-elf]
"""

import struct
import sys
from pathlib import Path

ELF_MAGIC = b"\x7fELF"
FLASH_SECTIONS = (".vector_table", ".text", ".rodata")
REPORTED = FLASH_SECTIONS + (".data", ".bss")


def sections(path: Path):
    """Yields (name, size) for every section in a 32-bit little-endian ELF."""
    data = path.read_bytes()
    if data[: len(ELF_MAGIC)] != ELF_MAGIC:
        raise SystemExit(f"{path} is not an ELF image")

    (sh_off,) = struct.unpack_from("<I", data, 0x20)
    sh_entsize, sh_num, sh_strndx = struct.unpack_from("<HHH", data, 0x2E)

    def header(index):
        return struct.unpack_from("<IIIIII", data, sh_off + index * sh_entsize)

    names_at = header(sh_strndx)[4]
    terminator = 0

    def name(offset):
        start = names_at + offset
        end = data.index(bytes([terminator]), start)
        return data[start:end].decode()

    for i in range(sh_num):
        name_off, _type, _flags, _addr, _off, size = header(i)
        yield name(name_off), size


def main() -> None:
    default = Path("target/thumbv7em-none-eabihf/release/fectp-footprint")
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else default

    flash = 0
    for name, size in sections(path):
        if size and name in REPORTED:
            print(f"  {name:<16}{size:>9} bytes")
            if name in FLASH_SECTIONS:
                flash += size
    print(f"  {'flash total':<16}{flash:>9} bytes  ({flash / 1024:.1f} KiB)")


if __name__ == "__main__":
    main()
