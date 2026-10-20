// Puts what the npm package carries where `npm pack` will find it.
//
//     node stage.mjs [path/to/library ...]
//
// Copies each shared library into prebuilds/<platform>-<arch>/ — this
// platform's from `cargo build -p fectp-ffi --release` unless paths are given,
// as CI gives the three platforms' — and the workspace LICENSE beside
// package.json. Both are build output and ignored by git.
//
// `--check` copies nothing and fails unless every platform the manifest names
// has a library staged, so a package missing one cannot be packed by accident.

import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..", "..");
const prebuilds = join(here, "prebuilds");
const expected = [
  "win32-x64/fectp.dll",
  "linux-x64/libfectp.so",
  "linux-arm64/libfectp.so",
  "darwin-universal/libfectp.dylib",
];

/**
 * Which prebuilds folder a library belongs in.
 *
 * Windows and macOS by name. Linux by the ELF header, because both Linux
 * libraries are called libfectp.so and the name says nothing about the
 * architecture: e_machine, at offset 18, is 62 for x86-64 and 183 for AArch64.
 * Anything else is refused rather than filed somewhere plausible.
 */
function folderFor(path) {
  const name = basename(path);
  if (name.endsWith(".dll")) return "win32-x64";
  if (name.endsWith(".dylib")) return "darwin-universal";
  const header = readFileSync(path).subarray(0, 20);
  if (header.length < 20 || header.readUInt32BE(0) !== 0x7f454c46) {
    throw new Error(`${path} is not an ELF library`);
  }
  const machine = header.readUInt16LE(18);
  if (machine === 62) return "linux-x64";
  if (machine === 183) return "linux-arm64";
  throw new Error(`${path} is an ELF library for machine ${machine}, which this package does not ship`);
}

const args = process.argv.slice(2);
if (args.includes("--check")) {
  const missing = expected.filter((p) => !existsSync(join(prebuilds, p)));
  if (missing.length) {
    console.error(`not staged: ${missing.join(", ")}. A package without them would install and fail to load.`);
    process.exit(1);
  }
  console.log(`all ${expected.length} platforms staged`);
  process.exit(0);
}

const libraries = args.length ? args : [join(root, "target", "release",
  process.platform === "win32" ? "fectp.dll" : process.platform === "darwin" ? "libfectp.dylib" : "libfectp.so")];
for (const library of libraries) {
  if (!existsSync(library)) {
    console.error(`${library} does not exist; build it with cargo first`);
    process.exit(1);
  }
  const folder = join(prebuilds, folderFor(library));
  mkdirSync(folder, { recursive: true });
  copyFileSync(library, join(folder, basename(library)));
  console.log(`staged ${basename(library)} (${statSync(library).size} bytes) in ${basename(folder)}`);
}
copyFileSync(join(root, "LICENSE"), join(here, "LICENSE"));
console.log(`prebuilds now: ${readdirSync(prebuilds).join(", ")}`);
