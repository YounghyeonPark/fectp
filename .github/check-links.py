#!/usr/bin/env python3
"""Checks that every link between the Markdown documents resolves.

Removing a section from the README broke nine internal anchors at once, which
is exactly the kind of thing a reader finds and an author does not: nothing
fails to build, the page just quietly stops working.

Three things are verified, for every Markdown file in the repository:

  * a relative link points at a file that exists
  * an anchor into another document names a heading that document has
  * an anchor into the same document names a heading it has

External links are not fetched. This has to be fast, offline and deterministic;
a network check would be none of those, and a rate-limited failure would teach
people to ignore the job.
"""

import os
import re
import sys

# `[text](target)` and `[text](target#anchor)`, ignoring images and bare `<...>`.
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s#]+)?(?:#([^)\s]+))?\)")
HEADING = re.compile(r"^(#{1,6})\s+(.*)$", re.M)
# A fenced block can contain anything, including things that look like headings.
FENCE = re.compile(r"^```.*?^```", re.M | re.S)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def headings(path):
    """The anchors GitHub generates for one file, in order, with -1 -2 suffixes."""
    with open(path, encoding="utf-8") as f:
        text = FENCE.sub("", f.read())
    seen, out = {}, []
    for _, title in HEADING.findall(text):
        # GitHub replaces each space with a hyphen and does *not* collapse
        # runs, so "D26 — Every way" — where removing the dash leaves two
        # spaces — becomes "d26--every-way". Collapsing here would report
        # every such heading as a broken link.
        slug = re.sub(r"[^\w\s-]", "", title.strip().lower()).replace(" ", "-")
        n = seen.get(slug, 0)
        seen[slug] = n + 1
        out.append(slug if n == 0 else f"{slug}-{n}")
    return set(out)


def markdown_files():
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in {".git", "target", "node_modules"}]
        for name in files:
            if name.endswith(".md"):
                yield os.path.join(base, name)


def main():
    anchors = {}
    problems = []

    for path in sorted(markdown_files()):
        relative = os.path.relpath(path, ROOT).replace(os.sep, "/")
        with open(path, encoding="utf-8") as f:
            text = FENCE.sub("", f.read())

        for target, anchor in LINK.findall(text):
            if target.startswith(("http://", "https://", "mailto:")):
                continue

            if target:
                resolved = os.path.normpath(os.path.join(os.path.dirname(path), target))
                if not os.path.exists(resolved):
                    problems.append(f"{relative}: no such file: {target}")
                    continue
            else:
                # `](#anchor)` — a link within this same file.
                resolved = path

            if not anchor or not resolved.endswith(".md"):
                continue
            if resolved not in anchors:
                anchors[resolved] = headings(resolved)
            if anchor not in anchors[resolved]:
                where = target if target else "this file"
                problems.append(f"{relative}: {where}#{anchor}: no such heading")

    if problems:
        print(f"{len(problems)} broken link(s):\n")
        print("\n".join(f"  {p}" for p in problems))
        return 1

    print("every documentation link resolves")
    return 0


if __name__ == "__main__":
    sys.exit(main())
