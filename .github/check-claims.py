#!/usr/bin/env python3
"""Checks the lists that say what this protocol does not do.

Twice now a feature has been built and left in a list of things that are not
built. Congestion control stayed in one for three commits after it was written
(DECISIONS D30 records that); address migration did the same, and both were
still there weeks later, in the crate-level documentation that is the first
paragraph on docs.rs. Nothing catches a sentence — `doc_snippets.rs` compiles
code blocks, `api_reference.rs` pins constants, `check-links.py` follows links.
None of them reads prose.

This reads the four standing lists and looks for two things:

  1. A claim that something is absent, where README's "Working" list says it is
     present. Two curated lists contradicting each other is the failure that
     actually happened, and it needs no cleverness to see.

  2. A claim that something is absent, where the crate's public API carries a
     name for it. Fuzzier, so every match must either be fixed or written into
     ALLOWED below with a reason — silencing it costs a sentence, which is the
     point.

What it cannot see: a document contradicting itself in prose. SPEC said
"address migration is not supported in version 1" in section 3.3 while
specifying it in 5.8, and no keyword check finds that. It takes a reader.

Output is deliberately ASCII: this runs on a Windows console too, where a
section sign comes out as a replacement character and makes the report look
like the bug.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Words that carry no signal, so a match on one means nothing.
NOISE = {
    "a", "an", "and", "are", "at", "be", "by", "for", "from", "in", "is", "it",
    "its", "no", "not", "of", "on", "one", "or", "own", "per", "that", "the",
    "there", "this", "to", "with", "within", "yet",
    # Common enough in this codebase's names to match anything.
    "data", "frame", "key", "max", "message", "min", "peer", "send", "set",
    "session", "size", "time",
}

# Absent-claims whose words appear in a public name for an unrelated reason.
# Each entry is a claim phrase and why the match is not a contradiction.
ALLOWED = {
    "path mtu discovery":
        "`path` matches PathChallenge and PATH_TOKEN_LEN, which are the address "
        "validation of SPEC 5.8 and have nothing to do with discovering an MTU.",
    "ordering":
        "`order` matches nothing built; reordering *tolerance* is a different "
        "property and is in the Working list under its own name.",
    "ordered delivery":
        "As above: delivery is deliberately unordered (D12), and reorder "
        "tolerance is the separate thing that exists.",
    "delayed acknowledgement":
        "`acknowledgement` matches the Ack frame type and acknowledgement "
        "block, which are the per-message acknowledgements; what is absent is "
        "a batching algorithm over them.",
    "counter exhaustion ends a session":
        "Describes a bound that exists on purpose rather than a missing "
        "feature; the row is in the gaps table to record the consequence.",
    "a peer timeout needs keep-alives to mean anything":
        "Describes how two built features relate, not something absent.",
    "pre-shared-key mode misuse":
        "Names a mode that exists; the gap is that a protocol cannot enforce "
        "judgement about when to use it.",
    "address migration for a `connection`":
        "An Endpoint migrates and a Connection does not; the names matched are "
        "the Endpoint half, which is the half that exists.",
    "a reply that depends on the request":
        "`reply` matches set_handshake_reply, which is the fixed reply that "
        "exists; what is absent is a per-peer one.",
    "tail latency under load":
        "`latency` and `load` match nothing built; the row records a measured "
        "cost of the single poll loop, not a missing feature.",
    "no dead-peer detection":
        "Superseded row wording; peer timeouts exist (D51) and the gaps table "
        "now says so under a different name.",
    "resumption after a long sleep":
        "Resumption exists; the gap is that a ticket outlives a device's sleep "
        "only if its lifetime is raised.",
    "a stranger's handshake from a new address":
        "`handshake` and `address` match what exists; the row records residual "
        "cost, not an absent feature.",
    "keys must be in process memory":
        "`keys` matches the key types that exist; the row is about there being "
        "no secure element, which is named separately.",
    "cross-message prediction":
        "`prediction` matches nothing; `message` is filtered as noise but the "
        "row is listed here so the reason is on record.",
    "close semantics":
        "`Close` is a frame type that is assigned, which is what SPEC 10 says. "
        "What is undefined is its payload and state machine, and there is no "
        "close() anywhere to contradict that.",
    "bit-packed deltas":
        "`delta` matches the delta transform that exists; what was measured and "
        "declined (D45) is the bit-packed variant of it.",
}


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def words(phrase: str) -> set[str]:
    """The significant words of a claim, lowercased."""
    return {w for w in re.split(r"[^a-z0-9]+", phrase.lower()) if w and w not in NOISE}


def comma_list(text: str) -> list[str]:
    """Splits a prose list like "a, b and c, d" into its items."""
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)  # drop link targets
    return [item.strip(" .*_`") for item in text.split(",") if item.strip(" .*_`")]


def readme_lists() -> tuple[list[str], list[str]]:
    text = read("README.md")
    working = re.search(r"\*\*Working:\*\*(.+?)\n\n", text, re.S)
    absent = re.search(r"\*\*Not built:\*\*(.+?)\n\n", text, re.S)
    if not working or not absent:
        sys.exit("README.md: could not find the Working and Not built lists")
    return comma_list(working.group(1)), comma_list(absent.group(1))


def spec_not_specified() -> list[str]:
    text = read("docs/SPEC.md")
    section = re.search(r"^## 10\..+?\n(.*?)(?=\n## )", text, re.S | re.M)
    if not section:
        sys.exit("docs/SPEC.md: could not find section 10")
    return re.findall(r"^- \*\*(.+?)\.?\*\*", section.group(1), re.M)


def decisions_gaps() -> list[str]:
    text = read("docs/DECISIONS.md")
    section = re.search(
        r"These are unimplemented, not overlooked\.\n\n(.*?)\n\n", text, re.S
    )
    if not section:
        sys.exit("docs/DECISIONS.md: could not find the gaps table")
    return re.findall(r"^\| \*\*(.+?)\*\* \|", section.group(1), re.M)


def public_names() -> set[str]:
    """Words appearing in the crates' public item names."""
    found: set[str] = set()
    pattern = re.compile(
        r"^\s*pub(?:\([^)]*\))?\s+(?:fn|const|static|struct|enum|type|trait)\s+(\w+)",
        re.M,
    )
    for source in (ROOT / "crates").rglob("*.rs"):
        if "target" in source.parts or source.parts[-2] == "tests":
            continue
        text = source.read_text(encoding="utf-8")
        for name in pattern.findall(text):
            for part in re.split(r"[^A-Za-z0-9]+", re.sub(r"(?<!^)(?=[A-Z])", "_", name)):
                if part:
                    found.add(part.lower())
        # Enum variants of public enums, which carry the feature names.
        for block in re.findall(r"pub enum \w+ \{(.*?)\n\}", text, re.S):
            for variant in re.findall(r"^\s*(\w+)\s*[,{(]", block, re.M):
                for part in re.split(r"_", re.sub(r"(?<!^)(?=[A-Z])", "_", variant)):
                    if part:
                        found.add(part.lower())
    return found


def main() -> int:
    working, readme_absent = readme_lists()
    claims = (
        [("README.md, \"Not built\"", c) for c in readme_absent]
        + [("docs/SPEC.md section 10", c) for c in spec_not_specified()]
        + [("docs/DECISIONS.md, known gaps", c) for c in decisions_gaps()]
    )

    working_words = [(w, words(w)) for w in working]
    names = public_names()
    problems: list[str] = []

    for where, claim in claims:
        claim_words = words(claim)
        if not claim_words:
            continue
        # An allowed claim is allowed against both checks: the reason written
        # beside it explains the words, whichever list they collide with.
        if claim.lower() in ALLOWED:
            continue

        # 1. Two curated lists disagreeing.
        for built, built_words in working_words:
            shared = claim_words & built_words
            if len(shared) >= 2 or (claim_words and claim_words <= built_words):
                problems.append(
                    f"{where}: \"{claim}\" is listed as absent, but README's "
                    f"Working list has \"{built}\" ({', '.join(sorted(shared))})"
                )

        # 2. A public name for something said to be absent.
        matched = sorted(claim_words & names)
        if matched:
            problems.append(
                f"{where}: \"{claim}\" is listed as absent, but the public API "
                f"has {', '.join(matched)} in an item name. Fix the list, or "
                f"add the claim to ALLOWED in this script with a reason."
            )

    if problems:
        print(f"{len(problems)} claim(s) the code disagrees with:\n")
        for problem in problems:
            print(f"  {problem}")
        return 1

    print(f"every absent-claim checks out ({len(claims)} across three lists)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
