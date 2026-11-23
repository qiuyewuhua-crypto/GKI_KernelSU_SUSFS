#!/usr/bin/env python3
"""Inject the SEL context-oracle filter into the root flavour's selinux_hide.c.

Anchored insertion instead of a context diff: the SUSFS composite action runs
sed over this very file before we get here (pointer-bool-conversion fixes and a
`static` strip), so a line-context patch would be fragile for no benefit. Every
anchor is required to match exactly once, and the script exits non-zero if it
does not -- a silently unpatched kernel is worse than no kernel.

Anchor candidates are listed oldest-last: selinux_hide.c was rewritten between
the two SukiSU revisions this repo can build, so the include tail and the init
signature differ (``()`` vs ``(void)``) while the enable function does not.

Usage: apply_sel_context_filter.py <workspace> [<inc file>]
"""

import os
import sys

MARKER = "ksu_sel_ctx_write_hook"

INCLUDES = [
    '#include "infra/symbol_resolver.h"',
    "#include <linux/set_memory.h>",
    # The older selinux_hide.c carries a much shorter include block, so the
    # declarations this filter needs are pulled in explicitly. Kernel headers
    # are include-guarded, so this is a no-op where they are already present.
    "#include <linux/fs.h>",
    "#include <linux/mm.h>",
    "#include <linux/cred.h>",
    "#include <linux/uaccess.h>",
    "#include <linux/string.h>",
]

# Inserted after the last include of the header block.
INC_ANCHORS = [
    '#include "objsec.h"',
    "#include <ss/conditional.h>",
]
# The implementation goes immediately above this definition (stable in both).
IMPL_ANCHOR = "static int ksu_selinux_hide_enable()"
# Call site: first statement of the unconditional (>= 5.10) init hook.
CALL_ANCHORS = [
    "void __init ksu_selinux_hide_init()",
    "void __init ksu_selinux_hide_init(void)",
]
CALL_BODY = "    ksu_sel_ctx_patch();"


def pick_anchor(src, candidates, what):
    """Return the first candidate that occurs exactly once (ordered preference).

    Ordered rather than "the unique one": the newer selinux_hide.c contains both
    an ``objsec.h`` and an ``<ss/conditional.h>`` include, so uniqueness across
    the candidate set would be ambiguous even though the preference is obvious.
    """
    for cand in candidates:
        if src.count(cand) == 1:
            return cand
    raise SystemExit(
        f"ERROR: no unique {what} anchor; counts were "
        + ", ".join(f"{c!r}={src.count(c)}" for c in candidates)
    )


def insert_after(src, anchor, payload):
    i = src.index(anchor) + len(anchor)
    return src[:i] + "\n" + payload + src[i:]


def insert_before(src, anchor, payload):
    i = src.index(anchor)
    return src[:i] + payload + "\n" + src[i:]


def insert_into_function(src, anchor, statement):
    start = src.index(anchor)
    brace = src.find("{", start)
    if brace < 0:
        raise SystemExit("ERROR: no opening brace after the init anchor")
    nl = src.find("\n", brace)
    if nl < 0:
        raise SystemExit("ERROR: malformed init function body")
    return src[: nl + 1] + statement + "\n" + src[nl + 1 :]


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    workspace = sys.argv[1]
    here = os.path.dirname(os.path.abspath(__file__))
    inc_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        here, os.pardir, "patches", "ksu_sel_context_filter.inc"
    )
    with open(inc_path, encoding="utf-8") as fh:
        impl = fh.read().rstrip("\n")

    targets = []
    for root, dirs, files in os.walk(os.path.join(workspace, "kernel")):
        dirs[:] = [d for d in dirs if d != ".git"]
        if "selinux_hide.c" in files:
            targets.append(os.path.join(root, "selinux_hide.c"))
    if not targets:
        raise SystemExit(
            "ERROR: no selinux_hide.c found under " + os.path.join(workspace, "kernel")
        )

    for path in targets:
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        if MARKER in src:
            print(f"[=] {path}: filter already present")
            continue

        inc = pick_anchor(src, INC_ANCHORS, "include")
        call = pick_anchor(src, CALL_ANCHORS, "init")
        if src.count(IMPL_ANCHOR) != 1:
            raise SystemExit(f"ERROR: enable anchor matched {src.count(IMPL_ANCHOR)} time(s)")

        src = insert_after(src, inc, "\n".join(INCLUDES))
        src = insert_before(src, IMPL_ANCHOR, impl + "\n")
        src = insert_into_function(src, call, CALL_BODY)

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(src)
        print(f"[+] {path}: context-oracle filter injected (include {inc!r})")

    # Verify, do not assume.
    for path in targets:
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        for needle in (MARKER, "sel_context_ops", CALL_BODY.strip()):
            if needle not in src:
                raise SystemExit(f"ERROR: {path} is missing {needle!r} after patching")
        print(f"[ok] {path}: verified")


if __name__ == "__main__":
    main()
