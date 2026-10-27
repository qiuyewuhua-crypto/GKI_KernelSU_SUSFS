#!/usr/bin/env python3
"""Point the kernel's embedded config blob at the vendor image's copy.

``/proc/config.gz`` is produced by Kbuild from ``kernel/config_data.gz``,
which is normally just ``gzip(.config)``.  A self-built GKI tree therefore
ships a blob that differs from the stock one in size, line count and the
version banner baked into the first few lines -- all trivially observable
from userspace without root.

This script rewires the ``kernel/Makefile`` rule so the blob is copied
verbatim from ``$(srctree)/factory_config.gz`` instead of being regenerated.

Run with the kernel tree root (the directory holding ``common/``) as the
current working directory.
"""

import sys

MAKEFILE = "common/kernel/Makefile"

OLD_RULE = (
    "$(obj)/config_data.gz: $(obj)/config_data FORCE\n"
    "\t$(call if_changed,gzip)"
)

NEW_RULE = (
    "quiet_cmd_copyfg = COPY    $@\n"
    "      cmd_copyfg = cp $< $@\n"
    "\n"
    "$(obj)/config_data.gz: $(srctree)/factory_config.gz FORCE\n"
    "\t$(call if_changed,copyfg)"
)


def main():
    try:
        with open(MAKEFILE, newline="") as fh:
            src = fh.read()
    except OSError as exc:
        print("ERROR: cannot read %s: %s" % (MAKEFILE, exc), file=sys.stderr)
        return 1

    if NEW_RULE in src:
        print("config_data.gz rule already patched; nothing to do")
        return 0

    if OLD_RULE not in src:
        print(
            "ERROR: expected config_data.gz rule not found in %s" % MAKEFILE,
            file=sys.stderr,
        )
        return 1

    with open(MAKEFILE, "w", newline="") as fh:
        fh.write(src.replace(OLD_RULE, NEW_RULE, 1))

    print("patched %s: config_data.gz now copied from factory_config.gz" % MAKEFILE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
