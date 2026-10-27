#!/usr/bin/env python3
"""Verify the kernel image embeds the vendor config blob verbatim.

Usage: check-config-blob.py <Image> <expected.gz> [expected_md5]

Locates the gzip stream whose payload is a kernel ``.config`` and compares
it against the reference blob.  Any mismatch means ``/proc/config.gz`` will
still betray the self-built kernel, so this exits non-zero.
"""

import hashlib
import re
import sys
import zlib


def extract_all(buf):
    """Yield (offset, compressed_length, raw) for every gzip stream found."""
    for match in re.finditer(rb"\x1f\x8b\x08", buf):
        start = match.start()
        try:
            raw, length = inflate(buf, start)
        except zlib.error:
            continue
        if raw:
            yield start, length, raw


def inflate(buf, start, limit=4 << 20):
    dobj = zlib.decompressobj(31)
    chunks = []
    pos = start
    while not dobj.eof:
        chunk = buf[pos:pos + 8192]
        if not chunk:
            break
        chunks.append(dobj.decompress(chunk))
        pos += len(chunk) - len(dobj.unused_data)
        if pos - start > limit:
            return b"", 0
    return b"".join(chunks), pos - start


def main():
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2

    image_path, ref_path = sys.argv[1], sys.argv[2]
    expected_md5 = sys.argv[3] if len(sys.argv) > 3 else None

    image = open(image_path, "rb").read()
    reference = open(ref_path, "rb").read()

    found = None
    for offset, length, raw in extract_all(image):
        if b"Kernel Configuration" in raw[:400]:
            found = (offset, length, raw)
            break

    if found is None:
        print("ERROR: no kernel config blob found in %s" % image_path, file=sys.stderr)
        return 1

    offset, length, raw = found
    blob_md5 = hashlib.md5(image[offset:offset + length]).hexdigest()
    banner = raw.decode("utf-8", "replace").splitlines()[2]

    print("config blob @%d: %d bytes, %d raw, %d lines" % (offset, length, len(raw), raw.count(b"\n")))
    print("banner: %s" % banner)
    print("md5: %s" % blob_md5)

    problems = []
    if length != len(reference):
        problems.append("compressed size %d != vendor %d" % (length, len(reference)))
    if raw != zlib.decompress(reference, 31):
        problems.append("decompressed payload differs from vendor config")
    if expected_md5 and blob_md5 != expected_md5:
        problems.append("md5 %s != expected %s" % (blob_md5, expected_md5))

    if problems:
        for item in problems:
            print("MISMATCH: %s" % item, file=sys.stderr)
        return 1

    print("OK: embedded config blob is byte-identical to the vendor image")
    return 0


if __name__ == "__main__":
    sys.exit(main())
