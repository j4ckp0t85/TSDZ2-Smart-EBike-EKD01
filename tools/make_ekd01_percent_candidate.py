import argparse
import hashlib
from pathlib import Path

from inspect_ekd01 import verify_battery


FULL_READBACK_SIZE = 8 * 1024 * 1024
FULL_READBACK_SHA256 = "88ba4e57c866f327c548fdd33e178e96bb2ade7ba52c44d18003f32278e8c842"
MAIN_IMAGE_OFFSET = 0x50000
MAIN_IMAGE_SIZE = 4403404
MAIN_IMAGE_SHA256 = "36dc7fe8716e30dd95f787aa2d96559643768679867bae9d0ffc290db02b3eb4"
FLASH_BASE = 0x10000000

PATCHES = (
    (0x160FBA, b"\x0c\x28", b"\x64\x28", "default battery clamp 12 -> 100"),
    (0x160FBE, b"\x0c\x20", b"\x64\x20", "default battery clamp value 12 -> 100"),
    (0x160FF8, bytes.fromhex("55 55 05 41"), bytes.fromhex("00 00 80 3f"), "default battery scale -> 1.0"),
    (0x15DF0E, b"\x0c\x28", b"\x64\x28", "custom battery clamp 12 -> 100"),
    (0x15DF12, b"\x0c\x20", b"\x64\x20", "custom battery clamp value 12 -> 100"),
    (0x15DF50, bytes.fromhex("55 55 05 41"), bytes.fromhex("00 00 80 3f"), "custom battery scale -> 1.0"),
)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(
        description="Create a non-flashable analysis copy of a verified full EKD01 N22 readback."
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("candidate", type=Path)
    args = parser.parse_args()

    source = args.source.resolve()
    candidate = args.candidate.resolve()
    if source == candidate:
        parser.error("candidate path must differ from source")
    if candidate.exists():
        parser.error("candidate already exists; refusing to overwrite")

    original = source.read_bytes()
    if len(original) != FULL_READBACK_SIZE:
        parser.error(f"expected {FULL_READBACK_SIZE} bytes, got {len(original)}")
    original_hash = sha256(original)
    if original_hash != FULL_READBACK_SHA256:
        parser.error(f"unexpected source SHA-256: {original_hash}")
    if original[:7] != b"SF_BOOT":
        parser.error("source does not have the expected SF_BOOT header")

    app = original[MAIN_IMAGE_OFFSET:MAIN_IMAGE_OFFSET + MAIN_IMAGE_SIZE]
    if sha256(app) != MAIN_IMAGE_SHA256:
        parser.error("N22 application region does not match the verified vendor image")

    patched = bytearray(original)
    for offset, expected, replacement, description in PATCHES:
        actual = bytes(patched[offset:offset + len(expected)])
        if actual != expected:
            parser.error(f"unexpected original bytes at {offset:#x}: {actual.hex(' ')}")
        patched[offset:offset + len(replacement)] = replacement
        print(f"patched full-flash offset {offset:#08x}: {expected.hex(' ')} -> {replacement.hex(' ')} ({description})")

    patched_bytes = bytes(patched)
    if len(patched_bytes) != len(original):
        raise AssertionError("candidate length changed")
    differences = [index for index, (before, after) in enumerate(zip(original, patched_bytes)) if before != after]
    expected_offsets = sorted(
        offset + index
        for offset, before, replacement, _ in PATCHES
        for index in range(len(before))
        if before[index] != replacement[index]
    )
    if differences != expected_offsets:
        raise AssertionError(f"unexpected modified byte offsets: {differences}")

    # Execute both patched callback routines from the candidate full-flash image.
    verify_battery(patched_bytes, FLASH_BASE, direct_soc=True)

    with candidate.open("xb") as output:
        output.write(patched_bytes)

    print(f"source SHA-256:    {original_hash}")
    print(f"candidate SHA-256: {sha256(patched_bytes)}")
    print(f"candidate size:    {len(patched_bytes)}")
    print(f"changed bytes:     {len(differences)}")
    print("ANALYSIS ONLY: raw NOR readback, not a MediaTek package and NOT for flashing.")


if __name__ == "__main__":
    main()
