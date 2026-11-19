import argparse
import hashlib
from pathlib import Path
import struct
import subprocess
import tempfile

from inspect_ekd01 import verify_battery
from inspect_ekd01_power import BASE, thumb_branch, verify_power_extension, verify_processed_power, verify_processed_capture


SOC_SHA256 = "9478720ca0510e7e76f2124fe0eca4f974c3216e6e0d4374b9bf74d411b139c4"
APP_NAME = "EKD01_TB_PCB01_gsm_MT2502_S00.EKD01_TB_N22.bin"
HARDWARE_FAILED_SHA256 = "2b180746650d34fe6bd1343f3b5a7ade775dd983cb7dcec5c0aff02003d39277"


# Executable ranges only; literal pools are excluded. Includes vendor functions as a validator sanity check.
ARMV5_CODE_RANGES = (
    (0x1012FCE8, 0x1012FD3C),
    (0x101918B0, 0x101918DE),
    (0x10197B2C, 0x10197BF6),
    (0x101E88A8, 0x101E890C),
    (0x1015DF0C, 0x1015DF4C),
    (0x10160D94, 0x10160DDC),
)


def thumb1_valid(halfword):
    if halfword >> 11 in (0b11101, 0b11111):
        return False
    if halfword >> 10 == 0b010001:
        operation = (halfword >> 8) & 3
        if operation == 3:
            return halfword & 7 == 0
        return halfword & 0xC0 != 0
    if halfword >> 12 == 0b1011:
        return (halfword >> 8) & 0xF in (0b0000, 0b0100, 0b0101, 0b1100, 0b1101, 0b1110)
    if halfword >> 12 == 0b1101:
        return (halfword >> 8) & 0xF != 0b1110
    return True


def armv5_thumb_errors(data):
    errors = []
    for start, end in ARMV5_CODE_RANGES:
        address = start
        while address < end:
            halfword = struct.unpack_from("<H", data, address - BASE)[0]
            if halfword >> 11 == 0b11110:
                suffix = struct.unpack_from("<H", data, address + 2 - BASE)[0]
                if not (suffix >> 11 == 0b11111 or (suffix >> 11 == 0b11101 and not suffix & 1)):
                    errors.append(f"{address:#x}: {halfword:04x} {suffix:04x}")
                address += 4
                continue
            if not thumb1_valid(halfword):
                errors.append(f"{address:#x}: {halfword:04x}")
            address += 2
    return errors


def verify_patch_instruction_set(data):
    errors = armv5_thumb_errors(data)
    if errors:
        raise ValueError("Not valid ARMv5 Thumb: " + ", ".join(errors))


def verify_assembler(clang):
    objcopy = clang.with_name("llvm-objcopy.exe")
    with tempfile.TemporaryDirectory(prefix="ekd01-isa-") as folder:
        for cpu, expected in (("arm926ej-s", "c046c046c046"), ("cortex-m3", "00bf00bf00bf")):
            obj = Path(folder) / "nop.o"
            raw = Path(folder) / "nop.bin"
            source = f".syntax unified\n.cpu {cpu}\n.thumb\n.text\nnop\nnop\nnop\n"
            subprocess.run([str(clang), "--target=arm-none-eabi", "-x", "assembler", "-c", "-o", str(obj), "-"],
                           input=source, text=True, capture_output=True, check=True)
            subprocess.run([str(objcopy), "-O", "binary", "--only-section=.text", str(obj), str(raw)],
                           capture_output=True, check=True)
            actual = raw.read_bytes().hex()
            if actual != expected:
                raise ValueError(f"Independent assembler mismatch: {cpu} {actual}")
            print(f"PASS: independent LLVM assembler {cpu} NOP bytes {actual}")
        source = (
            ".syntax unified\n.cpu arm926ej-s\n.thumb\n.text\n.org 2\n"
            "ldr r1, [r4, #44]\nstrh r0, [r1, #8]\nldr r1, payload\n"
            "strb r0, [r1, #19]\nlsrs r2, r0, #8\nstrb r2, [r1, #20]\n"
            "ldrb r2, [r1, #1]\nadds r2, #1\nmovs r3, #128\norrs r2, r3\n"
            "strb r2, [r1, #1]\nbx lr\n.org 32\npayload: .word 0xf020946e\n"
        )
        subprocess.run([str(clang), "--target=arm-none-eabi", "-x", "assembler", "-c", "-o", str(obj), "-"],
                       input=source, text=True, capture_output=True, check=True)
        subprocess.run([str(objcopy), "-O", "binary", "--only-section=.text", str(obj), str(raw)],
                       capture_output=True, check=True)
        assembled = raw.read_bytes()
        original = (Path(__file__).resolve().parent.parent / "bin" / "ekd01-soc-before-power" / APP_NAME).read_bytes()
        patched = build_patch(original)
        if assembled[2:26] != patched[0x1015DF32 - BASE:0x1015DF4A - BASE]:
            raise ValueError("Independent ARM926 assembler disagrees with processed-power capture instructions")
        if assembled[32:36] != patched[0x1015DF50 - BASE:0x1015DF54 - BASE]:
            raise ValueError("Independent ARM926 assembler disagrees with capture literal")
        print("PASS: entire processed-power helper and literal match independent ARM926 LLVM assembly")


def build_patch(original):
    if hashlib.sha256(original).hexdigest() != SOC_SHA256:
        raise ValueError("Input must be the exact verified SOC-only N22 application")
    capture_address = 0x1015DF32
    capture = struct.pack("<12H", 0x6AE1, 0x8108, 0x4906, 0x74C8, 0x0A02, 0x750A,
                          0x784A, 0x3201, 0x2380, 0x431A, 0x704A, 0x4770)
    changes = (
        (0x1015DF20, bytes.fromhex("13 d1"), bytes.fromhex("06 d1")),
        (0x1015DF26, bytes.fromhex("10 d0"), bytes.fromhex("03 d0")),
        (0x1015DF2A, original[0x1015DF2A - BASE:0x1015DF4A - BASE],
         b"\x20\x70" + thumb_branch(0x1015DF2C, 0x101DA614, True) + b"\x10\xbd" + capture),
        (0x1015DF50, struct.pack("<f", 1.0), struct.pack("<I", 0xF020946E)),
        (0x10160DB8, bytes.fromhex("e1 6a 08 81"), thumb_branch(0x10160DB8, capture_address, True)),
        (0x10197B54, bytes.fromhex("4d 70"), bytes.fromhex("c0 46")),
        (0x10197BDC, bytes.fromhex("28 0a f5 74 30 75"), bytes.fromhex("c0 46 c0 46 c0 46")),
    )
    patched = bytearray(original)
    for address, expected, replacement in changes:
        offset = address - BASE
        if len(expected) != len(replacement) or original[offset:offset + len(expected)] != expected:
            raise ValueError(f"Patch precondition failed at {address:#x}")
        patched[offset:offset + len(expected)] = replacement
    assert len(patched) == len(original)
    return bytes(patched)


def main():
    parser = argparse.ArgumentParser(description="Verify, optionally write, an experimental SOC + electrical-power N22 application patch. Never flashes hardware.")
    parser.add_argument("package", type=Path)
    parser.add_argument("--in-place", action="store_true", help="Replace only the main application after all checks pass")
    parser.add_argument("--backup-directory", type=Path)
    parser.add_argument("--source", type=Path, help="Verified SOC-only backup to use when replacing an earlier experimental candidate")
    parser.add_argument("--check-assembler", type=Path, help="Independently check NOP encodings using this LLVM clang executable")
    args = parser.parse_args()
    if args.in_place and not args.backup_directory:
        parser.error("--in-place requires --backup-directory")
    if args.check_assembler:
        verify_assembler(args.check_assembler)
    image = args.package / APP_NAME
    original = (args.source or image).read_bytes()
    patched = build_patch(original)
    verify_patch_instruction_set(patched)
    verify_battery(patched, BASE, direct_soc=True)
    verify_processed_power(patched)
    verify_processed_capture(patched)
    verify_power_extension(original, physical_image=patched)
    digest = hashlib.sha256(patched).hexdigest()
    differences = sum(before != after for before, after in zip(original, patched))
    print(f"Patched SHA-256: {digest}; differing bytes versus SOC-only: {differences}")
    print("Protocol v2: payload[19:21] = processed whole watts, uint16 LE; payload[1] = 0x80 | 7-bit sample sequence.")
    print("Experimental candidate: no boot, real-time scheduling or hardware BLE verification. No hardware flashed.")
    print(f"DO NOT FLASH the hardware-failed candidate SHA-256 {HARDWARE_FAILED_SHA256}.")
    if args.in_place:
        current = image.read_bytes()
        if hashlib.sha256(current).hexdigest() not in {
            SOC_SHA256, "7dfc44b0a63cfee79a4ccc215b42213e08f09d51a02b5dcd9d9e535aa4c93fb7",
            "24faf2f03547d8980c6202e80607e7c156e4449e8f0ecaf87266418ef0f84d6b",
            HARDWARE_FAILED_SHA256, digest}:
            raise ValueError("Destination is not a recognized candidate; refusing replacement")
        args.backup_directory.mkdir(parents=True, exist_ok=True)
        backup = args.backup_directory / APP_NAME
        if backup.exists():
            if backup.read_bytes() != original:
                raise ValueError("Existing backup differs; refusing to overwrite it")
        else:
            with backup.open("xb") as output:
                output.write(original)
        staging = image.with_suffix(".power-tmp.bin")
        with staging.open("xb") as output:
            output.write(patched)
        if hashlib.sha256(staging.read_bytes()).hexdigest() != digest:
            raise ValueError("Staged image hash mismatch")
        staging.replace(image)
        print(f"Updated only {image}; SOC-only backup retained at {backup}")


if __name__ == "__main__":
    main()