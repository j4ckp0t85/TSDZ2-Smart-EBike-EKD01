import argparse
import hashlib
from pathlib import Path
import shutil


RAW_SIZE = 8 * 1024 * 1024
RAW_CANDIDATE_SHA256 = "18461cf6f018befbc75a55ace96e2a7ccf558c5a9dbd434bee21c685701cbaf7"
RAW_APP_OFFSET = 0x50000
APP_NAME = "EKD01_TB_PCB01_gsm_MT2502_S00.EKD01_TB_N22.bin"
APP_SIZE = 4403404
APP_SHA256 = "36dc7fe8716e30dd95f787aa2d96559643768679867bae9d0ffc290db02b3eb4"
APP_PATCH_OFFSETS = (0x10DF0E, 0x10DF12, 0x10DF50, 0x10DF51, 0x10DF52, 0x10DF53,
                     0x110FBA, 0x110FBE, 0x110FF8, 0x110FF9, 0x110FFA, 0x110FFB)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(
        description="Assemble an isolated N22 component-bundle candidate. Never flash this experimental bundle."
    )
    parser.add_argument("vendor_package", type=Path)
    parser.add_argument("verified_raw_candidate", type=Path)
    parser.add_argument("output_directory", type=Path)
    args = parser.parse_args()

    vendor = args.vendor_package.resolve()
    raw_path = args.verified_raw_candidate.resolve()
    output = args.output_directory.resolve()
    main_path = vendor / APP_NAME
    config_path = vendor / "SOUTHBASE2502C_WT_11C_BB.cfg"

    if not vendor.is_dir() or not main_path.is_file() or not config_path.is_file():
        parser.error("vendor directory must contain the N22 main image and SOUTHBASE config")
    if output == vendor or vendor in output.parents or output in vendor.parents:
        parser.error("output must be a separate directory, not inside or above the source package")
    if output.exists():
        parser.error("output directory already exists; refusing to overwrite")

    raw = raw_path.read_bytes()
    if len(raw) != RAW_SIZE or sha256(raw) != RAW_CANDIDATE_SHA256:
        parser.error("raw input is not the previously verified 8 MiB N22 analysis candidate")

    original_app = main_path.read_bytes()
    if len(original_app) != APP_SIZE or sha256(original_app) != APP_SHA256:
        parser.error("vendor main image does not match the verified N22 package baseline")
    candidate_app = raw[RAW_APP_OFFSET:RAW_APP_OFFSET + APP_SIZE]
    if len(candidate_app) != APP_SIZE:
        parser.error("candidate main-region slice has an unexpected length")

    differences = [index for index, (before, after) in enumerate(zip(original_app, candidate_app))
                   if before != after]
    if differences != list(APP_PATCH_OFFSETS):
        parser.error(f"main-region changes differ from the expected 12 patch bytes: {differences}")

    config = config_path.read_text(encoding="utf-8")
    if APP_NAME not in config:
        parser.error("N22 config does not reference the main image filename")
    for required in ("EKD01_TB_BOOTLOADER_V005_MT2502_EKD01_TB_N22.bin", "EXT_BOOTLOADER"):
        if required not in config or not (vendor / required).is_file():
            parser.error(f"N22 package is missing configured boot component: {required}")

    shutil.copytree(vendor, output)
    (output / APP_NAME).write_bytes(candidate_app)

    for required in ("EKD01_TB_BOOTLOADER_V005_MT2502_EKD01_TB_N22.bin", "EXT_BOOTLOADER", config_path.name):
        if sha256((vendor / required).read_bytes()) != sha256((output / required).read_bytes()):
            raise AssertionError(f"unchanged package component differs: {required}")

    print(f"Candidate package directory: {output}")
    print(f"Main component size: {len(candidate_app)}")
    print(f"Main component SHA-256: {sha256(candidate_app)}")
    print(f"Changed main-component byte offsets: {[hex(offset) for offset in differences]}")
    print("Boot components and N22 config are byte-identical to the vendor package.")
    print("NOT FOR FLASH: boot acceptance, hidden integrity checks and restoration are unverified.")


if __name__ == "__main__":
    main()