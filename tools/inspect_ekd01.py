import argparse
import hashlib
import importlib.util
import pathlib
import re
import struct


def verify_battery(data, base, percent_patch=False, direct_soc=False):
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

    def float_bits(value):
        return struct.unpack("<I", struct.pack("<f", value))[0]

    def bits_float(value):
        return struct.unpack("<f", struct.pack("<I", value))[0]

    if percent_patch:
        data = bytearray(data)
        for address, original, replacement in (
            (0x10160FBA, b"\x0c\x28", b"\x64\x28"),
            (0x10160FBE, b"\x0c\x20", b"\x64\x20"),
            (0x1015DF0E, b"\x0c\x28", b"\x64\x28"),
            (0x1015DF12, b"\x0c\x20", b"\x64\x20"),
            (0x10160FF8, struct.pack("<I", 0x41055555), struct.pack("<f", 1.0)),
            (0x1015DF50, struct.pack("<I", 0x41055555), struct.pack("<f", 1.0)),
        ):
            offset = address - base
            assert data[offset:offset + len(original)] == original, hex(address)
            data[offset:offset + len(original)] = replacement
        data = bytes(data)
        print("Testing an IN-MEMORY percentage patch; no firmware file is written.")

    for entry, custom in ((0x10160FB8, False), (0x1015DF0C, True)):
        for code in range(256):
            machine = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
            machine.mem_map(base & ~4095, (len(data) + 4095) & ~4095)
            machine.mem_write(base, data)
            machine.mem_map(0xF0000000, 0x400000)
            machine.mem_map(0x20000000, 0x2000)
            output = 0xF0300000
            if custom:
                machine.mem_write(0xF021AB44 + 0x2C, struct.pack("<I", output))
                machine.mem_write(0xF021AB44, b"\xff")
            else:
                machine.mem_write(0xF021ADBC + 0x10, struct.pack("<I", output))
                machine.mem_write(0xF021ADBC + 2, b"\xff")
            published = []

            def hook(current, address, size, context):
                value = current.reg_read(UC_ARM_REG_R0)
                other = current.reg_read(UC_ARM_REG_R1)
                if address in (0x1016B474, 0x1016B4DC):
                    result = value
                elif address == 0x10227C80:
                    result = float_bits(value)
                elif address == 0x101BDCF8:
                    result = float_bits(bits_float(value) * bits_float(other))
                elif address == 0x101BDB84:
                    result = float_bits(bits_float(value) + bits_float(other))
                elif address == 0x10226AF8:
                    result = int(bits_float(value))
                elif address == 0x101DA614:
                    published.append(value)
                    result = value
                else:
                    return
                current.reg_write(UC_ARM_REG_R0, result)
                current.reg_write(UC_ARM_REG_PC, current.reg_read(UC_ARM_REG_LR))

            machine.hook_add(UC_HOOK_CODE, hook)
            machine.reg_write(UC_ARM_REG_R0, code)
            machine.reg_write(UC_ARM_REG_SP, 0x20000FF0)
            machine.reg_write(UC_ARM_REG_LR, 0x20001001)
            machine.emu_start(entry | 1, 0x20001000, count=200)
            expected = min(code, 100) if percent_patch or direct_soc else int(min(code, 12) * 100 / 12 + 0.5)
            assert published == [expected], (hex(entry), code, published, expected)
            assert machine.mem_read(output, 1)[0] == expected
            if code in (0, 1, 5, 6, 7, 11, 12, 13, 42, 50, 99, 100, 255):
                print(f"callback={entry:#x} code={code:3} percent={expected:3} PASS (filter/library stubs)")
        print(f"callback={entry:#x}: all 256 byte values PASS")


def simulate_battery_filter(data, base):
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

    def float_bits(value):
        return struct.unpack("<I", struct.pack("<f", value))[0]

    def bits_float(value):
        return struct.unpack("<f", struct.pack("<I", value))[0]

    def run_ring_filter(sequence):
        ring = [0] * 500
        total = 0
        count = 0
        position = 0
        outputs = []
        for value in sequence:
            if count < 500:
                ring[count] = value
                total += value
                count += 1
            else:
                old = ring[position]
                ring[position] = value
                total = total - old + value
                position = (position + 1) % 500
            outputs.append(int(total / count + 0.5))
        return outputs

    def run_n22_filter(sequence):
        machine = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        machine.mem_map(base & ~4095, (len(data) + 4095) & ~4095)
        machine.mem_write(base, data)
        machine.mem_map(0xF0000000, 0x400000)
        machine.mem_map(0x20000000, 0x2000)
        state = 0xF021AB44
        machine.mem_write(state, bytes(0x100))

        def hook(current, address, size, context):
            value = current.reg_read(UC_ARM_REG_R0)
            other = current.reg_read(UC_ARM_REG_R1)
            if address == 0x10227C80:
                result = float_bits(value)
            elif address == 0x101BDE1C:
                result = float_bits(bits_float(value) / bits_float(other))
            elif address == 0x101BDB84:
                result = float_bits(bits_float(value) + bits_float(other))
            elif address == 0x10226AF8:
                result = int(bits_float(value))
            else:
                return
            current.reg_write(UC_ARM_REG_R0, result)
            current.reg_write(UC_ARM_REG_PC, current.reg_read(UC_ARM_REG_LR))

        machine.hook_add(UC_HOOK_CODE, hook)
        outputs = []
        for value in sequence:
            machine.reg_write(UC_ARM_REG_R0, value)
            machine.reg_write(UC_ARM_REG_SP, 0x20000FF0)
            machine.reg_write(UC_ARM_REG_LR, 0x20001001)
            machine.emu_start(0x1016B475, 0x20001000, count=100)
            outputs.append(machine.reg_read(UC_ARM_REG_R0))
        return outputs

    window = 500
    for mode, high, low in (
        ("coarse-0..12 input", 12, 6),
        ("direct-0..100 input", 100, 50),
    ):
        sequence = [high] * window + [low] * window
        filtered = run_n22_filter(sequence)
        if high == 12:
            display = [int(value * 100.0 / 12.0 + 0.5) for value in filtered]
        else:
            display = filtered
        transition = next(index for index in range(window, len(display)) if display[index] < 100)
        updates = []
        previous = display[window - 1]
        for index in range(window, len(display)):
            if display[index] != previous:
                updates.append((index - window + 1, display[index]))
                previous = display[index]
        assert filtered[window - 1] == high
        assert filtered[-1] == low
        assert display[-1] == 50
        assert all(left[1] > right[1] for left, right in zip(updates, updates[1:]))
        print(f"{mode}: emulated output after stable full charge={display[window - 1]}%, after 500 low samples={display[-1]}%")
        print(f"{mode}: first visible drop at {transition - window + 1} low samples; first 8 updates={updates[:8]}")
        print(f"{mode}: visible steps={len(updates)}; all updates monotonically decrease (N22 filter ARM executed; float helpers stubbed)")

        ring_model = run_ring_filter(sequence)
        assert filtered == ring_model, f"{mode} ARM filter differs from ring recurrence"


def disassemble(data, base, start, length):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    decoder.skipdata = True
    for instruction in decoder.disasm(data[start:start + length], base + start):
        suffix = ""
        if instruction.mnemonic == "ldr" and "pc" in instruction.op_str:
            displacement = instruction.operands[1].mem.disp
            offset = ((instruction.address + 4) & ~3) + displacement - base
            if 0 <= offset <= len(data) - 4:
                value = struct.unpack_from("<I", data, offset)[0]
                suffix = f" ; [{base + offset:#x}]={value:#x}"
                target = value - base
                if 0 <= target < len(data):
                    text = data[target:target + 100].split(b"\0")[0]
                    if text and all(32 <= byte < 127 for byte in text):
                        suffix += f" {text.decode('ascii')}"
        print(f"{instruction.address:08x}: {instruction.bytes.hex():10} {instruction.mnemonic:7} {instruction.op_str}{suffix}")


def inspect_references(data, base, pattern):
    for match in re.finditer(rb"[ -~]{6,}", data):
        if not re.search(pattern.encode("ascii"), match.group(), re.IGNORECASE):
            continue
        address = base + match.start()
        references = [ref.start() for ref in re.finditer(re.escape(struct.pack("<I", address)), data)]
        print(f"{address:#x} {match.group().decode('ascii')}: refs={[hex(base + ref) for ref in references]}")
        for offset in range(max(0, match.start() - 1024), match.start(), 2):
            opcode = struct.unpack_from("<H", data, offset)[0]
            if opcode & 0xF800 == 0xA000:
                target = ((base + offset + 4) & ~3) + (opcode & 255) * 4
                if target == address:
                    print(f"ADR reference at {base + offset:#x}")


def inspect_image(path):
    data = path.read_bytes()
    print(f"\nFILE {path.name} size={len(data)}")
    print(f"sha256={hashlib.sha256(data).hexdigest()}")
    print(f"header={data[:128].hex(' ')}")
    pattern = rb"(?i)tong|tsdz|battery|soc_|bms|uart|ekd01|motor|capacity|checksum|parse"
    strings = [
        match for match in re.finditer(rb"[ -~]{6,}", data)
        if re.search(pattern, match.group())
    ]
    print(f"matching strings={len(strings)}")
    for match in strings[:200]:
        print(f"{match.start():08x}: {match.group().decode('ascii')[:220]}")
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("package", type=pathlib.Path)
    parser.add_argument("backup", type=pathlib.Path)
    parser.add_argument("--base", type=lambda value: int(value, 0), default=0x10050000)
    parser.add_argument("--xref")
    parser.add_argument("--word", type=lambda value: int(value, 0), action="append")
    parser.add_argument("--uses", type=lambda value: int(value, 0))
    parser.add_argument("--calls", type=lambda value: int(value, 0))
    parser.add_argument("--verify-battery", action="store_true")
    parser.add_argument("--verify-percent-patch", action="store_true")
    parser.add_argument("--simulate-filter", action="store_true")
    parser.add_argument("--start", type=lambda value: int(value, 0))
    parser.add_argument("--length", type=lambda value: int(value, 0), default=0x200)
    args = parser.parse_args()
    main_image = args.package / "EKD01_TB_PCB01_gsm_MT2502_S00.EKD01_TB_N22.bin"
    if args.simulate_filter:
        simulate_battery_filter(main_image.read_bytes(), args.base)
        return
    if args.verify_battery or args.verify_percent_patch:
        verify_battery(main_image.read_bytes(), args.base, args.verify_percent_patch)
        return
    if args.xref or args.word or args.uses is not None or args.calls is not None or args.start is not None:
        data = main_image.read_bytes()
        if args.xref:
            inspect_references(data, args.base, args.xref)
        for value in args.word or []:
            matches = re.finditer(re.escape(struct.pack("<I", value)), data)
            print(f"word={value:#x}: refs={[hex(args.base + match.start()) for match in matches]}")
        if args.uses is not None:
            for offset in range(0, len(data) - 4, 2):
                opcode = struct.unpack_from("<H", data, offset)[0]
                if opcode & 0xF800 == 0x4800:
                    literal = ((offset + args.base + 4) & ~3) + (opcode & 255) * 4 - args.base
                    if literal <= len(data) - 4 and struct.unpack_from("<I", data, literal)[0] == args.uses:
                        print(f"literal load at {args.base + offset:#x}, r{(opcode >> 8) & 7}")
        if args.calls is not None:
            from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
            decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
            for offset in range(0, len(data) - 4, 2):
                opcode = struct.unpack_from("<H", data, offset)[0]
                if opcode & 0xF800 != 0xF000:
                    continue
                for instruction in decoder.disasm(data[offset:offset + 4], args.base + offset):
                    if instruction.mnemonic in ("bl", "blx") and instruction.op_str == f"#{args.calls:#x}":
                        print(f"call at {instruction.address:#x}: {instruction.mnemonic} {instruction.op_str}")
        if args.start is not None:
            disassemble(data, args.base, args.start, args.length)
        return
    print(f"capstone available={importlib.util.find_spec('capstone') is not None}")
    backup = inspect_image(args.backup)
    for path in sorted(args.package.iterdir()):
        if not path.is_file() or path.suffix == ".cfg":
            continue
        data = inspect_image(path)
        if path == main_image:
            overlap = min(len(data), max(0, len(backup) - 0x50000))
            differences = sum(left != right for left, right in zip(data[:overlap], backup[0x50000:]))
            print(f"main overlap={overlap} differing bytes={differences} missing tail={len(data) - overlap}")
        for offset in (0, 0x100, 0x1000, 0x10000):
            sample = data[offset:offset + 128]
            if len(sample) == 128 and len(set(sample)) > 16:
                print(f"package sample at {offset:#x}: backup match={backup.find(sample):#x}")


if __name__ == "__main__":
    main()