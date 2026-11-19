import argparse
import hashlib
from pathlib import Path
import struct
import zipfile


BASE = 0x10050000
KNOWN_IMAGES = {
    "36dc7fe8716e30dd95f787aa2d96559643768679867bae9d0ffc290db02b3eb4",
    "9478720ca0510e7e76f2124fe0eca4f974c3216e6e0d4374b9bf74d411b139c4",
}


def verify_uart_power(data):
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
    from unicorn.arm_const import (
        UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP,
        UC_ARM_REG_LR, UC_ARM_REG_PC,
    )

    table = 0xF0300000
    frame_address = 0xF0310000
    flag_address = 0xF0320000
    decoder_state = 0xF0213924
    stop = 0x20001000
    for custom in (False, True):
        machine = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        machine.mem_map(BASE, (len(data) + 4095) & ~4095)
        machine.mem_write(BASE, data)
        machine.mem_map(0xF0000000, 0x400000)
        machine.mem_map(0x20000000, 0x2000)
        calls = []
        observed_handlers = {}

        def hook(current, address, size, context):
            value = current.reg_read(UC_ARM_REG_R0)
            if address == 0x10201A90:
                assert value == 0x8C, value
                current.reg_write(UC_ARM_REG_R0, table)
            elif address == 0x101BFE2C:
                assert value == table
                assert current.reg_read(UC_ARM_REG_R1) == 0x8C
                current.mem_write(table, bytes(0x8C))
            elif address == 0x10160DE8:
                calls.append(("power", value))
                return
            elif address in observed_handlers:
                calls.append((observed_handlers[address], value))
            else:
                return
            current.reg_write(UC_ARM_REG_PC, current.reg_read(UC_ARM_REG_LR))

        machine.hook_add(UC_HOOK_CODE, hook)

        def run(entry, value):
            machine.reg_write(UC_ARM_REG_R0, value)
            machine.reg_write(UC_ARM_REG_SP, 0x20000FF0)
            machine.reg_write(UC_ARM_REG_LR, stop | 1)
            machine.emu_start(entry | 1, stop, count=1000)
            assert machine.reg_read(UC_ARM_REG_PC) == stop, "Instruction budget exhausted"
            return machine.reg_read(UC_ARM_REG_R0)

        if custom:
            assert run(0x1014CE68, 0) == table
        else:
            run(0x1014DAD0, table)
        power_handler = struct.unpack("<I", machine.mem_read(table + 0x6C, 4))[0]
        assert power_handler == 0x10160DE9, hex(power_handler)
        assert data[0x10160DE8 - BASE:0x10160DEC - BASE] == bytes.fromhex("01 20 70 47")
        for offset, name in ((0x64, "battery"), (0x60, "error"), (0x5C, "speed"), (0x78, "whole-frame")):
            address = struct.unpack("<I", machine.mem_read(table + offset, 4))[0]
            if address:
                observed_handlers[address & ~1] = name
        machine.mem_write(decoder_state + 8, struct.pack("<I", flag_address))
        machine.mem_write(decoder_state + 0x14, struct.pack("<I", table))

        for power in range(256):
            battery = power % 101
            error = power % 16
            speed = (power * 257) ^ 0x5AA5
            frame = bytes((0x43, battery, 0, 0, power, error, speed & 255, speed >> 8))
            frame += bytes((sum(frame) & 255,))
            machine.mem_write(frame_address, frame)
            calls.clear()
            assert run(0x1012FCE8, frame_address) == 1
            expected = [("battery", battery), ("error", error), ("speed", speed), ("power", power)]
            if custom:
                expected.append(("whole-frame", frame_address))
            assert calls == expected, (custom, power, calls, expected)
            assert bytes(machine.mem_read(frame_address, len(frame))) == frame
        for invalid in ("header", "null", "disabled"):
            machine.mem_write(frame_address, bytes(9))
            machine.mem_write(flag_address, bytes((invalid == "disabled",)))
            if invalid == "disabled":
                machine.mem_write(frame_address, b"\x43")
            calls.clear()
            assert run(0x1012FCE8, 0 if invalid == "null" else frame_address) == 0
            assert not calls, (invalid, calls)
        print(f"PASS: {'custom' if custom else 'default'} initialization + UART decoder: all 256 power bytes, preserved fields, rejection gates")
    print("Power callback executes the original no-op. Other telemetry handlers and allocator/clear helpers are stubbed.")
    print("This verifies UART dispatch, not BLE forwarding, physical watts, or an end-to-end firmware patch.")


def verify_frame_builder(data):
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
    from unicorn.arm_const import (
        UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
        UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
    )

    machine = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    machine.mem_map(BASE, (len(data) + 4095) & ~4095)
    machine.mem_write(BASE, data)
    machine.mem_map(0xF0000000, 0x400000)
    machine.mem_map(0x20000000, 0x4000)
    payload_address = 0xF0310000
    stop = 0x20003000
    packets = []

    def hook(current, address, size, context):
        destination = current.reg_read(UC_ARM_REG_R0)
        source = current.reg_read(UC_ARM_REG_R1)
        length = current.reg_read(UC_ARM_REG_R2)
        if address == 0x101BFE2C:
            assert destination == 0xF02096B8 and source == 512
            current.mem_write(destination, bytes(source))
        elif address == 0x101DBE78:
            current.mem_write(destination, bytes(current.mem_read(source, length)))
        elif address == 0x10245D2C:
            assert destination == 3 and source == 0
            packets.append(bytes(current.mem_read(length, current.reg_read(UC_ARM_REG_R3))))
        else:
            return
        current.reg_write(UC_ARM_REG_PC, current.reg_read(UC_ARM_REG_LR))

    machine.hook_add(UC_HOOK_CODE, hook)
    for register, length in ((1, 21), (9, 16)):
        for power in range(256):
            payload = bytes((index * 17 + power) & 255 for index in range(length - 1)) + bytes((power,))
            machine.mem_write(payload_address, payload)
            machine.mem_write(0x20001FF0, struct.pack("<I", length))
            machine.reg_write(UC_ARM_REG_R0, 0x10)
            machine.reg_write(UC_ARM_REG_R1, 6)
            machine.reg_write(UC_ARM_REG_R2, register)
            machine.reg_write(UC_ARM_REG_R3, payload_address)
            machine.reg_write(UC_ARM_REG_SP, 0x20001FF0)
            machine.reg_write(UC_ARM_REG_LR, stop | 1)
            packets.clear()
            machine.emu_start(0x101E88A9, stop, count=2000)
            assert machine.reg_read(UC_ARM_REG_PC) == stop, "Framer instruction budget exhausted"
            prefix = bytes((0x55, 0xAA, length, 0x10, 0x11, 6, register)) + payload
            expected = prefix + struct.pack("<H", ~sum(prefix[2:]) & 0xFFFF)
            assert packets == [expected], (register, power, packets, expected)
            assert bytes(machine.mem_read(payload_address, length)) == payload
        print(f"PASS: actual N22 frame builder + checksum, reg={register:#x}, payload={length}, all 256 power-byte values")
    print("Framing test stubs only buffer clear/copy and the GATT transport; it does not establish a telemetry-field meaning.")


def thumb_branch(source, target, link):
    displacement = target - source - 4
    assert displacement % 2 == 0 and -(1 << 24) <= displacement < (1 << 24)
    sign = (displacement >> 24) & 1
    first = 0xF000 | (sign << 10) | ((displacement >> 12) & 0x3FF)
    jump_one = 1 ^ ((displacement >> 23) & 1) ^ sign
    jump_two = 1 ^ ((displacement >> 22) & 1) ^ sign
    second = (0xD000 if link else 0x9000) | (jump_one << 13) | (jump_two << 11) | ((displacement >> 1) & 0x7FF)
    return struct.pack("<HH", first, second)


def verify_power_extension(data, physical_image=None):
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
    from unicorn.arm_const import (
        UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
        UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_CPU_ARM_926,
    )

    code = 0x10800000
    scratch = 0xF03FF000
    table = 0xF0300000
    frame_address = 0xF0310000
    state = 0xF0321000
    settings = 0xF0322000
    battery_state = 0xF0323000
    flags = 0xF0324000
    stop = 0x20003000
    marker = 0xA1
    baseline_packets = {}
    for patched in (False, True):
        machine = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        if physical_image is not None:
            machine.ctl_set_cpu_model(UC_CPU_ARM_926)
        machine.mem_map(BASE, (len(data) + 4095) & ~4095)
        machine.mem_write(BASE, physical_image if patched and physical_image is not None else data)
        machine.mem_map(0xF0000000, 0x400000)
        machine.mem_map(0x20000000, 0x4000)
        packets = []
        getter_values = {
            0x1023A084: state,
            0x1023A204: settings,
            0x1021A8FC: battery_state,
            0x101F5E54: 0,
            0x10245CC4: flags,
        }
        uart_handlers = set()

        def hook(current, address, size, context):
            destination = current.reg_read(UC_ARM_REG_R0)
            source = current.reg_read(UC_ARM_REG_R1)
            length = current.reg_read(UC_ARM_REG_R2)
            if address in getter_values:
                current.reg_write(UC_ARM_REG_R0, getter_values[address])
            elif address in uart_handlers or address == 0x1015DDE0:
                pass
            elif address == 0x10051098:
                current.mem_write(source, struct.pack("<I", destination))
            elif address == 0x101BFE2C:
                assert 0 < source <= 512
                current.mem_write(destination, bytes(source))
            elif address == 0x101DBE78:
                assert length <= 512
                current.mem_write(destination, bytes(current.mem_read(source, length)))
            elif address == 0x10245D2C:
                assert destination == 3 and source == 0
                packets.append(bytes(current.mem_read(length, current.reg_read(UC_ARM_REG_R3))))
            else:
                return
            current.reg_write(UC_ARM_REG_PC, current.reg_read(UC_ARM_REG_LR))

        machine.hook_add(UC_HOOK_CODE, hook)

        def run(entry, value=0):
            machine.reg_write(UC_ARM_REG_R0, value)
            machine.reg_write(UC_ARM_REG_SP, 0x20001FF0)
            machine.reg_write(UC_ARM_REG_LR, stop | 1)
            machine.emu_start(entry | 1, stop, count=100000)
            assert machine.reg_read(UC_ARM_REG_PC) == stop, "Extension instruction budget exhausted"
            return machine.reg_read(UC_ARM_REG_R0)

        run(0x1014DAD0, table)
        for offset in (0x64, 0x60, 0x5C):
            uart_handlers.add(struct.unpack("<I", machine.mem_read(table + offset, 4))[0] & ~1)
        machine.mem_write(0xF0213924 + 8, struct.pack("<I", 0xF0320000))
        machine.mem_write(0xF0213924 + 0x14, struct.pack("<I", table))
        machine.mem_write(0xF021AB44 + 0x2C, struct.pack("<I", 0xF0330000))
        machine.mem_write(0xF0330002, struct.pack("<H", 500))
        recent_power = []
        samples = 0
        if patched and physical_image is None:
            assert data[0x10160DE8 - BASE:0x10160DEC - BASE] == bytes.fromhex("01 20 70 47")
            assert data[0x10197BDC - BASE:0x10197BE2 - BASE] == bytes.fromhex("28 0a f5 74 30 75")
            machine.mem_map(code, 0x1000)
            capture = struct.pack("<6HI", 0x4902, 0x7008, 0x2000 | marker, 0x7048, 0x2001, 0x4770, scratch)
            publish = struct.pack("<6HI", 0x4802, 0x8800, 0x74F0, 0x0A00, 0x7530, 0x4770, scratch)
            machine.mem_write(code, capture)
            machine.mem_write(code + 0x20, publish)
            machine.mem_write(0x10160DE8, thumb_branch(0x10160DE8, code, False))
            machine.mem_write(0x10197BDC, thumb_branch(0x10197BDC, code + 0x20, True) + b"\xc0\x46")
            run(0x101918B0)
            assert packets[-1][26:28] == bytes(2), "Power must remain unavailable until first UART sample"
            packets.clear()

        if patched and physical_image is not None:
            run(0x101918B0)
            assert packets[-1][26:28] == bytes(2), "Power must remain unavailable until first UART sample"
            packets.clear()

        for context in range(3):
            battery = (0, 58, 100)[context]
            speed = (0, 123, 65535)[context]
            assist = (0, 3, 5)[context]
            error = (0, 7, 12)[context]
            light = context % 2
            fixture = bytearray(0x20)
            struct.pack_into("<H", fixture, 0, speed)
            struct.pack_into("<II", fixture, 0xC, 0x15678, 0x15679)
            fixture[0x14:0x18] = bytes((assist, error, 0, 0x40 + context))
            machine.mem_write(state, bytes(fixture))
            machine.mem_write(settings + 1, b"\x05")
            machine.mem_write(battery_state, bytes((battery,)))
            machine.mem_write(flags + 0x15, b"\x01\x01")
            getter_values[0x101F5E54] = light
            for power in range(256):
                uart = bytes((0x43, battery, 0, 0, power, error, speed & 255, speed >> 8))
                uart += bytes((sum(uart) & 255,))
                machine.mem_write(frame_address, uart)
                assert run(0x1012FCE8, frame_address) == 1
                if physical_image is not None:
                    run(0x10160D94, frame_address)
                    recent_power.append(power * 10)
                    recent_power = recent_power[-10:]
                    samples += 1
                    processed = int(sum(recent_power) / len(recent_power) + 0.5)
                    assert struct.unpack("<H", machine.mem_read(0xF0330008, 2))[0] == processed
                packets.clear()
                run(0x101918B0)
                assert len(packets) == 1
                packet = packets[0]
                expected_payload = bytes((0x40 + context, 0, 3, light, error, assist, 5, battery, 1))
                expected_payload += struct.pack("<HII", speed, 0x15678, 0x15679)
                version = marker
                if patched and physical_image is not None:
                    version = 0x80 | (samples & 127)
                    expected_payload = expected_payload[:1] + bytes((version,)) + expected_payload[2:]
                    expected_payload += struct.pack("<H", processed)
                else:
                    expected_payload += bytes((power, version)) if patched else bytes(2)
                prefix = bytes.fromhex("55 aa 15 10 11 06 01") + expected_payload
                expected = prefix + struct.pack("<H", ~sum(prefix[2:]) & 0xFFFF)
                assert packet == expected, (patched, context, power, packet.hex(), expected.hex())
                if patched:
                    baseline = baseline_packets[context, power]
                    assert packet[:8] == baseline[:8] and packet[9:26] == baseline[9:26]
                    if physical_image is not None:
                        assert bytes(machine.mem_read(0xF0209481, 2)) == struct.pack("<H", processed)
                        assert machine.mem_read(0xF020946F, 1)[0] == version
                    else:
                        assert bytes(machine.mem_read(scratch, 2)) == bytes((power, version))
                    assert bytes(machine.mem_read(state, 0x20)) == bytes(fixture)
                    assert bytes(machine.mem_read(frame_address, 9)) == uart
                else:
                    baseline_packets[context, power] = packet
        print(f"PASS: {'in-memory extension' if patched else 'original'} UART-to-packet path: 768 cases, SOC/speed/assist/error/light/distance fields and checksum")
    if physical_image is not None:
        print("Protocol v2: payload[1] sample tag; payload[19:21] processed uint16 whole watts.")
    else:
        print("Legacy simulation: payload[19]=10W code; payload[20] format/sequence.")
    if physical_image is None:
        print("Only emulator memory is patched. Code/storage addresses are synthetic, NOT approved for physical firmware.")
    else:
        print("Actual patched-image instructions execute; storage is the existing primary payload tail. Hardware acceptance remains untested.")
    print("Getter results, unrelated UART handlers, memory helpers, ROM word serialization and GATT transport are stubbed.")


def verify_processed_power(data):
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
    from unicorn.arm_const import (
        UC_ARM_REG_R0, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_CPU_ARM_926,
    )

    machine = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    machine.ctl_set_cpu_model(UC_CPU_ARM_926)
    machine.mem_map(BASE, (len(data) + 4095) & ~4095)
    machine.mem_write(BASE, data)
    machine.mem_map(0xF0000000, 0x400000)
    machine.mem_map(0x20000000, 0x4000)
    machine.mem_write(0xF021AB44 + 0x2C, struct.pack("<I", 0xF0300000))
    machine.mem_write(0xF0300002, struct.pack("<H", 500))
    published = []

    def hook(current, address, size, context):
        if address == 0x1015DDE0:
            published.append(current.reg_read(UC_ARM_REG_R0))
            current.reg_write(UC_ARM_REG_PC, current.reg_read(UC_ARM_REG_LR))

    machine.hook_add(UC_HOOK_CODE, hook)
    for high_samples in range(11):
        for value in [26] * high_samples + [25] * (10 - high_samples):
            machine.mem_write(0xF0310000, bytes((0x43, 58, 0, 0, value, 0, 0, 0)))
            machine.reg_write(UC_ARM_REG_R0, 0xF0310000)
            machine.reg_write(UC_ARM_REG_SP, 0x20001FF0)
            machine.reg_write(UC_ARM_REG_LR, 0x20003001)
            machine.emu_start(0x10160D95, 0x20003000, count=100000)
            assert machine.reg_read(UC_ARM_REG_PC) == 0x20003000
        actual = struct.unpack("<H", machine.mem_read(0xF0300008, 2))[0]
        assert actual == 250 + high_samples, (high_samples, actual)
    assert published == list(range(250, 261)), published
    print("PASS: original processed power publishes every integer watt from 250 to 260 using only UART codes 25/26")
    print("Actual ARM arithmetic, ten-sample filter and publication gating execute; scale fixture=500, event transport stubbed.")


def verify_processed_capture(data):
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
    from unicorn.arm_const import (
        UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R4, UC_ARM_REG_SP,
        UC_ARM_REG_LR, UC_ARM_REG_PC, UC_CPU_ARM_926,
    )

    machine = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    machine.ctl_set_cpu_model(UC_CPU_ARM_926)
    machine.mem_map(BASE, (len(data) + 4095) & ~4095)
    machine.mem_write(BASE, data)
    machine.mem_map(0xF0000000, 0x400000)
    machine.mem_map(0x20000000, 0x4000)
    machine.mem_write(0xF021AB44 + 0x2C, struct.pack("<I", 0xF0300000))
    payload = bytearray(range(21))
    payload[1] = 0
    machine.mem_write(0xF020946E, bytes(payload))
    for watts in range(65536):
        machine.reg_write(UC_ARM_REG_R0, watts)
        machine.reg_write(UC_ARM_REG_R1, 0xF03FFFF0)
        machine.reg_write(UC_ARM_REG_R4, 0xF021AB44)
        machine.reg_write(UC_ARM_REG_SP, 0x20001FF0)
        machine.reg_write(UC_ARM_REG_LR, 0x20003001)
        machine.emu_start(0x1015DF33, 0x20003000, count=20)
        assert machine.reg_read(UC_ARM_REG_PC) == 0x20003000
        assert machine.reg_read(UC_ARM_REG_R0) == watts
        assert machine.reg_read(UC_ARM_REG_R4) == 0xF021AB44
        assert struct.unpack("<H", machine.mem_read(0xF0300008, 2))[0] == watts
        payload[1] = 0x80 | ((watts + 1) & 127)
        payload[19:21] = struct.pack("<H", watts)
        assert bytes(machine.mem_read(0xF020946E, 21)) == bytes(payload)
    print("PASS: physical capture helper preserves display store/r0/r4 and all other payload fields for all 65536 watt values")

    published = []

    def hook(current, address, size, context):
        if address == 0x1016B474:
            current.reg_write(UC_ARM_REG_PC, current.reg_read(UC_ARM_REG_LR))
        elif address == 0x101DA614:
            published.append(current.reg_read(UC_ARM_REG_R0))
            current.reg_write(UC_ARM_REG_PC, current.reg_read(UC_ARM_REG_LR))

    machine.hook_add(UC_HOOK_CODE, hook)
    for previous, suppressed, expected in ((58, 0, []), (57, 1, []), (57, 0, [58])):
        machine.mem_write(0xF021AB44, bytes((previous,)))
        machine.mem_write(0xF030000A, bytes((suppressed,)))
        before = bytes(machine.mem_read(0xF020946E, 21))
        published.clear()
        machine.reg_write(UC_ARM_REG_R0, 58)
        machine.reg_write(UC_ARM_REG_SP, 0x20001FF0)
        machine.reg_write(UC_ARM_REG_LR, 0x20003001)
        machine.emu_start(0x1015DF0D, 0x20003000, count=100)
        assert machine.reg_read(UC_ARM_REG_PC) == 0x20003000
        assert machine.reg_read(UC_ARM_REG_SP) == 0x20001FF0
        assert published == expected, (previous, suppressed, published)
        assert bytes(machine.mem_read(0xF020946E, 21)) == before
    print("PASS: reclaimed SOC code preserves unchanged/suppressed/published paths without entering the power helper")


def verify_capture(path):
    from inspect_ekd01_ble import application_frames

    primary = 0
    secondary = 0
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if "btsnoop_hci.log" not in name:
                continue
            for timestamp, key, frame in application_frames(archive.read(name)):
                if frame[3:7] == bytes.fromhex("10 11 06 01") and frame[2] == 21:
                    assert len(frame) == 30
                    assert frame[26:28] == bytes(2), "Capture uses the proposed extension bytes; review compatibility"
                    primary += 1
                elif frame[3:7] == bytes.fromhex("10 11 06 09"):
                    secondary += 1
    assert primary > 0, "No matching primary telemetry packets in capture"
    print(f"PASS: capture has {primary} checksum-valid primary packets with zero extension bytes; {secondary} secondary packets")
    print("Capture check establishes existing byte values, not measured power availability or hardware acceptance of the extension.")


def main():
    parser = argparse.ArgumentParser(description="Read-only offline checks of the verified EKD01 N22 power path.")
    parser.add_argument("image", type=Path, help="Original N22 or previously verified SOC-patched application image")
    parser.add_argument("--capture", type=Path, help="Optional private bugreport ZIP: check existing primary extension bytes")
    args = parser.parse_args()
    data = args.image.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest not in KNOWN_IMAGES:
        parser.error(f"Unsupported image SHA-256: {digest}")
    print(f"Input SHA-256: {digest}")
    verify_uart_power(data)
    verify_frame_builder(data)
    verify_power_extension(data)
    if args.capture:
        verify_capture(args.capture)


if __name__ == "__main__":
    main()