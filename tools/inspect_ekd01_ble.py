import argparse
from collections import Counter
from datetime import datetime, timezone
import struct
import zipfile


SNOOP_EPOCH_US = 0x00DCDDB30F2F8000


def timestamp_text(timestamp):
    return datetime.fromtimestamp((timestamp - SNOOP_EPOCH_US) / 1000000, timezone.utc).isoformat()


def records(data):
    if data[:8] != b"btsnoop\x00":
        raise ValueError("Not a BTSnoop file")
    version, link_type = struct.unpack_from(">II", data, 8)
    if version != 1 or link_type != 1002:
        raise ValueError(f"Unsupported BTSnoop version/link type: {version}/{link_type}")
    offset = 16
    while offset < len(data):
        if len(data) - offset < 24:
            raise ValueError(f"Truncated record header at {offset:#x}")
        original, included, flags, drops, timestamp = struct.unpack_from(">IIIIQ", data, offset)
        offset += 24
        if included > original or offset + included > len(data):
            raise ValueError(f"Invalid record length at {offset:#x}")
        yield timestamp, flags, drops, data[offset:offset + included]
        offset += included


def att_values(data):
    pending = {}
    for timestamp, flags, drops, packet in records(data):
        if len(packet) < 5 or packet[0] != 2:
            continue
        handle_flags, length = struct.unpack_from("<HH", packet, 1)
        if len(packet) != length + 5:
            continue
        key = (flags & 1, handle_flags & 0xFFF)
        boundary = (handle_flags >> 12) & 3
        payload = packet[5:]
        if boundary in (0, 2):
            pending[key] = bytearray(payload)
        elif boundary == 1 and key in pending:
            pending[key].extend(payload)
        else:
            continue
        buffer = pending[key]
        if len(buffer) < 4:
            continue
        total, channel = struct.unpack_from("<HH", buffer)
        if len(buffer) < total + 4:
            continue
        del pending[key]
        if len(buffer) != total + 4 or channel != 4:
            continue
        att = buffer[4:]
        if len(att) >= 3 and att[0] in (0x1B, 0x1D, 0x12, 0x52):
            attribute = struct.unpack_from("<H", att, 1)[0]
            yield timestamp, (*key, attribute), att[0], bytes(att[3:])


def application_frames(data):
    streams = {}
    for timestamp, key, opcode, value in att_values(data):
        buffer = streams.setdefault(key, bytearray())
        buffer.extend(value)
        while buffer:
            start = buffer.find(b"\x55\xaa")
            if start < 0:
                buffer[:] = buffer[-1:] if buffer[-1] == 0x55 else b""
                break
            if start:
                del buffer[:start]
            if len(buffer) < 9:
                break
            length = buffer[2] + 9
            if len(buffer) < length:
                break
            frame = bytes(buffer[:length])
            checksum = struct.unpack_from("<H", frame, length - 2)[0]
            if checksum != (~sum(frame[2:-2]) & 0xFFFF):
                del buffer[0]
                continue
            del buffer[:length]
            yield timestamp, key, frame


def self_test():
    def frame(battery):
        payload = bytearray(21)
        payload[7] = battery
        content = b"\x55\xaa\x15\x10\x11\x06\x01" + bytes(payload)
        return content + struct.pack("<H", ~sum(content[2:]) & 0xFFFF)

    def acl(boundary, payload):
        return b"\x02" + struct.pack("<HH", (boundary << 12) | 1, len(payload)) + payload

    def notification(value):
        att = b"\x1b\x04\x01" + value
        return struct.pack("<HH", len(att), 4) + att

    def capture(packets):
        data = bytearray(b"btsnoop\x00" + struct.pack(">II", 1, 1002))
        for index, packet in enumerate(packets):
            data.extend(struct.pack(">IIIIQ", len(packet), len(packet), 1, 0, SNOOP_EPOCH_US + index))
            data.extend(packet)
        return bytes(data)

    for battery in range(101):
        expected = frame(battery)
        l2cap = notification(expected)
        packets = [acl(2, l2cap[:11]), acl(1, l2cap[11:])]
        decoded = list(application_frames(capture(packets)))
        assert len(decoded) == 1 and decoded[0][2] == expected
        packets = [acl(2, notification(expected[:20])), acl(2, notification(expected[20:]))]
        decoded = list(application_frames(capture(packets)))
        assert len(decoded) == 1 and decoded[0][2] == expected
    corrupted = bytearray(frame(49))
    corrupted[-1] ^= 1
    decoded = list(application_frames(capture([acl(2, notification(bytes(corrupted) + frame(48)))])))
    assert len(decoded) == 1 and decoded[0][2] == frame(48)
    print("PASS: SOC 0..100, ACL fragmentation, characteristic fragmentation, bad checksum/resynchronization")


def inspect_capture(name, data, after=None):
    count = 0
    first = None
    last = None
    matches = Counter()
    battery = Counter()
    examples = []
    for timestamp, flags, drops, packet in records(data):
        if after is not None and timestamp < after:
            continue
        first = timestamp if first is None else first
        last = timestamp
        count += 1
        offset = packet.find(b"\x55\xaa")
        if offset < 0 or len(packet) - offset < 9:
            continue
        frame = packet[offset:]
        length = frame[2] + 9
        if len(frame) < length:
            continue
        frame = frame[:length]
        checksum = struct.unpack_from("<H", frame, length - 2)[0]
        if checksum != (~sum(frame[2:-2]) & 0xFFFF):
            continue
        matches[(frame[3], frame[4], frame[5], frame[6], frame[2])] += 1
        if frame[3:7] == b"\x10\x11\x06\x01" and len(frame) >= 18:
            battery[frame[14]] += 1
            if len(examples) < 3:
                examples.append((timestamp_text(timestamp), frame.hex(" ")))
    print(f"\n{name}: bytes={len(data)} records={count}")
    print(f"UTC first={timestamp_text(first) if first else 'none'} last={timestamp_text(last) if last else 'none'}")
    print(f"Checksum-valid complete frame signatures={dict(matches)}")
    print(f"Battery bytes={dict(sorted(battery.items()))}")
    print(f"First EKD01 telemetry examples={examples}")
    values = Counter()
    incomplete_examples = []
    for timestamp, key, opcode, value in att_values(data):
        if after is not None and timestamp < after:
            continue
        if value[:2] == b"\x55\xaa" and len(value) >= 7 and value[3] in (0x10, 0x11, 0xA5, 0xF1):
            values[(value[3], value[4], value[5], value[6], value[2], len(value))] += 1
            if value[3:7] == b"\x10\x11\x06\x01" and len(incomplete_examples) < 3:
                incomplete_examples.append((timestamp_text(timestamp), value.hex(" ")))
    rebuilt = Counter()
    rebuilt_battery = Counter()
    telemetry_fields = {}
    transitions = []
    previous_battery = None
    secondary_examples = []
    for timestamp, key, frame in application_frames(data):
        if after is not None and timestamp < after:
            continue
        rebuilt[(frame[3], frame[4], frame[5], frame[6], frame[2])] += 1
        if frame[3:7] == b"\xa5\x11\x04\x18":
            model = frame[7:-2].split(b"\0", 1)[0]
            if model.startswith(b"EKD01"):
                print(f"Model response UTC={timestamp_text(timestamp)} model={model.decode('ascii', errors='replace')}")
        if frame[3:6] == b"\x10\x11\x06":
            fields = telemetry_fields.setdefault((frame[6], frame[2]), [Counter() for _ in frame[7:-2]])
            for index, value in enumerate(frame[7:-2]):
                fields[index][value] += 1
        if frame[3:7] == b"\x10\x11\x06\x01" and len(frame) >= 18:
            rebuilt_battery[frame[14]] += 1
            if previous_battery != frame[14]:
                transitions.append((timestamp_text(timestamp), previous_battery, frame[14]))
            previous_battery = frame[14]
        if frame[3:7] == b"\x10\x11\x06\x09" and len(secondary_examples) < 3:
            secondary_examples.append((timestamp_text(timestamp), frame.hex(" ")))
    print(f"ATT value signatures (src,dst,op,reg,len,chunk)={dict(values)}")
    print(f"Reassembled frame signatures={dict(rebuilt)}")
    print(f"Reassembled battery bytes={dict(sorted(rebuilt_battery.items()))}")
    print(f"Telemetry chunk examples={incomplete_examples}")
    print(f"Battery transitions UTC={transitions}")
    print(f"Secondary telemetry examples={secondary_examples}")
    for signature, fields in sorted(telemetry_fields.items()):
        print(f"Telemetry fields reg/length={signature} (payload offsets, not absolute offsets):")
        for index, values in enumerate(fields):
            summary = sorted(values) if len(values) <= 16 else f"min={min(values)} max={max(values)} unique={len(values)}"
            print(f"  [{index}] {summary}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", nargs="?")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--after", help="Filter summaries to records at/after this ISO UTC timestamp")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.archive:
        parser.error("archive is required unless --self-test is selected")
    after = None
    if args.after:
        instant = datetime.fromisoformat(args.after.replace("Z", "+00:00"))
        if instant.tzinfo is None:
            parser.error("--after requires a timezone")
        after = int(instant.timestamp() * 1000000) + SNOOP_EPOCH_US
    with zipfile.ZipFile(args.archive) as archive:
        for name in archive.namelist():
            if "btsnoop_hci.log" in name:
                inspect_capture(name, archive.read(name), after)


if __name__ == "__main__":
    main()