import logging

import pytest

from enocean.protocol.packet import Packet, RadioPacket
from enocean.protocol.constants import RORG, PARSE_RESULT, PACKET
from enocean.protocol import crc8


def test_build_and_parse_radio_packet_logs(caplog):
    """Build a RadioPacket, convert to serial frame and reparse it, logging fields."""
    # Enable DEBUG logs for packet parsing
    caplog.set_level(logging.DEBUG)
    logging.getLogger("enocean.protocol.packet").setLevel(logging.DEBUG)

    # Create a simple RPS radio packet (supported by Packet.create)
    pkt = RadioPacket.create(
        RORG.RPS,  # supported RORG for create
        0x00,
        0x00,
        destination=[0x01, 0x02, 0x03, 0x04],
        sender=[0x10, 0x11, 0x12, 0x13],
    )

    # Build serial frame (list of ords) and convert to bytearray for parse_msg
    ords = pkt.build()
    frame = bytearray(ords)

    # Parse the raw serial frame
    result, remaining, parsed = Packet.parse_msg(frame)

    assert result == PARSE_RESULT.OK
    assert parsed is not None
    assert isinstance(parsed, Packet)

    # Log some helpful fields to verify visibility in test output
    logging.getLogger("enocean.protocol.packet").debug("Re-parsed packet: %s", parsed)
    if hasattr(parsed, "sender_hex"):
        logging.getLogger("enocean.protocol.packet").debug(
            "sender=%s dest=%s dBm=%s parsed=%s",
            getattr(parsed, "sender_hex", None),
            getattr(parsed, "destination_hex", None),
            getattr(parsed, "dBm", None),
            getattr(parsed, "parsed", None),
        )


def test_parse_real_raw_frames_from_logs():
    """Reconstruct serial frames from captured data/optional pairs and reparse with Packet.parse_msg."""
    logging.getLogger("enocean.protocol.packet").setLevel(logging.DEBUG)

    samples = [
        (
            [
                0x40,
                0x42,
                0x0,
                0x0,
                0x0,
                0x0,
                0x4,
                0x20,
                0x58,
                0xA5,
                0x80,
            ],
            [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x50, 0x0],
        ),
        (
            [
                0xD1,
                0x7,
                0x91,
                0x0,
                0x5A,
                0x0,
                0x4,
                0x3,
                0x4,
                0x20,
                0x58,
                0xA5,
                0x0,
            ],
            [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x52, 0x0],
        ),
        (
            [
                0x40,
                0x80,
                0x0,
                0x10,
                0xD1,
                0x7,
                0x93,
                0x12,
                0x11,
                0x10,
                0x4,
                0x20,
                0x58,
                0xA5,
                0x80,
            ],
            [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x4F, 0x0],
        ),
        (
            [
                0x40,
                0xC0,
                0x0,
                0x10,
                0xD1,
                0x7,
                0x94,
                0x1,
                0x1,
                0x0,
                0x4,
                0x20,
                0x58,
                0xA5,
                0x80,
            ],
            [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x4F, 0x0],
        ),
        (
            [
                0x40,
                0xC1,
                0xFA,
                0x18,
                0xA,
                0x7,
                0x61,
                0x30,
                0x0,
                0x0,
                0x4,
                0x20,
                0x58,
                0xA5,
                0x80,
            ],
            [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x50, 0x0],
        ),
        (
            [
                0x40,
                0xC2,
                0x0,
                0x0,
                0x0,
                0x4,
                0x20,
                0x58,
                0xA5,
                0x80,
            ],
            [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x4F, 0x0],
        ),
        (
            [
                0x40,
                0x40,
                0x0,
                0x10,
                0xD1,
                0x7,
                0x95,
                0x0,
                0x7,
                0x63,
                0x4,
                0x20,
                0x58,
                0xA5,
                0x80,
            ],
            [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x50, 0x0],
        ),
        (
            [
                0x40,
                0x41,
                0x1,
                0x7,
                0x64,
                0x2,
                0xA,
                0x47,
                0x0,
                0x0,
                0x4,
                0x20,
                0x58,
                0xA5,
                0x80,
            ],
            [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x50, 0x0],
        ),
        (
            [
                0xD1,
                0x7,
                0x96,
                0xFF,
                0x0,
                0x0,
                0xFF,
                0x0,
                0x0,
                0x4,
                0x20,
                0x58,
                0xA5,
                0x0,
            ],
            [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x4F, 0x0],
        ),
        (
            [
                0xD1,
                0x7,
                0x97,
                0x0,
                0xFF,
                0x0,
                0xFF,
                0x0,
                0xFF,
                0x64,
                0x4,
                0x20,
                0x58,
                0xA5,
                0x0,
            ],
            [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x4F, 0x0],
        ),
    ]

    for data_bytes, opt_bytes in samples:
        data_len = len(data_bytes)
        opt_len = len(opt_bytes)

        ords = [
            0x55,
            (data_len >> 8) & 0xFF,
            data_len & 0xFF,
            opt_len,
            int(PACKET.RADIO_ERP1),
        ]
        # header CRC
        ords.append(crc8.calc(ords[1:5]))
        ords.extend(data_bytes)
        ords.extend(opt_bytes)
        # data CRC
        ords.append(crc8.calc(ords[6:]))

        result, remaining, packet = Packet.parse_msg(bytearray(ords))
        assert result == PARSE_RESULT.OK

        # Intermediate fragments might be suppressed and return None
        if packet is None:
            continue

        logging.getLogger("enocean.protocol.packet").debug(
            "Parsed from log frame: %s", packet
        )

        # If EEP parsing produced parsed fields, verify structure and some expected values
        if getattr(packet, "parsed", None):
            assert isinstance(packet.parsed, dict)
            # Each parsed value should be a dict containing at least 'raw_value'
            for val in packet.parsed.values():
                assert isinstance(val, dict)
                assert "raw_value" in val

            # If command field is present and equals 0, assert BOOS and TEMPCHYDROR expectations
            cmd_entry = packet.parsed.get("CMD")
            if cmd_entry and cmd_entry.get("raw_value") == 0:
                boos = packet.parsed.get("BOOS")
                assert boos is not None and boos.get("raw_value") == 0

                temp = packet.parsed.get("TEMPCHYDROR")
                assert temp is not None
                # Accept either raw_value==18 or numeric 'value' == ~18
                raw_temp = temp.get("raw_value")
                val_temp = temp.get("value")
                assert raw_temp == 18 or (
                    isinstance(val_temp, (int, float)) and round(val_temp) == 18
                )


def test_parse_real_raw_frames_from_logs_chained():
    """Reconstruct serial frames from captured data/optional pairs and reparse with Packet.parse_msg.

    Note: The first sample (RORG=0x40 Ventilairsec CHAINED) contains an incomplete
    packet chunk. Incomplete CHAINED packets are suppressed and return None to
    prevent incomplete fragments from being propagated to listeners. This is the
    correct behavior.
    """
    from enocean.protocol.packet import _CHAINED_STORAGE
    _CHAINED_STORAGE.clear()
    
    logging.getLogger("enocean.protocol.packet").setLevel(logging.DEBUG)

    # Sample 1: Incomplete CHAINED packet (0x40 Ventilairsec) - should be suppressed
    chained_incomplete_data = [
        0x40,
        0x42,
        0x0,
        0x0,
        0x0,
        0x0,
        0x4,
        0x20,
        0x58,
        0xA5,
        0x80,
    ]
    chained_incomplete_opt = [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x50, 0x0]

    data_len = len(chained_incomplete_data)
    opt_len = len(chained_incomplete_opt)

    ords = [
        0x55,
        (data_len >> 8) & 0xFF,
        data_len & 0xFF,
        opt_len,
        int(PACKET.RADIO_ERP1),
    ]
    # header CRC
    ords.append(crc8.calc(ords[1:5]))
    ords.extend(chained_incomplete_data)
    ords.extend(chained_incomplete_opt)
    # data CRC
    ords.append(crc8.calc(ords[6:]))

    result, remaining, packet = Packet.parse_msg(bytearray(ords))
    assert result == PARSE_RESULT.OK
    # Incomplete CHAINED packets are suppressed (return None)
    assert packet is None
    logging.getLogger("enocean.protocol.packet").debug(
        "Incomplete CHAINED packet correctly suppressed: %s", packet
    )

    # Sample 2: Regular 4BS packet (0xA5) - should parse normally
    regular_4bs_data = [
        0xA5,
        0xD1,
        0x7,
        0x91,
        0x0,
        0x5A,
        0x0,
        0x4,
        0x3,
        0x4,
        0x20,
        0x58,
        0xA5,
        0x0,
    ]
    regular_4bs_opt = [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x52, 0x0]

    data_len = len(regular_4bs_data)
    opt_len = len(regular_4bs_opt)

    ords = [
        0x55,
        (data_len >> 8) & 0xFF,
        data_len & 0xFF,
        opt_len,
        int(PACKET.RADIO_ERP1),
    ]
    # header CRC
    ords.append(crc8.calc(ords[1:5]))
    ords.extend(regular_4bs_data)
    ords.extend(regular_4bs_opt)
    # data CRC
    ords.append(crc8.calc(ords[6:]))

    result, remaining, packet = Packet.parse_msg(bytearray(ords))
    assert result == PARSE_RESULT.OK
    assert packet is not None
    logging.getLogger("enocean.protocol.packet").debug(
        "Parsed from log frame: %s", packet
    )
