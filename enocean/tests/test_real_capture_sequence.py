import logging

from enocean.protocol.packet import Packet, _CHAINED_STORAGE
from enocean.protocol.constants import PACKET, PARSE_RESULT
from enocean.protocol import crc8


def build_frame(data_bytes, opt_bytes):
    data_len = len(data_bytes)
    opt_len = len(opt_bytes)

    ords = [0x55, (data_len >> 8) & 0xFF, data_len & 0xFF, opt_len, int(PACKET.RADIO_ERP1)]
    ords.append(crc8.calc(ords[1:5]))
    ords.extend(data_bytes)
    ords.extend(opt_bytes)
    ords.append(crc8.calc(ords[6:]))
    return bytearray(ords)


def test_real_capture_chained_reassembly():
    """Replay real captured chained frames and final MSC packet.

    Ensures chained frames are suppressed while incomplete and the final
    MSC (D1) packet is parsed and propagated.
    """
    logging.getLogger("enocean.protocol.packet").setLevel(logging.DEBUG)

    # Ensure clean storage
    _CHAINED_STORAGE.clear()

    opt = [0x01, 0xFF, 0x9C, 0x80, 0x80, 0x4A, 0x00]

    # Frame 1: CHAINED Ventilairsec first frame (seq=12, idx=0)
    f1 = [0x40, 0xC0, 0x00, 0x11, 0xD1, 0x07, 0x90, 0x01, 0x02, 0x00, 0x04, 0x20, 0x58, 0xA5, 0x80]
    # Frame 2: CHAINED continuation (idx=1)
    f2 = [0x40, 0xC1, 0x04, 0x20, 0x1C, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x04, 0x20, 0x58, 0xA5, 0x80]
    # Frame 3: CHAINED continuation (idx=2)
    f3 = [0x40, 0xC2, 0x00, 0x00, 0x00, 0x04, 0x20, 0x58, 0xA5, 0x80]

    # Final MSC packet observed shortly after
    d1 = [
        0xD1,
        0x07,
        0x98,
        0x04,
        0x20,
        0x74,
        0xC9,
        0x02,
        0x01,
        0x09,
        0x04,
        0x20,
        0x58,
        0xA5,
        0x00,
    ]

    # Parse frames in order
    for frame in (f1, f2):
        result, remaining, packet = Packet.parse_msg(build_frame(frame, opt))
        assert result == PARSE_RESULT.OK
        # Intermediate chained frames must be suppressed (None)
        assert packet is None

    # Final fragment should trigger reassembly and return the reassembled packet
    result, remaining, packet = Packet.parse_msg(build_frame(f3, opt))
    assert result == PARSE_RESULT.OK
    assert packet is not None
    assert packet.rorg == 0xD1

    # After the chained fragments, another MSC D1 packet should parse normally
    result, remaining, packet = Packet.parse_msg(build_frame(d1, opt))
    assert result == PARSE_RESULT.OK
    assert packet is not None
    # Confirm it's an MSC radio packet
    assert packet.rorg == 0xD1
    # Storage may or may not be cleaned up depending on how the final
    # reassembly/completion was delivered; ensure at least the final packet
    # was parsed successfully above.
