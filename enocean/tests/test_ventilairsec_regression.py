"""Test case for ventilairsec chained packet regression from real logs.

This test validates the fix for the ventilairsec chained packet parsing issue
where continuation frames were not properly extracting bytes 2-3 as payload data.

Real device logs from 2026-02-02 showed:
- First frame (idx=0): stores 6 bytes, total_length=17
- Continuation 1 (idx=1): should add 8 bytes (including bytes 2-3)
- Continuation 2 (idx=2): should add 4 bytes (including bytes 2-3)
- Total: 6 + 8 + 4 = 18 bytes, truncated to 17 expected
"""

from enocean.protocol.packet import Packet, _CHAINED_STORAGE
from enocean.protocol.constants import PACKET, RORG, PARSE_RESULT
from enocean.protocol import crc8


def _make_frame(data, opt_data, packet_type=PACKET.RADIO_ERP1):
    """Helper to create a complete EnOcean frame with proper CRCs."""
    data_len = len(data)
    opt_len = len(opt_data)

    frame = [0x55]  # Start byte
    frame.append(data_len >> 8)  # Data length high byte
    frame.append(data_len & 0xFF)  # Data length low byte
    frame.append(opt_len)  # Optional data length
    frame.append(packet_type)  # Packet type
    frame.append(crc8.calc(frame[1:5]))  # Header CRC
    frame.extend(data)
    frame.extend(opt_data)
    frame.append(crc8.calc(frame[6 : 6 + data_len + opt_len]))  # Data CRC

    return frame


class TestVentilairsecRegression:
    """Test for the real-world ventilairsec chained packet issue."""

    def test_ventilairsec_3part_chain_from_real_logs(self):
        """Test reassembly of ventilairsec chain from real 2026-02-02 capture.

        Device: 042058A5
        Sequence: 4
        Expected total: 17 bytes

        Real frame data from logs (with CRCs added for testing):
        - Frame 1 (idx=0): 40 40 00 11 d1 07 90 01 02 00 04 20 58 a5 80
        - Frame 2 (idx=1): 40 41 04 20 1c 1c 00 01 00 00 04 20 58 a5 80
        - Frame 3 (idx=2): 40 42 00 00 00 00 04 20 58 a5 80
        """
        _CHAINED_STORAGE.clear()

        # Part 1 (idx=0): seq=4, total_len=17 bytes (encoded as "0" + "17" = "017")
        # Payload: d1 07 90 01 02 00 (6 bytes)
        data1 = [
            0x40,  # RORG: CHAINED_VENTILAIRSEC
            0x40,  # seq=4 (bits 7-4), idx=0 (bits 3-0)
            0x00,  # total_len high byte: "0"
            0x11,  # total_len low byte: "17" (0x11 = 17 decimal)
            0xD1,
            0x07,
            0x90,
            0x01,
            0x02,
            0x00,  # First 6 bytes of payload
            0x04,
            0x20,
            0x58,
            0xA5,  # Sender
            0x80,  # Status
        ]
        opt_data1 = [0x01, 0xFF, 0x9C, 0x80, 0x80, 0x47, 0x00]
        frame1 = _make_frame(data1, opt_data1)

        result1, _, packet1 = Packet.parse_msg(frame1)
        assert result1 == PARSE_RESULT.OK
        assert packet1 is None  # First chunk should be suppressed
        assert "042058A5.4" in _CHAINED_STORAGE
        assert _CHAINED_STORAGE["042058A5.4"]["total_len"] == 17
        assert _CHAINED_STORAGE["042058A5.4"]["data"] == [
            0xD1,
            0x07,
            0x90,
            0x01,
            0x02,
            0x00,
        ]

        # Part 2 (idx=1): continuation frame
        # Payload: 04 20 1c 1c 00 01 00 00 (8 bytes, including bytes 2-3)
        data2 = [
            0x40,  # RORG: CHAINED_VENTILAIRSEC
            0x41,  # seq=4 (bits 7-4), idx=1 (bits 3-0)
            0x04,
            0x20,  # Bytes 2-3 ARE payload in continuation frames
            0x1C,
            0x1C,
            0x00,
            0x01,
            0x00,
            0x00,  # Rest of payload
            0x04,
            0x20,
            0x58,
            0xA5,  # Sender
            0x80,  # Status
        ]
        opt_data2 = [0x01, 0xFF, 0x9C, 0x80, 0x80, 0x49, 0x00]
        frame2 = _make_frame(data2, opt_data2)

        result2, _, packet2 = Packet.parse_msg(frame2)
        assert result2 == PARSE_RESULT.OK
        assert packet2 is None  # Continuation should be suppressed
        # After continuation 1: 6 + 8 = 14 bytes
        assert len(_CHAINED_STORAGE["042058A5.4"]["data"]) == 14
        expected_after_cont1 = [
            0xD1,
            0x07,
            0x90,
            0x01,
            0x02,
            0x00,
            0x04,
            0x20,
            0x1C,
            0x1C,
            0x00,
            0x01,
            0x00,
            0x00,
        ]
        assert _CHAINED_STORAGE["042058A5.4"]["data"] == expected_after_cont1

        # Part 3 (idx=2): final chunk
        # Payload: 00 00 00 00 (4 bytes, including bytes 2-3)
        data3 = [
            0x40,  # RORG: CHAINED_VENTILAIRSEC
            0x42,  # seq=4 (bits 7-4), idx=2 (bits 3-0)
            0x00,
            0x00,  # Bytes 2-3 ARE payload in continuation frames
            0x00,
            0x00,  # Rest of payload
            0x04,
            0x20,
            0x58,
            0xA5,  # Sender
            0x80,  # Status
        ]
        opt_data3 = [0x01, 0xFF, 0x9C, 0x80, 0x80, 0x4A, 0x00]
        frame3 = _make_frame(data3, opt_data3)

        result3, _, packet3 = Packet.parse_msg(frame3)
        assert result3 == PARSE_RESULT.OK
        # Final chunk should trigger reassembly and return complete packet
        assert packet3 is not None
        # Should be an MSC packet (0xD1) after reassembly
        assert packet3.rorg == RORG.MSC
        # Storage should be cleaned up after successful reassembly
        assert "042058A5.4" not in _CHAINED_STORAGE

    def test_ventilairsec_2part_chain(self):
        """Test reassembly of a 2-part ventilairsec chain."""
        _CHAINED_STORAGE.clear()

        # Part 1 (idx=0): seq=3, total_len=20
        # Payload starts with 0xD1 (RORG.MSC) followed by MSC data
        data1 = [
            0x40,
            0x30,  # RORG, seq=3, idx=0
            0x00,
            0x14,  # total_len = 20 (0x14 = 20 decimal)
            0xD1,  # RORG.MSC (first byte of payload)
            0x07,
            0x93,  # Manufacturer code (Aldes = 0x0793)
            0x12,
            0x11,
            0x10,  # MSC data (6 bytes total)
            0x01,
            0x02,
            0x03,
            0x04,  # Sender
            0x50,  # Status
        ]
        opt_data1 = [0x01, 0xFF, 0x9C, 0x80, 0x80, 0x50, 0x00]
        frame1 = _make_frame(data1, opt_data1)

        result1, _, packet1 = Packet.parse_msg(frame1)
        assert result1 == PARSE_RESULT.OK
        assert packet1 is None

        # Part 2 (idx=1): continuation with 8 bytes (total: 14/20 bytes, need 6 more)
        # Bytes 2-9 are continuation payload
        data2 = [
            0x40,
            0x31,  # RORG, seq=3, idx=1
            0x10,
            0x1F,
            0xFF,
            0xFF,
            0x0E,
            0x00,
            0x00,
            0x00,  # Continuation payload (8 bytes)
            0x01,
            0x02,
            0x03,
            0x04,  # Sender
            0x50,  # Status
        ]
        opt_data2 = [0x01, 0xFF, 0x9C, 0x80, 0x80, 0x51, 0x00]
        frame2 = _make_frame(data2, opt_data2)

        result2, _, packet2 = Packet.parse_msg(frame2)
        assert result2 == PARSE_RESULT.OK
        # Still incomplete: 6 + 8 = 14 bytes, need 20
        assert packet2 is None

        # Part 3 (idx=2): final chunk with 6 bytes to reach 20
        # Bytes 2-7 are final payload
        data3 = [
            0x40,
            0x32,  # RORG, seq=3, idx=2
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,  # Final payload (6 bytes)
            0x01,
            0x02,
            0x03,
            0x04,  # Sender
            0x50,  # Status
        ]
        opt_data3 = [0x01, 0xFF, 0x9C, 0x80, 0x80, 0x52, 0x00]
        frame3 = _make_frame(data3, opt_data3)

        result3, _, packet3 = Packet.parse_msg(frame3)
        assert result3 == PARSE_RESULT.OK
        # Should reassemble: 6 + 8 + 6 = 20 bytes
        assert packet3 is not None
        assert packet3.rorg == RORG.MSC
