"""Tests for CHAINED packet (0x40 Ventilairsec) handling and reassembly."""

import pytest
from collections import OrderedDict

from enocean.protocol.packet import Packet, ChainedPacket
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


class TestChainedPacketDetection:
    """Test detection of CHAINED packets (0x40 and 0xC8)."""

    def test_detect_ventilairsec_chained_0x40(self):
        """Test that 0x40 RORG is detected as CHAINED packet."""
        data = [
            0x40,
            0x80,
            0x0,
            0x10,
            0xD1,
            0x7,
            0x95,
            0x0,
            0x8,
            0x64,
            0x4,
            0x20,
            0x58,
            0xA5,
            0x80,
        ]
        opt_data = [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x50, 0x0]

        frame = _make_frame(data, opt_data)
        result, remaining, packet = Packet.parse_msg(frame)

        assert result == PARSE_RESULT.OK
        # Incomplete chunks should be suppressed
        assert packet is None

    def test_detect_standard_chained_0xc8(self):
        """Test that standard 0xC8 RORG is detected as CHAINED packet."""
        # Standard CHAINED packet with similar structure to Ventilairsec
        data = [
            0xC8,
            0x80,
            0x0,
            0x10,
            0xD1,
            0x7,
            0x95,
            0x0,
            0x8,
            0x64,
            0x4,
            0x20,
            0x58,
            0xA5,
            0x80,
        ]
        opt_data = [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x50, 0x0]

        frame = _make_frame(data, opt_data)
        result, remaining, packet = Packet.parse_msg(frame)

        assert result == PARSE_RESULT.OK
        # Incomplete chunks should be suppressed
        assert packet is None


class TestIncompleteChainedPackets:
    """Test handling of incomplete CHAINED packets."""

    def test_first_chunk_not_propagated(self):
        """Test that first chunk of a chain is suppressed from propagation."""
        # First chunk (idx=0) of a multi-part message
        # Byte 1: 0x80 = seq=8, idx=0
        # Bytes 2-3: total length = 0x0010 (16 bytes)
        data = [
            0x40,
            0x80,
            0x0,
            0x10,
            0xD1,
            0x7,
            0x95,
            0x0,
            0x8,
            0x64,
            0x4,
            0x20,
            0x58,
            0xA5,
            0x80,
        ]
        opt_data = [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x50, 0x0]

        frame = _make_frame(data, opt_data)
        result, remaining, packet = Packet.parse_msg(frame)

        # Should return OK status (packet was processed) but packet should be None
        assert result == PARSE_RESULT.OK
        assert packet is None  # Incomplete, not propagated

    def test_continuation_chunk_not_propagated(self):
        """Test that continuation chunks are suppressed from propagation."""
        # Continuation chunk (idx=1) of a multi-part message
        # Byte 1: 0x81 = seq=8, idx=1
        data = [
            0x40,
            0x81,
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
        ]
        opt_data = [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x4D, 0x0]

        frame = _make_frame(data, opt_data)
        result, remaining, packet = Packet.parse_msg(frame)

        assert result == PARSE_RESULT.OK
        assert packet is None  # Continuation, not propagated


class TestChainedPacketReassembly:
    """Test reassembly of complete CHAINED packets into MSC."""

    def test_complete_chain_reassembly(self):
        """Test that a complete 3-part chain is reassembled into MSC packet."""
        # Clear any previous storage
        from enocean.protocol.packet import _CHAINED_STORAGE

        _CHAINED_STORAGE.clear()

        # Part 1 (idx=0): seq=4, total_len=0x0010 (16 bytes)
        data1 = [
            0x40,
            0x40,
            0x0,
            0x10,
            0xD1,
            0x7,
            0x95,
            0x0,
            0x8,
            0x64,
            0x4,
            0x20,
            0x58,
            0xA5,
            0x80,
        ]
        opt_data1 = [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x50, 0x0]
        frame1 = _make_frame(data1, opt_data1)

        result1, _, packet1 = Packet.parse_msg(frame1)
        assert result1 == PARSE_RESULT.OK
        assert packet1 is None  # First chunk suppressed

        # Part 2 (idx=1): continuation
        data2 = [
            0x40,
            0x41,
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
        ]
        opt_data2 = [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x4D, 0x0]
        frame2 = _make_frame(data2, opt_data2)

        result2, _, packet2 = Packet.parse_msg(frame2)
        assert result2 == PARSE_RESULT.OK
        assert packet2 is None  # Continuation suppressed

        # Part 3 (idx=2): final chunk - should trigger reassembly
        data3 = [
            0x40,
            0x42,
            0xFA,
            0x18,
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
        opt_data3 = [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x4E, 0x0]
        frame3 = _make_frame(data3, opt_data3)

        result3, _, packet3 = Packet.parse_msg(frame3)
        assert result3 == PARSE_RESULT.OK
        # Final chunk should trigger reassembly and return complete packet
        assert packet3 is not None
        # Should be an MSC packet (0xD1) after reassembly
        assert packet3.rorg == RORG.MSC

    def test_incomplete_chain_not_reassembled(self):
        """Test that incomplete chains don't get prematurely reassembled."""
        from enocean.protocol.packet import _CHAINED_STORAGE

        _CHAINED_STORAGE.clear()

        # Single chunk of a multi-part message
        data = [
            0x40,
            0x80,
            0x0,
            0x20,
            0xD1,
            0x7,
            0x95,
            0x0,
            0x8,
            0x64,
            0x4,
            0x20,
            0x58,
            0xA5,
            0x80,
        ]
        opt_data = [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x50, 0x0]

        frame = _make_frame(data, opt_data)
        result, _, packet = Packet.parse_msg(frame)

        assert result == PARSE_RESULT.OK
        # Only 6 bytes received, but total_len is 0x0020 (32 bytes)
        # Should not be reassembled
        assert packet is None


class TestChainedPacketAttributes:
    """Test that CHAINED packets properly track state."""

    def test_incomplete_packet_has_empty_parsed(self):
        """Test that incomplete CHAINED packets have empty parsed OrderedDict."""
        from enocean.protocol.packet import _CHAINED_STORAGE

        _CHAINED_STORAGE.clear()

        # Create an incomplete CHAINED packet directly
        data = [
            0x40,
            0x80,
            0x0,
            0x10,
            0xD1,
            0x7,
            0x95,
            0x0,
            0x8,
            0x64,
            0x4,
            0x20,
            0x58,
            0xA5,
            0x80,
        ]
        opt_data = [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x50, 0x0]

        packet = ChainedPacket(
            packet_type=PACKET.RADIO_ERP1, data=data, optional=opt_data
        )

        # Should have empty parsed dict (falsy when empty)
        assert isinstance(packet.parsed, OrderedDict)
        assert not packet.parsed  # Empty OrderedDict is falsy

    def test_chained_packet_sender_extraction(self):
        """Test that sender info is properly extracted from CHAINED packets."""
        from enocean.protocol.packet import _CHAINED_STORAGE

        _CHAINED_STORAGE.clear()

        # CHAINED packet with specific sender: 04:20:58:A5
        data = [
            0x40,
            0x80,
            0x0,
            0x10,
            0xD1,
            0x7,
            0x95,
            0x0,
            0x8,
            0x64,
            0x4,
            0x20,
            0x58,
            0xA5,
            0x80,
        ]
        opt_data = [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x50, 0x0]

        packet = ChainedPacket(
            packet_type=PACKET.RADIO_ERP1, data=data, optional=opt_data
        )

        # Sender is in last 5 bytes before status byte
        assert packet.sender == [0x04, 0x20, 0x58, 0xA5]


class TestChainedPacketOrdering:
    """Test handling of out-of-order CHAINED packets."""

    def test_out_of_order_chunks_warns(self):
        """Test that out-of-order chunks generate appropriate warnings."""
        from enocean.protocol.packet import _CHAINED_STORAGE

        _CHAINED_STORAGE.clear()

        # Skip first chunk, send continuation directly
        # This should fail gracefully and be suppressed
        data = [
            0x40,
            0x41,
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
        ]
        opt_data = [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x4D, 0x0]

        frame = _make_frame(data, opt_data)
        result, _, packet = Packet.parse_msg(frame)

        # Should return OK but packet should be None (no first chunk to attach to)
        assert result == PARSE_RESULT.OK
        assert packet is None


class TestChainedPacketStorage:
    """Test internal storage management for CHAINED packets."""

    def test_storage_cleanup_after_complete(self):
        """Test that storage is cleaned up after successful reassembly."""
        from enocean.protocol.packet import _CHAINED_STORAGE

        _CHAINED_STORAGE.clear()

        # Send a complete 2-part chain with matching lengths
        # Part 1 (idx=0): seq=0, total_len=0x000C (12 bytes of data)
        # Provides 6 bytes: 0xd1, 0x7, 0x95, 0x0, 0x8, 0x64
        data1 = [
            0x40,
            0x00,
            0x0,
            0x0C,
            0xD1,
            0x7,
            0x95,
            0x0,
            0x8,
            0x64,
            0x4,
            0x20,
            0x58,
            0xA5,
            0x80,
        ]
        opt_data1 = [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x50, 0x0]
        frame1 = _make_frame(data1, opt_data1)
        Packet.parse_msg(frame1)

        # Storage should have entry
        assert len(_CHAINED_STORAGE) == 1

        # Part 2 (idx=1, final): provides remaining 6 bytes to complete 12-byte total
        # Provides 6 bytes: 0x0a, 0x7, 0x61, 0x30, 0x0, 0x0
        data2 = [
            0x40,
            0x01,
            0x0,
            0x0C,
            0x0A,
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
        ]
        opt_data2 = [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x4D, 0x0]
        frame2 = _make_frame(data2, opt_data2)
        Packet.parse_msg(frame2)

        # Storage should be cleaned up after reassembly completes
        assert len(_CHAINED_STORAGE) == 0

    def test_multiple_chains_independent(self):
        """Test that multiple chains from different senders are independent."""
        from enocean.protocol.packet import _CHAINED_STORAGE

        _CHAINED_STORAGE.clear()

        # Chain 1 from sender 04:20:58:A5
        data1 = [
            0x40,
            0x80,
            0x0,
            0x10,
            0xD1,
            0x7,
            0x95,
            0x0,
            0x8,
            0x64,
            0x4,
            0x20,
            0x58,
            0xA5,
            0x80,
        ]
        opt_data1 = [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x50, 0x0]
        frame1 = _make_frame(data1, opt_data1)
        Packet.parse_msg(frame1)

        # Chain 2 from sender 04:20:74:C9
        data2 = [
            0x40,
            0x80,
            0x0,
            0x10,
            0xD1,
            0x7,
            0x95,
            0x0,
            0x8,
            0x64,
            0x4,
            0x20,
            0x74,
            0xC9,
            0x80,
        ]
        opt_data2 = [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x50, 0x0]
        frame2 = _make_frame(data2, opt_data2)
        Packet.parse_msg(frame2)

        # Should have 2 independent entries
        assert len(_CHAINED_STORAGE) == 2
        assert any("042058A5" in k for k in _CHAINED_STORAGE.keys())
        assert any("042074C9" in k for k in _CHAINED_STORAGE.keys())


class TestChainedPacketCompleteness:
    """Test detection of complete vs incomplete chains."""

    def test_empty_first_chunk(self):
        """Test handling of first chunk (idx=0) with empty data."""
        from enocean.protocol.packet import _CHAINED_STORAGE

        _CHAINED_STORAGE.clear()

        # Minimal valid frame
        data = [0x40, 0x00, 0x0, 0x05, 0x01, 0x02, 0x03, 0x04, 0x20, 0x58, 0xA5, 0x80]
        opt_data = [0x1, 0xFF, 0x9C, 0x80, 0x80, 0x50, 0x0]

        frame = _make_frame(data, opt_data)
        result, _, packet = Packet.parse_msg(frame)

        assert result == PARSE_RESULT.OK
        assert packet is None  # Still incomplete
        assert len(_CHAINED_STORAGE) == 1
