# -*- encoding: utf-8 -*-
from __future__ import print_function, unicode_literals, division, absolute_import

from enocean.protocol.packet import Packet
from enocean.protocol.constants import PACKET, PARSE_RESULT


def test_msc_telegram():
    ''' Test MSC telegram parsing '''
    msg = bytearray([
        0x55,
        0x00, 0x0F, 0x07, 0x01,
        0x2B,
        0xD1, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0x00, 0x80, 0x35, 0xC4, 0x00,
        0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0x4D, 0x00,
        0xc0])
    status, remainder, pkt = Packet.parse_msg(msg)
    assert status == PARSE_RESULT.OK
    assert pkt.packet_type == PACKET.RADIO_ERP1
    assert len(pkt.data) == 15
    assert len(pkt.optional) == 7
    assert pkt.status == 0x00
    assert pkt.repeater_count == 0
