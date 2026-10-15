# -*- encoding: utf-8 -*-
from __future__ import print_function, unicode_literals, division, absolute_import

from enocean.communicators.communicator import Communicator
from enocean.protocol.packet import Packet, RadioPacket
from enocean.protocol.constants import PACKET
from enocean.decorators import timing


@timing(1000)
def test_buffer():
    ''' Test buffer parsing for Communicator '''
    data = bytearray([
        0x55,
        0x00, 0x0A, 0x07, 0x01,
        0xEB,
        0xA5, 0x00, 0x00, 0x55, 0x08, 0x01, 0x81, 0xB7, 0x44, 0x00,
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x2D, 0x00,
        0x75
    ])
    com = Communicator()
    com._buffer.extend(data[0:5])
    com.parse()
    assert com.receive.qsize() == 0
    com._buffer.extend(data[5:])
    com.parse()
    assert com.receive.qsize() == 1


@timing(1000)
def test_send():
    ''' Test sending packets to Communicator '''
    com = Communicator()
    assert com.send('AJSNDJASNDJANSD') is False
    assert com.transmit.qsize() == 0
    assert com._get_from_send_queue() is None
    assert com.send(Packet(PACKET.COMMON_COMMAND, [0x08])) is True
    assert com.transmit.qsize() == 1
    assert isinstance(com._get_from_send_queue(), Packet)


def test_stop():
    com = Communicator()
    com.stop()
    assert com._stop_flag.is_set()


def test_callback():
    def callback(packet):
        assert isinstance(packet, RadioPacket)

    data = bytearray([
        0x55,
        0x00, 0x0A, 0x07, 0x01,
        0xEB,
        0xA5, 0x00, 0x00, 0x55, 0x08, 0x01, 0x81, 0xB7, 0x44, 0x00,
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x2D, 0x00,
        0x75
    ])

    com = Communicator(callback=callback)
    com._buffer.extend(data)
    com.parse()
    assert com.receive.qsize() == 0


def test_base_id():
    com = Communicator()
    assert com.base_id is None

    other_data = bytearray([
        0x55,
        0x00, 0x0A, 0x07, 0x01,
        0xEB,
        0xA5, 0x00, 0x00, 0x55, 0x08, 0x01, 0x81, 0xB7, 0x44, 0x00,
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x2D, 0x00,
        0x75
    ])

    response_data = bytearray([
        0x55,
        0x00, 0x05, 0x00, 0x02,
        0xCE,
        0x00, 0xFF, 0x87, 0xCA, 0x00,
        0xA3
    ])

    com._buffer.extend(other_data)
    com._buffer.extend(response_data)
    com.parse()
    assert com.base_id == [0xFF, 0x87, 0xCA, 0x00]
    assert com.receive.qsize() == 2


def _ute_teach_in_packet(db6):
    ''' Build a UTE teach-in request with the given DB6 (communication / response / request type bits). '''
    packet = Packet(
        PACKET.RADIO_ERP1,
        data=[0xD4, db6, 0x00, 0x0B, 0x00, 0x00, 0x50, 0xD2, 0x05, 0x26, 0xA0, 0x6E, 0x30],
        optional=[0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x4A, 0x00]
    )
    return bytearray(packet.build())


def test_ute_teach_in_response():
    ''' A UTE response is only sent if the device expects one '''

    # Bidirectional, response expected -> response is sent
    com = Communicator()
    com._base_id = [0xDE, 0xAD, 0xBE, 0xEF]
    com._buffer.extend(_ute_teach_in_packet(0x80))
    com.parse()
    assert com.transmit.qsize() == 1
    assert com.receive.qsize() == 1

    # Unidirectional, no response expected (e.g. LUNOS UNI-EO) -> no response
    com = Communicator()
    com._base_id = [0xDE, 0xAD, 0xBE, 0xEF]
    com._buffer.extend(_ute_teach_in_packet(0x40))
    com.parse()
    assert com.transmit.qsize() == 0
    assert com.receive.qsize() == 1


def test_ignore_own_packets():
    ''' Packets sent from our own Base ID (e.g. repeated by a repeater) are not processed '''
    # The UTE teach-in request (sender 05:26:A0:6E) would be answered
    com = Communicator()
    com._base_id = [0xDE, 0xAD, 0xBE, 0xEF]
    com._buffer.extend(_ute_teach_in_packet(0x80))
    com.parse()
    assert com.transmit.qsize() == 1
    assert com.receive.qsize() == 1

    # The same request sent from our own Base ID is neither answered nor queued
    com = Communicator()
    com._base_id = [0x05, 0x26, 0xA0, 0x6E]
    com._buffer.extend(_ute_teach_in_packet(0x80))
    com.parse()
    assert com.transmit.qsize() == 0
    assert com.receive.qsize() == 0
