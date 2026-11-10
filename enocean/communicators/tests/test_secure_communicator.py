# -*- encoding: utf-8 -*-
''' Tests the decryption and encryption of the telegrams of secure devices by the Communicator '''
from __future__ import print_function, unicode_literals, division, absolute_import

from enocean.communicators.communicator import Communicator
from enocean.protocol import security
from enocean.protocol.constants import PACKET, RORG, SECURE_STATUS
from enocean.protocol.packet import RadioPacket
from enocean.protocol.secure_devices import SecureDevices

DEVICE = [0x01, 0xA2, 0xB3, 0xC4]
GATEWAY = [0xDE, 0xAD, 0xBE, 0xEF]
KEY = bytes(range(16))
PAYLOAD = [0x84, 0x00, 0x00, 0x8A, 0x1A, 0xA0]
# short enough to be sent in a single telegram once encrypted
SHORT_PAYLOAD = [0x0F, 0x00, 0x00]


def paired(rlc=0, rlc_snd=0):
    return SecureDevices({0x01A2B3C4: dict(key=KEY.hex().upper(), slf=0x8B, rlc=rlc, rlc_snd=rlc_snd)})


def receive(com, rorg, data, sender=DEVICE):
    ''' the packets delivered by the communicator for a received telegram '''
    packet = RadioPacket(PACKET.RADIO_ERP1, data=[rorg] + list(data) + sender + [0x00],
                         optional=[0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x4A, 0x00])
    com._buffer.extend(bytearray(packet.build()))
    com.parse()
    delivered = []
    while not com.receive.empty():
        delivered.append(com.receive.get())
    return delivered


def secure_telegram(rlc, payload=PAYLOAD, key=KEY):
    return security.encrypt(key, 0x8B, rlc, RORG.VLD, bytes(payload))


def sent(com):
    packets = []
    while not com.transmit.empty():
        packets.append(com.transmit.get())
    return packets


def plain_packet(destination=DEVICE, rorg=RORG.VLD, data=PAYLOAD):
    return RadioPacket(PACKET.RADIO_ERP1, data=[rorg] + list(data) + GATEWAY + [0x00],
                       optional=[0x03] + destination + [0xFF, 0x00])


def test_secure_telegram_is_delivered_decrypted():
    com = Communicator(secure_devices=paired(rlc=5))
    [packet] = receive(com, *secure_telegram(5))
    assert packet.secure_status == SECURE_STATUS.DECRYPTED
    assert (packet.rorg, packet.data[1:-5], packet.sender) == (RORG.VLD, PAYLOAD, DEVICE)
    assert packet.received is not None
    assert com.secure_devices.state(0x01A2B3C4)['rlc'] == 6


def test_replayed_telegram_is_rejected():
    com = Communicator(secure_devices=paired(rlc=5))
    receive(com, *secure_telegram(5))
    rorg, data = secure_telegram(5)
    [packet] = receive(com, rorg, data)
    assert packet.secure_status == SECURE_STATUS.REJECTED
    assert (packet.rorg, packet.data[1:-5]) == (RORG.SEC_ENCAPS, list(data))


def test_telegram_with_wrong_key_is_rejected():
    com = Communicator(secure_devices=paired())
    [packet] = receive(com, *secure_telegram(0, key=bytes(16)))
    assert packet.secure_status == SECURE_STATUS.REJECTED


def test_secure_telegram_of_unknown_device():
    com = Communicator(secure_devices=paired())
    rorg, data = secure_telegram(0)
    [packet] = receive(com, rorg, data, sender=[0x01, 0x02, 0x03, 0x04])
    assert packet.secure_status == SECURE_STATUS.UNKNOWN_KEY
    assert packet.rorg == RORG.SEC_ENCAPS


def test_sec_telegrams_are_not_supported():
    com = Communicator(secure_devices=paired())
    [packet] = receive(com, RORG.SEC, [0x01, 0x02, 0x03, 0x04, 0x05])
    assert packet.secure_status == SECURE_STATUS.UNSUPPORTED


def test_other_telegrams_are_left_as_they_are():
    com = Communicator(secure_devices=paired())
    [packet] = receive(com, RORG.VLD, PAYLOAD)
    assert packet.secure_status is None
    assert packet.data[1:-5] == PAYLOAD


def test_secure_telegrams_are_left_as_they_are_without_secure_devices():
    com = Communicator()
    rorg, data = secure_telegram(0)
    [packet] = receive(com, rorg, data)
    assert packet.secure_status is None
    assert (packet.rorg, packet.data[1:-5]) == (RORG.SEC_ENCAPS, list(data))


def test_key_is_learned_from_secure_teach_in():
    com = Communicator(secure_devices=SecureDevices())
    statuses = [receive(com, RORG.SEC_TI, part)[0].secure_status
                for part in security.build_teach_in(KEY, 0x8B, 0x10, telegrams=3)]
    assert statuses == [SECURE_STATUS.TEACH_IN, SECURE_STATUS.TEACH_IN, SECURE_STATUS.KEY_LEARNED]
    assert com.secure_devices.state(0x01A2B3C4)['key'] == KEY.hex().upper()
    [packet] = receive(com, *secure_telegram(0x10))
    assert packet.secure_status == SECURE_STATUS.DECRYPTED


def test_key_is_not_learned_when_teach_in_is_disabled():
    com = Communicator(teach_in=False, secure_devices=SecureDevices())
    statuses = [receive(com, RORG.SEC_TI, part)[0].secure_status for part in security.build_teach_in(KEY)]
    assert statuses == [SECURE_STATUS.TEACH_IN] * 2
    assert not com.secure_devices.is_secure(0x01A2B3C4)


def test_telegram_sent_to_secure_device_is_encrypted():
    com = Communicator(secure_devices=paired(rlc_snd=7))
    assert com.send(plain_packet(data=SHORT_PAYLOAD)) is True
    [packet] = sent(com)
    assert packet.rorg == RORG.SEC_ENCAPS
    assert (packet.sender, packet.destination) == (GATEWAY, DEVICE)
    assert security.decrypt(KEY, 0x8B, packet.rorg, bytes(packet.data[1:-5]), 7) == (7, RORG.VLD, bytes(SHORT_PAYLOAD))
    assert com.secure_devices.state(0x01A2B3C4)['rlc_snd'] == 8


def test_telegrams_sent_in_clear():
    com = Communicator(secure_devices=paired())
    teach_in = plain_packet(rorg=RORG.SEC_TI, data=security.build_teach_in(KEY, telegrams=3)[0])
    learn_4bs = plain_packet(rorg=RORG.BS4, data=[0x08, 0x28, 0x46, 0x80])
    other_device = plain_packet(destination=[0x01, 0x02, 0x03, 0x04])
    for packet in (teach_in, learn_4bs, other_device):
        com.send(packet)
    assert sent(com) == [teach_in, learn_4bs, other_device]
    assert com.secure_devices.state(0x01A2B3C4)['rlc_snd'] == 0


def test_telegrams_are_sent_in_clear_without_secure_devices():
    com = Communicator()
    packet = plain_packet()
    com.send(packet)
    assert sent(com) == [packet]


def test_long_telegram_is_encrypted_then_chained():
    com = Communicator(secure_devices=paired())
    program = [0x20, 0x00, 0x00, 0x00, 0x16, 0x80]
    assert com.send(plain_packet(data=program)) is True
    packets = sent(com)
    assert [p.data[:2] for p in packets] == [[0x40, 0x40], [0x40, 0x41]]
    assert all((p.sender, p.destination) == (GATEWAY, DEVICE) for p in packets)
    message = packets[0].data[4:-5] + packets[1].data[2:-5]
    assert len(message) == (packets[0].data[2] << 8 | packets[0].data[3]) + 1
    assert security.decrypt(KEY, 0x8B, message[0], bytes(message[1:]), 0) == (0, RORG.VLD, bytes(program))

    # The sequence number changes between chains
    com.send(plain_packet(data=program))
    assert [p.data[1] for p in sent(com)] == [0x80, 0x81]


def test_short_telegram_is_not_chained():
    com = Communicator(secure_devices=paired())
    com.send(plain_packet(data=SHORT_PAYLOAD))
    assert [p.rorg for p in sent(com)] == [RORG.SEC_ENCAPS]


def test_long_broadcast_telegram_is_not_chained():
    com = Communicator()
    packet = plain_packet(destination=[0xFF, 0xFF, 0xFF, 0xFF], data=list(range(12)))
    com.send(packet)
    assert sent(com) == [packet]
