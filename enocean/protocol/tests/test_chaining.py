# -*- encoding: utf-8 -*-
from __future__ import print_function, unicode_literals, division, absolute_import

import pytest

from enocean.protocol import chaining

# 11-byte SEC_ENCAPS message: the length of a secure D2-33 program telegram
MESSAGE = bytes(bytearray([0x31] + list(range(1, 11))))


def test_short_message_layout():
    # Layout of the chained telegrams of the Enki gateway: LEN does not count the R-ORG
    assert chaining.chain(MESSAGE, 3) == [
        bytes(bytearray([0x40, 0xC0, 0x00, 0x0A])) + MESSAGE[:6],
        bytes(bytearray([0x40, 0xC1])) + MESSAGE[6:],
    ]


def test_sequence_number():
    assert [bytearray(chaining.chain(MESSAGE, seq)[1])[1] for seq in (1, 2, 3)] == [0x41, 0x81, 0xC1]
    for seq in (0, 4):
        with pytest.raises(ValueError):
            chaining.chain(MESSAGE, seq)


def test_long_message_is_split_in_indexed_chunks():
    message = bytes(bytearray(range(30)))
    telegrams = [bytearray(t) for t in chaining.chain(message, 1)]
    assert [t[1] for t in telegrams] == [0x40, 0x41, 0x42, 0x43]
    assert telegrams[0][2] << 8 | telegrams[0][3] == 29
    assert telegrams[0][4:] + b''.join(t[2:] for t in telegrams[1:]) == message
    assert all(len(t) <= chaining.MAX_ADDRESSED_LENGTH for t in telegrams)


def test_needs_chaining():
    # The transceiver refuses an addressed 11-byte telegram
    assert chaining.needs_chaining(MESSAGE, addressed=True)
    assert not chaining.needs_chaining(MESSAGE[:10], addressed=True)
    assert not chaining.needs_chaining(MESSAGE, addressed=False)
    assert chaining.needs_chaining(bytes(16), addressed=False)
