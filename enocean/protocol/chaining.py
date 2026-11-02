# -*- encoding: utf-8 -*-
""" Chained data messages (R-ORG 0x40): sending telegrams too long for a single radio telegram.

The first telegram carries SEQ (2 bits) | IDX = 0 (6 bits), the length of the message (not counting
its R-ORG, 2 bytes) and its first bytes, the following telegrams SEQ | IDX and the next bytes of the message.
This is the layout of the telegrams of the Enki gateway sent to EQUATION Sorali heaters.
"""
from __future__ import print_function, unicode_literals, division, absolute_import

from enocean.protocol.constants import RORG

# Longest message (R-ORG + data) of a radio telegram: up to 14 data bytes, and 4 less for an addressed
# telegram, which also carries its destination. The transceiver refuses longer telegrams.
MAX_LENGTH = 15
MAX_ADDRESSED_LENGTH = 10

# Data bytes of the message carried by the first telegram and by the following ones:
# each chained telegram is 10 bytes long (R-ORG + data), so it can be addressed
FIRST_CHUNK_SIZE = 6
CHUNK_SIZE = 8


def needs_chaining(message, addressed):
    ''' Whether a message (R-ORG + data) is too long for a single radio telegram '''
    return len(message) > (MAX_ADDRESSED_LENGTH if addressed else MAX_LENGTH)


def chain(message, seq):
    ''' Splits a message (R-ORG + data) into the data (R-ORG 0x40 included) of chained telegrams.

    seq is the sequence number of the chain (1 to 3), it must change between successive chains. '''
    if not 1 <= seq <= 3:
        raise ValueError('invalid chain sequence number: %d' % seq)
    message = bytes(bytearray(message))
    length = len(message) - 1
    telegrams = [bytes(bytearray([RORG.CHAINED_VENTILAIRSEC, seq << 6, length >> 8, length & 0xFF]))
                 + message[:FIRST_CHUNK_SIZE]]
    for idx, offset in enumerate(range(FIRST_CHUNK_SIZE, len(message), CHUNK_SIZE), start=1):
        telegrams.append(bytes(bytearray([RORG.CHAINED_VENTILAIRSEC, (seq << 6) | idx]))
                         + message[offset:offset + CHUNK_SIZE])
    return telegrams
