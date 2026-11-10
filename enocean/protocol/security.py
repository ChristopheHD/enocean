# -*- encoding: utf-8 -*-
"""EnOcean security: VAES encryption: VAES encryption, AES-CMAC, rolling code and secure teach-in.

Implements the parts of "Security of EnOcean Radio Networks" (v3.02) needed to talk to
secure devices: SEC (0x30) / SEC_ENCAPS (0x31) telegrams and the SEC_TI (0x35) teach-in.
Only VAES encryption with a 3 or 4 byte CMAC is supported. Everything here is pure (no I/O),
the caller is responsible for persisting the keys and rolling codes.
"""
from __future__ import print_function, unicode_literals, division, absolute_import

import hmac
import secrets
from collections import namedtuple

from cryptography.hazmat.primitives import cmac as _cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from enocean.protocol.constants import RORG

# VAES initialization vector (spec 6.1)
VAES_INIT_VECTOR = bytes.fromhex("3410DE8F1ABA3EFF9F5A117172EACABD")

# 24-bit implicit rolling code, 3-byte CMAC, VAES
DEFAULT_SLF = 0x8B

# How far ahead of the expected rolling code an implicit rolling code is searched
DEFAULT_RLC_WINDOW = 128

# Split of the 16-byte key between the telegrams of a secure teach-in, by telegram count.
# 2 telegrams is the layout of the specification examples (A.4), 3 telegrams is used
# by some gateways (e.g. the Enki box for EQUATION Sorali radiators).
TEACH_IN_KEY_SPLITS = {
    2: (7, 9),
    3: (4, 8, 4),
}

KEY_SIZE = 16

Slf = namedtuple('Slf', ['rlc_size', 'rlc_tx', 'mac_size', 'encryption'])
TeachIn = namedtuple('TeachIn', ['slf', 'rlc', 'key', 'ptm', 'bidirectional'])


def generate_key():
    '''Generate a new random 16-byte key'''
    return secrets.token_bytes(KEY_SIZE)


def _aes_block(key, block):
    '''Encrypt a single 16-byte block with AES-128, the primitive VAES is built on'''
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def _xor(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def vaes(key, rlc, data):
    '''VAES stream cipher (spec 6.1). Encryption and decryption are the same operation.

    rlc is the rolling code as bytes, data can have any length.'''
    iv = _xor(VAES_INIT_VECTOR, rlc.ljust(16, b'\x00'))
    result = bytearray()
    keystream = None
    for offset in range(0, len(data), 16):
        keystream = _aes_block(key, iv if keystream is None else _xor(iv, keystream))
        result += _xor(data[offset:offset + 16], keystream)
    return bytes(result)


def cmac(key, data, size):
    '''AES-CMAC (RFC 4493) of data, truncated to its size most significant bytes'''
    ctx = _cmac.CMAC(algorithms.AES(key))
    ctx.update(data)
    return ctx.finalize()[:size]


def parse_slf(slf):
    '''Parse a Security Level Format byte.

    bits 7-6: rolling code size (none, 16, 24 or 32 bits), bit 5: rolling code transmitted,
    bits 4-3: CMAC size (none, 3 or 4 bytes), bits 2-0: encryption (3 = VAES)'''
    return Slf(rlc_size=(0, 2, 3, 4)[(slf >> 6) & 0x03],
               rlc_tx=bool((slf >> 5) & 0x01),
               mac_size=(0, 3, 4, 0)[(slf >> 3) & 0x03],
               encryption=slf & 0x07)


def check_slf(slf):
    '''Raise ValueError if the SLF uses features that are not supported'''
    fmt = parse_slf(slf)
    if fmt.encryption != 3 or not fmt.mac_size or not fmt.rlc_size:
        raise ValueError(f'unsupported SLF 0x{slf:02X} (only VAES with CMAC and rolling code)')
    return fmt


def rlc_to_bytes(rlc, size):
    '''Rolling code as big-endian bytes, wrapped to its size'''
    return (rlc % (1 << (8 * size))).to_bytes(size, 'big')


def encrypt(key, slf, rlc, rorg, payload):
    '''Encrypt a plain telegram into a secure one.

    Returns (secure rorg, secure data) where secure data is encrypted data [+ rolling code] + CMAC.
    RPS telegrams become SEC (0x30) with a single nibble, others are encapsulated in SEC_ENCAPS.
    The caller must increment and persist the rolling code once used.'''
    fmt = check_slf(slf)
    rlc_bytes = rlc_to_bytes(rlc, fmt.rlc_size)
    if rorg == RORG.RPS:
        rorg_s = RORG.SEC
        encrypted = bytes([vaes(key, rlc_bytes, bytes(payload[:1]))[0] & 0x0F])
    else:
        rorg_s = RORG.SEC_ENCAPS
        encrypted = vaes(key, rlc_bytes, bytes([rorg]) + bytes(payload))
    mac = cmac(key, bytes([rorg_s]) + encrypted + rlc_bytes, fmt.mac_size)
    return rorg_s, encrypted + (rlc_bytes if fmt.rlc_tx else b'') + mac


def decrypt(key, slf, rorg_s, data, next_rlc, window=DEFAULT_RLC_WINDOW):
    '''Authenticate and decrypt the data of a SEC (0x30) or SEC_ENCAPS (0x31) telegram.

    next_rlc is the lowest rolling code accepted (last accepted + 1), which protects against replay.
    An implicit rolling code is searched in [next_rlc, next_rlc + window).
    Returns (rolling code, inner rorg, payload) or None if the telegram does not authenticate.
    The inner rorg is None for SEC (0x30) telegrams as they do not carry it.'''
    fmt = check_slf(slf)
    modulo = 1 << (8 * fmt.rlc_size)
    data = bytes(data)
    if len(data) <= fmt.mac_size + (fmt.rlc_size if fmt.rlc_tx else 0):
        return None
    mac = data[-fmt.mac_size:]
    encrypted = data[:-fmt.mac_size]
    if fmt.rlc_tx:
        rlc = int.from_bytes(encrypted[-fmt.rlc_size:], 'big')
        encrypted = encrypted[:-fmt.rlc_size]
        # Only accept rolling codes ahead of the expected one (half of the space, to handle wrapping)
        candidates = [rlc] if (rlc - next_rlc) % modulo < modulo // 2 else []
    else:
        candidates = [(next_rlc + offset) % modulo for offset in range(window)]

    for rlc in candidates:
        rlc_bytes = rlc_to_bytes(rlc, fmt.rlc_size)
        if not hmac.compare_digest(cmac(key, bytes([rorg_s]) + encrypted + rlc_bytes, fmt.mac_size), mac):
            continue
        plain = vaes(key, rlc_bytes, encrypted)
        if rorg_s == RORG.SEC:
            return rlc, None, bytes([plain[0] & 0x0F])
        if not plain:
            return None
        return rlc, plain[0], plain[1:]
    return None


def build_teach_in(key, slf=DEFAULT_SLF, rlc=0, telegrams=2, ptm=False, bidirectional=False):
    '''Build the data of the SEC_TI (0x35) telegrams teaching our key and rolling code to a device.

    Returns one bytes object per telegram, each being the data following the 0x35 R-ORG.
    Pre-shared key (PSK) encrypted teach-ins are not supported.'''
    if telegrams not in TEACH_IN_KEY_SPLITS:
        raise ValueError(f'unsupported number of teach-in telegrams: {telegrams}')
    if len(key) != KEY_SIZE:
        raise ValueError('key must be 16 bytes')
    fmt = check_slf(slf)
    # TEACH_IN_INFO: IDX (7-6), CNT (5-4), PSK (3), TYPE (2), INFO (1-0)
    info = (telegrams << 4) | (int(ptm) << 2) | (0x01 if bidirectional and not ptm else 0x00)
    parts = []
    offset = 0
    for idx, size in enumerate(TEACH_IN_KEY_SPLITS[telegrams]):
        chunk = bytes(key[offset:offset + size])
        offset += size
        if idx == 0:
            parts.append(bytes([info, slf]) + rlc_to_bytes(rlc, fmt.rlc_size) + chunk)
        else:
            parts.append(bytes([idx << 6]) + chunk)
    return parts


def teach_in_index(data):
    '''Index of a SEC_TI telegram in its teach-in sequence, from its data (after the R-ORG)'''
    return (data[0] >> 6) & 0x03


def parse_teach_in(telegrams):
    '''Parse a complete secure teach-in received from a device.

    telegrams maps the index of each SEC_TI telegram to its data (after the R-ORG).
    Returns a TeachIn, or None if telegrams are missing, malformed or PSK encrypted.'''
    first = telegrams.get(0)
    if first is None or len(first) < 2:
        return None
    info, slf = first[0], first[1]
    count = (info >> 4) & 0x03
    if count < 2 or any(idx not in telegrams for idx in range(count)) or info & 0x08:
        return None
    try:
        fmt = check_slf(slf)
    except ValueError:
        return None
    combined = bytes(first[2:]) + b''.join(bytes(telegrams[idx][1:]) for idx in range(1, count))
    key = combined[fmt.rlc_size:]
    if len(key) != KEY_SIZE:
        return None
    ptm = bool(info & 0x04)
    return TeachIn(slf=slf,
                   rlc=int.from_bytes(combined[:fmt.rlc_size], 'big'),
                   key=key,
                   ptm=ptm,
                   bidirectional=not ptm and (info & 0x03) == 0x01)
