# -*- encoding: utf-8 -*-
''' Tests EnOcean security, against the known-answer vectors of
"Security of EnOcean Radio Networks" v3.02, Annex A.4 '''
from __future__ import print_function, unicode_literals, division, absolute_import

import pytest

from enocean.protocol import security
from enocean.protocol.constants import RORG

PK_A41 = bytes.fromhex("456E4F6365616E20476D62482E313300")
PK_A43 = bytes.fromhex("E50880CF67790D5D66AA7F3B7AD77A3F")
KEY = bytes(range(16))


def test_vaes_single_block():
    encrypted = security.vaes(PK_A41, bytes.fromhex("C0FFEE"), bytes.fromhex("A50827FF80"))
    assert encrypted.hex().upper() == "3EEAC4A2DF"


def test_cmac_3_bytes():
    assert security.cmac(PK_A41, bytes.fromhex("313EEAC4A2DFC0FFEE"), 3).hex().upper() == "EAF20E"


def test_vaes_multi_block_and_cmac_4_bytes():
    plain = bytes([0xD1]) + bytes(range(0x1E))
    encrypted = security.vaes(PK_A43, bytes.fromhex("01020304"), plain)
    assert encrypted.hex().upper() == "BB17C17A05CAF5575DE208302FB572A0FD3A4434A41096F102E60DC20D777A"
    assert security.cmac(PK_A43, b"\x31" + encrypted + bytes.fromhex("01020304"), 4).hex().upper() == "3B4C380F"


def test_vaes_is_symmetric():
    rlc = bytes.fromhex("ABCDEF")
    plain = bytes(range(20))
    assert security.vaes(KEY, rlc, security.vaes(KEY, rlc, plain)) == plain


def test_default_slf():
    assert security.parse_slf(0x8B) == security.Slf(rlc_size=3, rlc_tx=False, mac_size=3, encryption=3)


def test_transmitted_32_bit_rlc_4_byte_cmac():
    assert security.parse_slf(0xF3) == security.Slf(rlc_size=4, rlc_tx=True, mac_size=4, encryption=3)


def test_unsupported_slf():
    for slf in (0x00, 0x8C, 0x83, 0x0B):
        with pytest.raises(ValueError):
            security.check_slf(slf)


def test_encrypt_sec_encaps():
    assert security.encrypt(PK_A41, 0x8B, 0xC0FFEE, RORG.BS4, bytes.fromhex("0827FF80")) == \
        (RORG.SEC_ENCAPS, bytes.fromhex("3EEAC4A2DFEAF20E"))


def test_decrypt_sec_encaps():
    assert security.decrypt(PK_A41, 0x8B, RORG.SEC_ENCAPS, bytes.fromhex("3EEAC4A2DFEAF20E"), 0xC0FFEE) == \
        (0xC0FFEE, RORG.BS4, bytes.fromhex("0827FF80"))


def test_decrypt_sec_ptm():
    assert security.decrypt(PK_A41, 0x8B, RORG.SEC, bytes.fromhex("0E05E56D"), 0x3E2D00) == (0x3E2D00, None, b"\x09")


def test_decrypt_searches_implicit_rlc_in_window():
    data = bytes.fromhex("3EEAC4A2DFEAF20E")
    assert security.decrypt(PK_A41, 0x8B, RORG.SEC_ENCAPS, data, 0xC0FFE0)[0] == 0xC0FFEE
    assert security.decrypt(PK_A41, 0x8B, RORG.SEC_ENCAPS, data, 0xC0FFE0, window=8) is None


def test_decrypt_rejects_replay():
    assert security.decrypt(PK_A41, 0x8B, RORG.SEC_ENCAPS, bytes.fromhex("3EEAC4A2DFEAF20E"), 0xC0FFEF) is None


def test_decrypt_rejects_tampering():
    assert security.decrypt(PK_A41, 0x8B, RORG.SEC_ENCAPS, bytes.fromhex("3EEAC4A2DFEAF20F"), 0xC0FFEE) is None
    assert security.decrypt(PK_A41, 0x8B, RORG.SEC_ENCAPS, bytes.fromhex("3FEAC4A2DFEAF20E"), 0xC0FFEE) is None


def test_decrypt_rejects_wrong_key():
    assert security.decrypt(KEY, 0x8B, RORG.SEC_ENCAPS, bytes.fromhex("3EEAC4A2DFEAF20E"), 0xC0FFEE) is None


def test_roundtrip_wraps_rolling_code():
    rorg, data = security.encrypt(KEY, 0x8B, 0xFFFFFF, RORG.VLD, bytes.fromhex("200000001680"))
    assert security.decrypt(KEY, 0x8B, rorg, data, 0xFFFFFE) == (0xFFFFFF, RORG.VLD, bytes.fromhex("200000001680"))
    rorg, data = security.encrypt(KEY, 0x8B, 0x1000000, RORG.VLD, b"\x08\x00\x00")
    assert security.decrypt(KEY, 0x8B, rorg, data, 0xFFFFFF)[0] == 0


def test_roundtrip_transmitted_rlc():
    rorg, data = security.encrypt(KEY, 0xF3, 0x01020304, RORG.BS4, b"\x01\x02\x03\x04")
    assert data[-8:-4] == bytes.fromhex("01020304")
    assert security.decrypt(KEY, 0xF3, rorg, data, 0x01020300) == (0x01020304, RORG.BS4, b"\x01\x02\x03\x04")
    assert security.decrypt(KEY, 0xF3, rorg, data, 0x01020305) is None


def test_decrypt_rejects_short_telegram():
    assert security.decrypt(KEY, 0x8B, RORG.SEC_ENCAPS, b"\x01\x02\x03", 0) is None


def test_build_teach_in_two_telegrams():
    assert security.build_teach_in(KEY, 0x8B, 0x3E2D00) == [bytes.fromhex("208B3E2D00") + KEY[:7], b"\x40" + KEY[7:]]


def test_build_teach_in_three_telegrams():
    # Layout of the teach-in of the Enki gateway for EQUATION Sorali heaters
    assert security.build_teach_in(KEY, 0x8B, 0, telegrams=3) == \
        [bytes.fromhex("308B000000") + KEY[:4], b"\x40" + KEY[4:12], b"\x80" + KEY[12:]]


def test_build_teach_in_flags():
    assert security.build_teach_in(KEY, bidirectional=True)[0][0] == 0x21
    assert security.build_teach_in(KEY, ptm=True)[0][0] == 0x24


def test_build_teach_in_rejects_invalid_parameters():
    with pytest.raises(ValueError):
        security.build_teach_in(KEY, telegrams=4)
    with pytest.raises(ValueError):
        security.build_teach_in(KEY[:8])
    with pytest.raises(ValueError):
        security.build_teach_in(KEY, slf=0x00)


def test_parse_teach_in_roundtrip():
    for telegrams in (2, 3):
        parts = security.build_teach_in(KEY, 0x8B, 0x123456, telegrams=telegrams, bidirectional=True)
        received = {security.teach_in_index(data): data for data in parts}
        assert security.parse_teach_in(received) == \
            security.TeachIn(slf=0x8B, rlc=0x123456, key=KEY, ptm=False, bidirectional=True)


def test_parse_teach_in_incomplete():
    parts = security.build_teach_in(KEY, telegrams=3)
    assert security.parse_teach_in({0: parts[0], 2: parts[2]}) is None
    assert security.parse_teach_in({1: parts[1], 2: parts[2]}) is None


def test_parse_teach_in_rejects_psk():
    parts = security.build_teach_in(KEY)
    psk = bytes([parts[0][0] | 0x08]) + parts[0][1:]
    assert security.parse_teach_in({0: psk, 1: parts[1]}) is None


def test_generated_keys_are_random():
    assert len(security.generate_key()) == 16
    assert security.generate_key() != security.generate_key()
