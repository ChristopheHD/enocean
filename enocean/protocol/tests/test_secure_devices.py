# -*- encoding: utf-8 -*-
''' Tests the security state of secure devices '''
from __future__ import print_function, unicode_literals, division, absolute_import

import threading

import pytest

from enocean.protocol import security
from enocean.protocol.constants import RORG
from enocean.protocol.secure_devices import SecureDevices

ADDRESS = 0x01A2B3C4
KEY = bytes(range(16))
PAYLOAD = bytes.fromhex('8400008A1AA0')


def paired(**fields):
    ''' SecureDevices knowing the key of the device, and the list of the changes it reported '''
    changes = []
    state = dict(key=KEY.hex().upper(), slf=0x8B, rlc=0, rlc_snd=0)
    state.update(fields)
    devices = SecureDevices({ADDRESS: state}, on_change=lambda address, state: changes.append((address, state)))
    return devices, changes


def test_unknown_device_is_not_secure():
    devices = SecureDevices()
    assert not devices.is_secure(ADDRESS)
    assert devices.state(ADDRESS) == {}
    assert devices.encrypt(ADDRESS, RORG.VLD, PAYLOAD) is None
    assert devices.decrypt(ADDRESS, RORG.SEC_ENCAPS, b'\x00' * 10) is None


def test_states_are_restored():
    devices, _ = paired(rlc=5, rlc_snd=7)
    assert devices.is_secure(ADDRESS)
    assert devices.state(ADDRESS) == dict(key=KEY.hex().upper(), slf=0x8B, rlc=5, rlc_snd=7)


def test_state_is_a_copy():
    devices, _ = paired()
    devices.state(ADDRESS)['rlc'] = 99
    assert devices.state(ADDRESS)['rlc'] == 0


def test_encrypt_reports_next_rolling_code_first():
    devices, changes = paired(rlc_snd=41)
    reported = []

    def on_change(address, state):
        # the rolling code being used is already persisted as consumed
        reported.append(state['rlc_snd'])
    devices._on_change = on_change
    rorg, data = devices.encrypt(ADDRESS, RORG.VLD, PAYLOAD)
    assert reported == [42]
    assert security.decrypt(KEY, 0x8B, rorg, data, 41) == (41, RORG.VLD, PAYLOAD)
    rorg, data = devices.encrypt(ADDRESS, RORG.VLD, PAYLOAD)
    assert security.decrypt(KEY, 0x8B, rorg, data, 42)[0] == 42


def test_concurrent_senders_never_share_a_rolling_code():
    devices, _ = paired()
    used = []

    def send():
        for _ in range(50):
            rorg, data = devices.encrypt(ADDRESS, RORG.VLD, PAYLOAD)
            used.append(security.decrypt(KEY, 0x8B, rorg, data, 0, window=1000)[0])
    threads = [threading.Thread(target=send) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(used) == list(range(200))


def test_decrypt_updates_expected_rolling_code_and_rejects_replay():
    devices, changes = paired(rlc=10)
    rorg, data = security.encrypt(KEY, 0x8B, 12, RORG.VLD, PAYLOAD)
    assert devices.decrypt(ADDRESS, rorg, data) == (RORG.VLD, PAYLOAD)
    assert changes[-1] == (ADDRESS, dict(key=KEY.hex().upper(), slf=0x8B, rlc=13, rlc_snd=0))
    assert devices.decrypt(ADDRESS, rorg, data) is None


def test_decrypt_rejects_other_key():
    devices, changes = paired()
    rorg, data = security.encrypt(bytes(16), 0x8B, 0, RORG.VLD, PAYLOAD)
    assert devices.decrypt(ADDRESS, rorg, data) is None
    assert changes == []


def test_sec_telegrams_are_not_supported():
    devices, _ = paired()
    assert devices.decrypt(ADDRESS, RORG.SEC, b'\x00' * 4) is None


def taught(data):
    return security.parse_teach_in({security.teach_in_index(part): part for part in data})


def test_teach_in_generates_a_key():
    changes = []
    devices = SecureDevices(on_change=lambda address, state: changes.append((address, state)))
    data = devices.build_teach_in(ADDRESS, telegrams=3, bidirectional=True)
    assert devices.is_secure(ADDRESS)
    assert changes == [(ADDRESS, devices.state(ADDRESS))]
    assert taught(data).key.hex().upper() == devices.state(ADDRESS)['key']
    assert (taught(data).slf, taught(data).rlc, taught(data).bidirectional) == (security.DEFAULT_SLF, 0, True)


def test_teach_in_replaces_the_state_of_a_paired_device():
    # a device paired again restarts its rolling code from the one of the teach-in
    devices, changes = paired(rlc=0x456, rlc_snd=0x123)
    data = devices.build_teach_in(ADDRESS)
    state = devices.state(ADDRESS)
    assert state['key'] != KEY.hex().upper()
    assert (state['rlc'], state['rlc_snd'], taught(data).rlc) == (0, 0, 0)
    assert changes == [(ADDRESS, state)]
    rorg, data = security.encrypt(bytes.fromhex(state['key']), 0x8B, 0, RORG.VLD, PAYLOAD)
    assert devices.decrypt(ADDRESS, rorg, data) == (RORG.VLD, PAYLOAD)


def test_invalid_teach_in_is_refused():
    devices, changes = paired()
    with pytest.raises(ValueError):
        devices.build_teach_in(ADDRESS, telegrams=4)
    assert devices.state(ADDRESS)['key'] == KEY.hex().upper()
    assert changes == []


def test_key_is_learned_from_teach_in():
    changes = []
    devices = SecureDevices(on_change=lambda address, state: changes.append((address, state)))
    parts = security.build_teach_in(KEY, 0x8B, 0x10, telegrams=3)
    assert [devices.receive_teach_in(ADDRESS, part) for part in parts] == [False, False, True]
    assert changes == [(ADDRESS, dict(key=KEY.hex().upper(), slf=0x8B, rlc=0x10, rlc_snd=0))]
    rorg, data = security.encrypt(KEY, 0x8B, 0x10, RORG.VLD, PAYLOAD)
    assert devices.decrypt(ADDRESS, rorg, data) == (RORG.VLD, PAYLOAD)


def test_teach_in_restarts_on_first_telegram():
    devices = SecureDevices()
    old = security.build_teach_in(bytes(16), telegrams=3)
    new = security.build_teach_in(KEY, telegrams=3)
    assert not devices.receive_teach_in(ADDRESS, old[0])
    assert not devices.receive_teach_in(ADDRESS, old[1])
    assert [devices.receive_teach_in(ADDRESS, part) for part in new] == [False, False, True]
    assert devices.state(ADDRESS)['key'] == KEY.hex().upper()


def test_empty_teach_in_is_ignored():
    assert not SecureDevices().receive_teach_in(ADDRESS, b'')
