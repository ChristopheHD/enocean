# -*- encoding: utf-8 -*-
""" Secure devices: keys and rolling codes applied to the content of their telegrams.

The library stores nothing: the state of each device is given when creating SecureDevices,
and each change is reported to the application, which is responsible for persisting it.
"""
from __future__ import print_function, unicode_literals, division, absolute_import

import logging
import threading

from enocean.protocol import security
from enocean.protocol.constants import RORG


class SecureDevices(object):
    ''' Security state of secure devices, by address.

    The state of a device is a dict that can be stored as JSON: its key (hexadecimal), its SLF,
    the next rolling code expected from it (rlc) and the next one to send to it (rlc_snd).
    A device is secure once a key is known for it, from a secure teach-in sent to it or received from it.

    on_change(address, state) is called after each change of the state of a device, before the telegram
    using it is sent: it must persist the state before returning, as a rolling code must never be used twice. '''
    logger = logging.getLogger('enocean.protocol.secure_devices')

    def __init__(self, states=None, on_change=None, rlc_window=security.DEFAULT_RLC_WINDOW):
        self._states = {address: dict(state) for address, state in (states or {}).items()}
        self._on_change = on_change
        self._rlc_window = rlc_window
        # secure teach-in telegrams being received, by address
        self._teach_ins = {}
        # telegrams are sent and received from different threads
        self._lock = threading.RLock()

    def is_secure(self, address):
        ''' Whether a key is known for the device '''
        with self._lock:
            return 'key' in self._states.get(address, {})

    def state(self, address):
        ''' Copy of the state of the device, empty if unknown '''
        with self._lock:
            return dict(self._states.get(address, {}))

    def _update(self, address, **fields):
        self._states.setdefault(address, {}).update(fields)
        if self._on_change is not None:
            self._on_change(address, dict(self._states[address]))

    def decrypt(self, address, rorg, data):
        ''' Authenticates and decrypts the data of a secure telegram of the device,
        returns (inner R-ORG, payload) or None if it is rejected '''
        if rorg == RORG.SEC:
            self.logger.debug('%08X: SEC (0x30) telegrams are not supported', address)
            return None
        with self._lock:
            state = self._states.get(address, {})
            if 'key' not in state:
                self.logger.debug('%08X: secure telegram received but no key is known', address)
                return None
            result = security.decrypt(bytes.fromhex(state['key']), state['slf'], rorg, data,
                                      state.get('rlc', 0), self._rlc_window)
            if result is None:
                self.logger.debug('%08X: secure telegram rejected (wrong key, rolling code out of window or replay)',
                                  address)
                return None
            rlc, inner_rorg, payload = result
            self._update(address, rlc=rlc + 1)
            return inner_rorg, payload

    def encrypt(self, address, rorg, payload):
        ''' Encrypts the content of a telegram for the device, returns (secure R-ORG, data) or None '''
        with self._lock:
            state = self._states.get(address, {})
            if 'key' not in state:
                self.logger.error('%08X: no key known, send a secure teach-in first', address)
                return None
            rlc = state.get('rlc_snd', 0)
            # The next rolling code is persisted before this one is sent: it must never be used twice
            self._update(address, rlc_snd=rlc + 1)
            return security.encrypt(bytes.fromhex(state['key']), state['slf'], rlc, rorg, payload)

    def build_teach_in(self, address, telegrams=2, bidirectional=False):
        ''' Builds the data of the secure teach-in telegrams giving a new key and rolling code to the device.
        The device is expected to use them for its telegrams too: a device paired again (e.g. after a factory
        reset) restarts its rolling code from the one of the teach-in, so the previous state is replaced. '''
        key = security.generate_key()
        data = security.build_teach_in(key, security.DEFAULT_SLF, 0, telegrams=telegrams, bidirectional=bidirectional)
        with self._lock:
            self._update(address, key=key.hex().upper(), slf=security.DEFAULT_SLF, rlc=0, rlc_snd=0)
            self.logger.info('%08X: generated a new key', address)
        return data

    def receive_teach_in(self, address, data):
        ''' Learns the key of the device from the data of the secure teach-in telegrams it sends.
        Returns True once the key is learned. '''
        if not data:
            return False
        with self._lock:
            index = security.teach_in_index(data)
            if index == 0:
                self._teach_ins[address] = {}
                if data[0] & 0x08:
                    self.logger.warning('%08X: secure teach-ins encrypted with a pre-shared key are not supported',
                                        address)
            pending = self._teach_ins.setdefault(address, {})
            pending[index] = bytes(data)
            teach_in = security.parse_teach_in(pending)
            if teach_in is None:
                # wait for the remaining telegrams
                return False
            del self._teach_ins[address]
            self._update(address, key=teach_in.key.hex().upper(), slf=teach_in.slf, rlc=teach_in.rlc, rlc_snd=0)
            self.logger.info('%08X: key learned from secure teach-in', address)
            return True
