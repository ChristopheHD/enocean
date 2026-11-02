# -*- encoding: utf-8 -*-
from __future__ import print_function, unicode_literals, division, absolute_import
import logging
import datetime

import threading
try:
    import queue
except ImportError:
    import Queue as queue
from enocean.protocol.packet import Packet, RadioPacket, UTETeachInPacket
from enocean.protocol.constants import PACKET, PARSE_RESULT, RETURN_CODE, RORG, SECURE_STATUS


class Communicator(threading.Thread):
    '''
    Communicator base-class for EnOcean.
    Not to be used directly, only serves as base class for SerialCommunicator etc.

    When given the secure devices (SecureDevices), received secure telegrams are decrypted and delivered
    as the telegrams of the devices, telegrams sent to secure devices are encrypted, and the keys of devices
    sending a secure teach-in are learned when teach_in is set. The secure_status of received secure telegrams
    tells what happened to them.
    '''
    logger = logging.getLogger('enocean.communicators.Communicator')

    # R-ORGs never encrypted when sent: already secure, chained or teach-in telegrams
    UNENCRYPTED_RORGS = (RORG.SEC, RORG.SEC_ENCAPS, RORG.SEC_TI, RORG.CHAINED, RORG.CHAINED_VENTILAIRSEC, RORG.UTE)

    def __init__(self, callback=None, teach_in=True, secure_devices=None):
        super(Communicator, self).__init__()
        # Create an event to stop the thread
        self._stop_flag = threading.Event()
        # Input buffer
        self._buffer = []
        # Setup packet queues
        self.transmit = queue.Queue()
        self.receive = queue.Queue()
        # Set the callback method
        self.__callback = callback
        # Internal variable for the Base ID of the module.
        self._base_id = None
        # Should new messages be learned automatically? Defaults to True.
        # TODO: Not sure if we should use CO_WR_LEARNMODE??
        self.teach_in = teach_in
        # Security state of secure devices (SecureDevices), None to leave secure telegrams as they are
        self.secure_devices = secure_devices

    def _get_from_send_queue(self):
        ''' Get message from send queue, if one exists '''
        try:
            packet = self.transmit.get(block=False)
            self.logger.info('Sending packet')
            self.logger.debug(packet)
            return packet
        except queue.Empty:
            pass
        return None

    def send(self, packet):
        if not isinstance(packet, Packet):
            self.logger.error('Object to send must be an instance of Packet')
            return False
        if isinstance(packet, RadioPacket):
            packet = self.encrypt(packet)
            if packet is None:
                return False
        self.transmit.put(packet)
        return True

    def encrypt(self, packet):
        ''' Returns the radio packet encrypted if it is sent to a secure device, the packet itself otherwise.
        None if it cannot be encrypted. '''
        if (self.secure_devices is None or packet.rorg in self.UNENCRYPTED_RORGS
                or (packet.rorg in (RORG.BS1, RORG.BS4) and packet.learn)
                or not self.secure_devices.is_secure(packet.destination_int)):
            return packet
        result = self.secure_devices.encrypt(packet.destination_int, packet.rorg, packet.data[1:-5])
        if result is None:
            return None
        rorg, data = result
        return RadioPacket(packet.packet_type, data=[rorg] + list(data) + packet.data[-5:], optional=packet.optional)

    def _decrypt(self, packet):
        ''' Returns the telegram of the device for a received secure telegram, or the packet with its secure_status '''
        if packet.rorg == RORG.SEC_TI:
            learned = self.teach_in and self.secure_devices.receive_teach_in(packet.sender_int, packet.data[1:-5])
            packet.secure_status = SECURE_STATUS.KEY_LEARNED if learned else SECURE_STATUS.TEACH_IN
            return packet
        if packet.rorg not in (RORG.SEC, RORG.SEC_ENCAPS):
            return packet
        if not self.secure_devices.is_secure(packet.sender_int):
            packet.secure_status = SECURE_STATUS.UNKNOWN_KEY
            return packet
        if packet.rorg == RORG.SEC:
            packet.secure_status = SECURE_STATUS.UNSUPPORTED
            return packet
        result = self.secure_devices.decrypt(packet.sender_int, packet.rorg, packet.data[1:-5])
        if result is None:
            packet.secure_status = SECURE_STATUS.REJECTED
            return packet
        rorg, payload = result
        packet_class = UTETeachInPacket if rorg == RORG.UTE else RadioPacket
        decrypted = packet_class(packet.packet_type, data=[rorg] + list(payload) + packet.data[-5:],
                                 optional=packet.optional)
        decrypted.received = packet.received
        decrypted.secure_status = SECURE_STATUS.DECRYPTED
        return decrypted

    def stop(self):
        self._stop_flag.set()

    def parse(self):
        ''' Parses messages and puts them to receive queue '''
        # Loop while we get new messages
        while True:
            status, self._buffer, packet = Packet.parse_msg(self._buffer)
            # If message is incomplete -> break the loop
            if status == PARSE_RESULT.INCOMPLETE:
                return status

            # If message is OK, add it to receive queue or send to the callback method
            if status == PARSE_RESULT.OK and packet:
                packet.received = datetime.datetime.now()

                # Ignore radio packets sent from our own Base ID, e.g. our own packets
                # repeated by a repeater. Otherwise we would react to them, e.g. answer our
                # own UTE teach-in response again and again.
                if (isinstance(packet, RadioPacket) and self._base_id is not None
                        and list(packet.sender) == list(self._base_id)):
                    self.logger.debug('Ignoring packet sent from own Base ID.')
                    continue

                if isinstance(packet, RadioPacket) and self.secure_devices is not None:
                    packet = self._decrypt(packet)

                # Only answer if the device expects a response (UTE DB6.6 = 0).
                # Some devices, e.g. LUNOS UNI-EO, send unidirectional requests
                # with no response expected.
                if isinstance(packet, UTETeachInPacket) and self.teach_in and packet.response_expected:
                    response_packet = packet.create_response_packet(self.base_id)
                    self.logger.info('Sending response to UTE teach-in.')
                    self.send(response_packet)

                if self.__callback is None:
                    self.receive.put(packet)
                else:
                    self.__callback(packet)
                self.logger.debug(packet)

    @property
    def base_id(self):
        ''' Fetches Base ID from the transmitter, if required. Otherwise returns the currently set Base ID. '''
        # If base id is already set, return it.
        if self._base_id is not None:
            return self._base_id

        # Send COMMON_COMMAND 0x08, CO_RD_IDBASE request to the module
        self.send(Packet(PACKET.COMMON_COMMAND, data=[0x08]))
        # Loop over 10 times, to make sure we catch the response.
        # Thanks to timeout, shouldn't take more than a second.
        # Unfortunately, all other messages received during this time are ignored.
        for i in range(0, 10):
            try:
                packet = self.receive.get(block=True, timeout=0.1)
                # We're only interested in responses to the request in question.
                if packet.packet_type == PACKET.RESPONSE and packet.response == RETURN_CODE.OK and len(packet.response_data) == 4:  # noqa: E501
                    # Base ID is set in the response data.
                    self._base_id = packet.response_data
                    # Put packet back to the Queue, so the user can also react to it if required...
                    self.receive.put(packet)
                    break
                # Put other packets back to the Queue.
                self.receive.put(packet)
            except queue.Empty:
                continue
        # Return the current Base ID (might be None).
        return self._base_id

    @base_id.setter
    def base_id(self, base_id):
        ''' Sets the Base ID manually, only for testing purposes. '''
        self._base_id = base_id
