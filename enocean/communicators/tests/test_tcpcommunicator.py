# -*- encoding: utf-8 -*-
from __future__ import print_function, unicode_literals, division, absolute_import
import pytest
import socket
from unittest.mock import MagicMock, patch
from enocean.communicators.tcpcommunicator import TCPCommunicator


def test_tcp_communicator_init():
    ''' Test TCPCommunicator initialization '''
    with pytest.raises(TypeError):
        TCPCommunicator()
    com = TCPCommunicator('127.0.0.1')
    assert com.host == '127.0.0.1'
    assert com.port == 9637
    assert com.max_buffer_size == 10 * 1024 * 1024


@patch('socket.socket')
def test_tcp_communicator_buffer_limit(mock_socket_cls):
    ''' Test TCPCommunicator buffer limit '''
    mock_sock = MagicMock()
    mock_socket_cls.return_value = mock_sock

    mock_client = MagicMock()
    # accept once, then timeout to exit the outer loop (if _stop_flag is set)
    mock_sock.accept.side_effect = [(mock_client, ('127.0.0.1', 12346)), socket.timeout]

    # Simulate receiving data: first chunk is fine, second chunk exceeds limit
    # We use 0x55 to avoid the buffer being cleared by parse() if it thinks the data is garbage
    mock_client.recv.side_effect = [b'\x55' + b'A' * 59, b'A' * 60]

    com = TCPCommunicator('127.0.0.1')
    com.max_buffer_size = 100

    # We want to stop AFTER the first client is handled.
    # We can't easily do it without threading or side effects.
    # Let's make the second accept call set the stop flag.
    def side_effect_accept():
        if mock_sock.accept.call_count == 2:
            com._stop_flag.set()
            raise socket.timeout
        return (mock_client, ('127.0.0.1', 12346))

    mock_sock.accept.side_effect = side_effect_accept

    com.run()

    # recv should be called twice: once for the first chunk, once for the chunk that exceeds the limit
    assert mock_client.recv.call_count == 2
    # The first chunk should be in the buffer, the second one should be dropped
    assert len(com._buffer) == 60
    # Connection should be closed after breaking the loop
    mock_client.close.assert_called_once()
