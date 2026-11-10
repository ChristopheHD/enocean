# -*- encoding: utf-8 -*-
''' Tests EEP D2-33-00 (Intelligent, Bi-directional Heaters and Controllers).

Expected values are computed by hand from the bit layouts of the EEP specification,
and frames sent by a gateway to EQUATION Sorali heaters (decrypted). '''
from __future__ import print_function, unicode_literals, division, absolute_import

from enocean.protocol.packet import Packet, RadioPacket
from enocean.protocol.constants import PACKET, RORG

SENDER = [0x05, 0x0F, 0x1E, 0x57]


def parse(payload):
    ''' Parses a D2-33-00 telegram with the given payload (after the RORG) '''
    data = [RORG.VLD] + payload + SENDER + [0x00]
    raw = Packet(PACKET.RADIO_ERP1, data=data, optional=[0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x46, 0x00])
    _, _, packet = Packet.parse_msg(bytearray(raw.build()))
    packet.parse_eep(0x33, 0x00)
    return packet.parsed


def create(mid, **values):
    ''' Creates a D2-33-00 telegram, returns its payload (after the RORG) '''
    packet = RadioPacket.create(RORG.VLD, 0x33, 0x00, command=mid, sender=SENDER,
                                destination=[0x05, 0x8E, 0xDA, 0x56], MID=mid, **values)
    return packet.data[1:-5]


def test_gateway_request_status():
    parsed = parse([0x08, 0x00, 0x00])
    assert parsed['MID']['raw_value'] == 0
    assert parsed['REQ']['value'] == 'Question: status and flags'
    assert create(0, REQ=8) == [0x08, 0x00, 0x00]


def test_gateway_acknowledge():
    assert parse([0x0F, 0x00, 0x00])['REQ']['value'] == 'Acknowledge frame'
    assert create(0, REQ=15) == [0x0F, 0x00, 0x00]


def test_gateway_external_temperature():
    # EXT: 9 bits at offset 8, 20.5 °C = 205 = 0b011001101
    payload = [0x0D, 0b01100110, 0b10000000]
    parsed = parse(payload)
    assert parsed['REQ']['value'] == 'Information to heater'
    assert round(parsed['EXT']['value'], 1) == 20.5
    assert create(0, REQ=13, EXT=20.5) == payload


def test_sensor_parameters():
    # Default temperature scale (TSS=1), display the setpoint (DCS=5), derogation allowed (DGS=1)
    parsed = parse([0x10, 0x00, 0x12, 0xC0])
    assert parsed['MID']['value'] == 'Sensor parameters'
    assert parsed['WOS']['raw_value'] == 0
    assert parsed['TSS']['value'] == 'Default'
    assert parsed['TNS']['value'] == 'No change'
    assert parsed['DCS']['value'] == 'Temperature setpoint'
    assert parsed['DGS']['value'] == 'Derogation is allowed'
    assert create(1, TSS=1, DCS=5, DGS=1) == [0x10, 0x00, 0x12, 0xC0]


def test_program_permanent_setpoint():
    # One time program with start = stop (Monday 00:00), i.e. a permanent setpoint of 9.0 °C
    parsed = parse([0x20, 0x00, 0x00, 0x00, 0x16, 0x80])
    assert parsed['MID']['value'] == 'Program'
    assert parsed['TPT']['value'] == 'One time'
    for field in ('ETD', 'ETM', 'ETH', 'STD', 'STM', 'STH', 'CSC'):
        assert parsed[field]['raw_value'] == 0
    assert parsed['TSP']['raw_value'] == 90
    assert round(parsed['TSP']['value'], 1) == 9.0
    assert create(2, TSP=9.0) == [0x20, 0x00, 0x00, 0x00, 0x16, 0x80]


def test_program_setpoint_resolution():
    # TSP: 9 bits at offset 33, value / 10 °C
    for raw in range(1, 501):
        payload = create(2, TSP=raw / 10)
        assert (((payload[4] & 0x7F) << 2) | (payload[5] >> 6)) == raw
        assert round(parse(payload)['TSP']['value'], 1) == raw / 10


def test_program_weekly_timeslot():
    # Weekly, Tuesday 06:30 to Friday 22:15 at 19.5 °C
    bits = '0010' + '1' + '100' + '001111' + '10110' + '001' + '011110' + '00110' + '011000011' + '0' + '00000'
    payload = [int(bits[i:i + 8], 2) for i in range(0, 48, 8)]
    parsed = parse(payload)
    assert parsed['TPT']['value'] == 'Weekly'
    assert parsed['ETD']['value'] == 'Friday'
    assert (parsed['ETH']['raw_value'], parsed['ETM']['raw_value']) == (22, 15)
    assert parsed['STD']['value'] == 'Tuesday'
    assert (parsed['STH']['raw_value'], parsed['STM']['raw_value']) == (6, 30)
    assert round(parsed['TSP']['value'], 1) == 19.5
    assert create(2, TPT=1, ETD=4, ETM=15, ETH=22, STD=1, STM=30, STH=6, TSP=19.5) == payload


def test_time_and_date():
    # Monday 2026-10-26 14:30
    bits = '0011' + '11010' + '1010' + '011111101010' + '011110' + '01110' + '000' + '0'
    payload = [int(bits[i:i + 8], 2) for i in range(0, 40, 8)]
    parsed = parse(payload)
    assert parsed['MID']['value'] == 'Time and date'
    assert [parsed[f]['raw_value'] for f in ('DAY', 'MON', 'YR', 'HR', 'MIN')] == [26, 10, 2026, 14, 30]
    assert parsed['DAYW']['value'] == 'Monday'
    assert create(3, DAY=26, MON=10, YR=2026, MIN=30, HR=14, DAYW=0) == payload


def test_heater_status():
    # Information to gateway, heating, window closed, 21.3 °C internal temperature (213 = 0b011010101)
    bits = '1000' + '0100' + '0' * 16 + '1' + '00' + '01' + '00' + '0' + '0' + '0' + '011010101' + '00000'
    payload = [int(bits[i:i + 8], 2) for i in range(0, 48, 8)]
    assert payload == [0x84, 0x00, 0x00, 0x88, 0x1A, 0xA0]
    parsed = parse(payload)
    assert parsed['MID']['value'] == 'Request and status'
    assert parsed['REQ']['value'] == 'Information to gateway'
    assert parsed['ERF']['raw_value'] == 0
    assert parsed['HTF']['value'] == 'Heating up'
    assert parsed['PWF']['value'] == 'No pilot wire'
    assert parsed['WOF']['value'] == 'Close'
    assert parsed['PIF']['value'] == 'Disabled'
    assert parsed['KLU']['value'] == 'Key Lock is disabled'
    assert parsed['RTF']['value'] == 'Internal'
    assert parsed['DGF']['value'] == 'No derogation'
    assert round(parsed['INT']['value'], 1) == 21.3


def test_heater_requests():
    assert parse([0x83, 0x00, 0x00, 0x00, 0x00, 0x00])['REQ']['value'] == 'Question Time and date'
    assert parse([0x82, 0x00, 0x00, 0x00, 0x00, 0x00])['REQ']['value'] == 'Question Program'
    assert parse([0x8F, 0x00, 0x00, 0x00, 0x00, 0x00])['REQ']['value'] == 'Acknowledge frame'


def test_heater_parameters():
    # 1234.5 kWh (12345), derogation setpoint 19.0 °C (190), firmware version 100
    bits = '1001' + format(12345, '024b') + format(190, '09b') + format(100, '010b') + '0'
    payload = [int(bits[i:i + 8], 2) for i in range(0, 48, 8)]
    parsed = parse(payload)
    assert parsed['MID']['value'] == 'Heater parameters'
    assert round(parsed['EM']['value'], 1) == 1234.5
    assert round(parsed['DTS']['value'], 1) == 19.0
    assert parsed['FWV']['raw_value'] == 100


def test_heater_error_flags():
    # ERF is a set of error flags (heaters report 0 when everything is fine):
    # temperature sensor open (bit 0) and temperature greater than 50 °C (bit 2)
    bits = '1000' + '0100' + format(0b101, '016b') + '0' * 24
    payload = [int(bits[i:i + 8], 2) for i in range(0, 48, 8)]
    parsed = parse(payload)
    assert parsed['ERF']['raw_value'] == 0b101
    assert parsed['ERF']['value'] == 0b101


def test_air_hygrometry_pressure_temperature():
    # Sent by EQUATION Sorali heaters along with their status, although not listed for type 0x00:
    # INT is 11 bits at offset 33, 19.9 °C = 199
    payload = [0xC0, 0x00, 0x00, 0x00, 0x0C, 0x70]
    parsed = parse(payload)
    assert parsed['MID']['value'] == 'Value of air, hygro., pressure and temp.'
    assert round(parsed['INT']['value'], 1) == 19.9
    assert [parsed[field]['raw_value'] for field in ('AMV', 'PRV', 'HYV')] == [0, 0, 0]

    # 2 m/s air moving, pressure 1013 hPa (spec range 1...1023 for 500...1150 hPa), 45 % (90), 21.5 °C (215)
    bits = '1100' + '0010' + '0' * 7 + format(808, '010b') + format(90, '08b') + format(215, '011b') + '0000'
    payload = [int(bits[i:i + 8], 2) for i in range(0, 48, 8)]
    parsed = parse(payload)
    assert parsed['AMV']['raw_value'] == 2
    assert round(parsed['PRV']['value']) == 1013
    assert round(parsed['HYV']['value']) == 45
    assert round(parsed['INT']['value'], 1) == 21.5
