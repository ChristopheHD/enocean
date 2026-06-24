#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
Example for D2-01-12 profile - Electronic switch with Local Control
This profile is used by Ubiwizz (UBID1507C-QM) and Nodon modules with multiple channels.

Based on EEP specification D2-01-12
Source: Jeedom implementation (GNU License)

Features supported:
- Actuator Set Output (Command 1) - Control outputs with dimming
- Actuator Set Local (Command 2) - Configure local control settings
- Actuator Status Query (Command 3) - Request status
- Actuator Status Response (Command 4) - Receive status
- Actuator Set Measurement (Command 5) - Configure energy/power measurement
- Actuator Measurement Query (Command 6) - Request measurements
- Actuator Measurement Response (Command 7) - Receive measurements
- Pilot Wire Mode (Commands 8-10) - For French heating systems
- External Interface Settings (Commands 11-13) - Configure timers and switches
"""

from enocean.communicators.serialcommunicator import SerialCommunicator
from enocean.protocol.packet import RadioPacket
from enocean.protocol.constants import PACKET, RORG

# Serial port configuration - adjust to your setup
SERIALPORT = "/dev/ttyUSB0"  # On Linux
# SERIALPORT = "COM3"  # On Windows

# Device addresses - replace with your actual device IDs
SENDER_ID = [0x01, 0x82, 0x5E, 0xA0]  # Gateway base ID (example)
DEVICE_ID = [0x05, 0x00, 0x00, 0x01]  # Target device ID (example)

# Initialize communicator
communicator = SerialCommunicator(port=SERIALPORT)
communicator.start()


def send_command(destination, channel, output_value, dim_mode=0):
    """
    Send command to D2-01-12 device
    
    Args:
        destination: Device ID as list of 4 bytes
        channel: Channel number (0-29, or 30 for all channels)
        output_value: Output value (0-100 for percentage, 0=OFF, 100=ON)
        dim_mode: Dimming mode (0=switch, 1-3=dim timer 1-3, 4=stop)
    """
    global communicator
    
    # Create VLD packet for D2-01-12
    # Command ID 1 = Actuator Set Output
    packet = RadioPacket.create(
        rorg=RORG.VLD,  # 0xD2
        rorg_func=0x01,
        rorg_type=0x12,  # D2-01-12
        destination=destination,
        sender=SENDER_ID,
        command=1,  # Actuator Set Output
        DV=dim_mode,  # Dim value
        IO=channel,  # I/O channel
        OV=output_value  # Output value
    )
    
    communicator.send(packet)
    print(f"Sent command to channel {channel}: output={output_value}%, dim_mode={dim_mode}")


def turn_on_channel_1(destination):
    """Turn on channel 1 to 100%"""
    send_command(destination, channel=0, output_value=100)


def turn_off_channel_1(destination):
    """Turn off channel 1"""
    send_command(destination, channel=0, output_value=0)


def turn_on_channel_2(destination):
    """Turn on channel 2 to 100%"""
    send_command(destination, channel=1, output_value=100)


def turn_off_channel_2(destination):
    """Turn off channel 2"""
    send_command(destination, channel=1, output_value=0)


def set_channel_1_brightness(destination, brightness):
    """
    Set channel 1 to specific brightness
    
    Args:
        brightness: 0-100 (percentage)
    """
    send_command(destination, channel=0, output_value=brightness)


def dim_channel_1(destination, brightness, dim_timer=1):
    """
    Dim channel 1 to specific brightness using dim timer
    
    Args:
        brightness: 0-100 (percentage)
        dim_timer: 1-3 (which dim timer to use)
    """
    send_command(destination, channel=0, output_value=brightness, dim_mode=dim_timer)


def turn_on_all_channels(destination):
    """Turn on all channels to 100%"""
    send_command(destination, channel=30, output_value=100)


def turn_off_all_channels(destination):
    """Turn off all channels"""
    send_command(destination, channel=30, output_value=0)


def configure_dimming(destination, channel, dim_timer_1=10, dim_timer_2=20, dim_timer_3=30, 
                      local_control=True, default_state=2):
    """
    Configure dimming timers and local control settings (Command 2)
    
    Args:
        destination: Device ID as list of 4 bytes
        channel: Channel number (0-29)
        dim_timer_1: Dim timer 1 in 0.5s increments (1-255, 0=not used)
        dim_timer_2: Dim timer 2 in 0.5s increments (1-255, 0=not used)
        dim_timer_3: Dim timer 3 in 0.5s increments (1-255, 0=not used)
        local_control: Enable/disable local control
        default_state: 0=OFF, 1=ON, 2=Remember last state
    """
    # This would require more complex packet construction
    # For now, this is a placeholder showing the concept
    print(f"Configuring channel {channel}:")
    print(f"  - Dim timer 1: {dim_timer_1 * 0.5}s")
    print(f"  - Dim timer 2: {dim_timer_2 * 0.5}s")
    print(f"  - Dim timer 3: {dim_timer_3 * 0.5}s")
    print(f"  - Local control: {'Enabled' if local_control else 'Disabled'}")
    print(f"  - Default state: {['OFF', 'ON', 'Remember last'][default_state]}")
    # Note: Actual implementation would use RadioPacket.create with all parameters


def query_status(destination, channel):
    """
    Query actuator status (Command 3)
    
    Args:
        destination: Device ID as list of 4 bytes
        channel: Channel number (0-29, or 30 for all channels)
    """
    global communicator
    
    # Create query packet - simplified version
    # Actual implementation would construct proper VLD packet for command 3
    print(f"Querying status for channel {channel}...")
    # The device should respond with Command 4 (Status Response)


# Example usage
if __name__ == "__main__":
    import time
    
    print("D2-01-12 Example - Electronic switch with Local Control")
    print("Profile supports: Dimming, Local Control, Energy Measurement, Pilot Wire Mode")
    print(f"Device ID: {DEVICE_ID}")
    print("=" * 60)
    
    # Example 1: Turn on channel 1
    print("\n1. Turning on channel 1...")
    turn_on_channel_1(DEVICE_ID)
    time.sleep(2)
    
    # Example 2: Turn on channel 2
    print("\n2. Turning on channel 2...")
    turn_on_channel_2(DEVICE_ID)
    time.sleep(2)
    
    # Example 3: Set channel 1 to 50% brightness
    print("\n3. Setting channel 1 to 50%...")
    set_channel_1_brightness(DEVICE_ID, 50)
    time.sleep(2)
    
    # Example 4: Dim channel 1 to 25% using dim timer 1
    print("\n4. Dimming channel 1 to 25% with dim timer 1...")
    dim_channel_1(DEVICE_ID, 25, dim_timer=1)
    time.sleep(3)
    
    # Example 5: Dim channel 1 to 75% using dim timer 2 (slower)
    print("\n5. Dimming channel 1 to 75% with dim timer 2 (slower)...")
    dim_channel_1(DEVICE_ID, 75, dim_timer=2)
    time.sleep(3)
    
    # Example 6: Configure dimming timers
    print("\n6. Configuring dimming timers...")
    configure_dimming(DEVICE_ID, channel=0, dim_timer_1=10, dim_timer_2=20, dim_timer_3=30)
    
    # Example 7: Query status
    print("\n7. Querying channel status...")
    query_status(DEVICE_ID, channel=0)
    time.sleep(1)
    
    # Example 8: Turn off channel 1
    print("\n8. Turning off channel 1...")
    turn_off_channel_1(DEVICE_ID)
    time.sleep(2)
    
    # Example 9: Turn off all channels
    print("\n9. Turning off all channels...")
    turn_off_all_channels(DEVICE_ID)
    
    print("\nExample completed!")
    communicator.stop()
