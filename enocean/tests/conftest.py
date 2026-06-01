"""Test configuration for enocean tests."""

import pytest


# Disable pytest-asyncio's autouse fixtures for synchronous tests
# This prevents warnings about async fixtures in non-async test functions
@pytest.fixture
def enable_event_loop_debug():
    """Override pytest-asyncio's autouse fixture to prevent warnings."""
    pass
