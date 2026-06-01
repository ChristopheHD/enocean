"""Generic EEP field metadata and mappings.

This module builds field definitions dynamically from the bundled EEP.xml and
exposes utilities to load metadata for arbitrary telegram profiles. Use
``load_eep_fields`` with the appropriate telegram/profile identifiers.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from enocean.protocol.eep import get_eep

_LOGGER = logging.getLogger(__name__)

_EEP_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "EEP.xml")


def _build_enum_map(enum_element) -> dict[int, str]:
    """Create a value-to-description mapping from an <enum> element."""

    enum_map: dict[int, str] = {}

    for item in enum_element.find_all("item", recursive=False):
        try:
            enum_map[int(item["value"])] = item.get("description", "")
        except (KeyError, ValueError):
            continue

    for range_item in enum_element.find_all("rangeitem", recursive=False):
        try:
            start = int(range_item.get("start", -1))
            end = int(range_item.get("end", start))
        except ValueError:
            continue

        for value in range(start, end + 1):
            enum_map[value] = range_item.get("description", "").format(value=value)

    return enum_map


def load_eep_fields(
    telegram_rorg: str, profiles_func: str, profile_type: str
) -> dict[str, dict[str, Any]]:
    """Load EEP field metadata for a given telegram/profile identifiers.

    Args:
        telegram_rorg: Value of the telegram's ``rorg`` attribute (e.g. "0xD1079")
        profiles_func: Value of the enclosing ``profiles`` element's ``func``
            attribute (e.g. "0x01")
        profile_type: Value of the ``profile`` element's ``type`` attribute
            (e.g. "0x00")

    Returns:
        Mapping of field shortcuts to metadata dicts. Returns an empty dict on
        failure to read or find matching nodes.
    """

    # Use cached EEP parser to avoid repeatedly opening/parsing EEP.xml
    eep = get_eep()
    if not eep or not getattr(eep, "init_ok", False):
        _LOGGER.warning("Unable to load EEP.xml via cached EEP instance")
        return {}

    soup = eep.soup

    # Find matching telegram(s)
    telegrams = soup.find_all("telegram", {"rorg": telegram_rorg})
    if not telegrams:
        _LOGGER.debug("Telegram (rorg=%s) not found in EEP.xml", telegram_rorg)
        return {}

    # Find the profiles block with the specified func attribute
    profiles = None
    for telegram in telegrams:
        profiles = telegram.find("profiles", {"func": profiles_func})
        if profiles:
            break

    if not profiles:
        _LOGGER.debug(
            "Profiles with func=%s not found for telegram rorg=%s",
            profiles_func,
            telegram_rorg,
        )
        return {}

    profile = profiles.find("profile", {"type": profile_type})
    if not profile:
        _LOGGER.debug(
            "Profile with type=%s not found under profiles func=%s",
            profile_type,
            profiles_func,
        )
        return {}

    fields: dict[str, dict[str, Any]] = {}

    for data in profile.find_all("data", recursive=False):
        for element in data.find_all(["enum", "value"], recursive=False):
            shortcut = element.get("shortcut")
            if not shortcut:
                continue

            metadata: dict[str, Any] = {
                "name": element.get("description"),
                "unit": (element.get("unit") or None),
            }

            if element.name == "enum":
                enum_map = _build_enum_map(element)
                if enum_map:
                    metadata["enum_map"] = enum_map

            fields[shortcut] = metadata

    return fields


def get_field_metadata(
    field_shortcut: str, fields: dict[str, dict[str, Any]]
) -> dict[str, Any] | None:
    """Get metadata for a field from the provided fields mapping.

    This function requires a fields mapping returned by :func:`load_eep_fields`.
    """
    if not fields:
        return None
    return fields.get(field_shortcut)


def get_field_value_with_enum(
    parsed_data: dict[str, Any], field_shortcut: str, fields: dict[str, dict[str, Any]]
) -> Any | None:
    """Get a field value from parsed data, applying enum mapping if available.

    Args:
        parsed_data: Dictionary from a parser's `parse_packet()` result
        field_shortcut: Field shortcut (e.g., "MF")
        fields: Fields mapping returned by :func:`load_eep_fields` used for
            enum resolution (required)
    """
    if not parsed_data or not fields:
        return None

    value = parsed_data.get(field_shortcut)
    if value is None:
        return None

    metadata = fields.get(field_shortcut)
    if metadata and "enum_map" in metadata:
        return metadata["enum_map"].get(value, value)

    return value
