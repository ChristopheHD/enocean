import io
import os

from generate_supported_profiles import generate

DOC_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'SUPPORTED_PROFILES.md')


def test_supported_profiles_up_to_date():
    buffer = io.StringIO()
    generate(buffer)

    with io.open(DOC_PATH, encoding='utf-8') as f_handle:
        committed = f_handle.read()

    assert buffer.getvalue() == committed, \
        'SUPPORTED_PROFILES.md is out of date, run generate_supported_profiles.py'
