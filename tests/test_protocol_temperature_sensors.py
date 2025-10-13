from decorators import timing
from enocean.protocol.eep import EEP

eep = EEP()


@timing(1000)
def test_first_range():
    offset = -40
    values = range(0x01, 0x0C)
    for i in range(len(values)):
        minimum = float(i * 10 + offset)
        maximum = minimum + 40
        profile = eep.find_profile([], 0xA5, 0x02, values[i])
        assert profile is not None
        scale = profile.find('scale')
        if scale:
            assert scale.find('min').text == str(minimum)
            assert scale.find('max').text == str(maximum)


@timing(1000)
def test_second_range():
    offset = -60
    values = range(0x10, 0x1C)
    for i in range(len(values)):
        minimum = float(i * 10 + offset)
        maximum = minimum + 80
        profile = eep.find_profile([], 0xA5, 0x02, values[i])
        assert profile is not None
        scale = profile.find('scale')
        if scale:
            assert scale.find('min').text == str(minimum)
            assert scale.find('max').text == str(maximum)


@timing(1000)
def test_rest():
    profile = eep.find_profile([], 0xA5, 0x02, 0x20)
    assert profile is not None
    scale = profile.find('scale')
    if scale:
        assert scale.find('min').text == '-10.0'
        assert scale.find('max').text == '41.2'

    profile = eep.find_profile([], 0xA5, 0x02, 0x30)
    assert profile is not None
    scale = profile.find('scale')
    if scale:
        assert scale.find('min').text == '-40.0'
        assert scale.find('max').text == '62.3'