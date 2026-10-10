import pytest

from src.channels import channel_details


@pytest.mark.parametrize(("frequency_khz", "band", "channel"), [
    (2412000, "2.4 GHz", 1),
    (2437000, "2.4 GHz", 6),
    (2462000, "2.4 GHz", 11),
    (2484000, "2.4 GHz", 14),
    (5180000, "5 GHz", 36),
    (5745000, "5 GHz", 149),
    (5955000, "6 GHz", 1),
    (5975000, "6 GHz", 5),
    (7115000, "6 GHz", 233),
])
def test_real_center_frequency_maps_to_its_band_and_channel(frequency_khz, band, channel):
    assert channel_details(frequency_khz) == (band, channel)


@pytest.mark.parametrize("frequency_khz", [0, -1, 1000, 2500000, 4899000, 7126000, 60000000])
def test_out_of_scope_frequency_is_not_assigned_a_channel(frequency_khz):
    assert channel_details(frequency_khz) == ("Unknown", None)


@pytest.mark.parametrize(("frequency_khz", "band"), [(2485000, "2.4 GHz"), (5181000, "5 GHz"), (5926000, "6 GHz")])
def test_in_band_non_channel_center_keeps_only_the_band(frequency_khz, band):
    assert channel_details(frequency_khz) == (band, None)


@pytest.mark.parametrize("frequency_khz", [True, 5180.0, "5180000", None])
def test_frequency_requires_an_integer_kilohertz_value(frequency_khz):
    with pytest.raises((TypeError, ValueError)):
        channel_details(frequency_khz)
