import pytest
from src.aggregator import normalise_row


@pytest.mark.parametrize("row", [{"type": None, "value": "x"}, {"type": "ip", "value": 42}, {"type": "ip", "value": "x", "source": []}])
def test_non_string_fields_are_rejected(row):
    with pytest.raises(ValueError):
        normalise_row(row)
