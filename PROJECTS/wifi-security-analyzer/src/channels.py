"""Translate a Windows WLAN center frequency into a band and channel."""


def channel_details(center_frequency_khz: int) -> tuple[str, int | None]:
    """Return the band and channel derived from the reported center frequency.

    The band is retained when the frequency is in a recognized band but is not
    a recognized 20 MHz channel center. Unknown bands are never guessed.
    """
    if isinstance(center_frequency_khz, bool) or not isinstance(center_frequency_khz, int):
        raise TypeError("center frequency must be an integer number of kilohertz")
    frequency = center_frequency_khz
    if frequency <= 0:
        return "Unknown", None

    if 2_400_000 <= frequency < 2_500_000:
        if frequency == 2_484_000:
            return "2.4 GHz", 14
        first = 2_412_000
        last = 2_472_000
        if first <= frequency <= last and (frequency - first) % 5_000 == 0:
            return "2.4 GHz", (frequency - first) // 5_000 + 1
        return "2.4 GHz", None

    if 4_900_000 <= frequency < 5_925_000:
        base = 4_000_000 if frequency < 5_000_000 else 5_000_000
        delta = frequency - base
        if delta > 0 and delta % 5_000 == 0:
            return "5 GHz", delta // 5_000
        return "5 GHz", None

    if 5_925_000 <= frequency <= 7_125_000:
        if frequency == 5_935_000:
            return "6 GHz", 2
        delta = frequency - 5_950_000
        if delta >= 5_000 and delta % 5_000 == 0:
            channel = delta // 5_000
            if 1 <= channel <= 233:
                return "6 GHz", channel
        return "6 GHz", None

    return "Unknown", None
