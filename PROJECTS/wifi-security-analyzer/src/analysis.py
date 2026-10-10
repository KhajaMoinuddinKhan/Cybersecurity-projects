"""Evidence-based checks for observed access-point advertisements."""
from __future__ import annotations

from .baseline import WifiBaseline
from .models import AccessPoint, Finding, NetworkAssessment

_LEGACY_CIPHERS = frozenset({"WEP-40", "WEP-104", "TKIP"})


def _security_signature(profile):
    return (
        profile.protocols, profile.authentication_suites, profile.pairwise_ciphers,
        profile.group_ciphers, profile.pmf_capable, profile.pmf_required,
        profile.wps_advertised, profile.privacy_enabled, profile.parse_errors,
    )


def _is_definite_downgrade(previous, current) -> bool:
    """Only label changes supported by directly observed security attributes."""
    if previous.parse_errors or current.parse_errors:
        return False
    if "RSN" in previous.protocols and "RSN" not in current.protocols:
        return True
    old_ciphers = set(previous.pairwise_ciphers + previous.group_ciphers)
    new_ciphers = set(current.pairwise_ciphers + current.group_ciphers)
    if old_ciphers and old_ciphers.isdisjoint(_LEGACY_CIPHERS) and not new_ciphers.isdisjoint(_LEGACY_CIPHERS):
        return True
    if "SAE" in previous.authentication_suites and "SAE" not in current.authentication_suites:
        return True
    if previous.pmf_required is True and current.pmf_required is not True:
        return True
    if previous.protocols and not current.protocols and not current.privacy_enabled:
        return True
    return False


def _baseline_findings(access_point: AccessPoint, baseline: WifiBaseline | None) -> tuple[Finding, ...]:
    if baseline is None:
        return ()
    exact = next((entry for entry in baseline.access_points if entry.bssid == access_point.bssid), None)
    same_ssid = (
        [entry for entry in baseline.access_points if entry.ssid_hex == access_point.ssid_hex]
        if access_point.ssid_bytes else []
    )
    findings: list[Finding] = []
    if exact is None:
        if same_ssid:
            findings.append(Finding(
                "UNRECOGNIZED_BSSID", "MEDIUM",
                "An unapproved, potentially legitimate BSSID advertises an SSID present in the baseline; review it as a possible topology change or impersonation.",
                (f"Observed BSSID: {access_point.bssid}",
                 "A mesh, roaming, hardware replacement, or unauthorized access point can produce this observation; it is not proof of an evil twin."),
            ))
        return tuple(findings)

    if exact.ssid_hex != access_point.ssid_hex:
        findings.append(Finding(
            "BASELINE_SSID_CHANGED", "MEDIUM",
            "A baselined BSSID is now advertising different SSID bytes.",
            (f"Baseline SSID bytes: {exact.ssid_hex}", f"Observed SSID bytes: {access_point.ssid_hex}"),
        ))
    if _security_signature(exact.security) != _security_signature(access_point.security):
        if _is_definite_downgrade(exact.security, access_point.security):
            findings.append(Finding(
                "SECURITY_DOWNGRADE", "HIGH",
                "A baselined BSSID now advertises weaker security attributes.",
                (f"Baseline security: {exact.security.security_label}",
                 f"Observed security: {access_point.security.security_label}"),
            ))
        else:
            findings.append(Finding(
                "SECURITY_PROFILE_CHANGED", "MEDIUM",
                "A baselined BSSID advertises a different security profile; review the change.",
                (f"Baseline security: {exact.security.security_label}",
                 f"Observed security: {access_point.security.security_label}"),
            ))
    return tuple(findings)


def _assess_one(access_point: AccessPoint) -> tuple[Finding, ...]:
    security = access_point.security
    findings: list[Finding] = []

    if security.parse_errors:
        findings.append(Finding(
            "MALFORMED_SECURITY_IE", "INFO",
            "Security information was malformed; the analyzer cannot make a complete assessment.",
            tuple(security.parse_errors),
        ))
    elif not security.protocols and not security.privacy_enabled:
        findings.append(Finding(
            "OPEN_NETWORK", "MEDIUM",
            "The access point advertises no link-layer security.",
            ("No RSN or WPA security element was present and the privacy capability bit was clear.",),
        ))
    elif not security.protocols and security.privacy_enabled:
        findings.append(Finding(
            "LEGACY_PRIVACY_UNKNOWN", "MEDIUM",
            "Privacy is set but no recognized WPA or RSN element is advertised.",
            ("The advertisement may use WEP or an unrecognized legacy scheme; the analyzer does not guess which.",),
        ))

    legacy_ciphers = tuple(sorted(set(security.pairwise_ciphers + security.group_ciphers) & _LEGACY_CIPHERS))
    if legacy_ciphers:
        findings.append(Finding(
            "LEGACY_CIPHER", "HIGH",
            "The access point advertises a legacy WEP or TKIP cipher.", legacy_ciphers,
        ))
    if "WPA" in security.protocols and "RSN" not in security.protocols:
        findings.append(Finding(
            "LEGACY_WPA", "HIGH",
            "The access point advertises legacy WPA without RSN security.",
            ("Observed protocol elements: WPA; RSN was not present.",),
        ))
    if security.wps_advertised:
        findings.append(Finding(
            "WPS_ADVERTISED", "INFO",
            "The access point advertises WPS; this observation alone does not establish a vulnerability.",
            ("A Wi-Fi Protected Setup vendor information element was present.",),
        ))
    if "RSN" in security.protocols and security.pmf_capable is False:
        findings.append(Finding(
            "PMF_NOT_ADVERTISED", "INFO",
            "The RSN information element does not advertise protected management-frame capability.",
            ("The RSN capabilities field was present and its MFPC bit was clear.",),
        ))
    elif "RSN" in security.protocols and security.pmf_capable is True and security.pmf_required is False:
        findings.append(Finding(
            "PMF_NOT_REQUIRED", "INFO",
            "Protected management frames are advertised as capable but not required.",
            ("The RSN capabilities field advertised MFPC without MFPR.",),
        ))
    return tuple(findings)


def analyze_access_points(
    access_points: list[AccessPoint] | tuple[AccessPoint, ...], *, baseline: WifiBaseline | None = None
) -> tuple[NetworkAssessment, ...]:
    """Assess supplied observations; an empty scan is valid and produces no findings."""
    if not isinstance(access_points, (list, tuple)):
        raise TypeError("access points must be a list or tuple of observations")
    if any(not isinstance(item, AccessPoint) for item in access_points):
        raise TypeError("every scan item must be an AccessPoint observation")
    if baseline is not None and not isinstance(baseline, WifiBaseline):
        raise TypeError("baseline must be a WifiBaseline or None")
    return tuple(
        NetworkAssessment(item, _assess_one(item) + _baseline_findings(item, baseline))
        for item in access_points
    )
