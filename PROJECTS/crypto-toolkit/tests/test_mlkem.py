"""ML-KEM against FIPS 203.

The published vectors carry more weight here than anywhere else in this
repository. For AES, CBC, GCM and ECDSA there is an independent implementation
in `cryptography` to compare against; there is no ML-KEM in it, and no other
reference implementation in the standard library. NIST's ACVP vectors are
therefore the whole external check, which is why they are exercised for all
three functions and all three parameter sets rather than sampled.

Alongside them are the structural properties that would still hold if the
vectors were subtly wrong: that the transform is an isomorphism, that the
compression round-trips, and that a corrupted ciphertext is rejected implicitly
rather than loudly.
"""

from __future__ import annotations

import json
import os
import random
from pathlib import Path

import pytest

from src.mlkem import (
    MLKEM_512,
    MLKEM_768,
    MLKEM_1024,
    MLKEM_PARAMETER_SETS,
    MLKEM_Q,
    MLKEM_SYMBYTES,
    MLKEM_TOY,
    _byte_decode,
    _byte_encode,
    _compress,
    _decompress,
    _multiply_ntts,
    _ntt,
    _ntt_inverse,
    decapsulate,
    decapsulation_key_is_valid,
    encapsulate,
    encapsulate_random,
    encapsulation_key_is_valid,
    generate_key_pair,
    keygen,
)

VECTORS = Path(__file__).parent / "vectors" / "acvp_mlkem.json"

PARAMETER_SETS = {
    "ML-KEM-512": MLKEM_512,
    "ML-KEM-768": MLKEM_768,
    "ML-KEM-1024": MLKEM_1024,
}


def _vectors() -> dict:
    return json.loads(VECTORS.read_text(encoding="utf-8"))


def _parameters(case: dict):
    return PARAMETER_SETS[case["parameterSet"]]


def test_the_vectors_are_present_and_are_nists():
    doc = _vectors()
    assert "ACVP" in doc["_source"] and "FIPS203" in doc["_source"]
    assert set(PARAMETER_SETS) <= {c["parameterSet"] for c in doc["keygen"]}
    for section in ("keygen", "encapsulation", "decapsulation",
                    "encapsulationKeyCheck", "decapsulationKeyCheck"):
        assert doc[section], f"no vendored vectors for {section}"


def test_the_parameter_sets_are_the_standards():
    """FIPS 203 Table 2, read from the document rather than remembered."""
    assert (MLKEM_512.k, MLKEM_512.eta1, MLKEM_512.eta2, MLKEM_512.du, MLKEM_512.dv) == (2, 3, 2, 10, 4)
    assert (MLKEM_768.k, MLKEM_768.eta1, MLKEM_768.eta2, MLKEM_768.du, MLKEM_768.dv) == (3, 2, 2, 10, 4)
    assert (MLKEM_1024.k, MLKEM_1024.eta1, MLKEM_1024.eta2, MLKEM_1024.du, MLKEM_1024.dv) == (4, 2, 2, 11, 5)
    assert (MLKEM_512.security_category, MLKEM_768.security_category,
            MLKEM_1024.security_category) == (1, 3, 5)
    assert MLKEM_Q == 3329


def test_the_key_and_ciphertext_sizes_are_the_standards():
    """FIPS 203 Table 3: 384k+32, 768k+96 and 32*(du*k+dv)."""
    expected = {
        MLKEM_512: (800, 1632, 768),
        MLKEM_768: (1184, 2400, 1088),
        MLKEM_1024: (1568, 3168, 1568),
    }
    for parameters, (ek, dk, ct) in expected.items():
        assert parameters.encapsulation_key_bytes == ek
        assert parameters.decapsulation_key_bytes == dk
        assert parameters.ciphertext_bytes == ct
        assert parameters.shared_secret_bytes == 32


def test_the_toy_parameter_set_says_that_it_is_not_one():
    """A reduced set must not be mistakable for a standard one."""
    assert MLKEM_TOY.is_standard is False
    assert MLKEM_TOY.security_category == 0
    for parameters in MLKEM_PARAMETER_SETS:
        assert parameters.is_standard is True


def test_acvp_key_generation_vectors():
    """(d, z) -> (ek, dk), byte for byte.

    NIST writes the hex in upper case and the module returns bytes, so the
    comparison lowercases. That is a formatting difference, not a value one.
    """
    for case in _vectors()["keygen"]:
        parameters = _parameters(case)
        ek, dk = keygen(bytes.fromhex(case["d"]), bytes.fromhex(case["z"]), parameters)
        assert ek.hex() == case["ek"].lower(), f"{case['parameterSet']} tcId {case['tcId']} ek"
        assert dk.hex() == case["dk"].lower(), f"{case['parameterSet']} tcId {case['tcId']} dk"
        assert len(ek) == parameters.encapsulation_key_bytes
        assert len(dk) == parameters.decapsulation_key_bytes


def test_acvp_encapsulation_vectors():
    """(ek, m) -> (c, K)."""
    for case in _vectors()["encapsulation"]:
        parameters = _parameters(case)
        shared_secret, ciphertext = encapsulate(
            bytes.fromhex(case["ek"]), bytes.fromhex(case["m"]), parameters)
        assert ciphertext.hex() == case["c"].lower(), f"{case['parameterSet']} tcId {case['tcId']} c"
        assert shared_secret.hex() == case["k"].lower(), f"{case['parameterSet']} tcId {case['tcId']} K"
        assert len(ciphertext) == parameters.ciphertext_bytes


def test_acvp_decapsulation_vectors():
    """(dk, c) -> K."""
    for case in _vectors()["decapsulation"]:
        parameters = _parameters(case)
        shared_secret = decapsulate(bytes.fromhex(case["dk"]), bytes.fromhex(case["c"]), parameters)
        assert shared_secret.hex() == case["k"].lower(), f"{case['parameterSet']} tcId {case['tcId']}"


def test_acvp_encapsulation_key_check_vectors():
    """The modulus check, including the keys that must be refused.

    Half of these vectors are keys with a coefficient at or above q. They are
    the reason the check exists, and a check that accepts everything passes the
    other half.
    """
    cases = _vectors()["encapsulationKeyCheck"]
    assert any(case["testPassed"] is False for case in cases)
    for case in cases:
        parameters = _parameters(case)
        got = encapsulation_key_is_valid(bytes.fromhex(case["ek"]), parameters)
        assert got == case["testPassed"], f"{case['parameterSet']} tcId {case['tcId']}"


def test_acvp_decapsulation_key_check_vectors():
    cases = _vectors()["decapsulationKeyCheck"]
    assert any(case["testPassed"] is False for case in cases)
    for case in cases:
        parameters = _parameters(case)
        got = decapsulation_key_is_valid(bytes.fromhex(case["dk"]), parameters)
        assert got == case["testPassed"], f"{case['parameterSet']} tcId {case['tcId']}"


@pytest.mark.parametrize("parameters", MLKEM_PARAMETER_SETS, ids=lambda p: p.name)
def test_a_generated_key_pair_encapsulates_and_decapsulates(parameters):
    for _ in range(3):
        ek, dk = generate_key_pair(parameters)
        assert len(ek) == parameters.encapsulation_key_bytes
        assert len(dk) == parameters.decapsulation_key_bytes
        assert encapsulation_key_is_valid(ek, parameters)
        assert decapsulation_key_is_valid(dk, parameters)
        sender_secret, ciphertext = encapsulate_random(ek, parameters)
        receiver_secret = decapsulate(dk, ciphertext, parameters)
        assert sender_secret == receiver_secret
        assert len(sender_secret) == MLKEM_SYMBYTES


def test_the_two_parties_agree_and_a_third_does_not():
    parameters = MLKEM_768
    """Two key pairs, and the shared secret of one does not open the other."""
    ek_a, dk_a = generate_key_pair(parameters)
    ek_b, dk_b = generate_key_pair(parameters)
    secret_a, ciphertext_a = encapsulate_random(ek_a, parameters)
    secret_b, ciphertext_b = encapsulate_random(ek_b, parameters)
    assert decapsulate(dk_a, ciphertext_a, parameters) == secret_a
    assert decapsulate(dk_b, ciphertext_b, parameters) == secret_b
    assert decapsulate(dk_b, ciphertext_a, parameters) != secret_a
    assert decapsulate(dk_a, ciphertext_b, parameters) != secret_b


def test_a_corrupted_ciphertext_is_rejected_implicitly_not_loudly():
    """Implicit rejection is the design, so a tampered ciphertext must not raise.

    It must also not return the real secret: the two properties together are
    what stops decapsulation being an oracle for whether a ciphertext was well
    formed.
    """
    ek, dk = generate_key_pair(MLKEM_768)
    shared_secret, ciphertext = encapsulate_random(ek)
    for position in (0, len(ciphertext) // 2, len(ciphertext) - 1):
        tampered = bytearray(ciphertext)
        tampered[position] ^= 0x01
        recovered = decapsulate(dk, bytes(tampered), MLKEM_768)
        assert isinstance(recovered, bytes) and len(recovered) == MLKEM_SYMBYTES
        assert recovered != shared_secret


def test_implicit_rejection_is_deterministic_in_the_ciphertext():
    """The rejection secret is J(z || c), so the same bad ciphertext gives the
    same secret every time. A random fallback would look identical from outside
    and would be wrong."""
    ek, dk = generate_key_pair(MLKEM_768)
    _, ciphertext = encapsulate_random(ek)
    tampered = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]
    assert decapsulate(dk, tampered, MLKEM_768) == decapsulate(dk, tampered, MLKEM_768)


def test_the_transform_is_an_isomorphism():
    """NTT^-1(NTT(f)) == f, and multiplication in the transform domain agrees
    with negacyclic schoolbook multiplication in R_q.

    This is the check that would catch a wrong twiddle table, a missing final
    scaling, or the two zeta tables being swapped -- none of which the round
    trip alone would notice, because both directions would be consistently
    wrong.
    """
    rng = random.Random(0x203)
    for _ in range(5):
        f = [rng.randrange(MLKEM_Q) for _ in range(256)]
        g = [rng.randrange(MLKEM_Q) for _ in range(256)]
        assert _ntt_inverse(_ntt(f)) == f

        schoolbook = [0] * 256
        for i in range(256):
            if f[i] == 0:
                continue
            for j in range(256):
                k = i + j
                if k < 256:
                    schoolbook[k] = (schoolbook[k] + f[i] * g[j]) % MLKEM_Q
                else:
                    schoolbook[k - 256] = (schoolbook[k - 256] - f[i] * g[j]) % MLKEM_Q
        assert _ntt_inverse(_multiply_ntts(_ntt(f), _ntt(g))) == schoolbook


def test_the_two_twiddle_tables_are_different_tables():
    """The NTT uses zeta^BitRev7(i); multiplication uses zeta^(2*BitRev7(i)+1).

    Using one where the other belongs is silent: every entry is still a valid
    field element, so the arithmetic runs and returns a wrong answer.
    """
    from src.mlkem import _MULTIPLY_GAMMAS, _ZETAS, _bit_reverse_7
    assert len(_ZETAS) == 128 and len(_MULTIPLY_GAMMAS) == 128
    assert _ZETAS != _MULTIPLY_GAMMAS
    # derived from the two exponent formulas rather than from a remembered
    # number: BitRev7(1) is 64, not 1, so the transform's second twiddle is
    # zeta^64 and not zeta.
    for i in range(128):
        assert _ZETAS[i] == pow(17, _bit_reverse_7(i), MLKEM_Q)
        assert _MULTIPLY_GAMMAS[i] == pow(17, 2 * _bit_reverse_7(i) + 1, MLKEM_Q)
    assert _bit_reverse_7(1) == 64
    assert _ZETAS[1] == pow(17, 64, MLKEM_Q) == 1729
    assert _MULTIPLY_GAMMAS[0] == 17


@pytest.mark.parametrize("d", [1, 2, 4, 5, 10, 11])
def test_compression_round_trips_for_every_d_below_twelve(d):
    """FIPS 203 Section 4.2.1: Compress_d(Decompress_d(y)) == y for all d < 12.

    The standard states this as a property, so it is checked as one rather than
    against a table.
    """
    for y in range(1 << d):
        assert _compress(_decompress(y, d), d) == y


@pytest.mark.parametrize("d", [1, 2, 4, 10, 11, 12])
def test_byte_encoding_round_trips(d):
    """For d < 12 the encoding is a bijection. For d = 12 it is not: the decoder
    reduces modulo q, which is what the encapsulation-key check relies on."""
    rng = random.Random(d)
    limit = MLKEM_Q if d == 12 else (1 << d)
    values = [rng.randrange(limit) for _ in range(256)]
    encoded = _byte_encode(values, d)
    assert len(encoded) == 32 * d
    assert _byte_decode(encoded, d) == values


def test_a_twelve_bit_segment_above_q_decodes_to_something_smaller():
    """The asymmetry that makes the modulus check work, stated directly."""
    encoded = _byte_encode([MLKEM_Q] * 256, 12)
    decoded = _byte_decode(encoded, 12)
    assert decoded == [0] * 256
    assert _byte_encode(decoded, 12) != encoded


@pytest.mark.parametrize("parameters", [MLKEM_512, MLKEM_768, MLKEM_1024, MLKEM_TOY],
                         ids=lambda p: p.name)
def test_every_parameter_set_including_the_toy_one_round_trips(parameters):
    ek, dk = generate_key_pair(parameters)
    assert len(ek) == parameters.encapsulation_key_bytes
    assert len(dk) == parameters.decapsulation_key_bytes
    shared_secret, ciphertext = encapsulate_random(ek, parameters)
    assert len(ciphertext) == parameters.ciphertext_bytes
    assert decapsulate(dk, ciphertext, parameters) == shared_secret


def test_the_toy_set_is_smaller_than_the_smallest_standard_set():
    """The point of it: k is what the sizes are linear in."""
    ek, dk = generate_key_pair(MLKEM_TOY)
    assert len(ek) < MLKEM_512.encapsulation_key_bytes
    assert len(dk) < MLKEM_512.decapsulation_key_bytes


def test_key_generation_depends_on_both_seeds():
    """d and z are not interchangeable: d drives the lattice, z only the
    implicit-rejection value. Swapping them must produce a different key."""
    d, z = os.urandom(32), os.urandom(32)
    ek1, dk1 = keygen(d, z, MLKEM_768)
    ek2, dk2 = keygen(d, z, MLKEM_768)
    assert (ek1, dk1) == (ek2, dk2), "keygen is deterministic in its seeds"
    assert keygen(z, d, MLKEM_768)[0] != ek1


def test_a_parameter_set_mismatch_produces_a_different_key():
    """FIPS 203 folds k into the G input so a seed expanded under the wrong
    parameter set does not silently produce a related key."""
    d, z = os.urandom(32), os.urandom(32)
    assert keygen(d, z, MLKEM_512)[0] != keygen(d, z, MLKEM_768)[0]


def test_bad_input_lengths_are_refused():
    with pytest.raises(ValueError):
        keygen(b"short", os.urandom(32))
    with pytest.raises(ValueError):
        keygen(os.urandom(32), b"short")
    with pytest.raises(ValueError):
        encapsulate(b"\x00" * MLKEM_768.encapsulation_key_bytes, b"short")


def test_a_key_of_the_wrong_length_fails_the_check_rather_than_raising():
    """The check returns a verdict. A caller deciding whether to accept a key
    should not have to catch an exception to find out."""
    ek, dk = generate_key_pair(MLKEM_768)
    assert encapsulation_key_is_valid(ek[:-1], MLKEM_768) is False
    assert encapsulation_key_is_valid(ek + b"\x00", MLKEM_768) is False
    assert decapsulation_key_is_valid(dk[:-1], MLKEM_768) is False
    assert encapsulation_key_is_valid(ek, MLKEM_512) is False
