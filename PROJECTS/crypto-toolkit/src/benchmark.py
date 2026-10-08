"""The post-quantum comparison the project set out to make.

The point of this module is not to declare a winner. It is to put RSA and
ML-KEM side by side on the three axes the plan named -- key size, speed and
security margin -- with the timings measured here and the security margins
taken from the standards rather than estimated.

Every number this prints was measured on the machine it ran on, and the two
security columns are quoted, not computed:

* The RSA figures are the comparable security strengths of NIST SP 800-57
  Part 1 Rev 5, Table 2: a 2048-bit modulus is rated 112 bits and a 3072-bit
  modulus 128.
* The ML-KEM figures are the security categories of FIPS 203 Section 8, which
  Table 2 of that standard ties to the required randomness strength: ML-KEM-512
  is category 1, ML-KEM-768 category 3 and ML-KEM-1024 category 5.

A benchmark that quietly assigned its own security numbers would be the easiest
thing in this repository to fake, so it does not assign any.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .mlkem import MLKEM_PARAMETER_SETS
from .mlkem import decapsulate as mlkem_decapsulate
from .mlkem import encapsulate_random as mlkem_encapsulate
from .mlkem import generate_key_pair as mlkem_keygen
from .rsa import decrypt as rsa_decrypt
from .rsa import encrypt as rsa_encrypt
from .rsa import generate_key_pair as rsa_keygen

__all__ = [
    "SECURITY_STRENGTHS",
    "BenchmarkRow",
    "benchmark_mlkem",
    "benchmark_rsa",
    "format_report",
    "run",
]

# Cited, not measured. The key sizes are the ones each standard names.
SECURITY_STRENGTHS = {
    "RSA-1024": (80, "NIST SP 800-57 Part 1 Rev 5, Table 2, the <=80 row -- no longer "
                     "approved for applying protection"),
    "RSA-2048": (112, "NIST SP 800-57 Part 1 Rev 5, Table 2"),
    "RSA-3072": (128, "NIST SP 800-57 Part 1 Rev 5, Table 2"),
    "ML-KEM-512": (128, "FIPS 203 Section 8, security category 1"),
    "ML-KEM-768": (192, "FIPS 203 Section 8, security category 3"),
    "ML-KEM-1024": (256, "FIPS 203 Section 8, security category 5"),
    "ML-KEM-toy": (0, "not a standard parameter set"),
}


@dataclass(frozen=True)
class BenchmarkRow:
    name: str
    public_key_bytes: int
    private_key_bytes: int
    ciphertext_bytes: int
    keygen_ms: float
    encapsulate_ms: float
    decapsulate_ms: float
    # None when the size is not one the cited table covers. It is deliberately
    # not an estimate: a benchmark that interpolates a security level for an
    # uncited key size is inventing the one number a reader cannot check.
    security_bits: int | None
    security_source: str

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "public_key_bytes": self.public_key_bytes,
            "private_key_bytes": self.private_key_bytes,
            "ciphertext_bytes": self.ciphertext_bytes,
            "keygen_ms": round(self.keygen_ms, 3),
            "encapsulate_ms": round(self.encapsulate_ms, 3),
            "decapsulate_ms": round(self.decapsulate_ms, 3),
            "security_bits": self.security_bits,
            "security_source": self.security_source,
        }


def security_strength_for(name: str) -> tuple[int | None, str]:
    """The quoted strength for a scheme, or an explicit refusal to quote one."""
    if name in SECURITY_STRENGTHS:
        return SECURITY_STRENGTHS[name]
    return None, "not in the cited table, so no strength is claimed"


def _time(callable_, iterations: int) -> float:
    """Mean milliseconds per call, over `iterations` calls.

    The first call is not counted: it pays for whatever the interpreter warms
    up on, and including it makes a fast operation look slower than it is.
    """
    callable_()
    started = time.perf_counter()
    for _ in range(iterations):
        callable_()
    return (time.perf_counter() - started) * 1000.0 / iterations


def benchmark_rsa(bits=(2048, 3072), keygen_iterations: int = 1,
                  operation_iterations: int = 20) -> list[BenchmarkRow]:
    rows = []
    for size in bits:
        public, private = rsa_keygen(size)
        message = b"a shared secret of this length"
        ciphertext = rsa_encrypt(public, message)

        # The loop values are bound as defaults rather than closed over. `_time` calls
        # its argument immediately, so closing over them happened to be correct -- but a
        # closure reads the variable when it runs, not when it is written, so any change
        # to when the call happens would silently measure the last iteration's key size
        # for every row. A benchmark that measures the wrong thing is worse than none.
        keygen_ms = _time(lambda size=size: rsa_keygen(size), keygen_iterations)
        encrypt_ms = _time(lambda public=public, message=message:
                           rsa_encrypt(public, message), operation_iterations)
        decrypt_ms = _time(lambda private=private, ciphertext=ciphertext:
                           rsa_decrypt(private, ciphertext), operation_iterations)

        strength, source = security_strength_for(f"RSA-{size}")
        rows.append(BenchmarkRow(
            name=f"RSA-{size}",
            public_key_bytes=(public.n.bit_length() + 7) // 8,
            private_key_bytes=(private.n.bit_length() + 7) // 8,
            ciphertext_bytes=len(ciphertext),
            keygen_ms=keygen_ms,
            encapsulate_ms=encrypt_ms,
            decapsulate_ms=decrypt_ms,
            security_bits=strength,
            security_source=source,
        ))
    return rows


def benchmark_mlkem(parameter_sets=MLKEM_PARAMETER_SETS, keygen_iterations: int = 5,
                    operation_iterations: int = 20) -> list[BenchmarkRow]:
    rows = []
    for parameters in parameter_sets:
        public, private = mlkem_keygen(parameters)
        shared_secret, ciphertext = mlkem_encapsulate(public, parameters)

        keygen_ms = _time(lambda parameters=parameters: mlkem_keygen(parameters),
                          keygen_iterations)
        encapsulate_ms = _time(lambda public=public, parameters=parameters:
                               mlkem_encapsulate(public, parameters), operation_iterations)
        decapsulate_ms = _time(lambda private=private, ciphertext=ciphertext,
                               parameters=parameters:
                               mlkem_decapsulate(private, ciphertext, parameters),
                               operation_iterations)

        strength, source = security_strength_for(parameters.name)
        rows.append(BenchmarkRow(
            name=parameters.name,
            public_key_bytes=len(public),
            private_key_bytes=len(private),
            ciphertext_bytes=len(ciphertext),
            keygen_ms=keygen_ms,
            encapsulate_ms=encapsulate_ms,
            decapsulate_ms=decapsulate_ms,
            security_bits=strength,
            security_source=source,
        ))
    return rows


def run(rsa_bits=(2048, 3072), include_toy: bool = False,
        keygen_iterations: int = 1, mlkem_keygen_iterations: int = 5,
        operation_iterations: int = 20) -> dict:
    """Measure both families and return the rows plus the honest caveats."""
    parameter_sets = list(MLKEM_PARAMETER_SETS)
    if include_toy:
        from .mlkem import MLKEM_TOY
        parameter_sets.append(MLKEM_TOY)
    rsa_rows = benchmark_rsa(rsa_bits, keygen_iterations, operation_iterations)
    mlkem_rows = benchmark_mlkem(parameter_sets, mlkem_keygen_iterations, operation_iterations)
    return {
        "rsa": [row.as_dict() for row in rsa_rows],
        "mlkem": [row.as_dict() for row in mlkem_rows],
        "notes": [
            "Timings are wall-clock measurements from this run, on this machine, in "
            "pure Python. They compare the two implementations in this repository "
            "against each other and are not a claim about optimised libraries.",
            "Security strengths are quoted from the standards: NIST SP 800-57 Part 1 "
            "Rev 5 Table 2 for RSA, and the security categories of FIPS 203 Section 8 "
            "for ML-KEM. Nothing here estimates them.",
            "The two families are not interchangeable. RSA-OAEP encrypts a message; "
            "ML-KEM establishes a shared secret and is sized for that.",
            "ML-KEM's advantage is not size: at a comparable strength its keys and "
            "ciphertexts are larger than RSA's. What it buys is resistance to Shor's "
            "algorithm, which breaks RSA outright, and a far cheaper key generation.",
            "The speed comparison is not one-sided, and reading it as one would be "
            "wrong. RSA's encryption is the cheapest operation in the table because it "
            "uses a small public exponent; ML-KEM's encapsulation costs more than that "
            "and about the same as its own decapsulation, which is where its symmetry "
            "shows. Against RSA's decryption at the same strength, ML-KEM is faster.",
        ],
    }


def format_report(result: dict) -> str:
    """A fixed-width table, so the columns line up in a terminal."""
    header = ("scheme", "public", "private", "ciphertext", "keygen", "encaps", "decaps", "strength")
    lines = [
        "%-14s %8s %8s %11s %9s %9s %9s %9s" % (
            header[0], header[1], header[2], header[3], header[4], header[5], header[6], header[7]),
        "%s %s %s %s %s %s %s %s" % ("-" * 14, "-" * 8, "-" * 8, "-" * 11,
                                     "-" * 9, "-" * 9, "-" * 9, "-" * 9),
    ]
    for row in result["rsa"] + result["mlkem"]:
        if row["security_bits"] is None:
            strength = "not quoted"
        elif row["security_bits"] == 0:
            strength = "NOT a standard set"
        else:
            strength = "%d bits" % row["security_bits"]
        lines.append("%-14s %8d %8d %11d %8.2fms %8.2fms %8.2fms %9s" % (
            row["name"], row["public_key_bytes"], row["private_key_bytes"],
            row["ciphertext_bytes"], row["keygen_ms"], row["encapsulate_ms"],
            row["decapsulate_ms"], strength))
    lines.append("")
    lines.append("columns 2-4 are bytes; 5-7 are milliseconds per operation")
    lines.append("")
    for note in result["notes"]:
        lines.append("  " + note)
    return "\n".join(lines)
