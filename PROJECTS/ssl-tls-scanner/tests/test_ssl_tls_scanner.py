from src.scanner import certificate_issuer, certificate_subject, parse_certificate_time

def test_parse_certificate_time():
    assert parse_certificate_time("Jan 02 03:04:05 2030 GMT")=="2030-01-02T03:04:05+00:00"

def test_subject_and_issuer_are_readable():
    cert={"subject":((("commonName","example.test"),),),"issuer":((("organizationName","Lab CA"),),)}
    assert certificate_subject(cert)=="commonName=example.test"
    assert certificate_issuer(cert)=="organizationName=Lab CA"
