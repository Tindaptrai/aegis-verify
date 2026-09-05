"""Pure hashing tests: byte strings below are not security log fixtures."""

import pytest

from aegis_verify.evidence import hash_raw_event


@pytest.mark.parametrize("data,expected", [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
])
def test_sha256_matches_independent_known_vectors(data, expected):
    assert hash_raw_event(data) == expected
    assert hash_raw_event(data) == expected


def test_record_bytes_are_not_reformatted_before_hashing():
    records = [b"abc", b"abd", b"abc\n", b"abc\r\n", b" abc", b"abc ", b"\xffabc"]
    assert len({hash_raw_event(record) for record in records}) == len(records)


@pytest.mark.parametrize("data", ["abc", None, {}, bytearray(b"abc"), 123])
def test_hash_requires_explicit_immutable_bytes(data):
    with pytest.raises(TypeError):
        hash_raw_event(data)
