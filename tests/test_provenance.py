import hashlib
import os

from icsprio.provenance import log_fetch, sha256_bytes


def test_sha256_bytes_matches_hashlib():
    data = b"hello icsprio"
    assert sha256_bytes(data) == hashlib.sha256(data).hexdigest()


def test_log_fetch_appends_expected_fields(tmp_path):
    log_path = str(tmp_path / "PROVENANCE.txt")
    line = log_fetch(log_path, "example.json", b'{"a": 1}', "https://example.org/example.json", note="test")

    assert os.path.exists(log_path)
    with open(log_path, encoding="utf-8") as f:
        contents = f.read()
    assert line.strip() in contents
    assert "example.json" in line
    assert "8 bytes" in line
    assert "sha256:" in line
    assert "https://example.org/example.json" in line
    assert "test" in line


def test_log_fetch_appends_multiple_lines(tmp_path):
    log_path = str(tmp_path / "PROVENANCE.txt")
    log_fetch(log_path, "a.json", b"aaa", "https://example.org/a")
    log_fetch(log_path, "b.json", b"bb", "https://example.org/b")
    with open(log_path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    assert len(lines) == 2
