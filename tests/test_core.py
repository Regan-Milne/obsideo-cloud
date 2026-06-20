"""Core tests: crypto round-trip + S3 list parsing (mocked client)."""

import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest

# Isolate config dir so tests never touch ~/.obsideo.
os.environ["OBSIDEO_DATA_KEY"] = os.urandom(32).hex()

from obsideo_core import crypto, storage


def test_crypto_round_trip():
    data = os.urandom(4096)
    blob = crypto.encrypt(data)
    assert blob[:12] != data[:12]  # nonce prepended, not plaintext
    assert crypto.decrypt(blob) == data


def test_crypto_wrong_key_fails():
    blob = crypto.encrypt(b"secret")
    other = os.urandom(32).hex()
    with mock.patch.dict(os.environ, {"OBSIDEO_DATA_KEY": other}):
        with pytest.raises(Exception):
            crypto.decrypt(blob)


@pytest.fixture()
def s3_creds(monkeypatch):
    monkeypatch.setenv("OBSIDEO_S3_ACCESS_KEY", "AKIATEST")
    monkeypatch.setenv("OBSIDEO_S3_SECRET_KEY", "secret")
    monkeypatch.setenv("OBSIDEO_S3_BUCKET", "obsideo")
    storage.reset_client()
    yield
    storage.reset_client()


def test_list_prefix_parses_folders_and_files(s3_creds, monkeypatch):
    fake = mock.MagicMock()
    fake.list_objects_v2.return_value = {
        "CommonPrefixes": [{"Prefix": "docs/"}, {"Prefix": "photos/"}],
        "Contents": [
            {"Key": "readme.txt", "Size": 12},
            {"Key": "note.md", "Size": 40},
            {"Key": "", "Size": 0},  # folder marker for root - skipped
        ],
        "IsTruncated": False,
    }
    monkeypatch.setattr(storage, "_s3", lambda: fake)

    out = storage.list_prefix("")
    assert out["folders"] == ["docs", "photos"]
    names = [f["name"] for f in out["files"]]
    assert names == ["note.md", "readme.txt"]  # sorted


def test_get_uses_full_object_get(s3_creds, monkeypatch):
    fake = mock.MagicMock()
    body = mock.MagicMock(); body.read.return_value = b"ciphertext"
    fake.get_object.return_value = {"Body": body}
    monkeypatch.setattr(storage, "_s3", lambda: fake)

    assert storage.get("k") == b"ciphertext"
    fake.get_object.assert_called_once_with(Bucket="obsideo", Key="k")
    assert not fake.download_file.called  # never ranged
