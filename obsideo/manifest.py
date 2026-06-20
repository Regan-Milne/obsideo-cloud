"""Local manifest for tracking synced files (lifted from Cloud_Terminal,
re-homed under ~/.obsideo)."""

import hashlib
import json
from datetime import datetime, timezone

from obsideo_core import config

_MANIFEST_FILE = config.CONFIG_DIR / "manifest.json"


def _load() -> dict:
    if not _MANIFEST_FILE.exists():
        return {"files": {}}
    try:
        data = json.loads(_MANIFEST_FILE.read_text())
        if not isinstance(data, dict):
            return {"files": {}}
        data.setdefault("files", {})
        return data
    except Exception:
        return {"files": {}}


def _save(m: dict) -> None:
    _MANIFEST_FILE.parent.mkdir(parents=True, exist_ok=True)
    _MANIFEST_FILE.write_text(json.dumps(m, indent=2, sort_keys=True))


def upsert(name: str, remote_key: str, local_hash: str | None = None,
           size: int | None = None, encrypted: bool = True) -> None:
    m = _load()
    m["files"][name] = {
        "remote_key": remote_key,
        "local_hash": local_hash,
        "size": size,
        "encrypted": encrypted,
        "last_synced": datetime.now(timezone.utc).isoformat(),
    }
    _save(m)


def remove(name: str) -> None:
    m = _load()
    m["files"].pop(name, None)
    _save(m)


def get_all() -> dict:
    return _load()["files"]


def file_sha256(filepath) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"
