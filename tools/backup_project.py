"""Create a portable verified ZIP, excluding secrets and reinstallable runtimes."""
from pathlib import Path
import datetime
from contextlib import closing
import hashlib
import json
import os
import sqlite3
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def backup(destination=None):
    destination = Path(destination or ROOT.parent / 'recovery')
    destination.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    archive = destination / ('shield-checkpoint-' + stamp + '.zip')
    excluded = {'.venv', 'node_modules', '__pycache__', '.git', '.pytest_cache'}
    manifest = {}
    with tempfile.TemporaryDirectory() as tmp, zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
        paths = []
        for base, directories, files in os.walk(ROOT):
            directories[:] = sorted(d for d in directories if d not in excluded)
            paths.extend(Path(base) / name for name in sorted(files))
        for p in paths:
            rel = p.relative_to(ROOT)
            if not p.is_file() or any(x in excluded for x in rel.parts):
                continue
            if p.name in ('.training.lock', '.publish.lock', '.metadata.lock'):
                continue
            public_build_config = rel.as_posix() == 'frontend/.env.shield'
            if p.name == '.env' or (p.name.startswith('.env.') and p.name != '.env.example' and not public_build_config) or p.suffix == '.tmp':
                continue
            if p.suffix == '.log' and rel.parts[0] != 'audit':
                continue
            if p.name.endswith(('-wal', '-shm')):
                continue
            if p.suffix == '.db':
                snap = Path(tmp) / p.name
                with closing(sqlite3.connect(str(p))) as source, closing(sqlite3.connect(str(snap))) as dest:
                    with dest:
                        source.backup(dest)
                raw = snap.read_bytes()
            else:
                raw = p.read_bytes()
            manifest[rel.as_posix()] = hashlib.sha256(raw).hexdigest()
            z.writestr(rel.as_posix(), raw)
        z.writestr('BACKUP_MANIFEST.json', json.dumps(manifest, indent=2))
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        for name, expected in manifest.items():
            assert hashlib.sha256(z.read(name)).hexdigest() == expected, name
    receipt = dict(archive=str(archive), files=len(manifest),
                   sha256=hashlib.sha256(archive.read_bytes()).hexdigest(), verified=True)
    archive.with_suffix('.json').write_text(json.dumps(receipt, indent=2))
    print(json.dumps(receipt, indent=2))
    return receipt


if __name__ == '__main__':
    backup()
