"""Verify and restore a portable backup into an empty directory; never overwrite work."""
import argparse
import hashlib
import json
from pathlib import Path
import stat
import zipfile


def restore(archive, destination):
    destination = Path(destination).resolve()
    if destination.exists() and any(destination.iterdir()):
        raise RuntimeError('Restore destination must be empty; existing work is preserved')
    with zipfile.ZipFile(archive) as z:
        manifest = json.loads(z.read('BACKUP_MANIFEST.json'))
        # Verify the entire archive before writing anything.
        for name, expected in manifest.items():
            relative = Path(name.replace('\\', '/'))
            target = (destination / relative).resolve()
            if relative.is_absolute() or ':' in name or not target.is_relative_to(destination):
                raise RuntimeError('Unsafe archive path: ' + name)
            info = z.getinfo(name)
            if stat.S_ISLNK(info.external_attr >> 16):
                raise RuntimeError('Archive symlinks are not supported')
            if hashlib.sha256(z.read(name)).hexdigest() != expected:
                raise RuntimeError('Archive hash mismatch: ' + name)
        destination.mkdir(parents=True, exist_ok=True)
        for name in manifest:
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(z.read(name))
        (destination / 'BACKUP_MANIFEST.json').write_text(json.dumps(manifest, indent=2))
    rebased = []
    checkpoints = destination / 'checkpoints'
    for p in checkpoints.glob('*.json'):
        data = json.loads(p.read_text())
        if not isinstance(data, dict) or not isinstance(data.get('path'), str):
            continue
        old = data['path'].replace('\\', '/')
        tail = old.split('/checkpoints/', 1)[-1]
        new = (checkpoints / tail).resolve()
        if not new.is_relative_to(checkpoints) or not new.is_file():
            raise RuntimeError('Cannot rebase checkpoint reference: ' + data['path'])
        data['path'] = str(new)
        p.write_text(json.dumps(data, indent=2))
        rebased.append(str(p.relative_to(destination)))
    receipt = dict(archive=str(Path(archive).resolve()), restored_files=len(manifest),
                   all_original_hashes_verified=True, rebased_pointer_files=rebased)
    (destination / 'RESTORE_RECEIPT.json').write_text(json.dumps(receipt, indent=2))
    print(json.dumps(receipt, indent=2))
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('archive')
    parser.add_argument('destination')
    args = parser.parse_args()
    restore(args.archive, args.destination)
