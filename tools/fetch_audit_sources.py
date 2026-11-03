"""Capture timestamped sources. Never visits phishing pages or treats ranking as verified safety."""
import datetime
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    'openphish.txt': 'https://openphish.com/feed.txt',
    'tranco.zip': 'https://tranco-list.eu/top-1m.csv.zip',
    'umbrella.zip': 'https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip',
}


def main():
    now = datetime.datetime.now(datetime.timezone.utc)
    folder = ROOT / 'data' / 'external_audit' / now.strftime('%Y%m%dT%H%M%SZ')
    folder.mkdir(parents=True, exist_ok=True)
    manifest = {}
    for name, url in SOURCES.items():
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'Shield-research-audit/1.0'})
            with urllib.request.urlopen(request, timeout=120) as response:
                raw = response.read()
            (folder / name).write_bytes(raw)
            manifest[name] = dict(url=url, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                                  fetched_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
            if name.endswith('.zip'):
                import zipfile
                import shutil
                with zipfile.ZipFile(folder / name) as z:
                    assert z.testzip() is None
                lists = ROOT / 'data/lists'
                lists.mkdir(exist_ok=True)
                if not (lists / name).exists():
                    shutil.copy2(folder / name, lists / name)
        except Exception as ex:
            manifest[name] = dict(url=url, error=str(ex))
        (folder / 'manifest.json').write_text(json.dumps(manifest, indent=2))
        print(name, manifest[name], flush=True)
    print('Snapshot:', folder)


if __name__ == '__main__':
    main()
