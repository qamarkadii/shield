from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import backup_project, restore_backup


class BackupTests(unittest.TestCase):
    def test_backup_committed_wal_and_excludes_secrets(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'audit') as tmp:
            project, archives = Path(tmp) / 'project', Path(tmp) / 'archives'
            project.mkdir()
            (project / '.env').write_text('SECRET=not-for-backup')
            (project / '.env.example').write_text('SECRET=')
            (project / 'frontend').mkdir()
            (project / 'frontend/.env.shield').write_text('VITE_SHIELD_PUBLIC=1')
            (project / 'frontend/.env.production').write_text('SECRET=not-for-backup')
            (project / 'node_modules').mkdir()
            (project / 'node_modules/reinstallable.js').write_text('ignored dependency')
            conn = sqlite3.connect(project / 'shield.db')
            try:
                conn.execute('PRAGMA journal_mode=WAL')
                conn.execute('CREATE TABLE verified(value TEXT)')
                conn.execute("INSERT INTO verified VALUES ('committed')")
                conn.commit()
                with patch.object(backup_project, 'ROOT', project), redirect_stdout(io.StringIO()):
                    receipt = backup_project.backup(archives)
                with zipfile.ZipFile(receipt['archive']) as z:
                    self.assertNotIn('.env', z.namelist())
                    self.assertIn('.env.example', z.namelist())
                    self.assertIn('frontend/.env.shield', z.namelist())
                    self.assertNotIn('frontend/.env.production', z.namelist())
                    self.assertNotIn('node_modules/reinstallable.js', z.namelist())
                    snapshot = Path(tmp) / 'snapshot.db'
                    snapshot.write_bytes(z.read('shield.db'))
                check = sqlite3.connect(snapshot)
                try:
                    self.assertEqual(check.execute('SELECT value FROM verified').fetchone()[0], 'committed')
                finally:
                    check.close()
            finally:
                conn.close()

    def test_restore_rebases_paths_and_preserves_existing_work(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'audit') as tmp:
            archive = Path(tmp) / 'backup.zip'
            files = {'checkpoints/models/test.joblib': b'checkpoint bytes',
                     'checkpoints/best.json': json.dumps({'path': 'C:/old/project/checkpoints/models/test.joblib'}).encode()}
            with zipfile.ZipFile(archive, 'w') as z:
                for name, raw in files.items():
                    z.writestr(name, raw)
                z.writestr('BACKUP_MANIFEST.json', json.dumps({n: hashlib.sha256(b).hexdigest() for n,b in files.items()}))
            dest = Path(tmp) / 'restored'
            with redirect_stdout(io.StringIO()):
                restore_backup.restore(archive, dest)
            pointer = json.loads((dest / 'checkpoints/best.json').read_text())
            self.assertEqual(Path(pointer['path']), dest / 'checkpoints/models/test.joblib')
            with self.assertRaisesRegex(RuntimeError, 'empty'):
                restore_backup.restore(archive, dest)

    def test_unsafe_archive_path_is_rejected_before_write(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'audit') as tmp:
            archive = Path(tmp) / 'unsafe.zip'
            with zipfile.ZipFile(archive, 'w') as z:
                z.writestr('../outside', b'x')
                z.writestr('BACKUP_MANIFEST.json', json.dumps({'../outside': hashlib.sha256(b'x').hexdigest()}))
            dest = Path(tmp) / 'restored'
            with self.assertRaisesRegex(RuntimeError, 'Unsafe'):
                restore_backup.restore(archive, dest)
            self.assertFalse(dest.exists())


if __name__ == '__main__':
    unittest.main()
