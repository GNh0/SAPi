"""Check archive license validation rejects missing and altered license files."""
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from package import verify_license_archives


class LicenseArchiveTests(unittest.TestCase):
    def test_valid_and_missing_or_altered_archives(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp); license_bytes = b'expected license'
            with zipfile.ZipFile(folder / 'package.whl', 'w') as z: z.writestr('package.dist-info/LICENSE', license_bytes)
            with tarfile.open(folder / 'package.tgz', 'w:gz') as t:
                info=tarfile.TarInfo('package/LICENSE'); info.size=len(license_bytes); t.addfile(info,io.BytesIO(license_bytes))
            verify_license_archives(folder, ['package.whl'], ['package.tgz'], license_bytes)
            with zipfile.ZipFile(folder / 'package.whl', 'w') as z: z.writestr('package.dist-info/LICENSE', b'changed')
            with self.assertRaises(RuntimeError): verify_license_archives(folder, ['package.whl'], [], license_bytes)
            with tarfile.open(folder / 'package.tgz', 'w:gz'): pass
            with self.assertRaises(RuntimeError): verify_license_archives(folder, [], ['package.tgz'], license_bytes)

if __name__ == '__main__': unittest.main()
