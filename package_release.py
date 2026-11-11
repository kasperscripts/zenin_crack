#!/usr/bin/env python3
"""Stream a signed APK into ZIP64 and verify its complete extraction."""
import argparse
import hashlib
import json
from pathlib import Path
import time
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('apk', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--apk-sha256', required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    assert args.apk.resolve() != args.output.resolve() and not args.output.exists()
    info = zipfile.ZipInfo('Zenin_Icon_Crack.apk', (2026, 11, 11, 0, 0, 0))
    info.file_size = args.apk.stat().st_size
    info.compress_type = zipfile.ZIP_DEFLATED
    info._compresslevel = 6
    digest = hashlib.sha256()
    count = 0
    last = time.monotonic()
    with zipfile.ZipFile(args.output, 'w', allowZip64=True) as archive:
        with args.apk.open('rb') as source, archive.open(info, 'w', force_zip64=True) as target:
            while block := source.read(8 * 1024 * 1024):
                target.write(block)
                digest.update(block)
                count += len(block)
                if time.monotonic() - last > 20:
                    print(f'ZIP64: {count / info.file_size:.0%}', flush=True)
                    last = time.monotonic()
    assert digest.hexdigest() == args.apk_sha256
    with zipfile.ZipFile(args.output) as archive:
        assert archive.namelist() == [info.filename]
        assert archive.getinfo(info.filename).extract_version == 45
        with archive.open(info.filename) as source:
            assert hashlib.file_digest(source, 'sha256').hexdigest() == args.apk_sha256
    with args.output.open('rb') as source:
        checksum = hashlib.file_digest(source, 'sha256').hexdigest()
    size = args.output.stat().st_size
    assert size < 2**31, 'GitHub release asset size limit exceeded'
    report = {'format': 'ZIP64', 'zip_size': size, 'zip_sha256': checksum,
              'apk_size': count, 'apk_sha256': args.apk_sha256,
              'full_python_extraction_sha256_verified': True}
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2), flush=True)


if __name__ == '__main__':
    main()
