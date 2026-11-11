#!/usr/bin/env python3
"""Package the unchanged signed APK into two ZIP volumes without compression."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

APK_SHA256 = "1fdc769fc79852bb8ddfe768da5fb5009fd02e9d81085ad23087647667d65ce2"


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--sevenzip", default=shutil.which("7zz") or shutil.which("7z"))
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    apk = args.apk.resolve()
    assert apk.name == "Zenin_Icon_Crack.apk" and sha256(apk) == APK_SHA256
    assert args.sevenzip, "7-Zip is required for independent verification"
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / "Zenin_Icon_Crack_Store.zip"
    assert not list(output_dir.glob("Zenin_Icon_Crack_Store.z*")), "Output already exists"

    # Stable metadata makes the archive reproducible on the publishing runner.
    apk.chmod(0o644)
    os.utime(apk, (1794355200, 1794355200))  # 2026-11-11 00:00:00 UTC
    subprocess.run(
        ["zip", "-0", "-X", "-fz", "-s", "1500m", str(archive), apk.name],
        cwd=apk.parent, env={**os.environ, "TZ": "UTC"}, check=True,
    )
    parts = [archive.with_suffix(".z01"), archive]
    assert sorted(output_dir.glob("Zenin_Icon_Crack_Store.z*")) == sorted(parts)
    assert all(0 < part.stat().st_size < 2**31 for part in parts)
    subprocess.run([args.sevenzip, "t", str(archive)], check=True)
    metadata = subprocess.check_output([args.sevenzip, "l", "-slt", str(archive)], text=True)
    assert "\nMethod = Store\n" in metadata

    # Verify extraction across the volume boundary against the signed APK.
    digest = hashlib.sha256()
    count = 0
    with subprocess.Popen([args.sevenzip, "x", "-so", str(archive)], stdout=subprocess.PIPE) as process:
        while block := process.stdout.read(8 * 1024 * 1024):
            digest.update(block)
            count += len(block)
        assert process.wait() == 0
    assert digest.hexdigest() == APK_SHA256 and count == apk.stat().st_size
    report = {
        "format": "split ZIP64",
        "compression_method": "Store (0), no compression",
        "apk_sha256": APK_SHA256,
        "apk_size": count,
        "apk_bytes_unchanged": True,
        "sevenzip_test_passed": True,
        "sevenzip_full_extraction_sha256_verified": True,
        "parts": [{"name": part.name, "size": part.stat().st_size, "sha256": sha256(part)} for part in parts],
    }
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
