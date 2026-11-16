# Compatible ZIP packaging

The user reported `invalid distance code` while extracting the ZIP64 download. A complete public download of that exact release asset was streamed through zlib and SHA-256: both the outer ZIP and the complete extracted APK matched the published hashes. The extraction failure was not reproduced locally, and its cause on the Android device is unknown.

The original packer conservatively enabled ZIP64 above Python's 2 GiB threshold. The APK is 2,285,563,072 bytes, below ZIP32's unsigned 32-bit size limit (4 GiB minus one), so ZIP64 is not required. `repack_zip32.py` copies the existing compressed stream exactly while replacing only the outer ZIP headers and directory with ordinary ZIP 2.0 records. The local and central records have no ZIP64 extras. The APK, its signature and native module remain byte-identical to fix v2.

Run:

```sh
python repack_zip32.py NuarDLC_News_v1.2_fix_v2.zip NuarDLC_News_v1.2_v2_compat.zip --report zip32-packaging-verification.json
7zz t NuarDLC_News_v1.2_v2_compat.zip
unzip -t NuarDLC_News_v1.2_v2_compat.zip
```

The new archive is verified by full extraction/SHA-256 and CRC, 7-Zip and unzip. GitHub Actions recreates it from the already uploaded LFS artifact, verifies the complete extracted APK and exact ZIP checksum against the locally tested file, then publishes it in the existing v2 release. No second large LFS artifact or new APK signing is needed. Android archiver compatibility still needs confirmation on the user's device.
