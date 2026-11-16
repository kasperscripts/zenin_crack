# 7z packaging after the Android extraction error

MT Manager also reported `invalid block type` while reading the ZIP32 variant. Rewriting ZIP metadata did not resolve the user's problem. Desktop/public-download checks had passed, so the root cause on the phone remains unconfirmed.

This package uses a standard 7z container with a newly encoded LZMA2 stream and a 1 MiB dictionary. The signed APK is streamed directly from the already verified ZIP without changing any APK bytes. The output contains exactly `NuarDLC_News_v1.2_fix_v2.apk`. Its complete SHA-256 must remain `96656cba9da615a4a8f103fc5ee2469c8fbd1a77d203561c251ad4c86840e0ae`.

The compressor is official 7-Zip 25.01, downloaded by `setup_7zip.py` with pinned checksums for its release tar and executable. All timestamps are disabled and encoder options are fixed to make the runner's output match the locally tested archive. `package_7z.py` checks the original ZIP hash, input APK hash and the GitHub asset size limit. The fast LZMA2 encoder uses a small dictionary and bounded match searching; its settings are recorded in the report.

```sh
python setup_7zip.py tools
python package_7z.py NuarDLC_News_v1.2_fix_v2.zip NuarDLC_News_v1.2_v2.7z --sevenzip tools/7zz --report sevenzip-packaging-verification.json
tools/7zz t NuarDLC_News_v1.2_v2.7z
python verify_7z.py NuarDLC_News_v1.2_v2.7z --report libarchive-verification.json
```

The complete archive is tested with 7-Zip and independently decoded with libarchive, checking the extracted APK hash and size. GitHub Actions repeats the pinned build, matches its exact hash to the local report and publishes it in the existing release. Native/game behavior has not changed. MT Manager on the phone has not been tested here.

On Android, fully extract the 7z into a normal folder, then open the APK from that folder for installation.
