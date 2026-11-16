# Raw APK delivery

The phone reports `DATAERROR` from SevenZipJBinding. Full public-download hashes and desktop extraction checks passed, including SevenZipJBinding 16.02-2.01 on Linux (both ZIP and 7z, full `extract(..., false, ...)` callbacks). This does not reproduce or establish the Android failure cause. The Java verifier and its reports are included here; the JARs were obtained from Maven Central (`net.sf.sevenzipjbinding`, version `16.02-2.01`).

This delivery uses two raw byte segments and a small shell merger. The phone only needs standard file copying and SHA-256, with no ZIP/7z extraction. The complete APK exceeds GitHub's 2 GiB release-asset limit, while each part fits. The APK itself is unchanged from fix v2, with SHA-256 `96656cba9da615a4a8f103fc5ee2469c8fbd1a77d203561c251ad4c86840e0ae`.

On Android:

1. Save `NuarDLC_News_v1.2_v2.apk.part1`, `NuarDLC_News_v1.2_v2.apk.part2` and `Build_NuarDLC_News_APK.sh` into **Download**, keeping their original names.
2. Run `Build_NuarDLC_News_APK.sh` in the MT Manager terminal.
3. Install the resulting `NuarDLC_News_v1.2_v2_ready.apk` from Download.

Both parts are required. The script checks each part's SHA-256, writes to a temporary file, verifies the complete assembled APK, then gives it the final filename. It leaves the downloaded parts in place, does not replace an existing mismatched APK, and performs no installation or privilege elevation. It searches its own directory, the current working directory and standard Download paths so it also works when the file manager launches a temporary copy of the script.

Local reproduction:

```sh
python split_apk.py NuarDLC_News_v1.2_fix_v2.zip work --report raw-apk-parts-verification.json
sh work/Build_NuarDLC_News_APK.sh
sha256sum work/NuarDLC_News_v1.2_v2_ready.apk
```

The actual generated shell script was run on the complete parts under `/bin/sh` on Linux, and the assembled APK's full hash and size were independently checked. A damaged-part fixture was rejected without creating an APK. Execution on the Android device remains untested. GitHub Actions regenerates the parts and merger, matches all sizes/hashes to the locally tested report, and uploads the files to the existing release.
