# Reproduce NuarDLC_News 1.2 fix v2

Use Python 3.11+, `requirements-native.txt`, JDK 21 with its compiler module, and Android Build Tools 36/apksig. The original APK and native asset hashes are pinned in the patch/repacking scripts. No server key is used.

The source APK is signed with the public AOSP development test certificate (SHA-256 `a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc`). This build restores that exact certificate instead of the previous modified build's certificate. The published scripts contain no keystore or passwords. For reproduction, obtain the public `testkey.pk8` and `testkey.x509.pem` from the AOSP `platform_build/target/product/security` repository, check the certificate fingerprint, and import them into a local PKCS12 keystore. Pass its password by file.

Extract the original native asset named by `manifest_label.py`. Keep a copy of the previous patched payload if reproducing its regression cases with `--baseline`.

```sh
python patch_native.py original-payload.so patched-payload.so --report native-changes.json
python verify_startup.py patched-payload.so --baseline previous-payload.so --report native-verification.json
python verify_epoch_expiration.py patched-payload.so --report epoch-expiration-verification.json
python repack_preserve_layout.py original.apk patched-payload.so unsigned.apk --report repack-report.json --streams expected-streams.json
java --class-path /path/to/apksigner.jar PreserveLayoutSign.java unsigned.apk NuarDLC_News_v1.2_fix_v2.apk original-testkey.p12 password-file original
python verify_apk.py NuarDLC_News_v1.2_fix_v2.apk --streams expected-streams.json --native-report native-changes.json --apksigner /path/to/apksigner --zipalign /path/to/zipalign --report apk-verification.json
python package_release.py NuarDLC_News_v1.2_fix_v2.apk NuarDLC_News_v1.2_fix_v2.zip --apk-sha256 YOUR_APK_SHA256 --report packaging-verification.json
7zz t NuarDLC_News_v1.2_fix_v2.zip
unzip -t NuarDLC_News_v1.2_fix_v2.zip
```

`repack_preserve_layout.py` fits each replacement into its exact original compressed span using valid empty DEFLATE blocks. It changes only the native asset and the manifest labels. `PreserveLayoutSign.java` replaces the signing block while retaining every original local-record/data offset. Final verification compares every compressed stream with the expected source or replacement, verifies all CRCs, v2/v3 signatures, the original certificate, labels and 16 KiB alignment.

The native regressions execute original ARM64 handlers using Unicorn and controlled Android/JNI, clock, allocation, mutex and OS-accessibility fixtures. They reproduce incomplete hook records that could overwrite a working slot with zero, missing-original activation, zero restoration, and activation retained after invalidation of the original binding. The fixed module rejects incomplete records, retries after completion, restores valid originals, and returns a binding-backed 64-bit token. These tests do not execute VK, Android rendering, the full game, or establish that the reported 82.2% crash has the same cause.

Only display strings and the generated configuration filename are renamed. Internal game-object/shader identifiers, serialization signatures, and opaque application IDs retain their original values for compatibility. The original short encoded URL initializers remain untouched; display/open-link consumers point to a full immutable new URL without enlarging the ELF or BSS.
