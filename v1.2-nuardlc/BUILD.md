# Reproducing Zenin 1.2

Use Python 3.11+, `requirements-native.txt`, Android Build Tools with 16 KiB zipalign support, and a signing keystore. The private signing key/password are not included.

Extract the original APK from the provided source ZIP. Verify its SHA-256 against `source-verification.json`, then extract the native asset named by `repack.py`. Its pinned hash is checked by the patcher.

```sh
python patch_native.py original-payload.so patched-payload.so --report native-changes.json
python verify_startup.py patched-payload.so --report native-verification.json
python verify_epoch_expiration.py patched-payload.so --report epoch-expiration-verification.json
python repack.py original.apk patched-payload.so unsigned.apk --report repack-report.json
zipalign -c -P 16 4 unsigned.apk
apksigner sign --ks YOUR_KEYSTORE --min-sdk-version 25 --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true --out Zenin_v1.2_NuarDLC_News.apk unsigned.apk
apksigner verify --verbose Zenin_v1.2_NuarDLC_News.apk
python package_release.py Zenin_v1.2_NuarDLC_News.apk Zenin_v1.2_NuarDLC_News.zip --apk-sha256 YOUR_APK_SHA256 --report packaging-verification.json
7zz t Zenin_v1.2_NuarDLC_News.zip
unzip -t Zenin_v1.2_NuarDLC_News.zip
```
