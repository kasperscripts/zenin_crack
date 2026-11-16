#!/system/bin/sh
set -eu
task_p1='NuarDLC_News_v1.2_v2.apk.part1'
task_p2='NuarDLC_News_v1.2_v2.apk.part2'
task_here=$(cd "$(dirname "$0")" && pwd)
task_dir=''
for task_candidate in "$task_here" "$(pwd)" /storage/emulated/0/Download /sdcard/Download; do
    if [ -f "$task_candidate/$task_p1" ] && [ -f "$task_candidate/$task_p2" ]; then
        task_dir=$task_candidate
        break
    fi
done
if [ -z "$task_dir" ]; then
    printf '%s\n' 'Сохрани обе части APK и этот скрипт в одну папку с исходными именами.'
    exit 1
fi
if ! command -v sha256sum >/dev/null 2>&1; then
    printf '%s\n' 'Для проверки файла нужна команда sha256sum.'
    exit 1
fi
task_check() {
    task_sum=$(sha256sum "$1") || return 1
    [ "${task_sum%% *}" = "$2" ]
}
printf '%s\n' 'Проверка части 1...'
if ! task_check "$task_dir/$task_p1" '212e4bb2e4305fd630f37c233e50e9773c859db1fa57ba444c5252a35fb1a60b'; then
    printf '%s\n' 'SHA-256 части 1 не совпал. Скачай эту часть заново.'
    exit 1
fi
printf '%s\n' 'Проверка части 2...'
if ! task_check "$task_dir/$task_p2" 'e857215caf7cdcc79b81e7cd1cfc7f358b3be1b027471035f6ed13bcb2d31433'; then
    printf '%s\n' 'SHA-256 части 2 не совпал. Скачай эту часть заново.'
    exit 1
fi
task_output="$task_dir/NuarDLC_News_v1.2_v2_ready.apk"
if [ -e "$task_output" ]; then
    if task_check "$task_output" '96656cba9da615a4a8f103fc5ee2469c8fbd1a77d203561c251ad4c86840e0ae'; then
        printf 'APK уже собран: %s\n' "$task_output"
        exit 0
    fi
    printf 'Файл уже существует с другой контрольной суммой: %s\n' "$task_output"
    exit 1
fi
task_tmp=$(mktemp "$task_dir/.nuardlc-build.XXXXXX")
trap 'rm -f "$task_tmp"' 0
trap 'exit 1' 1 2 15
printf '%s\n' 'Сборка APK...'
cat "$task_dir/$task_p1" "$task_dir/$task_p2" > "$task_tmp"
printf '%s\n' 'Проверка готового APK...'
if ! task_check "$task_tmp" '96656cba9da615a4a8f103fc5ee2469c8fbd1a77d203561c251ad4c86840e0ae'; then
    printf '%s\n' 'Контрольная сумма собранного APK не совпала.'
    exit 1
fi
mv -n "$task_tmp" "$task_output"
if [ -e "$task_tmp" ]; then
    printf '%s\n' 'Целевой файл уже существует. Сборка остановлена.'
    exit 1
fi
chmod 644 "$task_output" 2>/dev/null || :
printf 'Готово: %s\n' "$task_output"
