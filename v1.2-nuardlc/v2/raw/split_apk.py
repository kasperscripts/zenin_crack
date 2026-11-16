#!/usr/bin/env python3
"""Publish byte-for-byte APK parts and a checked Android shell merger."""
import argparse,hashlib,json,time,zipfile
from pathlib import Path
SOURCE_SHA256='a5269c95b04bff67532379d184b2d525947091cfa827764bfb88294971c7c77a'
APK_SHA256='96656cba9da615a4a8f103fc5ee2469c8fbd1a77d203561c251ad4c86840e0ae'
APK_SIZE=2285563072
PART_NAMES=['NuarDLC_News_v1.2_v2.apk.part1','NuarDLC_News_v1.2_v2.apk.part2']
MERGER='Build_NuarDLC_News_APK.sh'
READY_APK='NuarDLC_News_v1.2_v2_ready.apk'

def digest(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def merger(parts):
    script='''#!/system/bin/sh
set -eu
task_p1='@PART1@'
task_p2='@PART2@'
task_here=$(cd "$(dirname "$0")" && pwd)
task_dir=''
for task_candidate in "$task_here" "$(pwd)" /storage/emulated/0/Download /sdcard/Download; do
    if [ -f "$task_candidate/$task_p1" ] && [ -f "$task_candidate/$task_p2" ]; then
        task_dir=$task_candidate
        break
    fi
done
if [ -z "$task_dir" ]; then
    printf '%s\\n' 'Сохрани обе части APK и этот скрипт в одну папку с исходными именами.'
    exit 1
fi
if ! command -v sha256sum >/dev/null 2>&1; then
    printf '%s\\n' 'Для проверки файла нужна команда sha256sum.'
    exit 1
fi
task_check() {
    task_sum=$(sha256sum "$1") || return 1
    [ "${task_sum%% *}" = "$2" ]
}
printf '%s\\n' 'Проверка части 1...'
if ! task_check "$task_dir/$task_p1" '@HASH1@'; then
    printf '%s\\n' 'SHA-256 части 1 не совпал. Скачай эту часть заново.'
    exit 1
fi
printf '%s\\n' 'Проверка части 2...'
if ! task_check "$task_dir/$task_p2" '@HASH2@'; then
    printf '%s\\n' 'SHA-256 части 2 не совпал. Скачай эту часть заново.'
    exit 1
fi
task_output="$task_dir/@READY@"
if [ -e "$task_output" ]; then
    if task_check "$task_output" '@APK_HASH@'; then
        printf 'APK уже собран: %s\\n' "$task_output"
        exit 0
    fi
    printf 'Файл уже существует с другой контрольной суммой: %s\\n' "$task_output"
    exit 1
fi
task_tmp=$(mktemp "$task_dir/.nuardlc-build.XXXXXX")
trap 'rm -f "$task_tmp"' 0
trap 'exit 1' 1 2 15
printf '%s\\n' 'Сборка APK...'
cat "$task_dir/$task_p1" "$task_dir/$task_p2" > "$task_tmp"
printf '%s\\n' 'Проверка готового APK...'
if ! task_check "$task_tmp" '@APK_HASH@'; then
    printf '%s\\n' 'Контрольная сумма собранного APK не совпала.'
    exit 1
fi
mv -n "$task_tmp" "$task_output"
if [ -e "$task_tmp" ]; then
    printf '%s\\n' 'Целевой файл уже существует. Сборка остановлена.'
    exit 1
fi
chmod 644 "$task_output" 2>/dev/null || :
printf 'Готово: %s\\n' "$task_output"
'''
    values={'@PART1@':PART_NAMES[0],'@PART2@':PART_NAMES[1],'@HASH1@':parts[0]['sha256'],'@HASH2@':parts[1]['sha256'],'@READY@':READY_APK,'@APK_HASH@':APK_SHA256}
    for key,value in values.items():script=script.replace(key,value)
    return script.encode('utf-8')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('directory',type=Path);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    assert digest(a.source)==SOURCE_SHA256
    a.directory.mkdir(parents=True,exist_ok=True)
    assert all(not (a.directory/n).exists() for n in [*PART_NAMES,MERGER])
    total=0;h=hashlib.sha256();parts=[];last=time.monotonic()
    with zipfile.ZipFile(a.source) as z:
        assert z.namelist()==['NuarDLC_News_v1.2_fix_v2.apk']
        with z.open(z.namelist()[0]) as source:
            for name,size in zip(PART_NAMES,[2**30,APK_SIZE-2**30]):
                ph=hashlib.sha256();remaining=size
                with (a.directory/name).open('xb') as out:
                    while remaining:
                        b=source.read(min(4*1024*1024,remaining));assert b
                        out.write(b);h.update(b);ph.update(b);total+=len(b);remaining-=len(b)
                        if time.monotonic()-last>20:print(f'Raw APK parts: {total/APK_SIZE:.0%}',flush=True);last=time.monotonic()
                parts.append({'name':name,'size':size,'sha256':ph.hexdigest()})
            assert source.read(1)==b''
    assert total==APK_SIZE and h.hexdigest()==APK_SHA256 and all(x['size']<2**31 for x in parts)
    script=merger(parts);(a.directory/MERGER).write_bytes(script)
    report={'format':'raw APK byte parts','compression':None,'parts':parts,'merger_name':MERGER,'merger_size':len(script),'merger_sha256':hashlib.sha256(script).hexdigest(),'assembled_apk_name':READY_APK,'apk_size':total,'apk_sha256':h.hexdigest(),'apk_changed':False,'source_zip_sha256':SOURCE_SHA256,'android_execution_tested':False}
    a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2),flush=True)
if __name__=='__main__':main()
