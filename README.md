# Zenin — @Icon_Crack

После ввода **`@Icon_Crack`** выполняется локальная проверка ключа. Экран входа получает результат через исходные методы интерфейса; сервер лицензирования для этой проверки не используется. Контактные ссылки направлены на <https://t.me/Icon_Crack>, подсказки показывают новый ключ. Название приложения — `Zenin @Icon_Crack`.

**[Скачать готовый ZIP с APK](https://github.com/kasperscripts/zenin_crack/raw/refs/tags/zenin-icon-crack-v1/artifacts/Zenin_Icon_Crack.zip)**

Распакуйте ZIP и установите `Zenin_Icon_Crack.apk`. Ключ вводится с учётом регистра, без пробелов: `@Icon_Crack`.

Сертификат APK отличается от исходной сборки. Если Android не разрешает обновить установленный Standoff/Zenin, потребуется удалить прежнее приложение; при удалении удаляются его локальные данные. Пакет сохранён: `com.axlebolt.standoff2.huawei`, версия игры `1.1.0`, versionCode 3982, minSdk 25, targetSdk 36. Модуль Zenin рассчитан на arm64.

## Изменения

- В ARM64-модуле заменён обработчик лицензионной сессии: он читает отправленный из интерфейса ключ, принимает `@Icon_Crack`, вызывает исходный обработчик успеха и обрабатывает неверный ввод. Между проверками поток ожидает 50 мс и учитывает штатный сигнал завершения.
- Вместо серверного доказательства сессии используется локальное состояние успешного входа. Публичные методы проверки доступа, проверка сохранённого токена и экран входа сохранены.
- Изменены подсказки ключа, адрес Telegram и адрес сайта в контактной панели. Тексты по-прежнему декодируются штатной функцией; длины буферов проверены.
- В manifest изменены только подписи приложения и основной activity. DEX игры и её библиотеки, ресурсы и игровые данные сохранены.

Нативный модуль находится в `assets/VozmiteMeniaNaRabotuNoTolkoNeTolchkiPidoritIseAndRestPidorasi`. Его размер и расположение секций ELF сохранены. Список участков изменений: [native-changes.json](native-changes.json).

## Проверки и ограничения

Проверены семь случаев ввода ключа в ARM64-эмуляции, исходные пути отправки ключа и обработки успеха/ошибки, пять исходных методов доступа, проверка блокировки, сохранённого токена и завершения потока. Неверный токен отклоняется. В этих проверках сетевые функции не вызывались.

Штатный инициализатор контактной панели и декодер строк исполнены в эмуляции: обе ссылки ведут на `https://t.me/Icon_Crack`, соседние флаги инициализации не повреждены. Mutex, часы, ожидание, статические guards и отрисовка контактов в тесте заменены заглушками.

Проверены подписи APK v2/v3, выравнивание, CRC всех записей APK и ZIP. Контрольные суммы: [SHA256SUMS](SHA256SUMS). Полный отчёт: [verification.json](verification.json).

**Запуск на Android-устройстве, подключение к игре и работа игровых функций не проверены.** Проверка в ARM64-эмуляции подтверждает логику ключа и состояния доступа.

## Воспроизведение

Нужны Python 3 с `keystone-engine`, `capstone`, `pyelftools`, `unicorn`, а также Android Build Tools.

Исходный APK SHA-256: `f8fd2c7bdf39f2774923925f08fe33e3e5967e46e170eeaf3c83aba5a80958e3`. Исходный модуль SHA-256: `e50bd056c3e3174c358c5c86508ac7c2eea82215c912d2de30482e91cd036a96`.

```sh
unzip -p original.apk assets/VozmiteMeniaNaRabotuNoTolkoNeTolchkiPidoritIseAndRestPidorasi > original-payload.so
python3 patch_native.py original-payload.so patched-payload.so --report changes.json
python3 verify_native.py patched-payload.so --report native-verification.json
python3 repack.py original.apk patched-payload.so unsigned.apk --report repack-report.json
zipalign -c -P 16 4 unsigned.apk
apksigner sign --ks YOUR_KEYSTORE --min-sdk-version 25 --v2-signing-enabled true --v3-signing-enabled true --out Zenin_Icon_Crack.apk unsigned.apk
apksigner verify --verbose Zenin_Icon_Crack.apk
```

Перепаковка копирует сжатые потоки неизменённых записей ZIP без повторного сжатия. Приватный ключ подписи, пароли и исходный лицензионный ключ не публикуются.
