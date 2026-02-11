# DFIR / Форензика: практичный конспект (Linux-аналитик → Windows-артефакты)
*Фокус: расследование инцидентов и форензика с акцентом на Windows и анализ с Linux (включая дампы памяти).*

> ⚠️ Этическая ремарка: ниже — про **защиту и расследование**. Используй только на легально полученных образах/дампах и в рамках полномочий.

---

## Содержание
1. [Базовые принципы и порядок работы](#1-базовые-принципы-и-порядок-работы)
2. [Подготовка кейса и доказательств (chain of custody)](#2-подготовка-кейса-и-доказательств-chain-of-custody)
3. [Быстрый триаж (что смотреть в первую очередь)](#3-быстрый-триаж-что-смотреть-в-первую-очередь)
4. [Memory forensics Windows на Linux (Volatility 3)](#4-memory-forensics-windows-на-linux-volatility-3)
5. [Извлечение образцов/артефактов из памяти](#5-извлечение-образцовартефактов-из-памяти)
6. [Дисковая форензика Windows с Linux (NTFS, артефакты)](#6-дисковая-форензика-windows-с-linux-ntfs-артефакты)
7. [Артефакты Windows: что, где и зачем](#7-артефакты-windows-что-где-и-зачем)
8. [Логи Windows (EVTX) и их анализ](#8-логи-windows-evtx-и-их-анализ)
9. [Таймлайн и корреляция источников](#9-таймлайн-и-корреляция-источников)
10. [Сеть: pcap/NetFlow/DNS/Proxy](#10-сеть-pcapnetflowdnsproxy)
11. [YARA/IOC/хэши и контентный поиск](#11-yaraioхэши-и-контентный-поиск)
12. [Типовые сценарии (playbooks)](#12-типовые-сценарии-playbooks)
13. [Чеклисты](#13-чеклисты)
14. [Шаблон структуры папок кейса](#14-шаблон-структуры-папок-кейса)

---

## 1) Базовые принципы и порядок работы
### Цели форензики
- **Сохранить** доказательства (integrity).
- **Понять** что произошло (scope, root cause).
- **Собрать** индикаторы (IOC), артефакты, временную линию.
- **Поддержать** реагирование (eradication, hardening) и отчётность.

### Ментальная модель расследования
- **Контекст**: где/когда/какая система/какие пользователи.
- **Поведение**: процессы/команды/сеть/доступ к файлам/привилегии.
- **Имплант**: где код, как закреплён, как общается.
- **Следы**: логи, реестр, файловые артефакты, память.

---

## 2) Подготовка кейса и доказательств (chain of custody)
### 2.1 Контроль целостности
Сразу фиксируй хэши (лучше SHA-256/512) и размеры.

```bash
sha256sum evidence.raw > evidence.raw.sha256
sha512sum evidence.raw > evidence.raw.sha512
ls -lh evidence.raw > evidence.raw.size.txt
file evidence.raw > evidence.raw.filetype.txt
```

### 2.2 Работа только с копиями
- Оригинал — **read-only**, копии — для анализа.
- Если диск-образ: монтируй **read-only**.

```bash
# Пример: защита от записи на уровне файловой системы
sudo mount -o ro,loop,show_sys_files,streams_interface=windows disk.img /mnt/img
```

### 2.3 Базовая структура кейса
См. раздел [14](#14-шаблон-структуры-папок-кейса).

---

## 3) Быстрый триаж (что смотреть в первую очередь)
### Если есть ТОЛЬКО дамп памяти Windows (частый кейс)
1. `windows.info` → версия/архитектура/валидность
2. Процессы: `pslist`, `pstree`, **сравнить** с `psscan`
3. Команды: `cmdline`, `consoles`
4. Сеть: `netscan` (IP:port ↔ PID)
5. Инъекции: `malfind`, `ldrmodules`, `dlllist`
6. Сервисы/драйверы: `svcscan`, `driverscan`
7. Реестр: `hivelist`, `printkey` (Run/Services/Shell)
8. Извлечение: `dumpfiles`, дамп подозрительных регионов

### Если есть диск-образ/файловая система
1. MFT/USN/Prefetch/Amcache/Shimcache
2. EVTX логи (Security/System/TaskScheduler/PowerShell)
3. Автозапуски (Run keys, services, scheduled tasks, startup folders)
4. Браузерные артефакты/загрузки
5. Поиск IOC (хэши/строки/домены)

---

## 4) Memory forensics Windows на Linux (Volatility 3)
### 4.1 Что такое Volatility 3
Volatility 3 — фреймворк, который:
- читает дамп RAM (разные форматы),
- интерпретирует структуры ОС через **символы**,
- запускает **плагины** для извлечения артефактов (процессы, сеть, реестр, инъекции и т.д.).

### 4.2 Установка (Linux)
```bash
python3 -m venv venv
source venv/bin/activate
pip install -U pip
pip install volatility3
python -m volatility3 -h
```

### 4.3 Базовый синтаксис
```bash
python -m volatility3 -f /path/to/memdump.bin windows.info
python -m volatility3 -f /path/to/memdump.bin <plugin> [options]
```

### 4.4 Первый запуск: идентификация ОС/валидность
```bash
python -m volatility3 -f memdump.bin windows.info
```

Если тут ошибки — дальше почти всё будет неполным:
- символы не подходят,
- формат дампа необычный,
- дамп неполный/повреждён.

### 4.5 Процессы: список, дерево, скан
```bash
python -m volatility3 -f memdump.bin windows.pslist
python -m volatility3 -f memdump.bin windows.pstree
python -m volatility3 -f memdump.bin windows.psscan
```

**Красные флаги**
- есть в `psscan`, но нет в `pslist` → скрытые/terminated артефакты
- странные родительские связи в `pstree`
- процессы из нестандартных путей (Temp/AppData/ProgramData)

### 4.6 Командные строки, консоли, переменные окружения
```bash
python -m volatility3 -f memdump.bin windows.cmdline
python -m volatility3 -f memdump.bin windows.consoles
python -m volatility3 -f memdump.bin windows.envars
```

Ищи:
- `powershell -enc`, `-w hidden`
- `rundll32` с непонятным экспортом
- `regsvr32`/`mshta`/`wscript`/`cscript`
- скачивание/исполнение из Temp/AppData

### 4.7 Сеть (связка PID ↔ соединения)
```bash
python -m volatility3 -f memdump.bin windows.netscan
```

Ищи:
- внешние IP/домены, необычные порты
- процессы без UI с активной сетью
- локальные LISTEN (бекдор)

### 4.8 DLL/модули/аномалии загрузчика
```bash
python -m volatility3 -f memdump.bin windows.dlllist
python -m volatility3 -f memdump.bin windows.ldrmodules
```

Ищи:
- DLL без пути/с путём в Temp/AppData
- несостыковки между списками (признак “необычной” загрузки)

### 4.9 Инъекции и подозрительные регионы памяти
```bash
python -m volatility3 -f memdump.bin windows.malfind
```

Смотри:
- RX/RWX регионы
- PE-заголовки в памяти
- признаки шеллкода/лоадеров

### 4.10 Сервисы/драйверы/ядро (закреп/руткит)
```bash
python -m volatility3 -f memdump.bin windows.svcscan
python -m volatility3 -f memdump.bin windows.driverscan
python -m volatility3 -f memdump.bin windows.modules
```

Ищи:
- сервис с `ImagePath` в пользовательских каталогах
- драйверы со странными именами/без явной легитимности

### 4.11 Реестр из памяти
```bash
python -m volatility3 -f memdump.bin windows.registry.hivelist
python -m volatility3 -f memdump.bin windows.registry.printkey --key "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
python -m volatility3 -f memdump.bin windows.registry.printkey --key "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
python -m volatility3 -f memdump.bin windows.registry.printkey --key "SYSTEM\\CurrentControlSet\\Services"
```

---

## 5) Извлечение образцов/артефактов из памяти
### 5.1 Поиск файловых объектов
```bash
python -m volatility3 -f memdump.bin windows.filescan
```

### 5.2 Дамп найденных файлов
```bash
mkdir -p out/dumpfiles
python -m volatility3 -f memdump.bin windows.dumpfiles --dump-dir out/dumpfiles --physaddr <ADDR>
```

### 5.3 Контентный поиск по дампу (быстро)
```bash
# Строки (можно добавить -el для wide-строк, но зависит от strings)
strings -a memdump.bin | rg -n "http|powershell|cmd\.exe|rundll32|\.ps1|\.dll|\.exe"
```

---

## 6) Дисковая форензика Windows с Linux (NTFS, артефакты)
> Этот раздел про кейс, когда у тебя **диск-образ** (`.E01`, `.img`, `.dd`) или смонтированный NTFS.

### 6.1 Монтирование NTFS read-only
```bash
sudo mkdir -p /mnt/img
sudo mount -o ro,loop,show_sys_files,streams_interface=windows disk.img /mnt/img
```

### 6.2 Работа с E01 (EnCase)
Если E01 — обычно используют `ewfmount` (libewf):
```bash
sudo mkdir -p /mnt/ewf /mnt/img
sudo ewfmount evidence.E01 /mnt/ewf
sudo mount -o ro,loop /mnt/ewf/ewf1 /mnt/img
```

### 6.3 Извлечение ключевых артефактов Windows (пути)
См. раздел [7](#7-артефакты-windows-что-где-и-зачем) — там перечисление.

---

## 7) Артефакты Windows: что, где и зачем
> Для каждого артефакта — “что доказывает” + типичные пути.

### 7.1 Prefetch (исполнение программ)
- **Зачем**: что запускалось, когда, сколько раз.
- **Где**: `C:\Windows\Prefetch\*.pf`

### 7.2 Amcache (Program Inventory)
- **Зачем**: сведения о запуске/установке, бинарники.
- **Где**: `C:\Windows\AppCompat\Programs\Amcache.hve`

### 7.3 Shimcache / AppCompatCache
- **Зачем**: следы исполнения/наличия файлов.
- **Где**: в реестре `SYSTEM` hive (извлекается утилитами).

### 7.4 SRUM (сетевые/энергетические/использование приложений)
- **Где**: `C:\Windows\System32\sru\SRUDB.dat`

### 7.5 Jump Lists (недавние документы/действия)
- **Где**:  
  `C:\Users\<u>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`  
  `C:\Users\<u>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`

### 7.6 LNK (ярлыки)
- **Где**: `C:\Users\<u>\AppData\Roaming\Microsoft\Windows\Recent\` и по системе.

### 7.7 Recycle Bin
- **Где**: `C:\$Recycle.Bin\`

### 7.8 Scheduled Tasks
- **Где**:  
  XML: `C:\Windows\System32\Tasks\`  
  и реестр/журналы TaskScheduler.

### 7.9 Автозапуски
- **Run keys**:
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- **Services**:
  - `HKLM\SYSTEM\CurrentControlSet\Services`
- **Startup folders**:
  - `C:\Users\<u>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
  - `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`

---

## 8) Логи Windows (EVTX) и их анализ
### 8.1 Где лежат EVTX
`C:\Windows\System32\winevt\Logs\*.evtx`

### 8.2 Инструменты на Linux
- `evtxdump` / `python-evtx`
- `Chainsaw` (быстрый hunting по правилам)
- `Sigma` правила (конвертация в формат Chainsaw/Elastic и т.д.)

### 8.3 Самые полезные логи (практика)
- **Security.evtx**: логон/привилегии/процессы (если включено)
- **System.evtx**: сервисы, драйверы, сбои
- **Microsoft-Windows-PowerShell/Operational**: PowerShell activity
- **Microsoft-Windows-TaskScheduler/Operational**: задачи
- **Microsoft-Windows-WMI-Activity/Operational**: WMI persistence/activity
- **Microsoft-Windows-Windows Defender/Operational**: детекты

### 8.4 Быстрый извлекающий дамп в JSON (примерный подход)
> Команды зависят от выбранной утилиты, но общий подход: EVTX → JSON → `jq/rg`.

Пример конвейера:
```bash
# псевдопример: evtx → jsonlines → фильтрация
evtxdump -f Security.evtx --format json | jq -c '.'
```

---

## 9) Таймлайн и корреляция источников
### 9.1 Что склеивать в таймлайн
- EVTX события (логон/процессы/PS/таски)
- Prefetch timestamps
- Amcache/Shimcache
- USN Journal (если есть)
- MFT timestamps
- Браузерные загрузки/история
- Сеть (DNS/Proxy/Firewall)

### 9.2 Практика корреляции
- выбираешь “якорное событие” (например, подозрительный `powershell -enc`)
- по времени ±30 минут собираешь:
  - какие процессы появились
  - какие соединения были
  - какие файлы создавались/менялись
  - какие задачи/сервисы добавлялись

---

## 10) Сеть: pcap/NetFlow/DNS/Proxy
### 10.1 Быстрый разбор pcap (tshark)
```bash
tshark -r traffic.pcapng -q -z conv,tcp
tshark -r traffic.pcapng -Y "dns" -T fields -e frame.time -e dns.qry.name | head
tshark -r traffic.pcapng -Y "http.request" -T fields -e frame.time -e ip.dst -e http.host -e http.request.uri | head
```

### 10.2 Извлечение доменов/серверов
```bash
tshark -r traffic.pcapng -Y "tls.handshake.extensions_server_name" \
  -T fields -e tls.handshake.extensions_server_name | sort -u | head
```

---

## 11) YARA/IOC/хэши и контентный поиск
### 11.1 Хэши
```bash
sha256sum sample.bin
md5sum sample.bin
```

### 11.2 YARA по файлам
```bash
yara -r rules.yar /mnt/img/ 2>/dev/null | head
```

### 11.3 YARA по памяти (через Volatility 3)
> Названия плагинов могут отличаться по сборкам, но типовой подход такой:

```bash
python -m volatility3 -f memdump.bin windows.vadyarascan --yara-file rules.yar
# либо
python -m volatility3 -f memdump.bin windows.yarascan --yara-file rules.yar
```

### 11.4 Поиск строк/IoC по смонтированному образу
```bash
rg -n --hidden -S "example\.com|/gate\.php|powershell -enc|rundll32" /mnt/img 2>/dev/null
```

---

## 12) Типовые сценарии (playbooks)
### 12.1 Подозрение на малварь в памяти (только RAM dump)
**Цель**: быстро найти исполняемый код, сеть, точки закрепа, извлечь образцы.

```bash
python -m volatility3 -f memdump.bin windows.info
python -m volatility3 -f memdump.bin windows.pslist
python -m volatility3 -f memdump.bin windows.psscan
python -m volatility3 -f memdump.bin windows.pstree
python -m volatility3 -f memdump.bin windows.cmdline
python -m volatility3 -f memdump.bin windows.consoles
python -m volatility3 -f memdump.bin windows.netscan
python -m volatility3 -f memdump.bin windows.ldrmodules
python -m volatility3 -f memdump.bin windows.dlllist
python -m volatility3 -f memdump.bin windows.malfind
python -m volatility3 -f memdump.bin windows.svcscan
python -m volatility3 -f memdump.bin windows.driverscan
python -m volatility3 -f memdump.bin windows.registry.hivelist
python -m volatility3 -f memdump.bin windows.registry.printkey --key "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
python -m volatility3 -f memdump.bin windows.filescan
```

Дальше:
- по `malfind`/`filescan` дампишь подозрительное
- выписываешь IOC из `netscan`/строк/YARA

### 12.2 Закреп через Scheduled Task / Service (диск-образ)
**Цель**: найти XML задач, сервисы, связанный бинарник, таймлайн создания.

```bash
# Tasks
find /mnt/img/Windows/System32/Tasks -type f -maxdepth 3 -print 2>/dev/null | head

# Services (на диске — через SYSTEM hive/инструменты; либо по EVTX)
# EVTX TaskScheduler
ls /mnt/img/Windows/System32/winevt/Logs | rg -i "TaskScheduler"
```

### 12.3 Подозрение на PowerShell
**Цель**: команды/скрипты/модули/запуски.

- Память: `windows.consoles`, `windows.cmdline`, strings + `rg "powershell| -enc|FromBase64String"`
- Диск/логи: PowerShell Operational EVTX, PSReadLine history (если сохранилось)

---

## 13) Чеклисты
### 13.1 Мини-чеклист “только дамп памяти”
- [ ] `windows.info` успешен
- [ ] `pslist/pstree/psscan` сравнить
- [ ] `cmdline` проверить подозрительные параметры
- [ ] `consoles` посмотреть реальные введённые команды
- [ ] `netscan` выписать IP:port ↔ PID
- [ ] `malfind` найти инъекции/RWX
- [ ] `ldrmodules/dlllist` аномальные модули
- [ ] `svcscan/driverscan` признаки закрепа/руткита
- [ ] `registry.*` Run/Services/Shell
- [ ] извлечь образцы (`dumpfiles`, дамп регионов) и посчитать хэши

### 13.2 Мини-чеклист “диск-образ”
- [ ] хэши образа
- [ ] монтирование ro
- [ ] EVTX экспорт/поиск ключевых событий
- [ ] Prefetch/Amcache/Shimcache/JumpLists/LNK
- [ ] Scheduled tasks / services / startup folders
- [ ] поиск IOC по файловой системе

---

## 14) Шаблон структуры папок кейса
```text
case_YYYYMMDD_name/
  00_notes/
    scope.md
    timeline_notes.md
  01_hashes/
    evidence.sha256
    evidence.sha512
  02_raw/
    memdump.bin
    disk.img
  03_outputs/
    volatility3/
      windows.info.txt
      pslist.txt
      psscan.txt
      pstree.txt
      cmdline.txt
      consoles.txt
      netscan.txt
      malfind.txt
      dlllist.txt
      ldrmodules.txt
      svcscan.txt
      driverscan.txt
      registry_run.txt
    evtx/
      parsed/
    network/
      tshark_conversations.txt
      dns_queries.txt
  04_extracted/
    dumpfiles/
    samples/
  05_ioc/
    ioc_domains.txt
    ioc_ips.txt
    ioc_hashes.txt
  06_report/
    report.md
```

---

## Быстрый “боевой” набор команд Vol3 (копипаста)
```bash
DUMP="memdump.bin"
OUT="case/03_outputs/volatility3"
mkdir -p "$OUT"

python -m volatility3 -f "$DUMP" windows.info        > "$OUT/windows.info.txt"
python -m volatility3 -f "$DUMP" windows.pslist      > "$OUT/pslist.txt"
python -m volatility3 -f "$DUMP" windows.psscan      > "$OUT/psscan.txt"
python -m volatility3 -f "$DUMP" windows.pstree      > "$OUT/pstree.txt"
python -m volatility3 -f "$DUMP" windows.cmdline     > "$OUT/cmdline.txt"
python -m volatility3 -f "$DUMP" windows.consoles    > "$OUT/consoles.txt"
python -m volatility3 -f "$DUMP" windows.envars      > "$OUT/envars.txt"
python -m volatility3 -f "$DUMP" windows.netscan     > "$OUT/netscan.txt"
python -m volatility3 -f "$DUMP" windows.dlllist     > "$OUT/dlllist.txt"
python -m volatility3 -f "$DUMP" windows.ldrmodules  > "$OUT/ldrmodules.txt"
python -m volatility3 -f "$DUMP" windows.malfind     > "$OUT/malfind.txt"
python -m volatility3 -f "$DUMP" windows.svcscan     > "$OUT/svcscan.txt"
python -m volatility3 -f "$DUMP" windows.driverscan  > "$OUT/driverscan.txt"
python -m volatility3 -f "$DUMP" windows.modules     > "$OUT/modules.txt"
python -m volatility3 -f "$DUMP" windows.filescan    > "$OUT/filescan.txt"

python -m volatility3 -f "$DUMP" windows.registry.hivelist > "$OUT/registry_hivelist.txt"
python -m volatility3 -f "$DUMP" windows.registry.printkey --key "Software\\Microsoft\\Windows\\CurrentVersion\\Run" > "$OUT/registry_run.txt"
python -m volatility3 -f "$DUMP" windows.registry.printkey --key "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" > "$OUT/registry_runonce.txt"
```

---

### Хочешь “версию 2.0” под твой кейс?
Если скажешь **тип дампа** (raw/crashdump/hiberfil/vmware) и версию Windows (из `windows.info`), я могу добавить:
- более точный набор плагинов под твою версию,
- команды извлечения PE/region dump для malfind-hit’ов,
- мини-шаблон отчёта (findings → evidence → IOC → timeline).
