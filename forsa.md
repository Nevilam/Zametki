Ниже — “скелет” виндовой форензики по одному дампу памяти, когда анализ делаешь с Linux. Это именно про приоритеты, куда смотреть первым делом, и про практичный пайплайн под Volatility3/альтернативы.

0) Что у тебя за дамп и почему это важно

Перед анализом пойми тип файла — от этого зависят плагины/конвертация:

Raw/aff4 (часто .raw, .mem, .bin) — самый прямой кейс.

Crash dump (MEMORY.DMP, minidump) — структура другая, иногда часть страниц отсутствует.

Hibernation (hiberfil.sys) — сжатие/шифрование в зависимости от версии/настроек.

VM снапшоты (.vmem, .vmss) — зависят от гипервизора.

Минимальная проверка на Linux:

file memdump.bin
ls -lh memdump.bin
sha256sum memdump.bin > memdump.bin.sha256

1) Базовый инструментарий на Linux (минимальный набор)
Must-have

Volatility 3 (актуальный стандарт для Windows memory forensics)

YARA (поиск сигнатур/семейств/конфигов в памяти)

strings, ripgrep, jq (быстрый греп/парсинг вывода)

Установка (обычно):

python3 -m venv venv && source venv/bin/activate
pip install volatility3 yara-python

2) Порядок действий: “сначала понять среду → потом быстро триажить → потом углубляться”
Шаг A — определить ОС/символы

Volatility3 умеет подтягивать символы, но сначала:

python -m volatility3 -f memdump.bin windows.info


Смотри: версия Windows, build, архитектура, KDBG/DTB.

Если windows.info ругается на символы — решай это до всего остального (иначе половина плагинов будет мусорить).

3) Триаж №1: процессная картина (самое важное “в первую очередь”)

Цель: быстро ответить “кто запущен”, “что выглядит не так”, “что скрывают”.

Список процессов (разные взгляды)

python -m volatility3 -f memdump.bin windows.pslist
python -m volatility3 -f memdump.bin windows.pstree
python -m volatility3 -f memdump.bin windows.psscan


pslist — “официальные” активные.

psscan — скан по структурам: находит завершённые/скрытые.

Сверяй расхождения: процесс есть в psscan, но нет в pslist → красный флаг.

Командные строки + окружение

python -m volatility3 -f memdump.bin windows.cmdline
python -m volatility3 -f memdump.bin windows.envars


Ищи:

странные пути (AppData\Roaming, Temp, ProgramData)

-enc, -w hidden, подозрительные параметры

запуск из архиваторов/Office/браузеров

Консоли/история команд

python -m volatility3 -f memdump.bin windows.consoles


Часто даёт прям “что вводили руками”.

4) Триаж №2: сеть (если была активность — это быстро даёт IoC)
python -m volatility3 -f memdump.bin windows.netscan


Ищи:

исходящие соединения на нетипичные порты

процессы без UI, но с сетью

локальные листенеры (backdoor)

Практика: сразу выписывай IP:port + PID + process name.

5) Триаж №3: признаки инъекций/вредоносного кода в адресном пространстве

DLL-модули и аномалии загрузчика

python -m volatility3 -f memdump.bin windows.dlllist
python -m volatility3 -f memdump.bin windows.ldrmodules


Красные флаги:

DLL без пути или из Temp/AppData

несостыковки между списками (ldrmodules показывает “не так загружено”)

Поиск инъекций/подозрительных VAD

python -m volatility3 -f memdump.bin windows.malfind


Смотри:

RX/RWX регионы

PE-заголовки в памяти

шеллкод-паттерны

YARA-скан по памяти

python -m volatility3 -f memdump.bin windows.vadyarascan --yara-file rules.yar
# или более общий (в зависимости от сборки volatility3)
python -m volatility3 -f memdump.bin windows.yarascan --yara-file rules.yar

6) Сервисы, драйверы, модули ядра (если подозрение на rootkit/драйвер)
python -m volatility3 -f memdump.bin windows.svcscan
python -m volatility3 -f memdump.bin windows.driverscan
python -m volatility3 -f memdump.bin windows.modules


Ищи:

сервисы с ImagePath в пользовательских директориях

драйверы без подписи/с рандомными именами

“висит” модуль в памяти, но странно зарегистрирован

7) Файлы/артефакты прямо из памяти (когда надо “достать образец”)

Поиск файловых объектов

python -m volatility3 -f memdump.bin windows.filescan


Дамп найденных файлов

python -m volatility3 -f memdump.bin windows.dumpfiles --physaddr <addr> --dump-dir out/


Дамп VAD/PE из процесса
(обычно через malfind/vad* плагины — зависит от того, какие доступны в твоей версии volatility3)

8) Реестр из памяти (очень полезно для автозапуска и контекста)
python -m volatility3 -f memdump.bin windows.registry.hivelist
python -m volatility3 -f memdump.bin windows.registry.printkey --key "Software\\Microsoft\\Windows\\CurrentVersion\\Run"


Что смотреть:

...CurrentVersion\Run, RunOnce

Services (драйверы/сервисы)

Shell, Userinit

профиль пользователя (подозрительные “постоянки”)

9) “Куда смотреть в первую очередь” — короткий чеклист (практический)

Если времени мало, делай в таком порядке:

windows.info (версия/символы)

pslist + pstree + psscan (расхождения!)

cmdline + consoles (что запускали и как)

netscan (кто общался наружу)

dlllist + ldrmodules (аномальные модули)

malfind (инъекции/шеллкод)

YARA (быстрый hit по семействам/конфигам)

svcscan + driverscan (закреп/руткит)

registry.* (автозапуски/персистентность)

filescan/dumpfiles (добыть артефакты)

10) Как “думать” при анализе дампа памяти (чтобы не утонуть)

Полезная ментальная модель:

Контекст: какая ОС, какие пользователи/сессии, аптайм.

Поведение: какие процессы/команды/сеть.

Имплант: где код (VAD/injection), как живёт (service/run key/scheduled task — часть можно увидеть через реестр/артефакты).

Доказательства: что можно извлечь (PE, конфиги, IoC).

11) Где искать инфу (чтобы быстро прокачаться именно в memory forensics Windows)

Документация/репо Volatility 3 + примеры плагинов (самое прикладное)

Книга Windows Internals (чтобы понимать процессы/память/объекты/реестр)

Материалы по DFIR (блоги/вики) по темам: VAD, EPROCESS, handle table, loader structures

Практика на тренировочных дампах: CTF/DFIR labs (важно именно руками прогонять пайплайн выше)

12) Если хочешь — дам “боевой” шаблон-командник под один дамп

Могу набросать готовый bash-скрипт, который:

создаёт папку кейса

гоняет ключевые плагины volatility3

складывает вывод в аккуратные txt/json

отдельным файлом собирает “красные флаги” (psscan≠pslist, сеть, malfind hits)

Скажи только: дамп у тебя raw/crashdump/hiberfil/vmware и примерное имя файла (расширение) — и я дам оптимальный шаблон под тип.

2) Установка на Linux (быстро и нормально)

Самый удобный вариант — venv:

python3 -m venv venv
source venv/bin/activate
pip install -U pip
pip install volatility3


Проверка:

python -m volatility3 -h

3) Базовый синтаксис (самая важная часть)

Общий вид:

python -m volatility3 -f /path/to/memdump.bin <плагин> [опции]


Пример:

python -m volatility3 -f memdump.bin windows.info


-f — путь к дампу

windows.info — плагин

4) Первый запуск: “понять что за ОС и всё ли ок”
python -m volatility3 -f memdump.bin windows.info


Смотри:

версию Windows / build

архитектуру

нашёл ли он нужные структуры/символы

Если тут плохо — дальше будет больно.

5) Самые ходовые плагины под Windows (и что они дают)
Процессы
python -m volatility3 -f memdump.bin windows.pslist
python -m volatility3 -f memdump.bin windows.pstree
python -m volatility3 -f memdump.bin windows.psscan


pslist — активные

psscan — “скан” по памяти (находит скрытые/завершённые)

расхождения pslist vs psscan = важный сигнал

Командные строки / консоли
python -m volatility3 -f memdump.bin windows.cmdline
python -m volatility3 -f memdump.bin windows.consoles
python -m volatility3 -f memdump.bin windows.envars

Сеть
python -m volatility3 -f memdump.bin windows.netscan

DLL/модули и инъекции
python -m volatility3 -f memdump.bin windows.dlllist
python -m volatility3 -f memdump.bin windows.ldrmodules
python -m volatility3 -f memdump.bin windows.malfind

Сервисы/драйверы
python -m volatility3 -f memdump.bin windows.svcscan
python -m volatility3 -f memdump.bin windows.driverscan
python -m volatility3 -f memdump.bin windows.modules

Реестр из памяти
python -m volatility3 -f memdump.bin windows.registry.hivelist
python -m volatility3 -f memdump.bin windows.registry.printkey --key "Software\\Microsoft\\Windows\\CurrentVersion\\Run"

Файлы в памяти (поиск/выгрузка)
python -m volatility3 -f memdump.bin windows.filescan
python -m volatility3 -f memdump.bin windows.dumpfiles --dump-dir out/ --physaddr <addr>

6) Как “правильно” пользоваться: типовой пайплайн

windows.info — убедиться что всё читается

pslist/pstree/psscan — понять картину процессов

cmdline/consoles — что запускали

netscan — сеть + PID

dlllist/ldrmodules + malfind — инъекции/аномалии

svcscan/driverscan — закреп/руткит

registry — автозапуски/контекст пользователя

dumpfiles / извлечение артефактов — если нужно добыть образец

7) Практичные советы, чтобы не страдать
Папка под кейс и логирование вывода
mkdir -p case/out
python -m volatility3 -f memdump.bin windows.pslist > case/pslist.txt
python -m volatility3 -f memdump.bin windows.netscan > case/netscan.txt

“Список доступных плагинов”
python -m volatility3 --help
# или
python -m volatility3 -h | less

Частые причины “ничего не работает”

дамп не raw (hiberfil/crashdump) и нужен другой подход/конвертация

символы не подтянулись / не подходят

дамп неполный/с битой областью

анализируешь 64-bit как 32-bit (реже, Vol3 обычно сам понимает)

8) Мини-чеклист по интерпретации результатов (на что смотреть)

psscan нашёл, pslist нет → подозрение на скрытие/terminated artefacts

netscan: неизвестный процесс с внешними IP → сразу в топ

cmdline: powershell с -enc, rundll32 с непонятным экспортом, regsvr32 /s /u, wscript/cscript → красные флаги

malfind: RX/RWX регионы, PE в памяти → инъекция/лоадер

svcscan/driverscan: сервис/драйвер из AppData/Temp/ProgramData → почти всегда плохо
