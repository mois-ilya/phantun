# Сравнение fake TCP: Phantun vs upstream udp2raw

Дата анализа: 2026-04-03

## Зачем нужен этот файл

В исходной заметке `project_phantun_fork.md` корректно описана проблема: текущий fake TCP в Phantun выглядит слишком упрощённо и, вероятно, поэтому палится stateful DPI/ТСПУ.  
Но для точного плана форка важно сравнить не только Phantun сам по себе, а именно с его "родительской" идеей в `udp2raw`, откуда Phantun исторически унаследовал сам подход fake TCP.

Этот файл фиксирует сравнение по реальному коду:

- текущий репозиторий: `fake-tcp/src/packet.rs`, `fake-tcp/src/lib.rs`
- upstream для сравнения: `udp2raw`, ветка `unified`
- локальная копия upstream, использованная для анализа: `/tmp/udp2raw-upstream`

Главный вывод: **Phantun перенял у udp2raw только базовую оболочку fake TCP, но не перенял большую часть stateful-мимикрии, которая делает udp2raw заметно более правдоподобным для DPI**.

## Краткий итог

`udp2raw` не реализует настоящий TCP-стек, но поддерживает достаточно много TCP-подобного состояния:

- случайные начальные `seq/ack_seq`
- Linux-подобный SYN fingerprint
- TCP timestamps на handshake и data
- перенос `ts_ack`
- вариативное window
- модель duplicate ACK / fast retransmit
- ограничение seq в пределах псевдо-окна

Phantun в текущем виде этого почти не делает:

- `seq` всегда стартует с нуля
- server-side SYN принимает только с `sequence == 0`
- SYN несёт только `wscale=14`
- data-пакеты идут без TCP options
- `window` всегда `65535`
- ACK обновляется крайне редко и нереалистично

То есть различие не косметическое. Это не "чуть менее реалистичная" реализация, а **почти полный отказ от stateful-симуляции TCP**, которая есть в udp2raw.

## Что реально делает upstream udp2raw

### 1. Хранит отдельное TCP-подобное состояние на соединение

В `udp2raw` на соединение хранится структура с ключевыми TCP-полями:

- `syn`, `ack`, `psh`, `rst`
- `seq`, `ack_seq`
- `ack_seq_counter`
- `ts`, `ts_ack`

См.:

- `/tmp/udp2raw-upstream/network.h:217`
- `/tmp/udp2raw-upstream/network.h:219`
- `/tmp/udp2raw-upstream/network.h:221`
- `/tmp/udp2raw-upstream/network.h:223`

Это принципиально отличается от Phantun, где состояние соединения минимально и в основном сведено к:

- `seq`
- `ack`
- `last_ack`
- `state`

См.:

- `fake-tcp/src/lib.rs:103`
- `fake-tcp/src/lib.rs:112`

Следствие: udp2raw моделирует не только "номер последовательности" и "номер подтверждения", а именно поддерживает некоторую правдоподобную эволюцию TCP header state между пакетами.

### 2. Рандомизирует начальные sequence/ack значения

В конструкторе `packet_info_t` upstream сразу инициализирует:

- `ack_seq = get_true_random_number()`
- `seq = get_true_random_number()`

См.:

- `/tmp/udp2raw-upstream/network.cpp:262`
- `/tmp/udp2raw-upstream/network.cpp:267`
- `/tmp/udp2raw-upstream/network.cpp:268`

В Phantun, напротив, каждый `Socket` создаётся с:

- `seq: AtomicU32::new(0)`

См.:

- `fake-tcp/src/lib.rs:136`
- `fake-tcp/src/lib.rs:142`

И это ещё не всё: серверный reader path у Phantun принимает SYN только если:

- `tcp_packet.get_sequence() == 0`

См.:

- `fake-tcp/src/lib.rs:498`
- `fake-tcp/src/lib.rs:506`

Это очень сильный и очень ненормальный fingerprint.  
Даже если бы всё остальное выглядело прилично, требование "все SYN должны стартовать ровно с нуля" уже выглядит как сигнатура туннеля.

### 3. SYN-пакет в udp2raw действительно имитирует типичный TCP SYN

В `udp2raw` при `syn == 1` собирается TCP header длиной `doff = 10`, то есть 40 байт заголовка TCP:

- MSS
- SACK permitted
- Timestamps
- Window Scale

См.:

- `/tmp/udp2raw-upstream/network.cpp:1646`
- `/tmp/udp2raw-upstream/network.cpp:1647`
- `/tmp/udp2raw-upstream/network.cpp:1649`
- `/tmp/udp2raw-upstream/network.cpp:1656`
- `/tmp/udp2raw-upstream/network.cpp:1659`
- `/tmp/udp2raw-upstream/network.cpp:1678`

Конкретно:

- MSS = `0x05b4` = `1460`
- SACK permitted включён
- timestamps есть уже в SYN
- `wscale = 5`

См. константу:

- `/tmp/udp2raw-upstream/network.cpp:46`

У Phantun SYN радикально проще:

- только `NOP + wscale(14)`
- ни MSS
- ни SACK
- ни timestamps

См.:

- `fake-tcp/src/packet.rs:46`
- `fake-tcp/src/packet.rs:47`
- `fake-tcp/src/packet.rs:90`
- `fake-tcp/src/packet.rs:91`
- `fake-tcp/src/packet.rs:92`

То есть по SYN fingerprint upstream действительно ближе к реальному TCP-стеку, а Phantun здесь упрощён очень агрессивно.

### 4. Data-пакеты в udp2raw несут timestamps на каждом пакете

В `udp2raw` non-SYN TCP header имеет `doff = 8`, то есть 32-байтный TCP header:

- `NOP`
- `NOP`
- `Timestamp`

См.:

- `/tmp/udp2raw-upstream/network.cpp:1682`
- `/tmp/udp2raw-upstream/network.cpp:1683`
- `/tmp/udp2raw-upstream/network.cpp:1686`
- `/tmp/udp2raw-upstream/network.cpp:1689`
- `/tmp/udp2raw-upstream/network.cpp:1695`
- `/tmp/udp2raw-upstream/network.cpp:1703`

Также upstream разбирает timestamps на приёме и сохраняет их в `recv_info.ts` / `recv_info.ts_ack`, после чего переносит `recv_info.ts` в `send_info.ts_ack` для следующих исходящих пакетов.

См.:

- `/tmp/udp2raw-upstream/network.cpp:2112`
- `/tmp/udp2raw-upstream/network.cpp:2137`
- `/tmp/udp2raw-upstream/network.cpp:2139`
- `/tmp/udp2raw-upstream/network.cpp:2140`
- `/tmp/udp2raw-upstream/network.cpp:2609`
- `/tmp/udp2raw-upstream/network.cpp:2611`

Это важный момент: в udp2raw timestamps не просто "присутствуют", а действительно живут в рамках минимальной двусторонней модели.

У Phantun data-пакеты не несут вообще никаких TCP options:

- `tcp_header_len = 20` для всего, что не SYN
- `data_offset = 5`

См.:

- `fake-tcp/src/packet.rs:46`
- `fake-tcp/src/packet.rs:47`
- `fake-tcp/src/packet.rs:90`

Следствие: после SYN с option-ами стек Phantun немедленно "исчезает" в полностью голый 20-byte TCP header. Это намного менее правдоподобно для современного TCP fingerprint.

### 5. Window в udp2raw меняется, а не зафиксировано навсегда

В upstream advertised window для каждого TCP packet выставляется как:

- `receive_window_lower_bound + random % receive_window_random_range`

Где:

- `receive_window_lower_bound = 40960`
- `receive_window_random_range = 512`

См.:

- `/tmp/udp2raw-upstream/network.cpp:44`
- `/tmp/udp2raw-upstream/network.cpp:45`
- `/tmp/udp2raw-upstream/network.cpp:1710`

У Phantun `window` всегда один и тот же:

- `0xffff`

См.:

- `fake-tcp/src/packet.rs:83`
- `fake-tcp/src/packet.rs:84`

Это не обязательно единственная причина дропа DPI, но как fingerprint это заметно хуже.

### 6. udp2raw моделирует seq/ack поведение существенно правдоподобнее

Ключевое отличие не только в packet layout, а в том, что udp2raw меняет `seq/ack_seq` после каждого send/recv.

После отправки data upstream обновляет `send_info.seq`, причём в `seq_mode 3/4` делает это с учётом псевдо-окна:

- увеличивает `seq` на длину payload
- вычисляет window size
- если `seq + max_data_len` уходит дальше окна, откатывает `seq` к `recv_info.ack_seq`
- при `ack_seq_counter >= 3` имитирует fast retransmit, тоже возвращаясь к `recv_info.ack_seq`

См.:

- `/tmp/udp2raw-upstream/network.cpp:2558`
- `/tmp/udp2raw-upstream/network.cpp:2571`
- `/tmp/udp2raw-upstream/network.cpp:2576`
- `/tmp/udp2raw-upstream/network.cpp:2583`
- `/tmp/udp2raw-upstream/network.cpp:2586`
- `/tmp/udp2raw-upstream/network.cpp:2589`

На приёме upstream:

- парсит `ack_seq`
- считает число duplicate ACK (`ack_seq_counter`)
- обновляет `send_info.ack_seq` только когда входящий `seq` совпадает с ожидаемым

См.:

- `/tmp/udp2raw-upstream/network.cpp:2309`
- `/tmp/udp2raw-upstream/network.cpp:2312`
- `/tmp/udp2raw-upstream/network.cpp:2314`
- `/tmp/udp2raw-upstream/network.cpp:2612`
- `/tmp/udp2raw-upstream/network.cpp:2617`
- `/tmp/udp2raw-upstream/network.cpp:2618`
- `/tmp/udp2raw-upstream/network.cpp:2619`

Это всё ещё далеко от реального TCP:

- upstream не хранит полноценную карту сегментов
- SACK реально не моделируется, хотя в SYN объявляется
- out-of-order обработка очень грубая

Но в сравнении с Phantun разница огромна.

### 7. Handshake в udp2raw действительно stateful

В клиентском handshake upstream:

- SYN уходит со случайными `seq/ack_seq`
- при получении SYN+ACK сверяется `recv_info.ack_seq`
- затем строится следующий пакет уже с обновлёнными `seq`, `ack_seq`, `ts_ack`

См.:

- `/tmp/udp2raw-upstream/client.cpp:181`
- `/tmp/udp2raw-upstream/client.cpp:188`
- `/tmp/udp2raw-upstream/client.cpp:189`
- `/tmp/udp2raw-upstream/client.cpp:220`
- `/tmp/udp2raw-upstream/client.cpp:221`
- `/tmp/udp2raw-upstream/client.cpp:406`
- `/tmp/udp2raw-upstream/client.cpp:412`

Сервер на входящий SYN отвечает SYN+ACK, при этом:

- `ack_seq = recv_info.seq + 1`
- `ts_ack = recv_info.ts`

См.:

- `/tmp/udp2raw-upstream/server.cpp:439`
- `/tmp/udp2raw-upstream/server.cpp:440`
- `/tmp/udp2raw-upstream/server.cpp:445`

А уже в дальнейшем handshake/data логика двигает `send_info.seq` и `send_info.ack_seq` в соответствии с реально увиденными пакетами.

У Phantun handshake намного более жёсткий и примитивный:

- клиент шлёт SYN
- сервер принимает только `seq == 0`
- сервер отвечает SYN+ACK
- клиент проверяет только `ack == self.seq + 1`
- затем ACK завершает handshake

См.:

- `fake-tcp/src/lib.rs:225`
- `fake-tcp/src/lib.rs:270`
- `fake-tcp/src/lib.rs:289`
- `fake-tcp/src/lib.rs:295`
- `fake-tcp/src/lib.rs:298`

Это рабочий минимальный handshake для NAT/firewall traversal, но очень слабая имитация реального TCP.

## Что именно было слишком сильно упрощено в Phantun

Ниже список того, что есть в `udp2raw`, но отсутствует или почти отсутствует в Phantun.

### 1. Случайный ISN

Есть в udp2raw:

- случайный `seq`
- случайный `ack_seq`

Нет в Phantun:

- `seq` всегда 0 при создании сокета
- сервер принимает только `SYN(seq=0)`

Это не просто недочёт, а сильнейшая сигнатура.

### 2. Нормальный SYN fingerprint

Есть в udp2raw:

- MSS
- SACK permitted
- timestamps
- `wscale = 5`

Нет в Phantun:

- MSS
- SACK
- timestamps

Есть только:

- `wscale = 14`

Причём `14` само по себе тоже выглядит значительно менее типично.

### 3. Timestamps на data

Есть в udp2raw:

- timestamps на каждом non-SYN TCP packet
- `ts_ack` обновляется от полученного `ts`

Нет в Phantun:

- на data TCP options отсутствуют полностью

### 4. Псевдо-окно и duplicate ACK tracking

Есть в udp2raw:

- `ack_seq_counter`
- логика fast retransmit
- ограничение seq в пределах окна

Нет в Phantun:

- никакой duplicate ACK модели
- никакого ограничения send-side seq окном peer-а

### 5. Более частое и осмысленное обновление ACK

Есть в udp2raw:

- `send_info.ack_seq` двигается после каждого релевантного принятого data packet

В Phantun:

- `ack` обновляется в `recv()`, то есть фактически по моменту чтения приложением
- самостоятельный ACK без payload шлётся только после разницы более `128 MB`

См.:

- `fake-tcp/src/lib.rs:203`
- `fake-tcp/src/lib.rs:207`

Это одна из самых нереалистичных частей текущего Phantun.

## Где первоначальная заметка была верна

### Верно: Phantun действительно слишком минималистичен

Это подтверждается напрямую кодом.

### Верно: timestamps в upstream являются важной частью правдоподобия

Да, upstream действительно использует timestamps и в SYN, и на обычных data-пакетах.

### Верно: window у Phantun слишком статичен

Да, upstream window варьирует, а Phantun держит константу `65535`.

### Верно: ACK-поведение у Phantun выглядит аномально

Да, обновление ACK по факту чтения приложением плюс редкий idle ACK очень плохо похоже на реальный TCP.

## Где первоначальную заметку стоит уточнить

### 1. "Нет MSS в SYN = нарушение RFC"

Это сформулировано слишком жёстко.

MSS option сама по себе не абсолютно обязательна в каждом SYN.  
Но в контексте современного TCP fingerprint отсутствие MSS вместе с отсутствием остальных типичных options действительно выглядит плохо.

Более точная формулировка:

- отсутствие MSS в SYN не обязательно ломает совместимость само по себе
- но сильно ухудшает правдоподобие и делает поток более сигнатурным

### 2. "doff=5 на data — это само по себе аномалия"

Тоже слишком жёстко.

Сам по себе data packet с `doff=5` нормален.  
Аномалией это становится в связке:

- SYN объявляет один TCP fingerprint
- дальнейшие data packets внезапно не несут вообще ничего из ожидаемых modern options

То есть проблема не в `doff=5` как таковом, а в **несогласованности поведенческого профиля**.

### 3. "udp2raw шлёт data как ACK+PSH"

По коду ветки `unified` это прямо не подтвердилось.

Я вижу:

- `send_info.psh = 0` в handshake путях
- поле `psh` реально присутствует в структуре
- TCP header пишет `tcph->psh = send_info.psh`

См.:

- `/tmp/udp2raw-upstream/client.cpp:184`
- `/tmp/udp2raw-upstream/client.cpp:225`
- `/tmp/udp2raw-upstream/server.cpp:442`
- `/tmp/udp2raw-upstream/network.cpp:1643`

Но явной установки `psh = 1` для data-path в исследованной ветке я не нашёл.

Значит корректнее писать так:

- upstream точно поддерживает поле `PSH`
- в analyzed `unified`-ветке нет уверенного подтверждения, что data packets систематически идут как `ACK+PSH`

Иными словами, upstream заметно лучше Phantun, но не настолько идеален, как это можно было бы понять из первой заметки.

## Что ещё важно добавить к исходному анализу

### 1. Самая сильная сигнатура Phantun не была отмечена: `seq == 0`

Это, возможно, даже сильнее по диагностической ценности, чем отсутствие timestamps.

Потому что:

- все исходящие соединения стартуют с `seq = 0`
- сервер требует `seq == 0` для входящего SYN

Если внешняя система сравнивает handshake-профили, это очень заметная аномалия.

### 2. Проблема Phantun не ограничивается packet layout

Недостаточно просто "добавить опции в SYN и data".

Если форк добавить:

- MSS
- SACK
- timestamps

но не добавить:

- состояние `ts_ack`
- честное обновление `ack`
- более правдоподобное движение `seq`

то получится только более красивый header, но не более правдоподобное TCP-поведение.

### 3. udp2raw сам тоже не является "настоящим TCP"

Это важно для планирования.

Он:

- не реализует реальную reassembly model
- не поддерживает полноценный SACK behavior
- не держит полноценную карту outstanding segments
- использует достаточно грубую псевдо-модель окна

См. даже комментарий в коде:

- `currently we dont remembr tcp segments,this is the simplest way`

Источник:

- `/tmp/udp2raw-upstream/network.cpp:2619`

То есть задача форка Phantun не в том, чтобы строить полноценный TCP stack.  
Задача в том, чтобы дойти хотя бы до уровня stateful-мимикрии `udp2raw`, а лучше чуть выше.

## Практический план форка на основе сравнения

Ниже приоритеты в том порядке, в котором их разумно внедрять.

### Этап 1. Убрать самые грубые сигнатуры

1. Случайный ISN вместо `seq = 0`
2. Убрать server-side требование `SYN(seq == 0)`
3. Нормализовать SYN fingerprint:
   - MSS=1460
   - SACK permitted
   - timestamps
   - wscale 5-7

Без этого Phantun остаётся слишком сигнатурным даже до начала data exchange.

### Этап 2. Добавить timestamps как живое состояние

Нужно добавить в состояние сокета как минимум:

- локальный `ts_val`
- последний увиденный remote `ts_val`
- `ts_ecr` для исходящих пакетов

И дальше:

- SYN/SYN-ACK/ACK должны согласованно нести TS
- data packets тоже должны нести TS
- при получении любого TS надо обновлять будущий `tsecr`

Просто "приклеить option bytes в packet builder" недостаточно.

### Этап 3. Переделать ACK-модель

Текущий порог `128 MB` слишком далёк от реального TCP.

Нужно минимум:

- обновлять `ack` на каждый принятый in-order data packet
- при необходимости слать ACK чаще, а не только после гигантского порога

Если хочется идти по минимальному пути, достаточно даже гораздо более простой модели, чем в udp2raw, но не текущей.

### Этап 4. Добавить псевдо-окно и базовую duplicate ACK логику

Не обязательно копировать udp2raw один в один, но желательно иметь:

- advertised receive window в правдоподобном диапазоне
- ограничение send-side seq в пределах окна peer-а
- счётчик duplicate ACK
- простейший fast retransmit-подобный откат send-side seq

Это уже сильно улучшит stateful-профиль потока.

### Этап 5. Опциональные улучшения

После базовой правдоподобности можно рассмотреть:

- профили fingerprint под Linux / Windows / mobile
- аккуратное использование `PSH`
- jitter / pacing для таймингов
- handshake packet под TLS-like first payload

Но это уже второй порядок пользы.

## Что менять в коде Phantun

### `fake-tcp/src/packet.rs`

Здесь потребуется:

- параметризовать TCP options, а не выводить их только из `flags & SYN`
- уметь строить:
  - SYN packet с MSS/SACK/TS/WS
  - non-SYN packet с TS
- убрать фиксированный `window=0xffff`
- начать принимать динамический `window` и timestamp-параметры из состояния сокета

Сейчас этот файл слишком "stateless" для нужной степени мимикрии.

### `fake-tcp/src/lib.rs`

Здесь потребуется:

- расширить состояние `Socket`
- хранить локальный ISN и текущее send/recv state
- отслеживать timestamps
- отслеживать duplicate ACK
- обновлять ACK существенно чаще и ближе к реальному TCP pattern
- убрать зависимость accept-path от `sequence == 0`

То есть главная часть работы будет именно здесь, а не только в packet builder.

## Практическое ограничение текущей среды

Локальный `cargo test` в этой среде не дал сетевой верификации форка, потому что дерево ориентировано на Linux, а зависимость `tokio-tun` в текущей среде не собирается как Linux-only crate.

Это не отменяет выводов анализа по коду.  
Но это означает, что:

- разрабатывать packet/state changes можно локально
- а реальные интеграционные проверки fake TCP against DPI нужно проводить на Linux

## Финальный вывод

Исходная гипотеза подтверждается и усиливается после сравнения с upstream:

- Phantun действительно упростил fake TCP намного сильнее, чем это допустимо для правдоподобной stateful-мимикрии
- отличие от udp2raw не сводится к отсутствию пары TCP options
- основные потери произошли в поддержании TCP-подобного состояния между пакетами

Самые важные недостающие элементы относительно upstream:

1. случайный ISN
2. реалистичный SYN fingerprint
3. timestamps на data и перенос `ts_ack`
4. переменный window
5. правдоподобное ACK behavior
6. базовая модель duplicate ACK / send window

Самая сильная дополнительная находка сверх исходной заметки:

- **Phantun сигнатурно требует `SYN(seq == 0)` и сам стартует все соединения с `seq = 0`**

Если делать форк "под ТСПУ", я бы начал именно с устранения этой сигнатуры и с переноса в Phantun хотя бы минимальной stateful-модели из upstream `udp2raw`.
