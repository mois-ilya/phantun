# TCB Liveness & Burst Coalescing

## Overview

Дампы показывают три воспроизводимые сигнатуры, нехарактерные для Linux-стека:

1. **Frozen ACK** — до 7 подряд исходящих data-сегментов несут одинаковый ACK, пока seq растёт (5 секунд).
2. **Frozen TSecr** — то же для TCP timestamp echo.
3. **Burst** — 7 крошечных TCP-сегментов за ~70µs с одинаковыми TSval/ACK, по одному на каждую UDP-дейтаграмму из входящего всплеска.

Все три — высоковероятные триггеры для ТСПУ DPI. Цель плана — устранить их, сохранив wire-compatibility в пределах ветки `mimic-clean` (обе стороны обновляются синхронно).

Дополнительные мелкие сигнатуры, которые чиним попутно (дёшево):

- TSval = epoch_ms, что даёт одинаковые значения у пакетов внутри одной ms → **монотонный TSval**.
- Data-пакеты летят с `ACK` без `PSH` → **PSH|ACK** на непустой payload.
- `Relaxed` memory ordering на `ack`/`ts_ecr` удлиняет окно устаревания → **Release/Acquire**.

## Acceptance Criteria

- На side-by-side сравнении phantun vs udp2raw в `docs/packet-compare.html` после фикса:
  - `Max frozen ACK` и `Max frozen TSecr` в phantun **не превышают** значения udp2raw на том же сценарии (frozen-ACK сам по себе нормален когда пир молчит; ненормально — наблюдать его, когда пир шлёт трафик).
  - `Max burst` снижается до ~2 (аналогично udp2raw).
  - `ACK=0 (data)` = 0.
- На integration-тестах (capture TUN egress): в потоке из N подряд исходящих data-сегментов при активном peer'е поле ACK меняется ≥ N/2 раз, TSecr меняется ≥ N/2 раз, TSval строго монотонен.
- ACK у исходящих data-сегментов **никогда не убывает** (монотонность).
- Throughput (через `./scripts/run-benchmarks.sh`) не деградирует > 5% относительно ветки до фикса.

## Context (from discovery)

Files involved:
- `fake-tcp/src/lib.rs` — Socket TCB, reader_task, Stack::accept/connect
- `phantun/src/xor.rs` — envelope encode/decode
- `phantun/src/wire.rs` — encode_payload / classify_incoming helpers
- `phantun/src/bin/client.rs`, `phantun/src/bin/server.rs` — per-connection workers

Related patterns:
- Per-socket `AtomicU32` state (seq, ack, ts_ecr) — продолжаем использовать
- `flume::Receiver<Bytes>` для incoming — добавляем второй канал `payload_rx`
- `tokio_util::CancellationToken` — уже используется для graceful shutdown
- `pnet::packet::tcp::TcpPacket` — парсинг остаётся, но переезжает в drainer

Dependencies: никаких новых крейтов.

External reference: анализ от Codex (GPT-5) подтвердил оба корня и добавил три мелкие сигнатуры (TSval monotonicity, PSH, memory ordering).

## Development Approach

- **Testing approach**: Regular (code first, then tests). Проект уже так устроен; на macOS `cargo build/test/clippy` локально не собирается (tokio-tun Linux-only) — весь билд/тест через `./scripts/run-tests.sh` (Docker).
- маленькие фокус-коммиты по одной задаче
- **каждая задача обязательно включает тесты** (unit где возможно; integration через testing.rs/Docker где требуется TUN)
- **все тесты должны проходить перед следующей задачей**
- backward compatibility в рамках ветки `mimic-clean`: wire format XOR-envelope меняется при внедрении length-framing → оба пира апдейтятся одновременно, в CLAUDE.md отразить

## Testing Strategy

- **Unit tests**: для xor-framing (encode/decode множественных frames), для monotonic-TSval helper
- **Integration tests** (feature `integration-tests` в fake-tcp): 
  - TCB liveness — пир посылает data/ACK-only пакеты, assert что `ack`/`ts_ecr` обновляются без вызова `Socket::recv()`
  - Burst coalescing — гоним 100 UDP за 200µs, assert что out-TCP-сегментов ≤ ~5
  - Monotonicity TSval — два `send()` в одной ms, TSval строго инкрементируется
- Проект не имеет UI/e2e тестов.

## Progress Tracking

- `[x]` при завершении
- ➕ для новых задач
- ⚠️ для блокеров

## What Goes Where

- **Implementation Steps**: код + тесты в репозитории
- **Post-Completion**: real-world проверка против ТСПУ, снятие дампов после фикса, сравнение в `docs/packet-compare.html`

## Implementation Steps

### Task 1: Monotonic TSval helper

Изолированная правка, не ломает ничего: cheap win против «одинаковых TSval у пакетов в одной ms».

**Files:**
- Modify: `fake-tcp/src/lib.rs`

- [ ] добавить поле `last_ts_val: AtomicU32` в `Socket` (рядом с `ts_ecr`)
- [ ] реализовать `current_ts_val()` через `fetch_update` (CAS-loop), чтобы быть race-free под конкурентными `send()` (data worker + heartbeat task одновременно): `self.last_ts_val.fetch_update(Release, Acquire, |prev| Some(epoch_ms().max(prev.wrapping_add(1)))).unwrap()`
- [ ] инициализировать `last_ts_val` нулём в `Socket::new`
- [ ] unit-тест: два последовательных вызова возвращают строго возрастающие значения
- [ ] unit-тест: **конкурентный** — 2 потока по 1000 вызовов `current_ts_val()`, собрать все 2000 значений, assert уникальность (race под concurrent send — не должно быть дубликатов)
- [ ] unit-тест: симулировать «NTP step назад» — сохранить prev, подменить epoch_ms (через тестовый хук или trait) на меньшее значение, assert что возвращённое > prev
- [ ] прогнать `./scripts/run-tests.sh` — должно зелёнить

### Task 2: PSH flag on data segments

Один символ кода, одна сигнатура уходит.

**Files:**
- Modify: `fake-tcp/src/lib.rs`

- [ ] в `Socket::send()` заменить `let flags = tcp::TcpFlags::ACK;` на `let flags = tcp::TcpFlags::ACK | tcp::TcpFlags::PSH;`
- [ ] комментарий в коде: «PSH на каждом data-сегменте корректно потому что `send()` = 1 сегмент; после Task 5 один батч = 1 сегмент = 1 write с точки зрения Linux, так что PSH по-прежнему семантически верно»
- [ ] unit-тест через `build_tcp_packet` с payload: PSH+ACK bits выставлены; для control-пакетов (accept/connect SYN/SYN+ACK) PSH НЕ выставлен (эти пути не трогаем)
- [ ] прогнать тесты

### Task 3: Drainer + переключение recv() на payload channel

Plan B в одну неделимую задачу: drainer обязан быть **единственным** consumer'ом `incoming` с самого начала, иначе старый `recv()` ворует пакеты.

**Files:**
- Modify: `fake-tcp/src/lib.rs`

- [ ] `Socket.ack`, `Socket.ts_ecr` обернуть в `Arc<AtomicU32>` (для shared доступа из drainer и send-path)
- [ ] добавить `drainer_cancel: CancellationToken` и `payload_rx: flume::Receiver<Bytes>` в `Socket`
- [ ] **НЕ удалять `Socket.incoming` до Established.** `accept()` (lib.rs:~250) и `connect()` (lib.rs:~390) читают из него для получения SYN+ACK/финального ACK во время handshake. Ownership передаётся drainer'у только в момент перехода в Established — см. bullet про спавн ниже. Простой путь: `Socket.incoming: Option<flume::Receiver<Bytes>>`, и drainer берёт его через `self.incoming.take().unwrap()` при спавне.
- [ ] реализовать drainer-task (свободная функция, не метод):
  - owns: `incoming: flume::Receiver<Bytes>`, `payload_tx: flume::Sender<Bytes>`, `Arc<AtomicU32>` для ack/ts_ecr, `CancellationToken`
  - в `tokio::select!`: `incoming.recv_async()` или `cancel.cancelled()` → exit
  - парсит IP+TCP через `parse_ip_packet`; на RST → exit
  - всегда обновляет `ts_ecr` (Release) из `parse_tcp_timestamps`
  - payload пустой → drop кадр (pure-ACK)
  - payload не пустой → **монотонное** обновление ACK (см. ниже), затем `payload_tx.send_async(Bytes::copy_from_slice(payload)).await`; если send вернул Err (rx закрыт) → exit
- [ ] **ACK monotonicity guard**: ACK обновлять только если новое значение «впереди» текущего по wrap-aware сравнению. Псевдокод: `let cur = ack.load(Acquire); let new = seq.wrapping_add(len); if new.wrapping_sub(cur) as i32 > 0 { ack.store(new, Release); }`. Это предотвращает откат ACK на переупорядоченных/дубликатных сегментах (fake-tcp явно заявляет «preserves out-of-order delivery», так что реордеры возможны). Откат ACK — сам по себе fingerprint, избегать любой ценой.
- [ ] **backpressure**: в drainer'е использовать `payload_tx.send_async().await` (натуральный backpressure, drainer засыпает → flume `incoming` наполняется → reader_task притормаживает на своём `send_async().await`). Соединение не рвём.
- [ ] спавнить drainer:
  - в `Stack::accept` после перехода в Established (lib.rs:326-341), перед `ready.send(self)`
  - в `Socket::connect` после Established (lib.rs:400-404)
- [ ] переписать `Socket::recv()`: `self.payload_rx.recv_async().await.ok().map(|b| { buf[..].copy_from_slice(&b); b.len() })`; удалить парсинг TCP из recv
- [ ] в `Drop for Socket` — `drainer_cancel.cancel()` **перед** отправкой RST; JoinHandle не храним (fire-and-forget, drainer выходит на следующем await), это явно задокументированное поведение
- [ ] memory ordering: `ack.load(Acquire)` / `ts_ecr.load(Acquire)` в `build_tcp_packet_with_seq`; stores в drainer — `Release`
- [ ] integration-test (через `testing.rs`, TUN egress capture): создать соединение → пир шлёт 3 data-сегмента → **не вызывая `recv()`**, параллельно вызываем `sock.send()` 3 раза → капчурим 3 исходящих сегмента → assert их `ack_no` **меняется** между сегментами (отражает растущий peer seq), TSecr меняется тоже. Это прямая проверка что fingerprint ушёл.
- [ ] integration-test: reordered packets — пир шлёт seq=1000 (len=100), потом seq=900 (len=100), потом seq=1100 (len=50) → assert `ack.load()` после всех трёх = 1150 (не 1000, не 1050)
- [ ] integration-test: pure-ACK с новым TSval → `ts_ecr.load()` обновляется без `recv()`
- [ ] integration-test: round-trip smoke — отправить/принять 10 payload'ов, всё доставляется в порядке (регрессия на новый recv)
- [ ] integration-test: drop Socket → drainer корректно завершается, нет panic, нет зависаний
- [ ] прогнать `./scripts/run-tests.sh`

### Task 4: Length-framing в XOR envelope

Подготовка к coalescing. Меняем формат тела envelope: вместо single payload — `[len:u16 BE][body]...` повторяющееся. Marker остаётся (`b` = data-batch, `h` = heartbeat).

**Решение по no-key mode:** length-framing **только когда --key задан**. Без ключа — оставляем текущий 1:1 passthrough (zero-copy Cow::Borrowed). Обоснование: пользователи без ключа не пытаются скрываться от DPI (envelope-обфускация и так выключена), им важнее минимальная latency/CPU. В итоге wire-compat ломается только в keyed-режиме — это уже отражено в CLAUDE.md.

**Files:**
- Modify: `phantun/src/xor.rs`
- Modify: `phantun/src/wire.rs`

- [ ] в `xor.rs` добавить `encode_batch(key, frames: &[&[u8]]) -> Vec<u8>` — выдаёт `[IV 8][marker 'b'][len u16 BE][body]...` под XOR-потоком. **Frames с `len == 0` запрещены на encode** (debug_assert + early-return Err/panic). Причина: пустой frame неразличим от trailing-zero padding на decode.
- [ ] добавить `decode_batch(key, data) -> Option<DecodedBatch>` где `DecodedBatch = Data(Vec<Bytes>) | Heartbeat`. Используем `Bytes` (а не `Vec<u8>`) и отдаём refcount-slice'ы в один декодированный буфер — cheaper than `Vec<Vec<u8>>`, сохраняет zero-copy философию `wire.rs::Cow`.
- [ ] **decode invariants**: marker != `'b'` при непустом списке frames → malformed; `len == 0` в потоке → malformed; `len > remaining_bytes` → malformed; trailing bytes после последнего frame → malformed. Все эти случаи → `None` (≡ `DecodeFailed` выше по стеку).
- [ ] сохранить `encode(key, payload)` как врапер над `encode_batch(&[payload])` (обратная совместимость API)
- [ ] `DecodedMessage::Data(Vec<u8>)` → `DecodedMessage::Data(Vec<Bytes>)`; heartbeat variant без изменений
- [ ] в `wire.rs` обновить `encode_payload` и `classify_incoming`:
  - с ключом: `classify_incoming` возвращает `Incoming::Data(Vec<Bytes>)` (batch)
  - без ключа: возвращает `Incoming::Data(Vec<Bytes>)` с одним элементом (passthrough) — API единообразный, но batch размера 1 без overhead
- [ ] unit-тест: round-trip с 1, 5, 100 frames; размеры frames 1 байт / typical WG-data / максимум (MAX_PACKET_LEN − overhead)
- [ ] unit-тест: malformed batch (len > осталось буфера, len=0 с ненулевым payload хвостом) → `DecodeFailed`
- [ ] unit-тест: heartbeat decode работает как раньше
- [ ] unit-тест: no-key mode `encode_payload(None, ...)` всё ещё выдаёт `Cow::Borrowed` (или эквивалентный zero-alloc path)
- [ ] прогнать `./scripts/run-tests.sh`

### Task 5: Micro-batcher в клиент/сервер воркерах

Финальный шаг — coalescing. Воркеры больше не шлют 1 UDP → 1 TCP, они буферизуют и флашат пачками.

**Активен только при --key:** без ключа воркер работает по старой 1:1 схеме (см. Task 4). В коде — явная ветка `if key.is_some() { batched_loop() } else { legacy_loop() }`.

**Инвариант:** одно fake-TCP соединение = один UDP flow. Сервер держит `UdpSocket::connect(peer)` per-connection (server.rs:233), клиент — тоже per-UDP-peer (client.rs:286). Поэтому в batch'е все frames относятся к одному (src, dst) UDP pair'у, адрес в envelope не тащим. **Нарушение этого инварианта = bug; если когда-нибудь появится multi-peer server — придётся ревизовать framing.**

**Files:**
- Modify: `phantun/src/bin/client.rs`
- Modify: `phantun/src/bin/server.rs`
- Create: `phantun/src/batcher.rs`
- Modify: `phantun/src/lib.rs` (register module)

- [ ] написать `Batcher` в `phantun/src/batcher.rs`:
  - state: `pending: Vec<Bytes>`, `pending_bytes: usize`, `oldest_ts: Option<Instant>`
  - `push(&mut self, frame: Bytes) -> PushOutcome` — один из: `Buffered`, `FlushNow(Vec<Bytes>)` (batch готов отправлять)
  - `next_flush_deadline(&self) -> Option<Instant>` — `oldest_ts + FLUSH_AGE`, или None
  - `take(&mut self) -> Vec<Bytes>`
- [ ] **Budget math (critical, нельзя упрощать):** TCP payload budget на wire = `MAX_PACKET_LEN − ip_hdr − tcp_hdr_with_ts_opts`. Для IPv4: 1500 − 20 − 32 = 1448; для IPv6: 1500 − 40 − 32 = 1428. Консервативно берём `MAX_BATCH_WIRE = 1428`.
- [ ] **Encoded length при N frames с суммарным payload P**: `encoded_len = xor::OVERHEAD (9) + 2 * N + P`. Эту формулу использовать **и в trigger'е push, и в assert перед `sock.send`**. Trigger: при попытке push нового frame считаем `would_be = 9 + 2*(pending_count + 1) + pending_bytes + new_frame_len`; если `would_be > MAX_BATCH_WIRE` **или** `would_be ≥ FLUSH_BYTES` — flush текущий pending сначала, потом push нового.
- [ ] пороги: `MAX_BATCH_WIRE = 1428` (жёсткий лимит на encoded batch), `FLUSH_BYTES = 1200` (soft-trigger для хорошей утилизации MSS), `FLUSH_AGE = Duration::from_micros(500)`, `SINGLE_FRAME_BYPASS = 1000` (frame сразу ≥1000 → flush без батчинга — смысла в batch нет)
- [ ] **Receive-side buffer**: `buf_tcp` должен быть `≥ MAX_PACKET_LEN` (уже так в client.rs:258, server.rs:194). Т.к. `encoded_len ≤ MAX_BATCH_WIRE ≤ MAX_PACKET_LEN`, overflow исключён, но всё равно assert'нуть в тесте.
- [ ] **flush timer без per-tick polling**: в worker loop использовать `tokio::time::sleep_until(deadline)` где deadline = `batcher.next_flush_deadline()`. Если batcher пуст — ветка `sleep_until` disabled (либо sleep на далёкое будущее, либо `pending.is_empty().then(||…)` gate). Это избегает 10kHz wake-up на idle connection.
- [ ] переписать worker loop в `client.rs` (старое тело client.rs:288-335 → новое `batched_loop`):
  - `tokio::select!` с ветками: `udp_sock.recv()`, `sock.recv()`, `sleep_until(deadline)`, `quit.cancelled()`
  - на UDP recv: `encode_payload` → `batcher.push(bytes)`; на `FlushNow(batch)` → `sock.send(xor::encode_batch(&key, &batch)).await`
  - на sleep_until tick: `batch = batcher.take()`; `sock.send(xor::encode_batch(&key, &batch)).await`
  - на TCP recv: `xor::decode_batch` → итерировать `Vec<Bytes>` → `udp_sock.send(frame).await` для каждого
- [ ] аналогично `server.rs`
- [ ] heartbeat task остаётся отдельной — шлёт свой `encode_heartbeat` напрямую, не через batcher (heartbeat должен идти точно по расписанию, не сливаться с data)
- [ ] receive-side: на `Incoming::Data(batch)` → `for frame in batch { udp_sock.send(frame).await }`; `packet_received.notify_one()` один раз за batch (чтобы idle-timer UDP_TTL не дёргался N раз на один TCP-сегмент)
- [ ] integration-test: 100 маленьких UDP (50 bytes каждый) за 200µs → число исходящих TCP-сегментов на проводе ≤ 5 (хук на TUN egress); каждый segment ≤ `MAX_BATCH_WIRE`
- [ ] integration-test: **automated frozen-ACK test** — пир шлёт 20 data-пакетов по 100 байт с паузой 10ms между ними; параллельно наш worker шлёт 20 data-пакетов; капчурим TUN egress; считаем longest run of equal ACK / equal TSecr на исходящих data-сегментах; assert `longest_run_ack ≤ 2` и `longest_run_tsecr ≤ 2` (это и есть прямая проверка что frozen-ACK fingerprint ушёл, deterministic, не требует сравнения с udp2raw-дампом)
- [ ] integration-test: worst-case batch math — 100 маленьких frames (по 3 байта) → encoded_len не превышает `MAX_BATCH_WIRE`, всё доставляется
- [ ] integration-test: 100 UDP пакетов доставляются на другую сторону целиком и в порядке отправки
- [ ] integration-test: одиночный UDP (не набирающий `FLUSH_BYTES`) улетает ≤ 1ms после recv (flush-by-age работает)
- [ ] integration-test: no-key mode — batcher не активен, 1 UDP = 1 TCP (регрессия: поведение как в mimic-clean до Task 5)
- [ ] integration-test: heartbeat-таск шлёт свои пакеты в срок даже когда batcher копит data (heartbeat не блокируется батчингом)
- [ ] прогнать `./scripts/run-tests.sh`

### Task 6: CI harness + verification + docs

- [ ] **harness fix (обязательно, иначе phantun-тесты не запускаются в CI)**:
  - `scripts/run-tests.sh`: добавить `cargo test -p phantun` (сейчас только `-p fake-tcp`)
  - `Dockerfile.test` CMD: расширить до обоих crate'ов, например `CMD ["sh","-c","cargo test -p fake-tcp --features integration-tests && cargo test -p phantun"]`
  - убедиться что новые unit-тесты (xor batch, wire, batcher) реально прогоняются через `./scripts/run-tests.sh`
- [ ] полный прогон `./scripts/run-tests.sh` — зелёный
- [ ] `cargo clippy --verbose` через Docker-раннер — без warning'ов
- [ ] проверить на свежих дампах (`docs/packet-compare.html`): `Max frozen ACK`/`Max frozen TSecr` не выше udp2raw, `Max burst` ≈2, `ACK=0 (data)` = 0
- [ ] обновить `CLAUDE.md`:
  - раздел «XOR Envelope & Heartbeat»: новый формат — length-framed batches в keyed режиме, wire-compat break, keyed-only gate для batcher/framing
  - раздел «Mimic Mode»: заменить «no PSH flag» → «PSH|ACK on data segments»
  - раздел «Code Conventions»: для `ack`/`ts_ecr` атомиков использовать Acquire/Release (исключение из общего Relaxed-правила, нужно для drainer↔send_path visibility); `seq` остаётся Relaxed
  - добавить заметки про monotonic TSval (`last_ts_val` + `fetch_update`), per-socket drainer task, ACK monotonicity guard
- [ ] переместить план в `docs/plans/completed/` после всех checkbox'ов `[x]`

## Technical Details

**Drainer lifecycle (Task 3):**

- Drainer спавнится как fire-and-forget `tokio::spawn` при переходе в `Established`.
- **JoinHandle НЕ храним** — задача завершается автоматически через `CancellationToken` в `Drop for Socket` (cancel перед отправкой RST). Следующий `await` внутри drainer видит cancel и выходит — без panic, без log-spam (ошибка send на закрытый `payload_rx` — ожидаемая).
- Никаких FD/ресурсов drainer не держит (flume channels drop через Arc), поэтому join не нужен.
- `Stack::shutdown()` отменяет `cancel` на уровне Stack; per-socket drainer'ы независимо реагируют на drop своих каналов, это нормально.

**Drainer архитектура (Task 3):**

```
reader_task (per TUN queue)
   └─► Shared.tuples[AddrTuple] = flume::Sender<Bytes>  (raw IP packets)
         └─► Socket.drainer (per-connection, spawned at Established)
               ├─ parses TCP, stores ack/ts_ecr (Release)
               ├─ drops pure-ACK frames
               └─► payload_tx ─► Socket.payload_rx ─► Socket::recv()
```

**XOR envelope new format (Task 4):**

```
[IV: 8B][marker: 1B][frame 1]...[frame N]
  XOR stream covers marker+frames

frame = [len: 2B BE][body: len bytes]

marker 'b' → one or more data frames (consumer splits)
marker 'h' → heartbeat, filler — not parsed as frames
```

**Batcher policy (Task 5):**

- Flush triggers:
  - `pending_bytes + new_frame_size + frame_overhead ≥ 1200` (будем проверять **перед** push)
  - `now - oldest_ts ≥ 500µs`
  - single frame ≥ 1000 bytes → flush сразу (≈MTU, coalescing смысла не имеет)
- Max age 500µs даёт субмиллисекундный latency — WG на это не реагирует (его RTT всё равно ≥5ms).
- Активен только в keyed-режиме (без ключа — 1:1 passthrough). Без ключа скрываться от DPI нечем, выгода coalescing обнуляется.
- **Инвариант:** один fake-TCP socket = один UDP flow (client.rs:286 делает connect per-UDP-peer, server.rs:233 аналогично). Frames в одном batch'е относятся к одному UDP-pair'у → peer-адресация в envelope не нужна.

**Memory ordering:**

- `ack.store / ts_ecr.store` в drainer → `Ordering::Release`
- `ack.load / ts_ecr.load` в build_tcp_packet_with_seq → `Ordering::Acquire`
- `seq.fetch_add` в `send()` остаётся `Relaxed` (per-connection, reservation-only, race-free без ordering)
- `last_ts_val` — `Acquire`/`Release` на load/store

## Post-Completion

**Manual verification:**
- снять свежий tcpdump после деплоя — phantun vs udp2raw side-by-side в `docs/packet-compare.html` должны показать:
  - `Max frozen ACK` = 1
  - `Max frozen TSecr` = 1 (или малое число)
  - `Max burst` ≈ 1–2 (вместо 7)
  - `ACK=0 (data)` = 0
- тест против реальных ТСПУ — пропадёт ли нестабильная детекция

**External system updates:**
- сервер и клиент phantun нужно апдейтить одновременно (wire-break из-за length-framing)
- в README.md пометить версию с breaking change

**Benchmarks:**
- прогнать `./scripts/run-benchmarks.sh` — убедиться что throughput не деградировал (батчинг скорее помог чем помешал)
- микробенчмарк на single-frame latency (чтобы Task 5 flush-by-age не добавлял >1ms)
