# Mimic udp2raw two-bucket size pattern

## Overview

Устранить fingerprint размеров пакетов, который отличает phantun от udp2raw в обходе ТСПУ.

**Проблема:** текущий `xor::encode` добавляет случайный padding 0..128 байт, создавая на проводе разброс 49..414 байт для одной и той же AWG-нагрузки. udp2raw же показывает только 2 размера: ~192 (AWG data + фиксированный overhead) и ~1248 (свой heartbeat `hb_len=1200` + overhead).

**Решение (Option B из обсуждения):**
1. Убрать случайный padding из XOR — размеры data-пакетов станут консистентными (~150 байт через AWG).
2. Добавить свой heartbeat-механизм — фиксированный псевдослучайный буфер 1200 байт, 1 раз в секунду, в обе стороны.

Результат: на проводе будут два "бакета" размеров, как у udp2raw, без случайной вариации.

**Область действия:** работает только при заданном `--xor-key` (без ключа получатель не сможет отличить heartbeat от data).

## Context (from discovery)

- `phantun/src/xor.rs` — envelope: `[IV 8] [pad_len 2] [random_pad] ['b'] [payload]`
- `phantun/src/bin/client.rs:22-33` — `encode_payload`/`decode_payload` wrappers
- `phantun/src/bin/client.rs:299-320` — per-connection async loop (send/recv), идеальное место для heartbeat таска
- `phantun/src/bin/server.rs` — симметрично
- `fake_tcp::Socket::send()` — шлёт произвольный буфер, не знает про содержимое
- Commits на ветке `mimic-clean`: TTL fix (8e31360), standalone ACK + PSH (308f350)

## Development Approach

- **testing approach:** Regular (code first, unit tests после)
- изменения в xor.rs ломают wire-совместимость с текущими phantun — это нормально, мы уже на ветке dev, обратная совместимость с предыдущими коммитами не нужна
- `--stealth 0` invariant не затрагиваем (это про TCP-стек, не про payload)
- локально на macOS собрать нельзя — верифицировать через `./scripts/run-tests.sh` (Docker)
- **CRITICAL: every task MUST include tests**
- **CRITICAL: all tests must pass before starting next task**

## Testing Strategy

- **unit tests:** xor.rs (encode/decode/encode_heartbeat round-trip, маркер 'h' корректно отличается от 'b')
- **integration tests:** в `fake-tcp/src/testing.rs` есть TestEnv, но он не тестирует phantun binary — только fake-tcp layer. Интеграционных тестов phantun (client↔server) в репозитории нет. Heartbeat логика будет покрыта только unit-тестами + ручным тестом через ТСПУ.
- **manual test:** после завершения — запуск в продакшене через ТСПУ, tcpdump, проверить что размеры схлопнулись в ~150/1248 байт.

## Progress Tracking

- `[x]` при завершении
- `➕` для новых задач
- `⚠️` для блокеров

## What Goes Where

- **Implementation Steps** (`[ ]`): код + unit-тесты + clippy/build verification
- **Post-Completion** (без чекбоксов): ручной тест через ТСПУ + решение про delayed ACK

## Implementation Steps

### Task 1: Refactor xor.rs — remove random pad, add heartbeat variant

**Files:**
- Modify: `phantun/src/xor.rs`

Изменение формата envelope:

```
[IV 8] [marker 1: 'b'=data | 'h'=heartbeat] [payload]
```

Убираем поле `pad_len` (2 bytes) и random padding. Overhead становится 9 байт вместо 11.

Новый API:

```rust
pub enum DecodedMessage {
    Data(Vec<u8>),
    Heartbeat,
}

/// Encode data message (marker 'b').
pub fn encode(key: &[u8], payload: &[u8]) -> Vec<u8>;

/// Encode heartbeat message (marker 'h') with `size` bytes of random filler.
pub fn encode_heartbeat(key: &[u8], size: usize) -> Vec<u8>;

/// Decode any message, distinguishing data from heartbeat.
pub fn decode(key: &[u8], data: &[u8]) -> Option<DecodedMessage>;
```

- [x] переписать `xor.rs`: новый формат envelope без `pad_len`
- [x] реализовать `encode(key, payload)` — marker 'b'
- [x] реализовать `encode_heartbeat(key, size)` — marker 'h' + `size` random bytes
- [x] реализовать `decode` возвращающий `Option<DecodedMessage>`
- [x] обновить docstring в начале файла
- [x] написать unit-тест: encode/decode round-trip для Data
- [x] написать unit-тест: encode_heartbeat → decode возвращает Heartbeat
- [x] написать unit-тест: decode с неверным ключом → None
- [x] написать unit-тест: decode со слишком коротким буфером → None
- [x] написать unit-тест: decode с неизвестным marker → None
- [x] `cargo clippy -p phantun --verbose` — чисто (pre-existing collapsible_if warnings in server.rs unrelated to this task; xor.rs + lib clippy-clean)
- [x] `./scripts/run-tests.sh` — все тесты проходят (fake-tcp 49 unit + 12 integration; phantun xor 8 unit tests)

### Task 2: Update client.rs — use new xor API, add heartbeat task

**Files:**
- Modify: `phantun/src/bin/client.rs`

- [x] обновить константы: `ENCODE_OVERHEAD: usize = 9` (было 11), удалить `MAX_PAD`
- [x] `encode_payload(key, payload)` — упростить, убрать `max_pad` расчёт, вызывать `xor::encode(k, payload)`
- [x] `decode_payload(key, data) -> Option<Vec<u8>>` — теперь возвращает `Option`:
  - `Some(Data(v))` → `Some(v)`
  - `Some(Heartbeat)` → `None` (вызывающий сторонний код пропускает)
  - `None` (decode failed) → `None`
- [x] в получающем коде (`sock.recv` → UDP send): если `decode_payload` вернул `None` — не слать в UDP, просто продолжить (без логирования, чтобы не шуметь — hb'ы частые)
- [x] добавить heartbeat task: `tokio::spawn` внутри per-connection block (рядом с fastpath task, cancel через `quit` token)
  - interval 600ms (`tokio::time::interval`) — как у udp2raw
  - на каждый tick: если `key.is_some()` — сгенерировать `encode_heartbeat(k, 1200)` и `sock.send`
  - если key отсутствует — таск не спавнить (hb только при XOR)
- [x] добавить константу `HEARTBEAT_SIZE: usize = 1200` и `HEARTBEAT_INTERVAL: Duration = Duration::from_millis(600)` (совпадает с udp2raw `heartbeat_interval = 600ms` из `misc.h:48`)
- [x] verify compiles: `cargo build --bin client` (через Docker)
- [x] интеграционных тестов phantun нет — ручная проверка после Task 4

### Task 3: Update server.rs — symmetric changes

**Files:**
- Modify: `phantun/src/bin/server.rs`

- [x] те же изменения констант: `ENCODE_OVERHEAD = 9`, убрать `MAX_PAD`
- [x] упростить `encode_payload` и обновить `decode_payload` (аналогично client)
- [x] filter heartbeat на recv-path (не слать в UDP бэкенд)
- [x] добавить heartbeat task в per-connection scope с теми же параметрами (1200 байт / 600ms)
- [x] verify compiles: `cargo build --bin phantun-server` (через Docker — `./scripts/run-tests.sh` builds workspace)

### Task 4: Verify acceptance criteria

- [ ] все юнит-тесты проходят: `./scripts/run-tests.sh`
- [ ] clippy чист: `cargo clippy --verbose` (в Docker)
- [ ] ручная проверка сборки обоих бинарников
- [ ] размер overhead в XOR envelope = 9 байт (было 11)
- [ ] при работе с ключом: heartbeat шлётся каждые 600ms с обеих сторон (как у udp2raw)
- [ ] при работе без ключа: heartbeat не шлётся (логика не ломается)

### Task 5: Update documentation and backlog

**Files:**
- Modify: `CLAUDE.md` (если появились новые patterns)
- Modify: `docs/plans/backlog.md` (удалить/обновить запись про размеры пакетов, если есть)

- [ ] добавить в `CLAUDE.md` краткое упоминание про heartbeat механизм (если нужно для будущих контрибьюторов)
- [ ] переместить этот план в `docs/plans/completed/` после успешного теста через ТСПУ

## Technical Details

### Wire format change

**Было:**
```
[IV 8 bytes] [pad_len 2 bytes LE] [random_pad pad_len bytes] ['b' 1 byte] [payload]
```
Overhead: 11 + 0..128 байт (случайный)

**Станет:**
```
[IV 8 bytes] [marker 1 byte: 'b'|'h'] [payload-or-filler]
```
Overhead: 9 байт (константный)

### Размеры на проводе

Для AWG ICMP ping (~128 байт UDP → 128 байт payload):
- **Data packet:** 128 + 9 (XOR) + 52 (IP+TCP+options) = 189 байт total IP packet. TCP payload = 137 байт. Близко к "~150 байт бакету".
- **Heartbeat:** 1200 + 9 + 52 = 1261 байт. TCP payload = 1209 байт. Близко к udp2raw 1248.

Точное попадание в 192/1248 не критично — главное чтобы **bucket pattern** совпадал (data < 200, hb > 1200, без промежуточных значений).

### Heartbeat flow

```
[tokio::spawn loop]
  interval.tick().await
  if key.is_some():
    buf = random(1200)
    encoded = xor::encode_heartbeat(key, 1200)
    socket.send(&encoded).await
```

Отмена через существующий `CancellationToken` при разрыве соединения.

### Receive filtering

```rust
match xor::decode(key, tcp_payload) {
    Some(DecodedMessage::Data(v)) => udp_sock.send(&v).await,
    Some(DecodedMessage::Heartbeat) => (), // discard silently
    None => (), // decode failed, discard
}
```

### Почему heartbeat только с ключом

Без XOR-ключа получатель не может отличить heartbeat-буфер от UDP-данных — он просто пропишет 1200 байт мусора в бэкенд UDP. Поэтому hb-таск спавнится только при `key.is_some()`.

Это ок: текущий use case (обход ТСПУ через AWG) всегда использует XOR-ключ.

## Post-Completion

**Manual verification:**
- развернуть на relay + nuremberg после коммита
- прогнать `ping -i 1 10.201.0.1 -c 30` через AWG-туннель
- tcpdump на relay: должно быть 30/30 received, packet loss 0%
- verify: все TCP payloads в одном из двух бакетов (~130-140 байт или ~1200-1210 байт), без промежуточных значений
- сравнить паттерн с udp2raw-baseline в `/tmp/phantun-analysis/dumps-*/tcpdump-relay-udp2raw-plain.txt`

**Related future work:**
- delayed ACK (уже в `backlog.md`) — если после этих изменений ТСПУ всё ещё блокирует, приоритет станет выше
- heartbeat jitter (сейчас строго 600ms, как у udp2raw) — если ТСПУ ловит на идеальной периодичности; но udp2raw тоже без jitter'а, так что приоритет низкий
