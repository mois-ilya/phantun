---
name: Phantun fork plan
description: Analysis of Phantun vs udp2raw fake TCP — why ТСПУ blocks Phantun, what to fix in a fork
type: project
---

# Phantun fork: контекст и план улучшений

## Зачем

udp2raw — единственный работающий транспорт AWG через ТСПУ, но он однопоточный и упирается в **~75 Mbps** (замерено 2026-04-03). SSH между серверами даёт 285 Mbps — udp2raw является узким местом. Phantun (Rust, многопоточный) даёт 2.38 Gbps на 4 vCPU в бенчмарках автора, но **не проходит через ТСПУ** из-за нереалистичного fake TCP.

## Что было сделано (2026-04-03)

1. Упакован Phantun v0.8.1 в Nix (`packages/phantun.nix`, pre-built musl binaries)
2. Развёрнут параллельно с udp2raw (nuremberg:4445 + ru-relay:444)
3. Fake TCP handshake (SYN/SYN-ACK) проходит успешно
4. Data-пакеты уходят с ru-relay (MASQUERADE работает, 7 пакетов в счётчике), но **не доходят до nuremberg**
5. Сервисы отключены (`wantedBy` закомментирован), код остаётся в конфиге

## Корневая причина: TCP fingerprint

Анализ исходников обоих проектов (fake-tcp/src/packet.rs у Phantun, network/net_util.cpp у udp2raw):

### Phantun — минималистичный fake TCP

| Параметр | Значение | Проблема |
|----------|----------|----------|
| SYN options | NOP + Window Scale (wscale=14) | **Нет MSS** (RFC 879 дефолт 536, но шлёт 1400+ payload) |
| Data options | **Нет** (doff=5, заголовок 20 байт) | Любой stateful DPI видит аномалию |
| Timestamps | **Отсутствуют везде** | Современные стеки всегда используют timestamps |
| Window size | Статичный 0xFFFF (65535) | Никогда не меняется — fingerprint туннеля |
| ACK поведение | Обновляется после ~128 МБ | seq уходит далеко вперёд от ack — невозможно в реальном TCP |
| Флаги на data | Только ACK | Нет PSH — нетипично для интерактивного трафика |

### udp2raw (--raw-mode faketcp) — реалистичная симуляция

| Параметр | Значение |
|----------|----------|
| SYN options | MSS=1460, SACK OK, Timestamps, Window Scale=5 (doff=10, 40 байт) |
| Data options | NOP + Timestamps (doff=8, 32 байта) |
| Timestamps | На всех пакетах, инкрементируются |
| Window size | Рандомизированный в диапазоне |
| ACK поведение | seq_mode=3: полная симуляция TCP-окна, fast retransmit при 3 duplicate ACK |
| Флаги на data | ACK + PSH |

### Что именно детектирует ТСПУ (гипотеза по приоритету)

1. **Отсутствие TCP timestamps на data** — после SYN с wscale это аномалия, легко ловится
2. **Статичный window + редкий ACK** — seq/ack divergence невозможна в реальном TCP
3. **Нет MSS в SYN** — нарушение RFC, fingerprint
4. **doff=5 на data** — 20-байтовый заголовок без options после SYN с options

## Что нужно добавить в форк Phantun

### Критично (без этого ТСПУ блокирует)

1. **TCP Timestamps** на всех пакетах (NOP + NOP + Timestamps, 12 байт)
   - `fake-tcp/src/packet.rs` → добавить в `build_tcp_packet()` для data
   - Инкрементировать tsval монотонно (~1ms), tsecr = последний полученный tsval
   - Overhead: +12 байт на пакет (doff=5→8, 20→32 байта)

2. **MSS в SYN** (MSS=1460)
   - Добавить в `build_syn_packet()` — 4 байта опции
   - Без этого промежуточные stateful firewall могут дропать

3. **SACK Permitted в SYN**
   - Стандартная опция, 2 байта + 2 padding

### Важно (повышает стелс)

4. **Динамический window size**
   - Не статичный 0xFFFF, а варьировать в диапазоне (напр. 32K-64K)
   - Уменьшать при быстрой отправке, увеличивать при паузах

5. **Частый ACK update**
   - Текущий порог ~128 МБ слишком большой
   - ACK должен расти пропорционально полученным данным (как в реальном TCP)

6. **PSH флаг на data-пакетах**
   - Добавить `PSH | ACK` вместо голого `ACK`

### Опционально (для полной совместимости)

7. **Window Scale в SYN** выровнять до стандартных значений (5-7, не 14)
8. **Имитация congestion control** (slow start → congestion avoidance)
9. **Handshake packet** с TLS Client Hello для мимикрии под HTTPS

## Архитектура форка

Phantun написан на Rust, структура:
```
fake-tcp/src/
  packet.rs    — конструкция TCP-пакетов (главный файл для изменений)
  lib.rs       — fake TCP state machine
phantun/src/
  client.rs    — клиентская логика
  server.rs    — серверная логика
```

Ключевое преимущество Phantun над udp2raw — **многопоточность** через multi-queue TUN (`num_cpus` очередей). Это сохраняется при добавлении TCP options.

## Ожидаемый результат

С добавлением timestamps + MSS + dynamic window + frequent ACK, форк должен:
- Проходить ТСПУ (пакеты будут неотличимы от реального TCP для stateful DPI)
- Сохранять многопоточность (2-3x быстрее udp2raw)
- Давать ~150-200 Mbps на ru-relay (2 vCPU) vs 75 Mbps у udp2raw
- Overhead: ~32 байта заголовок (vs 20 сейчас, vs 44 у udp2raw)

## Замеры (2026-04-03)

| Тест | Результат |
|------|-----------|
| SSH между серверами (TCP, encrypted) | 285 Mbps |
| udp2raw throughput (fake TCP, работает) | 75 Mbps |
| Phantun throughput (fake TCP, заблокирован) | ~0 Mbps (data пакеты дропаются) |
| Phantun handshake | Проходит (SYN/SYN-ACK OK) |
| ru-relay download Yandex (внутри РФ) | 483 Mbps |
| ru-relay NIC link | 2000 Mbps (виртуальный Hyper-V) |
