# Локальный harness для сравнения phantun/udp2raw

## Overview

Создать детерминированную локальную тестовую среду в Docker, которая одной командой:

1. Поднимает клиент-серверную топологию phantun (из текущего HEAD) с UDP-эхо-сервисом позади и iperf3-нагрузчиком впереди.
2. Снимает tcpdump с bridge-стороны phantun-клиента во время прогона.
3. Кладёт результат в `docs/runs/phantun-<timestamp>.txt` и обновляет `docs/runs/manifest.local.json` (локальный, gitignored — коммитится только `manifest.json` с baseline).

Отдельной разовой командой собирается baseline-прогон udp2raw в той же топологии (`docs/runs/baseline-udp2raw.txt`). Визуализатор `docs/packet-compare.html` переделывается с hard-coded `<script id="d-*">` блоков на динамическую загрузку через `fetch('runs/...')` + селектор прогонов. Все прогоны открываются на одной странице через локальный dev-server (`scripts/serve-compare.sh`).

### Проблема, которую решаем

Сейчас чтобы проверить, как изменения в phantun влияют на TCP-fingerprint, нужно вручную задеплоить код на сервер, снять дамп через tcpdump, скопировать его в `packet-compare.html` как inline-блок, и пересобрать HTML. Это медленно, недетерминированно (разные серверы, разная нагрузка), не воспроизводимо.

### Что получаем

- **Воспроизводимость**: одна команда `scripts/capture-run.sh` после каждой правки кода.
- **Сравнимость**: один и тот же сетевой путь, одна и та же нагрузка, один и тот же capture-точка.
- **История**: все прогоны сохраняются, в HTML селектор позволяет переключаться между ними (и между ними и baseline udp2raw).

### Что harness делает и чего НЕ делает

**Делает**: даёт детерминированный regression-сигнал — «изменил код → метрики в HTML изменились / не изменились». Это позволяет локально видеть эффект правок на структуру TCP-потока в фиксированных условиях (iperf3 constant-rate).

**НЕ делает**: не заменяет реальный ТСПУ-тестинг и не воспроизводит **в точности** тот fingerprint-дефект, который мы видели в Nuremberg/Relay дампах. Живые дампы — это WireGuard-паттерн (разрозненные пакеты + heartbeat'ы раз в 600ms), harness — это iperf3 constant stream 625 packets/sec. Frozen ACK и burst под постоянной нагрузкой возникают по частично другим причинам (кумуляция ACK у получателя под нагрузкой). Harness — инструмент **regression-проверки**, не replay реального fingerprint'а. Валидация против ТСПУ остаётся manual step после деплоя.

### Acceptance criteria

- `scripts/capture-baseline.sh` один раз генерирует `docs/runs/baseline-udp2raw.txt` с корректным tcpdump-выводом (парсится существующим JS-парсером в HTML).
- `scripts/capture-run.sh` генерирует `docs/runs/phantun-<ts>-<sha>.txt` и добавляет запись в `manifest.local.json` с `git_sha`, `git_branch`, `created`, `notes`.
- `scripts/serve-compare.sh` запускает `python3 -m http.server -d docs 8000`, пользователь открывает `http://localhost:8000/packet-compare.html` и видит селектор прогонов.
- В HTML выбор прогона из селектора перерисовывает все панели (Stats, Timeline, Histogram, Seq/ACK, Raw Packets) без перезагрузки страницы.
- Baseline udp2raw всегда показан рядом (вторая колонка), не зависит от выбора.
- **Детерминизм**: два подряд идущих прогона одного коммита дают близкие метрики — Max frozen ACK/TSecr/burst отличаются не более чем на ±1, top-sizes совпадают. Если разброс выше — harness недетерминистичен, разбираемся (Docker tаймеры, overhead VM).
- **Чувствительность**: phantun-прогон и baseline-udp2raw на одной и той же нагрузке дают **заметно различающиеся** метрики хотя бы по одному из: Max frozen ACK, Max burst, распределению размеров. Если прогоны идентичны — harness не различает реализации, что-то сломано.

## Context (from discovery)

### Существующая инфраструктура

- `docs/packet-compare.html` — визуализатор со встроенными `<script id="d-nuremberg-phantun">`, `<script id="d-nuremberg-udp2raw-plain">`, `<script id="d-relay-phantun">`, `<script id="d-relay-udp2raw-plain">`. JS-парсер tcpdump-текста, панели Stats/Timeline/Histogram/Seq-ACK/Raw, табы Nuremberg/Relay.
- `Dockerfile.test` + `scripts/run-tests.sh` — существующий паттерн запуска Rust-кода через Docker на macOS (Linux-only зависимости, TUN). Переиспользуем подход для сборки phantun в compare-окружении.
- `docker/` каталог уже есть в репо (деплойные конфиги) — рядом создадим `docker/compare/`.

### Зависимости

- **udp2raw** — Dockerfile собирает из исходников (https://github.com/wangyu-/udp2raw-tunnel), фиксируем коммит-SHA или релиз-тег.
- **iperf3** — один конкретный образ, запиненный по digest или версии (решаем в Task 1).
- **tcpdump** — `alpine:3.19` + `apk add tcpdump`. Post-process (pcap → text) **внутри** контейнера — macOS BSD tcpdump даёт немного другой формат.
- **socat** — `socat -v UDP-LISTEN:5000,fork EXEC:cat` в команде одной строки в compose.
- Python 3 — уже есть на macOS/Linux, нужен для `-m http.server` и однострочного `python3 -c "import json; ..."` в bash для обновления manifest.

### Технические ограничения

- macOS: Docker работает внутри Linux VM. Bridge-интерфейсы доступны только из контейнеров. Решение — tcpdump как sidecar-контейнер с `--network=container:phantun-client`, снимающий eth0 целевого контейнера (это bridge-сторона с точки зрения сети).
- phantun требует `CAP_NET_ADMIN` для создания TUN — фиксируем в compose.
- iperf3 через UDP имеет свой control-канал TCP/5201, который не должен попадать в capture — ограничиваем tcpdump фильтром по портам/хостам phantun.

## Development Approach

- **Testing approach**: Regular (сначала код, потом верификация). Основные артефакты — shell-скрипты, Docker и HTML/JS, где TDD неприменим. Главный тест — end-to-end smoke-прогон, визуальная проверка HTML.
- Каждая задача заканчивается рабочим состоянием (не оставляем HTML в полу-рефакторенном виде).
- После каждой задачи — прогон соответствующего смоука (см. Testing Strategy).
- Существующие inline-дампы в `packet-compare.html` **удаляем** в Task 4 (когда fetch-based загрузка готова). До этого момента HTML остаётся рабочим.
- Обновляем этот файл плана при отклонении от плана (`➕` для новых задач, `⚠️` для блокеров).

## Testing Strategy

Здесь нет unit-тестов в привычном смысле — основной инструмент верификации это **end-to-end smoke runs**:

- **Task 1 smoke**: `docker compose -f docker/compare/docker-compose.phantun.yml up` поднимается, iperf3 проходит, UDP-echo отвечает, никто не падает.
- **Task 2 smoke**: `scripts/capture-run.sh --notes "initial"` отрабатывает до конца, в `docs/runs/` появляется файл, `manifest.local.json` обновлён.
- **Task 3 smoke**: `scripts/capture-baseline.sh` отрабатывает, `docs/runs/baseline-udp2raw.txt` валиден (парсится существующим JS-парсером).
- **Task 4 smoke**: `scripts/serve-compare.sh` → открываем `http://localhost:8000/packet-compare.html` → селектор прогонов виден, все панели рисуются.
- **Task 5 smoke**: выбор разных прогонов в селекторе перерисовывает панели, сравнение с baseline показывает ожидаемые fingerprint-различия (frozen ACK > 0, burst > 1 для phantun — подтверждение, что harness воспроизводит проблему).

Unit-тесты для JS-парсера tcpdump и manifest-валидатор считаем over-engineering для internal tooling — не пишем, если не всплывёт необходимость.

## Progress Tracking

- Отмечаем завершённые пункты `[x]` сразу по факту.
- Новые задачи, всплывшие в ходе работы — с префиксом `➕`.
- Блокеры — с префиксом `⚠️`.

## What Goes Where

- **Implementation Steps**: всё что в репо (Docker-файлы, compose, shell-скрипты, правки HTML/JS, документация).
- **Post-Completion**: первый ручной baseline-прогон udp2raw, ручной smoke-просмотр HTML, фиксация версии udp2raw.

## Implementation Steps

### Task 1: Docker-топология phantun (клиент/сервер/echo/generator/capture)

**Files:**
- Create: `docker/compare/Dockerfile.phantun`
- Create: `docker/compare/Dockerfile.capturer` (alpine + tcpdump preinstalled — чтобы `apk add` был на этапе build, а не run)
- Create: `docker/compare/docker-compose.phantun.yml`
- Modify: `.gitignore` (добавить patterns заранее, до первого smoke)

- [x] Обновить `.gitignore` **первым делом** (до любого smoke):
  - `docker/compare/captures/` — промежуточные .pcap + .txt
  - `docs/runs/phantun-*.txt` — локальные прогоны
  - `docs/runs/manifest.local.json`
- [x] Зафиксировать значения как inline-дефолты в compose (`${VAR:-default}`):
  - `PHANTUN_TCP_PORT=4567` — fake-TCP client→server (capture filter = только этот порт)
  - `PHANTUN_LOCAL_UDP=4500` — UDP-listen phantun-client (вход от generator)
  - `IPERF_PORT=5201` — iperf3
  - `UDP_ECHO_PORT=5000` — echo-backend
  - `PHANTUN_KEY=compare-harness-local` — фиксированный ключ, одинаковый в обеих compose
  - `BRIDGE_SUBNET=100.64.240.0/24` — CGNAT-диапазон, не конфликтует с VPN/корп-сетями
- [x] `Dockerfile.phantun`: multi-stage — `rust:slim` build stage → `debian:slim` runtime. Бинари `phantun-client`, `phantun-server` в /usr/local/bin. Без cache mount — первая сборка ~2-3 минуты, терпимо для локального harness.
- [x] `Dockerfile.capturer`: 3 строки — `FROM alpine:3.19` + `RUN apk add --no-cache tcpdump` + `ENTRYPOINT ["/bin/sh"]`. Tcpdump в образе заранее — иначе `sleep 3` в generator не гарантирует, что capturer успеет открыть packet-сокет (apk скачивает из зеркал на старте контейнера, на холодном первом прогоне это дольше 3 секунд).
- [x] `docker-compose.phantun.yml`: сервисы:
  - `udp-echo` — `alpine:3.19` + однострочник socat в `command:`
  - `phantun-server`, `phantun-client` — `cap_add: [NET_ADMIN]`, `devices: ["/dev/net/tun:/dev/net/tun"]`, фиксированные IP в custom bridge `phantun-compare` (subnet через `${BRIDGE_SUBNET:-...}`)
  - `generator` — запиненный iperf3-образ. Команда: `sh -c "sleep 3 && iperf3 -c phantun-client -u -b 1M -l 200 -t 30"`. Sleep 3s — единственный sync-механизм с capturer'ом (у phantun userspace TCP, kernel-healthcheck не работает). Exit code обёрнут в `|| true` в `capture-run.sh` — iperf3 может вернуть non-zero при packet loss.
  - `capturer` — **собирается из `Dockerfile.capturer`** (tcpdump preinstalled), `network_mode: "container:phantun-client"`, `cap_add: [NET_ADMIN, NET_RAW]`, `stop_grace_period: 8s`, `depends_on: { phantun-client: { condition: service_started } }`. Фильтр `tcp and port ${PHANTUN_TCP_PORT}`, snaplen `-s 0`, флаг `-U` (packet-buffered). Trap на SIGTERM/SIGINT: корректный kill+wait pcap-писателя, затем `tcpdump -r ... -nn -tt -S -e -v > /captures/phantun.txt` (**важно**: `-e -v` обязательны — JS-парсер в `docs/packet-compare.html:1138` ожидает two-line формат с Ethernet-заголовком и IP `id`, без них HTML почти ничего не распарсит). См. Technical Details для точного snippet'а.
- [x] Ручной smoke: `docker compose -f docker/compare/docker-compose.phantun.yml up --abort-on-container-exit --exit-code-from generator || true` — все поднялись, generator отстрелялся, capturer записал `captures/phantun.txt` ненулевого размера с осмысленным tcpdump-выводом (хотя бы 500 строк для 30-секундного 1Mbit/s прогона). (skipped — Docker daemon not available on dev host; `docker compose -f docker/compare/docker-compose.phantun.yml config` validates the file structure. Defer live smoke to Task 6 / first use on a Docker-enabled host.)
- [x] Никаких unit-тестов — это инфраструктура.

### Task 2: Docker-топология udp2raw (идентичная по структуре)

**Files:**
- Create: `docker/compare/Dockerfile.udp2raw`
- Create: `docker/compare/docker-compose.udp2raw.yml`

- [ ] `Dockerfile.udp2raw`: сборка udp2raw из upstream (зафиксировать коммит-SHA или релиз-тег). Multi-stage в минимальный runtime.
- [ ] `docker-compose.udp2raw.yml`: те же сервисы `udp-echo`, `generator`, `capturer` (идентичная конфигурация), но `udp2raw-server` и `udp2raw-client` вместо phantun. Тот же bridge, те же IP-адреса, тот же XOR-ключ, те же UDP-порты.
- [ ] Ручной smoke: `docker compose -f docker/compare/docker-compose.udp2raw.yml up --abort-on-container-exit` — iperf3 через udp2raw проходит, пакеты в `captures/` есть.
- [ ] Визуально сравнить размер/количество пакетов в capture с phantun-прогоном — должны быть сравнимы по объёму (разница в fingerprint-параметрах нормальна).

### Task 3: Скрипты capture + serve

**Files:**
- Create: `scripts/capture-run.sh`
- Create: `scripts/capture-baseline.sh`
- Create: `scripts/serve-compare.sh`

- [ ] `capture-run.sh [--notes "..."]`:
  - `trap 'docker compose -f ... down -v' EXIT INT TERM` в начале — cleanup при Ctrl+C.
  - `docker compose -f docker/compare/docker-compose.phantun.yml up --build --abort-on-container-exit --exit-code-from generator || true` (не падаем на non-zero iperf3).
  - Копировать `captures/phantun.txt` → `docs/runs/phantun-<ts>-<sha>.txt`. Timestamp с секундами + короткий git-SHA. Если файл уже есть — суффикс `-2`, `-3`, ... до свободного имени.
  - Sanity check: файл не пуст и содержит хотя бы одну tcpdump-строку (`grep -q 'IP '`).
  - Обновить `docs/runs/manifest.local.json` inline через `python3 -c`:
    ```bash
    python3 -c "import json, os; p='docs/runs/manifest.local.json'; m=json.load(open(p)) if os.path.exists(p) else {'runs':[]}; m['runs'].append({...}); json.dump(m, open(p,'w'), indent=2)"
    ```
    Pretty-print через `indent=2`. Без flock — параллельный запуск скрипта на одной машине редок; docker compose сам сериализует по project name.
  - Очистить `captures/*` после копирования.
- [ ] `capture-baseline.sh [--force]`:
  - Тот же trap/cleanup.
  - Через `docker-compose.udp2raw.yml` → `docs/runs/baseline-udp2raw.txt`.
  - Обновляет `manifest.json` (не `.local.json`) в поле `baseline` аналогичным inline-python.
  - Если baseline уже существует: prompt `"baseline будет перезаписан, продолжить? (y/N)"`. В non-TTY (`[ ! -t 0 ]`) — выход с ошибкой, если не `--force`.
- [ ] `serve-compare.sh`: `cd docs && exec python3 -m http.server 8000`, печатает `open http://localhost:8000/packet-compare.html`.
- [ ] Все скрипты: `set -euo pipefail`, `chmod +x`, проверка зависимостей (`command -v docker`, `command -v python3`) в начале.
- [ ] Smoke: `scripts/capture-run.sh --notes "smoke"` → файл создан, `manifest.local.json` валиден (`python3 -m json.tool < docs/runs/manifest.local.json`).

### Task 4: Рефактор packet-compare.html на fetch-based загрузку

**Files:**
- Modify: `docs/packet-compare.html`
- Create: `docs/runs/.gitkeep`

- [ ] Удалить все `<script id="d-*" type="text/plain">` блоки (4 штуки). Старые табы Nuremberg/Relay тоже убрать — они заменяются селектором прогонов.
- [ ] При загрузке проверить `location.protocol === 'file:'` → показать баннер-предупреждение: «Откройте через `scripts/serve-compare.sh` → http://localhost:8000/packet-compare.html — file:// не работает из-за CORS.» и остановить дальнейшую инициализацию.
- [ ] Добавить UI: dropdown «Phantun run» (список прогонов, свежие сверху). Baseline показать как **статический label** (не dropdown — он всегда один): «Baseline: udp2raw, captured <date>».
- [ ] JS: при загрузке страницы `fetch('runs/manifest.json')` + опционально `fetch('runs/manifest.local.json')` (может отсутствовать — это норма, в репо его не коммитят). Объединить списки runs. При выборе прогона — `fetch('runs/<file>')`, текст прогоняется через существующий парсер tcpdump, результат рендерится в панели.
- [ ] Колонки страницы: левая — выбранный phantun-прогон, правая — baseline udp2raw (постоянно). Переименовать id'шки с `-left/-right` на `-selected/-baseline` (гигиенично, уменьшает путаницу при будущих правках).
- [ ] Добавить метаданные прогона под селектором: `git_sha`, `git_branch`, `created`, `notes`.
- [ ] Обработать случай пустого `manifest.json` (нет runs и нет baseline): показать плейсхолдер «Нет прогонов. Запустите scripts/capture-baseline.sh и scripts/capture-run.sh».
- [ ] Smoke: `scripts/serve-compare.sh`, открыть в браузере, проверить что прогон рендерится, что переключение работает без перезагрузки страницы, что все панели (Stats, Timeline, Histogram, Seq/ACK, Raw Packets) отрисованы корректно.
- [ ] Smoke file://: открыть HTML двойным кликом — убедиться, что виден баннер с инструкцией, а не пустая страница.

### Task 5: Первый baseline-прогон udp2raw + документация

**Files:**
- Create: `docs/runs/baseline-udp2raw.txt` (артефакт — коммитим)
- Create: `docs/runs/manifest.json` (коммитим начальную версию — только `baseline`)
- Modify: `README.md` (раздел «Local compare harness»)
- Modify: `CLAUDE.md` (раздел про harness)
(`.gitignore` уже обновлён в Task 1)

- [ ] Запустить `scripts/capture-baseline.sh`, закоммитить `baseline-udp2raw.txt` и `manifest.json` (только с `baseline`, без `runs`).
- [ ] Запустить `scripts/capture-run.sh --notes "initial harness validation"` для smoke-проверки, **не коммитить** получившийся phantun-прогон (локальный).
- [ ] Проверить в HTML:
  - **Детерминизм**: два подряд `capture-run.sh --notes "det-1"` и `--notes "det-2"` без правок кода дают близкие Max frozen ACK/TSecr/burst (разброс ±1). Если разброс больше — разбираемся до Task 6.
  - **Чувствительность**: сравнение phantun-прогона с baseline-udp2raw показывает видимые различия хотя бы в одной метрике (frozen ACK, burst, или гистограмма размеров). Цифры пока **не** фиксируем — первый прогон устанавливает baseline наблюдений, записываем их в `README.md` как reference.
  - Если прогоны идентичны udp2raw или случайны между собой — harness не работает, останавливаемся.
- [ ] `README.md`: новый раздел «Local compare harness» — 3-4 абзаца: как собирать, как запускать, как смотреть. Упомянуть что baseline одноразовый. **Не дублировать** версию udp2raw в тексте — ссылаться на `docs/runs/manifest.json` как источник истины.
- [ ] `CLAUDE.md`: короткая ссылка на harness в разделе «Testing» и одна строчка гоча: «baseline-udp2raw.txt pinned; regenerate via `capture-baseline.sh --force` only if comparison design changes (invalidates all phantun runs too)».
- [ ] Проверить что `.gitignore` (обновлённый в Task 1) действительно исключает все временные артефакты: `git status` после прогона не показывает ничего из `docker/compare/captures/`, `docs/runs/phantun-*.txt`, `manifest.local.json`.

### Task 6: Verify acceptance + cleanup

- [ ] Прогнать все acceptance criteria из Overview вручную.
- [ ] Убедиться что все chmod +x стоят на скриптах.
- [ ] Убедиться что `docker compose down -v` отрабатывает чисто (не остаётся висящих контейнеров/томов после прогона).
- [ ] Запустить полные тесты проекта (`./scripts/run-tests.sh`) — harness не должен ломать существующие тесты.
- [ ] Переместить план в `docs/plans/completed/`.

## Technical Details

### Структура каталогов (итоговая)

```
docker/compare/
  Dockerfile.phantun
  Dockerfile.udp2raw
  docker-compose.phantun.yml
  docker-compose.udp2raw.yml
  captures/                    (gitignored, промежуточные .pcap + .txt)

scripts/
  capture-baseline.sh
  capture-run.sh
  serve-compare.sh

docs/
  packet-compare.html          (рефакторенный)
  runs/
    .gitkeep
    baseline-udp2raw.txt       (коммитим)
    manifest.json              (коммитим: только baseline, без runs)
    phantun-*.txt              (gitignored)
    manifest.local.json        (gitignored — записи локальных phantun-прогонов)
```

Все значения (порты, ключ, subnet) — inline-дефолты в compose через `${VAR:-default}`. Нет отдельного `.env.example` / `.env` — минус один уровень косвенности.

### Таблица портов и capture filter

| Назначение | Порт | Протокол | Где используется |
|---|---|---|---|
| `PHANTUN_TCP_PORT` | 4567 | TCP | fake-TCP phantun-client → phantun-server. **Единственный порт в capture filter.** |
| `PHANTUN_LOCAL_UDP` | 4500 | UDP | phantun-client слушает generator локально |
| `IPERF_PORT` | 5201 | UDP+TCP | iperf3 data (UDP) + control (TCP). TCP-control на 5201 НЕ попадает в capture (фильтр `port 4567`). |
| `UDP_ECHO_PORT` | 5000 | UDP | echo-backend за phantun-server |

Capture filter (tcpdump): `tcp and port ${PHANTUN_TCP_PORT}`, snaplen `-s 0`.

### Формат manifest.json (коммитим, только baseline)

```json
{
  "baseline": {
    "file": "baseline-udp2raw.txt",
    "created": "2026-04-16T14:55:12Z",
    "tool_version": "udp2raw-mp v20200818.0",
    "generator": "iperf3 -u -b 1M -l 200 -t 30",
    "capture_point": "phantun-client eth0 (bridge side)",
    "capture_filter": "tcp and port 4567"
  }
}
```

### Формат manifest.local.json (gitignored, локальные phantun-прогоны)

```json
{
  "runs": [
    {
      "file": "phantun-20260416T145512Z-acd8f98.txt",
      "created": "2026-04-16T14:55:12Z",
      "git_sha": "acd8f98",
      "git_branch": "mimic-clean",
      "notes": "before frozen ACK fix"
    }
  ]
}
```

HTML при загрузке мёрджит оба: baseline из `manifest.json`, runs — из `manifest.local.json` (опционально, может отсутствовать). Это решает проблему «коммитить или нет phantun-прогоны» — коммитим только baseline, локальная история остаётся локальной.

### Docker-compose: capture через sidecar

Ключевой паттерн — sidecar делит network namespace с phantun-client, видит его eth0 целиком (это bridge-сторона), фильтрует только phantun-TCP. На macOS работает одинаково (всё внутри Docker VM, хостовый tcpdump не требуется).

```yaml
capturer:
  build:
    context: .
    dockerfile: Dockerfile.capturer
  stop_grace_period: 8s
  command:
    - -c
    - |
      tcpdump -i eth0 -s 0 -U -w /captures/phantun.pcap "tcp and port ${PHANTUN_TCP_PORT}" &
      PID=$!
      trap 'kill -TERM $PID 2>/dev/null; wait $PID 2>/dev/null; tcpdump -r /captures/phantun.pcap -nn -tt -S -e -v > /captures/phantun.txt; exit 0' TERM INT
      wait $PID
  network_mode: "container:phantun-client"
  cap_add: [NET_ADMIN, NET_RAW]
  volumes: ["./captures:/captures"]
  depends_on:
    phantun-client: { condition: service_started }
```

`Dockerfile.capturer` — 3 строки: `FROM alpine:3.19`, `RUN apk add --no-cache tcpdump`, `ENTRYPOINT ["/bin/sh"]`. Apk переносится в build-time: иначе на холодном первом запуске `apk add` в entrypoint может занять дольше, чем `sleep 3` в generator'е, и capturer пропустит начало прогона.

Ключевые моменты:
- `-U` заставляет tcpdump сбрасывать буфер после каждого пакета — иначе последние пакеты теряются при SIGTERM.
- `kill -TERM $PID && wait $PID` перед `tcpdump -r` — гарантирует, что pcap-файл закрыт до чтения.
- `stop_grace_period: 8s` — даёт trap'у время на post-process; иначе docker compose через 10s default пошлёт SIGKILL и сломает текстовый output.
- `depends_on: condition: service_started` (не `service_healthy`) — phantun-client использует userspace TCP stack, kernel healthcheck через `nc -z` не работает.

Post-process (pcap → text) выполняется **внутри** того же контейнера, чтобы формат был детерминированным (Linux tcpdump, не BSD tcpdump хоста).

### Фиксированные параметры прогона

- `PHANTUN_KEY=compare-harness-local` (одинаковый в обеих compose, inline-дефолт)
- iperf3: `-u -b 1M -l 200 -t 30` (UDP, 1Мбит/с, 200-байтовый payload, 30 секунд). Запиненный образ/версия.
- Capture filter: `tcp and port ${PHANTUN_TCP_PORT:-4567}`
- Bridge subnet: `100.64.240.0/24` (CGNAT)

### Синхронизация и cleanup

- **Capturer vs generator**: у phantun userspace TCP-стэк, kernel-healthcheck невозможен. Порядок: docker compose стартует phantun-server/client/capturer через `depends_on: service_started`, затем generator с `sleep 3` в первой строке команды — это даёт tcpdump внутри capturer время открыть сокет. Порядок старта: phantun-server → phantun-client → capturer → generator.
- **Capturer teardown**: tcpdump с флагом `-U` (flush после каждого пакета), trap на SIGTERM → `kill -TERM` писателя + `wait` + `tcpdump -r ... -nn -tt -S > .txt`, `stop_grace_period: 8s` даёт trap'у успеть до SIGKILL. Без этого последние пакеты теряются и выхлопной `.txt` обрезан.
- **Ctrl+C в скриптах**: `trap '...down -v' EXIT INT TERM` в начале → контейнеры и volumes снимаются гарантированно, на следующий запуск не остаётся мусора.
- **Timestamp-коллизии**: имя файла = `phantun-<ts>-<sha>.txt`. Если совпало (два прогона одной секунды одного коммита) — скрипт добавляет `-2`, `-3`, ... суффикс.

### Парсер tcpdump в HTML

Формат вывода `tcpdump -nn -tt -S` — two-line per packet, уже поддерживается существующим JS-парсером. Менять парсер не нужно, только **источник данных** — с `<script id>` на `fetch()`.

## Post-Completion

**Ручная верификация:**
- После первого полного прохода harness'а: визуально проверить, что fingerprint-метрики (Max frozen ACK, Max burst, Max frozen TSecr) соответствуют тому, что мы видели в реальных Nuremberg/Relay дампах. Если нет — разбираться почему (тайминги Docker, отсутствующая нагрузка, артефакт локальной сети).
- Проверить что harness показывает **одинаковую** картину для двух подряд идущих прогонов (детерминизм).

**Внешние системы:**
- Никаких изменений в потребителях — harness локальный, не влияет на деплой и пользователей phantun.
- После каждой существенной правки phantun-кода — прогнать `scripts/capture-run.sh`, положить прогон рядом с предыдущими, сравнить визуально в HTML.
