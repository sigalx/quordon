# Беклог Quordon

Этот документ фиксирует возможные следующие шаги после текущего MVP. Пункты
ниже не являются частью исполняемого API, пока соответствующий endpoint или
расширение не добавлены одновременно в OpenAPI, runtime, policy model,
документацию и contract tests.

Приоритет определяется практической пользой для локальных программных агентов,
которым нужно исследовать состояние продуктовой БД: находить данные, считать их,
сравнивать срезы и анализировать динамику. Пользователи и операторы сервиса
считаются доверенными, агенты — недоверенными. Все новые операции сохраняют
принцип: строгая валидация и policy authorization предшествуют любому обращению
к DBMS.

## Актуальный порядок работ

1. **P1 — `numeric_bucket`.** Добавляет новую аналитическую возможность для
   распределений по заранее заданным диапазонам, которой нельзя добиться
   текущими dimensions без выгрузки строк.
2. **P2 — эксплуатационная упаковка.** Пакеты, systemd/daemon mode, release
   artifacts и reference ingress нужны до регулярного развёртывания, но не
   меняют прикладной API и могут развиваться отдельным треком.
3. **P3 — специализированные `null_count` и `fill_rate`.** Это удобные сокращения,
   но те же значения уже выводятся из разрешённых `count_all` и `count(field)`,
   поэтому отдельные функции не блокируют повседневный анализ.

Заранее разрешённые enum-like distributions уже выражаются существующим
grouped aggregate с обычной dimension и `count_all`; новая runtime-операция для
них не требуется. Нужные распределения добавляются оператором как query shapes
и публикуются через discovery.

## Реализованные возможности

### Discovery разрешённых aggregate shapes

Статус: реализовано в runtime и исполняемом OpenAPI-модуле
[`openapi/query-shapes.yaml`](../openapi/query-shapes.yaml).

API:

```text
GET /query-shapes?profile={profile}
```

Endpoint позволяет агенту узнать, какие запросы к
`POST /queries/aggregate` он вправе построить, не читая серверный policy-файл и
не получая внутренние детали DBMS admission policy.

Ответ для каждого доступного shape содержит:

- публичное имя и человекочитаемое описание;
- режим `scalar` или `grouped`;
- разрешённый source;
- ordered projection с dimension/measure kind и aggregate function; фактический
  portable type возвращается только при выполнении aggregate;
- структуру filter с placeholder types и arity, но без значений;
- разрешённый `order_by`;
- максимальный grouped `limit`;
- порядок ожидаемых result columns через projection.

Нельзя возвращать `required_index`, SQL, DSN, plan-estimate bounds, credentials и
другие execution-only параметры. Core-owned capability `list_query_shapes`
выдаётся только для назначенных principal профилей и не раскрывает shapes
недоступных профилей.

Выполненные критерии:

- агент может построить OpenAPI-valid aggregate request только по discovery
  response;
- response использует закрытые типы и не содержит bind values или внутренних
  policy controls;
- policy deny и неизвестный profile не вызывают обращения к datasource;
- OpenAPI и runtime fixtures проверяют positive/negative response в обе стороны.

### Временные интервалы в aggregate

Статус: реализовано в runtime и исполняемых OpenAPI-модулях
[`openapi/aggregate.yaml`](../openapi/aggregate.yaml) и
[`openapi/query-shapes.yaml`](../openapi/query-shapes.yaml).

Policy-curated dimension для временной группировки имеет форму:

```json
{
  "kind": "time_bucket",
  "field": "created_at",
  "unit": "day",
  "timezone": "UTC",
  "alias": "day"
}
```

Поддерживаемые сценарии:

- количество регистраций или заказов по дням;
- динамика ошибок по часам;
- активность по неделям или месяцам;
- сравнение временных периодов без передачи строк агенту.

Реализованные ограничения:

- закрытый enum единиц времени: `hour`, `day`, `week`, `month`;
- field, unit, timezone и alias входят в полный aggregate policy shape;
- никаких пользовательских format strings, SQL functions или expressions;
- server генерирует выражение самостоятельно и проверяет совместимый temporal
  source type до выполнения;
- текущая версия поддерживает только `UTC`, поэтому не зависит от DST и наличия
  MySQL timezone tables;
- generated expression, projection, grouping и ordering должны проходить ту же
  preflight/admission проверку, что остальные aggregate shapes;
- discovery использует отдельную negotiated representation и не публикует
  time-bucket shape клиенту, который её не запросил;
- несовместимый temporal source и некорректные сгенерированные bucket values
  завершаются документированной ошибкой без смешивания с настоящим `NULL`.

### Runtime-статистика таблиц и партиций

Статус: реализовано в runtime и исполняемом OpenAPI-модуле
[`openapi/table-statistics.yaml`](../openapi/table-statistics.yaml).

API:

```text
GET /schemas/{schema}/objects/{object}/statistics?profile={profile}
```

Ответ включает:

- storage engine;
- приблизительное количество строк;
- `data_length` и `index_length`;
- текущее значение `auto_increment`, если применимо;
- gateway `observed_at` после завершённого чтения metadata;
- список партиций/субпартиций и portable method без partition expression;
- приблизительное количество строк и объём каждой партиции.

Требования безопасности и контракта:

- отдельная capability и отдельный operation-bound authorization token;
- только уже разрешённый physical base table, без views;
- policy-denied objects не читаются; отдельной per-partition policy в MVP нет;
- metadata lookup выполняется после полной проверки coordinates и capability;
- approximate значения имеют явный признак `estimated`; они не выдаются за
  точный `COUNT(*)`;
- unavailable metadata возвращает `null` либо закрытый status enum согласно
  OpenAPI, а не неявный zero value;
- точный подсчёт строк остаётся задачей curated aggregate shape;
- response budget проверяется до материализации больших metadata strings;
- поддерживаются только физические InnoDB tables; view, MyISAM, denied и
  отсутствующий object неразличимы и дают `404`;
- ответ полный или `413`: частичный список партиций не выдаётся.

### Keyset pagination для SELECT

Статус: реализовано в runtime и исполняемых OpenAPI-модулях
[`openapi/openapi.yaml`](../openapi/openapi.yaml),
[`openapi/keyset-pagination.yaml`](../openapi/keyset-pagination.yaml) и
[`openapi/query-shapes.yaml`](../openapi/query-shapes.yaml).

Добавить безопасное продолжение выборки без больших `OFFSET`. Спроектированная
форма продолжения:

```json
{
  "kind": "keyset",
  "profile": "reader",
  "shape": "employees_by_id",
  "query": {
    "source": {"schema": "application", "name": "employees"},
    "projection": [{"kind": "field", "field": "id"}],
    "order_by": [{"field": "id", "direction": "asc"}],
    "limit": 100
  },
  "page": {
    "kind": "after",
    "cursor": [
      {"type": "integer", "value": "1500"}
    ]
  }
}
```

Операция полезна для последовательного чтения больших разрешённых наборов и не
должна превращаться в произвольное управление индексом.

Ограничения:

- операция `select_keyset` выдаётся отдельно от обычного `select`;
- policy фиксирует named query shape, ordered unique key или уникальный
  составной key, projection, filter structure и maximum limit;
- количество и типы cursor values точно совпадают с key fields;
- client не передаёт имя индекса или SQL direction вне разрешённого shape;
- `limit` остаётся ограниченным effective `max_rows`;
- выбранный клиентом `limit` не входит в signature policy shape, но после
  проверки maximum/effective bounds отдельно и неизменяемо закрепляется в
  operation-bound token; adapter получает из token точный `LIMIT limit + 1`;
- cursor members проходят strict JSON/OpenAPI validation без преобразования
  строк и чисел; token scan до `encoding/json` отклоняет invalid UTF-8 и
  непарные UTF-16 surrogate escapes;
- cursor key разрешён только для целочисленных MySQL types, `CHAR`/`VARCHAR` с
  точным `utf8mb4` round-trip и `BINARY`/`VARBINARY`; `ENUM`/`SET`, text/blob,
  temporal, decimal, floating-point, `BIT`, JSON и spatial keys отклоняются до
  выполнения SELECT, поскольку их порядок или представление нельзя безопасно
  воспроизвести текущим cursor-контрактом;
- после чтения pinned metadata, но до `EXPLAIN`/`SELECT`, сервер консервативно
  проверяет, что канонический следующий запрос с максимально возможным cursor
  для этих key columns помещается в effective `max_request_bytes`; иначе запрос
  завершается `413 REQUEST_TOO_LARGE`, не обещая непригодный `next_cursor`;
- projection отклоняет MySQL `FLOAT`, `DOUBLE` и `REAL` до SELECT: закрытый
  portable-тип `decimal` предназначен только для точного fixed-point
  `DECIMAL`/`NUMERIC`, а отдельное приблизительное представление в MVP не
  вводится;
- discovery-схема выражает статические filter rules непосредственно в OpenAPI:
  `like` допускает только один `string`/`bytes` placeholder, а `in`/`not_in` —
  только непустой однородный список одного portable-типа;
- compiler использует только bind parameters и server-owned quoted identifiers;
- response возвращает закрытый тип `next_cursor` и однозначный `has_more`, не
  раскрывая имя индекса или иные execution-only параметры;
- расширение `POST /queries/select` моделируется непересекающимся `oneOf`:
  существующие `{profile, query}` request/response остаются валидными, а новая
  ветка однозначно выбирается обязательным `kind: keyset`;
- handler сохраняет выбранную request-ветку в типизированном dispatch:
  legacy request может вернуть только `SelectResult`, keyset request — только
  `KeysetSelectResult`; перекрёстная пара становится `500 INTERNAL_ERROR` до
  записи ошибочного HTTP 200 и покрывается semantic contract fixture;
- query-shape discovery добавляет v3 как явный opt-in, сохраняя допустимыми
  прежние отсутствующий `Accept`, `*/*`, `application/json` и v2 media type;
  обычные aggregate shapes доступны в v1/v2/v3, существующий `time_bucket`
  требует v2 или v3, keyset shapes — строго v3; запрос более старого
  представления получает аудируемый `406` вместо неполного списка;
- в контракте явно описывается отсутствие единого snapshot между отдельными
  HTTP requests и поведение при concurrent insert/update/delete;
- профили, которым нельзя последовательно выгружать все доступные строки, не
  должны получать эту возможность.

## Запланированные работы

### P2. Numeric bucket для aggregate

Добавить policy-curated dimension для распределения числового значения по
заранее заданным диапазонам. Границы принадлежат policy и публикуются через
query-shape discovery; клиент не передаёт произвольный набор диапазонов.

Основные сценарии:

- распределение длительности операций;
- распределение сумм, размеров и количественных метрик;
- обнаружение выбросов без выгрузки исходных строк;
- сравнение количества объектов в фиксированных продуктовых диапазонах.

Ограничения:

- source field, ordered boundaries, inclusivity, output alias и ordering входят
  в полный policy shape;
- только совместимые numeric source types без неявного преобразования string;
- decimal boundaries сохраняются точно и не проходят через `float64`;
- SQL expression полностью строится сервером; expressions и boundaries от
  клиента запрещены;
- discovery однозначно описывает границы и portable result representation;
- generated grouping проходит существующие required-index, EXPLAIN admission,
  deadline, row и byte bounds;
- значения ниже первой, выше последней границы и `NULL` получают явно
  определённые закрытые варианты, а не неявные labels.

### P2. Эксплуатационная упаковка

Вернуться к выбору способов установки и запуска перед регулярным использованием
на боевых базах. Этот трек не расширяет доверие к HTTP-клиентам и не превращает
Quordon в публичный edge-сервис.

Предварительный scope:

- release binaries для поддерживаемых Linux, macOS и Windows;
- systemd unit и документированный foreground/daemon lifecycle;
- пакеты только для выбранных целевых систем либо установка готового бинарника
  с checksums/signatures;
- стабильные пути для конфигурации и audit output без хранения secrets в
  package artifacts;
- отдельный read-only DB user и проверяемый минимальный набор grants;
- reference ingress для HTTPS termination и внешних rate/DoS controls;
- graceful upgrade/rollback, health checks и журналирование без SQL/DSN/secrets.

Конкретные package managers и daemon integration выбираются после фиксации
поддерживаемых платформ; до этого canonical deployment остаётся обычным
foreground-процессом или контейнером под управлением внешнего supervisor.

### P3. Специализированные measures качества данных

Рассмотреть `null_count` и `fill_rate` как удобные server-owned measures только
если они заметно упрощают работу клиентов. Они не являются новой аналитической
возможностью:

```text
null_count = count_all - count(field)
fill_rate  = count(field) / count_all
```

До появления отдельных функций оператор может публиковать shape с обеими
исходными measures, а клиент — вычислять производные значения. Если функции
будут добавлены, policy должен фиксировать source field и output alias, а
контракт — точно определить decimal precision, округление, zero-row result и
nullability. Numeric overflow и тип результата должны совпадать в OpenAPI и
adapter runtime.

## Что пока не планируется в MVP

Следующие возможности дают меньше пользы относительно расширения security и
resource-control boundary и поэтому остаются за рамками ближайшего беклога:

- arbitrary SQL и универсальный execute endpoint;
- joins, subqueries, unions, window functions и пользовательские expressions;
- `EXPLAIN ANALYZE`, выполняющий исследуемый запрос;
- произвольный `HAVING`;
- random sampling без доказуемой границы source work;
- batch endpoint с частичными результатами и неоднозначной audit-семантикой.

## Общий Definition of Done

Любой пункт переносится из беклога в исполняемый MVP только атомарно со
следующими изменениями:

- основной `openapi/openapi.yaml`, capabilities и stable error codes;
- strict decoder и semantic validation без type coercion;
- operation-bound authorization token и fail-closed audit;
- adapter capability и startup compatibility validation;
- дешёвые pre-action structural/resource bounds;
- positive и negative OpenAPI 3.1/runtime contract fixtures;
- unit, race и MySQL 8 integration tests;
- обновление `docs/api.md`, security model, policy configuration и operations
  guide.
