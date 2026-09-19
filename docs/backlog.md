# Беклог Quordon

Актуализировано 2026-09-18 для опубликованного релиза
[`v0.1.3`](https://github.com/sigalx/quordon/releases/tag/v0.1.3).

Этот документ фиксирует реализованные возможности и оставшиеся работы.
Запланированные расширения не являются частью исполняемого API, пока
соответствующий endpoint или расширение не добавлены одновременно в OpenAPI,
runtime, policy model, документацию и contract tests.

Приоритет определяется практической пользой для локальных программных агентов,
которым нужно исследовать состояние продуктовой БД: находить данные, считать их,
сравнивать срезы и анализировать динамику. Пользователи и операторы сервиса
считаются доверенными, агенты — недоверенными. Все новые операции сохраняют
принцип: строгая валидация и policy authorization предшествуют любому обращению
к DBMS.

## Актуальный порядок работ

1. **P2 — `ENUM` в keyset cursor.** Нужен отдельный adapter-owned контракт,
   сохраняющий позиционный, а не лексикографический порядок MySQL `ENUM`.
2. **P2 — параметризованная генерация keyset shapes.** `$ref`/`$override` уже
   переиспользуют готовые nodes/profiles. Генерация форм `latest`, `by watermark`
   и `by window` по явно заданным параметрам остаётся отдельной задачей без
   wildcard-доступа и автоматической выдачи прав по metadata.
3. **P2 — дальнейшее эксплуатационное сопровождение.** Linux archives, Debian
   packages, systemd и build provenance уже реализованы. Остаются другие
   платформы, SBOM/signing, модель APT repository и reference ingress.
4. **P3 — безопасный admission для оптимизированных `MIN`/`MAX`.** MySQL может
   вернуть план без table node для запроса экстремума по индексу; принимать
   такой план можно только после отдельного доказательства adapter-ом,
   сохраняя estimate bounds и проверку заданного `required_index` для остальных
   aggregates.
5. **P3 — специализированные `null_count` и `fill_rate`.** Это удобные сокращения,
   но те же значения уже выводятся из разрешённых `count_all` и `count(field)`,
   поэтому отдельные функции не блокируют повседневный анализ.

Заранее разрешённые enum-like distributions уже выражаются существующим
grouped aggregate с обычной dimension и `count_all`; новая runtime-операция для
них не требуется. Нужные распределения добавляются оператором как query shapes
и публикуются через discovery.

## Реализованные возможности

### Сборка policy через `$ref` и `$override`

Статус: реализовано и выпущено в `0.1.3`
([PR #5](https://github.com/sigalx/quordon/pull/5)).

- локальный `$ref` заменяет YAML-узел целиком на любом уровне: profile,
  allow/deny-list, shapes, отдельный shape, limits или scalar;
- поддерживаются внутренние ссылки, файлы и JSON Pointer fragments; вложенные
  ссылки разрешаются относительно собственного исходного файла;
- optional `$override` заменяет или добавляет непосредственные поля mapping
  после полного разрешения базы; вложенного merge, объединения массивов и
  удаления через `null` нет;
- `config.LoadFile` ограничивает ссылки каталогом основной policy через
  `os.Root`, проверяет regular descriptors ровно `0600` и фиксированные budgets;
  inline `Load` поддерживает внутренние ссылки и не открывает внешние файлы;
- после сборки выполняются строгие types/presence и semantic validation;
  runtime получает обычный `Config`; profile и principal содержат непустые
  datasource allowlists, а runtime авторизует их пересечение;
- fingerprint вычисляется по canonical redacted effective policy, независимо
  от путей и разбиения на файлы; diagnostics не раскрывают config values;
- `--check-config` проверяет сборку и общую semantics без adapters, DB, HTTP
  и credential resolvers; DB readiness, grants и физические shapes он не проверяет;
- integration покрывает два datasource с различимыми данными, shared refs,
  правильную маршрутизацию, authorization denials и plan admission.

Контракт описан в [policy configuration](policy-configuration.md), процедуры
immutable bundles, candidate checks и rollback — в [operations](operations.md).
Параметров шаблонов и генерации shapes в этом механизме нет.

### Linux release artifacts и Debian/systemd

Статус: реализовано; полный release CI `0.1.3`
[завершился успешно](https://github.com/sigalx/quordon/actions/runs/35365184206).

- статические Linux-бинарники для `amd64` и `arm64`, архивы `tar.gz`, Debian
  packages и SHA-256 checksum manifest;
- непривилегированный systemd service, стабильные пути, manual page и
  third-party notices; fresh install не создаёт рабочую policy и не запускает service;
- Debian lint и lifecycle smoke tests установки, upgrade, remove/purge и
  восстановления service при отмене package operations;
- draft release публикуется только после source/OpenAPI, race, MySQL integration,
  package tests и GitHub build provenance attestations;
- versioned policy bundles, атомарная замена основного файла и документированный
  rollback; перед возвратом бинарника `0.1.2` восстанавливается inline-policy.

Установка и release procedure описаны в [packaging](packaging.md).
APT repository, отдельные signatures, SBOM и macOS/Windows distributions пока
не реализованы; оставшийся scope приведён ниже.

### Исторические даты и диагностический temporal text

Статус: реализовано. Календарные DATE/DATETIME поддерживаются с `0001` года;
`source_text` явно сохраняет нулевые, неполные и некалендарные значения для
вывода, filters, grouping и keyset. Permission по умолчанию выключено.
Discovery объединён в один JSON-контракт без дополнительного media type version.
Внешние клиенты должны использовать единый `application/json`; их миграция
выполняется в соответствующих клиентских репозиториях.
Оптимизация планов для текстовых expressions и расследование scan-estimate
отказов существующих shapes относятся к отдельной работе.

### Queries над trusted views

Статус: реализовано. Query operations читают настроенный объект с columns;
discovery включает разрешённые tables/views. Statistics ограничен physical InnoDB
metrics, view даёт `422 UNSUPPORTED_QUERY`.

Quordon защищает от недоверенного клиента и ИИ-агента. Администратор СУБД и
автор policy входят в доверенную границу. SELECT, EXPLAIN, aggregate и keyset
читают настроенный объект с колонками, включая views. Denylist применяется к
полям запрошенного объекта; запрет исходной колонки не распространяется
автоматически на alias во view. Безопасность определений views, их dependencies,
отсутствие раскрытия запрещённых данных через aliases и изменения схемы являются
ответственностью администраторов. Анализ dependencies не выполняется.

Специального удержания схемы и защиты от concurrent DDL нет. Обычные metadata
locks СУБД сохраняются. Readiness и обычный SELECT используют scoped SELECT учётку. MySQL требует
scoped SHOW VIEW для EXPLAIN views, включая preflight aggregate и keyset;
при SELECT-only эти операции над views дают `503 DATABASE_UNAVAILABLE` до
основного SELECT. Integration сохраняет SELECT-only учётку и проверяет это
ограничение. Административное право BACKUP_ADMIN не требуется. Read-only transactions,
session setup, deadlines, packet/result bounds и конечные cleanup deadlines
сохраняются.

`required_index` — необязательный execution-only portable identifier.
Omission означает отсутствие условия; явные `null`, пустая строка и неверный тип
блокируют startup. SQL index hints и проверка наличия индекса на запрошенном
объекте отсутствуют. Если индекс задан, хотя бы один физический узел чтения
принятого плана обязан его использовать; индекс materialized result не подходит.

Обязательный положительный `maximum_rows_examined_per_scan` ограничивает estimate
каждого узла чтения, включая materialized results. Полный scan и несколько source
nodes доверенного view допускаются в пределах bounds. `allow_temporary_table` и
`allow_filesort` — optional strict booleans с default `false` для всех aggregate
и keyset shapes. Materialization требует разрешённой temporary work. Time-bucket
shapes по-прежнему требуют оба controls явно. Отказ admission даёт
`422 UNSUPPORTED_QUERY` до основного SELECT. Estimate остаётся эвристикой;
deadlines, server-side timeout и concurrency limits обязательны.

Keyset строит ключ из настроенного `order_by` и metadata его колонок.
Автор shape гарантирует уникальность полного ordered tuple; доказательство через
unique index не требуется. Key columns остаются `NOT NULL`, поддерживаемых точных
типов, с проверкой cursor arity, precision, charset round-trip и budgets.
Отдельные страницы не имеют общего snapshot. Read-only `REPEATABLE READ`, UTC
session и bounded cleanup выполняются на одном соединении.

Перед обновлением бинарника оператор удаляет `ddl_guard_mode` из конфигов.
Старое поле является unknown configuration field и блокирует startup; режима
совместимости с игнорированием нет. В audit поле режима отсутствует. HTTP shapes
и единый JSON discovery используются; execution-only controls не публикуются.

### Discovery разрешённых aggregate shapes

Статус: реализовано в runtime и исполняемом OpenAPI-модуле
[`openapi/query-shapes.yaml`](../openapi/query-shapes.yaml).

API:

```text
GET /query-shapes?profile={profile}&datasource={datasource}
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
- discovery публикует time-bucket shapes вместе с остальными разрешёнными
  shapes в едином полном `application/json` payload;
- несовместимый temporal source и некорректные сгенерированные bucket values
  завершаются документированной ошибкой без смешивания с настоящим `NULL`.

### Runtime-статистика таблиц и партиций

Статус: реализовано в runtime и исполняемом OpenAPI-модуле
[`openapi/table-statistics.yaml`](../openapi/table-statistics.yaml).

API:

```text
GET /schemas/{schema}/objects/{object}/statistics?profile={profile}&datasource={datasource}
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
- поддерживаются только физические InnoDB tables; view даёт `422 UNSUPPORTED_QUERY`, MyISAM, denied и
  отсутствующий object дают `404`;
- ответ полный или `413`: частичный список партиций не выдаётся.

### Keyset pagination для SELECT

Статус: реализовано в runtime и исполняемых OpenAPI-модулях
[`openapi/openapi.yaml`](../openapi/openapi.yaml),
[`openapi/keyset-pagination.yaml`](../openapi/keyset-pagination.yaml) и
[`openapi/query-shapes.yaml`](../openapi/query-shapes.yaml).

Позволяет безопасно продолжать выборку без больших `OFFSET`. Реализованная
форма продолжения:

```json
{
  "kind": "keyset",
  "profile": "reader",
  "datasource": "primary-mysql",
  "shape": "records_by_id",
  "query": {
    "source": {"schema": "application", "name": "records"},
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
- cursor key в MySQL adapter разрешён для целочисленных types,
  `CHAR`/`VARCHAR` с server-verified обратимым source charset ↔ UTF-8
  round-trip без application charset allowlist, `BINARY`/`VARBINARY`, `DATE`,
  `DATETIME` и `TIMESTAMP`; `ENUM`/`SET`, `TIME`/`YEAR`, text/blob, decimal,
  floating-point, `BIT`, JSON и spatial keys отклоняются до выполнения SELECT;
- после чтения metadata, но до `EXPLAIN`/`SELECT`, сервер консервативно
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
  legacy `{profile, datasource, query}` и keyset request/response остаются
  различимыми, а keyset
  ветка однозначно выбирается обязательным `kind: keyset`;
- handler сохраняет выбранную request-ветку в типизированном dispatch:
  legacy request может вернуть только `SelectResult`, keyset request — только
  `KeysetSelectResult`; перекрёстная пара становится `500 INTERNAL_ERROR` до
  записи ошибочного HTTP 200 и покрывается semantic contract fixture;
- query-shape discovery публикует весь набор aggregate, time-bucket и keyset
  templates через единый `application/json`; предыдущие vendor media types
  отклоняются с 400, частичного списка и нескольких payload snapshots нет;
- в контракте явно описывается отсутствие единого snapshot между отдельными
  HTTP requests и поведение при concurrent insert/update/delete;
- профили, которым нельзя последовательно выгружать все доступные строки, не
  должны получать эту возможность.

### Temporal-компоненты составного keyset cursor

Статус: реализовано в portable runtime contract и MySQL 8 adapter без нового
discovery media type.

Поддержка использует существующую операцию, составной ordered unique key и
лексикографическое продолжение. К прежним portable cursor types `integer`,
`string` и `bytes` добавлены отдельные `date`, `datetime` и `timestamp`, поэтому
temporal-компонент больше не делает весь составной ключ непригодным.

Поддерживаются смешанные составные ключи, например `integer + date`,
`integer + datetime` и `timestamp + bytes`.

Реализованные свойства:

- в cursor/OpenAPI добавлены закрытые portable-варианты `date`, `datetime` и
  `timestamp`, не маскируя temporal values под обычный `string`;
- зафиксирована adapter-neutral wire semantics:
  `date` — конечная Gregorian date `YYYY-MM-DD`, `datetime` — timezone-naive
  wall-clock `YYYY-MM-DD HH:MM:SS[.fraction]`, `timestamp` — UTC instant в
  RFC 3339 с обязательными `T` и `Z`; общий envelope использует годы
  `0001`–`9999` и не более девяти знаков дробной секунды;
- сохранены существующий массив cursor values и лексикографическая компиляция
  для смешанных составных ключей, например `integer + date + integer`;
- core проверяет только JSON/OpenAPI shape, канонический portable-формат,
  календарную корректность и общий envelope; zero/incomplete/non-finite values,
  неявный coercion и `null` отклоняются до datasource call;
- adapter проверяет точное соответствие cursor type физическому типу,
  source range и fractional precision key column, а также native bind и
  comparison representation; несовместимость даёт `422` до `EXPLAIN`
  и `SELECT`;
- первая реализация находится в MySQL 8 adapter: `DATE` отображается в `date`,
  `DATETIME` — в `datetime`, `TIMESTAMP` — в `timestamp`; MySQL-specific ranges,
  UTC session handling и server-owned casts остаются только в mysql8 package;
- ветвления по adapter name, MySQL types/ranges и SQL fragments отсутствуют в
  `queryspec`, policy, query service и других общих packages;
- `next_cursor` формируется из полного ключа последней возвращённой строки и
  повторно проверяется общими и adapter-owned правилами до успешного ответа;
- worst-case temporal representation учитывается в preflight
  `max_request_bytes`, audit-size и response-size budget;
- OpenAPI/runtime negative fixtures покрывают неверный token type, формат,
  общий envelope, cursor arity и mixed-type composite key; adapter tests
  отдельно покрывают физический диапазон, precision, binding и comparison;
- единый JSON discovery включает все новые публичные members и cursor types;
- MySQL 8 integration tests покрывают прямой и обратный порядок; для каждого
  будущего адаптера остаются обязательными те же adapter-neutral contract
  fixtures и его собственные integration scenarios.

Отдельные HTTP-страницы по-прежнему не образуют единый snapshot: поддержка
temporal cursor не меняет eventual-consistency semantics keyset pagination.

### Фиксированные числовые распределения

Статус: реализовано. `numeric_bucket` — dimension существующего grouped
aggregate с 1–64 точными policy-owned fixed-point границами. INTEGER/DECIMAL
поддерживаются, FLOAT/DOUBLE и нечисловые источники дают semantic `422`.
Индексы `0…N` имеют `type: integer`, `encoding: string`, DB NULL сохраняется;
возвращаются только непустые группы. Discovery публикует границы, request их
не принимает. Capability gate `numeric_bucket_exact`, глубокие snapshots,
полный parameter budget и существующий EXPLAIN admission сохраняются.

Контракт и примеры: [API](api.md), [policy](policy-configuration.md).
Выпуск и развёртывание оформляются отдельно.

## Запланированные работы

### P2. Позиционный `ENUM` в keyset cursor

Составной PK с компонентом `ENUM` нельзя выдавать за набор `integer + string`:
MySQL сравнивает `ENUM` по позиции значения в объявлении, а не по
лексикографическому порядку label.

Безопасная реализация должна:

- ввести отдельный cursor type для enum-like key component;
- читать полный ordered domain и проверять его связь с конкретной key column;
- сравнивать cursor по adapter-owned ordinal representation без SQL fragments
  от policy или клиента;
- отклонять обнаруженное до основного запроса изменение domain/order;
  concurrent DDL остаётся ответственностью администратора;
- не распространять поддержку на `SET`, пока для него не определён отдельный
  однозначный контракт;
- покрыть mixed composite key `integer + enum`, неизвестный label, неверный
  регистр/коллацию, изменённый domain и повторную отправку `next_cursor`.

### P2. Параметризованная генерация keyset shapes

Сборка через `$ref`/`$override` уже позволяет разделять готовые профили и shapes.
Она не генерирует формы `latest`, `by watermark` и `by window` для разных таблиц.
Добавить отдельный config-only механизм параметризованной генерации этих форм,
который уменьшает повторение YAML и сохраняет явные полномочия клиента.

Ограничения:

- оператор по-прежнему явно перечисляет каждый source, projection, ordered
  tuple с гарантированной уникальностью, filters, optional index и plan bounds;
- шаблон не может раскрывать таблицы или поля через wildcard и не создаёт shapes
  автоматически из живой schema metadata;
- startup разворачивает шаблоны в обычные конкретные shapes до полной config,
  resource, field, overlap и effective-limit validation;
- canonical effective policy и fingerprint учитывают развёрнутые формы;
- discovery публикует только итоговые именованные shapes и не раскрывает имя
  шаблона, индекса или plan thresholds;
- ошибка хотя бы в одной развёрнутой форме блокирует startup целиком.

### P3. Admission оптимизированных `MIN`/`MAX`

Для получения верхнего watermark MySQL может оптимизировать `MAX(id)` без table
node в `EXPLAIN FORMAT=JSON`. Сейчас такой aggregate намеренно отвергается,
поэтому policy использует эквивалентную форму `ORDER BY id DESC LIMIT 1`.

Разрешать plan без table node можно только для отдельной доказуемой формы:

- один policy-curated `MIN` или `MAX` над подходящей key column без joins,
  grouping, пользовательских expressions и неоднозначных filters;
- adapter подтверждает metadata, совместимый индекс и известный
  MySQL-specific optimized-away plan marker;
- отсутствие ожидаемого marker, изменение metadata или любой неизвестный plan
  остаются fail-closed;
- общее требование bounded table nodes для остальных aggregates сохраняется;
  optional required_index проверяется только когда задан.

До реализации рабочим и безопасным вариантом остаётся `ORDER BY ... LIMIT 1`.


### P2. Дальнейшее эксплуатационное сопровождение

Linux/Debian/systemd baseline уже реализован и проверен release CI. Продолжить
этот трек для выбранных дополнительных платформ и эксплуатационных требований.
Он не расширяет доверие к HTTP-клиентам и не превращает Quordon в публичный
edge-сервис.

Оставшийся scope:

- выбрать поддерживаемые macOS/Windows targets, их release artifacts,
  package managers и service/supervisor integration;
- добавить SBOM, определить отдельные artifact signatures и проверку
  reproducibility; существующие build provenance attestations сохраняются;
- определить APT repository hosting, подписывание metadata, хранение и rotation
  ключей до публикации repository;
- reference ingress для HTTPS termination и внешних rate/DoS controls;
- audit retention, dashboards/alerts, capacity tests и failure injection для
  подтверждённых deployment scenarios.

Документированные least-privilege grants, health checks, bounded lifecycle и
журналирование без SQL/DSN/secrets сохраняются во всех новых distributions.

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

Новая или изменённая API-возможность переносится из беклога в исполняемый MVP
только атомарно со следующими изменениями:

- основной `openapi/openapi.yaml`, capabilities и stable error codes;
- strict decoder и semantic validation без type coercion;
- operation-bound authorization token и fail-closed audit;
- adapter capability и startup compatibility validation;
- дешёвые pre-action structural/resource bounds;
- positive и negative OpenAPI 3.1/runtime contract fixtures;
- unit, race и MySQL 8 integration tests;
- обновление `docs/api.md`, security model, policy configuration и operations
  guide.

Для config-only механизмов нужны strict config schema, bounds до раскрытия,
полная validation итоговой policy, canonical redacted fingerprint и
positive/negative loader tests. Packaging и operations проверяются своим
release/lifecycle scope; изменения публичного API требуют перечисленных выше
contract fixtures.
