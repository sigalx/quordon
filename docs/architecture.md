# Архитектура

## Цели

- изолировать реквизиты и сетевой доступ к базам данных;
- предоставить небольшой и однозначный REST API без передачи SQL;
- поддерживать несколько datasources и DBMS в одном процессе;
- авторизовывать типизированные операции, ресурсы, поля и возможности;
- генерировать SQL только внутри адаптера конкретной DBMS;
- ограничивать нагрузку и объём возвращаемых данных;
- формировать воспроизводимый аудит каждого решения.

## Не входит в цели

- универсальный SQL proxy;
- приём SQL или его фрагментов через API;
- выполнение DDL или DML;
- интерактивная SQL-консоль;
- общий знаменатель, скрывающий все различия DBMS;
- автоматическая эмуляция отсутствующей возможности адаптера;
- замена grants и сетевых ограничений базы данных.

## Контекст

```text
API client
    |
    | HTTP Basic Auth over an allowed transport
    v
+-------------------------------------------------------+
| Quordon                                             |
|                                                       |
| Router -> Authenticator -> Request validator          |
|                               |                       |
|                               v                       |
|                     Policy engine                     |
|                               |                       |
|                               v                       |
|                     DBMS adapter registry              |
|                               |                       |
|               +---------------+---------------+       |
|               |               |               |       |
|            MySQL 8         PostgreSQL       others    |
|               |               |               |       |
|               +---------------+---------------+       |
|                               |                       |
|                    Database executor                  |
|                               |                       |
|                               v                       |
|                     Result limiter                    |
|                                                       |
| Audit sink receives decision and completion events   |
+------------------------------+------------------------+
                               |
                               | restricted DB users
                               v
                     Database endpoints
```

Gateway может работать рядом с базой данных, на отдельном сервере или локально на машине разработчика, у которой уже есть сетевой доступ к DB endpoint.

## Версионирование API

Один процесс gateway реализует ровно одну major-версию API. Его собственные HTTP routes не содержат version prefix: например, `GET /capabilities` и `POST /queries/explain`.

Если API публикуется для внешних потребителей, version namespace принадлежит border proxy. Он может преобразовать `/v1/queries/explain` в `/queries/explain` экземпляра с API major version `1`, а `/v2/queries/explain` направить на отдельный экземпляр следующей major-версии. Gateway не маршрутизирует несколько несовместимых major-версий внутри одного процесса.

Версия API-контракта и версия сборки сервиса независимы. Они публикуются как `api_version` и `service_version` в capabilities; `info.version` в OpenAPI обозначает версию API-контракта.

## Core и adapters

### Core

Core не содержит SQL конкретного диалекта и отвечает за:

- HTTP transport и строгую десериализацию;
- Basic Auth и создание `Principal`;
- immutable policy snapshot;
- общую модель `QuerySpec`;
- авторизацию операции;
- системные и профильные лимиты;
- выбор datasource и его адаптера;
- ограничение результата;
- аудит и observability;
- стабильные HTTP и reason codes.

Граница относится не только к SQL. В core также запрещены product-specific
типы и диапазоны, системные каталоги, DSN/driver options, placeholder и cast
syntax, session variables, форматы планов и native error codes. Общая модель
описывает семантику portable type и выполняет только те проверки, для которых
не нужны сведения о конкретной СУБД. Если поведение требует ветвления по имени
адаптера, его следует выразить узким типизированным adapter interface или
capability, а реализацию оставить внутри adapter package.

### DBMS adapter

Каждый адаптер реализует поддерживаемое подмножество следующих интерфейсов:

```text
Compiler
Introspector
SessionController
Explainer
Selector
Canceller
ErrorClassifier
```

Адаптер отвечает за:

- quoting identifiers;
- placeholder syntax и bind parameter mapping;
- построение SQL из `AuthorizedQuerySpec`;
- metadata queries;
- проверку product/version подключённого сервера;
- DBMS-specific read-only и timeout settings;
- формат `EXPLAIN`;
- server-side cancellation;
- нормализацию типов результата;
- классификацию ошибок драйвера.

Весь код, зависящий от конкретной СУБД или Go driver, расположен в
`internal/adapters/<adapter>/`. Адаптер отображает portable types на физические,
проверяет их диапазоны и precision по metadata источника, выбирает безопасное bind
representation и генерирует собственный SQL. Проверка общих wire-инвариантов
происходит раньше в core; проверка физических свойств — после авторизации, но
до `EXPLAIN` или основного запроса.

Например, portable temporal types означают конечную календарную дату,
timezone-naive wall-clock value и UTC instant. MySQL, PostgreSQL, SQLite или
Oracle adapter самостоятельно решает, какие физические типы способны
реализовать каждую семантику без потери порядка и точности. Наличие похожего
native type по имени само по себе не является доказательством совместимости.

Адаптер объявляет `CapabilitySet`. Наличие endpoint в OpenAPI не означает, что каждая DBMS поддерживает его. Если выбранный адаптер не объявил требуемую capability, core не вызывает базу данных и возвращает HTTP `501` с кодом `CAPABILITY_NOT_IMPLEMENTED`.

`list_query_shapes` — исключение в смысле владельца capability: её реализует
core, а adapter не вправе её объявлять. Core публикует операцию только если
adapter поддерживает зависимую `aggregate` capability и при запуске построен
disclosure-safe snapshot для конкретного профиля.

При создании manager декларация проверяется до разрешения DSN и открытия pool:
неизвестные или повторные operations и
`list_objects`/`describe_object`/`describe_object_statistics`/`explain_select`/
`select`/`select_keyset`/`aggregate` без соответствующего Go interface являются
ошибкой конфигурации и блокируют
запуск даже для optional datasource. Перед каждым adapter action manager
повторно проверяет cached capability; одного наличия Go interface недостаточно.
Runtime assertion остаётся только fail-closed защитой от внутренней ошибки, а
не штатной веткой выполнения.

Адаптеры компилируются в официальный бинарник и регистрируются при старте. Go runtime plugins не используются. Независимый out-of-process protocol для сторонних адаптеров может быть спроектирован позднее.

## Типизированный поток

```text
RawRequest
  -> ValidatedQuerySpec
  -> AuthorizedQuerySpec
  -> CompiledQuery
  -> QueryResult
```

### `ValidatedQuerySpec`

Transport отклоняет неизвестные поля, неверные типы, пустые identifiers,
превышение глубины выражений и структурных hard limits. Aggregate token scanner
считает суммарные filter predicates, bind parameters и допустимое число filter
objects до полной десериализации дерева. Спецификация может содержать только
предусмотренные моделью ресурсы, проекции, predicates, grouping, aggregates,
sorting, limit и offset.

### `AuthorizedQuerySpec`

Policy engine сначала проверяет трёхстороннее пересечение principal/profile/
datasource и создаёт непрозрачный `AuthorizedBinding`, затем проверяет operation, resource,
fields, operators, aggregates и effective limits. Создание значения ограничено
пакетом авторизации. Возвращаемые копии authorization token глубоко копируют
bind payload bytes; вызывающий код не может изменить сохранённый запрос через
`json.RawMessage` alias.

Schema metadata использует такую же типизированную границу. Policy engine
создаёт непрозрачный `AuthorizedSchema`, привязанный либо к `list_objects` и
schema, либо к `describe_object` и конкретному schema/object. Database manager
не принимает raw datasource/schema/object, проверяет operation token и
возвращает только policy-filtered objects или columns. Только DBMS adapter под
этой границей работает с необработанными identifiers системного каталога.

Aggregate использует отдельный непрозрачный `AuthorizedAggregate`. Token
содержит уже нормализованный exact query shape, effective limits, выбранный
policy-owned index и maximum plan estimate. Его нельзя передать в `Select` или
`Explain`, а manager повторно проверяет operation и adapter capability до
любого DBMS call.

Discovery использует отдельный `AuthorizedQueryShapeList`, привязанный к
principal, Basic username, profile, policy hash/version, datasource, adapter,
identifier semantics и точному поколению неизменяемого публичного shape set.
Response builder принимает только этот token; raw policy и execution-only
поля не пересекают границу ответа.

### `CompiledQuery`

Создаётся только выбранным DBMS adapter. Содержит SQL, bind parameters и необходимые driver metadata. Пользовательские значения не интерполируются в SQL, а физические identifiers берутся только из авторизованного server-side mapping.

Database executor принимает только `CompiledQuery`. В коде не должно существовать публичного метода `execute(rawSQL string)`.

## QuerySpec

Переносимое ядро первой версии описывает запрос к одному источнику:

```text
QuerySpec
  source
  projection
  filter
  group_by
  order_by
  limit
  offset
```

MVP не включает joins, subqueries, unions, raw expressions и пользовательские
функции. Расширение общей модели проектируется DBMS-neutral с первого релиза.
Оно может сначала получить реализацию только в одном адаптере, если
неподдерживающие адаптеры fail closed через capability или документированную
проверку совместимости физического типа, а общие contract fixtures не содержат
условий конкретной СУБД. Добавление следующего адаптера не должно требовать
изменения уже опубликованной portable семантики; каждый адаптер добавляет
собственные unit и integration tests.

## Поток выполнения

1. Ограничить размер HTTP request до его полного чтения.
2. Назначить `request_id`.
3. Проверить Basic Auth и создать `Principal`.
4. Строго десериализовать и валидировать API request.
5. Получить immutable snapshot политики.
6. Авторизовать назначенную пару profile-datasource по пересечению allowlists.
7. Проверить capability выбранного адаптера; при её отсутствии вернуть `501` без обращения к БД.
8. Авторизовать `QuerySpec` и вычислить effective limits.
9. Создать `AuthorizedQuerySpec`.
10. Скомпилировать запрос DBMS adapter.
11. Зарезервировать соединение из pool выбранного datasource.
12. Установить DBMS-specific read-only и server-side limits.
13. Выполнить compiled statement с bind parameters.
14. Ограничить входящий DBMS packet до выделения памяти под его тело, затем проверить точный размер и сериализовать результат.
15. Записать итоговое событие аудита.
16. Вернуть соединение в pool только после успешного reset; иначе закрыть его.

## MVP MySQL 8

MySQL 8 adapter реализует capabilities `list_objects`, `describe_object`,
`describe_object_statistics`, `explain_select`, `select` и `aggregate`. Для
`explain_select`:

1. Получает `AuthorizedQuerySpec`.
2. Строит один ограниченный `SELECT`.
3. Проверяет, что сервер сообщает MySQL major version `8` и не является
   MariaDB, и читает `lower_case_table_names`.
4. На том же соединении открывает read-only transaction и выполняет только
   `EXPLAIN FORMAT=JSON` с bind parameters.
5. Проверяет bounded JSON plan и завершает transaction.

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

MySQL protocol compression для datasource отключается адаптером: иначе драйверу пришлось бы распаковать фрейм до проверки размера логического пакета. Входящий пакет плана ограничивается на уровне драйвера до чтения тела; превышение закрывает соединение и возвращает `RESULT_TOO_LARGE`.

`EXPLAIN ANALYZE` запрещён, поскольку выполняет statement. MVP не позволяет клиенту выбирать произвольный explain mode.

Schema capabilities читают таблицы и views из `information_schema` и
возвращают core только DBMS-neutral metadata; policy engine дополнительно
фильтрует объекты и columns до сериализации ответа. Profile
`max_result_bytes` проверяется в core только для уже отфильтрованного payload,
поэтому закрытые metadata не влияют на доступность разрешённого результата и
не раскрывают свой совокупный размер через этот лимит. Adapter не получает
profile budget и использует отдельный абсолютный read/materialization bound
16 MiB. `describe_object` возвращает одинаковый `404` для отсутствующего,
запрещённого объекта; views описываются без выдуманных PK/index metadata.

`describe_object_statistics` принимает только отдельный operation-bound token,
требует InnoDB `BASE TABLE` только для физических statistics. Adapter читает явный allowlist колонок из
`information_schema.tables` и `information_schema.partitions`, проверяет
канонические unsigned значения и полную ordinal shape партиций. Profile budget
заряжается до удержания следующей записи; ответ либо полный, либо
`RESULT_TOO_LARGE`, без truncation. Разрешённый view даёт `422 UNSUPPORTED_QUERY`;
non-InnoDB, denied и отсутствующий object возвращают `404`.

Для `select` adapter начинает read-only transaction и выполняет ограниченный
SELECT из настроенной таблицы или view. Compiler допускает только field
projections, один source, allowlisted filters и sorting; aggregates и свойство
`group_by`, включая пустой массив, отклоняются до policy и DBMS.

Фактический SQL получает server-side timeout и `LIMIT effective_limit + 1` для
определения `truncated`. Effective result budget применяется к сериализованным
columns/rows, а отдельный абсолютный logical-packet bound 16 MiB плюс 1 KiB
framing allowance ограничивает предварительное чтение одной строки из драйвера.
До создания Go string, base64 и row JSON adapter подсчитывает точный encoded
size, включая JSON escaping; не помещающаяся строка не материализуется.
Поэтому строка, которая не помещается в profile budget, даёт безопасный
префикс и `truncated: true`, даже если этот префикс не содержит rows; packet
выше абсолютного предела даёт `RESULT_TOO_LARGE`.
Rows возвращаются positional arrays: `NULL` как JSON `null`, binary и spatial
как opaque base64, остальные точные значения как строки. Temporal values
сохраняют нативный текст MySQL, а unsigned integer metadata нормализуется в
portable type `integer`.

Keyset cursor использует закрытые portable variants `integer`, `string`,
`bytes`, `date`, `datetime` и `timestamp`. Core проверяет только их wire grammar,
finite calendar envelope и форму tuple. MySQL 8 adapter после чтения metadata
связывает `DATE` с `date`, `DATETIME` с timezone-naive `datetime`, а `TIMESTAMP`
с RFC3339 UTC `timestamp`, проверяет физический range/FSP и сам строит `CAST`.
Нативная проекция MySQL `TIMESTAMP` остаётся row type `datetime`; adapter
нормализует только cursor в форму с `T`/`Z`, а query service проверяет их
семантическое совпадение. Другой adapter обязан реализовать собственные range,
precision, bind и comparison rules, не добавляя ветку по его имени в core.

Для `aggregate` и `select_keyset` adapter явно выбирает `REPEATABLE READ`,
открывает read-only consistent snapshot и выполняет `EXPLAIN FORMAT=JSON` точного
SELECT перед его выполнением. Scalar result возвращается целиком или ошибкой;
grouped result может быть усечён только по complete-row boundary.

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

## Структура исходного кода

```text
cmd/quordon/
internal/
  api/
  auth/
  policy/
  queryspec/
  queryservice/
  database/
  adapters/
    mysql8/
  audit/
  configuration/
  observability/
config/
docs/
testdata/
```

`queryservice` координирует use cases, но не содержит HTTP, SQL конкретной DBMS или формата policy-файла.

## Состояние и масштабирование

Сервис stateless за исключением connection pools и краткоживущего реестра выполняющихся запросов. Для каждого datasource создаётся отдельный pool. Политика загружается как неизменяемый snapshot.

Несколько экземпляров могут работать параллельно при общем audit sink. Надёжная межэкземплярная отмена требует общего query registry или корректной маршрутизации к экземпляру-владельцу и поэтому не входит в MVP.

Первая версия применяет изменения политики после restart. Возможный hot reload должен сначала полностью скомпилировать новый snapshot, а затем заменить старый атомарно.
