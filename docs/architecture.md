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

Адаптер объявляет `CapabilitySet`. Наличие endpoint в OpenAPI не означает, что каждая DBMS поддерживает его. Если выбранный адаптер не объявил требуемую capability, core не вызывает базу данных и возвращает HTTP `501` с кодом `CAPABILITY_NOT_IMPLEMENTED`.

`list_query_shapes` — исключение в смысле владельца capability: её реализует
core, а adapter не вправе её объявлять. Core публикует операцию только если
adapter поддерживает зависимую `aggregate` capability и при запуске построен
disclosure-safe snapshot для конкретного профиля.

При создании manager декларация проверяется до разрешения DSN и открытия pool:
неизвестные или повторные operations и
`list_objects`/`describe_object`/`select`/`aggregate` без соответствующего Go
interface являются ошибкой конфигурации и блокируют
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

Policy engine проверяет principal, profile, datasource, operation, resource,
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

MVP не включает joins, subqueries, unions, raw expressions и пользовательские функции. Расширения добавляются в общую модель только после реализации и contract tests минимум в двух адаптерах либо оформляются как capability конкретного адаптера.

## Поток выполнения

1. Ограничить размер HTTP request до его полного чтения.
2. Назначить `request_id`.
3. Проверить Basic Auth и создать `Principal`.
4. Строго десериализовать и валидировать API request.
5. Получить immutable snapshot политики.
6. Выбрать назначенный principal профиль и datasource.
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
4. Получает `LOCK INSTANCE FOR BACKUP`, который не разрешает concurrent DDL, и
   только затем проверяет через системный каталог, что source является
   физической таблицей с учётом case semantics сервера. Обычный view
   отклоняется до разрешения его зависимостей.
5. Под тем же guard открывает read-only transaction и оборачивает `SELECT`
   только в `EXPLAIN FORMAT=JSON`, передавая значения как bind parameters.
6. До возврата plan повторно проверяет тип source, завершает transaction и
   освобождает instance DDL guard.

Guard берётся до первого lookup, поэтому между проверкой и `EXPLAIN` объект уже
нельзя заменить view. Проверки, guard и `EXPLAIN` привязаны к одному физическому
соединению из локального pool. MySQL-пользователю нужны scoped `SELECT` grants и
динамическое право `BACKUP_ADMIN`; отсутствие последнего делает datasource
неготовым. Внешний datasource proxy по-прежнему обязан соблюдать инвариант
однородности backend-серверов из модели угроз.

MySQL protocol compression для datasource отключается адаптером: иначе драйверу пришлось бы распаковать фрейм до проверки размера логического пакета. Входящий пакет плана ограничивается на уровне драйвера до чтения тела; превышение закрывает соединение и возвращает `RESULT_TOO_LARGE`.

`EXPLAIN ANALYZE` запрещён, поскольку выполняет statement. MVP не позволяет клиенту выбирать произвольный explain mode.

Schema capabilities читают только `BASE TABLE` из `information_schema` и
возвращают core только DBMS-neutral metadata; policy engine дополнительно
фильтрует объекты и columns до сериализации ответа. Profile
`max_result_bytes` проверяется в core только для уже отфильтрованного payload,
поэтому закрытые metadata не влияют на доступность разрешённого результата и
не раскрывают свой совокупный размер через этот лимит. Adapter не получает
profile budget и использует отдельный абсолютный read/materialization bound
16 MiB. `describe_object` возвращает одинаковый `404` для отсутствующего,
запрещённого и не-физического объекта.

`describe_object_statistics` принимает только отдельный operation-bound token,
берёт instance DDL guard до первого lookup token-bound resource и требует
InnoDB `BASE TABLE`. Adapter читает явный allowlist колонок из
`information_schema.tables` и `information_schema.partitions`, проверяет
канонические unsigned значения и полную ordinal shape партиций. Profile budget
заряжается до удержания следующей записи; ответ либо полный, либо
`RESULT_TOO_LARGE`, без truncation. View, non-InnoDB, denied и отсутствующий
object неразличимы как `404` на HTTP boundary.

Для `select` adapter получает instance DDL guard до case-aware проверки
`BASE TABLE`, затем начинает read-only transaction и выполняет пользовательский
SELECT. Guard удерживается до завершения transaction, поэтому concurrent DDL не
может заменить проверенную таблицу представлением между validation и execution,
а уже существующий view отклоняется до разрешения его зависимостей. Compiler допускает только
field projections, один source, allowlisted filters и sorting; aggregates и
само свойство `group_by`, включая пустой массив, отклоняются строгим
endpoint-specific decoder до policy и DBMS.
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

Для `aggregate` adapter под тем же DDL guard допускает только InnoDB
`BASE TABLE`, явно выбирает `REPEATABLE READ`, открывает read-only consistent
snapshot и выполняет `EXPLAIN FORMAT=JSON` точного `FORCE INDEX` запроса перед
его выполнением. Plan admission проверяет единственный server-owned source
alias, policy index, access type, `rows_examined_per_scan`, temporary table и
filesort. Scalar result возвращается целиком или ошибкой; grouped result может
быть усечён только по complete-row boundary с явным `truncated`.

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
