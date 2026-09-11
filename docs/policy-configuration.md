# Конфигурация политик

## Принципы

- всё запрещено по умолчанию;
- Basic Auth username сопоставляется с одним principal;
- principal получает только явно назначенные profiles;
- profile связан с одним datasource;
- datasource выбирает один compile-in DBMS adapter;
- deny имеет приоритет над allow;
- авторизация применяется к структурированному `QuerySpec`;
- неизвестные поля и значения конфигурации приводят к ошибке запуска;
- plaintext Basic Auth passwords никогда не хранятся в policy-файле;
- DSN можно хранить inline для локального запуска либо получать через secret reference;
- bcrypt password hash можно хранить inline либо получать через secret reference.

Пример находится в [config/policy.example.yaml](../config/policy.example.yaml).

Рабочий policy обязан быть обычным файлом с точными правами `0600`. Проверка
выполняется до разбора YAML и запуска зависимостей; любой другой режим приводит
к отказу в запуске:

```bash
install -m 600 config/policy.example.yaml config/policy.yaml
```

## HTTP server

```yaml
server:
  listen: 127.0.0.1:8085
```

Флаг `--listen` (`-l`) или переменная `QUORDON_LISTEN` переопределяет значение из
policy для конкретного запуска. Итоговый адрес независимо от источника должен
иметь форму `host:port` с портом от `1` до `65535`; некорректный override
останавливает запуск до инициализации внешних зависимостей.

`server.listen` всегда настраивает обычный HTTP listener. Quordon не
терминирует HTTPS; для удалённого доступа TLS и perimeter controls настраиваются
на внешнем ingress или reverse proxy. Встроенных rate limit и DoS controls нет.

## Basic Auth

```yaml
authentication:
  basic:
    realm: quordon
    users:
      explain-client:
        principal: readonly-client
        password_hash_secret_ref: env:QUORDON_EXPLAIN_PASSWORD_HASH
```

Имя в `users` является Basic Auth username. Secret provider возвращает
канонически закодированный 60-символьный bcrypt hash с префиксом `$2a$`,
`$2b$` или `$2y$`. Весь hash, а не только version и cost, проверяется до
перехода сервиса в ready. Поддерживается bcrypt cost от 10 до 14 включительно;
значения вне диапазона отклоняются до выполнения затратной bcrypt-операции.
Plaintext password не хранится в policy и не логируется.

Для локальной установки bcrypt hash можно записать непосредственно в policy:

```yaml
authentication:
  basic:
    realm: quordon
    users:
      sigalx:
        principal: readonly-client
        password_hash: "$2y$12$..."
```

У каждого пользователя должен быть указан ровно один атрибут: `password_hash`
или `password_hash_secret_ref`. При inline-хранении policy-файл содержит
credential material и должен быть доступен только владельцу процесса, например
с правами `0600`.

Неизвестный username, неверный password и неразрешимый secret приводят к отказу.
Недоступность обязательного credential secret или некорректный bcrypt hash при
старте переводят readiness в false.

## Principal

```yaml
principals:
  readonly-client:
    profiles:
      - query-explainer
```

Клиент не может расширить набор profiles параметрами запроса или заголовками.

## Datasource

```yaml
datasources:
  primary-mysql:
    adapter: mysql8
    dsn_secret_ref: file:/run/credentials/primary-mysql-dsn
    tls_required: true
    pool:
      max_open_connections: 4
      max_idle_connections: 2
      max_connection_lifetime_seconds: 900
```

`adapter` ссылается на зарегистрированный в бинарнике DBMS adapter. Неизвестный adapter блокирует запуск.

`mysql8` принимает серверы MySQL major version `8` (`>= 8.0, < 9.0`) и
отклоняет MySQL 5.7, MySQL 9 и MariaDB. Для обязательного datasource
несовместимость делает `/health/ready` неготовым; operation path выполняет ту же
проверку для optional datasource.

Datasource user должен иметь scoped `SELECT` grants на доступные таблицы и
динамическое право `BACKUP_ADMIN`. Adapter использует `LOCK INSTANCE FOR BACKUP`
до первой проверки `BASE TABLE` и удерживает guard до завершения операции, чтобы
concurrent DDL не мог подменить разрешённую таблицу view. Отсутствие этого права
делает datasource неготовым и возвращает `503` в operation path.

Один процесс может содержать несколько datasources, включая несколько серверов одной DBMS. Для каждого datasource создаётся отдельный pool и отдельное health state.

Разрешение объекта в policy не меняет ограничения adapter capability. В MySQL
8 MVP `explain_select` принимает только физические таблицы (`BASE TABLE`): даже
явно разрешённый view будет отклонён с `422 UNSUPPORTED_QUERY` без плана.

Для локальной разработки DSN можно хранить непосредственно в policy:

```yaml
datasources:
  local-mysql:
    adapter: mysql8
    dsn: "db_user:db_password@tcp(127.0.0.1:3306)/"
    tls_required: false
```

MySQL adapter всегда принудительно отключает `interpolateParams`,
`multiStatements`, `allowAllFiles`, `parseTime`, `columnsWithAlias` и protocol
compression независимо от параметров DSN. Connection collation принудительно
устанавливается в `utf8mb4_general_ci`, а DSN option `charset` не поддерживается
и блокирует запуск. Значения запроса передаются только через server-side
prepared statements, а сервер MySQL не может запросить загрузку произвольного
локального файла gateway через `LOAD DATA LOCAL INFILE`.
Отключённый `parseTime` сохраняет стабильный нативный текст MySQL для
`DATE`/`DATETIME`/`TIMESTAMP`; DSN не может заменить его RFC3339-представлением
`time.Time`. Отключённый `columnsWithAlias` сохраняет source/alias column name
без добавления table qualifier, а фиксированная UTF8MB4 collation не позволяет
legacy single-byte DSN-настройке повредить JSON text.

Session setting `transaction_read_only=ON` принадлежит адаптеру. Generic DSN
parameters, которые драйвер преобразует в назначения session variables, в MVP
не поддерживаются и блокируют запуск. Поэтому DSN не может переопределить
read-only режим через регистр, квалификаторы `@@session`/`@@local`, legacy alias
`tx_read_only` или составное SQL-выражение. Обычные driver options не являются
generic session parameters, но security- и contract-sensitive options adapter
нормализует самостоятельно.

В MVP поддерживаются только два однозначных режима соединения с MySQL:

- `tls_required: false` и отсутствие `tls` в DSN (либо `tls=false`) для
  локальной или доверенной сети;
- `tls_required: true` вместе с `tls=true` для TLS с проверкой сертификата и
  имени сервера через системное хранилище CA.

Поле `tls_required` обязательно для каждого datasource и должно быть задано
явно. Его отсутствие считается ошибкой конфигурации: plaintext допускается
только осознанным значением `tls_required: false`.

Режимы `tls=skip-verify`, `tls=preferred`, пользовательские TLS profiles и
несогласованность между `tls_required` и DSN блокируют запуск. Собственные CA
и mTLS не входят в MVP.

У datasource должен быть указан ровно один атрибут: `dsn` или
`dsn_secret_ref`. Inline DSN содержит открытый пароль к СУБД, поэтому такой
policy-файл нельзя коммитить и следует защищать правами `0600`.

## Profile

Profile объединяет:

- datasource;
- разрешённые API operations;
- resource и field policy;
- разрешённые query features;
- resource limits.

`max_concurrency` ограничивает число одновременно выполняемых DB operations
после decode и validation и может находиться в диапазоне от 1 до 1024. Он не
ограничивает Basic Auth, чтение body и построение JSON tree. Встроенного
ограничения количества запросов за единицу времени и защиты local mode от
authenticated flooding в MVP нет; при необходимости admission control
применяет внешний ingress.

Операции продукта:

```text
list_objects
describe_object
describe_object_statistics
explain_select
select
select_keyset
aggregate
list_query_shapes
```

`object_definition` и `cancel_query` пока не поддерживаются конфигурацией и
будут добавлены только вместе с соответствующими adapter capabilities.

`describe_object_statistics` — отдельное разрешение aggregate-конфиденциальности.
Оно не следует из `describe_object`: endpoint раскрывает приблизительное
распределение данных и полный набор имён партиций разрешённой таблицы. Политика
объекта применяется до первого lookup этого resource; разрешения полей для
этой операции не используются.

Разрешение операции в policy не означает наличие capability у adapter. После
проверки назначения profile core проверяет capability и возвращает `501`, если
adapter её не реализует. `list_query_shapes` реализует сам core: для неё
проверяются зависимые adapter capabilities `aggregate` и/или `select_keyset`,
соответствующие настроенным shapes, и наличие опубликованного startup snapshot.

## Resource policy

```yaml
resources:
  schemas:
    allow: [application]
  objects:
    allow: ["application.*"]
    deny:
      - application.credentials
      - application.access_tokens
  fields:
    deny:
      - application.users.password_hash
      - application.users.secret
```

Первая версия поддерживает точные identifiers и простой сегментный wildcard `*`. Произвольные регулярные выражения не используются.

Физические identifiers разрешаются только через policy и metadata adapter. Query values никогда не интерпретируются как identifiers.

## Query policy

```yaml
query:
  allow_filtering: true
  allow_group_by: true
  allow_sorting: true
  allowed_filter_operators:
    - eq
    - ne
    - lt
    - lte
    - gt
    - gte
    - in
    - is_null
    - is_not_null
  allowed_aggregates:
    - count
    - min
    - max
    - sum
    - avg
```

MVP не поддерживает joins, subqueries, unions, raw expressions и пользовательские функции. Неизвестная query feature всегда отклоняется.

Operation `select` использует более узкий subset: только field projections, без
aggregates и `group_by`. Для такого профиля `allowed_aggregates` должен быть
пустым, а `allow_group_by` — `false`. Row-level predicates не внедряются:
resources профиля должны содержать только таблицы, все строки которых principal
может читать. Для данных с tenant/owner isolation operation `select` пока
включать нельзя.

### Keyset SELECT shapes

Operation `select_keyset` требует непустой список
`query.keyset_select_shapes`. Каждый shape задаёт полную клиентскую форму и
закрытые admission controls:

```yaml
query:
  allow_filtering: true
  allow_group_by: false
  allow_sorting: true
  allowed_filter_operators: [eq]
  allowed_aggregates: []
  keyset_select_shapes:
    - name: orders_by_id
      public_description: Page through orders in stable primary-key order.
      source: {schema: application, name: orders}
      projection:
        - {kind: field, field: id}
        - {kind: field, field: status}
      filter:
        kind: predicate
        field: status
        operator: eq
        value_types: [string]
      order_by:
        - {field: id, direction: asc}
      maximum_limit: 100
      required_index: PRIMARY
      maximum_rows_examined_per_scan: 100000
```

Shape фиксирует source, ordered field-only projection, полное normalized filter
tree с типами и arity placeholders и ordered key directions. Каждый key field
должен быть спроецирован ровно один раз. `maximum_limit` ограничен effective
`max_rows`; continuation cursor дополнительно расходует triangular число bind
parameters, поэтому вся форма обязана помещаться в `max_parameters`.

`required_index` и `maximum_rows_examined_per_scan` принадлежат оператору,
входят в operation-bound token и никогда не публикуются discovery endpoint.
Имена shapes общие для aggregate и keyset; дубли и пересекающиеся client-visible
signatures блокируют startup. Для keyset действуют те же строгие YAML rules:
явный `null`, merge keys, type coercion, пустые optional identifiers и
неканонические integer bounds запрещены.

Суммарное число `aggregate_shapes` и `keyset_select_shapes` в одном profile не
может превышать 1000 независимо от наличия `list_query_shapes`. Ограничение
действует и для непубликуемых shapes, поскольку они участвуют в authorization
matching на request path.

`list_query_shapes` можно включить вместе с `select_keyset`, чтобы v3 discovery
публиковал безопасную construction template. В response остаются name,
description, source, projection/filter/order и `maximum_limit`; имя индекса,
estimate bound, SQL и cursor values отсутствуют. Row-level policy predicates в
MVP не внедряются, поэтому `select_keyset` разрешается только для datasets,
строки которых principal вправе последовательно прочитать полностью.

### Aggregate shapes

Operation `aggregate` дополнительно требует непустой список
`query.aggregate_shapes`. Каждый shape — не подсказка, а точная allowlist-форма
запроса и DBMS admission policy:

`list_query_shapes` можно включить вместе с `aggregate`, `select_keyset` или
обеими операциями. Тогда core при старте создаёт disclosure-safe snapshot всех
shapes профиля и публикует capability только после успешной проверки. Optional `public_description`
выводится клиентам буквально: это непустая YAML string до 512 Unicode code
points без C0/C1 control characters. Явный `null`, другой YAML type, пустая или
слишком длинная строка блокируют startup. `required_index` и
`maximum_rows_examined_per_scan` остаются закрытыми и в discovery не попадают.

Отсутствующий optional member и YAML `null` не эквивалентны: явный `null`
запрещён для всех policy fields, включая `filter`, `order_by` и
`maximum_limit`. Явная пустая строка также не считается отсутствием
branch-specific member и отклоняется до typed decode. Неиспользуемый member
нужно опустить полностью. YAML aliases разыменовываются при presence-sensitive
проверках: alias для `mode` не может скрыть явно заданный `maximum_limit` у
scalar shape. YAML merge keys (`<<`) запрещены во всём policy: унаследованные
members не должны обходить canonical scalar, presence, unknown-field и
branch-specific validation. Обычные aliases разрешены и проверяются по
разыменованному значению, включая aliases для canonical integer bounds
`maximum_limit` и `maximum_rows_examined_per_scan`. Все строковые members
aggregate shape обязаны быть
именно YAML strings: boolean/integer/number tokens вроде `field: true` или
`alias: 1` отклоняются до typed decode и не преобразуются в строки.

Time bucket задаётся только точным output shape `time_bucket`; wildcard opt-in
нет. Для такого shape обязательны оба execution-only boolean members
`allow_temporary_table` и `allow_filesort` с настоящим YAML tag `!!bool`, даже
когда значение `false`. Они не публикуются через `/query-shapes`, но входят в
authorization token и redacted policy fingerprint.

Отсутствие у выбранного adapter статически объявленной feature
`time_bucket_utc` не делает policy синтаксически некорректной: bucket-запрос и
`list_query_shapes` возвращают `501 CAPABILITY_NOT_IMPLEMENTED` без обращения к
datasource, а неполный discovery snapshot не публикуется. Эта optional feature
сама по себе не переводит readiness в ошибку.

Пример:

```yaml
- name: orders_by_created_day
  mode: grouped
  source: {schema: application, name: orders}
  projection:
    - {kind: time_bucket, field: created_at, unit: day, timezone: UTC, alias: created_day}
    - {kind: measure, function: count_all, alias: orders_count}
  maximum_limit: 100
  required_index: idx_orders_created_at
  maximum_rows_examined_per_scan: 100000
  allow_temporary_table: true
  allow_filesort: true
```

```yaml
query:
  allow_filtering: true
  allow_group_by: true
  allow_sorting: false
  allowed_filter_operators: [eq]
  allowed_aggregates: [count, max]
  aggregate_shapes:
    - name: orders_for_status
      mode: scalar
      source:
        schema: application
        name: orders
      projection:
        - kind: measure
          function: count_all
          alias: orders_count
        - kind: measure
          function: max
          field: created_at
          alias: latest_created_at
      filter:
        kind: predicate
        field: status
        operator: eq
        value_types: [string]
      required_index: idx_orders_status
      maximum_rows_examined_per_scan: 100000
```

Shape фиксирует mode, source, ordered projection, полную рекурсивную структуру
filter, тип и arity каждого placeholder и ordered `order_by`. Для grouped mode
также обязателен `maximum_limit`; request limit может быть меньше или равен ему,
а число dimensions не может превышать effective `max_group_by_fields`.
`maximum_limit` и `maximum_rows_examined_per_scan` записываются только как plain
base-10 YAML integers без кавычек, знака, fraction, exponent или digit separators;
любой другой scalar и range overflow блокируют startup до typed decode. Parameter
values намеренно не записываются в policy и не входят в shape.
Коммутативные filter children request и policy канонизируются одним общим
алгоритмом по фиксированным SHA-256 digest поддеревьев; рекурсивный JSON не
вкладывается в строки и не подвергается повторному escaping на каждом уровне.

Все aggregate shapes профиля должны иметь непересекающиеся client-visible
signatures. Startup validation сравнивает mode, source, ordered projection,
полный canonical filter и ordered sorting. Имя shape и execution-only параметры
`required_index` и `maximum_rows_examined_per_scan` не различают запросы.
`maximum_limit` также не различает одинаковые grouped shapes: оба разрешённых
диапазона начинаются с 1 и неизбежно пересекаются. Неоднозначная конфигурация
блокирует запуск вместо runtime-denial любого совпавшего запроса.

Все source, field, alias, order target и другие portable identifiers shape
используют тот же предел 128 ASCII bytes, что request schema. Каждый predicate
shape содержит не более 200 `value_types`, даже если профиль задаёт больший
суммарный `max_parameters`; иначе соответствующий request невозможно выразить
через OpenAPI и policy блокирует startup.

`required_index` — portable MySQL identifier из доверенной конфигурации. Adapter
сам добавляет quoted `FORCE INDEX`, до компиляции требует видимый index и
проверяет тот же index в JSON-плане.
`maximum_rows_examined_per_scan` — положительный `uint64`; missing, malformed,
fractional или превышенный estimate отклоняет запрос с
`422 UNSUPPORTED_QUERY`. Это эвристический admission threshold, а не жёсткий
source-row limit: оператор обязан выбирать действительно selective indexed
shapes, короткие deadlines и подходящие DB grants.

Output names и order targets проверяются case-insensitively по MySQL semantics.
`count_all` и `count` требуют policy value `count`; `count_distinct` требует
отдельный `count_distinct`. Shape с filter/grouping/sorting также требует
соответствующий feature flag и operator allowlist. Структурно некорректный или
несовместимый с feature allowlist shape блокирует startup; точное отсутствие
единственного совпадения с запросом закрывается в runtime до обращения к БД.

Aggregate имеет ту же row/field confidentiality scope, что и обычный SELECT.
Он не является способом дать доступ только к «обезличенной статистике»:
dimensions и повторные filters могут восстановить отдельные значения. Поэтому
resources/fields профиля должны разрешать principal прямое чтение охваченных
строк и колонок.

## Limits

```yaml
limits:
  deadline_ms: 3000
  max_request_bytes: 65536
  max_projection_fields: 50
  max_group_by_fields: 50
  max_order_by_fields: 50
  max_predicates: 50
  max_expression_depth: 8
  max_parameters: 100
  max_rows: 1000
  max_result_bytes: 1048576
  max_offset: 10000
  max_concurrency: 2
```

Эффективные лимиты вычисляются как наиболее строгое пересечение system hard limits и profile limits. System hard limits нельзя повысить параметрами API или профиля. `group_by` и `order_by` ограничиваются сначала protocol maximum в 100 элементов, затем соответствующим effective limit профиля.

Для размера request глобальный hard limit применяется при чтении body, а
меньший effective profile limit — после strict decode, когда profile уже
извлечён из JSON. Это per-request semantic limit, а не ingress memory quota.

Реализация также устанавливает абсолютные безопасные maxima: `deadline_ms` —
300000, request и result — по 16777216 bytes, expression depth — 64,
predicates и parameters — по 10000, rows — 1000000, offset — 1000000000,
concurrency — 1024. Конфигурация вне этих границ отклоняется при запуске.
Datasource pool дополнительно ограничен 1024 connections и lifetime в 86400
seconds, чтобы исключить переполнение duration и неограниченный pool.

## Загрузка

При запуске gateway:

1. Проверяет строгую схему конфигурации.
2. Отклоняет неизвестные поля.
3. Проверяет уникальность usernames, principals, datasources и profiles.
4. Проверяет все ссылки между разделами.
5. Проверяет регистрацию adapters.
6. Проверяет, что limits не превышают hard limits.
7. Разрешает обязательные credential и DSN secret references.
8. Компилирует immutable policy snapshot.
9. Вычисляет канонический fingerprint разобранного snapshot с фиксированными
   маркерами вместо inline bcrypt hashes и DSN, затем публикует fingerprint и
   версию в audit metadata. Изменения форматирования и значений секретов не
   меняют fingerprint; изменения authorization policy и limits меняют.

Первая версия применяет изменения после restart. Возможный hot reload сначала полностью компилирует новый snapshot, затем заменяет старый атомарно.

## Решение policy engine

```text
Decision
  allowed
  reason_code
  principal
  policy_profile
  datasource
  required_capability
  policy_version
  effective_limits
  referenced_resources
  referenced_fields
```

Reason codes стабильны. Текстовое объяснение может меняться и не используется клиентом для ветвления логики.
