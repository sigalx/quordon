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

Рабочий policy и каждый подключаемый YAML-файл обязаны быть обычными файлами
с точными правами `0600`. Проверка открытого descriptor
выполняется до разбора YAML и запуска зависимостей; любой другой режим приводит
к отказу в запуске:

```bash
install -m 600 config/policy.example.yaml config/policy.yaml
```

## Локальные `$ref` и `$override`

В 0.1.3 ссылки заменяют узел целиком: profile, allow/deny-list, список shapes,
отдельный shape, limits или scalar. Runtime получает обычный `Config`. Клиент
выбирает назначенный profile; один profile связан ровно с одним datasource.
HTTP API, authorization tokens и discovery используют итоговую policy.

```yaml
profiles:
  reader:
    $ref: './policy.d/bundle-001/reader.yaml'
  rc-reader:
    $ref: './policy.d/bundle-001/reader.yaml'
    $override:
      datasource: rc-backend
```

`reader.yaml` содержит полный профиль, включая datasource. Новый профиль
нужно явно назначить в `principals.<name>.profiles`. Полный пример:
[config/policy.references.yaml](../config/policy.references.yaml).

Узел ссылки содержит только непустую string `$ref` и optional mapping
`$override`. Другие соседние fields, override без ref, неверные types и null
запрещены. Поддерживаются внутренний pointer `#/profiles/reader`, файл целиком
`./reader.yaml` и фрагмент `./common.yaml#/deny_fields`. Фрагмент — URI-форма
[JSON Pointer, RFC 6901](https://www.rfc-editor.org/rfc/rfc6901.html): точные
имена, `~0` для `~`, `~1` для `/`, UTF-8 percent-encoding и zero-based array
indices без ведущих нулей. `-` не выбирает существующий элемент.

Путь считается от документа ссылки. Вложенные ссылки сохраняют свой исходный
файл; значения override используют документ override. Сначала полностью
разрешается база, затем override. Override разрешён только над mapping и
целиком заменяет или добавляет непосредственные поля. Deep merge, объединения
массивов и удаления через null нет. Для изменения только одного limit:

```yaml
limits:
  $ref: './common.yaml#/limits'
  $override:
    max_rows: 500
```

Missing target, неправильный pointer, цикл и ошибки разрешения базы блокируют
загрузку, даже если ошибочная ветка заменяется. `$override` — расширение Quordon;
совместимость с OpenAPI Reference Object не заявляется. Библиотечные документы
имеют произвольную структуру; итоговая конфигурация сохраняет закрытую схему.
Template sections, параметры и генерация shapes не вводятся.

Разрешены относительные локальные пути внутри каталога основного policy.
URI schemes, authority, абсолютные пути, query strings и выход за корень
запрещены до открытия цели. Переход из подкаталога к соседнему файлу внутри
корня допустим. Symlinks внутри корня разрешены; [`os.Root`](https://go.dev/blog/osroot)
защищает открытие от traversal, включая symlink escape и races. Regular file и
точный режим `0600` проверяются на открытом descriptor.

Каждый файл содержит один YAML-документ. Duplicate keys, нестроковые keys,
merge keys, recursive aliases, unknown tags и invalid UTF-8 запрещены. Обычные
anchors/aliases сохраняются и учитываются после раскрытия. Scalar types
сохраняются без coercion; explicit null запрещён. Native YAML integer/boolean
spellings сохраняются; прежние canonical-decimal и literal-boolean rules shapes
и `allow_source_text` продолжают действовать.
После сборки types и required/presence rules проверяются до typed decode.
Затем semantic validation проверяет shapes, resources и effective limits;
все эти проверки завершаются до runtime initialization.

| Бюджет | Фиксированный предел |
| --- | --- |
| Один файл / inline input | 8 MiB |
| Все прочитанные файлы | 16 MiB |
| Документы | 64 |
| Глубина структуры и раскрытия | 64 |
| `$ref`, UTF-8 bytes | 4096 |
| Исходные / раскрытые узлы | 250 000 / 250 000 |
| Собранное JSON-представление | 16 MiB |

Пределы применяются и к inline-синтаксису. Document wrapper не считается узлом.
Source limits проверяются parser до выделения очередного AST node. Expanded
budget включает aliases, refs и промежуточную базу override. Encoded size
проверяется до материализации. Каждый нормализованный document URI читается
один раз за загрузку; кэш неизменяемый, typed profiles и snapshots не разделяют
mutable maps/slices. При одинаковой версии и effective policy canonical
redacted fingerprint одинаков для inline/ref: пути и разбиение его не меняют.

`config.LoadFile(path)` выполняет файловую сборку. `config.Load([]byte)`
поддерживает inline и внутренние ссылки; внешние refs отклоняются без filesystem
access. Diagnostic содержит `POLICY_*` code, ordinal документа, line/column и
цепочку числовых позиций refs. Основной документ — 1, остальные нумеруются при
первом чтении. Filename, pointer, YAML snippet, keys/values и raw decoder/OS
errors не выводятся.

## Проверка без внешних зависимостей

```bash
quordon --check-config --config /etc/quordon/policy.yaml
```

Команда собирает policy, проверяет строгие types/presence и общую semantic
validation. Adapters, БД, credential resolvers и HTTP listener не запускаются.
Режим не подтверждает adapter registration, DSN options, DB readiness, grants
или физическую совместимость shapes. Exit codes: `0` — успешно, `1` — ошибка
конфигурации, `2` — ошибка аргументов. Сочетание с `--version` запрещено.
`--listen` проверяется как обычный address override.

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

Перед обновлением бинарника оператор удаляет `ddl_guard_mode` из конфигов.
Старое поле является unknown configuration field и блокирует startup; режима
совместимости с игнорированием нет. В audit поле режима отсутствует. HTTP shapes
и единый JSON discovery используются; execution-only controls не публикуются.

Один процесс может содержать несколько datasources, включая несколько серверов одной DBMS. Для каждого datasource создаётся отдельный pool и отдельное health state.

Все query operations поддерживают разрешённые таблицы и доверенные views.
Statistics сохраняет физические InnoDB-метрики: разрешённый view даёт
`422 UNSUPPORTED_QUERY`; denied/missing/non-InnoDB objects дают `404 NOT_FOUND`.

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

Типы cursor не задаются в YAML: concrete adapter выводит их из metadata
настроенных `NOT NULL` order-by колонок. Автор shape гарантирует уникальность tuple. Общий API поддерживает `integer`, `string`,
`bytes`, `date`, `datetime` и `timestamp`; temporal wire values ограничены
годами `0001`–`9999` и девятью знаками дробной секунды. MySQL 8 adapter допускает
для key columns соответственно integral, `CHAR`/`VARCHAR`,
`BINARY`/`VARBINARY`, `DATE`, `DATETIME` и `TIMESTAMP`, затем проверяет свой
физический диапазон и точное FSP 0–6. Оператору не нужно и нельзя указывать SQL
cast или нативный driver type в shape.

Суммарное число `aggregate_shapes` и `keyset_select_shapes` в одном profile не
может превышать 1000 независимо от наличия `list_query_shapes`. Ограничение
действует и для непубликуемых shapes, поскольку они участвуют в authorization
matching на request path.

`list_query_shapes` можно включить вместе с `select_keyset`, чтобы JSON discovery
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

`required_index` — необязательный execution-only portable identifier.
Omission означает отсутствие условия; явные `null`, пустая строка и неверный тип
блокируют startup. SQL index hints и проверка наличия индекса на запрошенном
объекте отсутствуют. Если индекс задан, хотя бы один физический узел чтения
принятого плана обязан его использовать; индекс materialized result не подходит.

MySQL 8 JSON EXPLAIN не экранирует пунктуацию имён в `index_merge.key`.
Адаптер проверяет полные native identities из `possible_keys` и число отдельных
`key_length`. Merge-планы с `(`, `)` или `,` в candidate index names отклоняются
с `422 UNSUPPORTED_QUERY`, в том числе без `required_index`: их неоднозначное
представление не позволяет подтвердить используемые индексы. В остальных access
types `key` сравнивается как целое имя.
Физический источник определяется по структуре плана, а не по имени alias:
alias вроде `<orders>` сам по себе не обозначает materialized result.

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

### Numeric bucket shapes

`numeric_bucket` разрешён только в grouped aggregate. Policy output содержит
`kind`, исходный `field`, уникальный `alias` и `boundaries`: 1–64 настоящие YAML
strings, каждая до 128 ASCII bytes, с fixed-point decimal grammar
`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$`. Exponent, `+`, whitespace, leading zeros,
NaN и Infinity запрещены. Порядок проверяется точным сравнением без `float64`;
численно равные соседние границы отклоняются. До fingerprint дробные trailing
zeros удаляются, отрицательный ноль становится `0`.

```yaml
- name: operations_by_duration
  mode: grouped
  source: {schema: application, name: operations}
  projection:
    - kind: numeric_bucket
      field: duration_ms
      alias: duration_bucket
      boundaries: ["0", "100", "500", "1000"]
    - {kind: measure, function: count_all, alias: operations_count}
  order_by:
    - {kind: numeric_bucket, alias: duration_bucket, direction: asc}
  maximum_limit: 20
  maximum_rows_examined_per_scan: 100000
  allow_temporary_table: true
  allow_filesort: true
```

Оба execution controls обязательны и должны быть явными YAML booleans, включая
`false`. Optional `required_index`, plan estimate admission, grouping/sorting
permissions, denylist исходного поля, output collisions и effective limits
сохраняются. Для numeric output запрещены `function`, `unit`, `timezone` и
`representation`; `boundaries` запрещён во всех остальных output branches и
в orders. Order numeric bucket задаётся только `kind`, `alias`, `direction`.
Один source можно группировать несколькими numeric buckets с разными aliases.

Request signature включает поле и alias, но исключает границы. Два shapes с
одинаковой клиентской формой и разными границами блокируют startup; различать
их можно aliases. Границы включены в redacted policy fingerprint и публичный
discovery hash, глубоко копируются в snapshots и authorization token.

Для N границ индекс 0 означает ниже первой, i — `[boundary[i−1], boundary[i])`,
N — от последней включительно. Output имеет `type: integer`, `encoding: string`,
nullable по исходной metadata; только DB NULL становится null. Пустые группы
не добавляются. Подробнее о сортировке и результате — в [API](api.md).

В `max_parameters` входят все повторы границ в projection, GROUP BY и numeric
ORDER BY, filter parameters и server-owned LIMIT. Например, четыре границы с
одним numeric order без filter требуют `4 × 3 + 1 = 13` parameters.
Конфигурация сверх effective budget отклоняется при загрузке до SQL construction.

`--check-config` проверяет сборку, grammar, порядок и общие budgets без adapters,
metadata или планов БД. Физические source types и representability границ
проверяются MySQL adapter до EXPLAIN: точные INTEGER/DECIMAL поддерживаются,
FLOAT/DOUBLE и нечисловые поля дают `422 UNSUPPORTED_QUERY`. Граница не обязана
помещаться в диапазон самого источника; требуется точный MySQL
`DECIMAL(p,s)` cast с `p ≤ 65`, `s ≤ 30`, без округления. MySQL compiler
повторяет тот же CASE для grouping и возвращает/сортирует `MIN(CASE …)`:
индекс одинаков внутри каждой группы, а aggregate wrapper позволяет подготовить
statement с разными placeholders при сохранённом `ONLY_FULL_GROUP_BY`.

Без cached feature `numeric_bucket_exact` execution и discovery всего профиля
возвращают `501 CAPABILITY_NOT_IMPLEMENTED` без datasource calls. Неполный
snapshot не публикуется; сама optional feature не блокирует readiness.

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

1. Ограниченно читает открытые regular `0600` descriptors, проверяет AST и
   собирает refs/overrides, затем проверяет строгую схему конфигурации.
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

## Исторические даты и `source_text`

`query.allow_source_text` — optional strict YAML boolean с default `false`.
Явные null, строки и числа запрещены. Диагностические shapes требуют `true` при
startup; unsupported adapter feature также блокирует startup до подключения к БД.
Обычные policies без диагностических shapes сохраняют прежнее поведение.

В projection, predicate filter, ordering и aggregate dimension можно явно задать
`representation: source_text`. В опубликованном discovery member сохраняется;
`value_types` таких predicates содержит только `string` (либо пуст для null
operators). Representation входит в shape matching и fingerprints. Нельзя
указывать его на group, measure или time bucket. Представление keyset order
должно совпадать с единственной проекцией этого ключа.

MySQL поддерживает диагностический текст DATE/DATETIME/TIMESTAMP и сохраняет
нулевые, неполные и невозможные даты. Корректные календарные DATE/DATETIME
поддерживаются начиная с `0001` года, TIMESTAMP сохраняет прежний диапазон.
Автор keyset shape гарантирует уникальность ordered tuple именно при выбранном
представлении и побайтовом сравнении. Текстовые casts могут потребовать scan или
filesort, поэтому отдельно настроенные execution bounds остаются обязательными.
