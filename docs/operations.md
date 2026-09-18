# Эксплуатация

## Формы запуска

Gateway поставляется как Go binary и поддерживает два режима размещения:

- local mode на машине разработчика с доступом к DBMS;
- server mode рядом с DBMS или в доверенном сетевом сегменте.

Процесс запускается под отдельной непривилегированной OS account. Для server mode рекомендуются read-only root filesystem, запрет privilege escalation и явные ingress/egress rules.

## Периметр и принятые риски

Quordon сознательно является внутренним application service, а не публичным
edge-компонентом. Его HTTP listener не поддерживает терминацию HTTPS. В процессе
также отсутствуют rate limit запросов и попыток входа, WAF, IP filtering,
DDoS/DoS-защита и admission control до аутентификации и разбора JSON.

Это принятые ограничения MVP, а не заявленные гарантии безопасности. Текущая
модель угроз не включает прямое публичное размещение, multi-tenant эксплуатацию
для недоверенных клиентов или обеспечение доступности при намеренном flooding.
Для remote mode внешний ingress или reverse proxy обязан терминировать HTTPS и
реализовать необходимые сетевые ACL, rate limits, connection/body/time limits,
ограничение параллелизма и, где требуется, WAF/DDoS controls. Между ingress и
Quordon HTTP допустим только внутри доверенного сетевого сегмента.

Эта граница не делает программный агент доверенным относительно данных. Каждый
его прикладной запрос по-прежнему проходит Basic Auth, строгую validation,
policy authorization и обязательный аудит.

## Local mode

Безопасные defaults:

- bind только на `127.0.0.1` и `::1`;
- запрет wildcard interface без явного server configuration;
- Basic Auth обязателен и на loopback;
- plaintext HTTP допустим только при явно включённом local mode;
- небольшой connection pool;
- короткие deadlines;
- secrets из environment, OS credential store или защищённого файла;
- audit в локальный структурированный sink.

Запуск на машине разработчика не расширяет его сетевые или DB grants: gateway использует только предоставленные credentials и доступные маршруты.

Доверенный человек управляет процессом и policy, а локальный агент считается
недоверенным относительно доступа к данным. Намеренный authenticated HTTP flood
и гарантированная доступность самого локального gateway не входят в MVP; после
остановки или перегрузки процесс может быть перезапущен оператором.

## Server mode

Минимальные требования:

- HTTPS termination на внешнем ingress и TLS для DB connections;
- отдельный OS user;
- входящие connections только от разрешённых API clients;
- исходящий доступ только к настроенным datasources, audit sink и secret provider;
- secrets в mounted credentials или внешнем secret provider;
- отдельный DB user и pool для каждого требуемого security profile;
- внешний ingress admission/concurrency control до передачи запросов gateway;
- systemd hardening либо эквивалентные container restrictions.

Совместное размещение с MySQL допустимо, но gateway не запускается от пользователя `mysql`, не получает доступ к data directory и не получает административные grants.

## Несколько datasources

На каждый datasource создаётся отдельный `sql.DB` pool со своими limits и health state:

```text
datasource -> adapter -> credentials -> connection pool -> capability set
```

Недоступность одного необязательного datasource не должна останавливать остальные. Readiness policy определяет, какие datasources обязательны для готовности экземпляра.

Один datasource обязан вести на один MySQL-сервер либо на логический кластер с
одинаковым `lower_case_table_names` на всех backend-серверах. Балансировка между
серверами с различной identifier semantics в MVP не поддерживается; такие
серверы настраиваются как отдельные datasources.

## Basic Auth

Basic credentials передаются и проверяются в каждом прикладном request. Заголовок `Authorization` удаляется из access и application logs.

Ротация password hash выполняется через secret provider. После ротации новая версия применяется при restart; hot reload credentials не входит в MVP.

Authentication failures не различают unknown username и wrong password в HTTP response. Встроенного лимита попыток нет; защита от перебора credentials возлагается на внешний ingress и сетевой периметр.

## Health checks

### Liveness

`GET /health/live` проверяет только способность процесса обслужить HTTP request.

### Readiness

`GET /health/ready` проверяет:

- policy snapshot загружен и валиден;
- Basic Auth secret references разрешены;
- adapters зарегистрированы;
- pools обязательных datasources созданы;
- обязательные database endpoints доступны;
- обязательный audit sink доступен.

Readiness не раскрывает DSN, usernames или raw connection errors.

## Ограничение нагрузки

Защита применяется на нескольких уровнях:

- HTTP body limit;
- structural limits `QuerySpec`;
- глобальный и профильный concurrency limits;
- ограниченный connection pool;
- DBMS-specific server-side timeout;
- request context deadline;
- max rows и max serialized bytes.

При исчерпании concurrency capacity gateway возвращает HTTP `503 CAPACITY_EXCEEDED`.

В MVP `max_concurrency` ограничивает прошедшие decode, validation, identifier
semantics lookup и policy authorization DB operations. Capacity захватывается
после обязательного allow/deny decision, поэтому policy-denied запрос не
подменяется ответом `CAPACITY_EXCEEDED`. Лимит не охватывает Basic Auth, чтение
HTTP body или построение JSON request tree. Глобальный
`max_request_bytes` является pre-decode лимитом одного request; меньший лимит
profile проверяется после строгого decode. Это защищает от случайно крупных
запросов и ограничивает нагрузку на DBMS, но не является защитой от намеренного
параллельного flooding аутентифицированным локальным агентом. Для server mode
такая защита обеспечивается внешним ingress до допуска недоверенных клиентов.

Structural validation прекращает обход filter tree сразу при достижении
effective limits глубины, числа predicates или bind parameters. Невалидные
деревья ограничены hard body/depth bounds, но их decode выполняется до входа в
execution capacity gate. Identifier semantics lookup также выполняется до
capacity, поскольку его результат необходим для корректной resource
authorization; datasource pool отдельно ограничивает число таких обращений.

## MySQL 8 query operations

Capability `explain_select` выполняет только `EXPLAIN FORMAT=JSON` над `SELECT`,
скомпилированным MySQL 8 adapter. Поддерживается MySQL `>= 8.0, < 9.0`; MySQL
5.7, MySQL 9 и MariaDB отклоняются как недоступный datasource. Product/version
проверяется readiness probe и в operation path. `EXPLAIN ANALYZE`,
`FOR CONNECTION` и выбор произвольного формата клиентом запрещены.

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

Statistics сохраняет контракт физических InnoDB-метрик; разрешённый view даёт
`422 UNSUPPORTED_QUERY`. Endpoint не выполняет scan или точный COUNT; estimates
могут быть stale и не образуют DML snapshot.

Timeout обеспечивается одновременно request context и MySQL server-side setting. После timeout или protocol error соединение возвращается в pool только после подтверждённого reset; иначе закрывается.

Абсолютный operation deadline закрепляется за MySQL connection и ограничивает
в том числе не принимающие context `Commit`/`Rollback`. Если срабатывает именно
этот socket deadline, driver сохраняет `context.DeadlineExceeded`, поэтому API
и audit классифицируют результат как timeout (`504`), а не datasource outage.

При раннем отказе после получения первой строки adapter дочитывает terminator
при ещё активном request context и только затем вызывает `Rows.Close`. Поэтому
зависший cleanup также ограничен query deadline и не удерживает concurrency
capacity бессрочно.

Schema discovery читает table/view metadata и фильтрует objects/columns
через профиль. Effective result budget применяется после этой фильтрации;
закрытые objects и columns его не расходуют. Отдельный абсолютный adapter bound
ограничивает ещё не отфильтрованное чтение metadata. `select` использует
field-only QuerySpec, read-only transaction,
server-side timeout и `LIMIT normalized_limit + 1`; дополнительная строка нужна
только для вычисления `truncated` и клиенту не возвращается. Binary values
и spatial values кодируются base64, остальные ненулевые values — строками.
Adapter принудительно отключает driver `parseTime` и `columnsWithAlias`, а
connection collation фиксирует в `utf8mb4_general_ci`; поэтому temporal values,
имена колонок и UTF-8 text не зависят от DSN. DSN option `charset` отклоняется,
поскольку драйвер не позволяет безопасно нормализовать его после parsing.
Effective byte budget может дать пустой либо непустой безопасный префикс;
encoded size строки проверяется до выделения string/base64/row JSON, поэтому
большое значение с интенсивным JSON escaping не создаёт многократную временную
копию сверх effective budget. Сам входящий MySQL packet всё равно читается в
пределах абсолютного bound. Отдельный абсолютный logical-packet bound 16 MiB
плюс 1 KiB framing allowance
остаётся жёстким и при превышении возвращает `RESULT_TOO_LARGE`.

Перед включением `select` operator обязан проверить, что разрешённая таблица не
требует row-level isolation: текущий MVP не добавляет tenant predicates. Также
следует выбирать curated indexed filters и короткий deadline: response `LIMIT`
не ограничивает объём scan и не заменяет анализ плана.

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

Shapes проверяются на production-like statistics и пересматриваются после
изменений схемы или распределения данных. Cursor values и rows не записываются
в audit; completion сохраняет shape name, row count и has_more.

Для профилей с `list_query_shapes` core до открытия HTTP listener один раз
получает identifier semantics datasource и строит неизменяемый disclosure-safe
snapshot. Постоянная несовместимость shape с resource/field policy, response
budget или публичным контрактом блокирует запуск. Временная недоступность
datasource оставляет snapshot неопубликованным; для required datasource это
также делает readiness неготовым, для optional — только скрывает capability и
оставляет прямой запрос с `503` до перезапуска. HTTP-путь `/query-shapes` не
получает connection и не вызывает adapter. Единственный JSON-контракт содержит
все shapes; прежние vendor media types отклоняются с 400. Наблюдение другой операцией новых
identifier semantics атомарно инвалидирует все snapshots этого datasource;
автоматического refresh в MVP нет.

До первого datasource probe core без полной JSON-материализации проверяет
16 MiB audit bound для denial каждого настроенного Basic credential и для
`501`/`503` completion каждого доступного ему discovery profile. После
построения snapshot тем же способом проверяются allow/completion с полным
resource/field scope. Любое превышение считается несовместимой конфигурацией и
блокирует запуск, включая случаи без опубликованного snapshot.

HTTP `WriteTimeout` включает полный `ReadTimeout`, максимальный query deadline
и запас на сериализацию ответа. Поэтому допустимое время чтения request body
не расходует дедлайн выполнения запроса и записи ответа.

## Неподдерживаемые возможности

Если endpoint присутствует в API, но выбранный adapter не реализует capability, core возвращает HTTP `501 CAPABILITY_NOT_IMPLEMENTED` до получения соединения из pool.

Если adapter объявил capability, но не реализует обязательный для неё Go
interface, manager считает это постоянной ошибкой конфигурации до разрешения
secret и открытия datasource. Такой процесс не начинает обслуживать HTTP.

Capabilities должны быть видны в `/capabilities`, чтобы клиент мог не вызывать неподдерживаемые операции. Ответ также публикует `api_version` и `service_version`, поскольку внутренние routes не содержат version prefix.

## Cancellation

Cancellation не входит в MVP. Adapter может объявить `cancel_query` только после integration test, подтверждающего остановку server-side statement и безопасный lifecycle соединения.

Несколько экземпляров gateway потребуют shared query registry либо sticky routing к экземпляру-владельцу. До появления такого механизма отсутствие cancellation возвращает `501`.

## Метрики

```text
http_requests_total{operation,status_class}
authentication_attempts_total{outcome}
policy_decisions_total{operation,decision,reason_code}
adapter_operations_total{adapter,operation,outcome}
query_duration_seconds{operation,profile,adapter,outcome}
query_result_bytes{operation,profile,adapter}
query_timeouts_total{profile,adapter}
database_pool_connections{datasource,state}
database_up{datasource}
audit_write_failures_total
```

QuerySpec hash, resource name и principal не используются как metric labels высокой кардинальности.

## Логи и аудит

Application logs и security audit являются разными структурированными потоками.

Все records содержат `request_id`; DB operation получает `query_id`.
Аутентифицированные query records содержат отдельно policy `principal` и
`client_identifier` с Basic username. Basic password, `Authorization` header,
query values, compiled SQL, DSN и raw driver errors не логируются.

Allow decision и completion event содержат один и тот же нормализованный
`query_shape_hash`, в том числе при timeout, недоступности datasource,
превышении размера результата и других ошибках выполнения. Hash учитывает
структуру запроса, типы и количество параметров, но не их значения.
Неуспешный completion event сохраняет безопасный стабильный `error_kind`:
`invalid`, `timeout`, `unavailable`, `result_too_large` либо `upstream`; raw
driver error в audit не попадает. `invalid` используется, в частности, когда
source либо field отсутствует или plan не проходит admission. Отказ MySQL в доступе или
аутентификации datasource (1044/1045) классифицируется как `unavailable` и
возвращается клиенту как `503 DATABASE_UNAVAILABLE`.
Детерминированный отказ keyset admission, когда сервер не может выдать cursor,
помещающийся в следующий request, возвращается как HTTP `413
REQUEST_TOO_LARGE`, но в completion audit относится к стабильному классу
`invalid`: внешний HTTP code и audit `error_kind` описывают разные уровни
контракта.
Если datasource недоступен до авторизации ресурса или adapter не может получить
семантику identifiers, completion event всё равно содержит `query_shape_hash`
и `error_kind`, но не помечает запрошенные resources и fields как разрешённые.
Allow decision и completion также содержат авторизованные schema/object и
исходные fields. Успешный completion записывает размер plan/row payload в
`result_bytes`; SELECT metadata содержит `row_count` и `truncated`, но не row
values. Поле `duration_ms` присутствует в completion даже при значении
`0`, если операция заняла меньше одной миллисекунды; в decision event оно
отсутствует. Denial audit не отменяется при разрыве клиентского HTTP-соединения
и ограничивается собственным timeout audit sink.

`policy_hash` детерминирован по разобранному authorization policy, но не
содержит inline credential material: bcrypt hashes и DSN перед вычислением
заменяются постоянными маркерами.

Сбой обязательного audit sink переводит readiness в false. Операции fail closed, если невозможно зафиксировать обязательное decision event.

## Ротация DB credentials

1. Secret provider публикует новую версию.
2. Gateway создаёт новый datasource pool.
3. Adapter проверяет connection и session restrictions.
4. Новые requests переключаются на новый pool.
5. Старый pool дренируется и закрывается.

MVP может выполнять эту процедуру через restart. In-process rotation добавляется после появления атомарной замены pool.

## Graceful shutdown

После `SIGINT` или `SIGTERM` сервис прекращает принимать новые соединения и до
10 секунд ожидает завершения активных HTTP handlers, включая DB operation и
обязательный completion audit. Datasource pools закрываются только после
завершения этого ожидания. По истечении срока соединения принудительно
закрываются, а процесс завершается с ненулевым кодом.

## Аварийные режимы

- authentication dependency unavailable: `503`, операция не выполняется;
- invalid policy: сервис не становится ready;
- missing adapter capability: `501`;
- datasource unavailable: `503`;
- request timeout: `504`;
- adapter/compiler internal error: `500`, SQL не выполняется;
- audit sink unavailable: readiness false и новые операции fail closed;
- подозрение на ошибку adapter: отключить profile или datasource.

## Последовательность внедрения

1. Local MySQL 8 с production-подобной minor version и scoped `SELECT` grants.
2. MVP explain в local mode.
3. Staging server mode.
4. Production explain profile.
5. Второй adapter и общий contract suite.
6. Schema и SELECT capabilities отдельными этапами.

Для диагностики ошибочных исторических temporal values profile явно включает
`allow_source_text: true` и задаёт `representation: source_text` в нужных shapes.
SQL modes и DB grants для этого не расширяются. Диагностические expressions
остаются под плановыми bounds; переход на text ordering не гарантирует сохранение
индексного плана. Discovery clients используют `application/json`, включая
timebook-mcp (`representation=v1` выбирает этот media type; default v3 требует
отдельного обновления инструмента).
