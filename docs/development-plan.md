# План разработки

## Зафиксированные решения

- язык и целевая toolchain — Go 1.26;
- внешний API не принимает SQL;
- core не зависит от DBMS;
- DBMS-specific поведение реализуется compile-in adapters;
- несколько datasources могут обслуживаться одним процессом;
- один процесс реализует одну major-версию API, а его routes не содержат version prefix;
- публичные version prefixes и маршрутизация между major-версиями принадлежат border proxy;
- отсутствие capability у адаптера приводит к HTTP `501`;
- MVP использует MySQL 8.x (`>= 8.0, < 9.0`), HTTP Basic Auth,
  policy-filtered schema discovery, `EXPLAIN FORMAT=JSON` и ограниченный
  field-only `SELECT`, а также отдельную capability для ограниченных агрегатов;
  MariaDB не поддерживается;
- `EXPLAIN ANALYZE`, aggregates/grouping в обычном исполняемом `SELECT` и
  row-level security не входят в текущий MVP;
- Quordon не является публичным edge-сервисом: HTTPS termination, rate
  limiting, WAF и DDoS/DoS controls остаются ответственностью ingress и не
  входят в threat model процесса.

## Этап 0. Контракт MVP

- поддерживаемый диапазон зафиксирован как MySQL `>= 8.0, < 9.0`;
- утвердить OpenAPI для `QuerySpec` и explain;
- согласовать Basic Auth credential provider;
- согласовать hard limits;
- описать минимальные grants пользователя MySQL;
- подготовить корпус структурированных запросов и ожидаемого SQL;
- определить обязательный audit sink для local и server modes.

Критерий завершения: для каждого MVP endpoint известны principal, profile, datasource, adapter, DB user, capability и effective limits.

## Этап 1. Go core без базы данных

- Go module и `cmd/quordon`;
- HTTP server и request IDs;
- Basic Auth на каждом прикладном запросе;
- strict request decoding;
- strict configuration loader;
- immutable policy snapshot;
- чистый policy engine;
- adapter registry и capability checks;
- liveness и readiness;
- decision audit;
- API и policy unit tests.

Критерий завершения: синтетические `QuerySpec` приводят к воспроизводимым allow/deny решениям, неизвестная конфигурация блокирует запуск, а отсутствующая capability возвращает `501` без вызова adapter executor.

## Этап 2. MySQL 8 explain vertical slice — MVP

- MySQL 8 driver через `database/sql`;
- отдельный pool для datasource;
- типы `ValidatedQuerySpec`, `AuthorizedQuerySpec` и `CompiledQuery`;
- MySQL identifier mapping и quoting;
- runtime validation product/version и `lower_case_table_names`;
- таблицы и trusted views с одинаковой authorization boundary;
- безопасность views и изменения схемы — доверенная обязанность администратора;

- компиляция ограниченного `SELECT`;
- только `EXPLAIN FORMAT=JSON`;
- bind parameters;
- server-side timeout;
- concurrency limits;
- result size limit;
- completion audit;
- integration tests на поддерживаемых MySQL 8 versions;
- подтверждение отсутствия `EXPLAIN ANALYZE` и других исполняющих режимов.

Критерий завершения: аутентифицированный и авторизованный клиент получает JSON plan для структурированного запроса, а неавторизованные, неподдерживаемые и превышающие лимиты операции завершаются до выполнения SQL.

## Этап 3. Минимальные schema operations — выполнен

- list objects;
- describe object;
- object definition как отдельная capability — отложена;
- фильтрация metadata по политике;
- integration tests grants;
- result sanitization.

Критерий завершения: schema endpoints возвращают только разрешённые объекты, а запрещённые объекты неразличимы по внешним ошибкам.

## Этап 4. Второй адаптер

- выбрать PostgreSQL как второй reference adapter;
- реализовать тот же общий contract;
- разделить общие и vendor-specific capabilities;
- запустить единый adapter contract suite на MySQL и PostgreSQL;
- скорректировать QuerySpec до стабилизации API major version `1`.

Критерий завершения: core и OpenAPI не содержат скрытых MySQL-only предположений, а различия DBMS изолированы в adapters.

## Этап 5. Ограниченный SELECT — минимальный vertical slice выполнен

- endpoint выполнения того же `QuerySpec`;
- column policy;
- curated resources;
- max rows, max bytes и `truncated` semantics;
- проверенная cancellation для адаптеров, которые её объявляют — отложена;
- security acceptance tests.

Текущий slice принимает только field projections, без aggregates и `group_by`.
Row-level isolation отсутствует: operation включается только для curated
resources, все строки которых доступны назначенному principal. Следующее
расширение этого этапа — обязательные policy predicates либо отдельная модель
row scopes, а затем cost controls/cancellation.

Критерий завершения: профиль `select` включается независимо для каждого datasource и adapter capability set.

## Этап 5.1. Ограниченный AGGREGATE — выполнен

`openapi/aggregate.yaml` является исполняемым модулем корневого контракта.
Реализация:

- читать настроенный объект с columns, включая views;
- явно установить REPEATABLE READ и открыть read-only transaction;
- проверить exact SELECT через EXPLAIN на том же connection;
- проверить estimates каждого read node и optional physical-index constraint;
- temporary/filesort work требует execution-only opt-ins, default false;

- считать `count_all` и `count(field)` существующим policy feature `count`, а
  `count_distinct` — отдельным opt-in feature, не включаемым через `count`;
- включает configuration validation, отдельный operation-bound authorization
  token, strict runtime decoder/handler и двунаправленные OpenAPI 3.1 fixtures.

Shape matcher связывает полную normalized query structure: projection order,
AND/OR topology и predicate count, fields/operators, placeholder types/arity,
sort order/directions и limit под policy maximum. Значения параметров в shape не
входят; typed range/enum constraints в текущем MVP не поддерживаются. Частичное
совпадение только по fields/operators запрещено.

Клиент не выбирает index, cost bounds или исключения из preflight. EXPLAIN
estimate является только эвристическим admission signal: stale statistics и
широкий index range могут дать больше фактической работы, и этот residual risk
явно принимает оператор при включении shape. Group `LIMIT` ограничивает только
ответ и не считается source-work control. Если фиксированный response envelope
и column metadata не помещаются в `max_result_bytes`, aggregate не исполняется и
возвращается `413`; только overflow при добавлении rows даёт безопасный prefix с
`200` и `truncated: true`.
Отсутствие совпавшего authorized shape возвращает `403 DENIED_QUERY_FEATURE` и
denial audit до EXPLAIN/aggregate DBMS call; отклонение его плана возвращает
`422 UNSUPPORTED_QUERY`, completion `error_kind: invalid` и не выполняет
aggregate. Aggregate filter groups используют recursive schema с `uniqueItems`;
normalized duplicate predicates/subgroups отклоняются повторно до authorization
token.
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

Критерий завершения: scalar и grouped aggregate проходят unit, contract и MySQL
integration tests; несовпавший shape не обращается к DBMS, rejected plan не
выполняется, а успешный результат остаётся строго bounded и типизированным.

## Этап 6. Production и product hardening

- local mode с безопасным loopback default;
- systemd и container distributions;
- release binaries для Linux, macOS и Windows;
- TLS для DB connections и secret rotation; HTTPS termination для API остаётся
  ответственностью ingress;
- audit retention;
- dashboards и alerts;
- failure injection;
- capacity tests;
- единый `sql.Conn` для identifier semantics, authorization и execution при
  поддержке балансируемых heterogeneous datasource endpoints;
- reference ingress configuration для HTTPS, rate limiting и
  concurrency/admission control вне процесса;
- SBOM, signatures и reproducible releases;
- независимый security review;
- стабильный adapter development contract.

## Первые изменения реализации

1. OpenAPI-generated Go transport types и strict decoder.
2. Basic Auth, principals и policy engine без БД.
3. Общий `QuerySpec` и adapter interfaces.
4. MySQL 8 compiler с golden tests.
5. Vertical slice `POST /queries/explain`.

Такой порядок фиксирует security boundary и переносимый core до появления удобного пути выполнения запросов.
