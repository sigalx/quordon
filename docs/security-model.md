# Модель безопасности

## Защищаемые активы

- DB credentials и TLS-материалы;
- содержимое разрешённых и запрещённых объектов;
- структура закрытых schemas;
- доступность DBMS при выполнении разрешённых запросов;
- Basic Auth credentials;
- целостность policy и adapter implementations;
- достоверность аудита.

## Граница доверия MVP

Основной сценарий первой версии — local mode на машине доверенного разработчика
или оператора. Человек, policy, secrets и конфигурация datasource считаются
доверенными. Программный агент считается недоверенным относительно содержимого
БД: он может формировать произвольные запросы API, менять регистр identifiers и
повторять запрещённые запросы, но не имеет доступа к policy и DB credentials.

MVP защищает конфиденциальность данных и DBMS от тяжёлых разрешённых операций.
Он не заявляет устойчивость локального HTTP-процесса к намеренному flooding со
стороны уже аутентифицированного агента. Глобальный body limit ограничивает один
request, а execution concurrency начинает действовать после decode и validation.
Публичное, недоверенное или multi-tenant размещение требует отдельного ingress
admission/concurrency control и не входит в threat model MVP.

## Сознательно принятые риски и non-goals

Quordon не позиционируется как публичный edge-сервис для недоверенных
клиентов. Текущая модель угроз предполагает доверенного человека-оператора и
контролируемый локальный либо внутренний сетевой периметр. Программный агент при
этом остаётся недоверенным относительно того, какие данные ему разрешено
запрашивать: Basic Auth, policy authorization, безопасная компиляция SQL,
минимальные DB grants и аудит обязательны.

В MVP сознательно не реализуются внутри процесса:

- терминация HTTPS, управление сертификатами, HSTS и mTLS для HTTP API;
- request rate limiting, лимит попыток Basic Auth и пользовательские квоты;
- WAF, IP reputation/block lists и защита от DDoS/DoS или HTTP flooding;
- connection-level admission control и глобальная capacity gate до
  аутентификации, чтения body и JSON decode;
- гарантии доступности при действиях злонамеренного аутентифицированного клиента
  или большом числе параллельных соединений.

Эти риски приняты для текущего MVP и не считаются уязвимостями в рамках его
заявленной модели угроз. Они не отменяют лимиты одного запроса и DB operation,
которые защищают данные и СУБД от ошибочных или чрезмерно тяжёлых запросов.

Если сервис используется удалённо, внешний ingress или reverse proxy обязан
обеспечить HTTPS, сетевые ACL, допустимые размеры и timeouts, rate limiting,
ограничение соединений и параллелизма, а при необходимости WAF и DDoS-защиту.
Прямое публичное размещение Quordon либо использование его как multi-tenant
сервиса для недоверенных клиентов не поддерживается.

## Рассматриваемые угрозы

- обход авторизации через некорректный или неоднозначный `QuerySpec`;
- identifier injection через имена schemas, objects или fields;
- SQL injection через predicate values;
- ошибка DBMS compiler, создающая более широкую операцию;
- доступ к запрещённому полю через aggregation, grouping или sorting;
- тяжёлый разрешённый запрос;
- извлечение большого объёма данных множеством небольших запросов;
- подбор закрытых объектов по различиям errors;
- утечка Basic credentials, parameters или plans через logs;
- использование украденных DB credentials вне gateway;
- несоответствие объявленной capability фактическому поведению adapter;
- вредоносное текстовое содержимое в metadata или результатах.

## Базовые предположения

- gateway работает под отдельной непривилегированной OS account;
- удалённый клиент подключается только к HTTPS ingress; сам Quordon принимает
  HTTP от loopback interface или внутри доверенного сетевого сегмента;
- local mode по умолчанию слушает только loopback interface;
- база данных ограничивает источники подключения на сетевом уровне;
- каждый профиль использует DB user с минимальными grants;
- каждый datasource указывает на один сервер или логический кластер, все
  backend-серверы которого имеют одинаковую identifier semantics, включая
  `lower_case_table_names`, поддерживаемую MySQL 8.x version и согласованную
  схему; неоднородные backend-серверы должны быть оформлены отдельными
  datasources;
- policy-файлы и secrets недоступны API-клиенту;
- процесс запускается только с обычным policy-файлом, имеющим точные права `0600`;
- DBMS adapter считается security-critical частью доверенной кодовой базы.

## Эшелоны защиты

### Сеть

- Quordon предоставляет HTTP listener и не выполняет TLS termination;
- plaintext client-to-edge разрешён только в local mode на loopback;
- удалённый клиент подключается по HTTPS к ingress, который передаёт запросы
  gateway внутри доверенного сегмента;
- DBMS принимает соединения только от ожидаемых gateway hosts или developer machines;
- исходящий трафик gateway ограничен настроенными datasources, audit sink и secret provider;
- административные endpoints отделяются от прикладного API.

### Basic Auth

- credentials проверяются в каждом прикладном запросе;
- username сопоставляется с server-side `Principal`;
- password hash получается через secret provider;
- passwords и заголовок `Authorization` не логируются;
- сравнение credentials не должно раскрывать существование username по времени или тексту ошибки;
- отсутствие и неверность credentials возвращают одинаково безопасный `401` response;
- внешний ingress может ограничивать частоту authentication failures;
- переданные клиентом identity headers игнорируются.

### Авторизация

- default decision — deny;
- profile выбирается только из profiles назначенного principal;
- datasource выбирается только из datasources назначенного principal;
- profile содержит собственный datasource allowlist, и разрешена только пара
  из пересечения двух назначений;
- deny rules имеют приоритет над allow;
- решение привязано к версии immutable policy snapshot;
- capability проверяется только после аутентификации и проверки всей пары.

Policy package сначала создаёт непрозрачный `AuthorizedBinding`, связанный с
principal, profile, datasource, operation, effective limits и policy hash.
Только после capability check и получения server identifier semantics из него
создаётся более узкий operation token. Raw datasource из request дальше
resolver не проходит.

### QuerySpec и SQL compilation

API не принимает SQL или SQL fragments. Разрешённый запрос определяется общей типизированной моделью и allowlist возможностей.

Gateway отклоняет:

- неизвестные JSON fields и discriminator values;
- неизвестные resources и fields;
- запрещённые filter operators и aggregates;
- превышение глубины или количества predicates;
- joins, subqueries, unions и raw expressions в MVP;
- значения, которые нельзя безопасно преобразовать в заявленный тип;
- любые DBMS-specific extensions, не выраженные отдельной capability.

Identifiers нельзя получить из predicate values. Adapter разрешает физические identifiers через авторизованный mapping и использует DBMS-specific quoting. Все значения передаются отдельными bind parameters.

Database executor принимает только `CompiledQuery`, созданный adapter из `AuthorizedQuerySpec`. Публичный путь выполнения произвольного SQL запрещён архитектурными тестами и package boundaries Go.

Metadata executor аналогично принимает только созданный policy engine
`AuthorizedSchema`. Token привязан к `list_objects` либо к `describe_object` и
конкретному object; raw datasource/schema/object не являются публичным
интерфейсом manager. Manager применяет object/field policy до возврата metadata
вызывающему core-коду.

Статистика использует отдельный `AuthorizedObjectStatistics`, привязанный к
principal, Basic credential identifier, profile, policy snapshot, datasource,
adapter, операции `describe_object_statistics`, каноническим schema/object,
identifier semantics и effective limits. `AuthorizedSchema` нельзя применить к
этому manager method и наоборот. После capability/semantics/resource policy и
allow audit adapter требует физическую InnoDB `BASE TABLE` только для statistics
и читает allowlisted колонки
`INFORMATION_SCHEMA.TABLES` и `INFORMATION_SCHEMA.PARTITIONS`. Имена партиций и
значения метрик не попадают в audit.

### Discovery query shapes

`GET /query-shapes` не является metadata adapter operation. При запуске core
до первого datasource probe проверяет публичную структуру, feature policy и
полный JSON budget. После получения identifier semantics каждый aggregate и
keyset shape дополнительно проверяется по resource и field policy, затем core
публикует неизменяемый disclosure-safe snapshot. На HTTP request path нет
datasource lookup или adapter call. Operation-bound token связывает точное
поколение snapshot с principal, credential identifier, profile, policy hash,
datasource, adapter и effective limits.

Публичный shape set содержит только данные, необходимые для построения
типизированного aggregate или keyset request. SQL, bind/cursor values,
credentials, DSN,
`required_index`, plan estimate bounds и raw policy не раскрываются. Denial до
token не пишет raw requested profile или datasource: audit сохраняет для обоих
отдельные domain-separated SHA-256 и byte length. Allow/completion записывают hash публичного shape set, количество
shapes, response bytes и разрешённые resources/fields, но не сериализованные
shapes и descriptions. Имена resources/fields в audit канонизируются по
проверенным identifier semantics datasource, сортируются и устраняют дубликаты;
публичный response при этом сохраняет написание operator-curated shape. Ответ
отправляется только после обязательного completion audit и всегда помечается
`Cache-Control: no-store`.
До datasource probe bounded-счётчик проверяет denial event для каждой
настроенной пары principal/Basic username, даже если у principal нет profile,
публикующего shapes. Для назначенных discovery profiles он также проверяет
completion events веток `501` и `503`, которым snapshot не требуется. После
создания token отдельно проверяются allow/completion с полным авторизованным
scope. Подсчёт использует консервативные request-id, timestamp и duration,
останавливается при исчерпании лимита и не материализует полный JSON. Запуск
блокируется, если любая JSONL-запись может превысить 16 MiB.

### MySQL 8 query operations

Query operations генерируют только:

```text
<compiled SELECT>
EXPLAIN FORMAT=JSON <compiled SELECT>
```

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

Adapter принимает только серверы MySQL major version `8` и явно отклоняет
MariaDB. Проверка выполняется readiness probe и повторно в operation path,
поэтому optional datasource также не может выполнить запрос на неподдерживаемом
диалекте.

Клиент не выбирает explain mode. `EXPLAIN ANALYZE` запрещён, поскольку выполняет
statement. Scoped SELECT grants остаются обязательными. Клиент не передаёт
subqueries, functions или определения views.

Исполняемый `select` использует field projections, один configured source,
allowlisted filters/sorting, bind parameters и mandatory server-side LIMIT.
Aggregates и `group_by` отклоняются до DBMS.

Исполняемый `select_keyset` использует отдельный operation-bound token и только
точно совпавший именованный policy shape. Shape связывает source, ordered
field-only projection, normalized filter topology/types/arity, полный ordered
key, requested limit, optional plan index и estimate bound.
Cursor не выбирает SQL или индекс: это закрытый typed tuple точных значений
`integer`/`string`/`bytes`/`date`/`datetime`/`timestamp`, чья arity и physical
source types повторно проверяются adapter до SELECT. Общий слой принимает
только finite temporal values в канонических формах, годах `0001`–`9999` и с
не более чем девятью знаками дробной секунды. `datetime` остаётся
timezone-naive wall clock, а `timestamp` требует точного UTC `T`/`Z`; offset и
неявное преобразование между ними запрещены.

Для temporal cursor и filter adapter связывает `TIMESTAMP` как UTC instant под
проверенной UTC session, но сохраняет исходные wall-clock fields для
timezone-naive `DATETIME`; несовпадение physical fractional precision даёт
`422 UNSUPPORTED_QUERY` до `EXPLAIN`/`SELECT`. До DBMS также проверяются
физические диапазоны MySQL (`DATE`/`DATETIME` с `0001` года, `TIMESTAMP` от
1970-01-01 00:00:01 до 2038-01-19 03:14:07.499999 UTC), а operand получает
явный adapter-owned temporal `CAST`. `BIT` не считается binary/blob family и
не допускается для typed `bytes` predicate.
MySQL `TIMESTAMP` row cell сохраняет существующее portable представление
`datetime`, тогда как server-issued cursor нормализуется в UTC `timestamp`;
service сравнивает их как одну и ту же временную величину, а не как разные
байтовые строки.
Charset и collation character source берутся из metadata источника и проверяются
перед включением server-owned names в SQL. Приложение не перечисляет кодировки:
MySQL проверяет побайтный `UTF-8 → source charset → UTF-8` round-trip всех
typed string/UUID filters и string cursors одним bounded constant SELECT до
`EXPLAIN`/source SELECT. UUID дополнительно требует character source шириной
не менее 36 символов. Operand явно преобразуется в исходный charset/collation;
индексированный field не преобразуется. Для читаемых character keys отдельные
скрытые markers проверяют побайтный `source → UTF-8 → source` round-trip до
materialization. Любая необратимость даёт `422 UNSUPPORTED_QUERY`, даже если
MySQL сообщил о замене символов только warning; частичный ответ не выдаётся.
Проверяются только authorized fields bounded page, без предварительного
сканирования таблицы. Native character conversion errors классифицируются без
SQL, значений или raw driver error в ответе/audit.

Keyset строит ключ из настроенного `order_by` и metadata его колонок.
Автор shape гарантирует уникальность полного ordered tuple; доказательство через
unique index не требуется. Key columns остаются `NOT NULL`, поддерживаемых точных
типов, с проверкой cursor arity, precision, charset round-trip и budgets.
Отдельные страницы не имеют общего snapshot. Read-only `REPEATABLE READ`, UTC
session и bounded cleanup выполняются на одном соединении.

Исполняемый aggregate использует отдельный contract module
`openapi/aggregate.yaml`. Preflight и execution используют одинаковый SELECT,
connection и read-only transaction. Views и non-InnoDB objects разрешены;
свойства snapshot underlying данных определяются СУБД.

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

Отсутствие разрешённого shape даёт `403 DENIED_QUERY_FEATURE` и `query_decision`
с `decision: deny` до EXPLAIN/aggregate DBMS call. Отклонение уже разрешённого
shape по plan admission даёт `422 UNSUPPORTED_QUERY` и `query_completion` с
`outcome: error`, `error_kind: invalid`, без выполнения aggregate. DBMS failure
самого EXPLAIN использует обычную timeout/unavailable/upstream классификацию.

Policy shape сопоставляется не по набору fields/operators, а по полной
нормализованной структуре: ordered projection; всё рекурсивное AND/OR-дерево и
число predicates; field/operator и type/arity placeholders каждого predicate;
ordered sort targets с directions; requested limit в пределах shape maximum.
Дети коммутативных AND/OR и в request, и в policy сортируются одним общим
SHA-256 shape digest, а normalized duplicates запрещены. Значения bind
parameters не входят в shape; typed
range/enum constraints в текущем MVP не поддерживаются. Authorized token
связывает весь normalized shape, частичное совпадение запрещено.

Коллизии output names, которые можно доказать без сведений от datasource
(например, aliases `total` и `TOTAL`), отклоняются локальной semantic validation
до получения identifier semantics и любого DBMS-вызова. После получения
семантики server выполняется повторная, более точная canonicalization всех
source identifiers и order targets. Policy configuration при startup запрещает
пересекающиеся client-visible aggregate signatures: другое имя shape,
`required_index`, plan-estimate bound или меньший grouped `maximum_limit` не
устраняют неоднозначность одного и того же принимаемого request.

Adapter рекурсивно проверяет `rows_examined_per_scan` каждого table node,
включая чтение materialized result. Nodes могут иметь разные aliases и sources.
Missing, null, string, fraction, negative, malformed и overflow estimates дают
`422 UNSUPPORTED_QUERY` до основного SELECT. Policy maximum является positive
plain base-10 YAML `uint64`; неверный config блокирует startup.

Единственное zero-table исключение — закрытый envelope с
`query_block.select_id: 1` и сообщением `Impossible WHERE` либо
`no matching row in const table`. Другие планы без table nodes отвергаются.

Time bucket остаётся частью того же curated aggregate boundary. Policy фиксирует
temporal field, unit, UTC, alias и отдельно принимает риск temporary table и
filesort. Adapter до транзакции сохраняет session timezone, устанавливает и
проверяет `+00:00`, а после bounded transaction finalization восстанавливает и
проверяет исходное значение; при невозможности восстановления physical
connection отбрасывается. Bucket expression полностью server-owned. Hidden
aggregate flag и строгая проверка канонического результата не позволяют zero или
incomplete temporal value слиться с легитимной группой SQL NULL.

Текущая policy является object/column/query-feature policy, но не row-level
policy: она не добавляет обязательный tenant predicate и не проверяет
принадлежность каждой строки principal. Поэтому `select` и `aggregate`
разрешаются только для curated tables, где все строки разрешённых columns
доступны данному principal. Агрегация не считается anonymization boundary:
уникальные dimensions и differencing filters могут восстановить row values.
Это осознанная граница MVP; выдавать такой профиль для multi-tenant или иначе
построчно закрытых данных нельзя.

### База данных

Policy engine и compiler не заменяют защиту DBMS. DB user должен независимо запрещать:

- изменение данных и схемы;
- файловые операции;
- выполнение procedures и пользовательских функций;
- доступ к закрытым schemas и objects;
- создание временных объектов;
- подключение с неожиданных hosts.

Для разных profiles могут использоваться разные DB users и pools. Каждый adapter обязан применять поддерживаемые read-only session settings и server-side timeout.

### Capabilities

Отсутствующая capability не эмулируется. Core возвращает
`501 CAPABILITY_NOT_IMPLEMENTED` до обращения к DBMS. Capability считается
реализованной только после adapter contract и integration tests. При старте
manager также проверяет, что каждая объявленная schema/select/keyset/aggregate
capability подкреплена соответствующим Go interface; несовпадение блокирует
запуск до инициализации datasource.

### Ресурсы

Каждый профиль ограничивает:

- deadline;
- размер HTTP body;
- число projection fields, predicates и parameters;
- глубину expression tree;
- limit и offset;
- размер DB result;
- concurrency.

В local MVP profile body limit и concurrency являются semantic/execution
ограничениями: profile определяется из уже прочитанного JSON, а capacity gate
захватывается после decode, validation, resource authorization и обязательного
policy decision audit. Поэтому исчерпание capacity не скрывает policy denial и
не подавляет denial audit. Если capacity исчерпана уже после allow decision,
записывается парный `query_completion` с `outcome: error` и
`error_kind: capacity`. Эти ограничения не заявлены как защита процесса от
параллельного authenticated flooding.

Для aggregate и keyset hard `max_predicates`, `max_parameters` (включая
server-owned `LIMIT` и cursor ladder) и производный максимум filter objects
применяются streaming token scanner до `encoding/json` decode.
Превышенный массив или суммарный budget останавливает scan немедленно, поэтому
рекурсивное дерево сверх hard limits не материализуется. Меньшие effective
profile limits повторно проверяются до авторизации и DBMS action.

Ограничение результата не ограничивает работу DBMS, поэтому применяется совместно с server-side timeout, pool limits и ограниченным набором resources.

SELECT обязан прочитать один MySQL packet в пределах абсолютного adapter bound,
но не создаёт string/base64/JSON для строки, которая не помещается в effective
profile budget. Предварительный подсчёт учитывает base64 expansion, control
characters, HTML-safe JSON escaping и invalid UTF-8 replacement. Это ограничивает
избегаемое memory amplification одного запроса; полноценной DoS-защитой не
является.

Aggregate использует такое же предварительное byte accounting для envelope,
column metadata и каждой positional row. Scalar result либо помещается целиком,
либо возвращает `RESULT_TOO_LARGE`; grouped result может вернуть пустой или
непустой безопасный prefix с `truncated: true`. Source-work admission
дополнительно проверяет policy-owned index и MySQL estimate, но эта эвристика не
заменяет deadline, concurrency, pool limits и scoped DB grants.

Keyset до SELECT проверяет фиксированный response envelope/metadata budget и
консервативный размер следующего canonical request с максимальным cursor для
физических key columns. Каждая строка и cursor учитываются до materialization;
страница либо возвращает полный безопасный prefix с пригодным `next_cursor`,
либо завершается `RESULT_TOO_LARGE` без ложного обещания продолжения.

Для schema metadata profile byte budget применяется только к разрешённому
policy-filtered payload. До policy-фильтрации adapter использует отдельный
абсолютный предел 16 MiB: он ограничивает память процесса, но не позволяет
закрытым объектам расходовать более узкий лимит профиля или определять его
результат.

### Результаты и plans

- query rows не кэшируются без отдельного решения;
- усечение всегда обозначается `truncated: true`;
- безопасный префикс SELECT может содержать ноль rows, если первая строка не
  помещается в effective byte budget;
- explain plan считается потенциально чувствительной metadata;
- plan возвращается только для авторизованного объекта; администратор принимает
  раскрытие dependencies trusted view через plan;
- raw driver errors проходят sanitization;
- клиент должен считать текстовые значения в metadata и plan недоверенными данными.

### Аудит

Записываются:

- `request_id` и `query_id`;
- `principal` и `client_identifier`, равный прошедшему проверку Basic username;
- operation, profile, datasource, adapter и policy version;
- allow/deny и reason code;
- нормализованный hash `QuerySpec`, не содержащий значений параметров и сохраняемый также при ошибке выполнения;
- нормализованный hash сохраняется и для resource/field/feature denial после
  успешной валидации; ранний отказ неназначенной пары может не иметь query hash;
- completion с `CAPABILITY_NOT_IMPLEMENTED` после успешной валидации также
  сохраняет `query_shape_hash`, хотя не содержит неавторизованные resources;
- разрешённые resources в виде пар schema/object и уникальный отсортированный
  список исходных fields;
- allow decision и completion для `select_keyset` содержат имя разрешённого
  публичного shape; при отказе неназначенной пары сырые profile и datasource из
  request не записываются — аудит получает отдельные domain-separated SHA-256
  и длины в UTF-8 bytes;
- длительность и размер JSON plan либо bounded row payload в `result_bytes` для
  успешного completion; SELECT, keyset и aggregate дополнительно записывают
  `row_count` и `truncated`, aggregate — mode и имя shape, keyset — имя shape и
  `has_more`, но никогда значения rows или cursor;
- классифицированная DBMS error в поле `error_kind` (`invalid`, `timeout`,
  `unavailable`, `result_too_large` или `upstream`) без raw driver error.

Невозможность сформировать повторно отправляемый keyset cursor в пределах
`max_request_bytes` возвращается клиенту как `413 REQUEST_TOO_LARGE`, а в audit
классифицируется как `invalid`: это детерминированный отказ admission до SELECT,
а не переполнение уже полученного результата.

`invalid` на стадии adapter execution означает, что авторизованный source не
оказался физической таблицей. Ошибки MySQL 1044/1045 считаются недоступностью
datasource (`unavailable`), а не ошибкой выполнения SQL.

Сбой datasource при получении семантики identifiers происходит до resource
authorization. Для него записывается completion с `query_shape_hash` и
`error_kind`, но без allow decision и без resources/fields, которые ещё не были
авторизованы.

`policy_hash` вычисляется из канонического разобранного policy после замены
inline bcrypt hashes и DSN постоянными redaction-маркерами. Он идентифицирует
authorization snapshot и не является verifier для credentials.

До запуска listener выполняется bounded preflight всех достижимых audit events
`select_keyset`: denial, unsupported capability, identifier-semantics failure,
allow, capacity, response-budget и execution completion. Настройка, для которой
такое событие может превысить process-wide audit bound, блокирует запуск до
обращения к datasource.

Не записываются:

- Basic password и `Authorization` header;
- query values;
- скомпилированный SQL с literals;
- DB rows;
- DSN, DB password и TLS private keys;
- сырые driver errors без sanitization.

## Предотвращение утечки существования объектов

Авторизация выполняется до metadata lookup запрещённого объекта. Запрос к недоступному resource возвращает общий HTTP `403` независимо от его фактического существования.

## Остаточные риски

- разрешённые metadata и plans могут быть скопированы законным клиентом;
- estimates плана могут раскрывать приблизительные размеры таблиц;
- дефект adapter compiler может сформировать неверный SQL;
- поведение timeout и cancellation зависит от DBMS и driver;
- компрометация gateway host раскрывает доступ его DB users;
- Basic password является повторно используемым секретом и требует TLS и ротации.

Риски уменьшаются минимальными profiles, adapter contract tests, concurrency
limits, ограничениями частоты на внешнем ingress, изоляцией hosts и
независимыми DB grants.

## Диагностические temporal values

Явный `source_text` является опубликованным представлением поля, а не неявным
преобразованием calendar type. Оно требует отдельного profile permission и
adapter feature; отсутствие permission отклоняется до datasource lookup.
Denylist применяется к исходному полю во всех placements. Неверный native type
отклоняется адаптером после authorization и до EXPLAIN/SELECT.

Нативные нулевые и некалендарные temporal values сохраняются строкой; истинный
DB NULL остаётся null. Filter operands связываются как binary text, не проходят
DATE/DATETIME casts и сравниваются побайтно так же, как grouping, ordering и cursor.
TIMESTAMP читается под проверенной UTC session с bounded восстановлением.
Обычные calendar cursors и typed values сохраняют проверку реального календаря.
Уникальность полного ordered tuple при выбранном представлении гарантирует автор
shape. Deadline, packet/result/request budgets, plan admission и audit redaction
не ослабляются; SQL modes читающего соединения не изменяются.
