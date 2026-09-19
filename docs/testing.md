# Стратегия тестирования

Policy assembly покрывает refs на каждом уровне, RFC 6901 pointers, shallow
overrides, origin resolution, document cache, anchors/aliases и независимость
typed profiles. Negative fixtures проверяют закрытую схему, types/presence,
cycles, unsafe paths/symlinks, descriptor modes и каждый фиксированный budget.
Parser limits и upstream YAML compatibility tests запускаются в `make test`.
`--check-config` проверяется с отсутствующими secret dependencies и spy startup:
внешние dependencies не запускаются при проверке и ранних отказах.

`make integration` запускает два SELECT-only MySQL 8 datasource с различимыми
`routing_marker` fixtures. Профили из общих refs должны выбирать правильный
контур, сохранять denylist, aggregate/keyset plan admission и `503` для EXPLAIN
views без `SHOW VIEW`. Исходная inline integration policy сохраняется для
существующих unit/contract fixtures; runtime использует файловый refs wrapper.

## Цели

Тесты доказывают не только успешность разрешённых операций, но и невозможность сформировать или выполнить SQL в обход strict request validation, policy engine и DBMS adapter.

## Unit tests policy engine

Policy engine тестируется как чистая функция. Проверяются:

- allow, deny и default deny;
- приоритет deny;
- Basic username -> principal mapping;
- profile assignment;
- datasource и required capability;
- schemas, resources и fields;
- filter operators, grouping, sorting и aggregates;
- наиболее строгие effective limits;
- стабильные reason codes;
- immutable policy snapshot.

Config fixtures отдельно проверяют strict YAML boundary: optional member можно
опустить, но явный `null` и explicit empty branch member запрещены до
типизированного декодирования. В частности, это покрывает `filter`, `order_by`,
`maximum_limit` и вложенные projection/filter/order members aggregate shape.
Presence-sensitive проверки разыменовывают YAML alias, включая alias scalar
`mode` вместе с явно заданным `maximum_limit`, а также canonical integer aliases
для `maximum_limit` и `maximum_rows_examined_per_scan`. YAML merge keys отклоняются во
всём policy до typed decode; fixtures отдельно покрывают обычный config mapping,
унаследованные `maximum_limit`, non-canonical bound и projection member.
Строковые aggregate shape members дополнительно проверяются на YAML tag:
boolean/number tokens для name, mode, schema, field, alias, operator,
`value_types` и required index не могут быть неявно преобразованы в строки.

## QuerySpec validation

Корпус содержит разрешённые и атакующие JSON requests:

- простой field projection;
- aggregation и group by;
- вложенные `and`/`or` filter groups;
- все typed values;
- unknown, case-folded и повторяющиеся JSON fields, а также discriminator values;
- пустые и oversized identifiers;
- неподходящее число values для operator;
- неизвестные resources и fields;
- превышение expression depth, predicates и parameters;
- попытки передать SQL в identifiers, values и aliases;
- неподдерживаемые joins, subqueries, unions и raw expressions;
- conflicting limit и profile limits.

Unknown field всегда приводит к отказу, а не игнорируется.

### Паритет OpenAPI и runtime

OpenAPI является исполняемым transport-контрактом, а не только документацией.
Для каждого изменённого request/response schema один и тот же набор fixtures
проверяется OpenAPI 3.1 validator и runtime decoder/handler:

- positive fixture принимается обоими;
- structurally invalid fixture отклоняется обоими;
- детерминированно неподдерживаемая endpoint shape запрещается схемой, если это
  выразимо, либо явно документируется и возвращает semantic `422`;
- JSON token types не преобразуются: string, number, integer, boolean и null
  сохраняют исходный тип;
- required presence, explicit null, discriminator branch, exact/duplicate keys,
  numeric range и array bounds проверяются одинаково;
- response fixture также валидируется по OpenAPI, включая тип каждого поля.

Vacuum lint обязателен, но не заменяет эту двустороннюю проверку. Библиотека,
поддерживающая только OpenAPI 3.0 или неполный JSON Schema, не может считаться
доказательством корректности OpenAPI 3.1 без отдельно зафиксированных gaps.
Contract suite использует `libopenapi-validator`: он загружает полный
`openapi/openapi.yaml`, валидирует сам документ как OpenAPI 3.1, затем проверяет те же
SELECT request fixtures, что runtime decoder, и positive/negative SELECT
response fixtures по конкретному HTTP operation. Для metadata endpoints suite
также фиксирует документированное semantic-расширение закрытого query string:
OpenAPI распознаёт operation и обязательные `profile`/`datasource`, а handler
дополнительно отклоняет неизвестные, case-folded и повторные параметры, а также
невалидный UTF-8 с `400`.
Positive contract fixtures проходят через реальные handlers для успешных
`list_objects`, `describe_object`, `describe_object_statistics`, `select`,
`aggregate` и `list_query_shapes`, после чего их фактические `200`
responses валидируются OpenAPI 3.1, а не подменяются вручную собранными JSON.

Подробные обязательные правила реализации и negative-test matrix находятся в
корневом [AGENTS.md](../AGENTS.md).

## Compiler golden tests

Для каждого DBMS adapter фиксируются пары:

```text
AuthorizedQuerySpec -> SQL + parameters
```

Проверяются:

- quoting каждого identifier;
- отсутствие interpolation values;
- placeholder numbering и ordering;
- precedence filter expressions;
- `IS NULL`, `IS NOT NULL`, `IN`, grouping, sorting, limit и offset;
- deterministic compilation;
- невозможность скомпилировать unauthorized spec;
- отсутствие SQL fragments из API input.

## MySQL 8 MVP tests

- explain adapter генерирует только `EXPLAIN FORMAT=JSON SELECT ...`, select
  adapter — только bounded field-only `SELECT ... LIMIT ? OFFSET ?`, а aggregate
  adapter — только policy-curated aggregate `SELECT` и его exact EXPLAIN prefix;
- `EXPLAIN ANALYZE`, `FOR CONNECTION`, DDL и DML отсутствуют во всех code paths;
- discovery и description возвращают trusted views без выдуманных PK/index flags;
- обычный SELECT проходит для case-colliding view, aliases, join-view и
  materialized view; scoped SELECT-only учётка остаётся без SHOW VIEW;
- EXPLAIN, scalar/grouped aggregate и keyset views возвращают
  `503 DATABASE_UNAVAILABLE` из-за требования MySQL SHOW VIEW, до основного SELECT;
  положительное выполнение этих операций над views в integration не заявляется;
- denylist скрывает direct view fields и запрещает их projection/filter/sort;
  synthetic alias подтверждает отсутствие автоматического dependency deny;
- readiness и поддерживаемые при SELECT-only операции проходят с одной scoped SELECT учёткой без BACKUP_ADMIN;
  SQL lock/unlock и поле режима в audit отсутствуют;
- прежнее поле ddl_guard_mode блокирует startup как unknown config field;

- MySQL major version `8` принимается, а MySQL 5.7/9, MariaDB и malformed
  version отклоняются до выполнения операции;
- отсутствующее разрешённое поле (`ER_BAD_FIELD_ERROR`, 1054) возвращает
  `422 UNSUPPORTED_QUERY`, а не `502 UPSTREAM_ERROR`;
- JSON plan корректно разбирается и ограничивается по bytes;
- schema discovery возвращает policy-разрешённые tables/views и columns;
- database manager не принимает raw metadata coordinates: list/describe требуют
  непрозрачный operation-bound `AuthorizedSchema`, а token другой операции и
  zero value отклоняются до adapter call;
- policy constructor не выпускает metadata token для пустых или непереносимых
  schema/object identifiers даже при wildcard allow policy;
- profile metadata budget применяется после policy-фильтрации: множество
  закрытых tables/columns не вызывает `413`, но превышение уже разрешённым
  payload возвращает `RESULT_TOO_LARGE` без частичного metadata response;
- для `describe_object_statistics` contract suite отдельно проверяет запрет
  body, HEAD/non-GET semantics, закрытый query string, канонические uint64
  strings, nullable metrics и `none`/`partitioned`/`subpartitioned` response
  branches; raw-token fixture отклоняет duplicate response members, а typed
  encoder fixture проверяет точные закрытые JSON-ветки; MySQL integration
  создаёт InnoDB-таблицы без партиций, с RANGE
  partitioning и с RANGE+HASH subpartitioning, а view проверяет как unsupported statistics (`422`), MyISAM — как
  неразличимые `404`;
- SELECT rows positional, сохраняют exact numeric/date text, кодируют binary и
  spatial values как base64 и всегда отражают усечение через `truncated`;
- character keyset tests не предполагают application charset allowlist:
  MySQL metadata задаёт charset/collation, входящие string/UUID binds проходят
  побайтный round-trip до EXPLAIN/source SELECT, а скрытые markers проверяют
  исходные ключи bounded page до materialization. Unit tests покрывают unsafe
  metadata names, пустые значения, вложенные filters, NULL/неверные markers,
  потери в первой/последующих строках и timeout/unavailable mapping.
  `scripts/integration-keyset-characters.sh` проверяет полные ASC/DESC проходы
  synthetic composite keys с utf8mb3, latin1, cp1251, utf16 и ascii, native
  collation equality для регистра/диакритики/пробелов, supplementary characters,
  точный server-issued cursor round-trip, `422` для непредставимых cursors и
  filters, `422` для необратимого CP932 source key после валидного префикса и
  `403 DENIED_QUERY_FEATURE` при добавлении скрытых projection/filter fields.
  Ad-hoc SELECT отдельно проверяет deny-overrides-allow через
  `403 DENIED_FIELD` для projection/filter и отсутствие поля в metadata;
- `parseTime=true` и `columnsWithAlias=true` в исходном DSN принудительно
  отключаются, connection collation канонизируется в UTF8MB4, `charset`
  отклоняется, temporal output остаётся нативным MySQL text, а unsigned integer
  metadata остаётся `integer`;
- строка больше effective result budget даёт `200` и `truncated: true` как
  после помещённого префикса, так и для пустого префикса; logical packet больше
  абсолютных 16 MiB плюс 1 KiB framing allowance даёт `413`;
- encoded row size совпадает с `encoding/json` для control/HTML characters,
  Unicode, invalid UTF-8 replacement и base64; превышение определяется до
  materialization string/base64/row JSON;
- aggregates и наличие `group_by` (включая пустой массив) недостижимы
  через executable SELECT; transport сверяется с `SimpleSelectQuerySpec`, а
  policy повторно проверяет operation-specific инварианты перед выпуском token;
- SELECT сохраняет read-only transaction, packet/result bounds и deadlines;

- aggregate decoder и OpenAPI одинаково отклоняют неверные discriminator
  branches, null/unknown/case-folded/duplicate fields, неверные typed values и
  excessive recursive filters;
- нормализация валидного глубоко вложенного aggregate filter использует
  фиксированные digest keys для shape и values, не создавая рекурсивно
  экранированные JSON strings;
- duplicate scan aggregate filter вычисляет exact digest снизу вверх и не
  пересериализует уже проверенное поддерево на каждом уровне;
- aggregate policy выпускает отдельный operation-bound token только при точном
  совпадении полного normalized shape, разрешённых resources/fields/features и
  effective limits, включая отдельный `max_group_by_fields` для dimensions;
- aggregate config до typed decode отклоняет quoted, fractional, exponent и
  overflowing `maximum_limit`/`maximum_rows_examined_per_scan`;
- aggregate startup validation применяет request limits к каждому portable
  identifier и predicate `value_types`, не создавая недостижимых policy shapes;
- локальная aggregate validation отклоняет case-insensitive output collisions
  до identifier-semantics lookup, а startup validation отклоняет одинаковые и
  пересекающиеся scalar/grouped request signatures независимо от shape name,
  execution hints и различий верхнего grouped limit;
- оба compiler обходятся без index hints, используют binds и один SELECT для
  preflight/execution; required_index optional, malformed values блокируют startup;
- native MySQL JSON `index_merge` expressions (`union`, `intersect`, `sort_union`)
  проверяются на exact aggregate/keyset preflight с SELECT-only учёткой: каждый
  участвующий индекс удовлетворяет `required_index`, несовпадение и запрещённый
  filesort дают `422` до основного SELECT; unit fixtures покрывают вложенность,
  malformed expressions и сохранение estimate/work bounds;
- merge с native index `idx_a,idx_b` и `idx_c` проверяется в aggregate/keyset:
  расхождение числа leaves и native key lengths даёт `422` до основного SELECT,
  включая shapes без index requirement; unit fixtures также покрывают unary
  wrappers, malformed key lengths и вложенные неоднозначные expressions;
  полные native identities из `possible_keys` исключают подмену имён через
  parentheses даже при совпадающем количестве leaves и key lengths;
- вне `index_merge` native `key` сравнивается как целое имя: unit fixtures
  покрывают `ref`/`range`/`index`, а integration с quoted index `idx_a,idx_b`
  проверяет `422` для обоих фрагментов имени в aggregate/keyset до основного
  SELECT и успешные queries без `required_index`;
- physical aliases с префиксом `<` не исключают matching index; materialized
  и shared temporary reads определяются структурно независимо от alias.
  Native MERGE-view с alias `<orders>` наблюдается fixture-admin: его
  aggregate/keyset JSON plans проверяются adapter Go test, а SELECT-only
  service по-прежнему получает `503` без основного SELECT и без SHOW VIEW grant;
- plan admission проверяет estimate каждого physical/materialized read node,
  optional index на physical node, temporary/filesort controls и malformed plan;
  bounded full scans и multi-source plans допустимы. Unit fixtures покрывают
  join/materialized plans; integration проверяет optional index, estimates и
  work controls на физических objects и отсутствие main SELECT при отказе
  по журналу изолированного MySQL fixture;
- только два точных закрытых empty plans обходятся без table node;

- scalar aggregate имеет ровно одну row и не допускает partial response;
  integration fixture с отсутствующим PK проверяет zero-table EXPLAIN и
  результат `COUNT = "0"` вместе с nullable measure `null`;
  grouped aggregate возвращает только полный safe prefix и корректный
  `truncated`, причём encoded size считается до materialization и учитывает
  однобайтовую разницу между JSON `false` и `true` до отбрасывания row;
- aggregate result metadata различает nullable scalar measures и grouped
  measures над `NOT NULL`/nullable source fields;
- time-bucket decoder/config tests проверяют required non-null string members,
  закрытые unit/UTC branches, duplicate exact keys и обязательные YAML boolean
  opt-ins; compiler использует одно server-owned expression в projection,
  grouping и ordering, а result validation отклоняет invalid temporal flags и
  неканонические UTC boundaries без частичного ответа;
- bind parameters не появляются в logs и audit;
- identifier mapping не допускает injection;
- server-side timeout действует;
- после timeout connection reset или закрывается;
- scoped `SELECT` grants независимо запрещают DDL, DML, files, procedures и
  закрытые objects; административных прав service user не имеет;
- тесты выполняются на минимальной и максимальной заявленной MySQL 8 minor version.

## Adapter contract suite

Каждый adapter должен пройти общий suite:

- capability declaration соответствует реализации;
- неизвестная/повторная capability и объявленная schema/select/keyset/aggregate capability без
  обязательного Go interface блокируют startup до открытия datasource;
- unsupported capability не открывает connection и возвращает `501`; cached
  capability повторно проверяется на manager boundary до вызова любого adapter
  method, включая прямой внутренний вызов с корректным authorization token;
- connection и pool lifecycle;
- readiness probe проверяет доступность, product/version и identifier semantics
  datasource;
- typed parameter binding;
- принудительное отключение client-side `interpolateParams` из DSN;
- принудительное отключение `allowAllFiles` из DSN и невозможность загрузки
  произвольного локального файла по запросу MySQL server;
- принудительное отключение `columnsWithAlias`, каноническая UTF8MB4 collation
  и отказ от DSN `charset`;
- отказ от generic DSN session-variable parameters, включая
  регистронезависимые и квалифицированные `transaction_read_only`/`tx_read_only`;
- ранняя остановка filter validation на effective depth, predicate и parameter limits;
- aggregate token scan считает суммарные hard predicate/parameter limits,
  server-owned grouped `LIMIT` и производный предел filter objects до полной
  десериализации дерева;
- повторная проверка effective limits использует сохранённую validated structure
  и не декодирует bind values повторно до capacity gate;
- protocol и effective limits для количества `group_by` и `order_by` terms;
- отказ запуска при числовых limits выше безопасных implementation maxima;
- стабильный redacted `policy_hash`, не зависящий от inline secrets и YAML formatting;
- глубокая неизменяемость policy snapshot относительно исходной конфигурации и
  возвращаемых accessor values;
- aggregate authorization token глубоко копирует каждый `TypedValue.Value`, и
  изменение возвращённого `json.RawMessage` не меняет последующий adapter input;
- required/discriminator-specific JSON fields;
- отклонение некорректного UTF-8 до JSON decode с `400 INVALID_REQUEST` без
  неявной замены байтов на `U+FFFD`;
- отклонение явно пустых optional identifiers до потери presence-информации;
- отклонение явного `null` для optional полей, не допускающих `null` по OpenAPI;
- сохранение `query_shape_hash` в failed completion audit;
- сохранение `query_shape_hash` в resource/field/feature denial после validation
  при допустимом отсутствии hash у раннего unassigned-profile denial;
- сохранение `query_shape_hash` в `not_implemented` completion после validation;
- сохранение `duration_ms: 0` в completion при отсутствии duration у decision;
- canonical matching переставленных `AND`/`OR` children до datasource lookup;
- отклонение keyset response, чей `next_cursor` не совпадает с ordered key
  tuple последней возвращённой строки;
- запись denial audit после отмены клиентского request context;
- аудит классифицированного сбоя identifier semantics до resource authorization;
- отклонение типизированного `null`, строкового и неинтегрального JSON number
  для типа `integer`; точные `1`, `1.0` и `1e0` принимаются без float64;
- явные OpenAPI bounds signed `int64` и канонический standard Base64 одинаково
  проверяются contract validator и runtime decoder;
- фактический HTTP JSON body не получает неучтённый trailing newline, а
  aggregate byte accounting совпадает с compact `encoding/json` payload;
- ожидание активных handlers при graceful shutdown;
- type normalization;
- read-only session setup;
- timeout;
- сохранение timeout classification при срабатывании socket operation deadline,
  даже если внешний context ещё не сообщил собственный deadline;
- дренирование EXPLAIN rows при активном request context до `Rows.Close`, чтобы
  cleanup не мог выйти за query deadline;
- metadata sanitization;
- error classification;
- классификация MySQL 1044/1045 как недоступности datasource (`503`), а не
  upstream execution error (`502`);
- connection reset после failure;
- resource result limits.

Capability `cancel_query` требует отдельного server-side proof.

## Basic Auth tests

- credentials обязательны для каждого прикладного endpoint;
- health endpoints доступны без credentials;
- valid username/password создаёт ожидаемый principal и сохраняет Basic username
  как отдельный client identifier;
- некорректная или неканоническая bcrypt encoding переводит readiness в false;
- bcrypt cost вне поддерживаемого диапазона 10–14 отклоняется до генерации
  dummy hash;
- missing, malformed, unknown и wrong credentials возвращают `401`;
- `WWW-Authenticate` присутствует;
- responses не различают unknown username и wrong password;
- `Authorization` header и password отсутствуют в logs, traces и audit;
- Quordon не терминирует TLS: local plaintext разрешён только на loopback, а
  remote test topology использует HTTPS termination на ingress;
- встроенные rate limit и DoS controls отсутствуют и не заявляются как
  security acceptance criteria MVP.

Allow/completion audit tests проверяют авторизованные schema/object, уникальный
список fields, `result_bytes`, а для SELECT, keyset и aggregate также
`row_count` и `truncated`; aggregate сохраняет mode и shape name, keyset — shape
name и `has_more`. Predicate, cursor и result values в аудит не попадают. Отказ
capacity после allow decision сохраняет парный completion с
`error_kind: capacity` без вызова adapter.

Для keyset отдельно проверяются startup audit-size preflight без adapter call,
наличие имени shape уже в allow decision и замена сырых неназначенных profile и
datasource на отдельные hash+byte-length в denial event.

## Fuzz и property tests

- JSON decoder и QuerySpec validator не падают на произвольном input;
- unknown fields не принимаются;
- expression depth hard limit всегда действует;
- compiler output содержит только server-selected identifiers;
- изменение predicate value не меняет структуру SQL;
- число placeholders равно числу parameters;
- executor невозможно вызвать до authorization и compilation;
- неизвестное поле policy всегда блокирует запуск.

## Integration tests DBMS

Тестовая DBMS соответствует adapter и заявленному диапазону versions. Проверяются:

- grants каждого DB user;
- два поддерживаемых TLS-режима и отказ для `skip-verify`, `preferred` и
  несогласованности policy с DSN;
- отсутствие raw driver errors во встроенном MySQL logger;
- isolation нескольких datasources;
- независимые binding quotas для одного profile на разных datasources при
  сохранении global concurrency limit;
- явная маршрутизация metadata, EXPLAIN, SELECT, aggregate, keyset и discovery
  одной policy profile в различимые test/RC databases;
- pool и concurrency limits;
- parameter binding и database types;
- timeout и connection cleanup;
- закрытые schemas и resources;
- adapter-specific explain behavior;
- policy-filtered schema discovery, bounded executable SELECT, curated keyset и aggregate;
- отсутствие чувствительных деталей в errors.

## API tests

- Basic Auth и profile selection;
- strict JSON decoding;
- HTTP status mapping;
- единый error body;
- `403` не раскрывает существование resource;
- `501` для отсутствующей adapter capability;
- `503 CAPACITY_EXCEEDED` при исчерпании concurrency capacity;
- liveness не зависит от DBMS;
- readiness отражает policy, credential secrets, adapters, datasources и audit;
- request и query identifiers проходят через API, logs и audit.

## Failure injection

- datasource недоступен;
- connection разорван во время explain;
- policy snapshot повреждён;
- credential или DSN secret недоступен;
- audit sink недоступен;
- adapter compiler возвращает internal error;
- timeout до и после получения DB response;
- client disconnect во время DB operation;
- один из нескольких datasources недоступен.

Во всех случаях операция либо завершается в разрешённом ограниченном состоянии, либо fail closed.

## Security acceptance MVP

Перед выпуском MySQL 8 query profiles необходимо подтвердить:

- API не принимает raw SQL;
- Basic credentials защищены transport и отсутствуют в telemetry;
- прямой DB access определяется независимо от gateway;
- QuerySpec adversarial corpus отклоняется ожидаемыми reason codes;
- DB grants независимо блокируют опасные operations;
- adapter генерирует только разрешённые metadata queries,
  `EXPLAIN FORMAT=JSON`, bounded field-only `SELECT`, exact policy-indexed
  keyset либо aggregate;
- `EXPLAIN ANALYZE` недостижим;
- timeout ограничивает DB statement;
- values отсутствуют в logs и audit;
- отсутствие capability возвращает `501` без DB call;
- сбой обязательного audit sink блокирует новые operations.

Для `select` дополнительно проводится ручная проверка, что curated resources не
требуют row-level isolation. Наличие `LIMIT` не считается доказательством
дешёвого запроса; для production-like profiles проверяются индексы и worst-case
plan разрешённых filters.

Для `select_keyset` дополнительно проверяются first/after pages, составной и
обратный порядок, точное воспроизведение typed cursor, `NOT NULL` order-by columns,
optional index admission и гарантированную автором уникальность tuple, source type/range mismatch,
continuation-request budget, `LIMIT + 1`, plan rejection до SELECT и отсутствие
общего snapshot между отдельными requests. Adapter-neutral temporal fixtures
проверяют cursor types `date`, `datetime`, `timestamp`, реальные календарные
даты, годы `0001`–`9999`, дробную часть до девяти знаков, обязательные формы
space и uppercase `T`/`Z`, запрет offset/infinity/null/coercion и смешанный
составной key. MySQL fixtures отдельно проверяют physical
`DATE`/`DATETIME`/`TIMESTAMP` ranges, точное совпадение source FSP 0–6,
adapter-owned `CAST`, UTC binding и нормализацию server-issued timestamp cursor;
`BIT` отрицательно проверяется как bytes source.
Канонический `TIME` допускает только optional minus; leading plus, включая
`+01:00:00`, отклоняется одинаково adapter и service response boundary.
Пустая final page проверяется как ненулевой JSON array `rows: []`; adapter
zero value `Rows: nil` обязан дать internal invariant error до HTTP 200.
DATE/DATETIME с корректным календарём начиная с `0001` года принимаются;
TIMESTAMP вне поддерживаемого физического диапазона отклоняется на MySQL adapter boundary; service независимо проверяет
общий portable temporal response range и семантическое совпадение UTC
`timestamp` cursor с нативным `datetime` row cell.
Отдельная fixture проверяет, что невозможный по request budget continuation
остаётся HTTP `413`, но получает документированный audit `error_kind=invalid`.
Первая усечённая страница должна завершаться без unread-row drain, discard-ить
physical connection и не мешать следующей странице открыть чистое соединение.
Legacy и keyset request/response
branches проверяются как непересекающиеся пары реального handler.

Config fixtures ограничивают суммарное число aggregate/keyset shapes значением
1000 даже без discovery operation. Lookup предвычисленного shape capability
проверяется как allocation-free, чтобы `/capabilities` и request path не
клонировали полный policy graph до capacity gate.

Для `aggregate` дополнительно проверяются exact shape matching, реальные
required indexes, worst-case ranges, plan rejection до execution и отсутствие
предположения, что MySQL estimate является жёстким source-work limit.

## Диагностические temporal integration fixtures

`make integration` проверяет synthetic `diagnostic_dates`: ранние календарные,
нулевые, неполные и некалендарные DATE/DATETIME, zero TIMESTAMP и DB NULL.
Fixture administrator временно меняет только свою session для вставки и
восстанавливает SQL mode/timezone; service account остаётся SELECT-only.
`integration-source-text.py` проверяет SELECT/EXPLAIN, text predicates,
grouped/scalar aggregates, ASC/DESC multi-page keyset, обычные calendar cursors
раньше 1000 года и сохранение их отказа для действительно неверного календаря.
Admission denials проверяются по отсутствию основного SELECT в isolated general log.
Для проверки TIMESTAMP fixture administrator временно задаёт default timezone
`+03:00` и пересоздаёт service connections внутри isolated MySQL. Проверяются
UTC-значения в SELECT, keyset и aggregates, восстановление session timezone
и отсутствие изменений SQL mode у reader. Default timezone восстанавливается
при завершении проверки.
После diagnostic SELECT/EXPLAIN проверяется повторное чтение и readiness за
пределами cleanup deadline. Медленный synthetic view проверяет сохранение
`504 QUERY_TIMEOUT` и работоспособность следующего запроса после discard.

Запуски выполняются для обоих поддерживаемых семейств:

```bash
MYSQL_IMAGE=mysql:8.0 make integration
MYSQL_IMAGE=mysql:8.4 make integration
```

OpenAPI/runtime fixtures проверяют новые members в обе стороны; unit negative
fixtures дополнительно проверяют strict duplicate/exact keys и feature/policy
отказы без datasource calls. Discovery публикует все shapes через один JSON
контракт, а прежние vendor media types отклоняются с 400.
