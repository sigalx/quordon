# REST API

## Общие правила

- прикладные endpoints процесса не содержат version prefix;
- один процесс реализует одну major-версию API;
- запросы и ответы используют `application/json`;
- каждый прикладной запрос проходит HTTP Basic Auth;
- liveness и readiness не требуют аутентификации;
- каждый ответ содержит `X-Request-ID`;
- имена JSON properties регистрозависимы и должны в точности соответствовать
  OpenAPI; неизвестные, отличающиеся регистром и повторяющиеся fields
  отклоняются;
- явный JSON `null` отклоняется для свойств, в схеме которых не разрешён тип `null`;
- API принимает структурированный `QuerySpec`, а не SQL или SQL fragments;
- клиент явно передаёт `profile` и `datasource`; разрешена только пара из
  пересечения назначений principal и allowlist профиля;
- значения predicates передаются отдельно от identifiers;
- наличие endpoint не гарантирует поддержку capability выбранным адаптером.

Полный машинно-читаемый контракт находится в
[openapi/openapi.yaml](../openapi/openapi.yaml).

## Версионирование и border proxy

Внутренние routes gateway не версионируются в URL:

```text
GET  /capabilities
POST /queries/explain
```

Публичный HTTP-сервис может добавить version prefix на border proxy и удалить его при передаче запроса backend-процессу:

```text
/v1/capabilities     -> gateway API 1 /capabilities
/v1/queries/explain  -> gateway API 1 /queries/explain
/v2/...              -> gateway API 2 /...
```

Один процесс не обслуживает несколько несовместимых major-версий. `info.version` в OpenAPI относится к API-контракту, а версия конкретной сборки публикуется отдельно. Endpoint capabilities возвращает оба значения в полях `api_version` и `service_version`.

Переход с scalar `profiles.*.datasource` на обязательные массивы
`principals.*.datasources` и `profiles.*.datasources`, а также обязательный
`datasource` во всех profile-scoped запросах является сознательно breaking
изменением внутри API major `1`. Старый и новый сервер, policy и клиент нельзя
смешивать; совместимой ветки decoder нет.

## Аутентификация

Клиент передаёт Basic credentials в каждом запросе:

```http
Authorization: Basic base64(username:password)
```

Успешная проверка username и password создаёт `Principal`. Клиент не может изменить principal, profile assignments или datasource дополнительными заголовками.

Ответ `401` содержит `WWW-Authenticate: Basic realm="quordon", charset="UTF-8"`.
Quordon сам принимает HTTP и не терминирует TLS. В local mode plaintext
разрешён на loopback interface; при удалённом доступе клиент использует HTTPS
до внешнего ingress, а ingress пересылает запрос во внутренний HTTP listener.
Rate limiting, защита от перебора Basic credentials и DoS controls также
являются ответственностью ingress и не входят в API-контракт MVP.

## MVP endpoints

### `GET /health/live`

Проверяет, что процесс способен обслуживать HTTP-запрос. Не обращается к DBMS.

### `GET /health/ready`

Проверяет policy snapshot, credentials, обязательный audit sink, доступность
datasource и соответствие `mysql8` datasource поддерживаемому MySQL 8.x
(`>= 8.0, < 9.0`). MySQL 5.7, MySQL 9 и MariaDB дают `503` readiness.

### `GET /capabilities`

Возвращает major-версию API, версию сборки сервиса и только назначенные principal
профили. В каждом профиле находится отсортированный список datasource из
пересечения principal/profile allowlists; operations вычисляются отдельно для
каждой пары как пересечение policy, adapter capabilities и готового discovery
snapshot. Запрещённые пары не публикуются.

Capability описывает реализацию скомпилированного adapter. Готовность и
совместимость фактического сервера проверяются `/health/ready` и повторно на
пути выполнения операции; неподдерживаемый сервер не получает `EXPLAIN`.

```json
{
  "api_version": "1",
  "service_version": "0.1.0",
  "policy_version": "17",
  "profiles": [{
    "name": "analytics",
    "limits": {
      "deadline_ms": 3000,
      "max_request_bytes": 65536,
      "max_projection_fields": 50,
      "max_group_by_fields": 20,
      "max_order_by_fields": 20,
      "max_predicates": 50,
      "max_expression_depth": 8,
      "max_parameters": 100,
      "max_rows": 1000,
      "max_result_bytes": 1048576,
      "max_offset": 0,
      "max_concurrency": 2
    },
    "datasources": [{
      "name": "primary-mysql",
      "adapter": "mysql8",
      "operations": ["aggregate", "list_query_shapes"]
    }]
  }]
}
```

Capability `list_query_shapes` принадлежит core и публикуется только когда
profile одновременно разрешает `list_query_shapes` и хотя бы одну операцию
`aggregate`/`select_keyset`, adapter поддерживает соответствующие операции, а
disclosure-safe snapshot успешно построен при запуске. Сам adapter эту
capability не объявляет.

### `GET /query-shapes?profile=...&datasource=...`

Возвращает полный список публичных operator-curated шаблонов aggregate и
keyset SELECT для одной назначенной пары. Query string закрыт: `profile` и
`datasource` обязательны ровно по одному разу; дополнительные, повторные,
case-folded, пустые параметры и invalid UTF-8 дают `400 INVALID_REQUEST`. Любой HTTP method кроме `GET`, включая
`HEAD`, отклоняется с `405 METHOD_NOT_ALLOWED` до аутентификации и audit. Все
ответы, включая ошибки аутентификации и неподдерживаемые методы, содержат
`Cache-Control: no-store` и `Vary: Accept`.

Отсутствующий `Accept`, `*/*` и точный `application/json` выбирают единственный
JSON-контракт. Он публикует все разрешённые aggregate, time-bucket и keyset shapes,
включая `representation: source_text`. Vendor media types прежних v2/v3, списки,
параметры media type и остальные значения дают `400 INVALID_REQUEST`.
Частичный список никогда не формируется; отдельного version negotiation нет.

Ответ строится только из неизменяемого startup snapshot и на request path не
обращается к datasource или adapter. В нём есть public name/description,
operation, source, projection, структура filter с `value_types`, ordering и
максимальный limit. В нём никогда нет bind values, cursor values, SQL,
`required_index`, `maximum_rows_examined_per_scan`, DSN или иных execution-only
controls.

```json
{
  "policy_profile": "analytics",
  "policy_version": "17",
  "datasource": "primary-mysql",
  "adapter": "mysql8",
  "shapes": [{
    "name": "orders_by_status",
    "description": "Count orders grouped by their current status.",
    "operation": "aggregate",
    "query": {
      "mode": "grouped",
      "source": {"schema": "application", "name": "orders"},
      "projection": [
        {"kind": "dimension", "field": "status"},
        {"kind": "measure", "function": "count_all", "alias": "orders_count"}
      ],
      "maximum_limit": 100
    }
  }]
}
```

Неизвестный profile/datasource, отсутствие любого назначения или запрещённая
пара одинаково
возвращает `403 DENIED_OPERATION`. Отсутствующая aggregate capability даёт
`501 CAPABILITY_NOT_IMPLEMENTED`; тот же ответ без datasource call используется,
если profile содержит `time_bucket`, а adapter не объявляет cached feature
`time_bucket_utc`, либо содержит `numeric_bucket` без feature
`numeric_bucket_exact`. Непостроенный или инвалидированный snapshot —
`503 SERVICE_UNAVAILABLE`. Для required datasource отсутствие snapshot делает
`/health/ready` неготовым. Обновление snapshot в MVP выполняется только через
перезапуск процесса.

### `POST /queries/explain`

Принимает обязательные `profile`, `datasource` и структурированный `QuerySpec`.
В MVP MySQL 8 adapter строит
ограниченный `SELECT`, затем выполняет только `EXPLAIN FORMAT=JSON`. `source`
может быть разрешённой таблицей или доверенным view. Неизвестные объекты и
отсутствующие поля возвращают `422 UNSUPPORTED_QUERY`. Definitions, aliases и
dependencies views находятся под ответственностью администратора; denylist
проверяет только fields запрошенного объекта.

```json
{
  "profile": "query-explainer",
  "datasource": "primary-mysql",
  "query": {
    "source": {
      "schema": "application",
      "name": "orders"
    },
    "projection": [
      {"kind": "field", "field": "id"},
      {"kind": "field", "field": "status"},
      {
        "kind": "aggregate",
        "function": "count",
        "field": "id",
        "alias": "order_count"
      }
    ],
    "filter": {
      "kind": "predicate",
      "field": "status",
      "operator": "eq",
      "values": [
        {"type": "string", "value": "active"}
      ]
    },
    "group_by": ["id", "status"],
    "order_by": [
      {"field": "id", "direction": "desc"}
    ],
    "limit": 100,
    "offset": 0
  }
}
```

MVP не принимает client-defined joins, subqueries, unions, raw expressions,
пользовательские функции и выбор explain mode.

MySQL требует `SHOW VIEW` для EXPLAIN views, в том числе для обязательного plan
preflight aggregate и keyset. При SELECT-only datasource учётке эти операции
над разрешёнными views возвращают `503 DATABASE_UNAVAILABLE` до основного SELECT.
Preflight не обходится. Readiness, discovery, description и обычный SELECT views
работают с scoped SELECT; integration сохраняет именно SELECT-only учётку.

`order_by.field` всегда обозначает поле источника, а не alias проекции. Для grouped или aggregate запроса каждое поле сортировки должно также присутствовать в `group_by`; несовместимая форма отклоняется до обращения к СУБД.

### `GET /schemas/{schema}/objects?profile=...&datasource=...`

Возвращает полный policy-filtered список таблиц и views в
разрешённой схеме. Запрещённые objects не появляются в результате.
Effective `max_result_bytes` применяется только после policy-фильтрации:
закрытые objects не занимают бюджет и не могут вызвать его превышение.
Если уже разрешённый результат не помещается, возвращается
`413 RESULT_TOO_LARGE`; частичный список не выдаётся. Нефильтрованное чтение
metadata в adapter отдельно ограничено абсолютным implementation maximum.

Query string этих metadata endpoints закрыт: параметры `profile` и `datasource`
обязательны и должны встретиться ровно по одному разу, любые дополнительные,
case-folded либо повторяющиеся
параметры и percent-decoded значения с невалидным UTF-8 отклоняются с
`400 INVALID_REQUEST` до policy lookup и denial audit. Стандартные OpenAPI parameter
objects не выражают закрытость всего query string, поэтому контракт явно
помечает это application semantic через
`x-quordon-strict-query-parameters: true`, а runtime-поведение закреплено
двусторонними contract fixtures.

```json
{
  "policy_profile": "data-reader",
  "policy_version": "17",
  "datasource": "primary-mysql",
  "adapter": "mysql8",
  "schema": "application",
  "objects": [{"name": "orders"}]
}
```

### `GET /schemas/{schema}/objects/{object}?profile=...&datasource=...`

Возвращает только разрешённые columns таблицы или view: portable type,
MySQL-native type, nullable, primary-key и indexed flags. Отсутствующий,
запрещённый object неразличимы для клиента и возвращают `404 NOT_FOUND`.
Views возвращают свои columns без выдуманных primary-key/index flags.
Каждый schema request явно передаёт пару `profile`/`datasource`.

### `GET /schemas/{schema}/objects/{object}/statistics?profile=...&datasource=...`

Возвращает полное bounded-наблюдение engine metadata для разрешённой физической
InnoDB `BASE TABLE`: приблизительные `table_rows`, `data_length`,
`index_length`, наблюдаемое `auto_increment`, а также полный ordinally ordered
список партиций и субпартиций с их приблизительными метриками. Это отдельная
capability `describe_object_statistics`; разрешение `describe_object` её не
даёт. Разрешённый view возвращает `422 UNSUPPORTED_QUERY`: statistics для него
не поддерживается. Missing/denied objects, MyISAM и прочие неподдерживаемые
физические объекты возвращают `404 NOT_FOUND`.

Все целочисленные метрики передаются как канонические беззнаковые decimal
strings внутри `{value, estimated}` или как JSON `null`; JSON number,
экспонента, знак и leading zero запрещены. Endpoint не выполняет точный count и
не возвращает partition expressions, boundary values, comments, tablespaces,
пути, SQL, индексы или колонки. `observed_at` — UTC-время gateway после чтения
и валидации metadata, а не транзакционный snapshot DBMS.

Query string закрыт и содержит ровно по одному `profile` и `datasource`. Request body запрещён:
положительный `Content-Length`, handler-visible `Transfer-Encoding` или хотя бы
один decoded byte дают `400 INVALID_REQUEST` после Basic Auth, но до profile и
datasource. Любой метод кроме `GET` отклоняется до аутентификации с `405`;
реальный `HEAD` имеет пустое тело и передаёт stable code в
`X-Quordon-Error-Code`. Все ответы содержат `Cache-Control: no-store`.

Ответ никогда не усекается. Если даже минимальный envelope или полный набор
разрешённых partition metadata не помещается в effective `max_result_bytes`,
возвращается `413 RESULT_TOO_LARGE`. На одном ответе поддерживается не более
8192 физических partition leaves.

### `POST /queries/select`

Использует тот же envelope, но отдельную строгую OpenAPI-схему
`SimpleSelectQuerySpec`: только field projections, а свойство `group_by` и
aggregate-ветка projection отсутствуют в контракте. Поэтому даже
`"group_by": []` и aggregate projection отклоняются transport-валидацией с
`400 INVALID_REQUEST`, до policy и DBMS. Filter и sorting дополнительно
ограничиваются policy профиля. Adapter выполняет запрос в read-only
transaction, bind-ит все значения и всегда задаёт server-side `LIMIT`; source —
настроенный объект с колонками, включая trusted views.

Опубликованные protocol bounds одинаковы для SELECT и EXPLAIN: `limit` — от 1
до 1000000, `offset` — от 0 до 1000000000. Значения вне этих границ не
соответствуют OpenAPI и отклоняются строгим decoder с `400 INVALID_REQUEST`;
математически целые JSON numbers (`100`, `100.0`, `1e2`) эквивалентны и
принимаются без float64, но строки и числа с ненулевой дробной частью запрещены;
меньший `max_rows` профиля нормализует допустимый `limit`, а превышение
profile `max_offset` остаётся semantic error `422 UNSUPPORTED_QUERY`.

```json
{
  "profile": "data-reader",
  "datasource": "primary-mysql",
  "query": {
    "source": {"schema": "application", "name": "orders"},
    "projection": [
      {"kind": "field", "field": "id"},
      {"kind": "field", "field": "status"}
    ],
    "filter": {
      "kind": "predicate",
      "field": "status",
      "operator": "eq",
      "values": [{"type": "string", "value": "active"}]
    },
    "limit": 100
  }
}
```

Rows возвращаются positional arrays в порядке `columns`. SQL `NULL` кодируется
JSON `null`, binary и spatial values — opaque base64 string с
`encoding: "base64"`, остальные значения — строками без потери точности.
Unsigned integer metadata имеет portable type `integer`. `DATE`, `DATETIME` и
`TIMESTAMP` сохраняют нативное текстовое представление MySQL независимо от
`parseTime` в исходном DSN.
`row_count` равно числу реально возвращённых rows. `truncated: true` означает,
что дополнительные строки не вошли из-за normalized `limit` или
effective `max_result_bytes`; успешный усечённый ответ остаётся `200`.
Если не помещается уже первая строка, безопасный префикс содержит пустой
`rows`, `row_count: 0` и `truncated: true`.
Adapter отдельно ограничивает один входящий MySQL logical packet абсолютным
пределом 16 MiB плюс фиксированный 1 KiB allowance для result-row/protocol
framing. Packet выше этого implementation maximum возвращает
`413 RESULT_TOO_LARGE`, даже если до него были прочитаны другие строки; обычное
превышение effective profile byte budget возвращает безопасный префикс с
`truncated: true`.

```json
{
  "query_id": "q-01",
  "policy_profile": "data-reader",
  "policy_version": "17",
  "datasource": "primary-mysql",
  "adapter": "mysql8",
  "columns": [
    {"name": "id", "type": "integer", "encoding": "string", "nullable": false},
    {"name": "status", "type": "string", "encoding": "string", "nullable": false}
  ],
  "rows": [["42", "active"]],
  "row_count": 1,
  "truncated": false,
  "limits": {
    "deadline_ms": 1500,
    "max_request_bytes": 32768,
    "max_projection_fields": 25,
    "max_group_by_fields": 1,
    "max_order_by_fields": 10,
    "max_predicates": 25,
    "max_expression_depth": 6,
    "max_parameters": 50,
    "max_rows": 100,
    "max_result_bytes": 262144,
    "max_offset": 0,
    "max_concurrency": 1
  },
  "warnings": []
}
```

Row-level security в текущем MVP отсутствует. Профиль `select` должен разрешать
только таблицы, в которых principal может читать любую строку разрешённых
columns. `LIMIT` ограничивает ответ, но не число строк, просмотренных optimizer.

#### Keyset pagination

Тот же `POST /queries/select` имеет вторую, непересекающуюся ветку с обязательным
`kind: "keyset"`. Она требует отдельной capability `select_keyset` и точного
совпадения с одним именованным `query.keyset_select_shapes` выбранного profile.
Обычный SELECT не содержит `kind`; ответ на него также не содержит `kind`.

```json
{
  "kind": "keyset",
  "profile": "analytics",
  "datasource": "primary-mysql",
  "shape": "orders_by_id",
  "query": {
    "source": {"schema": "application", "name": "orders"},
    "projection": [
      {"kind": "field", "field": "id"},
      {"kind": "field", "field": "status"}
    ],
    "order_by": [{"field": "id", "direction": "asc"}],
    "limit": 100
  },
  "page": {"kind": "first"}
}
```

Следующая страница повторяет тот же query и передаёт выданный сервером cursor
без изменения его типов или порядка:

```json
{
  "kind": "after",
  "cursor": [{"type": "integer", "value": "1500"}]
}
```

Cursor — закрытый ordered tuple со string-encoded значениями типов `integer`,
`string`, `bytes`, `date`, `datetime` или `timestamp`; JSON numbers, `null` и
произвольные cursor types запрещены. `date` имеет канонический вид
`YYYY-MM-DD`, `datetime` — timezone-naive `YYYY-MM-DD HH:MM:SS[.fraction]`, а
`timestamp` — UTC instant с обязательными заглавными `T` и `Z`. Общий контракт
допускает только конечные значения, годы `0001`–`9999` и до девяти знаков
дробной секунды; offset, lowercase `t`/`z` и `infinity` запрещены до обращения к
datasource.

Полный order key задаётся `order_by` и состоит из `NOT NULL` columns.
Уникальность полного tuple гарантирует автор shape; unique index не требуется. MySQL adapter поддерживает точные
целочисленные keys, `CHAR`/`VARCHAR` с проверенным обратимым преобразованием
между исходным charset и UTF-8,
`BINARY`/`VARBINARY`, а также `DATE`, `DATETIME` и `TIMESTAMP`. Последние
отображаются соответственно в cursor types `date`, `datetime` и `timestamp`.
`ENUM`, `SET`, `TIME`, `YEAR`, decimal, floating-point, TEXT/BLOB, JSON и
spatial cursor keys отклоняются до SELECT.
Проекции `FLOAT`/`DOUBLE`/`REAL`, а также integer или DECIMAL columns с
`ZEROFILL` отклоняются с `422 UNSUPPORTED_QUERY` до EXPLAIN/SELECT: их native
представление не соответствует закрытому каноническому формату row values.
Для temporal cursor и typed temporal filters adapter до EXPLAIN проверяет
физические диапазоны MySQL: `DATE`/`DATETIME` начинаются с `0001` года, а
`TIMESTAMP` ограничен UTC диапазоном 1970-01-01 00:00:01 —
2038-01-19 03:14:07.499999. Cursor обязан иметь ровно FSP физической key column
(0–6). Параметры связываются через server-owned `CAST` с этой precision;
MySQL не получает произвольную строку для неявного temporal conversion.
`timestamp` cursor преобразуется adapter-ом из portable UTC `T`/`Z` в нативный
UTC operand. `bytes` filters разрешены только для binary/blob columns; `BIT`
отклоняется до EXPLAIN/SELECT.

Charset и collation character keys определяются из metadata, без списка
разрешённых кодировок в приложении. До `EXPLAIN`/`SELECT` MySQL проверяет
`UTF-8 → source charset → UTF-8` для каждого string/UUID filter и string cursor
посредством одного bounded constant SELECT без чтения source table. Совпадение
должно быть побайтным; замена символов или потеря данных даёт
`422 UNSUPPORTED_QUERY`. При чтении страницы скрытые boolean markers проверяют
обратный путь `source key → UTF-8 → source charset` для каждого character key;
необратимый ключ отвергает весь ответ до выдачи `200`, без пропуска строки или
частичной страницы. Markers не входят в публичные columns, rows или cursor.
В seek/filter predicates только параметр получает явный charset conversion и
исходную collation; индексированная колонка и `ORDER BY` не преобразуются.

Keyset строит ключ из настроенного `order_by` и metadata его колонок.
Автор shape гарантирует уникальность полного ordered tuple; доказательство через
unique index не требуется. Key columns остаются `NOT NULL`, поддерживаемых точных
типов, с проверкой cursor arity, precision, charset round-trip и budgets.
Отдельные страницы не имеют общего snapshot. Read-only `REPEATABLE READ`, UTC
session и bounded cleanup выполняются на одном соединении.

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

```json
{
  "kind": "keyset",
  "query_id": "q-01",
  "policy_profile": "analytics",
  "policy_version": "17",
  "shape": "orders_by_id",
  "datasource": "primary-mysql",
  "adapter": "mysql8",
  "columns": [
    {"name": "id", "type": "integer", "encoding": "string", "nullable": false},
    {"name": "status", "type": "string", "encoding": "string", "nullable": false}
  ],
  "rows": [["1501", "active"]],
  "row_count": 1,
  "truncated": true,
  "page": {
    "has_more": true,
    "next_cursor": [{"type": "integer", "value": "1501"}]
  },
  "limits": {
    "deadline_ms": 3000,
    "max_request_bytes": 65536,
    "max_projection_fields": 50,
    "max_group_by_fields": 20,
    "max_order_by_fields": 20,
    "max_predicates": 50,
    "max_expression_depth": 8,
    "max_parameters": 100,
    "max_rows": 1000,
    "max_result_bytes": 1048576,
    "max_offset": 0,
    "max_concurrency": 2
  },
  "warnings": []
}
```

`has_more: true` всегда сопровождается `next_cursor`, хотя бы одной строкой и
`truncated: true`; финальная страница имеет `has_more: false`, не содержит
cursor и возвращает `truncated: false`. Server заранее проверяет, что
канонический continuation request с максимальным cursor помещается в
`max_request_bytes`, поэтому не выдаёт непригодный cursor. Отдельные HTTP pages
не образуют общий snapshot: конкурентные изменения строк между запросами
наблюдаются по обычной keyset-семантике.
Когда safe prefix уже определён, adapter не дренирует оставшиеся строки:
physical connection немедленно закрывается и исключается из pool, что заодно
завершает read-only transaction
в пределах deadline.
`rows` всегда является JSON array, включая пустую финальную страницу; `null`
на месте массива считается внутренним нарушением adapter contract и не выдаётся
как успешный ответ. Portable response boundary проверяет канонический temporal
формат и общий диапазон, а concrete adapter — физический диапазон и precision.
Чтобы не менять существующий row contract, проекция MySQL `TIMESTAMP` остаётся
колонкой `datetime` с нативным текстом `YYYY-MM-DD HH:MM:SS[.fraction]`; только
соответствующий `next_cursor` нормализуется в `timestamp` с `T` и `Z`.

### `POST /queries/aggregate`

Выполняет scalar или grouped агрегат по одному настроенному объекту с columns, включая view. Это
отдельная capability и отдельный закрытый request contract: клиент выбирает
только mode, source, projection, filter, order и group limit. SQL, index hint,
estimate bound, `GROUP BY` expressions, arbitrary functions, joins, `HAVING`,
`OFFSET` и execution settings клиент передать не может.

```json
{
  "profile": "analytics",
  "datasource": "primary-mysql",
  "query": {
    "mode": "grouped",
    "source": {"schema": "application", "name": "orders"},
    "projection": [
      {"kind": "dimension", "field": "status"},
      {"kind": "measure", "function": "count_all", "alias": "orders_count"}
    ],
    "limit": 100
  }
}
```

Scalar mode допускает только measures и всегда возвращает ровно одну row.
Grouped mode требует хотя бы одну dimension, одну measure и `limit`; dimensions
одновременно задают `GROUP BY` и ограничиваются effective
`max_group_by_fields`. Поддерживаются `count_all`, `count`,
`count_distinct`, `min`, `max`, `sum` и `avg`. `count_distinct` имеет отдельное
policy-разрешение и не включается обычным `count`.

Grouped projection также поддерживает policy-curated UTC bucket:

```json
{"kind":"time_bucket","field":"created_at","unit":"day","timezone":"UTC","alias":"created_day"}
```

`unit` закрыт значениями `hour`, `day`, `week`, `month`, timezone в MVP всегда
явно равен `UTC`. Source должен быть `TIMESTAMP` или `DATETIME`; второй трактуется
как UTC wall-clock. Adapter генерирует одно собственное выражение для projection,
`GROUP BY` и bucket-order, возвращая канонический start вида
`2026-08-15T00:00:00Z`. Клиент не передаёт expression, format или offset.

Запрос должен точно совпасть с одним `aggregate_shapes` выбранного profile после
канонизации MySQL identifiers. Shape связывает ordered projection, полное
AND/OR-дерево filters с типами и arity placeholders, ordered sorting и
максимальный group limit. Значения bind parameters в shape не входят. При
отсутствии ровно одного совпадения возвращается `403 DENIED_QUERY_FEATURE` без
DBMS-вызова.

Output names (dimension fields и measure aliases) обязаны быть уникальны без
учёта ASCII-регистра. Доказуемая до обращения к datasource коллизия, например
`total`/`TOTAL`, возвращает `422 UNSUPPORTED_QUERY`; identifier-semantics lookup
и aggregate SQL в этом случае не выполняются.

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

MySQL может оптимизировать заведомо пустой aggregate до плана без `table` node.
Quordon принимает только два точных и структурно закрытых empty-plan варианта:
`Impossible WHERE` и `no matching row in const table`. Scalar response при этом
всё равно содержит одну строку: `COUNT` равен строке `"0"`, nullable measures
равны `null`. Другие планы без source table отклоняются fail-closed.

Вся последовательность выполняется на одном соединении в read-only
`REPEATABLE READ` consistent snapshot. Views и non-InnoDB objects допустимы;
изоляция underlying данных определяется СУБД. Definitions views и изменения
схемы являются доверенной обязанностью администратора, специального DDL lock нет.

Aggregate не является более слабой confidentiality boundary, чем `select`:
уникальные dimensions и differencing filters способны восстановить отдельные
строки. Profile может агрегировать только те rows и fields, которые principal
вправе читать напрямую. Отдельная aggregate-only модель disclosure suppression
в MVP отсутствует.

Результаты содержат positional string/null rows и portable column metadata.
Для grouped aggregate nullability `sum`/`avg`/`min`/`max` наследуется от source
field; для scalar aggregate эти measures nullable даже у `NOT NULL` source,
поскольку пустой input всё равно создаёт одну строку с SQL `NULL`.
Scalar response никогда не усекается: если envelope, metadata или единственная
row не помещаются, возвращается `413 RESULT_TOO_LARGE`. Grouped response при
row-limit или byte-budget overflow возвращает наибольший полный безопасный
prefix с `200` и `truncated: true`; prefix может быть пустым. Если не помещаются
уже фиксированный envelope и metadata, aggregate не выполняется и возвращается
`413`. Byte budget считается по фактически отправляемому compact JSON без
добавочного перевода строки или иного transport whitespace.

#### Фиксированные числовые распределения

В grouped `/queries/aggregate` dimension `numeric_bucket` возвращает индекс
фиксированного диапазона. Request projection содержит только `kind`, `field` и
`alias`; границы берутся из единственного совпавшего policy shape:

```json
{
  "profile": "analytics",
  "datasource": "primary-mysql",
  "query": {
    "mode": "grouped",
    "source": {"schema": "application", "name": "operations"},
    "projection": [
      {"kind": "numeric_bucket", "field": "duration_ms", "alias": "duration_bucket"},
      {"kind": "measure", "function": "count_all", "alias": "operations_count"}
    ],
    "order_by": [{"kind": "numeric_bucket", "alias": "duration_bucket", "direction": "asc"}],
    "limit": 20
  }
}
```

Для границ `["0", "100", "500", "1000"]` индексы `0…4` обозначают
`(-∞, 0)`, `[0, 100)`, `[100, 500)`, `[500, 1000)` и `[1000, +∞)`.
Колонка имеет `type: integer`, `encoding: string`, а `nullable` следует metadata
исходной колонки. Настоящий DB NULL становится JSON null; все индексы передаются
каноническими целыми строками. Возвращаются только непустые группы; пустой input
даёт `rows: []`, `row_count: 0`, `truncated: false`.

`asc` сортирует индексы численно с NULL первым; `desc` — с NULL последним.
Без `order_by` порядок не гарантируется. Несколько buckets, обычные и time
dimensions, filters и существующие measures комбинируются в точном policy shape;
row/byte bounds сохраняются.

Поддерживаются точные signed/unsigned INTEGER и DECIMAL. FLOAT/DOUBLE и
нечисловые источники дают `422 UNSUPPORTED_QUERY` до EXPLAIN и основного SELECT.
Дробные границы для integer-источника и границы вне его диапазона допустимы.
MySQL 8 выбирает точный `DECIMAL(p,s)` cast отдельно для каждой границы:
`p ≤ 65`, `s ≤ 30`. Непредставимая граница даёт такой же semantic `422`.
Это [сохраняет точное сравнение DECIMAL с INTEGER/DECIMAL](https://dev.mysql.com/doc/refman/8.4/en/type-conversion.html).

Discovery публикует `kind`, `field`, `alias`, `boundaries`; клиент при сборке
request исключает `boundaries`, а `maximum_limit` заменяет выбранным `limit`.
В request границы и лишние branch fields дают `400 INVALID_REQUEST`.
Adapter без cached feature `numeric_bucket_exact` возвращает
`501 CAPABILITY_NOT_IMPLEMENTED` для bucket execution и discovery всего
содержащего его профиля, без datasource calls. Частичный snapshot не публикуется.
API major остаётся `1`.

## Планируемые endpoints

### Cancellation

```text
POST /queries/{query_id}/cancellation
```

Доступен только для адаптеров с подтверждённой server-side cancellation. Принятие HTTP request не считается подтверждением остановки DB statement.

## Capability negotiation

Операции имеют стабильные имена:

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

`object_definition` и `cancel_query` зарезервированы как возможные будущие
capabilities, но текущая конфигурация их не принимает.

Если операция разрешена профилем, но выбранный adapter не реализует capability, gateway возвращает:

```http
HTTP/1.1 501 Not Implemented
```

```json
{
  "code": "CAPABILITY_NOT_IMPLEMENTED",
  "message": "The selected datasource adapter does not implement this capability",
  "request_id": "req-01",
  "policy_version": "17"
}
```

Проверка principal и всей пары profile-datasource выполняется до обращения к
adapter или datasource. Структурно неверный либо отсутствующий `datasource`
даёт `400`; неизвестная или запрещённая пара — неразличимый `403
DENIED_OPERATION`; отсутствующая capability разрешённой пары — `501`.

## HTTP-статусы

| Status | Значение |
|---:|---|
| `200` | Операция успешно выполнена |
| `202` | Асинхронная операция принята |
| `204` | Операция выполнена, body отсутствует |
| `400` | Некорректный JSON или параметры API |
| `401` | Basic credentials отсутствуют или неверны |
| `403` | Операция, профиль или ресурс отклонены политикой |
| `404` | Endpoint не найден либо schema object отсутствует или запрещён; statistics также скрывает неподдерживаемые физические объекты |
| `405` | HTTP method не поддерживается endpoint; для `/query-shapes` и table-statistics любой метод кроме `GET` отклоняется до аутентификации и audit |
| `409` | Конфликт состояния запроса |
| `413` | HTTP request (`REQUEST_TOO_LARGE`) или DBMS result (`RESULT_TOO_LARGE`) превышает допустимый размер |
| `415` | `Content-Type` отсутствует или не равен `application/json` |
| `422` | Структурированный запрос не поддерживается моделью или настроенными execution bounds; statistics для view не поддерживается |
| `500` | Внутренняя ошибка gateway |
| `501` | Adapter не реализует требуемую capability |
| `502` | Ошибка протокола или выполнения операции DBMS |
| `503` | Исчерпана concurrency capacity либо DBMS/обязательная зависимость недоступна; сюда относится отказ в аутентификации или необходимых datasource privileges |
| `504` | Истёк deadline операции |

HTTP `206` не используется для ограниченного результата. Успешный SELECT или
grouped aggregate возвращает `200` и `truncated: true`.

## Стабильные error codes

```text
AUTHENTICATION_REQUIRED
INVALID_CREDENTIALS
METHOD_NOT_ALLOWED
DENIED_OPERATION
DENIED_RESOURCE
DENIED_FIELD
DENIED_QUERY_FEATURE
INVALID_REQUEST
UNSUPPORTED_MEDIA_TYPE
REQUEST_TOO_LARGE
RESULT_TOO_LARGE
UNSUPPORTED_QUERY
CAPABILITY_NOT_IMPLEMENTED
QUERY_CONFLICT
QUERY_TIMEOUT
CAPACITY_EXCEEDED
SERVICE_UNAVAILABLE
DATABASE_UNAVAILABLE
UPSTREAM_ERROR
NOT_FOUND
INTERNAL_ERROR
```

Error message не содержит сведений о существовании закрытого объекта, адресе DBMS, DB user, DSN или исходном сообщении драйвера.

Тело `application/json` обязано быть корректным UTF-8. Некорректные байтовые
последовательности не нормализуются и возвращают `400 INVALID_REQUEST`.

## Успешный результат explain

```json
{
  "query_id": "q-01",
  "policy_profile": "query-explainer",
  "policy_version": "17",
  "datasource": "primary-mysql",
  "adapter": "mysql8",
  "format": "mysql_json",
  "plan": {
    "query_block": {
      "select_id": 1
    }
  },
  "limits": {
    "deadline_ms": 3000,
    "max_request_bytes": 65536,
    "max_projection_fields": 50,
    "max_group_by_fields": 50,
    "max_order_by_fields": 50,
    "max_predicates": 50,
    "max_expression_depth": 8,
    "max_parameters": 100,
    "max_rows": 1000,
    "max_result_bytes": 1048576,
    "max_offset": 10000,
    "max_concurrency": 2
  },
  "warnings": []
}
```

Gateway не пытается преобразовать vendor plan в общий универсальный формат. Поля `adapter` и `format` позволяют клиенту выбрать подходящий renderer.

## Диагностическое представление temporal-полей

По умолчанию календарные DATE/DATETIME используют корректные даты с годами
`0001–9999`; нулевые и невозможные даты не являются допустимыми typed dates или
temporal cursors. Обычный SELECT сохраняет прежнее чтение нативного текста.
Для гарантированного диагностического контракта выбирается `source_text`:

```json
{"kind":"field","field":"date_end","representation":"source_text"}
```

Этот optional non-null member допустим в field projections SELECT/EXPLAIN/keyset,
predicate filters, сортировке SELECT/keyset, aggregate dimensions и соответствующей
dimension sorting. В filter groups, measures, time buckets и проекциях legacy
aggregate EXPLAIN он запрещён. Единственное явное значение — `source_text`;
пустая строка, другие значения, неверные JSON types и `null` дают `400 INVALID_REQUEST`.

Для MySQL поддерживаются только DATE, DATETIME и TIMESTAMP; иной native type
даёт `422 UNSUPPORTED_QUERY` до основного SELECT/EXPLAIN. Колонка возвращается как
`type: string`, `encoding: string`. Нулевые, неполные и некалендарные значения
сохраняются текстом; DB NULL остаётся JSON null. TIMESTAMP выводится как нативный
текст в проверенной UTC session, без добавления `T`/`Z`.

Предикаты используют typed values `string`, включая equality/range/IN/LIKE;
null operators сохраняют пустой values array. Comparisons, grouping, ordering и
keyset continuation используют одно побайтовое текстовое представление без
календарной интерпретации. В aggregate диагностическая dimension поддерживает
обычные COUNT/COUNT_DISTINCT measures; representation на measure не добавляется.

Keyset ordering и единственная проекция каждого key field обязаны иметь одинаковое
представление. Диагностический key использует cursor `string`, возвращаемый сервером;
неверный cursor type отклоняется до datasource calls. Автор shape гарантирует
уникальность полного tuple при выбранном сравнении. NULL keys запрещены.

Profile должен явно разрешить `allow_source_text: true`; иначе запрос даёт
`403 DENIED_QUERY_FEATURE` до metadata lookup. Unsupported adapter feature даёт
`501 CAPABILITY_NOT_IMPLEMENTED` без DB calls. Denylist применяется к исходному
полю; representation не предоставляет дополнительные права. Scan estimate,
index constraints и temporary/filesort controls действуют и на диагностику.
Автоматического fallback из календарного представления нет.

## Типизированные значения

Predicate values имеют явный тип:

```json
{"type": "datetime", "value": "2026-08-14T12:00:00Z"}
```

Общий набор типов:

```text
boolean
integer
decimal
string
uuid
date
datetime
bytes
```

`datetime` соответствует OpenAPI `format: date-time` и RFC 3339. Разделители
`T`/`Z` регистронезависимы: варианты `2026-08-14T12:00:00Z` и
`2026-08-14t12:00:00z` одинаково допустимы. Gateway проверяет, но не
переписывает исходное строковое значение перед bind.

`integer` принимает математически целое JSON number в диапазоне `int64`:
`1`, `1.0` и `1e2` допустимы и означают соответственно `1`, `1` и `100`.
Строка `"1"` и числа с ненулевой дробной частью не принимаются. Для проверки SQL `NULL`
используются операторы `is_null` и `is_not_null` без bind-значений;
типизированное bind-значение `null` не поддерживается.

`decimal` принимает JSON number, включая экспоненциальную запись (`1e2`), либо
строку в fixed-point форме (`"100.00"`) для точного сохранения представления.
Экспоненциальная запись внутри строки не поддерживается.

`bytes` принимает только канонический standard Base64. Padding обязателен для
неполного четырёхсимвольного блока; URL-safe alphabet, переносы строк,
отсутствующий padding и ненулевые padding bits отклоняются без нормализации.

DBMS adapter валидирует преобразование общего типа в тип драйвера. Значения передаются через parameter binding и никогда не интерполируются в SQL.
