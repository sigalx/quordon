# Quordon

**Policy-controlled gateway for agent access to infrastructure.**

Quordon хранит реквизиты подключения в доверенной среде и предоставляет агентам
ограниченный типизированный API к инфраструктурным сервисам. Текущий MVP
реализует адаптер MySQL 8: клиент передаёт `QuerySpec`, а не SQL. Policy engine
авторизует всю спецификацию, после чего DBMS adapter безопасно строит SQL с
bind-параметрами. Архитектура допускает будущие адаптеры Redis, AMQP и других
сервисов без привязки имени продукта к конкретному протоколу.

Основной сценарий MVP — локальный gateway для программных агентов на машине
доверенного разработчика или оператора. Человек, policy и инфраструктура
считаются доверенными; агент не считается доверенным в вопросах доступа к
данным. Устойчивость локального HTTP-процесса к намеренному flooding со стороны
уже аутентифицированного агента не является гарантией MVP.

Quordon не является публичным edge-сервисом и не предназначен для прямого
размещения в недоверенной сети. Процесс сознательно не реализует терминацию
HTTPS, rate limiting, WAF, DDoS/DoS-защиту и другие perimeter controls. Для
удалённого использования их обеспечивает внешний ingress или reverse proxy;
соответствующие availability-риски приняты для MVP и исключены из его модели
угроз.

## MVP

Первая версия написана на Go 1.26 и поддерживает MySQL 8.x
(`>= 8.0, < 9.0`). MySQL 5.7, MySQL 9 и MariaDB этим adapter не
поддерживаются:

- `GET /health/live`;
- `GET /health/ready`;
- `GET /capabilities`;
- `GET /query-shapes?profile=...` — разрешённые публичные шаблоны для
  конструирования aggregate- и keyset-запросов без раскрытия execution policy;
  UTC time-bucket templates доступны через v2/v3, keyset templates — через
  явно выбранное v3-представление;
- `GET /schemas/{schema}/objects?profile=...` — policy-filtered список физических
  таблиц;
- `GET /schemas/{schema}/objects/{object}?profile=...` — разрешённые колонки,
  типы и признаки primary/index;
- `GET /schemas/{schema}/objects/{object}/statistics?profile=...` — полная
  bounded-статистика InnoDB-таблицы, партиций и субпартиций без точного count;
- `POST /queries/explain` — только `EXPLAIN FORMAT=JSON` над сгенерированным
  `SELECT` из физической таблицы MySQL 8;
- `POST /queries/select` — ограниченный field-only `SELECT` из физической
  таблицы с bind-параметрами, обязательным `LIMIT` и явным `truncated`, а также
  policy-curated keyset pagination по полному уникальному индексу;
- `POST /queries/aggregate` — scalar/grouped агрегаты, включая operator-curated
  UTC hour/day/week/month buckets, по заранее разрешённым indexed shapes с
  bind-параметрами, policy-owned `FORCE INDEX` и plan preflight;
- HTTP Basic Auth на каждом прикладном запросе;
- строгую policy-конфигурацию, allow/deny для схем, объектов, полей и операций;
- deadlines, server-side execution timeout, concurrency/body/result limits;
- обязательные структурированные audit events без SQL, значений и секретов;
- несколько datasources с отдельными connection pools.

MVP не принимает произвольный SQL и не поддерживает `EXPLAIN ANALYZE`, views,
joins, subqueries, unions или raw expressions. Исполняемый `SELECT` уже, чем
explain: только поля, без aggregates и `group_by`. Агрегаты имеют отдельный
закрытый request contract и требуют точного совпадения с operator-curated shape
из policy. Источник любой query operation обязан быть физической таблицей: это
не даёт плану или результату раскрыть зависимости представления, закрытые
policy.

Row-level security и обязательные server-side predicates пока не реализованы.
Профиль с operation `select` или `select_keyset` безопасно назначать только для
curated tables, где агенту разрешено читать любую строку в пределах разрешённых
columns. `LIMIT` ограничивает объём ответа, но сам по себе не гарантирует дешёвый
план запроса; keyset дополнительно требует policy-owned index и plan preflight.

## Архитектура

Core не зависит от конкретной DBMS. Особенности SQL, quoting, `EXPLAIN`,
соединений и ошибок изолированы в adapters:

```text
HTTP request
  -> Validated QuerySpec
  -> operation-bound Authorized QuerySpec
  -> MySQL 8 adapter
  -> schema/statistics metadata / EXPLAIN FORMAT=JSON / bounded SELECT, keyset or aggregate
```

Один процесс предоставляет одну major-версию API. Внутренние маршруты не имеют
приставки `/v1`; при необходимости её добавляет и снимает border proxy.

## Сборка и проверка

```bash
make verify
make build VERSION=0.1.0
./bin/quordon --version
```

`make verify` запускает unit-тесты, `go vet` и Vacuum для OpenAPI. Полный smoke
test с настоящим MySQL 8.4:

```bash
make integration
```

Для запуска создайте policy с обязательными правами `0600`:

```bash
install -m 600 config/policy.example.yaml config/policy.yaml
```

Задайте bcrypt hash Basic-пароля и DSN inline либо через secret references,
затем выдайте MySQL-пользователю разрешённые `SELECT` grants и динамическое
право `BACKUP_ADMIN`. Последнее нужно adapter для `LOCK INSTANCE FOR BACKUP`:
guard берётся до проверки `BASE TABLE` и не позволяет concurrent DDL подменить
проверенный объект view до окончания `EXPLAIN`/`SELECT`/`AGGREGATE` либо чтения
статистики таблицы и партиций. После этого запустите:

```bash
QUORDON_CONFIG=config/policy.yaml ./bin/quordon
```

Адрес задаётся полем `server.listen` в policy. Флаг `--listen` (`-l`) и переменная
`QUORDON_LISTEN` позволяют переопределить его при запуске; override проходит
ту же проверку `host:port` и диапазона порта, что и policy. Audit JSON пишется в
stdout, application logs — в stderr. Сам Quordon принимает HTTP и не
терминирует TLS. Удалённый клиент должен обращаться к HTTPS ingress, который
передаёт запросы Quordon внутри доверенного сетевого сегмента.

Готовые Linux archives и Debian packages для `amd64`/`arm64` публикуются в
GitHub Releases. Пакет устанавливает hardened systemd unit, но не создаёт
рабочую policy и не запускает service до явного решения оператора. Полная
инструкция: [сборка и установка пакетов](docs/packaging.md).

Quordon безусловно отказывается запускаться, если policy не является обычным
файлом или его Unix permissions отличаются от `0600`.

## Документация

- [Обязательные правила разработки для агентов](AGENTS.md)
- [OpenAPI MVP](openapi/openapi.yaml)
- [OpenAPI aggregate module](openapi/aggregate.yaml)
- [OpenAPI keyset-pagination module](openapi/keyset-pagination.yaml)
- [OpenAPI query-shape discovery module](openapi/query-shapes.yaml)
- [OpenAPI table-statistics module](openapi/table-statistics.yaml)
- [REST API](docs/api.md)
- [Архитектура](docs/architecture.md)
- [Модель безопасности](docs/security-model.md)
- [Конфигурация политик](docs/policy-configuration.md)
- [Эксплуатация](docs/operations.md)
- [Сборка и установка пакетов](docs/packaging.md)
- [Стратегия тестирования](docs/testing.md)
- [План развития](docs/development-plan.md)
- [Беклог](docs/backlog.md)

## Лицензия

Собственный код Quordon распространяется на условиях
[Apache License 2.0](LICENSE).

Встроенная модифицированная копия `github.com/go-sql-driver/mysql` сохраняет
лицензию MPL-2.0. Её условия и описание локальных изменений находятся в
[`third_party/go-sql-driver/mysql`](third_party/go-sql-driver/mysql).
Уведомления и полные тексты лицензий остальных статически слинкованных
компонентов перечислены в [third-party notices](third_party/NOTICE.md).
