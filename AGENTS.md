# Правила разработки Quordon для агентов

Этот файл действует для всего репозитория. Любое изменение реализации, OpenAPI,
конфигурации или тестов обязано соблюдать правила ниже. Если требование задачи
противоречит этому файлу, нельзя молча ослаблять проверку: сначала явно описать
противоречие и согласовать изменение контракта.

## Базовый принцип

Сначала проверить и авторизовать, затем выполнять действие.

Никакой SQL, metadata lookup по пользовательскому resource, вызов DBMS adapter,
внешний network call или иное прикладное действие не должно происходить, пока
соответствующий input не прошёл все доступные для этого этапа проверки.
Security audit отказа или ошибки разрешён и может быть обязательным, но он не
должен содержать credentials, query values, SQL, DSN или raw driver errors.

Обязательный типизированный поток:

```text
raw bytes
  -> structurally bounded input
  -> strictly decoded input
  -> OpenAPI-valid input
  -> semantically validated input
  -> authorized operation-bound token
  -> adapter/compiler/executor action
  -> bounded contract-valid response
```

Нельзя сокращать этот поток из соображений удобства или потому, что сейчас у
метода только один вызывающий код.

## OpenAPI является исполняемым контрактом

`openapi/openapi.yaml` и runtime обязаны совпадать в обе стороны:

- runtime не принимает значения, которые запрещены OpenAPI;
- OpenAPI не объявляет допустимыми формы, которые runtime детерминированно
  отвергает;
- required, nullable, enum/const, discriminator, `oneOf`, minimum/maximum,
  pattern, format, `minItems`/`maxItems` и `additionalProperties` реализуются
  буквально;
- если ограничение невозможно выразить схемой, оно документируется как
  semantic validation и покрывается contract-тестом;
- изменение runtime-типа требует одновременного изменения OpenAPI, примеров,
  документации и positive/negative tests;
- изменение OpenAPI без соответствующего runtime-теста не считается
  завершённым.

Vacuum проверяет качество и структуру спецификации, но сам по себе не доказывает
совпадение runtime с OpenAPI. Для изменённого endpoint нужны contract fixtures,
которые проверяются как схемой OpenAPI 3.1, так и реальным decoder/handler.

### Неисполняемые OpenAPI design drafts

По явно согласованной design-only задаче разрешён отдельный файл
`openapi/<feature>.yaml` со статусом `x-quordon-status: draft`. Такой файл:

- не является контрактом текущего бинарника, не публикуется как service
  discovery document и не используется для генерации клиентского кода;
- обязан прямо указывать в `info.description`, что runtime support отсутствует;
- не добавляет операцию в `openapi/openapi.yaml` или в фактически возвращаемый
  `/capabilities`;
- проверяется YAML/OpenAPI lint в `make lint`, но не требует фиктивного decoder
  или handler только ради design review;
- переносится в `openapi/openapi.yaml` только атомарно с implementation, positive и
  negative runtime tests и двунаправленными OpenAPI 3.1 contract fixtures.

Наличие design draft нельзя описывать как реализованный endpoint. Как только
появляется любой runtime path этой функции, исключение прекращает действовать:
draft и реализация должны быть перенесены в основной исполняемый контракт и
проверяться в обе стороны в одном изменении.

## Запрещено неявное преобразование типов

Тип JSON token является частью контракта. Нельзя автоматически преобразовывать:

- JSON string в integer/number/boolean;
- integer/number/boolean в JSON string;
- `null` в zero value, пустую строку, `false`, `0` или отсутствие поля;
- decimal/exponent number в integer без правила схемы, проверки точной
  интегральности и диапазона; при OpenAPI `type: integer` формы `1`, `1.0` и
  `1e0` являются одним математическим значением и не считаются coercion;
- пустую строку в отсутствующий optional identifier;
- массив из одного элемента в scalar и scalar в массив;
- неизвестное enum/discriminator value в default branch.

`"1"` и `1`, `"false"` и `false`, отсутствующее поле и явный `null` — разные
inputs. Если OpenAPI явно допускает несколько представлений через `oneOf`,
decoder обязан сохранить выбранную ветку и валидировать её отдельно; нельзя
сначала привести обе ветки к удобному типу и тем самым скрыть неверный token.

Явное представление в опубликованном контракте не является coercion: например,
если response schema определяет точное DB numeric value как string, ответ обязан
быть string. Но input number нельзя принимать как такую string и наоборот.

Не полагаться на нестрогие особенности `encoding/json`:

- он сопоставляет имена struct fields без учёта регистра;
- принимает duplicate object members и может объединять их;
- заменяет invalid UTF-8;
- zero values не сохраняют факт присутствия required/optional member;
- отдельные target types могут принять quoted number.

До обычного `Unmarshal` использовать strict token scan или presence-aware wire
types. Отклонять invalid UTF-8, duplicate keys, case-folded keys, unknown fields,
не-объектный top level, запрещённый `null` и branch-specific лишние поля.

## Порядок обработки HTTP request

Для прикладного request соблюдать порядок:

1. Проверить method/path, Basic Auth и точный media type.
2. Применить hard body limit до полного чтения и построения дерева.
3. Проверить UTF-8, top-level JSON type, duplicate/exact keys и structural
   maxima во время token scan; depth и array limits останавливают scan рано.
4. Выполнить strict decode без coercion и без молчаливых defaults.
5. Проверить OpenAPI shape, required/presence/discriminator rules и затем
   domain semantics.
6. Определить назначенный principal/profile/operation и effective limits.
7. Проверить capability до обращения к datasource.
8. Если policy зависит от server identifier semantics, получать их только после
   предыдущих проверок; failure классифицировать и аудировать. Datasource proxy
   обязан соответствовать задокументированному инварианту однородности.
9. Policy engine создаёт непрозрачный operation-bound authorization token.
10. Записать обязательный allow decision и получить execution capacity.
11. Только теперь вызвать manager/adapter/DBMS.
12. До материализации проверить result/packet/deadline limits, сформировать
    response точного OpenAPI-типа и записать completion audit.

Проверка после действия не заменяет проверку до действия. Повторная проверка
после действия допустима как дополнительная защита, например для concurrent DDL.

## Типизированная граница авторизации

- Только policy package создаёт `AuthorizedQuery`, `AuthorizedSchema` и будущие
  authorization tokens; их security-critical fields остаются unexported.
- Token привязывается к principal, profile, datasource, operation, resource,
  effective limits и нужной identifier semantics.
- Manager/executor принимает token, а не raw datasource/schema/object/query.
- Для разных операций используются разные constructors или более узкие token
  types. Token одной операции нельзя применить к другой.
- Metadata manager возвращает только policy-filtered objects/fields. Raw
  adapter metadata не пересекает trusted executor boundary.
- Нельзя добавлять `execute(sql)`, универсальный raw request executor или
  обходной helper «только для внутреннего использования».
- Capability проверяется до database call; unsupported operation возвращает
  `501` без открытия connection или metadata probe.

## Лимиты проверяются до дорогой работы

- Hard structural limits применяются до полной десериализации.
- Effective profile limits применяются сразу после определения profile и до
  выполнения запроса.
- Верхние границы конфигурации учитывают downstream arithmetic, duration
  conversion, channel allocation и platform `int`; overflow недопустим.
- Byte budget проверяется до создания больших string/base64/JSON buffers.
  Сначала вычислить точный или консервативный encoded size, затем
  материализовать значение.
- Packet/read limit действует до чтения тела пакета; effective response limit —
  после policy-фильтрации. Закрытые metadata не расходуют profile budget.
- Нельзя считать `LIMIT` достаточной защитой DBMS: сохраняются deadline,
  server-side timeout, curated indexed filters и pool/concurrency limits.
- Cleanup, row draining, audit write и graceful shutdown имеют собственные
  конечные deadlines и не могут зависнуть после request deadline.

MVP сознательно не реализует rate limiting и полноценную DoS-защиту. Это не
разрешает игнорировать дешёвые per-request bounds или допускать avoidable memory
amplification внутри одного корректно аутентифицированного request.

## Конфигурация и DBMS adapters

- Config decode отклоняет unknown fields, неверные типы, отсутствующие required
  fields и явный `null`, где он не разрешён.
- Presence-sensitive security options не моделировать обычным `bool`, если
  omission должен отличаться от `false`.
- Неизвестный adapter, capability, DSN option или несовместимая комбинация
  блокирует startup, если нет явно документированной безопасной нормализации.
- Security- и result-affecting DSN options adapter либо канонизирует, либо
  отклоняет. DSN не может ослабить TLS/read-only/bind-only/result encoding.
- Policy snapshot глубоко копирует maps/slices и не возвращает mutable aliases.
- Fingerprint вычисляется по canonical redacted policy; secrets не хешируются в
  audit-visible verifier.
- DBMS product/version и identifier semantics валидируются до readiness и
  повторно на operation path, где это требуется контрактом.

## Responses, errors и audit

- Response field types точно соответствуют OpenAPI; не использовать `any`, если
  набор вариантов можно выразить закрытым типом.
- Все внешние ошибки используют документированный HTTP status и stable code.
  Новый emitted code одновременно добавляется в OpenAPI и `docs/api.md`.
- Raw SQL, parameters, credentials, DSN, endpoints и driver errors не попадают
  в response/application logs/audit.
- Database errors классифицируются до audit: invalid, timeout, unavailable,
  result-too-large и upstream не смешиваются.
- Mandatory audit работает fail-closed и имеет bounded write timeout.
- Denial/completion audit не отменяется при disconnect клиента.
- Completion сохраняет duration, query shape hash, credential identifier,
  authorized resources/fields, result size и stable failure classification,
  когда эти данные уже известны.

## Обязательные negative tests

Для каждого нового или изменённого input/endpoint добавить, где применимо:

- отсутствие каждого required field;
- explicit `null` для required и optional non-null fields;
- string вместо number/integer/boolean и наоборот;
- quoted integer, non-integral fraction/exponent и range overflow для integer,
  а также positive fixtures для точных integral decimal/exponent forms;
- пустые identifiers и branch-specific лишние/отсутствующие fields;
- unknown, case-folded и duplicate JSON keys на каждом уровне;
- invalid UTF-8 и non-object top level;
- пустые/oversized arrays, excessive depth и повторяющиеся terms;
- OpenAPI-valid positive fixtures и OpenAPI-invalid negative fixtures;
- детерминированно unsupported endpoint shapes как schema restriction либо
  документированный semantic `422`;
- unsupported capability без datasource call;
- policy deny и попытку использовать zero/wrong-operation authorization token;
- hidden metadata, result truncation, oversized first/later row и encoded-value
  expansion до материализации;
- timeout/unavailable/invalid/result-too-large error mapping и audit fields;
- unsafe DSN/config aliases, omission и numeric overflow.

Проверять не только status, но и отсутствие DB/adapter call при раннем отказе.

## Критерий завершения изменения

Перед заявлением о готовности выполнить минимум:

```text
gofmt
go test ./...
go test -race ./...
go vet ./...
vacuum lint -d openapi/openapi.yaml
git diff --check
```

Для изменений adapter, SQL, schema metadata, DB errors, readiness или SELECT
обязателен `make integration` на поддерживаемой MySQL 8. Успешный lint OpenAPI
без contract fixtures не считается достаточной проверкой. Нельзя сообщать, что
проверка прошла, если она не запускалась или завершилась только частично.
