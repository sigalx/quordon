# Quordon

**Policy-controlled gateway for agent access to infrastructure.**

Quordon keeps connection credentials inside a trusted environment and exposes a
limited, typed API through which software agents can access infrastructure
services. The current MVP implements a MySQL 8 adapter: clients submit a
`QuerySpec`, not SQL. The policy engine authorizes the complete specification,
after which the DBMS adapter safely compiles it into SQL with bound parameters.
The architecture allows future Redis, AMQP, and other service adapters without
tying the product name to a specific protocol.

The primary MVP use case is a local gateway for software agents running on a
trusted developer or operator machine. The human operator, policy, and
infrastructure are trusted; the agent is not trusted to decide which data it may
access. Resilience of the local HTTP process against deliberate flooding by an
already authenticated agent is not an MVP guarantee.

Quordon is not a public edge service and must not be exposed directly to an
untrusted network. The process deliberately does not implement HTTPS
termination, rate limiting, WAF, DDoS/DoS protection, or other perimeter
controls. For remote use, an external ingress or reverse proxy must provide
those controls. The corresponding availability risks are consciously accepted
for the MVP and excluded from its threat model.

## MVP

The first release is written in Go 1.26 and supports MySQL 8.x
(`>= 8.0, < 9.0`). MySQL 5.7, MySQL 9, and MariaDB are not supported by this
adapter:

- `GET /health/live`;
- `GET /health/ready`;
- `GET /capabilities`;
- `GET /query-shapes?profile=...` — authorized public templates for composing
  aggregate and keyset queries through one `application/json` contract, including
  UTC time buckets and explicit diagnostic temporal text; execution controls
  remain private;
- `GET /schemas/{schema}/objects?profile=...` — a policy-filtered list of
  tables and trusted views;
- `GET /schemas/{schema}/objects/{object}?profile=...` — authorized columns,
  portable types, and primary/index attributes;
- `GET /schemas/{schema}/objects/{object}/statistics?profile=...` — fully
  bounded InnoDB table, partition, and subpartition statistics without an exact
  row count;
- `POST /queries/explain` — only `EXPLAIN FORMAT=JSON` over a generated `SELECT`
  from a MySQL 8 table or trusted view;
- `POST /queries/select` — a bounded field-only `SELECT` from a table or trusted view,
  with bound parameters, a mandatory `LIMIT`, explicit `truncated` state, and
  policy-curated keyset pagination over a policy-defined unique ordered tuple;
- `POST /queries/aggregate` — scalar and grouped aggregates, including
  operator-curated UTC hour/day/week/month buckets, over pre-authorized
  shapes with bound parameters and bounded plan preflight;
- HTTP Basic Auth on every application request;
- strict policy configuration with allow/deny rules for schemas, objects,
  fields, and operations;
- deadlines, server-side execution timeout, and concurrency/body/result
  limits;
- mandatory structured audit events without SQL, values, or secrets;
- multiple datasources with independent connection pools.

The MVP does not accept arbitrary SQL, `EXPLAIN ANALYZE`, client-defined joins,
subqueries, unions, functions or raw expressions. Trusted views may contain joins
and materialized results. Executable `SELECT` uses fields only, without aggregates
or `group_by`; aggregates must match an operator-curated policy shape.

The DBMS administrator and policy author are trusted. Deny rules apply to fields
of the requested object; an underlying-column denial does not propagate to view
aliases. Administrators own view definitions, dependency disclosure, alias safety,
schema changes and uniqueness of each full keyset ordered tuple. Quordon does not
analyze view dependencies or protect against concurrent DDL. Ordinary DBMS metadata
locks remain in effect.

Row-level security and mandatory server-side predicates are not implemented
yet. A profile containing the `select` or `select_keyset` operation is safe to
assign only for curated tables where the agent may read every row within the
authorized columns. `LIMIT` bounds response volume but does not by itself
guarantee an inexpensive query plan; aggregate and keyset queries additionally require bounded plan preflight.
Optional `required_index` constrains physical plan reads without an SQL hint.
Temporary work and filesort require execution-only opt-ins, default false.

## Architecture

The core does not depend on a specific DBMS. SQL dialect details, quoting,
`EXPLAIN`, connections, and driver errors are isolated in adapters:

```text
HTTP request
  -> Validated QuerySpec
  -> operation-bound Authorized QuerySpec
  -> MySQL 8 adapter
  -> schema/statistics metadata / EXPLAIN FORMAT=JSON / bounded SELECT, keyset or aggregate
```

One process exposes one major API version. Internal routes do not use a `/v1`
prefix; a border proxy may add and remove one when required.

## Build and verification

```bash
make verify
make build VERSION=0.1.3
./bin/quordon --version
```

`make verify` runs unit and vendored-driver regression tests, `go vet`, Vacuum
OpenAPI linting, and third-party notice verification. Run the full smoke test
against a real MySQL 8.4 instance with:

```bash
make integration
```

Create a policy file with the mandatory `0600` permissions before starting the
service:

```bash
install -m 600 config/policy.example.yaml config/policy.yaml
```

From 0.1.3, policies can reuse local YAML nodes with `$ref` and replace direct
mapping fields with `$override`. One profile still routes to one datasource;
clients select assigned profiles. See [the reference example](config/policy.references.yaml)
and [assembly rules and limits](docs/policy-configuration.md).
All referenced files must also have mode `0600` and stay inside the main policy
directory. Validate assembly and general semantics without database, HTTP or
credential resolution:

```bash
./bin/quordon --check-config --config config/policy.yaml
```

This check does not confirm database readiness, grants or physical shape
compatibility. Exit status is 0 for success, 1 for configuration errors and 2
for argument errors; `--check-config` cannot be combined with `--version`.

Set a bcrypt hash for the Basic Auth password and configure each DSN either
inline or through secret references. Grant the MySQL user the authorized
`SELECT` privileges. MySQL additionally requires scoped `SHOW VIEW` privileges
for EXPLAIN views, including aggregate and keyset plan preflight. Readiness and
ordinary SELECT work with SELECT-only credentials; view EXPLAIN, aggregate and
keyset return `503 DATABASE_UNAVAILABLE` without SHOW VIEW, before the main
SELECT. Integration deliberately keeps its account SELECT-only and verifies
this MySQL limitation. No operation requires an administrative privilege.
Remove the obsolete `ddl_guard_mode` field before upgrading: it is now an
unknown configuration field and blocks startup. Then start Quordon:

```bash
QUORDON_CONFIG=config/policy.yaml ./bin/quordon
```

The listen address is configured through `server.listen` in the policy. The
`--listen` (`-l`) flag and `QUORDON_LISTEN` environment variable can override it
at startup; the override is subject to the same `host:port` and port-range
validation as the policy. Audit JSON is written to stdout and application logs
to stderr. Quordon itself accepts HTTP and does not terminate TLS. Remote clients
must connect through an HTTPS ingress that forwards requests to Quordon within a
trusted network segment.

Prebuilt Linux archives and Debian packages for `amd64` and `arm64` are
published through GitHub Releases. The package installs a hardened systemd unit
but does not create an active policy or start the service without an explicit
operator decision. See [Building and installing packages](docs/packaging.md)
for the complete instructions.

Quordon always refuses to start unless the policy is a regular file whose Unix
permissions are exactly `0600`.

## Documentation

- [Mandatory development rules for agents](AGENTS.md)
- [MVP OpenAPI](openapi/openapi.yaml)
- [Aggregate OpenAPI module](openapi/aggregate.yaml)
- [Keyset pagination OpenAPI module](openapi/keyset-pagination.yaml)
- [Query-shape discovery OpenAPI module](openapi/query-shapes.yaml)
- [Table statistics OpenAPI module](openapi/table-statistics.yaml)
- [REST API](docs/api.md)
- [Architecture](docs/architecture.md)
- [Security model](docs/security-model.md)
- [Policy configuration](docs/policy-configuration.md)
- [Operations](docs/operations.md)
- [Building and installing packages](docs/packaging.md)
- [Testing strategy](docs/testing.md)
- [Development plan](docs/development-plan.md)
- [Backlog](docs/backlog.md)

## License

Quordon's original code is distributed under the
[Apache License 2.0](LICENSE).

The bundled modified copy of `github.com/go-sql-driver/mysql` remains licensed
under MPL-2.0. Its license terms and a description of the local changes are in
[`third_party/go-sql-driver/mysql`](third_party/go-sql-driver/mysql).
Notices and complete license texts for the other statically linked components
are listed in [third-party notices](third_party/NOTICE.md).
