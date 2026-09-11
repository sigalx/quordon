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
  aggregate and keyset queries without exposing the execution policy; UTC time
  bucket templates are available through v2/v3 representations, while keyset
  templates require an explicitly selected v3 representation;
- `GET /schemas/{schema}/objects?profile=...` — a policy-filtered list of
  physical tables;
- `GET /schemas/{schema}/objects/{object}?profile=...` — authorized columns,
  portable types, and primary/index attributes;
- `GET /schemas/{schema}/objects/{object}/statistics?profile=...` — fully
  bounded InnoDB table, partition, and subpartition statistics without an exact
  row count;
- `POST /queries/explain` — only `EXPLAIN FORMAT=JSON` over a generated `SELECT`
  from a physical MySQL 8 table;
- `POST /queries/select` — a bounded field-only `SELECT` from a physical table,
  with bound parameters, a mandatory `LIMIT`, explicit `truncated` state, and
  policy-curated keyset pagination over a complete unique index;
- `POST /queries/aggregate` — scalar and grouped aggregates, including
  operator-curated UTC hour/day/week/month buckets, over pre-authorized indexed
  shapes with bound parameters, a policy-owned `FORCE INDEX`, and plan
  preflight;
- HTTP Basic Auth on every application request;
- strict policy configuration with allow/deny rules for schemas, objects,
  fields, and operations;
- deadlines, server-side execution timeout, and concurrency/body/result
  limits;
- mandatory structured audit events without SQL, values, or secrets;
- multiple datasources with independent connection pools.

The MVP does not accept arbitrary SQL and does not support `EXPLAIN ANALYZE`,
views, joins, subqueries, unions, or raw expressions. Executable `SELECT` is
narrower than explain: fields only, without aggregates or `group_by`.
Aggregates have a separate closed request contract and must exactly match an
operator-curated shape from the policy. Every query operation must use a
physical table as its source, preventing a plan or result from exposing view
dependencies that are closed by policy.

Row-level security and mandatory server-side predicates are not implemented
yet. A profile containing the `select` or `select_keyset` operation is safe to
assign only for curated tables where the agent may read every row within the
authorized columns. `LIMIT` bounds response volume but does not by itself
guarantee an inexpensive query plan; keyset queries additionally require a
policy-owned index and plan preflight.

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
make build VERSION=0.1.0
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

Set a bcrypt hash for the Basic Auth password and configure each DSN either
inline or through secret references. Grant the MySQL user the authorized
`SELECT` privileges and the dynamic `BACKUP_ADMIN` privilege. The adapter needs
the latter for `LOCK INSTANCE FOR BACKUP`: the guard is acquired before the
`BASE TABLE` check and prevents concurrent DDL from replacing the verified
object with a view before `EXPLAIN`, `SELECT`, `AGGREGATE`, or table and
partition statistics collection completes. Then start Quordon:

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
