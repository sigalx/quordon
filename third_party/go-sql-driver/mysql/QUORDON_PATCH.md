# Quordon patch

This directory is a source copy of `github.com/go-sql-driver/mysql` v1.10.0,
licensed under MPL-2.0. Quordon adds a context-scoped incoming MySQL packet
limit so an oversized `EXPLAIN FORMAT=JSON` row is rejected from its protocol
header before the driver allocates memory for the packet body. It also exposes
an absolute per-connection operation deadline that caps configured socket
timeouts and therefore bounds context-free transaction `Commit` and `Rollback`.
When that absolute deadline expires, packet I/O preserves
`context.DeadlineExceeded` instead of collapsing it into an unavailable
connection error, so the gateway can keep its stable timeout classification.

The local changes are intentionally limited to `connection.go`,
`connection_test.go`, `errors.go`, `packets.go`, `readlimit.go`, and `rows.go`.
