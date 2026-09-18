# Third-party notices

The Quordon executable is statically linked with the Go 1.26 standard library
and the following runtime modules. Their copyright notices and license terms
must accompany binary distributions.

The corresponding complete notices are distributed in `licenses/`:

- Go 1.26 standard library — BSD 3-Clause;
- `filippo.io/edwards25519` v1.2.0 — BSD 3-Clause;
- `github.com/go-sql-driver/mysql` v1.10.0 — MPL-2.0; Quordon carries a
  modified source copy and describes those changes in
  `go-sql-driver-mysql.md`;
- `golang.org/x/crypto` v0.55.0 — BSD 3-Clause;
- `gopkg.in/yaml.v3` v3.0.1 — MIT and Apache-2.0.

Quordon itself is licensed under Apache-2.0. Its license is distributed as
`LICENSE` in portable archives and documented by the Debian copyright file in
the Debian package.
