#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
dist_dir=${1:-"$repo_root/dist"}

case "$(uname -m)" in
    x86_64)
        package_arch=amd64
        ;;
    aarch64|arm64)
        package_arch=arm64
        ;;
    *)
        echo "unsupported smoke-test architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

mapfile -t packages < <(find "$dist_dir" -maxdepth 1 -type f -name "quordon_*_${package_arch}.deb" -print | sort)
if [ "${#packages[@]}" -ne 1 ]; then
    echo "expected exactly one ${package_arch} Debian package in $dist_dir, found ${#packages[@]}" >&2
    exit 1
fi

package=${packages[0]}

mapfile -t archives < <(find "$dist_dir" -maxdepth 1 -type f -name "quordon_*_linux_${package_arch}.tar.gz" -print | sort)
if [ "${#archives[@]}" -ne 1 ]; then
    echo "expected exactly one ${package_arch} Linux archive in $dist_dir, found ${#archives[@]}" >&2
    exit 1
fi

archive=${archives[0]}
archive_root=$(basename "$archive" .tar.gz)
for archived_path in \
    quordon \
    LICENSE \
    README.md \
    config/policy.example.yaml \
    packaging/man/quordon.1 \
    packaging/systemd/quordon.service \
    licenses/filippo.io-edwards25519-BSD-3-Clause.txt \
    licenses/go-sql-driver-mysql-MPL-2.0.txt \
    licenses/go-standard-library-BSD-3-Clause.txt \
    licenses/golang.org-x-crypto-BSD-3-Clause.txt \
    licenses/gopkg.in-yaml.v3-MIT-and-Apache-2.0.txt \
    third-party/NOTICE.md \
    third-party/go-sql-driver-mysql.md; do
    tar -tzf "$archive" "$archive_root/$archived_path" >/dev/null
done

if ! tar --numeric-owner -tvzf "$archive" | awk '
    $1 ~ /^-/ && $2 != "0/0" {
        print "non-root archive ownership: " $0 > "/dev/stderr"
        invalid = 1
    }
    END { exit invalid }
'; then
    echo "portable archive contains files not owned by root:root" >&2
    exit 1
fi

(cd "$dist_dir" && sha256sum --check checksums.txt)

for packaged_path in \
    ./usr/bin/quordon \
    ./usr/lib/systemd/system/quordon.service \
    ./usr/share/doc/quordon/examples/policy.yaml \
    ./usr/share/doc/quordon/copyright \
    ./usr/share/man/man1/quordon.1.gz \
    ./usr/share/doc/quordon/third-party/NOTICE.md \
    ./usr/share/doc/quordon/third-party/go-sql-driver-mysql.md \
    ./usr/share/doc/quordon/third-party/licenses/filippo.io-edwards25519-BSD-3-Clause.txt \
    ./usr/share/doc/quordon/third-party/licenses/go-sql-driver-mysql-MPL-2.0.txt \
    ./usr/share/doc/quordon/third-party/licenses/go-standard-library-BSD-3-Clause.txt \
    ./usr/share/doc/quordon/third-party/licenses/golang.org-x-crypto-BSD-3-Clause.txt \
    ./usr/share/doc/quordon/third-party/licenses/gopkg.in-yaml.v3-MIT-and-Apache-2.0.txt; do
    dpkg-deb --fsys-tarfile "$package" | tar -tf - "$packaged_path" >/dev/null
done

docker run --rm \
    --mount "type=bind,source=$package,target=/tmp/quordon.deb,readonly" \
    --mount "type=bind,source=$repo_root/config/policy.example.yaml,target=/tmp/policy.example.yaml,readonly" \
    --mount "type=bind,source=$repo_root/packaging/tests/mock-bin,target=/tmp/quordon-mock-bin,readonly" \
    debian:bookworm-slim \
    sh -euxc '
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y /tmp/quordon.deb

        test "$(dpkg-query -W -f="\${db:Status-Status}" quordon)" = installed
        test "$(quordon --version)" != dev
        test -f /usr/lib/systemd/system/quordon.service
        test ! -e /etc/quordon/policy.yaml
        test ! -e /etc/systemd/system/multi-user.target.wants/quordon.service
        test "$(stat -c %a /etc/quordon)" = 750
        test "$(stat -c %U:%G /etc/quordon)" = root:quordon
        getent passwd quordon >/dev/null
        DPKG_MAINTSCRIPT_PACKAGE=quordon deb-systemd-helper debian-installed quordon.service

        install -o quordon -g quordon -m 0600 \
            /tmp/policy.example.yaml \
            /etc/quordon/policy.yaml
        before=$(sha256sum /etc/quordon/policy.yaml)

        DEBIAN_FRONTEND=noninteractive apt-get install --reinstall -y /tmp/quordon.deb
        test "$before" = "$(sha256sum /etc/quordon/policy.yaml)"
        test "$(stat -c %a /etc/quordon/policy.yaml)" = 600
        test "$(stat -c %U:%G /etc/quordon/policy.yaml)" = quordon:quordon

        maintscript_log=/tmp/quordon-maintscript.log
        : >"$maintscript_log"
        before_alt_root=$(sha256sum /etc/quordon/policy.yaml)
        if DPKG_ROOT=/tmp/quordon-alt-root \
            PATH=/tmp/quordon-mock-bin:$PATH \
            QUORDON_MAINTSCRIPT_TEST_LOG="$maintscript_log" \
            /var/lib/dpkg/info/quordon.postinst configure \
            >/tmp/dpkg-root-postinst.log 2>&1; then
            echo "postinst accepted a non-empty DPKG_ROOT" >&2
            exit 1
        fi
        if DPKG_ROOT=/tmp/quordon-alt-root \
            PATH=/tmp/quordon-mock-bin:$PATH \
            QUORDON_MAINTSCRIPT_TEST_LOG="$maintscript_log" \
            /var/lib/dpkg/info/quordon.prerm remove \
            >/tmp/dpkg-root-prerm.log 2>&1; then
            echo "prerm accepted a non-empty DPKG_ROOT" >&2
            exit 1
        fi
        if DPKG_ROOT=/tmp/quordon-alt-root \
            PATH=/tmp/quordon-mock-bin:$PATH \
            QUORDON_MAINTSCRIPT_TEST_LOG="$maintscript_log" \
            /var/lib/dpkg/info/quordon.postrm purge \
            >/tmp/dpkg-root-postrm.log 2>&1; then
            echo "postrm accepted a non-empty DPKG_ROOT" >&2
            exit 1
        fi
        grep -F "chrootless maintainer scripts with DPKG_ROOT are not supported" \
            /tmp/dpkg-root-postinst.log \
            /tmp/dpkg-root-prerm.log \
            /tmp/dpkg-root-postrm.log
        test ! -s "$maintscript_log"
        test "$before_alt_root" = "$(sha256sum /etc/quordon/policy.yaml)"

        if PATH=/tmp/quordon-mock-bin:$PATH \
            QUORDON_TEST_NSS_SHADOW=group \
            /var/lib/dpkg/info/quordon.postinst configure \
            >/tmp/group-shadow.log 2>&1; then
            echo "postinst accepted a shadowed NSS group" >&2
            exit 1
        fi
        grep -F "refusing NSS group shadowing for quordon" /tmp/group-shadow.log

        if PATH=/tmp/quordon-mock-bin:$PATH \
            QUORDON_TEST_NSS_SHADOW=passwd \
            /var/lib/dpkg/info/quordon.postinst configure \
            >/tmp/passwd-shadow.log 2>&1; then
            echo "postinst accepted a shadowed NSS account" >&2
            exit 1
        fi
        grep -F "refusing NSS account shadowing for quordon" /tmp/passwd-shadow.log

        DPKG_MAINTSCRIPT_PACKAGE=quordon deb-systemd-helper enable quordon.service
        test -L /etc/systemd/system/multi-user.target.wants/quordon.service
        DPKG_MAINTSCRIPT_PACKAGE=quordon \
            DPKG_MAINTSCRIPT_NAME=prerm \
            /var/lib/dpkg/info/quordon.prerm remove
        test ! -e /etc/systemd/system/multi-user.target.wants/quordon.service
        DPKG_MAINTSCRIPT_PACKAGE=quordon \
            DPKG_MAINTSCRIPT_NAME=postinst \
            /var/lib/dpkg/info/quordon.postinst abort-remove 0.0.0
        test -L /etc/systemd/system/multi-user.target.wants/quordon.service
        DPKG_MAINTSCRIPT_PACKAGE=quordon deb-systemd-helper disable quordon.service

        install -d /run/systemd/system
        : >"$maintscript_log"
        if PATH=/tmp/quordon-mock-bin:$PATH \
            QUORDON_MAINTSCRIPT_TEST_LOG="$maintscript_log" \
            QUORDON_TEST_SYSTEMD_ACTIVE=yes \
            QUORDON_TEST_INVOKE_RESTART_FAIL=yes \
            /var/lib/dpkg/info/quordon.postinst configure 0.0.0; then
            echo "mocked failing upgrade restart unexpectedly succeeded" >&2
            exit 1
        fi
        test -f /run/quordon-maintscript/service-was-active-before-upgrade
        grep -F "deb-systemd-invoke restart quordon.service" "$maintscript_log"
        PATH=/tmp/quordon-mock-bin:$PATH \
            QUORDON_MAINTSCRIPT_TEST_LOG="$maintscript_log" \
            QUORDON_TEST_SYSTEMD_ACTIVE=no \
            /var/lib/dpkg/info/quordon.postinst abort-upgrade 0.0.1
        test ! -e /run/quordon-maintscript/service-was-active-before-upgrade
        grep -F "systemctl --system start quordon.service" "$maintscript_log"

        : >"$maintscript_log"
        PATH=/tmp/quordon-mock-bin:$PATH \
            QUORDON_MAINTSCRIPT_TEST_LOG="$maintscript_log" \
            QUORDON_TEST_SYSTEMD_ACTIVE=yes \
            /var/lib/dpkg/info/quordon.prerm remove
        test -f /run/quordon-maintscript/service-was-active-before-remove
        grep -F "deb-systemd-invoke stop quordon.service" "$maintscript_log"
        PATH=/tmp/quordon-mock-bin:$PATH \
            QUORDON_MAINTSCRIPT_TEST_LOG="$maintscript_log" \
            QUORDON_TEST_SYSTEMD_ACTIVE=no \
            /var/lib/dpkg/info/quordon.postinst abort-remove 0.0.0
        test ! -e /run/quordon-maintscript/service-was-active-before-remove
        grep -F "systemctl --system start quordon.service" "$maintscript_log"
        rmdir /run/systemd/system

        DPKG_MAINTSCRIPT_PACKAGE=quordon deb-systemd-helper enable quordon.service
        test -L /etc/systemd/system/multi-user.target.wants/quordon.service

        DEBIAN_FRONTEND=noninteractive apt-get remove -y quordon
        test ! -e /usr/bin/quordon
        test -f /etc/quordon/policy.yaml
        test ! -e /etc/systemd/system/multi-user.target.wants/quordon.service

        DEBIAN_FRONTEND=noninteractive apt-get purge -y quordon
        test ! -e /etc/quordon/policy.yaml
        if DPKG_MAINTSCRIPT_PACKAGE=quordon deb-systemd-helper debian-installed quordon.service; then
            echo "deb-systemd-helper state survived purge" >&2
            exit 1
        fi

        deluser quordon
        addgroup --system quordon
        adduser \
            --uid 1000 \
            --ingroup quordon \
            --home /home/quordon \
            --shell /bin/sh \
            --disabled-password \
            --gecos "Conflicting login account" \
            quordon
        if DEBIAN_FRONTEND=noninteractive apt-get install -y /tmp/quordon.deb >/tmp/collision.log 2>&1; then
            echo "package accepted a conflicting login account" >&2
            exit 1
        fi
        grep -F "existing user quordon is not the dedicated system account expected by this package" /tmp/collision.log
    '
