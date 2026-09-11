#!/bin/sh
set -eu

unit=quordon.service
rollback_dir=/run/quordon-maintscript
rollback_marker=$rollback_dir/service-was-active-before-remove
enabled_rollback_marker=$rollback_dir/service-was-enabled-before-remove
maintscript_action=${1:-}

if [ -n "${DPKG_ROOT:-}" ]; then
    echo "quordon: chrootless maintainer scripts with DPKG_ROOT are not supported" >&2
    exit 1
fi

create_rollback_marker() {
    marker=$1
    if [ -L "$rollback_dir" ]; then
        echo "quordon: refusing symbolic-link package rollback directory $rollback_dir" >&2
        exit 1
    fi
    install -d -o root -g root -m 0755 "$rollback_dir"
    if [ -L "$marker" ]; then
        echo "quordon: refusing symbolic-link package rollback marker $marker" >&2
        exit 1
    fi
    : >"$marker"
    chmod 0600 "$marker"
}

case "$maintscript_action" in
    remove|deconfigure)
        if deb-systemd-helper --quiet is-enabled "$unit"; then
            create_rollback_marker "$enabled_rollback_marker"
        fi
        if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
            if systemctl --system is-active --quiet "$unit"; then
                create_rollback_marker "$rollback_marker"
            fi
            deb-systemd-invoke stop "$unit" >/dev/null || true
        fi
        deb-systemd-helper disable "$unit" >/dev/null || true
        ;;
esac

exit 0
