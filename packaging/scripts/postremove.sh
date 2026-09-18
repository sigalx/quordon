#!/bin/sh
set -eu

config_dir=/etc/quordon
unit=quordon.service
rollback_dir=/run/quordon-maintscript
rollback_marker=$rollback_dir/service-was-active-before-remove
enabled_rollback_marker=$rollback_dir/service-was-enabled-before-remove
upgrade_rollback_marker=$rollback_dir/service-was-active-before-upgrade
maintscript_action=${1:-}

if [ -n "${DPKG_ROOT:-}" ]; then
    echo "quordon: chrootless maintainer scripts with DPKG_ROOT are not supported" >&2
    exit 1
fi

if [ "$maintscript_action" = remove ] && [ -d /run/systemd/system ] && \
    command -v systemctl >/dev/null 2>&1; then
    systemctl --system daemon-reload >/dev/null || true
fi

case "$maintscript_action" in
    remove|purge)
        if [ -f "$rollback_marker" ] && [ ! -L "$rollback_marker" ]; then
            rm -f "$rollback_marker"
        fi
        if [ -f "$enabled_rollback_marker" ] && [ ! -L "$enabled_rollback_marker" ]; then
            rm -f "$enabled_rollback_marker"
        fi
        if [ -f "$upgrade_rollback_marker" ] && [ ! -L "$upgrade_rollback_marker" ]; then
            rm -f "$upgrade_rollback_marker"
        fi
        if [ -d "$rollback_dir" ] && [ ! -L "$rollback_dir" ]; then
            rmdir "$rollback_dir" 2>/dev/null || true
        fi
        ;;
esac

if [ "$maintscript_action" = purge ]; then
    deb-systemd-helper purge "$unit" >/dev/null || true

    if [ -d "$config_dir" ] && [ ! -L "$config_dir" ]; then
        if [ -f "$config_dir/policy.yaml" ] && [ ! -L "$config_dir/policy.yaml" ]; then
            rm -f "$config_dir/policy.yaml"
        fi
        rmdir "$config_dir" 2>/dev/null || true
    fi
fi

exit 0
