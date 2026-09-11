#!/bin/sh
set -eu

service_user=quordon
service_group=quordon
config_dir=/etc/quordon
unit=quordon.service
rollback_dir=/run/quordon-maintscript
rollback_marker=$rollback_dir/service-was-active-before-remove
enabled_rollback_marker=$rollback_dir/service-was-enabled-before-remove
maintscript_action=${1:-}
previous_version=${2:-}
upgrade_rollback_marker=$rollback_dir/service-was-active-before-upgrade

if [ -n "${DPKG_ROOT:-}" ]; then
    echo "quordon: chrootless maintainer scripts with DPKG_ROOT are not supported" >&2
    exit 1
fi

is_package_system_id() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$1" -ge 100 ] && [ "$1" -le 999 ]
}

if [ -L "$rollback_dir" ]; then
    echo "quordon: refusing symbolic-link package rollback directory $rollback_dir" >&2
    exit 1
fi
if [ -L "$rollback_marker" ]; then
    echo "quordon: refusing symbolic-link package rollback marker $rollback_marker" >&2
    exit 1
fi
if [ -L "$enabled_rollback_marker" ]; then
    echo "quordon: refusing symbolic-link package rollback marker $enabled_rollback_marker" >&2
    exit 1
fi
if [ -L "$upgrade_rollback_marker" ]; then
    echo "quordon: refusing symbolic-link package rollback marker $upgrade_rollback_marker" >&2
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

if group_record=$(getent group "$service_group"); then
    if ! local_group_record=$(getent -s files group "$service_group"); then
        echo "quordon: refusing non-local NSS group collision for $service_group" >&2
        exit 1
    fi
    if [ "$group_record" != "$local_group_record" ]; then
        echo "quordon: refusing NSS group shadowing for $service_group" >&2
        exit 1
    fi
    group_record=$local_group_record
    IFS=: read -r found_group _ group_gid _ <<EOF
$group_record
EOF
    if [ "$found_group" != "$service_group" ] || ! is_package_system_id "$group_gid"; then
        echo "quordon: existing group $service_group is not a compatible system group" >&2
        exit 1
    fi
else
    if getent -s files group "$service_group" >/dev/null; then
        echo "quordon: local group $service_group is not the effective NSS identity" >&2
        exit 1
    fi
    addgroup --system "$service_group"
    group_record=$(getent -s files group "$service_group")
    effective_group_record=$(getent group "$service_group")
    if [ "$effective_group_record" != "$group_record" ]; then
        echo "quordon: created group $service_group is shadowed in NSS" >&2
        exit 1
    fi
    IFS=: read -r found_group _ group_gid _ <<EOF
$group_record
EOF
    if [ "$found_group" != "$service_group" ] || ! is_package_system_id "$group_gid"; then
        echo "quordon: failed to create a compatible system group $service_group" >&2
        exit 1
    fi
fi

if account_record=$(getent passwd "$service_user"); then
    if ! local_account_record=$(getent -s files passwd "$service_user"); then
        echo "quordon: refusing non-local NSS account collision for $service_user" >&2
        exit 1
    fi
    if [ "$account_record" != "$local_account_record" ]; then
        echo "quordon: refusing NSS account shadowing for $service_user" >&2
        exit 1
    fi
    account_record=$local_account_record
    IFS=: read -r found_user _ account_uid account_gid _ account_home account_shell <<EOF
$account_record
EOF
    if [ "$found_user" != "$service_user" ] || \
        ! is_package_system_id "$account_uid" || \
        [ "$account_gid" != "$group_gid" ] || \
        [ "$account_home" != /nonexistent ] || \
        [ "$account_shell" != /usr/sbin/nologin ]; then
        echo "quordon: existing user $service_user is not the dedicated system account expected by this package" >&2
        exit 1
    fi
else
    if getent -s files passwd "$service_user" >/dev/null; then
        echo "quordon: local user $service_user is not the effective NSS identity" >&2
        exit 1
    fi
    adduser \
        --system \
        --ingroup "$service_group" \
        --no-create-home \
        --home /nonexistent \
        --shell /usr/sbin/nologin \
        --disabled-password \
        --gecos "Quordon service account" \
        "$service_user"
    local_account_record=$(getent -s files passwd "$service_user")
    effective_account_record=$(getent passwd "$service_user")
    if [ "$effective_account_record" != "$local_account_record" ]; then
        echo "quordon: created user $service_user is shadowed in NSS" >&2
        exit 1
    fi
fi

if [ -L "$config_dir" ]; then
    echo "quordon: refusing symbolic-link configuration directory $config_dir" >&2
    exit 1
fi

install -d -o root -g "$service_group" -m 0750 "$config_dir"

case "$maintscript_action" in
    configure|abort-upgrade|abort-deconfigure|abort-remove)
        if deb-systemd-helper debian-installed "$unit"; then
            deb-systemd-helper unmask "$unit" >/dev/null || true
            if deb-systemd-helper --quiet was-enabled "$unit"; then
                deb-systemd-helper enable "$unit" >/dev/null || true
            fi
        fi
        deb-systemd-helper update-state "$unit" >/dev/null || true
        if { [ "$maintscript_action" = abort-remove ] || [ "$maintscript_action" = abort-deconfigure ]; } && \
            [ -f "$enabled_rollback_marker" ]; then
            deb-systemd-helper enable "$unit" >/dev/null
            rm -f "$enabled_rollback_marker"
        fi
        ;;
esac

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl --system daemon-reload >/dev/null || true

    case "$maintscript_action" in
        configure)
            if [ -n "$previous_version" ] && systemctl --system is-active --quiet "$unit"; then
                create_rollback_marker "$upgrade_rollback_marker"
                if deb-systemd-invoke restart "$unit" >/dev/null; then
                    rm -f "$upgrade_rollback_marker"
                else
                    exit 1
                fi
            fi
            ;;
        abort-upgrade)
            if [ -f "$upgrade_rollback_marker" ] && [ ! -L "$upgrade_rollback_marker" ]; then
                systemctl --system start "$unit"
                rm -f "$upgrade_rollback_marker"
            fi
            ;;
        abort-remove|abort-deconfigure)
            if [ -f "$rollback_marker" ] && [ ! -L "$rollback_marker" ]; then
                systemctl --system start "$unit"
                rm -f "$rollback_marker"
            fi
            ;;
    esac
fi

if [ ! -e "$rollback_marker" ] && [ ! -e "$enabled_rollback_marker" ] && \
    [ ! -e "$upgrade_rollback_marker" ] && \
    [ -d "$rollback_dir" ] && [ ! -L "$rollback_dir" ]; then
    rmdir "$rollback_dir" 2>/dev/null || true
fi

exit 0
