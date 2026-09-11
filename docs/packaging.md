# Сборка и установка Quordon

## Release artifacts

Каждый semantic-version tag вида `v0.1.0` запускает GitHub Actions release.
GoReleaser 2.18.1 собирает статические Linux-бинарники для `amd64` и `arm64`,
архивы `tar.gz`, Debian packages и единый `checksums.txt`. Release workflow
сначала загружает artifacts в draft GitHub Release, проверяет жизненный цикл
реального `.deb`, создаёт GitHub build provenance attestation для файлов из
checksum manifest и только после успешного завершения всех этих шагов публикует
release. При любой ошибке он остаётся draft.
Повторный запуск workflow для того же tag переиспользует существующий draft и
атомарно заменяет уже загруженные artifacts, поэтому восстановление после сбоя
lint, smoke-теста, attestation или публикации не требует ручного удаления
GitHub Release.

Локальная проверка release-конфигурации:

```bash
make release-check
make release-snapshot
make package-lint
make package-smoke
```

Для этих целей нужны GoReleaser 2.18.1, `lintian`, `dpkg-deb`, Docker и
`sha256sum`; `package-smoke` дополнительно использует Linux-утилиты `tar` и
`find`.

`package-smoke` устанавливает пакет текущей архитектуры в чистый
`debian:bookworm-slim`, проверяет upgrade/remove/purge и не изменяет host.
Файлы в переносимых `tar.gz` всегда записываются с владельцем `root:root`,
независимо от UID/GID пользователя, который выполнял сборку.

## Установка Debian package

Скачайте `.deb` для архитектуры машины и `checksums.txt` из одного GitHub
Release, затем проверьте SHA-256 и установите пакет:

```bash
sha256sum --check --ignore-missing checksums.txt
sudo apt install ./quordon_0.1.0_amd64.deb
```

Пакет устанавливает:

- `/usr/bin/quordon`;
- `/usr/lib/systemd/system/quordon.service`;
- пример policy в `/usr/share/doc/quordon/examples/policy.yaml`;
- Debian copyright metadata и полный набор third-party notices для Go runtime
  и всех статически слинкованных модулей в `/usr/share/doc/quordon`;
- manual page `quordon(1)`;
- отдельные system user/group `quordon` и каталог `/etc/quordon` с правами
  `root:quordon 0750`.

Пакет сознательно не создаёт рабочий `/etc/quordon/policy.yaml`, не включает и
не запускает service. Установка не должна случайно поднять gateway с примером
credentials или непроверенной сетевой конфигурацией.

Если имя `quordon` уже занято обычной login/NSS-учётной записью либо
несовместимой группой, установка завершается отказом: пакет не передаёт такому
пользователю доступ к policy и DBMS credentials. Повторно используется только
выделенная системная учётная запись с home `/nonexistent`, shell
`/usr/sbin/nologin` и системными UID/GID. Эффективная NSS-запись обязана точно
совпадать с локальной записью из `files`; LDAP/SSSD identity, затеняющая
локального пользователя или группу `quordon`, также блокирует установку.

Chrootless-вызов maintainer scripts с непустым `DPKG_ROOT` сознательно не
поддерживается и завершается отказом до изменения пользователей, systemd state
или файлов хоста. Для установки в альтернативный root следует запускать `dpkg`
внутри настоящего chroot/container, где `DPKG_ROOT` не требуется.

После заполнения policy установите её с обязательными правами `0600` и
владельцем service account:

```bash
sudo install -o quordon -g quordon -m 0600 policy.yaml /etc/quordon/policy.yaml
sudo systemctl enable --now quordon.service
systemctl status quordon.service
journalctl -u quordon.service
```

Unit запускает процесс без root privileges и использует systemd hardening:
read-only filesystem namespace, пустой capability set, запрет privilege
escalation и ограничение address families. Audit остаётся в stdout и доступен
через journal.

При upgrade ранее запущенный service перезапускается после установки нового
binary, если локальная service policy разрешает package scripts управлять им;
выключенный service остаётся выключенным. Если restart нового binary завершился
ошибкой и dpkg откатывает upgrade, `abort-upgrade` восстанавливает ранее
активный service со старым binary. `apt remove` сохраняет созданный оператором
policy, а явный `apt purge` удаляет
`/etc/quordon/policy.yaml`. System account сохраняется, чтобы его UID не был
переиспользован для оставшихся файлов с секретами.

Состояние unit регистрируется через `deb-systemd-helper`, но fresh install не
создаёт enable-ссылок. Удаление снимает созданные оператором enable-ссылки,
purge очищает helper state, а `abort-remove`/`abort-deconfigure` восстанавливает
сервис, если он был активен до начала неуспешной пакетной операции.

## Публикация release

Перед тегированием `master` должна пройти CI. Затем создайте и отправьте
annotated tag:

```bash
git tag -a v0.1.0 -m "Quordon v0.1.0"
git push origin v0.1.0
```

APT repository пока намеренно не публикуется: до него нужно определить модель
подписания repository metadata, хранение ключей, rotation и hosting. На первом
этапе `.deb` устанавливается напрямую из GitHub Release.
