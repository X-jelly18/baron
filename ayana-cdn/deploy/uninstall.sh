#!/usr/bin/env bash
# Removes ayana-cdn: the service, the binary, the private Go toolchain and
# the kernel tuning. The config (/etc/ayana-cdn) and the ACME certificate
# cache (/var/lib/ayana-cdn) are kept unless you pass --purge.
set -Eeuo pipefail
purge=0
for a in "$@"; do
	case "$a" in
	--purge) purge=1 ;;
	-h | --help) echo "usage: sudo $0 [--purge]   (--purge also deletes /etc/ayana-cdn, /var/lib/ayana-cdn and the service user)"; exit 0 ;;
	*) echo "unknown option: $a" >&2; exit 1 ;;
	esac
done
[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0" >&2; exit 1; }
if [ -d /run/systemd/system ]; then
	systemctl disable --now ayana-cdn >/dev/null 2>&1 || true
	rm -f /etc/systemd/system/ayana-cdn.service
	rm -rf /etc/systemd/system/ayana-cdn.service.d
	systemctl daemon-reload
fi
rm -f /usr/local/bin/ayana-cdn /etc/sysctl.d/99-ayana-cdn.conf /etc/sysctl.d/98-ayana-cdn-filemax.conf \
	/usr/share/bash-completion/completions/ayana-cdn /etc/bash_completion.d/ayana-cdn \
	/etc/sysctl.d/99-cdn.conf /etc/modules-load.d/ayana-cdn.conf # the last two are v1 leftovers
rm -rf /opt/ayana-cdn /run/ayana-cdn
if [ "$purge" = 1 ]; then
	# with the copies a restore leaves (setup.sh --restore); they hold the keys too
	rm -rf /etc/ayana-cdn /var/lib/ayana-cdn /etc/ayana-cdn.*-restore-* /var/lib/ayana-cdn.*-restore-* /etc/ayana-cdn.restore.*
	userdel ayana-cdn >/dev/null 2>&1 || true
	echo "removed ayana-cdn, its config, its certificates and its service user (backups in /root are kept)"
else
	echo "removed ayana-cdn; kept /etc/ayana-cdn and /var/lib/ayana-cdn (rerun with --purge to delete them)"
fi
