#!/usr/bin/env bash
# One command for this VPS: install or upgrade ayana-cdn, ask for the routes
# (client path -> server), apply them, probe the server of every path, show
# the status and print the client payload for each route.
#
#   sudo ./setup.sh                    interactive: prompts for the routes
#   sudo ./setup.sh --routes FILE      apply a routes.json instead of prompting
#   sudo ./setup.sh --keep-config      upgrade only: keep the domains, email and routes
#   sudo ./setup.sh --backup [FILE]    only save the settings (to move them to a new VPS)
#   sudo ./setup.sh --restore FILE     new VPS: install with the settings of a backup
#   (other options are passed to deploy/install.sh, e.g. --test --no-sysctl)
#
# Routes you enter are saved to /etc/ayana-cdn/routes.json. Every run also saves
# the settings (config, routes, panel login, certificates) to
# /root/ayana-cdn-backup.tar.gz, ready for --restore on another VPS.
set -Eeuo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT=/ # the system root; everything below is relative to it
CONF_DIR=${ROOT}etc/ayana-cdn
STATE_DIR=${ROOT}var/lib/ayana-cdn # ACME account and certificates
CONF=$CONF_DIR/config.json
ROUTES=$CONF_DIR/routes.json
BACKUP=${ROOT}root/ayana-cdn-backup.tar.gz
mode=prompt
routes_file=""
backup_file=$BACKUP
restore_file=""
args=()

# set_mode MODE: --keep-config (keep), --routes (file), --backup and --restore
# each pick what this run does; they cannot be combined, except that a restore
# already keeps the settings like --keep-config.
set_mode() {
	local flag
	if [ "$mode" = prompt ] || [ "$mode" = "$1" ]; then mode=$1; return; fi
	case "$mode$1" in restorekeep) return ;; keeprestore) mode=restore; return ;; esac
	for flag in "$mode" "$1"; do
		case "$flag" in keep) echo -n "--keep-config " ;; file) echo -n "--routes " ;; *) echo -n "--$flag " ;; esac
	done >&2
	echo "cannot be combined" >&2
	exit 1
}

while [ $# -gt 0 ]; do
	case "$1" in
	--keep-config) set_mode keep ;;
	--routes)
		[ $# -ge 2 ] || { echo "--routes needs a file" >&2; exit 1; }
		set_mode file; routes_file=$2; shift ;;
	--routes=*) set_mode file; routes_file=${1#--routes=} ;;
	--backup)
		set_mode backup
		if [ $# -ge 2 ] && [[ $2 != -* ]]; then backup_file=$2; shift; fi ;;
	--backup=*) set_mode backup; backup_file=${1#--backup=} ;;
	--restore)
		[ $# -ge 2 ] || { echo "--restore needs the backup file" >&2; exit 1; }
		set_mode restore; restore_file=$2; shift ;;
	--restore=*) set_mode restore; restore_file=${1#--restore=} ;;
	-h | --help)
		sed -n '2,/^set /{/^#/p}' "$0" | sed 's/^# \{0,1\}//'
		exit 0 ;;
	*) args+=("$1") ;;
	esac
	shift
done
[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0" >&2; exit 1; }

# ---- backup and restore ---------------------------------------------------------------

SERVICE_USER=ayana-cdn

# save_backup FILE: everything that makes this edge what it is, in one archive:
# the config (domains, paths and servers, panel login and secret path), the
# routes file, and the ACME account and certificates, so a new VPS serves at
# once without asking Let's Encrypt again. The file holds private keys: it is
# written mode 600. A backup it replaces is kept with its date in the name
# (the five newest), so a run never loses one. Sets SAVED_TO.
save_backup() {
	local out=$1 tmp manifest old members=(etc/ayana-cdn)
	[ -n "$out" ] || { echo "--backup needs a file name" >&2; return 1; }
	[ ! -d "$out" ] || out=${out%/}/ayana-cdn-backup.tar.gz
	out=$(realpath -m "$out")
	case "$out" in "$CONF_DIR"/* | "$STATE_DIR"/*)
		echo "save the backup outside $CONF_DIR and $STATE_DIR (it would contain itself)" >&2
		return 1 ;;
	esac
	[ -f "$CONF" ] || { echo "nothing to save: no $CONF" >&2; return 1; }
	[ ! -d "$STATE_DIR" ] || members+=(var/lib/ayana-cdn)
	mkdir -p "$(dirname "$out")"
	tmp=$(mktemp "$out.XXXXXX") || return 1 # mode 600, never an existing file
	manifest=$(mktemp -d)
	{
		echo "ayana-cdn backup"
		echo "created $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(hostname 2>/dev/null || echo '?')"
		echo "version $(ayana-cdn version 2>/dev/null || echo '?')"
	} >"$manifest/ayana-cdn-backup.txt"
	# Links are stored as the files they point to, so a restore gets plain files.
	if ! (umask 077 && tar -czf "$tmp" --dereference --hard-dereference --exclude='*.lock' \
		-C "$manifest" ayana-cdn-backup.txt -C "$ROOT" "${members[@]}"); then
		rm -rf "$tmp" "$manifest"
		return 1
	fi
	rm -rf "$manifest"
	if [ -f "$out" ]; then
		old="${out%.tar.gz}.$(date -r "$out" +%Y%m%d-%H%M%S).tar.gz"
		mv -f "$out" "$old"
		ls -1t "${out%.tar.gz}".2*.tar.gz 2>/dev/null | tail -n +6 | while IFS= read -r old; do rm -f -- "$old"; done || true
	fi
	mv -f "$tmp" "$out" || { rm -f "$tmp"; return 1; }
	SAVED_TO=$out
	# Certificate files kept outside /etc/ayana-cdn are not in the archive.
	if command -v python3 >/dev/null; then
		python3 - "$CONF" <<'PY' || true
import json, sys
t = json.load(open(sys.argv[1])).get("tls") or {}
if t.get("mode") == "files":
    out = [p for p in (t.get("cert_file"), t.get("key_file")) if p and not p.startswith("/etc/ayana-cdn/")]
    if out:
        print("warning: copy these certificate files to the same paths on the new VPS yourself: " + ", ".join(out))
PY
	fi
}

backup_hint() {
	echo "    To move to a new VPS, copy it there and restore it:"
	echo "      scp $1 root@NEW-VPS-IP:/root/"
	echo "      (on the new VPS, in this package) sudo ./setup.sh --restore /root/$(basename "$1")"
}

# restore_backup FILE: put a backup's settings in place before the install, so
# the installer keeps them (like an upgrade with --keep-config). The archive is
# checked and unpacked into a scratch directory first, so a wrong file or a
# full disk changes nothing; whatever this VPS already had is moved aside, not
# deleted, and undo_restore puts it back if the install then fails.
RESTORE_TS="" stopped_for_restore=0 restore_moved=()
restore_backup() {
	local f=$1 list n t stage src dst
	[ -f "$f" ] || { echo "no such file: $f" >&2; exit 1; }
	tar -tzf "$f" >/dev/null 2>&1 || { echo "$f is not a backup (.tar.gz) file" >&2; exit 1; }
	list=$(paste -d '\t' <(tar -tvzf "$f" | cut -c1) <(tar -tzf "$f"))
	# Only regular files and directories inside ayana-cdn's own two directories:
	# no links, and no entries for /, /etc or /var themselves.
	while IFS=$'\t' read -r t n; do
		n=${n#./}
		case "$n" in
		/* | .. | ../* | */../* | */..) ;;
		ayana-cdn-backup.txt | etc/ayana-cdn | etc/ayana-cdn/* | var/lib/ayana-cdn | var/lib/ayana-cdn/*)
			[[ $t == [-d] ]] && continue ;;
		esac
		echo "$f is not an ayana-cdn backup: it contains ${n:-./}" >&2
		exit 1
	done <<<"$list"
	echo "==> restoring the settings from $f"
	tar -xzOf "$f" ayana-cdn-backup.txt 2>/dev/null | sed -n '2,3s/^/    /p' || true
	mkdir -p "$(dirname "$CONF_DIR")"
	stage=$(mktemp -d "$CONF_DIR.restore.XXXXXX")
	if ! tar -xzf "$f" -C "$stage" --no-same-owner --exclude=ayana-cdn-backup.txt --exclude=./ayana-cdn-backup.txt ||
		[ ! -f "$stage/etc/ayana-cdn/config.json" ]; then
		rm -rf "$stage"
		echo "$f could not be unpacked, or has no etc/ayana-cdn/config.json; nothing was changed" >&2
		exit 1
	fi
	# A running edge sees these directories through systemd's sandbox, which
	# would keep pointing at the old ones: stop it, and the install starts it
	# again with the restored settings.
	if command -v systemctl >/dev/null && systemctl is-active --quiet ayana-cdn 2>/dev/null; then
		echo "    stopping the edge running on this VPS for the restore"
		systemctl stop ayana-cdn
		stopped_for_restore=1
	fi
	RESTORE_TS=$(date +%Y%m%d-%H%M%S)
	for src in etc/ayana-cdn var/lib/ayana-cdn; do
		[ -d "$stage/$src" ] || continue
		dst=$ROOT$src
		if [ -e "$dst" ]; then
			mv "$dst" "$dst.before-restore-$RESTORE_TS"
			restore_moved+=("$dst")
			echo "    this VPS's previous $dst is kept as $dst.before-restore-$RESTORE_TS"
		fi
		mkdir -p "$(dirname "$dst")"
		mv "$stage/$src" "$dst"
	done
	rm -rf "$stage"
	# The files belong to the service user (the installer does it too, but
	# only once it has built the new binary).
	if id -u "$SERVICE_USER" >/dev/null 2>&1; then
		for dst in "$CONF_DIR" "$STATE_DIR"; do
			[ ! -d "$dst" ] || chown -R "$SERVICE_USER:$SERVICE_USER" "$dst"
		done
	fi
}

# undo_restore: the install failed after a restore; put back what this VPS had.
undo_restore() {
	local d
	for d in ${restore_moved[@]+"${restore_moved[@]}"}; do
		[ ! -e "$d" ] || mv "$d" "$d.failed-restore-$RESTORE_TS"
		mv "$d.before-restore-$RESTORE_TS" "$d"
		echo "    put this VPS's previous $d back (the restored one is in $d.failed-restore-$RESTORE_TS)" >&2
	done
	if [ "$stopped_for_restore" = 1 ]; then
		systemctl start ayana-cdn || true
	fi
	echo "the install failed, so the restore was undone; fix the error above and run: sudo $0 --restore $restore_file" >&2
}

restored=0
case "$mode" in
backup)
	save_backup "$backup_file"
	echo "==> saved the settings to $SAVED_TO (keep it private: it holds the panel login and the TLS keys)"
	backup_hint "$SAVED_TO"
	exit 0 ;;
restore)
	restore_backup "$restore_file"
	mode=keep restored=1 ;;
esac

# Where to read answers from: the terminal, even under sudo or a pipe.
IN=""
if [ -t 0 ]; then IN=/dev/stdin; elif { : </dev/tty; } 2>/dev/null; then IN=/dev/tty; fi
ask() { # ask VAR "prompt"
	local __var=$1
	[ -n "$IN" ] || { echo "no terminal available; set AYANA_CDN_DOMAIN and AYANA_CDN_EMAIL" >&2; return 1; }
	read -r -p "$2" "${__var?}" <"$IN"
}

# Ask for the public TLS/CDN hostname before installation. Environment variables
# also allow unattended deployments without silently using the package default.
# An upgrade with --keep-config changes nothing: no prompt, and the domains
# (including any added from the web panel) and the ACME email stay as they are.
DOMAIN=${AYANA_CDN_DOMAIN:-}
DOMAIN=${DOMAIN,,}
EMAIL=${AYANA_CDN_EMAIL:-}
if [ "$mode" = keep ] && [ -f "$CONF" ] && [ -z "$DOMAIN" ]; then
	echo "==> --keep-config: keeping the domains and email in $CONF"
else
	if [ -z "$DOMAIN" ]; then
		while true; do
			ask DOMAIN "Domain for this CDN (e.g. cdn.example.com): "
			DOMAIN=${DOMAIN,,}
			if [[ "$DOMAIN" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$ ]]; then break; fi
			echo "Enter a hostname only (no https://, port, path, or IP address)." >&2
			DOMAIN=""
		done
	fi
	[[ "$DOMAIN" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$ ]] || { echo "invalid AYANA_CDN_DOMAIN hostname: $DOMAIN" >&2; exit 1; }
	if [ -z "$EMAIL" ]; then
		ask EMAIL "ACME certificate email [admin@$DOMAIN]: " || exit 1
		EMAIL=${EMAIL:-admin@$DOMAIN}
	fi
	[[ "$EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || { echo "invalid email address: $EMAIL" >&2; exit 1; }
	export AYANA_CDN_DOMAIN="$DOMAIN" AYANA_CDN_EMAIL="$EMAIL"
fi

if ! "$DIR/deploy/install.sh" "${args[@]}"; then
	[ "$restored" = 0 ] || undo_restore
	exit 1
fi

# Restored certificates belong to the service user, which the installer may
# have only just created (systemd also fixes this when it starts the service).
if [ "$restored" = 1 ] && [ -d "$STATE_DIR" ] && id -u "$SERVICE_USER" >/dev/null 2>&1; then
	chown -R "$SERVICE_USER:$SERVICE_USER" "$STATE_DIR"
fi

# ---- routes --------------------------------------------------------------------------

apply_routes() { # apply_routes FILE
	echo "==> applying routes from $1"
	ayana-cdn routes import "$1" -replace -config "$CONF"
}

# validate_routes FILE: run the real importer against a scratch copy of the
# config, so the entries are checked exactly as they will be applied.
validate_routes() {
	local tmp
	tmp=$(mktemp)
	cp "$CONF" "$tmp"
	if ayana-cdn routes import "$1" -replace -no-reload -config "$tmp" >/dev/null 2>"$tmp.err"; then
		rm -f "$tmp" "$tmp.err" "$tmp.bak" "$tmp.lock"
		return 0
	fi
	sed 's/^ayana-cdn: //' "$tmp.err" >&2
	rm -f "$tmp" "$tmp.err" "$tmp.bak" "$tmp.lock"
	return 1
}

prompt_routes() {
	local n path target host entries answer
	echo
	echo "==> Routes"
	if ayana-cdn backend ls -config "$CONF" 2>/dev/null | tail -n +2 | grep -q .; then
		echo "Current routes:"
		ayana-cdn backend ls -config "$CONF" | tail -n +2 | awk '{sub(/\/$/, "", $2); printf "  %-14s -> %s (%s)\n", $2, $4, $3}'
		echo "Enter new routes now? They replace the current ones; an empty first path keeps them."
	else
		echo "No routes yet."
	fi
	while true; do
		entries=$(mktemp)
		n=1
		echo
		echo "One route at a time; leave the path empty when done."
		echo "  path:   what clients use, one segment, e.g. /s1"
		echo "  target: http://IP-or-host[:port] (plain) or https://host[:port] (TLS);"
		echo "          exactly one per path (a path connects to one server: no load"
		echo "          balancing, no failover); for another server, add another path"
		while true; do
			ask path "Path [$n]: "
			path=${path// /}
			[ -n "$path" ] || break
			case "$path" in /*) ;; *) path="/$path" ;; esac
			ask target "Target for $path: "
			target=${target// /}
			[ -n "$target" ] || { echo "  a target is required" >&2; continue; }
			case "$target" in *,*)
				echo "  one target per path: give each server its own path (e.g. $path and $path-2)" >&2
				continue ;;
			esac
			ask host "Host header for $path (Enter = the target's hostname): "
			printf '%s\t%s\t%s\n' "$path" "$target" "${host// /}" >>"$entries"
			n=$((n + 1))
		done
		if ! grep -q . "$entries"; then
			rm -f "$entries"
			echo "no routes entered; keeping the current ones"
			return 0
		fi
		python3 - "$entries" >"$ROUTES.new" <<'PY'
import json, sys
routes = {}
for line in open(sys.argv[1]):
    path, target, host = line.rstrip("\n").split("\t")
    routes[path] = {"target": target, "host": host} if host else target
json.dump(routes, sys.stdout, indent=2)
print()
PY
		rm -f "$entries"
		echo
		echo "Routes to apply:"
		sed 's/^/  /' "$ROUTES.new"
		if ! validate_routes "$ROUTES.new"; then
			echo "please enter the routes again" >&2
			continue
		fi
		ask answer "Apply these routes? [Y/n]: "
		case "${answer:-y}" in
		[Yy]*) break ;;
		*) echo "let's redo them" ;;
		esac
	done
	install -m 0644 "$ROUTES.new" "$ROUTES"
	rm -f "$ROUTES.new"
	apply_routes "$ROUTES"
}

case "$mode" in
keep) echo "==> keeping the routes in $CONF" ;;
file)
	[ -f "$routes_file" ] || { echo "no such file: $routes_file" >&2; exit 1; }
	validate_routes "$routes_file"
	install -m 0644 "$routes_file" "$ROUTES"
	apply_routes "$ROUTES" ;;
prompt)
	if [ -n "$IN" ]; then
		prompt_routes
	elif [ -f "$ROUTES" ]; then
		echo "==> no terminal: reapplying $ROUTES"
		err=$(mktemp)
		if ! apply_routes "$ROUTES" 2>"$err"; then
			cat "$err" >&2
			if ! grep -q 'connects to exactly one server' "$err"; then
				rm -f "$err"
				exit 1
			fi
			# An older setup.sh could save several targets for one path, which a
			# path no longer takes. Keep the running routes (each path uses its
			# first server) instead of stopping the upgrade here.
			echo "warning: $ROUTES was not applied; keeping the routes in $CONF." >&2
			echo "         Give each server its own path, then run: sudo ./setup.sh --routes FILE" >&2
		fi
		rm -f "$err"
	else
		echo "==> no terminal and no $ROUTES: keeping the routes in $CONF" >&2
	fi ;;
esac

# ---- save the settings ----------------------------------------------------------------

echo
if save_backup "$BACKUP"; then
	echo "==> saved the settings to $SAVED_TO (keep it private: it holds the panel login and the TLS keys)"
	backup_hint "$SAVED_TO"
else
	echo "warning: could not save the settings to $BACKUP" >&2
fi

# ---- verify --------------------------------------------------------------------------

echo
echo "==> probing the server of every path"
ayana-cdn check -config "$CONF" || echo "warning: some servers are unreachable from this VPS (see above)" >&2

echo
if ayana-cdn status -config "$CONF" 2>/dev/null; then
	echo
	echo "Client payloads (host and SNI: the first cdn_hosts entry):"
	ayana-cdn config show -config "$CONF" | python3 -c '
import json, sys
c = json.load(sys.stdin)
host = (c.get("cdn_hosts") or ["<cdn host>"])[0]
for b in c.get("backends", []):
    print("  GET /%s HTTP/1.1[crlf]Host: %s[crlf]Upgrade: websocket[crlf][crlf]" % (b["name"], host))
'
else
	echo "the edge is not running yet: systemctl start ayana-cdn, then: ayana-cdn status"
fi

if [ "$restored" = 1 ]; then
	echo
	echo "==> restored from $restore_file. Before clients use this VPS:"
	python3 - "$CONF" <<'PY' || true
import json, sys
c = json.load(open(sys.argv[1]))
hosts = c.get("cdn_hosts") or ([c["cdn_host"]] if c.get("cdn_host") else [])
print("  - point the DNS of %s at this VPS's IP" % (", ".join(hosts) or "your domains"))
local = []
for b in c.get("backends", []):
    for u in [b.get("upstream")] + list(b.get("upstreams") or []):
        if u and u.rsplit(":", 1)[0].strip("[]") in ("127.0.0.1", "localhost", "::1"):
            local.append("/%s/ -> %s" % (b.get("name"), u))
if local:
    print("  - these paths go to services on the VPS itself; install them here too: " + ", ".join(local))
print("  - servers that only accept the old VPS's IP must now accept this one")
PY
fi
