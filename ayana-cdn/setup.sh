#!/usr/bin/env bash
# One command for this VPS: install or upgrade ayana-cdn, ask for the routes
# (client path -> server), apply them, probe the server of every path, show
# the status and print the client payload for each route.
#
#   sudo ./setup.sh                    interactive: prompts for the routes
#   sudo ./setup.sh --routes FILE      apply a routes.json instead of prompting
#   sudo ./setup.sh --keep-config      upgrade only: keep the domains, email and routes
#   (other options are passed to deploy/install.sh, e.g. --test --no-sysctl)
#
# Routes you enter are saved to /etc/ayana-cdn/routes.json.
set -Eeuo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF=/etc/ayana-cdn/config.json
ROUTES=/etc/ayana-cdn/routes.json
mode=prompt
routes_file=""
args=()

while [ $# -gt 0 ]; do
	case "$1" in
	--keep-config) mode=keep ;;
	--routes)
		[ $# -ge 2 ] || { echo "--routes needs a file" >&2; exit 1; }
		mode="file"; routes_file=$2; shift ;;
	--routes=*) mode="file"; routes_file=${1#--routes=} ;;
	-h | --help)
		sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
		exit 0 ;;
	*) args+=("$1") ;;
	esac
	shift
done
[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0" >&2; exit 1; }

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

"$DIR/deploy/install.sh" "${args[@]}"

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
