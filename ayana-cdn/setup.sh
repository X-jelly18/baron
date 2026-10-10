#!/usr/bin/env bash
# One command for this VPS: install or upgrade ayana-cdn, ask for the routes
# (client path -> backend), apply them, probe every upstream, show the status
# and print the client payload for each route.
#
#   sudo ./setup.sh                    interactive: prompts for the routes
#   sudo ./setup.sh --routes FILE      apply a routes.json instead of prompting
#   sudo ./setup.sh --keep-config      leave the routes as they are
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
	read -r -p "$2" "${__var?}" <"$IN"
}

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
		echo "          several separated by commas = failover, the first is tried first"
		while true; do
			ask path "Path [$n]: "
			path=${path// /}
			[ -n "$path" ] || break
			case "$path" in /*) ;; *) path="/$path" ;; esac
			ask target "Target for $path: "
			target=${target// /}
			[ -n "$target" ] || { echo "  a target is required" >&2; continue; }
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
    targets = [t for t in target.split(",") if t]
    if host:
        routes[path] = {"targets": targets, "host": host}
    elif len(targets) == 1:
        routes[path] = targets[0]
    else:
        routes[path] = targets
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
		apply_routes "$ROUTES"
	else
		echo "==> no terminal and no $ROUTES: keeping the routes in $CONF" >&2
	fi ;;
esac

# ---- verify --------------------------------------------------------------------------

echo
echo "==> probing every upstream"
ayana-cdn check -config "$CONF" || echo "warning: some upstreams are unreachable from this VPS (see above)" >&2

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
