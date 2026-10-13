#!/usr/bin/env bash
# ayana-cdn installer and upgrader.
#
#   sudo ./deploy/install.sh [--no-sysctl] [--no-start] [--test] [--skip-preflight] [--go-root DIR]
#
# Safe to run again for upgrades: the existing config is kept and validated
# with the new build before anything is replaced; a running v2 edge is
# restarted without dropping connections.
set -Eeuo pipefail
umask 022

PREFIX=/opt/ayana-cdn
BIN=/usr/local/bin/ayana-cdn
CONF_DIR=/etc/ayana-cdn
CONF=$CONF_DIR/config.json
UNIT=/etc/systemd/system/ayana-cdn.service
DROPIN_DIR=/etc/systemd/system/ayana-cdn.service.d
SYSCTL_FILE=/etc/sysctl.d/99-ayana-cdn.conf
SERVICE_USER=ayana-cdn
MIN_GO_MINOR=26          # go.mod requires Go 1.26 or newer
FALLBACK_GO=go1.27.1     # only if go.dev cannot name the latest release
MANAGED_MARK='# managed by ayana-cdn install.sh'

PKG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -t 1 ]; then G=$'\033[1;32m' Y=$'\033[1;33m' R=$'\033[1;31m' N=$'\033[0m'; else G='' Y='' R='' N=''; fi
log()  { printf '%s==>%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%swarning:%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }
trap 'die "install.sh failed at line $LINENO: $BASH_COMMAND"' ERR

usage() {
	cat <<EOF
usage: sudo $0 [options]

  --no-sysctl        do not install the kernel network tuning (deploy/sysctl-99-ayana-cdn.conf)
  --no-start         install but do not start the service on a fresh install
  --test             run the test suite before installing (about a minute)
  --skip-preflight   skip the port / DNS / clock checks
  --go-root DIR      build with the Go toolchain in DIR (1.$MIN_GO_MINOR or newer) instead of
                     downloading the latest release into $PREFIX
EOF
}

opt_sysctl=1 opt_start=1 opt_test=0 opt_preflight=1 GO_ROOT=""
while [ $# -gt 0 ]; do
	case "$1" in
	--no-sysctl) opt_sysctl=0 ;;
	--no-start) opt_start=0 ;;
	--test) opt_test=1 ;;
	--skip-preflight) opt_preflight=0 ;;
	--go-root) GO_ROOT="${2:?--go-root needs a directory}"; shift ;;
	--go-root=*) GO_ROOT="${1#*=}" ;;
	-h | --help) usage; exit 0 ;;
	*) usage >&2; die "unknown option: $1" ;;
	esac
	shift
done

[ "$(id -u)" -eq 0 ] || die "run as root: sudo $0"
[ "$(uname -s)" = Linux ] || die "ayana-cdn runs on Linux only"
if [ ! -f "$PKG_DIR/go.mod" ] || [ ! -d "$PKG_DIR/cmd/ayana-cdn" ]; then
	die "run this from the unpacked ayana-cdn package"
fi
have_systemd=0
[ -d /run/systemd/system ] && have_systemd=1
VERSION=$(sed -nE 's/^var version = "([^"]+)"/\1/p' "$PKG_DIR/cmd/ayana-cdn/server.go")
[ -n "$VERSION" ] || die "cannot read the version from cmd/ayana-cdn/server.go"

case "$(uname -m)" in
x86_64 | amd64) GOARCH=amd64 ;;
aarch64 | arm64) GOARCH=arm64 ;;
armv7l | armv6l) GOARCH=armv6l ;;
i386 | i686) GOARCH=386 ;;
*) die "unsupported CPU architecture: $(uname -m)" ;;
esac

# ---- dependencies ---------------------------------------------------------------------

need=()
for c in curl tar sha256sum; do command -v "$c" >/dev/null || need+=("$c"); done
if [ ${#need[@]} -gt 0 ]; then
	if command -v apt-get >/dev/null; then
		log "installing ${need[*]}"
		DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates curl tar coreutils >/dev/null
	else
		die "please install: ${need[*]}"
	fi
fi

# ---- Go toolchain ---------------------------------------------------------------------

go_version_ok() { # $1 = go binary; prints its version if it is new enough
	local v minor
	v=$(GOTOOLCHAIN=local "$1" env GOVERSION 2>/dev/null) || return 1
	minor=$(printf '%s' "$v" | sed -nE 's/^go1\.([0-9]+).*/\1/p')
	[ -n "$minor" ] && [ "$minor" -ge "$MIN_GO_MINOR" ] || return 1
	printf '%s' "$v"
}

# latest_go prints "<version> <sha256> <file>" for the newest stable Go release.
latest_go() {
	local json v file sum
	if command -v python3 >/dev/null && json=$(curl -fsSL --max-time 30 'https://go.dev/dl/?mode=json'); then
		if printf '%s' "$json" | python3 -c '
import json, sys
arch = sys.argv[1]
for rel in json.load(sys.stdin):
    if not rel.get("stable"):
        continue
    for f in rel.get("files", []):
        if f.get("kind") == "archive" and f.get("os") == "linux" and f.get("arch") == arch:
            print(rel["version"], f["sha256"], f["filename"])
            sys.exit(0)
sys.exit(1)' "$GOARCH"; then
			return 0
		fi
	fi
	v=$(curl -fsSL --max-time 30 'https://go.dev/VERSION?m=text' 2>/dev/null | head -n1) || v=""
	[[ "$v" =~ ^go1\.[0-9]+(\.[0-9]+)?$ ]] || v=$FALLBACK_GO
	file="$v.linux-$GOARCH.tar.gz"
	sum=$(curl -fsSL --max-time 30 "https://dl.google.com/go/$file.sha256" | tr -d '[:space:]') || return 1
	[[ "$sum" =~ ^[0-9a-f]{64}$ ]] || return 1
	printf '%s %s %s\n' "$v" "$sum" "$file"
}

setup_go() {
	if [ -n "$GO_ROOT" ]; then
		GO="$GO_ROOT/bin/go"
		[ -x "$GO" ] || die "no go binary at $GO"
		gv=$(go_version_ok "$GO") || die "$GO is older than Go 1.$MIN_GO_MINOR"
		log "using $gv from $GO_ROOT"
		return
	fi
	local gv gsum gfile dest tmp
	read -r gv gsum gfile < <(latest_go || true) || true
	[ -n "${gfile:-}" ] || die "could not get the latest Go release and its checksum from go.dev / dl.google.com.
       Retry later, or build with an existing toolchain: --go-root /usr/local/go (Go 1.$MIN_GO_MINOR+)"
	dest="$PREFIX/$gv"
	install -d -m 0755 "$PREFIX"
	if [ -x "$dest/bin/go" ]; then
		log "Go $gv already installed in $dest"
	else
		log "downloading $gfile (checksum from go.dev)"
		tmp=$(mktemp -d "$PREFIX/.download.XXXXXX")
		if ! curl -fSL --retry 3 --max-time 900 -o "$tmp/$gfile" "https://dl.google.com/go/$gfile"; then
			rm -rf "$tmp"
			die "download of $gfile failed"
		fi
		if ! printf '%s  %s\n' "$gsum" "$tmp/$gfile" | sha256sum -c --quiet -; then
			rm -rf "$tmp"
			die "checksum mismatch for $gfile: not installing it"
		fi
		tar -C "$tmp" -xzf "$tmp/$gfile"
		mv "$tmp/go" "$dest"
		rm -rf "$tmp"
	fi
	ln -sfn "$dest" "$PREFIX/go"
	for old in "$PREFIX"/go1.*; do
		[ "$old" = "$dest" ] || rm -rf "$old"
	done
	GO="$PREFIX/go/bin/go"
	gv=$(go_version_ok "$GO") || die "the downloaded toolchain does not work"
	log "using private toolchain $gv ($PREFIX/go; /usr/local/go is not touched)"
}

# ---- build ------------------------------------------------------------------------------

build() {
	local src="$PREFIX/src"
	log "building ayana-cdn $VERSION"
	rm -rf "$src.new"
	install -d -m 0755 "$src.new"
	(cd "$PKG_DIR" && tar --exclude=./.git --exclude=./bin -cf - .) | tar -C "$src.new" -xf -
	rm -rf "$src"
	mv "$src.new" "$src"
	export GOTOOLCHAIN=local GOPATH="$PREFIX/gopath" GOCACHE="$PREFIX/cache" CGO_ENABLED=0
	if ! (cd "$src" && "$GO" mod tidy); then
		die "go mod tidy failed: it downloads golang.org/x/crypto and verifies it (needs https://proxy.golang.org and https://sum.golang.org)"
	fi
	if [ "$opt_test" = 1 ]; then
		log "running the test suite"
		(cd "$src" && "$GO" test -count=1 ./...) || die "tests failed; nothing was installed"
	fi
	(cd "$src" && "$GO" build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$PREFIX/ayana-cdn.new" ./cmd/ayana-cdn)
	NEWBIN="$PREFIX/ayana-cdn.new"
	log "built: $("$NEWBIN" version)"
}

# ---- config ---------------------------------------------------------------------------------

cfg_field() { # prints tab-separated: listen tls.mode tls.cache_dir tls.key_file hosts...
	command -v python3 >/dev/null || return 1
	"$NEWBIN" config show -config "$CONF" 2>/dev/null | python3 -c '
import json, sys
c = json.load(sys.stdin)
t = c.get("tls", {})
udp = [b.get("listen", "") for b in (c.get("backends") or []) if b.get("proto") == "udp" and b.get("listen")]
print("\t".join([c.get("listen", ""), t.get("mode", ""), t.get("cache_dir", ""), t.get("key_file", ""), " ".join(c.get("cdn_hosts") or []), " ".join(udp)]))'
}

setup_config() {
	install -d -m 0755 "$CONF_DIR"
	if [ -f "$CONF" ]; then
		log "keeping your config $CONF (the package default is in $CONF_DIR/config.json.example)"
		install -m 0644 "$PKG_DIR/config/config.json" "$CONF_DIR/config.json.example"
	else
		install -m 0644 "$PKG_DIR/config/config.json" "$CONF"
		log "installed the default config $CONF: review cdn_hosts, tls.email and backends"
	fi
	# The service runs as $SERVICE_USER; when the web panel's control actions
	# are enabled it rewrites this config (the unit grants ReadWritePaths here),
	# so the directory must be writable by that user. root (the CLI) keeps full
	# access regardless. The user is created before this runs.
	chown -R "$SERVICE_USER":"$SERVICE_USER" "$CONF_DIR"
	chmod 0750 "$CONF_DIR"
	# Apply the domain/email collected by setup.sh to both fresh installs and
	# existing configs, while preserving their routes and other settings.
	if [ -n "${AYANA_CDN_DOMAIN:-}" ]; then
		python3 - "$CONF" "$AYANA_CDN_DOMAIN" "${AYANA_CDN_EMAIL:-admin@$AYANA_CDN_DOMAIN}" <<'PYCFG'
import json, os, sys, tempfile
path, domain, email = sys.argv[1:]
with open(path, encoding="utf-8") as f:
    config = json.load(f)
config["cdn_hosts"] = [domain]
tls = config.setdefault("tls", {})
if tls.get("mode", "acme") == "acme":
    tls["email"] = email
fd, tmp = tempfile.mkstemp(prefix=".config.json.", dir=os.path.dirname(path))
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, os.stat(path).st_mode & 0o777)
    os.replace(tmp, path)
finally:
    if os.path.exists(tmp):
        os.unlink(tmp)
PYCFG
		chown "$SERVICE_USER:$SERVICE_USER" "$CONF"
		log "configured CDN domain $AYANA_CDN_DOMAIN"
	fi
	# CLI commands run as root can create the lock file. Keep it owned by the
	# service account so panel edits can acquire it after installation.
	if [ -e "$CONF.lock" ]; then
		chown "$SERVICE_USER:$SERVICE_USER" "$CONF.lock"
		chmod 0600 "$CONF.lock"
	fi
	if ! "$NEWBIN" check -no-dial -config "$CONF"; then
		rm -f "$NEWBIN"
		die "$CONF does not validate with $VERSION (details above). Nothing was replaced; the running service is untouched."
	fi
	local info
	if info=$(cfg_field); then
		IFS=$'\t' read -r C_LISTEN C_MODE C_CACHE C_KEY C_HOSTS C_UDP <<<"$info"
		if [ "$C_MODE" = acme ] && [[ "$C_CACHE" != /var/lib/ayana-cdn/* ]]; then
			warn "tls.cache_dir ($C_CACHE) is outside /var/lib/ayana-cdn: the sandboxed service cannot write there"
		fi
		if [ "$C_MODE" = files ] && [ -n "$C_KEY" ] && id -u "$SERVICE_USER" >/dev/null 2>&1 &&
			! runuser -u "$SERVICE_USER" -- test -r "$C_KEY" 2>/dev/null; then
			warn "the service user '$SERVICE_USER' cannot read $C_KEY; see docs/OPERATIONS.md (\"Certificates from files\")"
		fi
	fi
}

# ---- system integration --------------------------------------------------------------------

memory_dropin() {
	local f="$DROPIN_DIR/10-memory.conf" kb mib
	if [ -f "$f" ] && ! grep -qF "$MANAGED_MARK" "$f"; then
		log "keeping your $f"
		return
	fi
	kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
	mib=$((kb * 3 / 4 / 1024))
	install -d -m 0755 "$DROPIN_DIR"
	printf '%s (75%% of RAM); remove this line to keep your own value\n[Service]\nEnvironment=GOMEMLIMIT=%dMiB\n' \
		"$MANAGED_MARK" "$mib" >"$f"
	log "GOMEMLIMIT=${mib}MiB ($f)"
}

setup_sysctl() {
	install -m 0644 "$PKG_DIR/deploy/sysctl-99-ayana-cdn.conf" "$SYSCTL_FILE"
	if [ -f /etc/sysctl.d/99-cdn.conf ] && grep -q 'Tuning for an edge that holds many long-lived' /etc/sysctl.d/99-cdn.conf; then
		rm -f /etc/sysctl.d/99-cdn.conf # v1's file, superseded
	fi
	modprobe tcp_bbr 2>/dev/null || true
	local line key val failed=0
	while IFS= read -r line; do
		case "$line" in '' | '#'*) continue ;; esac
		line=${line#-}
		key=$(printf '%s' "${line%%=*}" | tr -d ' ')
		val=$(printf '%s' "${line#*=}" | sed -E 's/^ +//; s/ +$//')
		[ -e "/proc/sys/${key//.//}" ] || continue # module not loaded / not in this kernel
		sysctl -q -w "$key=$val" >/dev/null 2>&1 || failed=1
	done <"$SYSCTL_FILE"
	[ "$failed" = 0 ] || warn "some kernel settings could not be applied now (containers often forbid this); they apply at boot where allowed"
	local fmax
	fmax=$(cat /proc/sys/fs/file-max)
	if [ "$fmax" -lt 2097152 ]; then
		printf 'fs.file-max = 2097152\n' >/etc/sysctl.d/98-ayana-cdn-filemax.conf
		sysctl -q -w fs.file-max=2097152 >/dev/null 2>&1 || true
	fi
	log "kernel network tuning in $SYSCTL_FILE"
}

install_completion() {
	local d=/usr/share/bash-completion/completions
	[ -d "$d" ] || d=/etc/bash_completion.d
	[ -d "$d" ] || return 0
	install -m 0644 "$PKG_DIR/deploy/ayana-cdn.bash-completion" "$d/ayana-cdn"
}

preflight() {
	[ -n "${C_LISTEN:-}" ] || return 0
	local port=${C_LISTEN##*:} holders
	if command -v ss >/dev/null; then
		holders=$(ss -Hltnp "sport = :$port" 2>/dev/null || true)
		if [ -n "$holders" ] && ! grep -q '"ayana-cdn"' <<<"$holders"; then
			warn "port $port is already in use by: $(grep -oE 'users:\(\("[^"]+"' <<<"$holders" | sed 's/users:(("//' | sort -u | tr '\n' ' ')"
			warn "stop that service, or keep it and put nginx in front: deploy/frontdoor.conf"
		fi
	fi
	local localips h ips
	localips=" $(hostname -I 2>/dev/null || true) "
	for h in ${C_HOSTS:-}; do
		ips=$(getent ahosts "$h" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' || true)
		if [ -z "$ips" ]; then
			warn "$h does not resolve yet: point its DNS at this server before clients (and ACME) can reach it"
			continue
		fi
		local match=0 ip
		for ip in $ips; do [[ "$localips" == *" $ip "* ]] && match=1; done
		[ "$match" = 1 ] || log "note: $h resolves to $ips; not an address on this machine (fine behind NAT or a floating IP)"
	done
	local uport uholders
	for uport in ${C_UDP:-}; do
		uport=${uport##*:}
		if command -v ss >/dev/null; then
			uholders=$(ss -Hlunp "sport = :$uport" 2>/dev/null || true)
			if [ -n "$uholders" ] && ! grep -q '"ayana-cdn"' <<<"$uholders"; then
				warn "udp port $uport is already in use by: $(grep -oE 'users:\(\("[^"]+"' <<<"$uholders" | sed 's/users:(("//' | sort -u | tr '\n' ' ')"
				if grep -q '"systemd-resolve' <<<"$uholders"; then
					warn "that is systemd-resolved. Free :$uport with DNSStubListener=no in /etc/systemd/resolved.conf, then: systemctl restart systemd-resolved"
				fi
				warn "the edge still starts and serves TCP and its other UDP backends; this one will not receive datagrams until the port is free"
			fi
		fi
	done
	if command -v timedatectl >/dev/null && [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" != yes ]; then
		warn "the clock is not NTP-synchronized; TLS and ACME need the correct time (timedatectl set-ntp true)"
	fi
}

# ---- main -------------------------------------------------------------------------------------

setup_go
build
id -u "$SERVICE_USER" >/dev/null 2>&1 ||
	useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$SERVICE_USER"
setup_config
[ "$opt_preflight" = 1 ] && preflight

install -m 0755 "$NEWBIN" "$BIN.new"
mv -f "$BIN.new" "$BIN" # atomic: a running process keeps the old file
rm -f "$NEWBIN"
log "installed $BIN"
install_completion
[ "$opt_sysctl" = 1 ] && setup_sysctl

if [ "$have_systemd" = 0 ]; then
	warn "systemd is not running here: the unit was not installed. Start manually: $BIN serve -config $CONF"
	exit 0
fi

unit_changed=1
[ -f "$UNIT" ] && cmp -s "$PKG_DIR/deploy/ayana-cdn.service" "$UNIT" && unit_changed=0
install -m 0644 "$PKG_DIR/deploy/ayana-cdn.service" "$UNIT"
memory_dropin
systemctl daemon-reload
systemctl enable ayana-cdn >/dev/null 2>&1

if systemctl is-active --quiet ayana-cdn; then
	if "$BIN" status -config "$CONF" >/dev/null 2>&1; then
		log "restarting without downtime"
		if ! "$BIN" restart -config "$CONF"; then
			warn "zero-downtime restart failed (see above); doing a regular restart"
			systemctl restart ayana-cdn
		elif [ "$unit_changed" = 1 ]; then
			log "the systemd unit changed: it applies at the next 'systemctl restart ayana-cdn' (clients reconnect once)"
		fi
	else
		log "upgrading from v1: one regular restart (clients reconnect once; later upgrades have no downtime)"
		systemctl restart ayana-cdn
	fi
elif [ "$opt_start" = 1 ]; then
	log "starting ayana-cdn"
	systemctl start ayana-cdn
else
	log "not started (--no-start). Start with: systemctl start ayana-cdn"
	exit 0
fi

sleep 2
if ! "$BIN" status -config "$CONF"; then
	journalctl -u ayana-cdn -n 40 --no-pager || true
	die "the edge is not answering; see the log above"
fi
log "done. Try: ayana-cdn status | ayana-cdn check | ayana-cdn backend ls"
