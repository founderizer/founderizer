#!/bin/bash
# The door's parts on one managed host (DevOps plan, section 2: "The host login" and "Server access in Founderizer").
# The owner's app runs it once as root, over the owner's own SSH, from a folder that holds this script, ops-root,
# ops-read, inventory and release-key.pub out of its signed bundle:
#
#   install.sh --level read --door-key "ssh-ed25519 AAAA... door"          Read: ops-agent, ops-read, the second sshd
#   install.sh --level fix --mode fix|rule-only --door-key "..."           Fix: Read, ops-root and its sudoers line
#   install.sh --remove                                                     No access: every part of the door leaves
#
# Options of a Fix host: --hidden <path> (an app tree or a secret path more, again for each), --fleet-kit <path> (a
# Fleet machine's checkout), --pool <lvm path> (a CI host's pool volume), --build-file <path> (a CI host's sparse ext4
# file on a loop device, which holds its runners' builds) and --runner-user <user> (a CI host's rootless Docker user,
# whose containers are its runners). The app names neither: when an install named neither, ops-root finds both on the
# host itself, the one user other than root whose rootless Docker keeps its data on such a file, and that file
# (ci_layout). --port <n> is the second sshd's port, and --address <ip> the address it listens
# on, this host's Tailscale address unless a test host names 127.0.0.1.
#
# It refuses a distribution release that the tests did not cover. A second run is safe: it writes the same files
# again and keeps the host key. Its last line is the host key of the second sshd, which the door's access file needs.
set -euo pipefail
umask 022

PORT=2244
LEVEL="" MODE="" DOOR_KEY="" REMOVE=0 KIT="" POOL="" BUILD_FILE="" RUNNER_USER="" ADDRESS=""
HIDDEN=()
COVERED="ubuntu:24.04 ubuntu:26.04"          # the releases whose test 5 ran on a temporary server
HERE="$(cd "$(dirname "$0")" && pwd)"
ETC=/etc/ops-root LIB=/usr/local/lib/ops-root SBIN=/usr/local/sbin/ops-root STATE=/var/lib/ops-root
UNIT=/etc/systemd/system/ops-sshd.service SUDOERS=/etc/sudoers.d/ops-agent
BOOT_UNIT=/etc/systemd/system/ops-root-rollback-at-boot.service      # ops-root's own: each arm puts it in place

die() { echo "install.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --level) LEVEL="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --door-key) DOOR_KEY="$2"; shift 2 ;;
        --hidden) HIDDEN+=("$2"); shift 2 ;;
        --fleet-kit) KIT="$2"; shift 2 ;;
        --pool) POOL="$2"; shift 2 ;;
        --build-file) BUILD_FILE="$2"; shift 2 ;;
        --runner-user) RUNNER_USER="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --address) ADDRESS="$2"; shift 2 ;;
        --remove) REMOVE=1; shift ;;
        *) die "unknown option $1" ;;
    esac
done

[ "$(id -u)" = 0 ] || die "run it as root"
. /etc/os-release
case " $COVERED " in
    *" ${ID:-?}:${VERSION_ID:-?} "*) ;;
    *) die "${PRETTY_NAME:-this system} is not a release that the door's tests covered ($COVERED)" ;;
esac
[[ "$PORT" =~ ^[1-9][0-9]{2,4}$ ]] || die "--port is a port number"

remove() {
    systemctl disable --now ops-sshd.service 2>/dev/null || true
    systemctl disable "${BOOT_UNIT##*/}" 2>/dev/null || true
    rm -f "$UNIT" "$BOOT_UNIT" "$SUDOERS"
    rm -rf /etc/systemd/system/ops-sshd.service.d
    systemctl daemon-reload
    if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
        ufw delete allow in on tailscale0 to any port "$PORT" proto tcp >/dev/null 2>&1 || true
    fi
    if id ops-agent >/dev/null 2>&1; then
        pkill -u ops-agent 2>/dev/null || true
        userdel ops-agent
    fi
    if [ -f "$ETC/installed-openssh" ]; then      # this script installed sshd for itself: it leaves with it
        apt-get purge -y -o DPkg::Lock::Timeout=600 openssh-server >/dev/null
    fi
    rm -rf "$ETC" "$LIB" "$STATE" "$SBIN" /var/lib/ops-agent
    echo "removed: ops-agent, ops-read, ops-root and the second sshd"
}

if [ "$REMOVE" = 1 ]; then
    remove
    exit 0
fi

case "$LEVEL" in
    read) [ -z "$MODE" ] || die "--mode goes with --level fix" ;;
    fix) case "$MODE" in fix|rule-only) ;; *) die "--level fix needs --mode fix or --mode rule-only" ;; esac ;;
    *) die "--level is read or fix" ;;
esac
[[ "$DOOR_KEY" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]{60,100}(\ [A-Za-z0-9@._-]{1,64})?$ ]] || \
    die "--door-key is the door's ssh-ed25519 public key"
for f in ops-read inventory app-release release-key.pub; do [ -f "$HERE/$f" ] || die "$f is not beside this script"; done
[ "$LEVEL" = read ] || [ -f "$HERE/ops-root" ] || die "ops-root is not beside this script"
if [ -z "$ADDRESS" ]; then
    ADDRESS="$(tailscale ip -4 2>/dev/null | head -n 1 || true)"
    [[ "$ADDRESS" =~ ^100\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Tailscale gives this host no address: the second sshd listens there"
fi
[[ "$ADDRESS" =~ ^(100\.[0-9]+\.[0-9]+\.[0-9]+|127\.0\.0\.1)$ ]] || die "--address is a Tailscale address, or 127.0.0.1 on a test host"
if ss -Htln "sport = :$PORT" | grep -q . && ! systemctl is-active --quiet ops-sshd.service; then
    die "port $PORT is in use on this host"
fi

# sshd's program, without a public sshd: a host that has no openssh-server gets it with its own units masked first
if ! dpkg-query -W -f='${Status}' openssh-server 2>/dev/null | grep -q 'install ok installed'; then
    systemctl mask ssh.service ssh.socket >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y -o DPkg::Lock::Timeout=600 openssh-server >/dev/null
    mkdir -p "$ETC"
    touch "$ETC/installed-openssh"
fi

install -d -m 0755 -o root -g root "$ETC" "$LIB"
install -d -m 0700 -o root -g root "$STATE"
install -m 0755 -o root -g root "$HERE/ops-read" "$LIB/ops-read"
install -m 0755 -o root -g root "$HERE/inventory" "$LIB/inventory"
install -m 0755 -o root -g root "$HERE/app-release" "$LIB/app-release"     # the product's release helper (plan N4)
install -m 0644 -o root -g root "$HERE/release-key.pub" "$ETC/release-key.pub"
[ ! -f "$HERE/early-key.pub" ] || install -m 0644 -o root -g root "$HERE/early-key.pub" "$ETC/early-key.pub"

# ops-agent: no password and not locked (UsePAM no refuses a locked account), its login shell is ops-read, and it
# reads the logs
if ! id ops-agent >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/ops-agent --no-create-home --shell "$LIB/ops-read" ops-agent
fi
usermod -p '*' -s "$LIB/ops-read" -G adm,systemd-journal ops-agent
install -d -m 0750 -o root -g ops-agent /var/lib/ops-agent

# the door's key, in a root-owned file, with every restriction on the key itself too
printf 'restrict,command="%s" %s\n' "$LIB/ops-read" "$DOOR_KEY" > "$ETC/authorized_keys.new"
chmod 0644 "$ETC/authorized_keys.new"
mv -f "$ETC/authorized_keys.new" "$ETC/authorized_keys"
[ -f "$ETC/ssh_host_ed25519_key" ] || ssh-keygen -q -t ed25519 -N '' -C "ops-sshd" -f "$ETC/ssh_host_ed25519_key"
chmod 0600 "$ETC/ssh_host_ed25519_key"

cat > "$ETC/sshd_config" <<EOF
# The second sshd: the door's key only, as ops-agent, on the private network (written by the door's install.sh)
Port $PORT
ListenAddress $ADDRESS
HostKey $ETC/ssh_host_ed25519_key
PidFile /run/ops-sshd.pid
AuthorizedKeysFile $ETC/authorized_keys
AllowUsers ops-agent
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
UsePAM no
PermitTTY no
AllowTcpForwarding no
AllowStreamLocalForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no
PermitUserRC no
ForceCommand $LIB/ops-read
MaxAuthTries 2
MaxSessions 4
LogLevel VERBOSE
EOF
chmod 0644 "$ETC/sshd_config"
# sshd -t needs its privilege separation folder, which only a running sshd's unit makes: on a host that Tailscale's own
# SSH serves, OpenSSH is masked and the folder is not there (7 November 2026). The unit below makes it at each start.
install -d -m 0755 -o root -g root /run/sshd
/usr/sbin/sshd -t -f "$ETC/sshd_config"

cat > "$UNIT" <<EOF
[Unit]
Description=The door's second sshd (ops-agent only)
After=network-online.target tailscaled.service
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
ExecStartPre=/bin/mkdir -p /run/sshd
ExecStartPre=/bin/chmod 0755 /run/sshd
ExecStartPre=/usr/sbin/sshd -t -f $ETC/sshd_config
ExecStart=/usr/sbin/sshd -D -e -f $ETC/sshd_config
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable ops-sshd.service >/dev/null 2>&1
systemctl restart ops-sshd.service
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow in on tailscale0 to any port "$PORT" proto tcp comment 'ops-sshd' >/dev/null
fi

if [ "$LEVEL" = fix ]; then
    install -m 0755 -o root -g root "$HERE/ops-root" "$SBIN"
    echo "$MODE" > "$ETC/mode"
    printf '%s\n' "${HIDDEN[@]+"${HIDDEN[@]}"}" | grep '^/' > "$ETC/hidden" || true
    [ -z "$KIT" ] || echo "$KIT" > "$ETC/fleet-kit"
    [ -z "$POOL" ] || echo "$POOL" > "$ETC/pool"
    [ -z "$BUILD_FILE" ] || echo "$BUILD_FILE" > "$ETC/build-file"
    [ -z "$RUNNER_USER" ] || echo "$RUNNER_USER" > "$ETC/runner-user"
    chmod 0644 "$ETC/mode" "$ETC/hidden"
    printf 'ops-agent ALL=(root) NOPASSWD: %s\n' "$SBIN" > "$SUDOERS.new"
    chmod 0440 "$SUDOERS.new"
    visudo -c -q -f "$SUDOERS.new" >/dev/null
    mv -f "$SUDOERS.new" "$SUDOERS"
else
    # from Fix down to Read: the root path leaves, and so do the files that only ops-root reads, the rollback's
    # snapshot too: no ops-root fires it here, and a Fix much later must not find it at its first boot
    rm -f "$SUDOERS" "$SBIN" "$ETC/mode" "$ETC/fleet-kit" "$ETC/pool" "$ETC/build-file" "$ETC/runner-user"
    rm -rf "$STATE/rollback"
fi
systemctl is-active --quiet ops-sshd.service || die "the second sshd did not start: journalctl -u ops-sshd"
echo "installed: level $LEVEL${MODE:+, mode $MODE}, the second sshd on $ADDRESS:$PORT"
echo "host-key: $(cut -d' ' -f1,2 "$ETC/ssh_host_ed25519_key.pub")"
