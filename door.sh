#!/bin/bash
# The door on a server of its own (DevOps plan version 44, step C1). A Mac session runs it once as root, over the
# owner's SSH, from a checkout of Fleet, with the signed manifest of the release that the door is to run:
#
#   door.sh --manifest <file>
#
# It makes the OS user `door`, its folders, the door's own vault key (an age identity, whose recipient the owner pins in
# the central vault) and its SSH key to the hosts' second sshd, the three root commands, the service on the private
# network and the local patch timer, and pins the release keys of this checkout. The code comes from the public
# repository at the manifest's revision (door.py update), never from this checkout. There is no release timer: when
# the app sees a new release, it writes the signed manifest to `door-update` over its own SSH, and the door checks the
# release key and the floor itself. A second run is safe, and keeps every key. It prints no secret: its last lines are
# the vault recipient, the SSH public key and the address of the door.
set -euo pipefail
umask 022

MANIFEST=""
PORT=8766
HERE="$(cd "$(dirname "$0")" && pwd)"
COVERED="ubuntu:24.04 ubuntu:26.04"

die() { echo "door.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --manifest) MANIFEST="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        *) die "unknown option $1" ;;
    esac
done
[ "$(id -u)" = 0 ] || die "run it as root"
. /etc/os-release
case " $COVERED " in
    *" ${ID:-?}:${VERSION_ID:-?} "*) ;;
    *) die "${PRETTY_NAME:-this system} is not a release that the door's tests covered ($COVERED)" ;;
esac
[ -n "$MANIFEST" ] && [ -f "$MANIFEST" ] || die "--manifest <file>: the signed manifest of the release to run"
[ -f "$HERE/door.py" ] && [ -f "$HERE/release-key.pub" ] || die "run it from a checkout of Fleet"
ADDRESS="$(tailscale ip -4 2>/dev/null | head -n 1 || true)"
[[ "$ADDRESS" =~ ^100\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Tailscale gives this server no address: the door listens there"

DEBIAN_FRONTEND=noninteractive apt-get install -y -o DPkg::Lock::Timeout=600 \
    git age openssh-client python3 gh unattended-upgrades >/dev/null

getent group door >/dev/null || groupadd --system door
id door >/dev/null 2>&1 || useradd --system --gid door --home-dir /var/lib/fleet-door --no-create-home \
    --shell /usr/sbin/nologin door
install -d -m 0750 -o root -g door /etc/fleet-door
install -d -m 0700 -o door -g door /var/lib/fleet-door /var/lib/fleet-door/ssh /var/lib/fleet-door/secrets
install -d -m 0755 -o root -g root /opt/fleet-door
install -m 0644 -o root -g root "$HERE/release-key.pub" /etc/fleet-door/release-key.pub

# the door's own keys: made here, by its own user, and never copied anywhere
[ -f /var/lib/fleet-door/vault.key ] || runuser -u door -- age-keygen -o /var/lib/fleet-door/vault.key 2>/dev/null
[ -f /var/lib/fleet-door/ssh/id_ed25519 ] || \
    runuser -u door -- ssh-keygen -q -t ed25519 -N '' -C door -f /var/lib/fleet-door/ssh/id_ed25519
chmod 0600 /var/lib/fleet-door/vault.key /var/lib/fleet-door/ssh/id_ed25519

printf '{"address": "%s", "port": %s}\n' "$ADDRESS" "$PORT" > /etc/fleet-door/door.json
chown root:door /etc/fleet-door/door.json
chmod 0640 /etc/fleet-door/door.json

for verb in access update hub-secrets; do
    printf '#!/bin/sh\n# the door'"'"'s root command %s (door.sh)\nexec /usr/bin/python3 -I /opt/fleet-door/current/door.py %s\n' \
        "$verb" "$verb" > "/usr/local/sbin/door-$verb"
    chmod 0755 "/usr/local/sbin/door-$verb"
done

# the code of the signed release, from the public repository: the first update runs this checkout's door.py, and every
# later one the door's own
(cd "$HERE" && FLEET_DOOR_ROOT= python3 -I door.py update < "$MANIFEST")

cat > /etc/systemd/system/fleet-door.service <<EOF
[Unit]
Description=The door (Founderizer)
After=network-online.target tailscaled.service
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
User=door
Group=door
WorkingDirectory=/opt/fleet-door/current
ExecStart=/usr/bin/python3 -I /opt/fleet-door/current/door.py serve
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/fleet-door
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet=
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable fleet-door.service >/dev/null 2>&1
systemctl restart fleet-door.service
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow in on tailscale0 to any port "$PORT" proto tcp comment 'fleet door' >/dev/null
fi

# the local patch timer: security updates every day, and a reboot at 04:30 UTC when one needs it
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
cat > /etc/apt/apt.conf.d/52fleet-door <<'EOF'
// The door patches itself (door.sh): no agent holds it.
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:30";
EOF
systemctl enable --now unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1

systemctl is-active --quiet fleet-door.service || die "the door did not start: journalctl -u fleet-door"
echo "the door runs on $ADDRESS:$PORT"
echo "vault-recipient: $(age-keygen -y /var/lib/fleet-door/vault.key)"
echo "ssh-key: $(cut -d' ' -f1,2 /var/lib/fleet-door/ssh/id_ed25519.pub) door"
