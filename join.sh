#!/bin/sh
# Founderizer join script (owner feature servers). The hub serves it at GET /join with its own address in HUB and REPO. The
# owner runs it with the one line from Founderizer (Servers, Add server); FLEET_JOIN holds the one-time join code.
#
#   A VPS (Ubuntu 22.04, 24.04 or 26.04, or Debian 12 or 13), as root: base packages, the user fleet, then the join,
#   security updates, the firewall and the server's own hardening (SSH keys only, npm's seven days, Tailscale's own
#   updates). The line has joined the private network (Tailscale) before this script, and after it SSH reaches the
#   machine over that network only. With a restart time (UTC) from the hub's answer to the join, or else with
#   FLEET_REBOOT_TIME=<HH:MM> on the line, an Ubuntu server also takes the fleet patch policy: Ubuntu's -updates as
#   well as -security, and a restart at that time when an update needs one. Without a time it takes security updates
#   only and never restarts by itself.
#   A Mac (macOS 14 or later, with Tailscale and Homebrew), as the user that will run the agents: tmux and Python
#   with Homebrew, then the join, then this Mac's vault, the one step that asks for that user's password, then
#   Claude's extension for Chrome. The Founderizer installer runs the same line as root behind macOS's own password
#   dialog, with that user in FLEET_MAC_USER: each step of that user still runs as that user, and the vault asks nothing.
#
# The join itself is server.py in a new checkout of the Founderizer repository: the server key, POST /join with the code, and
# the server service. The code goes to server.py on standard input, never in a command argument or a URL. The script
# is safe to run again: each step checks first, and the hub knows the same server again by its address and key.
#
# Then, on Linux, the root helper that makes an agent's OS user and one OS user for each agent this machine already
# has: each agent's session runs as its own user, so its checkout, its runtime, that runtime's credential and its
# vault token are in a home of mode 700 that no other agent can open (PRODUCT.md 4.1). The agents the owner adds
# later are installed under their own users by the server service, which has no root and uses that helper. The last
# step is
# `python3 fleet.py verify` (PRODUCT.md 4.1), whose lines this script prints: a join that half worked says which
# check failed and how to fix it, instead of looking finished. The line ends with a failure when a check failed.
set -eu

HUB="__FLEET_HUB__"
REPO="__FLEET_REPO__"
FLEET="__FLEET_ID__"            # the fleet's id at its release channel, where a Mac takes its signed vault
CHANNEL="__FLEET_CHANNEL__"
TRACK="__FLEET_TRACK__"         # the fleet's track there: early when its setting releases.early is on, else approved
WORKER=fleet
PACKAGES="git tmux python3 curl ca-certificates ufw unattended-upgrades sudo"
MAC_USER=""     # the user that will run a Mac's agents
USER_PATH=""    # that user's PATH
REBOOT_TIME=""  # FLEET_REBOOT_TIME: this server's own restart time (UTC, HH:MM) for the fleet patch policy, or none
ready=yes       # what the last step, verify, answered about this machine
# Seconds that each apt-get waits for the package lock: a new server runs its first updates for about 9 minutes after
# its first boot, and they hold it (hubsetup.py's APT_LOCK_WAIT).
APT_LOCK_WAIT=1200

say() { printf 'Founderizer: %s\n' "$*"; }
stop() { printf 'Founderizer join stopped: %s\n' "$*" >&2; exit 1; }
# `apt-get update` tries the lock of the package lists once: apt reads DPkg::Lock::Timeout only for the lock of dpkg.
# The first updates of a new server hold the lock of the lists while they read the lists, so `update` gets up to 10
# tries, 15 seconds apart. The first 9 say nothing; the words and the exit status of the 10th are the function's.
# hub.sh has the same function.
apt_update() {
    update_try=1
    while [ "$update_try" -lt 10 ]; do
        if apt-get -o "DPkg::Lock::Timeout=$APT_LOCK_WAIT" update -q </dev/null >/dev/null 2>&1; then return 0; fi
        update_try=$((update_try + 1))
        sleep 15
    done
    apt-get -o "DPkg::Lock::Timeout=$APT_LOCK_WAIT" update -q </dev/null >/dev/null
}

linux() {
    [ "$(id -u)" = 0 ] || stop "Run the line as root (for example after sudo -i)."
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-} ${VERSION_ID:-}" in
        "ubuntu 22.04"|"ubuntu 24.04"|"ubuntu 26.04"|"debian 12"|"debian 13") ;;
        *) stop "This system is ${ID:-unknown} ${VERSION_ID:-}. Use Ubuntu 22.04, 24.04 or 26.04, or Debian 12 or 13." ;;
    esac
    case "$REBOOT_TIME" in
        "") ;;
        [01][0-9]:[0-5][0-9]|2[0-3]:[0-5][0-9])
            [ "${ID:-}" = ubuntu ] || stop "FLEET_REBOOT_TIME is for Ubuntu only: the fleet patch policy is Ubuntu's." ;;
        *) stop "FLEET_REBOOT_TIME is \"$REBOOT_TIME\": give the restart time in UTC as HH:MM, for example 02:18." ;;
    esac
    command -v systemctl >/dev/null 2>&1 || stop "systemd is required."
    reach
    missing=""
    for p in $PACKAGES; do
        dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || missing="$missing $p"
    done
    if [ -n "$missing" ]; then
        say "installing$missing"
        export DEBIAN_FRONTEND=noninteractive
        apt_update
        # shellcheck disable=SC2086
        apt-get -o "DPkg::Lock::Timeout=$APT_LOCK_WAIT" install -y -q --no-install-recommends $missing </dev/null >/dev/null
    fi
    say "the user $WORKER: locked password, no sudo, its services run after logout"
    id -u "$WORKER" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash --user-group "$WORKER"
    passwd -l "$WORKER" >/dev/null
    chmod 700 "/home/$WORKER"
    for g in sudo admin wheel; do gpasswd -d "$WORKER" "$g" >/dev/null 2>&1 || true; done
    loginctl enable-linger "$WORKER"
    uid=$(id -u "$WORKER")
    i=0
    while [ ! -d "/run/user/$uid" ] && [ "$i" -lt 30 ]; do sleep 1; i=$((i + 1)); done
    ports=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' | sort -u)
    first=$(printf '%s\n' "$ports" | head -n 1)
    checkout "/home/$WORKER/fleet-server" as_worker
    printf '%s\n' "$code" | as_worker python3 "/home/$WORKER/fleet-server/server.py" join --hub "$HUB" --kind linux \
        --ssh-port "${first:-22}"
    hub_time
    updates
    firewall "/home/$WORKER/fleet-server"
    harden "/home/$WORKER/fleet-server"
    current "/home/$WORKER/fleet-server" as_worker
    agent_helper "/home/$WORKER/fleet-server"
    agent_users "/home/$WORKER/fleet-server"
    vault_broker "/home/$WORKER/fleet-server"
    verify_step "/home/$WORKER/fleet-server" as_worker
    say "done. Add an agent to this server in Founderizer: Settings, Servers, this server, Add agent."
}

as_worker() {    # the command as the user of the service, from its home folder, with its user services reachable
    # shellcheck disable=SC2016
    runuser -u "$WORKER" -- env HOME="/home/$WORKER" XDG_RUNTIME_DIR="/run/user/$(id -u "$WORKER")" \
        PATH="/home/$WORKER/.local/bin:/usr/local/bin:/usr/bin:/bin" sh -c 'cd "$HOME" && exec "$@"' sh "$@"
}

as_self() { "$@"; }

as_mac_user() { # The command as that Mac user, when the installer runs this script as root. Root's own PATH stays the
                # system's: that user can change what stands in its folders and in Homebrew's.
    sudo -u "$MAC_USER" -H env PATH="$USER_PATH" "$@"
}

reach() {
    curl -fsS -m 10 "$HUB/health" >/dev/null 2>&1 || stop "This machine cannot reach the Founderizer hub at $HUB. Check that \
Tailscale is connected, and the Tailscale access rules for the hub's ports 8765 and 9418."
}

take() {        # $1: the checkout; $2: how to run a command as the user of the service. The checkout's own ref, fetched,
                # and taken only where `lifecycle.py may-take` lets it (DevOps plan 0.1): the data that the hub writes,
                # or a release that a release key signed. A refusal leaves the checkout where it is, and says why.
                # The ref is read once, as one commit: the commit checked is the commit taken.
    "$2" git -C "$1" fetch -q origin </dev/null || return 1
    target=$("$2" git -C "$1" rev-parse --verify -q "@{upstream}^{commit}" </dev/null) || return 1
    "$2" python3 "$1/lifecycle.py" may-take "$1" "$target" </dev/null || return 1
    "$2" git -C "$1" merge -q --ff-only "$target" </dev/null
}

checkout() {    # $1: the folder; $2: how to run a command as the user of the service
    if [ -d "$1/.git" ]; then
        say "the Founderizer repository in $1: up to date"
        take "$1" "$2" || say "$1 could not update; it stays as it is"
    else
        say "the Founderizer repository in $1"
        # On the configuration ref, which is the branch the hub writes and every machine's checkout stands on. A hub
        # from before the split of 2026-10-17 has no such ref, and its checkout starts where it always did.
        "$2" git clone -q -b config "$REPO" "$1" </dev/null \
            || "$2" git clone -q "$REPO" "$1" </dev/null \
            || stop "Could not get the Founderizer repository from $REPO. Check the Tailscale access rules for the hub's \
port 9418."
    fi
}

current() {     # $1: the checkout; $2: how to run a command as the user of the service. The join put this machine in
                # the fleet's team.json, so the checkout takes that commit before anything reads it.
    take "$1" "$2" || say "$1 could not take the hub's newest commit; it stays as it is"
}

agent_helper() { # $1: the checkout. The two root commands of this machine, and the sudoers file that says who may
                 # run them. The server service installs the agents the owner adds later and has no root of its
                 # own, so this is how an agent gets a user, how `fleet.py verify` reads one, and how a release
                 # that changed vault.py reaches this machine's vault broker, which no checkout holds.
    say "the root helpers that make an agent's OS user and update this machine's vault broker, and the sudoers \
lines for them"
    python3 "$1/hubsetup.py" agent-helper --user "$WORKER" --repo "$REPO" </dev/null \
        || stop "The root helpers of this machine's agent users and its vault broker could not be put in place."
}

agent_users() { # $1: the checkout whose team.json names this fleet's agents. One OS user for each agent of this
                # machine, so that no agent's home is readable by another agent's user. A machine that has no agent
                # yet makes none: each agent gets its own when it is added.
    name=$(as_worker python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("name") or "")' \
        "/home/$WORKER/.fleet/server.json" </dev/null 2>/dev/null || true)
    if [ -z "$name" ]; then
        say "this machine has no name from the hub yet, so no agent user is made"
        return 0
    fi
    python3 "$1/hubsetup.py" agent-users --team "$1/team.json" --machine "$name" </dev/null \
        || stop "The OS users of this machine's agents could not be made."
}

vault_broker() { # $1: the checkout. This machine's vault broker: its own user keeps the key of the store and the key
                 # that opens sealed handovers, so that no agent of this machine can read either and no answer of it
                 # gives a login. It belongs to the machine and not to one agent, so it is installed now, before the
                 # machine has its first agent; the agents the owner adds later reach it through the group of their
                 # OS users. A machine with no broker gets the fleet's own store, which needs no account and no
                 # token of the owner's. A broker that is already there keeps the store it has.
    say "this machine's vault, kept by its own user"
    python3 "$1/hubsetup.py" vault --hub "$HUB" --kit "$1" </dev/null \
        || stop "The vault of this machine could not be set up. Nothing of the owner's was read or changed."
}

# The Mac vault as the app's own Vault/install.py and Vault/update.zsh check it: signed by our Developer ID team, with
# the vault's identifier. Nothing of a downloaded build runs as root before it has passed this check.
VAULT_REQUIREMENT='anchor apple generic and certificate leaf[subject.OU] = "6EBZ756H9Q" and identifier "local.agent-fleet.vault"'
VAULT_CONFIG="/Library/Application Support/Fleet Vault/config.json"
VAULT_APP="build/Founderizer.app/Contents/Library/Fleet Vault.app"     # in an unpacked Mac build
# The root half of mac_vault, run once with sudo. The vault is copied into a folder of root's own and checked there, and
# only then is the install.py that it carries run, from that copy: nothing that this user can change runs as root.
# $1 the vault, $2 the Mac user, $3 this Mac's name, $4 the hub, $5 the fleet's id, $6 the channel, $7 the requirement,
# $8 the track. Only an early fleet passes --track: the vault's updater then takes each vault of the early track. An
# approved fleet passes nothing, because the install.py of an approved build may be older than --track and refuse it.
# shellcheck disable=SC2016
VAULT_ROOT_STEP='set -eu
stage=$(mktemp -d /tmp/fleet-vault-root.XXXXXX)
trap "rm -rf \"$stage\"" EXIT
ditto "$1" "$stage/Fleet Vault.app"
chown -R root:wheel "$stage"
codesign --verify --deep --strict -R "=$7" "$stage/Fleet Vault.app"
installer="$stage/Fleet Vault.app/Contents/Resources/install.py"
[ -f "$installer" ] || { echo "the vault of the release channel carries no installer yet" >&2; exit 1; }
early=""
[ "$8" != early ] || early=yes
/usr/bin/python3 "$installer" --app "$stage/Fleet Vault.app" --user "$2" --agent "$3" --hub "$4" --store \
    --fleet "$5" --channel "$6" ${early:+--track early} >/dev/null'

mac_vault() {   # This Mac's vault, which every agent of it reaches (the owner, 28 October 2026: "it is essential that
                # they all have access to secrets"): the signed Fleet Vault that the release channel's newest Mac build
                # carries, put in place by the install.py inside it. It opens the fleet's own store, so it needs no
                # account and no token of the owner's, and it is named after this Mac, because each request of an
                # agent names that agent and carries its key. It is the one step of a Mac's join that needs root, so
                # macOS asks for this user's password here and nowhere else. A Mac whose vault is there keeps it.
    if [ -e "$VAULT_CONFIG" ]; then
        say "this Mac's vault: installed already"
        return 0
    fi
    name=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("name") or "")' \
        "$HOME/.fleet/server.json" </dev/null 2>/dev/null || true)
    if [ -z "$name" ] || [ -z "$FLEET" ]; then
        ready=no
        say "this Mac's vault was not installed: the hub gave no name or no release channel. Run the line again."
        return 0
    fi
    work=$(mktemp -d "${TMPDIR:-/tmp}/fleet-vault.XXXXXX")
    if ! vault_build "$work"; then
        ready=no
        say "this Mac's vault was not installed: $CHANNEL gave no signed vault. Run the line again."
    else
        say "this Mac's vault: macOS asks once for the password of $MAC_USER, because only root installs it"
        if sudo /bin/sh -c "$VAULT_ROOT_STEP" sh "$work/$VAULT_APP" "$MAC_USER" "$name" "$HUB" "$FLEET" "$CHANNEL" \
                "$VAULT_REQUIREMENT" "$TRACK" </dev/null; then
            say "this Mac's vault: installed, with the fleet's own store; it updates itself every hour"
        else
            ready=no
            say "this Mac's vault was not installed: the lines above say why. Run the line again."
        fi
    fi
    rm -rf "$work"
}

vault_build() { # $1: an empty folder. The release channel's newest Mac build, as the vault's own updater takes it: this
                # fleet's manifest, of its track (only the exact word early asks for the early track), then the zip
                # that it names on the channel's own host, by its SHA-256, unpacked.
    manifest="$CHANNEL/releases/app"
    [ "$TRACK" != early ] || manifest="$manifest?track=early"
    curl -fsS --proto '=https' --max-time 60 -H "Founderizer-Fleet: $FLEET" -o "$1/manifest.json" \
        "$manifest" </dev/null || return 1
    url=$(plutil -extract url raw -o - "$1/manifest.json" 2>/dev/null || true)
    digest=$(plutil -extract sha256 raw -o - "$1/manifest.json" 2>/dev/null || true)
    case "$url" in "$CHANNEL"/*) ;; *) return 1 ;; esac
    case "$url" in *..*) return 1 ;; esac
    printf '%s' "$digest" | grep -Eq '^[0-9a-f]{64}$' || return 1
    curl -fsS --proto '=https' --max-time 900 -o "$1/build.zip" "$url" </dev/null || return 1
    [ "$(shasum -a 256 "$1/build.zip" | cut -d' ' -f1)" = "$digest" ] || return 1
    ditto -x -k "$1/build.zip" "$1/build" </dev/null || return 1
    [ -d "$1/$VAULT_APP" ]
}

verify_step() { # $1: the checkout; $2: how to run a command as the user of the service. The last step: the one health
                # check of the whole product (PRODUCT.md 4.1), in its readable form.
    say "verify: is this machine of the fleet healthy? (selftest.py takes about a minute)"
    if "$2" python3 "$1/fleet.py" verify </dev/null; then
        say "this machine of the fleet is healthy"
    else
        ready=no
        say "this machine is NOT ready: the lines above name each check that failed and the fix it carries"
    fi
}

hub_time() {    # The restart time that the hub keeps for this server, from the hub's answer to the join (server.py
                # writes it to server.json): a hub whose setting servers.reboot_times lists times gives one to each
                # Linux server. It wins over FLEET_REBOOT_TIME, so that the hub's record is the server's own time.
    given=$(as_worker python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("reboot_time") or "")' \
        "/home/$WORKER/.fleet/server.json" </dev/null 2>/dev/null || true)
    case "$given" in
        [01][0-9]:[0-5][0-9]|2[0-3]:[0-5][0-9]) ;;
        *) return 0 ;;
    esac
    if [ "${ID:-}" != ubuntu ]; then
        say "the hub keeps the restart time $given for this server, but only Ubuntu takes the fleet patch policy"
        return 0
    fi
    [ -z "$REBOOT_TIME" ] || [ "$REBOOT_TIME" = "$given" ] \
        || say "the hub keeps the restart time $given for this server, so FLEET_REBOOT_TIME=$REBOOT_TIME is not used"
    REBOOT_TIME=$given
}

updates() {     # unattended security updates on, then the pending ones once; the join itself never restarts the
                # server. They run as apt's own two daily services, so apt records the run as its timers do
                # (upgrade-stamp, which the server's own reading gives the hub as the time of its last good security
                # update): a bare unattended-upgrade installs the same and records nothing until the first daily run.
                # With FLEET_REBOOT_TIME the fleet patch policy comes last, after the pending updates, so that no
                # restart comes in the middle of the join.
    printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' \
        > /etc/apt/apt.conf.d/20auto-upgrades
    systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
    eval "$(apt-config shell AUTO_REBOOT Unattended-Upgrade::Automatic-Reboot/b)"
    if [ "${AUTO_REBOOT:-false}" = true ]; then
        say "security updates are on; this server restarts by itself after updates, so they install in its daily run"
    else
        say "security updates are on; installing the pending ones (this can take some minutes)"
        apt-get -o "DPkg::Lock::Timeout=$APT_LOCK_WAIT" -q install </dev/null >/dev/null 2>&1 || true
        apt_daily || say "some security updates did not install now; the daily run tries again"
        [ -n "$REBOOT_TIME" ] || [ ! -f /var/run/reboot-required ] \
            || say "this server needs a restart for its updates; restart it when it has no work"
    fi
    if [ -n "$REBOOT_TIME" ]; then
        patch_policy || stop "The fleet patch policy could not be written: the line above says why. Run the line again."
    fi
}

patch_policy() { # The fleet patch policy, as every Ubuntu server of the fleet has it: the bytes of
                 # scripts/security/apt/52fleet-unattended-upgrades in the DevOps repository (a copy: change both
                 # together), with this server's own time in place of @REBOOT_TIME@. apt reads it after its 50 and 51
                 # files, so it adds -updates to the stock origins and turns the restart on, at that time (UTC) and
                 # only when an update needs one.
    sed "s/@REBOOT_TIME@/$REBOOT_TIME/" > /etc/apt/apt.conf.d/52fleet-unattended-upgrades <<'EOF' || return 1
// Fleet patch policy. Installed as /etc/apt/apt.conf.d/52fleet-unattended-upgrades
// on every Ubuntu host, with @REBOOT_TIME@ set to the host's time from
// docs/patch-policy.md. Change this file in the repo, not on the host.
//
// 1. Take Ubuntu -updates as well as -security. Ubuntu can publish a fixed
//    kernel in -updates days before -security (CVE-2026-98432, 2026-11).
// 2. A new kernel protects a host only after a reboot, so reboot when a
//    package needs it, at the host's own time (UTC).
Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}-updates";
};
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
Unattended-Upgrade::Automatic-Reboot-Time "@REBOOT_TIME@";
EOF
    eval "$(apt-config shell AUTO_REBOOT Unattended-Upgrade::Automatic-Reboot/b \
        AT Unattended-Upgrade::Automatic-Reboot-Time)"
    if [ "${AUTO_REBOOT:-false}" = true ] && [ "${AT:-}" = "$REBOOT_TIME" ]; then
        say "the fleet patch policy: -security and -updates, and a restart at $REBOOT_TIME UTC when an update needs one"
    else
        say "the fleet patch policy is written, but apt-config shows no restart at $REBOOT_TIME: another file in \
/etc/apt/apt.conf.d changes it"
    fi
}

apt_daily() {   # apt's two daily services once, to their end: true when both ended well. A systemctl start that waits
                # holds one connection to systemd, and an update of libc6 or systemd re-executes systemd, which closes
                # that connection with an error while the services go on (a Debian 13 join, 5 November 2026). So the
                # join only starts them, asks every 5 seconds whether a job of theirs is still listed, and then reads
                # the result of each. While systemd re-executes it answers no question, so an unanswered one is asked
                # again: only 12 in a row end the wait.
    systemctl start --no-block apt-daily.service apt-daily-upgrade.service </dev/null >/dev/null 2>&1 || return 1
    unanswered=0
    while [ "$unanswered" -lt 12 ]; do
        if ! listed=$(systemctl list-jobs --no-legend apt-daily.service apt-daily-upgrade.service 2>/dev/null); then
            unanswered=$((unanswered + 1))
        elif [ -z "$listed" ]; then
            [ "$(systemctl show -p Result --value apt-daily.service 2>/dev/null)" = success ] \
                && [ "$(systemctl show -p Result --value apt-daily-upgrade.service 2>/dev/null)" = success ]
            return
        else
            unanswered=0
        fi
        sleep 5
    done
    return 1
}

firewall() {    # $1: the checkout. Incoming traffic over the private network only, SSH included: this machine joined it
                # before this script, and SSH from anywhere else is closed (hubsetup.py firewall). An active firewall
                # keeps its other rules and its defaults; one that was off keeps open the ports that answered before.
    python3 "$1/hubsetup.py" firewall </dev/null \
        || stop "The firewall of this machine could not be set: the line above says why. Run the line again."
}

harden() {      # $1: the checkout. SSH takes keys only with no X11 forwarding, npm takes no package version newer than
                # seven days, and Tailscale updates itself (hubsetup.py harden). Each part checks first and says what
                # it did. A part that cannot be done leaves the server as it was and does not stop the join: the
                # server's own reading tells the hub what holds.
    python3 "$1/hubsetup.py" harden --user "$WORKER" </dev/null \
        || say "the hardening of this server did not finish: the lines above say why"
}

mac() {
    runner=as_self
    MAC_USER=$(id -un)
    if [ "$(id -u)" = 0 ]; then
        [ -n "${FLEET_MAC_USER:-}" ] || stop "Run the line in Terminal as the Mac user that will run the agents, not as root."
        runner=as_mac_user
        MAC_USER=$FLEET_MAC_USER
        HOME=$(dscl . -read "/Users/$MAC_USER" NFSHomeDirectory | awk '{print $2}')
        export HOME
    fi
    version=$(sw_vers -productVersion)
    [ "${version%%.*}" -ge 14 ] 2>/dev/null || stop "macOS $version is too old. Use macOS 14 or later."
    reach
    brew=""
    for b in /opt/homebrew/bin/brew /usr/local/bin/brew; do [ -x "$b" ] && { brew=$b; break; }; done
    [ -n "$brew" ] || stop "Homebrew is not installed. Install it from https://brew.sh, then run the line again."
    USER_PATH="$HOME/.local/bin:$(dirname "$brew"):$PATH"
    prefix=$("$runner" "$brew" --prefix)
    USER_PATH="$HOME/.local/bin:$prefix/bin:$PATH"
    if [ "$runner" = as_self ]; then
        PATH=$USER_PATH
        export PATH
    fi
    need=""
    "$runner" sh -c 'command -v tmux' >/dev/null 2>&1 || need="$need tmux"
    "$runner" "$prefix/bin/python3" -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null || need="$need python"
    [ -x "$prefix/bin/git" ] || git --version >/dev/null 2>&1 || need="$need git"
    if [ -n "$need" ]; then
        say "installing with Homebrew:$need"
        # shellcheck disable=SC2086
        "$runner" "$brew" install $need </dev/null || stop "Homebrew could not install$need."
    fi
    checkout "$HOME/fleet-server" "$runner"
    printf '%s\n' "$code" | "$runner" "$prefix/bin/python3" "$HOME/fleet-server/server.py" join --hub "$HUB" --kind mac
    current "$HOME/fleet-server" "$runner"
    # No OS user for each agent on a Mac, and no root helper: a Mac agent's service is a LaunchAgent of a desktop
    # session, so a second user would have to be logged in at the screen. A Mac keeps one user for its agents
    # (PRODUCT.md P2), and its agents share that user's runtime credential.
    mac_vault
    if [ "$runner" = as_mac_user ]; then
        say "the installer goes on from here, and it runs the checks itself"    # a minute saved for the owner
        return 0
    fi
    verify_step "$HOME/fleet-server" "$runner"
    say "done. Add an agent to this Mac in Founderizer: Settings, Servers, this Mac, Add agent. Its agents run while this user is logged in."
}

main() {
    [ -n "${FLEET_JOIN:-}" ] || stop "No join code. Copy the whole line from Founderizer: Settings, Servers, Add server."
    code=$FLEET_JOIN
    unset FLEET_JOIN
    REBOOT_TIME=${FLEET_REBOOT_TIME:-}
    case "$(uname -s)" in
        Linux) linux ;;
        Darwin) mac ;;
        *) stop "This system is not supported. Use Ubuntu 22.04, 24.04 or 26.04, Debian 12 or 13, or macOS 14 or \
later." ;;
    esac
    [ "$ready" = yes ] || exit 1
}

# The whole script is read before main runs: a command that reads standard input cannot take the rest of the script.
main
