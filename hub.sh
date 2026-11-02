#!/bin/sh
# Founderizer hub installer. One line turns a fresh server into a working Founderizer hub: the one the Mac app and the iPhone app
# connect to, and the one every worker and joined server then fetches its code from.
#
#   A VPS (Ubuntu 22.04 or 24.04, or Debian 12), as root, from a copy of the Founderizer repository on that server:
#
#       sh hub.sh                           the install
#       sh hub.sh --source <git url>        clone the Founderizer repository first, then install from that clone
#       sh hub.sh --check                   say what it would do, change nothing
#
# Its steps: base packages, the user fleet with lingering, the private network (Tailscale), the firewall, the bare
# repository and the hub's checkout on the configuration ref, the first team.json with the owner's own Mac proved by
# a one-time code, the root helper that makes an agent's OS user, one OS user for each agent of this machine,
# the fleet-hub and fleet-git user services, each agent of this machine under its own OS user (its checkout,
# its runtime and its service), the end checks, this fleet's own id, security updates, and verify.
#
# Each agent's session runs as its own user, `fleet-<agent>`, so its checkout, its runtime, that runtime's
# credential and its vault token are in a home of mode 700 that no other agent of this machine can open
# (PRODUCT.md 4.1).
#
# The last step is `python3 fleet.py verify` (PRODUCT.md 4.1), whose lines this installer prints: an install that
# half worked says which check failed and how to fix it, instead of looking finished. The line ends with a failure
# when a check failed, so the agent or the app that ran it knows.
#
# The Tailscale auth key comes on standard input, never in an argument or a URL: it goes to a file that only root can
# read, and `tailscale up --auth-key=file:<path>` reads it from there. The claim code is made on this machine and
# never leaves it as text; the owner's Mac sends it back, and the address of that call becomes addresses.owner.
#
# It is safe to run again: every step checks first, nothing is destroyed, and a second run on a working hub changes
# nothing. A step that failed can be repeated by running the line again.
#
# IT TOUCHES NO MODEL PROVIDER CREDENTIAL. It installs the runtime and signs in to nothing: it never signs in to a
# provider, never writes, copies or refreshes a provider token, and makes no vault entry. It never touches that login.
# The owner signs in to their own account afterwards, from the app (UI-API.md, "Sign a machine in"): the app gives
# them the provider's own link, they authenticate in their own browser, and the code they get back is typed into the
# sign-in running on this server, which is where the provider's client writes the credential. That is the condition on
# which Anthropic permits an operator to host the unmodified binary, and it is what makes this install lawful to sell.
set -eu

HUB_USER=fleet
HUB_PORT=8765
PACKAGES="git tmux python3 curl ca-certificates ufw unattended-upgrades sudo"
# The Founderizer files this installer needs in the copy it runs from. The rules, the manager's parts of them and its
# profile are in the list because the manager reads them at every start: a hub without them runs but has no manager
# worth the name.
NEEDED="hub.py fleet.py hubsetup.py selftest.py config-ref.sh team.json RULES.md rules/lead.md rules/manager.md profiles/manager.md"

check=no
source=""
port=$HUB_PORT
timezone=""
runtime=claude
claim_wait=1800
reclaim=no
hostname=""             # its name in Tailscale, which is its name in Fleet: the name its provider gave it
root=""                 # --check only: a folder that stands in for / so the plan can be read on any machine
step=0
ready=yes               # what the last step, verify, answered about this machine

say() { printf 'Founderizer: %s\n' "$*"; }
stop() { printf 'Founderizer install stopped: %s\n' "$*" >&2; exit 1; }
heading() { step=$((step + 1)); printf '\nFounderizer step %d: %s\n' "$step" "$*"; }
act() {                 # one changing command: in check mode it is only named
    if [ "$check" = yes ]; then
        printf 'Founderizer:   would run: %s\n' "$*"
    else
        "$@"
    fi
}
plan() { [ "$check" = yes ] && printf 'Founderizer:   would %s\n' "$*" || true; }

usage() {
    printf '%s\n' "Usage: sh hub.sh [--check] [--source <git url or path>] [--port N] [--timezone Z]" \
        "              [--runtime claude|codex] [--hostname NAME] [--claim-wait SECONDS] [--reclaim]"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --check) check=yes; shift ;;
        --source) source=${2:?--source needs a git url or a path}; shift 2 ;;
        --port) port=${2:?--port needs a number}; shift 2 ;;
        --timezone) timezone=${2:?--timezone needs a time zone}; shift 2 ;;
        --runtime) runtime=${2:?--runtime needs claude or codex}; shift 2 ;;
        --hostname) hostname=${2:?--hostname needs a name}; shift 2 ;;
        --claim-wait) claim_wait=${2:?--claim-wait needs seconds}; shift 2 ;;
        --reclaim) reclaim=yes; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; stop "unknown option $1" ;;
    esac
done
case "$port" in ''|*[!0-9]*) stop "--port must be a number" ;; esac
case "$claim_wait" in ''|*[!0-9]*) stop "--claim-wait must be seconds" ;; esac
case "$runtime" in claude|codex) ;; *) stop "--runtime must be claude or codex" ;; esac
if [ "$check" = yes ]; then
    root=${FLEET_CHECK_ROOT:-}
    say "check only: nothing on this machine changes."
fi

home="$root/home/$HUB_USER"
bare="$home/fleet-pilot.git"
kit="$home/fleet-pilot"
tree=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

as_user() {     # the command as the user of the services, from its home folder, with its user services reachable
    if [ "$check" = yes ]; then
        printf 'Founderizer:   would run as %s: %s\n' "$HUB_USER" "$*"
        return 0
    fi
    # shellcheck disable=SC2016
    runuser -u "$HUB_USER" -- env HOME="$home" XDG_RUNTIME_DIR="/run/user/$(id -u "$HUB_USER")" \
        PATH="$home/.local/bin:/usr/local/bin:/usr/bin:/bin" sh -c 'cd "$HOME" && exec "$@"' sh "$@"
}

take() {        # $1: a checkout; the rest: how to run a command as its user. The checkout's own ref, fetched, and taken
                # only where `lifecycle.py may-take` lets it (DevOps plan 0.1): the data that the hub writes, or a
                # release that a release key signed. A refusal leaves the checkout where it is, and says why.
    taking=$1
    shift
    "$@" git -C "$taking" fetch -q origin </dev/null || return 1
    # the ref read once, as one commit: the commit checked is the commit taken
    target=$("$@" git -C "$taking" rev-parse --verify -q "@{upstream}^{commit}" </dev/null) || return 1
    "$@" python3 "$taking/lifecycle.py" may-take "$taking" "$target" </dev/null || return 1
    "$@" git -C "$taking" merge -q --ff-only "$target" </dev/null
}

as_agent() {    # $1: an agent's own OS user; the rest: the command, as that user, from that user's own home
    agent_as=$1
    shift
    if [ "$check" = yes ]; then
        printf 'Founderizer:   would run as %s: %s\n' "$agent_as" "$*"
        return 0
    fi
    # shellcheck disable=SC2016
    runuser -u "$agent_as" -- env HOME="/home/$agent_as" XDG_RUNTIME_DIR="/run/user/$(id -u "$agent_as")" \
        PATH="/home/$agent_as/.local/bin:/usr/local/bin:/usr/bin:/bin" sh -c 'cd "$HOME" && exec "$@"' sh "$@"
}

# ---------------------------------------------------------------- the steps

preflight() {
    heading "this server and this copy of Founderizer"
    if [ "$(id -u)" != 0 ]; then
        [ "$check" = yes ] || stop "Run the line as root (for example after sudo -i)."
        say "  this run is not root; the install itself needs root"
    fi
    if [ -r "$root/etc/os-release" ]; then
        # shellcheck disable=SC1090,SC1091
        . "$root/etc/os-release"
        case "${ID:-} ${VERSION_ID:-}" in
            "ubuntu 22.04"|"ubuntu 24.04"|"debian 12") say "  ${PRETTY_NAME:-$ID $VERSION_ID}" ;;
            *) [ "$check" = yes ] || stop "This system is ${ID:-unknown} ${VERSION_ID:-}. Use Ubuntu 22.04 or 24.04, \
or Debian 12."
               say "  this system is ${ID:-unknown} ${VERSION_ID:-}; the install needs Ubuntu 22.04 or 24.04, or Debian 12" ;;
        esac
    else
        [ "$check" = yes ] || stop "This system has no /etc/os-release. Use Ubuntu 22.04 or 24.04, or Debian 12."
        say "  no $root/etc/os-release here; the install needs Ubuntu 22.04 or 24.04, or Debian 12"
    fi
    if ! command -v systemctl >/dev/null 2>&1; then
        [ "$check" = yes ] || stop "systemd is required: the hub runs as a systemd user service."
        say "  no systemd here; the hub runs as a systemd user service"
    fi
    # The clone and the check of the copy's commit both need git, which a minimal server does not carry: without
    # it a copy of the repository was refused as "not a git checkout" (the installer test of 22 October 2026).
    if ! command -v git >/dev/null 2>&1; then
        if [ "$check" = yes ]; then
            plan "install git, which the clone and the check of this copy's commit need"
        else
            say "  installing git"
            export DEBIAN_FRONTEND=noninteractive
            apt-get -o DPkg::Lock::Timeout=300 update -q </dev/null >/dev/null
            apt-get -o DPkg::Lock::Timeout=300 install -y -q --no-install-recommends git </dev/null >/dev/null
        fi
    fi
    if [ -n "$source" ]; then
        plan "clone the Founderizer repository from $source, then install from that clone"
        if [ "$check" = yes ]; then
            # The clone is not made in check mode, so there is no copy yet to measure.
            plan "check that the clone carries $NEEDED, and a commit"
            return 0
        fi
        fresh="/root/fleet-kit"
        if git -C "$fresh" rev-parse --git-dir >/dev/null 2>&1; then
            say "  the Founderizer repository is in $fresh already"
        else
            [ ! -e "$fresh" ] || stop "$fresh is there and is not a Founderizer checkout. Move it away, or run the \
line from a copy of the repository without --source."
            say "  cloning the Founderizer repository into $fresh"
            git clone -q -- "$source" "$fresh" || stop "Could not clone the Founderizer repository from $source."
        fi
        tree=$fresh
    fi
    missing=""
    for f in $NEEDED; do [ -f "$tree/$f" ] || missing="$missing $f"; done
    [ -z "$missing" ] || stop "$tree is not a copy of the Founderizer repository: it has no$missing. Copy the repository to \
this server, or pass --source with its address."
    if [ "$check" = yes ] && ! command -v git >/dev/null 2>&1; then
        plan "check that $tree is a git checkout with a commit, once git is installed"
    else
        git -C "$tree" rev-parse HEAD >/dev/null 2>&1 || stop "$tree is not a git checkout with a commit. The hub's own \
repository is made from this one, so it must carry its history: copy a git checkout, or pass --source with its address."
    fi
    say "  Founderizer is in $tree"
}

packages() {
    heading "base packages"
    missing=""
    for p in $PACKAGES; do
        dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || missing="$missing $p"
    done
    if [ -z "$missing" ]; then
        say "  every package is installed"
        return 0
    fi
    if [ "$check" = yes ]; then
        plan "apt-get update, then apt-get install$missing"
        return 0
    fi
    say "  installing$missing"
    export DEBIAN_FRONTEND=noninteractive
    apt-get -o DPkg::Lock::Timeout=300 update -q </dev/null >/dev/null
    # shellcheck disable=SC2086
    apt-get -o DPkg::Lock::Timeout=300 install -y -q --no-install-recommends $missing </dev/null >/dev/null
}

hub_user() {
    heading "the user $HUB_USER: locked password, no sudo, its services run after logout"
    if id -u "$HUB_USER" >/dev/null 2>&1; then
        say "  the user $HUB_USER is there"
    else
        act useradd --create-home --shell /bin/bash --user-group "$HUB_USER"
    fi
    if [ "$check" = yes ]; then act passwd -l "$HUB_USER"; else passwd -l "$HUB_USER" >/dev/null; fi
    act chmod 700 "/home/$HUB_USER"
    for g in sudo admin wheel; do
        [ "$check" = yes ] || gpasswd -d "$HUB_USER" "$g" >/dev/null 2>&1 || true
    done
    plan "take $HUB_USER out of the groups sudo, admin and wheel"
    act loginctl enable-linger "$HUB_USER"
    [ "$check" = yes ] && return 0
    uid=$(id -u "$HUB_USER")
    i=0
    while [ ! -d "/run/user/$uid" ] && [ "$i" -lt 30 ]; do sleep 1; i=$((i + 1)); done
    [ -d "/run/user/$uid" ] || stop "the user services of $HUB_USER are not reachable (/run/user/$uid). Check \
lingering: loginctl show-user $HUB_USER -p Linger"
}

network() {
    heading "the private network (Tailscale)"
    if [ "$check" = yes ]; then
        command -v tailscale >/dev/null 2>&1 || plan "install Tailscale from https://tailscale.com/install.sh"
        plan "read the Tailscale auth key on standard input into a file that only root can read, then run: \
tailscale up --auth-key=file:<that file>${hostname:+ --hostname=$hostname} --accept-dns=false"
        plan "take this machine's address from: tailscale ip -4"
        address="100.64.0.1"
        say "  check only: the plan below uses $address as this machine's address"
        return 0
    fi
    if ! command -v tailscale >/dev/null 2>&1; then
        say "  installing Tailscale"
        curl -fsSL https://tailscale.com/install.sh | sh >/dev/null || stop "Could not install Tailscale."
    fi
    if tailscale status >/dev/null 2>&1; then
        say "  this machine is on the private network already"
    else
        printf 'Founderizer: paste this fleet'\''s Tailscale auth key and press Enter (it is not shown): '
        keydir=$(mktemp -d /root/.fleet-hub-install.XXXXXX) || stop "Could not make a folder for the auth key."
        chmod 700 "$keydir"
        trap 'rm -rf "$keydir"' EXIT INT TERM
        stty -echo 2>/dev/null || true
        IFS= read -r key || { stty echo 2>/dev/null || true; stop "No Tailscale auth key came in. Run the line in a \
terminal on this server and paste the key."; }
        stty echo 2>/dev/null || true
        printf '\n'
        [ -n "$key" ] || stop "No Tailscale auth key came in."
        ( umask 077; printf '%s\n' "$key" > "$keydir/authkey" )
        key=""
        unset key
        tailscale up --auth-key="file:$keydir/authkey" ${hostname:+--hostname="$hostname"} --accept-dns=false \
            || { rm -rf "$keydir"; stop "Tailscale did not join with that auth key. Make a new key in the fleet's \
Tailscale admin console, then run the line again."; }
        rm -rf "$keydir"
        trap - EXIT INT TERM
        say "  this machine joined the private network${hostname:+ as $hostname}"
    fi
    address=$(tailscale ip -4 2>/dev/null | head -n 1)
    case "$address" in
        100.*) say "  this hub's address is $address" ;;
        *) stop "Tailscale gave no address for this machine. Check: tailscale status" ;;
    esac
}

firewall() {    # before the claim: the owner's Mac must reach port $port while the install runs. SSH too comes in over
                # the private network only, which this machine joined in the step before (hubsetup.py firewall).
    heading "the firewall: the private network only"
    if [ "$check" = yes ]; then
        plan "let everything on tailscale0 in, deny other incoming traffic, remove the public SSH rule of an earlier \
Founderizer, and turn the firewall on: SSH then reaches this server over the private network only"
        return 0
    fi
    python3 "$tree/hubsetup.py" firewall \
        || stop "the firewall of this server could not be set: the line above says why. Run the line again."
}

repository() {
    heading "the Founderizer repository on this hub: the bare repository and the hub's checkout"
    if [ "$check" = yes ]; then
        plan "make the bare repository $bare from $tree, with main and config at its commit: it is the origin that \
every worker and joined server of this fleet fetches from"
        plan "clone it to $kit, the hub's checkout, on the configuration ref config"
        plan "give both to $HUB_USER"
        return 0
    fi
    python3 "$tree/hubsetup.py" repository --tree "$tree" --bare "$bare" --kit "$kit" \
        || stop "the hub's own repository could not be made."
    chown -R "$HUB_USER:$HUB_USER" "$bare" "$kit"
}

first_team() {
    heading "the first team.json, and the owner's own Mac"
    if [ "$check" = yes ]; then
        plan "write $kit/team.json: the hub machine at $address, one manager agent on it with runtime $runtime and \
\"vault\": \"none\", and no credential of any kind"
        plan "make a one-time claim code, print the line for the owner's Mac, and serve it on $address:$port until \
that Mac sends the code back; its address becomes addresses.owner"
        plan "commit team.json on config and push it to $bare"
        return 0
    fi
    ports=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' | sort -u)     # the SSH port team.json records
    [ -n "$ports" ] || ports=22
    zone=""
    [ -z "$timezone" ] || zone="--timezone $timezone"
    more=""
    [ "$reclaim" = no ] || more="--reclaim"
    # shellcheck disable=SC2086
    as_user python3 "$kit/hubsetup.py" claim --address "$address" --port "$port" --out "$kit/team.json" \
        --runtime "$runtime" --ssh-user "$HUB_USER" --ssh-port "$(printf '%s' "$ports" | head -n 1)" \
        --wait "$claim_wait" --commit $zone $more \
        || stop "the owner claim did not finish, so team.json was not written."
}

services() {
    heading "the services fleet-hub, fleet-git and fleet-channels"
    if [ "$check" = yes ]; then
        plan "run: python3 $kit/fleet.py service hub and git"
        plan "run: python3 $kit/fleet.py service channels, the chat apps bridge"
        plan "run: systemctl --user enable --now fleet-hub fleet-git fleet-channels, as $HUB_USER"
        plan "leave each agent to its own user, in the next step: no agent's session runs as $HUB_USER"
        return 0
    fi
    for name in hub git channels; do
        as_user python3 "$kit/fleet.py" service "$name" >/dev/null \
            || stop "Could not write the fleet-$name service. Run it by hand to see why: \
runuser -u $HUB_USER -- python3 $kit/fleet.py service $name"
        as_user systemctl --user enable "fleet-$name.service" >/dev/null 2>&1 || true
        as_user systemctl --user restart "fleet-$name.service" \
            || stop "fleet-$name did not start. Look at: runuser -u $HUB_USER -- systemctl --user status fleet-$name"
    done
    i=0
    while [ "$i" -lt 20 ]; do
        as_user systemctl --user is-active -q fleet-hub && break
        sleep 1
        i=$((i + 1))
    done
    as_user systemctl --user is-active -q fleet-hub || stop "fleet-hub is not running. Look at: \
runuser -u $HUB_USER -- systemctl --user status fleet-hub"
    say "  fleet-hub, fleet-git and fleet-channels are enabled and running"
}

agents() {      # each agent of this machine under its own OS user: its checkout, its runtime and its service, so
                # that its runtime credential and its vault token are in a home no other agent can open
    heading "each agent of this machine, under its own OS user"
    if [ "$check" = yes ]; then
        plan "read this machine's agents: python3 $kit/hubsetup.py agent-list --team $kit/team.json"
        plan "for each agent, as its own user fleet-<agent>: clone git://$address/fleet-pilot.git on the \
configuration ref into /home/fleet-<agent>/fleet-<agent>, install its runtime into that user's own ~/.local/bin, \
write its service with fleet.py service <agent>, and enable and start it in that user's own systemd manager"
        plan "sign in to nothing: the owner signs each agent in from the app, and only they can"
        return 0
    fi
    list=$(mktemp) || stop "Could not make a temporary file."
    # shellcheck disable=SC2064
    trap "rm -f $list" EXIT INT TERM
    python3 "$kit/hubsetup.py" agent-list --team "$kit/team.json" > "$list" \
        || stop "The agents of this machine could not be read from $kit/team.json."
    while read -r agent agent_runtime user; do
        [ -n "$agent" ] || continue
        say "  $agent, as the user $user"
        uid=$(id -u "$user") || stop "The OS user $user of $agent is not there. Run the line again."
        i=0
        while [ ! -d "/run/user/$uid" ] && [ "$i" -lt 30 ]; do sleep 1; i=$((i + 1)); done
        [ -d "/run/user/$uid" ] || stop "The user services of $user are not reachable (/run/user/$uid). Check \
lingering: loginctl show-user $user -p Linger"
        folder="/home/$user/fleet-$agent"
        if [ -d "$folder/.git" ]; then
            take "$folder" as_agent "$user" || say "  $folder could not update; it stays as it is"
        else
            as_agent "$user" git clone -q -b config "git://$address/fleet-pilot.git" "$folder" </dev/null \
                || stop "The checkout of $agent could not be cloned from git://$address/fleet-pilot.git. Check that \
fleet-git runs: runuser -u $HUB_USER -- systemctl --user status fleet-git"
        fi
        as_agent "$user" python3 "$folder/hubsetup.py" runtime --runtime "$agent_runtime" </dev/null \
            || stop "$agent_runtime did not install for $agent. Install it as $user, then run the line again."
        as_agent "$user" python3 "$folder/fleet.py" service "$agent" >/dev/null </dev/null \
            || stop "Could not write the fleet-$agent service. Run it by hand to see why: \
runuser -u $user -- python3 $folder/fleet.py service $agent"
        as_agent "$user" systemctl --user enable "fleet-$agent.service" >/dev/null 2>&1 || true
        as_agent "$user" systemctl --user restart "fleet-$agent.service" \
            || stop "fleet-$agent did not start. Look at: runuser -u $user -- systemctl --user status fleet-$agent"
    done < "$list"
    rm -f "$list"
    trap - EXIT INT TERM
    say "  every agent of this machine runs as its own user, and none of them as $HUB_USER"
}

checks() {
    heading "the checks the owner can act on"
    if [ "$check" = yes ]; then
        plan "run: python3 $kit/hubsetup.py check --address $address --port $port (selftest.py and GET /health)"
        plan "print the hub's address as the line to paste in Founderizer"
        return 0
    fi
    as_user python3 "$kit/hubsetup.py" check --address "$address" --port "$port" --kit "$kit" \
        || stop "the hub is installed but it does not answer. Look at: \
runuser -u $HUB_USER -- systemctl --user status fleet-hub"
    # The hub works from here: the owner can paste the address while the last step installs the security updates.
    say "  the hub is yours at http://$address:$port — the next step only hardens this server"
}

updates() {     # unattended security updates on, then the pending ones once; never a restart of the server
    heading "security updates"
    if [ "$check" = yes ]; then
        plan "turn unattended security updates on and install the pending ones once, without restarting the server"
        return 0
    fi
    printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' \
        > /etc/apt/apt.conf.d/20auto-upgrades
    systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
    eval "$(apt-config shell AUTO_REBOOT Unattended-Upgrade::Automatic-Reboot/b)"
    if [ "${AUTO_REBOOT:-false}" = true ]; then
        say "  security updates are on; this server restarts by itself after updates, so they install in its daily run"
        return 0
    fi
    say "  security updates are on; installing the pending ones (this can take some minutes)"
    apt-get -o DPkg::Lock::Timeout=600 -q install </dev/null >/dev/null 2>&1 || true
    unattended-upgrade </dev/null >/dev/null 2>&1 || say "  some security updates did not install now; the daily run \
tries again"
    [ ! -f /var/run/reboot-required ] || say "  this server needs a restart for its updates; restart it when it has \
no work"
}

agent_helper() { # the two root commands of this machine, and the sudoers file that says who may run them
    heading "the root helpers that make an agent's OS user and update this machine's vault broker"
    if [ "$check" = yes ]; then
        plan "run: python3 $kit/hubsetup.py agent-helper --user $HUB_USER --repo git://$address/fleet-pilot.git"
        plan "write /usr/local/sbin/fleet-agent-user, the one root command that makes the OS user of one agent, \
/usr/local/sbin/fleet-vault-program, which takes no argument and brings this machine's vault broker onto the \
vault.py of the fleet's configuration ref, and /etc/sudoers.d/fleet-agents, which lets $HUB_USER run those two \
commands and become the group fleet-agents and nothing else; the sudoers file is read by visudo -c before it is \
moved in"
        plan "let an agent the owner adds later from the app, which the server service installs without root, get a \
user of its own, so that fleet.py verify can read each agent (PRODUCT.md 4.1), and let a release that changed \
vault.py reach a vault broker on this machine, which no checkout holds"
        return 0
    fi
    python3 "$kit/hubsetup.py" agent-helper --user "$HUB_USER" --repo "git://$address/fleet-pilot.git" \
        || stop "the root helpers of this machine's agent users and its vault broker could not be put in place."
}

agent_users() {  # one OS user for each agent of this machine, so that no agent's home is readable by another's user
    heading "one OS user for each agent of this machine"
    if [ "$check" = yes ]; then
        plan "run: python3 $kit/hubsetup.py agent-users --team $kit/team.json"
        plan "make the user fleet-<agent> for each agent team.json gives this machine: a locked password, no sudo, \
lingering on, the group fleet-agents, and the home /home/fleet-<agent> of mode 700 that belongs to it alone"
        plan "run each agent's session as that user, which the next steps install (PRODUCT.md 4.1)"
        return 0
    fi
    python3 "$kit/hubsetup.py" agent-users --team "$kit/team.json" \
        || stop "the OS users of this machine's agents could not be made."
}

fleet_identity() {  # this fleet's own id, after the hub has answered, so its records are there to keep it in
    heading "this fleet's own id"
    if [ "$check" = yes ]; then
        plan "run: python3 $kit/hubsetup.py fleet-id"
        plan "make this fleet's id, sixteen hex characters, once and never again, and keep it in the hub's key \
store: it says nothing about its owner (PRODUCT.md 4.2)"
        plan "claim no entitlement with it: a claim key works once, so the app is the one caller of the claim \
(PRODUCT.md 4.5)"
        return 0
    fi
    as_user python3 "$kit/hubsetup.py" fleet-id || stop "this fleet's own id could not be made."
}

verify_step() {  # the last step: the one health check of the whole product (PRODUCT.md 4.1), in its readable form
    heading "verify: is this machine of the fleet healthy?"
    if [ "$check" = yes ]; then
        plan "run: python3 $kit/fleet.py verify, and print the line of every check it answers"
        plan "end with a failure when a check failed, so the agent or the app that ran this line knows"
        return 0
    fi
    say "  reading this machine's own checks; selftest.py takes about a minute"
    if as_user python3 "$kit/fleet.py" verify; then
        say "  this machine of the fleet is healthy"
    else
        ready=no
        say "  this hub is NOT ready: the lines above name each check that failed and the fix it carries"
    fi
}

done_text() {
    printf '\n'
    if [ "$check" = yes ]; then
        say "then the hub would be installed, and its address would be the line to paste in Founderizer:"
    elif [ "$ready" = no ]; then
        say "the hub is installed, and verify says it is not healthy yet. Its address, to paste in Founderizer:"
    else
        say "the hub is installed and verify says READY. Paste this address in Founderizer:"
    fi
    printf '\n    http://%s:%s\n\n' "$address" "$port"
    say "what is left, and only you can do it, all of it in Founderizer:"
    printf '%s\n' \
        "  1. Sign in to your own $runtime account: Settings, Servers, this server, Sign in." \
        "     The app gives you a link, you authenticate in your own browser, and you paste the code it gives you" \
        "     back into the app. The sign-in happens on this server, and nothing of it is stored by Founderizer." \
        "     Nobody can do this for you, and the same button signs you in again when the login expires." \
        "  2. Add your agents: the + at the top of the sidebar, Add agent. Each one is signed in the same way," \
        "     on its own server." \
        ""
}

main() {
    preflight
    packages
    hub_user
    network
    firewall
    repository
    first_team
    agent_helper
    agent_users
    services
    agents
    checks
    fleet_identity
    updates
    verify_step
    done_text
    [ "$check" = no ] || say "check only: nothing on this machine changed."
    [ "$ready" = yes ] || exit 1
}

# The whole script is read before main runs: the command that reads the auth key on standard input cannot take the
# rest of the script.
main
