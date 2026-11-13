#!/usr/bin/env python3
"""The Python half of the Founderizer hub installer (hub.sh): the first team.json, the owner claim and the end checks.
Standard library only, and it reads no credential of a model provider.

    python3 hubsetup.py template --address IP [--port N] [--timezone Z] [--owner IP]
                                                    print the first team.json; write nothing
    python3 hubsetup.py repository --tree PATH --bare PATH --kit PATH
                                                    this hub's own repository: the bare one that every machine of the
                                                    fleet fetches from, and the hub's checkout on the configuration ref
    python3 hubsetup.py claim --address IP --out PATH [--port N] [--timezone Z] [--wait S] [--reclaim] [--commit]
                              [--manager-later]
                                                    the owner claim, then write team.json, and commit it on the ref;
                                                    --manager-later: the app gives the manager a server of its own;
                                                    --reclaim: a new owner for a hub that has one; a hub that runs
                                                    is stopped for the time of the claim and started again
    python3 hubsetup.py runtime --runtime claude|codex
                                                    install the runtime of an agent of this machine, so that the owner
                                                    can sign in to their own account from the app (it signs in to
                                                    nothing itself); a hub whose manager gets a server of its own
                                                    has no agent, so hub.sh runs it for none there
    python3 hubsetup.py agent-users --team PATH --machine NAME [--check]
                                                    one OS user for each agent of this machine, so that no agent's
                                                    user can read another agent's home
    python3 hubsetup.py agent-helper [--user NAME] [--repo URL] [--check]
                                                    the two root commands this machine's service user may run, and
                                                    the one sudoers file that says so
    python3 hubsetup.py vault --hub URL [--kit PATH] [--check]
                                                    this machine's vault broker: its own user keeps the store's key
                                                    and the handover key, so no agent of the machine can read either
    python3 hubsetup.py firewall [--check]          as root: incoming traffic over the private network only, SSH
                                                    included, and no public SSH rule of an earlier installer
    python3 hubsetup.py harden [--user NAME] [--check]
                                                    as root: SSH takes keys only with no X11 forwarding, npm takes no
                                                    package version newer than seven days, Tailscale updates itself
    python3 hubsetup.py check --address IP [--port N] [--kit PATH] [--no-selftest]
                                                    the end checks on this machine: selftest.py and GET /health;
                                                    --no-selftest for a caller that runs verify next
    python3 hubsetup.py fleet-id [--db PATH]        this fleet's own id in the hub's key store, made once
    python3 hubsetup.py kit-clone [--hub-user fleet] [--source URL]
                                                    as root on the hub's machine: root's own clone of the published
                                                    repository at /usr/local/lib/founderizer-kit, at the revision of
                                                    the hub's signed release.json and never older; safe to run again
    python3 /usr/local/lib/founderizer-kit/hubsetup.py central-vault --owner-key KEY [--hub-user fleet] [--fleet ID]
                                                    as root on the hub's machine, from that clone only: the central
                                                    vault, its own user and service, which the hub's user can ask and
                                                    neither read nor replace; kit-clone and a second run of it are how
                                                    it is updated
    python3 /usr/local/lib/founderizer-kit/hubsetup.py connect on|off [--hub-user fleet]
                                                    as root on the hub's Linux machine, from that clone only: the gate
                                                    of the remote MCP address, its own user and service, and Tailscale
                                                    Funnel on port 443 to it; off undoes the Funnel and the service

Why the claim exists. The owner is a Tailscale address and no token (hub.py `allowed("owner")`), so a hub with the
wrong `addresses.owner` serves the owner's pages to the wrong machine, and one with none serves them to nobody. The
installer therefore proves the address before it finishes, with the same one-time code that join.sh uses, the other
way round: this machine makes the code, the owner's Mac sends it back, and the address of that call is the owner.

The claim listener holds the hub's own address and port, so the Tailscale access rules for port 8765 are proved
before the hub exists. It keeps only the code's SHA-256, never writes the code anywhere, takes one code once, and
stops as soon as it has the address. The script it serves at GET /claim then waits for the hub itself on the same
port and prints the address to paste in Founderizer, so the final check is made from the owner's own machine.

A second claim (`--reclaim`: the owner's Mac is lost, or it has a new address) finds a hub that runs, and that hub
holds the address and port. So the claim stops the hub's own service for its time and starts it again in every case
(HubPause). The hub reads team.json at that start: from then on it serves the owner's pages to the new address and
refuses the one from before.

This program never signs in to Claude, Codex or Grok, never reads or writes a provider credential, and never makes
a vault entry. The customer signs in to their own account in their own session; `"vault": "none"` in the template
says that the manager holds no credential of ours.
"""
import argparse
import base64
import errno
import fnmatch
import glob
import hashlib
import http.server
import json
import os
import pathlib
import platform
import pwd
import re
import secrets
import shlex
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zoneinfo

import hub
import lifecycle
import onboard
import releases

KIT = os.path.dirname(os.path.abspath(__file__))
CODE_LENGTH = 12                # hub.LINK_ALPHABET: 12 characters, 60 bits, as a join code
CLAIM_TRIES = hub.JOIN_TRIES    # wrong codes from one address; then the claim refuses that address
CLAIM_LIFE = hub.JOIN_LIFE      # seconds the claim waits for the owner's Mac
HUB_SERVICE = "fleet-hub.service"   # the hub, as `fleet.py service hub` installs it: a user service of the hub's user
PORT_TRIES = 20                 # readings of the hub's port, a second apart, after a claim stopped the hub's service
BACK_TRIES = 60                 # readings of GET /health, a second apart, after a claim started that service again
CLAIM_ENDS = ("SIGHUP", "SIGTERM")  # what ends a claim from outside: a terminal that closed, and a kill
# The manager's start policy, as team.json has it on the pilot hub, and a worker's or a lead's for the first one of a
# fleet, where the hub has no other worker to copy from (hub.py `server_agent_entry`). Both are that runtime's own
# entry of the runtime table (lifecycle.RUNTIMES "manager_access" and "first_worker"), so the installer writes the
# same start the hub would. The runtime signs in by itself, in the owner's own session: no argument of either form
# carries a key, and the installer sets none.
STARTS = {name: e["manager_access"]["start"] for name, e in lifecycle.RUNTIMES.items() if e["manager_access"]}
WORKER_STARTS = {name: e["first_worker"] for name, e in lifecycle.RUNTIMES.items() if e["first_worker"]}
FIRST_COMMIT = "The first team.json of this hub: one manager, and the owner's own Mac"
OWNER_COMMIT = "The owner of this hub is another Mac: a second owner claim, made on the hub's own server"
# One OS user for each agent (PRODUCT.md P2), in this one place: both installers call the command that uses it, so
# no second copy of the name can drift from it. The agent's name comes from the hub's own pattern.
AGENT_USER = "fleet-%s"
DB_PATH = os.path.join("~", ".fleet", "pilot.db")   # the hub's own records, where hub.py --db keeps them
USER_LIMIT = 32                                     # the longest user name this system makes (useradd)
AGENT_GROUP = "fleet-agents"                        # every agent user of this machine, and nobody else
VAULT_USER = "fleet-vault"                          # the broker's own user: the only one that reads the store's key
VAULT_LIB = "/usr/local/lib/fleet-vault"            # the broker program, root-owned and outside every checkout
VAULT_CONF_DIR = "/etc/fleet-vault"
VAULT_CONF = VAULT_CONF_DIR + "/vault.json"         # no secret in it, and root with mode 644: see vault_install()
VAULT_STATE = "/var/lib/fleet-vault"                # the store, its key and the handover key: the vault user alone
VAULT_UNIT = "/etc/systemd/system/fleet-vault.service"
VAULT_SOCKET = "/run/fleet-vault/vault.sock"
VAULT_SETTLE = 3                                    # seconds before the service is read: see vault_install()
VAULT_SOURCE = VAULT_LIB + "/source.git"            # root's own bare clone of the ref: see vault_program_script()
# The key swap (VAULT.md): the proxy that puts an API key into a request to the key's own site, as a second service of
# the same program with a user of its own. That user is not in RESERVED_USERS on purpose: a name there changes the
# bytes of the root helper fleet-agent-user, and no agent's user has this name anyway (each one begins with fleet-).
SWAP_USER = "founderizer-swap"
SWAP_SERVICE = "fleet-vault-swap"
SWAP_UNIT = "/etc/systemd/system/fleet-vault-swap.service"
SWAP_STATE = "/var/lib/fleet-vault-swap"
SWAP_PORT = 876                                     # below 1024: no user without the right can listen on it
SWAP_LOW_PORTS = "/proc/sys/net/ipv4/ip_unprivileged_port_start"
ROOT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"   # a root command's own PATH
HELPER = "/usr/local/sbin/fleet-agent-user"         # one of the two root commands the server service may run
VAULT_UPDATE = "/usr/local/sbin/fleet-vault-program"    # the other: the broker's program, and nothing else
SUDOERS = "/etc/sudoers.d/fleet-agents"             # what that service may do, and nothing more
EXPORT_OK = "git-daemon-export-ok"                  # git daemon serves a repository only when this file is in it
# The central vault's own user: no login, no shell, no home. Not a fleet-* name, because the hub's user can put any
# fleet-* user into the agents' group (fleet-agent-user), and this user must be one that it cannot move (DevOps plan V2).
CENTRAL_USER = "founderizer-vault"
CENTRAL_SERVICE = "fleet-vault-central"
CENTRAL_LIB = "/usr/local/lib/fleet-vault-central"  # its program, root-owned 644, outside every checkout
CENTRAL_CONF_DIR = "/etc/fleet-vault-central"
CENTRAL_CONF = CENTRAL_CONF_DIR + "/vault.json"     # root with mode 644, and no secret in it
CENTRAL_STATE = "/var/lib/fleet-vault-central"      # its key, the store's key, the store and the pins: its user alone
CENTRAL_UNIT = "/etc/systemd/system/fleet-vault-central.service"
# DevOps plan 0.3: what the vault program checks a release with, root-owned beside the broker's program and put there
# by the root step of a machine (agent_helper) and never by a release, and the floor of the releases it took.
RELEASE_CHECK = VAULT_LIB + "/releases.py"          # this checkout's releases.py, the one check of a release
RELEASE_KEYS = VAULT_LIB + "/release-key.pub"       # the release keys that this machine pinned
EARLY_KEYS = VAULT_LIB + "/early-key.pub"           # and the early ones: a fleet that takes releases early took one
VAULT_FLOOR = VAULT_LIB + "/release-floor"          # the newest release whose vault.py the broker took
RESERVED_USERS = (VAULT_USER, CENTRAL_USER)         # this machine's own users, which never become an agent's
# The check itself, run by root as python3 -I -S with the root-owned copy first on its path: the revision of a
# release.json that a pinned key of either file signed, and nothing for one that is held or that no such key signed.
VAULT_CHECK = ("import json, sys\n"
               "sys.path.insert(0, sys.argv[1])\n"
               "import releases\n"
               "try:\n"
               "    with open(sys.argv[2], encoding='utf-8') as f:\n"
               "        m = releases.check(json.load(f), releases.read_keys(sys.argv[1])\n"
               "                           + releases.read_keys(sys.argv[1], 'early-key.pub'))\n"
               "except (ValueError, releases.Untrusted) as e:\n"
               "    sys.exit('fleet-vault-program: the release on the configuration ref is refused: ' + str(e))\n"
               "if m['hold']:\n"
               "    sys.exit('fleet-vault-program: release ' + m['version'] + ' is held')\n"
               "print(m['revision'])\n")
FLEET_ID = re.compile(r"[0-9a-f]{16}")              # hub.fleet_id(): sixteen lowercase hex characters
# Root's own clone of the published repository on the hub's machine, at the revision of a signed release (kit_clone).
# The owner's app runs central-vault as root from here and from nowhere else, so it never runs a program that the
# hub's user can change, or a path that the hub names (DevOps plan V2).
ROOT_KIT = "/usr/local/lib/founderizer-kit"
RELEASE_FILE = "release.json"                       # the signed manifest of the release a checkout runs (plan 0.1)
# The gate of the remote MCP address (connected apps, `connect on|off`): its own user, which cannot read the hub's or
# the vault's folders, its root-owned program, the folder of the hub's socket, and its service. Not a fleet-* name,
# for the reason of CENTRAL_USER.
CONNECT_USER = "founderizer-connect"
CONNECT_SERVICE = "founderizer-connect"
CONNECT_LIB = "/usr/local/lib/founderizer-connect"  # gate.py, root-owned 644, outside every checkout
CONNECT_STATE = "/var/lib/founderizer-connect"      # hub.sock: the hub's user, group founderizer-connect, 2750
CONNECT_UNIT = "/etc/systemd/system/founderizer-connect.service"
CONNECT_TARGET = "http://127.0.0.1:8767"            # gate.LISTEN and gate.PORT: the one target that Funnel publishes
CONNECT_HTTPS = 443                                 # the public port of the address
CONNECT_SETTLE = 2                                  # seconds before the gate's service is read after its start
# The names of the hub's own checkout in its user's home, as hub.sh gives them: founderizer on a new hub, fleet-pilot
# on each hub made before that name. hub.sh holds the same two, and test_hub_install holds them equal.
HUB_CHECKOUTS = ("founderizer", "fleet-pilot")
PRIVATE = re.compile(r"100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.(?:[0-9]{1,3})\.(?:[0-9]{1,3})$")


class Stop(Exception):
    """Something the installer must say and then stop for."""


def say(text):
    print("Founderizer: " + text, flush=True)


def address(value, what):
    """An IPv4 address in plain dotted form, as team.json keeps one."""
    parts = str(value).split(".")
    if len(parts) != 4 or not all(re.fullmatch(r"0|[1-9][0-9]{0,2}", p) and int(p) < 256 for p in parts):
        raise Stop(f"{what} must be an IPv4 address, not {value!r}.")
    return str(value)


def machine_timezone():
    """The server's own time zone when it names one that Python knows, else UTC."""
    for path in ("/etc/timezone",):
        try:
            with open(path, encoding="utf-8") as f:
                name = f.read().strip()
        except OSError:
            continue
        try:
            zoneinfo.ZoneInfo(name)
            return name
        except (ValueError, zoneinfo.ZoneInfoNotFoundError, OSError):
            continue
    link = "/etc/localtime"
    if os.path.islink(link):
        name = os.path.realpath(link).split("/zoneinfo/")[-1]
        try:
            zoneinfo.ZoneInfo(name)
            return name
        except (ValueError, zoneinfo.ZoneInfoNotFoundError, OSError):
            pass
    return "UTC"


def template(hub_ip, port=8765, timezone=None, owner=None, runtime="claude", ssh_user="fleet", ssh_port=22,
             placed=True):
    """The first team.json of a new hub: one manager, this machine's address, and the owner's Mac when the claim has
    proved it. Nothing here holds a credential: `"vault": "none"` says that the manager has no vault access, because
    its runtime is the customer's own subscription, signed in by the customer.

    `placed=False` (`claim --manager-later`; hub.sh's FLEET_MANAGER_SERVER=later, which Founderizer 0.1.112 and later
    set): the manager has no server yet (`"placed": false`, hub.unplaced), so no agent runs on the hub's server, and
    its own setup page in the app gives it a server of its own, then its provider and its sign-in. Its `machine` names
    this machine only so that the hub finds an address for it, and `runtime` is the provider that page offers first.
    Without it the manager runs beside the hub, as it always did: an app from before has no page that gives the manager
    a server, and a new hub clones the newest release, which reaches it before the app that /download gives does."""
    if runtime not in STARTS:
        raise Stop(f"the manager runs claude or codex, not {runtime!r}.")
    try:
        zoneinfo.ZoneInfo(timezone or "UTC")
    except (ValueError, zoneinfo.ZoneInfoNotFoundError, OSError):
        raise Stop(f"{timezone!r} is not a time zone that this machine knows.") from None
    addresses = {"hub": address(hub_ip, "the hub's address")}
    if owner is not None:
        addresses["owner"] = address(owner, "the owner's address")
    manager = {"role": "manager", "machine": "hub", "runtime": runtime, "can": ["shell", "web"], "vault": "none",
               "start": STARTS[runtime]}
    if not placed:
        manager["placed"] = False
    return {
        "hub": {"machine": "hub", "port": int(port)},
        "goals": {"sweep_minutes": 15, "review_hour": 9, "timezone": timezone or "UTC"},
        "addresses": addresses,
        "access": {"hub": {"ssh_user": ssh_user, "ssh_port": int(ssh_port)}},
        "agents": {"manager": manager},
    }


def install_runtime(runtime):
    """An agent's runtime, from the vendor's own installer at the version Founderizer pins, into ~/.local/bin. It
    installs the program and nothing else: no sign-in, no key, no token. The owner signs in to their own account
    afterwards, from the app (UI-API.md, "Sign a machine in"), and only they can.

    Grok is refused: xAI's terms do not let a third party run it this way."""
    if runtime == "grok":
        raise Stop("Founderizer installs no Grok: xAI's terms do not let a third party run it this way.")
    if runtime not in STARTS:
        raise Stop(f"the manager runs claude or codex, not {runtime!r}.")
    here = lifecycle.exe(runtime)
    if here:
        say(f"{runtime} is installed on this machine ({here}).")
        return here
    pin, label = onboard.RUNTIME_PINS[runtime], lifecycle.RUNTIMES[runtime]["label"]
    # An installer that could not reach the internet runs again by itself (onboard.NETWORK_RETRIES). Its own words
    # go to this install's log, and the line that stops the install says what failed in plain words (T-35).
    for again in range(onboard.NETWORK_RETRIES + 1):
        say(f"installing {runtime} {pin} from its own installer, into ~/.local/bin"
            + (f" (again: {again} of {onboard.NETWORK_RETRIES})." if again else "."))
        done = subprocess.run(["sh", "-c", 'mkdir -p "$HOME/.local/bin" && ' + onboard.runtime_install(runtime, pin)],
                              capture_output=True, text=True, timeout=900, stdin=subprocess.DEVNULL)
        here = lifecycle.exe(runtime)
        if done.returncode == 0 and here:
            break
        offline = onboard.network_failure(f"{done.stderr}\n{done.stdout}")
        say(f"{runtime} did not install{', a network error' if offline else ''}: "
            f"{(done.stderr or done.stdout or '').strip()[-300:]}")
        if not offline or again == onboard.NETWORK_RETRIES:
            raise Stop(f"{label} did not install: this server could not reach the internet." if offline else
                       f"{label} did not install.")
        time.sleep(onboard.NETWORK_WAIT)
    if runtime == "claude":         # its updates follow the stable channel, as on every other Founderizer machine
        subprocess.run([sys.executable, "-c", onboard.CLAUDE_CHANNEL, here], capture_output=True, text=True, timeout=120)
    say(f"{runtime} is installed ({here}). Nobody is signed in to it: that is the owner's own step, in the app.")
    return here


def agent_user(agent, conf=None):
    """The OS user that belongs to one agent: `fleet-<agent>`, or the user it keeps after a rename (its team.json
    entry's "user", owner feature agent_rename). Its home is where that agent's own runtime credential, vault token
    and session files go, and no other agent's user can open it."""
    if not hub.AGENT_NAME.fullmatch(str(agent or "")):
        raise Stop(f"{agent!r} is no agent name this fleet can give a user of its own.")
    kept = (conf or {}).get("user")
    if isinstance(kept, str) and hub.AGENT_OS_USER.fullmatch(kept):
        return kept
    user = AGENT_USER % agent
    if len(user) > USER_LIMIT:
        raise Stop(f"the agent {agent!r} needs the OS user {user!r}, which is longer than the {USER_LIMIT} characters "
                   f"this system allows. Rename the agent in the app, then run this line again.")
    return user


def agents_of(team, machine):
    """The agents that team.json gives this machine, in the order their users are made. An agent the owner has
    turned off keeps its user: the owner turns it on again from the app, and no install runs in between. A manager
    with no server yet is on no machine (hub.unplaced), so such a hub makes no user, runtime or service for it."""
    return sorted(name for name, conf in ((team or {}).get("agents") or {}).items()
                  if isinstance(conf, dict) and conf.get("machine") == machine and conf.get("placed") is not False)


def user_reading(user):
    """The shell that reads one agent's user, so that a second run of the installer changes nothing."""
    return ("id -u %(u)s >/dev/null 2>&1 && echo exists=yes || echo exists=no\n"
            "passwd -S %(u)s 2>/dev/null | awk '{print \"locked=\"$2}'\n"
            "id -nG %(u)s 2>/dev/null | tr ' ' '\\n' | grep -qxE 'sudo|admin|wheel' && echo sudo=yes || echo sudo=no\n"
            # systemd's own record of lingering is the file; loginctl can only answer for a user it still holds.
            "echo linger=$([ -e /var/lib/systemd/linger/%(u)s ] && echo yes || "
            "loginctl show-user %(u)s -p Linger --value 2>/dev/null || echo unknown)\n"
            "echo mode=$(stat -c %%a /home/%(u)s 2>/dev/null || echo none)\n"
            "echo owner=$(stat -c %%U /home/%(u)s 2>/dev/null || echo none)\n"
            # the group the machine's service user may become, so that it can install and read this agent
            "id -nG %(u)s 2>/dev/null | tr ' ' '\\n' | grep -qx %(g)s && echo group=yes || echo group=no") % {
                "u": user, "g": AGENT_GROUP}


def user_script(user):
    """The shell that makes one agent's user, each line safe to run again: a locked password, no sudo, its services
    kept after logout, and a home of mode 700 that belongs to it. Lingering is the one line that can fail on a
    machine without loginctl, and it is reported instead of stopping the install, because nothing of the agent runs
    as that user until the fleet moves its session there."""
    return (  # DevOps plan 0.3: any user of this machine outside the agents, and the vault's own, stay as they are
            "if id -u %(u)s >/dev/null 2>&1 && ! id -nG %(u)s | tr ' ' '\\n' | grep -qx %(g)s; then"
            " echo \"fleet: %(u)s is an OS user of this machine and no agent's, so it stays as it is\" >&2; exit 3; fi\n"
            "case %(u)s in %(reserved)s) echo \"fleet: %(u)s is a user of this machine's vault, never an agent's\" >&2;"
            " exit 3;; esac\n"
            "id -u %(u)s >/dev/null 2>&1 || useradd --create-home --shell /bin/bash --user-group %(u)s\n"
            "passwd -l %(u)s >/dev/null\n"
            "groupadd -f %(g)s\n"
            "usermod -aG %(g)s %(u)s\n"
            "chown %(u)s:%(u)s /home/%(u)s\n"
            "chmod 700 /home/%(u)s\n"
            "for g in sudo admin wheel; do gpasswd -d %(u)s $g >/dev/null 2>&1 || true; done\n"
            "loginctl enable-linger %(u)s 2>/dev/null || echo \"fleet: no lingering for %(u)s\"") % {
                "u": user, "g": AGENT_GROUP, "reserved": "|".join(RESERVED_USERS)}


def remove_script(user):
    """The shell that takes one agent's user away with its home (owner feature agent_remove), each line safe to run
    again: a user that is not there is gone already, and one outside the agents' group, or one of the vault's, stays
    as it is. Its lingering, its sessions and its processes end first, because userdel refuses a user that still runs a
    process; then the user, its group and its home go."""
    return ('id -u %(u)s >/dev/null 2>&1 || { echo "fleet-agent-user: %(u)s is not there"; exit 0; }\n'
            "if ! id -nG %(u)s | tr ' ' '\\n' | grep -qx %(g)s; then"
            " echo \"fleet: %(u)s is an OS user of this machine and no agent's, so it stays as it is\" >&2; exit 3; fi\n"
            "case %(u)s in %(reserved)s) echo \"fleet: %(u)s is a user of this machine's vault, never an agent's\" >&2;"
            " exit 3;; esac\n"
            "loginctl disable-linger %(u)s 2>/dev/null || true\n"
            "loginctl terminate-user %(u)s 2>/dev/null || true\n"
            "pkill -KILL -u %(u)s 2>/dev/null || true\n"
            "for i in 1 2 3 4 5 6 7 8 9 10; do pgrep -u %(u)s >/dev/null 2>&1 || break; sleep 1; done\n"
            "crontab -r -u %(u)s 2>/dev/null || true\n"
            "userdel -r %(u)s 2>/dev/null || true\n"
            'if id -u %(u)s >/dev/null 2>&1; then echo "fleet-agent-user: %(u)s could not be removed" >&2; exit 4; fi\n'
            "rm -rf -- /home/%(u)s") % {"u": user, "g": AGENT_GROUP, "reserved": "|".join(RESERVED_USERS)}


def _shell(script, timeout=120):
    done = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=timeout,
                          stdin=subprocess.DEVNULL)
    return done.returncode, (done.stdout or "").strip(), (done.stderr or "").strip()


def kv(text):
    """key=value lines as a dict, as the readings of this installer print them."""
    out = {}
    for line in (text or "").splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip()
    return out


def agent_users(team, machine, check=False, run=None):
    """One OS user for each agent of this machine, so that one agent's home is not readable by another's user.

    Today a machine runs every agent as the one user of its services, so each agent can read every other agent's
    runtime credential and vault token (README.md, "the vault token"). This makes the user that each agent's own
    files belong to: `fleet-<agent>`, with a locked password (nobody logs in as it), no sudo, lingering on, and a
    home of mode 700 that belongs to it alone.

    The agent's session runs as this user (PRODUCT.md, "What the move to per-agent users decided"): its checkout,
    its runtime, that runtime's credential and its systemd user service are all in this home. The user is also in
    the group `fleet-agents`, which `agent_helper` lets the machine's service user become, because that service
    installs an agent the owner adds later and `fleet.py verify` reads one. Safe to run again: a user that is as
    required is left exactly as it is.

    Returns the list of (agent, user, "made"|"there"|"would make")."""
    run = run or _shell
    agents = agents_of(team, machine)
    if not agents:
        say(f"team.json gives the machine {machine} no agent yet, so there is no user to make. Each agent gets its "
            f"own when it is added.")
        return []
    done = []
    for agent in agents:
        user = agent_user(agent, team["agents"][agent])
        before = kv(run(user_reading(user))[1])
        if (before.get("exists") == "yes" and before.get("locked") == "L" and before.get("sudo") == "no"
                and before.get("mode") == "700" and before.get("owner") == user
                and before.get("group") == "yes"):
            say(f"{user} is the user of the agent {agent} already: locked password, no sudo, its own home")
            done.append((agent, user, "there"))
            continue
        if check:
            say(f"  would make the user {user} for the agent {agent}: locked password, no sudo, lingering on, and "
                f"the home /home/{user} of mode 700 that belongs to it")
            done.append((agent, user, "would make"))
            continue
        code, out, err = run(user_script(user))
        after = kv(run(user_reading(user))[1])
        if code != 0 or after.get("exists") != "yes":
            raise Stop(f"the user {user} of the agent {agent} could not be made: {(err or out).strip()[-300:]}")
        bad = [f"{what} is {after.get(what)!r}" for what, want in (("locked", "L"), ("sudo", "no"),
                                                                   ("mode", "700"), ("owner", user),
                                                                   ("group", "yes"))
               if after.get(what) != want]
        if bad:
            raise Stop(f"the user {user} of the agent {agent} is not as Founderizer needs it: {', '.join(bad)}")
        say(f"{user} is the user of the agent {agent}: locked password, no sudo, and the home /home/{user} that only "
            f"it can open")
        if after.get("linger") != "yes":
            say(f"  {user} has no lingering on this machine, so its own services would not survive a reboot; "
                f"nothing of {agent} runs as it yet")
        done.append((agent, user, "made"))
    return done


def helper_script():
    """The one root command of this machine: `/usr/local/sbin/fleet-agent-user fleet-<agent>` makes that agent's OS
    user, and `fleet-agent-user --remove=fleet-<agent>` takes it away with its home once the owner deleted the agent
    (owner feature agent_remove), and nothing else. Its only input is that one argument, and it is checked against a
    closed pattern of the agent users this fleet can have, with or without `--remove=`, before any line reads it or
    any line of `user_script` or `remove_script` runs (selftest: a root command checks its argument first)."""
    name = r"(--remove=)?fleet-[a-z][a-z0-9-]{1,%d}" % (USER_LIMIT - len(AGENT_USER % "") - 1)
    return ("#!/bin/sh\n"
            "# Founderizer: make the OS user of one agent, or remove it, and nothing else. hubsetup.py writes this file.\n"
            "#\n"
            "# It is the one root command that this machine's service user may run (%(sudoers)s), because\n"
            "# the server service installs an agent the owner adds in the app, and removes one the owner deletes, and has\n"
            "# no root of its own. The user it makes has a locked password, no sudo, lingering on, the group %(group)s\n"
            "# and a home of mode 700 that belongs to it alone. --remove= takes away only a user of that group, with its\n"
            "# home. Safe to run again: every line reads first.\n"
            "set -eu\n"
            'test "$(id -u)" = 0 || { echo "fleet-agent-user: this command needs root" >&2; exit 1; }\n'
            'test "$#" = 1 || { echo "fleet-agent-user: one argument, which is fleet-<agent> or --remove=fleet-<agent>"'
            ' >&2; exit 2; }\n'
            'printf %%s "$1" | grep -qxE %(name)s || { echo "fleet-agent-user: $1 is no agent user of a fleet" >&2;'
            ' exit 2; }\n'
            "u=${1#--remove=}\n"
            'if [ "$u" != "$1" ]; then\n'
            "%(remove)s\n"
            'echo "fleet-agent-user: $u is removed"\n'
            "exit 0\n"
            "fi\n"
            "%(script)s\n"
            'echo "fleet-agent-user: $u is the OS user of that agent"\n') % {
                "sudoers": SUDOERS, "group": AGENT_GROUP, "name": shlex.quote(name), "script": user_script("$u"),
                "remove": remove_script("$u")}


def vault_program_script(repo, branch=lifecycle.CONFIG_BRANCH):
    """The second root command of this machine: `/usr/local/sbin/fleet-vault-program` brings the vault broker onto
    the `vault.py` of the fleet's configuration ref, and does nothing else. It takes no argument at all.

    **Why it exists.** A release updates every checkout on a machine and never the broker, which runs a root-owned
    copy of `vault.py` outside all of them as a system service, and `lifecycle.OWNER_ONLY` lets a commit that
    changes only that file count as taken. So a release that changed `vault.py` left every broker running the copy
    installed before it while each machine reported `current`, and the owner pasted one root command per machine to
    catch them up -- for ever, and from memory. Measured on 22 October 2026: two releases of one day changed
    `vault.py`, nobody in the fleet had cut either of them, both left every Linux broker behind, both brokers were
    brought level by hand that afternoon, and in between both lacked the `deposit` operation those releases
    shipped. What the hand route pastes is this command's own reason for existing: it installs `vault.py` from an
    agent's checkout, which that agent owns and can write, so automating it this way is narrower than the line it
    replaces and not wider.

    **What the service user gains, exactly.** It can ask root to replace the broker's program with the `vault.py`
    on the fleet's configuration ref and restart the broker. It cannot name the file, the source, the destination,
    the revision or the service, and it passes no bytes: the bytes are fetched here, as root, from the address this
    machine already takes all of its code from, into a bare repository that only root can write. So it removes the
    hop the pasted command had through a checkout a user can write -- that command read `vault.py` out of an
    agent's own checkout. Nothing else of the broker is touched: its user, its store, its store key and its
    handover key are never read here, and the handover key is never remade, because a new one would turn every
    agent's access into `vault_store_mismatch`.

    **What root's own clone proves, and the signature proves the rest** (DevOps plan 0.3). Root's own clone proves
    that nobody below root on this machine wrote those bytes. That they are the bytes the owner meant is the release
    signature: the ref's `release.json` is checked with root-owned copies of the check (`releases.py`, RELEASE_CHECK)
    and of the release keys (RELEASE_KEYS), which the root step of the machine put in place and no release changes,
    its revision must come after the floor of the releases this broker took (VAULT_FLOOR), and `vault.py` is read out
    of that signed revision and never out of the ref's own tree. So whoever can push the configuration ref still
    cannot put a program here: a release whose signature or floor is refused leaves the broker on its program.

    Nothing is fetched into a working tree and nothing of the fetched repository is ever run: the program is read
    out of the fetch with `git cat-file`, so no hook, filter or submodule of it executes as root.

    **A broker that does not come up keeps the program that was serving.** This runs unattended after a release, and
    an installed broker that is not serving means no agent of that machine can use a secret it holds. So the copy
    that was serving goes back, and the hub's own `vault_behind` warning is then the one that says this machine
    needs a person -- which is what that warning is for.

    `repo` is the address of the fleet's configuration ref, as the hub serves it to this machine. Without one the
    command refuses and says to run the join line again, because a source read from anywhere else on this machine
    is a source somebody else can write."""
    return ("#!/bin/sh\n"
            "# Founderizer: bring this machine's vault broker onto the vault.py of the fleet's configuration ref,\n"
            "# and nothing else. hubsetup.py writes this file.\n"
            "#\n"
            "# It is one of the two root commands that this machine's service user may run (%(sudoers)s), and it\n"
            "# takes no argument. A release updates every checkout here and never the broker, which runs the\n"
            "# root-owned copy of vault.py at %(lib)s outside all of them, so without this a release that changed\n"
            "# that file left the broker behind and the owner pasted one root command per machine after every one.\n"
            "#\n"
            "# What the service user gains is exactly this: it can ask root to replace the broker's program with\n"
            "# the vault.py on the configuration ref and restart the broker. It names no file, no source, no\n"
            "# destination and no service, and it passes no bytes: they are fetched here, as root, from the\n"
            "# address this machine already takes all of its code from, into a bare repository only root can\n"
            "# write. Nothing is checked out and nothing fetched is ever run, so no hook of it runs as root. The\n"
            "# broker's user, its store, its store key and its handover key are not read here, and the handover\n"
            "# key is never remade. A broker that does not come up gets back the program that was serving.\n"
            "set -eu\n"
            # Root's own PATH and not the caller's, so that none of the commands below can be chosen by whoever
            # ran this. sudo already resets it on a stock Debian or Ubuntu; this does not depend on that.
            "PATH=%(path)s\n"
            "export PATH\n"
            'test "$(id -u)" = 0 || { echo "fleet-vault-program: this command needs root" >&2; exit 1; }\n'
            'test "$#" = 0 || { echo "fleet-vault-program: this command takes no argument" >&2; exit 2; }\n'
            "# A machine with no broker is not behind: there is nothing here to bring up to date.\n"
            'test -s %(conf)s && test -s %(program)s || { echo "fleet-vault-program: this machine has no vault'
            ' broker"; exit 0; }\n'
            "repo=%(repo)s\n"
            'test -n "$repo" || { echo "fleet-vault-program: this machine has no address for the fleet\'s'
            ' configuration ref. Run the join line again." >&2; exit 3; }\n'
            "umask 077\n"
            'new=$(mktemp); old=$(mktemp); manifest=$(mktemp)\n'
            "trap 'rm -f \"$new\" \"$old\" \"$manifest\"' EXIT\n"
            "test -d %(source)s || git init -q --bare %(source)s\n"
            # Into a ref of its own and not FETCH_HEAD: what a fetch leaves unreachable is what the next
            # housekeeping run throws away, and then every catch-up downloads the whole repository again.
            'git -C %(source)s fetch -q --no-tags "$repo" %(refspec)s\n'
            # DevOps plan 0.3: the release that the ref carries, checked with this machine's own root-owned copy of
            # the check and of the release keys, after the floor of the releases this broker took, and vault.py from
            # that signed revision and from nowhere else.
            "git -C %(source)s cat-file blob %(local)s:release.json > \"$manifest\" 2>/dev/null || {"
            ' echo "fleet-vault-program: the configuration ref carries no signed release, so the broker keeps its'
            ' program" >&2; exit 4; }\n'
            'revision=$(python3 -I -S -c %(check)s %(lib)s "$manifest") || exit 6\n'
            "floor=$(cat %(floor)s 2>/dev/null || true)\n"
            'if [ -n "$floor" ] && ! git -C %(source)s merge-base --is-ancestor "$floor" "$revision" 2>/dev/null\n'
            "then\n"
            '    echo "fleet-vault-program: release $revision does not come after the release this broker took'
            ' ($floor)" >&2\n'
            "    exit 7\n"
            "fi\n"
            'git -C %(source)s cat-file blob "$revision:vault.py" > "$new" 2>/dev/null || :\n'
            'test -s "$new" || { echo "fleet-vault-program: the signed release carries no vault.py" >&2; exit 4; }\n'
            'want=$(sha256sum "$new" | cut -d\' \' -f1)\n'
            "have=$(sha256sum %(program)s | cut -d' ' -f1)\n"
            # The floor moves only to a release whose vault.py the broker runs: a broker that does not come up on
            # the new one gets the old one back, and keeps its floor.
            'if [ "$want" = "$have" ]; then\n'
            "    printf '%%s\\n' \"$revision\" > %(floor)s\n"
            '    echo "fleet-vault-program: the broker already runs this vault.py ($want)"\n'
            "    exit 0\n"
            "fi\n"
            "cp -p %(program)s \"$old\"\n"
            'install -o root -g root -m 644 "$new" %(program)s\n'
            "systemctl reset-failed fleet-vault >/dev/null 2>&1 || true\n"
            "systemctl restart fleet-vault || true\n"
            "sleep %(settle)d\n"
            "active=$(systemctl is-active fleet-vault 2>/dev/null || true)\n"
            "# As the installer reads it: a broker that crashes on its own program is active for an instant and\n"
            "# then gone, so the restarts since the reset are what say whether it stayed up. An older systemd that\n"
            "# does not answer the property says nothing either way.\n"
            "crashes=$(systemctl show -p NRestarts --value fleet-vault 2>/dev/null || true)\n"
            'if [ "$active" = active ] && { [ -z "$crashes" ] || [ "$crashes" = 0 ] ||'
            ' [ "$crashes" = unknown ]; }; then\n'
            "    printf '%%s\\n' \"$revision\" > %(floor)s\n"
            '    echo "fleet-vault-program: the broker runs the vault.py of the configuration ref ($want)"\n'
            "    exit 0\n"
            "fi\n"
            'install -o root -g root -m 644 "$old" %(program)s\n'
            "systemctl reset-failed fleet-vault >/dev/null 2>&1 || true\n"
            "systemctl restart fleet-vault || true\n"
            'echo "fleet-vault-program: the broker did not come up on the new vault.py, so this machine keeps the'
            ' one that was serving. Read: journalctl -u fleet-vault -n 30" >&2\n'
            "exit 5\n") % {
                "sudoers": SUDOERS, "lib": VAULT_LIB, "conf": VAULT_CONF, "program": VAULT_LIB + "/vault.py",
                "source": VAULT_SOURCE, "repo": shlex.quote(repo or ""), "path": ROOT_PATH,
                "refspec": shlex.quote(f"+{branch}:refs/heads/{branch}"),
                "local": shlex.quote(f"refs/heads/{branch}"), "settle": VAULT_SETTLE,
                "check": shlex.quote(VAULT_CHECK), "floor": VAULT_FLOOR}


def sudoers_text(service_user):
    """What this machine's service user may do with root, and nothing else: the two helpers above as root, and any
    command as a member of `fleet-agents`, which holds the agent users alone. The service installs each agent under
    its own user with the last right, and `fleet.py verify` reads one with it (PRODUCT.md 4.1). That user is no
    agent and runs no AI session on a joined server, so this is not a way from one agent to another.

    **Both root rights are one mechanical act with no input.** `fleet-agent-user` makes the OS user of one agent,
    and its only argument is checked against the agent users a fleet can have before a line of it runs.
    `fleet-vault-program` takes no argument at all and fetches what it installs itself. Neither takes a path, a
    value or a command from the caller, so neither is a way for this user to run code of its own as root -- which
    is the one thing a second root right must not become.

    **The second rule says that in sudoers and not only in the program.** A command written with no arguments at
    all may be run with any arguments the caller chooses (sudoers(5): "If no command line arguments are specified,
    the user may run the command with any arguments they choose"), and `""` is how sudoers says "with no
    arguments". The program refuses an argument itself as well, so the two layers say the same thing; this is the
    one that holds whatever the program on the machine turns out to be."""
    return ("# Founderizer: hubsetup.py writes this file. Three rights for the user that runs this machine's\n"
            "# Founderizer services, and nothing else: the helper that makes one agent's OS user, as root; the\n"
            "# helper that brings this machine's vault broker onto the vault.py of the fleet's configuration ref,\n"
            "# as root; and any command as a member of the group %(group)s, which holds the agent users alone.\n"
            "# Each root command does one mechanical thing and takes nothing from the caller: the first takes one\n"
            "# agent user name, which it checks itself, and the second takes no argument and fetches what it\n"
            "# installs itself. The empty argument list is sudoers saying \"with no arguments at all\"; a command\n"
            "# written with none may be run with any. This user may not become root.\n"
            "%(user)s ALL=(root) NOPASSWD: %(helper)s\n"
            '%(user)s ALL=(root) NOPASSWD: %(vault)s ""\n'
            "%(user)s ALL=(%%%(group)s) NOPASSWD: ALL\n") % {
                "group": AGENT_GROUP, "user": service_user, "helper": HELPER, "vault": VAULT_UPDATE}


def helper_install_script(helper_from, vault_from, sudoers_from, check_from, keys_from, early_from):
    """The shell that puts the group, the two root helpers, the sudoers file and the root-owned copies of the release
    check and of both release key files in place. `visudo -c` reads the new file before it is moved in, because a file that sudo
    cannot parse takes sudo away from the whole machine."""
    return ("groupadd -f %(group)s\n"
            "install -d -o root -g root -m 755 %(lib)s\n"
            "install -o root -g root -m 644 %(check_from)s %(check)s\n"
            "install -o root -g root -m 644 %(keys_from)s %(keys)s\n"
            "install -o root -g root -m 644 %(early_from)s %(early)s\n"
            "install -o root -g root -m 755 %(helper_from)s %(helper)s\n"
            "install -o root -g root -m 755 %(vault_from)s %(vault)s\n"
            "visudo -cqf %(sudoers_from)s\n"
            "install -o root -g root -m 440 %(sudoers_from)s %(sudoers)s\n") % {
                "group": AGENT_GROUP, "helper_from": shlex.quote(helper_from), "helper": HELPER,
                "vault_from": shlex.quote(vault_from), "vault": VAULT_UPDATE,
                "sudoers_from": shlex.quote(sudoers_from), "sudoers": SUDOERS, "lib": VAULT_LIB,
                "check_from": shlex.quote(check_from), "check": RELEASE_CHECK,
                "keys_from": shlex.quote(keys_from), "keys": RELEASE_KEYS,
                "early_from": shlex.quote(early_from), "early": EARLY_KEYS}


def agent_helper(service_user="fleet", repo=None, check=False, run=None, read=None, kit=KIT):
    """The group, the two root helpers and the sudoers file that the agent-add path, the vault broker and `verify`
    need on this machine.

    An agent the owner adds later from the app is installed by the server service, which runs as this machine's
    service user without root (server.py), so it cannot make the OS user of the agent it installs, and it cannot
    bring the machine's vault broker onto the `vault.py` of a release either. This puts the two root commands in
    place that it may run, and the one sudoers file that says what it may do -- all three together, so that the
    rights and the commands they name can never be read apart. Both installers call it; nothing of it reaches a
    Mac, which keeps one user for its agents (PRODUCT.md P2) and whose vault is the signed app the owner's Mac
    updates itself.

    `repo` is the address of the fleet's configuration ref, which the vault helper fetches the broker's program
    from; both installers know it already. Without one that helper refuses and says to run the join line again.

    Safe to run again, and it changes nothing when all three files are already the ones this version writes.
    Returns "made", "there" or "would make"."""
    run = run or _shell
    read = read or (lambda path: pathlib.Path(path).read_text(encoding="utf-8"))
    helper, vault, sudoers = helper_script(), vault_program_script(repo), sudoers_text(service_user)
    # DevOps plan 0.3: the vault program checks a release with root's own copies of this checkout's check and keys
    release_check = pathlib.Path(kit, "releases.py").read_text(encoding="utf-8")
    release_keys = pathlib.Path(kit, "release-key.pub").read_text(encoding="utf-8")
    early_keys = pathlib.Path(kit, releases.EARLY_KEY_FILE).read_text(encoding="utf-8")
    try:
        there = read(HELPER) == helper and read(VAULT_UPDATE) == vault and read(SUDOERS) == sudoers and \
            read(RELEASE_CHECK) == release_check and read(RELEASE_KEYS) == release_keys and read(EARLY_KEYS) == early_keys
    except OSError:
        there = False
    if there:
        say(f"{HELPER}, {VAULT_UPDATE} and {SUDOERS} are in place already: the server service can make one agent's "
            f"OS user and bring this machine's vault broker onto a release, and nothing else with root")
        return "there"
    if check:
        say(f"  would write {HELPER}, the one root command that makes the OS user of one agent, {VAULT_UPDATE}, "
            f"which brings this machine's vault broker onto the vault.py of the fleet's configuration ref, and "
            f"{SUDOERS}, which lets {service_user} run those two commands and become the group {AGENT_GROUP} and "
            f"nothing else")
        return "would make"
    folder = tempfile.mkdtemp(prefix="fleet-agent-helper-")
    try:
        one, two = os.path.join(folder, "fleet-agent-user"), os.path.join(folder, "fleet-vault-program")
        three, four, five, six = (os.path.join(folder, name) for name in ("sudoers", "releases.py", "release-key.pub",
                                                                          releases.EARLY_KEY_FILE))
        for path, text in ((one, helper), (two, vault), (three, sudoers), (four, release_check), (five, release_keys),
                           (six, early_keys)):
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        code, out, err = run(helper_install_script(one, two, three, four, five, six))
        if code != 0:
            raise Stop(f"the root helpers of this machine's agents and its vault broker could not be put in place: "
                       f"{(err or out).strip()[-300:]}")
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    say(f"{HELPER} makes the OS user of one agent, {VAULT_UPDATE} brings this machine's vault broker onto the "
        f"vault.py of the fleet's configuration ref, and {SUDOERS} lets {service_user} run those two commands as "
        f"root and become the group {AGENT_GROUP}: nothing else, and never root")
    if not repo:
        say(f"  this run had no address for the configuration ref, so {VAULT_UPDATE} refuses until the join line "
            f"is run again; a release that changes vault.py then leaves this machine's broker behind")
    return "made"


KEPT_SPEC = re.compile(r"[0-9]{1,5}/(?:tcp|udp)$")
# A client's own port, which the server only receives answers on: DHCP over IPv4 and over IPv6.
CLIENT_PORTS = {("udp", "68"), ("udp", "546")}


def public_listeners(text, ssh_ports=("22",)):
    """The ports this machine answers on from the internet before its firewall goes on, read from `ss -H -ltnup` as
    root, as "80/tcp", "443/tcp", "41641/udp". A VPS whose firewall is off serves them today, so the firewall step
    keeps them open, and a website on that VPS stays up: only SSH moves to the private network (the owner, 4 November
    2026, of a VPS that a customer already uses: "it needs to work"). Left out: SSH on each of its ports, by its port
    and by its process, because a socket that systemd holds for sshd names systemd; what listens on loopback,
    link-local or Tailscale's own addresses; and a DHCP client's port. None of them is a service that the internet
    reaches today."""
    ssh = {str(port) for port in ssh_ports}
    kept = set()
    for line in (text or "").splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0] not in ("tcp", "udp"):
            continue
        address, _, port = fields[4].rpartition(":")
        address = address.split("%", 1)[0].strip("[]").lower()
        if not port.isdigit() or port in ssh or '"sshd' in " ".join(fields[5:]) or (fields[0], port) in CLIENT_PORTS:
            continue
        if (address.startswith(("127.", "::ffff:127.", "fe80:", "fd7a:115c:a1e0:")) or address == "::1"
                or PRIVATE.match(address)):
            continue
        kept.add(f"{port}/{fields[0]}")
    return sorted(kept, key=lambda spec: (int(spec.split("/")[0]), spec))


def firewall_script(kept=()):
    """The shell that sets this machine's firewall, as root. Everything on the private network comes in, SSH included,
    and nothing else does: no public SSH rule is added, and the one that the installers before 2 November 2026 added
    (comment `fleet ssh`, port 22 from anywhere) is removed. It is found by that comment, so a rule of the owner's own
    stays, and deleted from the highest number down, so that each number still names the rule it was read for. An
    active firewall keeps its defaults. A session that came in over the public address keeps going: only a new one
    is refused.

    A firewall that was off gets one rule for each port in `kept` (`public_listeners`) before its incoming default
    turns to deny, comment `fleet kept`, so that what the machine served before the install it serves after it. An
    active firewall gets none: its own rules already say what may come in."""
    for spec in kept:
        if not KEPT_SPEC.match(spec):
            raise ValueError(f"not a port of the firewall: {spec!r}")
    keep = "".join(f"    ufw allow {spec} comment 'fleet kept' >/dev/null\n"
                   f'    kept="$kept {spec}"\n' for spec in kept)
    return ("set -eu\n"
            "active=no\n"
            "ufw status 2>/dev/null | grep -q '^Status: active' && active=yes\n"
            "kept=\n"
            'if [ "$active" = no ]; then\n'
            + keep +
            "    ufw default deny incoming >/dev/null\n"
            "    ufw default allow outgoing >/dev/null\n"
            "fi\n"
            "ufw allow in on tailscale0 comment 'fleet tailscale' >/dev/null\n"
            '[ "$active" = yes ] || ufw --force enable >/dev/null\n'
            "removed=0\n"
            "for n in $(ufw status numbered | sed -n 's/^\\[ *\\([0-9][0-9]*\\)\\].*# fleet ssh *$/\\1/p' | sort -rn); do\n"
            '    ufw --force delete "$n" >/dev/null\n'
            "    removed=$((removed + 1))\n"
            "done\n"
            "ufw status | grep -q '^Status: active' || { echo 'the firewall did not turn on' >&2; exit 1; }\n"
            "if ufw status | grep -q '# fleet ssh *$'; then echo 'the public SSH rule is still there' >&2; exit 1; fi\n"
            'echo "removed=$removed"\n'
            'echo "kept=$kept"\n')


def firewall(check=False, run=None):
    """The firewall of this Linux machine: incoming traffic over the private network only, SSH included (the owner's
    words, 2 November 2026: SSH reachable only over Tailscale after setup). Both installers call it as their firewall
    step, and a machine that an earlier installer set up takes it as root in its own checkout, once.

    It runs only on a machine that is on the private network, because a firewall that lets SSH in over Tailscale
    alone leaves no way in to a machine that is not on it. Its sign of the private network is an address from
    `tailscale ip -4` and a `tailscale status` that succeeds, as in the installers' network steps. An address alone is
    not enough. Tailscale gives one to a machine that waits for an admin of the tailnet to approve it
    (NeedsMachineAuth), and nothing on the private network reaches that machine until then. Neither read proves that
    the owner's Mac reaches SSH on that address: onboard.py's firewall step proves that over SSH first.
    A machine whose firewall was off keeps open the ports that answered from the internet before
    (`public_listeners`): a VPS that a customer already uses keeps its website.
    Safe to run again. Returns "set" or "would set"."""
    run = run or _shell

    def off_network(why):
        return Stop(f"this machine is not on the private network ({why}), so its firewall stays as it is: one that "
                    "lets SSH in over the private network only would leave no way in. Connect Tailscale, then run "
                    "this again.")

    _code, out, _err = run("tailscale ip -4 2>/dev/null | head -n 1")
    ip = (out or "").strip()
    if not PRIVATE.match(ip):
        raise off_network("tailscale ip -4 gave none of its addresses")
    # Plain `tailscale status` ends with 1 in each state but Running and Starting. `--json` ends with 0 in each state,
    # and it names the state (Tailscale 1.104.6, cmd/tailscale/cli/status.go).
    if run("tailscale status >/dev/null 2>&1")[0] != 0:
        _code, out, _err = run("tailscale status --json 2>/dev/null")
        try:
            status = json.loads(out or "{}")
        except ValueError:
            status = None
        backend = status.get("BackendState") if isinstance(status, dict) else None
        if backend == "NeedsMachineAuth":
            raise Stop("this machine waits for an admin to approve it in the fleet's Tailscale admin console. Until "
                       "then, nothing on the private network reaches it. So its firewall stays as it is: one that "
                       "lets SSH in over the private network only would leave no way in. Approve this machine there, "
                       "then run this again.")
        raise off_network("tailscale status failed" + (f"; Tailscale's state is {backend}"
                                                       if isinstance(backend, str) and backend.isalpha() else ""))
    _code, listening, _err = run("ss -H -ltnup 2>/dev/null")
    _code, ports, _err = run("sshd -T 2>/dev/null | sed -n 's/^port //p'")
    kept = public_listeners(listening, ssh_ports={"22", *(ports or "").split()})
    if check:
        say(f"  would let everything on tailscale0 in, deny other incoming traffic, remove the public SSH rule of an "
            f"earlier Founderizer, and turn the firewall on: SSH then reaches this machine at {ip} only"
            + (f"; a firewall that is off now keeps open the ports that answer now: {', '.join(kept)}" if kept else ""))
        return "would set"
    code, out, err = run(firewall_script(kept))
    if code != 0:
        raise Stop(f"the firewall could not be set: {(err or out).strip()[-300:]}")
    said = kv(out)
    removed, stayed = said.get("removed", "0"), said.get("kept", "").split()
    say(f"the firewall is on: incoming traffic over the private network only, SSH included, at {ip}"
        + (f"; these ports stay open as they were: {', '.join(stayed)}" if stayed else "")
        + (f"; the public SSH rule of an earlier Founderizer is removed ({removed} lines)" if removed != "0" else ""))
    return "set"
# ---------------------------------------------------------------- the server's own hardening (join.sh)

SSHD_DIR = "/etc/ssh/sshd_config.d"
SSHD_HARDENING = SSHD_DIR + "/10-fleet-hardening.conf"
# sshd takes the first value that it reads of a setting, and sshd_config reads this folder before its own settings on
# every system the join takes (Ubuntu 22.04 to 26.04, Debian 12 and 13), so these lines come before the system's own
# and a provider's later file.
SSHD_TEXT = ("# Founderizer's join writes this file (hubsetup.py harden): SSH takes keys only, and no X11 forwarding.\n"
             "PasswordAuthentication no\n"
             "KbdInteractiveAuthentication no\n"
             "X11Forwarding no\n")
SSHD_WANTED = {"passwordauthentication": "no", "kbdinteractiveauthentication": "no", "x11forwarding": "no"}
# Where an account of the server keeps the keys it logs in with over SSH (sshd's default AuthorizedKeysFile).
KEY_FILES = ("/root/.ssh/authorized_keys", "/root/.ssh/authorized_keys2", "/home/*/.ssh/authorized_keys",
             "/home/*/.ssh/authorized_keys2")
NPMRC = "/etc/npmrc"                    # npm's file for every user of the system on Debian and Ubuntu
NPM_RULE = "min-release-age=7"          # npm takes no package version that was published less than seven days ago
NPM_RULE_LINE = re.compile(r"^\s*min-release-age\s*=", re.M)


def put_file(path, text, mode, uid=None, gid=None):
    """The whole file at once, as root: a new file beside it, then renamed over it, so a reader never sees half."""
    folder = os.path.dirname(path)
    fd, temp = tempfile.mkstemp(dir=folder, prefix=".fleet-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(temp, mode)
        if uid is not None:
            os.chown(temp, uid, gid)
        os.replace(temp, path)
    except BaseException:
        if os.path.exists(temp):
            os.remove(temp)
        raise


def has_ssh_key(root=""):
    """Whether an account of this server logs in with an SSH key: a key line in root's authorized_keys or in that of a
    user in /home. Without one, a server whose SSH takes keys only would let nobody in."""
    for pattern in KEY_FILES:
        for path in glob.glob(root + pattern):
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    if any(line.strip() and not line.lstrip().startswith("#") for line in f):
                        return True
            except OSError:
                continue
    return False


def harden_ssh(check, run, root=""):
    """SSH takes keys only, with no X11 forwarding, through one file in sshd's own folder. sshd checks the new file
    (sshd -t) before it reloads, and a file that it refuses is taken back. The words of what it did."""
    _code, out, _err = run("systemctl is-active ssh.service ssh.socket")
    if "active" not in out.split():
        return "SSH: OpenSSH does not run on this server, so no password lets anybody in through it"
    if not has_ssh_key(root):
        return ("SSH keeps password login: no account on this server has an SSH key, and a server that takes keys only "
                "would let nobody in")
    if not os.path.isdir(root + SSHD_DIR):
        return "SSH keeps its settings: this system has no folder for sshd's own files"
    path = root + SSHD_HARDENING
    try:
        with open(path, encoding="utf-8") as f:
            before = f.read()
    except OSError:
        before = None
    if check:
        return "would make SSH take keys only, with no X11 forwarding" if before != SSHD_TEXT \
            else "SSH takes keys only already, with no X11 forwarding"
    if before != SSHD_TEXT:
        put_file(path, SSHD_TEXT, 0o644, *((0, 0) if not root else ()))
        code, out, err = run("sshd -t")
        if code != 0:
            if before is None:
                os.remove(path)
            else:
                put_file(path, before, 0o644, *((0, 0) if not root else ()))
            return f"SSH keeps its settings: sshd refused the new file ({(err or out).strip()[-200:]})"
    run("systemctl try-reload-or-restart ssh.service")      # a session that is open keeps going
    code, out, _ = run("sshd -T")
    seen = dict(line.split(" ", 1) for line in out.lower().splitlines() if " " in line)
    still = [key for key, value in SSHD_WANTED.items() if seen.get(key) != value]
    if code != 0 or still:
        return "SSH does not take keys only yet: " + ("an earlier file of sshd sets " + ", ".join(still)
                                                      if code == 0 else "sshd -T did not answer")
    return "SSH takes keys only, with no X11 forwarding"


def harden_npm(service_user, check, root="", account=None):
    """npm takes no package version that is newer than seven days: for every user of the system (/etc/npmrc) and for
    the service user (its ~/.npmrc), each where no min-release-age line is yet, so a line of the owner's own stays. A
    new /etc/npmrc holds that one line and nothing else. The words of what it did."""
    if account is None:
        try:
            entry = pwd.getpwnam(service_user)
            account = (entry.pw_dir, entry.pw_uid, entry.pw_gid)
        except KeyError:
            account = None
    files = [(root + NPMRC, 0o644, None if root else 0, None if root else 0)]
    if account:
        files.append((root + os.path.join(account[0], ".npmrc"), 0o600, account[1], account[2]))
    added = []
    for path, mode, uid, gid in files:
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read()
        except FileNotFoundError:
            text = None
        except OSError:
            continue
        if text is not None and NPM_RULE_LINE.search(text):
            continue
        added.append(path[len(root):])
        if check:
            continue
        if text is None:
            put_file(path, NPM_RULE + "\n", mode, uid, gid)
        else:
            st = os.stat(path)
            put_file(path, text + ("" if not text or text.endswith("\n") else "\n") + NPM_RULE + "\n",
                     stat.S_IMODE(st.st_mode), st.st_uid if not root else None, st.st_gid if not root else None)
    if not added:
        return "npm takes no package version newer than seven days already"
    return ("would make" if check else "made") + " npm take no package version newer than seven days (" + \
        ", ".join(added) + ")"


def harden_tailscale(check, run):
    """Tailscale updates itself, which is its own setting for a new device of a new tailnet. The words of what it did."""
    if check:
        return "would turn on Tailscale's own updates"
    code, out, err = run("tailscale set --auto-update")
    if code != 0:
        return f"Tailscale's own updates stay as they are: {(err or out).strip()[-200:] or 'tailscale did not answer'}"
    return "Tailscale updates itself"


def harden(service_user="fleet", check=False, run=None, root="", account=None):
    """The server's own hardening, which the join takes after its firewall (the owner, 3 November 2026: Add server
    ends at the baseline, for any user): SSH takes keys only with no X11 forwarding, npm takes no package version
    newer than seven days, and Tailscale updates itself. Each part checks first, so a second run changes nothing. A
    part that cannot be done says why and leaves the server as it was: none of them stops the join, and the server's
    own reading (lifecycle.Lifecycle.security) tells the hub what holds. Returns the lines that it said."""
    run = run or _shell
    said = [harden_ssh(check, run, root), harden_npm(service_user, check, root, account), harden_tailscale(check, run)]
    for line in said:
        say(line)
    return said
# ---------------------------------------------------------------- the hub's TCP window (hub.sh)

SYSCTL_DIR = "/etc/sysctl.d"
HUB_TCP = SYSCTL_DIR + "/60-fleet-hub-tcp.conf"
HUB_TCP_KEY = "net.ipv4.tcp_slow_start_after_idle"
HUB_TCP_LIVE = "/proc/sys/net/ipv4/tcp_slow_start_after_idle"     # the value that the kernel uses now
# Where a file of the system itself can set the value: each folder that systemd-sysctl and `sysctl --system` read at a
# start, in their order (a file name in an earlier folder hides the same name in a later one, and a link to /dev/null
# there switches the later file off), and the one old file.
SYSCTL_SOURCES = ("/etc/sysctl.d", "/run/sysctl.d", "/usr/local/lib/sysctl.d", "/usr/lib/sysctl.d", "/lib/sysctl.d")
SYSCTL_CONF = "/etc/sysctl.conf"
HUB_TCP_TEXT = (
    "# Founderizer's hub installer writes this file (hubsetup.py tcp): a kept connection keeps its TCP window\n"
    "# over an idle time. The Mac app reads this hub's state every 3 seconds on one kept connection, and with the\n"
    "# default (1) each answer starts again from a window of 10 packets: an answer of 474 KB took 6 round trips,\n"
    "# and with 0 it takes 1 (0.29 s against 0.06 s at a round trip of 56 ms, measured on 10 November 2026).\n"
    "# To undo it: delete this file, then run  sysctl -w net.ipv4.tcp_slow_start_after_idle=1\n"
    "net.ipv4.tcp_slow_start_after_idle = 0\n")


def sysctl_value(path):
    """The value in one file of /proc/sys, as its text, or None when it cannot be read."""
    try:
        with open(path, encoding="ascii") as f:
            return f.read().strip()
    except (OSError, UnicodeDecodeError):
        return None


def sets_tcp_key(text):
    """Whether the text of a sysctl file sets net.ipv4.tcp_slow_start_after_idle: a line `key = value` whose key, read
    as systemd-sysctl reads one ("/" as ".", a "-" before it, a glob such as net.ipv4.tcp_*), names it. A "*" here
    also crosses a ".", which systemd's does not: such a key counts too, and the step then writes nothing, the safe
    side."""
    for line in text.lstrip("\ufeff").splitlines():
        line = line.strip()
        if not line or line[0] in "#;" or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip().lstrip("-").strip().replace("/", ".")
        if key and fnmatch.fnmatchcase(HUB_TCP_KEY, key):
            return True
    return False


def system_tcp_setting(root=""):
    """The file of the system itself that sets net.ipv4.tcp_slow_start_after_idle (its path, without `root`), or None.
    It is a setting of the owner's own, or of the system's vendor, and it decides at every start: hub_tcp leaves it.
    Only the files that a start reads count: of each file name, the one in the first folder of SYSCTL_SOURCES."""
    first = {}
    for folder in SYSCTL_SOURCES:
        for path in sorted(glob.glob(glob.escape(root + folder) + "/*.conf")):
            first.setdefault(os.path.basename(path), path)
    for path in [first[name] for name in sorted(first)] + [root + SYSCTL_CONF]:
        if path == root + HUB_TCP:
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                if sets_tcp_key(f.read()):
                    return path[len(root):]
        except OSError:
            continue
    return None


def hub_tcp_step(check, root):
    own = system_tcp_setting(root)
    if own and os.path.lexists(root + HUB_TCP):         # a file of the system's own that came after an earlier run
        return (f"TCP keeps this server's own setting: {own} sets {HUB_TCP_KEY}, and so does {HUB_TCP} of an earlier "
                "run; of the two, the file that a start reads last decides")
    if own:
        return f"TCP keeps this server's own setting: {own} sets {HUB_TCP_KEY}"
    path, live = root + HUB_TCP, root + HUB_TCP_LIVE
    try:
        with open(path, encoding="utf-8") as f:
            before = f.read()
    except OSError:
        before = None
    if before == HUB_TCP_TEXT and sysctl_value(live) == "0":
        return "a kept connection keeps its TCP window over an idle time already"
    if check:
        return f"would keep the TCP window of a kept connection over an idle time ({HUB_TCP_KEY} = 0 in {HUB_TCP})"
    if before != HUB_TCP_TEXT:
        try:
            os.makedirs(root + SYSCTL_DIR, mode=0o755, exist_ok=True)
            put_file(path, HUB_TCP_TEXT, 0o644, *((0, 0) if not root else ()))
        except OSError as e:
            return f"TCP keeps its setting: {HUB_TCP} could not be written ({e.strerror or e})"
    try:
        with open(live, "w", encoding="ascii") as f:
            f.write("0\n")
    except OSError as e:
        return (f"this server did not take {HUB_TCP_KEY} = 0 now ({e.strerror or e}): {HUB_TCP} sets it at a start "
                "where /proc/sys can be written")
    now = sysctl_value(live)
    if now != "0":
        return (f"this server still reads {HUB_TCP_KEY} = {now or 'nothing'} after the write: {HUB_TCP} sets 0 at a "
                "start where /proc/sys can be written")
    return f"a kept connection keeps its TCP window over an idle time ({HUB_TCP_KEY} = 0)"


def hub_tcp(check=False, root=""):
    """A kept connection to the hub keeps its TCP window over an idle time (the owner, 10 November 2026: "Yes, every
    hub"). The Mac app reads the whole state every 3 seconds on one kept connection. Linux starts an answer that comes
    after an idle time longer than the connection's retransmission time-out (about 0.26 s at a round trip of 56 ms)
    from a window of 10 packets again (net.ipv4.tcp_slow_start_after_idle, RFC 5681 4.1): the state of 474 KB took 6
    round trips, 0.29 s of each read, and with the value 0 it takes one, 0.06 s. A connection that is open takes the
    value at its next answer, so nothing restarts.

    One file in /etc/sysctl.d holds the value for every start, and the kernel takes it at once as well. A file of the
    system itself that sets the value stays the one that decides, and this step then writes nothing. A server that does
    not take the value now (a container whose /proc/sys is read-only) keeps the file, which a start reads only where
    /proc/sys can be written. Like the join's hardening, it stops no install. It runs as root from the copy of
    Founderizer that the installer runs from, or from root's own clone (kit_clone), never from a folder that the hub's
    user can change. Returns the words of what it did, which it also says."""
    line = hub_tcp_step(check, root)
    say(line)
    return line
# ---------------------------------------------------------------- the machine's vault broker (PRODUCT.md P5)

def vault_reading(user=VAULT_USER, group=AGENT_GROUP):
    """The shell that reads this machine's broker, so that a second run of the installer changes nothing."""
    return ("id -u %(u)s >/dev/null 2>&1 && echo user=yes || echo user=no\n"
            "getent group %(g)s >/dev/null 2>&1 && echo group=yes || echo group=no\n"
            "command -v age >/dev/null 2>&1 && echo age=yes || echo age=no\n"
            "command -v age-keygen >/dev/null 2>&1 && echo keygen=yes || echo keygen=no\n"
            "echo program=$(sha256sum %(lib)s/vault.py 2>/dev/null | cut -d' ' -f1)\n"
            "test -s %(state)s/age.key && echo key=yes || echo key=no\n"
            "echo active=$(systemctl is-active fleet-vault 2>/dev/null || true)\n"
            # A broker that crashes on its own configuration is `active` for an instant and then gone, so the count
            # of restarts since the last reset is what says whether it stayed up. worker4 reported a finished
            # install three times over a service systemd had already given up on.
            "echo restarts=$(systemctl show -p NRestarts --value fleet-vault 2>/dev/null || echo unknown)\n"
            "echo recipient=$(sed -n 's/^# public key: //p' %(state)s/age.key 2>/dev/null)\n") % {
                "u": user, "g": group, "lib": VAULT_LIB, "state": VAULT_STATE}


def vault_user_script(user=VAULT_USER, group=AGENT_GROUP):
    """The shell that makes the broker's user and the folders it needs, each line safe to run again. The user has no
    login and no home of its own making; its state folder is made here, because the handover key is written into it
    before the service starts for the first time (systemd's StateDirectory comes too late for that)."""
    return ("id -u %(u)s >/dev/null 2>&1 || useradd --system --home-dir %(state)s --shell /usr/sbin/nologin %(u)s\n"
            "groupadd -f %(g)s\n"
            "install -d -o root -g root -m 755 %(lib)s %(conf_dir)s\n"
            "install -d -o %(u)s -g %(u)s -m 700 %(state)s\n") % {
                "u": user, "g": group, "lib": VAULT_LIB, "conf_dir": VAULT_CONF_DIR, "state": VAULT_STATE}


# Seconds that each apt-get of an install waits for the package lock. A new Ubuntu server runs its first updates for
# about 9 minutes after its first boot, and they hold the lock: in the proof run of 5 November 2026 a wait of 5 minutes
# stopped the vault step of a join, and the same step passed 10 minutes later. hub.sh and join.sh wait as long.
APT_LOCK_WAIT = 1200
# `apt-get update` tries the lock of the package lists once: apt reads DPkg::Lock::Timeout only for the lock of dpkg.
# The first updates of a new server hold the lock of the lists while they read the lists, so `update` gets up to 10
# tries, 15 seconds apart, as hub.sh's and join.sh's apt_update does: the 10th try comes after the loop, so that its
# words and its exit status are the step's.
_UPDATE_ONCE = f"apt-get -o DPkg::Lock::Timeout={APT_LOCK_WAIT} update -q </dev/null >/dev/null"
APT_UPDATE = f"for try in 1 2 3 4 5 6 7 8 9; do {_UPDATE_ONCE} && break; sleep 15; false; done || {_UPDATE_ONCE}"
AGE_INSTALL = ("export DEBIAN_FRONTEND=noninteractive\n"
               f"{APT_UPDATE}\n"
               f"apt-get -o DPkg::Lock::Timeout={APT_LOCK_WAIT} install -y -q --no-install-recommends age "
               "</dev/null >/dev/null\n")
# The time of AGE_INSTALL: the wait of its `apt-get install` for the lock of dpkg, the 9 pauses of APT_UPDATE, and the
# work, with room to spare.
AGE_INSTALL_TIME = 2 * APT_LOCK_WAIT + 300


def vault_key_script(user=VAULT_USER):
    """The shell that makes the broker's handover key, once. A key that is there is kept: a new one would leave
    every handover already made for this machine unreadable, and the hub pins its public half."""
    return ("umask 077\n"
            "test -s %(key)s || age-keygen -o %(key)s >/dev/null 2>&1\n"
            "chown %(u)s:%(u)s %(key)s\n"
            "chmod 600 %(key)s\n") % {"u": user, "key": VAULT_STATE + "/age.key"}


def vault_config(hub_address, group=AGENT_GROUP, before=None, owner_keys=None, fleet=None):
    """The broker's own configuration, which holds no secret: what it opens, where its keys are, and who may ask it.

    A machine that has no broker yet gets **the fleet's own store** (`store`, `store_key`): one age file on this
    machine, made by `vault.py store-init`, with no account, no organization and no token, so that installing a
    machine needs nothing of the owner. A broker that is already there keeps its store, its keys and its values.
    This installer writes no Bitwarden key: Founderizer has no Bitwarden backend any more, and a broker refuses a
    configuration that names one (vault.py, load_config).

    `worker_group` is the one field this always brings up to date: the group of every agent user of this machine
    (AGENT_GROUP), so an agent added later, or one whose OS user changed, reaches the broker with no change here.
    `ssh` is added once and kept as it is after that.
    An existing `worker_uid` stays beside it, because a uid of this machine's own making is an agent user either
    way and removing a field the owner did not write buys nothing."""
    conf = dict(before or {})
    if not conf:
        conf = {"hub": hub_address, "store": VAULT_STATE + "/store.age", "store_key": VAULT_STATE + "/store.key",
                "age_key": VAULT_STATE + "/age.key", "socket": VAULT_SOCKET, "age": "/usr/bin/age"}
    # The curl program that the broker sends an agent's API request with (call_api). A broker whose configuration
    # names none sends no request, so every call_api of its machine is refused (broker_without_requests). join.sh's
    # base packages put curl at this path; one that is missing, or that an agent could change, stops the broker at
    # its start, as such an age does. Added once, and a path that is there is kept.
    conf.setdefault("curl", "/usr/bin/curl")
    conf["worker_group"] = group
    # place left the broker (DevOps plan 0.3), and with it the ssh client it wrote a key into a target with.
    conf.pop("ssh", None)
    # The owner's keys and the fleet's ID (DevOps plan 0.3): the broker hands a login over only to a recipient that
    # the owner signed a pin for, checked with these. Given by the root step of the machine, and kept after it.
    if owner_keys:
        conf.update(owner_keys=list(owner_keys), fleet=fleet)
    return conf


def vault_install(kit=None, hub_address=None, user=VAULT_USER, group=AGENT_GROUP, check=False, run=None, read=None,
                  system=None, owner_keys=None, fleet=None):
    """This machine's vault broker, as a step of installing the machine instead of a page of commands the owner runs
    by hand (WORKER-INSTALL.md, "Vault broker").

    The broker holds the key of the store and the key that opens sealed handovers, as its own user, so that no agent
    of this machine can read either and no answer of it gives a login (UI-API.md, "Vault isolation (V3)"). Every
    part of that is mechanical and needs root, which the installer has: the user, the folders, `age`, the root-owned
    copy of the broker program, the handover key, the configuration, the store and the service. Nothing here reads
    or writes a credential of the owner's.

    It belongs to the machine and not to one agent, so it is installed before the machine has its first agent: such
    a broker has no `agent` of its own and every request to it names its caller (`vault.py`). The agents the owner
    adds later reach it through `worker_group` with no change to it.

    **The configuration is root with mode 644 and holds no secret.** Group-reading it would be worse than useless:
    the service sets `Group=`, so the vault user's own group is not among its groups, and the broker would fail on
    its own configuration and the service would restart for ever.

    Safe to run again: each step reads first, and the service is restarted only when something changed. Returns
    `{"state": "made"|"there"|"would make", "store": ..., "recipient": ..., "active": ...}`; the recipient is the
    broker's public handover key, which the hub records when the owner first gives an agent of this machine its
    vault (`hub.offered_store`)."""
    run = run or _shell
    read = read or (lambda path: pathlib.Path(path).read_text(encoding="utf-8"))
    kit = kit or KIT
    if system and system != "Linux":
        # A Mac's vault is the signed Fleet Vault.app in the user's login session: the app repository's
        # Vault/install.py installs it once as root, with a root updater that puts each newer signed vault of the
        # release channel in place by itself (Vault/update.zsh). Nothing of this program runs there, and a file
        # written for it would be read by no process.
        say(f"this machine runs {system}, whose vault is the signed Fleet Vault app with its own installer and "
            f"updater, so there is nothing to set up here")
        return {"state": "there", "store": None, "recipient": None, "active": None}
    if not hub_address:
        raise Stop("the vault broker needs the hub's address, which the installer reads from this machine's join.")
    before = kv(run(vault_reading(user, group))[1])
    try:
        current = json.loads(read(VAULT_CONF))
        current = current if isinstance(current, dict) else None
    except (OSError, ValueError):
        current = None
    conf = vault_config(hub_address, group, current, owner_keys, fleet)
    # A configuration of the old Bitwarden backend names no store: the broker refuses it, and the install stops
    # below with the broker's own words in its journal.
    store = "the fleet's own store" if "store" in conf else "no store that this vault opens"
    try:
        program = hashlib.sha256(pathlib.Path(os.path.join(kit, "vault.py")).read_bytes()).hexdigest()
    except OSError:
        raise Stop(f"{os.path.join(kit, 'vault.py')} is not readable, so the broker program cannot be installed.") from None
    done = (before.get("user") == "yes" and before.get("age") == "yes" and before.get("keygen") == "yes"
            and before.get("key") == "yes" and before.get("program") == program and current == conf
            and before.get("active") == "active")
    if done:
        say(f"this machine's vault broker is in place already, kept by {user}: it opens {store}, and the agent "
            f"users of {group} may ask it")
        return {"state": "there", "store": store, "recipient": before.get("recipient") or None, "active": True}
    if check:
        say(f"  would {'install' if current is None else 'bring up to date'} this machine's vault broker: the user "
            f"{user}, age, the root-owned broker program, its handover key, {store}, and the service that keeps "
            f"them away from every agent of this machine")
        return {"state": "would make", "store": store, "recipient": before.get("recipient") or None, "active": False}
    for script, what in ((vault_user_script(user, group), f"the user {user} and the folders of the vault broker"),
                         (AGE_INSTALL if before.get("age") != "yes" or before.get("keygen") != "yes" else "",
                          "the age program, which locks the store and a handover"),
                         (vault_key_script(user), "the broker's handover key")):
        if not script:
            continue
        code, out, err = run(script, timeout=AGE_INSTALL_TIME if script == AGE_INSTALL else 900)
        if code != 0:
            raise Stop(f"{what} could not be put in place: {(err or out).strip()[-300:]}")
    folder = tempfile.mkdtemp(prefix="fleet-vault-install-")
    try:
        one = os.path.join(folder, "vault.json")
        with open(one, "w", encoding="utf-8") as f:
            f.write(json.dumps(conf, indent=2) + "\n")
        # The program first, because `unit` and `store-init` are run from the installed copy, which checks that the
        # worker's user can neither change nor replace it; then the configuration it reads.
        code, out, err = run("install -o root -g root -m 644 %s %s/vault.py\n"
                             "install -o root -g root -m 644 %s %s\n"
                             % (shlex.quote(os.path.join(kit, "vault.py")), VAULT_LIB, shlex.quote(one), VAULT_CONF))
        if code != 0:
            raise Stop(f"the broker program and its configuration could not be installed: {(err or out).strip()[-300:]}")
        if "store" in conf:     # the fleet's own store: its key and an empty store, and a store that is there stays
            code, out, err = run(f"python3 {VAULT_LIB}/vault.py store-init --config {VAULT_CONF} --user {user}",
                                 timeout=300)
            if code != 0:
                raise Stop(f"the fleet's own store could not be made on this machine: {(err or out).strip()[-300:]}")
        code, unit, err = run(f"python3 {VAULT_LIB}/vault.py unit --config {VAULT_CONF} --user {user} --group {group}")
        if code != 0 or "ExecStart=" not in unit:
            raise Stop(f"the service of the vault broker could not be written: {(err or unit).strip()[-300:]}")
        two = os.path.join(folder, "fleet-vault.service")
        with open(two, "w", encoding="utf-8") as f:
            f.write(unit if unit.endswith("\n") else unit + "\n")
        # The restart counter is zeroed first, so what it reads afterwards is this start and no earlier one, and
        # the settle gives a broker that refuses its own configuration time to exit before it is read.
        code, out, err = run("install -o root -g root -m 644 %s %s\nsystemctl daemon-reload\n"
                             "systemctl enable fleet-vault >/dev/null 2>&1\n"
                             "systemctl reset-failed fleet-vault >/dev/null 2>&1 || true\n"
                             "systemctl restart fleet-vault\nsleep %d\n"
                             % (shlex.quote(two), VAULT_UNIT, VAULT_SETTLE), timeout=300)
        if code != 0:
            raise Stop(f"the vault broker service could not be started: {(err or out).strip()[-300:]}")
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    after = kv(run(vault_reading(user, group))[1])
    if after.get("active") != "active" or after.get("restarts") not in ("0", "unknown"):
        raise Stop(f"the vault broker of this machine is {after.get('active') or 'not running'} "
                   f"{VAULT_SETTLE} seconds after its install"
                   + (f", having restarted {after['restarts']} time(s)" if after.get("restarts") not in (None, "unknown")
                      else "") + ". It is installed and not serving, so no agent of this machine can use a secret "
                   f"it holds. Read `journalctl -u fleet-vault -n 30` on this machine: a broker that refuses its "
                   f"own configuration says so on its first line.")
    if not after.get("recipient"):
        raise Stop("the vault broker runs, but its handover key has no public half, so the hub could not pin it.")
    say(f"this machine's vault broker runs as {user}: it opens {store}, the agent users of {group} may ask it, and "
        f"its store key and handover key belong to {user} alone")
    say(f"  its public handover key is {after['recipient']}; Founderizer records it when you first give an agent of "
        f"this machine its vault")
    return {"state": "made", "store": store, "recipient": after["recipient"], "active": True}


def swap_reading(user=SWAP_USER):
    """The shell that reads this machine's key swap, so that a second run of its step changes nothing."""
    return ("id -u %(u)s >/dev/null 2>&1 && echo user=yes || echo user=no\n"
            "echo low=$(cat %(low)s 2>/dev/null)\n"
            "echo unit=$(sha256sum %(unit)s 2>/dev/null | cut -d' ' -f1)\n"
            "echo broker=$(systemctl is-active fleet-vault 2>/dev/null || true)\n"
            "echo broker_restarts=$(systemctl show -p NRestarts --value fleet-vault 2>/dev/null || echo unknown)\n"
            "echo active=$(systemctl is-active %(service)s 2>/dev/null || true)\n"
            "echo restarts=$(systemctl show -p NRestarts --value %(service)s 2>/dev/null || echo unknown)\n") % {
                "u": user, "low": SWAP_LOW_PORTS, "unit": SWAP_UNIT, "service": SWAP_SERVICE}


def swap_install(user=SWAP_USER, port=SWAP_PORT, check=False, run=None, read=None):
    """This machine's key swap (VAULT.md, "The key swap"), on a machine that has its vault broker: an API key that an
    agent reads then stays out of its sessions. `hubsetup.py vault --swap` runs it after vault_install, and nothing
    else does: a machine that nobody ran it on gives each key as a variable, as before.

    It makes the proxy's own user, which is in no group of the agents or of the broker; writes the part "swap" into
    the broker's configuration, which stays root's with mode 644 and holds no secret; restarts the broker, so that it
    reads the part and opens its socket for the proxy; and installs and starts the proxy's service. It changes no
    line of the root helpers and of the sudoers file. That part of the configuration is the switch: with it, the
    broker gives a key that has a site as a placeholder or not at all, and a vault.py from before the swap does not
    start on it, so no release steps the machine down.

    The order matters. The installed broker program prints the proxy's unit before anything changes: a program that
    does not know the swap fails there. A broker that does not stay up on the new configuration gets the old one
    back.

    It stops on a machine where each user can listen on the proxy's port (the kernel's setting of the low ports):
    there an agent could take the proxy's place. Safe to run again. Returns "made", "there" or "would make"."""
    run = run or _shell
    read = read or (lambda path: pathlib.Path(path).read_text(encoding="utf-8"))
    before = kv(run(swap_reading(user))[1])
    try:
        current = json.loads(read(VAULT_CONF))
        current = current if isinstance(current, dict) else None
    except (OSError, ValueError):
        current = None
    if current is None or not current.get("worker_group"):
        if check:
            say("  would switch this machine's key swap on, after its vault broker is in place")
            return "would make"
        raise Stop("the key swap needs this machine's vault broker, with worker_group in its configuration: run "
                   "`hubsetup.py vault` first.")
    low = before.get("low", "")
    if low.isdigit() and int(low) <= port:
        raise Stop(f"on this machine each user can listen on port {port} (net.ipv4.ip_unprivileged_port_start is "
                   f"{low}), so an agent could take the place of the vault's proxy. The key swap is not switched on. "
                   f"Set net.ipv4.ip_unprivileged_port_start to 1024, its default, and run this step again.")
    part = {"user": user, "vault": VAULT_USER, "port": port, "openssl": "/usr/bin/openssl"}
    conf = dict(current, swap=part)
    # The installed program prints the proxy's unit, which changes nothing: a program that does not know the swap
    # fails here, before the configuration has the part that it would refuse.
    code, unit, err = run(f"python3 {VAULT_LIB}/vault.py unit --swap --config {VAULT_CONF} --user {user}")
    unit = unit if unit.endswith("\n") or not unit else unit + "\n"
    known = code == 0 and "ExecStart=" in unit
    done = (known and before.get("user") == "yes" and current == conf
            and before.get("unit") == hashlib.sha256(unit.encode()).hexdigest()
            and before.get("broker") == "active" and before.get("active") == "active")
    if done:
        say(f"this machine's key swap is in place already: {user} runs the vault's proxy on 127.0.0.1:{port}")
        return "there"
    if check:
        say(f"  would switch this machine's key swap on: the user {user}, the part swap of {VAULT_CONF}, and the "
            f"service {SWAP_SERVICE}, which puts an API key into a request to the key's own site and cannot read the "
            f"store")
        return "would make"
    if not known:
        raise Stop(f"the vault broker program of this machine does not know the key swap, so nothing changed: "
                   f"{(err or unit).strip()[-300:]}. Run `hubsetup.py vault` from a checkout at the release first.")
    code, out, err = run("id -u %(u)s >/dev/null 2>&1 || useradd --system --user-group --home-dir %(state)s "
                         "--shell /usr/sbin/nologin %(u)s\n" % {"u": user, "state": SWAP_STATE})
    if code != 0:
        raise Stop(f"the user {user} of the vault's proxy could not be made: {(err or out).strip()[-300:]}")
    folder = tempfile.mkdtemp(prefix="fleet-vault-swap-")
    try:
        new, old, service = (os.path.join(folder, name) for name in ("vault.json", "vault.json.before", "unit"))
        for path, text in ((new, json.dumps(conf, indent=2) + "\n"), (old, json.dumps(current, indent=2) + "\n"),
                           (service, unit)):
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        restart = ("systemctl reset-failed fleet-vault >/dev/null 2>&1 || true\n"
                   "systemctl restart fleet-vault\nsleep %d\n" % VAULT_SETTLE)
        if current != conf:
            code, out, err = run("install -o root -g root -m 644 %s %s\n" % (shlex.quote(new), VAULT_CONF) + restart,
                                 timeout=300)
            now = kv(run(swap_reading(user))[1])
            if code != 0 or now.get("broker") != "active" or now.get("broker_restarts") not in ("0", "unknown"):
                run("install -o root -g root -m 644 %s %s\n" % (shlex.quote(old), VAULT_CONF) + restart, timeout=300)
                raise Stop("the vault broker of this machine did not stay up with the key swap in its configuration, "
                           "so the configuration is as it was. Read `journalctl -u fleet-vault -n 30` on this machine.")
        code, out, err = run("install -o root -g root -m 644 %s %s\nsystemctl daemon-reload\n"
                             "systemctl enable %s >/dev/null 2>&1\n"
                             "systemctl reset-failed %s >/dev/null 2>&1 || true\n"
                             "systemctl restart %s\nsleep %d\n"
                             % (shlex.quote(service), SWAP_UNIT, SWAP_SERVICE, SWAP_SERVICE, SWAP_SERVICE, VAULT_SETTLE),
                             timeout=300)
        if code != 0:
            raise Stop(f"the service of the vault's proxy could not be started: {(err or out).strip()[-300:]}")
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    after = kv(run(swap_reading(user))[1])
    if after.get("active") != "active" or after.get("restarts") not in ("0", "unknown"):
        raise Stop(f"the vault's proxy of this machine is {after.get('active') or 'not running'} {VAULT_SETTLE} "
                   f"seconds after its start. The broker serves, and a key that has a site is not given to a session "
                   f"until the proxy runs. Read `journalctl -u {SWAP_SERVICE} -n 30` on this machine: a proxy that "
                   f"does not start says why on its first line.")
    say(f"this machine's key swap is on: {user} runs the vault's proxy on 127.0.0.1:{port}. A key that an agent "
        f"reads and that has a site now reaches a session as a placeholder, and the proxy puts the key into the "
        f"Authorization header of a request to that site only")
    return "made"


def keep_fleet_id(db=None):
    """This fleet's own id in the hub's key store: sixteen hex characters, made once and never again.

    It identifies this fleet to the release channel and says nothing about its owner (PRODUCT.md 4.2): it is derived
    from no address, no name and no account. A second id would orphan the fleet's subscription, so the installer
    makes one only when the store has none, and a second run of the line finds the same one.

    **The installer claims no entitlement with it.** A claim key works once, so the claim has exactly one caller and
    that is the app (PRODUCT.md 4.5): it reads this id from the hub, calls the website and posts the token back. Had
    both claimed, the second would be refused and the customer would need a new key."""
    path = os.path.expanduser(db or DB_PATH)
    if not os.path.exists(path):
        raise Stop(f"the hub keeps no records in {path} yet, so this fleet's id cannot be kept there. The hub writes "
                   f"them when it starts: look at systemctl --user status fleet-hub")
    kept, hub.DB = hub.DB, sqlite3.connect(path, timeout=30)    # a store this program opened, never one it found
    hub.DB.row_factory = sqlite3.Row
    try:
        found = hub.kv_get("fleet_id")
        if found:
            say(f"this fleet's id is {found} already, and it is never made a second time.")
            return found
        made = hub.fleet_id()           # it makes one and keeps it in the same store the app reads it from
        say(f"this fleet's id is {made}: it identifies this fleet to us and nothing else — no address, no name, no "
            f"account. The app binds it to a subscription; this installer claims nothing.")
        return made
    except sqlite3.Error as e:
        raise Stop(f"this fleet's id could not be kept in {path}: {e}. The hub writes its records when it starts: "
                   f"look at systemctl --user status fleet-hub") from None
    finally:
        hub.DB.close()
        hub.DB = kept


# ---------------------------------------------------------------- root's own clone (DevOps plan V2)
#
# The central vault is installed and updated as root, so the program that does it must be one that the hub's user
# cannot change: the hub's own checkout is that user's, and a hub that is broken into could put anything there. So
# root keeps a clone of the published repository of its own, in one fixed place (ROOT_KIT), at the revision of the
# release that the hub runs, whose manifest (release.json on the configuration ref) one of the release keys signed.
# The keys are the clone's own, at its current revision, or, the first time, those of the copy of this program that
# runs (the day of the cut-over, when the hub is trusted once). A revision that does not descend from the clone's own
# is refused, so no old release comes back. A second run with nothing new changes nothing.

def git_root(*args, cwd=None, timeout=releases.GIT_WAIT):
    """(exit status, stdout, stderr) of one git command as root, with no prompt and no hooks of anybody's."""
    try:
        r = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "transfer.fsckObjects=true", *args],
                           cwd=cwd, capture_output=True, text=True, timeout=timeout,
                           env={"PATH": ROOT_PATH, "GIT_TERMINAL_PROMPT": "0", "HOME": "/nonexistent"})
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, "", str(e)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def root_owned(path):
    """True when root owns the path, and no group or other user can write it or anything in it."""
    for folder, dirs, files in os.walk(path):
        for one in [folder] + [os.path.join(folder, f) for f in files]:
            info = os.lstat(one)
            if info.st_uid != 0 or info.st_mode & 0o022:
                return False
    return os.path.isdir(path)


def give_to_root(path):
    """Every file of the clone root's, and writable by no one else."""
    code, out, err = _shell(f"chown -R root:root {shlex.quote(path)} && chmod -R go-w {shlex.quote(path)}")
    if code != 0 or not root_owned(path):
        raise Stop(f"root's own clone could not be given to root: {(err or out).strip()[-200:]}")


def hub_checkout(home):
    """The hub's own checkout in the home folder of its user: the first name of HUB_CHECKOUTS that is a folder there,
    and the first name when none is. A link is not taken: root reads that folder, and a link of the hub's user could
    lead it to another one, so a hub with a link of the new name to its old folder is read in the old folder."""
    for name in HUB_CHECKOUTS:
        path = os.path.join(home, name)
        try:
            if stat.S_ISDIR(os.lstat(path).st_mode):
                return path
        except OSError:
            pass
    return os.path.join(home, HUB_CHECKOUTS[0])


def kit_clone(hub_user="fleet", source=None, root_kit=None, checkout=None, git=None, own=None, keys=None):
    """As root on the hub's machine: root's own clone of the published repository at the revision of the hub's signed
    release.json (the section above). Returns {"revision", "version", "state": "made"|"moved"|"there"}.

    checkout: the hub's own checkout, where release.json is read (default: hub_checkout of the hub user). source: the
    published repository (releases.DEFAULT_UPSTREAM); the signature names the commit, so it is the same commit from
    any source. git, own and keys are for the tests: git_root, the step that gives the clone to root, and the release
    keys a run trusts when it cannot read them from the clone itself."""
    git, root_kit = git or git_root, root_kit or ROOT_KIT
    source = source or releases.DEFAULT_UPSTREAM
    checkout = checkout or hub_checkout(hub_account(hub_user)["home"])
    try:
        # The hub's user writes this folder: root reads a plain file of it, never a link or a pipe of that user's
        fd = os.open(os.path.join(checkout, RELEASE_FILE), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
                raise ValueError("not a plain file")
            raw = json.loads(os.read(fd, 65537).decode("utf-8"))
        finally:
            os.close(fd)
    except (OSError, ValueError):
        raise Stop(f"the hub's checkout {checkout} carries no {RELEASE_FILE} that can be read, so no release is signed "
                   f"for it yet: the hub writes one with the release it takes") from None
    there = os.path.isdir(os.path.join(root_kit, ".git"))
    trusted = releases.every_key(root_kit) if there else (keys if keys is not None else releases.every_key(KIT))
    try:
        manifest = releases.check(raw, trusted)
    except releases.Untrusted as e:
        raise Stop(f"the hub's {RELEASE_FILE} is not a release that this clone can trust: {e}") from None
    revision = manifest["revision"]
    if there:
        code, current, _ = git("rev-parse", "HEAD", cwd=root_kit)
        if code != 0:
            raise Stop(f"root's own clone in {root_kit} names no revision: remove it, and run kit-clone again")
        if current == revision and not git("status", "--porcelain", cwd=root_kit)[1]:
            say(f"root's own clone is at release {manifest['version']} already ({revision[:12]})")
            return {"revision": revision, "version": manifest["version"], "state": "there"}
        code, _, err = git("fetch", "-q", source, cwd=root_kit)
        if code != 0:
            raise Stop(f"root's own clone could not fetch {source}: {err[-200:]}")
        if git("merge-base", "--is-ancestor", current, revision, cwd=root_kit)[0] != 0:
            raise Stop(f"release {manifest['version']} ({revision[:12]}) does not descend from the revision that root's "
                       f"own clone holds ({current[:12]}), so it is not taken: an older release never comes back")
    else:
        code, _, err = git("clone", "-q", "--no-checkout", source, root_kit)
        if code != 0:
            raise Stop(f"root's own clone of {source} could not be made: {err[-200:]}")
    code, _, err = git("checkout", "-q", "--force", "--detach", revision, cwd=root_kit)
    if code != 0 or git("rev-parse", "HEAD", cwd=root_kit)[1] != revision:
        raise Stop(f"root's own clone could not take release {manifest['version']} ({revision[:12]}): {err[-200:]}")
    git("clean", "-q", "-f", "-d", "-x", cwd=root_kit)
    (own or give_to_root)(root_kit)
    say(f"root's own clone is at release {manifest['version']} ({revision[:12]}) in {root_kit}")
    return {"revision": revision, "version": manifest["version"], "state": "moved" if there else "made"}


# ---------------------------------------------------------------- the central vault (owner feature central_vault)
#
# One vault on the hub's machine that holds every secret of the fleet, as a service of its own user. The hub's user
# may ask it over its socket and can neither read its files nor replace its program, and it seals a copy only to a
# machine key, and its backup only to a recovery key, that the owner signed with the key named here. So this is a
# root step, run by the owner (his app does it over his own SSH) from root's own clone (ROOT_KIT), and kit-clone and a
# second run of it are how the vault is updated: there is no sudoers line and no root helper that lets the hub's user
# install or change it.

def owner_public_key(value):
    """The owner's public key as his app gives it: the base64 of a 65-byte uncompressed P-256 point (0x04, X, Y).
    Only its shape is checked here; the central vault refuses to start with a point that is not on the curve."""
    try:
        raw = base64.b64decode(value or "", validate=True)
    except (ValueError, TypeError):
        raw = b""
    if len(raw) != 65 or raw[0] != 4 or base64.b64encode(raw).decode() != value:
        raise Stop("--owner-key is the base64 of the owner's 65-byte P-256 public key, as their app gives it.")
    return value


def hub_account(user):
    """{uid, group, home} of the hub's own user: the central vault admits that uid alone, and its socket belongs to
    that user's primary group."""
    import grp
    import pwd
    try:
        info = pwd.getpwnam(user)
    except KeyError:
        raise Stop(f"there is no user {user} on this machine: name the user the hub runs as with --hub-user.") from None
    if info.pw_uid == 0:
        raise Stop("the hub never runs as root, so root cannot be the one user the central vault answers.")
    try:
        group = grp.getgrgid(info.pw_gid).gr_name
    except KeyError:
        group = str(info.pw_gid)
    return {"uid": info.pw_uid, "group": group, "home": info.pw_dir}


def hub_fleet(db):
    """This fleet's id as the hub keeps it (hub.fleet_id), read and never written: this runs as root, and a write
    could leave a file of root's beside the hub's own records."""
    if not os.path.exists(db):
        raise Stop(f"the hub keeps no records in {db}, so this fleet's id is not known here: give it with --fleet.")
    try:
        con = sqlite3.connect(pathlib.Path(db).resolve().as_uri() + "?mode=ro", uri=True, timeout=30)
        try:
            row = con.execute("SELECT v FROM kv WHERE k='fleet_id'").fetchone()
        finally:
            con.close()
    except sqlite3.Error as e:
        raise Stop(f"this fleet's id could not be read from {db}: {e}. Give it with --fleet.") from None
    if not row or not FLEET_ID.fullmatch(str(row[0] or "")):
        raise Stop("the hub has made no fleet id yet: run `python3 hubsetup.py fleet-id` as the hub's user, or give "
                   "it with --fleet.")
    return row[0]


def central_config(hub_uid, fleet, owner_key):
    """The central vault's configuration (vault.py, central mode), which holds no secret: the one uid it answers, the
    fleet each signed statement must name, the owner's public key, and where its files are. owner_keys is the key
    of this run and nothing else, so a run from a new Mac replaces the key of a lost one: root on the hub's machine
    is the owner's own authority, and the key files themselves are never replaced (central_install)."""
    return {"central": True, "hub_uid": hub_uid, "fleet": fleet, "owner_keys": [owner_key], "age": "/usr/bin/age",
            "age_key": CENTRAL_STATE + "/age.key", "store": CENTRAL_STATE + "/store.age",
            "store_key": CENTRAL_STATE + "/store.key", "socket": hub.CENTRAL_SOCKET,
            "state": CENTRAL_STATE + "/central.json"}


def central_reading():
    """The shell that reads the central vault, so that a second run changes nothing. It names no key's content."""
    return ("id -u %(u)s >/dev/null 2>&1 && echo user=yes || echo user=no\n"
            "command -v age >/dev/null 2>&1 && echo age=yes || echo age=no\n"
            "command -v age-keygen >/dev/null 2>&1 && echo keygen=yes || echo keygen=no\n"
            "echo program=$(sha256sum %(lib)s/vault.py 2>/dev/null | cut -d' ' -f1)\n"
            "for f in age.key store.key store.age; do test -s %(state)s/$f && echo $f=yes || echo $f=no; done\n"
            "echo active=$(systemctl is-active %(svc)s 2>/dev/null || true)\n"
            "echo restarts=$(systemctl show -p NRestarts --value %(svc)s 2>/dev/null || echo unknown)\n") % {
                "u": CENTRAL_USER, "lib": CENTRAL_LIB, "state": CENTRAL_STATE, "svc": CENTRAL_SERVICE}


def central_user_script():
    """The central vault's user and folders, each line safe to run again. Its state folder is made here, because its
    own key goes in before the service first starts. A state folder that is there already is given to this user
    whole: a vault installed before the user's name left fleet-* (fleet-vault-central, DevOps plan V2) keeps its keys,
    its store and the owner's pins and recovery key in files of the old user, which the vault reads only as its own."""
    return ("id -u %(u)s >/dev/null 2>&1 || useradd --system --home-dir %(state)s --shell /usr/sbin/nologin %(u)s\n"
            "if test -d %(state)s; then chown -R %(u)s:%(u)s %(state)s; fi\n"
            "install -d -o root -g root -m 755 %(lib)s %(conf)s\n"
            "install -d -o %(u)s -g %(u)s -m 700 %(state)s\n") % {
                "u": CENTRAL_USER, "lib": CENTRAL_LIB, "conf": CENTRAL_CONF_DIR, "state": CENTRAL_STATE}


def central_key_script():
    """The central vault's own key, which owners seal new values to, made once. A key that is there is kept: a new
    one would leave every copy sealed to the old one unreadable."""
    return ("umask 077\n"
            "test -s %(key)s || age-keygen -o %(key)s >/dev/null 2>&1\n"
            "chown %(u)s:%(u)s %(key)s\n"
            "chmod 600 %(key)s\n") % {"u": CENTRAL_USER, "key": CENTRAL_STATE + "/age.key"}


def central_unit_text(run, group):
    """The central vault's service, as its own installed program prints it (vault.py unit --central). Reading it
    changes nothing."""
    code, unit, err = run(f"python3 {CENTRAL_LIB}/vault.py unit --central --config {CENTRAL_CONF} "
                          f"--group {shlex.quote(group)}")
    if code != 0 or f"User={CENTRAL_USER}" not in unit or \
            f"ExecStart=/usr/bin/python3 {CENTRAL_LIB}/vault.py serve" not in unit:
        raise Stop("this kit's vault.py does not print the central vault's service (vault.py unit --central), so it "
                   "is older than the central vault: " + (err or unit or "no output").strip()[-300:])
    return unit if unit.endswith("\n") else unit + "\n"


# Asked as the hub's user, because the central vault answers that uid alone: one status line, and nothing that a key
# file holds. The socket's path is its one argument.
CENTRAL_ASK = ("import socket, sys\n"
               "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
               "s.settimeout(10)\n"
               "s.connect(sys.argv[1])\n"
               "s.sendall(b'{\"v\": 2, \"op\": \"status\"}\\n')\n"
               "data = b''\n"
               "while not data.endswith(b'\\n'):\n"
               "    chunk = s.recv(65536)\n"
               "    if not chunk:\n"
               "        break\n"
               "    data += chunk\n"
               "sys.stdout.write(data.decode())\n")


def central_status(run, hub_user, fleet):
    """The central vault's own status, asked over its socket as the hub's user: {recipient, store_recipient, fleet},
    its public keys only."""
    code, out, err = run(f"runuser -u {shlex.quote(hub_user)} -- python3 -c {shlex.quote(CENTRAL_ASK)} "
                         f"{hub.CENTRAL_SOCKET}", timeout=60)
    try:
        answer = json.loads(out.strip().splitlines()[-1]) if code == 0 and out.strip() else None
    except ValueError:
        answer = None
    if not isinstance(answer, dict) or answer.get("ok") is not True or answer.get("central") is not True:
        said = answer.get("error") if isinstance(answer, dict) and isinstance(answer.get("error"), str) else \
            (err or out or "no answer").strip()[-200:]
        raise Stop(f"the central vault does not answer the hub's user {hub_user} on {hub.CENTRAL_SOCKET}: {said}")
    if answer.get("fleet") != fleet:
        raise Stop(f"the central vault answers for another fleet than {fleet}.")
    keys = (answer.get("recipient"), answer.get("store_recipient"))
    if not all(isinstance(k, str) and hub.AGE_RECIPIENT.fullmatch(k) for k in keys):
        raise Stop("the central vault's status gives no public key.")
    return {"recipient": keys[0], "store_recipient": keys[1], "fleet": fleet}


class OtherOwner(Stop):
    """central-vault --keep-owner on a machine whose central vault holds another owner key: nothing was changed."""


def central_install(owner_key, hub_user="fleet", fleet=None, kit=None, run=None, read=None, account=None, db=None,
                    keep_owner=False):
    """The central vault on the hub's machine, as root (HUB-INSTALL.md, "The central vault"): age, its own user, the
    kit's vault.py as a root-owned program, its configuration, its own key, the store's key and the empty store, its
    service, and then its status, asked as the hub's user.

    Safe to run again, and that is how it is updated: each step reads first, the service is restarted only when
    something changed, and a key, a store or a state file that is there is never replaced (age-keygen behind
    `test -s`, and `vault.py store-init`, which keeps what it finds). The configuration is written whole on every run
    that changes it, with this run's owner key as the only one (central_config). keep_owner: the owner's app runs it
    by itself, so a vault whose configuration names another owner key, or cannot be read, is left as it is
    (OtherOwner): only the owner's own Set up takes a vault over. The fleet id is the one given, else the hub's own
    (hub_fleet). Returns {"state": "made"|"there", "recipient", "store_recipient", "fleet"}: public
    keys only, because nothing here reads or prints a key file."""
    run = run or _shell
    read = read or (lambda path: pathlib.Path(path).read_text(encoding="utf-8"))
    kit, key = kit or KIT, owner_public_key(owner_key)
    who = (account or hub_account)(hub_user)
    fleet = fleet or hub_fleet(db or os.path.join(who["home"], ".fleet", "pilot.db"))
    if not FLEET_ID.fullmatch(fleet):
        raise Stop("--fleet is this fleet's id: sixteen lowercase hex characters, as GET /ui/vault gives it.")
    try:
        program = hashlib.sha256(pathlib.Path(kit, "vault.py").read_bytes()).hexdigest()
    except OSError:
        raise Stop(f"{os.path.join(kit, 'vault.py')} is not readable, so the central vault cannot be installed.") from None
    conf = central_config(who["uid"], fleet, key)
    before = kv(run(central_reading())[1])
    try:
        current = json.loads(read(CENTRAL_CONF))
    except OSError:
        current = None
    except ValueError:
        current = False                 # there, and not readable: another owner's, for keep_owner
    if keep_owner and current is not None and not (isinstance(current, dict) and key in (current.get("owner_keys") or [])):
        raise OtherOwner("the central vault on this machine holds another owner key")
    try:
        unit_now = read(CENTRAL_UNIT)
    except OSError:
        unit_now = None
    if all(before.get(k) == "yes" for k in ("user", "age", "keygen", "age.key", "store.key", "store.age")) and \
            before.get("program") == program and current == conf and before.get("active") == "active" and \
            unit_now and central_unit_text(run, who["group"]) == unit_now:
        say(f"the central vault is in place already, kept by {CENTRAL_USER}: only {hub_user} may ask it")
        return dict(central_status(run, hub_user, fleet), state="there")
    for script, what in ((central_user_script(), f"the user {CENTRAL_USER} and the central vault's folders"),
                         (AGE_INSTALL if before.get("age") != "yes" or before.get("keygen") != "yes" else "",
                          "the age program, which locks the store and every sealed copy"),
                         (central_key_script(), "the central vault's own key")):
        if not script:
            continue
        code, out, err = run(script, timeout=AGE_INSTALL_TIME if script == AGE_INSTALL else 900)
        if code != 0:
            raise Stop(f"{what} could not be put in place: {(err or out).strip()[-300:]}")
    folder = tempfile.mkdtemp(prefix="fleet-vault-central-")
    try:
        one = os.path.join(folder, "vault.json")
        with open(one, "w", encoding="utf-8") as f:
            f.write(json.dumps(conf, indent=2) + "\n")
        # The program first: store-init and unit run from the installed copy, which no checkout can change.
        code, out, err = run("install -o root -g root -m 644 %s %s/vault.py\n"
                             "install -o root -g root -m 644 %s %s\n"
                             % (shlex.quote(os.path.join(kit, "vault.py")), CENTRAL_LIB, shlex.quote(one), CENTRAL_CONF))
        if code != 0:
            raise Stop(f"the central vault's program and configuration could not be installed: "
                       f"{(err or out).strip()[-300:]}")
        code, out, err = run(f"python3 {CENTRAL_LIB}/vault.py store-init --config {CENTRAL_CONF} --user {CENTRAL_USER}",
                             timeout=300)
        if code != 0:
            raise Stop(f"the central vault's store could not be made: {(err or out).strip()[-300:]}")
        two = os.path.join(folder, CENTRAL_SERVICE + ".service")
        with open(two, "w", encoding="utf-8") as f:
            f.write(central_unit_text(run, who["group"]))
        # A restart and not `enable --now` alone: a running vault reads a new program or a new owner key only when
        # it starts again. The restart counter is zeroed first, so what is read after it is this start's.
        code, out, err = run("install -o root -g root -m 644 %s %s\nsystemctl daemon-reload\n"
                             "systemctl enable %s >/dev/null 2>&1\n"
                             "systemctl reset-failed %s >/dev/null 2>&1 || true\n"
                             "systemctl restart %s\nsleep %d\n"
                             % (shlex.quote(two), CENTRAL_UNIT, CENTRAL_SERVICE, CENTRAL_SERVICE, CENTRAL_SERVICE,
                                VAULT_SETTLE), timeout=300)
        if code != 0:
            raise Stop(f"the central vault's service could not be started: {(err or out).strip()[-300:]}")
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    after = kv(run(central_reading())[1])
    if after.get("active") != "active" or after.get("restarts") not in ("0", "unknown"):
        raise Stop(f"the central vault is {after.get('active') or 'not running'} {VAULT_SETTLE} seconds after its "
                   f"install. Read `journalctl -u {CENTRAL_SERVICE} -n 30` on this machine: a vault that refuses its "
                   f"own configuration says so on its first line.")
    done = central_status(run, hub_user, fleet)
    say(f"the central vault runs as {CENTRAL_USER}, and only {hub_user} may ask it; its public key is "
        f"{done['recipient']}")
    return dict(done, state="made")


# ---------------------------------------------------------------- the gate of the remote MCP address (connected apps)
#
# The owner's app runs `connect on` as root over the owner's SSH, from root's own clone (ROOT_KIT), as for the central
# vault: the gate's user and group, the folder of the hub's socket, gate.py as a root-owned program, its service, and
# then Tailscale Funnel on port 443 to the gate. Each part reads first and says one line, so a second run changes
# nothing. `connect off` undoes the Funnel and the service, and keeps the user, the folder and the program. Nothing
# runs this step by itself: the hub opens its socket only when team.json says hub.connect, and until the last commit
# of the feature validate_team refuses that key.

def tailscale_argv(what, target=CONNECT_TARGET):
    """The Tailscale commands of this step, with their exact arguments. what: status, serve-status, funnel-on,
    funnel-off or funnel-status. The funnel forms are those of the CLI since Tailscale 1.52. A real Funnel took each
    of them with Tailscale 1.104.7 on 13 November 2026: on, off, and `funnel status --json`, which prints the serve
    config, also for a user that is not root."""
    return {
        "status": ["tailscale", "status", "--json"],
        "serve-status": ["tailscale", "serve", "status", "--json"],
        "funnel-on": ["tailscale", "funnel", "--bg", "--yes", f"--https={CONNECT_HTTPS}", target],
        "funnel-off": ["tailscale", "funnel", f"--https={CONNECT_HTTPS}", "off"],
        "funnel-status": ["tailscale", "funnel", "status", "--json"],
    }[what]


def connect_unit_text(name):
    """The gate's service: its own user, no state directory (the folder of the hub's socket belongs to the hub's
    user), and the network of a listener on 127.0.0.1 only. name: the hub's DNS name, which the gate holds every
    request's Host to."""
    if not isinstance(name, str) or not hub.HOST_NAME.fullmatch(name) or "." not in name:
        raise Stop(f"the hub's DNS name {name!r} is not a full name of the private network.")
    return f"""[Unit]
Description=Founderizer connect gate (forwards the hub's public MCP address to the hub's own socket)
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
User={CONNECT_USER}
Group={CONNECT_USER}
ExecStart=/usr/bin/python3 -I {CONNECT_LIB}/gate.py --name {name}
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
LimitCORE=0
ProtectProc=invisible
ProcSubset=pid
RestrictAddressFamilies=AF_UNIX AF_INET
IPAddressDeny=any
IPAddressAllow=127.0.0.1/32
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
"""


def connect_reading():
    """The shell that reads the gate's parts, so that a second run changes nothing. user= is the user's primary group,
    or empty when there is no such user; folder= is owner:group:mode."""
    return ("echo user=$(id -u %(u)s >/dev/null 2>&1 && id -gn %(u)s)\n"
            "echo folder=$(stat -c '%%U:%%G:%%a' %(state)s 2>/dev/null)\n"
            "echo program=$(sha256sum %(lib)s/gate.py 2>/dev/null | cut -d' ' -f1)\n"
            "echo started=$(cat %(lib)s/started 2>/dev/null)\n"
            "echo active=$(systemctl is-active %(svc)s 2>/dev/null || true)\n"
            "echo enabled=$(systemctl is-enabled %(svc)s 2>/dev/null || true)\n"
            "echo restarts=$(systemctl show -p NRestarts --value %(svc)s 2>/dev/null || echo unknown)\n") % {
                "u": CONNECT_USER, "state": CONNECT_STATE, "lib": CONNECT_LIB, "svc": CONNECT_SERVICE}


def connect_user_script():
    """The gate's group and user: a system user with no login, no shell and no home, each line safe to run again."""
    return ("getent group %(u)s >/dev/null 2>&1 || groupadd --system %(u)s\n"
            "id -u %(u)s >/dev/null 2>&1 || useradd --system --gid %(u)s --no-create-home --home-dir /nonexistent "
            "--shell /usr/sbin/nologin %(u)s\n") % {"u": CONNECT_USER}


def connect_folder_script(hub_user):
    """The folder of the hub's socket: the hub's user makes hub.sock in it, and the gate's group may only reach it.
    The setgid bit gives the socket that group."""
    return ("install -d -o %(h)s -g %(u)s -m 2750 %(state)s\n"
            "chown %(h)s:%(u)s %(state)s\n"
            "chmod 2750 %(state)s\n") % {"h": shlex.quote(hub_user), "u": CONNECT_USER, "state": CONNECT_STATE}


def _json_of(run, what, empty=None):
    """The JSON object that one Tailscale command prints. Stop when it fails or prints no object."""
    argv = tailscale_argv(what)
    code, out, err = run(shlex.join(argv), timeout=60)
    if code != 0:
        raise Stop(f"`{shlex.join(argv)}` failed: {(err or out or 'no output').strip()[-300:]}")
    if not out.strip() and empty is not None:
        return empty
    try:
        value = json.loads(out)
    except ValueError:
        value = None
    if not isinstance(value, dict):
        raise Stop(f"`{shlex.join(argv)}` printed no JSON object.")
    return value


CONNECT_FUNNEL_TIME = 60            # seconds for `tailscale funnel` to turn Funnel on: it waits for ever without the right
# What stops `connect on` before it changes anything, when the private network does not let this machine publish.
# The owner's app reads these words (the Mac app's ConnectGate), so a change here is a change there.
CONNECT_NO_FUNNEL = ("the policy of the private network does not give this machine the funnel attribute, so Tailscale "
                     "Funnel cannot publish the address. Nothing was changed.")
CONNECT_NO_HTTPS = ("HTTPS certificates are off for the private network, so Tailscale Funnel cannot publish the "
                    "address. Nothing was changed.")
CONNECT_FUNNEL_WAITS = (f"Tailscale did not turn Funnel on in {CONNECT_FUNNEL_TIME} seconds: the private network does "
                        f"not let this machine publish the address yet.")


def tailnet_self(run):
    """(this machine's full name on the private network, its rights) from one `tailscale status --json`. The name is
    Self.DNSName, the name of the public address. The rights are the names of Self.CapMap and Self.Capabilities,
    where the network says what this machine may do ("funnel", "https"), or None when the status has neither field
    (an older Tailscale): then nothing is known, and nothing is refused on it."""
    me = _json_of(run, "status").get("Self") or {}
    name = str(me.get("DNSName") or "").rstrip(".").lower()
    if not hub.HOST_NAME.fullmatch(name) or "." not in name:
        raise Stop("Tailscale gives this machine no full DNS name: turn on MagicDNS for the private network.")
    caps, old = me.get("CapMap"), me.get("Capabilities")
    if not isinstance(caps, dict) and not isinstance(old, list):
        return name, None
    return name, {str(c) for c in (caps if isinstance(caps, dict) else {})} | \
        {str(c) for c in (old if isinstance(old, list) else [])}


def connect_right(rights, what):
    """True when the network gives this machine the right `what` ("funnel" or "https"), by its short name or by the
    older address form (https://tailscale.com/cap/funnel)."""
    return what in rights or f"https://tailscale.com/cap/{what}" in rights


def serve_configs(conf):
    """A Tailscale serve config and every config inside it (Foreground, Services), each as a dict."""
    if not isinstance(conf, dict):
        return
    yield conf
    for key in ("Foreground", "Services"):
        inner = conf.get(key)
        if isinstance(inner, dict):
            for one in inner.values():
                yield from serve_configs(one)


def serve_targets(conf):
    """Every target of a serve config (`tailscale serve status --json`): [{"port", "where", "target", "funnel"}].
    target: a proxy address, or tcp://<address> for a TCP forward, or what else the handler serves (text, a path, a
    redirect). funnel: True when Funnel publishes that host and port."""
    out = []
    for one in serve_configs(conf):
        allow = one.get("AllowFunnel") if isinstance(one.get("AllowFunnel"), dict) else {}
        funnel = {str(k) for k, v in allow.items() if v is True}
        tcp = one.get("TCP") if isinstance(one.get("TCP"), dict) else {}
        for port, handler in tcp.items():
            if isinstance(handler, dict) and handler.get("TCPForward"):
                out.append({"port": str(port), "where": f"TCP {port}", "target": f"tcp://{handler['TCPForward']}",
                            "funnel": any(k.rpartition(":")[2] == str(port) for k in funnel)})
        web = one.get("Web") if isinstance(one.get("Web"), dict) else {}
        for hostport, server in web.items():
            handlers = server.get("Handlers") if isinstance(server, dict) else None
            for mount, h in (handlers.items() if isinstance(handlers, dict) else ()):
                h = h if isinstance(h, dict) else {}
                target = h.get("Proxy") or (h.get("Path") and "path " + str(h["Path"])) or \
                    (h.get("Text") and "text") or (h.get("Redirect") and "redirect " + str(h["Redirect"])) or "unknown"
                out.append({"port": str(hostport).rpartition(":")[2], "where": f"{hostport}{mount}",
                            "target": str(target), "funnel": str(hostport) in funnel})
        for hostport in funnel:                 # Funnel on with no handler of its own
            if not any(t["where"].startswith(hostport) for t in out):
                out.append({"port": hostport.rpartition(":")[2], "where": hostport, "target": "none", "funnel": True})
    return out


def connect_conflicts(conf):
    """What stops `connect on`: every target on port 443 other than the gate at the root path, and every other
    target that Funnel publishes (the hub keeps its socket closed while Funnel publishes anything but the gate)."""
    found = []
    for t in serve_targets(conf):
        ours = t["target"] == CONNECT_TARGET and t["where"].endswith(":443/")
        if t["port"] == str(CONNECT_HTTPS) and not ours:
            found.append(f"{t['where']} to {t['target']}")
        elif t["funnel"] and t["target"] != CONNECT_TARGET:
            found.append(f"Funnel {t['where']} to {t['target']}")
    return found


def connect_in_place(conf, name):
    """True when Funnel publishes https://<name>:443/ to the gate and to nothing else."""
    if not isinstance(conf, dict) or connect_conflicts(conf):
        return False
    tcp = (conf.get("TCP") or {}).get(str(CONNECT_HTTPS)) if isinstance(conf.get("TCP"), dict) else None
    web = (conf.get("Web") or {}).get(f"{name}:{CONNECT_HTTPS}") if isinstance(conf.get("Web"), dict) else None
    allow = conf.get("AllowFunnel") if isinstance(conf.get("AllowFunnel"), dict) else {}
    return isinstance(tcp, dict) and tcp.get("HTTPS") is True and isinstance(web, dict) and \
        web.get("Handlers") == {"/": {"Proxy": CONNECT_TARGET}} and allow.get(f"{name}:{CONNECT_HTTPS}") is True


def connect_on(hub_user="fleet", kit=None, run=None, read=None, account=None):
    """`connect on`, as root on the hub's Linux machine (the build specification of the remote MCP address, section
    7, step 2). First the checks that change nothing: the machine's name, port 443, which may hold no other Funnel or
    Serve target, and the two rights that the private network must give this machine, Funnel and HTTPS
    certificates. Without them `tailscale funnel` prints a link and waits for ever (a real Funnel test, 13 November
    2026), so the run stops here with the reason, and no part is made. Then each part, read first: the user and
    group founderizer-connect, the folder of the hub's socket, gate.py in /usr/local/lib/founderizer-connect/, the
    unit and its service, and Funnel. Returns {"name", "address", "state": "made"|"there"}."""
    run = run or _shell
    read = read or (lambda path: pathlib.Path(path).read_text(encoding="utf-8"))
    kit = kit or KIT
    (account or hub_account)(hub_user)
    name, rights = tailnet_self(run)
    conf = _json_of(run, "serve-status", empty={})
    other = connect_conflicts(conf)
    if other:
        raise Stop(f"this machine's Tailscale already publishes {other[0]}, so the connect gate is not put in place. "
                   f"Nothing was changed.")
    if rights is not None and not connect_in_place(conf, name):
        if not connect_right(rights, "funnel"):
            raise Stop(CONNECT_NO_FUNNEL)
        if not connect_right(rights, "https"):
            raise Stop(CONNECT_NO_HTTPS)
    try:
        program = hashlib.sha256(pathlib.Path(kit, "gate.py").read_bytes()).hexdigest()
    except OSError:
        raise Stop(f"{os.path.join(kit, 'gate.py')} is not readable, so the connect gate cannot be installed.") from None
    unit = connect_unit_text(name)
    # What a start that ended well leaves behind (CONNECT_LIB/started): the program and the unit that it started.
    # A run that put one of them in place and then stopped (a lost SSH connection, a reload that failed) leaves the
    # old mark or none, so the next run starts the gate again, where it would have found each part in place and
    # left an older gate running.
    mark = hashlib.sha256((program + "\n" + unit).encode()).hexdigest()
    before = kv(run(connect_reading())[1])
    made = False

    def step(script, what, timeout=120):
        code, out, err = run(script, timeout=timeout)
        if code != 0:
            raise Stop(f"{what} could not be put in place: {(err or out or 'no output').strip()[-300:]}")

    if before.get("user") == CONNECT_USER:
        say(f"the user {CONNECT_USER} is there")
    elif before.get("user"):
        raise Stop(f"the user {CONNECT_USER} is there with another group ({before['user']}). Nothing more was changed.")
    else:
        step(connect_user_script(), f"the user {CONNECT_USER}")
        made = True
        say(f"made the system user {CONNECT_USER}, with no login and no home")
    want = f"{hub_user}:{CONNECT_USER}:2750"
    if before.get("folder") == want:
        say(f"the folder {CONNECT_STATE} is there ({want})")
    else:
        step(connect_folder_script(hub_user), f"the folder {CONNECT_STATE}")
        made = True
        say(f"made the folder {CONNECT_STATE}: {hub_user} makes the hub's socket in it, {CONNECT_USER} may only reach it")
    changed = False
    if before.get("program") == program:
        say(f"the gate's program in {CONNECT_LIB} is this kit's")
    else:
        step("install -d -o root -g root -m 755 %s\ninstall -o root -g root -m 644 %s %s/gate.py\n"
             % (CONNECT_LIB, shlex.quote(os.path.join(kit, "gate.py")), CONNECT_LIB), "the gate's program")
        changed = True
        say(f"installed the gate's program in {CONNECT_LIB}, owned by root")
    try:
        unit_now = read(CONNECT_UNIT)
    except OSError:
        unit_now = None
    if unit_now == unit:
        say(f"the service {CONNECT_SERVICE} is written as it should be")
    else:
        folder = tempfile.mkdtemp(prefix="founderizer-connect-")
        try:
            one = os.path.join(folder, CONNECT_SERVICE + ".service")
            with open(one, "w", encoding="utf-8") as f:
                f.write(unit)
            # set -e: without it the step's exit code is the reload's alone, and a unit that was not written passed
            step(f"set -e\ninstall -o root -g root -m 644 {shlex.quote(one)} {CONNECT_UNIT}\n"
                 f"systemctl daemon-reload\n", f"the service {CONNECT_SERVICE}")
        finally:
            shutil.rmtree(folder, ignore_errors=True)
        changed = True
        say(f"wrote the service {CONNECT_SERVICE}")
    if not changed and before.get("active") == "active" and before.get("enabled") == "enabled" \
            and before.get("started") == mark:
        say(f"the gate runs as {CONNECT_USER} on {CONNECT_TARGET}")
    else:
        # A restart and not `enable --now` alone: a running gate reads a new program only when it starts again.
        # The reload first: a run that wrote the unit and then failed at its reload leaves the unit in place, and
        # the next run writes nothing, so it would start the gate from a unit that systemd never read. A reload that
        # fails stops the step: its exit code is the last command's, and a gate that started from the old unit would
        # get the mark of the new one.
        step("systemctl daemon-reload || exit 1\nsystemctl enable %(s)s >/dev/null 2>&1\n"
             "systemctl reset-failed %(s)s >/dev/null 2>&1 || true\n"
             "systemctl restart %(s)s\nsleep %(t)d\n" % {"s": CONNECT_SERVICE, "t": CONNECT_SETTLE},
             f"the service {CONNECT_SERVICE}", timeout=120)
        after = kv(run(connect_reading())[1])
        if after.get("active") != "active" or after.get("restarts") not in ("0", "unknown"):
            raise Stop(f"the gate is {after.get('active') or 'not running'} {CONNECT_SETTLE} seconds after its start. "
                       f"Read `journalctl -u {CONNECT_SERVICE} -n 30` on this machine.")
        step(f"set -e\nprintf '%s\\n' {mark} > {CONNECT_LIB}/started\n"
             f"chown root:root {CONNECT_LIB}/started\nchmod 644 {CONNECT_LIB}/started\n",
             "the mark of the gate's start")
        made = True
        say(f"started the gate as {CONNECT_USER} on {CONNECT_TARGET}")
    if connect_in_place(conf, name):
        say(f"Funnel publishes https://{name} to the gate already")
    else:
        try:
            step(shlex.join(tailscale_argv("funnel-on")), "Tailscale Funnel on port 443", timeout=CONNECT_FUNNEL_TIME)
        except subprocess.TimeoutExpired:
            # a status that names no rights (an older Tailscale), or a right that went after the check above
            raise Stop(CONNECT_FUNNEL_WAITS) from None
        made = True
        say(f"Funnel publishes https://{name} to the gate")
    if not connect_in_place(_json_of(run, "funnel-status", empty={}), name):
        raise Stop(f"`{shlex.join(tailscale_argv('funnel-status'))}` does not show https://{name} published to "
                   f"{CONNECT_TARGET} alone. The Tailscale policy may not give this machine the funnel attribute.")
    say(f"the remote MCP address is https://{name}/mcp")
    return {"name": name, "address": f"https://{name}/mcp", "state": "made" if made or changed else "there"}


def connect_off(run=None):
    """`connect off`, as root on the hub's machine: Funnel off on port 443 when it publishes the gate, then the
    gate's service stopped and disabled. A port 443 that holds another target is left as it is. The user, the folder
    and the program stay, so that a later `connect on` is quick. Returns {"state": "off"}."""
    run = run or _shell
    targets = serve_targets(_json_of(run, "serve-status", empty={}))
    on_443 = [t for t in targets if t["port"] == str(CONNECT_HTTPS)]
    ours = [t for t in on_443 if t["target"] == CONNECT_TARGET]
    if ours and len(ours) == len(on_443):
        argv = tailscale_argv("funnel-off")
        code, out, err = run(shlex.join(argv), timeout=60)
        if code != 0:
            raise Stop(f"`{shlex.join(argv)}` failed: {(err or out or 'no output').strip()[-300:]}")
        say("Funnel publishes nothing on port 443 now")
    elif ours:
        say("port 443 holds the gate beside another target, so Funnel is left as it is: the gate stops, and that "
            "path answers no more")
    elif on_443:
        say("port 443 holds another target, which is left as it is")
    else:
        say("Funnel publishes nothing on port 443")
    before = kv(run(connect_reading())[1])
    if before.get("active") in ("active", "activating") or before.get("enabled") == "enabled":
        code, out, err = run(f"systemctl disable --now {CONNECT_SERVICE}", timeout=120)
        if code != 0:
            raise Stop(f"the service {CONNECT_SERVICE} could not be stopped: {(err or out or 'no output').strip()[-300:]}")
        say(f"stopped and disabled the service {CONNECT_SERVICE}")
    else:
        say(f"the service {CONNECT_SERVICE} does not run")
    return {"state": "off"}


def write_team(path, team):
    """Write team.json, after hub.validate_team has taken it. Atomic: a run that stops leaves the old file."""
    try:
        hub.validate_team(team)
    except ValueError as e:
        raise Stop(f"the first team.json is not one the hub can run: {e}") from None
    new = path + ".new"
    with open(new, "w", encoding="utf-8") as f:
        json.dump(team, f, indent=2)
        f.write("\n")
    os.replace(new, path)
    return path


def read_team(path):
    """The team.json that is there, or None when it is absent or not a team.json the hub can run."""
    try:
        with open(path, encoding="utf-8") as f:
            team = json.load(f)
        hub.validate_team(team)
    except (OSError, ValueError):
        return None
    return team


def own_team(path, hub_ip, port):
    """The team.json that is there when it is this hub's own - the same hub address and the same port - and else
    None.

    The installer runs from a checkout of the Founderizer repository, and that checkout carries a team.json of its own:
    the fleet it was published from, with that fleet's hub address, machines and agents. A new hub must take none
    of it. It would otherwise start as that fleet: its git daemon listens on the address team.json gives the hub
    (fleet.py `service git`), which this machine does not have, and `agent-users` makes the users of another
    fleet's agents. So the file counts as this hub's own only when it names this machine's address and port, which
    is what a second run of the installer finds and what the first run writes."""
    team = read_team(path)
    if not team:
        return None
    hub = team.get("hub") or {}         # the hub's machine by its name in team.json: its name in Tailscale since
    same = ((team.get("addresses") or {}).get(hub.get("machine")) == hub_ip      # the hub follows that (rename_machine)
            and int(hub.get("port") or 0) == int(port))
    return team if same else None


def claimed_by(path, hub_ip, port):
    """The owner address of a hub that is set up already, for this address and port; else None. The one check that
    makes a second run of the installer change nothing."""
    owner = ((own_team(path, hub_ip, port) or {}).get("addresses") or {}).get("owner")
    return owner or None


def git(*args, folder=None, identity=False):
    """One git command. identity: a name and an address for a commit, so the machine needs no git settings of its
    own, the way the hub makes its own commits (hub.commit_kit_file).

    `safe.directory`, for this one command and no file: the installer runs as root, and from its second run on, the
    hub's bare repository and its checkout belong to the service user. Without this, git refuses them as dubious
    ownership, and a refusal reads like "there is no checkout here" - so the installer would try to clone over a
    checkout that is there and stop. The repositories are the machine's own and root may read them anyway."""
    who = ["-c", "user.name=Founderizer install", "-c", "user.email=install@fleet.invalid"] if identity else []
    done = subprocess.run(["git", "-c", "safe.directory=*", *(["-C", folder] if folder else []), *who, *args],
                          capture_output=True, text=True, stdin=subprocess.DEVNULL)
    return done.returncode, (done.stdout or "").strip(), (done.stderr or "").strip()


def repository(tree, bare, kit):
    """This hub's own repository, from the copy of Founderizer that the installer runs from.

    `bare` is the origin of the whole fleet: the hub serves it read-only over git:// (fleet-git), and every worker and
    joined server fetches its code from it. `kit` is the hub's own checkout, and it stands on the configuration ref,
    because the hub writes the owner's changes to that ref and no other (hub.CONFIG_BRANCH). Both refs start at the
    commit the installer's copy is at, so the code the hub serves is the code it runs.

    Safe to run again: a bare repository that holds both refs, or a checkout that is there, is left as it is, and
    the checkout's branch is checked either way. A bare repository without them, as a failed first push leaves it,
    is filled, by one push that writes both refs or none."""
    code, commit, err = git("rev-parse", "HEAD", folder=tree)
    if code != 0:
        raise Stop(f"{tree} is not a git checkout with a commit, so the hub's repository cannot be made from it: {err}")
    if all(git(f"--git-dir={bare}", "rev-parse", "--verify", "--quiet", f"refs/heads/{ref}")[0] == 0
           for ref in (hub.CODE_BRANCH, hub.CONFIG_BRANCH)):
        say(f"the bare repository is in {bare}")
    else:
        if git("init", "-q", "--bare", bare)[0] != 0:
            raise Stop(f"could not make the bare repository {bare}.")
        code, _, err = git("push", "-q", "--atomic", bare, f"{commit}:refs/heads/{hub.CODE_BRANCH}",
                           f"{commit}:refs/heads/{hub.CONFIG_BRANCH}", folder=tree)
        if code != 0:
            raise Stop(f"could not put the Founderizer code in {bare}: {err}")
        git("symbolic-ref", "HEAD", f"refs/heads/{hub.CODE_BRANCH}", folder=bare)
        say(f"{bare} carries {hub.CODE_BRANCH} and {hub.CONFIG_BRANCH} at {commit[:7]}")
    # `git daemon` serves a repository only when it is marked exported, and fleet.py runs it without
    # --export-all, so every machine of this fleet would be refused its clone over git:// without this one
    # empty file. It is written on a second run too, which is how a hub made before this line is repaired.
    marker = os.path.join(bare, EXPORT_OK)
    if not os.path.exists(marker):
        try:
            pathlib.Path(marker).touch()
        except OSError as e:
            raise Stop(f"could not mark {bare} as served over git://: {e}. Every machine of this fleet fetches "
                       f"its code from there.") from None
        say(f"{bare} is marked as served over git://, which is how every machine of this fleet fetches its code")
    if git("rev-parse", "--git-dir", folder=kit)[0] == 0:
        say(f"the hub's checkout is in {kit}")
    else:
        code, _, err = git("clone", "-q", "-b", hub.CONFIG_BRANCH, bare, kit)
        if code != 0:
            raise Stop(f"could not make the hub's checkout {kit}: {err}")
    on = git("symbolic-ref", "--short", "--quiet", "HEAD", folder=kit)[1]
    if on != hub.CONFIG_BRANCH:
        raise Stop(f"the hub's checkout {kit} is on {on or 'no branch'}, not the configuration ref "
                   f"{hub.CONFIG_BRANCH}. Put it on that ref with: sh {kit}/config-ref.sh {kit}")
    say(f"the hub's checkout stands on {hub.CONFIG_BRANCH}, the ref the hub writes")
    return commit


def commit_team(kit, message):
    """Commit team.json on the configuration ref and push it to this hub's own bare repository. Nothing to commit is
    no failure: that is what a second run of the installer finds."""
    if git("status", "--porcelain", "--", "team.json", folder=kit)[1] == "":
        say("team.json is as it was; nothing to commit")
        return None
    code, _, err = git("commit", "-q", "-m", message, "--", "team.json", folder=kit, identity=True)
    if code != 0:
        raise Stop(f"could not commit team.json in {kit}: {err}")
    code, _, err = git("push", "-q", "origin", f"HEAD:refs/heads/{hub.CONFIG_BRANCH}", folder=kit)
    if code != 0:
        raise Stop(f"could not push team.json to this hub's own repository: {err}")
    commit = git("rev-parse", "HEAD", folder=kit)[1]
    say(f"team.json is committed on {hub.CONFIG_BRANCH} as {commit[:7]} and pushed to the hub's own repository")
    return commit


def new_code():
    """A one-time claim code: 12 characters of hub.LINK_ALPHABET, written as three groups of four."""
    raw = "".join(secrets.choice(hub.LINK_ALPHABET) for _ in range(CODE_LENGTH))
    return raw, "-".join(raw[i:i + 4] for i in range(0, CODE_LENGTH, 4))


def normalise(text):
    """A code as the owner can have pasted it: without spaces or dashes, in capitals."""
    return re.sub(r"[\s-]", "", str(text or "")).upper()


def claim_script(hub_ip, port):
    """The script that GET /claim serves and the owner's Mac runs: it sends the code on standard input, then waits for
    the hub itself on the same port and prints the address to paste in Founderizer, whose first-run window connects
    to it at once. The code is in the environment of that line and goes to curl's standard input, never in an
    argument and never in a URL."""
    base = f"http://{hub_ip}:{port}"
    return f"""#!/bin/sh
# Claim a new Founderizer hub for this Mac. The hub printed the line that runs this script; FLEET_CLAIM holds the one-time
# code. The code goes to the hub on standard input, never in an argument or a URL.
set -eu
[ -n "${{FLEET_CLAIM:-}}" ] || {{ echo "Founderizer: no claim code. Copy the whole line from the hub's installer." >&2; exit 1; }}
code=$FLEET_CLAIM
unset FLEET_CLAIM
printf '%s' "$code" | curl -fsS -m 20 -X POST --data-binary @- {base}/claim || {{
    echo "Founderizer: this Mac could not claim the hub. Check the code and the Tailscale access rules for port {port}." >&2
    exit 1
}}
unset code
i=0
while [ "$i" -lt 60 ]; do
    if curl -fsS -m 5 -o /dev/null "{base}/ui/state"; then
        echo "Founderizer: this Mac reads the hub. Paste this address in Founderizer: {base}"
        exit 0
    fi
    sleep 5
    i=$((i + 1))
done
echo "Founderizer: the hub does not answer yet. When its install is done, paste this address in Founderizer: \
{base}" >&2
exit 1
"""


class ClaimServer(http.server.HTTPServer):
    """One request at a time, on purpose: the claim takes one code once, and handle_request must have written the
    answer before the listener closes, because the owner's script waits for it."""

    def __init__(self, where, hub_ip, port, digest, away=False):
        self.hub_ip, self.hub_port, self.digest, self.away = hub_ip, port, digest, away
        self.owner, self.wrong = None, {}
        super().__init__(where, ClaimHandler)

    def handle_error(self, request, client_address):
        """A caller that went away, or that the listener cut off (ClaimHandler.cut), is no error of the claim's. Any
        other error prints as before."""
        if isinstance(sys.exc_info()[1], OSError):
            return
        super().handle_error(request, client_address)


class ClaimHandler(http.server.BaseHTTPRequestHandler):
    """GET /claim gives the owner's script; POST /claim takes the code on the request body. Nothing else is served,
    and the code is never written to the output."""
    server_version = "fleet-hubsetup/1"
    protocol_version = "HTTP/1.0"
    timeout = 20                # a connection cannot hold the claim for longer, whatever it sends or does not send

    def setup(self):
        """One connection gets `timeout` seconds in all, and not only for each read. The listener takes one request at
        a time, so a caller that sent one byte now and then held it for as long as it liked: past the time of the
        claim, which is read between two requests, and with it a hub that the claim stopped (HubPause). Each machine
        of the private network can open that connection, a lost Mac too."""
        super().setup()
        self.limit = threading.Timer(self.timeout, self.cut)
        self.limit.daemon = True
        self.limit.start()

    def cut(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)      # a read that waits ends at once, and the request with it
        except OSError:
            pass

    def finish(self):
        self.limit.cancel()
        try:
            super().finish()
        except OSError:
            pass                # the caller is gone, or cut off: there is nobody to answer

    def log_message(self, *_args):
        return          # a request line can hold a code: this listener writes none

    def text(self, status, body):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def elsewhere(self):
        """A request that is not the claim. On a new hub nothing else comes, and it gets 404. A second claim stands
        on the port of a hub that has a fleet (`away`), and every machine and agent of that fleet calls it meanwhile.
        They read 404 as a hub that does not have this route yet, or as a thing that is gone: a session then starts
        without its credential or its tokens and says nothing, a server's job is given up, a record is dropped
        (fleet.py `session_credential` and `session_env`, server.py `Gone`). 503 is to them a hub that does not
        answer: a helper tries again, a session does not start or says what it did not get, and a server's job that
        needs the hub fails with its reason after three tries."""
        if self.server.away:
            return self.text(503, "Founderizer: the hub is away for an owner claim on its own server. It answers "
                                  "again when the claim ends.\n")
        self.text(404, "Founderizer: this is the hub installer, and it serves only the claim.\n")

    def do_GET(self):
        if self.path.split("?")[0] != "/claim":
            return self.elsewhere()
        self.text(200, claim_script(self.server.hub_ip, self.server.hub_port))

    def do_POST(self):
        src = self.client_address[0]
        if self.path.split("?")[0] != "/claim":
            return self.elsewhere()
        if self.server.owner is not None:
            return self.text(410, "Founderizer: this claim code was used. The hub has its owner.\n")
        if src == self.server.hub_ip:
            return self.text(403, "Founderizer: this address is the hub itself. Claim the hub from the Mac that will own it.\n")
        if self.server.wrong.get(src, 0) >= CLAIM_TRIES:
            return self.text(429, "Founderizer: too many wrong codes from this address.\n")
        try:
            size = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            size = 0
        given = normalise(self.rfile.read(size)[:200].decode("utf-8", "replace")) if 0 < size <= 200 else ""
        if not given or hashlib.sha256(given.encode()).hexdigest() != self.server.digest:
            self.server.wrong[src] = self.server.wrong.get(src, 0) + 1
            return self.text(403, "Founderizer: this is not the claim code. Copy the whole line from the installer again.\n")
        self.server.owner = src
        self.text(200, f"Founderizer: this Mac ({src}) is now the owner of the hub at "
                       f"http://{self.server.hub_ip}:{self.server.hub_port}\n")


def claim(hub_ip, port, wait=CLAIM_LIFE, where=None, away=False):
    """Make a one-time code, print the line for the owner's Mac, and serve the claim until that Mac sends the code
    back. Returns the address of the call that sent it. The code is kept only as its SHA-256. away: this is a second
    claim, on the port of a hub that has a fleet, and that fleet's calls get 503 meanwhile (ClaimHandler.elsewhere)."""
    raw, code = new_code()
    server = ClaimServer(where or (hub_ip, int(port)), hub_ip, int(port), hashlib.sha256(raw.encode()).hexdigest(),
                         away)
    del raw
    try:
        bound = server.hub_port = server.server_address[1]      # in a test the listener takes a free port
        say(f"the owner claim is open on http://{hub_ip}:{bound} for {int(wait / 60)} minutes.")
        print(f"""
    Paste this line in Terminal on the Mac that will own this fleet:

        FLEET_CLAIM={code} sh -c "$(curl -fsS http://{hub_ip}:{bound}/claim)"

    That Mac must be on this fleet's private network (Tailscale). The line proves its address, so the hub serves the
    owner's pages to it and to nothing else. Waiting.
""", flush=True)
        server.timeout = 1
        deadline = time.monotonic() + wait
        while server.owner is None and time.monotonic() < deadline:
            server.handle_request()
    finally:
        # However the claim ends, also when it is ended from outside: a hub that this claim stopped (HubPause) starts
        # on this address and port next, and a listener that is still open here would refuse it its port.
        server.server_close()
    owner = server.owner
    if owner is None:
        raise Stop(f"no Mac claimed this hub in {int(wait / 60)} minutes, so nothing was written. Run the installer "
                   f"again; it makes a new code.")
    if not PRIVATE.match(owner):
        say(f"the claim came from {owner}, which is not a Tailscale address (100.64.0.0/10). It is taken as the "
            f"owner, but check that the app reaches the hub over the private network.")
    say(f"the owner of this hub is the Mac at {owner}.")
    return owner


def own_user():
    """The name of the user that runs this program, or its number when the system has no name for it."""
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return str(os.getuid())


def service_call(word):
    """The command `systemctl --user <word> fleet-hub.service` and its environment, for the user that runs this
    program. The hub is a user service of the hub's own user (fleet.py `service hub`), and XDG_RUNTIME_DIR is how
    systemctl finds that user's service manager. It is this user's own folder in every case, as hub.sh's as_user
    gives it: `runuser -u fleet --` from a root login keeps root's value, /run/user/0, which this user cannot open,
    and the hub's service then reads as not active."""
    return ["systemctl", "--user", word, HUB_SERVICE], dict(os.environ, XDG_RUNTIME_DIR=f"/run/user/{os.getuid()}")


def hub_service(word, wait=60):
    """`systemctl --user <word> fleet-hub.service` (service_call): (exit code, what it said)."""
    argv, env = service_call(word)
    try:
        done = subprocess.run(argv, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=wait, env=env)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)
    return done.returncode, " ".join(((done.stdout or "") + " " + (done.stderr or "")).split())


def port_taken(hub_ip, port):
    """True when a listener holds this address and port, so that the claim's own listener cannot open there."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)     # as the claim's own listener binds
        probe.bind((hub_ip, int(port)))
    except OSError as e:
        return e.errno == errno.EADDRINUSE
    finally:
        probe.close()
    return False


def ref_tip(kit):
    """The commit at the tip of the configuration ref in the hub's own repository, read there and not from the
    checkout's copy of it; "" when it cannot be read."""
    code, out, _err = git("ls-remote", "origin", f"refs/heads/{hub.CONFIG_BRANCH}", folder=kit)
    return out.split()[0] if code == 0 and out.split() else ""


def ref_ahead(kit):
    """True when the configuration ref of the hub's own repository holds a commit that the hub's checkout `kit` does
    not have. The hub pushes each write of its own, and each release, to that ref before it moves its checkout, so
    this is a hub in the middle of one. A commit of team.json on such a checkout cannot be pushed, and the hub then
    refuses every write (hub.commit_kit_file: "lacks commits that the hub has"). False when the ref cannot be read:
    a folder that is no checkout says so at its commit."""
    tip = ref_tip(kit)
    return bool(tip) and git("merge-base", "--is-ancestor", tip, "HEAD", folder=kit)[0] != 0


def team_fault(path):
    """Why the team.json at `path` is not one the hub can run, for the line that says so; "" when it is one."""
    try:
        with open(path, encoding="utf-8") as f:
            hub.validate_team(json.load(f))
    except (OSError, ValueError) as e:
        return str(e)
    return ""


def take_back(kit, head):
    """A second claim that failed between its write of team.json and its push leaves the hub's checkout as it found
    it, at the commit `head`: a commit that it made and could not push comes off the branch, and team.json is the
    file of `head` again. The hub then starts on what it ran before, and it can write. With team.json changed and not
    committed, or with a commit that its ref does not have, it refuses every write from then on (hub.commit_kit_file).
    Nothing but team.json is touched. A commit that did reach the ref stays: that write is whole, and what failed
    came after it."""
    now, fault = git("rev-parse", "HEAD", folder=kit)[1], ""
    if now != head:
        if ref_tip(kit) == now:
            return
        code, _out, err = git("reset", "-q", "--soft", head, folder=kit)
        if code != 0:
            fault = (f"the commit that the claim made and could not push is still on the branch of {kit} "
                     f"({err[-200:]}), and the hub refuses its writes until it is gone: git -C {kit} reset --soft "
                     f"{head[:12]}")
    code, _out, err = git("checkout", "-q", head, "--", "team.json", folder=kit)
    if code != 0:
        fault = fault or f"team.json could not be put back as it was before the claim: {err[-200:]}"
    try:
        say(fault or "team.json is as it was before the claim.")
    except OSError:
        pass


# The program of a claim's guard (HubPause.watch), which runs in a session of its own. It waits for one byte on its
# standard input. The claim writes that byte when it has started the hub's service again itself. An end of the input
# with no byte means that the claim's program is gone while the hub was stopped for it: a SIGKILL, the kernel's
# out-of-memory kill, a signal in the one moment that the claim cannot catch. The guard then starts the service. It
# ignores what ends a claim, and it gives back the signals that the claim held while it started the guard.
GUARD = ("import signal, subprocess, sys\n"
         "for one in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):\n"
         "    signal.signal(one, signal.SIG_IGN)\n"
         "signal.pthread_sigmask(signal.SIG_SETMASK, set())\n"
         "if not sys.stdin.buffer.read(1):\n"
         "    subprocess.run(sys.argv[1:], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,\n"
         "                   stderr=subprocess.DEVNULL)\n")


class HubPause:
    """The hub's own service, stopped for the time of a claim that needs the address and port it holds, and started
    again in every case.

    The claim listens on the hub's own address and port (the top of this file). On a hub that runs, the hub listens
    there, and the claim's listener could not open: `OSError: [Errno 98] Address already in use` (10 November 2026).
    That is every second claim, `--reclaim` on a hub whose owner's Mac is lost or has a new address, so the one
    documented way to give a hub a new owner did not work on a hub that runs. Another port is no way out: the fleet's
    Tailscale access rules can name the hub's port alone, and the claim proves exactly that port.

    So the claim stops `fleet-hub`, the service of this user, serves the claim, and starts the service when the claim
    has ended: after team.json is written and committed, so that the hub reads the new owner at its start and refuses
    the address from before; and as well when no Mac claimed in time, when a step failed, and when the claim was ended
    from outside (Ctrl-C, a terminal that closed, a kill). When the claim's own program is gone before it could do
    that (a SIGKILL), its guard starts the service (GUARD). The hub is away for the time of the claim only. The start
    is a restart, so that a hub which something else started meanwhile reads team.json again too.

    It stops nothing when the address and port are free: a first claim, and a claim on a hub that somebody stopped
    before it, run as they always did, and it starts no hub that it did not stop. And it stops nothing that it should
    not: not when this user's `fleet-hub` does not run, so that another program holds the port; not when team.json is
    not this hub's own, because the claim would then write a new first team.json over the team of a fleet that runs;
    not without `--commit`, because the hub refuses every write while its checkout has a change that is not
    committed; and not in the middle of a write or a release of the hub's own (ref_ahead), read again after the stop.

    before: the owner's address that team.json has before the claim, or None for a first claim."""

    def __init__(self, hub_ip, port, out, commit, before=None):
        self.hub_ip, self.port, self.out, self.commit, self.before = hub_ip, int(port), out, commit, before
        self.kit, self.where = os.path.dirname(os.path.abspath(out)), f"{hub_ip}:{int(port)}"
        self.stopped, self.handlers, self.guard = False, {}, None

    def __enter__(self):
        return self

    def claim(self, wait):
        """The owner claim. When a hub that runs holds its address and port: with that hub's service stopped. A hub
        that has an owner has a fleet, whose calls to this port get 503 while the claim holds it, and no 404."""
        try:
            return claim(self.hub_ip, self.port, wait, away=bool(self.before))
        except OSError as e:
            if e.errno != errno.EADDRINUSE:
                raise
        self.stop()
        try:
            owner = claim(self.hub_ip, self.port, wait, away=True)
        except OSError as e:
            if e.errno != errno.EADDRINUSE:
                raise
            raise Stop(f"the hub's service {HUB_SERVICE} stopped, and another program took {self.where} before the "
                       f"claim could: the claim has no port. Nothing was written.") from None
        self.hold()             # the owner is known: what is left takes seconds, and nothing ends it half done
        return owner

    def stop(self):
        """Stop the hub's own service, or say why this claim cannot have the port. Every refusal before the stop
        leaves the machine as it was."""
        code, said = hub_service("is-active")
        if code != 0:
            raise Stop(f"{self.where} is in use, so the owner claim cannot listen there, and the service fleet-hub of "
                       f"the user {own_user()} does not run, so it is another program that holds it (systemctl --user "
                       f"is-active {HUB_SERVICE}: {said[-200:] or 'no answer'}). Run this as the user that runs the "
                       f"hub, or stop the program that listens on that port. Nothing changed.")
        if own_team(self.out, self.hub_ip, self.port) is None:
            raise Stop(f"a hub runs at {self.where}, and {self.out} is not a team.json of that hub that the hub can "
                       f"run ({team_fault(self.out) or 'it names another hub address or port'}). The claim would "
                       f"write a new first team.json over it, so nothing was stopped and nothing changed.")
        if not self.commit:
            raise Stop(f"a hub runs at {self.where}, and a hub refuses every write while its checkout has a change "
                       f"that is not committed. Run the claim with --commit. Nothing was stopped and nothing changed.")
        if ref_ahead(self.kit):
            raise Stop(f"the hub at {self.where} is in the middle of a write or an update of its own: its "
                       f"configuration ref holds a commit that its checkout does not have yet. Nothing was stopped "
                       f"and nothing changed. Run this again in a few minutes.")
        # A signal in the middle of the guard's start would leave a guard that nobody can tell to end, and it would
        # restart a hub that was never stopped. So the signals wait for these two lines.
        ends = {getattr(signal, name) for name in (*CLAIM_ENDS, "SIGINT")}
        held = signal.pthread_sigmask(signal.SIG_BLOCK, ends)
        try:
            self.watch()
            self.catch()
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, held)
        self.stopped = True
        code, said = hub_service("stop")
        if code != 0:
            raise Stop(f"the hub's service {HUB_SERVICE} did not stop for the claim ({said[-200:] or 'no answer'}), "
                       f"so the claim has no port. Nothing was written.")
        tries = 0
        while port_taken(self.hub_ip, self.port):
            tries += 1
            if tries >= PORT_TRIES:
                raise Stop(f"the hub's service {HUB_SERVICE} stopped, and {self.where} is still in use: another "
                           f"program listens there, so the claim has no port. Nothing was written.")
            time.sleep(1)
        if ref_ahead(self.kit):
            raise Stop(f"the hub at {self.where} was stopped in the middle of a write or an update of its own: its "
                       f"configuration ref holds a commit that its checkout does not have. Nothing was written. The "
                       f"hub runs again now, and it takes that commit back or in by itself: a write of team.json or "
                       f"of a profile at its start, another one at its next write. Run this again after that.")
        say(f"the hub's service {HUB_SERVICE} is stopped for the time of the claim, because the claim listens on the "
            f"hub's own address and port. It starts again when the claim ends, also when no Mac claims.")

    def catch(self):
        """From here on, what would end this program from outside ends the claim instead, so that __exit__ runs and
        the hub starts again. A thread that is not the main one sets nothing: no signal reaches Python code there."""
        def ended(number, _frame):
            self.hold()         # one end is enough: a second signal must not end the start of the hub
            sys.exit(f"Founderizer install stopped: the owner claim was ended from outside "
                     f"({signal.Signals(number).name}), so nothing was written.")
        for name in CLAIM_ENDS:
            try:
                self.handlers[name] = signal.signal(getattr(signal, name), ended)
            except ValueError:
                return

    def watch(self):
        """Start the guard of this claim (GUARD). A claim that cannot have one stops nothing. -I: the guard takes
        no module from the folder that the claim was started in."""
        argv, env = service_call("restart")
        try:
            self.guard = subprocess.Popen([sys.executable, "-I", "-c", GUARD, *argv], stdin=subprocess.PIPE,
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
                                          start_new_session=True)
        except OSError as e:
            raise Stop(f"the claim could not start its guard, which starts the hub's service again when the claim's "
                       f"own program is killed ({e}). Nothing was stopped and nothing changed.") from None

    def release(self):
        """Tell the guard that the hub's service is started again, or was never stopped: it ends and starts nothing."""
        guard, self.guard = self.guard, None
        if guard is None:
            return
        try:
            guard.stdin.write(b"k")
            guard.stdin.close()
            guard.wait(10)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass

    def hold(self):
        """Nothing ends this program from here to the hub's start: a commit of team.json that stops half done, or a
        hub that stays stopped, costs more than the seconds that are left."""
        for name in (*CLAIM_ENDS, "SIGINT"):
            try:
                before = signal.signal(getattr(signal, name), signal.SIG_IGN)
            except ValueError:
                return
            self.handlers.setdefault(name, before)     # the first one read is the one to give back

    def give_back(self):
        for name, before in self.handlers.items():
            if before is not None:
                signal.signal(getattr(signal, name), before)
        self.handlers = {}

    def __exit__(self, kind, _error, _trace):
        if not self.stopped:
            self.release()
            self.give_back()
            return False
        self.hold()
        code, said = hub_service("restart")     # first, and before any word: the terminal can be gone
        self.release()
        self.give_back()
        ended, fault = kind is not None and not issubclass(kind, Exception), ""
        if code != 0:
            fault = (f"the hub's service {HUB_SERVICE} did not start again ({said[-200:] or 'no answer'}). Start it "
                     f"as the user {own_user()}: systemctl --user start {HUB_SERVICE}")
        elif not ended:         # a claim that was ended from outside does not wait for the hub's answer
            for _ in range(BACK_TRIES):
                if health(self.hub_ip, self.port, timeout=3)[0]:
                    break
                time.sleep(1)
            else:
                fault = (f"the hub's service {HUB_SERVICE} was started again, and the hub does not answer at "
                         f"http://{self.where}/health yet. Look at: systemctl --user status {HUB_SERVICE}")
        if fault and kind is None:
            raise Stop(fault)
        try:
            if fault:
                print("Founderizer: " + fault, file=sys.stderr, flush=True)
            elif ended:
                say(f"the hub's service {HUB_SERVICE} is started again.")
            elif kind is None:
                owner = claimed_by(self.out, self.hub_ip, self.port)
                say(f"the hub's service {HUB_SERVICE} runs again and answers at http://{self.where}. It read "
                    f"team.json at its start: the owner is the Mac at {owner}"
                    + (", as before." if owner == self.before else ", and the address from before is refused."))
            else:
                say(f"the hub's service {HUB_SERVICE} runs again and answers at http://{self.where}.")
        except (OSError, ValueError):
            pass                # a terminal that is gone takes no word, and the hub runs all the same
        return False


def selftest(kit=KIT):
    """python3 selftest.py in the checkout: its last line, and whether it ended with 0."""
    done = subprocess.run([sys.executable, os.path.join(kit, "selftest.py")], cwd=kit, capture_output=True, text=True)
    lines = [line for line in (done.stdout or "").splitlines() if line.strip()]
    return done.returncode == 0, (lines[-1] if lines else (done.stderr or "").strip()[-300:] or "no output")


def health(hub_ip, port, timeout=10):
    """GET /health of the running hub: (True, the agents it lists) or (False, why not)."""
    request = urllib.request.Request(f"http://{hub_ip}:{port}/health", headers={"Accept": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as answer:
            body = json.loads(answer.read() or b"{}")
        return bool(body.get("ok")), ", ".join(body.get("agents") or []) or "no agent"
    except (urllib.error.URLError, OSError, ValueError) as e:
        return False, str(e)


def cmd_template(args):
    print(json.dumps(template(args.address, args.port, args.timezone or machine_timezone(), args.owner,
                              args.runtime, args.ssh_user, args.ssh_port, placed=not args.manager_later), indent=2))


def cmd_repository(args):
    repository(args.tree, args.bare, args.kit)


def cmd_claim(args):
    here = address(args.address, "the hub's address")
    already = claimed_by(args.out, here, args.port)
    if already and not args.reclaim:
        say(f"this hub belongs to the Mac at {already} already, so no code was made and nothing changed.")
        if args.commit:
            commit_team(os.path.dirname(os.path.abspath(args.out)), FIRST_COMMIT)
        return
    if args.reclaim and not already:
        # --reclaim is the word for a hub that has an owner. Without this, a claim on a port that is free took the
        # file for no team of this hub and wrote the first team.json over it: the team of a fleet, when the port or
        # the address that was given is not the hub's own (`hub.sh --reclaim` without the --port of the install).
        raise Stop(f"--reclaim gives a new owner to a hub that has one, and {args.out} is not the team.json of a hub "
                   f"at {here}:{args.port} that has an owner "
                   f"({team_fault(args.out) or 'it names another hub address or port'}). A claim would write a new "
                   f"first team.json over it, so no code was made and nothing changed. Give the hub's own address "
                   f"and port, as its team.json has them.")
    # A hub that runs holds the claim's address and port: its service makes way for the time of the claim, and it
    # starts again when this block ends, whatever ended it (HubPause). On a port that is free, nothing is stopped.
    with HubPause(here, args.port, args.out, args.commit, before=already) as pause:
        owner = pause.claim(args.wait)
        team = own_team(args.out, here, args.port) or template(args.address, args.port,
                                                               args.timezone or machine_timezone(),
                                                               runtime=args.runtime, ssh_user=args.ssh_user,
                                                               ssh_port=args.ssh_port, placed=not args.manager_later)
        team.setdefault("addresses", {})["owner"] = owner
        kit = os.path.dirname(os.path.abspath(args.out))
        # A second claim changes the team.json of a fleet. When its write, its commit or its push fails, the checkout
        # goes back to this commit (take_back), and the hub starts on what it ran before.
        head = git("rev-parse", "HEAD", folder=kit)[1] if already and args.commit else ""
        try:
            write_team(args.out, team)
            try:
                say(f"{args.out} names {owner} as the owner.")
            except OSError:
                pass            # a terminal that is gone does not undo a claim that the Mac made
            if args.commit:     # the record says which of the two it was: a second claim is not the first team.json
                commit_team(kit, OWNER_COMMIT if already else FIRST_COMMIT)
        except BaseException:
            if head:
                take_back(kit, head)
            raise


def cmd_runtime(args):
    install_runtime(args.runtime)


def cmd_agent_users(args):
    team = read_team(args.team)
    if team is None:
        raise Stop(f"{args.team} is not a team.json the hub can run, so this machine's agents are not known yet.")
    agent_users(team, args.machine or (team.get("hub") or {}).get("machine"), check=args.check)


def cmd_agent_helper(args):
    agent_helper(service_user=args.user, repo=args.repo, check=args.check)


def cmd_vault(args):
    if bool(args.owner_key) != bool(args.fleet) or (args.fleet and not FLEET_ID.fullmatch(args.fleet)):
        raise Stop("--owner-key and --fleet go together: the owner's public keys and the fleet's 16-character ID")
    vault_install(kit=args.kit or KIT, hub_address=args.hub, check=args.check, system=platform.system(),
                  owner_keys=args.owner_key, fleet=args.fleet)
    if args.swap and platform.system() == "Linux":      # only when asked: no install gives a machine the key swap
        swap_install(check=args.check)
    elif args.swap:
        say("the key swap is for a Linux server: nothing was switched on for it on this machine")


def cmd_firewall(args):
    firewall(check=args.check)


def cmd_harden(args):
    harden(service_user=args.user, check=args.check)


def cmd_tcp(args):
    hub_tcp(check=args.check)


def cmd_agent_list(args):
    """One line for each agent of this machine: its name, its runtime and its OS user. The installers read it, so
    it prints nothing else."""
    team = read_team(args.team)
    if team is None:
        raise Stop(f"{args.team} is not a team.json the hub can run, so this machine's agents are not known yet.")
    for agent in agents_of(team, args.machine or (team.get("hub") or {}).get("machine")):
        conf = team["agents"][agent]
        print(f"{agent} {conf.get('runtime') or 'claude'} {agent_user(agent, conf)}")


def cmd_fleet_id(args):
    keep_fleet_id(args.db)


def cmd_central_vault(args):
    """central-vault, as root on the hub's machine. The owner's app runs it over his SSH and reads its last line on
    standard output, which is always one JSON object: {"ok": true, "recipient", "store_recipient", "fleet"}, or
    {"ok": false, "error": "<one sentence>"} with a non-zero exit. Every line before it is progress."""
    try:
        if platform.system() != "Linux":
            raise Stop("the central vault runs on the hub's Linux server, and this machine is not one.")
        if os.geteuid() != 0:
            raise Stop(f"run it as root on the hub's machine: sudo python3 {ROOT_KIT}/hubsetup.py central-vault "
                       f"--owner-key <key>")
        if os.path.realpath(KIT) != ROOT_KIT or not root_owned(ROOT_KIT):
            raise Stop(f"the central vault is installed only from root's own clone, {ROOT_KIT}, which kit-clone makes: "
                       f"never from a folder that the hub's user can change")
        done = central_install(args.owner_key, hub_user=args.hub_user, fleet=args.fleet, keep_owner=args.keep_owner)
    except OtherOwner as e:             # the app's own install reads this line and changes nothing
        print(json.dumps({"ok": False, "owner": "other", "error": str(e)}), flush=True)
        raise
    except Stop as e:
        print(json.dumps({"ok": False, "error": str(e)}), flush=True)
        raise
    except Exception as e:          # never a trace on the last line: the app reads it as the answer
        print(json.dumps({"ok": False, "error": f"the central vault could not be installed ({type(e).__name__})."}),
              flush=True)
        raise Stop(f"the central vault could not be installed ({type(e).__name__}).") from None
    print(json.dumps({"ok": True, "recipient": done["recipient"], "store_recipient": done["store_recipient"],
                      "fleet": done["fleet"]}), flush=True)


def cmd_connect(args):
    """connect on|off, as root on the hub's Linux machine, from root's own clone. The owner's app reads its last line
    on standard output, which is always one JSON object: {"ok": true, "state", ...}, or {"ok": false, "error": "<one
    sentence>"} with a non-zero exit. Every line before it is progress."""
    try:
        if platform.system() == "Darwin":
            raise Stop("a hub on a Mac keeps the remote MCP address off in this build: Funnel on macOS needs another "
                       "Tailscale client.")
        if platform.system() != "Linux":
            raise Stop("the remote MCP address runs on the hub's Linux server, and this machine is not one.")
        if os.geteuid() != 0:
            raise Stop(f"run it as root on the hub's machine: sudo python3 {ROOT_KIT}/hubsetup.py connect {args.turn}")
        if os.path.realpath(KIT) != ROOT_KIT or not root_owned(ROOT_KIT):
            raise Stop(f"the connect gate is installed only from root's own clone, {ROOT_KIT}, which kit-clone makes: "
                       f"never from a folder that the hub's user can change")
        done = connect_on(hub_user=args.hub_user) if args.turn == "on" else connect_off()
    except Stop as e:
        print(json.dumps({"ok": False, "error": str(e)}), flush=True)
        raise
    except Exception as e:          # never a trace on the last line: the app reads it as the answer
        print(json.dumps({"ok": False, "error": f"connect {args.turn} stopped ({type(e).__name__})."}), flush=True)
        raise Stop(f"connect {args.turn} stopped ({type(e).__name__}).") from None
    print(json.dumps(dict({"ok": True}, **done)), flush=True)


def cmd_kit_clone(args):
    """kit-clone, as root on the hub's machine (kit_clone)."""
    if platform.system() != "Linux":
        raise Stop("root's own clone is for the hub's Linux server, and this machine is not one.")
    if os.geteuid() != 0:
        raise Stop("run it as root on the hub's machine: sudo python3 hubsetup.py kit-clone")
    kit_clone(hub_user=args.hub_user, source=args.source)


def cmd_check(args):
    """check: selftest.py and GET /health. With --no-selftest only GET /health, for a caller whose own last step is
    `fleet.py verify` (hub.sh): verify runs the self-test itself, so the install ran the same minute two times."""
    ok, last = (True, None) if args.no_selftest else selftest(args.kit)
    if last is not None:
        say(f"selftest.py: {last}")
    live, agents = health(address(args.address, "the hub's address"), args.port)
    say(f"the hub answers /health: {agents}" if live else f"the hub does not answer /health: {agents}")
    if not live:
        raise Stop("the hub is not serving. Look at: systemctl --user status fleet-hub")
    if not ok:
        say("selftest.py reports failures. The hub runs; tell the operator what the line above says.")


def main(argv=None):
    ap = argparse.ArgumentParser(description="The first team.json, the owner claim and the end checks of a new hub")
    sub = ap.add_subparsers(dest="what", required=True)
    rt = sub.add_parser("runtime")
    rt.add_argument("--runtime", default="claude", choices=sorted(STARTS))
    rt.set_defaults(fn=cmd_runtime)
    au = sub.add_parser("agent-users")
    au.add_argument("--team", required=True, help="the team.json that names this fleet's agents")
    au.add_argument("--machine", help="the machine of team.json whose agents get a user here; the hub's own machine "
                                      "when it is left out")
    au.add_argument("--check", action="store_true", help="say what it would make, change nothing")
    au.set_defaults(fn=cmd_agent_users)
    va = sub.add_parser("vault")
    va.add_argument("--hub", required=True, help="the hub's address, for example http://100.80.1.2:8765")
    va.add_argument("--kit", help="the checkout whose vault.py is installed; default: this one")
    va.add_argument("--owner-key", action="append", help="one public key of the owner (base64 of 65 bytes, as the "
                                                         "app shows it); with --fleet, a handover goes only to a key "
                                                         "that the owner signed a pin for")
    va.add_argument("--fleet", help="the fleet's ID, 16 lowercase hex characters")
    va.add_argument("--check", action="store_true")
    va.add_argument("--swap", action="store_true",
                    help="also switch this machine's key swap on (VAULT.md): an API key that an agent reads and that "
                         "has a site then stays out of its sessions. Without it, the step is as it was")
    va.set_defaults(fn=cmd_vault)
    fw = sub.add_parser("firewall")
    fw.add_argument("--check", action="store_true", help="say what it would do, change nothing")
    fw.set_defaults(fn=cmd_firewall)
    hd = sub.add_parser("harden")
    hd.add_argument("--user", default="fleet", help="the user that runs this machine's Founderizer services")
    hd.add_argument("--check", action="store_true", help="say what it would do, change nothing")
    hd.set_defaults(fn=cmd_harden)
    tc = sub.add_parser("tcp")
    tc.add_argument("--check", action="store_true", help="say what it would do, change nothing")
    tc.set_defaults(fn=cmd_tcp)
    ah = sub.add_parser("agent-helper")
    ah.add_argument("--user", default="fleet", help="the user that runs this machine's Founderizer services")
    ah.add_argument("--repo", help="the address of the fleet's configuration ref, which the vault helper fetches "
                                   "the broker's program from, for example git://100.80.1.2/founderizer.git")
    ah.add_argument("--check", action="store_true", help="say what it would write, change nothing")
    ah.set_defaults(fn=cmd_agent_helper)
    al = sub.add_parser("agent-list")
    al.add_argument("--team", required=True, help="the team.json that names this fleet's agents")
    al.add_argument("--machine", help="the machine of team.json whose agents are listed; the hub's own machine when "
                                      "it is left out")
    al.set_defaults(fn=cmd_agent_list)


    fid = sub.add_parser("fleet-id")
    fid.add_argument("--db", default=DB_PATH, help="the hub's own records; the default is where hub.py keeps them")
    fid.set_defaults(fn=cmd_fleet_id)
    kc = sub.add_parser("kit-clone")
    kc.add_argument("--hub-user", default="fleet", help="the user the hub runs as: its checkout holds release.json")
    kc.add_argument("--source", help="the published repository; default: " + releases.DEFAULT_UPSTREAM)
    kc.set_defaults(fn=cmd_kit_clone)
    cv = sub.add_parser("central-vault")
    cv.add_argument("--owner-key", required=True, help="the owner's public key, as their app gives it (base64)")
    cv.add_argument("--hub-user", default="fleet", help="the user the hub runs as: the one the central vault answers")
    cv.add_argument("--fleet", help="this fleet's id; default: the one in the hub's own records")
    cv.add_argument("--keep-owner", action="store_true", help="leave a central vault that another owner key holds as "
                                                               "it is: the app's own install, which takes nothing over")
    cv.set_defaults(fn=cmd_central_vault)
    cn = sub.add_parser("connect")
    cn.add_argument("turn", choices=("on", "off"), help="on: the gate, its service and Funnel; off: Funnel and the "
                                                        "service")
    cn.add_argument("--hub-user", default="fleet", help="the user the hub runs as: it makes the hub's socket")
    cn.set_defaults(fn=cmd_connect)
    one = sub.add_parser("repository")
    for what, why in (("tree", "the copy of Founderizer that this installer runs from"),
                      ("bare", "the bare repository that every machine of this fleet fetches from"),
                      ("kit", "the hub's own checkout")):
        one.add_argument("--" + what, required=True, help=why)
    one.set_defaults(fn=cmd_repository)
    for name, fn in (("template", cmd_template), ("claim", cmd_claim), ("check", cmd_check)):
        p = sub.add_parser(name)
        p.add_argument("--address", required=True, help="this machine's address on the private network")
        p.add_argument("--port", type=int, default=8765)
        p.set_defaults(fn=fn)
        if name == "check":
            p.add_argument("--kit", default=KIT)
            p.add_argument("--no-selftest", action="store_true", help="only GET /health: the caller runs verify next")
            continue
        p.add_argument("--timezone")
        p.add_argument("--runtime", default="claude", choices=sorted(STARTS))
        p.add_argument("--ssh-user", default="fleet")
        p.add_argument("--ssh-port", type=int, default=22)
        p.add_argument("--manager-later", action="store_true",
                       help="the manager has no server yet: the app that installs this hub gives it one")
        if name == "template":
            p.add_argument("--owner")
        else:
            p.add_argument("--out", required=True, help="where team.json goes")
            p.add_argument("--wait", type=float, default=CLAIM_LIFE)
            p.add_argument("--reclaim", action="store_true",
                           help="a new claim although this hub has an owner; a hub that runs is stopped for the "
                                "time of the claim and started again (with --commit, as the hub's own user)")
            p.add_argument("--commit", action="store_true", help="commit team.json on the configuration ref too")
    args = ap.parse_args(argv)
    try:
        args.fn(args)
    except Stop as e:
        print("Founderizer install stopped: " + str(e), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
