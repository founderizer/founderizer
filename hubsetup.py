#!/usr/bin/env python3
"""The Python half of the Founderizer hub installer (hub.sh): the first team.json, the owner claim and the end checks.
Standard library only, and it reads no credential of a model provider.

    python3 hubsetup.py template --address IP [--port N] [--timezone Z] [--owner IP]
                                                    print the first team.json; write nothing
    python3 hubsetup.py repository --tree PATH --bare PATH --kit PATH
                                                    this hub's own repository: the bare one that every machine of the
                                                    fleet fetches from, and the hub's checkout on the configuration ref
    python3 hubsetup.py claim --address IP --out PATH [--port N] [--timezone Z] [--wait S] [--reclaim] [--commit]
                                                    the owner claim, then write team.json, and commit it on the ref
    python3 hubsetup.py runtime --runtime claude|codex
                                                    install the manager's runtime, so that the owner can sign in to
                                                    their own account from the app (it signs in to nothing itself)
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
    python3 hubsetup.py check --address IP [--port N] [--kit PATH]
                                                    the end checks on this machine: selftest.py and GET /health
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

Why the claim exists. The owner is a Tailscale address and no token (hub.py `allowed("owner")`), so a hub with the
wrong `addresses.owner` serves the owner's pages to the wrong machine, and one with none serves them to nobody. The
installer therefore proves the address before it finishes, with the same one-time code that join.sh uses, the other
way round: this machine makes the code, the owner's Mac sends it back, and the address of that call is the owner.

The claim listener holds the hub's own address and port, so the Tailscale access rules for port 8765 are proved
before the hub exists. It keeps only the code's SHA-256, never writes the code anywhere, takes one code once, and
stops as soon as it has the address. The script it serves at GET /claim then waits for the hub itself on the same
port and prints the address to paste in Founderizer, so the final check is made from the owner's own machine.

This program never signs in to Claude, Codex or Grok, never reads or writes a provider credential, and never makes
a vault entry. The customer signs in to their own account in their own session; `"vault": "none"` in the template
says that the manager holds no credential of ours.
"""
import argparse
import base64
import hashlib
import http.server
import json
import os
import pathlib
import platform
import re
import secrets
import shlex
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
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
# The manager's start policy, as team.json has it on the pilot hub, and a worker's or a lead's for the first one of a
# fleet, where the hub has no other worker to copy from (hub.py `server_agent_entry`). Both are that runtime's own
# entry of the runtime table (lifecycle.RUNTIMES "manager_access" and "first_worker"), so the installer writes the
# same start the hub would. The runtime signs in by itself, in the owner's own session: no argument of either form
# carries a key, and the installer sets none.
STARTS = {name: e["manager_access"]["start"] for name, e in lifecycle.RUNTIMES.items() if e["manager_access"]}
WORKER_STARTS = {name: e["first_worker"] for name, e in lifecycle.RUNTIMES.items() if e["first_worker"]}
FIRST_COMMIT = "The first team.json of this hub: one manager, and the owner's own Mac"
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
VAULT_FLOOR = VAULT_LIB + "/release-floor"          # the newest release whose vault.py the broker took
RESERVED_USERS = (VAULT_USER, CENTRAL_USER)         # this machine's own users, which never become an agent's
# The check itself, run by root as python3 -I -S with the root-owned copy first on its path: the revision of a
# release.json that a pinned key signed, and nothing for one that is held or that no such key signed.
VAULT_CHECK = ("import json, sys\n"
               "sys.path.insert(0, sys.argv[1])\n"
               "import releases\n"
               "try:\n"
               "    with open(sys.argv[2], encoding='utf-8') as f:\n"
               "        m = releases.check(json.load(f), releases.read_keys(sys.argv[1]))\n"
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


def template(hub_ip, port=8765, timezone=None, owner=None, runtime="claude", ssh_user="fleet", ssh_port=22):
    """The first team.json of a new hub: one manager on the hub machine, this machine's address, and the owner's Mac
    when the claim has proved it. Nothing here holds a credential: `"vault": "none"` says that the manager has no
    vault access, because its runtime is the customer's own subscription, signed in by the customer."""
    if runtime not in STARTS:
        raise Stop(f"the manager runs claude or codex, not {runtime!r}.")
    try:
        zoneinfo.ZoneInfo(timezone or "UTC")
    except (ValueError, zoneinfo.ZoneInfoNotFoundError, OSError):
        raise Stop(f"{timezone!r} is not a time zone that this machine knows.") from None
    addresses = {"hub": address(hub_ip, "the hub's address")}
    if owner is not None:
        addresses["owner"] = address(owner, "the owner's address")
    return {
        "hub": {"machine": "hub", "port": int(port)},
        "goals": {"sweep_minutes": 15, "review_hour": 9, "timezone": timezone or "UTC"},
        "addresses": addresses,
        "access": {"hub": {"ssh_user": ssh_user, "ssh_port": int(ssh_port)}},
        "agents": {
            "manager": {
                "role": "manager",
                "machine": "hub",
                "runtime": runtime,
                "can": ["shell", "web"],
                "vault": "none",
                "start": STARTS[runtime],
            },
        },
    }


def install_runtime(runtime):
    """The manager's runtime, from the vendor's own installer at the version Founderizer pins, into ~/.local/bin. It
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
    turned off keeps its user: the owner turns it on again from the app, and no install runs in between."""
    return sorted(name for name, conf in ((team or {}).get("agents") or {}).items()
                  if isinstance(conf, dict) and conf.get("machine") == machine)


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
    user and nothing else. Its only input is that one argument, and it is checked against the agent names this
    fleet can give a user of its own before any line of `user_script` runs."""
    name = r"fleet-[a-z][a-z0-9-]{1,%d}" % (USER_LIMIT - len(AGENT_USER % "") - 1)
    return ("#!/bin/sh\n"
            "# Founderizer: make the OS user of one agent, and nothing else. hubsetup.py writes this file.\n"
            "#\n"
            "# It is the one root command that this machine's service user may run (%(sudoers)s), because the\n"
            "# server service installs an agent the owner adds in the app and has no root of its own. The user it\n"
            "# makes has a locked password, no sudo, lingering on, the group %(group)s and a home of mode 700 that\n"
            "# belongs to it alone. Safe to run again: every line reads first.\n"
            "set -eu\n"
            'test "$(id -u)" = 0 || { echo "fleet-agent-user: this command needs root" >&2; exit 1; }\n'
            'test "$#" = 1 || { echo "fleet-agent-user: one argument, which is fleet-<agent>" >&2; exit 2; }\n'
            'printf %%s "$1" | grep -qxE %(name)s || { echo "fleet-agent-user: $1 is no agent user of a fleet" >&2;'
            ' exit 2; }\n'
            "u=$1\n"
            "%(script)s\n"
            'echo "fleet-agent-user: $u is the OS user of that agent"\n') % {
                "sudoers": SUDOERS, "group": AGENT_GROUP, "name": shlex.quote(name), "script": user_script("$u")}


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
            "printf '%%s\\n' \"$revision\" > %(floor)s\n"
            'want=$(sha256sum "$new" | cut -d\' \' -f1)\n'
            "have=$(sha256sum %(program)s | cut -d' ' -f1)\n"
            'if [ "$want" = "$have" ]; then\n'
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


def helper_install_script(helper_from, vault_from, sudoers_from, check_from, keys_from):
    """The shell that puts the group, the two root helpers, the sudoers file and the root-owned copies of the release
    check and the release keys in place. `visudo -c` reads the new file before it is moved in, because a file that sudo
    cannot parse takes sudo away from the whole machine."""
    return ("groupadd -f %(group)s\n"
            "install -d -o root -g root -m 755 %(lib)s\n"
            "install -o root -g root -m 644 %(check_from)s %(check)s\n"
            "install -o root -g root -m 644 %(keys_from)s %(keys)s\n"
            "install -o root -g root -m 755 %(helper_from)s %(helper)s\n"
            "install -o root -g root -m 755 %(vault_from)s %(vault)s\n"
            "visudo -cqf %(sudoers_from)s\n"
            "install -o root -g root -m 440 %(sudoers_from)s %(sudoers)s\n") % {
                "group": AGENT_GROUP, "helper_from": shlex.quote(helper_from), "helper": HELPER,
                "vault_from": shlex.quote(vault_from), "vault": VAULT_UPDATE,
                "sudoers_from": shlex.quote(sudoers_from), "sudoers": SUDOERS, "lib": VAULT_LIB,
                "check_from": shlex.quote(check_from), "check": RELEASE_CHECK,
                "keys_from": shlex.quote(keys_from), "keys": RELEASE_KEYS}


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
    try:
        there = read(HELPER) == helper and read(VAULT_UPDATE) == vault and read(SUDOERS) == sudoers and \
            read(RELEASE_CHECK) == release_check and read(RELEASE_KEYS) == release_keys
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
        three, four, five = (os.path.join(folder, name) for name in ("sudoers", "releases.py", "release-key.pub"))
        for path, text in ((one, helper), (two, vault), (three, sudoers), (four, release_check), (five, release_keys)):
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        code, out, err = run(helper_install_script(one, two, three, four, five))
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


def firewall_script():
    """The shell that sets this machine's firewall, as root. Everything on the private network comes in, SSH included,
    and nothing else does: no public SSH rule is added, and the one that the installers before 2 November 2026 added
    (comment `fleet ssh`, port 22 from anywhere) is removed. It is found by that comment, so a rule of the owner's own
    stays, and deleted from the highest number down, so that each number still names the rule it was read for. An
    active firewall keeps its defaults. A session that came in over the public address keeps going: only a new one
    is refused."""
    return ("set -eu\n"
            "active=no\n"
            "ufw status 2>/dev/null | grep -q '^Status: active' && active=yes\n"
            'if [ "$active" = no ]; then\n'
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
            'echo "removed=$removed"\n')


def firewall(check=False, run=None):
    """The firewall of this Linux machine: incoming traffic over the private network only, SSH included (the owner's
    words, 2 November 2026: SSH reachable only over Tailscale after setup). Both installers call it as their firewall
    step, and a machine that an earlier installer set up takes it as root in its own checkout, once.

    It runs only on a machine that is on the private network, because a firewall that lets SSH in over Tailscale
    alone leaves no way in to a machine that is not on it. Safe to run again. Returns "set" or "would set"."""
    run = run or _shell
    _code, out, _err = run("tailscale ip -4 2>/dev/null | head -n 1")
    ip = (out or "").strip()
    if not PRIVATE.match(ip):
        raise Stop("this machine is not on the private network (tailscale ip -4 gave none of its addresses), so its "
                   "firewall stays as it is: one that lets SSH in over the private network only would leave no way "
                   "in. Connect Tailscale, then run this again.")
    if check:
        say(f"  would let everything on tailscale0 in, deny other incoming traffic, remove the public SSH rule of an "
            f"earlier Founderizer, and turn the firewall on: SSH then reaches this machine at {ip} only")
        return "would set"
    code, out, err = run(firewall_script())
    if code != 0:
        raise Stop(f"the firewall could not be set: {(err or out).strip()[-300:]}")
    removed = kv(out).get("removed", "0")
    say(f"the firewall is on: incoming traffic over the private network only, SSH included, at {ip}"
        + (f"; the public SSH rule of an earlier Founderizer is removed ({removed} lines)" if removed != "0" else ""))
    return "set"
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


AGE_INSTALL = ("export DEBIAN_FRONTEND=noninteractive\n"
               "apt-get -o DPkg::Lock::Timeout=300 update -q </dev/null >/dev/null\n"
               "apt-get -o DPkg::Lock::Timeout=300 install -y -q --no-install-recommends age </dev/null >/dev/null\n")


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
    machine needs nothing of the owner. A broker that is already there keeps the store it has, whatever it is: the
    token of a Bitwarden project is the owner's and this installer neither reads nor replaces it.

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
    store = "the fleet's own store" if "store" in conf else "a Bitwarden project"
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
        code, out, err = run(script, timeout=900)
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


def kit_clone(hub_user="fleet", source=None, root_kit=None, checkout=None, git=None, own=None, keys=None):
    """As root on the hub's machine: root's own clone of the published repository at the revision of the hub's signed
    release.json (the section above). Returns {"revision", "version", "state": "made"|"moved"|"there"}.

    checkout: the hub's own checkout, where release.json is read (default: the hub user's ~/fleet-pilot). source: the
    published repository (releases.DEFAULT_UPSTREAM); the signature names the commit, so it is the same commit from
    any source. git, own and keys are for the tests: git_root, the step that gives the clone to root, and the release
    keys a run trusts when it cannot read them from the clone itself."""
    git, root_kit = git or git_root, root_kit or ROOT_KIT
    source = source or releases.DEFAULT_UPSTREAM
    checkout = checkout or os.path.join(hub_account(hub_user)["home"], "fleet-pilot")
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
    trusted = releases.read_keys(root_kit) if there else (keys if keys is not None else releases.read_keys(KIT))
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
        raise Stop("--owner-key is the base64 of the owner's 65-byte P-256 public key, as his app gives it.")
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
        code, out, err = run(script, timeout=900)
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

    Safe to run again: a bare repository or a checkout that is there is left as it is, and the checkout's branch is
    checked either way."""
    code, commit, err = git("rev-parse", "HEAD", folder=tree)
    if code != 0:
        raise Stop(f"{tree} is not a git checkout with a commit, so the hub's repository cannot be made from it: {err}")
    if os.path.isdir(bare):
        say(f"the bare repository is in {bare}")
    else:
        if git("init", "-q", "--bare", bare)[0] != 0:
            raise Stop(f"could not make the bare repository {bare}.")
        code, _, err = git("push", "-q", bare, f"{commit}:refs/heads/{hub.CODE_BRANCH}",
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

    def __init__(self, where, hub_ip, port, digest):
        self.hub_ip, self.hub_port, self.digest = hub_ip, port, digest
        self.owner, self.wrong = None, {}
        super().__init__(where, ClaimHandler)


class ClaimHandler(http.server.BaseHTTPRequestHandler):
    """GET /claim gives the owner's script; POST /claim takes the code on the request body. Nothing else is served,
    and the code is never written to the output."""
    server_version = "fleet-hubsetup/1"
    protocol_version = "HTTP/1.0"
    timeout = 20                # a connection that says nothing cannot hold the claim

    def log_message(self, *_args):
        return          # a request line can hold a code: this listener writes none

    def text(self, status, body):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.split("?")[0] != "/claim":
            return self.text(404, "Founderizer: this is the hub installer, and it serves only the claim.\n")
        self.text(200, claim_script(self.server.hub_ip, self.server.hub_port))

    def do_POST(self):
        src = self.client_address[0]
        if self.path.split("?")[0] != "/claim":
            return self.text(404, "Founderizer: this is the hub installer, and it serves only the claim.\n")
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


def claim(hub_ip, port, wait=CLAIM_LIFE, where=None):
    """Make a one-time code, print the line for the owner's Mac, and serve the claim until that Mac sends the code
    back. Returns the address of the call that sent it. The code is kept only as its SHA-256."""
    raw, code = new_code()
    server = ClaimServer(where or (hub_ip, int(port)), hub_ip, int(port), hashlib.sha256(raw.encode()).hexdigest())
    del raw
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
    owner = server.owner
    server.server_close()
    if owner is None:
        raise Stop(f"no Mac claimed this hub in {int(wait / 60)} minutes, so nothing was written. Run the installer "
                   f"again; it makes a new code.")
    if not PRIVATE.match(owner):
        say(f"the claim came from {owner}, which is not a Tailscale address (100.64.0.0/10). It is taken as the "
            f"owner, but check that the app reaches the hub over the private network.")
    say(f"the owner of this hub is the Mac at {owner}.")
    return owner


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
                              args.runtime, args.ssh_user, args.ssh_port), indent=2))


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
    owner = claim(here, args.port, args.wait)
    team = own_team(args.out, here, args.port) or template(args.address, args.port,
                                                           args.timezone or machine_timezone(),
                                                           runtime=args.runtime, ssh_user=args.ssh_user,
                                                           ssh_port=args.ssh_port)
    team.setdefault("addresses", {})["owner"] = owner
    write_team(args.out, team)
    say(f"{args.out} names {owner} as the owner.")
    if args.commit:
        commit_team(os.path.dirname(os.path.abspath(args.out)), FIRST_COMMIT)


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


def cmd_firewall(args):
    firewall(check=args.check)


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


def cmd_kit_clone(args):
    """kit-clone, as root on the hub's machine (kit_clone)."""
    if platform.system() != "Linux":
        raise Stop("root's own clone is for the hub's Linux server, and this machine is not one.")
    if os.geteuid() != 0:
        raise Stop("run it as root on the hub's machine: sudo python3 hubsetup.py kit-clone")
    kit_clone(hub_user=args.hub_user, source=args.source)


def cmd_check(args):
    ok, last = selftest(args.kit)
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
    va.set_defaults(fn=cmd_vault)
    fw = sub.add_parser("firewall")
    fw.add_argument("--check", action="store_true", help="say what it would do, change nothing")
    fw.set_defaults(fn=cmd_firewall)
    ah = sub.add_parser("agent-helper")
    ah.add_argument("--user", default="fleet", help="the user that runs this machine's Founderizer services")
    ah.add_argument("--repo", help="the address of the fleet's configuration ref, which the vault helper fetches "
                                   "the broker's program from, for example git://100.80.1.2/fleet-pilot.git")
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
    cv.add_argument("--owner-key", required=True, help="the owner's public key, as his app gives it (base64)")
    cv.add_argument("--hub-user", default="fleet", help="the user the hub runs as: the one the central vault answers")
    cv.add_argument("--fleet", help="this fleet's id; default: the one in the hub's own records")
    cv.add_argument("--keep-owner", action="store_true", help="leave a central vault that another owner key holds as "
                                                               "it is: the app's own install, which takes nothing over")
    cv.set_defaults(fn=cmd_central_vault)
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
            continue
        p.add_argument("--timezone")
        p.add_argument("--runtime", default="claude", choices=sorted(STARTS))
        p.add_argument("--ssh-user", default="fleet")
        p.add_argument("--ssh-port", type=int, default=22)
        if name == "template":
            p.add_argument("--owner")
        else:
            p.add_argument("--out", required=True, help="where team.json goes")
            p.add_argument("--wait", type=float, default=CLAIM_LIFE)
            p.add_argument("--reclaim", action="store_true", help="a new claim although this hub has an owner")
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
