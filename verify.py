#!/usr/bin/env python3
"""Is this machine of a fleet healthy? The one check that PRODUCT.md 4.1 freezes, as `fleet.py verify`.

    python3 fleet.py verify           one readable line for each check, then READY
    python3 fleet.py verify --json    the array of 4.1 and nothing else

Each check answers {"check", "state": ok|warn|fail, "says", "fix"}, with the ids of CHECKS and nothing else, and
"command" when its fix has one. `says` and `fix` are the owner's words, because the app shows them: no file name,
path, command or internal id, "server" and never "machine", agents by the names both apps give them. The exact
command is apart, in "command": the readable form prints it in a terminal as (run: ...), and the app shows it nowhere
but gives it to an agent, in the prompt that Report a problem copies. An answer without one has the four fields alone.

A check that does not apply to this machine is absent from the array: a worker has no hub_answers and no
owner_claimed. An agent of this machine that a check does not read is named in it and warns - one team.json
keeps inactive until the owner has signed it in and activated it, and one the hub answers for that this
checkout does not name yet - because a machine never answers for its own agents in silence. Nothing failing
means READY and exit 0, because a warn is not a failure; else the failing ids and exit 1.

One check reads a file and not the machine: `team` runs the rules of hub.validate_team over this checkout's
team.json, because a hub starts on a file that does not validate and nothing else on a machine says so.

It changes nothing, ever: every command it runs reads, and it needs no root. It runs on Linux and on macOS, and
reads the places the helper's own status reading reads (lifecycle.Lifecycle.security and .runtime), so the two
never disagree - and on a Mac, where the runtime's credential is in the login Keychain and only the login session
opens it, `runtime_signed_in` is that helper's own reading (signed_in). On Linux each agent's session runs as its
own OS user, so the three checks that read a user -
services, runtime_installed and runtime_signed_in - are taken as that agent's user, and a reading this command
cannot take is named and warns, never passes (PRODUCT.md 4.1). Three lanes read this shape: the installers end with it, the app shows it as the owner's
checklist, and the support duty runs it from a heartbeat.

The recorded pilot case checker, which held this name until 2026-10-17, is verify_case.py.
"""
import ast
import email.utils
import ipaddress
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

from lifecycle import (CONFIG_BRANCH, checkout_branch, desktop_items, desktop_path, exe, runtime_fact, shown_name,
                       signed_in_path)

# PRODUCT.md 4.1: these ids and nothing else. The order is the order of the readable lines.
CHECKS = ("services", "hub_answers", "owner_claimed", "tailnet", "firewall", "clock", "disk",
          "runtime_installed", "runtime_signed_in", "desktop", "selftest", "version", "team")
OK, WARN, FAIL = "ok", "warn", "fail"

# The three checks that read an agent of this machine: its service, its runtime binary and that runtime's
# credential. They are the checks that must also name the agents of this machine they do not read - the ones
# team.json keeps inactive, and the ones it does not know yet - which `one` does for all three (and_agents).
AGENT_CHECKS = ("services", "runtime_installed", "runtime_signed_in")

# selftest.py passes whole on the code branch since 18 October 2026 (COORDINATION.md rule 5): of the five standing
# failures, two were counts the tool sets had outgrown, two were a fixture that owner API 1.12 made wrong, and two
# were defects of the hub, all of them fixed. So nothing is expected to fail and every failure is this machine's own
# or the code's. The name stays, because releases.py reads it and the release check and `fleet.py verify` must not
# drift apart about what a pass is; a baseline that ever has to be recorded again goes here.
SELFTEST_BASELINE = ()

# The checks a release cannot be judged by, because no release can pass them for the owner: signing a machine in to
# its provider is the owner's own step, in the app, and a fleet whose owner has not taken it yet is not an unhealthy
# fleet — it is a new one. releases.Update reads this, so the release gate and `fleet.py verify` agree about which
# failures are the code's. Everything else a release can break stays in the gate. A Mac's desktop is the same: its
# sign-ins, its lock and its Chrome need hands at that Mac, and no release can pass them.
OWNER_STEPS = ("runtime_signed_in", "desktop")
SELFTEST_WAIT = 300         # it waits for the hub's own timers, so about a minute on a quiet machine
# How old a helper's own sign-in reading may be and still answer for this machine: three of its reports
# (lifecycle.REPORT_EVERY), so one missed report is not an unread check. Only a Mac answers from it (signed_in).
HELPER_READING = 900
CLOCK_LIMIT = 60            # seconds: a minute, because token expiry and signatures depend on this clock
DISK_FAIL, DISK_WARN = 1.0, 5.0         # GiB free for the database and the checkouts
UFW_CONF = "/etc/ufw/ufw.conf"          # readable without root, which `ufw status` is not
TAILNET = ipaddress.ip_network("100.64.0.0/10")     # the private network every machine of a fleet is on
HUB_SERVICES = ("hub", "git")           # the hub machine's own two, beside the service of each agent on it
SERVICE_NAMES = {"hub": "the hub", "git": "the git service"}   # those two as the owner reads them

# The OS user of one agent on Linux, which hubsetup.AGENT_USER makes: its home holds that agent's session, its
# runtime credential and its vault token, at mode 700, so no other agent's user can open it. A Mac keeps one user
# for its agents (PRODUCT.md P2), and so does a machine from before the move: there this user does not exist and
# every reading is the running user's own, exactly as before.
AGENT_USER = "fleet-%s"
AGENT_PATH = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
# One reading of a runtime binary in another user's home, which shutil.which cannot make: that user's own PATH and
# then its ~/.local/bin, the two places lifecycle.exe looks in.
RUNTIME_PATH = 'command -v "$1" || { [ -x "$HOME/.local/bin/$1" ] && printf %s "$HOME/.local/bin/$1"; }'
LINGER_FILE = "/var/lib/systemd/linger/%s"      # systemd's own record of lingering, readable without root
# The fixes that several answers give, in the owner's words.
BLIND_FIX = "Run the check again as root, or as each agent's own user."
SIGN_IN_FIX = "Sign the AI provider in from the app: Settings, Servers, this server, Sign in."
FETCH_FIX = "Fetch Founderizer on this server again."
SELFTEST_FIX = "Run the self-test by hand on this server."
# The runtime's own status command, which signed_in runs: the command that reads a sign-in by hand.
SIGN_IN_STATUS = {"claude": "claude auth status", "codex": "codex login status"}
TEAM_PROBLEM = "team.json does not validate: "      # how hub.team_problem starts its line
# An address the hub keeps for a server is the fleet's team.json, and no command on a server puts it right: on a
# server `fleet.py addresses` changes that server's copy, which then stops taking the hub's (lifecycle
# .follow_config_ref), and on the hub it leaves the checkout with local changes, so the hub refuses every save of the
# app with 409 until somebody commits them (the review of 30 October 2026). So the fix is his one step, with no command.
ADDRESS_FIX = "Report a problem from the Help menu, so that the hub gets this address right."


def _run(argv, timeout=20):
    """One command that reads. It never raises: a machine that cannot run it gives a reading, not a crash."""
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return done.returncode, done.stdout, done.stderr
    except (OSError, subprocess.SubprocessError) as e:
        return 1, "", str(e)


def _fetch(url, timeout=8):
    """GET url: (code, body, headers), with code 0 and the reason in the body when it did not answer. The hub's
    /health needs no credential, so verify carries none."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        with e:
            return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)
    except (urllib.error.URLError, OSError, ValueError) as e:
        return 0, str(getattr(e, "reason", e)), {}


def _count(number, thing):
    """"1 second", "2 seconds": these lines are read by the owner in the app."""
    return f"{number:.0f} {thing}" + ("" if round(number) == 1 else "s")


def _line(text):
    """One line, because `says` and `fix` are one line each."""
    return " ".join(str(text).split())[:300]


def _said(text):
    """One line the owner reads in the app, so it is a sentence: a capital at the start (the owner, 19 October
    2026: every message he reads starts with one) and a full stop at the end, in at most 300 characters. A line
    that starts with a name this server itself uses keeps that name as it is: an address, a count or a revision.
    A command never passes here: it is in the answer's own "command", with its own spelling."""
    line = _line(text)
    head = line.split(" ", 1)[0]
    word = head[:-2] if head.endswith("'s") else head      # an agent's name in the possessive is a word too
    if word[:1].islower() and word.isalpha() and not re.fullmatch(r"[0-9a-f]{7,}", word):
        line = line[0].upper() + line[1:]
    return line if line.endswith((".", "!", "?")) else line[:299] + "."


def _cap(text):
    """A sentence after the first one of a line starts with a capital too."""
    return text[:1].upper() + text[1:]


def _names(names):
    """"Manager", "the hub and Manager", "the hub, the git service and Manager": a list as a sentence says it."""
    names = list(names)
    return ", ".join(names[:-1]) + " and " + names[-1] if len(names) > 1 else "".join(names)


def _sentences(lines):
    """One sentence for each line, each with its capital and its full stop; "" for none."""
    return " ".join(_cap(line) + "." for line in lines)


def _one(things, one, more):
    """The word that agrees with how many things a line names: "is" for one service, "are" for two."""
    return one if len(things) == 1 else more


def _label(runtime):
    """A runtime as the owner knows it, "Claude Code" or "Codex": its label (lifecycle.RUNTIMES), as the hub's own
    owner lines name it."""
    return runtime_fact(runtime, "label", runtime)


def _passwd(user):
    """(uid, home) of an OS user, or None when this machine has no such user. The password database is readable
    without root, which is how this check knows whose services and whose credential it must read."""
    try:
        found = pwd.getpwnam(str(user or ""))
    except (KeyError, TypeError):
        return None
    return found.pw_uid, found.pw_dir


def _me():
    """(the user running this check, its uid)."""
    try:
        return pwd.getpwuid(os.geteuid()).pw_name, os.geteuid()
    except KeyError:
        return os.environ.get("USER") or os.environ.get("LOGNAME") or "this user", os.geteuid()


class Verify:
    """The reading of one machine. Every reading of the outside goes through run, fetch, which, disk and now, so a
    test gives this class a healthy machine and a broken one without touching the machine it runs on."""

    def __init__(self, kit, team, hub="", *, agent=None, run=_run, fetch=_fetch, which=exe, usage=shutil.disk_usage,
                 now=time.time, platform=sys.platform, home=None, ufw_conf=UFW_CONF, selftest_wait=SELFTEST_WAIT,
                 me=None, passwd=_passwd, linger_file=LINGER_FILE):
        # conf, not team: the check whose id is `team` reads this same dict, and one name cannot be both
        self.kit, self.conf, self.hub = kit, team or {}, (hub or "").rstrip("/")
        self.run, self.fetch, self.which, self.usage, self.now = run, fetch, which, usage, now
        self.asking = None              # the id of the check being answered, for answer()
        self.platform, self.ufw_conf, self.selftest_wait = platform, ufw_conf, selftest_wait
        self.passwd, self.linger_file = passwd, linger_file
        self.me, self.my_uid = me if me else _me()      # the user running this check, and its uid
        self.ways = {}                  # user -> how this check runs one reading as it, or None: see as_user
        self.home = home or os.path.expanduser("~")
        self.addresses = self.conf.get("addresses") or {}
        self.agent = agent              # FLEET_AGENT: the name this machine answers to, when the session has one
        self.address = self.tailnet_address()
        self.named = self.machine_of(self.agent)            # the machine team.json gives that agent
        self.machine = self.named or self.machine_here()    # which machine of team.json this is, or None
        self.is_hub = self.machine == self.hub_machine() if self.machine else self.hub_service_here()
        here = [(name, conf) for name, conf in sorted((self.conf.get("agents") or {}).items())
                if self.machine and conf.get("machine") == self.machine]
        self.agents = [name for name, conf in here if conf.get("active", True) is not False]
        # The agents team.json places here and keeps inactive: a new agent until the owner signs it in and
        # activates it, and one the owner switched off. Their service, runtime and credential need not be there,
        # so the three checks of AGENT_CHECKS do not read them - but they name them, because a machine that holds
        # an agent must not answer for it in silence (and_agents).
        self.inactive = [name for name, conf in here if conf.get("active", True) is False]
        self.unknown = None             # the agents the hub knows and this checkout does not: read once, lazily

    # ---- which machine is this

    def tailscale(self):
        app = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
        return self.which("tailscale") or (app if os.path.exists(app) else None)

    def tailnet_address(self):
        """This machine's address on the private network, or None. team.json names every machine by it."""
        ts = self.tailscale()
        code, out, _ = self.run([ts, "ip", "-4"]) if ts else (1, "", "")
        first = (out or "").split("\n")[0].strip()
        return first if code == 0 and first else None

    def machine_of(self, agent):
        return ((self.conf.get("agents") or {}).get(agent) or {}).get("machine") or None

    def machine_here(self):
        """The machine of team.json whose address this machine answers to."""
        return next((name for name, ip in sorted(self.addresses.items()) if ip and ip == self.address), None)

    def hub_machine(self):
        hub = self.conf.get("hub")
        if isinstance(hub, dict):
            return hub.get("machine") or None
        host = (str(hub or "").split("//")[-1].split(":")[0] or "").strip()      # a hub given as a URL
        return next((name for name, ip in sorted(self.addresses.items()) if ip and ip == host), None)

    def hub_service_here(self):
        """A hub whose private network is down still answers for itself: its own service is written here. This is
        the reading the hub installer needs, because it runs verify before any agent session exists."""
        return os.path.exists(os.path.join(self.home, ".config", "systemd", "user", "fleet-hub.service"))

    # ---- which user holds which service, which runtime and which credential (PRODUCT.md 4.1)

    def agent_user(self, agent):
        """The OS user whose service, runtime and sign-in belong to this agent: its os_user where that user exists,
        which is every Linux machine an installer or the agent-add path made, and otherwise the user running this
        check (a Mac, and a machine from before the move)."""
        if self.platform == "darwin":
            return self.me
        user = self.os_user(agent)
        return user if self.passwd(user) else self.me

    def os_user(self, agent):
        """`fleet-<agent>`, or the OS user the agent keeps after a rename (team.json "user", owner feature
        agent_rename): the one whose home its runtime and its sign-in are in."""
        return ((self.conf.get("agents") or {}).get(agent) or {}).get("user") or AGENT_USER % agent

    def as_user(self, user, argv):
        """argv as that user, or None when this check cannot become it — and then the reading is not taken, because
        this check needs no root and changes nothing. It becomes the user itself always, any user as root, and the
        agents of this machine as the service user, which one sudoers line of the installers allows. The reading
        keeps that user's own HOME and PATH, so the runtime and its credential are read where the agent has them."""
        if not user or user == self.me:
            return list(argv)
        if user not in self.ways:
            if self.my_uid == 0:
                self.ways[user] = ["runuser", "-u", user, "--"]
            else:
                code, _out, _err = self.run(["sudo", "-n", "-u", user, "--", "true"])
                self.ways[user] = ["sudo", "-n", "-u", user, "--"] if code == 0 else None
        if self.ways[user] is None:
            return None
        uid, home = self.passwd(user) or (0, f"/home/{user}")
        return self.ways[user] + ["env", f"HOME={home}", f"XDG_RUNTIME_DIR=/run/user/{uid}",
                                  f"PATH={home}/.local/bin:{AGENT_PATH}"] + list(argv)

    def service_user(self):
        """The user that holds this machine's own two services, fleet-hub and fleet-git: the user running this
        check. None when it cannot be that user — an agent's own user never holds them, and root has a systemd
        manager of its own — and then the two are reported as unread instead of as stopped."""
        if self.me in {self.os_user(a) for a in (self.conf.get("agents") or {})}:
            return None
        if self.my_uid == 0 and not self.hub_service_here():
            return None
        return self.me

    def holders(self):
        """{the fleet service on this machine: the user that holds it, or None when this check cannot know whose it
        is}, in the order the readable lines name them: the hub's own two, then each agent's as its own user."""
        units = {name: self.service_user() for name in HUB_SERVICES
                 if self.is_hub and self.platform != "darwin"}
        units.update({name: self.agent_user(name) for name in self.agents})
        return units

    # ---- the checks, in the order of CHECKS

    def services(self):
        """The fleet's services are running and enabled: the hub's own two and one for each agent on this machine,
        each read as the user that holds it. A service this check could not read is named and warns, so a reader
        never takes it for a pass."""
        holders = self.holders()
        if not holders:
            return None
        readings = {name: (self.service(name, user) if user and self.as_user(user, ["true"]) is not None else None)
                    for name, user in holders.items()}
        blind = [n for n, r in readings.items() if r is None]
        seen = {n: r for n, r in readings.items() if r is not None}
        stopped = [n for n, (active, _) in seen.items() if active is not True]
        off = [n for n, (active, enabled) in seen.items() if active is True and enabled is not True]
        no_linger = [user for user in sorted({u for u in holders.values() if u}) if self.linger(user) is False]
        unread = (f"{_cap(self.shown(blind))} could not be read: {_one(blind, 'it belongs', 'they belong')} to "
                  f"another user of this server.") if blind else ""
        if stopped:
            return self.answer(FAIL, self.and_unread(f"{self.shown(stopped)} {_one(stopped, 'is', 'are')} not "
                                                     f"running.", unread),
                               f"Start {_one(stopped, 'it', 'them')} again on this server.",
                               self.start_command(stopped, holders))
        if off:
            return self.answer(WARN, self.and_unread(f"{self.shown(off)} {_one(off, 'is', 'are')} running, but will "
                                                     f"not start again after a reboot.", unread),
                               f"Set {_one(off, 'it', 'them')} to start with this server.",
                               self.enable_command(off, holders))
        if blind:
            return self.answer(WARN, unread, BLIND_FIX)
        if no_linger:
            late = [n for n in seen if holders[n] in no_linger]     # only the services of those users stop
            return self.answer(WARN, f"{self.shown(late)} {_one(late, 'is', 'are')} running, but will stop when "
                                     f"nobody is logged in.",
                               f"Let {_one(late, 'it', 'them')} run when nobody is logged in.",
                               "loginctl enable-linger --no-ask-password " + " ".join(no_linger))
        return self.answer(OK, f"{self.shown(seen)} {_one(seen, 'is', 'are')} running.")

    def hub_answers(self):
        """The hub answers its own address: the address every machine and the app use, never loopback."""
        if not self.is_hub:
            return None
        if not self.hub:
            return self.answer(FAIL, "The hub has no address, so no server can reach it.", ADDRESS_FIX)
        code, body, _ = self.fetch(self.hub + "/health")
        try:
            answer = json.loads(body or "{}")
        except ValueError:
            answer = {}
        if code == 200 and answer.get("ok"):
            agents = [shown_name(name) for name in answer.get("agents") or []]
            return self.answer(OK, f"The hub answers at {self.hub}"
                                   + (f" for {_names(agents)}." if agents else ", with no agent yet."))
        # What it answered instead is an HTTP code or a body, not his words: the command shows it.
        return self.answer(FAIL, f"The hub does not answer at {self.hub}.",
                           "Look at the hub's service on this server.", "systemctl --user status fleet-hub")

    def owner_claimed(self):
        """The hub has an owner address, which only the claim writes: without it no Mac reaches this fleet."""
        if not self.is_hub:
            return None
        owner = (self.addresses.get("owner") or "").strip()
        if not owner:
            return self.answer(FAIL, "No Mac has claimed this hub yet.",
                               "Run the installer's claim step again, and give its code to the app.")
        if not self.private(owner):
            return self.answer(WARN, f"Your Mac's address {owner} is not on the private network.",
                               "Check that the app reaches the hub over the private network.")
        return self.answer(OK, f"Your Mac at {owner} owns this hub.")

    def tailnet(self):
        """The private network is up and this machine answers to the address team.json gives it. The hub takes a
        name only from its own machine, so a wrong address here refuses every call this machine makes."""
        if not self.tailscale():
            return self.answer(FAIL, "Tailscale is not installed, so this server is on no private network.",
                               "Install Tailscale on this server.", "curl -fsSL https://tailscale.com/install.sh | sh")
        state = self.backend_state()
        if state != "Running" and (state is not None or not self.address):
            return self.answer(FAIL, "Tailscale is not up, so this server is on no private network.",
                               "Start Tailscale on this server.", "tailscale up --accept-dns=false")
        if not self.address:
            return self.answer(FAIL, "Tailscale gives this server no address.",
                               "Look at Tailscale's status on this server.", "tailscale status")
        want = self.addresses.get(self.named) if self.named else None
        if want and want != self.address:
            return self.answer(FAIL, f"This server is {self.address}, but the hub expects {want} and refuses its "
                                     f"calls.", ADDRESS_FIX)
        if not self.machine:
            return self.answer(FAIL, f"The hub has no server at {self.address}, this server's address.", ADDRESS_FIX)
        if state is None:       # a status that failed while Tailscale still gives its address says nothing of the network
            return self.answer(WARN, "Tailscale could not be read.", "Read Tailscale's state by hand on this server.",
                               "tailscale status")
        return self.answer(OK, f"{self.address} is up, and it is {self.machine}'s address.")

    def firewall(self):
        """The firewall is on: only the private network reaches this machine, SSH included."""
        state, _how = self.firewall_state()
        mac = self.platform == "darwin"
        if state is True:
            return self.answer(OK, "The firewall is on.")
        if state is False:
            if mac:
                return self.answer(FAIL, "The firewall is off.",
                                   "Turn the firewall on in System Settings, Network, Firewall.")
            return self.answer(FAIL, "The firewall is off.", "Turn the firewall on.", "sudo ufw --force enable")
        return self.answer(WARN, "The firewall could not be read.", "Read the firewall's state by hand on this server.",
                           "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate" if mac
                           else "sudo ufw status")

    def clock(self):
        """The clock is within a minute of true: token expiry and signatures depend on it."""
        skew, source = self.hub_skew()
        if skew is not None:
            if abs(skew) <= CLOCK_LIMIT:
                return self.answer(OK, f"The clock is {_count(abs(skew), 'second')} from {source}.")
            return self.answer(FAIL, f"The clock is {_count(abs(skew), 'second')} from {source}, over the minute "
                                     f"allowed.", *self.time_fix())
        synced = self.network_time()
        if synced is True:
            return self.answer(OK, "The clock follows network time.")
        if synced is False:
            return self.answer(FAIL, "This server does not follow network time, so its clock drifts.",
                               *self.time_fix())
        return self.answer(WARN, "The clock could not be checked against the hub or network time.", *self.time_fix())

    def disk(self):
        """The disk has room for the database and the checkouts."""
        try:
            total, _used, free = self.usage(self.kit)
        except OSError:
            return self.answer(WARN, "The free disk space could not be read.",
                               "Read the free disk space by hand on this server.", f"df -h {self.kit}")
        gib, whole = free / 2 ** 30, total / 2 ** 30
        says = f"{gib:.1f} GiB free of {whole:.0f} GiB on the disk Founderizer uses."
        if gib < DISK_FAIL:
            return self.answer(FAIL, says, "Free disk space on this server: Founderizer needs room to work.")
        if gib < DISK_WARN:
            return self.answer(WARN, says, "Free disk space soon: under 5 GiB leaves little room for updates.")
        return self.answer(OK, says)

    def runtime_installed(self):
        """The runtime binary of each agent on this machine is installed, in the home of that agent's own user."""
        if not self.agents:
            return None
        found = sorted({name: (self.runtime_of(name), *self.runtime_path(name)) for name in self.agents}.items())
        missing = [(name, rt) for name, (rt, path, read) in found if read and not path]
        blind = _sentences(f"{shown_name(name)}'s {_label(rt)} could not be read"
                           for name, (rt, _p, read) in found if not read)
        if missing:
            return self.answer(FAIL, self.and_unread(_sentences(f"{shown_name(name)} has no {_label(rt)} installed"
                                                                for name, rt in missing), blind),
                               "Install the AI provider on this server with its own installer.",
                               " && ".join(f"python3 hubsetup.py runtime --runtime {rt}"
                                           for rt in sorted({rt for _name, rt in missing})))
        if blind:
            return self.answer(WARN, blind, BLIND_FIX)
        return self.answer(OK, _sentences(f"{shown_name(name)} runs {_label(rt)}" for name, (rt, _p, _r) in found))

    def runtime_signed_in(self):
        """The runtime of each agent is signed in, read as that agent's own user, because the credential is in that
        user's home and belongs to it alone. The owner signs each agent in from the app, and only they can. On a
        Mac the credential is in the login Keychain instead, so the reading comes from the one process that can
        open it, the agent's own helper in the login session (signed_in)."""
        if not self.agents:
            return None
        readings = {}
        for name in self.agents:
            runtime = self.runtime_of(name)
            path, read = self.runtime_path(name)
            readings[name] = (runtime, self.signed_in(runtime, path, self.agent_user(name), name) if path else None,
                              read)
        rows = sorted(readings.items())
        out = [f"{shown_name(name)} is not signed in to {_label(rt)}" for name, (rt, state, read) in rows
               if read and state is False]
        unknown = [(name, rt) for name, (rt, state, read) in rows if read and state is None]
        blind = _sentences(f"{shown_name(name)}'s {_label(rt)} sign-in could not be read: it belongs to another user "
                           f"of this server" for name, (rt, _s, read) in rows if not read)
        if out:
            return self.answer(FAIL, self.and_unread(_sentences(out), blind), SIGN_IN_FIX)
        if unknown:
            why, fix, command = self.unread_signin(rt for _name, rt in unknown)
            return self.answer(WARN, self.and_unread(_sentences(f"{shown_name(name)}'s {_label(rt)} {why}"
                                                                for name, rt in unknown), blind), fix, command)
        if blind:
            return self.answer(WARN, blind, BLIND_FIX)
        return self.answer(OK, _sentences(f"{shown_name(name)} is signed in to {_label(rt)}"
                                          for name, (rt, _s, _read) in rows))

    def desktop(self):
        """A Mac's desktop can serve its agents: the items of the helper's own setup check (lifecycle.desktop_items), so
        the two never disagree. Whether Chrome answers the runtime's account can be read in the login session alone, so
        that part is the server service's reading, and a run with no such reading says nothing about it. Each line is
        what a person does at that Mac, so a failure carries no command."""
        if self.platform != "darwin" or not self.agents:
            return None
        tabs = any(runtime_fact(self.runtime_of(name), "browser_tabs") for name in self.agents)
        items = desktop_items(self.run, self.home, self.me, tabs, self.helper_browser())
        wanted = {c for name in self.agents for c in (self.conf["agents"][name].get("can") or [])}
        failed = [detail for kind, ref, state, detail in items
                  if state == "failed" and (kind != "capability" or ref in wanted)]      # as the hub's activation counts
        open_ = [detail for kind, _ref, state, detail in items if state == "not_verified" and kind == "mac"]
        if failed:
            return self.answer(FAIL, " ".join(failed)[:300], "Put this right at this Mac's own screen.")
        if open_:
            return self.answer(WARN, " ".join(open_)[:300], "Look at this at this Mac's own screen.")
        return self.answer(OK, "This Mac stays awake, logs in by itself, and Chrome is ready for its agents.")

    def selftest(self):
        """selftest.py passes against its recorded baseline, which is not zero failures (COORDINATION.md rule 5)."""
        path = os.path.join(self.kit, "selftest.py")
        if not os.path.exists(path):
            return self.answer(FAIL, "Founderizer on this server has no self-test, so it cannot check itself.",
                               FETCH_FIX)
        code, out, err = self.run([sys.executable, path], timeout=self.selftest_wait)
        summary = self.summary(out)
        by_hand = f"cd {self.kit} && python3 selftest.py"
        if not summary:
            # A run that ended without its summary line crashed; only one that never ended ran out of time (the
            # installer test of 22 October 2026 read a timeout for a self-test that had stopped on an error after 24
            # seconds). The error itself is a traceback's words, so it stays with the command, which prints it.
            said = (f"The self-test did not answer in {self.selftest_wait} seconds" if "timed out after" in (err or "")
                    else "The self-test stopped with an error")
            return self.answer(FAIL, said, SELFTEST_FIX, by_hand)
        passed, total, failed = summary
        says = f"The self-test passed {passed} of {total} checks."
        new = [name for name in failed if name not in SELFTEST_BASELINE]
        if new:
            # The failing checks' names are the self-test's own words ("... of a machine ..."): the command
            # that the answer gives prints them.
            return self.answer(FAIL, says, SELFTEST_FIX, by_hand + " -v")
        if code != 0 and not failed:
            return self.answer(FAIL, f"The self-test ended in failure, with {passed} of {total} checks passed.",
                               SELFTEST_FIX, by_hand)
        return self.answer(OK, says + (f" The {len(failed)} failures are the recorded baseline." if failed else ""))

    def version(self):
        """The checkout's revision, so the app and the release channel can compare."""
        code, out, _ = self.run(["git", "-C", self.kit, "rev-parse", "HEAD"])
        revision = (out or "").strip()
        if code != 0 or not re.fullmatch(r"[0-9a-f]{40}", revision):
            return self.answer(FAIL, "Founderizer on this server has no readable revision.", FETCH_FIX)
        branch = checkout_branch(self.kit, self.run)
        _c, out, _e = self.run(["git", "-C", self.kit, "status", "--porcelain"])
        changed = [line for line in (out or "").split("\n") if line.strip()]
        runs = f"This server runs revision {revision[:12]}"
        if branch != CONFIG_BRANCH:
            return self.answer(WARN, f"{runs}, which does not follow the fleet's updates.",
                               "Put this server back on the fleet's updates.",
                               f"sh {self.kit}/config-ref.sh {self.kit}")
        if changed:
            return self.answer(WARN, f"{runs}, with {_count(len(changed), 'changed file')} of its own.",
                               "Look at the changed files on this server.", f"git -C {self.kit} status")
        return self.answer(OK, f"{runs}.")

    def team(self):
        """The team.json of this checkout is one the hub can run: the rules of hub.validate_team, which every
        owner write of the file goes through, read here on the file the machines actually have. A hub starts on a
        file that does not validate and says so itself (PRODUCT.md 4.8), so this is the reading an installer, the
        app and the support duty get for the same file on every machine. It applies to every machine, because
        every machine of a fleet has this checkout."""
        if not self.conf:
            return self.answer(FAIL, "This server has no team file, so it knows no fleet.", FETCH_FIX)
        try:
            import hub                 # the rules only; nothing of the hub runs, and this reads no machine
        except Exception:
            return self.answer(WARN, "This server cannot read the rules of the team file.",
                               "Look at the error by hand on this server.", f"cd {self.kit} && python3 -c 'import hub'")
        problem = hub.team_problem(self.conf)
        if problem:
            # The hub's own line for the rule, in his words: the team file, and a server where the rule says machine.
            rule = problem[len(TEAM_PROBLEM):] if problem.startswith(TEAM_PROBLEM) else problem
            rule = re.sub(r"\bmachine(s?)\b", r"server\1", rule).replace("team.json", "the team file")
            own = rule.startswith("the team file ")     # "the team file needs exactly one manager"
            # A rule about the file itself is his words. Any other rule names the file's own keys, OS users and
            # values ("would share the OS user fleet-vps"), so it stays with the command, which prints it.
            return self.answer(FAIL, "The team file " + (rule[len("the team file "):] if own else
                                                         "breaks one of its rules."),
                               "Put the rule right in the team file. Until then, the app cannot change your team.",
                               None if own else f"cd {self.kit} && python3 -c 'import json, hub; "
                                                f"print(hub.team_problem(json.load(open(\"team.json\"))))'")
        machines = {a.get("machine") for a in (self.conf.get("agents") or {}).values()}
        return self.answer(OK, f"The team file is valid: {_count(len(self.conf.get('agents') or {}), 'agent')} on "
                               f"{_count(len(machines), 'server')}.")

    # ---- the readings each check needs

    def unit(self, name):
        return f"com.agentfleet.{name}" if self.platform == "darwin" else f"fleet-{name}"

    def service(self, name, user=None):
        """(active, enabled) of one fleet service, each True, False or None when it could not be read. On Linux the
        unit is in that user's own systemd manager, so the two readings are taken as it."""
        if self.platform == "darwin":
            code, out, _ = self.run(["launchctl", "print", f"gui/{os.getuid()}/com.agentfleet.{name}"])
            if code != 0:           # no such job: nothing is loaded, so nothing starts at login either
                return False, False
            return "state = running" in out, True
        unit = f"fleet-{name}.service"
        said = []
        for what in ("is-active", "is-enabled"):
            argv = self.as_user(user, ["systemctl", "--user", what, unit])
            if argv is None:
                return None, None
            _code, out, _err = self.run(argv)
            said.append((out or "").strip())
        return (said[0] == "active" if said[0] else None, said[1] == "enabled" if said[1] else None)

    def linger(self, user=None):
        """Whether that user's services survive a reboot. systemd's own record is a file that any user can read, so
        no root is needed for another user's; loginctl answers only for a user it still holds. macOS LaunchAgents
        need no lingering."""
        if self.platform == "darwin":
            return None
        user = user or self.me
        if os.path.exists(self.linger_file % user):
            return True
        found = self.passwd(user)
        code, out, _ = self.run(["loginctl", "show-user", str(found[0] if found else user), "-p", "Linger",
                                 "--value"])
        return out.strip() == "yes" if code == 0 and out.strip() else None

    def unknown_here(self):
        """The agents the hub answers for that this checkout's team.json does not name and that have an OS user on
        this machine: an agent added to this machine while its checkout stayed behind. That is how a worker could
        answer READY for its own agents and say nothing about the one it had just installed - the server service
        leaves its checkout alone while a job of its own is open, so until the sign-in ends the team.json this
        check reads does not know the agent. The hub's /health needs no credential, so this check still carries
        none; a hub that does not answer, a Mac and a machine from before the per-agent users say nothing, and a
        checkout that is behind catches up by itself."""
        if self.unknown is None:
            self.unknown = []
            if self.hub and self.platform != "darwin":
                code, body, _ = self.fetch(self.hub + "/health")
                try:
                    answer = json.loads(body or "{}") if code == 200 else {}
                except ValueError:
                    answer = {}
                named = set(self.conf.get("agents") or {})
                self.unknown = sorted(name for name in (answer.get("agents") or []) if isinstance(name, str)
                                      and name not in named and self.passwd(AGENT_USER % name))
        return self.unknown

    def user(self):
        return self.me or "the fleet user"

    def shown(self, names):
        """Fleet services as the owner knows them, in one phrase: the hub's own two by what they are, and an agent's
        by the agent's name as both apps write it ("the hub, the git service and Manager")."""
        return _names(SERVICE_NAMES[n] if n in SERVICE_NAMES and n not in self.agents else shown_name(n)
                      for n in names)

    def as_line(self, user, line):
        """One readable command, said as the user that must run it when that is not the one running this check."""
        return line if not user or user == self.me else f"sudo -u {user} {line}"

    def start_command(self, names, holders):
        """The command that starts these services again: the ones of the first one's user, as that user."""
        if self.platform == "darwin":
            return f"launchctl kickstart gui/{os.getuid()}/{self.unit(names[0])}"
        user = holders.get(names[0])
        mine = [self.unit(n) for n in names if holders.get(n) == user]
        return self.as_line(user, "systemctl --user restart " + " ".join(mine))

    def enable_command(self, names, holders):
        """The command that makes these services start again after a reboot, as start_command chooses them."""
        if self.platform == "darwin":
            return f"launchctl bootstrap gui/{os.getuid()} ~/Library/LaunchAgents/{self.unit(names[0])}.plist"
        user = holders.get(names[0])
        mine = [self.unit(n) for n in names if holders.get(n) == user]
        return self.as_line(user, "systemctl --user enable " + " ".join(mine))

    def backend_state(self):
        ts = self.tailscale()
        code, out, _ = self.run([ts, "status", "--json"]) if ts else (1, "", "")
        try:
            return json.loads(out or "{}").get("BackendState") if code == 0 else None
        except ValueError:
            return None

    def private(self, address):
        try:
            return ipaddress.ip_address(address) in TAILNET
        except ValueError:
            return False

    def firewall_state(self):
        """(on, how): the same two places the helper's own status reading reads."""
        if self.platform == "darwin":
            code, out, _ = self.run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
            if code != 0 or not out.strip():
                return None, "macOS did not answer"
            return "enabled" in out.lower(), "macOS application firewall"
        try:
            with open(self.ufw_conf, encoding="utf-8") as f:
                found = re.search(r"^ENABLED=(\w+)", f.read(), re.M)
        except OSError as e:
            return None, _line(e)
        if not found:
            return None, f"{self.ufw_conf} names no ENABLED"
        return found.group(1).lower() == "yes", "ufw"

    def hub_skew(self):
        """(seconds, source): this clock against the hub's own, which is the clock that checks this machine's
        tokens. None on the hub itself, because a clock cannot check itself."""
        if not self.hub or self.is_hub:
            return None, None
        before = self.now()
        code, _body, headers = self.fetch(self.hub + "/health")
        after = self.now()
        date = (headers or {}).get("Date")
        if not code or not date:
            return None, None
        try:
            theirs = email.utils.parsedate_to_datetime(date).timestamp()
        except (TypeError, ValueError):
            return None, None
        return (before + after) / 2 - theirs, "the hub's clock"

    def time_fix(self):
        """(the fix, its command) of a clock that is off or not read."""
        if self.platform == "darwin":
            return "Turn network time on: System Settings, General, Date & Time.", None
        return "Turn network time on for this server.", "sudo timedatectl set-ntp true"

    def network_time(self):
        code, out, _ = self.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
        return out.strip() == "yes" if code == 0 and out.strip() else None

    def runtime_of(self, agent):
        return ((self.conf.get("agents") or {}).get(agent) or {}).get("runtime") or ""

    def runtime_path(self, agent):
        """(the path of this agent's runtime binary or None, whether the reading was taken). For the user running
        this check it is lifecycle.exe, so the helper and verify look in the same two places; for another user the
        same two places read as it, because a home of mode 700 cannot be read from outside."""
        runtime, user = self.runtime_of(agent), self.agent_user(agent)
        if user == self.me:
            return self.which(runtime, self.home), True
        argv = self.as_user(user, ["sh", "-c", RUNTIME_PATH, "sh", runtime])
        if argv is None:
            return None, False
        code, out, _err = self.run(argv)
        return (((out or "").strip() or None) if code == 0 else None), True

    def login_session(self):
        """Whether this run is inside the Mac's login session, the one session that opens the login Keychain.
        `Aqua` is launchd's own name for it: an SSH session answers `Background` and a daemon `System`."""
        code, out, _ = self.run(["launchctl", "managername"])
        return (out or "").strip() == "Aqua" if code == 0 else False

    def helper_signed_in(self, agent, runtime):
        """What this machine's own helper last read about that runtime's sign-in - True or False - or None when
        there is no reading of the last HELPER_READING seconds. The helper writes it as the user whose agents
        these are, which on a Mac is the user running this check (agent_user), so the file is this user's own."""
        try:
            with open(signed_in_path(self.home, agent)) as f:
                said = json.load(f)
            at = float(said["at"])
            state = said["signed_in"][runtime]
        except (OSError, ValueError, TypeError, KeyError):
            return None
        return state if isinstance(state, bool) and self.now() - at <= HELPER_READING else None

    def helper_browser(self):
        """What this Mac's server service last read about Chrome and the runtime's account (lifecycle.browser_connected),
        or None when it has no reading of the last HELPER_READING seconds."""
        try:
            with open(desktop_path(self.home)) as f:
                said = json.load(f)
            state = said.get("browser")
            return state if isinstance(state, bool) and self.now() - float(said["at"]) <= HELPER_READING else None
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            return None

    def unread_signin(self, runtimes):
        """Why a sign-in reading of these runtimes was not taken here, and what takes it, as (the words after the
        name, the fix, its command). On a Mac outside the login session the reason is the machine's and not the
        agent's, and the answer is no command the owner can run from where the app runs this check: its helper
        reads it in that session, the one session that opens the login Keychain."""
        if self.platform == "darwin" and not self.login_session():
            return ("sign-in is in the login Keychain, out of this check's reach",
                    "Start this Mac's agents in its login session, then check again.", None)
        return ("sign-in could not be read", "Read the sign-in by hand on this server.",
                "; ".join(SIGN_IN_STATUS[rt] for rt in sorted(set(runtimes)) if rt in SIGN_IN_STATUS) or None)

    def signed_in(self, runtime, path, user=None, agent=None):
        """True, False or None, from the runtime's own status command: the reading lifecycle.Lifecycle.runtime
        makes, so the app and verify never disagree, run as the user whose credential it is. No model runs and
        nothing is written.

        A Mac answers from the helper's own reading of that same command, because there the credential is in the
        login Keychain and no run outside the login session can open it (lifecycle.Lifecycle.remember_signed_in
        says what was proved). In that session - an installer in a Terminal, the agent's own duty session - the
        command is run here as everywhere else. With neither, the reading is not taken: never a pass and never a
        failure (PRODUCT.md 4.1)."""
        if self.platform == "darwin":
            said = self.helper_signed_in(agent, runtime)
            if said is not None or not self.login_session():
                return said
        if runtime == "codex":
            argv = self.as_user(user, [path, "login", "status"])
            _code, out, err = self.run(argv) if argv else (1, "", "")
            text = (out or "") + (err or "")
            return "Logged in" in text and "Not logged in" not in text if text.strip() else None
        if runtime == "claude":
            argv = self.as_user(user, [path, "auth", "status"])
            _code, out, _err = self.run(argv) if argv else (1, "", "")
            try:
                return bool(json.loads(out or "").get("loggedIn"))
            except (ValueError, AttributeError):
                return None
        return None

    def summary(self, out):
        """(passed, of, the names it failed) from selftest.py's own last line, or None when it printed none."""
        for line in reversed([line for line in (out or "").split("\n") if line.strip()]):
            found = re.search(r"(\d+) of (\d+) checks passed\.(?:\s*FAILED:\s*(\[.*\]))?\s*$", line)
            if not found:
                continue
            try:
                failed = list(ast.literal_eval(found.group(3))) if found.group(3) else []
            except (ValueError, SyntaxError):
                failed = []
            return int(found.group(1)), int(found.group(2)), failed
        return None

    # ---- the array

    def and_unread(self, says, unread):
        """One line that names what this check found and, after it, what it could not read: a reader of a failing
        check must not take the rest of the machine for a pass either (PRODUCT.md 4.1). Both are sentences."""
        return f"{says} {unread}" if unread else says

    def answer(self, state, says, fix=None, command=None):
        """One answer of 4.1: `says` and `fix` in the owner's words, and the exact command of the fix apart, under
        "command", only when there is one, so a reader of the four fields sees every answer as before."""
        found = {"check": self.asking, "state": state, "says": _said(says), "fix": _said(fix) if fix else None}
        if command:
            found["command"] = _line(command)
        return found

    def unanswered(self):
        """The agents of this machine that a check which reads an agent does not answer for, each as (one line,
        the fix, its command or None): the ones team.json keeps inactive, and the ones it does not name at all."""
        said = []
        if self.inactive:
            said.append((f"{_names(shown_name(a) for a in self.inactive)} {_one(self.inactive, 'is', 'are')} not "
                         f"active, so {_one(self.inactive, 'it is', 'they are')} not checked here.",
                         "Open the agent in the app and finish its setup.", None))
        if self.unknown_here():
            unknown = self.unknown_here()
            said.append((f"This server does not know {_names(shown_name(a) for a in unknown)} yet, so "
                         f"{_one(unknown, 'it is', 'they are')} not checked here.",
                         "Bring this server up to date with the hub.",
                         f"git -C {self.kit} fetch origin && git -C {self.kit} merge --ff-only origin/{CONFIG_BRANCH}"))
        return said

    def and_agents(self, found):
        """One answer of a check that reads an agent, with the agents of this machine it does not answer for named
        after it. It never passes while one of them is there, and never fails for one either: both are states of a
        machine that is being set up, so they warn, and a failure of what was read stays a failure. An absent
        check is not a pass (PRODUCT.md 4.1), and neither is a check that answers for a machine's other agents."""
        said = self.unanswered()
        if not said:
            return found
        note = " ".join(line for line, _fix, _command in said)
        if found is None:
            return self.answer(WARN, note, *said[0][1:])
        fix, command = (found["fix"], found.get("command")) if found["fix"] else said[0][1:]
        return self.answer(FAIL if found["state"] == FAIL else WARN, self.and_unread(found["says"], note), fix, command)

    def one(self, name):
        """One check by its id: its answer, or None when it does not apply to this machine. The three checks that
        read an agent also name the agents of this machine they do not read, in that one answer (and_agents)."""
        self.asking = name
        found = getattr(self, name)()
        return self.and_agents(found) if name in AGENT_CHECKS else found

    def all(self):
        """The array of PRODUCT.md 4.1 for this machine, in the order of CHECKS and without what does not apply."""
        return [found for found in (self.one(name) for name in CHECKS) if found is not None]


def checks(kit, team, hub="", **how):
    """The array of PRODUCT.md 4.1 for the machine this runs on."""
    return Verify(kit, team, hub, **how).all()


def failed(results):
    """The ids that failed. A warn is not a failure."""
    return [r["check"] for r in results if r["state"] == FAIL]


def report(results):
    """The readable form: one line for each check, then READY or the failing ids. A fix with a command carries it
    at the end of its line, for whoever reads this in a terminal (INSTALL-PROMPT.md)."""
    lines = [f"  {r['state']:<4}  {r['check']}: {r['says']}" + (f"  (fix: {r['fix']})" if r["fix"] else "")
             + (f"  (run: {r['command']})" if r.get("command") else "") for r in results]
    bad = failed(results)
    return "\n".join(lines + (["READY"] if not bad else ["NOT READY: " + ", ".join(bad)]))
