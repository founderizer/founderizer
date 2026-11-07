#!/usr/bin/env python3
"""The Fleet server service (owner feature servers): one on each server that joined with a join code, as the OS user of
its agents (fleet on Linux, the Mac user on a Mac). Standard library only.

    python3 server.py join --hub URL --kind linux|mac [--ssh-port N]    once, from the join line (join.sh); the join
                                                                        code comes on standard input
    python3 server.py service                                           write and start this server's service again
    python3 server.py run                                               the service

The service sends the server's reading every five minutes, takes the server's jobs from the hub and updates its own
checkout when it has no job. With no job it also brings this machine's vault broker onto the vault.py of that
checkout, through the second root command the installers put in place (hubsetup.vault_program_script): a release
reaches every checkout here and never the broker's root-owned copy, so without that step a release that changed
vault.py left the broker behind while this machine reported the new revision.

Three job kinds. install: an agent. Its steps on Linux: the agent's own OS user fleet-<agent>, then its
runtime, its checkout ~fleet-<agent>/fleet-<agent>, its service and the runtime's sign-in
when that user is not signed in (Codex: a link and a code in Fleet; Claude Code: the sign-in that the hub drives for
that agent, machine_signin, which the owner finishes in the app and never in a terminal). Everything of one agent is
in that user's home at mode 700, so no other agent of the machine can read its runtime credential or its vault token. This service has no root, so the user is made by the one root command the
installers put in place (/usr/local/sbin/fleet-agent-user, hubsetup.agent_helper) and the rest is run as that user
through the one sudoers line beside it. A Mac keeps one user for its agents (PRODUCT.md P2), and so does an agent
from before the move: there every step is this service's own user, as it was. prepare: the other runtime of an agent
on this server, before the owner switches it, with the same runtime and sign-in steps, under that agent's own user;
it changes no agent, checkout or service. rename: an agent the owner gave a new name (agent_rename): its checkout, its
agent key and its service move to the new name under the OS user it already has, so it keeps its runtime and its
sign-in. The service runs no AI session and reads no secret. Its key is
~/.fleet/server.key (mode 600); the hub keeps only its SHA-256, and it opens only this server's routes.
"""
import argparse
import contextlib
import hashlib
import json
import os
import plistlib
import pwd
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

import lifecycle
import onboard
from lifecycle import shown_name      # a name as the apps show it

KIT = os.path.dirname(os.path.abspath(__file__))
HOME = os.path.expanduser("~")
FLEET = os.path.join(HOME, ".fleet")
KEY_FILE = os.path.join(FLEET, "server.key")
CONF_FILE = os.path.join(FLEET, "server.json")
LABEL, UNIT = "com.agentfleet.server", "fleet-server.service"
REPORT_EVERY = 300              # seconds between readings
# The features of this service that the hub reads: it reports its status while a job runs too (beating), so the
# hub tells a long step of a live server from a server that stopped, with no clock of its own (plan C2).
JOB_HEARTBEAT = "job_heartbeat"
NAMES_FEATURE = "server_names"  # it takes a new name from the hub (adopt): hub.NAMES_FEATURE
KEY_FEATURE = "rename_key"      # its rename job moves the agent's key file (carry_key): hub.KEY_FEATURE
INSTALL_KEY = "install_key"     # its install job registers the new agent's key (key_step): hub.INSTALL_KEY
POLL = 5                        # seconds between looks for a job
CHROME_SETTLES = 30             # seconds from Chrome's start to the reading that says whether it answers
SIGN_IN_WAIT = 900              # seconds a sign-in may take
HELPER_WAIT = 120               # seconds for a new agent's own helper to reach the hub, before its sign-in can start
PATH_ENV = os.pathsep.join([os.path.join(HOME, ".local", "bin"), "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin",
                            "/usr/sbin", "/sbin"])
# The runtimes this service installs and signs an agent in to, with the word the owner reads for each
# (lifecycle.RUNTIMES): a runtime the fleet drives no sign-in for is none of this service's business.
LABELS = {name: e["label"] for name, e in lifecycle.RUNTIMES.items() if e["sign_in"]}
NAME = re.compile(r"[a-z][a-z0-9-]{1,30}")
# One agent's own OS user (hubsetup.AGENT_USER), the one root command that makes it (hubsetup.HELPER), and the PATH
# of a command run as that user: its own ~/.local/bin, then the machine's.
AGENT_USER = "fleet-%s"
USER_NAME = re.compile(r"fleet-[a-z][a-z0-9-]{1,25}")       # a user a job names: an agent keeps it after a rename
AGENT_HELPER = "/usr/local/sbin/fleet-agent-user"
AGENT_PATH = os.pathsep.join(["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"])
# This machine's vault broker: the root-owned copy of vault.py it runs (hubsetup.VAULT_LIB), and the other root
# command the installers put in place, which brings that copy onto the vault.py of the fleet's configuration ref
# (hubsetup.VAULT_UPDATE). A release reaches every checkout here and never that copy, so this service asks for it.
VAULT_PROGRAM = "/usr/local/lib/fleet-vault/vault.py"
VAULT_HELPER = "/usr/local/sbin/fleet-vault-program"
VAULT_EVERY = 600               # seconds before a try that did not settle it is made again
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


class StepFailed(Exception):
    def __init__(self, step, detail, timed_out=False):
        super().__init__(detail)
        self.step = step
        self.timed_out = timed_out      # only the owner's own step did not come in time (UI-API.md, `timed_out`)


def failed(step, words, raw=None):
    """A step that failed, in the words he reads on the server's page. The system's own text (a command's error, a
    status number) goes to this service's log, never to his screen (UX fix round 3)."""
    if raw:
        print(f"{step or 'job'}: {ANSI.sub('', str(raw).strip())[-2000:]}", file=sys.stderr, flush=True)
    return StepFailed(step, words)


class Gone(Exception):
    """The hub ended the job (the owner removed the server): stop working on it."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an answer, never a second request: the server key must not go to another place."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Hub:
    def __init__(self, url, key=None):
        self.url, self.key = url.rstrip("/"), key
        self.headers = {}               # tests: the caller's test address

    def call(self, method, path, body=None, timeout=30):
        headers = dict(self.headers, **{"Accept": "application/json", "X-Fleet-Client": "fleet-server/1"})
        if self.key:
            headers["Authorization"] = "Bearer " + self.key
        data = None
        if body is not None:
            data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
        request = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
        try:
            with opener.open(request, timeout=timeout) as answer:
                return answer.status, json.loads(answer.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except ValueError:
                return e.code, {}
        except (urllib.error.URLError, OSError, ValueError) as e:
            return 0, {"error": str(e)}


def account(user):
    """(uid, home) of an OS user, or None when this machine has no such user."""
    try:
        found = pwd.getpwnam(str(user or ""))
    except (KeyError, TypeError):
        return None
    return found.pw_uid, found.pw_dir


def die(text):
    print("Founderizer join stopped: " + text, file=sys.stderr)
    sys.exit(1)


def tail(text, n=200):
    return ANSI.sub("", (text or "").strip())[-n:]


def program_sha256(path):
    """The SHA-256 of a file, or None when it cannot be read. The broker's installed program is root-owned and
    world-readable, so this service reads it with no root at all."""
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def server_key(make=False):
    """This server's key, or None. make: a new key when it has none (256 random bits, mode 600)."""
    try:
        with open(KEY_FILE, encoding="utf-8") as f:
            key = f.read().strip()
        if key:
            return key
    except OSError:
        pass
    if not make:
        return None
    os.makedirs(FLEET, mode=0o700, exist_ok=True)
    os.chmod(FLEET, 0o700)
    key, new = secrets.token_urlsafe(32), KEY_FILE + ".new"
    fd = os.open(new, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(key + "\n")
    os.replace(new, KEY_FILE)
    return key


def load_conf():
    try:
        with open(CONF_FILE, encoding="utf-8") as f:
            conf = json.load(f)
        return conf if isinstance(conf, dict) and NAME.fullmatch(str(conf.get("name"))) else None
    except (OSError, ValueError):
        return None


def save_conf(conf):
    os.makedirs(FLEET, mode=0o700, exist_ok=True)
    with open(CONF_FILE + ".new", "w", encoding="utf-8") as f:
        json.dump(conf, f, indent=2)
    os.replace(CONF_FILE + ".new", CONF_FILE)


def cmd_join(args):
    """The join: the server key, POST /join with the code from standard input, then the server service. The same
    server again (the line once more after a failed step) is a repeat for the hub."""
    code = sys.stdin.readline().strip()
    if not code:
        die("No join code. Copy the whole line from Founderizer: Settings, Servers, Add server.")
    key = server_key(make=True)
    status, answer = Hub(args.hub).call("POST", "/join", {
        "code": code, "key_sha256": hashlib.sha256(key.encode()).hexdigest(), "kind": args.kind,
        "user": pwd.getpwuid(os.getuid()).pw_name, "ssh_port": args.ssh_port})
    if status != 200:
        die(answer.get("error") or f"The hub did not answer ({status}). Check the private network, then run the line "
                                   f"again.")
    name = answer.get("server")
    if not NAME.fullmatch(str(name)) or not re.fullmatch(r"http://[0-9.:\[\]a-f]+", str(answer.get("hub"))):
        die("The hub gave an answer that Founderizer cannot use.")
    conf = {"name": name, "hub": answer["hub"], "repo": answer.get("repo")}
    if re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", str(answer.get("reboot_time"))):
        conf["reboot_time"] = answer["reboot_time"]     # join.sh: the fleet patch policy at this server's own time
    save_conf(conf)
    again = " (it had joined already)" if answer.get("replayed") else ""
    print(f"Founderizer: this machine is the server {name}{again}", flush=True)
    install_service()
    print("Founderizer: the server service runs", flush=True)
    if args.kind == "mac" and answer.get("extension", True):    # a sitting for ChatGPT alone shows no Claude prompt
        lifecycle.offer_extension(HOME)
        print("Founderizer: Claude's extension: Chrome fetches it at its next start and asks once to enable it", flush=True)


def install_service(run=subprocess.run, platform=sys.platform):
    """Write this server's service and start it again: a LaunchAgent on a Mac, a systemd user service on Linux."""
    argv = [sys.executable, os.path.join(KIT, "server.py"), "run"]
    os.makedirs(FLEET, mode=0o700, exist_ok=True)
    if platform == "darwin":
        folder = os.path.join(HOME, "Library", "LaunchAgents")
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, LABEL + ".plist")
        with open(path, "wb") as f:
            plistlib.dump({"Label": LABEL, "ProgramArguments": argv, "WorkingDirectory": KIT,
                           "EnvironmentVariables": {"PATH": PATH_ENV}, "RunAtLoad": True, "KeepAlive": True,
                           "ThrottleInterval": 10, "ProcessType": "Background",
                           "StandardOutPath": os.path.join(FLEET, "server.log"),
                           "StandardErrorPath": os.path.join(FLEET, "server.err")}, f)
        domain = f"gui/{os.getuid()}"
        run(["launchctl", "bootout", f"{domain}/{LABEL}"], capture_output=True)
        started = run(["launchctl", "bootstrap", domain, path], capture_output=True, text=True)
        if started.returncode != 0:
            die("The server service did not start: " + tail(started.stderr))
        return path

    def quote(x):
        return json.dumps(x.replace("%", "%%"))
    folder = os.path.join(HOME, ".config", "systemd", "user")
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, UNIT)
    with open(path, "w", encoding="utf-8") as f:
        f.write("[Unit]\nDescription=Founderizer server service\nAfter=network-online.target\n[Service]\nType=simple\n"
                "WorkingDirectory=" + KIT.replace("%", "%%").replace(" ", r"\x20") + "\nEnvironment=" +
                quote("PATH=" + PATH_ENV) + "\nExecStart=" + " ".join(map(quote, argv)) + "\nRestart=always\n"
                "RestartSec=5\nKillMode=process\nTimeoutStopSec=15\n[Install]\nWantedBy=default.target\n")
    for step in (["systemctl", "--user", "daemon-reload"], ["systemctl", "--user", "enable", UNIT],
                 ["systemctl", "--user", "restart", UNIT]):
        done = run(step, capture_output=True, text=True)
        if done.returncode != 0:
            die("The server service did not start: " + tail(done.stderr))
    return path


def cmd_finish(args):
    """The installer's last press on a new Mac: the hub goes on with this Mac's setup, now or after its restart."""
    conf, key = load_conf(), server_key()
    if not conf or not key:
        die("This machine has not joined your fleet.")
    code, out, _ = lifecycle.Lifecycle(KIT, None, {}, None, lambda: False).run(["sysctl", "-n", "kern.bootsessionuuid"])
    status, answer = Hub(conf["hub"], key).call("POST", f"/server/{conf['name']}/setup", {
        "boot": out.strip() if code == 0 else None, "restarts": not args.no_restart})
    if status not in (200, 404):        # 404: a Mac of the fleet from before, whose sitting the hub does not carry
        die(answer.get("error") or f"The hub did not answer ({status}).")


def cmd_needs(args):
    """What this Mac needs, as one line of JSON, for its installer. A hub that does not know this Mac any more answers
    403, and the installer goes back to its link code."""
    conf, key = load_conf(), server_key()
    if not conf or not key:
        die("This machine has not joined your fleet.")
    status, answer = Hub(conf["hub"], key).call("GET", f"/server/{conf['name']}/needs")
    print(json.dumps(dict(answer, status=status)))


def cmd_add_claude(args):
    """Claude Code and Chrome's offer of its extension, for the installer's Add Claude on a Mac that had no Claude."""
    if not lifecycle.exe("claude", HOME):
        pin = onboard.RUNTIME_PINS["claude"]
        done = subprocess.run(["/bin/sh", "-c", 'mkdir -p "$HOME/.local/bin" && ' + onboard.runtime_install("claude", pin)],
                              cwd=HOME, capture_output=True, text=True, timeout=900)
        exe = lifecycle.exe("claude", HOME)
        if done.returncode != 0 or not exe:
            die("Claude Code did not install. Try again.")
        subprocess.run([sys.executable, "-c", onboard.CLAUDE_CHANNEL, exe], capture_output=True, timeout=120)
    lifecycle.offer_extension(HOME)


def cmd_desktop(args):
    """What this Mac's desktop is now, as one line of JSON: the reading of its status report, for the installer."""
    print(json.dumps(lifecycle.Lifecycle(KIT, None, {}, None, lambda: False).desktop()))


def cmd_chrome_script(args):
    """One harmless script through this Mac's vault, so that macOS asks its one question while a person is here."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(280)
        s.connect(os.path.join(HOME, "Library", "Application Support", "AgentFleet", "vault.sock"))
        s.sendall(b'{"v": 2, "op": "chrome"}\n')
        print(s.makefile().readline().strip())


def cmd_computer_use(args):
    """One harmless call of Computer Use, so that it asks macOS for its two permissions while a person is here: macOS
    lists an app on those pages only once the app has asked. No model runs."""
    client = os.path.join(HOME, ".codex", "computer-use", "Codex Computer Use.app", "Contents", "SharedSupport",
                          "SkyComputerUseClient.app", "Contents", "MacOS", "SkyComputerUseClient")
    print(lifecycle.mcp_call([client, "mcp"], "list_apps", timeout=60))


def cmd_service(args):
    if not load_conf():
        die("This machine has not joined your fleet. Run the join line from Founderizer: Settings, Servers, Add "
            "server.")
    print("Founderizer: wrote and started " + install_service())


def cmd_run(args):
    conf, key = load_conf(), server_key()
    if not conf or not key:
        print("This server has not joined your fleet; its Founderizer service waits.", flush=True)
        while True:
            time.sleep(600)
    Service(conf, Hub(conf["hub"], key), floor=lifecycle.floor_path(HOME)).loop()


class Service:
    """The loop of one server's service. run(argv, cwd, timeout, env) -> (code, out, err) runs a command; tests replace
    it, popen, the clock and the sleep."""

    # clock measures only how long something has taken here — the report cadence and the two waits of a sign-in —
    # and nothing of it is ever reported or written down, so it is the monotonic clock and not the wall clock. A wall
    # clock steps (NTP correcting a drifted server, a VM's host setting it back), and a step backwards would stop
    # this service's five-minute reading for the whole of the step while the hub went on showing the last one.
    def __init__(self, conf, hub, kit=KIT, home=HOME, run=None, clock=time.monotonic, sleep=time.sleep,
                 platform=sys.platform, life=None, popen=subprocess.Popen, users=account, lives=None, floor=None):
        self.name, self.repo, self.hub, self.kit, self.home = conf["name"], conf.get("repo"), hub, kit, home
        self.floor = floor              # this user's release floor (lifecycle.floor_path), under which its checkout moves
        self.run, self.popen = run or self.command, popen
        self.clock, self.sleep, self.platform = clock, sleep, platform
        self.users = users              # (OS user) -> (uid, home) or None: which agent user this machine has
        self.lives = lives or self.agent_lifecycle      # (OS user) -> the reading of that agent's runtime
        self.kept = {}                  # one reading for each agent user, because each makes its own git call
        self.life = life or lifecycle.Lifecycle(kit, None, {}, None, lambda: False, platform_name=platform, home=home)
        self.loaded = self.revision()
        self.desired = self.last_report = None
        self.chrome_opened = self.report_at = None      # keep_chrome: when it last opened Chrome, and the reading due
        self.stuck = None               # a revision that did not fast-forward: no new try for it
        self.vault_tried = None         # when the vault broker was last asked to catch up (vault_program)

    @staticmethod
    def command(argv, cwd=None, timeout=120, env=None):
        try:
            done = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                                  stdin=subprocess.DEVNULL, env=env)
        except (OSError, subprocess.SubprocessError) as e:
            return 1, "", str(e)
        return done.returncode, done.stdout, done.stderr

    def sh(self, script, cwd=None, timeout=120):
        return self.run(["/bin/sh", "-c", script], cwd=cwd, timeout=timeout,
                        env=dict(os.environ, PATH=PATH_ENV, HOME=self.home))

    # ---- each agent under its own OS user (PRODUCT.md, "What the move to per-agent users decided")

    @staticmethod
    def os_user(agent, named=None):
        """The OS user of this agent on Linux: the one its job names, which an agent keeps after a rename (team.json
        "user", owner feature agent_rename), else `fleet-<agent>`."""
        return named if isinstance(named, str) and USER_NAME.fullmatch(named) else AGENT_USER % agent

    def agent_user(self, agent, named=None):
        """The OS user whose home holds this agent's checkout, runtime, credential and service (os_user), where that
        user exists. None on a Mac, which keeps one user for its agents, and None for an agent from before the move,
        whose checkout then stays where this service made it."""
        if self.platform == "darwin":
            return None
        user = self.os_user(agent, named)
        return user if self.users(user) else None

    def home_of(self, user):
        return (self.users(user) or (0, f"/home/{user}"))[1] if user else self.home

    def short_of(self, agent, user=None):
        """The agent's checkout as a line the owner reads: the whole path under its own user's home, and the old
        `~/fleet-<agent>` where the agents share this service's user."""
        return os.path.join(self.home_of(user), f"fleet-{agent}") if user else f"~/fleet-{agent}"

    def as_agent(self, user, argv):
        """argv as that agent's own OS user, through the one sudoers line the installers put in place: its own HOME,
        PATH and user services. This service has no root and the agent's home is of mode 700, so this is the only
        way it reaches it. Without a user, argv as it is."""
        if not user:
            return list(argv)
        uid, home = self.users(user) or (0, f"/home/{user}")
        return ["sudo", "-n", "-u", user, "--", "env", f"HOME={home}", f"XDG_RUNTIME_DIR=/run/user/{uid}",
                f"PATH={home}/.local/bin{os.pathsep}{AGENT_PATH}"] + list(argv)

    def in_folder(self, user, folder, argv):
        """argv as that agent's own user, from that folder: sudo cannot be given a folder this service may not
        open, so the folder is entered after it has become the user."""
        if not user:
            return list(argv), folder
        return self.as_agent(user, ["sh", "-c", 'cd "$1" && shift && exec "$@"', "sh", folder] + list(argv)), None

    def agent_run(self, user):
        """A `run` for another module (lifecycle), every command of it taken as that agent's own user."""
        def run(argv, cwd=None, timeout=120, env=None):
            return self.run(self.as_agent(user, argv), cwd=cwd, timeout=timeout, env=env)
        return run

    def agent_life(self, user):
        """The reading of one agent's runtime: this service's own user when the agents share it, else that agent's
        own user, where its credential is."""
        return self.life if not user else self.lives(user)

    def agent_lifecycle(self, user):
        """One agent's reading, made in that user's own home. It is the reading lifecycle makes everywhere else, so
        this service and the agent's own helper never disagree.

        Every part of it runs as that agent, the look for the executable first of all: this service may not open a
        home of mode 700, and its own PATH is not that agent's. Without that the reading was of the wrong user or
        of nobody, and the sign-in step of an install waited out its fifteen minutes on a machine that was signed
        in."""
        if user not in self.kept:
            self.kept[user] = lifecycle.Lifecycle(self.kit, None, {}, None, lambda: False,
                                                  platform_name=self.platform, home=self.home_of(user),
                                                  run=self.agent_run(user),
                                                  which=lambda name: self.agent_exe(name, user))
        return self.kept[user]

    def user_step(self, job, agent):
        """The agent's own OS user, made by the one root command the installers put in place. This service runs as
        the machine's service user and has no root, so that command and nothing else is what it may run as root."""
        if self.platform == "darwin":
            return None
        user = self.os_user(agent, job.get("user"))
        self.post(job, "running", "user", f"Preparing {shown_name(agent)}'s account on {self.name}.")
        code, out, err = self.run(["sudo", "-n", AGENT_HELPER, user], timeout=120)
        if code != 0 or not self.users(user):
            raise failed("user", f"{shown_name(agent)}'s account on {self.name} could not be made. Run the join line "
                                 f"again on {self.name}.", f"OS user {user}: {err or out}")
        return user

    def revision(self):
        code, out, _ = self.run(["git", "-C", self.kit, "rev-parse", "HEAD"])
        return out.strip() if code == 0 and re.fullmatch(r"[0-9a-f]{40}", out.strip()) else None

    # ---- the reading
    def reading(self):
        life = self.life
        return {"revision": self.loaded, "os": life.os_info(), "security": life.security(),
                "runtimes": self.runtimes(), "load": lifecycle.machine_load(self.platform),
                "access": dict(life.access(), user=pwd.getpwuid(os.getuid()).pw_name),
                "features": [JOB_HEARTBEAT, NAMES_FEATURE, KEY_FEATURE, INSTALL_KEY]}

    def runtimes(self):
        """Codex and Claude Code as this server's agent reads them: as its own OS user, in its own home and on its own
        PATH (agent_life), so this reading says what that agent's own helper says.

        On Linux this service's user is not that user: each agent has a user of its own, and its runtime and its
        credential are in a home of mode 700. Read as this service, one of the owner's servers said that neither
        runtime was there and another an older Claude Code that nobody had signed in to, while the helper of each
        agent read Claude Code signed in (27 October 2026). A Mac's agents share this service's user, and so does an
        agent from before the move, so there and on a server with no agent yet the reading is this service's own."""
        here, life = self.agents_here(), self.life
        if here:
            agent, entry = here[0]
            life = self.agent_life(self.agent_user(agent, entry.get("user")))
        runtimes = {n: life.runtime(n) for n in lifecycle.SWITCH_RUNTIMES}
        return {n: {"version": r["version"], "signed_in": r["signed_in"]} for n, r in runtimes.items()}

    def agents_here(self):
        """[(agent, its team.json entry)] of this server, in team order, from the team.json of this service's own
        checkout: it stands on the fleet's configuration ref, where the hub writes it (update), and the join's
        agent-users step reads the same file. A server can have several agents (hub.add_server_agent)."""
        try:
            with open(os.path.join(self.kit, "team.json"), encoding="utf-8") as f:
                agents = json.load(f).get("agents") or {}
            return [(name, a) for name, a in agents.items() if isinstance(a, dict) and a.get("machine") == self.name]
        except (OSError, ValueError, AttributeError):
            return []

    def report(self):
        reading = self.reading()
        reading["security"]["tailscale"] = self.life.private_network()      # as it leaves (Lifecycle.report)
        status, answer = self.hub.call("POST", f"/server/{self.name}/status", reading)
        self.last_report = self.clock()
        if status == 200 and re.fullmatch(r"[0-9a-f]{40}", str(answer.get("desired_revision"))):
            self.desired = answer["desired_revision"]
        if status == 200:
            self.adopt(answer.get("server"))
        return status

    def adopt(self, name):
        """The name the hub gives this server in its answer to a reading: its name in Tailscale. A machine renamed there
        gets its new name in Fleet (hub.rename_machine), which it takes once its own checkout's team.json has it, so
        that agents_here always reads one name in one file; it keeps it in server.json and calls with it from then on.
        Until then it calls with the old one, and the hub knows it by its address and key."""
        if name == self.name or not NAME.fullmatch(str(name)):
            return
        try:
            with open(os.path.join(self.kit, "team.json"), encoding="utf-8") as f:
                if name not in (json.load(f).get("addresses") or {}):
                    return
        except (OSError, ValueError, AttributeError):
            return
        conf = load_conf() or {"hub": getattr(self.hub, "url", None), "repo": self.repo}
        save_conf(dict(conf, name=name))
        print(f"Founderizer: this machine is the server {name} now, its name in Tailscale (it was {self.name})",
              flush=True)
        self.name = name

    # ---- the loop
    def keep_chrome(self):
        """Chrome stays open on a Mac whose extension is on, so browser tasks work after a restart with no hands. A
        Chrome that opens gets a reading of its own soon: it answers the runtime's account some seconds later. It is
        opened once in REPORT_EVERY, so a Chrome that does not start stops no reading, and a person can quit it."""
        if self.platform != "darwin" or lifecycle.chrome_extension(self.home) is not True or \
                (self.chrome_opened is not None and self.clock() - self.chrome_opened < REPORT_EVERY) or \
                self.run(["pgrep", "-x", "Google Chrome"])[0] == 0:
            return
        self.run(["open", "-g", "-a", "Google Chrome"])
        self.chrome_opened = self.clock()
        self.report_at = self.clock() + CHROME_SETTLES

    def loop(self, rounds=None):
        while rounds is None or rounds > 0:
            rounds = None if rounds is None else rounds - 1
            self.keep_chrome()
            if self.last_report is None or self.clock() - self.last_report >= REPORT_EVERY or \
                    (self.report_at is not None and self.clock() >= self.report_at):
                self.report_at = None
                self.report()
            status, answer = self.hub.call("GET", f"/server/{self.name}/jobs")
            if status == 403:
                print("The hub does not know this server, or its key: the service waits. It joins again with a new "
                      "join line.", flush=True)
                self.sleep(600)
                continue
            jobs = answer.get("jobs") if status == 200 else None
            for job in jobs or []:
                with self.beating():
                    self.work(job)
                self.report()
            if jobs == []:
                self.vault_program()
                self.update()
            self.sleep(POLL)

    @contextlib.contextmanager
    def beating(self):
        """The status goes on while a job runs, every REPORT_EVERY seconds: a first install or clone can take an
        hour, and its own steps say nothing in between (plan C2, hub.expire_server_jobs)."""
        done = threading.Event()

        def beat():
            while not done.wait(REPORT_EVERY):
                try:
                    self.report()
                except Exception:
                    pass        # the next beat, or the report after the job, tries again
        threading.Thread(target=beat, name="job-heartbeat", daemon=True).start()
        try:
            yield
        finally:
            done.set()

    def work(self, job):
        try:
            kind = {"install": self.install, "prepare": self.prepare, "rename": self.rename}.get(job.get("kind"))
            if kind is None:
                # The job's kind is the hub's own id, not his word: a server that does not know it is older.
                raise failed(None, f"{self.name} runs an older Founderizer that cannot do this. Update Founderizer, "
                                   f"then try again.", f"no job {job.get('kind')!r} here")
            kind(job)
        except StepFailed as e:
            self.post(job, "failed", e.step, str(e)[:500], quiet=True, timed_out=e.timed_out)
        except Gone:
            pass
        except Exception as e:          # one bad job never stops the service
            print(f"job {job.get('id')}: {e!r}", file=sys.stderr, flush=True)
            self.post(job, "failed", None, "The server service failed. Try again.", quiet=True)

    def post(self, job, state, step, detail, prompt=None, quiet=False, timed_out=False):
        body = {"state": state, "step": step, "detail": detail, "prompt": prompt}
        if timed_out:
            body["timed_out"] = True
        status, answer = self.hub.call("POST", f"/server/{self.name}/jobs/{job['id']}", body)
        if status in (404, 409) and not quiet:
            raise Gone()
        return status

    # ---- install an agent
    def install(self, job):
        agent, runtime = job.get("agent"), job.get("runtime")
        if not NAME.fullmatch(str(agent)) or runtime not in LABELS:
            raise StepFailed(None, f"{self.name} runs an older Founderizer that cannot do this. Update Founderizer, "
                                   f"then try again.")      # a newer hub's provider or name (review, 30 October)
        user = self.user_step(job, agent)
        exe = self.runtime_step(job, runtime, user)
        folder = self.checkout_step(job, agent, user)
        self.key_step(job, agent, folder, user)
        self.service_step(job, agent, runtime, folder, user)
        if job.get("sign_in") != "at_the_mac":      # the installer leads this sign-in, at this Mac's own screen
            self.sign_in_step(job, agent, runtime, exe, user)
        self.post(job, "done", "sign_in", f"{shown_name(agent)} runs on {self.name}. Open it to finish its setup.")

    # ---- prepare the other runtime of an agent (owner feature runtime_switch)
    def prepare(self, job):
        """The runtime that the owner switches the agent to, with the runtime and sign-in steps of an install: the
        pinned version when the server has none, for Codex the trust of the agent's checkout, and the sign-in in that
        checkout when the server is not signed in. The agent keeps its runtime until the owner switches it."""
        agent, runtime = job.get("agent"), job.get("runtime")
        if not NAME.fullmatch(str(agent)) or runtime not in LABELS:
            raise StepFailed(None, f"{self.name} runs an older Founderizer that cannot do this. Update Founderizer, "
                                   f"then try again.")      # a newer hub's provider or name (review, 30 October)
        user = self.agent_user(agent, job.get("user"))
        folder = os.path.join(self.home_of(user), f"fleet-{agent}")
        if not self.ours(folder, agent, user):
            raise failed(None, f"{shown_name(agent)} has no copy of Founderizer on {self.name}. Report a problem "
                               f"from the Help menu.", f"no checkout of Founderizer's at {self.short_of(agent, user)}")
        exe = self.runtime_step(job, runtime, user)
        if runtime == "codex":
            self.codex_trust(folder, "runtime", user, agent)
        self.sign_in_step(job, agent, runtime, exe, user)
        self.post(job, "done", "sign_in", f"{LABELS[runtime]} is installed and signed in on {self.name}. Now switch "
                                          f"{shown_name(agent)} to it.")

    # ---- a new name for an agent (owner feature agent_rename)
    def rename(self, job):
        """The agent under the new name the hub gave it: its checkout moves to fleet-<new> and is marked as the new
        name's, the service of the old name ends, its agent key takes the new name and the service of the new name
        starts. It stays in the home of the OS user it has (the job names that user once the agent keeps an earlier
        name's), so its runtime and its sign-in stay where they are and nobody signs in again. Each step reads first,
        so Try again repeats only what is missing."""
        agent, was, runtime = job.get("agent"), job.get("was"), job.get("runtime")
        if not NAME.fullmatch(str(agent)) or not NAME.fullmatch(str(was)) or agent == was or runtime not in LABELS:
            raise StepFailed(None, f"{self.name} runs an older Founderizer that cannot do this. Update Founderizer, "
                                   f"then try again.")      # a newer hub's provider or name (review, 30 October)
        user = self.agent_user(agent, job.get("user"))
        old, folder = (os.path.join(self.home_of(user), f"fleet-{name}") for name in (was, agent))
        if not self.there(folder, user) and self.ours(old, was, user):
            self.post(job, "running", "checkout", f"Moving {shown_name(was)}'s files to {shown_name(agent)}.")
            code, out, err = self.run(self.as_agent(user, ["mv", old, folder]))
            if code != 0:
                raise failed("checkout", f"{shown_name(was)}'s files could not move to {shown_name(agent)}. Try "
                                         f"again.", f"{self.short_of(was, user)} -> {self.short_of(agent, user)}: "
                                                    f"{err or out}")
            self.mark(folder, agent, user)
        folder = self.checkout_step(job, agent, user)
        self.post(job, "running", "service", f"The service of {shown_name(was)} ends, and the service of "
                                             f"{shown_name(agent)} starts.")
        self.retire(job, was, user)
        self.carry_key(was, agent, user)
        self.service_step(job, agent, runtime, folder, user)
        self.post(job, "done", "service", f"{shown_name(agent)} runs on {self.name}.")

    def carry_key(self, was, agent, user=None):
        """The agent's key file under its new name, as the hub's record of that key is (hub.rename_rows): after the
        old name's helper stopped, and before the new name's starts. On a machine with several agents a helper cannot
        register a key, so without this file the agent would stay out of the hub until the owner registers one."""
        old, new = (os.path.join(self.home_of(user), ".fleet", f"agent-{name}.key") for name in (was, agent))
        if self.there(old, user):
            code, out, err = self.run(self.as_agent(user, ["mv", "-f", old, new]))
            if code != 0:
                raise failed("service", f"The key of {shown_name(agent)} could not take its new name. Try again.",
                             err or out)

    def retire(self, job, was, user=None):
        """The old name of a renamed agent ends on this server: its service stops and never starts again, and its tmux
        session ends. What is not there is no failure; a service that still runs is."""
        if self.platform == "darwin":
            job_name = f"gui/{os.getuid()}/com.agentfleet.{was}"
            self.run(["launchctl", "bootout", job_name])
            self.run(["rm", "-f", os.path.join(self.home, "Library", "LaunchAgents", f"com.agentfleet.{was}.plist")])
            if self.run(["launchctl", "print", job_name])[0] == 0:
                raise StepFailed("service", f"The service of {shown_name(was)} did not stop. Restart "
                                            f"{self.name}, then try again.")
        else:
            unit = f"fleet-{was}.service"
            self.run(self.as_agent(user, ["systemctl", "--user", "disable", "--now", unit]))
            code, out, _err = self.run(self.as_agent(user, ["systemctl", "--user", "is-active", unit]))
            if out.strip() == "active":
                raise StepFailed("service", f"The service of {shown_name(was)} did not stop. Restart "
                                            f"{self.name}, then try again.")
            self.run(self.as_agent(user, ["rm", "-f", os.path.join(self.home_of(user), ".config", "systemd", "user",
                                                                   unit)]))
            self.run(self.as_agent(user, ["systemctl", "--user", "daemon-reload"]))
        self.run(self.as_agent(user, ["tmux", "kill-session", "-t", f"=fleet-{was}:"]))

    def runtime_step(self, job, runtime, user=None):
        """The runtime of this agent, in the home of its own user: the credential the vendor's client writes lives
        beside it, and a home of mode 700 cannot be shared, so a machine with several agents carries one copy for
        each.

        A vendor installer that could not reach the internet is run again by itself, up to onboard.NETWORK_RETRIES
        times, while the owner's page stays on its moving words and the job's line stays "Installing Codex.". Its own
        words go to this service's log, one line for each try with the job's id, and the job's line says what failed
        in plain words: the owner can act on "could not reach the internet", and on no installer's error text
        (T-35)."""
        label = LABELS[runtime]
        self.post(job, "running", "runtime", f"Looking for {label}.")
        exe = self.agent_exe(runtime, user)
        if exe:
            return exe
        pin = onboard.RUNTIME_PINS[runtime]
        script = 'mkdir -p "$HOME/.local/bin" && ' + onboard.runtime_install(runtime, pin)
        for again in range(onboard.NETWORK_RETRIES + 1):
            # One line for every try, without the version: the tries are the log's (T-35). Each try still posts it,
            # so a job cancelled between two tries stops here (Gone).
            self.post(job, "running", "runtime", f"Installing {label}.")
            code, out, err = self.agent_sh(user, script, timeout=900)
            exe = self.agent_exe(runtime, user)
            if code == 0 and exe:
                break
            offline = onboard.network_failure(f"{err}\n{out}")
            print(f"job {job.get('id')}: {label} {pin} did not install (try {again + 1} of "
                  f"{onboard.NETWORK_RETRIES + 1}{', a network error' if offline else ''}): "
                  f"{' '.join(tail(err or out, 500).split())}", flush=True)
            if not offline or again == onboard.NETWORK_RETRIES:
                raise StepFailed("runtime", f"{label} did not install: {self.name} could not reach the internet. "
                                            f"Try again when it can." if offline else f"{label} did not install. Try again.")
            self.sleep(onboard.NETWORK_WAIT)
        if runtime == "claude":         # its updates follow the stable channel, as after the SSH setup
            self.run(self.as_agent(user, [sys.executable, "-c", onboard.CLAUDE_CHANNEL, exe]), timeout=120)
        return exe

    def agent_sh(self, user, script, timeout=120):
        """One shell script as that agent's own user, from its home."""
        if not user:
            return self.sh(script, timeout=timeout)
        return self.run(self.as_agent(user, ["/bin/sh", "-c", 'cd "$HOME" && ' + script]), timeout=timeout)

    def agent_exe(self, runtime, user=None):
        """This agent's runtime binary: lifecycle.exe for this service's own user, and the same two places read as
        the agent's user, because its home cannot be read from outside."""
        if not user:
            return lifecycle.exe(runtime, self.home)
        code, out, _err = self.run(self.as_agent(user, [
            "/bin/sh", "-c", 'command -v "$1" || { [ -x "$HOME/.local/bin/$1" ] && printf %s "$HOME/.local/bin/$1"; }',
            "sh", runtime]))
        return (out.strip() or None) if code == 0 else None

    def checkout_step(self, job, agent, user=None):
        """The agent's own checkout fleet-<agent> in the home of its own OS user, on the fleet's configuration ref:
        the branch that the hub writes, so the folder never starts on the code branch and the agent reads the
        owner's team.json, its profile and the owner's knowledge from its first task session. It is cloned as that
        user, over git:// like every worker's, so this service never writes into the agent's home. A folder that
        this service did not make stays as it is and stops the job."""
        folder, short = os.path.join(self.home_of(user), f"fleet-{agent}"), self.short_of(agent, user)
        self.post(job, "running", "checkout", f"Getting Founderizer for {shown_name(agent)}.")
        if self.there(folder, user):
            if not self.ours(folder, agent, user):
                raise failed("checkout", f"{shown_name(agent)}'s folder on {self.name} was not made by Founderizer, "
                                         f"and Founderizer leaves it as it is. Move it aside, then try again.",
                             f"the folder {short}")
        else:
            if not self.repo:
                raise StepFailed("checkout", "This server has no repository address. Run the join line again.")
            # The clone is made beside the folder and moved into its place only once it is marked and at this server's
            # own revision. A clone that its timeout or a stop cut off, or one whose reset failed, is then never the
            # folder: the next try makes it again, where it found a folder with no mark, which it may not touch, or a
            # marked one at whatever the hub's repository holds.
            partial = folder + ".partial"
            self.run(self.as_agent(user, ["rm", "-rf", "--", partial]))
            code, out, err = self.run(self.as_agent(user, ["git", "clone", "-q", self.repo, partial]), timeout=300)
            if code != 0:
                raise failed("checkout", f"{self.name} could not get the Founderizer repository. Try again.",
                             err or out)
            self.mark(partial, agent, user)
            # DevOps plan 0.2: a new checkout starts at this machine's own checked revision, the one this service
            # took under lifecycle.may_take, and not at whatever the hub's repository holds; from there it moves
            # under the same check. A commit is named by its content, so the clone's objects cannot change it.
            here = self.revision()
            code, out, err = self.run(self.as_agent(user, ["git", "-C", partial, "reset", "-q", "--hard",
                                                           here or "missing"]))
            if not here or code != 0:
                raise failed("checkout", f"{shown_name(agent)}'s copy of Founderizer could not start at this "
                                         f"server's own revision. Try again.", err or out)
            code, out, err = self.run(self.as_agent(user, ["mv", "--", partial, folder]))
            if code != 0 or not self.ours(folder, agent, user):
                raise failed("checkout", f"{shown_name(agent)}'s copy of Founderizer could not be put in its place. "
                                         f"Try again.", err or out or f"{folder} holds no copy of Founderizer's")
        # an origin from before the split stays as it was
        problem = lifecycle.follow_config_ref(folder, self.agent_run(user))
        if problem:
            # His words only: the one plain reason stays, git's own text goes to the log.
            own = problem.startswith("the checkout has its own changes")
            raise failed("checkout", f"{shown_name(agent)}'s copy of Founderizer has changes of its own, and "
                         f"Founderizer leaves it as it is. Put those changes away, then try again." if own else
                         f"{shown_name(agent)}'s copy of Founderizer could not be brought up to date. Try again.",
                         f"{short}: {problem}")
        code, out, _err = self.run(self.as_agent(user, ["cat", os.path.join(folder, "team.json")]))
        try:
            listed = code == 0 and agent in (json.loads(out or "{}").get("agents") or {})
        except ValueError:
            listed = False
        if not listed:
            branch = lifecycle.checkout_branch(folder, self.agent_run(user))
            raise failed("checkout", f"The repository does not list {shown_name(agent)} yet. Try again in a minute.",
                         f"{short}: no {agent} in team.json on {branch or 'this checkout'}")
        return folder

    def mark(self, folder, agent, user=None):
        """The checkout's .git/fleet-server mark, which names the agent whose checkout this service made: written as
        the agent's own user, because this service never writes into an agent's home itself."""
        mark = os.path.join(folder, ".git", "fleet-server")
        code, out, err = self.run(self.as_agent(user, ["/bin/sh", "-c", 'printf "%s\\n" "$2" > "$1"', "sh", mark,
                                                       agent]))
        if code != 0:
            raise failed("checkout", f"{shown_name(agent)}'s folder could not be marked as Founderizer's. Try "
                                     f"again.", f"{self.short_of(agent, user)}: {err or out}")

    def there(self, path, user=None):
        """Whether this folder or file is there, read as the agent's own user: its home is of mode 700, so this
        service cannot even look inside it."""
        if not user:
            return os.path.exists(path)
        return self.run(self.as_agent(user, ["test", "-e", path]))[0] == 0

    def ours(self, folder, agent, user=None):
        """True for the agent's checkout that this service made: its .git/fleet-server mark names the agent, read
        as the agent's own user."""
        if not user:
            try:
                with open(os.path.join(folder, ".git", "fleet-server"), encoding="utf-8") as f:
                    return f.read().strip() == agent
            except OSError:
                return False
        code, out, _err = self.run(self.as_agent(user, ["cat", os.path.join(folder, ".git", "fleet-server")]))
        return code == 0 and out.strip() == agent

    def service_step(self, job, agent, runtime, folder, user=None):
        """The agent's service from its own checkout, as `fleet.py service` writes it, then started. On Linux both
        happen as the agent's own OS user, so the unit is in that user's own systemd manager and its session runs
        as it. A Codex agent's checkout is trusted first, as the worker installer does it; an owner's own setting
        that does not trust it stays."""
        self.post(job, "running", "service", f"Starting {shown_name(agent)}.")
        if runtime == "codex":
            self.codex_trust(folder, "service", user, agent)
        argv, cwd = self.in_folder(user, folder, [sys.executable, "fleet.py", "service", agent])
        code, out, err = self.run(argv, cwd=cwd)
        if code != 0:
            raise failed("service", f"The service of {shown_name(agent)} could not be written. Try again.", err or out)
        if self.platform == "darwin":
            job_name = f"gui/{os.getuid()}/com.agentfleet.{agent}"
            if self.run(["launchctl", "print", job_name])[0] == 0:
                code, out, err = self.run(["launchctl", "kickstart", job_name])
            else:
                plist = os.path.join(self.home, "Library", "LaunchAgents", f"com.agentfleet.{agent}.plist")
                code, out, err = self.run(["launchctl", "bootstrap", f"gui/{os.getuid()}", plist])
        else:
            code, out, err = self.run(self.as_agent(user, ["systemctl", "--user", "enable", "--now",
                                                           f"fleet-{agent}.service"]))
        if code != 0:
            raise failed("service", f"The service of {shown_name(agent)} did not start. Try again.", err or out)

    def key_step(self, job, agent, folder, user=None):
        """The agent's key, before its helper first starts: `fleet.py key` makes it in that agent's own home (mode 600)
        when it has none and prints only its SHA-256, which goes to the hub with this job (hub.install_key). A helper
        registers its own key only while it is alone on its machine, so without this the second agent of a server would
        never reach the hub. The key itself never leaves that home, and is never on a command line."""
        argv, cwd = self.in_folder(user, folder, [sys.executable, "fleet.py", "key", agent])
        code, out, err = self.run(argv, cwd=cwd)
        digest = (out.strip().splitlines() or [""])[-1]
        if code != 0 or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise failed("service", f"{shown_name(agent)}'s key could not be made. Try again.", err or out)
        for again in range(3):          # a hub that did not answer is asked again, as a heartbeat would be
            status, answer = self.hub.call("POST", f"/server/{self.name}/jobs/{job['id']}",
                                           {"state": "running", "step": "service", "prompt": None,
                                            "detail": f"Starting {shown_name(agent)}.", "key_sha256": digest})
            if (status != 0 and status < 500) or again == 2:
                break
            self.sleep(5)
        if status == 404 or (status == 409 and str(answer.get("error") or "").startswith("the job is")):
            raise Gone()
        if status != 200:
            raise failed("service", f"The hub did not take {shown_name(agent)}'s key. Try again.",
                         str(answer.get("error") or status))

    def codex_trust(self, folder, step, user=None, agent=None):
        """Codex's trust of the agent's checkout, with the worker installer's function, so that a Codex session there
        does not stop at its trust question. It is that agent's own setting in its own home. An owner's own setting
        that does not trust it stays and stops the job."""
        argv, cwd = self.in_folder(user, folder, [sys.executable, "-c", "import worker_install; "
                                                  "print(worker_install.trust_codex_checkout())"])
        code, out, err = self.run(argv, cwd=cwd)
        if code != 0:
            raise failed(step, f"Codex could not be set to trust {shown_name(agent)}'s folder. Try again.",
                         f"{folder}: {err or out}")
        if out.strip() == "kept":
            raise failed(step, f"Codex has its own setting that does not trust {shown_name(agent)}'s folder. "
                               f"Founderizer leaves it as it is. Change it, then try again.",
                         f"the setting for {folder}")

    def sign_in_step(self, job, agent, runtime, exe, user=None):
        """The sign-in of this agent's own runtime. The credential is in that agent's user's home, so the sign-in
        runs as that user and signs that agent in; every agent of a machine is signed in on its own row of
        Machines in the app."""
        label = LABELS[runtime]
        self.post(job, "running", "sign_in", f"Checking the sign-in of {label}.")
        if self.agent_life(user).runtime(runtime)["signed_in"] is True:
            return
        if runtime == "codex":
            return self.codex_sign_in(job, exe, user)
        return self.claude_sign_in(job, agent, runtime, user)

    def claude_sign_in(self, job, agent, runtime, user=None):
        """Claude Code's own sign-in, driven by the hub for this agent (machine_signin), which is the one way a
        runtime is ever signed in: the agent's own helper runs `claude /login` in that agent's own home, where the
        credential belongs, the owner reads the link in the app and pastes the code back there. This service asks
        for it and waits. No link, no code and no credential passes through it, and no console is opened.

        The agent's helper was started one step earlier, so a hub that answers 503 has not heard from it yet and is
        asked again; every other refusal fails this step with the hub's own words."""
        deadline = self.clock() + HELPER_WAIT
        while True:
            status, answer = self.hub.call("POST", f"/server/{self.name}/signin", {"agent": agent, "runtime": runtime})
            if status == 200:
                break
            if status != 503 or self.clock() >= deadline:
                # The hub's own refusal is words for him; a status number alone is not, so it goes to the log.
                if answer.get("error"):
                    raise StepFailed("sign_in", f"The sign-in did not start: {answer['error']}")
                raise failed("sign_in", "The sign-in did not start, because the hub did not answer. Try again.",
                             f"POST /server/{self.name}/signin answered {status}")
            self.post(job, "running", "sign_in", f"Waiting for {shown_name(agent)} to reach the hub.")
            self.sleep(10)
        self.post(job, "needs_owner", "sign_in", f"Sign {shown_name(agent)} in to {LABELS[runtime]} in Founderizer.",
                  prompt={"kind": "signin", "purpose": "claude_login", "agent": agent, "login": answer["login"]["id"]})
        self.wait_signed_in(runtime, user)

    def codex_sign_in(self, job, exe, user=None):
        """Codex's device sign-in: its link and code go to Fleet, then a wait for the sign-in. It runs as the
        agent's own user, because the credential it writes is that agent's. The output of the login stays in a
        mode-600 file of this service, which reads the link and the code and removes it afterwards."""
        folder = os.path.join(self.home, ".fleet")
        log = os.path.join(folder, "codex-login.log")
        self.agent_sh(user, onboard.STOP_CODEX_LOGIN)
        os.makedirs(folder, mode=0o700, exist_ok=True)
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            login = self.popen(self.as_agent(user, [exe, "login", "--device-auth"]), stdout=fd,
                               stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True,
                               env=dict(os.environ, PATH=PATH_ENV))
        finally:
            os.close(fd)
        try:
            url = code = None
            for _ in range(15):
                with open(log, encoding="utf-8", errors="replace") as f:
                    text = ANSI.sub("", f.read())
                found_url = re.search(r"https://auth\.openai\.com/\S+", text)
                found_code = re.search(r"\b[A-Z0-9]{4}-[A-Z0-9]{4,6}\b", text)
                if found_url and found_code:
                    url, code = found_url.group(0), found_code.group(0)
                    break
                self.sleep(2)
            if not url:
                raise StepFailed("sign_in", "Codex gave no sign-in link. Try again.")
            self.post(job, "needs_owner", "sign_in", "Sign in to Codex with this code.",
                      prompt={"kind": "open_url", "purpose": "codex_login", "url": url, "code": code})
            self.wait_signed_in("codex", user)
        finally:
            if login.poll() is None:
                login.terminate()
            try:
                os.remove(log)
            except OSError:
                pass

    def wait_signed_in(self, runtime, user=None):
        life = self.agent_life(user)
        deadline = self.clock() + SIGN_IN_WAIT
        while self.clock() < deadline:
            if life.runtime(runtime)["signed_in"] is True:
                return
            self.sleep(2)           # the owner's sign-in shows as soon as it is made (live_changes)
        raise StepFailed("sign_in", f"{LABELS[runtime]} did not sign in within 15 minutes. Try again in Founderizer.",
                         timed_out=True)

    # ---- updates
    def update(self):
        """With no job: the hub's revision, when it changes a Python file or team.json, by a fast-forward of this
        checkout and a new start of this process. The revision is a commit of the fleet's configuration ref, so the
        checkout follows that ref first (lifecycle.follow_config_ref: it moves a checkout that still stands on the
        code branch, and leaves an origin from before the split as it was). A revision that does not fast-forward
        gets no second try."""
        desired = self.desired
        if not desired or desired in (self.loaded, self.stuck):
            return
        if self.run(["git", "-C", self.kit, "fetch", "-q", "origin"], timeout=120)[0] != 0:
            return                      # no network: this revision keeps its try for the next round
        code, out, _ = self.run(["git", "-C", self.kit, "diff", "--name-only", self.loaded or "HEAD", desired])
        # Every move under the one check (lifecycle.may_take): onto the ref, and onto the hub's revision.
        problem = "git diff failed" if code != 0 else \
            lifecycle.follow_config_ref(self.kit, self.run, self.floor) or \
            lifecycle.take(self.kit, desired, self.run, self.floor)
        if problem:
            self.stuck = desired
            print(f"Fleet could not fast-forward {lifecycle.checkout_branch(self.kit, self.run) or 'this checkout'} "
                  f"to {desired[:12]}: {problem}; this server keeps {str(self.loaded)[:12]}.", file=sys.stderr,
                  flush=True)
            return
        if any((p.endswith(".py") and not p.startswith((lifecycle.OUTPUTS, lifecycle.SKILLS + "/"))) or p == "team.json"
               for p in out.split()):
            self.restart()              # a task's output and an agent's skill are no code that this service loads
        self.loaded = desired

    def vault_program(self):
        """This machine's vault broker onto the vault.py of this checkout, through the one root command the
        installers put in place for it (hubsetup.vault_program_script).

        **Why the service does this at all.** A release updates every checkout on this machine and never the
        broker: it runs a root-owned copy of vault.py outside all of them as a system service, and a helper never
        loads that file (lifecycle.OWNER_ONLY), so a commit that changes only it advances the revision this
        machine reports. A release that changed vault.py therefore left the broker running the copy installed
        before it while the Updates page said the fleet was current, and the owner pasted one root command per
        machine after every such release. This is that catch-up, done by the machine that needs it.

        **The gate is a reading and needs no root.** The installed program is root-owned and world-readable, so
        this service hashes it and this checkout's vault.py itself and asks for nothing while they agree. Where
        they differ it asks, and root fetches the bytes from the configuration ref itself: this service passes no
        bytes, no path and no revision, so a wrong reading here can only cost root one fetch that finds nothing to
        do. A try that did not settle it -- no network, or a broker that did not come up and kept the program that
        was serving -- is made again at VAULT_EVERY and not once a round; a broker that stays behind is what the
        hub's own `vault_behind` warning is for."""
        if self.platform == "darwin":
            return                      # a Mac's vault is the signed app, which Founderizer updates itself
        here = program_sha256(os.path.join(self.kit, "vault.py"))
        there = program_sha256(VAULT_PROGRAM)
        if not here or not there or here == there:
            return                      # no broker on this machine, or it runs this vault.py already
        if self.vault_tried is not None and self.clock() - self.vault_tried < VAULT_EVERY:
            return
        self.vault_tried = self.clock()
        code, out, err = self.run(["sudo", "-n", VAULT_HELPER], timeout=300)
        said = tail(err or out, 300)
        if code == 0:
            print(said or f"Fleet brought this machine's vault broker onto the vault.py of "
                          f"{str(self.loaded)[:12]}.", flush=True)
            return
        # The command says its own name, so a line that does not carry it is sudo refusing the command and not the
        # command refusing the work: the first needs the installer run again, the second needs reading.
        ran = said.startswith(os.path.basename(VAULT_HELPER) + ":")
        print(f"Fleet could not bring this machine's vault broker onto the vault.py of {str(self.loaded)[:12]}: "
              + (said if ran else f"{said or 'the command said nothing'}. The server needs {VAULT_HELPER} from "
                                  f"the Fleet installer; run the join line again on {self.name}."),
              file=sys.stderr, flush=True)

    def restart(self):
        os.execv(sys.executable, [sys.executable, os.path.join(self.kit, "server.py"), "run"])


def main():
    parser = argparse.ArgumentParser(description="The Fleet server service")
    sub = parser.add_subparsers(dest="cmd", required=True)
    join = sub.add_parser("join")
    join.add_argument("--hub", required=True)
    join.add_argument("--kind", choices=("linux", "mac"), required=True)
    join.add_argument("--ssh-port", type=int)
    sub.add_parser("service")
    sub.add_parser("run")
    finish = sub.add_parser("finish")
    finish.add_argument("--no-restart", action="store_true")
    sub.add_parser("desktop")
    sub.add_parser("needs")
    sub.add_parser("add-claude")
    sub.add_parser("chrome-script")
    sub.add_parser("computer-use")
    args = parser.parse_args()
    {"join": cmd_join, "service": cmd_service, "run": cmd_run, "finish": cmd_finish, "desktop": cmd_desktop,
     "needs": cmd_needs, "add-claude": cmd_add_claude, "chrome-script": cmd_chrome_script,
     "computer-use": cmd_computer_use}[args.cmd](args)


if __name__ == "__main__":
    main()
