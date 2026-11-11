#!/usr/bin/env python3
"""Fleet machine onboarding executor (owner API 1.2, protocol version 1).

Runs on the owner Mac, outside the app sandbox, started by the signed local setup
helper. It prepares one fresh Linux VPS as a Fleet worker: pinned host keys, a
managed admin key, packages, security updates, a dedicated worker user, Tailscale,
a firewall that lets SSH in over Tailscale only, registration on the hub, the agent
runtime and the worker service. From the firewall on, every connection of the run
goes to the server's Tailscale address.

With --existing-machine (owner API 1.12) it adds one inactive agent with no
credential access to a machine that the hub has ready: its own checkout, agent key
and service, with the machine's existing SSH access, worker user and signed-in
runtime. It changes no other agent, OS user, sign-in or machine setting.

With --prepare-runtime (executor 1.3.0) it prepares the other runtime of one
existing agent before a provider switch, on a machine that this Mac set up, with
only that setup's managed key and pinned host keys. A runtime command that the
worker's service PATH finds stays in any version; only when there is none is the
pinned version installed, and it is signed in only when a fresh check says that it
is not. It registers nothing, switches nothing and changes no session, chat,
service or setting of the agent. Its saved state is its own.

Protocol: JSON Lines on standard output; answers on standard input; secrets on file
descriptor 3. See UI-API.md, "Version 1.2". Standard library only; Python 3.9+.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

PROTOCOL = 1
EXECUTOR_VERSION = "1.3.3"
CAPABILITIES = ["existing_machine", "prepare_runtime"]
WORKER_USER = "fleet"
CONFIG_BRANCH = "config"     # the hub's configuration ref: a team.json change belongs there, never on the code branch
# How a checkout on a worker takes its ref, in its own folder: fetched, and taken only where `lifecycle.py may-take`
# lets it (DevOps plan 0.1). A refusal leaves the checkout where it is, as a failed pull did. The ref is read once, as
# one commit: the commit checked is the commit taken.
TAKE = ('git fetch -q origin && t=$(git rev-parse --verify -q "@{upstream}^{commit}") && '
        'python3 lifecycle.py may-take . "$t" && git merge -q --ff-only "$t"')
# The tags of a new run's machine when the run names none come from network_tags, by the rule of the hub's join line
# (hub.hub_tags): the hub's own, else the product's own tag where the tailnet has it, else none. A tailnet whose policy
# gives the fleet's machines their rights by other tags names them with --tailscale-tag or the config file.
FLEET_TAG = "tag:founderizer"       # hub.FLEET_TAG, the app's PrivateNetwork.tag
TAG_RE = re.compile(r"^tag:[A-Za-z][A-Za-z0-9-]*$")
TAILSCALE_APP = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"      # the command on a Mac, as the hub reads it
# Both at least 7 days old on 10 October 2026. A Codex version stays until someone installs another one. The Claude
# version is only the first build: Claude Code's own installation updates itself (see CLAUDE_CHANNEL).
RUNTIME_PINS = {"codex": "0.160.0", "claude": "2.1.287"}
SECRET_MAX_BYTES = 2048
SUPPORTED_OS = {("ubuntu", "22.04"), ("ubuntu", "24.04"), ("ubuntu", "26.04"), ("debian", "12"), ("debian", "13")}
PACKAGES = "git tmux python3 curl ca-certificates ufw unattended-upgrades"
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,30}\Z")                # \Z: `$` lets a final newline through .match
MACHINE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
GENERATION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RUNTIME_LABELS = {"codex": "Codex", "claude": "Claude"}
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
STEPS = [
    ("preflight", "Check the hub before any server change"),
    ("host_key", "Confirm the server identity"),
    ("provider_login", "Sign in with the provider access"),
    ("managed_key", "Prove the managed admin key"),
    ("packages", "Install base packages"),
    ("security_updates", "Turn on security updates"),
    ("worker_user", "Create the worker user"),
    ("tailscale", "Join the private network"),
    ("firewall", "Turn on the firewall"),
    ("hub_reach", "Reach the hub"),
    ("register", "Register the worker on the hub"),
    ("runtime", "Install the agent runtime"),
    ("runtime_login", "Sign in the agent runtime"),
    ("worker_install", "Install the worker service"),
    ("verify", "Check the finished machine"),
]
# Add agent on an existing machine (owner API 1.12). Same events; steps with the same id differ in what they do.
EXISTING_STEPS = [
    ("preflight", "Check the hub and the machine"),
    ("host_key", "Confirm the server identity"),
    ("runtime_check", "Check the installed runtime"),
    ("checkout", "Clone a separate checkout"),
    ("agent_key", "Create the agent key"),
    ("register", "Register the agent on the hub"),
    ("worker_install", "Install the agent service"),
    ("verify", "Check the new agent"),
]
# Prepare the other runtime of an existing agent (executor 1.3.0). Same events; host_key and managed_key as above.
PREPARE_STEPS = [
    ("preflight", "Check the hub, the agent and this Mac's setup of the machine"),
    ("host_key", "Check the pinned server identity"),
    ("managed_key", "Prove the managed admin key"),
    ("worker_check", "Check the worker user and the agent's checkout"),
    ("runtime", "Find or install the runtime"),
    ("runtime_login", "Sign in the runtime"),
    ("verify", "Check the prepared runtime"),
]


def fleet_home() -> Path:
    return Path(os.environ.get("FLEET_HOME") or (Path.home() / ".fleet"))


class Abort(Exception):
    """The run cannot continue."""


class StepFailed(Exception):
    """One step failed its check."""


class NeedsOwner(Exception):
    """The owner must act outside this run before it can finish."""


# ---------------------------------------------------------------- protocol

class Channel:
    """JSON Lines out, JSON answers in, secrets on descriptor 3. Masks every secret it has seen."""

    def __init__(self, out=None, inp=None, secret_fd=3, run_id=None):
        self.out = out or sys.stdout
        self.inp = inp or sys.stdin
        self.secret_fd = secret_fd
        self.secret_file = None
        self.run = run_id or uuid.uuid4().hex[:12]
        self.seq = 0
        self.secrets = []
        self.prompts = 0

    def mask(self, value):
        if isinstance(value, str):
            for s in self.secrets:
                if s and s in value:
                    value = value.replace(s, "[secret removed]")
            return value
        if isinstance(value, dict):
            return {k: self.mask(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.mask(v) for v in value]
        return value

    def emit(self, type_, **fields):
        self.seq += 1
        line = {"v": PROTOCOL, "run": self.run, "seq": self.seq, "type": type_}
        line.update(self.mask(fields))
        self.out.write(json.dumps(line, sort_keys=True) + "\n")
        self.out.flush()

    def step(self, id_, status, title, detail=""):
        self.emit("step", id=id_, status=status, title=title, detail=detail)

    def log(self, text, level="info"):
        self.emit("log", level=level, text=text)

    def _answer(self, pid):
        while True:
            raw = self.inp.readline()
            if not raw:
                raise Abort("The setup helper closed the answer channel.")
            try:
                msg = json.loads(raw)
            except ValueError:
                continue
            if isinstance(msg, dict) and msg.get("prompt") == pid:
                return msg.get("answer")

    def prompt(self, kind, data):
        self.prompts += 1
        pid = f"p{self.prompts}"
        self.emit("prompt", id=pid, kind=kind, data=data)
        return self._answer(pid)

    def secret(self, label):
        """Ask for one secret. The value arrives on descriptor 3; only an acknowledgement arrives on stdin."""
        self.prompts += 1
        pid = f"p{self.prompts}"
        self.emit("prompt", id=pid, kind="secret", data={"label": label})
        if self.secret_file is None:
            try:
                self.secret_file = os.fdopen(self.secret_fd, "r", closefd=False)
            except OSError:
                raise Abort("The secret channel (descriptor 3) is not open.")
        value = self.secret_file.readline(SECRET_MAX_BYTES + 2).rstrip("\r\n")
        if not value:
            raise Abort("No secret arrived on descriptor 3.")
        if len(value.encode()) > SECRET_MAX_BYTES:
            raise Abort("A secret line is longer than %d bytes." % SECRET_MAX_BYTES)
        self.secrets.append(value)
        self._answer(pid)
        return value


# ---------------------------------------------------------------- system access

class AskpassServer:
    """Gives one secret to ssh's askpass program through a private Unix socket.

    The secret never goes into an argument, an environment variable or a file."""

    def __init__(self, secret, uses=3):
        self.dir = tempfile.mkdtemp(prefix="fleet-askpass-")
        os.chmod(self.dir, 0o700)
        self.path = os.path.join(self.dir, "s")
        self.script = os.path.join(self.dir, "askpass")
        with open(self.script, "w") as f:
            f.write("#!/bin/sh\nexec %s %s askpass\n" % (shlex.quote(sys.executable),
                                                          shlex.quote(os.path.abspath(__file__))))
        os.chmod(self.script, 0o700)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.path)
        self.sock.listen(1)
        self.secret, self.uses = secret, uses
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while self.uses > 0:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                conn.sendall(self.secret.encode())
            self.uses -= 1

    def env(self):
        return {"SSH_ASKPASS": self.script, "SSH_ASKPASS_REQUIRE": "force", "DISPLAY": "fleet:0",
                "FLEET_ASKPASS_SOCKET": self.path}

    def close(self):
        try:
            self.sock.close()
        finally:
            shutil.rmtree(self.dir, ignore_errors=True)


def askpass_main():
    path = os.environ.get("FLEET_ASKPASS_SOCKET", "")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(path)
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    sys.stdout.write(data.decode() + "\n")
    return 0


class System:
    """Every outside effect of the executor. Tests replace it."""

    def __init__(self, known_hosts: Path):
        self.known_hosts = known_hosts

    def run(self, argv, input=None, env=None, timeout=120):
        full_env = dict(os.environ)
        full_env.update(env or {})
        try:
            r = subprocess.run(argv, input=input if input is not None else "", capture_output=True,
                               text=True, env=full_env, timeout=timeout)
        except subprocess.TimeoutExpired:
            return 124, "", "timed out"
        return r.returncode, r.stdout, r.stderr

    def ssh(self, host, port, login, script, *, auth, identity=None, askpass=None, timeout=300):
        """auth: managed (only the given key), identity (provider key file), agent, password.
        The script goes to the remote bash on stdin, never in arguments."""
        args = ["ssh", "-F", "/dev/null", "-p", str(port), "-o", "StrictHostKeyChecking=yes",
                "-o", "UserKnownHostsFile=%s" % self.known_hosts, "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
                "-o", "LogLevel=ERROR"]
        env = {}
        if auth in ("managed", "identity"):
            args += ["-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-i", str(identity)]
        elif auth == "agent":
            args += ["-o", "BatchMode=yes", "-o", "PasswordAuthentication=no"]
        elif auth == "password":
            args += ["-o", "BatchMode=no", "-o", "PubkeyAuthentication=no", "-o", "IdentityAgent=none",
                     "-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "NumberOfPasswordPrompts=1"]
            env = askpass.env()
        else:
            raise ValueError(auth)
        args += ["%s@%s" % (login, host), "bash -s"]
        return self.run(args, input="set -eu\n" + script + "\n", env=env, timeout=timeout)

    def keyscan(self, host, port):
        return self.run(["ssh-keyscan", "-p", str(port), "-T", "10", "-t", "ed25519,ecdsa,rsa", host], timeout=30)

    def keygen(self, path: Path, comment):
        return self.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(path)], timeout=30)

    def git(self, args, cwd=None):
        try:
            r = subprocess.run(["git", "-c", "user.name=Fleet onboarding", "-c", "user.email=fleet-onboard@pilot.local"]
                               + list(args), cwd=cwd, capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            return 124, "", "timed out"
        return r.returncode, r.stdout, r.stderr

    def http(self, method, url, body=None, headers=None):
        data = None if body is None else json.dumps(body).encode()
        h = {"Accept": "application/json"}
        if body is not None:
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=30) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except ValueError:
                return e.code, {}
        except (urllib.error.URLError, OSError, ValueError) as e:
            return 0, {"error": str(e)}

    def sleep(self, seconds):
        time.sleep(seconds)

    def now(self):
        return time.time()


# ---------------------------------------------------------------- helpers

def fingerprint(blob_b64):
    digest = hashlib.sha256(base64.b64decode(blob_b64)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def ssh_quote(path):
    return '"%s"' % path if " " in str(path) else str(path)


def write_ssh_config(name, ip, login, port, key):
    """One block per onboarded worker in the executor's own SSH settings file. It matches only that worker's
    Tailscale address, so other hosts keep their own settings."""
    path = fleet_home() / "ssh" / "config"
    begin, end = "# fleet: %s" % name, "# end fleet: %s" % name
    block = [begin, "Host %s" % ip, "  User %s" % login, "  Port %d" % int(port),
             "  IdentityFile %s" % ssh_quote(key), "  IdentitiesOnly yes", "  IdentityAgent none",
             "  UserKnownHostsFile %s" % ssh_quote(fleet_home() / "ssh" / "known_hosts"),
             "  StrictHostKeyChecking yes", end]
    lines = path.read_text().splitlines() if path.exists() else []
    if begin in lines and end in lines:
        lines[lines.index(begin):lines.index(end) + 1] = block
    else:
        lines += ([""] if lines else []) + block
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    return path


def ssh_include_line():
    return "Include %s" % ssh_quote(fleet_home() / "ssh" / "config")


def ssh_include_state():
    """present, absent, or symlink (the owner's ~/.ssh/config is a link, which the executor never replaces)."""
    user = Path.home() / ".ssh" / "config"
    if user.is_symlink():
        return "symlink"
    return "present" if user.exists() and ssh_include_line() in user.read_text().splitlines() else "absent"


def ssh_include():
    """Owner action, once: let normal SSH (and ssh:// links) read the executor's settings file. The Include line
    goes first in ~/.ssh/config, as ssh_config(5) requires for it to apply to every host; nothing else changes.
    A ~/.ssh/config that is a symbolic link is refused, never replaced."""
    line = ssh_include_line()
    user = Path.home() / ".ssh" / "config"
    state = ssh_include_state()
    if state != "absent":
        return ("refused" if state == "symlink" else state), user
    text = user.read_text() if user.exists() else ""
    user.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    mode = user.stat().st_mode & 0o777 if user.exists() else 0o600
    tmp = user.with_name(".config.fleet-tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write("# Fleet onboarding: SSH settings for the machines that it onboarded only.\n%s\n\n%s" % (line, text))
    os.replace(str(tmp), str(user))
    return "added", user


def host_token(host, port):
    return host if int(port) == 22 else "[%s]:%s" % (host, port)


def parse_keyscan(text):
    keys = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and not line.startswith("#"):
            try:
                keys.append({"type": parts[1], "blob": parts[2], "sha256": fingerprint(parts[2])})
            except (ValueError, TypeError):
                continue
    return keys


def kv(text):
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def tail(text, n=300):
    text = (text or "").strip()
    return text[-n:]


# Stop only a process whose own command line is the Codex login. The shell that starts the login has the same
# words later in its command line, so an unanchored pattern also stopped that shell (live worker4: "Terminated").
CODEX_LOGIN = r"^([^[:space:]]*/)?codex login --device-auth([[:space:]]|$)"
STOP_CODEX_LOGIN = "pkill -u $(id -u) -f %s || true" % shlex.quote(CODEX_LOGIN)

# The worker's own `claude auth status`, reduced on the worker to its exit code (0 signed in, 1 not) and its loggedIn
# field. Only these derived lines leave the machine: never the status text, which names the account.
CLAUDE_STATUS = r"""s=$("$HOME/.local/bin/claude" auth status --json 2>/dev/null); rc=$?
case "$s" in *'"loggedIn": true'*|*'"loggedIn":true'*) li=yes;; *'"loggedIn": false'*|*'"loggedIn":false'*) li=no;; *) li=unknown;; esac
echo fleet-claude-auth=1; echo rc=$rc; echo logged_in=$li"""

# The PATH of every worker service (`fleet.py service`). With it, preparation finds the same runtime command as the
# helper's status commands, which also try ~/.local/bin, the first folder here.
SERVICE_PATH = "$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
CODEX_STATUS = ('s=$("$exe" login status 2>&1 || true); case "$s" in *"Not logged in"*) echo signed_in=no;; '
                '*"Logged in"*) echo signed_in=yes;; *) echo signed_in=unknown;; esac')


def runtime_probe(rt):
    """As the worker user: the runtime command that its service PATH finds, the first line of its --version and its
    derived sign-in. Only these lines leave the machine: never a status text, which can name the account."""
    status = CODEX_STATUS if rt == "codex" else CLAUDE_STATUS.replace('"$HOME/.local/bin/claude"', '"$exe"')
    return ('echo fleet-prepare=1; echo user=$(id -un); echo home=$HOME; export PATH="%s"; exe=$(type -P %s || true); '
            'echo exe=$exe\nif [ -n "$exe" ]; then\necho version=$("$exe" --version 2>/dev/null | head -n 1)\n%s\nfi'
            % (SERVICE_PATH, rt, status))


# Claude Code's own installation updates itself, and a version number at installation sets no channel: it then follows
# "latest". After Fleet's own installation, this program (python3, as the worker user, with the claude command as its
# argument) makes the updates follow the vendor's "stable" channel (about one week old) and sets a floor at the
# installed version, so that a newer build never goes back to an older stable one. It changes only these two keys of
# the user's Claude settings. Every other key stays, also a higher floor and a setting that turns updates off; a file
# that is a link, or that is no JSON object, is not changed.
CLAUDE_CHANNEL = r"""
import json, os, re, stat, subprocess, sys

def stop(why):
    sys.stderr.write(why + "\n")
    sys.exit(1)

path = os.path.expanduser("~/.claude/settings.json")
try:
    shown = subprocess.run([sys.argv[1], "--version"], capture_output=True, text=True, timeout=60).stdout
except (OSError, subprocess.SubprocessError):
    shown = ""
found = re.search(r"\d+\.\d+\.\d+", shown)
if not found:
    stop("the claude command gave no version")
version = found.group(0)
if os.path.islink(path):
    stop("~/.claude/settings.json is a symbolic link; it was not changed")
try:
    with open(path) as f:
        data = json.load(f)
except FileNotFoundError:
    data = {}
except (OSError, ValueError):
    stop("~/.claude/settings.json cannot be read as JSON; it was not changed")
if not isinstance(data, dict):
    stop("~/.claude/settings.json is not a JSON object; it was not changed")
number = lambda value: tuple(int(part) for part in value.split("."))
floor = data.get("minimumVersion")
if not (isinstance(floor, str) and re.fullmatch(r"\d+\.\d+\.\d+", floor) and number(floor) >= number(version)):
    floor = version
changed = (data.get("autoUpdatesChannel"), data.get("minimumVersion")) != ("stable", floor)
if changed:
    data["autoUpdatesChannel"], data["minimumVersion"] = "stable", floor
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    mode = stat.S_IMODE(os.stat(path).st_mode) if os.path.exists(path) else 0o600
    with os.fdopen(os.open(path + ".fleet-tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode), "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.chmod(path + ".fleet-tmp", mode)
    os.replace(path + ".fleet-tmp", path)
env = data.get("env") if isinstance(data.get("env"), dict) else {}
off = [key for key in ("DISABLE_AUTOUPDATER", "DISABLE_UPDATES")
       if str(env.get(key, "")).strip().lower() not in ("", "0", "false")]
print("fleet-claude-channel=1")
print("floor=" + floor)
print("changed=" + ("yes" if changed else "no"))
print("updates_off=" + ",".join(off))
"""


def not_older(current, wanted):
    """True when the installed version (a --version line) is the wanted X.Y.Z or a newer one. A runtime that updated
    itself, or that its owner updated, stays: the installer never puts an older build over a newer one."""
    have, want = (re.search(r"\d+\.\d+\.\d+", text or "") for text in (current, wanted))
    return bool(have and want) and tuple(map(int, have.group(0).split("."))) >= tuple(map(int, want.group(0).split(".")))


# The vendor's Codex installer, for the worker user into ~/.local/bin. Without --release it installs the newest release.
CODEX_INSTALLER = ("curl -fsSL https://chatgpt.com/codex/install.sh | CODEX_INSTALLER_USE_RELEASES_OPENAI_COM=false "
                   "CODEX_NON_INTERACTIVE=1 sh -s --")
# A setting in the env of ~/.claude/settings.json that turns Claude Code's updates off (UI-API.md, "To stop updates on
# one machine"). CLAUDE_CHANNEL above reads the same two names.
CLAUDE_UPDATES_OFF = ("DISABLE_AUTOUPDATER", "DISABLE_UPDATES")


def runtime_install(rt, ver):
    """The vendor's installer of one runtime version for the worker user, into ~/.local/bin. The helper also runs it,
    to put the previous version back after an update that failed its check (lifecycle.Lifecycle.update_runtime)."""
    if rt == "codex":
        return CODEX_INSTALLER + " --release %s" % shlex.quote(ver)
    return "curl -fsSL https://claude.ai/install.sh | bash -s %s" % shlex.quote(ver)


# What a vendor installer prints when the machine could not reach the internet: the system's codes, as npm gives them,
# and curl's and wget's own words. Such a failure usually passes, so an install tries the step again by itself
# (NETWORK_RETRIES) before it says that it failed (T-35).
NETWORK_ERROR = re.compile(r"\bE(?:TIMEDOUT|CONNRESET|CONNREFUSED|AI_AGAIN|NOTFOUND|NETUNREACH|HOSTUNREACH)\b|"
                           r"\bcurl: \((?:6|7|28|35|52|56)\)|could not resolve host|unable to resolve host|"
                           r"temporary failure in name resolution|failed to connect|connection timed out|"
                           r"operation timed out|connection reset|network is unreachable|no route to host",
                           re.IGNORECASE)
NETWORK_RETRIES = 3     # tries again of an install step that failed on a network error, before it fails
NETWORK_WAIT = 20       # seconds before each of those tries


def network_failure(text):
    """True when an installer's output says that the machine could not reach the internet."""
    return bool(NETWORK_ERROR.search(text or ""))


def runtime_update(rt):
    """The vendor's own update of one runtime of the worker user in ~/.local/bin, to the newest version that the vendor
    gives: Claude Code's `update` command, which follows the channel and the floor that CLAUDE_CHANNEL set and does
    not go below the build that runs it, and Codex's installer without a release. The helper runs it, as the worker
    user, and checks what it installed (lifecycle.Lifecycle.update_runtime)."""
    if rt == "codex":
        return CODEX_INSTALLER
    return '"$HOME/.local/bin/claude" update'


def updates_off(rt, home):
    """Why the owner keeps this runtime's version as it is in this home, or None. For Claude Code that is a setting
    that turns its updates off (CLAUDE_UPDATES_OFF), and the helper's updates keep to it as Claude Code's own do.
    Codex has no such setting."""
    if rt != "claude":
        return None
    try:
        with open(os.path.join(home, ".claude", "settings.json")) as f:
            env = json.load(f).get("env")
    except (OSError, ValueError, AttributeError):
        return None
    off = [key for key in CLAUDE_UPDATES_OFF if isinstance(env, dict)
           and str(env.get(key, "")).strip().lower() not in ("", "0", "false")]
    return ("%s in ~/.claude/settings.json turns its updates off" % " and ".join(off)) if off else None


def claude_login_command(config, ip, login, checkout='"$HOME/fleet-pilot"', exe='"$HOME/.local/bin/claude"'):
    """The one command that the owner runs in Terminal for a worker's first Claude sign-in: this worker's managed SSH
    settings (its key and pinned host key), then the worker's own claude in its checkout, with the same worker
    environment as installation and the status check, so that Claude's first folder trust is for that checkout. Fleet
    does not run it and never sees what the owner types into Claude. A preparation gives the agent's checkout and the
    command that the worker's PATH finds, both as shell words."""
    remote = as_worker("cd %s && exec %s" % (checkout, exe))
    if login != "root":
        remote = "sudo -n " + remote
    return shlex.join(["ssh", "-F", str(config), "-t", str(ipaddress.ip_address(ip)), remote])


def tailscale_tags(value):
    """The --advertise-tags value of a new run: one or more tag:<name>, separated by commas, or "" for none. A saved run
    keeps its own."""
    if not str(value or "").strip():
        return ""
    tags = [t.strip() for t in str(value).split(",")]
    if not all(TAG_RE.match(t) for t in tags) or len(set(tags)) != len(tags):
        raise Abort("A Tailscale tag list is tag:<name>[,tag:<name>...], for example %s." % FLEET_TAG)
    return ",".join(tags)


def network_tags(hub):
    """The tags of a new run that names none, as this computer's own Tailscale sees the tailnet, by the rule of the
    hub's join line (hub.hub_tags): the tags of the hub's machine; where it carries none, FLEET_TAG only when a
    machine of the tailnet carries it already, which proves that the policy defines it; else "" for none, because
    Tailscale refuses a tag that the policy does not define. "" also when nothing says."""
    host = urllib.parse.urlparse(hub).hostname
    ts = shutil.which("tailscale") or (TAILSCALE_APP if os.path.exists(TAILSCALE_APP) else None)
    if not ts or not host:
        return ""
    try:
        done = subprocess.run([ts, "status", "--json"], capture_output=True, text=True, timeout=5,
                              stdin=subprocess.DEVNULL)
        status = json.loads(done.stdout) if done.returncode == 0 else {}
        nodes = [status.get("Self") or {}] + list((status.get("Peer") or {}).values())
        tagged = [n.get("Tags") or [] for n in nodes]
        own = next((t for n, t in zip(nodes, tagged) if host in (n.get("TailscaleIPs") or [])), [])
        own = [t for t in own if isinstance(t, str) and TAG_RE.match(t)]
        return ",".join(own) if own else FLEET_TAG if any(FLEET_TAG in t for t in tagged) else ""
    except (OSError, ValueError, AttributeError, TypeError, subprocess.SubprocessError):
        return ""


def as_worker(cmd):
    """A shell command that runs as the worker user, from its home folder, with its user services reachable.
    runuser keeps the caller's folder (/root), which the worker user cannot open, so the command starts with cd."""
    inner = ('cd "$HOME" || exit 1; export XDG_RUNTIME_DIR=/run/user/$(id -u); export PATH="$HOME/.local/bin:$PATH"; '
             + cmd)
    return "runuser -u %s -- bash -lc %s" % (WORKER_USER, shlex.quote(inner))


def as_user(login, user, cmd):
    """The same for the worker user of an existing machine (owner API 1.12), on Linux or macOS. The SSH login is that
    user or root. The command stops at its first error and gets the PATH of the worker services."""
    inner = ('set -e; cd "$HOME"; if [ -d "/run/user/$(id -u)" ]; then export XDG_RUNTIME_DIR="/run/user/$(id -u)"; fi; '
             'export PATH="$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"; ' + cmd)
    if login == user:
        return "bash -lc %s" % shlex.quote(inner)
    who, script = shlex.quote(user), shlex.quote(inner)
    return ("if command -v runuser >/dev/null 2>&1; then runuser -u %s -- bash -lc %s; "
            "else sudo -n -u %s -H bash -lc %s; fi" % (who, script, who, script))


# ---------------------------------------------------------------- the executor

class Onboarding:
    def __init__(self, channel: Channel, system: System, state_path: Path, state: dict, auth: dict, hub: str, repo: str):
        self.ch, self.sys, self.state_path, self.state, self.auth = channel, system, state_path, state, auth
        self.hub, self.repo = hub.rstrip("/"), repo
        self.askpass = None
        self.provider_secret = None

    # ---- state
    def save(self):
        self.state["updated"] = self.sys.now()
        tmp = self.state_path.with_suffix(".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.ch.mask(self.state), f, indent=2, sort_keys=True)   # no secret reaches the disk
        os.replace(str(tmp), str(self.state_path))

    @property
    def name(self):
        return self.state["name"]

    @property
    def host(self):
        return self.state["host"]

    @property
    def port(self):
        return int(self.state["port"])

    @property
    def address(self):
        """Where this run reaches the server: the address it was given, until the firewall step lets SSH in over
        Tailscale only (executor 1.3.2); from then on, and on every resume after it, the Tailscale address."""
        return self.state["tailscale_ip"] if self.state.get("ssh_private") else self.state["host"]

    @property
    def key_path(self):
        """The managed admin key. A preparation uses the key of the machine that this Mac set up."""
        return fleet_home() / "ssh" / ("%s_admin" % (self.state["machine"] if self.preparing else self.name))

    @property
    def existing(self):
        """Add agent on an existing machine (owner API 1.12) instead of a fresh server."""
        return self.state.get("mode") == "existing_machine"

    @property
    def preparing(self):
        """Prepare the other runtime of an existing agent (executor 1.3.0)."""
        return self.state.get("mode") == "prepare_runtime"

    # ---- ssh
    def managed(self, script, host=None, input=None, timeout=300, root=True):
        login = self.state["login"]
        if input is not None:
            # Data (for example an auth key) travels inside the script on stdin, never in arguments.
            script = "FLEET_INPUT=$(cat <<'FLEET_EOF'\n%s\nFLEET_EOF\n)\n%s" % (input, script)
        if root and login != "root":
            script = "sudo -n bash -s <<'FLEET_ROOT'\nset -eu\n%s\nFLEET_ROOT" % script
        return self.sys.ssh(host or self.address, self.port, login, script, auth="managed", identity=self.key_path,
                            timeout=timeout)

    def root(self, script, input=None, timeout=300, host=None):
        code, out, err = self.managed(script, host=host, input=input, timeout=timeout)
        return code, out, err

    def must(self, script, what, input=None, timeout=300):
        code, out, err = self.root(script, input=input, timeout=timeout)
        if code != 0:
            raise StepFailed("%s failed: %s" % (what, tail(err or out)))
        return out

    def proof(self, host):
        code, out, _ = self.managed("echo fleet-proof", host=host, root=False, timeout=60)
        return code == 0 and "fleet-proof" in out

    def provider(self, script, timeout=300):
        mode = self.auth.get("mode")
        if mode == "password":
            if self.provider_secret is None:
                self.provider_secret = self.ch.secret("provider_password")
                # An existing machine keeps its own access, so every one of its at most five connections uses it.
                self.askpass = AskpassServer(self.provider_secret, uses=8 if self.existing else 3)
            return self.sys.ssh(self.address, self.port, self.state["login"], script, auth="password",
                                askpass=self.askpass, timeout=timeout)
        if mode == "identity":
            return self.sys.ssh(self.address, self.port, self.state["login"], script, auth="identity",
                                identity=self.auth.get("identity_file"), timeout=timeout)
        return self.sys.ssh(self.address, self.port, self.state["login"], script, auth="agent", timeout=timeout)

    # ---- hub
    def hub_state(self):
        code, data = self.sys.http("GET", self.hub + "/ui/state")
        if code != 200:
            raise StepFailed("The hub did not answer /ui/state (%s): %s" % (code, data.get("error", "")))
        return data

    def hub_agent(self, data):
        for a in data.get("agents", []):
            if a.get("name") == self.name:
                return a
        return None

    # ---- known hosts
    def pin(self, host, port, keys):
        kh = fleet_home() / "ssh" / "known_hosts"
        kh.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(kh.parent), 0o700)
        existing = kh.read_text().splitlines() if kh.exists() else []
        token = host_token(host, port)
        lines = list(existing)
        for k in keys:
            line = "%s %s %s" % (token, k["type"], k["blob"])
            if line not in lines:
                lines.append(line)
        fd = os.open(str(kh), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")

    def scan(self, host):
        code, out, err = self.sys.keyscan(host, self.port)
        keys = parse_keyscan(out)
        if not keys:
            raise StepFailed("No host key from %s:%s: %s" % (host, self.port, tail(err)))
        return keys

    # ---- steps
    def s_preflight(self):
        """Before any change on the server: the hub must offer machines, and the name and address must be free."""
        data = self.hub_state()
        if "machines" not in (data.get("ui_features") or []):
            raise StepFailed("The hub does not offer machine onboarding yet ('machines' is not in ui_features). "
                             "Nothing on the server was changed.")
        code, mdata = self.sys.http("GET", "%s/ui/machines?db=%s" % (self.hub, urllib.parse.quote(str(data.get("db", "")))))
        if code != 200:
            raise StepFailed("The hub did not answer /ui/machines (%s): %s" % (code, mdata.get("error", "")))
        ours = self.state.get("registration_commit")
        for m in mdata.get("machines", []):
            same_name = self.name in (m.get("agent"), m.get("machine"))
            if same_name and not (ours and m.get("address") == self.state.get("tailscale_ip")):
                raise StepFailed("The hub already has a worker or machine named %s. Choose another name." % self.name)
            if m.get("address") and m.get("address") == self.host:
                raise StepFailed("The hub already has a machine at %s." % self.host)
        return ("skipped" if ours else "done"), "The hub offers machine onboarding; %s is free." % self.name

    def s_host_key(self):
        keys = self.scan(self.address)
        pinned = {k["sha256"] for k in self.state.get("host_keys", [])}
        if pinned:
            changed = [k for k in keys if k["sha256"] not in pinned]
            if changed:
                raise Abort("The server host key changed since it was confirmed (%s). Stop and check the server."
                            % ", ".join(k["sha256"] for k in changed))
            self.pin(self.address, self.port, keys)
            return "skipped", "The pinned host keys match."
        answer = self.ch.prompt("confirm_host_key", {"host": self.address, "port": self.port,
                                                     "fingerprints": [{"algorithm": k["type"], "sha256": k["sha256"]}
                                                                      for k in keys]})
        if answer is not True:
            raise Abort("The owner did not confirm the host key.")
        self.state["host_keys"] = [{"type": k["type"], "blob": k["blob"], "sha256": k["sha256"]} for k in keys]
        self.pin(self.address, self.port, keys)
        return "done", "%d host keys pinned." % len(keys)

    def ensure_key(self):
        path = self.key_path
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(str(path.parent), 0o700)
            code, _, err = self.sys.keygen(path, "fleet-admin %s" % self.name)
            if code != 0:
                raise StepFailed("Could not make the managed key: %s" % tail(err))
        os.chmod(str(path), 0o600)
        self.state["managed_key"] = str(path)
        return Path(str(path) + ".pub").read_text().strip()

    def s_provider_login(self):
        pub = self.ensure_key()
        if self.proof(self.address):
            info = kv(self.root(OS_CHECK)[1])
            self.check_os(info)
            return "skipped", "The managed key already works; provider access was not needed."
        script = BOOTSTRAP % {"key": shlex.quote(pub)}
        code, out, err = self.provider(script)
        if code != 0:
            raise StepFailed("Provider sign-in failed: %s" % tail(err or out))
        info = kv(out)
        self.check_os(info)
        if info.get("key") != "present":
            raise StepFailed("The managed key was not added.")
        return "done", "%s, %s access." % (info.get("os"), info.get("root"))

    def check_os(self, info):
        os_id = tuple((info.get("os") or " ").split(" ", 1))
        self.state["os"] = info.get("os")
        if os_id not in SUPPORTED_OS:
            raise StepFailed("Unsupported system %s. Use Ubuntu 22.04, 24.04 or 26.04, or Debian 12 or 13."
                             % info.get("os"))
        if info.get("systemd") != "yes":
            raise StepFailed("systemd is required.")
        if info.get("root") not in ("yes", "sudo"):
            raise StepFailed("The provider login needs root or passwordless sudo.")
        self.state["root_via"] = info.get("root")

    def s_managed_key(self):
        if not self.proof(self.address):
            raise StepFailed("A fresh connection with only the managed key failed.")
        code, out, _ = self.root("id -u")
        if code != 0 or out.strip() != "0":
            raise StepFailed("The managed key does not reach root.")
        return "done", "A fresh connection with only the managed key reached root."

    def s_packages(self):
        check = ("for p in %s; do dpkg-query -W -f='${Status}' \"$p\" 2>/dev/null | grep -q 'install ok installed' "
                 "|| echo \"missing=$p\"; done; echo checked=yes" % PACKAGES)

        def missing():
            out = self.root(check)[1]
            if "checked=yes" not in out:
                raise StepFailed("The package check did not run.")
            return [line.split("=", 1)[1] for line in out.splitlines() if line.startswith("missing=")]

        if not missing():
            return "skipped", "All base packages are installed."
        self.must("export DEBIAN_FRONTEND=noninteractive\n%s\n"
                  "apt-get -o DPkg::Lock::Timeout=%d install -y -q --no-install-recommends %s"
                  % (APT_UPDATE, APT_LOCK_WAIT, PACKAGES),
                  "Package installation", timeout=2 * APT_LOCK_WAIT + 600)
        left = missing()
        if left:
            raise StepFailed("Packages still missing: %s." % ", ".join(left))
        return "done", "Installed: %s." % PACKAGES

    def security_status(self):
        s = kv(self.must(SECURITY_STATUS, "Security update count"))
        if not s.get("pending", "").isdigit():
            raise StepFailed("The security update count gave no number.")
        return int(s["pending"]), s.get("reboot") == "yes", s.get("auto_reboot") == "true"

    def s_security_updates(self):
        """Turn on unattended security updates, then install the pending ones once with the same updater and policy.
        Never restarts the server: a needed reboot is only reported."""
        check = ("apt-config dump | grep -q 'APT::Periodic::Unattended-Upgrade \"1\"' && "
                 "systemctl is-enabled unattended-upgrades >/dev/null && echo enabled=yes || echo enabled=no")
        before = kv(self.root(check)[1]).get("enabled") == "yes"
        if not before:
            self.must("printf 'APT::Periodic::Update-Package-Lists \"1\";\\nAPT::Periodic::Unattended-Upgrade \"1\";\\n' "
                      "> /etc/apt/apt.conf.d/20auto-upgrades\nsystemctl enable --now unattended-upgrades",
                      "Security update setup")
            if kv(self.root(check)[1]).get("enabled") != "yes":
                raise StepFailed("Unattended security updates are still off.")
        self.must(APT_UPDATE, "Package list update",
                  timeout=APT_LOCK_WAIT + 300)
        pending, reboot, auto_reboot = self.security_status()
        found, installed = pending, False
        if pending and not auto_reboot:
            self.must(SECURITY_APPLY, "Security update installation", timeout=APT_LOCK_WAIT + 1800)
            installed = True
            pending, reboot, _ = self.security_status()
        self.state["security"] = {"pending_security": pending, "reboot_required": reboot}
        detail = "Security updates on; %d pending; reboot %s." % (pending, "required" if reboot else "not required")
        if installed:
            detail = "Installed the pending security updates (%d before). %s" % (found, detail)
        elif pending:
            detail += (" Not installed now: this server restarts by itself after updates "
                       "(Unattended-Upgrade::Automatic-Reboot), and setup never restarts a server.")
        return ("done" if installed or not before else "skipped"), detail

    def s_worker_user(self):
        check = ("id -u %(u)s >/dev/null 2>&1 && echo exists=yes || echo exists=no\n"
                 "passwd -S %(u)s 2>/dev/null | awk '{print \"locked=\"$2}'\n"
                 "id -nG %(u)s 2>/dev/null | tr ' ' '\\n' | grep -qxE 'sudo|admin|wheel' && echo sudo=yes || echo sudo=no\n"
                 "echo linger=$(loginctl show-user %(u)s -p Linger --value 2>/dev/null || echo no)\n"
                 "echo mode=$(stat -c %%a /home/%(u)s 2>/dev/null || echo none)") % {"u": WORKER_USER}

        def good(i):
            return (i.get("exists") == "yes" and i.get("locked") == "L" and i.get("sudo") == "no"
                    and i.get("linger") == "yes" and i.get("mode") == "700")

        if good(kv(self.root(check)[1])):
            return "skipped", "User %s exists: locked password, no sudo, linger on." % WORKER_USER
        self.must(("id -u %(u)s >/dev/null 2>&1 || useradd --create-home --shell /bin/bash --user-group %(u)s\n"
                   "passwd -l %(u)s >/dev/null\nchmod 700 /home/%(u)s\n"
                   "for g in sudo admin wheel; do gpasswd -d %(u)s $g >/dev/null 2>&1 || true; done\n"
                   "loginctl enable-linger %(u)s") % {"u": WORKER_USER}, "Worker user setup")
        info = kv(self.root(check)[1])
        if not good(info):
            raise StepFailed("The worker user is not as required: %s" % info)
        return "done", "User %s: locked password, no sudo, linger on." % WORKER_USER

    def ts_status(self):
        code, out, _ = self.root("tailscale status --json 2>/dev/null || true")
        try:
            data = json.loads(out or "{}")
        except ValueError:
            return {}, ""
        ips = [ip for ip in ((data.get("Self") or {}).get("TailscaleIPs") or []) if "." in ip]
        return data, (ips[0] if ips else "")

    def s_tailscale(self):
        data, ip = self.ts_status()
        if data.get("BackendState") == "Running" and ip:
            self.state["tailscale_ip"] = ip
            self.pin_tailscale(ip)
            return "skipped", "Joined as %s." % ip
        self.must(TAILSCALE_INSTALL, "Tailscale installation", timeout=2 * APT_LOCK_WAIT + 300)
        tag = self.state.get("tailscale_tag") or ""
        tags = " --advertise-tags=%s" % shlex.quote(tag) if tag else ""
        up = "tailscale up%s --accept-dns=false --ssh=false" % tags        # its own name
        if self.auth.get("tailscale") == "auth_key":
            # --reset: an earlier `tailscale up` on this server (a join line, a sign-in or a run with another tag) left
            # its settings, and Tailscale refuses a `tailscale up` that does not name each of them again. This line runs
            # only when Tailscale does not run (ts_status above): it has no login, it waits for a sign-in or for an
            # admin, or somebody stopped it. --reset then also removes the settings of a stopped Tailscale, which a
            # worker does not need.
            key = self.ch.secret("tailscale_auth_key")
            self.must("printf '%%s\\n' \"$FLEET_INPUT\" | install -m 600 /dev/stdin /run/fleet-ts-authkey\n"
                      "%s --reset --auth-key=file:/run/fleet-ts-authkey --timeout=%ds "
                      "|| { rm -f /run/fleet-ts-authkey; exit 1; }\n"
                      "rm -f /run/fleet-ts-authkey" % (up, TAILSCALE_UP_WAIT), "Tailscale join", input=key,
                      timeout=TAILSCALE_UP_WAIT + 60)
        else:
            self.root("%s --timeout=10s >/dev/null 2>&1 || true" % up, timeout=120)
            data, ip = self.ts_status()
            if not (data.get("BackendState") == "Running" and ip):
                url = data.get("AuthURL") or ""
                if not url:
                    raise StepFailed("Tailscale gave no sign-in link.")
                self.ch.prompt("open_url", {"url": url, "purpose": "tailscale_login"})
                deadline = self.sys.now() + 600
                while self.sys.now() < deadline:
                    data, ip = self.ts_status()
                    if data.get("BackendState") == "Running" and ip:
                        break
                    self.sys.sleep(5)
        data, ip = self.ts_status()
        if not (data.get("BackendState") == "Running" and ip):
            raise StepFailed("The server did not join the private network.")
        self.state["tailscale_ip"] = ip
        self.pin_tailscale(ip)
        return "done", "Joined as %s with %s." % (ip, tag)

    def pin_tailscale(self, ip):
        pinned = {k["sha256"] for k in self.state.get("host_keys", [])}
        keys = self.scan(ip)
        if any(k["sha256"] not in pinned for k in keys):
            raise Abort("The host key on the Tailscale address differs from the confirmed key. Stop and check.")
        self.pin(ip, self.port, keys)
        write_ssh_config(self.name, ip, self.state["login"], self.port, self.key_path)

    def s_firewall(self):
        """Incoming traffic over Tailscale only, SSH included (executor 1.3.2): no public SSH rule is added, and the one
        that executors before it added (`fleet ssh`) is removed. The firewall changes only after a fresh SSH proof on
        the Tailscale address and over that address, so a tailnet that does not let this Mac in leaves the server as it
        was. The run then saves that it moved, so a resume never goes back to the public address. The setup arms a
        rollback that turns the firewall off after five minutes; only a second fresh proof on the Tailscale address
        cancels it. A rollback that an earlier run armed and did not cancel (a failed proof, or a stop) is cancelled
        after the same proof. A firewall with no armed rollback gets no change."""
        ip = self.state.get("tailscale_ip")
        if not ip:
            raise StepFailed("The server has no Tailscale address, so the firewall stays as it is: one that lets SSH in "
                             "over Tailscale only would leave no way in.")
        check = ("ufw status verbose 2>/dev/null | grep -q '^Status: active' && echo active=yes || echo active=no\n"
                 "ufw status 2>/dev/null | grep -q '# fleet ssh *$' && echo public=yes || echo public=no\n"
                 "ufw status 2>/dev/null | grep -qE 'on tailscale0 +ALLOW|ALLOW IN +Anywhere on tailscale0' && echo ts=yes || echo ts=no\n"
                 "systemctl is-active --quiet fleet-ufw-rollback.timer && echo rollback=armed || echo rollback=none")
        want = {"active": "yes", "public": "no", "ts": "yes"}
        info = kv(self.root(check)[1])
        proved = {k: info.get(k) for k in want} == want and self.proof(ip)
        if proved and info.get("rollback") != "armed":
            self.state["ssh_private"] = True
            return "skipped", "Firewall active; SSH comes in over Tailscale only."
        if not proved:
            if not self.proof(ip):
                raise StepFailed("SSH does not reach the server on its Tailscale address %s, so the firewall stays as it "
                                 "is: it lets SSH in over Tailscale alone. Let this Mac reach %s on port %d in the "
                                 "tailnet policy, then resume." % (ip, ip, self.port))
            self.state["ssh_private"] = True        # from here, every connection goes to the Tailscale address
            self.save()
            self.must(FIREWALL, "Firewall setup")
            if not self.proof(ip):
                raise StepFailed("A fresh SSH proof on the Tailscale address %s failed. The firewall turns itself off "
                                 "within five minutes." % ip)
        self.must("systemctl stop fleet-ufw-rollback.timer", "Rollback cancel")
        info = kv(self.root(check)[1])
        if {k: info.get(k) for k in want} != want or info.get("rollback") != "none":
            raise StepFailed("Firewall rules are not as required: %s" % info)
        return "done", ("Firewall active; SSH proved on the Tailscale address; the rollback that an earlier run armed is "
                        "cancelled." if proved else "Firewall active; SSH comes in over Tailscale only, proved there; "
                        "rollback cancelled.")

    def s_hub_reach(self):
        out = self.must(as_worker("curl -fsS -m 10 %s/health >/dev/null && echo health=yes; "
                                  "git ls-remote %s HEAD >/dev/null && echo git=yes; true"
                                  % (shlex.quote(self.hub), shlex.quote(self.repo))),
                        "Hub reach")
        info = kv(out)
        if info.get("health") != "yes" or info.get("git") != "yes":
            raise StepFailed("The worker cannot reach the hub over Tailscale. Check the access rule for "
                             "%s to the hub ports 8765 and 9418." % (self.state.get("tailscale_tag") or "this machine"))
        return "done", "The worker reaches the hub and its Git repository."

    def s_register(self):
        data = self.hub_state()
        if self.hub_agent(data) and self.state.get("registration_commit"):
            return "skipped", "The hub lists %s." % self.name
        ip = self.state.get("tailscale_ip")
        revision = self.registration(data, lambda kit: register_in_kit(kit, self.name, self.state["runtime"], ip,
                                                                       self.state["login"], self.port),
                                     "Register worker %s at %s" % (self.name, ip))
        return "done", "Registered at %s in %s." % (ip, revision[:12])

    def config_ref(self, kit):
        """Check out the hub's configuration ref in this clone and return its name: a registration changes team.json
        and a profile, which belong there and never on the code branch. An origin without that ref is a Fleet before
        the split of 2026-10-17, and the clone's own branch is used."""
        if self.sys.git(["rev-parse", "--verify", "--quiet", "refs/remotes/origin/" + CONFIG_BRANCH],
                        cwd=str(kit))[0] != 0:
            code, out, _ = self.sys.git(["symbolic-ref", "--short", "HEAD"], cwd=str(kit))
            return out.strip() if code == 0 and out.strip() else "main"
        code, _, err = self.sys.git(["checkout", "-q", CONFIG_BRANCH], cwd=str(kit))
        if code != 0:
            raise StepFailed("Could not check out %s in the fleet repository: %s" % (CONFIG_BRANCH, tail(err)))
        return CONFIG_BRANCH

    def registration(self, data, change, message):
        """Make the team change in a temporary clone, push it, reload the hub and wait until it lists the agent.

        A push that fails is followed by a fresh fetch, and the change is made again on the ref's new tip: the hub
        commits by itself after a registration ("Fleet gave <agent> by default"), and a rebase onto that commit can
        conflict, which leaves HEAD at the tip without the change, so that the next push sends nothing and the hub
        reloads a revision without the agent. A tip that holds the change already needs no push."""
        work = Path(tempfile.mkdtemp(prefix="fleet-register-"))
        try:
            code, _, err = self.sys.git(["clone", "-q", self.repo, str(work / "kit")])
            if code != 0:
                raise StepFailed("Could not clone the fleet repository: %s" % tail(err))
            kit = work / "kit"
            branch = self.config_ref(kit)
            made = None                                 # the last commit that this run made
            for attempt in range(3):
                steps = ([["fetch", "-q", "origin"], ["reset", "-q", "--hard", "origin/" + branch]] if attempt else [])
                for args in steps:
                    code, _, err = self.sys.git(args, cwd=str(kit))
                    if code != 0:
                        raise StepFailed("git %s failed: %s" % (args[0], tail(err)))
                if not change(kit):
                    break
                for args in (["add", "team.json", "profiles/%s.md" % self.name],
                             ["commit", "-q", "-m", message]):
                    code, _, err = self.sys.git(args, cwd=str(kit))
                    if code != 0:
                        raise StepFailed("git %s failed: %s" % (args[0], tail(err)))
                made = self.sys.git(["rev-parse", "HEAD"], cwd=str(kit))[1].strip()
                code, _, err = self.sys.git(["push", "-q", "origin", "HEAD:" + branch], cwd=str(kit))
                if code == 0:
                    break
            else:
                raise StepFailed("git push failed: %s" % tail(err))
            code, rev, err = self.sys.git(["rev-parse", "HEAD"], cwd=str(kit))
            revision = rev.strip()
            if made and self.sys.git(["merge-base", "--is-ancestor", made, revision], cwd=str(kit))[0] != 0:
                raise StepFailed("The revision %s does not hold the registration commit %s. Nothing was reloaded."
                                 % (revision[:12], made[:12]))
        finally:
            shutil.rmtree(str(work), ignore_errors=True)
        self.state["registration_commit"] = revision
        self.save()     # before the reload: a run that stops after the hub applied it must not refuse its own name
        code, body = self.sys.http("POST", self.hub + "/ui/team/reload",
                                   {"request_id": str(uuid.uuid4()), "db": data.get("db"), "revision": revision},
                                   {"X-Fleet-Client": "fleet-onboard/%d/%s" % (PROTOCOL, self.ch.run)})
        if code != 200:
            raise StepFailed("The hub did not reload the team (%s): %s" % (code, body.get("error", "")))
        if not self.hub_agent(self.hub_state()):
            raise StepFailed("The hub does not list %s after the reload." % self.name)
        return revision

    # ---- add agent on an existing machine (owner API 1.12)
    def team_view(self, db):
        code, team = self.sys.http("GET", "%s/ui/team?db=%s" % (self.hub, urllib.parse.quote(str(db or ""))))
        if code != 200:
            raise StepFailed("The hub did not answer /ui/team (%s): %s" % (code, team.get("error", "")))
        return team

    def worker(self, cmd, timeout=300):
        """One command as the machine's worker user, over the machine's existing SSH access."""
        return self.provider(as_user(self.state["login"], self.state["worker_user"], cmd), timeout=timeout)

    def service_name(self):
        system = self.state.get("system")
        return None if system is None else ("com.agentfleet.%s" if system == "Darwin" else "fleet-%s.service") % self.name

    def x_preflight(self):
        """Before any change: the hub must offer agents on a shared machine, have this machine ready for one more
        agent, and not know the name. Host, port, login and worker user come from the hub, never from the caller."""
        data = self.hub_state()
        if "agent_auth" not in (data.get("ui_features") or []):
            raise StepFailed("The hub does not offer agents on a shared machine yet ('agent_auth' is not in "
                             "ui_features). Nothing was changed.")
        team, machine = self.team_view(data.get("db")), self.state["machine"]
        machines = team.get("machines") if isinstance(team.get("machines"), dict) else {}
        entry = machines.get(machine)
        if not isinstance(entry, dict) and self.state.get("host"):
            # A machine takes its name from Tailscale (release 2026.11.146), so it can be renamed under a saved run.
            # Its address stays: the run follows the machine that has the address it saved.
            same = [n for n, m in machines.items() if isinstance(m, dict) and m.get("address") == self.state["host"]]
            if len(same) == 1:
                machine = self.state["machine"] = same[0]
                entry = machines[machine]
        if not isinstance(entry, dict):
            raise StepFailed("The hub has no machine %s. Nothing was changed." % machine)
        ours = self.state.get("registration_commit")
        if not ours:   # after its registration, a half-installed agent makes its own machine not ready
            if self.name in machines or any(line.get("agent") == self.name for line in team.get("lines") or []):
                raise StepFailed("The hub already has an agent or machine named %s. Choose another name." % self.name)
            ready = entry.get("add_agent") or {}
            if ready.get("ready") is not True:
                raise StepFailed("%s is not ready for another agent (%s). Nothing was changed."
                                 % (machine, ", ".join(map(str, ready.get("missing") or [])) or "no reason given"))
        ssh = entry.get("ssh") or {}
        access = {"host": entry.get("address"), "port": ssh.get("port"), "login": ssh.get("user"),
                  "worker_user": entry.get("worker_user")}
        try:
            ipaddress.ip_address(str(access["host"]))
            good = (isinstance(access["port"], int) and 1 <= access["port"] <= 65535
                    and all(USER_RE.match(str(access[k] or "")) for k in ("login", "worker_user")))
        except ValueError:
            good = False
        if not good:
            raise StepFailed("The hub gave no usable SSH access for %s. Nothing was changed." % machine)
        if access["login"] not in ("root", access["worker_user"]):
            raise StepFailed("The SSH user of %s is neither root nor its worker user. Nothing was changed." % machine)
        saved = {k: self.state.get(k) for k in access}
        if any(v is not None for v in saved.values()) and saved != access:
            raise StepFailed("The SSH access of %s changed since this run started. Nothing was changed." % machine)
        self.state.update(access)
        return ("skipped" if ours else "done"), "%s can take %s; SSH as %s, worker user %s." % (
            machine, self.name, access["login"], access["worker_user"])

    def s_runtime_check(self):
        """The runtime must be installed for the worker user. Its sign-in is read, never changed: a status that the
        runtime does not report clearly stays unknown, and the agent's setup check confirms it before activation."""
        rt = self.state["runtime"]
        status = ('s=$(codex login status 2>&1 || true); case "$s" in *"Not logged in"*) echo signed_in=no;; '
                  '*"Logged in"*) echo signed_in=yes;; *) echo signed_in=unknown;; esac' if rt == "codex" else
                  's=$(claude auth status --json 2>/dev/null || true); '
                  'if printf "%s" "$s" | grep -q "\\"loggedIn\\": *true"; then echo signed_in=yes; '
                  'elif printf "%s" "$s" | grep -q "\\"loggedIn\\": *false"; then echo signed_in=no; '
                  'else echo signed_in=unknown; fi')
        # Only these derived lines leave the machine: never the runtime's own status text, which can name the account.
        code, out, err = self.worker("echo fleet-runtime-check=1; echo user=$(id -un); echo system=$(uname -s); "
                                     "if ! command -v %s >/dev/null 2>&1; then echo installed=no; exit 0; fi; "
                                     "echo installed=yes; echo version=$(%s --version 2>/dev/null | head -n 1); %s"
                                     % (rt, rt, status), timeout=120)
        info = kv(out)
        if code != 0 or info.get("fleet-runtime-check") != "1":
            raise StepFailed("The runtime check did not run: %s" % tail(err, 160))
        if info.get("user") != self.state["worker_user"]:
            raise StepFailed("The check ran as %s, not as the worker user %s." % (info.get("user"), self.state["worker_user"]))
        self.state["system"] = info.get("system")
        user, label = self.state["worker_user"], rt.capitalize()
        if info.get("installed") != "yes":
            raise StepFailed("%s is not installed for %s. Setup does not install a runtime on an existing machine; "
                             "nothing was changed." % (label, user))
        version = info.get("version") or "version not reported"
        signed = info.get("signed_in")
        if signed == "no" and info.get("system") == "Darwin":
            # A Mac keeps the sign-in in the login keychain, which an SSH session cannot read: a signed-in Mac reads
            # "no" here (lifecycle.remember_signed_in). The setup check reads it in the login session.
            signed = "unknown"
        if signed == "no":
            raise NeedsOwner("%s (%s) is installed for %s but not signed in. Setup does not sign in a runtime, so it "
                             "stopped before any change. Resume this run when it is signed in." % (label, version, user))
        if signed == "yes":
            return "done", "%s (%s) is installed and signed in for %s." % (label, version, user)
        return "done", ("%s (%s) is installed for %s. Its sign-in status is unknown; the agent's setup check confirms "
                        "it before activation." % (label, version, user))

    def s_checkout(self):
        """A separate checkout for the new agent, on the configuration ref when the origin has it, as join.sh clones
        one: the code branch of the hub's repository stays at an old release, and its fleet.py could not make the
        service. A folder that this run did not make stops the run."""
        folder = "fleet-%s" % self.name
        token = self.state.setdefault("checkout_token", uuid.uuid4().hex)
        self.save()                                   # the mark exists before the folder
        mark = '"$HOME/%s/.git/fleet-onboarding"' % folder
        # DevOps plan 0.2: the new checkout starts at the machine's own checked revision, the one that its first
        # agent's checkout ~/fleet-pilot took under lifecycle.may_take, and not at whatever the hub's repository holds;
        # from there it moves under the same check. A machine with no such checkout takes the clone as its first one.
        # A clone that cannot start there is removed again: this run made it a moment before.
        code, out, err = self.worker(
            'if [ -e "$HOME/%(f)s" ]; then echo fleet-checkout=exists; echo mark=$(cat %(m)s 2>/dev/null || true); '
            'exit 0; fi; here=$(git -C "$HOME/fleet-pilot" rev-parse -q --verify HEAD 2>/dev/null || true); '
            '{ git clone -q -b %(b)s %(repo)s "$HOME/%(f)s" || git clone -q %(repo)s "$HOME/%(f)s"; } || exit 1; '
            'if [ -n "$here" ] && ! git -C "$HOME/%(f)s" reset -q --hard "$here"; then rm -rf "$HOME/%(f)s"; '
            'echo "the new checkout could not start at this machine\'s own revision $here" >&2; exit 1; fi; '
            'echo %(t)s > %(m)s && echo fleet-checkout=cloned'
            % {"f": folder, "m": mark, "b": CONFIG_BRANCH, "repo": shlex.quote(self.repo), "t": token}, timeout=300)
        info = kv(out)
        if code != 0 or info.get("fleet-checkout") not in ("exists", "cloned"):
            raise StepFailed("The checkout could not be cloned: %s" % tail(err, 160))
        if info["fleet-checkout"] == "exists":
            if info.get("mark") != token:
                raise StepFailed("~/%s already exists on %s. Setup does not use a folder that it did not make."
                                 % (folder, self.state["machine"]))
            return "skipped", "~/%s is the checkout that this run made." % folder
        return "done", "Cloned ~/%s for %s." % (folder, self.state["worker_user"])

    def s_agent_key(self):
        """The agent's key stays on the machine; only its SHA-256 leaves it, and the owner key route registers it."""
        code, out, _ = self.worker('cd "$HOME/fleet-%s"; python3 fleet.py key %s' % (self.name, shlex.quote(self.name)),
                                   timeout=120)
        lines = [line.strip() for line in out.splitlines() if line.strip()]
        sha = lines[-1] if lines else ""
        if code != 0 or len(lines) != 1 or not SHA256_RE.match(sha):
            # Its output is never repeated: if a key command printed more than the SHA-256, it stays off the record.
            raise StepFailed("The agent key command did not give one SHA-256 (exit %s)." % code)
        saved = self.state.get("agent_key") or {}
        if saved.get("sha256") == sha and saved.get("registered"):
            return "skipped", "The hub has the key %s…." % sha[:12]
        request = saved["request_id"] if saved.get("sha256") == sha and saved.get("request_id") else str(uuid.uuid4())
        self.state["agent_key"] = {"sha256": sha, "request_id": request, "registered": False}
        self.save()                                   # a repeat sends the same request
        db = self.hub_state().get("db")
        code, body = self.sys.http("POST", "%s/ui/team/agents/%s/key" % (self.hub, urllib.parse.quote(self.name)),
                                   {"request_id": request, "db": db, "sha256": sha},
                                   {"X-Fleet-Client": "fleet-onboard/%d/%s" % (PROTOCOL, self.ch.run)})
        if code != 200 or body.get("agent") != self.name or body.get("key") is not True:
            raise StepFailed("The hub did not register the agent key (%s): %s" % (code, body.get("error", "")))
        self.state["agent_key"]["registered"] = True
        return "done", "Registered the key %s…; the key stays on %s." % (sha[:12], self.state["machine"])

    def x_register(self):
        data = self.hub_state()
        if self.hub_agent(data) and self.state.get("registration_commit"):
            return "skipped", "The hub lists %s." % self.name
        machine = self.state["machine"]
        revision = self.registration(data, lambda kit: register_in_kit(kit, self.name, self.state["runtime"], None,
                                                                       machine=machine),
                                     "Register agent %s on %s" % (self.name, machine))
        return "done", "Registered on %s in %s: inactive, no credential access." % (machine, revision[:12])

    def service_state(self):
        """This agent's service on the machine: its definition file (unit=none, ours or other), the job that the
        service manager has loaded (loaded=none, ours or other) and whether it runs. Ours means exactly the new
        checkout's fleet.py for this agent, as `fleet.py service` writes it."""
        a = self.name
        if self.state.get("system") == "Darwin":
            script = ('dir="$HOME/fleet-%(a)s"; unit="$HOME/Library/LaunchAgents/com.agentfleet.%(a)s.plist"; '
                      'if [ ! -e "$unit" ]; then echo unit=none; '
                      'elif grep -qF "<string>$dir/fleet.py</string>" "$unit" && grep -qF "<string>%(a)s</string>" "$unit"; '
                      'then echo unit=ours; else echo unit=other; fi; '
                      'job=$(launchctl print "gui/$(id -u)/com.agentfleet.%(a)s" 2>/dev/null || true); '
                      'if [ -z "$job" ]; then echo loaded=none; echo running=no; else '
                      'case "$job" in *"$dir/fleet.py"*) echo loaded=ours;; *) echo loaded=other;; esac; '
                      'case "$job" in *"state = running"*) echo running=yes;; *) echo running=no;; esac; fi')
        else:
            script = ('dir="$HOME/fleet-%(a)s"; unit="$HOME/.config/systemd/user/fleet-%(a)s.service"; '
                      'if [ ! -e "$unit" ]; then echo unit=none; '
                      'elif grep -qF "$dir/fleet.py" "$unit" && grep -qF \'"run" "%(a)s"\' "$unit"; '
                      'then echo unit=ours; else echo unit=other; fi; '
                      'wd=$(systemctl --user show -p WorkingDirectory --value fleet-%(a)s.service 2>/dev/null || true); '
                      'if [ -z "$wd" ]; then echo loaded=none; elif [ "$wd" = "$dir" ]; then echo loaded=ours; '
                      'else echo loaded=other; fi; '
                      'if systemctl --user is-active --quiet fleet-%(a)s.service; then echo running=yes; '
                      'else echo running=no; fi')
        code, out, err = self.worker(script % {"a": a}, timeout=60)
        info = kv(out)
        if code != 0 or not {"unit", "loaded", "running"} <= set(info):
            raise StepFailed("The agent service could not be checked: %s" % tail(err, 160))
        return info

    def x_worker_install(self):
        """The service of the new checkout, made by `fleet.py service` and then started. A service of this name for
        another checkout or agent, running or not, stays as it is and stops the run. A Codex agent's checkout is
        trusted first with the existing installer function; an owner's own setting that does not trust it stays."""
        service, where = self.service_name(), self.state["machine"]
        found = self.service_state()
        if "other" in (found["unit"], found["loaded"]):
            raise StepFailed("%s on %s belongs to another checkout or agent. Setup leaves it unchanged." % (service, where))
        if (found["unit"], found["loaded"], found["running"]) == ("ours", "ours", "yes"):
            return "skipped", "%s is running from ~/fleet-%s." % (service, self.name)
        trust = ('t=$(python3 -c "import worker_install; print(worker_install.trust_codex_checkout())"); '
                 'echo trust=$t; if [ "$t" = kept ]; then exit 0; fi; ' if self.state["runtime"] == "codex" else "")
        if self.state.get("system") == "Darwin":
            job = '"gui/$(id -u)/com.agentfleet.%s"' % self.name
            start = ('if launchctl print %s >/dev/null 2>&1; then launchctl kickstart %s; else launchctl bootstrap '
                     '"gui/$(id -u)" "$HOME/Library/LaunchAgents/com.agentfleet.%s.plist"; fi' % (job, job, self.name))
        else:
            start = "systemctl --user enable --now fleet-%s.service" % self.name
        code, out, err = self.worker('cd "$HOME/fleet-%s"; %s; %spython3 fleet.py service %s >/dev/null; %s; '
                                     'echo started=yes' % (self.name, TAKE, trust, shlex.quote(self.name), start),
                                     timeout=300)
        info = kv(out)
        if info.get("trust") == "kept":
            raise NeedsOwner("Codex has its own setting for ~/fleet-%s that does not trust it. Setup leaves that "
                             "setting unchanged, and a Codex session there would stop at its trust question. "
                             "Resume this run when the setting trusts the checkout." % self.name)
        if code != 0 or info.get("started") != "yes":
            raise StepFailed("The agent service did not start: %s" % tail(err, 160))
        after = self.service_state()
        if (after["unit"], after["loaded"], after["running"]) != ("ours", "ours", "yes"):
            raise StepFailed("%s is not running from ~/fleet-%s." % (service, self.name))
        return "done", "%s is running from ~/fleet-%s." % (service, self.name)

    def x_verify(self):
        """The new agent reports a fresh status with its key, and the hub has it inactive with no credential access."""
        line, problems = {}, []
        for _ in range(12):
            data = self.hub_state()
            seen = (self.hub_agent(data) or {}).get("last_seen")
            fresh = bool(seen) and self.sys.now() - float(seen) < 120
            code, mdata = self.sys.http("GET", "%s/ui/machines?db=%s" % (self.hub, urllib.parse.quote(str(data.get("db", "")))))
            row = next((m for m in (mdata.get("machines") or []) if m.get("agent") == self.name), {}) if code == 200 else {}
            keyed = "agent_key" in (row.get("features") or [])
            line = next((x for x in self.team_view(data.get("db")).get("lines") or [] if x.get("agent") == self.name), {})
            auth = (line.get("auth") or {}).get("key") is True
            if fresh and keyed and auth:
                break
            self.sys.sleep(10)
        else:
            problems += [what for what, ok in (("a fresh status", fresh), ("the agent_key feature", keyed),
                                               ("its key on the hub", auth)) if not ok]
        if line.get("active") is not False:
            problems.append("it must be inactive")
        if line.get("vault") != "none":
            problems.append("it must have no credential access")
        if problems:
            raise StepFailed("Not ready: " + "; ".join(problems) + ".")
        return "done", "%s reports with its key; inactive with no credential access until its setup." % self.name

    def runtime_bin(self):
        return "$HOME/.local/bin/%s" % self.state["runtime"]

    def s_runtime(self):
        rt, ver = self.state["runtime"], self.state.get("runtime_version") or RUNTIME_PINS[self.state["runtime"]]
        check = as_worker("%s --version 2>/dev/null || true" % self.runtime_bin())
        current = self.root(check)[1].strip()
        if current and (ver == "stable" or ver in current or not_older(current, ver)):
            return "skipped", current + self.claude_updates(self.runtime_bin())     # also a newer build: its floor
        self.must(as_worker("mkdir -p $HOME/.local/bin; " + runtime_install(rt, ver)), "Runtime installation", timeout=900)
        current = self.root(check)[1].strip()
        if not current or (ver != "stable" and ver not in current):
            raise StepFailed("The runtime is not installed as %s: %s" % (ver, current))
        return "done", current + self.claude_updates(self.runtime_bin())

    def claude_updates(self, exe):
        """After Fleet's own installation of Claude Code (exe: its command, a shell word): its updates follow the stable
        channel, with a floor at the installed version (CLAUDE_CHANNEL). Text for the step's detail; "" for Codex,
        whose installed version stays by itself."""
        if self.state["runtime"] != "claude":
            return ""
        code, out, err = self.root(as_worker("python3 -c %s %s" % (shlex.quote(CLAUDE_CHANNEL), exe)), timeout=120)
        info = kv(out)
        if code != 0 or info.get("fleet-claude-channel") != "1" or not info.get("floor"):
            raise StepFailed("The update channel of Claude could not be set: %s" % tail(err or out, 200))
        return ". Updates follow the stable channel, not below %s%s." % (
            info["floor"], "; an existing setting turns updates off, and it stays" if info.get("updates_off") else "")

    def s_runtime_login(self):
        if self.state["runtime"] != "codex":
            return self.claude_login()
        status_cmd = as_worker("%s login status 2>&1 || true" % self.runtime_bin())

        def signed_in():
            text = self.root(status_cmd)[1]
            return "Logged in" in text and "Not logged in" not in text

        if signed_in():
            return "skipped", "Codex is signed in."
        return self.codex_device_login(self.runtime_bin(), signed_in)

    def codex_device_login(self, exe, signed_in):
        """Codex device sign-in with the command exe (a shell word): its link and code go to the app, then a wait of up
        to 15 minutes for signed_in(). The code log is removed afterwards."""
        self.must(as_worker("umask 077; %s; nohup %s login --device-auth > $HOME/.fleet-codex-login.log 2>&1 &"
                            % (STOP_CODEX_LOGIN, exe)), "Codex sign-in start")
        url = code = ""
        for _ in range(15):
            text = ANSI_RE.sub("", self.root(as_worker("cat $HOME/.fleet-codex-login.log 2>/dev/null || true"))[1])
            m_url = re.search(r"https://\S+", text)
            m_code = re.search(r"\b[A-Z0-9]{4}-[A-Z0-9]{4,6}\b", text)
            if m_url and m_code:
                url, code = m_url.group(0), m_code.group(0)
                break
            self.sys.sleep(2)
        if not url:
            raise StepFailed("Codex gave no sign-in link.")
        try:
            self.ch.prompt("open_url", {"url": url, "code": code, "purpose": "codex_login"})
            deadline = self.sys.now() + 900
            while self.sys.now() < deadline:
                if signed_in():
                    return "done", "Codex is signed in."
                self.sys.sleep(5)
            raise StepFailed("Codex sign-in did not finish within 15 minutes.")
        finally:
            self.root(as_worker("%s; rm -f $HOME/.fleet-codex-login.log" % STOP_CODEX_LOGIN))

    def claude_signed_in(self):
        """yes, no or unknown, from the worker's derived status lines. A status command that fails, or that disagrees
        with itself, is unknown: never "not signed in"."""
        code, out, _ = self.root(as_worker(CLAUDE_STATUS), timeout=120)
        info = kv(out)
        if code != 0 or info.get("fleet-claude-auth") != "1":
            return "unknown"
        if info.get("rc") == "0" and info.get("logged_in") == "yes":
            return "yes"
        if info.get("rc") == "1" and info.get("logged_in") == "no":
            return "no"
        return "unknown"

    def claude_login(self):
        """Claude Code documents its sign-in on a server only in its own terminal screen: open the link, sign in, paste
        the code that the browser shows. So the app shows one command for the owner's Terminal, and setup waits until
        the worker reports a sign-in. Copying the command only starts the wait. A signed-in account stays as it is."""
        state = self.claude_signed_in()
        if state == "yes":
            return "skipped", "Claude is signed in."
        if state == "unknown":
            raise StepFailed("The Claude status check failed on the worker. Resume to check again.")
        ip = self.state.get("tailscale_ip")
        if not ip:
            raise StepFailed("The worker has no private address for the sign-in command.")
        self.must(as_worker("test -d $HOME/fleet-pilot || git clone -q %s $HOME/fleet-pilot" % shlex.quote(self.repo)),
                  "Worker checkout")
        return self.claude_terminal(ip, '"$HOME/fleet-pilot"', '"$HOME/.local/bin/claude"', self.claude_signed_in)

    def claude_terminal(self, ip, checkout, exe, status):
        """The `terminal` prompt with the command that opens exe in checkout (shell words) on the worker at ip, then a
        wait of up to 15 minutes until status() gives yes. The SSH settings block is the machine's own."""
        config = write_ssh_config(self.state["machine"] if self.preparing else self.name, ip, self.state["login"],
                                  self.port, self.key_path)
        self.ch.prompt("terminal", {"purpose": "claude_login",
                                    "command": claude_login_command(config, ip, self.state["login"], checkout, exe)})
        self.ch.log("Waiting up to 15 minutes for Claude to report a sign-in on the worker.")
        deadline, last = self.sys.now() + 900, "no"
        while self.sys.now() < deadline:
            last = status()
            if last == "yes":
                return "done", "Claude is signed in."
            self.sys.sleep(5)
        raise StepFailed("The Claude status check failed on the worker. Resume to check again." if last == "unknown"
                         else "Claude did not report a sign-in within 15 minutes. Resume when it is signed in.")

    def service_active(self):
        out = self.root(as_worker("systemctl --user is-active fleet-%s.service 2>/dev/null || true" % self.name))[1]
        return out.strip() == "active"

    def s_worker_install(self):
        if self.service_active():
            return "skipped", "fleet-%s.service is active." % self.name
        self.must(as_worker("test -d $HOME/fleet-pilot || git clone -q %s $HOME/fleet-pilot; cd $HOME/fleet-pilot; "
                            "%s; python3 worker_install.py --agent %s --start"
                            % (shlex.quote(self.repo), TAKE, shlex.quote(self.name))), "Worker installation", timeout=600)
        if not self.service_active():
            raise StepFailed("fleet-%s.service is not active." % self.name)
        return "done", "fleet-%s.service is active." % self.name

    def s_verify(self):
        problems = []
        ip = self.state.get("tailscale_ip")
        if not (ip and self.proof(ip)):
            problems.append("managed key on the Tailscale address")
        info = kv(self.root(VERIFY)[1])
        for k, label in (("ufw", "firewall"), ("uu", "security updates"), ("ts", "Tailscale")):
            if info.get(k) != "yes":
                problems.append(label)
        if not self.service_active():
            problems.append("worker service")
        code, out, _ = self.root(as_worker("cd $HOME/fleet-pilot && python3 worker_install.py --agent %s --check"
                                           % shlex.quote(self.name)), timeout=180)
        if code != 0:
            problems.append("worker check: " + tail(out, 160))
        agent = None
        for _ in range(12):
            agent = self.hub_agent(self.hub_state())
            seen = (agent or {}).get("last_seen")
            if seen and self.sys.now() - float(seen) < 120:
                break
            self.sys.sleep(10)
        else:
            problems.append("helper check-in on the hub")
        if problems:
            raise StepFailed("Not ready: " + "; ".join(problems))
        return "done", "Ready: keys, firewall, security updates, Tailscale, service and hub check-in."

    # ---- prepare the other runtime of an existing agent (executor 1.3.0)
    def label(self):
        return RUNTIME_LABELS[self.state["runtime"]]

    def machine_setup(self):
        """This Mac's own saved setup of the agent's machine (Add server), read only. Its SSH login and port, private
        address, pinned host keys and managed key are the only access that a preparation uses."""
        machine = self.state["machine"]
        try:
            saved = json.loads((fleet_home() / "onboarding" / ("%s.json" % machine)).read_text())
        except (OSError, ValueError):
            saved = None
        if not isinstance(saved, dict) or saved.get("name") != machine or saved.get("mode") is not None:
            raise NeedsOwner("This Mac did not set up %s, so it has no managed key for it, and a preparation uses only "
                             "that key for now. Install and sign in %s there by hand. Nothing was changed."
                             % (machine, self.label()))
        keys = saved.get("host_keys") or []
        try:
            ipaddress.ip_address(str(saved.get("tailscale_ip")))
            good = (saved.get("finished") and keys and all(isinstance(k, dict) and k.get("sha256") for k in keys)
                    and USER_RE.match(str(saved.get("login"))) and 1 <= int(saved.get("port")) <= 65535
                    and self.key_path.exists())
        except (ValueError, TypeError):
            good = False
        if not good:
            raise StepFailed("This Mac's setup of %s did not finish with a private address, pinned host keys and a "
                             "managed key. Nothing was changed." % machine)
        return saved

    def p_preflight(self):
        """Before any change: the same hub generation; the agent on this machine, with a switch to this runtime that the
        hub offers; the machine's address and worker user on the hub; and this Mac's own setup of the machine at that
        address. A saved preparation continues only with the same placement and setup."""
        s, agent, machine, label = self.state, self.name, self.state["machine"], self.label()
        data = self.hub_state()
        if data.get("db") != s["generation"]:
            raise StepFailed("The hub generation is now %s, not %s. Reload and start again. Nothing was changed."
                             % (data.get("db"), s["generation"]))
        if "runtime_switch" not in (data.get("ui_features") or []):
            raise StepFailed("The hub does not offer a provider switch ('runtime_switch' is not in ui_features). "
                             "Nothing was changed.")
        team = self.team_view(s["generation"])
        line = next((x for x in team.get("lines") or [] if x.get("agent") == agent), None)
        if line is None:
            raise StepFailed("The hub has no agent %s. Nothing was changed." % agent)
        place, switch = line.get("placement") or {}, line.get("runtime_switch") or {}
        current = place.get("runtime")
        if place.get("machine") != machine:
            raise StepFailed("%s is on %s, not on %s. Nothing was changed." % (agent, place.get("machine"), machine))
        blocked = [c for c in switch.get("missing") or [] if c in ("manager_not_supported", "runtime_not_supported")]
        if switch.get("to") != s["runtime"] or blocked:
            raise StepFailed("%s cannot switch to %s (%s). Nothing was changed."
                             % (agent, label, ", ".join(blocked) or "it runs %s" % RUNTIME_LABELS.get(current, current)))
        entry = (team.get("machines") or {}).get(machine) or {}
        address = entry.get("address")
        if not address or address != place.get("address"):
            raise StepFailed("The hub gives no address for %s. Nothing was changed." % machine)
        if entry.get("worker_user") != WORKER_USER:
            raise StepFailed("The hub reports the worker user %s on %s, not %s. Nothing was changed."
                             % (entry.get("worker_user"), machine, WORKER_USER))
        saved = self.machine_setup()
        if saved["tailscale_ip"] != address:
            raise StepFailed("This Mac set up %s at %s, but the hub has it at %s. Nothing was changed."
                             % (machine, saved["tailscale_ip"], address))
        pinned = {"address": address, "worker_user": WORKER_USER, "login": saved["login"], "port": int(saved["port"]),
                  "host_keys": sorted(k["sha256"] for k in saved["host_keys"]), "setup": saved.get("registration_commit")}
        if s.get("placement") not in (None, pinned):
            raise StepFailed("The placement of %s or this Mac's setup of %s changed since this preparation started. "
                             "Nothing was changed. To start again, remove %s." % (agent, machine, self.state_path))
        s.update(placement=pinned, host=address, login=pinned["login"], port=pinned["port"], worker_user=WORKER_USER,
                 host_keys=saved["host_keys"], current_runtime=current)
        if "chat_not_bound" in (switch.get("missing") or []):
            self.ch.log("The open chat of %s has no recorded conversation (chat_not_bound). The preparation leaves the "
                        "chat as it is; record it on the machine with fleet.py chat-session %s <conversation id> before "
                        "a switch." % (agent, agent), "warning")
        return "done", "%s runs %s on %s at %s, which this Mac set up." % (agent, RUNTIME_LABELS.get(current, current),
                                                                          machine, address)

    def p_worker_check(self):
        """Before any change on the machine: commands run as its worker user, and the agent's service runs from the
        agent's own Fleet checkout there: ~/fleet-pilot for the machine's first agent, else ~/fleet-<agent>."""
        agent, machine = self.name, self.state["machine"]
        code, out, err = self.root(as_worker(
            'echo fleet-prepare-check=1; echo user=$(id -un); echo system=$(uname -s); echo home=$HOME; '
            'dir=$(systemctl --user show -p WorkingDirectory --value fleet-%s.service 2>/dev/null || true); '
            'echo checkout=$dir; if [ -n "$dir" ] && [ -f "$dir/fleet.py" ] && [ -d "$dir/.git" ]; '
            'then echo checkout_ok=yes; else echo checkout_ok=no; fi' % agent), timeout=120)
        info = kv(out)
        if code != 0 or info.get("fleet-prepare-check") != "1":
            raise StepFailed("The worker check did not run: %s" % tail(err, 160))
        if info.get("user") != WORKER_USER or info.get("system") != "Linux":
            raise StepFailed("The check ran as %s on %s, not as %s on Linux. Nothing was changed."
                             % (info.get("user"), info.get("system"), WORKER_USER))
        home = info.get("home") or ""
        checkout = home + ("/fleet-pilot" if agent == machine else "/fleet-%s" % agent)
        if not home.startswith("/") or info.get("checkout") != checkout or info.get("checkout_ok") != "yes":
            raise StepFailed("fleet-%s.service on %s does not run from its Fleet checkout %s. Nothing was changed."
                             % (agent, machine, checkout))
        if self.state.get("checkout") not in (None, checkout):
            raise StepFailed("The checkout of %s changed since this preparation started. Nothing was changed. To start "
                             "again, remove %s." % (agent, self.state_path))
        self.state["checkout"] = checkout
        return "done", "%s runs from %s as %s." % (agent, checkout, WORKER_USER)

    def probe(self):
        """The runtime command that the worker's service PATH finds, its version and its derived sign-in (yes, no or
        unknown). A check that did not run fails the step: it never counts as a missing command."""
        rt = self.state["runtime"]
        code, out, err = self.root(as_worker(runtime_probe(rt)), timeout=120)
        info = kv(out)
        if code != 0 or info.get("fleet-prepare") != "1" or info.get("user") != WORKER_USER:
            raise StepFailed("The runtime check did not run as %s: %s" % (WORKER_USER, tail(err, 160)))
        exe = info.get("exe") or ""
        version = re.sub(r"[^\x20-\x7e]", "", info.get("version") or "")[:120] or None
        if not exe:
            signed = "unknown"
        elif rt == "codex":
            signed = info.get("signed_in") if info.get("signed_in") in ("yes", "no") else "unknown"
        else:
            signed = {("0", "yes"): "yes", ("1", "no"): "no"}.get((info.get("rc"), info.get("logged_in")), "unknown")
        return {"exe": exe, "home": info.get("home") or "", "version": version, "signed_in": signed}

    def p_runtime(self):
        """A runtime command that the worker's service PATH finds stays as it is, in any version: no second copy, no
        upgrade and no downgrade. Only when there is none, the pinned version goes to ~/.local/bin, the first folder of
        that PATH, so the helper uses that copy."""
        rt, label = self.state["runtime"], self.label()
        found = self.probe()
        if found["exe"]:
            if not found["version"]:
                raise StepFailed("%s at %s gives no version, so the helper counts it as not installed. A preparation "
                                 "keeps a command that it finds: repair or remove it. Nothing was changed."
                                 % (label, found["exe"]))
            if found["exe"] != self.state.get("executable") or self.state.get("source") != "installed":
                self.state["source"] = "existing"
            self.state.update(executable=found["exe"], version=found["version"])
            # Only this preparation's own installation gets the update channel; a command that it found keeps its
            # owner's update settings (also a package from a package manager, which never updates itself).
            policy = (self.claude_updates(shlex.quote(found["exe"])) if self.state["source"] == "installed" else "") or "."
            return "skipped", "%s (%s) at %s stays as it is%s" % (label, found["version"], found["exe"], policy)
        pin = RUNTIME_PINS[rt]
        self.must(as_worker("mkdir -p $HOME/.local/bin; " + runtime_install(rt, pin)), "Runtime installation", timeout=900)
        found = self.probe()
        if found["exe"] != "%s/.local/bin/%s" % (found["home"], rt) or pin not in (found["version"] or ""):
            raise StepFailed("%s %s is not in ~/.local/bin after its installation: %s"
                             % (label, pin, found["exe"] or "no command found"))
        self.state.update(executable=found["exe"], version=found["version"], source="installed")
        return "done", "Installed %s (%s) at %s%s" % (label, found["version"], found["exe"],
                                                      self.claude_updates(shlex.quote(found["exe"])) or ".")

    def p_runtime_login(self):
        """No sign-in when a fresh check says signed in, and a status that cannot be read is a failure. Else the sign-in
        of a new machine, with the command that the worker's PATH finds: Codex device sign-in, or one Terminal command
        that opens Claude in the agent's checkout."""
        label, found = self.label(), self.probe()
        if not found["exe"] or found["exe"] != self.state.get("executable"):
            raise StepFailed("The %s command changed during this preparation. Resume to check again." % label)
        if found["signed_in"] == "yes":
            self.state["signed_in"] = True
            return "skipped", "%s is signed in." % label
        if found["signed_in"] != "no":
            raise StepFailed("The %s status check failed on the worker. Resume to check again." % label)
        self.state["signed_in"] = False
        self.save()

        def status():
            try:
                return self.probe()["signed_in"]
            except StepFailed:                  # one lost reading does not end the wait
                return "unknown"

        exe = shlex.quote(found["exe"])
        if self.state["runtime"] == "codex":
            result = self.codex_device_login(exe, lambda: status() == "yes")
        else:
            result = self.claude_terminal(self.state["host"], shlex.quote(self.state["checkout"]), exe, status)
        self.state["signed_in"] = True
        return result

    def p_verify(self):
        """The helper's status commands will find the same command, with a version and a sign-in."""
        label, found = self.label(), self.probe()
        if found["exe"] != self.state.get("executable") or not found["version"] or found["signed_in"] != "yes":
            raise StepFailed("%s is not ready: command %s, version %s, signed in %s."
                             % (label, found["exe"] or "not found", found["version"], found["signed_in"]))
        self.state.update(version=found["version"], signed_in=True)
        return "done", "%s (%s) at %s is installed and signed in for %s." % (label, found["version"], found["exe"],
                                                                            WORKER_USER)

    def prepared(self):
        """The result of a preparation: what is ready for which agent. It never means that an agent was added or
        switched; the agent keeps current_runtime until the owner switches it."""
        s = self.state
        return {"agent": self.name, "machine": s.get("machine"), "runtime": s.get("runtime"),
                "generation": s.get("generation"), "current_runtime": s.get("current_runtime"),
                "executable": s.get("executable"), "version": s.get("version"), "source": s.get("source"),
                "signed_in": s.get("signed_in")}

    # ---- run
    def run(self):
        steps = self.state.setdefault("steps", {})
        self.state.pop("finished", None)        # an earlier run's: only this run's good end says it again
        plan, prefix = ((PREPARE_STEPS, "p_") if self.preparing else (EXISTING_STEPS, "x_") if self.existing
                        else (STEPS, None))
        try:
            for sid, title in plan:
                self.ch.step(sid, "running", title)
                try:
                    step = getattr(self, prefix + sid, None) if prefix else None
                    status, detail = (step or getattr(self, "s_" + sid))()
                except (StepFailed, NeedsOwner, Abort) as e:      # a run that ends in a step ends that step too
                    steps[sid] = {"status": "failed", "detail": str(e), "at": self.sys.now()}
                    self.save()
                    self.ch.step(sid, "failed", title, str(e))
                    if not isinstance(e, StepFailed):
                        raise
                    self.ch.emit("result", status="failed", summary=str(e), **self.outcome())
                    return 1
                steps[sid] = {"status": status, "detail": detail, "at": self.sys.now()}
                self.save()
                self.ch.step(sid, status, title, detail)
            if not (self.existing or self.preparing):
                self.offer_ssh_include()
            self.state["finished"] = self.sys.now()
            self.save()
            current = RUNTIME_LABELS.get(self.state.get("current_runtime"), self.state.get("current_runtime"))
            summary = ("%s is prepared for %s on %s: installed and signed in. %s still runs %s; the switch is a separate "
                       "owner action." % (self.label(), self.name, self.state.get("machine"), self.name, current)
                       if self.preparing else
                       "%s is on %s: inactive, with no credential access, until the owner sets up its profile."
                       % (self.name, self.state.get("machine")) if self.existing else "%s is a Fleet worker." % self.name)
            self.ch.emit("result", status="ok", summary=summary, **self.outcome())
            return 0
        except NeedsOwner as e:
            self.save()
            self.ch.emit("result", status="needs_owner", summary=str(e), **self.outcome())
            return 2
        except Abort as e:
            self.save()
            self.ch.emit("result", status="failed", summary=str(e), **self.outcome())
            return 1
        finally:
            if self.askpass:
                self.askpass.close()

    def offer_ssh_include(self):
        """After a good run, ask once whether normal SSH should read the executor's SSH settings. Only the owner's
        choice changes ~/.ssh/config."""
        state = ssh_include_state()
        if state == "present" or self.state.get("ssh_include") in ("added", "not_now", "refused"):
            return
        if state == "symlink":
            self.state["ssh_include"] = "refused"
            self.ch.log("~/.ssh/config is a symbolic link, so the executor leaves it alone. To open %s from SSH links, "
                        "add this line at the top of the file it points to: %s" % (self.name, ssh_include_line()), "warning")
            return
        answer = self.ch.prompt("choice", {
            "question": "Let normal SSH, and the app's Terminal links, open %s with its managed key and pinned host key? "
                        "This adds one line at the top of ~/.ssh/config: %s. Other hosts keep their settings."
                        % (self.name, ssh_include_line()),
            "options": [{"value": "add", "label": "Add the Fleet Include line"}, {"value": "not_now", "label": "Not now"}]})
        result = ssh_include()[0] if answer == "add" else "not_now"
        self.state["ssh_include"] = result
        self.save()
        self.ch.log({"added": "Added the Fleet Include line to ~/.ssh/config.",
                     "present": "~/.ssh/config already has the Fleet Include line.",
                     "refused": "~/.ssh/config is a symbolic link; nothing was changed.",
                     "not_now": "~/.ssh/config was not changed."}[result])

    def machine(self):
        s = self.state
        return {"name": s.get("name"), "host": s.get("host"), "port": s.get("port"), "login": s.get("login"),
                "os": s.get("os"), "runtime": s.get("runtime"), "worker_user": WORKER_USER,
                "tailscale_ip": s.get("tailscale_ip"), "registration_commit": s.get("registration_commit"),
                "security": s.get("security")}

    def outcome(self):
        """The machine of a result, and for an existing machine (owner API 1.12) also the agent that it added. A
        preparation (executor 1.3.0) gives only what it prepared: no machine and no agent."""
        if self.preparing:
            return {"prepared": self.prepared()}
        if not self.existing:
            return {"machine": self.machine()}
        s = self.state
        return {"machine": {"name": s.get("machine"), "host": s.get("host"), "port": s.get("port"),
                            "login": s.get("login"), "worker_user": s.get("worker_user")},
                "agent": {"name": self.name, "machine": s.get("machine"), "runtime": s.get("runtime"),
                          "checkout": "~/fleet-%s" % self.name, "service": self.service_name(),
                          "registration_commit": s.get("registration_commit"), "active": False, "vault": "none"}}


# ---------------------------------------------------------------- remote scripts

OS_CHECK = """. /etc/os-release
echo "os=$ID $VERSION_ID"
command -v systemctl >/dev/null && echo systemd=yes || echo systemd=no
if [ "$(id -u)" = 0 ]; then echo root=yes; elif sudo -n true 2>/dev/null; then echo root=sudo; else echo root=no; fi"""

BOOTSTRAP = OS_CHECK + """
umask 077
mkdir -p "$HOME/.ssh"
touch "$HOME/.ssh/authorized_keys"
grep -qxF %(key)s "$HOME/.ssh/authorized_keys" || printf '%%s\\n' %(key)s >> "$HOME/.ssh/authorized_keys"
echo key=present"""

# A new server runs its first security updates for about nine minutes after its first start, and they hold apt's lock
# (the proof run of 5 November 2026): every apt-get here waits that out, as hub.sh, join.sh and hubsetup.py do.
APT_LOCK_WAIT = 1200
# `apt-get update` tries the lock of the package lists once: apt reads DPkg::Lock::Timeout only for the lock of dpkg.
# The first updates of a new server hold the lock of the lists while they read the lists, so `update` gets up to 10
# tries, 15 seconds apart, as hub.sh's and join.sh's apt_update does: the 10th try comes after the loop, so that its
# words and its exit status are the step's.
_UPDATE_ONCE = "apt-get -o DPkg::Lock::Timeout=%d update -q" % APT_LOCK_WAIT
APT_UPDATE = "for try in 1 2 3 4 5 6 7 8 9; do %s && break; sleep 15; false; done || %s" % (_UPDATE_ONCE, _UPDATE_ONCE)

TAILSCALE_INSTALL = """export DEBIAN_FRONTEND=noninteractive
if ! command -v tailscale >/dev/null; then
  . /etc/os-release
  curl -fsSL "https://pkgs.tailscale.com/stable/${ID}/${VERSION_CODENAME}.noarmor.gpg" -o /usr/share/keyrings/tailscale-archive-keyring.gpg
  curl -fsSL "https://pkgs.tailscale.com/stable/${ID}/${VERSION_CODENAME}.tailscale-keyring.list" -o /etc/apt/sources.list.d/tailscale.list
  %s
  apt-get -o DPkg::Lock::Timeout=%d install -y -q tailscale
fi
systemctl enable --now tailscaled""" % (APT_UPDATE, APT_LOCK_WAIT)
# Seconds that `tailscale up` waits for the private network with the owner's key. With no limit it waits for ever on a
# tailnet that approves each new machine by hand: then the SSH call ends first, and the key file stays on the server.
# The line ends by itself before its SSH call does, and removes the key file (hub.sh's TAILSCALE_UP_WAIT).
TAILSCALE_UP_WAIT = 300

# SSH comes in over tailscale0 alone, which the third line allows; the public SSH rule of an earlier executor goes,
# found by its comment, from the highest number down (hubsetup.firewall_script does the same).
FIREWALL = """ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow in on tailscale0 comment 'fleet tailscale' >/dev/null
systemctl stop fleet-ufw-rollback.timer >/dev/null 2>&1 || true
systemctl reset-failed fleet-ufw-rollback.timer fleet-ufw-rollback.service >/dev/null 2>&1 || true
systemd-run --quiet --unit=fleet-ufw-rollback --on-active=300 /usr/sbin/ufw --force disable
ufw --force enable >/dev/null
for n in $(ufw status numbered | sed -n 's/^\\[ *\\([0-9][0-9]*\\)\\].*# fleet ssh *$/\\1/p' | sort -rn); do
  ufw --force delete "$n" >/dev/null
done"""

# The same count as the helper's report: security lines of a simulated upgrade.
SECURITY_STATUS = """sim=$(apt-get -s -o Debug::NoLocking=1 upgrade) || exit 1
echo "pending=$(printf '%s\\n' "$sim" | grep -c '^Inst .*[Ss]ecurity' || true)"
test -f /var/run/reboot-required && echo reboot=yes || echo reboot=no
eval "$(apt-config shell AUTO_REBOOT Unattended-Upgrade::Automatic-Reboot/b)"
echo auto_reboot=${AUTO_REBOOT:-false}"""

# unattended-upgrade does not wait for the package lock, so an empty install waits first (apt's own lock timeout;
# it installs nothing). Then the server's own updater installs what its policy allows, as its daily run would.
SECURITY_APPLY = """export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=%d -q install </dev/null >/dev/null || exit 1
unattended-upgrade -v </dev/null""" % APT_LOCK_WAIT

VERIFY = """ufw status 2>/dev/null | grep -q '^Status: active' && echo ufw=yes || echo ufw=no
systemctl is-enabled unattended-upgrades >/dev/null 2>&1 && echo uu=yes || echo uu=no
tailscale status --json 2>/dev/null | grep -q '"BackendState": *"Running"' && echo ts=yes || echo ts=no"""


# ---------------------------------------------------------------- registration in a kit clone

PROFILE_TEMPLATE = """# Profile: %(name)s

Written by the owner. Agents cannot change it.

**Character.** Fast and exact. Text in, text out.

**Responsible for.** Research, writing, code and files %(where)s. It has no browser and no screen.

**May do without asking.** Anything its access allows: files, shell, git and the web, and every repository, service and login that it holds.

**Must ask first.** New money, a new account, or a step that only the owner can take. A task that needs a browser or a screen: reject it and say why.

**Logins it may use.** None until the owner adds them here.
"""


RUNTIME_SETTINGS = ("start", "allow")     # what a new agent takes from a worker of its runtime: its start command
                                          # and Claude's allow list; the helper reads no other runtime key


def register_in_kit(kit: Path, name, runtime, address, ssh_user=None, ssh_port=22, machine=None):
    """Add the worker to team.json (with the owner's SSH user and port for "Open machine") and write its profile.
    With machine (owner API 1.12) the agent uses that existing machine, gets no address or access entry, and has
    vault "none". Returns True when anything changed."""
    team_path = kit / "team.json"
    team = json.loads(team_path.read_text())
    agents, addresses = team["agents"], team.setdefault("addresses", {})
    existing = machine is not None
    place = {"machine": machine if existing else name, "runtime": runtime, **({"vault": "none"} if existing else {})}
    if name in agents:
        a = agents[name]
        if any(a.get(k) != v for k, v in place.items()) or (not existing and addresses.get(name) != address):
            raise StepFailed("team.json already has %s with other settings. Choose another name." % name)
        changed = False
    else:
        if name in addresses:
            raise StepFailed("team.json already has a machine named %s." % name)
        if existing and machine not in addresses:
            raise StepFailed("team.json has no machine %s." % machine)
        workers = [a for a in agents.values() if a.get("role") == "worker" and a.get("runtime") == runtime]
        template = next((a for a in workers if a.get("machine") == place["machine"]), workers[0] if workers else None)
        if template is None:
            raise StepFailed("No %s worker in team.json to copy settings from." % runtime)
        # Only how the runtime starts is copied (RUNTIME_SETTINGS). Never another agent's identity (title, expertise,
        # account label), placement (machine, screen runtime and its settings), grants (capabilities, vault, handover
        # key), reporting line or requested model. A new agent starts in setup; the owner activates it (owner API 1.9).
        entry = {k: template[k] for k in RUNTIME_SETTINGS if k in template}
        entry.update({"role": "worker", "can": ["shell", "web"], "active": False, **place})
        agents[name] = entry
        if not existing:
            addresses[name] = address
            if ssh_user:
                team.setdefault("access", {})[name] = {"ssh_user": ssh_user, "ssh_port": int(ssh_port)}
        team_path.write_text(json.dumps(team, indent=2) + "\n")
        changed = True
    profile = kit / "profiles" / ("%s.md" % name)
    if not profile.exists():
        profile.parent.mkdir(parents=True, exist_ok=True)
        profile.write_text(PROFILE_TEMPLATE % {"name": name, "where": "on its machine" if existing else "on a Linux server"})
        changed = True
    return changed


# ---------------------------------------------------------------- command line

def kit_defaults():
    team_file = Path(__file__).resolve().parent / "team.json"
    try:
        team = json.loads(team_file.read_text())
        hub = team["hub"]
        ip = team["addresses"][hub["machine"]]
        return "http://%s:%d" % (ip, int(hub.get("port") or 8765)), "git://%s/fleet-pilot.git" % ip
    except (OSError, ValueError, KeyError, TypeError):
        return "", ""


def main(argv=None):
    ap = argparse.ArgumentParser(description="Fleet machine onboarding executor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("version")
    sub.add_parser("askpass")
    st = sub.add_parser("status")
    st.add_argument("--name", required=True)
    sub.add_parser("ssh-include", help="owner action: let normal SSH use the settings of onboarded workers")
    r = sub.add_parser("run")
    r.add_argument("--json", action="store_true", required=True)
    r.add_argument("--resume", metavar="NAME")
    r.add_argument("--existing-machine", metavar="MACHINE", help="add an agent to this machine of the hub (owner API 1.12)")
    r.add_argument("--prepare-runtime", metavar="AGENT",
                   help="install and sign in --runtime for this existing agent, on a machine that this Mac set up")
    r.add_argument("--generation", metavar="DB", help="with --prepare-runtime: the hub's db")
    r.add_argument("--machine", metavar="MACHINE", help="with --prepare-runtime: the agent's machine on the hub")
    r.add_argument("--host")
    r.add_argument("--port", type=int, help="default 22")
    r.add_argument("--login")
    r.add_argument("--name")
    r.add_argument("--runtime", choices=("codex", "claude"))
    r.add_argument("--runtime-version")
    r.add_argument("--auth", choices=("agent", "identity", "password"), required=True)
    r.add_argument("--identity-file")
    r.add_argument("--tailscale", choices=("login_url", "auth_key"), help="default login_url")
    r.add_argument("--tailscale-tag")
    r.add_argument("--hub")
    r.add_argument("--repo")
    r.add_argument("--config", help="JSON file with non-secret defaults: hub, repo, tailscale_tag, runtime_pins")
    args = ap.parse_args(argv)

    if args.cmd == "askpass":
        return askpass_main()
    if args.cmd == "version":
        print(json.dumps({"v": PROTOCOL, "type": "version", "executor": EXECUTOR_VERSION, "capabilities": CAPABILITIES}))
        return 0
    if args.cmd == "ssh-include":
        result, path = ssh_include()
        print(json.dumps({"v": PROTOCOL, "type": "ssh_include", "state": result, "path": str(path)}))
        return 0 if result != "refused" else 1
    state_dir = fleet_home() / "onboarding"
    if args.cmd == "status":
        path = state_dir / ("%s.json" % args.name)
        state = json.loads(path.read_text()) if path.exists() else None
        print(json.dumps({"v": PROTOCOL, "type": "state", "state": state}, sort_keys=True))
        return 0

    ch = Channel()
    try:
        if args.prepare_runtime is not None:
            return prepare_main(args, ch)
        if args.generation is not None or args.machine is not None:
            raise Abort("--generation and --machine go only with --prepare-runtime.")
        name = args.resume or args.name
        if not name or not NAME_RE.match(name):
            raise Abort("Give --name (or --resume) with a lowercase worker name, 2-31 characters.")
        if args.existing_machine is not None:
            if args.resume:
                raise Abort("Give --existing-machine for a new run, or --resume NAME alone to continue one.")
            given = [flag for flag, value in (("--host", args.host), ("--port", args.port), ("--login", args.login),
                                              ("--runtime-version", args.runtime_version), ("--tailscale", args.tailscale),
                                              ("--tailscale-tag", args.tailscale_tag), ("--config", args.config))
                     if value is not None]
            if given:
                raise Abort("--existing-machine takes host, port and login from the hub; remove %s." % ", ".join(given))
            if not MACHINE_RE.match(args.existing_machine):
                raise Abort("Give --existing-machine with the name that the hub uses for the machine.")
        if args.auth == "identity" and not (args.identity_file and Path(args.identity_file).is_file()):
            raise Abort("--auth identity needs --identity-file with an existing key file.")
        config = {}
        if args.config:
            try:
                config = json.loads(Path(args.config).read_text())
            except (OSError, ValueError) as e:
                raise Abort("Cannot read --config: %s" % e)
            if any(k in config for k in ("password", "token", "auth_key", "private_key")):
                raise Abort("--config must not hold secrets.")
        default_hub, default_repo = kit_defaults()
        hub = args.hub or config.get("hub") or default_hub
        repo = args.repo or config.get("repo") or default_repo
        if not hub or not repo:
            raise Abort("Give --hub and --repo, a --config file, or run from a Fleet kit checkout.")
        pins = dict(RUNTIME_PINS)
        pins.update(config.get("runtime_pins") or {})
        tag = tailscale_tags(args.tailscale_tag or config.get("tailscale_tag"))
        state_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(str(state_dir), 0o700)
        path = state_dir / ("%s.json" % name)
        lock = open(str(state_dir / (".%s.lock" % name)), "w")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise Abort("Another onboarding run for %s is active." % name)
        if args.resume:
            if not path.exists():
                raise Abort("No saved run for %s." % name)
            state = json.loads(path.read_text())
        else:
            if path.exists():
                raise Abort("A saved run for %s exists. Use --resume %s." % (name, name))
            if args.existing_machine is not None:
                if not args.runtime:
                    raise Abort("A new run needs --runtime.")
                state = {"mode": "existing_machine", "machine": args.existing_machine, "name": name,
                         "runtime": args.runtime, "created": time.time(), "executor": EXECUTOR_VERSION}
            else:
                if not (args.host and args.login and args.runtime):
                    raise Abort("A new run needs --host, --login and --runtime.")
                state = {"name": name, "host": args.host, "port": 22 if args.port is None else args.port,
                         "login": args.login, "runtime": args.runtime,
                         "runtime_version": args.runtime_version or pins.get(args.runtime),
                         "tailscale_tag": tag or network_tags(hub), "created": time.time(),
                         "executor": EXECUTOR_VERSION}
        auth = {"mode": args.auth, "identity_file": args.identity_file, "tailscale": args.tailscale or "login_url"}
        state["auth"] = {"mode": args.auth, "identity_file": args.identity_file}
        ob = Onboarding(ch, System(fleet_home() / "ssh" / "known_hosts"), path, state, auth, hub, repo)
        return ob.run()
    except Abort as e:
        ch.emit("result", status="failed", summary=str(e),
                **({"prepared": None} if args.prepare_runtime is not None else {"machine": None}))
        return 1


def prepare_main(args, ch):
    """run --prepare-runtime (executor 1.3.0). It takes the agreed --auth agent, but connects only with the managed key
    and pinned host keys of this Mac's setup of the machine; --repo is not used. The same command again continues an
    unfinished preparation from its own saved state; the saved setup of the machine is only read."""
    others = [flag for flag, value in (("--resume", args.resume), ("--existing-machine", args.existing_machine),
                                       ("--name", args.name), ("--host", args.host), ("--port", args.port),
                                       ("--login", args.login), ("--identity-file", args.identity_file),
                                       ("--runtime-version", args.runtime_version), ("--tailscale", args.tailscale),
                                       ("--tailscale-tag", args.tailscale_tag), ("--config", args.config))
              if value is not None] + (["--auth %s" % args.auth] if args.auth != "agent" else [])
    if others:
        raise Abort("--prepare-runtime takes the access of the machine that this Mac set up (its managed key and pinned "
                    "host keys); remove %s." % ", ".join(others))
    agent, target, generation, machine = args.prepare_runtime, args.runtime, args.generation, args.machine
    if not NAME_RE.match(agent):
        raise Abort("Give --prepare-runtime with the agent's name.")
    if not target:
        raise Abort("--prepare-runtime needs --runtime codex or claude: the runtime to prepare.")
    if not (generation and GENERATION_RE.match(generation)):
        raise Abort("--prepare-runtime needs --generation with the hub's db.")
    if not (machine and MACHINE_RE.match(machine)):
        raise Abort("--prepare-runtime needs --machine with the name that the hub uses for the agent's machine.")
    hub = (args.hub or kit_defaults()[0]).rstrip("/")
    if not hub:
        raise Abort("Give --hub.")
    folder = fleet_home() / "onboarding" / "prepare"
    folder.mkdir(parents=True, exist_ok=True)
    for f in (folder.parent, folder):
        os.chmod(str(f), 0o700)
    with open(str(folder / (".%s.lock" % machine)), "w") as lock:       # one preparation on a machine at a time
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise Abort("Another preparation on %s is active." % machine)
        path = folder / ("%s-%s.json" % (agent, target))
        try:
            saved = json.loads(path.read_text()) if path.exists() else None
        except (OSError, ValueError):
            raise Abort("The saved preparation %s cannot be read. Nothing was changed. Remove it to start again." % path)
        request = {"hub": hub, "generation": generation, "machine": machine}
        if isinstance(saved, dict) and saved.get("placement") and not saved.get("finished"):
            changed = [k for k in request if saved.get(k) != request[k]]
            if changed:
                raise Abort("This unfinished preparation of %s for %s started with another %s. Nothing was changed. To "
                            "start again, remove %s." % (RUNTIME_LABELS[target], agent, " and ".join(changed), path))
            state = saved
        else:           # nothing saved, nothing that passed preflight, or a finished preparation: a new run
            state = dict(request, mode="prepare_runtime", name=agent, runtime=target, created=time.time(),
                         executor=EXECUTOR_VERSION)
        ob = Onboarding(ch, System(fleet_home() / "ssh" / "known_hosts"), path, state, {}, hub, args.repo or "")
        return ob.run()


if __name__ == "__main__":
    sys.exit(main())
