#!/usr/bin/env python3
"""Fleet machine onboarding executor (owner API 1.2, protocol version 1): the runtime change of one agent.

Runs on the owner Mac, outside the app sandbox, started by the signed local setup helper. With --prepare-runtime
(executor 1.3.0) it prepares the other runtime of one existing agent before a provider switch, on a machine that this
Mac set up, with only that setup's managed key and pinned host keys. A runtime command that the worker's service PATH
finds stays in any version; only when there is none is the pinned version installed, and it is signed in only when a
fresh check says that it is not. It registers nothing, switches nothing and changes no session, chat, service or
setting of the agent. Its saved state is its own.

Until executor 2.0.0 (16 November 2026) it also set up a fresh Linux server as a worker, and with --existing-machine it
added an agent to a machine of the hub. Both registered the agent with a push to the hub's git service, which refuses
every push since 17 October 2026, so no run of them could finish, and the app started neither: a server joins the fleet
with the hub's join line, and Add agent puts an agent on a server. A run of either gets one sentence (REMOVED). The
helpers and the installers still take the runtime pins, the vendors' install and update lines and the update channel of
Fleet's own Claude installation from this file.

Protocol: JSON Lines on standard output; answers on standard input. See UI-API.md, "Version 1.2" and "Prepare the other
runtime". Standard library only; Python 3.9+.
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
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

PROTOCOL = 1
EXECUTOR_VERSION = "2.0.0"
CAPABILITIES = ["prepare_runtime"]
WORKER_USER = "fleet"
# Both at least 7 days old on 10 October 2026. A Codex version stays until someone installs another one. The Claude
# version is only the first build: Claude Code's own installation updates itself (see CLAUDE_CHANNEL).
RUNTIME_PINS = {"codex": "0.160.0", "claude": "2.1.287"}
# The programs that the fleet downloads by itself, each at one version and never at its vendor's newest (the AI
# providers build spec, section 3.9). For each Linux platform: the addresses of its file, in the order to try them; the
# SHA-512 of that file as it is downloaded; and `member`, the program's path in a .tgz, or None for a file that is the
# program. `python3 pins.py <name> <version>` makes an entry. It takes only a version that npm published at least
# lifecycle.NPM_DAYS days before, it holds each file of npm to npm's own digest, and it holds Grok Build's files, which
# come from the vendor's own store, to the copy that npm holds of them: `packed` names npm's file of that platform,
# npm's own SHA-512 of it, and the member that opens with Brotli to the same bytes as the store's file. That copy is
# what proves the age of a store's file, so the tool makes no such entry without it. These two are of 12 November
# 2026. At OpenCode 2.2.5 the program of linux-x64-baseline is byte for byte the program of linux-x64. No code reads
# this before step 1 of that spec.
PINNED = {
    "grok": {"version": "1.0.77", "published": "2026-11-05", "bin": "grok", "files": {
        "linux-x64": {
            "urls": [
                "https://x.ai/cli/grok-1.0.77-linux-x86_64",
                "https://storage.googleapis.com/grok-build-public-artifacts/cli/grok-1.0.77-linux-x86_64"],
            "sha512": ("05a5285e23d2a8276c4f89b1399c1d515527349af64fd4fc01f93e38787ff8f9"
                       "5726d015ef9c44709cd6cc4fc138a8a536ba2a5aa5ab0e02c981da958fde0254"),
            "member": None,
            "packed": {
                "url": "https://registry.npmjs.org/@xai-official/grok-linux-x64/-/grok-linux-x64-1.0.77.tgz",
                "sha512": ("0ee3d2130d4d623fdbc0b3822bfecb270f37375ae029cf2112c220e0282027dc"
                           "bbe3269b00e51d6a6af895f23e8b670a2cfabd87c4d07f628d6f213fcd7f3dca"),
                "member": "package/bin/grok.br"}},
        "linux-arm64": {
            "urls": [
                "https://x.ai/cli/grok-1.0.77-linux-aarch64",
                "https://storage.googleapis.com/grok-build-public-artifacts/cli/grok-1.0.77-linux-aarch64"],
            "sha512": ("8ade765c405e9f47c481686018c5e0b35666170cc3ce54f77d43e615d5fc711e"
                       "f05fd3b3eb38007eb301f0ec710d8eb27e2c80234618f8cca7c47dd7c4abb78c"),
            "member": None,
            "packed": {
                "url": "https://registry.npmjs.org/@xai-official/grok-linux-arm64/-/grok-linux-arm64-1.0.77.tgz",
                "sha512": ("29be3229b544ced5f4ee233b72f281d8bff18903f533f90b8c99f2464f3880db"
                           "6bdc81bb6a1a89a7ad34e6e07f54bbf0d22b2fd428f9d3327d8d84caecd88eab"),
                "member": "package/bin/grok.br"}}}},
    "opencode": {"version": "2.2.5", "published": "2026-10-30", "bin": "opencode", "files": {
        "linux-x64": {
            "urls": [
                "https://registry.npmjs.org/@opencode/cli-linux-x64/-/cli-linux-x64-2.2.5.tgz"],
            "sha512": ("0641c07d3a8db20feaa61c8736b9c7f831a43b166c1a36a63693390efc2812fc"
                       "fb6403cdc3c9846cc5c64c20ce007fbffb8d04a9e89ee8a359059650c0f0a368"),
            "member": "package/bin/opencode"},
        "linux-x64-baseline": {
            "urls": [
                "https://registry.npmjs.org/@opencode/cli-linux-x64-baseline/-/cli-linux-x64-baseline-2.2.5.tgz"],
            "sha512": ("a0f393f84326773e7a1e74853d157067441354be5d79f84e69c9f0cdaceed173"
                       "ae09652d10a87c89c227df6dd27422eda99b738ee5359adea9dbfd7757ddd65a"),
            "member": "package/bin/opencode"},
        "linux-arm64": {
            "urls": [
                "https://registry.npmjs.org/@opencode/cli-linux-arm64/-/cli-linux-arm64-2.2.5.tgz"],
            "sha512": ("3b8a8ecbf5916109a10a5301ff9a816a861fcda0cad7e3c945039f53cd22c728"
                       "f9aee41b0b1ada1fe556d94c876fa4563a552fe357de73e8ac77ad8bbc2bb0b8"),
            "member": "package/bin/opencode"}}},
}
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,30}\Z")                # \Z: `$` lets a final newline through .match
MACHINE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
GENERATION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
RUNTIME_LABELS = {"codex": "Codex", "claude": "Claude"}
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# The steps of a preparation (executor 1.3.0), in their order: each one is the method p_<id>.
PREPARE_STEPS = [
    ("preflight", "Check the hub, the agent and this Mac's setup of the machine"),
    ("host_key", "Check the pinned server identity"),
    ("managed_key", "Prove the managed admin key"),
    ("worker_check", "Check the worker user and the agent's checkout"),
    ("runtime", "Find or install the runtime"),
    ("runtime_login", "Sign in the runtime"),
    ("verify", "Check the prepared runtime"),
]
# What a run of the two modes that executor 2.0.0 removed gets, whatever else it names (UI-API.md 1.206).
REMOVED = ("onboard.py runs only --prepare-runtime now: a server joins the fleet with the hub's join line, which Add "
           "server in Founderizer gives, and Add agent puts an agent on a server.")


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
    """JSON Lines out, JSON answers in."""

    def __init__(self, out=None, inp=None, run_id=None):
        self.out = out or sys.stdout
        self.inp = inp or sys.stdin
        self.run = run_id or uuid.uuid4().hex[:12]
        self.seq = 0
        self.prompts = 0

    def emit(self, type_, **fields):
        self.seq += 1
        line = {"v": PROTOCOL, "run": self.run, "seq": self.seq, "type": type_}
        line.update(fields)
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


# ---------------------------------------------------------------- system access

class System:
    """Every outside effect of the executor. Tests replace it."""

    def __init__(self, known_hosts: Path):
        self.known_hosts = known_hosts

    def run(self, argv, input=None, timeout=120):
        try:
            r = subprocess.run(argv, input=input if input is not None else "", capture_output=True, text=True,
                               timeout=timeout)
        except subprocess.TimeoutExpired:
            return 124, "", "timed out"
        return r.returncode, r.stdout, r.stderr

    def ssh(self, host, port, login, script, *, identity, timeout=300):
        """One connection with the managed key `identity` alone and the pinned host keys. The script goes to the remote
        bash on stdin, never in arguments."""
        args = ["ssh", "-F", "/dev/null", "-p", str(port), "-o", "StrictHostKeyChecking=yes",
                "-o", "UserKnownHostsFile=%s" % self.known_hosts, "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
                "-o", "LogLevel=ERROR", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
                "-i", str(identity), "%s@%s" % (login, host), "bash -s"]
        return self.run(args, input="set -eu\n" + script + "\n", timeout=timeout)

    def keyscan(self, host, port):
        return self.run(["ssh-keyscan", "-p", str(port), "-T", "10", "-t", "ed25519,ecdsa,rsa", host], timeout=30)

    def http(self, method, url, body=None, headers=None):
        """One call, with this computer's key for that hub as its bearer when it has one, to the hub's number
        (owner_computer_call). A hub from before the key refuses a bearer on an owner route before it does anything
        (403, auth key_not_expected): the same call then goes again with none, to the address as it is written."""
        key, numbered = owner_computer_call(url)
        code, answer = self.http_once(method, numbered, body, headers, key)
        if key and code == 403 and answer.get("auth") == "key_not_expected":
            return self.http_once(method, url, body, headers, None)
        return code, answer

    def http_once(self, method, url, body, headers, key):
        data = None if body is None else json.dumps(body).encode()
        h = {"Accept": "application/json"}
        if key:
            h["Authorization"] = "Bearer " + key
        if body is not None:
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
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

def canonical_address(text):
    """An address in the one spelling that names a key's file, or None for what is no address: IPv4 as it is
    written, IPv6 as the system writes it (owner_mcp.canonical_address)."""
    try:
        return socket.inet_ntop(socket.AF_INET, socket.inet_pton(socket.AF_INET, text))
    except (OSError, ValueError, TypeError):
        pass
    try:
        return socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, text)).lower()
    except (OSError, ValueError, TypeError):
        return None


def chosen_address(addresses):
    """The one address of a name's addresses that names its key's file, the same one for the same set in any order:
    an address of the fleet's private network first (100.64.0.0/10), else the lowest IPv4 address, else the lowest
    of the others (owner_mcp.chosen_address)."""
    fours, others = [], []
    for text in addresses:
        try:
            fours.append((socket.inet_pton(socket.AF_INET, text), text))
        except (OSError, ValueError, TypeError):
            one = canonical_address(text)
            if one:
                others.append(one)
    fours.sort()
    for packed, text in fours:
        if packed[0] == 100 and 64 <= packed[1] <= 127:
            return text
    return fours[0][1] if fours else (sorted(others)[0] if others else None)


def host_address(host):
    """The numeric address of a host: an address as it is, a name through the system's own lookup, or None."""
    one = canonical_address(host)
    if one:
        return one
    try:
        found = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return None
    return chosen_address([a[4][0] for a in found])


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an answer, never a second request: this computer's key for the hub must not go to another place
    with it (urllib would send the same headers there)."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def owner_computer_call(url, home=None, lookup=host_address):
    """(this computer's key for the hub of `url`, the address that a call with that key goes to), or (None, url)
    (hub.py, owner feature owner_key): the hub knows the owner's computer by its address and this key, both, so that
    a VM or a container on it is not the owner. One file for each hub address, `<address>_<port>` in
    ~/.founderizer/owner-keys, named by the hub's number, which Founderizer or the claim wrote and only this user
    reads. A call to anything that is no hub of this computer has no such file, and so no key.

    A hub that is called by a name: the name is looked up once, the file of that number is the key, and the call
    with the key goes to that number, never to the name again, as the app and owner_mcp.py do it
    (owner_mcp.owner_key_place says why). A name that has no number now has no key. While the folder holds no file
    of that port nothing is looked up."""
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return None, url
    folder = os.path.join(home or os.path.expanduser("~"), ".founderizer", "owner-keys")
    if not host:
        return None, url
    address = canonical_address(host)
    if not address:
        try:
            if not any(n.endswith(f"_{port}") and not n.startswith(".") for n in os.listdir(folder)):
                return None, url
        except OSError:
            return None, url
        address = canonical_address(lookup(host) or "")
        if not address:
            return None, url
    try:
        with open(os.path.join(folder, re.sub(r"[^a-z0-9.-]", "-", address) + f"_{port}"), encoding="utf-8") as f:
            key = f.read(257).strip()
    except (OSError, ValueError):
        return None, url
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", key):
        return None, url
    shown = f"[{address}]" if ":" in address else address
    return key, urllib.parse.urlunsplit(parts._replace(netloc=f"{shown}:{port}"))


def owner_computer_key(url, home=None, lookup=host_address):
    """This computer's key for the hub of `url`, or None (owner_computer_call)."""
    return owner_computer_call(url, home, lookup)[0]


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


def claude_login_command(config, ip, login, checkout, exe):
    """The one command that the owner runs in Terminal for a worker's first Claude sign-in: this worker's managed SSH
    settings (its key and pinned host key), then the worker's own claude in its checkout, with the same worker
    environment as installation and the status check, so that Claude's first folder trust is for that checkout. Fleet
    does not run it and never sees what the owner types into Claude. checkout and exe are the agent's checkout and the
    command that the worker's PATH finds, both as shell words."""
    remote = as_worker("cd %s && exec %s" % (checkout, exe))
    if login != "root":
        remote = "sudo -n " + remote
    return shlex.join(["ssh", "-F", str(config), "-t", str(ipaddress.ip_address(ip)), remote])


def as_worker(cmd):
    """A shell command that runs as the worker user, from its home folder, with its user services reachable.
    runuser keeps the caller's folder (/root), which the worker user cannot open, so the command starts with cd."""
    inner = ('cd "$HOME" || exit 1; export XDG_RUNTIME_DIR=/run/user/$(id -u); export PATH="$HOME/.local/bin:$PATH"; '
             + cmd)
    return "runuser -u %s -- bash -lc %s" % (WORKER_USER, shlex.quote(inner))


# ---------------------------------------------------------------- the executor

class Onboarding:
    """One preparation of the other runtime of one agent (prepare_main): its saved state, its steps and its result."""

    def __init__(self, channel: Channel, system: System, state_path: Path, state: dict, hub: str):
        self.ch, self.sys, self.state_path, self.state = channel, system, state_path, state
        self.hub = hub.rstrip("/")

    # ---- state
    def save(self):
        self.state["updated"] = self.sys.now()
        tmp = self.state_path.with_suffix(".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.state, f, indent=2, sort_keys=True)
        os.replace(str(tmp), str(self.state_path))

    @property
    def name(self):
        return self.state["name"]

    @property
    def address(self):
        """Where the run reaches the machine: its private address, which the hub and this Mac's setup of the machine
        both give (p_preflight)."""
        return self.state["host"]

    @property
    def port(self):
        return int(self.state["port"])

    @property
    def key_path(self):
        """The managed admin key of the machine, which this Mac's setup of it made."""
        return fleet_home() / "ssh" / ("%s_admin" % self.state["machine"])

    # ---- ssh
    def managed(self, script, timeout=300, root=True):
        """One command on the machine with its managed key alone, as root unless root is False."""
        login = self.state["login"]
        if root and login != "root":
            script = "sudo -n bash -s <<'FLEET_ROOT'\nset -eu\n%s\nFLEET_ROOT" % script
        return self.sys.ssh(self.address, self.port, login, script, identity=self.key_path, timeout=timeout)

    def root(self, script, timeout=300):
        return self.managed(script, timeout=timeout)

    def must(self, script, what, timeout=300):
        code, out, err = self.root(script, timeout=timeout)
        if code != 0:
            raise StepFailed("%s failed: %s" % (what, tail(err or out)))
        return out

    def proof(self):
        code, out, _ = self.managed("echo fleet-proof", root=False, timeout=60)
        return code == 0 and "fleet-proof" in out

    # ---- hub
    def hub_state(self):
        code, data = self.sys.http("GET", self.hub + "/ui/state")
        if code != 200:
            raise StepFailed("The hub did not answer /ui/state (%s): %s" % (code, data.get("error", "")))
        return data

    def team_view(self, db):
        code, team = self.sys.http("GET", "%s/ui/team?db=%s" % (self.hub, urllib.parse.quote(str(db or ""))))
        if code != 200:
            raise StepFailed("The hub did not answer /ui/team (%s): %s" % (code, team.get("error", "")))
        return team

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

    # ---- the runtime's installation and sign-in
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

    def claude_terminal(self, ip, checkout, exe, status):
        """The `terminal` prompt with the command that opens exe in checkout (shell words) on the worker at ip, then a
        wait of up to 15 minutes until status() gives yes. The SSH settings block is the machine's own."""
        config = write_ssh_config(self.state["machine"], ip, self.state["login"], self.port, self.key_path)
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

    # ---- the steps (PREPARE_STEPS)
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

    def p_host_key(self):
        """Every key that the machine shows must be one that this Mac's setup of it pinned (p_preflight): a changed key
        stops the run, and no prompt asks the owner to trust another one."""
        keys = self.scan(self.address)
        pinned = {k["sha256"] for k in self.state.get("host_keys", [])}
        changed = [k for k in keys if k["sha256"] not in pinned]
        if changed:
            raise Abort("The server host key changed since it was confirmed (%s). Stop and check the server."
                        % ", ".join(k["sha256"] for k in changed))
        self.pin(self.address, self.port, keys)
        return "skipped", "The pinned host keys match."

    def p_managed_key(self):
        if not self.proof():
            raise StepFailed("A fresh connection with only the managed key failed.")
        code, out, _ = self.root("id -u")
        if code != 0 or out.strip() != "0":
            raise StepFailed("The managed key does not reach root.")
        return "done", "A fresh connection with only the managed key reached root."

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
        try:
            for sid, title in PREPARE_STEPS:
                self.ch.step(sid, "running", title)
                try:
                    status, detail = getattr(self, "p_" + sid)()
                except (StepFailed, NeedsOwner, Abort) as e:      # a run that ends in a step ends that step too
                    steps[sid] = {"status": "failed", "detail": str(e), "at": self.sys.now()}
                    self.save()
                    self.ch.step(sid, "failed", title, str(e))
                    if not isinstance(e, StepFailed):
                        raise
                    self.ch.emit("result", status="failed", summary=str(e), prepared=self.prepared())
                    return 1
                steps[sid] = {"status": status, "detail": detail, "at": self.sys.now()}
                self.save()
                self.ch.step(sid, status, title, detail)
            self.state["finished"] = self.sys.now()
            self.save()
            current = RUNTIME_LABELS.get(self.state.get("current_runtime"), self.state.get("current_runtime"))
            summary = ("%s is prepared for %s on %s: installed and signed in. %s still runs %s; the switch is a separate "
                       "owner action." % (self.label(), self.name, self.state.get("machine"), self.name, current))
            self.ch.emit("result", status="ok", summary=summary, prepared=self.prepared())
            return 0
        except NeedsOwner as e:
            self.save()
            self.ch.emit("result", status="needs_owner", summary=str(e), prepared=self.prepared())
            return 2
        except Abort as e:
            self.save()
            self.ch.emit("result", status="failed", summary=str(e), prepared=self.prepared())
            return 1


# ---------------------------------------------------------------- command line

def kit_hub():
    """The hub of the fleet whose checkout holds this file, when it runs from one: the address of the hub of its
    team.json, or "" (the app always gives --hub)."""
    folder = Path(__file__).resolve().parent
    try:
        team = json.loads((folder / "team.json").read_text())
        hub = team["hub"]
        return "http://%s:%d" % (team["addresses"][hub["machine"]], int(hub.get("port") or 8765))
    except (OSError, ValueError, KeyError, TypeError):
        return ""


def main(argv=None):
    ap = argparse.ArgumentParser(description="Fleet machine onboarding executor: the runtime change of one agent")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("version")
    r = sub.add_parser("run")
    # Nothing is required here, so that a run of a removed mode gets REMOVED in any form. prepare_main asks for what a
    # preparation needs, and refuses each other flag.
    r.add_argument("--json", action="store_true")
    r.add_argument("--prepare-runtime", metavar="AGENT",
                   help="install and sign in --runtime for this existing agent, on a machine that this Mac set up")
    r.add_argument("--runtime", choices=("codex", "claude"))
    r.add_argument("--generation", metavar="DB", help="the hub's db")
    r.add_argument("--machine", metavar="MACHINE", help="the agent's machine on the hub")
    r.add_argument("--auth", help="agent, the agreed form: a preparation connects only with the managed key")
    r.add_argument("--hub")
    r.add_argument("--repo", help="the agreed command names it; no step of a preparation reads it")
    args, extra = ap.parse_known_args(argv)
    if args.cmd == "version":
        if extra:
            ap.error("unrecognized arguments: %s" % " ".join(extra))
        print(json.dumps({"v": PROTOCOL, "type": "version", "executor": EXECUTOR_VERSION, "capabilities": CAPABILITIES}))
        return 0
    ch = Channel()
    try:
        if args.prepare_runtime is None:
            raise Abort(REMOVED)
        return prepare_main(args, extra, ch)
    except Abort as e:
        ch.emit("result", status="failed", summary=str(e), prepared=None)
        return 1


def prepare_main(args, extra, ch):
    """run --prepare-runtime (executor 1.3.0). It takes the agreed --auth agent, but connects only with the managed key
    and pinned host keys of this Mac's setup of the machine; --repo is not used. The same command again continues an
    unfinished preparation from its own saved state; the saved setup of the machine is only read."""
    others = extra + (["--auth %s" % args.auth] if args.auth not in (None, "agent") else [])
    if others:
        raise Abort("--prepare-runtime takes the access of the machine that this Mac set up (its managed key and pinned "
                    "host keys); remove %s." % " ".join(others))
    if not (args.json and args.auth):
        raise Abort("--prepare-runtime needs --json and --auth agent, as the app gives them.")
    agent, target, generation, machine = args.prepare_runtime, args.runtime, args.generation, args.machine
    if not NAME_RE.match(agent):
        raise Abort("Give --prepare-runtime with the agent's name.")
    if not target:
        raise Abort("--prepare-runtime needs --runtime codex or claude: the runtime to prepare.")
    if not (generation and GENERATION_RE.match(generation)):
        raise Abort("--prepare-runtime needs --generation with the hub's db.")
    if not (machine and MACHINE_RE.match(machine)):
        raise Abort("--prepare-runtime needs --machine with the name that the hub uses for the agent's machine.")
    hub = (args.hub or kit_hub()).rstrip("/")
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
        ob = Onboarding(ch, System(fleet_home() / "ssh" / "known_hosts"), path, state, hub)
        return ob.run()


if __name__ == "__main__":
    sys.exit(main())
