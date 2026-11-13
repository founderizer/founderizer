"""Onboarding executor checks. A simulated server and hub; real Git in temporary folders. No network."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import onboard
from onboard import Channel, Onboarding, StepFailed, System

NETWORK_TAGS = onboard.network_tags     # the real one: Base gives every test a tailnet with no tag


def blob(seed):
    raw = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes([seed]) * 32
    return base64.b64encode(raw).decode()


def read_askpass(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(path)
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                return data.decode()
            data += chunk


class Server:
    def __init__(self, os_line="ubuntu 24.04"):
        self.os_line = os_line
        self.managed_ok = self.packages = self.uu = self.user = self.ts_installed = False
        self.ts_state, self.ts_ip = "NoState", "100.99.1.2"
        self.ufw, self.rollback = False, None
        self.public_rule = False                # the public SSH rule (`fleet ssh`) that executors before 1.3.2 added
        self.ts_refused = False                 # the tailnet policy does not let the owner's Mac reach SSH here
        self.ts_settings = []                   # the settings that an earlier `tailscale up` left, as its flags
        self.codex = self.codex_login = self.login_started = self.login_cleaned = self.service = False
        self.claude_auth, self.claude_signs_in = "no", False     # the worker's derived Claude status: yes, no or fail
        self.block_ts_proof = False
        self.fail_rollback_stop = False         # the cancel of the firewall rollback fails on the server
        self.fail_packages_with = None
        self.security_pending, self.security_held, self.security_reboot, self.auto_reboot = 2, 0, False, False
        self.fail_security_with, self.count_fails = None, False
        self.applies, self.events = [], []
        # An existing machine (owner API 1.12): its runtime, the new checkout, the agent key command and the service.
        self.system, self.rt_installed, self.rt_signed = "Linux", True, "yes"
        self.checkout, self.foreign_checkout, self.key_fails, self.trust = None, False, False, "added"
        self.unit, self.loaded, self.running = "none", "none", False
        # A preparation (executor 1.3.0): what the worker's service PATH finds, and the agent service's checkout.
        self.paths = {"codex": "/home/fleet/.local/bin/codex"}
        self.versions = {"codex": "codex-cli 0.160.0"}
        self.unit_dir, self.unit_dir_ok = "/home/fleet/fleet-pilot", True
        self.claude_settings = None             # the worker user's Claude update settings, once the installer set them
        self.claude_settings_broken = False     # a settings file that is no JSON object: the installer leaves it


KEY_SHA = "ab" * 32
KEY_SECRET = "AGENT-KEY-SECRET-VALUE"      # what a careless key command could print; it must never be repeated


class FakeSystem:
    def __init__(self, server, public, bare, password=None):
        self.server, self.public, self.bare, self.password = server, public, bare, password
        self.clock = 1000.0
        self.blob = self.ts_blob = blob(7)
        self.calls, self.scripts, self.askpass_reads = [], [], []
        self.ssh_timeouts = []                  # the time limit of each SSH call, beside its script
        self.opened = set()
        self.team = json.loads(json.dumps(TEAM))
        self.features = ["thread_events", "task_controls", "limit_holds", "liveness", "machines"]
        self.reloads = []
        self.real = System(Path("/dev/null"))
        self.keys, self.key_posts = {}, []
        self.ready, self.missing = True, []
        self.access = {"user": "root", "port": 22, "worker_user": "fleet"}
        self.switch_missing = {}

    @property
    def hub_agents(self):
        return set(self.team["agents"])

    # ssh
    def closed(self, host):
        """The server does not answer SSH at this address: its public address once a firewall without the public rule
        is on, and its Tailscale address when the tailnet policy does not let this Mac in."""
        s = self.server
        return (host == s.ts_ip and s.ts_refused) or (host != s.ts_ip and s.ufw and not s.public_rule)

    def ssh(self, host, port, login, script, *, auth, identity=None, askpass=None, timeout=300):
        self.calls.append(("ssh", host, auth, str(identity)))
        self.scripts.append(script)
        self.ssh_timeouts.append(timeout)
        s = self.server
        if self.closed(host):
            return 255, "", "ssh: connect to host %s port %s: Operation timed out" % (host, port)
        if auth == "password":
            secret = read_askpass(askpass.env()["FLEET_ASKPASS_SOCKET"])
            self.askpass_reads.append(secret)
            if secret != self.password:
                return 255, "", "Permission denied"
        if auth == "managed":
            if not s.managed_ok:
                return 255, "", "Permission denied (publickey)."
            if host == s.ts_ip and s.block_ts_proof and s.ufw:
                return 255, "", "Connection timed out"
        wrapper = "sudo -n bash -s <<'FLEET_ROOT'\nset -eu\n"
        if script.startswith(wrapper) and script.endswith("\nFLEET_ROOT"):
            script = script[len(wrapper):-len("\nFLEET_ROOT")]
        return self.dispatch(script, host)

    def dispatch(self, script, host):
        s = self.server
        has = lambda marker: marker in script
        user = self.access["worker_user"]
        if has("echo fleet-prepare-check=1"):
            return 0, "fleet-prepare-check=1\nuser=%s\nsystem=%s\nhome=/home/%s\ncheckout=%s\ncheckout_ok=%s\n" % (
                user, s.system, user, s.unit_dir, "yes" if s.unit_dir_ok else "no"), ""
        if has("echo fleet-prepare=1"):
            rt = re.search(r"type -P (\w+)", script).group(1)
            exe = s.paths.get(rt, "")
            out = "fleet-prepare=1\nuser=%s\nhome=/home/%s\nexe=%s\n" % (user, user, exe)
            if exe and rt == "codex":
                out += "version=%s\nsigned_in=%s\n" % (s.versions.get(rt, ""), "yes" if s.codex_login else "no")
            elif exe:
                rc, li = {"yes": (0, "yes"), "no": (1, "no")}.get(s.claude_auth, (2, "unknown"))
                out += "version=%s\nfleet-claude-auth=1\nrc=%d\nlogged_in=%s\n" % (s.versions.get(rt, ""), rc, li)
            return 0, out, ""
        if has("fleet-claude-channel=1") and s.claude_settings_broken:
            return 1, "", "~/.claude/settings.json is not a JSON object; it was not changed\n"
        if has("fleet-claude-channel=1"):            # the update channel and floor of Fleet's own Claude installation
            floor = re.search(r"[0-9.]+", s.versions.get("claude", "")).group(0)
            changed = s.claude_settings != ("stable", floor)
            s.claude_settings = ("stable", floor)
            if changed:
                s.applies.append("channel")
            return 0, "fleet-claude-channel=1\nfloor=%s\nchanged=%s\nupdates_off=\n" % (floor, "yes" if changed else "no"), ""
        if has("echo fleet-claude-auth=1"):
            s.events.append("claude_status")
            if s.claude_auth == "fail":
                return 255, "", "Connection reset"
            rc, li = {"yes": (0, "yes"), "no": (1, "no")}.get(s.claude_auth, (2, "unknown"))
            return 0, "fleet-claude-auth=1\nrc=%d\nlogged_in=%s\n" % (rc, li), ""
        if has("test -d $HOME/fleet-pilot || git clone -q") and not has("worker_install.py"):
            s.applies.append("checkout_clone")
            return 0, "", ""
        if has("echo fleet-runtime-check=1"):
            head = "fleet-runtime-check=1\nuser=%s\nsystem=%s\n" % (self.access["worker_user"], s.system)
            if not s.rt_installed:
                return 0, head + "installed=no\n", ""
            return 0, head + "installed=yes\nversion=codex-cli 0.160.0\nsigned_in=%s\n" % s.rt_signed, ""
        if has("echo fleet-checkout=cloned"):
            if s.foreign_checkout or s.checkout:
                return 0, "fleet-checkout=exists\nmark=%s\n" % ("" if s.foreign_checkout else s.checkout), ""
            s.checkout = re.search(r"echo ([0-9a-f]{32}) >", script).group(1)
            s.applies.append("checkout")
            return 0, "fleet-checkout=cloned\n", ""
        if has("fleet.py key"):
            return (1, "", "Traceback: " + KEY_SECRET) if s.key_fails else (0, KEY_SHA + "\n", "debug " + KEY_SECRET)
        if has("echo unit="):
            return 0, "unit=%s\nloaded=%s\nrunning=%s\n" % (s.unit, s.loaded, "yes" if s.running else "no"), ""
        if has("fleet.py service"):
            trusted = has("trust_codex_checkout")
            if trusted and s.trust == "kept":
                return 0, "trust=kept\n", ""
            s.unit, s.loaded, s.running = "ours", "ours", True
            s.applies.append("service")
            return 0, ("trust=%s\n" % s.trust if trusted else "") + "started=yes\n", ""
        if has("echo ufw=yes"):
            return 0, "ufw=%s\nuu=%s\nts=%s\n" % ("yes" if s.ufw else "no", "yes" if s.uu else "no",
                                                  "yes" if s.ts_state == "Running" else "no"), ""
        if has("key=present"):
            s.managed_ok = True
            return 0, "os=%s\nsystemd=yes\nroot=yes\nkey=present\n" % s.os_line, ""
        if has("echo fleet-proof"):
            self.server.events.append("proof:" + host)
            return 0, "fleet-proof\n", ""
        if has("os-release") and not has("pkgs.tailscale.com"):
            return 0, "os=%s\nsystemd=yes\nroot=yes\n" % s.os_line, ""
        if script.strip().endswith("id -u") and len(script.strip()) < 80:
            return 0, "0\n", ""
        if has("checked=yes"):
            return 0, ("" if s.packages else "missing=ufw\nmissing=tmux\n") + "checked=yes\n", ""
        if has("apt-get") and has("install -y") and has("unattended-upgrades"):
            if s.fail_packages_with:
                return 100, "", "E: broken: " + s.fail_packages_with
            s.packages = True
            s.applies.append("packages")
            return 0, "", ""
        if has("echo enabled=yes"):
            return 0, "enabled=%s\n" % ("yes" if s.uu else "no"), ""
        if has("20auto-upgrades"):
            s.uu = True
            s.applies.append("security")
            return 0, "", ""
        if has("update -q") and not has("install"):
            s.events.append("lists")
            return 0, "", ""
        if has("pending="):
            if s.count_fails:
                return 100, "", "E: The package lists are broken."
            s.events.append("count")
            return 0, "pending=%d\nreboot=%s\nauto_reboot=%s\n" % (
                s.security_pending, "yes" if s.security_reboot else "no", "true" if s.auto_reboot else "false"), ""
        if has("unattended-upgrade -v"):
            if s.fail_security_with:
                return 1, "", "E: " + s.fail_security_with
            s.applies.append("security_updates")
            s.events.append("install")
            s.security_pending, s.security_reboot = s.security_held, True     # for example a new kernel
            return 0, "Packages that will be upgraded: libssl3t64 openssh-server\n", ""
        if has("echo exists=yes"):
            if s.user:
                return 0, "exists=yes\nlocked=L\nsudo=no\nlinger=yes\nmode=700\n", ""
            return 0, "exists=no\nlocked=\nsudo=no\nlinger=no\nmode=none\n", ""
        if has("useradd"):
            s.user = True
            s.applies.append("user")
            return 0, "", ""
        if has("pkgs.tailscale.com"):
            s.ts_installed = True
            s.applies.append("tailscale_install")
            return 0, "", ""
        if has("tailscale up"):
            # Tailscale keeps the settings of an earlier `tailscale up`, and refuses one that does not name each of
            # them again, unless it has --reset (Tailscale 1.104.6, checkForAccidentalSettingReverts).
            missing = [flag for flag in s.ts_settings if flag.split("=")[0] not in script]
            if missing and not has("--reset"):
                return 1, "", ("Error: changing settings via 'tailscale up' requires mentioning all\nnon-default "
                               "flags. To proceed, either re-run your command with --reset or ...\n\n\t"
                               "tailscale up ... %s\n" % " ".join(missing))
            if has("--auth-key=file:") and has("FLEET_INPUT=") and has("tskey-auth-"):
                s.ts_state = "Running"
                s.applies.append("tailscale_key")
            else:
                s.ts_state = "NeedsLogin"
                s.applies.append("tailscale_url")
            return 0, "", ""
        if has("tailscale status --json"):
            data = {"BackendState": s.ts_state}
            if s.ts_state == "Running":
                data["Self"] = {"TailscaleIPs": [s.ts_ip, "fd7a::1"]}
            elif s.ts_state == "NeedsLogin":
                data["AuthURL"] = "https://login.tailscale.com/a/abc123"
            return 0, json.dumps(data) if s.ts_installed else "", ""
        if has("echo active=yes || echo active=no"):
            yes = "yes" if s.ufw else "no"
            rollback = ("rollback=%s\n" % ("armed" if s.rollback == "armed" else "none")
                        if has("echo rollback=armed") else "")
            return 0, "active=%s\npublic=%s\nts=%s\n%s" % (yes, "yes" if s.public_rule else "no", yes, rollback), ""
        if has("systemd-run"):
            s.ufw, s.rollback = True, "armed"
            s.public_rule = s.public_rule and "# fleet ssh" not in script
            s.events.append("armed")
            s.applies.append("firewall")
            return 0, "", ""
        if script.strip().endswith("systemctl stop fleet-ufw-rollback.timer"):
            if s.fail_rollback_stop:
                return 1, "", "Failed to stop fleet-ufw-rollback.timer: Access denied"
            s.rollback = "cancelled"
            s.events.append("cancelled")
            return 0, "", ""
        if has("echo health=yes"):
            return 0, "health=yes\ngit=yes\n", ""
        if has("--version"):
            if has("bin/claude --version"):
                return 0, (s.versions["claude"] + "\n" if "claude" in s.paths else ""), ""
            return 0, ("codex-cli 0.160.0\n" if s.codex else ""), ""
        if has("install.sh"):
            rt = "claude" if has("claude.ai/install.sh") else "codex"
            version = re.search(r"(?:--release|bash -s) '?([0-9.]+)", script).group(1)
            s.codex = s.codex or rt == "codex"
            s.paths[rt] = "/home/%s/.local/bin/%s" % (user, rt)
            s.versions[rt] = ("codex-cli %s" if rt == "codex" else "%s (Claude Code)") % version
            s.applies.append("runtime")
            return 0, "", ""
        if has("login status"):
            return 0, ("Logged in using ChatGPT\n" if s.codex_login else "Not logged in\n"), ""
        if has("--device-auth >"):
            s.login_started = True
            s.applies.append("login_start")
            return 0, "", ""
        if has("cat $HOME/.fleet-codex-login.log"):
            if not s.login_started:
                return 0, "", ""
            return 0, ("\x1b[94mhttps://auth.openai.com/codex/device\x1b[0m\n2. Enter this one-time code\n"
                       "   \x1b[94mWXYZ-12345\x1b[0m\n"), ""
        if has("rm -f $HOME/.fleet-codex-login.log"):
            s.login_cleaned = True
            return 0, "", ""
        if has("is-active fleet-"):
            return 0, ("active\n" if s.service else "inactive\n"), ""
        if has("worker_install.py --agent") and has("--start"):
            s.service = True
            s.applies.append("worker")
            return 0, "", ""
        if has("worker_install.py --agent") and has("--check"):
            return 0, "READY\n", ""
        return 0, "", ""

    def keyscan(self, host, port):
        if self.closed(host):
            return 1, "", "%s: Operation timed out" % host
        key = self.ts_blob if host == self.server.ts_ip else self.blob
        return 0, "%s ssh-ed25519 %s\n" % (host, key), ""

    def keygen(self, path, comment):
        Path(path).write_text("PRIVATE KEY\n")
        Path(str(path) + ".pub").write_text("ssh-ed25519 AAAAC3NzaFAKE %s\n" % comment)
        return 0, "", ""

    def git(self, args, cwd=None):
        return self.real.git(args, cwd=cwd)

    def http(self, method, url, body=None, headers=None):
        if url.endswith("/ui/state"):
            named = getattr(self, "repository", None)       # what a hub since owner API 1.139 names
            if named == 503:
                return 503, {"error": "the hub restarts"}
            return 200, dict({"db": "g1", "ui_features": self.features,
                              "agents": [{"name": n, "last_seen": self.clock} for n in sorted(self.hub_agents)]},
                             **({"repository": named} if named else {}))
        if "/ui/machines?db=" in url:
            return 200, {"db": "g1", "machines": [
                {"agent": n, "machine": a["machine"], "address": self.team["addresses"].get(a["machine"]),
                 "features": ["agent_key"] if n in ("manager", "vps") or (n in self.keys and self.server.running) else []}
                for n, a in sorted(self.team["agents"].items())]}
        if "/ui/team?db=" in url:
            if not url.endswith("?db=g1"):
                return 409, {"error": "hub generation changed; refresh state"}
            other = {"codex": "claude", "claude": "codex"}
            lines = [{"agent": n, "role": a["role"], "active": a.get("active", True), "vault": a.get("vault", "file"),
                      "auth": {"key": n in self.keys or n in ("manager", "vps"), "since": self.clock},
                      "placement": {"machine": a["machine"], "runtime": a["runtime"],
                                    "address": self.team["addresses"].get(a["machine"])},
                      "runtime_switch": {"to": other.get(a["runtime"]), "ready": False,
                                         "missing": ["manager_not_supported"] if a["role"] == "manager" else
                                         self.switch_missing.get(n, ["runtime_not_installed"])}}
                     for n, a in sorted(self.team["agents"].items())]
            machines = {}
            for n, a in sorted(self.team["agents"].items()):
                entry = machines.setdefault(a["machine"], {
                    "address": self.team["addresses"].get(a["machine"]), "agents": [],
                    "ssh": {"user": self.access["user"], "port": self.access["port"]},
                    "worker_user": self.access["worker_user"],
                    "runtimes": {"codex": {"version": "codex-cli 0.160.0", "signed_in": True}},
                    "add_agent": {"ready": self.ready, "missing": self.missing}})
                entry["agents"].append(n)
            return 200, {"db": "g1", "lines": lines, "machines": machines}
        key = re.fullmatch(r".*/ui/team/agents/([a-z0-9-]+)/key", url)
        if key and method == "POST":
            self.key_posts.append((key.group(1), body, headers))
            self.keys[key.group(1)] = body["sha256"]
            return 200, {"ok": True, "agent": key.group(1), "key": True, "since": self.clock,
                         "request_id": body["request_id"], "replayed": False}
        if url.endswith("/ui/team/reload"):
            self.reloads.append((body, headers))
            rev = body.get("revision", "")
            ok = subprocess.run(["git", "--git-dir", str(self.bare), "cat-file", "-e", rev],
                                capture_output=True).returncode == 0
            if not ok:
                return 409, {"error": "unknown revision"}
            self.team = json.loads(subprocess.run(["git", "--git-dir", str(self.bare), "show", rev + ":team.json"],
                                                  capture_output=True, text=True).stdout)
            return 200, {"ok": True}
        return 404, {"error": "unknown"}

    def sleep(self, seconds):
        self.clock += seconds
        if self.server.ts_state == "NeedsLogin" and "tailscale_login" in self.opened:
            self.server.ts_state = "Running"
        if self.server.login_started and "codex_login" in self.opened:
            self.server.codex_login = True
        if self.server.claude_signs_in and "claude_login" in self.opened:
            self.server.claude_auth = "yes"

    def now(self):
        return self.clock


class AutoAnswer:
    def __init__(self, out, fake, confirm=True):
        self.out, self.fake, self.confirm = out, fake, confirm
        self.urls, self.choices, self.choice, self.terminals = [], [], "not_now", []

    def readline(self):
        last = json.loads(self.out.getvalue().strip().splitlines()[-1])
        if last["type"] != "prompt":
            return ""
        kind, pid = last["kind"], last["id"]
        if kind == "confirm_host_key":
            answer = self.confirm
        elif kind == "open_url":
            self.urls.append(last["data"])
            self.fake.opened.add(last["data"]["purpose"])
            answer = "opened"
        elif kind == "secret":
            answer = "sent"
        elif kind == "terminal":
            self.terminals.append(last["data"])
            self.fake.opened.add(last["data"]["purpose"])
            answer = "copied"
        elif kind == "choice":
            self.choices.append(last["data"])
            answer = self.choice
        else:
            answer = None
        return json.dumps({"prompt": pid, "answer": answer}) + "\n"


TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"hub": "100.111.0.10", "vps": "100.111.0.20", "owner": "100.111.0.40"},
        "agents": {"manager": {"role": "manager", "machine": "hub", "runtime": "claude"},
                   "vps": {"role": "worker", "machine": "vps", "runtime": "codex", "can": ["shell", "web"],
                           "start": "codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}"}}}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.old_home = os.environ.get("FLEET_HOME")
        os.environ["FLEET_HOME"] = str(self.tmp / "fleet")
        self.bare = self.tmp / "fleet-pilot.git"
        self.home = patch("onboard.Path.home", return_value=self.tmp / "home")     # never the real ~/.ssh
        self.home.start()
        self.tags = patch("onboard.network_tags", return_value="")      # never the real Tailscale: no tag anywhere
        self.tags.start()
        seed = self.tmp / "seed"
        (seed / "profiles").mkdir(parents=True)
        (seed / "team.json").write_text(json.dumps(TEAM, indent=2) + "\n")
        (seed / "profiles" / "vps.md").write_text("# Profile: vps\n")
        git = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main"]
        subprocess.run(git + ["init", "-q", str(seed)], check=True)
        subprocess.run(git + ["-C", str(seed), "add", "-A"], check=True)
        subprocess.run(git + ["-C", str(seed), "commit", "-q", "-m", "seed"], check=True)
        subprocess.run(git + ["clone", "-q", "--bare", str(seed), str(self.bare)], check=True)

    def tearDown(self):
        self.home.stop()
        self.tags.stop()
        if self.old_home is None:
            os.environ.pop("FLEET_HOME", None)
        else:
            os.environ["FLEET_HOME"] = self.old_home
        shutil.rmtree(str(self.tmp), ignore_errors=True)

    def make(self, server=None, auth="agent", login="root", tailscale="login_url", secrets="", password=None,
             confirm=True, fake=None, state=None):
        server = server or Server()
        fake = fake or FakeSystem(server, "203.0.113.10", self.bare, password=password)
        out = io.StringIO()
        ch = Channel(out=out, inp=None, run_id="r1")
        ch.inp = AutoAnswer(out, fake, confirm=confirm)
        ch.secret_file = io.StringIO(secrets)
        state_dir = Path(os.environ["FLEET_HOME"]) / "onboarding"
        state_dir.mkdir(parents=True, exist_ok=True)
        path = state_dir / "vps2.json"
        state = state if state is not None else {
            "name": "vps2", "host": "203.0.113.10", "port": 22, "login": login, "runtime": "codex",
            "runtime_version": "0.160.0", "tailscale_tag": "tag:claude-code-dev"}
        ob = Onboarding(ch, fake, path, state, {"mode": auth, "identity_file": None, "tailscale": tailscale},
                        "http://hub.test:8765", str(self.bare))
        return ob, fake, out, path

    @staticmethod
    def lines(out):
        return [json.loads(line) for line in out.getvalue().splitlines()]

    def statuses(self, out):
        result = {}
        for e in self.lines(out):
            if e["type"] == "step" and e["status"] != "running":
                result[e["id"]] = e["status"]
        return result


class FullRun(Base):
    def test_fresh_server_reaches_ready(self):
        ob, fake, out, path = self.make()
        self.assertEqual(ob.run(), 0)
        st = self.statuses(out)
        self.assertEqual([s for s, _ in onboard.STEPS], list(st))
        self.assertTrue(all(v == "done" for v in st.values()), st)
        result = self.lines(out)[-1]
        self.assertEqual((result["type"], result["status"]), ("result", "ok"))
        self.assertEqual(result["machine"]["tailscale_ip"], "100.99.1.2")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        known = (Path(os.environ["FLEET_HOME"]) / "ssh" / "known_hosts").read_text()
        self.assertIn("203.0.113.10 ssh-ed25519", known)
        self.assertIn("100.99.1.2 ssh-ed25519", known)
        team = json.loads(subprocess.run(["git", "--git-dir", str(self.bare), "show", "main:team.json"],
                                         capture_output=True, text=True, check=True).stdout)
        self.assertEqual(team["agents"]["vps2"]["machine"], "vps2")
        self.assertEqual(team["addresses"]["vps2"], "100.99.1.2")
        self.assertEqual(team["agents"]["vps2"]["can"], ["shell", "web"])
        self.assertEqual(team["access"]["vps2"], {"ssh_user": ob.state["login"], "ssh_port": ob.port})
        config = (Path(os.environ["FLEET_HOME"]) / "ssh" / "config").read_text()
        self.assertIn("Host 100.99.1.2\n  User root\n  Port 22\n  IdentityFile ", config)
        self.assertIn("  UserKnownHostsFile %s" % (Path(os.environ["FLEET_HOME"]) / "ssh" / "known_hosts"), config)
        self.assertIn("  StrictHostKeyChecking yes", config)
        subprocess.run(["git", "--git-dir", str(self.bare), "cat-file", "-e", "main:profiles/vps2.md"], check=True)
        self.assertEqual(len(fake.reloads), 1)
        self.assertTrue(fake.reloads[0][1]["X-Fleet-Client"].startswith("fleet-onboard/1/"))

    def test_each_clone_takes_the_repository_that_the_hub_names(self):
        """A hub since owner API 1.139 names its repository in GET /ui/state, and its name can be new: the run
        clones that one, and asks once. The address that the run was given is the one of a hub that names none, of a
        hub that names no git:// repository, and of a hub that does not answer now."""
        for named, wanted in (("git://hub.test/founderizer.git", "git://hub.test/founderizer.git"),
                              (None, str(self.bare)), ("file:///etc", str(self.bare)),
                              ("git://hub.test/../x.git", str(self.bare)), (503, str(self.bare))):
            ob, fake, _out, _path = self.make()
            fake.repository = named
            self.assertEqual((ob.repo, ob.repo), (wanted, wanted), named)
        ob, fake, _out, _path = self.make()
        fake.repository, asked, real = "git://hub.test/founderizer.git", [], fake.http
        fake.http = lambda method, url, *a, **k: (asked.append(url), real(method, url, *a, **k))[1]
        self.assertEqual([ob.repo, ob.repo], ["git://hub.test/founderizer.git"] * 2)
        self.assertEqual(sum(url.endswith("/ui/state") for url in asked), 1)

    def test_firewall_rollback_is_armed_before_proofs_and_cancelled_after(self):
        ob, fake, out, _ = self.make()
        self.assertEqual(ob.run(), 0)
        ev = fake.server.events
        armed, cancelled = ev.index("armed"), ev.index("cancelled")
        proofs = {ev[i] for i, e in enumerate(ev) if e.startswith("proof:") and armed < i < cancelled}
        self.assertEqual(proofs, {"proof:100.99.1.2"})                  # the public address is closed by then
        self.assertIn("proof:100.99.1.2", ev[:armed], "the firewall changed before SSH was proved over Tailscale")
        self.assertEqual(fake.server.rollback, "cancelled")

    def test_a_new_server_gets_no_public_ssh_rule(self):
        """Executor 1.3.2: SSH comes in over Tailscale only. The firewall script lets tailscale0 in and allows no port
        from anywhere, and after it every connection of the run goes to the Tailscale address."""
        ob, fake, out, _ = self.make()
        self.assertEqual(ob.run(), 0)
        script = next(x for x in fake.scripts if "systemd-run" in x)
        allows = [line for line in script.splitlines() if line.startswith("ufw allow")]
        self.assertEqual(allows, ["ufw allow in on tailscale0 comment 'fleet tailscale' >/dev/null"])
        self.assertNotIn("/tcp", script)
        self.assertFalse(fake.server.public_rule)
        at = next(i for i, x in enumerate(fake.scripts) if "systemd-run" in x)
        self.assertEqual({c[1] for c in fake.calls[at:]}, {"100.99.1.2"})
        self.assertTrue(ob.state["ssh_private"])
        self.assertEqual(ob.address, "100.99.1.2")

    def test_the_public_ssh_rule_of_an_earlier_executor_is_removed(self):
        """A run that an executor before 1.3.2 finished left `22/tcp ALLOW Anywhere` (`fleet ssh`). A resume with this
        executor removes it, after a proof on the Tailscale address, and from then on reaches the server there."""
        ob, fake, out, path = self.make()
        self.assertEqual(ob.run(), 0)
        old = json.loads(path.read_text())
        old.pop("ssh_private")
        fake.server.public_rule = True                  # as the old executor's firewall left it
        ob2, _, out2, _ = self.make(fake=fake, state=old)
        self.assertEqual(ob2.run(), 0)
        firewall = [e for e in self.lines(out2) if e["type"] == "step" and e["id"] == "firewall"][-1]
        self.assertEqual(firewall["status"], "done")
        self.assertFalse(fake.server.public_rule)
        script = [x for x in fake.scripts if "systemd-run" in x][-1]
        self.assertIn("# fleet ssh *$/\\1/p' | sort -rn); do", script)
        self.assertIn('ufw --force delete "$n"', script)

    def test_a_tailnet_that_refuses_this_mac_leaves_the_server_as_it_was(self):
        """The firewall changes only after SSH answers on the Tailscale address, so a tailnet policy that does not let
        the owner's Mac reach port 22 there stops the run with the public address still open: at the Tailscale step,
        whose host key scan is the first connection to that address."""
        server = Server()
        server.ts_refused = True
        ob, fake, out, path = self.make(server=server)
        self.assertEqual(ob.run(), 1)
        self.assertNotIn(self.statuses(out).get("firewall"), ("done", "skipped"))
        self.assertEqual((server.ufw, server.rollback, server.events.count("armed")), (False, None, 0))
        self.assertNotIn("ssh_private", json.loads(path.read_text()))
        self.assertEqual(fake.ssh("203.0.113.10", 22, "root", "echo fleet-proof", auth="managed")[0], 0)

    def test_the_firewall_waits_for_ssh_on_the_tailscale_address(self):
        """A Tailscale address that answers a host key scan and refuses the login is not one the run moves to."""
        server = Server()
        ob, fake, out, path = self.make(server=server)
        real = fake.ssh

        def refused(host, port, login, script, **kw):
            if host == server.ts_ip and "echo fleet-proof" in script and not server.ufw:
                fake.calls.append(("ssh", host, kw.get("auth"), str(kw.get("identity"))))
                return 255, "", "Permission denied (publickey)."
            return real(host, port, login, script, **kw)
        fake.ssh = refused
        self.assertEqual(ob.run(), 1)
        failed = [e for e in self.lines(out) if e["type"] == "step" and e["status"] == "failed"][-1]
        self.assertEqual(failed["id"], "firewall")
        self.assertIn("tailnet policy", failed["detail"])
        self.assertEqual((server.ufw, server.rollback), (False, None))
        self.assertNotIn("ssh_private", json.loads(path.read_text()))

    def test_the_ssh_include_is_offered_once_and_changes_only_on_the_owners_choice(self):
        ob, fake, out, path = self.make()
        self.assertEqual(ob.run(), 0)
        user_config = self.tmp / "home" / ".ssh" / "config"
        self.assertEqual(len(ob.ch.inp.choices), 1)
        self.assertEqual([o["value"] for o in ob.ch.inp.choices[0]["options"]], ["add", "not_now"])
        self.assertIn("Include ", ob.ch.inp.choices[0]["question"])
        self.assertFalse(user_config.exists())                          # "Not now" changes nothing
        ob2, _, _, _ = self.make(fake=fake, state=json.loads(path.read_text()))
        self.assertEqual(ob2.run(), 0)
        self.assertEqual(ob2.ch.inp.choices, [])                        # asked once per machine
        state = json.loads(path.read_text())
        state.pop("ssh_include")
        ob3, _, _, _ = self.make(fake=fake, state=state)
        ob3.ch.inp.choice = "add"
        self.assertEqual(ob3.run(), 0)
        self.assertTrue(user_config.read_text().startswith("# Fleet onboarding"))
        self.assertEqual(json.loads(path.read_text())["ssh_include"], "added")

    def test_second_run_changes_nothing(self):
        ob, fake, out, path = self.make()
        self.assertEqual(ob.run(), 0)
        applies = list(fake.server.applies)
        state = json.loads(path.read_text())
        ob2, _, out2, _ = self.make(fake=fake, state=state)
        self.assertEqual(ob2.run(), 0)
        self.assertEqual(fake.server.applies, applies)
        self.assertEqual(len(fake.reloads), 1)
        self.assertTrue(set(self.statuses(out2).values()) <= {"skipped", "done"})

    def test_sudo_login_wraps_root_commands(self):
        ob, fake, out, _ = self.make(login="ubuntu")
        self.assertEqual(ob.run(), 0)
        rooted = [s for s in fake.scripts if "useradd" in s]
        self.assertTrue(rooted and rooted[0].startswith("sudo -n bash -s <<'FLEET_ROOT'"))


class SecurityUpdates(Base):
    """A fresh server gets its pending security updates once, from its own updater; setup never restarts it."""
    REBOOT = re.compile(r"(^|[;&|(]\s*|\bsudo\s+)(reboot|shutdown|poweroff|halt)\b(?![-=])|\bsystemctl\s+"
                        r"(reboot|poweroff|halt|kexec)\b|\binit\s+[06]\b", re.M)

    def detail(self, out, step="security_updates"):
        return [e for e in self.lines(out) if e["type"] == "step" and e["id"] == step][-1]["detail"]

    def test_pending_security_updates_are_installed_once_and_reported(self):
        ob, fake, out, path = self.make()
        self.assertEqual(ob.run(), 0)
        self.assertEqual(fake.server.applies.count("security_updates"), 1)
        steps = [e for e in fake.server.events if e in ("lists", "count", "install")]
        self.assertEqual(steps, ["lists", "count", "install", "count"])     # fresh lists first; counted again after
        self.assertEqual(self.lines(out)[-1]["machine"]["security"], {"pending_security": 0, "reboot_required": True})
        self.assertEqual(self.detail(out), "Installed the pending security updates (2 before). "
                                           "Security updates on; 0 pending; reboot required.")
        apply = [x for x in fake.scripts if "unattended-upgrade -v" in x][0]
        self.assertLess(apply.index("DPkg::Lock::Timeout"), apply.index("unattended-upgrade -v"))
        ob2, _, out2, _ = self.make(fake=fake, state=json.loads(path.read_text()))
        self.assertEqual(ob2.run(), 0)
        self.assertEqual(fake.server.applies.count("security_updates"), 1)      # nothing pending: nothing installed
        self.assertEqual(self.statuses(out2)["security_updates"], "skipped")

    def test_setup_never_restarts_a_server(self):
        ob, fake, out, _ = self.make()
        self.assertEqual(ob.run(), 0)
        self.assertTrue(fake.server.security_reboot)
        self.assertEqual([x for x in fake.scripts if self.REBOOT.search(x)], [])
        self.assertIsNone(self.REBOOT.search("test -f /var/run/reboot-required && echo reboot=yes || echo reboot=no"))
        self.assertIsNotNone(self.REBOOT.search("set -eu\nsystemctl reboot"))

    def test_no_install_now_on_a_server_that_restarts_itself_after_updates(self):
        server = Server()
        server.auto_reboot = True
        ob, fake, out, _ = self.make(server=server)
        self.assertEqual(ob.run(), 0)
        self.assertNotIn("security_updates", fake.server.applies)
        self.assertEqual(self.lines(out)[-1]["machine"]["security"], {"pending_security": 2, "reboot_required": False})
        self.assertIn("Not installed now", self.detail(out))

    def test_updates_that_stay_pending_are_reported(self):
        server = Server()
        server.security_held = 1
        ob, fake, out, _ = self.make(server=server)
        self.assertEqual(ob.run(), 0)
        self.assertEqual(self.lines(out)[-1]["machine"]["security"], {"pending_security": 1, "reboot_required": True})
        self.assertIn("1 pending", self.detail(out))

    def test_a_failed_install_or_count_fails_the_step_and_a_rerun_tries_again(self):
        server = Server()
        server.fail_security_with = "dpkg was interrupted"
        ob, fake, out, path = self.make(server=server)
        self.assertEqual(ob.run(), 1)
        self.assertEqual(self.statuses(out)["security_updates"], "failed")
        self.assertIn("Security update installation failed: E: dpkg was interrupted", self.detail(out))
        self.assertNotIn("security", json.loads(path.read_text()))
        server.fail_security_with, server.count_fails = None, True
        ob2, _, out2, _ = self.make(fake=fake, state=json.loads(path.read_text()))
        self.assertEqual(ob2.run(), 1)
        self.assertIn("Security update count failed", self.detail(out2))          # never read as "0 pending"
        server.count_fails = False
        ob3, _, out3, _ = self.make(fake=fake, state=json.loads(path.read_text()))
        self.assertEqual(ob3.run(), 0)
        self.assertEqual(fake.server.applies.count("security_updates"), 1)

    def run_script(self, script, stubs, strict):
        """The real script text under bash, with stand-in commands; strict is the sudo wrapper's set -eu."""
        bin_ = self.tmp / "bin"
        bin_.mkdir(exist_ok=True)
        for name, body in stubs.items():
            (bin_ / name).write_text("#!/bin/sh\n" + body + "\n")
            (bin_ / name).chmod(0o755)
        return subprocess.run(["bash", "-c", ("set -eu\n" if strict else "") + script], capture_output=True,
                              text=True, env={"PATH": "%s:/usr/bin:/bin" % bin_, "LOG": str(self.tmp / "log")})

    def test_the_count_script_reads_security_lines_reboot_and_the_restart_setting(self):
        listing = ("Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, "
                   "Ubuntu:24.04/noble-security [amd64])\n"
                   "Inst openssl [3.0.14-1~deb12u1] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])\n"
                   "Inst base-files [13ubuntu10.4] (13ubuntu10.5 Ubuntu:24.04/noble-updates [amd64])\n"
                   "Conf libssl3t64 (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-security [amd64])\n")
        (self.tmp / "listing").write_text(listing)
        marker = self.tmp / "reboot-required"
        script = onboard.SECURITY_STATUS.replace("/var/run/reboot-required", str(marker))
        for strict in (False, True):
            marker.unlink(missing_ok=True)
            r = self.run_script(script, {"apt-get": "cat %s" % (self.tmp / "listing"), "apt-config": "true"}, strict)
            self.assertEqual((r.returncode, onboard.kv(r.stdout)),
                             (0, {"pending": "2", "reboot": "no", "auto_reboot": "false"}), r.stderr)
            marker.write_text("*** System restart required ***\n")
            r = self.run_script(script, {"apt-config": "echo \"AUTO_REBOOT='true'\""}, strict)
            self.assertEqual(onboard.kv(r.stdout), {"pending": "2", "reboot": "yes", "auto_reboot": "true"})
            r = self.run_script(script, {"apt-get": "echo 'E: broken' >&2; exit 100"}, strict)
            self.assertNotEqual(r.returncode, 0)
            self.assertNotIn("pending=", r.stdout)

    def test_the_install_script_waits_for_the_package_lock_and_stops_on_failure(self):
        record = 'echo "$(basename "$0") $*" >> "$LOG"'
        for strict in (False, True):
            log = self.tmp / "log"
            log.unlink(missing_ok=True)
            r = self.run_script(onboard.SECURITY_APPLY, {"apt-get": record, "unattended-upgrade": record}, strict)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(log.read_text(), "apt-get -o DPkg::Lock::Timeout=%d -q install\nunattended-upgrade -v\n" % onboard.APT_LOCK_WAIT)
            log.unlink()
            r = self.run_script(onboard.SECURITY_APPLY, {"apt-get": record + "; exit 100",
                                                         "unattended-upgrade": record}, strict)
            self.assertNotEqual(r.returncode, 0)
            self.assertNotIn("unattended-upgrade", log.read_text())        # never runs after a failed wait
            r = self.run_script(onboard.SECURITY_APPLY, {"apt-get": record, "unattended-upgrade": "exit 1"}, strict)
            self.assertNotEqual(r.returncode, 0)


class Secrets(Base):
    def test_provider_password_goes_only_through_askpass(self):
        secret = "Pr0vider-Secret-123"
        ob, fake, out, path = self.make(auth="password", secrets=secret + "\n", password=secret)
        self.assertEqual(ob.run(), 0)
        self.assertEqual(fake.askpass_reads, [secret])
        self.assertNotIn(secret, out.getvalue())
        self.assertNotIn(secret, path.read_text())
        self.assertFalse(any(secret in s for s in fake.scripts))
        prompts = [e for e in self.lines(out) if e["type"] == "prompt" and e["kind"] == "secret"]
        self.assertEqual([p["data"]["label"] for p in prompts], ["provider_password"])

    def test_secret_in_remote_output_is_masked(self):
        secret = "Pr0vider-Secret-123"
        server = Server()
        server.fail_packages_with = "leaked " + secret
        ob, fake, out, path = self.make(server=server, auth="password", secrets=secret + "\n", password=secret)
        self.assertEqual(ob.run(), 1)
        self.assertNotIn(secret, out.getvalue())
        self.assertNotIn(secret, path.read_text())
        self.assertIn("[secret removed]", out.getvalue())

    def test_tailscale_auth_key_travels_only_on_stdin(self):
        key = "tskey-auth-abc123XYZ"
        ob, fake, out, path = self.make(tailscale="auth_key", secrets=key + "\n")
        self.assertEqual(ob.run(), 0)
        self.assertIn("tailscale_key", fake.server.applies)
        self.assertNotIn(key, out.getvalue())
        self.assertNotIn(key, path.read_text())
        body = [s for s in fake.scripts if key in s]
        self.assertEqual(len(body), 1)
        self.assertIn("FLEET_INPUT=$(cat <<'FLEET_EOF'", body[0])
        self.assertIn("rm -f /run/fleet-ts-authkey", body[0])

    def test_tailscale_up_with_the_key_drops_earlier_settings_and_ends_before_its_ssh_call(self):
        """**The `tailscale up` with the owner's key has `--reset`, and a `--timeout` that ends it before its SSH call
        ends.** An earlier `tailscale up` on the server (the hub's join line, a sign-in, a run with another tag) left
        its settings, and Tailscale refuses a `tailscale up` that does not name each of them again, unless it has
        `--reset`: until 11 November 2026 such a server never joined with a key. With no `--timeout`, `tailscale up`
        waits for ever on a tailnet that approves each new machine by hand: the SSH call ended first, and the key file
        stayed on the server."""
        key = "tskey-auth-abc123XYZ"
        untagged = {"name": "vps2", "host": "203.0.113.10", "port": 22, "login": "root", "runtime": "codex",
                    "runtime_version": "0.160.0"}           # a saved run with no tag: its line names none
        for earlier, state in ((["--advertise-tags=tag:fleet,tag:server", "--accept-dns=false"], untagged),
                               (["--hostname=worker-1", "--accept-dns=false"], None)):
            with self.subTest(earlier=earlier):
                ob, fake, out, path = self.make(tailscale="auth_key", secrets=key + "\n", state=state)
                fake.server.ts_settings = earlier
                self.assertEqual(ob.run(), 0, out.getvalue()[-600:])
                self.assertIn("tailscale_key", fake.server.applies)
                [at] = [n for n, script in enumerate(fake.scripts) if key in script]
                wait = re.search(r"tailscale up [^|]*--timeout=(\d+)s ", fake.scripts[at])
                self.assertIsNotNone(wait, fake.scripts[at])
                self.assertLess(int(wait[1]), fake.ssh_timeouts[at])

    def test_ssh_arguments_never_hold_the_password(self):
        captured = []
        sysm = System(Path("/tmp/kh"))
        sysm.run = lambda argv, input=None, env=None, timeout=120: captured.append((argv, env, input)) or (0, "", "")
        server = onboard.AskpassServer("SecretValue-9")
        try:
            sysm.ssh("h", 22, "root", "echo hi", auth="password", askpass=server)
        finally:
            server.close()
        argv, env, stdin = captured[0]
        self.assertNotIn("SecretValue-9", " ".join(argv))
        self.assertNotIn("SecretValue-9", json.dumps(env))
        self.assertNotIn("SecretValue-9", stdin)
        self.assertEqual(env["SSH_ASKPASS_REQUIRE"], "force")
        self.assertIn("StrictHostKeyChecking=yes", argv)


class Refusals(Base):
    def test_rejected_host_key_stops_and_pins_nothing(self):
        ob, fake, out, _ = self.make(confirm=False)
        self.assertEqual(ob.run(), 1)
        self.assertEqual(self.lines(out)[-1]["status"], "failed")
        self.assertFalse((Path(os.environ["FLEET_HOME"]) / "ssh" / "known_hosts").exists())
        self.assertEqual(fake.calls, [])

    def test_changed_host_key_aborts_a_resume(self):
        ob, fake, out, path = self.make()
        self.assertEqual(ob.run(), 0)
        fake.blob = fake.ts_blob = blob(9)             # a resume reaches the Tailscale address: the key changed there
        ob2, _, out2, _ = self.make(fake=fake, state=json.loads(path.read_text()))
        self.assertEqual(ob2.run(), 1)
        self.assertIn("host key changed", self.lines(out2)[-1]["summary"])

    def test_a_resume_that_fails_or_stops_is_not_finished_and_leaves_no_step_running(self):
        """An earlier run finished; a resume that fails in a step, or stops in one (an Abort here; a NeedsOwner takes
        the same path), is no longer finished, and the step that it ended in is failed: before, the saved run kept
        `finished` and the step stayed running."""
        ob, fake, out, path = self.make()
        self.assertEqual(ob.run(), 0)
        finished = json.loads(path.read_text())
        self.assertIn("finished", finished)
        fake.server.block_ts_proof = True                # a step fails: the managed key no longer reaches the server
        ob2, _, out2, _ = self.make(fake=fake, state=json.loads(json.dumps(finished)))
        self.assertEqual(ob2.run(), 1)
        self.assertEqual(self.statuses(out2)["managed_key"], "failed")
        self.assertNotIn("finished", json.loads(path.read_text()))
        fake.server.block_ts_proof = False
        fake.blob = fake.ts_blob = blob(9)               # the run stops in a step: the host key changed
        ob3, _, out3, _ = self.make(fake=fake, state=json.loads(json.dumps(finished)))
        self.assertEqual(ob3.run(), 1)
        last = [e for e in self.lines(out3) if e["type"] == "step"][-1]
        self.assertEqual((last["id"], last["status"]), ("host_key", "failed"))
        saved = json.loads(path.read_text())
        self.assertEqual(("finished" in saved, saved["steps"]["host_key"]["status"]), (False, "failed"))

    def test_tailscale_address_must_have_the_confirmed_key(self):
        server = Server()
        fake = FakeSystem(server, "203.0.113.10", self.bare)
        fake.ts_blob = blob(3)
        ob, _, out, _ = self.make(server=server, fake=fake)
        self.assertEqual(ob.run(), 1)
        self.assertIn("Tailscale address differs", self.lines(out)[-1]["summary"])

    def test_failed_proof_keeps_the_rollback_armed(self):
        server = Server()
        server.block_ts_proof = True
        ob, fake, out, _ = self.make(server=server)
        self.assertEqual(ob.run(), 1)
        self.assertEqual(self.statuses(out)["firewall"], "failed")
        self.assertEqual(server.rollback, "armed")

    def test_ubuntu_26_04_passes_the_system_check(self):
        ob, fake, out, _ = self.make(server=Server(os_line="ubuntu 26.04"))
        ob.run()
        self.assertEqual(self.statuses(out)["provider_login"], "done")

    def test_debian_13_passes_the_system_check(self):
        ob, fake, out, _ = self.make(server=Server(os_line="debian 13"))
        ob.run()
        self.assertEqual(self.statuses(out)["provider_login"], "done")

    def test_unsupported_system_is_refused(self):
        ob, fake, out, _ = self.make(server=Server(os_line="centos 9"))
        self.assertEqual(ob.run(), 1)
        self.assertEqual(self.statuses(out)["provider_login"], "failed")
        self.assertNotIn("packages", fake.server.applies)

    def test_preflight_needs_the_machines_feature_before_any_server_change(self):
        server = Server()
        fake = FakeSystem(server, "203.0.113.10", self.bare)
        fake.features = ["thread_events"]
        ob, _, out, _ = self.make(server=server, fake=fake)
        self.assertEqual(ob.run(), 1)
        self.assertEqual(self.statuses(out), {"preflight": "failed"})
        self.assertEqual(fake.calls, [])

    def test_preflight_refuses_a_registered_name(self):
        server = Server()
        fake = FakeSystem(server, "203.0.113.10", self.bare)
        fake.team["agents"]["vps2"] = {"role": "worker", "machine": "vps2", "runtime": "codex"}
        fake.team["addresses"]["vps2"] = "100.70.0.9"
        ob, _, out, _ = self.make(server=server, fake=fake)
        self.assertEqual(ob.run(), 1)
        self.assertIn("already has a worker or machine named vps2", self.lines(out)[-1]["summary"])
        self.assertEqual(fake.calls, [])

    def test_secret_longer_than_2048_bytes_is_refused(self):
        ob, fake, out, _ = self.make(auth="password", secrets="x" * 2049 + "\n", password="x")
        self.assertEqual(ob.run(), 1)
        self.assertIn("longer than 2048 bytes", self.lines(out)[-1]["summary"])

    def test_runtime_pins_are_exact_versions(self):
        self.assertTrue(all(re.fullmatch(r"\d+\.\d+\.\d+", v) for v in onboard.RUNTIME_PINS.values()))

    def test_ssh_settings_stay_one_block_and_the_include_is_added_once(self):
        key = Path(os.environ["FLEET_HOME"]) / "ssh" / "vps2_admin"
        onboard.write_ssh_config("vps2", "100.99.1.2", "root", 22, key)
        onboard.write_ssh_config("vps2", "100.99.1.2", "admin", 2222, key)
        config = (Path(os.environ["FLEET_HOME"]) / "ssh" / "config").read_text()
        self.assertEqual(config.count("Host 100.99.1.2"), 1)
        self.assertIn("  User admin\n  Port 2222", config)
        home = self.tmp / "home"
        (home / ".ssh").mkdir(parents=True)
        (home / ".ssh" / "config").write_text("Host old\n  User me\n")
        os.chmod(str(home / ".ssh" / "config"), 0o644)
        self.assertEqual(onboard.ssh_include()[0], "added")
        self.assertEqual(onboard.ssh_include()[0], "present")
        text = (home / ".ssh" / "config").read_text()
        self.assertTrue(text.splitlines()[1].startswith("Include "))
        self.assertTrue(text.endswith("Host old\n  User me\n"))
        self.assertEqual((home / ".ssh" / "config").stat().st_mode & 0o777, 0o644)

    def test_a_symlinked_ssh_config_is_refused_not_replaced(self):
        home = self.tmp / "home"
        (home / ".ssh").mkdir(parents=True)
        target = self.tmp / "dotfiles-ssh-config"
        target.write_text("Host old\n")
        (home / ".ssh" / "config").symlink_to(target)
        self.assertEqual(onboard.ssh_include()[0], "refused")
        self.assertTrue((home / ".ssh" / "config").is_symlink())
        self.assertEqual(target.read_text(), "Host old\n")

    def test_a_new_agent_takes_only_how_its_runtime_starts_from_the_template(self):
        import hub
        kit = self.tmp / "kit"
        (kit / "profiles").mkdir(parents=True)
        team = json.loads(json.dumps(TEAM))
        team["addresses"]["studio"] = "100.111.0.30"
        team["accounts"] = {"claude-studio": {"provider": "anthropic", "title": "Studio account"}}
        template = {"role": "worker", "machine": "studio", "runtime": "claude", "reports_to": "manager", "active": True,
                    "can": ["shell", "web", "browser", "screen"],
                    "start": "claude --permission-mode dontAsk {chrome} {settings} {prompt}",     # a form (plan 0.2)
                    "allow": ["Bash(git:*)"], "title": "SEO Expert", "expertise": ["seo"], "account": "claude-studio",
                    "screen_command": "/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex",
                    "screen": {"model": "gpt-6-luna", "effort": "high"},
                    "model": "opus", "effort": "max", "vault": "broker", "vault_recipient": "age1" + "s" * 58}
        team["agents"]["studio"] = template
        hub.validate_team(team)
        (kit / "team.json").write_text(json.dumps(team))
        self.assertTrue(onboard.register_in_kit(kit, "linux-claude", "claude", "100.99.1.3"))
        saved = json.loads((kit / "team.json").read_text())
        self.assertEqual(saved["agents"]["linux-claude"],
                         {"start": template["start"], "allow": template["allow"], "role": "worker",
                          "machine": "linux-claude", "runtime": "claude", "can": ["shell", "web"], "active": False})
        self.assertEqual(saved["agents"]["studio"], template)                     # the template stays as it was
        hub.validate_team(saved)                                                  # the new team is valid

    def test_register_refuses_a_conflicting_existing_name(self):
        kit = self.tmp / "kit"
        (kit / "profiles").mkdir(parents=True)
        team = json.loads(json.dumps(TEAM))
        team["agents"]["vps2"] = {"role": "worker", "machine": "other", "runtime": "codex"}
        (kit / "team.json").write_text(json.dumps(team))
        with self.assertRaises(StepFailed):
            onboard.register_in_kit(kit, "vps2", "codex", "100.99.1.2")


class Stop(BaseException):
    """The executor process ends here. run() catches no BaseException, so nothing after it is saved, as after a kill."""


class Interruptions(Base):
    """A run that ends at a boundary, then a resume of its saved state. With FLEET_ONBOARD_EVENTS=<folder>, each run's
    JSON Lines stay in that folder, for the app's consumer check."""
    def keep(self, out, phase):
        folder = os.environ.get("FLEET_ONBOARD_EVENTS")
        if folder:
            Path(folder).mkdir(parents=True, exist_ok=True)
            (Path(folder) / ("%s.%s.jsonl" % (self._testMethodName, phase))).write_text(out.getvalue())

    def commits(self):
        return int(subprocess.run(["git", "--git-dir", str(self.bare), "rev-list", "--count", "main"],
                                  capture_output=True, text=True, check=True).stdout)

    def test_a_stop_after_the_hub_reloads_the_registration_resumes_with_its_own_name(self):
        ob, fake, out, path = self.make()
        http = fake.http

        def reload_then_stop(method, url, body=None, headers=None):
            answer = http(method, url, body, headers)
            if url.endswith("/ui/team/reload") and answer[0] == 200:
                raise Stop()            # the hub lists the worker; the step's own save never comes
            return answer
        fake.http = reload_then_stop
        with self.assertRaises(Stop):
            ob.run()
        self.keep(out, "stopped")
        fake.http = http
        ob2, _, out2, _ = self.make(fake=fake, state=json.loads(path.read_text()))
        self.assertEqual(ob2.run(), 0)
        self.keep(out2, "resumed")
        st = self.statuses(out2)
        self.assertEqual((st["preflight"], st["register"]), ("skipped", "skipped"))
        self.assertEqual((self.commits(), len(fake.reloads)), (2, 1))      # the seed and one registration; one reload

    def test_a_push_that_arrives_without_its_answer_makes_no_second_commit(self):
        """The fresh fetch after the failed push finds the change on the ref, so the run goes on with that revision."""
        ob, fake, out, path = self.make()
        git = fake.git

        def lost_answer(args, cwd=None):
            answer = git(args, cwd=cwd)
            if args[:1] == ["push"] and answer[0] == 0:
                return 128, "", "fatal: the remote end hung up unexpectedly"
            return answer
        fake.git = lost_answer
        self.assertEqual(ob.run(), 0)
        self.keep(out, "finished")
        self.assertEqual(self.statuses(out)["register"], "done")
        main = subprocess.run(["git", "--git-dir", str(self.bare), "rev-parse", "main"], capture_output=True, text=True,
                              check=True).stdout.strip()
        self.assertEqual(json.loads(path.read_text())["registration_commit"], main)
        self.assertEqual((self.commits(), len(fake.reloads)), (2, 1))

    def test_a_resume_cancels_an_armed_rollback_only_after_a_proof(self):
        server = Server()
        server.block_ts_proof = True                    # ufw is on and its rollback is armed; the Tailscale proof fails
        ob, fake, out, path = self.make(server=server)
        self.assertEqual(ob.run(), 1)
        self.keep(out, "failed")
        resume = lambda: self.make(fake=fake, state=json.loads(path.read_text()))
        ob2, _, out2, _ = resume()                      # the owner resumes before the rollback fires; SSH still fails
        before = len(fake.calls)
        self.assertEqual(ob2.run(), 1)
        self.assertEqual(server.rollback, "armed")
        self.assertEqual({c[1] for c in fake.calls[before:]}, {"100.99.1.2"})     # never the public address again
        server.block_ts_proof, server.fail_rollback_stop = False, True
        ob3, _, out3, _ = resume()                      # the proof works, but the cancel fails: no success
        self.assertEqual(ob3.run(), 1)
        self.keep(out3, "cancel_failed")
        self.assertEqual((self.statuses(out3)["firewall"], server.rollback), ("failed", "armed"))
        server.fail_rollback_stop = False
        ob4, _, out4, _ = resume()
        self.assertEqual(ob4.run(), 0)
        self.keep(out4, "resumed")
        firewall = [e for e in self.lines(out4) if e["type"] == "step" and e["id"] == "firewall"][-1]
        self.assertEqual((firewall["status"], server.rollback), ("done", "cancelled"))
        self.assertIn("an earlier run armed", firewall["detail"])
        cancels = server.events.count("cancelled")
        ob5, _, out5, _ = resume()                      # no armed rollback: no change and no stop
        self.assertEqual(ob5.run(), 0)
        self.assertEqual((self.statuses(out5)["firewall"], server.events.count("cancelled")), ("skipped", cancels))


class Protocol(Base):
    def test_lines_have_version_run_and_increasing_seq(self):
        ob, fake, out, _ = self.make()
        ob.run()
        events = self.lines(out)
        self.assertEqual([e["seq"] for e in events], list(range(1, len(events) + 1)))
        self.assertTrue(all(e["v"] == 1 and e["run"] == "r1" for e in events))
        kinds = {e["kind"] for e in events if e["type"] == "prompt"}
        self.assertEqual(kinds, {"confirm_host_key", "open_url", "choice"})
        choice = [e for e in events if e["type"] == "prompt" and e["kind"] == "choice"][0]["data"]
        self.assertEqual(set(choice), {"question", "options"})
        self.assertEqual(set(choice["options"][0]), {"value", "label"})
        fp = [e for e in events if e["type"] == "prompt" and e["kind"] == "confirm_host_key"][0]["data"]
        self.assertEqual(set(fp["fingerprints"][0]), {"algorithm", "sha256"})
        self.assertTrue(fp["fingerprints"][0]["sha256"].startswith("SHA256:"))

    def test_codex_sign_in_prompt_has_link_and_code(self):
        ob, fake, out, _ = self.make()
        ob.run()
        codex = [u for u in ob.ch.inp.urls if u["purpose"] == "codex_login"][0]
        self.assertEqual(codex["url"], "https://auth.openai.com/codex/device")
        self.assertEqual(codex["code"], "WXYZ-12345")
        self.assertTrue(fake.server.login_cleaned)

    def test_command_line_refuses_identity_without_file_and_secret_config(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = onboard.main(["run", "--json", "--name", "vps2", "--host", "h", "--login", "root",
                                 "--runtime", "codex", "--auth", "identity", "--hub", "http://h", "--repo", "git://h/r"])
        self.assertEqual(code, 1)
        self.assertIn("--identity-file", json.loads(buf.getvalue())["summary"])
        cfg = self.tmp / "cfg.json"
        cfg.write_text(json.dumps({"hub": "http://h", "repo": "git://h/r", "password": "x"}))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = onboard.main(["run", "--json", "--name", "vps2", "--host", "h", "--login", "root",
                                 "--runtime", "codex", "--auth", "agent", "--config", str(cfg)])
        self.assertEqual(code, 1)
        self.assertIn("must not hold secrets", json.loads(buf.getvalue())["summary"])

    def test_new_runs_get_the_network_tags_unless_a_flag_config_or_saved_run_names_others(self):
        """The product names no tag of one owner's tailnet (the owner, 3 November 2026: "this app needs to work for ANY
        user"): a run that names none takes network_tags, by the rule of the hub's join line, and a run with no tag
        asks for none."""
        self.assertEqual(onboard.tailscale_tags(" tag:a-1 , tag:B2 "), "tag:a-1,tag:B2")
        self.assertEqual((onboard.tailscale_tags(None), onboard.tailscale_tags(" ")), ("", ""))
        for bad in ("claude-code-dev", "tag:", "tag:a b", "tag:a,,tag:b", "tag:a,tag:a", "tag:-a", "tag:a;id"):
            with self.assertRaises(onboard.Abort):
                onboard.tailscale_tags(bad)
        cfg = self.tmp / "cfg.json"
        cfg.write_text(json.dumps({"tailscale_tag": "tag:from-config"}))
        base = ["run", "--json", "--host", "h", "--login", "root", "--runtime", "codex", "--auth", "agent",
                "--hub", "http://h", "--repo", "git://h/r"]
        seen = []
        with patch.object(onboard.Onboarding, "run", lambda ob: seen.append(ob.state["tailscale_tag"]) or 0), \
                patch.object(onboard, "network_tags", return_value="tag:founderizer") as network, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(onboard.main(base + ["--name", "new-a"]), 0)
            self.assertEqual(onboard.main(base + ["--name", "new-b", "--tailscale-tag", "tag:owner-choice"]), 0)
            self.assertEqual(onboard.main(base + ["--name", "new-c", "--config", str(cfg)]), 0)
            network.return_value = ""                       # a tailnet where no machine carries the product's tag
            self.assertEqual(onboard.main(base + ["--name", "new-e"]), 0)
            saved = Path(os.environ["FLEET_HOME"]) / "onboarding" / "old-run.json"
            saved.write_text(json.dumps({"name": "old-run", "host": "h", "port": 22, "login": "root",
                                         "runtime": "codex", "tailscale_tag": "tag:claude-code-dev"}))
            self.assertEqual(onboard.main(["run", "--json", "--resume", "old-run", "--auth", "agent",
                                           "--hub", "http://h", "--repo", "git://h/r"]), 0)
        network.assert_called_with("http://h")
        self.assertEqual(seen, ["tag:founderizer", "tag:owner-choice", "tag:from-config", "", "tag:claude-code-dev"])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(onboard.main(base + ["--name", "new-d", "--tailscale-tag", "claude-code-dev"]), 1)
        self.assertIn("tag:<name>", json.loads(buf.getvalue())["summary"])
        state = {"name": "vps2", "host": "203.0.113.10", "port": 22, "login": "root", "runtime": "codex",
                 "runtime_version": "0.160.0"}                       # a saved run with no tag asks for none
        ob, fake, _, _ = self.make(state=state)
        self.assertEqual(ob.run(), 0)
        up = [x for x in fake.scripts if "tailscale up" in x][0]
        self.assertIn("tailscale up --accept-dns=false --ssh=false", up)
        self.assertNotIn("--advertise-tags", up)
        # A saved run that holds the hub's own tag of the connected apps joins without it (ONE_MACHINE_TAG): its
        # join key does not carry that tag, and no server but the hub's may publish an address.
        for saved, line in (("tag:founderizer,tag:founderizer-hub", "tailscale up --advertise-tags=tag:founderizer "),
                            ("tag:founderizer-hub", "tailscale up --accept-dns=false --ssh=false")):
            ob, fake, _, _ = self.make(state=dict(state, tailscale_tag=saved))
            self.assertEqual(ob.run(), 0)
            up = [x for x in fake.scripts if "tailscale up" in x][0]
            self.assertIn(line, up, saved)
            self.assertNotIn("founderizer-hub", up, saved)

    def test_the_network_tags_are_the_hubs_else_the_product_tag_where_the_tailnet_has_it(self):
        hub_tagged = {"Self": {"TailscaleIPs": ["100.64.0.5"]},
                      "Peer": {"h": {"TailscaleIPs": ["100.64.0.1", "fd7a::1"], "Tags": ["tag:a", "tag:x;id"]},
                               "p": {"TailscaleIPs": ["100.64.0.2"], "Tags": None},
                               "f": {"TailscaleIPs": ["100.64.0.3"], "Tags": ["tag:founderizer"]}}}
        no_product = {"Self": {"TailscaleIPs": ["100.64.0.1"]},
                      "Peer": {"o": {"TailscaleIPs": ["100.64.0.4"], "Tags": ["tag:other"]}}}

        def answer(code, out):
            return patch.object(onboard.subprocess, "run", return_value=subprocess.CompletedProcess([], code, out, ""))
        with patch.object(onboard.shutil, "which", return_value="/usr/bin/tailscale"):
            with answer(0, json.dumps(hub_tagged)):
                self.assertEqual([NETWORK_TAGS(f"http://{h}:8765") for h in ("100.64.0.1", "100.64.0.2", "100.64.0.9")],
                                 ["tag:a", "tag:founderizer", "tag:founderizer"])
            with answer(0, json.dumps(no_product)):
                self.assertEqual(NETWORK_TAGS("http://100.64.0.1:8765"), "")       # the hub is this computer
            # The hub's own tag of the connected apps is a tag of one machine (ONE_MACHINE_TAG): a new run takes the
            # hub's other tags, and with no other tag the product tag where the tailnet has it.
            with_hub_tag = json.loads(json.dumps(hub_tagged))
            with_hub_tag["Peer"]["h"]["Tags"] = ["tag:founderizer-hub", "tag:a"]
            with answer(0, json.dumps(with_hub_tag)):
                self.assertEqual(NETWORK_TAGS("http://100.64.0.1:8765"), "tag:a")
            with_hub_tag["Peer"]["h"]["Tags"] = ["tag:founderizer-hub"]
            with answer(0, json.dumps(with_hub_tag)):
                self.assertEqual(NETWORK_TAGS("http://100.64.0.1:8765"), "tag:founderizer")
            for code, out in ((1, ""), (0, "not json"), (0, "[]")):
                with answer(code, out):
                    self.assertEqual(NETWORK_TAGS("http://100.64.0.1:8765"), "", (code, out))
            with patch.object(onboard.subprocess, "run", side_effect=subprocess.TimeoutExpired(["tailscale"], 5)):
                self.assertEqual(NETWORK_TAGS("http://100.64.0.1:8765"), "")
        with patch.object(onboard.shutil, "which", return_value=None), \
                patch.object(onboard.os.path, "exists", return_value=False):
            self.assertEqual(NETWORK_TAGS("http://100.64.0.1:8765"), "")

    def test_stopping_the_codex_login_spares_the_shell_that_starts_it(self):
        """The exact start and clean-up text from a run, with a harmless fake login: <home>/.local/bin/codex is a link
        to bash, so its process shows "<home>/.local/bin/codex login --device-auth" like the real binary."""
        pattern = onboard.CODEX_LOGIN
        uid = str(os.getuid())
        if subprocess.run(["pgrep", "-u", uid, "-f", pattern], capture_output=True).returncode == 0:
            self.skipTest("a real Codex login runs as this user; this check would stop it")
        ob, fake, _, _ = self.make()
        self.assertEqual(ob.run(), 0)
        start = shlex.split(next(x for x in fake.scripts if "--device-auth >" in x))[6]
        stop = shlex.split(next(x for x in fake.scripts if "rm -f $HOME/.fleet-codex-login.log" in x))[6]
        home, elsewhere = self.tmp / "whome", self.tmp / "root"
        (home / ".local/bin").mkdir(parents=True)
        elsewhere.mkdir()
        (home / ".local/bin/codex").symlink_to(shutil.which("bash"))
        (home / "login").write_text("while :; do sleep 0.2; done\n")       # what the fake codex runs
        # Linux pkill also matches the shell that runs it (that was the live failure); macOS pkill skips its own
        # ancestors unless given -a. This wrapper gives the Linux rule on both.
        pbin = self.tmp / "pbin"
        pbin.mkdir()
        (pbin / "pkill").write_text("#!/bin/sh\nexec %s %s\"$@\"\n" % (shutil.which("pkill"),
                                                                       "-a " if sys.platform == "darwin" else ""))
        (pbin / "pkill").chmod(0o755)
        env = {"HOME": str(home), "PATH": "%s:/usr/bin:/bin" % pbin}
        self.addCleanup(subprocess.run, ["pkill", "-u", uid, "-f", str(home)], capture_output=True)
        old = subprocess.Popen([str(home / ".local/bin/codex"), "login", "--device-auth"], cwd=str(home), env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        launcher = subprocess.run(["bash", "-c", start + "\nsleep 1; echo launcher survived"], cwd=str(elsewhere),
                                  env=env, capture_output=True, text=True, timeout=30)
        self.assertIn("launcher survived", launcher.stdout, launcher.stderr)  # it holds the same words, later on
        self.assertIsNotNone(old.wait(timeout=5))                               # the earlier login was stopped
        started = subprocess.run(["pgrep", "-u", uid, "-f", pattern], capture_output=True, text=True).stdout.split()
        self.assertEqual(len(started), 1)                                       # the new login runs
        cleanup = subprocess.run(["bash", "-c", stop + "\necho cleanup survived"], cwd=str(elsewhere), env=env,
                                 capture_output=True, text=True, timeout=30)
        self.assertIn("cleanup survived", cleanup.stdout, cleanup.stderr)
        for _ in range(50):
            if subprocess.run(["pgrep", "-u", uid, "-f", pattern], capture_output=True).returncode != 0:
                break
            time.sleep(0.1)
        else:
            self.fail("the clean-up did not stop the fake login")
        self.assertFalse((home / ".fleet-codex-login.log").exists())

    def test_worker_commands_start_in_the_worker_home_or_not_at_all(self):
        argv = shlex.split(onboard.as_worker("pwd"))
        self.assertEqual(argv[:6], ["runuser", "-u", "fleet", "--", "bash", "-lc"])
        home, root = self.tmp / "worker-home", self.tmp / "root"
        home.mkdir()
        root.mkdir()
        run = lambda h: subprocess.run(["bash", "-c", argv[6]], cwd=str(root), capture_output=True, text=True,
                                       env={"HOME": str(h), "PATH": "/usr/bin:/bin"})
        r = run(home)                                   # runuser keeps the caller's folder, such as /root
        self.assertEqual((r.returncode, os.path.realpath(r.stdout.strip())), (0, os.path.realpath(str(home))))
        r = run(self.tmp / "missing")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "")                  # the command never ran in the wrong folder

    def test_version_line(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(onboard.main(["version"]), 0)
        self.assertEqual(json.loads(buf.getvalue()), {"v": 1, "type": "version", "executor": "1.3.3",
                                                      "capabilities": ["existing_machine", "prepare_runtime"]})


class ClaudeSignIn(Base):
    """A new worker's first Claude sign-in: one command for the owner's Terminal, then a wait on the worker's derived
    status. Fleet never runs the sign-in, never sees its code and never signs an account out."""

    def claude(self, auth="no", signs_in=True):
        ob, fake, out, _ = self.make()
        ob.state.update({"runtime": "claude", "runtime_version": "2.1.287", "tailscale_ip": "100.99.1.2"})
        fake.server.managed_ok = True
        fake.server.claude_auth, fake.server.claude_signs_in = auth, signs_in
        return ob, fake, out

    def test_an_unsigned_claude_gets_one_terminal_command_and_setup_waits_for_its_own_sign_in(self):
        ob, fake, out = self.claude()
        self.assertEqual(ob.s_runtime_login(), ("done", "Claude is signed in."))
        [prompt] = ob.ch.inp.terminals
        config = Path(os.environ["FLEET_HOME"]) / "ssh" / "config"
        remote = onboard.as_worker('cd "$HOME/fleet-pilot" && exec "$HOME/.local/bin/claude"')
        self.assertEqual(prompt, {"purpose": "claude_login",
                                  "command": shlex.join(["ssh", "-F", str(config), "-t", "100.99.1.2", remote])})
        self.assertIn("Host 100.99.1.2", config.read_text())     # the managed key and pinned host key of this worker
        self.assertIn("checkout_clone", fake.server.applies)       # Claude's first folder trust is for this checkout
        status = [x for x in fake.scripts if "echo fleet-claude-auth=1" in x]
        self.assertTrue(status and all(x.startswith("runuser -u fleet") and '"$HOME/.local/bin/claude" auth status --json' in x
                                       for x in status))
        self.assertTrue(any(e["type"] == "log" and "15 minutes" in e["text"] for e in self.lines(out)))
        self.assertNotIn("logout", "\n".join(fake.scripts))

    def test_the_command_reaches_the_worker_checkout_and_its_claude_without_a_local_home(self):
        work = self.tmp / "run"
        fakebin, home, owner = work / "bin", work / "home-fleet", work / "home-owner"
        for d in (fakebin, home / "fleet-pilot", home / ".local" / "bin", owner):
            d.mkdir(parents=True)
        def script(path, body):
            path.write_text("#!/bin/sh\n" + body)
            path.chmod(0o755)
        script(fakebin / "ssh", 'for a in "$@"; do printf "%s\\0" "$a"; done > "$SSH_ARGS"\n')
        script(fakebin / "runuser", 'while [ "$1" != "--" ]; do shift; done; shift; exec "$@"\n')   # as the worker
        script(home / ".local" / "bin" / "claude", 'pwd > "$CLAUDE_RAN"\n')
        command = onboard.claude_login_command(self.tmp / "my config", "100.99.1.2", "root")
        env = {"PATH": "%s:/usr/bin:/bin" % fakebin, "HOME": str(owner), "SSH_ARGS": str(work / "args"),
               "CLAUDE_RAN": str(work / "ran")}
        subprocess.run(["sh", "-c", command], env=env, check=True)                     # the owner's Terminal
        argv = (work / "args").read_text().split("\0")[:-1]
        self.assertEqual(argv[:4], ["-F", str(self.tmp / "my config"), "-t", "100.99.1.2"])
        self.assertEqual(len(argv), 5)                                                  # one remote argument
        remote = argv[4]
        self.assertIn('"$HOME/.local/bin/claude"', remote)                             # not expanded on the Mac
        self.assertNotIn(str(owner), remote)
        subprocess.run(["bash", "-c", remote], env=dict(env, HOME=str(home)), check=True)   # the worker's shell
        self.assertEqual(Path((work / "ran").read_text().strip()).resolve(), (home / "fleet-pilot").resolve())
        self.assertTrue(onboard.claude_login_command("/c", "100.99.1.2", "admin").endswith(
            shlex.quote("sudo -n " + onboard.as_worker('cd "$HOME/fleet-pilot" && exec "$HOME/.local/bin/claude"'))))

    def test_a_signed_in_claude_is_kept_and_gets_no_command(self):
        ob, fake, _ = self.claude(auth="yes")
        self.assertEqual(ob.s_runtime_login(), ("skipped", "Claude is signed in."))
        self.assertEqual(ob.ch.inp.terminals, [])
        self.assertNotIn("checkout_clone", fake.server.applies)
        self.assertNotIn("logout", "\n".join(fake.scripts))

    def test_a_failed_status_check_is_not_a_missing_sign_in(self):
        ob, _, _ = self.claude(auth="fail")
        with self.assertRaisesRegex(onboard.StepFailed, "status check failed"):
            ob.s_runtime_login()
        self.assertEqual(ob.ch.inp.terminals, [])                  # no sign-in command for an unknown status

    def test_copying_the_command_only_starts_the_wait_and_a_timeout_can_resume(self):
        ob, fake, _ = self.claude(signs_in=False)
        with self.assertRaisesRegex(onboard.StepFailed, "within 15 minutes. Resume"):
            ob.s_runtime_login()
        self.assertEqual(len(ob.ch.inp.terminals), 1)
        fake.server.claude_auth = "yes"                            # the owner finished later
        self.assertEqual(ob.s_runtime_login(), ("skipped", "Claude is signed in."))

    def test_the_status_lines_name_no_account(self):
        home = self.tmp / "worker"
        (home / ".local" / "bin").mkdir(parents=True)
        claude = home / ".local" / "bin" / "claude"
        def status(body, code):
            claude.write_text("#!/bin/sh\n[ \"$1 $2 $3\" = \"auth status --json\" ] || exit 9\n"
                              "printf '%%s\\n' %s\nexit %d\n" % (shlex.quote(body), code))
            claude.chmod(0o755)
            env = {"HOME": str(home), "PATH": "/usr/bin:/bin"}
            return subprocess.run(["bash", "-c", onboard.CLAUDE_STATUS], capture_output=True, text=True, env=env).stdout
        account = '"email": "owner@example.com", "orgName": "Example"'
        self.assertEqual(status('{"loggedIn": true, %s}' % account, 0), "fleet-claude-auth=1\nrc=0\nlogged_in=yes\n")
        self.assertEqual(status('{"loggedIn": false}', 1), "fleet-claude-auth=1\nrc=1\nlogged_in=no\n")
        self.assertEqual(status("Error: unexpected", 2), "fleet-claude-auth=1\nrc=2\nlogged_in=unknown\n")
        claude.unlink()                                            # no runtime: unknown, not "not signed in"
        missing = subprocess.run(["bash", "-c", onboard.CLAUDE_STATUS], capture_output=True, text=True,
                                 env={"HOME": str(home), "PATH": "/usr/bin:/bin"}).stdout
        self.assertEqual(missing, "fleet-claude-auth=1\nrc=127\nlogged_in=unknown\n")


class ClaudeUpdates(Base):
    """The Claude version of an installation is only its first build: Claude Code's own installation updates itself.
    After Fleet's own installation, updates follow the vendor's stable channel, with a floor at the installed version.
    Only those two keys of the worker user's Claude settings change."""

    def channel(self, home, shown="2.1.287 (Claude Code)"):
        """The real program, as the worker user would run it: python3 with the claude command as its argument."""
        claude = home / "claude"
        claude.write_text("#!/bin/sh\n[ \"$1\" = --version ] && echo %s\n" % shlex.quote(shown))
        claude.chmod(0o755)
        return subprocess.run([sys.executable, "-c", onboard.CLAUDE_CHANNEL, str(claude)], capture_output=True, text=True,
                              env={"HOME": str(home), "PATH": "/usr/bin:/bin"})

    def test_a_new_claude_worker_follows_the_stable_channel_after_its_first_install(self):
        ob, fake, _, _ = self.make()
        ob.state.update({"runtime": "claude", "runtime_version": "2.1.287"})
        fake.server.managed_ok = True
        self.assertEqual(ob.s_runtime(), ("done", "2.1.287 (Claude Code). Updates follow the stable channel, not below 2.1.287."))
        install = next(i for i, x in enumerate(fake.scripts) if "claude.ai/install.sh | bash -s 2.1.287" in x)
        [channel] = [i for i, x in enumerate(fake.scripts) if "fleet-claude-channel=1" in x]
        self.assertGreater(channel, install)
        self.assertTrue(fake.scripts[channel].startswith("runuser -u fleet"))
        self.assertIn("$HOME/.local/bin/claude", fake.scripts[channel])
        self.assertEqual(ob.s_runtime()[0], "skipped")                      # a later run checks the settings again
        self.assertEqual((fake.server.applies.count("runtime"), fake.server.applies.count("channel")), (1, 1))
        # A run that continues after Claude updated itself: the newer build stays, and its version is the floor.
        newer, moved, _, _ = self.make()
        newer.state.update({"runtime": "claude", "runtime_version": "2.1.287"})
        moved.server.managed_ok = True
        moved.server.paths["claude"], moved.server.versions["claude"] = "/home/fleet/.local/bin/claude", "2.1.296 (Claude Code)"
        self.assertEqual(newer.s_runtime(), ("skipped", "2.1.296 (Claude Code). Updates follow the stable channel, not below 2.1.296."))
        self.assertFalse(any("install.sh" in x for x in moved.scripts))
        self.assertEqual(moved.server.claude_settings, ("stable", "2.1.296"))
        moved.server.versions["claude"] = "2.1.100 (Claude Code)"           # an older build than the pin is replaced
        self.assertEqual(newer.s_runtime()[0], "done")
        self.assertTrue(any("claude.ai/install.sh | bash -s 2.1.287" in x for x in moved.scripts))
        self.assertTrue(onboard.not_older("codex-cli 0.162.1", "0.160.0") and onboard.not_older("2.1.287 (Claude Code)", "2.1.287"))
        self.assertFalse(onboard.not_older("2.1.99", "2.1.287") or onboard.not_older("", "2.1.287")
                         or onboard.not_older("2.1.296", "stable"))
        fake.server.claude_settings_broken = True                           # a file that it must not replace
        with self.assertRaisesRegex(StepFailed, "could not be set: .*not a JSON object; it was not changed"):
            ob.s_runtime()
        codex, other, _, _ = self.make()                                    # Codex: its version stays by itself
        other.server.managed_ok = True
        self.assertEqual(codex.s_runtime(), ("done", "codex-cli 0.160.0"))
        self.assertFalse(any("fleet-claude-channel" in x for x in other.scripts))

    def test_only_the_channel_and_the_floor_change_in_the_users_settings(self):
        home = self.tmp / "worker"
        (home / ".claude").mkdir(parents=True)
        path = home / ".claude" / "settings.json"
        r = self.channel(home)                                              # no settings file yet
        self.assertEqual((r.returncode, onboard.kv(r.stdout)), (0, {"fleet-claude-channel": "1", "floor": "2.1.287",
                                                                    "changed": "yes", "updates_off": ""}), r.stderr)
        self.assertEqual(json.loads(path.read_text()), {"autoUpdatesChannel": "stable", "minimumVersion": "2.1.287"})
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        before = path.read_bytes()
        self.assertEqual(onboard.kv(self.channel(home).stdout)["changed"], "no")       # the same again: no write
        self.assertEqual(path.read_bytes(), before)
        # The owner's other settings stay, also a setting that turns updates off. A lower floor goes up.
        owner = {"permissions": {"allow": ["Bash(git:*)"], "deny": ["Read(~/.ssh/**)"]}, "hooks": {"Stop": []},
                 "env": {"DISABLE_AUTOUPDATER": "1", "OTHER": "kept"}, "model": "opus",
                 "autoUpdatesChannel": "latest", "minimumVersion": "2.1.200"}
        path.write_text(json.dumps(owner))
        path.chmod(0o644)
        r = self.channel(home)
        self.assertEqual(onboard.kv(r.stdout), {"fleet-claude-channel": "1", "floor": "2.1.287", "changed": "yes",
                                                "updates_off": "DISABLE_AUTOUPDATER"})
        self.assertEqual(json.loads(path.read_text()), dict(owner, autoUpdatesChannel="stable", minimumVersion="2.1.287"))
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)
        # A higher floor stays. A newer installed build sets its own floor, so stable cannot take it back.
        path.write_text(json.dumps({"minimumVersion": "2.1.300"}))
        self.assertEqual(onboard.kv(self.channel(home).stdout)["floor"], "2.1.300")
        self.assertEqual(json.loads(path.read_text()), {"minimumVersion": "2.1.300", "autoUpdatesChannel": "stable"})
        path.write_text(json.dumps({"autoUpdatesChannel": "stable", "minimumVersion": "2.1.287"}))
        self.assertEqual(onboard.kv(self.channel(home, "2.1.296 (Claude Code)").stdout)["floor"], "2.1.296")
        self.assertEqual(json.loads(path.read_text())["minimumVersion"], "2.1.296")
        self.assertEqual(onboard.kv(self.channel(home, "2.1.10 (Claude Code)").stdout)["floor"], "2.1.296")   # 10 < 296

    def test_a_settings_file_that_it_cannot_merge_is_left_as_it_is(self):
        home = self.tmp / "worker"
        (home / ".claude").mkdir(parents=True)
        path = home / ".claude" / "settings.json"
        for text, words in (("{not json", "cannot be read as JSON"), ('["a list"]', "not a JSON object")):
            path.write_text(text)
            r = self.channel(home)
            self.assertEqual((r.returncode, r.stdout, path.read_text()), (1, "", text))
            self.assertIn(words + "; it was not changed", r.stderr)
        path.unlink()
        target = self.tmp / "dotfiles-settings.json"
        target.write_text("{}")
        path.symlink_to(target)
        r = self.channel(home)
        self.assertEqual((r.returncode, target.read_text(), path.is_symlink()), (1, "{}", True))
        self.assertIn("symbolic link", r.stderr)
        path.unlink()
        r = self.channel(home, "no version here")
        self.assertEqual((r.returncode, path.exists()), (1, False))
        self.assertIn("gave no version", r.stderr)


class ExistingMachine(Base):
    """Add agent on an existing machine (owner API 1.12): one inactive agent with no credential access, with the
    machine's own SSH access, worker user and runtime, in its own checkout and service."""

    def existing(self, fake=None, name="seo", runtime="codex", auth="agent", secrets="", **access):
        fake = fake or FakeSystem(Server(), "203.0.113.10", self.bare)
        if "agent_auth" not in fake.features:
            fake.features = fake.features + ["agent_auth"]
        fake.access.update(access)
        out = io.StringIO()
        ch = Channel(out=out, inp=None, run_id="r2")
        ch.inp = AutoAnswer(out, fake)
        ch.secret_file = io.StringIO(secrets)
        state_dir = Path(os.environ["FLEET_HOME"]) / "onboarding"
        state_dir.mkdir(parents=True, exist_ok=True)
        path = state_dir / ("%s.json" % name)
        state = json.loads(path.read_text()) if path.exists() else {   # a saved run continues, as --resume does
            "mode": "existing_machine", "machine": "vps", "name": name, "runtime": runtime, "created": 1.0,
            "executor": onboard.EXECUTOR_VERSION}
        ob = Onboarding(ch, fake, path, state, {"mode": auth, "identity_file": None, "tailscale": "login_url"},
                        "http://hub.test:8765", str(self.bare))
        return ob, fake, out

    def team(self):
        return json.loads(subprocess.run(["git", "--git-dir", str(self.bare), "show", "main:team.json"],
                                         capture_output=True, text=True, check=True).stdout)

    def hub_commit(self, edit, branch="main", message="A change of the hub"):
        """A commit that the hub makes on its repository by itself: edit changes team.json in place."""
        work = Path(tempfile.mkdtemp(dir=str(self.tmp)))
        git = ["git", "-c", "user.name=hub", "-c", "user.email=hub@t"]
        known = subprocess.run(["git", "--git-dir", str(self.bare), "rev-parse", "--verify", "-q", branch],
                               capture_output=True).returncode == 0
        subprocess.run(git + ["clone", "-q"] + (["-b", branch] if known else []) + [str(self.bare), str(work)], check=True)
        team = json.loads((work / "team.json").read_text())
        edit(team)
        (work / "team.json").write_text(json.dumps(team, indent=2) + "\n")
        subprocess.run(git + ["-C", str(work), "commit", "-q", "-am", message], check=True)
        subprocess.run(git + ["-C", str(work), "push", "-q", "origin", "HEAD:" + branch], check=True)

    def test_an_existing_machine_gets_one_inactive_agent_with_no_credential_access(self):
        ob, fake, out = self.existing()
        self.assertEqual(ob.run(), 0)
        self.assertEqual(self.statuses(out), {sid: "done" for sid, _ in onboard.EXISTING_STEPS})
        commit = subprocess.run(["git", "--git-dir", str(self.bare), "rev-parse", "main"],
                                capture_output=True, text=True, check=True).stdout.strip()
        result = self.lines(out)[-1]
        self.assertEqual((result["type"], result["status"]), ("result", "ok"))
        self.assertEqual(result["machine"], {"name": "vps", "host": "100.111.0.20", "port": 22, "login": "root",
                                             "worker_user": "fleet"})
        self.assertEqual(result["agent"], {"name": "seo", "machine": "vps", "runtime": "codex", "checkout": "~/fleet-seo",
                                           "service": "fleet-seo.service", "registration_commit": commit,
                                           "active": False, "vault": "none"})
        team = self.team()
        self.assertEqual(team["agents"]["seo"], {"start": TEAM["agents"]["vps"]["start"], "role": "worker",
                                                 "machine": "vps", "runtime": "codex", "can": ["shell", "web"],
                                                 "active": False, "vault": "none"})
        self.assertNotIn("seo", team["addresses"])
        self.assertEqual(team["agents"]["vps"], TEAM["agents"]["vps"])           # the agent already there is unchanged
        # The key stays on the machine: only its SHA-256 went to the owner key route, once, and no output repeats it.
        self.assertEqual([(agent, body["sha256"]) for agent, body, _ in fake.key_posts], [("seo", KEY_SHA)])
        self.assertNotIn(KEY_SECRET, out.getvalue())
        self.assertNotIn(KEY_SECRET, (Path(os.environ["FLEET_HOME"]) / "onboarding" / "seo.json").read_text())
        # Everything ran as the worker user; nothing but the new checkout and its service changed on the machine.
        scripts = "\n".join(fake.scripts)
        self.assertTrue(all(s.startswith("if command -v runuser") and "runuser -u fleet" in s for s in fake.scripts))
        for other in ("useradd", "apt-get", "ufw", "tailscale up", "--device-auth", "authorized_keys", "fleet-vps",
                      "worker_install.py --agent", "loginctl"):
            self.assertNotIn(other, scripts)
        self.assertIn("trust_codex_checkout", scripts)                         # a Codex checkout is trusted first
        self.assertIn("python3 fleet.py service seo", scripts)
        self.assertIn("systemctl --user enable --now fleet-seo.service", scripts)
        self.assertEqual(fake.server.applies, ["checkout", "service"])

    def test_a_stopped_run_resumes_with_its_own_checkout_and_without_a_ready_machine(self):
        fake = FakeSystem(Server(), "203.0.113.10", self.bare)
        fake.server.key_fails = True
        ob, fake, out = self.existing(fake=fake)
        self.assertEqual(ob.run(), 1)
        result = self.lines(out)[-1]
        self.assertEqual((result["status"], self.statuses(out)["agent_key"]), ("failed", "failed"))
        self.assertEqual(result["agent"]["registration_commit"], None)
        self.assertNotIn(KEY_SECRET, out.getvalue())                           # a failed key command is not repeated
        # The app quit; --resume continues the saved run. The checkout is the one that this run made.
        fake.server.key_fails, fake.server.trust = False, "kept"
        ob, fake, out = self.existing(fake=fake)
        self.assertEqual(ob.run(), 2)
        self.assertEqual(self.statuses(out)["checkout"], "skipped")
        result = self.lines(out)[-1]
        self.assertEqual(result["status"], "needs_owner")
        self.assertIn("does not trust it", result["summary"])
        self.assertEqual((fake.server.unit, fake.server.running), ("none", False))   # no service was written
        # Registered and half installed, the agent makes its own machine not ready; a resume continues all the same.
        fake.server.trust, fake.ready, fake.missing = "present", False, ["helper_offline:seo"]
        ob, fake, out = self.existing(fake=fake)
        self.assertEqual(ob.run(), 0)
        statuses = self.statuses(out)
        self.assertEqual((statuses["preflight"], statuses["checkout"], statuses["register"], statuses["worker_install"]),
                         ("skipped", "skipped", "skipped", "done"))
        self.assertEqual(fake.server.applies.count("checkout"), 1)
        self.assertEqual(len(fake.key_posts), 1)                               # the same key was not sent again

    def test_a_folder_that_the_run_did_not_make_stops_it(self):
        fake = FakeSystem(Server(), "203.0.113.10", self.bare)
        fake.server.foreign_checkout = True
        ob, fake, out = self.existing(fake=fake)
        self.assertEqual(ob.run(), 1)
        self.assertIn("did not make", self.lines(out)[-1]["summary"])
        self.assertEqual((fake.key_posts, fake.server.applies), ([], []))

    def test_the_runtime_sign_in_is_read_and_unknown_is_not_absent(self):
        for installed, signed, code, words in ((False, "yes", 1, "not installed"), (True, "no", 2, "not signed in")):
            with self.subTest(signed=signed):
                fake = FakeSystem(Server(), "203.0.113.10", self.bare)
                fake.server.rt_installed, fake.server.rt_signed = installed, signed
                ob, fake, out = self.existing(fake=fake, name="seo-" + signed)
                self.assertEqual(ob.run(), code)
                self.assertIn(words, self.lines(out)[-1]["summary"])
                self.assertEqual((fake.server.applies, fake.key_posts), ([], []))  # it stopped before any change
        fake = FakeSystem(Server(), "203.0.113.10", self.bare)
        fake.server.rt_signed = "unknown"
        ob, fake, out = self.existing(fake=fake)
        self.assertEqual(ob.run(), 0)
        detail = next(e["detail"] for e in self.lines(out) if e.get("id") == "runtime_check" and e["status"] == "done")
        self.assertIn("sign-in status is unknown", detail)
        self.assertIn("before activation", detail)
        self.assertNotIn("--device-auth", "\n".join(fake.scripts))              # no sign-in was started

    def test_a_machine_that_is_not_ready_a_used_name_or_an_older_hub_changes_nothing(self):
        for name, change, words in (("seo", lambda f: setattr(f, "ready", False) or setattr(f, "missing", ["legacy_windows:vps"]),
                                     "legacy_windows:vps"),
                                    ("vps", lambda f: None, "already has an agent or machine named vps"),
                                    ("ads", lambda f: setattr(f, "features", ["machines"]), "agent_auth")):
            with self.subTest(name=name):
                fake = FakeSystem(Server(), "203.0.113.10", self.bare)
                fake.features = fake.features + ["agent_auth"]
                change(fake)
                out = io.StringIO()
                ch = Channel(out=out, inp=None, run_id="r3")
                ch.inp = AutoAnswer(out, fake)
                state = {"mode": "existing_machine", "machine": "vps", "name": name, "runtime": "codex"}
                ob = Onboarding(ch, fake, self.tmp / ("%s.json" % name), state, {"mode": "agent"}, "http://hub.test:8765",
                                str(self.bare))
                self.assertEqual(ob.run(), 1)
                self.assertIn(words, self.lines(out)[-1]["summary"])
                self.assertEqual((fake.calls, fake.key_posts, fake.reloads), ([], [], []))

    def test_a_service_of_another_checkout_stays_as_it_is_running_or_not(self):
        for name, unit, loaded, running in (("seo", "other", "other", True), ("ads", "other", "none", False),
                                            ("dev", "none", "other", True)):
            with self.subTest(name=name):
                fake = FakeSystem(Server(), "203.0.113.10", self.bare)
                fake.server.unit, fake.server.loaded, fake.server.running = unit, loaded, running
                ob, fake, out = self.existing(fake=fake, name=name)
                self.assertEqual(ob.run(), 1)
                self.assertEqual(self.statuses(out)["worker_install"], "failed")
                self.assertIn("belongs to another checkout or agent", self.lines(out)[-1]["summary"])
                self.assertEqual((fake.server.unit, fake.server.loaded, fake.server.running), (unit, loaded, running))
                self.assertNotIn("fleet.py service", "\n".join(fake.scripts))

    def test_a_running_service_of_this_checkout_is_kept_on_resume(self):
        fake = FakeSystem(Server(), "203.0.113.10", self.bare)
        ob, fake, out = self.existing(fake=fake)
        self.assertEqual(ob.run(), 0)
        ob, fake, out = self.existing(fake=fake)
        self.assertEqual(ob.run(), 0)
        self.assertEqual(self.statuses(out)["worker_install"], "skipped")
        self.assertEqual(fake.server.applies.count("service"), 1)

    def test_a_mac_uses_its_launch_agent_as_its_own_worker_user(self):
        fake = FakeSystem(Server(), "203.0.113.10", self.bare)
        fake.server.system = "Darwin"
        ob, fake, out = self.existing(fake=fake, user="dana", worker_user="dana")
        self.assertEqual(ob.run(), 0)
        result = self.lines(out)[-1]
        self.assertEqual(result["machine"]["login"], "dana")
        self.assertEqual(result["agent"]["service"], "com.agentfleet.seo")
        scripts = "\n".join(fake.scripts)
        self.assertTrue(all(s.startswith("bash -lc ") for s in fake.scripts))   # no root and no other user
        self.assertIn('launchctl bootstrap "gui/$(id -u)"', scripts)
        self.assertNotIn("systemctl", scripts)

    def test_a_claude_agent_gets_no_codex_trust_and_its_own_sign_in_check(self):
        ob, fake, out = self.existing(runtime="claude")
        ob.state.update({"host": "100.111.0.20", "port": 22, "login": "root", "worker_user": "fleet"})
        ob.s_runtime_check()
        self.assertIn("claude auth status --json", fake.scripts[-1])
        self.assertNotIn("codex", fake.scripts[-1])
        ob.x_worker_install()
        self.assertNotIn("trust_codex_checkout", "\n".join(fake.scripts))

    def test_the_checkout_stands_on_the_configuration_ref_when_the_origin_has_one(self):
        """The hub's repository keeps its code branch at an old release, whose fleet.py could not make the service
        ("Linux services require hub, git or a configured agent name"). An origin from before the split keeps its one
        branch. The clone runs for real, in a folder that stands for the worker's home."""
        home = self.tmp / "machine"
        home.mkdir()

        def worker(cmd, timeout=300):
            r = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, env=dict(os.environ, HOME=str(home)))
            return r.returncode, r.stdout, r.stderr
        for name, branch in (("seo", "main"), ("ads", "config")):
            with self.subTest(branch=branch):
                if branch == "config":
                    self.hub_commit(lambda team: team["agents"]["vps"].update(title="Researcher"), branch="config")
                ob, fake, out = self.existing(name=name)
                ob.state["worker_user"], ob.worker = "fleet", worker
                self.assertEqual(ob.s_checkout()[0], "done")
                git = lambda *args: subprocess.run(["git", "-C", str(home / ("fleet-" + name)), *args],
                                                   capture_output=True, text=True, check=True).stdout.strip()
                tip = subprocess.run(["git", "--git-dir", str(self.bare), "rev-parse", branch], capture_output=True,
                                     text=True, check=True).stdout.strip()
                self.assertEqual((git("symbolic-ref", "--short", "HEAD"), git("rev-parse", "HEAD")), (branch, tip))
                self.assertEqual((home / ("fleet-%s/.git/fleet-onboarding" % name)).read_text().strip(),
                                 ob.state["checkout_token"])

    def test_a_new_checkout_starts_at_the_machines_own_checked_revision(self):
        """DevOps plan 0.2: the hub's repository can hold a commit that no release brought. A new agent's checkout
        starts at the revision of the machine's own checkout ~/fleet-pilot, which moved only under lifecycle.may_take,
        and never at the hub's newer commit. The clone runs for real, in a folder that stands for the worker's home."""
        home = self.tmp / "machine"
        home.mkdir()

        def worker(cmd, timeout=300):
            r = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, env=dict(os.environ, HOME=str(home)))
            return r.returncode, r.stdout, r.stderr
        self.hub_commit(lambda team: team["agents"]["vps"].update(title="Researcher"), branch="config")
        subprocess.run(["git", "clone", "-q", "-b", "config", str(self.bare), str(home / "fleet-pilot")], check=True,
                       capture_output=True)
        checked = subprocess.run(["git", "-C", str(home / "fleet-pilot"), "rev-parse", "HEAD"], capture_output=True,
                                 text=True, check=True).stdout.strip()
        self.hub_commit(lambda team: team["agents"]["vps"].update(title="Not released"), branch="config")
        ob, fake, out = self.existing(name="ads")
        ob.state["worker_user"], ob.worker = "fleet", worker
        self.assertEqual(ob.s_checkout()[0], "done")
        git = lambda *args: subprocess.run(["git", "-C", str(home / "fleet-ads"), *args], capture_output=True,
                                           text=True, check=True).stdout.strip()
        self.assertEqual((git("symbolic-ref", "--short", "HEAD"), git("rev-parse", "HEAD")), ("config", checked))
        self.assertEqual((home / "fleet-ads/.git/fleet-onboarding").read_text().strip(), ob.state["checkout_token"])

    def test_a_mac_that_reads_signed_out_over_ssh_has_an_unknown_sign_in(self):
        """A Mac keeps the runtime's sign-in in the login keychain, which no SSH session can read, so a signed-in Mac
        reads "not signed in" there. The agent's setup check, made in the login session, confirms it before
        activation. Elsewhere "not signed in" still stops the run."""
        fake = FakeSystem(Server(), "203.0.113.10", self.bare)
        fake.server.system, fake.server.rt_signed = "Darwin", "no"
        ob, fake, out = self.existing(fake=fake, runtime="claude", user="dana", worker_user="dana")
        ob.state.update({"host": "100.111.0.20", "port": 22, "login": "dana", "worker_user": "dana"})
        status, detail = ob.s_runtime_check()
        self.assertEqual(status, "done")
        self.assertIn("sign-in status is unknown", detail)
        self.assertIn("before activation", detail)
        fake.server.system = "Linux"
        with self.assertRaises(onboard.NeedsOwner):
            ob.s_runtime_check()

    def test_a_hub_commit_before_the_push_stays_and_the_change_is_made_again_on_it(self):
        """The hub commits by itself after a registration ("Fleet gave <agent> by default"). When that commit reaches
        the ref between this run's clone and its push, the push is refused. A rebase onto it conflicted, left HEAD at
        the hub's commit without the change, the next push sent nothing, and the hub reloaded a revision without the
        agent."""
        fake = FakeSystem(Server(), "203.0.113.10", self.bare)
        git, raced = fake.git, []

        def hub_first(args, cwd=None):
            if args[:1] == ["push"] and not raced:
                raced.append(True)
                self.hub_commit(lambda team: team["agents"]["vps"].update(vault="broker"),
                                message="Fleet gave vps by default: its machine's vault")
            return git(args, cwd=cwd)
        fake.git = hub_first
        ob, fake, out = self.existing(fake=fake)
        self.assertEqual(ob.run(), 0, self.lines(out)[-1])
        team = self.team()
        self.assertEqual((team["agents"]["vps"]["vault"], team["agents"]["seo"]["machine"]), ("broker", "vps"))
        log = subprocess.run(["git", "--git-dir", str(self.bare), "log", "--format=%s", "main"], capture_output=True,
                             text=True, check=True).stdout.split("\n")
        self.assertEqual(log[:2], ["Register agent seo on vps", "Fleet gave vps by default: its machine's vault"])
        self.assertEqual([body["revision"] for body, _ in fake.reloads], [ob.state["registration_commit"]])

    def test_a_resume_follows_its_machine_to_the_name_that_tailscale_gave_it(self):
        """A machine takes its name from Tailscale (release 2026.11.146), so it can be renamed under a saved run. The
        resume finds the machine by the address that the run saved, and the agent is registered under the new name."""
        fake = FakeSystem(Server(), "203.0.113.10", self.bare)
        fake.server.key_fails = True
        ob, fake, out = self.existing(fake=fake)
        self.assertEqual(ob.run(), 1)                               # it stopped before its registration

        def rename(team):
            team["addresses"]["worker-1"] = team["addresses"].pop("vps")
            team["agents"]["vps"]["machine"] = "worker-1"
        rename(fake.team)
        self.hub_commit(rename, message="vps is worker-1 in Tailscale")
        fake.server.key_fails = False
        ob, fake, out = self.existing(fake=fake)                    # --resume continues the saved run
        self.assertEqual(ob.run(), 0, self.lines(out)[-1])
        result = self.lines(out)[-1]
        self.assertEqual((result["machine"]["name"], result["agent"]["machine"]), ("worker-1", "worker-1"))
        self.assertEqual(self.team()["agents"]["seo"]["machine"], "worker-1")
        self.assertEqual(self.statuses(out)["checkout"], "skipped")             # the same checkout on the same machine

    def test_a_password_is_asked_once_for_the_whole_run(self):
        fake = FakeSystem(Server(), "203.0.113.10", self.bare, password="pw-123")
        ob, fake, out = self.existing(fake=fake, auth="password", secrets="pw-123\n")
        self.assertEqual(ob.run(), 0)
        self.assertEqual(sum(1 for e in self.lines(out) if e.get("kind") == "secret"), 1)
        self.assertEqual(set(fake.askpass_reads), {"pw-123"})
        self.assertNotIn("pw-123", out.getvalue())

    def test_command_line_for_an_existing_machine(self):
        base = ["run", "--json", "--existing-machine", "vps", "--name", "seo", "--auth", "agent",
                "--hub", "http://h", "--repo", "git://h/r"]
        for extra, words in ((["--runtime", "codex", "--host", "h"], "--host"), (["--runtime", "codex", "--port", "22"], "--port"),
                             (["--runtime", "codex", "--login", "root"], "--login"),
                             (["--runtime", "codex", "--tailscale", "login_url"], "--tailscale"),
                             (["--runtime", "codex", "--config", "c.json"], "--config"),
                             (["--runtime", "codex", "--resume", "seo"], "--resume NAME alone"), ([], "--runtime")):
            with self.subTest(extra=extra):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    self.assertEqual(onboard.main(base + extra), 1)
                self.assertIn(words, json.loads(buf.getvalue())["summary"])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(onboard.main(["run", "--json", "--existing-machine", "bad name", "--name", "seo", "--runtime",
                                           "codex", "--auth", "agent", "--hub", "http://h", "--repo", "git://h/r"]), 1)
        self.assertIn("name that the hub uses", json.loads(buf.getvalue())["summary"])
        # The saved state of a new run, without starting it: an existing machine has no host of its own, and a
        # fresh server keeps port 22 and the Tailscale sign-in link as its defaults.
        saved = []
        with patch.object(onboard.Onboarding, "run", lambda ob: saved.append((ob.state, ob.auth)) or 0):
            self.assertEqual(onboard.main(base + ["--runtime", "claude"]), 0)
            self.assertEqual(onboard.main(["run", "--json", "--name", "vps3", "--host", "203.0.113.11", "--login", "root",
                                           "--runtime", "codex", "--auth", "agent", "--hub", "http://h", "--repo", "git://h/r"]), 0)
        (mine, _), (fresh, auth) = saved
        self.assertEqual({k: mine[k] for k in ("mode", "machine", "name", "runtime")},
                         {"mode": "existing_machine", "machine": "vps", "name": "seo", "runtime": "claude"})
        self.assertNotIn("host", mine)
        self.assertEqual((fresh["port"], auth["tailscale"], "mode" in fresh), (22, "login_url", False))


class PrepareRuntime(Base):
    """Prepare the other runtime of an existing agent (executor 1.3.0): only on a machine that this Mac set up, with that
    setup's managed key and pinned host keys; a command that the service PATH finds stays; a sign-in only when a fresh
    check says not signed in; no registration, switch, session, chat or service change."""
    ADDRESS = "100.111.0.50"

    def setUp(self):
        super().setUp()
        home = Path(os.environ["FLEET_HOME"])
        (home / "ssh").mkdir(parents=True)
        self.key = home / "ssh" / "worker4_admin"
        self.key.write_text("PRIVATE KEY\n")
        self.setup = home / "onboarding" / "worker4.json"           # this Mac's own Add server run of worker4
        self.setup.parent.mkdir(parents=True)
        self.setup.write_text(json.dumps({
            "name": "worker4", "host": "203.0.113.10", "port": 22, "login": "root", "runtime": "codex",
            "tailscale_ip": self.ADDRESS, "managed_key": str(self.key), "registration_commit": "c0ffee",
            "host_keys": [{"type": "ssh-ed25519", "blob": blob(7), "sha256": onboard.fingerprint(blob(7))}],
            "finished": 900.0, "steps": {}}))
        self.before = self.setup.read_bytes()
        self.saved = home / "onboarding" / "prepare" / "worker4-claude.json"

    def fake(self):
        fake = FakeSystem(Server(), "203.0.113.10", self.bare)
        fake.features = fake.features + ["agent_auth", "runtime_switch"]
        fake.team["agents"]["worker4"] = {"role": "worker", "machine": "worker4", "runtime": "codex",
                                          "can": ["shell", "web"], "start": "codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}"}
        fake.team["addresses"]["worker4"] = self.ADDRESS
        fake.server.managed_ok, fake.server.ts_ip = True, self.ADDRESS
        return fake

    def main(self, fake, *extra, agent="worker4", runtime="claude", machine="worker4", generation="g1"):
        """The exact command of the app (2a29369), through main, with this fake as the system."""
        buf = io.StringIO()
        self.answers = AutoAnswer(buf, fake)
        argv = ["run", "--json", "--auth", "agent", "--hub", "http://hub.test:8765", "--repo", "git://hub.test/fleet-pilot.git",
                "--prepare-runtime", agent, "--runtime", runtime, "--generation", generation, "--machine", machine] + list(extra)
        with patch("onboard.System", return_value=fake), patch("sys.stdin", self.answers), contextlib.redirect_stdout(buf):
            code = onboard.main(argv)
        return code, [json.loads(line) for line in buf.getvalue().splitlines()]

    @staticmethod
    def steps(events):
        return {e["id"]: e["status"] for e in events if e["type"] == "step" and e["status"] != "running"}

    def test_an_absent_runtime_gets_the_pinned_version_and_a_sign_in_and_nothing_else_changes(self):
        fake = self.fake()
        fake.server.claude_signs_in = True
        code, events = self.main(fake)
        self.assertEqual(code, 0)
        self.assertEqual(self.steps(events), {"preflight": "done", "host_key": "skipped", "managed_key": "done",
                                              "worker_check": "done", "runtime": "done", "runtime_login": "done",
                                              "verify": "done"})
        result = events[-1]
        self.assertEqual((result["type"], result["status"]), ("result", "ok"))
        self.assertNotIn("machine", result)                     # never "Server connected" or "Agent added"
        self.assertNotIn("agent", result)
        self.assertEqual(result["prepared"], {"agent": "worker4", "machine": "worker4", "runtime": "claude",
                                              "generation": "g1", "current_runtime": "codex",
                                              "executable": "/home/fleet/.local/bin/claude",
                                              "version": "2.1.287 (Claude Code)", "source": "installed", "signed_in": True})
        self.assertIn("worker4 still runs Codex", result["summary"])
        [install] = [x for x in fake.scripts if "install.sh" in x]
        self.assertTrue(install.startswith("runuser -u fleet"))
        self.assertIn("claude.ai/install.sh | bash -s 2.1.287", install)
        [prompt] = self.answers.terminals          # Claude opens in the agent's checkout, with the command that it uses
        config = Path(os.environ["FLEET_HOME"]) / "ssh" / "config"
        self.assertEqual(prompt["command"], shlex.join(["ssh", "-F", str(config), "-t", self.ADDRESS, onboard.as_worker(
            "cd /home/fleet/fleet-pilot && exec /home/fleet/.local/bin/claude")]))
        self.assertEqual(config.read_text().count("Host %s" % self.ADDRESS), 1)
        # Only worker4's managed key, at its private address; no hub change, clone, service, session, chat or account file.
        self.assertEqual({c[1:] for c in fake.calls}, {(self.ADDRESS, "managed", str(self.key))})
        # Its own installation follows the stable channel from then on, with a floor at the installed version.
        self.assertEqual((fake.reloads, fake.key_posts, fake.server.applies), ([], [], ["runtime", "channel"]))
        self.assertEqual(fake.server.claude_settings, ("stable", "2.1.287"))
        channel = [i for i, x in enumerate(fake.scripts) if "fleet-claude-channel=1" in x]
        self.assertGreater(channel[0], fake.scripts.index(install))
        self.assertTrue(fake.scripts[channel[0]].startswith("runuser -u fleet"))
        self.assertIn("/home/fleet/.local/bin/claude", fake.scripts[channel[0]])
        self.assertIn("stable channel, not below 2.1.287", next(e["detail"] for e in events
                                                                if e.get("id") == "runtime" and e["status"] == "done"))
        scripts = "\n".join(x for x in fake.scripts if "fleet-claude-channel=1" not in x)
        for other in ("git ", "python3", "worker_install", "enable", "restart", "stop", "tmux", "kill", "logout",
                      "auth.json", ".credentials", "--device-auth", "chat-session", "settings.json"):
            self.assertNotIn(other, scripts)
        self.assertEqual(self.setup.read_bytes(), self.before)             # the machine's setup is only read
        self.assertEqual(self.saved.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.saved.parent.stat().st_mode & 0o777, 0o700)

    def test_a_command_that_the_service_path_finds_stays_in_any_version_and_signs_in(self):
        for version in ("2.1.296 (Claude Code)", "2.1.100 (Claude Code)"):        # newer and older than the pin
            with self.subTest(version=version):
                fake = self.fake()
                fake.server.paths["claude"], fake.server.versions["claude"] = "/usr/local/bin/claude", version
                fake.server.claude_signs_in = True
                code, events = self.main(fake)
                self.assertEqual(code, 0)
                self.assertEqual(self.steps(events)["runtime"], "skipped")
                self.assertFalse(any("install.sh" in x for x in fake.scripts))        # no second copy, no downgrade
                self.assertFalse(any("fleet-claude-channel" in x for x in fake.scripts))   # its update settings stay
                self.assertIsNone(fake.server.claude_settings)
                prepared = events[-1]["prepared"]
                self.assertEqual((prepared["executable"], prepared["version"], prepared["source"]),
                                 ("/usr/local/bin/claude", version, "existing"))
                self.assertTrue(self.answers.terminals[0]["command"].endswith(shlex.quote(onboard.as_worker(
                    "cd /home/fleet/fleet-pilot && exec /usr/local/bin/claude"))))
        # Codex for a Claude agent that shares the machine: its own checkout, and the device sign-in with that command.
        fake = self.fake()
        fake.team["agents"]["seo"] = {"role": "worker", "machine": "worker4", "runtime": "claude",
                                      "can": ["shell", "web"], "vault": "none"}
        fake.server.paths, fake.server.unit_dir = {"codex": "/usr/local/bin/codex"}, "/home/fleet/fleet-seo"
        code, events = self.main(fake, agent="seo", runtime="codex")
        self.assertEqual(code, 0)
        self.assertIn("nohup /usr/local/bin/codex login --device-auth", next(x for x in fake.scripts if "--device-auth >" in x))
        self.assertEqual([(u["purpose"], u["code"]) for u in self.answers.urls], [("codex_login", "WXYZ-12345")])
        self.assertTrue(fake.server.login_cleaned)
        self.assertEqual((events[-1]["prepared"]["current_runtime"], events[-1]["prepared"]["source"]), ("claude", "existing"))

    def test_no_sign_in_when_signed_in_and_an_unreadable_status_is_a_failure(self):
        fake = self.fake()
        fake.server.paths["claude"], fake.server.versions["claude"] = "/home/fleet/.local/bin/claude", "2.1.287 (Claude Code)"
        fake.server.claude_auth = "yes"
        code, events = self.main(fake)
        self.assertEqual((code, self.steps(events)["runtime"], self.steps(events)["runtime_login"]), (0, "skipped", "skipped"))
        self.assertEqual((self.answers.terminals, fake.server.applies), ([], []))
        fake.server.claude_auth = "fail"
        code, events = self.main(fake)
        self.assertEqual((code, self.steps(events)["runtime_login"]), (1, "failed"))
        self.assertIn("status check failed", events[-1]["summary"])
        self.assertEqual(self.answers.terminals, [])                # no sign-in for a status that cannot be read

    def test_a_machine_that_this_mac_did_not_set_up_stops_before_any_connection(self):
        fake = self.fake()
        code, events = self.main(fake, agent="vps", machine="vps")
        self.assertEqual((code, events[-1]["status"]), (2, "needs_owner"))
        self.assertIn("This Mac did not set up vps", events[-1]["summary"])
        self.assertEqual(events[-1]["prepared"]["executable"], None)
        self.assertEqual(fake.calls, [])

    def test_a_changed_hub_or_placement_changes_nothing(self):
        cases = (({}, dict(generation="g0"), "generation is now g1"),
                 ({}, dict(machine="vps"), "worker4 is on worker4, not on vps"),
                 ({}, dict(runtime="codex"), "cannot switch to Codex (it runs Codex)"),
                 ({}, dict(agent="manager", machine="hub", runtime="codex"), "manager_not_supported"),
                 ({"features": ["machines", "agent_auth"]}, {}, "'runtime_switch' is not in ui_features"),
                 ({"address": "100.111.0.59"}, {}, "at 100.111.0.50, but the hub has it at 100.111.0.59"),
                 ({"worker_user": "ubuntu"}, {}, "worker user ubuntu"))
        for change, args, words in cases:
            with self.subTest(words=words):
                fake = self.fake()
                if "features" in change:
                    fake.features = change["features"]
                if "address" in change:
                    fake.team["addresses"]["worker4"] = change["address"]
                if "worker_user" in change:
                    fake.access["worker_user"] = change["worker_user"]
                code, events = self.main(fake, **args)
                self.assertEqual((code, self.steps(events)), (1, {"preflight": "failed"}))
                self.assertIn(words, events[-1]["summary"])
                self.assertEqual(fake.calls, [])
        fake = self.fake()
        fake.server.unit_dir = "/home/fleet/fleet-other"              # the agent's service runs from another folder
        code, events = self.main(fake)
        self.assertEqual((code, self.steps(events)["worker_check"]), (1, "failed"))
        self.assertIn("does not run from its Fleet checkout /home/fleet/fleet-pilot", events[-1]["summary"])
        self.assertFalse(any("install.sh" in x or "fleet-prepare=1" in x for x in fake.scripts))

    def test_the_same_command_continues_its_own_saved_preparation_only_with_the_same_hub_and_placement(self):
        fake = self.fake()                          # the owner does not finish the Claude sign-in within 15 minutes
        code, events = self.main(fake)
        self.assertEqual((code, self.steps(events)["runtime_login"]), (1, "failed"))
        self.assertIn("within 15 minutes", events[-1]["summary"])
        self.assertEqual(events[-1]["prepared"]["signed_in"], False)
        fake.server.claude_auth = "yes"             # signed in later: the same command continues
        code, events = self.main(fake)
        self.assertEqual(code, 0)
        self.assertEqual((self.steps(events)["runtime"], self.steps(events)["runtime_login"]), ("skipped", "skipped"))
        self.assertEqual((events[-1]["prepared"]["source"], fake.server.applies), ("installed", ["runtime", "channel"]))
        self.assertIn("stable channel, not below 2.1.287", next(e["detail"] for e in events
                                                                if e.get("id") == "runtime" and e["status"] == "skipped"))
        self.assertEqual(self.answers.terminals, [])
        # An unfinished preparation continues only with the same generation, hub and machine setup.
        fake = self.fake()
        self.saved.unlink()
        self.assertEqual(self.main(fake)[0], 1)
        calls = len(fake.calls)
        code, events = self.main(fake, generation="g2")
        self.assertEqual((code, events[-1]["prepared"]), (1, None))
        self.assertIn("started with another generation", events[-1]["summary"])
        self.assertIn(str(self.saved), events[-1]["summary"])
        setup = json.loads(self.before)
        setup["registration_commit"] = "d00d"                     # worker4 was set up again since then
        self.setup.write_text(json.dumps(setup))
        code, events = self.main(fake)
        self.assertEqual((code, self.steps(events)), (1, {"preflight": "failed"}))
        self.assertIn("changed since this preparation started", events[-1]["summary"])
        self.assertEqual(len(fake.calls), calls)                  # neither run connected to the machine

    def test_command_line_for_a_preparation(self):
        base = ["run", "--json", "--auth", "agent", "--hub", "http://h", "--repo", "git://h/r", "--prepare-runtime",
                "worker4", "--runtime", "claude", "--generation", "g1", "--machine", "worker4"]
        refused = [(["--resume", "worker4"], "--resume"), (["--existing-machine", "vps"], "--existing-machine"),
                   (["--name", "x1"], "--name"), (["--host", "h"], "--host"), (["--port", "22"], "--port"),
                   (["--login", "root"], "--login"), (["--identity-file", "/k"], "--identity-file"),
                   (["--runtime-version", "2.1.287"], "--runtime-version"), (["--tailscale", "auth_key"], "--tailscale"),
                   (["--tailscale-tag", "tag:a"], "--tailscale-tag"), (["--config", "c.json"], "--config")]
        cases = [(base + extra, words) for extra, words in refused] + [
            ([x if x != "agent" else "password" for x in base], "--auth password"),
            (base[:10] + base[12:], "needs --runtime"), (base[:12] + ["--generation", "g 1"] + base[14:], "--generation"),
            (base[:14], "--machine"),
            (["run", "--json", "--name", "vps2", "--host", "h", "--login", "root", "--runtime", "codex", "--auth", "agent",
              "--hub", "http://h", "--repo", "git://h/r", "--generation", "g1"], "only with --prepare-runtime")]
        for argv, words in cases:
            with self.subTest(words=words):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    self.assertEqual(onboard.main(argv), 1)
                result = json.loads(buf.getvalue())
                self.assertIn(words, result["summary"])
                self.assertEqual("prepared" in result, "--prepare-runtime" in argv)
        saved = []
        with patch.object(onboard.Onboarding, "run", lambda ob: saved.append((ob.state, ob.state_path)) or 0):
            self.assertEqual(onboard.main(base), 0)
        [(state, path)] = saved
        self.assertEqual({k: state[k] for k in ("mode", "name", "machine", "runtime", "generation", "hub")},
                         {"mode": "prepare_runtime", "name": "worker4", "machine": "worker4", "runtime": "claude",
                          "generation": "g1", "hub": "http://h"})
        self.assertEqual(path, self.saved)
        self.assertEqual(self.setup.read_bytes(), self.before)

    def test_the_probe_finds_what_the_service_path_finds_and_gives_derived_lines_only(self):
        home, elsewhere = self.tmp / "worker", self.tmp / "elsewhere"
        (home / ".local" / "bin").mkdir(parents=True)
        elsewhere.mkdir()

        def tool(path, status):
            path.write_text('#!/bin/sh\ncase "$1" in --version) echo "9.9.9 (Tool)";; *) printf "%%s\\n" %s;; esac\n'
                            % shlex.quote(status))
            path.chmod(0o755)

        def probe(rt):
            script = onboard.runtime_probe(rt).replace("type -P %s" % rt, "type -P fleetprobe")
            r = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                               env={"HOME": str(home), "PATH": "%s:/usr/bin:/bin" % elsewhere})
            return r.stdout

        account = '{"loggedIn": true, "email": "owner@example.com"}'
        tool(elsewhere / "fleetprobe", account)                 # on the caller's PATH only, not the service's
        self.assertEqual(onboard.kv(probe("claude"))["exe"], "")
        local = home / ".local" / "bin" / "fleetprobe"
        tool(local, account)
        out = probe("claude")
        self.assertEqual({k: onboard.kv(out)[k] for k in ("exe", "version", "rc", "logged_in")},
                         {"exe": str(local), "version": "9.9.9 (Tool)", "rc": "0", "logged_in": "yes"})
        self.assertNotIn("example.com", out)
        for status, signed in (("Logged in using ChatGPT (owner@example.com)", "yes"), ("Not logged in", "no")):
            tool(local, status)
            out = probe("codex")
            self.assertEqual(onboard.kv(out)["signed_in"], signed)
            self.assertNotIn("example.com", out)


if __name__ == "__main__":
    unittest.main()
