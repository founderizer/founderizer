"""Onboarding executor checks: the runtime change of one agent (`--prepare-runtime`), the refusal of the two modes that
executor 2.0.0 removed, and the parts that the helpers and the installers take from onboard.py. A simulated machine and
hub. No network."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import onboard


def blob(seed):
    raw = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes([seed]) * 32
    return base64.b64encode(raw).decode()


class Server:
    """The agent's machine: what the worker's service PATH finds, the runtimes' sign-ins and the agent's service."""

    def __init__(self):
        self.managed_ok = True                  # the managed key of this Mac's setup reaches the machine
        self.host_key = blob(7)                 # what ssh-keyscan reads on the machine
        self.system = "Linux"
        self.codex_login = self.login_started = self.login_cleaned = False
        self.claude_auth, self.claude_signs_in = "no", False     # the worker's derived Claude status: yes, no or fail
        # What the worker's service PATH finds, and the agent service's checkout.
        self.paths = {"codex": "/home/fleet/.local/bin/codex"}
        self.versions = {"codex": "codex-cli 0.160.0"}
        self.unit_dir, self.unit_dir_ok = "/home/fleet/fleet-pilot", True
        self.claude_settings = None             # the worker user's Claude update settings, once the installer set them
        self.claude_settings_broken = False     # a settings file that is no JSON object: the installer leaves it
        self.applies = []


class FakeSystem:
    """onboard.System for a preparation: the machine over SSH with its managed key, and the hub's two reads."""

    def __init__(self, server):
        self.server = server
        self.clock = 1000.0
        self.calls, self.scripts, self.opened = [], [], set()
        self.sessions = []                      # (login, through sudo, the script as the machine runs it) of each call
        self.team = json.loads(json.dumps(TEAM))
        self.features = ["thread_events", "task_controls", "limit_holds", "liveness", "machines"]
        self.worker_user = "fleet"
        self.switch_missing = {}
        self.writes = []                        # each call to the hub that is no read: a preparation makes none

    def ssh(self, host, port, login, script, *, identity, timeout=300):
        self.calls.append((host, str(identity)))
        self.scripts.append(script)
        if not self.server.managed_ok:
            return 255, "", "Permission denied (publickey)."
        wrapper = "sudo -n bash -s <<'FLEET_ROOT'\nset -eu\n"
        sudo = script.startswith(wrapper) and script.endswith("\nFLEET_ROOT")
        if sudo:
            script = script[len(wrapper):-len("\nFLEET_ROOT")]
        self.sessions.append((login, sudo, script))
        return self.dispatch(script)

    def dispatch(self, script):
        s = self.server
        has = lambda marker: marker in script
        user = self.worker_user
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
        if has("echo fleet-proof"):
            return 0, "fleet-proof\n", ""
        if script.strip() == "id -u":
            return 0, "0\n", ""
        if has("install.sh"):
            rt = "claude" if has("claude.ai/install.sh") else "codex"
            version = re.search(r"(?:--release|bash -s) '?([0-9.]+)", script).group(1)
            s.paths[rt] = "/home/%s/.local/bin/%s" % (user, rt)
            s.versions[rt] = ("codex-cli %s" if rt == "codex" else "%s (Claude Code)") % version
            s.applies.append("runtime")
            return 0, "", ""
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
        return 0, "", ""

    def keyscan(self, host, port):
        return 0, "%s ssh-ed25519 %s\n" % (host, self.server.host_key), ""

    def http(self, method, url, body=None, headers=None):
        if method != "GET":
            self.writes.append((method, url, body))
            return 404, {"error": "unknown"}
        if url.endswith("/ui/state"):
            return 200, {"db": "g1", "ui_features": self.features}
        if "/ui/team?db=" in url:
            if not url.endswith("?db=g1"):
                return 409, {"error": "hub generation changed; refresh state"}
            other = {"codex": "claude", "claude": "codex"}
            lines = [{"agent": n, "role": a["role"],
                      "placement": {"machine": a["machine"], "runtime": a["runtime"],
                                    "address": self.team["addresses"].get(a["machine"])},
                      "runtime_switch": {"to": other.get(a["runtime"]), "ready": False,
                                         "missing": ["manager_not_supported"] if a["role"] == "manager" else
                                         self.switch_missing.get(n, ["runtime_not_installed"])}}
                     for n, a in sorted(self.team["agents"].items())]
            machines = {a["machine"]: {"address": self.team["addresses"].get(a["machine"]), "worker_user": self.worker_user}
                        for a in self.team["agents"].values()}
            return 200, {"db": "g1", "lines": lines, "machines": machines}
        return 404, {"error": "unknown"}

    def sleep(self, seconds):
        self.clock += seconds
        if self.server.login_started and "codex_login" in self.opened:
            self.server.codex_login = True
        if self.server.claude_signs_in and "claude_login" in self.opened:
            self.server.claude_auth = "yes"

    def now(self):
        return self.clock


class AutoAnswer:
    """The owner's answers as the app sends them: Sign in for the Codex link, Copy command for the Claude command."""

    def __init__(self, out, fake):
        self.out, self.fake = out, fake
        self.urls, self.terminals, self.kinds = [], [], []

    def readline(self):
        last = json.loads(self.out.getvalue().strip().splitlines()[-1])
        if last["type"] != "prompt":
            return ""
        kind, pid = last["kind"], last["id"]
        self.kinds.append(kind)
        if kind == "open_url":
            self.urls.append(last["data"])
            self.fake.opened.add(last["data"]["purpose"])
            answer = "opened"
        elif kind == "terminal":
            self.terminals.append(last["data"])
            self.fake.opened.add(last["data"]["purpose"])
            answer = "copied"
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
        self.home = patch("onboard.Path.home", return_value=self.tmp / "home")     # never the real home folder
        self.home.start()

    def tearDown(self):
        self.home.stop()
        if self.old_home is None:
            os.environ.pop("FLEET_HOME", None)
        else:
            os.environ["FLEET_HOME"] = self.old_home
        shutil.rmtree(str(self.tmp), ignore_errors=True)


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
        fake = FakeSystem(Server())
        fake.features = fake.features + ["agent_auth", "runtime_switch"]
        fake.team["agents"]["worker4"] = {"role": "worker", "machine": "worker4", "runtime": "codex",
                                          "can": ["shell", "web"], "start": "codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}"}
        fake.team["addresses"]["worker4"] = self.ADDRESS
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

    def seo(self, fake, codex):
        """Codex for a Claude agent that shares worker4: its own checkout, and the command `codex` on the service PATH."""
        fake.team["agents"]["seo"] = {"role": "worker", "machine": "worker4", "runtime": "claude",
                                      "can": ["shell", "web"], "vault": "none"}
        fake.server.paths, fake.server.unit_dir = {"codex": codex}, "/home/fleet/fleet-seo"
        return fake

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
        self.assertEqual(set(fake.calls), {(self.ADDRESS, str(self.key))})
        self.assertEqual({(login, sudo) for login, sudo, _ in fake.sessions}, {("root", False)})   # root needs no sudo
        # Its own installation follows the stable channel from then on, with a floor at the installed version.
        self.assertEqual((fake.writes, fake.server.applies), ([], ["runtime", "channel"]))
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
        self.assertFalse((self.tmp / "home").exists())                     # the owner's own SSH settings stay as they are

    def test_a_preparation_sends_its_lines_in_order_and_asks_only_for_a_sign_in(self):
        """The app takes only these two prompts (SetupEvent.accepts): the Claude command and the Codex link."""
        fake = self.fake()
        fake.server.claude_signs_in = True
        claude = self.main(fake)[1]
        codex = self.main(self.seo(self.fake(), "/usr/local/bin/codex"), agent="seo", runtime="codex")[1]
        for events in (claude, codex):
            self.assertEqual([e["seq"] for e in events], list(range(1, len(events) + 1)))
            self.assertEqual({(e["v"], e["run"]) for e in events}, {(1, events[0]["run"])})
            self.assertEqual(events[-1]["type"], "result")
        prompts = lambda events: [(e["kind"], e["data"]["purpose"]) for e in events if e["type"] == "prompt"]
        self.assertEqual(prompts(claude), [("terminal", "claude_login")])
        self.assertEqual(prompts(codex), [("open_url", "codex_login")])

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
        fake = self.seo(self.fake(), "/usr/local/bin/codex")
        code, events = self.main(fake, agent="seo", runtime="codex")
        self.assertEqual(code, 0)
        self.assertIn("nohup /usr/local/bin/codex login --device-auth", next(x for x in fake.scripts if "--device-auth >" in x))
        self.assertEqual(self.answers.urls, [{"url": "https://auth.openai.com/codex/device", "code": "WXYZ-12345",
                                              "purpose": "codex_login"}])        # the whole link, with no color code
        self.assertTrue(fake.server.login_cleaned)
        self.assertFalse(any("fleet-claude-channel" in x for x in fake.scripts))      # Codex keeps its own version
        self.assertEqual((events[-1]["prepared"]["current_runtime"], events[-1]["prepared"]["source"]), ("claude", "existing"))

    def test_a_machine_set_up_with_another_login_gets_its_root_commands_through_sudo(self):
        """The SSH login of this Mac's setup can be a user with passwordless sudo: each root command goes through
        `sudo -n`, the proof of the managed key alone runs as that user, and so does the Claude command."""
        setup = json.loads(self.before)
        setup["login"] = "ubuntu"
        self.setup.write_text(json.dumps(setup))
        fake = self.fake()
        fake.server.claude_signs_in = True
        code, events = self.main(fake)
        self.assertEqual((code, self.steps(events)["verify"]), (0, "done"))
        self.assertTrue(fake.sessions)
        for login, sudo, script in fake.sessions:
            self.assertEqual((login, sudo), ("ubuntu", script != "echo fleet-proof"), script[:60])
        [prompt] = self.answers.terminals
        self.assertTrue(prompt["command"].endswith(shlex.quote("sudo -n " + onboard.as_worker(
            "cd /home/fleet/fleet-pilot && exec /home/fleet/.local/bin/claude"))))
        self.assertIn("  User ubuntu\n", (Path(os.environ["FLEET_HOME"]) / "ssh" / "config").read_text())

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

    def test_a_claude_settings_file_that_it_cannot_merge_fails_its_own_installation_until_it_can(self):
        fake = self.fake()
        fake.server.claude_settings_broken = True                  # a file that it must not replace
        code, events = self.main(fake)
        self.assertEqual((code, self.steps(events)["runtime"]), (1, "failed"))
        self.assertRegex(events[-1]["summary"], "could not be set: .*not a JSON object; it was not changed")
        self.assertEqual(self.answers.terminals, [])
        fake.server.claude_settings_broken, fake.server.claude_signs_in = False, True
        code, events = self.main(fake)                              # the same command, once the owner fixed the file
        self.assertEqual((code, self.steps(events)["runtime"], events[-1]["prepared"]["source"]), (0, "skipped", "installed"))
        self.assertEqual((fake.server.applies, fake.server.claude_settings), (["runtime", "channel"], ("stable", "2.1.287")))

    def test_a_changed_host_key_stops_the_run_before_any_command(self):
        fake = self.fake()
        fake.server.host_key = blob(8)                              # not the key that this Mac's setup pinned
        code, events = self.main(fake)
        self.assertEqual((code, self.steps(events)), (1, {"preflight": "done", "host_key": "failed"}))
        self.assertIn("host key changed since it was confirmed", events[-1]["summary"])
        self.assertEqual((fake.calls, self.answers.kinds), ([], []))  # no command, and no question to trust another key
        self.assertFalse((Path(os.environ["FLEET_HOME"]) / "ssh" / "known_hosts").exists())

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
                    fake.worker_user = change["worker_user"]
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
        # The flags of the two removed modes are no flags of a run any more: a preparation names each one it gets.
        refused = [(["--resume", "worker4"], "--resume"), (["--existing-machine", "vps"], "--existing-machine"),
                   (["--name", "x1"], "--name"), (["--host", "h"], "--host"), (["--port", "22"], "--port"),
                   (["--login", "root"], "--login"), (["--identity-file", "/k"], "--identity-file"),
                   (["--runtime-version", "2.1.287"], "--runtime-version"), (["--tailscale", "auth_key"], "--tailscale"),
                   (["--tailscale-tag", "tag:a"], "--tailscale-tag"), (["--config", "c.json"], "--config")]
        cases = [(base + extra, words) for extra, words in refused] + [
            ([x if x != "agent" else "password" for x in base], "--auth password"),
            ([x for x in base if x != "--json"], "needs --json and --auth agent"),
            (base[:2] + base[4:], "needs --json and --auth agent"),
            (base[:10] + base[12:], "needs --runtime"), (base[:12] + ["--generation", "g 1"] + base[14:], "--generation"),
            (base[:14], "--machine")]
        for argv, words in cases:
            with self.subTest(words=words):
                buf = io.StringIO()
                with patch("onboard.System", side_effect=AssertionError("no system access")), \
                        contextlib.redirect_stdout(buf):
                    self.assertEqual(onboard.main(argv), 1)
                result = json.loads(buf.getvalue())
                self.assertIn(words, result["summary"])
                self.assertIsNone(result["prepared"])
        saved = []
        with patch.object(onboard.Onboarding, "run", lambda ob: saved.append((ob.state, ob.state_path)) or 0):
            self.assertEqual(onboard.main(base), 0)
        [(state, path)] = saved
        self.assertEqual({k: state[k] for k in ("mode", "name", "machine", "runtime", "generation", "hub")},
                         {"mode": "prepare_runtime", "name": "worker4", "machine": "worker4", "runtime": "claude",
                          "generation": "g1", "hub": "http://h"})
        self.assertEqual(path, self.saved)
        self.assertEqual(self.setup.read_bytes(), self.before)

    def test_a_removed_mode_gets_one_sentence_that_names_the_join_line_and_changes_nothing(self):
        """The new-server path and --existing-machine went with executor 2.0.0: each could only stop at its push to the
        hub's git service, which refuses every push. A run of either, in the forms that the documents gave, gets
        REMOVED and reaches no machine, no hub and no file."""
        home = Path(os.environ["FLEET_HOME"])
        before = sorted(str(p) for p in home.rglob("*"))
        runs = [["run", "--json", "--name", "vps2", "--host", "203.0.113.10", "--port", "22", "--login", "root",
                 "--runtime", "codex", "--auth", "agent", "--hub", "http://hub.test:8765", "--repo", "git://hub.test/fleet-pilot.git"],
                ["run", "--json", "--existing-machine", "worker4", "--name", "seo", "--runtime", "claude", "--auth", "agent",
                 "--hub", "http://hub.test:8765", "--repo", "git://hub.test/fleet-pilot.git"],
                ["run", "--json", "--resume", "vps2", "--auth", "password", "--identity-file", "/k"],
                ["run", "--json", "--auth", "agent", "--generation", "g1", "--machine", "worker4"],
                ["run"]]
        for argv in runs:
            with self.subTest(argv=argv):
                buf = io.StringIO()
                with patch("onboard.System", side_effect=AssertionError("no system access")), \
                        contextlib.redirect_stdout(buf):
                    self.assertEqual(onboard.main(argv), 1)
                [result] = [json.loads(line) for line in buf.getvalue().splitlines()]
                self.assertEqual((result["type"], result["status"], result["summary"], result["prepared"]),
                                 ("result", "failed", onboard.REMOVED, None))
        self.assertIn("the hub's join line", onboard.REMOVED)
        self.assertEqual(sorted(str(p) for p in home.rglob("*")), before)
        # The commands that only those modes used are gone too, and `version` takes nothing more.
        for argv in (["status", "--name", "vps2"], ["askpass"], ["ssh-include"], ["version", "--name", "x"]):
            with self.subTest(argv=argv), self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                onboard.main(argv)

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

    def test_stopping_the_codex_login_spares_the_shell_that_starts_it(self):
        """The exact start and clean-up text of a preparation's Codex sign-in, with a harmless fake login:
        <home>/.local/bin/codex is a link to bash, so its process shows "<home>/.local/bin/codex login --device-auth"
        like the real binary."""
        pattern = onboard.CODEX_LOGIN
        uid = str(os.getuid())
        if subprocess.run(["pgrep", "-u", uid, "-f", pattern], capture_output=True).returncode == 0:
            self.skipTest("a real Codex login runs as this user; this check would stop it")
        home, elsewhere = self.tmp / "whome", self.tmp / "root"
        fake = self.seo(self.fake(), str(home / ".local/bin/codex"))
        self.assertEqual(self.main(fake, agent="seo", runtime="codex")[0], 0)
        start = shlex.split(next(x for x in fake.scripts if "--device-auth >" in x))[6]
        stop = shlex.split(next(x for x in fake.scripts if "rm -f $HOME/.fleet-codex-login.log" in x))[6]
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


class Helpers(Base):
    """The parts of onboard.py that a preparation shares with the helpers and the installers."""

    def test_version_line(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(onboard.main(["version"]), 0)
        self.assertEqual(json.loads(buf.getvalue()), {"v": 1, "type": "version", "executor": "2.0.0",
                                                      "capabilities": ["prepare_runtime"]})

    def test_runtime_pins_are_exact_versions(self):
        self.assertTrue(all(re.fullmatch(r"\d+\.\d+\.\d+", v) for v in onboard.RUNTIME_PINS.values()))

    def test_an_installed_version_is_kept_when_it_is_the_pin_or_newer(self):
        self.assertTrue(onboard.not_older("codex-cli 0.162.1", "0.160.0") and onboard.not_older("2.1.287 (Claude Code)", "2.1.287"))
        self.assertFalse(onboard.not_older("2.1.99", "2.1.287") or onboard.not_older("", "2.1.287")
                         or onboard.not_older("2.1.296", "stable"))

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

    def test_the_ssh_settings_of_a_machine_stay_one_block(self):
        key = Path(os.environ["FLEET_HOME"]) / "ssh" / "vps2_admin"
        onboard.write_ssh_config("vps2", "100.99.1.2", "root", 22, key)
        onboard.write_ssh_config("vps2", "100.99.1.2", "admin", 2222, key)
        path = Path(os.environ["FLEET_HOME"]) / "ssh" / "config"
        config = path.read_text()
        self.assertEqual(config.count("Host 100.99.1.2"), 1)
        self.assertIn("  User admin\n  Port 2222", config)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)


class ClaudeSignIn(Base):
    """A machine's first Claude sign-in: one command for the owner's Terminal, then a wait on the worker's derived
    status. Fleet never runs the sign-in, never sees its code and never signs an account out."""

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
        command = onboard.claude_login_command(self.tmp / "my config", "100.99.1.2", "root", '"$HOME/fleet-pilot"',
                                               '"$HOME/.local/bin/claude"')
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
        self.assertTrue(onboard.claude_login_command("/c", "100.99.1.2", "admin", "/home/fleet/fleet-seo",
                                                     "/usr/local/bin/claude").endswith(
            shlex.quote("sudo -n " + onboard.as_worker("cd /home/fleet/fleet-seo && exec /usr/local/bin/claude"))))

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


if __name__ == "__main__":
    unittest.main()
