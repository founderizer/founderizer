"""The hub installer (hub.sh, hubsetup.py): the steps it would take, the refusals it makes, the first team.json, the
owner claim, and the rule that nothing in it touches a model provider credential.

Nothing here reaches a real machine: hub.sh runs in its check mode against a temporary folder that stands in for /,
the claim listener runs on the loopback with a free port, and the provider refusals go through the hub's own tools
with the in-process hub of test_create_login. No apt, no Tailscale, no systemd, no Chrome, no vault, no AI call.

The rule the last class measures is the condition on which this product is lawful to sell: Anthropic permits an
operator to host the unmodified Claude Code only while each end user signs in through Anthropic's own flow and the
operator never collects, stores or intermediates the credential. So the installer may not sign in for the customer,
and no Founderizer login may be a provider's own site.
"""
import contextlib
import hashlib
import http.server
import io
import itertools
import json
import os
import re
import select
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

import fleet
import hub
import hubsetup
import vault
KIT = Path(__file__).resolve().parent
SCRIPT = KIT / "hub.sh"
HUB_IP = "100.80.1.2"           # a Tailscale address that is not this machine's
LOOP = "127.0.0.1"              # a hub's address that this machine has: a hub that runs and a claim can meet on it
OLD_MAC, NEW_MAC = "100.90.3.4", "100.90.9.9"   # the owner's Mac from before, and the Mac that claims the hub now
REAL_HUB_SERVICE = getattr(hubsetup, "hub_service", None)       # SecondClaim puts a service manager of its own there
REAL_SERVICE_CALL = getattr(hubsetup, "service_call", None)     # and a command that does nothing
CODE = "ABCDEFGHJKLM"           # a claim code of hub.LINK_ALPHABET, as new_code makes one
SHOWN = "ABCD-EFGH-JKLM"        # the same code as the installer prints it
# The steps of hub.sh, in the order the installer takes them. The claim and the services come after the private
# network and the firewall, because the owner's Mac must reach the hub's port while the install still runs.
STEPS = ["this server and this copy of Founderizer", "base packages", "the user fleet", "the private network (Tailscale)",
         "the firewall", "the Founderizer repository on this hub", "the first team.json",
         "the root helpers that make an agent's OS user and update this machine's vault broker",
         "one OS user for each agent of this machine",
         "the services fleet-hub, fleet-git and fleet-channels", "each agent of this machine, under its own OS user",
         "the checks the owner can act on", "this fleet's own id", "security updates",
         "the network: a kept connection keeps its speed", "verify: is this machine of the fleet healthy?"]
PROMPT = KIT / "INSTALL-PROMPT.md"      # the text a customer pastes into the agent they already run
# The systems a VPS may run, as `ID` and `VERSION_ID` of its /etc/os-release: both installers and the setup executor
# take these, and the words after them are how each of them names the list to a server that runs another system.
SYSTEMS = {("ubuntu", "22.04"), ("ubuntu", "24.04"), ("ubuntu", "26.04"), ("debian", "12"), ("debian", "13")}
SYSTEMS_SAID = "Ubuntu 22.04, 24.04 or 26.04, or Debian 12 or 13"


def shell_function(script, name):
    """One function of a POSIX shell script, as its text. The installers run main() at the end of the file, so a
    test cannot source them; it takes the function it measures and gives it its own stubs."""
    out, taking = [], False
    for line in script.read_text().splitlines():
        if re.match(r"^%s\(\) *\{" % re.escape(name), line):
            taking = True
        if taking:
            out.append(line)
            if line == "}":
                return "\n".join(out) + "\n"
    raise AssertionError(f"{script.name} has no function {name}()")


def run_shell(body, extra=""):
    """A fragment of a shell installer with its own stubs: (exit code, output)."""
    text = ("set -eu\n"
            "say() { printf 'Founderizer: %s\\n' \"$*\"; }\n"
            "stop() { printf 'Founderizer stopped: %s\\n' \"$*\" >&2; exit 1; }\n"
            "step=0\n"
            "heading() { step=$((step + 1)); printf '\\nFounderizer step %d: %s\\n' \"$step\" \"$*\"; }\n"
            "plan() { [ \"$check\" = yes ] && printf 'Founderizer:   would %s\\n' \"$*\" || true; }\n"
            "check=no\nready=yes\nkit=/kit\nHUB_USER=fleet\nWORKER=fleet\ncaller_verifies=no\n" + extra + body)
    done = subprocess.run(["sh", "-c", text], capture_output=True, text=True, timeout=60,
                          stdin=subprocess.DEVNULL)
    return done.returncode, done.stdout + done.stderr


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (Template, Repository, Claim, SecondClaim, AgentUsers, FleetId, VerifyStep, Prompt, PromptThroughSudo,
                CheckMode, Systems, NoProviderCredential, ProviderToolsRefuse, RuntimeInstall, Firewall, Harden, HubTcp,
                NetworkStep, AptUpdate):
        suite.addTests(loader.loadTestsFromTestCase(cls))
    return suite


class RuntimeInstall(unittest.TestCase):
    """hubsetup.py runtime (T-35): the vendor installer runs again by itself when it could not reach the internet,
    three times, and the line that stops the install says what failed in plain words. The installer's own words
    stay in the install's log."""

    def install(self, answers, runtime="codex"):
        """(the Stop it raised or None, the installer's runs, the waits, what it printed)."""
        runs, waits, printed = [], [], io.StringIO()

        def run(argv, **_kw):
            if "install.sh" not in argv[-1]:
                return subprocess.CompletedProcess(argv, 0, "", "")
            code, err = answers[min(len(runs), len(answers) - 1)]
            runs.append(code)
            return subprocess.CompletedProcess(argv, code, "", err)
        with patch.object(hubsetup.subprocess, "run", run), patch.object(hubsetup.time, "sleep", waits.append), \
                patch.object(hubsetup.lifecycle, "exe", lambda *_a: "/home/fleet/.local/bin/x" if 0 in runs else None), \
                contextlib.redirect_stdout(printed):
            try:
                hubsetup.install_runtime(runtime)
                stopped = None
            except hubsetup.Stop as e:
                stopped = str(e)
        return stopped, runs, waits, printed.getvalue()

    def test_a_network_error_is_tried_again_and_then_said_in_plain_words(self):
        stopped, runs, waits, log = self.install([(1, "curl: (6) Could not resolve host: chatgpt.com")])
        self.assertEqual(stopped, "Codex did not install: this server could not reach the internet.")
        self.assertEqual((runs, waits), ([1, 1, 1, 1], [hubsetup.onboard.NETWORK_WAIT] * 3))
        self.assertEqual(log.count("Could not resolve host: chatgpt.com"), 4)      # the cause is in the log
        self.assertIn("(again: 3 of 3)", log)
        stopped, runs, waits, _log = self.install([(1, "npm ERR! code ECONNRESET"), (0, "")], runtime="claude")
        self.assertEqual((stopped, runs, len(waits)), (None, [1, 0], 1))

    def test_any_other_failure_stops_at_once(self):
        stopped, runs, waits, log = self.install([(1, "error: this system is not supported")], runtime="claude")
        self.assertEqual((stopped, runs, waits), ("Claude Code did not install.", [1], []))
        self.assertIn("error: this system is not supported", log)


class Template(unittest.TestCase):
    """The first team.json: one manager (on this machine, or with no server yet when the app gives it one), this
    machine's address, and the owner's Mac. The hub must be able to run it, and nothing in it may hold a credential."""

    def test_the_template_is_a_team_the_hub_can_run(self):
        team = hubsetup.template(HUB_IP, owner="100.90.3.4", timezone="Europe/Madrid")
        hub.validate_team(team)             # raises ValueError when the hub could not run it
        self.assertEqual(team["addresses"], {"hub": HUB_IP, "owner": "100.90.3.4"})
        self.assertEqual(team["hub"], {"machine": "hub", "port": 8765})
        self.assertEqual(list(team["agents"]), ["manager"])
        self.assertEqual(team["agents"]["manager"]["role"], "manager")
        self.assertEqual(team["agents"]["manager"]["machine"], "hub")
        self.assertEqual(team["goals"]["timezone"], "Europe/Madrid")
        self.assertEqual(team["access"]["hub"], {"ssh_user": "fleet", "ssh_port": 22})

    def test_the_manager_has_no_server_yet_so_the_hub_runs_no_agent(self):
        """No agent runs on the hub's server (the owner, 2 November 2026): the install makes the fleet, and the
        manager's own setup in the app gives it a server of its own (hub.unplaced, owner feature manager_server). Its
        machine names the hub only so that the hub finds an address for it; no installer finds it there."""
        team = hubsetup.template(HUB_IP, owner="100.90.3.4", runtime="codex", placed=False)
        self.assertIs(team["agents"]["manager"]["placed"], False)
        self.assertTrue(hub.unplaced("manager", team))
        self.assertEqual((team["agents"]["manager"]["runtime"], team["agents"]["manager"]["start"]),
                         ("codex", hubsetup.STARTS["codex"]))
        self.assertEqual(hubsetup.agents_of(team, "hub"), [])
        self.assertEqual(hub.server_agents("hub", team), [])
        said = []
        with patch.object(hubsetup, "say", said.append):
            self.assertEqual(hubsetup.agent_users(team, "hub", run=lambda _s: self.fail("it read a user")), [])
        self.assertIn("no agent yet", said[0])
        # a hub from before keeps its manager on its own machine, and the installers keep installing it there
        del team["agents"]["manager"]["placed"]
        hub.validate_team(team)
        self.assertEqual(hubsetup.agents_of(team, "hub"), ["manager"])

    def test_without_the_apps_word_the_manager_runs_on_the_hub_as_before(self):
        """A new hub clones the newest release, which reaches it before the app that the download page gives does,
        and an app from before has no page that gives the manager a server: so only --manager-later (hub.sh's
        FLEET_MANAGER_SERVER=later, which Founderizer 0.1.112 and later set) leaves the manager without one."""
        team = hubsetup.template(HUB_IP, owner="100.90.3.4")
        self.assertNotIn("placed", team["agents"]["manager"])
        self.assertFalse(hub.unplaced("manager", team))
        self.assertEqual(hubsetup.agents_of(team, "hub"), ["manager"])
        for more, placed in (([], None), (["--manager-later"], False)):
            done = subprocess.run([sys.executable, str(KIT / "hubsetup.py"), "template", "--address", HUB_IP,
                                   "--timezone", "UTC", *more], capture_output=True, text=True, timeout=120,
                                  stdin=subprocess.DEVNULL)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(json.loads(done.stdout)["agents"]["manager"].get("placed"), placed)

    def test_the_manager_holds_no_credential(self):
        """"vault": "none" is the line that says it: the manager's runtime is the owner's own subscription, signed in
        by the owner, so Founderizer gives that agent no vault access at all."""
        team = hubsetup.template(HUB_IP, owner="100.90.3.4")
        self.assertEqual(team["agents"]["manager"]["vault"], "none")
        text = json.dumps(team).lower()
        for word in ("api_key", "token", "secret", "password", "bws://", "oauth", "anthropic", "openai", "xai"):
            self.assertNotIn(word, text, f"the template mentions {word}")
        for agent in team["agents"].values():
            self.assertNotIn("secrets", agent)
            self.assertNotIn("vault_create", agent)

    def test_a_hub_without_a_proved_owner_is_no_team_the_hub_can_run(self):
        """Why the claim exists at all: the owner is an address and no token, so the hub refuses to run without one
        and the installer must prove the address before it finishes."""
        with self.assertRaises(ValueError) as refused:
            hub.validate_team(hubsetup.template(HUB_IP))
        self.assertIn("owner", str(refused.exception))

    def test_it_refuses_what_it_cannot_write(self):
        for bad in ({"hub_ip": "not-an-address"}, {"hub_ip": HUB_IP, "owner": "100.90.3"},
                    {"hub_ip": HUB_IP, "timezone": "Mars/Olympus"}, {"hub_ip": HUB_IP, "runtime": "grok"}):
            with self.assertRaises(hubsetup.Stop):
                hubsetup.template(**bad)

    def test_the_runtime_start_carries_no_key(self):
        for runtime, start in hubsetup.STARTS.items():
            self.assertNotIn("KEY", start.upper().replace("{PROMPT}", ""))
            self.assertNotIn("TOKEN", start.upper())
            self.assertNotIn("login", start)
            self.assertIn("{prompt}", start, runtime)

    def test_write_team_refuses_a_team_the_hub_could_not_run_and_leaves_the_old_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "team.json")
            good = hubsetup.template(HUB_IP, owner="100.90.3.4")
            hubsetup.write_team(path, good)
            with self.assertRaises(hubsetup.Stop):
                hubsetup.write_team(path, hubsetup.template(HUB_IP))        # no owner
            with open(path, encoding="utf-8") as f:
                self.assertEqual(json.load(f), good)


class Repository(unittest.TestCase):
    """The hub's own repository, made for real in a temporary folder: the bare repository that every machine of the
    fleet fetches from, and the hub's checkout on the configuration ref. Real git, no machine."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-hub-repo-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.tree = self.tmp / "tree"
        (self.tree / "profiles").mkdir(parents=True)
        (self.tree / "hub.py").write_text("# the hub\n")
        (self.tree / "team.json").write_text(json.dumps(hubsetup.template(HUB_IP, owner="100.90.3.4"), indent=2) + "\n")
        self.git("init", "-q", "-b", "main", str(self.tree))
        self.git("add", "-A", folder=self.tree)
        self.git("commit", "-q", "-m", "the Founderizer code", folder=self.tree)
        self.commit = self.git("rev-parse", "HEAD", folder=self.tree)
        self.bare, self.kit = str(self.tmp / "fleet-pilot.git"), str(self.tmp / "fleet-pilot")
        quiet = patch.object(hubsetup, "say", lambda *_a: None)
        quiet.start()
        self.addCleanup(quiet.stop)

    def git(self, *args, folder=None):
        return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *(["-C", str(folder)] if folder else []),
                               *args], check=True, capture_output=True, text=True).stdout.strip()

    def make(self):
        return hubsetup.repository(str(self.tree), self.bare, self.kit)

    def test_both_refs_start_at_the_code_the_installer_runs(self):
        """So the code the hub serves to every machine is the code the hub itself runs."""
        self.assertEqual(self.make(), self.commit)
        for branch in (hub.CODE_BRANCH, hub.CONFIG_BRANCH):
            self.assertEqual(self.git("rev-parse", branch, folder=self.bare), self.commit, branch)

    def test_the_hubs_checkout_stands_on_the_ref_the_hub_writes(self):
        self.make()
        self.assertEqual(self.git("symbolic-ref", "--short", "HEAD", folder=self.kit), hub.CONFIG_BRANCH)
        self.assertEqual(self.git("rev-parse", "HEAD", folder=self.kit), self.commit)
        self.assertEqual(self.git("remote", "get-url", "origin", folder=self.kit), self.bare)

    def test_a_second_run_changes_nothing(self):
        self.make()
        (Path(self.kit) / "team.json").write_text("the owner's own change\n")
        self.make()
        self.assertEqual((Path(self.kit) / "team.json").read_text(), "the owner's own change\n")
        self.assertEqual(self.git("rev-parse", "HEAD", folder=self.kit), self.commit)

    def test_a_bare_repository_that_a_failed_first_push_left_empty_is_filled_by_the_next_run(self):
        real = hubsetup.git

        def push_fails(*args, **kw):
            return (1, "", "the push stopped half way") if args[:1] == ("push",) else real(*args, **kw)
        with patch.object(hubsetup, "git", push_fails), self.assertRaisesRegex(hubsetup.Stop, "could not put"):
            self.make()
        self.assertTrue(os.path.isdir(self.bare))                   # made, and holding no branch
        self.assertEqual(self.make(), self.commit)
        for branch in (hub.CODE_BRANCH, hub.CONFIG_BRANCH):
            self.assertEqual(self.git("rev-parse", branch, folder=self.bare), self.commit, branch)
        self.assertEqual(self.git("rev-parse", "HEAD", folder=self.kit), self.commit)

    def test_a_bare_repository_that_holds_only_the_code_ref_gets_the_configuration_ref_too(self):
        """A run that stopped between the two refs of one push left the code ref alone, and the hub's checkout is a
        clone of the configuration ref: the next run fills it."""
        self.git("init", "-q", "--bare", self.bare)
        self.git("push", "-q", self.bare, f"{self.commit}:refs/heads/{hub.CODE_BRANCH}", folder=self.tree)
        self.assertEqual(self.make(), self.commit)
        self.assertEqual(self.git("rev-parse", hub.CONFIG_BRANCH, folder=self.bare), self.commit)
        self.assertEqual(self.git("rev-parse", "HEAD", folder=self.kit), self.commit)

    def test_it_refuses_a_checkout_that_is_not_on_the_configuration_ref(self):
        self.make()
        self.git("checkout", "-q", "-B", "elsewhere", folder=self.kit)
        with self.assertRaises(hubsetup.Stop) as refused:
            self.make()
        self.assertIn("config-ref.sh", str(refused.exception))

    def test_the_bare_repository_is_one_git_daemon_serves(self):
        """Every machine of a fleet clones its code over git://, and `git daemon` refuses a repository that is not
        marked as exported (fleet.py `service git` passes no --export-all). So the installer must mark it, or no
        agent, worker or joined server ever gets its checkout."""
        self.make()
        self.assertTrue(Path(self.bare, hubsetup.EXPORT_OK).exists())
        self.assertIn(b"refs/heads/" + hub.CONFIG_BRANCH.encode(), self.served())

    def test_a_bare_repository_from_before_the_marker_is_repaired_by_a_second_run(self):
        self.make()
        Path(self.bare, hubsetup.EXPORT_OK).unlink()
        self.assertIn(b"not exported", self.served())       # what every machine of such a fleet is told
        self.make()
        self.assertIn(b"refs/heads/" + hub.CONFIG_BRANCH.encode(), self.served())

    def served(self):
        """What `git daemon` answers a machine that asks for this fleet's repository. --inetd speaks the protocol on
        standard input and output, so this needs no port and leaves no process behind."""
        ask = b"git-upload-pack /%s\x00host=fleet\x00" % os.path.basename(self.bare).encode()
        done = subprocess.run(["git", "daemon", "--inetd", "--forbid-override=receive-pack",
                               "--base-path=" + os.path.dirname(self.bare), self.bare],
                              input=b"%04x" % (len(ask) + 4) + ask, capture_output=True, timeout=30)
        return (done.stdout or b"") + (done.stderr or b"")

    def test_a_second_run_reads_a_checkout_that_belongs_to_the_service_user(self):
        """From its second run on, the installer is root and the hub's repositories belong to the service user.
        git refuses such a repository as dubious ownership, and that refusal reads exactly like "there is no
        checkout here": the installer would then clone over the checkout that is there and stop at step 6. It must
        read them instead, which is what it does on the one run that made them."""
        self.make()
        other = dict(os.environ, GIT_TEST_ASSUME_DIFFERENT_OWNER="1")
        plain = subprocess.run(["git", "-C", self.kit, "rev-parse", "--git-dir"], env=other, capture_output=True)
        if plain.returncode == 0:
            self.skipTest("this git does not refuse a repository of another owner in a test")
        with patch.dict(os.environ, {"GIT_TEST_ASSUME_DIFFERENT_OWNER": "1"}):
            self.assertEqual(hubsetup.repository(str(self.tree), self.bare, self.kit), self.commit)

    def test_it_refuses_a_copy_of_fleet_without_a_commit(self):
        loose = self.tmp / "loose"
        loose.mkdir()
        with self.assertRaises(hubsetup.Stop) as refused:
            hubsetup.repository(str(loose), str(self.tmp / "b.git"), str(self.tmp / "k"))
        self.assertIn("not a git checkout", str(refused.exception))

    def test_the_first_team_json_is_committed_on_the_ref_and_pushed(self):
        self.make()
        team = hubsetup.template(HUB_IP, owner="100.90.3.4")
        team["goals"]["review_hour"] = 7            # a change, so there is something to commit
        hubsetup.write_team(os.path.join(self.kit, "team.json"), team)
        commit = hubsetup.commit_team(self.kit, hubsetup.FIRST_COMMIT)
        self.assertEqual(self.git("rev-parse", hub.CONFIG_BRANCH, folder=self.bare), commit)
        self.assertEqual(json.loads(self.git("show", f"{commit}:team.json", folder=self.kit)), team)
        self.assertEqual(self.git("log", "-1", "--format=%s", folder=self.kit), hubsetup.FIRST_COMMIT)
        self.assertIsNone(hubsetup.commit_team(self.kit, hubsetup.FIRST_COMMIT))     # again: nothing to commit
        self.assertEqual(self.git("rev-parse", hub.CONFIG_BRANCH, folder=self.bare), commit)

    def test_the_code_ref_is_not_moved_by_the_owners_first_write(self):
        """main is the code and config is what the fleet runs: the hub writes only the second one."""
        self.make()
        team = hubsetup.template(HUB_IP, owner="100.90.3.4")
        team["goals"]["review_hour"] = 7
        hubsetup.write_team(os.path.join(self.kit, "team.json"), team)
        hubsetup.commit_team(self.kit, hubsetup.FIRST_COMMIT)
        self.assertEqual(self.git("rev-parse", hub.CODE_BRANCH, folder=self.bare), self.commit)


class Claim(unittest.TestCase):
    """The owner claim: a one-time code made on the new hub, sent back from the owner's Mac. The address of that call
    becomes addresses.owner, which is the whole of the owner's identity (hub.py allowed("owner"))."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-hub-install-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.out = str(self.tmp / "team.json")
        self.said, self.owner, self.error = [], [], []
        for one in (patch.object(hubsetup, "new_code", lambda: (CODE, SHOWN)),
                    patch.object(hubsetup, "say", self.said.append),
                    patch("builtins.print", lambda *a, **k: None)):     # the block with the code stays out of the log
            one.start()
            self.addCleanup(one.stop)

    # ---- helpers
    def start(self, wait=20, hub_ip=HUB_IP):
        """The claim, in a thread, on the loopback with a free port. Returns its base address."""
        def run():
            try:
                self.owner.append(hubsetup.claim(hub_ip, 8765, wait=wait, where=("127.0.0.1", 0)))
            except Exception as e:              # shown by the test
                self.error.append(e)
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        deadline = time.time() + 10
        while time.time() < deadline:
            found = re.search(r"http://%s:(\d+)" % re.escape(hub_ip), " ".join(self.said))
            if found:
                return "http://127.0.0.1:" + found.group(1)
            time.sleep(0.02)
        self.fail("the claim did not say where it listens: " + " ".join(self.said) + " ".join(map(str, self.error)))

    def post(self, base, body):
        request = urllib.request.Request(base + "/claim", data=body, method="POST")
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=5) as answer:
                return answer.status, answer.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def get(self, base, path="/claim"):
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(base + path, timeout=5) as answer:
                return answer.status, answer.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    # ---- the checks
    def test_the_owners_mac_claims_the_hub_with_the_code(self):
        base = self.start()
        status, text = self.post(base, SHOWN.encode())
        self.assertEqual(status, 200, text)
        self.thread.join(5)
        self.assertEqual(self.owner, ["127.0.0.1"], self.error)
        self.assertIn("127.0.0.1", text)

    def test_the_code_is_taken_as_the_owner_can_have_pasted_it(self):
        base = self.start()
        self.assertEqual(self.post(base, b"  abcd-efgh jklm \n")[0], 200)
        self.thread.join(5)
        self.assertEqual(self.owner, ["127.0.0.1"], self.error)

    def test_another_code_is_refused_and_counted_until_the_address_must_wait(self):
        base = self.start()
        for _ in range(hubsetup.CLAIM_TRIES):
            status, text = self.post(base, b"ZZZZ-ZZZZ-ZZZZ")
            self.assertEqual(status, 403, text)
        self.assertEqual(self.post(base, b"ZZZZ-ZZZZ-ZZZZ")[0], 429)
        self.assertEqual(self.post(base, SHOWN.encode())[0], 429)       # the right code too: the address waits
        self.assertEqual(self.owner, [])

    def test_the_code_works_once(self):
        base = self.start()
        self.assertEqual(self.post(base, SHOWN.encode())[0], 200)
        self.thread.join(5)
        self.assertEqual(self.owner, ["127.0.0.1"], self.error)
        try:                                    # the listener stops with the claim, so a second call reaches nothing
            self.assertEqual(self.post(base, SHOWN.encode())[0], 410)
        except (urllib.error.URLError, OSError):
            pass

    def test_the_hub_cannot_claim_itself(self):
        """A claim from the hub's own address is no proof of anything: the owner's Mac is another machine."""
        base = self.start(hub_ip="127.0.0.1")
        status, text = self.post(base, SHOWN.encode())
        self.assertEqual(status, 403, text)
        self.assertIn("the Mac that will own it", text)
        self.assertEqual(self.owner, [])

    def test_it_serves_the_owners_script_and_nothing_else(self):
        base = self.start()
        status, script = self.get(base)
        self.assertEqual(status, 200)
        self.assertIn("/claim", script)
        self.assertIn("/ui/state", script)      # the owner's own machine makes the end check
        # the address goes to the first-run window, which connects at once: the app has no Settings field for it
        self.assertIn(f"Paste this address in Founderizer: http://{HUB_IP}:{base.rsplit(':', 1)[1]}", script)
        self.assertNotIn("Settings", script)
        # a hub that is slow to come up: his words, with the address and no route of the hub (T-18)
        printed = " ".join(line for line in script.splitlines() if line.lstrip().startswith(("echo", "http")))
        self.assertIn("the hub does not answer yet. When its install is done, paste this address in Founderizer",
                      printed)
        self.assertNotIn("/ui/state", printed)
        self.assertNotIn("owner", printed)
        self.assertIn("--data-binary @-", script)       # the code goes to curl on standard input
        self.assertNotIn(CODE, script)                  # and never into the script
        self.assertNotIn(SHOWN, script)
        self.assertEqual(self.get(base, "/anything")[0], 404)
        self.assertEqual(self.post(base, b"x")[0], 403)

    def test_the_printed_line_keeps_the_code_out_of_the_url(self):
        self.start()
        line = next(s for s in self.said if "claim" in s)
        self.assertNotIn(CODE, line)        # say() prints where it listens; the code is in the block print()s
        script = hubsetup.claim_script(HUB_IP, 8765)
        self.assertNotRegex(script, r"https?://[^\s\"']*" + CODE)

    def test_a_connection_that_sends_a_byte_now_and_then_cannot_hold_the_claim(self):
        """One connection gets the listener's time limit in all, and not for each read. The listener takes one
        request at a time and reads the claim's own time between two requests, so a caller that sent a byte now and
        then held the claim open for as long as it liked, and with it a hub that a second claim had stopped. Each
        machine of the private network can be that caller."""
        with patch.object(hubsetup.ClaimHandler, "timeout", 0.5):
            port = int(self.start(wait=1.5).rsplit(":", 1)[1])
            began = time.time()

            def slow():
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=5) as caller:
                        for _ in range(40):         # eight seconds of it
                            caller.sendall(b"G")
                            time.sleep(0.2)
                except OSError:
                    pass                            # the listener cut it off
            threading.Thread(target=slow, daemon=True).start()
            self.thread.join(6)
            took = time.time() - began
        self.assertFalse(self.thread.is_alive(), "one slow connection held the claim past its time")
        self.assertLess(took, 5)
        self.assertEqual([type(e) for e in self.error], [hubsetup.Stop])    # the claim's own end: no Mac claimed

    def test_nothing_is_written_when_no_mac_claims_the_hub(self):
        with self.assertRaises(hubsetup.Stop):
            hubsetup.claim(HUB_IP, 8765, wait=0.2, where=("127.0.0.1", 0))
        self.assertFalse(os.path.exists(self.out))

    def test_the_claim_writes_the_owner_into_team_json(self):
        base = self.start()
        self.assertEqual(self.post(base, SHOWN.encode())[0], 200)
        self.thread.join(5)
        team = hubsetup.template(HUB_IP)
        team["addresses"]["owner"] = self.owner[0]
        hubsetup.write_team(self.out, team)
        self.assertEqual(hubsetup.claimed_by(self.out, HUB_IP, 8765), "127.0.0.1")

    def test_a_hub_renamed_after_its_name_in_tailscale_is_still_claimed(self):
        """The hub follows its machine's name in Tailscale (hub.rename_machine), so its machine is not "hub" for long.
        A second run finds its own team.json by the hub's machine, or it would start a new claim over the live one."""
        hubsetup.write_team(self.out, hub.renamed_machine_team(hubsetup.template(HUB_IP, owner="100.90.3.4"), "hub",
                                                               "worker-2"))
        self.assertEqual(hubsetup.claimed_by(self.out, HUB_IP, 8765), "100.90.3.4")

    def test_a_second_run_on_a_claimed_hub_makes_no_code_and_changes_nothing(self):
        hubsetup.write_team(self.out, hubsetup.template(HUB_IP, owner="100.90.3.4"))
        before = Path(self.out).read_text()
        args = type("A", (), {"address": HUB_IP, "port": 8765, "out": self.out, "reclaim": False, "timezone": None,
                              "runtime": "claude", "ssh_user": "fleet", "ssh_port": 22, "wait": 1, "commit": False,
                              "manager_later": False})()
        with patch.object(hubsetup, "claim", lambda *a, **k: self.fail("it made a second claim")):
            hubsetup.cmd_claim(args)
        self.assertIn("100.90.3.4", " ".join(self.said))
        self.assertEqual(Path(self.out).read_text(), before)

    def test_the_first_team_json_is_not_the_one_the_repository_ships(self):
        """The installer runs from a checkout of Founderizer, and that checkout carries a team.json of its own: the fleet
        it was published from. A new hub must take none of it. It would otherwise run as that fleet - its git daemon
        listens on the address team.json gives the hub, which this machine does not have, and `agent-users` makes
        the users of another fleet's agents."""
        other = hubsetup.template("100.111.0.10", owner="100.111.0.40")
        other["addresses"]["worker4"] = "100.111.0.50"
        other["agents"]["worker4"] = {"role": "worker", "machine": "worker4", "runtime": "codex", "can": ["shell"],
                                      "vault": "none", "start": "codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}"}
        hubsetup.write_team(self.out, other)
        args = type("A", (), {"address": HUB_IP, "port": 8765, "out": self.out, "reclaim": False, "timezone": "UTC",
                              "runtime": "claude", "ssh_user": "fleet", "ssh_port": 22, "wait": 1, "commit": False,
                              "manager_later": False})()
        with patch.object(hubsetup, "claim", lambda *a, **k: "100.90.3.4"):
            hubsetup.cmd_claim(args)
        written = json.loads(Path(self.out).read_text())
        self.assertEqual(written["addresses"], {"hub": HUB_IP, "owner": "100.90.3.4"})
        self.assertEqual(sorted(written["agents"]), ["manager"])

    def test_a_second_run_on_this_hub_keeps_what_the_first_wrote(self):
        """The same hub, so the file is this hub's own: a new claim replaces the owner and nothing else."""
        mine = hubsetup.template(HUB_IP, owner="100.90.3.4")
        mine["goals"]["review_hour"] = 7                    # something only this fleet has
        hubsetup.write_team(self.out, mine)
        args = type("A", (), {"address": HUB_IP, "port": 8765, "out": self.out, "reclaim": True, "timezone": None,
                              "runtime": "claude", "ssh_user": "fleet", "ssh_port": 22, "wait": 1, "commit": False,
                              "manager_later": False})()
        with patch.object(hubsetup, "claim", lambda *a, **k: "100.90.9.9"):
            hubsetup.cmd_claim(args)
        written = json.loads(Path(self.out).read_text())
        self.assertEqual(written["addresses"]["owner"], "100.90.9.9")
        self.assertEqual(written["goals"]["review_hour"], 7)

    def test_a_hub_whose_address_changed_is_not_taken_as_claimed(self):
        hubsetup.write_team(self.out, hubsetup.template(HUB_IP, owner="100.90.3.4"))
        self.assertIsNone(hubsetup.claimed_by(self.out, "100.80.9.9", 8765))
        self.assertIsNone(hubsetup.claimed_by(self.out, HUB_IP, 9000))
        self.assertIsNone(hubsetup.claimed_by(str(self.tmp / "nothing.json"), HUB_IP, 8765))


class HubAnswers(http.server.BaseHTTPRequestHandler):
    """What a second claim needs of a hub that runs: it holds the hub's address and port, and it answers /health."""

    def log_message(self, *_args):
        return

    def do_GET(self):
        live = self.path == "/health"
        body = json.dumps({"ok": True, "agents": ["manager"]} if live else {"error": "not here"}).encode()
        self.send_response(200 if live else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class SecondClaim(unittest.TestCase):
    """A second owner claim (`--reclaim`) on a hub that runs: the owner's Mac is lost, or it has a new address.

    The claim listens on the hub's own address and port, and the hub that runs holds them: until 10 November 2026 the
    claim ended there with "Address already in use", so the one documented way to give a hub a new owner did not work
    on a hub that runs. The tests of `Claim` could not show it, because each gives the listener a free port (`where=`).
    Here the hub is a real listener on the address and port of team.json, the claim gets no `where=`, and
    `systemctl --user ... fleet-hub.service` is this test's own: stop closes that listener and start opens it again.
    The hub's repository is a real one, because the claim commits team.json on it while the hub is stopped."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-hub-reclaim-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.said, self.error, self.calls, self.started_on = [], [], [], []
        self.hub, self.managed, self.at_stop, self.stops_after = None, True, None, 0
        self.mac, self.answers = NEW_MAC, {}
        real = hubsetup.ClaimServer.get_request

        def from_the_new_mac(server):       # the call comes from the Mac, not from the hub's own address
            request, (_address, port) = real(server)
            return request, (self.mac, port)
        for one in (patch.object(hubsetup, "new_code", lambda: (CODE, SHOWN)),
                    patch.object(hubsetup, "say", self.said.append),
                    patch("builtins.print", lambda *a, **k: None),      # the block with the code stays out of the log
                    # create: on a hubsetup.py from before, these tests then show the fault itself
                    patch.object(hubsetup, "hub_service", self.service, create=True),
                    # The guard of a claim runs this command when the claim's program ends with no word. A test run
                    # that is killed in the middle of a claim must not restart a real fleet-hub of this machine.
                    patch.object(hubsetup, "service_call", lambda word: ([sys.executable, "-c", "pass"],
                                                                         dict(os.environ)), create=True),
                    patch.object(hubsetup.ClaimServer, "get_request", from_the_new_mac)):
            one.start()
            self.addCleanup(one.stop)
        self.addCleanup(self.hub_stops)
        self.port = self.hub_starts(0)                  # the hub runs, on a port of its own that team.json then names
        tree = self.tmp / "tree"                        # the copy of Founderizer that the installer ran from
        tree.mkdir()
        (tree / "hub.py").write_text("# the hub\n")
        (tree / "team.json").write_text(json.dumps(hubsetup.template("100.111.0.10", owner="100.111.0.40")) + "\n")
        self.git("init", "-q", "-b", "main", str(tree))
        self.git("add", "-A", folder=tree)
        self.git("commit", "-q", "-m", "the Founderizer code", folder=tree)
        self.bare, self.kit = str(self.tmp / "fleet-pilot.git"), str(self.tmp / "fleet-pilot")
        hubsetup.repository(str(tree), self.bare, self.kit)
        self.out = os.path.join(self.kit, "team.json")
        mine = hubsetup.template(LOOP, self.port, owner=OLD_MAC)
        mine["goals"]["review_hour"] = 7                # something only this fleet has
        hubsetup.write_team(self.out, mine)
        hubsetup.commit_team(self.kit, hubsetup.FIRST_COMMIT)
        self.first = self.git("rev-parse", "HEAD", folder=self.kit)
        self.said.clear()

    # ---- helpers
    def git(self, *args, folder=None):
        return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *(["-C", str(folder)] if folder else []),
                               *args], check=True, capture_output=True, text=True).stdout.strip()

    def hub_starts(self, port):
        self.hub = http.server.HTTPServer((LOOP, port), HubAnswers)
        threading.Thread(target=self.hub.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        return self.hub.server_address[1]

    def hub_stops(self):
        hub_, self.hub = self.hub, None
        if hub_ is not None:
            hub_.shutdown()
            hub_.server_close()

    def service(self, word, wait=60):
        """`systemctl --user <word> fleet-hub.service`, for a hub that is this test's own listener. A test can give
        one word its own answer (`answers`), and then nothing is done for that word."""
        self.calls.append(word)
        if word in self.answers:
            return self.answers[word]
        if word == "is-active":
            return (0, "active") if self.managed and self.hub is not None else (3, "inactive")
        if word == "stop":
            if self.stops_after:        # the port is free a moment after systemctl answered
                threading.Timer(self.stops_after, self.hub_stops).start()
            else:
                self.hub_stops()
            if self.at_stop:
                self.at_stop()
        elif word == "restart":     # what the hub finds at its start: the owner, a clean checkout, and the ref at it
            self.hub_stops()
            self.started_on.append((self.owner(), self.git("status", "--porcelain", folder=self.kit),
                                    self.git("rev-parse", hub.CONFIG_BRANCH, folder=self.bare) == self.head()))
            self.hub_starts(self.port)
        return 0, ""

    def args(self, **changed):
        return type("A", (), dict({"address": LOOP, "port": self.port, "out": self.out, "reclaim": True,
                                   "timezone": None, "runtime": "claude", "ssh_user": "fleet", "ssh_port": 22,
                                   "wait": 20, "commit": True, "manager_later": False}, **changed))()

    def owner(self):
        return json.loads(Path(self.out).read_text())["addresses"].get("owner")

    def head(self):
        return self.git("rev-parse", "HEAD", folder=self.kit)

    def claim_in_a_thread(self, **changed):
        """The claim, as hub.sh runs it, in a thread. Returns the thread when the claim is open."""
        def run():
            try:
                hubsetup.cmd_claim(self.args(**changed))
            except Exception as e:              # shown by the test
                self.error.append(e)
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.wait_for_the_claim(thread)
        return thread

    def wait_for_the_claim(self, thread=None):
        deadline = time.time() + 10
        while time.time() < deadline and not self.error and (thread is None or thread.is_alive()):
            if f"the owner claim is open on http://{LOOP}:{self.port} " in " ".join(self.said):
                return True
            time.sleep(0.02)
        if thread is not None:
            self.fail("the claim did not open on the hub's own address and port: "
                      + " | ".join([*self.said, *map(repr, self.error)]))
        return False

    def post(self, body=SHOWN.encode(), path="/claim"):
        request = urllib.request.Request(f"http://{LOOP}:{self.port}{path}", data=body, method="POST")
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=5) as answer:
                return answer.status, answer.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def a_call_of_the_fleet(self):
        """What a machine or an agent of the fleet gets from the hub's port while the claim holds it: (GET, POST)."""
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
                    f"http://{LOOP}:{self.port}/ui/state", timeout=5) as answer:
                got = answer.status
        except urllib.error.HTTPError as e:
            got = e.code
        return got, self.post(b"{}", "/helper/session/manager")[0]

    def ref_gets_a_commit_of_the_hubs_own(self):
        """The hub pushed a write of its own to its configuration ref, and its checkout does not have it yet."""
        other = self.tmp / "a-write-of-the-hub"
        self.git("clone", "-q", "-b", hub.CONFIG_BRANCH, self.bare, str(other))
        (other / "knowledge.md").write_text("a write of the hub's own\n")
        self.git("add", "-A", folder=other)
        self.git("commit", "-q", "-m", "a write of the hub's own", folder=other)
        self.git("push", "-q", "origin", f"HEAD:{hub.CONFIG_BRANCH}", folder=other)
        shutil.rmtree(str(other))

    def nothing_changed(self):
        self.assertEqual(self.owner(), OLD_MAC)
        self.assertEqual(self.head(), self.first)
        self.assertEqual(self.git("status", "--porcelain", folder=self.kit), "")

    # ---- the checks
    def test_the_claim_stops_a_hub_that_runs_and_starts_it_again_on_the_new_owner(self):
        """The fault of 10 November 2026: with a hub on the address and port of team.json, this ended with
        OSError "Address already in use" before the claim opened."""
        thread = self.claim_in_a_thread()
        self.assertEqual(self.calls, ["is-active", "stop"])
        self.assertIsNone(self.hub)                     # the claim has the hub's own address and port to itself
        self.assertIn("is stopped for the time of the claim", " ".join(self.said))
        # The fleet goes on calling that port. 404 would tell a helper "a hub from before this route" or "gone", and
        # it would start a session without its credential or give a job up: 503 is what it waits out.
        self.assertEqual(self.a_call_of_the_fleet(), (503, 503))
        status, text = self.post()
        self.assertEqual(status, 200, text)
        self.assertIn(NEW_MAC, text)
        thread.join(30)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.error, [])
        self.assertEqual(self.calls, ["is-active", "stop", "restart"])
        team = json.loads(Path(self.out).read_text())
        self.assertEqual(team["addresses"], {"hub": LOOP, "owner": NEW_MAC})
        self.assertEqual(team["goals"]["review_hour"], 7)       # the claim changed the owner and nothing else
        # The hub started after team.json was written, committed and pushed: it reads the new owner at its start, and
        # its checkout is one that it can write from.
        self.assertEqual(self.started_on, [(NEW_MAC, "", True)])
        self.assertEqual(self.git("log", "-1", "--format=%s", folder=self.kit), hubsetup.OWNER_COMMIT)
        self.assertEqual(self.git("rev-list", "--count", f"{self.first}..HEAD", folder=self.kit), "1")
        self.assertTrue(hubsetup.health(LOOP, self.port, timeout=2)[0])     # and it answers again
        self.assertIn(f"the owner is the Mac at {NEW_MAC}, and the address from before is refused",
                      " ".join(self.said))

    def test_the_hub_starts_again_when_no_mac_claims_in_time(self):
        before = signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGHUP), signal.getsignal(signal.SIGINT)
        with self.assertRaisesRegex(hubsetup.Stop, "no Mac claimed this hub"):
            hubsetup.cmd_claim(self.args(wait=0.3))
        self.assertEqual(self.calls, ["is-active", "stop", "restart"])
        self.assertEqual(self.started_on, [(OLD_MAC, "", True)])            # as it was: the old owner keeps the hub
        self.nothing_changed()
        self.assertTrue(hubsetup.health(LOOP, self.port, timeout=2)[0])
        self.assertEqual((signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGHUP),
                          signal.getsignal(signal.SIGINT)), before)         # and this program's signals are its own

    def ends_the_claim(self, number):
        """A thread that sends this program the signal `number` when the claim is open, and only then: a signal that
        went out later would end another test, or the whole run. The caller joins it."""
        def end():
            if self.wait_for_the_claim():
                os.kill(os.getpid(), number)
        thread = threading.Thread(target=end, daemon=True)
        thread.start()
        return thread

    def test_a_claim_that_is_ended_from_outside_starts_the_hub_again(self):
        """A terminal that closed, or a kill, while the claim waits for the Mac: the hub must not stay stopped. The
        claim's own listener is closed by then, or the hub could not open its port."""
        for name in ("SIGHUP", "SIGTERM"):
            with self.subTest(signal=name):
                self.calls.clear(), self.said.clear(), self.started_on.clear()
                number, missed = getattr(signal, name), []

                def mine(*_args):       # a claim that catches nothing must not end the whole test run
                    missed.append(1)
                before = signal.signal(number, mine)
                self.addCleanup(signal.signal, number, before)
                thread = self.ends_the_claim(number)
                try:
                    with self.assertRaises(SystemExit) as stopped:
                        hubsetup.cmd_claim(self.args(wait=20))
                finally:
                    thread.join(15)
                self.assertIn(f"the owner claim was ended from outside ({name}), so nothing was written",
                              str(stopped.exception.code))
                self.assertEqual(missed, [])
                self.assertEqual(self.calls, ["is-active", "stop", "restart"])
                self.assertIs(signal.getsignal(number), mine)       # the program has its own handler again
                self.nothing_changed()
                self.assertTrue(hubsetup.health(LOOP, self.port, timeout=2)[0])
                self.assertIn("is started again", " ".join(self.said))

    def test_ctrl_c_while_the_claim_waits_starts_the_hub_again(self):
        before = signal.signal(signal.SIGINT, signal.default_int_handler)   # a run in the background ignores it
        self.addCleanup(signal.signal, signal.SIGINT, before)
        thread = self.ends_the_claim(signal.SIGINT)
        try:
            with self.assertRaises(KeyboardInterrupt):
                hubsetup.cmd_claim(self.args(wait=20))
        finally:
            thread.join(15)
        self.assertEqual(self.calls, ["is-active", "stop", "restart"])
        self.assertIs(signal.getsignal(signal.SIGINT), signal.default_int_handler)
        self.nothing_changed()
        self.assertTrue(hubsetup.health(LOOP, self.port, timeout=2)[0])

    def test_nothing_ends_the_claim_between_the_owner_and_the_start_of_the_hub(self):
        """The Mac has claimed the hub. From there to the hub's start, a signal ends nothing: a commit of team.json
        that stopped half done, or a hub that stayed stopped, would cost more than the seconds that are left."""
        missed, real = [], hubsetup.write_team

        def mine(*_args):
            missed.append(1)
        before = signal.signal(signal.SIGTERM, mine)
        self.addCleanup(signal.signal, signal.SIGTERM, before)

        def write_with_a_kill(path, team):
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(0.2)                     # the signal is delivered while the claim still has work
            return real(path, team)

        def the_mac():
            if self.wait_for_the_claim():
                self.post()
        mac = threading.Thread(target=the_mac, daemon=True)
        mac.start()
        try:
            with patch.object(hubsetup, "write_team", write_with_a_kill):
                hubsetup.cmd_claim(self.args(wait=20))          # it ends as a claim that nothing disturbed
        finally:
            mac.join(15)
        self.assertEqual(missed, [])
        self.assertEqual(self.started_on, [(NEW_MAC, "", True)])
        self.assertIs(signal.getsignal(signal.SIGTERM), mine)

    def test_a_claim_whose_own_program_is_killed_gets_its_hub_started_by_its_guard(self):
        """A SIGKILL cannot be caught, so the claim cannot start the hub then. Its guard does: a small program in a
        session of its own, which starts the hub's service when the claim's program ends with no word. A claim that
        ended by itself gives that word, and the guard starts nothing."""
        code = ("import os, signal, sys\n"
                "import hubsetup\n"
                "mark = [sys.executable, '-c', 'import sys; open(sys.argv[1], \"w\").write(sys.argv[2])', sys.argv[1]]\n"
                "hubsetup.service_call = lambda word: (mark + [word], dict(os.environ))\n"
                "pause = hubsetup.HubPause('127.0.0.1', 1, sys.argv[2], True, before='100.90.3.4')\n"
                "pause.watch()\n"
                "if sys.argv[3] == 'killed':\n"
                "    os.kill(os.getpid(), signal.SIGKILL)\n"
                "pause.release()\n")
        for how, wanted in (("killed", "restart"), ("ended", None)):
            with self.subTest(how=how):
                marker = self.tmp / f"the-guard-ran-{how}"
                done = subprocess.run([sys.executable, "-B", "-c", code, str(marker), self.out, how], cwd=str(KIT),
                                      capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
                self.assertEqual(done.returncode, -signal.SIGKILL if how == "killed" else 0, done.stderr)
                deadline = time.time() + (15 if wanted else 2)
                while time.time() < deadline and not marker.exists():
                    time.sleep(0.05)
                time.sleep(0.2)
                self.assertEqual(marker.read_text() if marker.exists() else None, wanted)

    def test_a_port_that_another_program_holds_stops_the_claim_in_words_and_stops_nothing(self):
        self.managed = False            # the listener is not this user's fleet-hub
        with self.assertRaisesRegex(hubsetup.Stop, "is in use.*the service fleet-hub of the user .* does not run.*"
                                                   "Nothing changed"):
            hubsetup.cmd_claim(self.args())
        self.assertEqual(self.calls, ["is-active"])
        self.assertIsNotNone(self.hub)
        self.nothing_changed()

    def test_the_service_is_asked_in_the_users_own_folder_whatever_the_caller_gave(self):
        """`runuser -u fleet --` from a root login keeps root's XDG_RUNTIME_DIR, /run/user/0. With it, systemctl
        cannot reach the service manager of the hub's user, and the claim read a hub that runs as "not the service
        fleet-hub": the line that HUB-INSTALL.md gives for the claim alone was refused. Here the real hub_service
        runs, against a systemctl of this test's own."""
        folder = self.tmp / "bin"
        folder.mkdir()
        (folder / "systemctl").write_text('#!/bin/sh\nprintf "%s|%s" "$*" "$XDG_RUNTIME_DIR" > "$ASKED"\necho active\n')
        (folder / "systemctl").chmod(0o755)
        asked = self.tmp / "asked"
        with patch.dict(os.environ, {"PATH": f"{folder}:/usr/bin:/bin", "XDG_RUNTIME_DIR": "/run/user/0",
                                     "ASKED": str(asked)}), patch.object(hubsetup, "service_call", REAL_SERVICE_CALL):
            self.assertEqual(REAL_HUB_SERVICE("is-active"), (0, "active"))
        self.assertEqual(asked.read_text(), f"--user is-active fleet-hub.service|/run/user/{os.getuid()}")

    def test_a_hub_that_somebody_stopped_before_is_claimed_as_always_and_not_started(self):
        """The app's own restore stops the hub, runs the claim and starts the hub: the claim then finds the port free,
        asks the service manager nothing, and starts nothing. A first claim finds the same."""
        self.hub_stops()
        thread = self.claim_in_a_thread()
        self.assertEqual(self.a_call_of_the_fleet(), (503, 503))    # the fleet is there all the same, and it waits
        self.assertEqual(self.post()[0], 200)
        thread.join(30)
        self.assertEqual((self.error, self.calls), ([], []))
        self.assertIsNone(self.hub)
        self.assertEqual(self.owner(), NEW_MAC)
        self.assertEqual(self.git("rev-parse", hub.CONFIG_BRANCH, folder=self.bare), self.head())

    def test_the_team_of_a_fleet_that_runs_is_never_replaced_by_a_first_team_json(self):
        """A claim writes the first team.json when the file is not this hub's own. With a hub that runs on that
        address and port, that would put one manager in the place of a whole fleet: a file that the hub cannot run
        any more, and a file that names another port."""
        team = json.loads(Path(self.out).read_text())
        for what, why in (("no owner", "team.json needs the owner address"),
                          ("another port", "it names another hub address or port")):
            with self.subTest(what=what):
                self.calls.clear()
                if what == "no owner":
                    changed = dict(team, addresses={"hub": LOOP})       # by hand: the hub cannot run it any more
                else:
                    changed = dict(team, hub=dict(team["hub"], port=self.port + 1))
                Path(self.out).write_text(json.dumps(changed, indent=2) + "\n")
                before = Path(self.out).read_text()
                with self.assertRaisesRegex(hubsetup.Stop, "not a team.json of that hub that the hub can run ."
                                            + re.escape(why) + ".*nothing was stopped and nothing changed"):
                    hubsetup.cmd_claim(self.args(reclaim=False))
                self.assertEqual(self.calls, ["is-active"])
                self.assertIsNotNone(self.hub)
                self.assertEqual(Path(self.out).read_text(), before)

    def test_a_reclaim_takes_only_the_hubs_own_team_json_also_on_a_port_that_is_free(self):
        """--reclaim is the word for a hub that has an owner. On a port that is free the claim stops no hub, so
        nothing else stood between a wrong --port (the line of HUB-INSTALL.md, on a hub that was installed with
        another port) and a first team.json over the team of a fleet."""
        with socket.socket() as free:           # a port that team.json does not name, and that is free
            free.bind((LOOP, 0))
            other = free.getsockname()[1]
        before = Path(self.out).read_text()
        with patch.object(hubsetup, "claim", lambda *a, **k: self.fail("it made a code")):
            for port, why in ((other, "it names another hub address or port"), (self.port, "team.json needs the owner")):
                with self.subTest(port=port == other and "another" or "the hub's own, with no owner"):
                    if port == self.port:
                        team = json.loads(before)
                        Path(self.out).write_text(json.dumps(dict(team, addresses={"hub": LOOP})) + "\n")
                    kept = Path(self.out).read_text()
                    with self.assertRaisesRegex(hubsetup.Stop, "--reclaim gives a new owner to a hub that has one.*"
                                                + re.escape(why) + ".*no code was made and nothing changed"):
                        hubsetup.cmd_claim(self.args(port=port))
                    self.assertEqual(Path(self.out).read_text(), kept)
        self.assertEqual(self.calls, [])
        self.assertIsNotNone(self.hub)

    def test_a_hub_that_runs_is_stopped_only_for_a_claim_that_commits(self):
        """The hub refuses every write while its checkout has a change that is not committed (commit_kit_file)."""
        with self.assertRaisesRegex(hubsetup.Stop, "Run the claim with --commit. Nothing was stopped"):
            hubsetup.cmd_claim(self.args(commit=False))
        self.assertEqual(self.calls, ["is-active"])
        self.assertIsNotNone(self.hub)
        self.nothing_changed()

    def test_a_hub_in_the_middle_of_a_write_of_its_own_is_not_stopped(self):
        """The hub pushes a write, and a release, to its configuration ref before it moves its checkout. A commit of
        team.json on a checkout without that commit cannot be pushed, and the hub then refuses every write."""
        self.ref_gets_a_commit_of_the_hubs_own()
        with self.assertRaisesRegex(hubsetup.Stop, "in the middle of a write or an update of its own.*Nothing was "
                                                   "stopped and nothing changed. Run this again"):
            hubsetup.cmd_claim(self.args())
        self.assertEqual(self.calls, ["is-active"])
        self.assertIsNotNone(self.hub)
        self.nothing_changed()

    def test_a_hub_that_the_stop_met_in_the_middle_of_a_write_starts_again_with_nothing_written(self):
        self.at_stop = self.ref_gets_a_commit_of_the_hubs_own       # between the claim's look and its stop
        with self.assertRaisesRegex(hubsetup.Stop, "was stopped in the middle of a write or an update of its own.*"
                                                   "Nothing was written.*Run this again"):
            hubsetup.cmd_claim(self.args())
        self.assertEqual(self.calls, ["is-active", "stop", "restart"])
        self.assertNotIn("the owner claim is open", " ".join(self.said))    # no code was made for it
        self.nothing_changed()
        self.assertTrue(hubsetup.health(LOOP, self.port, timeout=2)[0])

    def claimed_from_the_mac(self, **changed):
        """A whole claim, with the Mac's call: what the claim ended with, an error or None."""
        self.calls.clear(), self.said.clear(), self.started_on.clear(), self.error.clear()
        thread = self.claim_in_a_thread(**changed)
        self.assertEqual(self.post()[0], 200)
        thread.join(30)
        self.assertFalse(thread.is_alive())
        return self.error[0] if self.error else None

    def test_a_claim_that_cannot_commit_or_push_is_taken_back(self):
        """With team.json changed and not committed, or with a commit that its ref does not have, the hub refuses
        every write from then on. So a second claim that fails there leaves the checkout as it found it, and the
        hub starts on what it ran before."""
        real = hubsetup.git
        for word in ("push", "commit"):
            with self.subTest(fails=word):
                def fails(*args, **kw):
                    return (1, "", f"the {word} was refused") if args[:1] == (word,) else real(*args, **kw)
                with patch.object(hubsetup, "git", fails):
                    error = self.claimed_from_the_mac()
                self.assertRegex(str(error), f"could not {word} team.json")
                self.assertEqual(self.calls, ["is-active", "stop", "restart"])
                self.assertEqual(self.started_on, [(OLD_MAC, "", True)])
                self.nothing_changed()
                self.assertIn("team.json is as it was before the claim.", self.said)

    def test_a_commit_that_cannot_be_taken_back_is_said_with_the_command_that_does_it(self):
        real = hubsetup.git

        def fails(*args, **kw):
            return (1, "", f"the {args[0]} was refused") if args[:1] in (("push",), ("reset",)) else real(*args, **kw)
        with patch.object(hubsetup, "git", fails):
            self.assertRegex(str(self.claimed_from_the_mac()), "could not push team.json")
        said = " ".join(self.said)
        self.assertIn("is still on the branch", said)
        self.assertIn(f"reset --soft {self.first[:12]}", said)
        self.assertNotIn("team.json is as it was before the claim.", said)
        self.assertEqual(self.owner(), OLD_MAC)         # the file itself is the one from before

    def test_a_port_that_another_program_takes_after_the_stop_is_said_in_words(self):
        """The claim's second try to open its listener. A program from before this change said "Address already in
        use" there, and the Mac app reads those words as an installer from before, which it must help."""
        self.answers["stop"] = (0, "")                  # systemctl says stopped, and the port stays in use
        with patch.object(hubsetup, "port_taken", lambda *_a: False), \
                self.assertRaisesRegex(hubsetup.Stop, "another program took .* before the claim could") as stopped:
            hubsetup.cmd_claim(self.args())
        self.assertNotIn("Address already in use", str(stopped.exception))
        self.assertEqual(self.calls, ["is-active", "stop", "restart"])
        self.nothing_changed()

    def test_a_commit_that_reached_the_ref_stays_when_a_later_step_fails(self):
        """The write is whole then. Taking it back would leave the hub on the old owner with the new one on its ref."""
        def say(text):
            if text.startswith("team.json is committed"):
                raise OSError(5, "the terminal is gone")
            self.said.append(text)
        with patch.object(hubsetup, "say", say):
            error = self.claimed_from_the_mac()
        self.assertIsInstance(error, OSError)
        self.assertEqual(self.started_on, [(NEW_MAC, "", True)])
        self.assertEqual(self.owner(), NEW_MAC)

    def test_a_hub_that_does_not_come_back_ends_the_claim_with_a_failure_that_says_what_to_do(self):
        self.answers["restart"] = (1, "Job for fleet-hub.service failed")
        self.assertRegex(str(self.claimed_from_the_mac()), "did not start again .Job for fleet-hub.service failed.*"
                                                           "systemctl --user start fleet-hub.service")
        self.assertEqual(self.owner(), NEW_MAC)         # the claim itself is done, and committed
        self.hub_starts(self.port)                      # somebody started it, and the next claim finds it
        self.answers["restart"] = (0, "")               # this time systemctl is content, and no hub listens
        self.mac = OLD_MAC
        with patch.object(hubsetup, "BACK_TRIES", 2):
            self.assertRegex(str(self.claimed_from_the_mac(reclaim=True)),
                             f"was started again, and the hub does not answer at http://{LOOP}:{self.port}/health")

    def test_the_claim_waits_for_the_port_after_the_stop(self):
        self.stops_after = 1.3          # systemctl has answered, and the hub's listener closes a moment later
        self.assertIsNone(self.claimed_from_the_mac())
        self.assertEqual(self.owner(), NEW_MAC)

    def test_a_stop_that_is_broken_off_or_fails_still_starts_the_hub(self):
        def broken_off():
            raise KeyboardInterrupt
        self.at_stop = broken_off
        with self.assertRaises(KeyboardInterrupt):
            hubsetup.cmd_claim(self.args())
        self.assertEqual(self.calls, ["is-active", "stop", "restart"])
        self.at_stop, self.answers["stop"] = None, (1, "Failed to stop fleet-hub.service")
        self.calls.clear()
        with self.assertRaisesRegex(hubsetup.Stop, "did not stop for the claim .Failed to stop fleet-hub.service"):
            hubsetup.cmd_claim(self.args())
        self.assertEqual(self.calls, ["is-active", "stop", "restart"])
        self.nothing_changed()
        self.assertTrue(hubsetup.health(LOOP, self.port, timeout=2)[0])

    def test_the_same_mac_that_claims_again_keeps_the_hub_and_reads_that(self):
        self.mac = OLD_MAC
        self.assertIsNone(self.claimed_from_the_mac())
        self.nothing_changed()
        said = " ".join(self.said)
        self.assertIn(f"the owner is the Mac at {OLD_MAC}, as before.", said)
        self.assertNotIn("the address from before is refused", said)


class AgentUsers(unittest.TestCase):
    """One OS user for each agent of a machine (hub.sh, join.sh): `fleet-<agent>`, a locked password, no sudo,
    lingering on, and a home of mode 700 that belongs to it alone, so that no agent's user can read another agent's
    runtime credential or vault token. Nothing here makes a user: every command goes through a reader that answers
    from a table, so the test measures the commands and the refusals."""

    def setUp(self):
        self.ran = []
        self.state = {}                 # user -> the reading it answers with, before anything is made

    def reader(self, script):
        self.ran.append(script)
        for user, reading in self.state.items():
            if f"id -u {user} " in script.split("\n")[0]:
                if "useradd" in script:         # the making script: the user is as Founderizer needs it afterwards
                    self.state[user] = self.good(user)
                    return 0, "", ""
                return 0, reading, ""
        return 0, "", ""

    @staticmethod
    def good(user, **changed):
        reading = {"exists": "yes", "locked": "L", "sudo": "no", "linger": "yes", "mode": "700", "owner": user,
                   "group": "yes"}
        reading.update(changed)
        return "\n".join(f"{k}={v}" for k, v in reading.items())

    @staticmethod
    def team(**agents):
        return {"agents": {name: {"machine": machine} for name, machine in agents.items()}}

    def made(self, out):
        return [(agent, user) for agent, user, what in out if what == "made"]

    def test_each_agent_of_this_machine_gets_its_own_user(self):
        team = self.team(manager="hub", writer="hub", vps="vps")
        self.state = {"fleet-manager": "exists=no", "fleet-writer": "exists=no"}
        out = hubsetup.agent_users(team, "hub", run=self.reader)
        self.assertEqual(out, [("manager", "fleet-manager", "made"), ("writer", "fleet-writer", "made")])
        made = "\n".join(self.ran)
        for user in ("fleet-manager", "fleet-writer"):
            self.assertIn(f"useradd --create-home --shell /bin/bash --user-group {user}", made)
            self.assertIn(f"passwd -l {user}", made)
            self.assertIn(f"chmod 700 /home/{user}", made)
            self.assertIn(f"chown {user}:{user} /home/{user}", made)
            self.assertIn(f"loginctl enable-linger {user}", made)
            self.assertIn(f"for g in sudo admin wheel; do gpasswd -d {user} $g", made)
            # the group the service user may become, which is how the agent is installed and read under its own user
            self.assertIn(f"usermod -aG {hubsetup.AGENT_GROUP} {user}", made)
        self.assertIn(f"groupadd -f {hubsetup.AGENT_GROUP}", made)
        self.assertNotIn("fleet-vps", made, "an agent of another machine got a user here")

    def test_a_second_run_changes_nothing(self):
        self.state = {"fleet-manager": self.good("fleet-manager")}
        out = hubsetup.agent_users(self.team(manager="hub"), "hub", run=self.reader)
        self.assertEqual(out, [("manager", "fleet-manager", "there")])
        self.assertEqual([s for s in self.ran if "useradd" in s or "chmod" in s or "passwd -l" in s], [])

    def test_a_user_that_is_not_as_fleet_needs_it_is_made_right(self):
        """A home that is readable by other users, a password that is not locked, or sudo: all three are put right."""
        for broken in ({"mode": "755"}, {"locked": "P"}, {"sudo": "yes"}, {"owner": "root"}):
            self.ran, self.state = [], {"fleet-manager": self.good("fleet-manager", **broken)}
            out = hubsetup.agent_users(self.team(manager="hub"), "hub", run=self.reader)
            self.assertEqual(self.made(out), [("manager", "fleet-manager")], broken)
            self.assertIn("chmod 700 /home/fleet-manager", "\n".join(self.ran), broken)

    def test_a_user_that_stays_wrong_stops_the_install(self):
        self.state = {"fleet-manager": "exists=no"}
        bad = lambda script: (0, "", "") if "useradd" in script else (0, self.good("fleet-manager", mode="755"), "")
        with self.assertRaises(hubsetup.Stop) as stopped:
            hubsetup.agent_users(self.team(manager="hub"), "hub", run=bad)
        self.assertIn("mode is '755'", str(stopped.exception))

    def test_a_machine_with_no_agent_yet_makes_no_user(self):
        out = hubsetup.agent_users(self.team(manager="hub"), "box", run=self.reader)
        self.assertEqual((out, self.ran), ([], []))

    def test_check_mode_says_what_it_would_make_and_runs_nothing_that_changes(self):
        self.state = {"fleet-manager": "exists=no"}
        out = hubsetup.agent_users(self.team(manager="hub"), "hub", check=True, run=self.reader)
        self.assertEqual(out, [("manager", "fleet-manager", "would make")])
        self.assertEqual([s for s in self.ran if "useradd" in s], [])

    def test_the_user_name_comes_from_one_place_and_both_installers_use_it(self):
        """The convention is in hubsetup.AGENT_USER and nowhere else: both installers call the one command, so no
        second copy of the name can drift from it."""
        self.assertEqual((hubsetup.AGENT_USER, hubsetup.agent_user("manager")), ("fleet-%s", "fleet-manager"))
        for script in (SCRIPT, KIT / "join.sh"):
            text = script.read_text()
            self.assertIn("hubsetup.py\" agent-users", text, script.name)
            self.assertNotIn("useradd --create-home --shell /bin/bash --user-group fleet-", text,
                             f"{script.name} makes an agent's user itself instead of through the one command")

    def test_the_agents_session_runs_as_that_user_and_product_md_says_so(self):
        """From 17 October 2026 the service moves with the user: each agent's session runs as `fleet-<agent>`, so
        its runtime credential and its vault token are in a home no other agent can open. PRODUCT.md P2 and 4.1
        carry the decision."""
        self.assertIn("each agent of this machine, under its own OS user", SCRIPT.read_text())
        self.assertNotIn("leave every service as it is", SCRIPT.read_text())
        if not (KIT / "PRODUCT.md").is_file():
            self.skipTest("PRODUCT.md is not in a published copy")     # the installer's half has run
        product = (KIT / "PRODUCT.md").read_text()
        p2 = product.split("**P2 —")[1].split("**P3 —")[0]
        self.assertIn("one OS user for each agent", p2)
        self.assertIn("hub.sh", p2)
        self.assertIn("join.sh", p2)
        self.assertIn("every agent's session runs as `fleet-<agent>`", p2)
        self.assertIn("mode 700", hubsetup.agent_users.__doc__ or "")

    def test_an_agent_name_that_would_not_fit_is_refused(self):
        for name, why in (("", "no agent name"), ("Manager", "no agent name"), ("a", "no agent name"),
                          ("x" * 27, "longer than the 32 characters")):
            with self.assertRaises(hubsetup.Stop) as stopped:
                hubsetup.agent_user(name)
            self.assertIn(why, str(stopped.exception), name)
        self.assertEqual(hubsetup.agent_user("x" * 26), "fleet-" + "x" * 26)

    def test_the_command_reads_the_team_json_it_is_given(self):
        tmp = Path(tempfile.mkdtemp(prefix="fleet-agent-users-"))
        self.addCleanup(shutil.rmtree, str(tmp), True)
        team = tmp / "team.json"
        first = hubsetup.template(HUB_IP, owner="100.90.3.4", placed=False)
        team.write_text(json.dumps(first))
        done = subprocess.run([sys.executable, str(KIT / "hubsetup.py"), "agent-users", "--team", str(team),
                               "--check"], capture_output=True, text=True, timeout=120,
                              stdin=subprocess.DEVNULL)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("gives the machine hub no agent yet", done.stdout)       # a new fleet's manager has no server
        del first["agents"]["manager"]["placed"]                              # a hub from before keeps it here
        team.write_text(json.dumps(first))
        done = subprocess.run([sys.executable, str(KIT / "hubsetup.py"), "agent-users", "--team", str(team),
                               "--check"], capture_output=True, text=True, timeout=120,
                              stdin=subprocess.DEVNULL)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("would make the user fleet-manager for the agent manager", done.stdout)
        team.write_text("not a team.json")
        done = subprocess.run([sys.executable, str(KIT / "hubsetup.py"), "agent-users", "--team", str(team),
                               "--check"], capture_output=True, text=True, timeout=120,
                              stdin=subprocess.DEVNULL)
        self.assertEqual(done.returncode, 1)
        self.assertIn("is not a team.json the hub can run", done.stderr)

    def test_with_no_machine_it_lists_the_agents_of_the_hubs_machine_whatever_it_is_called(self):
        """hub.sh lists the hub's own agents with no --machine: the hub's machine takes its name in Tailscale. A new
        fleet's manager has no server, so a new hub lists none (and hub.sh says so); a hub from before lists its
        own manager."""
        tmp = Path(tempfile.mkdtemp(prefix="fleet-agent-list-"))
        self.addCleanup(shutil.rmtree, str(tmp), True)
        team = tmp / "team.json"
        renamed = hub.renamed_machine_team(hubsetup.template(HUB_IP, owner="100.90.3.4", placed=False), "hub",
                                           "worker-2")
        for placed, listed in ((False, []), (None, ["manager"])):
            if placed is None:
                del renamed["agents"]["manager"]["placed"]
            hub.validate_team(renamed)          # the rename keeps an unplaced manager on the hub's machine
            team.write_text(json.dumps(renamed))
            done = subprocess.run([sys.executable, str(KIT / "hubsetup.py"), "agent-list", "--team", str(team)],
                                  capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
            self.assertEqual((done.returncode, done.stdout.split()[:1]), (0, listed), done.stderr)

    def test_the_installers_make_the_users_from_the_team_json_of_the_fleet(self):
        """Both installers call the one command, with the machine whose agents they are."""
        self.assertIn("hubsetup.py\" agent-users --team \"$kit/team.json\" \\\n", SCRIPT.read_text())   # its machine
        join = (KIT / "join.sh").read_text()
        self.assertIn('hubsetup.py" agent-users --team "$1/team.json" --machine "$name"', join)
        self.assertNotIn("useradd", shell_function(KIT / "join.sh", "mac"),
                         "a Mac agent's service is a LaunchAgent of a desktop session, so a Mac keeps one user")


class FleetId(unittest.TestCase):
    """This fleet's own id (PRODUCT.md 4.2): sixteen hex characters in the hub's key store, made by the installer
    once and never again, because a second id would orphan the fleet's subscription. The records are a temporary
    SQLite file with the hub's own schema; no hub runs."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-id-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.db = self.tmp / "pilot.db"

    def store(self, schema=True):
        made = sqlite3.connect(str(self.db))
        if schema:
            made.executescript(hub.SCHEMA)
        made.close()
        return str(self.db)

    def test_the_installer_makes_one_id_and_never_a_second(self):
        path = self.store()
        first = hubsetup.keep_fleet_id(path)
        self.assertRegex(first, r"^[0-9a-f]{16}$")
        self.assertEqual(hubsetup.keep_fleet_id(path), first, "a second run made another id")
        kept = sqlite3.connect(path)
        self.assertEqual(kept.execute("SELECT v FROM kv WHERE k='fleet_id'").fetchall(), [(first,)])
        kept.close()

    def test_it_is_the_id_the_hub_and_the_app_read(self):
        """The same key of the same store the hub's own fleet_id() reads, so the app and we agree on one id."""
        path = self.store()
        made = hubsetup.keep_fleet_id(path)
        hub.DB = sqlite3.connect(path)
        hub.DB.row_factory = sqlite3.Row
        try:
            self.assertEqual((hub.kv_get("fleet_id"), hub.fleet_id()), (made, made))
        finally:
            hub.DB.close()
            hub.DB = None

    def test_the_id_says_nothing_about_its_owner(self):
        """It is made of random bytes (releases.new_fleet_id), so no address, name or account is in it."""
        import releases
        self.assertRegex(releases.new_fleet_id(), r"^[0-9a-f]{16}$")
        path = self.store()
        with patch.object(releases, "new_fleet_id", return_value="0123456789abcdef") as asked:
            self.assertEqual(hubsetup.keep_fleet_id(path), "0123456789abcdef")
        self.assertEqual(asked.call_count, 1)
        team = json.dumps(hubsetup.template(HUB_IP, owner="100.90.3.4"))
        self.assertNotIn("0123456789abcdef", team)

    def test_it_says_what_is_wrong_when_the_hub_keeps_no_records(self):
        with self.assertRaises(hubsetup.Stop) as stopped:
            hubsetup.keep_fleet_id(str(self.db))
        self.assertIn("keeps no records", str(stopped.exception))
        self.assertFalse(self.db.exists(), "it made an empty records file")
        self.store(schema=False)
        with self.assertRaises(hubsetup.Stop) as stopped:
            hubsetup.keep_fleet_id(str(self.db))
        self.assertIn("could not be kept", str(stopped.exception))

    def test_the_installer_claims_no_entitlement(self):
        """A claim key works once, so the claim has exactly one caller and that is the app (PRODUCT.md 4.5). An
        installer that claimed too would leave the customer with a key that has to be re-issued."""
        for script in (SCRIPT, KIT / "join.sh", KIT / "hubsetup.py"):
            text = script.read_text()
            # Not "/releases" itself: a Mac's join reads /releases/app, the Mac build's manifest that every Mac's
            # vault updater reads with the fleet's id alone, for its signed vault (join.sh mac_vault). That is no
            # claim; the claim is POST /api/entitlement/claim, and the hub's own check is /releases/latest.
            for word in ("claim_key", "claim-key", "/releases/latest", "entitlement/"):
                self.assertNotIn(word, text, f"{script.name} would claim a subscription")
            for line in text.splitlines():           # a command, not a line that only says something
                if any(word in line for word in ("curl ", "hubsetup.py", "fleet.py ", "urlopen")) \
                        and not line.lstrip().startswith(("#", "plan ", "say ", '"""')):
                    self.assertNotIn("entitlement", line, f"{script.name} runs a claim: {line.strip()}")
        self.assertIn("claim no entitlement with it", SCRIPT.read_text())
        self.assertIn("claims no entitlement", hubsetup.keep_fleet_id.__doc__)
        self.assertIn("one caller", hubsetup.keep_fleet_id.__doc__)

    def test_a_joining_machine_makes_no_fleet_id(self):
        """A fleet is one hub and its machines, so the id belongs to the hub and to no machine that joins it."""
        self.assertNotIn("fleet-id", (KIT / "join.sh").read_text())

    def test_the_step_comes_after_the_hub_answers(self):
        """The hub writes its records when it starts, so the id is kept after the end checks proved it answers."""
        main = shell_function(SCRIPT, "main")
        steps = [line.strip() for line in main.splitlines() if re.fullmatch(r" {4}[a-z_]+", line)]
        self.assertEqual(steps[steps.index("checks") + 1], "fleet_identity")


class VerifyStep(unittest.TestCase):
    """The last step of both installers is `python3 fleet.py verify` (PRODUCT.md 4.1), and its lines are printed, so
    an install that half worked says which check failed instead of looking finished."""

    def test_the_hub_installer_ends_with_verify_and_prints_its_lines(self):
        code, out = run_shell(shell_function(SCRIPT, "verify_step") + "\nverify_step\n",
                              extra='as_user() { shift 2; printf "  ok    disk: room\\nREADY\\n"; }\n')
        self.assertEqual(code, 0, out)
        self.assertIn("ok    disk: room", out)
        self.assertIn("READY", out)
        self.assertIn("this machine of the fleet is healthy", out)

    def test_a_failing_check_makes_the_installer_say_so_and_end_with_a_failure(self):
        for script, who in ((SCRIPT, "as_user"), (KIT / "join.sh", "as_worker")):
            body = shell_function(script, "verify_step")
            call = "verify_step\n" if script == SCRIPT else "verify_step /kit as_worker\n"
            code, out = run_shell(body + "\n" + call + '[ "$ready" = yes ] || exit 1\n',
                                  extra='%s() { shift 2; printf "  fail  services: The hub is not running.  '
                                        '(fix: Start it again on this server.)  (run: systemctl --user restart '
                                        'fleet-hub)\\nNOT READY: services\\n"; return 1; }\n' % who)
            self.assertEqual(code, 1, out)
            self.assertIn("NOT READY: services", out)
            self.assertIn("(fix: Start it again on this server.)  (run: systemctl --user restart fleet-hub)", out)
            self.assertIn("NOT ready", out)

    def test_the_apps_word_leaves_verify_to_the_app_and_the_log_still_says_ready(self):
        """FLEET_VERIFY=caller is the word of an app whose own next step is verify: the installer runs none, so the
        self-test runs one time, and its log still holds the READY that the app waits for."""
        code, out = run_shell(shell_function(SCRIPT, "verify_step") + '\nverify_step\n[ "$ready" = yes ] || exit 1\n',
                              extra='caller_verifies=yes\nas_user() { echo "verify ran"; return 1; }\n')
        self.assertEqual(code, 0, out)
        self.assertNotIn("verify ran", out)
        self.assertIn("READY", out)
        self.assertNotIn("NOT", out)
        text = SCRIPT.read_text()
        self.assertIn('if [ "${FLEET_VERIFY:-}" = caller ]; then caller_verifies=yes; fi', text)
        self.assertIn("caller_verifies=no ", text)                  # without the word it ends with verify, as before

    def test_the_installers_check_step_leaves_the_self_test_to_verify(self):
        """`checks` ran selftest.py and verify ran it again, about a minute each: the step now reads only /health."""
        self.assertIn('--kit "$kit" --no-selftest', shell_function(SCRIPT, "checks"))
        with patch.object(hubsetup, "selftest", side_effect=AssertionError("the self-test ran")), \
                patch.object(hubsetup, "health", return_value=(True, "manager")), \
                contextlib.redirect_stdout(io.StringIO()) as said:
            hubsetup.main(["check", "--address", "100.64.0.1", "--no-selftest"])
        self.assertNotIn("selftest.py", said.getvalue())
        with patch.object(hubsetup, "selftest", return_value=(True, "passed 3 of 3")) as ran, \
                patch.object(hubsetup, "health", return_value=(True, "manager")), \
                contextlib.redirect_stdout(io.StringIO()) as said:
            hubsetup.main(["check", "--address", "100.64.0.1"])
        self.assertEqual(ran.call_count, 1)
        self.assertIn("selftest.py: passed 3 of 3", said.getvalue())

    def test_verify_is_the_last_step_of_the_hub_installer(self):
        main = shell_function(SCRIPT, "main")
        steps = [line.strip() for line in main.splitlines() if re.fullmatch(r" {4}[a-z_]+", line)]
        self.assertEqual(steps[-1], "done_text")
        self.assertEqual(steps[-2], "verify_step")
        self.assertEqual(steps[steps.index("first_team") + 1], "agent_helper")
        self.assertEqual(steps[steps.index("agent_helper") + 1], "agent_users")
        self.assertEqual(steps[steps.index("services") + 1], "agents")
        self.assertIn('[ "$ready" = yes ] || exit 1', main)

    def test_the_join_script_ends_both_kinds_of_machine_with_verify(self):
        join = (KIT / "join.sh").read_text()
        for kind in ("linux", "mac"):
            body = shell_function(KIT / "join.sh", kind)
            self.assertIn("verify_step", body, kind)
            lines = [line for line in body.splitlines() if "verify_step" in line or "say \"done." in line]
            self.assertTrue(lines[0].strip().startswith("verify_step"), lines)
        self.assertIn('[ "$ready" = yes ] || exit 1', shell_function(KIT / "join.sh", "main"))
        self.assertIn('git clone -q -b config "$REPO"', join, "a machine's checkout stands on the configuration ref")


# A stand-in for ufw, as the firewall script uses it: its state in a JSON file, its rules numbered as ufw numbers them
# (the IPv4 rules first, then the IPv6 ones), and the comment at the end of a rule's line.
FAKE_UFW = r"""#!/usr/bin/env python3
import json, os, sys
path = os.environ["UFW_STATE"]
state = json.load(open(path))
args = [a for a in sys.argv[1:] if a != "--force"]
state.setdefault("log", []).append(" ".join(sys.argv[1:]))

def save():
    json.dump(state, open(path, "w"))

def line(rule):
    six = " (v6)" if rule["v6"] else ""
    text = "%-26s %-11s %s" % (rule["to"] + six, "ALLOW IN", "Anywhere" + six)
    return text + ("   # " + rule["comment"] if rule.get("comment") else "")

if args[0] == "status":
    if not state["active"]:
        print("Status: inactive")
    else:
        print("Status: active")
        if "verbose" in args:
            print("Default: %s (incoming), allow (outgoing), disabled (routed)" % state["incoming"])
        print()
        print("     To                         Action      From")
        print("     --                         ------      ----")
        for n, rule in enumerate(state["rules"], 1):
            print(("[%2d] " % n if "numbered" in args else "") + line(rule))
elif args[0] == "default":
    state[args[2]] = args[1]
elif args[0] == "allow":
    comment = args[args.index("comment") + 1] if "comment" in args else ""
    to = "Anywhere on tailscale0" if args[1:4] == ["in", "on", "tailscale0"] else args[1]
    for six in (False, True):
        rule = {"to": to, "v6": six, "comment": comment}
        if rule not in state["rules"]:
            at = len(state["rules"]) if six else len([r for r in state["rules"] if not r["v6"]])
            state["rules"].insert(at, rule)
elif args[0] == "delete":
    del state["rules"][int(args[1]) - 1]
elif args[0] == "enable":
    state["active"] = True
save()
"""


# `ss -H -ltnup` as root on a VPS that serves a website with its firewall off: nginx on 80 and 443, an app on 8080 on
# both stacks and Tailscale's own port, beside what must not open: sshd (on its own and as the socket that systemd
# holds for it), loopback, the resolver, a DHCP client, the hub on its Tailscale address, an IPv6 link-local and a
# Tailscale address, and loopback seen through IPv6.
SS_ON_A_USED_VPS = """\
udp   UNCONN 0      0           127.0.0.53%lo:53         0.0.0.0:*    users:(("systemd-resolve",pid=568,fd=13))
udp   UNCONN 0      0      116.203.1.2%eth0:68         0.0.0.0:*    users:(("systemd-network",pid=541,fd=22))
udp   UNCONN 0      0     [fe80::9400:ff:fe12:3456]%eth0:546      [::]:*    users:(("systemd-network",pid=541,fd=24))
udp   UNCONN 0      0               0.0.0.0:41641      0.0.0.0:*    users:(("tailscaled",pid=1203,fd=12))
tcp   LISTEN 0      4096          127.0.0.53%lo:53         0.0.0.0:*    users:(("systemd-resolve",pid=568,fd=14))
tcp   LISTEN 0      4096              0.0.0.0:22         0.0.0.0:*    users:(("systemd",pid=1,fd=103))
tcp   LISTEN 0      511               0.0.0.0:80         0.0.0.0:*    users:(("nginx",pid=1400,fd=6),("nginx",pid=1401,fd=6))
tcp   LISTEN 0      128             127.0.0.1:5432       0.0.0.0:*    users:(("postgres",pid=900,fd=7))
tcp   LISTEN 0      4096           100.90.1.2:8765       0.0.0.0:*    users:(("python3",pid=2000,fd=5))
tcp   LISTEN 0      4096                 [::]:22            [::]:*    users:(("sshd",pid=1000,fd=4))
tcp   LISTEN 0      511                  [::]:443           [::]:*    users:(("nginx",pid=1400,fd=8))
tcp   LISTEN 0      4096                    *:8080             *:*    users:(("app",pid=3000,fd=9))
tcp   LISTEN 0      4096   [fd7a:115c:a1e0::1]:8765          [::]:*    users:(("python3",pid=2000,fd=6))
tcp   LISTEN 0      128    [::ffff:127.0.0.1]:6379          [::]:*    users:(("redis-server",pid=950,fd=6))
"""


class Firewall(unittest.TestCase):
    """hubsetup.py firewall: incoming traffic over the private network only, SSH included. Both installers call it as
    their firewall step, and a machine that an earlier installer set up takes it once, as root, in its own checkout.
    The script itself runs here against a stand-in ufw, so the rules it leaves are read and not guessed."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-firewall-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        (self.tmp / "bin").mkdir()
        ufw = self.tmp / "bin" / "ufw"
        ufw.write_text(FAKE_UFW)
        ufw.chmod(0o755)
        self.state = self.tmp / "ufw.json"
        self.ran = []
        self.listening, self.ssh_ports = "", ""

    def machine(self, active, rules, incoming="allow"):
        self.state.write_text(json.dumps({"active": active, "incoming": incoming, "outgoing": "allow",
                                          "rules": rules}))

    def rule(self, to, comment="", six=False):
        return {"to": to, "v6": six, "comment": comment}

    def run_on_machine(self, address="100.90.1.2", backend="Running", status_json=None):
        """The machine's shell. Its Tailscale gives `address` and is in the state `backend`, as Tailscale 1.104.6 does
        it (cmd/tailscale/cli/status.go): plain `status` ends with 1 in each state but Running and Starting, and
        `status --json` ends with 0 in each state and names it in BackendState, or prints `status_json`."""
        def run(script, timeout=120):
            self.ran.append(script)
            if script.startswith("tailscale ip -4"):
                return 0, address, ""
            if script.startswith("tailscale status --json"):
                if status_json is not None:
                    return 0, status_json, ""
                return 0, json.dumps({"Version": "1.104.6", "BackendState": backend}, indent=2), ""
            if script.startswith("tailscale status"):
                return (0, "", "") if backend in ("Running", "Starting") else (1, "", "")
            if script.startswith("ss -H"):
                return 0, self.listening, ""
            if script.startswith("sshd -T"):
                return 0, self.ssh_ports, ""
            env = dict(os.environ, PATH=f"{self.tmp / 'bin'}:{os.environ['PATH']}", UFW_STATE=str(self.state))
            done = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=60, env=env)
            return done.returncode, done.stdout.strip(), done.stderr.strip()
        return run

    def left(self):
        return json.loads(self.state.read_text())

    def test_a_new_machine_lets_in_the_private_network_and_no_public_ssh(self):
        self.machine(False, [])
        with contextlib.redirect_stdout(io.StringIO()) as said:
            self.assertEqual(hubsetup.firewall(run=self.run_on_machine()), "set")
        state = self.left()
        self.assertTrue(state["active"])
        self.assertEqual(state["incoming"], "deny")
        self.assertEqual(state["rules"], [self.rule("Anywhere on tailscale0", "fleet tailscale"),
                                          self.rule("Anywhere on tailscale0", "fleet tailscale", six=True)])
        self.assertFalse(any("/tcp" in line for line in state["log"]), state["log"])
        self.assertIn("SSH included, at 100.90.1.2", said.getvalue())

    def test_the_public_ssh_rule_of_an_earlier_installer_goes_and_every_other_rule_stays(self):
        """The rules as his machines held them on 2 November 2026, with a rule of the owner's own that names port 22
        too: only the two lines with the installers' comment go, IPv4 and IPv6."""
        mine = [self.rule("41641/udp"), self.rule("22/tcp", "fleet ssh"),
                self.rule("Anywhere on tailscale0", "fleet tailscale"), self.rule("22/tcp")]
        self.machine(True, mine + [dict(r, v6=True) for r in mine], incoming="deny")
        with contextlib.redirect_stdout(io.StringIO()) as said:
            hubsetup.firewall(run=self.run_on_machine())
        rules = self.left()["rules"]
        self.assertNotIn("fleet ssh", [r["comment"] for r in rules])
        self.assertEqual([r for r in rules if not r["v6"]], [self.rule("41641/udp"),
                                                            self.rule("Anywhere on tailscale0", "fleet tailscale"),
                                                            self.rule("22/tcp")])
        self.assertEqual(len(rules), 6)
        self.assertNotIn("default deny incoming", " ".join(self.left()["log"]), "an active firewall keeps its defaults")
        self.assertIn("removed (2 lines)", said.getvalue())

    def test_a_second_run_changes_nothing(self):
        self.machine(False, [])
        with contextlib.redirect_stdout(io.StringIO()):
            hubsetup.firewall(run=self.run_on_machine())
            first = self.left()["rules"]
            hubsetup.firewall(run=self.run_on_machine())
        self.assertEqual(self.left()["rules"], first)

    def test_the_ports_that_answer_from_the_internet_are_read_and_ssh_is_not(self):
        self.assertEqual(hubsetup.public_listeners(SS_ON_A_USED_VPS), ["80/tcp", "443/tcp", "8080/tcp", "41641/udp"])
        moved = SS_ON_A_USED_VPS + 'tcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("systemd",pid=1,fd=110))\n'
        self.assertIn("2222/tcp", hubsetup.public_listeners(moved))
        self.assertNotIn("2222/tcp", hubsetup.public_listeners(moved, ssh_ports={"22", "2222"}),
                         "SSH on a port of its own, which `sshd -T` names, moves to the private network too")
        self.assertEqual(hubsetup.public_listeners(""), [])

    def test_a_firewall_that_was_off_keeps_the_website_and_moves_only_ssh(self):
        """A VPS that a customer already uses, with its firewall off: what answered from the internet before the
        install still answers after it, and SSH answers over the private network only (the owner, 4 November 2026,
        of adding a VPS: "it needs to work")."""
        self.machine(False, [])
        self.listening = SS_ON_A_USED_VPS
        with contextlib.redirect_stdout(io.StringIO()) as said:
            self.assertEqual(hubsetup.firewall(run=self.run_on_machine()), "set")
        state = self.left()
        self.assertTrue(state["active"])
        self.assertEqual(state["incoming"], "deny")
        self.assertCountEqual([r for r in state["rules"] if not r["v6"]],
                              [self.rule("80/tcp", "fleet kept"), self.rule("443/tcp", "fleet kept"),
                               self.rule("8080/tcp", "fleet kept"), self.rule("41641/udp", "fleet kept"),
                               self.rule("Anywhere on tailscale0", "fleet tailscale")])
        self.assertNotIn("22/tcp", [r["to"] for r in state["rules"]])
        self.assertIn("these ports stay open as they were: 80/tcp, 443/tcp, 8080/tcp, 41641/udp", said.getvalue())

    def test_an_active_firewall_keeps_its_own_rules_and_gets_no_kept_port(self):
        self.machine(True, [self.rule("22/tcp")], incoming="deny")
        self.listening = SS_ON_A_USED_VPS
        with contextlib.redirect_stdout(io.StringIO()) as said:
            hubsetup.firewall(run=self.run_on_machine())
        rules = self.left()["rules"]
        self.assertNotIn("fleet kept", [r["comment"] for r in rules])
        self.assertEqual([r for r in rules if not r["v6"]], [self.rule("22/tcp"),
                                                            self.rule("Anywhere on tailscale0", "fleet tailscale")])
        self.assertNotIn("stay open", said.getvalue())

    def test_the_check_names_the_ports_that_a_firewall_that_is_off_keeps(self):
        self.machine(False, [])
        self.listening = SS_ON_A_USED_VPS
        before = self.state.read_text()
        with contextlib.redirect_stdout(io.StringIO()) as said:
            self.assertEqual(hubsetup.firewall(check=True, run=self.run_on_machine()), "would set")
        self.assertEqual(self.state.read_text(), before)
        self.assertIn("keeps open the ports that answer now: 80/tcp, 443/tcp, 8080/tcp, 41641/udp", said.getvalue())

    def test_the_script_takes_a_port_and_its_protocol_and_nothing_else(self):
        for bad in ("80/tcp; reboot", "80", "http", "99999999/tcp"):
            with self.assertRaises(ValueError):
                hubsetup.firewall_script([bad])

    def test_a_rule_that_an_inactive_firewall_kept_does_not_come_back_on(self):
        """ufw lists no rule while it is off, so the public rule is looked for after the firewall is on."""
        self.machine(False, [self.rule("22/tcp", "fleet ssh"), self.rule("22/tcp", "fleet ssh", six=True)])
        with contextlib.redirect_stdout(io.StringIO()):
            hubsetup.firewall(run=self.run_on_machine())
        self.assertNotIn("fleet ssh", [r["comment"] for r in self.left()["rules"]])

    def test_a_machine_off_the_private_network_keeps_its_firewall(self):
        """A firewall that lets SSH in over Tailscale alone would leave no way into a machine that is not on it."""
        self.machine(True, [self.rule("22/tcp", "fleet ssh")], incoming="deny")
        before = self.state.read_text()
        for address in ("", "203.0.113.9", "10.0.0.4"):
            with self.assertRaises(hubsetup.Stop) as stop:
                hubsetup.firewall(run=self.run_on_machine(address))
            self.assertIn("not on the private network", str(stop.exception))
        self.assertEqual(self.state.read_text(), before)
        self.assertTrue(all(script.startswith("tailscale ip -4") for script in self.ran))

    def stops_before_the_firewall(self, words, **tailscale):
        """The firewall step, with and without --check, on a machine with the public SSH rule and the given Tailscale:
        each run stops with `words`, changes nothing, and runs only Tailscale's reads."""
        self.machine(True, [self.rule("22/tcp", "fleet ssh"), self.rule("22/tcp", "fleet ssh", six=True)],
                     incoming="deny")
        before = self.state.read_text()
        for check in (False, True):
            with self.subTest(check=check, **tailscale):
                self.ran = []
                with contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(hubsetup.Stop) as stop:
                        hubsetup.firewall(check=check, run=self.run_on_machine(**tailscale))
                self.assertIn(words, str(stop.exception))
                self.assertEqual(self.state.read_text(), before)
                self.assertTrue(all(script.startswith("tailscale ") for script in self.ran), self.ran)

    def test_a_machine_that_waits_for_an_admins_approval_keeps_its_firewall(self):
        """**An address alone is no proof of the private network.** Tailscale gives a machine its address also while
        the machine waits for an admin of the tailnet to approve it (NeedsMachineAuth), and nothing on the private
        network reaches it until then. Until 11 November 2026 the address was the only proof: on such a machine the
        firewall let SSH in over tailscale0 only and removed the public SSH rule, so no new SSH session could come in.
        Now `tailscale status` must also succeed, as in the installers' network steps, and the stop names the
        approval. A machine whose Tailscale stopped or has no login keeps its firewall too, and the stop names the
        state."""
        self.stops_before_the_firewall("waits for an admin to approve it in the fleet's Tailscale admin console",
                                       backend="NeedsMachineAuth")
        for backend in ("Stopped", "NeedsLogin"):
            self.stops_before_the_firewall("not on the private network (tailscale status failed; Tailscale's state is "
                                           f"{backend}), so", backend=backend)

    def test_a_status_that_names_no_state_keeps_the_firewall_with_the_usual_words(self):
        """A `tailscale status --json` that gives no JSON object (no text, null, a list, cut JSON) names no state. The
        step stops with the usual words, and with no traceback."""
        for text in ("", "null", '["BackendState", "NeedsMachineAuth"]', '{"BackendState": "NeedsMach'):
            self.stops_before_the_firewall("not on the private network (tailscale status failed), so",
                                           backend="NeedsMachineAuth", status_json=text)

    def test_the_check_says_what_it_would_do_and_changes_nothing(self):
        self.machine(True, [self.rule("22/tcp", "fleet ssh")], incoming="deny")
        before = self.state.read_text()
        with contextlib.redirect_stdout(io.StringIO()) as said:
            self.assertEqual(hubsetup.firewall(check=True, run=self.run_on_machine()), "would set")
        self.assertEqual(self.state.read_text(), before)
        self.assertIn("remove the public SSH rule", said.getvalue())

    def test_a_script_that_fails_stops_the_installer_with_its_words(self):
        def run(script, timeout=120):
            return (0, "100.90.1.2", "") if script.startswith("tailscale") else (1, "", "ERROR: You need to be root")
        with self.assertRaises(hubsetup.Stop) as stop:
            hubsetup.firewall(run=run)
        self.assertIn("You need to be root", str(stop.exception))

    def test_both_installers_take_it_as_their_firewall_step_and_add_no_public_rule(self):
        join = shell_function(KIT / "join.sh", "firewall")
        self.assertIn('python3 "$1/hubsetup.py" firewall', join)
        self.assertIn('firewall "/home/$WORKER/fleet-server"', shell_function(KIT / "join.sh", "linux"))
        self.assertIn('python3 "$tree/hubsetup.py" firewall', shell_function(SCRIPT, "firewall"))
        for script in (SCRIPT, KIT / "join.sh", KIT / "hubsetup.py", KIT / "onboard.py"):
            self.assertNotRegex(script.read_text(), r"ufw allow [^\n]*/tcp",
                                f"{script.name} still opens a TCP port to the whole internet")
            self.assertNotRegex(script.read_text(), r"comment 'fleet ssh'", script.name)

    def test_the_hub_installer_still_records_its_ssh_port(self):
        """team.json keeps the SSH port of the hub's machine for the app's connection, read where it is used."""
        body = shell_function(SCRIPT, "first_team")
        self.assertIn("sshd -T", body)
        self.assertIn('--ssh-port "$(printf', body)


class Harden(unittest.TestCase):
    """hubsetup.py harden, the join's step after its firewall (the owner, 3 November 2026: Add server ends at the
    baseline, for any user): SSH takes keys only with no X11 forwarding, npm takes no package version newer than seven
    days, and Tailscale updates itself. Its files are written under a folder of the test's own, and its commands
    answer from a stand-in, so what it leaves is read and not guessed."""

    KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyOfTheOwnerForThisTest owner@mac\n"
    HARDENED = "passwordauthentication no\nkbdinteractiveauthentication no\nx11forwarding no\npermitrootlogin " \
               "prohibit-password\n"

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="fleet-harden-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        (self.root / "etc/ssh/sshd_config.d").mkdir(parents=True)
        (self.root / "root/.ssh").mkdir(parents=True)
        (self.root / "root/.ssh/authorized_keys").write_text(self.KEY)
        self.home = self.root / "home/fleet"
        self.home.mkdir(parents=True)
        self.account = (str(self.home)[len(str(self.root)):], os.getuid(), os.getgid())
        self.ran, self.answers = [], {"sshd -T": (0, self.HARDENED, ""),
                                      "systemctl is-active ssh.service ssh.socket": (0, "active\ninactive", "")}

    def run_cmd(self, script, timeout=120):
        self.ran.append(script)
        return self.answers.get(script, (0, "", ""))

    def harden(self, check=False):
        with contextlib.redirect_stdout(io.StringIO()) as said:
            lines = hubsetup.harden(check=check, run=self.run_cmd, root=str(self.root), account=self.account)
        self.assertEqual(said.getvalue().splitlines(), ["Founderizer: " + line for line in lines])
        return lines

    def file(self, path):
        return (self.root / path.lstrip("/")).read_text()

    def mode(self, path):
        return (self.root / path.lstrip("/")).stat().st_mode & 0o777

    def test_a_new_server_takes_keys_only_npms_seven_days_and_tailscales_own_updates(self):
        lines = self.harden()
        self.assertEqual(self.file(hubsetup.SSHD_HARDENING), hubsetup.SSHD_TEXT)
        self.assertEqual(self.mode(hubsetup.SSHD_HARDENING), 0o644)
        for setting in ("PasswordAuthentication no", "KbdInteractiveAuthentication no", "X11Forwarding no"):
            self.assertIn(setting + "\n", hubsetup.SSHD_TEXT)
        self.assertEqual(self.ran, ["systemctl is-active ssh.service ssh.socket", "sshd -t",
                                    "systemctl try-reload-or-restart ssh.service", "sshd -T",
                                    "tailscale set --auto-update"])
        # The bytes that the owner's devops repository pins for /etc/npmrc (trust-anchors.tsv of its workers)
        self.assertEqual(hashlib.sha256((self.root / "etc/npmrc").read_bytes()).hexdigest(),
                         "519276feb13d043ab3c200e50cbc4136fc84c243d8cc74342afde0ce22fa502c")
        self.assertEqual(self.mode("/etc/npmrc"), 0o644)
        self.assertEqual(self.file("/home/fleet/.npmrc"), "min-release-age=7\n")
        self.assertEqual(self.mode("/home/fleet/.npmrc"), 0o600)
        self.assertEqual(lines, ["SSH takes keys only, with no X11 forwarding",
                                 "made npm take no package version newer than seven days (/etc/npmrc, "
                                 "/home/fleet/.npmrc)",
                                 "Tailscale updates itself"])

    def test_a_second_run_writes_nothing_new(self):
        self.harden()
        before = {p: self.file(p) for p in (hubsetup.SSHD_HARDENING, "/etc/npmrc", "/home/fleet/.npmrc")}
        self.ran.clear()
        lines = self.harden()
        self.assertEqual({p: self.file(p) for p in before}, before)
        self.assertNotIn("sshd -t", self.ran, "an unchanged file needs no new check")
        self.assertEqual(lines[1], "npm takes no package version newer than seven days already")

    def test_a_server_where_no_account_has_an_ssh_key_keeps_password_login(self):
        (self.root / "root/.ssh/authorized_keys").write_text("# no key here\n\n")
        lines = self.harden()
        self.assertFalse((self.root / hubsetup.SSHD_HARDENING.lstrip("/")).exists())
        self.assertNotIn("sshd -t", self.ran)
        self.assertIn("SSH keeps password login: no account on this server has an SSH key", lines[0])
        self.assertEqual(self.file("/etc/npmrc"), "min-release-age=7\n", "npm's rule does not wait for SSH")
        (self.root / "home/admin/.ssh").mkdir(parents=True)
        (self.root / "home/admin/.ssh/authorized_keys").write_text(self.KEY)
        self.assertEqual(self.harden()[0], "SSH takes keys only, with no X11 forwarding", "a user's key counts too")

    def test_a_server_whose_openssh_does_not_run_gets_no_file_for_it(self):
        """A server that Tailscale's own SSH serves has OpenSSH masked: no password lets anybody in through it, and
        `sshd -t` fails there for want of the folder that its service makes."""
        self.answers["systemctl is-active ssh.service ssh.socket"] = (3, "inactive\ninactive", "")
        lines = self.harden()
        self.assertFalse((self.root / hubsetup.SSHD_HARDENING.lstrip("/")).exists())
        self.assertNotIn("sshd -t", self.ran)
        self.assertEqual(lines[0], "SSH: OpenSSH does not run on this server, so no password lets anybody in through it")
        self.assertEqual(self.file("/etc/npmrc"), "min-release-age=7\n")

    def test_a_file_that_sshd_refuses_is_taken_back(self):
        old = "# the owner's own\nX11Forwarding no\n"
        (self.root / hubsetup.SSHD_HARDENING.lstrip("/")).write_text(old)
        self.answers["sshd -t"] = (255, "", "/etc/ssh/sshd_config.d/10-fleet-hardening.conf line 2: Bad configuration")
        lines = self.harden()
        self.assertEqual(self.file(hubsetup.SSHD_HARDENING), old)
        self.assertNotIn("systemctl try-reload-or-restart ssh.service", self.ran)
        self.assertIn("SSH keeps its settings: sshd refused the new file", lines[0])
        (self.root / hubsetup.SSHD_HARDENING.lstrip("/")).unlink()
        self.harden()
        self.assertFalse((self.root / hubsetup.SSHD_HARDENING.lstrip("/")).exists(), "a new file goes again")

    def test_an_earlier_file_that_lets_passwords_in_is_said_and_not_hidden(self):
        self.answers["sshd -T"] = (0, self.HARDENED.replace("passwordauthentication no", "passwordauthentication yes"),
                                   "")
        self.assertEqual(self.harden()[0], "SSH does not take keys only yet: an earlier file of sshd sets "
                                           "passwordauthentication")

    def test_an_npm_file_of_the_owners_own_keeps_its_lines_and_its_own_rule(self):
        (self.root / "etc/npmrc").write_text("registry=https://registry.npmjs.org/")
        (self.root / "etc/npmrc").chmod(0o640)
        (self.root / "home/fleet/.npmrc").write_text("min-release-age = 14\n")
        lines = self.harden()
        self.assertEqual(self.file("/etc/npmrc"), "registry=https://registry.npmjs.org/\nmin-release-age=7\n")
        self.assertEqual(self.mode("/etc/npmrc"), 0o640)
        self.assertEqual(self.file("/home/fleet/.npmrc"), "min-release-age = 14\n")
        self.assertEqual(lines[1], "made npm take no package version newer than seven days (/etc/npmrc)")

    def test_tailscale_that_refuses_its_own_updates_is_said_and_stops_nothing(self):
        self.answers["tailscale set --auto-update"] = (1, "", "auto-updates are not supported on this platform")
        self.assertEqual(self.harden()[2], "Tailscale's own updates stay as they are: auto-updates are not supported "
                                           "on this platform")

    def test_the_check_says_what_it_would_do_and_changes_nothing(self):
        lines = self.harden(check=True)
        self.assertEqual(self.ran, ["systemctl is-active ssh.service ssh.socket"], "it only reads")
        self.assertFalse((self.root / hubsetup.SSHD_HARDENING.lstrip("/")).exists())
        self.assertFalse((self.root / "etc/npmrc").exists())
        self.assertEqual(lines, ["would make SSH take keys only, with no X11 forwarding",
                                 "would make npm take no package version newer than seven days (/etc/npmrc, "
                                 "/home/fleet/.npmrc)",
                                 "would turn on Tailscale's own updates"])

    def test_the_join_takes_it_after_its_firewall_as_the_one_hardening_command(self):
        join = shell_function(KIT / "join.sh", "linux")
        self.assertLess(join.index('firewall "/home/$WORKER/fleet-server"'),
                        join.index('harden "/home/$WORKER/fleet-server"'))
        self.assertIn('python3 "$1/hubsetup.py" harden --user "$WORKER"', shell_function(KIT / "join.sh", "harden"))
        for script in (SCRIPT, KIT / "join.sh"):
            self.assertNotIn("10-fleet-hardening", script.read_text(), f"{script.name} writes sshd's file itself")
            self.assertNotIn("min-release-age", script.read_text(), f"{script.name} writes npm's rule itself")


class HubTcp(unittest.TestCase):
    """hubsetup.py tcp, the hub installer's step before verify (the owner, 10 November 2026: "Yes, every hub"): a kept
    connection keeps its TCP window over an idle time, through one file in /etc/sysctl.d and the kernel's value at
    once. Its files, the kernel's value among them, are under a folder of the test's own, so what it leaves is read."""

    # The bytes that the owner's devops repository records for this file on the hub's server
    # (hosts/<the hub's server>/sysctl.d/60-fleet-hub-tcp.conf): a new text goes there too.
    TEXT_SHA256 = "d2d6220c46433bd37dfcda22ba9d82116152a4bac8b943a02c6131798c01e335"
    DONE = "a kept connection keeps its TCP window over an idle time (net.ipv4.tcp_slow_start_after_idle = 0)"
    ALREADY = "a kept connection keeps its TCP window over an idle time already"

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="fleet-tcp-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        self.live = self.root / hubsetup.HUB_TCP_LIVE.lstrip("/")
        self.live.parent.mkdir(parents=True)
        self.live.write_text("1\n")                         # the kernel's default
        (self.root / "usr/lib/sysctl.d").mkdir(parents=True)
        (self.root / "usr/lib/sysctl.d/50-default.conf").write_text("net.ipv4.conf.default.rp_filter = 2\n")
        self.file = self.root / hubsetup.HUB_TCP.lstrip("/")

    def tcp(self, check=False):
        with contextlib.redirect_stdout(io.StringIO()) as said:
            line = hubsetup.hub_tcp(check=check, root=str(self.root))
        self.assertEqual(said.getvalue(), "Founderizer: " + line + "\n")
        return line

    def own(self, where, text):
        path = self.root / where
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def test_a_new_hub_gets_the_file_and_the_value_at_once(self):
        self.assertFalse((self.root / "etc/sysctl.d").exists(), "a system with no folder for it gets one")
        self.assertEqual(self.tcp(), self.DONE)
        self.assertEqual(self.file.read_text(), hubsetup.HUB_TCP_TEXT)
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.live.read_text().strip(), "0")
        self.assertTrue(hubsetup.HUB_TCP_TEXT.endswith("\nnet.ipv4.tcp_slow_start_after_idle = 0\n"))
        self.assertEqual(hashlib.sha256(hubsetup.HUB_TCP_TEXT.encode()).hexdigest(), self.TEXT_SHA256)

    def test_the_command_takes_check_to_the_step(self):
        for argv, check in ((["tcp", "--check"], True), (["tcp"], False)):
            with patch.object(hubsetup, "hub_tcp") as step:        # the step itself would read this machine
                self.assertEqual(hubsetup.main(argv), 0)
            step.assert_called_once_with(check=check)

    def test_a_second_run_writes_nothing(self):
        self.tcp()
        os.utime(self.file, ns=(1, 1))
        os.utime(self.live, ns=(1, 1))
        self.assertEqual(self.tcp(), self.ALREADY)
        self.assertEqual(self.file.stat().st_mtime_ns, 1)
        self.assertEqual(self.live.stat().st_mtime_ns, 1, "a value that holds is not written again")

    def test_a_value_that_went_back_is_set_again_and_its_file_stays(self):
        self.tcp()
        os.utime(self.file, ns=(1, 1))
        self.live.write_text("1\n")
        self.assertEqual(self.tcp(), self.DONE)
        self.assertEqual(self.live.read_text().strip(), "0")
        self.assertEqual(self.file.stat().st_mtime_ns, 1)

    def test_an_older_text_of_its_own_is_written_again(self):
        self.own(hubsetup.HUB_TCP.lstrip("/"), "net.ipv4.tcp_slow_start_after_idle = 0\n")
        self.live.write_text("0\n")
        self.assertEqual(self.tcp(), self.DONE)
        self.assertEqual(self.file.read_text(), hubsetup.HUB_TCP_TEXT)

    def test_a_setting_of_the_servers_own_decides_and_nothing_is_written(self):
        for where, line in (("etc/sysctl.conf", "net.ipv4.tcp_slow_start_after_idle=1"),
                            ("etc/sysctl.d/99-own.conf", "  - net/ipv4/tcp_slow_start_after_idle = 1"),
                            ("run/sysctl.d/10-boot.conf", "net.ipv4.tcp_slow_start_after_idle\t= 1"),
                            ("usr/local/lib/sysctl.d/30-site.conf", "net.ipv4.tcp_slow_start_after_idle = 1"),
                            ("lib/sysctl.d/70-vendor.conf", "net.ipv4.tcp_slow_start_after_idle = 0")):
            with self.subTest(where=where):
                path = self.own(where, "# the owner's own\n" + line + "\n")
                self.assertEqual(self.tcp(), f"TCP keeps this server's own setting: /{where} sets "
                                             "net.ipv4.tcp_slow_start_after_idle")
                self.assertFalse(self.file.exists())
                self.assertEqual(self.live.read_text(), "1\n")
                self.assertEqual(self.tcp(check=True), self.tcp(), "the check says the same")
                path.unlink()
        self.assertEqual(self.tcp(), self.DONE)

    def test_a_glob_or_a_mark_at_the_start_of_a_file_is_a_setting_too(self):
        for text in ("net.ipv4.tcp_slow*=1\n", "net/ipv4/tcp_*_after_idle = 1\n",
                     "\ufeffnet.ipv4.tcp_slow_start_after_idle = 1\n"):
            with self.subTest(text=text):
                path = self.own("etc/sysctl.d/99-own.conf", text)
                self.assertEqual(self.tcp(), "TCP keeps this server's own setting: /etc/sysctl.d/99-own.conf sets "
                                             "net.ipv4.tcp_slow_start_after_idle")
                self.assertFalse(self.file.exists())
                path.unlink()

    def test_a_vendor_file_that_an_earlier_folder_hides_or_switches_off_is_no_setting(self):
        """systemd-sysctl reads one file of each name, from the first folder that has it: a file of /etc/sysctl.d
        hides the vendor's file of the same name, and a link to /dev/null switches it off."""
        self.own("usr/lib/sysctl.d/50-vendor.conf", "net.ipv4.tcp_slow_start_after_idle = 1\n")
        self.own("usr/lib/sysctl.d/51-vendor.conf", "net.ipv4.tcp_slow_start_after_idle = 1\n")
        self.own("etc/sysctl.d/50-vendor.conf", "net.ipv4.tcp_fin_timeout = 30\n")
        (self.root / "etc/sysctl.d/51-vendor.conf").symlink_to("/dev/null")
        self.assertEqual(self.tcp(), self.DONE)
        self.assertEqual(self.live.read_text().strip(), "0")
        (self.root / "etc/sysctl.d/51-vendor.conf").unlink()
        self.assertEqual(self.tcp(), "TCP keeps this server's own setting: /usr/lib/sysctl.d/51-vendor.conf sets "
                                     "net.ipv4.tcp_slow_start_after_idle, and so does "
                                     "/etc/sysctl.d/60-fleet-hub-tcp.conf of an earlier run; of the two, the file "
                                     "that a start reads last decides", "a vendor file that a start reads counts")
        self.assertEqual(self.file.read_text(), hubsetup.HUB_TCP_TEXT, "no file of its own goes")
        self.file.unlink()
        self.assertEqual(self.tcp(), "TCP keeps this server's own setting: /usr/lib/sysctl.d/51-vendor.conf sets "
                                     "net.ipv4.tcp_slow_start_after_idle")
        self.assertFalse(self.file.exists())

    def test_a_comment_or_another_key_is_no_setting_of_its_own(self):
        self.own("etc/sysctl.d/99-own.conf", "# net.ipv4.tcp_slow_start_after_idle = 1\n"
                                             "; net.ipv4.tcp_slow_start_after_idle = 1\n"
                                             "net.ipv4.tcp_slow_start_after_idle_x = 1\n"
                                             "net.ipv4.tcp_notsent_lowat = 16384\n")
        self.own("etc/sysctl.d/README.sysctl", "net.ipv4.tcp_slow_start_after_idle = 1\n")
        self.assertEqual(self.tcp(), self.DONE, "a file that systemd-sysctl does not read is no setting either")
        self.assertEqual(self.live.read_text().strip(), "0")

    def test_a_server_that_does_not_take_the_value_now_keeps_the_file_for_its_next_start(self):
        self.live.unlink()
        self.live.mkdir()                                   # it cannot be written, as a read-only /proc/sys
        line = self.tcp()
        self.assertEqual(self.file.read_text(), hubsetup.HUB_TCP_TEXT)
        self.assertTrue(line.startswith("this server did not take net.ipv4.tcp_slow_start_after_idle = 0 now ("), line)
        self.assertTrue(line.endswith("): /etc/sysctl.d/60-fleet-hub-tcp.conf sets it at a start where /proc/sys can "
                                      "be written"), line)

    def test_a_value_that_does_not_read_back_as_0_is_said(self):
        self.live.unlink()
        self.live.symlink_to("/dev/null")                   # it takes the write, and reads back nothing
        self.assertEqual(self.tcp(), "this server still reads net.ipv4.tcp_slow_start_after_idle = nothing after the "
                                     "write: /etc/sysctl.d/60-fleet-hub-tcp.conf sets 0 at a start where /proc/sys can "
                                     "be written")
        self.assertEqual(self.file.read_text(), hubsetup.HUB_TCP_TEXT)

    def test_a_folder_that_cannot_be_written_leaves_the_server_as_it_was(self):
        (self.root / "etc").mkdir()
        (self.root / "etc/sysctl.d").write_text("not a folder\n")
        line = self.tcp()
        self.assertTrue(line.startswith("TCP keeps its setting: /etc/sysctl.d/60-fleet-hub-tcp.conf could not be "
                                        "written ("), line)
        self.assertEqual(self.live.read_text(), "1\n")

    def test_the_check_says_what_it_would_do_and_changes_nothing(self):
        self.assertEqual(self.tcp(check=True), "would keep the TCP window of a kept connection over an idle time "
                                               "(net.ipv4.tcp_slow_start_after_idle = 0 in "
                                               "/etc/sysctl.d/60-fleet-hub-tcp.conf)")
        self.assertFalse((self.root / "etc").exists())
        self.assertEqual(self.live.read_text(), "1\n")
        self.tcp()
        self.assertEqual(self.tcp(check=True), self.ALREADY)

    def test_the_hub_installer_takes_it_before_verify_and_goes_on_when_it_fails(self):
        main = shell_function(SCRIPT, "main")
        steps = [line.strip() for line in main.splitlines() if re.fullmatch(r" {4}[a-z_]+", line)]
        self.assertEqual(steps[-4:], ["updates", "tcp_window", "verify_step", "done_text"])
        body = shell_function(SCRIPT, "tcp_window")
        self.assertIn('python3 "$tree/hubsetup.py" tcp </dev/null', body, "root runs the copy it runs from")
        self.assertNotIn("$kit", body, "the hub user's checkout is not root's to run")
        code, out = run_shell(body + "\ntcp_window\nsay went on\n",
                              extra='tree=/tree\npython3() { echo "the stand-in failed"; return 1; }\n')
        self.assertEqual(code, 0, out)
        self.assertIn("Founderizer:   the TCP setting of this hub did not finish: the line above says why", out)
        self.assertIn("Founderizer: went on", out)
        code, out = run_shell(body + "\ntcp_window\n", extra='tree=/tree\npython3() { echo "ran $*"; }\n')
        self.assertEqual((code, out.split("\n")[-2]), (0, "ran /tree/hubsetup.py tcp"))
        for script in (SCRIPT, KIT / "join.sh"):
            self.assertNotRegex(script.read_text(), r"sysctl -w|/proc/sys/|> */etc/sysctl",
                                f"{script.name} sets the value itself")


class NetworkStep(unittest.TestCase):
    """**hub.sh's network step waits for apt's lock before each try of Tailscale's installer, and tries it three times
    at most**, as INSTALL-PROMPT.md A2 and the Mac app's install do. Tailscale's installer runs apt-get with no wait for
    the lock, which the first updates of a new server hold. Until 11 November 2026 the step did not wait: the apt-gets
    of the steps before it wait only when a package is missing, so on a new server the installer stopped at once, and
    so did the install. The step runs as root on a StandInServer that is on the private network already, so it reads
    no key."""

    def network(self, stops, misses=0):
        """The network step on a server with no Tailscale, whose first updates hold the lock of dpkg for 540 seconds
        and stop the next `stops` tries of `apt-get update`, and whose next `misses` tries of curl get no script: the
        server, and how the step ended."""
        server = StandInServer()
        self.addCleanup(server.remove)
        (server.state / "backend").write_text("Running\n")
        server.hold_apt_lock(540)
        server.hold_lists_lock(stops)
        server.fail_curl(misses)
        [wait] = re.findall(r"(?m)^APT_LOCK_WAIT=.*$", SCRIPT.read_text())
        body = ("set -eu\nsay() { printf 'Founderizer: %s\\n' \"$*\"; }\n"
                "stop() { printf 'Founderizer install stopped: %s\\n' \"$*\" >&2; exit 1; }\n"
                "heading() { :; }\nplan() { :; }\ncheck=no\nhostname=\n" + wait + "\n"
                + shell_function(SCRIPT, "network") + "network\n")
        with server.opened():
            return server, server.execute(["/bin/sh", "-c", body], server.env(PATH=f"{server.system}:{server.tools}"))

    def test_it_waits_for_the_lock_of_dpkg_before_it_runs_tailscales_installer(self):
        server, ran = self.network(0)
        self.assertEqual((ran.status, server.has("tailscale"), server.apt_waits(), server.slept()),
                         (0, True, [540], []), ran.out + ran.err)
        self.assertIn("this hub's address is 100.101.102.103", ran.out)

    def test_a_try_that_the_updates_stopped_is_made_again_after_20_seconds(self):
        server, ran = self.network(1)
        self.assertEqual((ran.status, server.has("tailscale"), server.apt_waits(), server.slept()),
                         (0, True, [540], [20]), ran.out + ran.err)

    def test_a_try_that_got_no_script_from_curl_is_made_again(self):
        """`sh` ends with 0 when curl gives it nothing: the try counts only when `tailscale` is there after it."""
        server, ran = self.network(0, misses=1)
        self.assertEqual((ran.status, server.has("tailscale"), server.apt_waits(), server.slept()),
                         (0, True, [540], [20]), ran.out + ran.err)

    def test_when_three_tries_stop_the_install_stops_with_its_words(self):
        server, ran = self.network(3)
        self.assertEqual((ran.status, server.has("tailscale"), server.slept()), (1, False, [20, 20]), ran.out + ran.err)
        self.assertIn("Founderizer install stopped: Could not install Tailscale.", ran.err)

    def keyed(self, approval=False):
        """The network step with the owner's key on standard input, on a server that has Tailscale and is not on the
        private network: the hub's join line ran there before with no key, and its `tailscale up` waited for a
        sign-in that nobody gave. With `approval`, the tailnet holds each new machine until an admin approves it.
        /root/ stands for the server's folder. The server, and how the step ended."""
        server = StandInServer()
        self.addCleanup(server.remove)
        server.give("tailscale")
        tags = "--advertise-tags=tag:fleet,tag:server"
        self.assertIn(tags, server.earlier_up(tags, "--accept-dns=false"))
        if approval:
            server.approve_by_hand()
        waits = "\n".join(re.findall(r"(?m)^(?:APT_LOCK_WAIT|TAILSCALE_UP_WAIT)=.*$", SCRIPT.read_text()))
        body = ("set -eu\nsay() { printf 'Founderizer: %s\\n' \"$*\"; }\n"
                "stop() { printf 'Founderizer install stopped: %s\\n' \"$*\" >&2; exit 1; }\n"
                "heading() { :; }\nplan() { :; }\ncheck=no\nhostname=\n" + waits + "\n"
                + shell_function(SCRIPT, "network").replace("/root/", f"{server.root}/") + "network\n")
        with server.opened():
            ran = server.execute(["/bin/sh", "-c", body], server.env(PATH=f"{server.system}:{server.tools}"),
                                 stdin=server.keyfile)
            left = sorted(path.name for path in server.root.iterdir())
        return server, ran, left

    def test_a_server_that_an_earlier_tailscale_up_left_waiting_joins_with_the_key(self):
        """**`tailscale up` has `--reset`.** The join line's `tailscale up` with no key keeps its settings, its tags
        too, while it waits, and also after it was stopped. Tailscale then refuses a `tailscale up` that does not name
        each of them again, unless it has `--reset`: until 11 November 2026 each new run of the line stopped there, with
        "requires mentioning all non-default flags" (Tailscale 1.104.6 in a Debian 12 container)."""
        server, ran, left = self.keyed()
        self.assertEqual((ran.status, server.given_key(), left), (0, server.KEY, []), ran.out + ran.err)
        self.assertIn("this machine joined the private network", ran.out)
        self.assertIn("this hub's address is 100.101.102.103", ran.out)

    def test_tailscale_up_waits_five_minutes_at_most_for_an_admin_who_must_approve_the_machine(self):
        """**`tailscale up` waits 300 seconds at most.** With no `--timeout` it waits for ever on a tailnet that holds
        each new machine until an admin approves it, and the install waits with it, with no word. Now the step stops
        after 5 minutes with Tailscale's own words, removes the key, and says what to do."""
        server, ran, left = self.keyed(approval=True)
        self.assertEqual((ran.status, server.up_waits(), left), (1, ["300s"], []), ran.out + ran.err)
        self.assertIn("To approve your machine, visit (as admin):", ran.err)
        self.assertIn("timeout waiting for Tailscale service to enter a Running state", ran.err)
        self.assertNotIn("waits here for ever", ran.err)
        self.assertIn("Founderizer install stopped: Tailscale did not join with that auth key. If Tailscale asked you "
                      "to approve this machine, approve it in the fleet's Tailscale admin console.", ran.err)


class AptUpdate(unittest.TestCase):
    """**Each `apt-get update` of the installers is tried again while the lock of the package lists is held.** apt
    reads DPkg::Lock::Timeout only for the lock of dpkg (apt-pkg/deb/debsystem.cc), and `update` takes the lock of the
    lists with one try (apt-pkg/acquire.cc): so it stops at once while the first updates of a new server read their
    lists. hub.sh and join.sh have one function for it, the same in both, which shows the words of its last try only;
    hubsetup.py's age install and onboard.py have one loop each. Until 11 November 2026 none of them tried again. Each
    runs as root on a StandInServer, whose apt-get plays that lock (`hold_lists_lock`)."""

    def run_on(self, text, stops):
        """`text` as root on a new StandInServer whose next `stops` tries of `apt-get update` find the lock of the
        lists held: the server, and how `text` ended."""
        server = StandInServer()
        self.addCleanup(server.remove)
        server.hold_lists_lock(stops)
        with server.opened():
            ran = server.execute(["/bin/sh", "-c", text], server.env(PATH=f"{server.system}:{server.tools}",
                                                                     DEBIAN_FRONTEND="noninteractive"))
        return server, ran

    @staticmethod
    def function(script):
        """The function of `script`, with the script's own APT_LOCK_WAIT, then a call of it."""
        [wait] = re.findall(r"(?m)^APT_LOCK_WAIT=.*$", script.read_text())
        return wait + "\n" + shell_function(script, "apt_update") + "apt_update\n"

    def test_hub_sh_and_join_sh_have_one_function_and_use_it_for_each_update(self):
        function = shell_function(SCRIPT, "apt_update")
        self.assertEqual(function, shell_function(KIT / "join.sh", "apt_update"))
        self.assertEqual(re.findall(r"apt-get (.*?) update", function), ['-o "DPkg::Lock::Timeout=$APT_LOCK_WAIT"'] * 2)
        for script, name in ((SCRIPT, "preflight"), (SCRIPT, "packages"), (KIT / "join.sh", "linux")):
            body = shell_function(script, name)
            self.assertRegex(body, r"(?m)^\s*apt_update$", name)
            self.assertNotRegex(body, r"(?m)^\s*apt-get[^\n]*\bupdate\b", name)

    def test_the_function_tries_again_and_says_only_its_last_words(self):
        for script in (SCRIPT, KIT / "join.sh"):
            server, ran = self.run_on(self.function(script), 2)
            self.assertEqual((ran.status, ran.err, server.slept()), (0, "", [15, 15]), script.name)
            server, ran = self.run_on(self.function(script), 10)
            self.assertEqual((ran.status, server.slept()), (100, [15] * 9), script.name)
            self.assertEqual(ran.err.count("Could not get lock /var/lib/apt/lists/lock"), 1, ran.err)

    def test_the_age_install_and_the_setup_executor_try_again(self):
        import onboard
        for name, text in (("hubsetup.APT_UPDATE", hubsetup.APT_UPDATE), ("onboard.APT_UPDATE", onboard.APT_UPDATE)):
            server, ran = self.run_on(text + "\n", 9)
            self.assertEqual((ran.status, server.slept()), (0, [15] * 9), name + ": " + ran.err)
            server, ran = self.run_on(text + "\n", 10)
            self.assertEqual((ran.status, server.slept()), (100, [15] * 9), name + ": " + ran.err)
            self.assertIn("Could not get lock /var/lib/apt/lists/lock", ran.err.splitlines()[-2], name)
        self.assertIn(hubsetup.APT_UPDATE, hubsetup.AGE_INSTALL)
        self.assertIn(onboard.APT_UPDATE, onboard.TAILSCALE_INSTALL)
        for module in (hubsetup, onboard):
            loose = [line for line in Path(module.__file__).read_text().splitlines()
                     if "update -q" in line and "_UPDATE_ONCE =" not in line]
            self.assertEqual(loose, [], module.__name__)


class Prompt(unittest.TestCase):
    """INSTALL-PROMPT.md: the text a customer pastes into the agent they already run. It is read by a model, so what
    it must never do is in it in writing, and every command it gives is one the installers really take."""

    def setUp(self):
        self.text = PROMPT.read_text()
        cut = self.text.split("---8<---")
        self.assertEqual(len(cut), 5, "the prompt is not between the two cut markers")
        self.prompt = cut[2]

    def test_it_refuses_every_provider_credential_in_writing(self):
        for refusal in ("claude setup-token", "claude login", "codex login", "~/.claude.json", "ANTHROPIC_API_KEY",
                        "CLAUDE_CODE_OAUTH_TOKEN", "OPENAI_API_KEY", "XAI_API_KEY"):
            self.assertIn(refusal, self.prompt, f"the prompt does not refuse {refusal}")
        self.assertIn("You never touch a model provider credential", self.prompt)
        self.assertIn("Never invent", self.prompt)

    def test_it_never_signs_a_provider_in_itself(self):
        """Every command of the prompt, measured against the words that would mean a sign-in."""
        for line in self.prompt.splitlines():
            if not line.startswith("    ") or line.strip().startswith("#"):
                continue
            low = line.lower()
            for forbidden in ("setup-token", "auth login", "claude login", "codex login", "api_key", "oauth"):
                self.assertNotIn(forbidden, low, f"a command of the prompt would touch a credential: {line.strip()}")

    def test_the_auth_key_goes_on_standard_input_and_never_into_an_argument(self):
        self.assertIn("'/bin/sh -c \"umask 077; cat > /root/fleet-authkey\"' < \"$KEYFILE\"", self.prompt)
        self.assertIn("--auth-key=file:/root/fleet-authkey", self.prompt)
        self.assertIn("rm -f /root/fleet-authkey", self.prompt)
        for line in self.prompt.splitlines():
            self.assertNotRegex(line, r"--auth-key[= ]ts[a-z]*-", "an auth key would stand in an argument")

    def test_both_jobs_end_with_verify_and_report_its_lines(self):
        self.assertIn("READY", self.prompt)
        self.assertIn("NOT READY", self.prompt)
        self.assertIn("every line `verify` printed", self.prompt)
        hub_job = self.prompt.split("## Job A")[1].split("## Job B")[0]
        self.assertIn("verify", hub_job.split("### A8")[1])
        self.assertIn("verify", self.prompt.split("### B4")[1])

    def test_every_installer_command_it_names_is_one_the_installers_have(self):
        self.assertIn("sh /root/fleet-kit/hub.sh --check", self.prompt)
        self.assertIn("sh /root/fleet-kit/hub.sh < /dev/null", self.prompt)
        self.assertIn("FLEET_CLAIM=", self.prompt)                  # the claim line the installer prints
        self.assertIn("/claim", self.prompt)
        self.assertIn("--reclaim", self.prompt)                     # and that it is the owner's own word
        for option in re.findall(r"hub\.sh ([-]{2}[a-z-]+)", self.prompt):
            self.assertIn(option, SCRIPT.read_text(), f"the prompt names {option}, which hub.sh does not take")

    def test_both_jobs_reach_the_server_on_its_private_address_after_the_network_step(self):
        """The installers let SSH in over the private network only (hubsetup.py firewall), so a command after the
        network step that still went to the public address would not arrive."""
        for job, network, after in (("## Job A", "### A2", "### A3"), ("## Job B", "### B2", "### B3")):
            step = self.prompt.split(job)[1].split(network)[1].split(after)[0]
            self.assertIn("tailscale ip -4", step)
            self.assertIn("HOST=<the address the last command printed>", step)
        hub_job = self.prompt.split("## Job A")[1].split("## Job B")[0]
        self.assertLess(hub_job.index("private network"), hub_job.index("hub.sh --check"))
        self.assertNotIn("hub.sh < /root/fleet-authkey", self.prompt, "the hub's installer asks for no key now")

    def test_it_says_the_owner_signs_in_and_the_model_does_not(self):
        self.assertIn("The owner signs each server in to their own account", self.prompt)
        self.assertIn("Sign in", self.prompt)

    def test_it_takes_no_step_on_a_fleet_that_already_runs(self):
        self.assertIn("Touch no fleet that is already running", self.prompt)
        for word in ("systemctl --user restart fleet-hub", "git push", "deploy"):
            run_as_step = [line for line in self.prompt.splitlines()
                           if line.startswith("    ") and word in line and "fix:" not in line]
            self.assertEqual(run_as_step, [], f"the prompt would run {word}")


class StandInServer:
    """A server of PromptThroughSudo, in a folder of this machine. `root` is its /root, which only the stand-in for
    `sudo` opens (mode 000 outside it); `system` holds the programs that an install adds, which only that stand-in lets
    a program change (mode 555 outside it); `user` is the PATH of the user who is not root, with `sudo` alone in it;
    `tools` is the rest of root's PATH; `files` is what Tailscale's host, the repository and the hub give. Each stand-in
    writes what reached it to `log`."""

    KEY = "tskey-auth-kStandIn0000-0123456789abcdef\n"          # what the owner's key file holds: it is not a key
    SOURCE = "https://example.com/owner/founderizer-fleet.git"  # the repository address of A3
    PUBLIC = "203.0.113.9"                                      # the address that the owner gave, where A1 reads it
    ADDRESS = "100.101.102.103"                                 # the server's address on the private network
    # The public key of the server's SSH, which it gives at each of its addresses (SSH).
    HOSTKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZvdW5kZXJpemVyU3RhbmRJbkhvc3RLZXkwMTIzNDU2Nzg5"
    COMMIT = "1a2b3c4"                                          # what `git rev-parse --short HEAD` prints
    CODE = "ABCD-EFGH-JKLM"                                     # the one-time code of the join line
    VERIFY = "Founderizer step 16: verify: is this machine of the fleet healthy?\nFounderizer:   ok  the hub answers\nREADY\n"
    INSTALL_LOG = ("Founderizer step 1: this server and this copy of Founderizer\n"
                   f'FLEET_CLAIM={CODE} sh -c "$(curl -fsS http://{ADDRESS}:8765/claim)"\n' + VERIFY)
    # The start of /etc/os-release on Ubuntu 24.04, which A1 reads (`readable`).
    OS_RELEASE = 'PRETTY_NAME="Ubuntu 24.04.3 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\nID_LIKE=debian\n'

    # sudo, as far as the prompt uses it. With -i, root's login shell gets the words joined with spaces, with a
    # backslash before each byte that is not a letter, a digit, "_", "-" or "$" (`man sudo`, -i), and an environment of
    # its own; without -i, root runs the words themselves. Root's folders are open while root's programs run, also those
    # that it leaves in the background: they hold fd 9, and sudo waits until no program holds it. `record` stands
    # first, so that the log says what root's login shell made of the words.
    SUDO = r'''#!/bin/sh
LC_ALL=C; export LC_ALL
login=no
while [ "$#" -gt 0 ]; do
    case $1 in
    --) shift; break ;;
    --login) login=yes; shift ;;
    --*) shift ;;
    -*i*) login=yes; shift ;;
    -*) shift ;;
    *) break ;;
    esac
done
{ printf 'sudo gets'; printf ' [%s]' "$@"; echo; } >> "$LOG"
line=
add() {
    rest=$1
    [ -z "$line" ] || line="$line "
    while [ -n "$rest" ]; do
        after=${rest#?}; c=${rest%"$after"}; rest=$after
        case $c in [A-Za-z0-9_-] | \$) line=$line$c ;; *) line=$line\\$c ;; esac
    done
}
add "$RECORD"
for word in "$@"; do add "$word"; done
/bin/chmod 700 "$ROOTHOME" && /bin/chmod 755 "$SYSTEM" || exit 1
ended=$STATE/sudo.$$
exec 3>&1
if [ "$login" = yes ]; then
    { /usr/bin/env -i PATH="$SYSTEM:$TOOLS" LC_ALL=C LOG="$LOG" STATE="$STATE" FILES="$FILES" ROOTHOME="$ROOTHOME" \
          SYSTEM="$SYSTEM" PROGRAM_SH="$PROGRAM_SH" "$ROOT_SH" -c "$line" 9>&1 1>&3 3>&-
      echo $? > "$ended"; } | /bin/cat > /dev/null
else
    { /usr/bin/env -i PATH="$SYSTEM:$TOOLS" LC_ALL=C LOG="$LOG" STATE="$STATE" FILES="$FILES" ROOTHOME="$ROOTHOME" \
          SYSTEM="$SYSTEM" PROGRAM_SH="$PROGRAM_SH" "$RECORD" "$@" 9>&1 1>&3 3>&-
      echo $? > "$ended"; } | /bin/cat > /dev/null
fi
exec 3>&-
status=$(/bin/cat "$ended"); /bin/rm -f "$ended"
/bin/chmod 000 "$ROOTHOME"; /bin/chmod 555 "$SYSTEM"
echo 'sudo ends' >> "$LOG"
exit "$status"
'''

    # What root's login shell made of the words, word by word. Then it runs them as one simple command of bash, so that
    # a builtin runs too, and a program for /bin/sh with the shell of the test.
    RECORD = r'''#!/bin/sh
{ printf 'root runs'; printf ' [%s]' "$@"; echo; } >> "$LOG"
if [ "$1" = /bin/sh ]; then shift; exec "$PROGRAM_SH" "$@"; fi
exec /bin/bash -c '"$@"' bash "$@"
'''

    # The agent's ssh: it takes its options and the host off, and the rest is the remote command, its words joined with
    # spaces, which the login shell of the user reads in the environment of a new session. Before that, it checks the
    # key that the server gives (HOSTKEY) against the agent's known_hosts (KNOWN, one "<host> <type> <key>" a line), as
    # OpenSSH does (sshconnect.c, check_host_key) with the first value of StrictHostKeyChecking that it gets. A key
    # that it keeps for the host goes on. Another key for the host stops it, unless the value is "no" or "off". It
    # keeps the key of a host that it does not know with "accept-new", "no" or "off", and stops with "yes". With "ask",
    # the value when nothing gives one (this Mac's `ssh -G`), SSH asks on a terminal, and it stops in BatchMode and
    # when there is no terminal, as in the shell of an agent. When it stops, the server gets nothing.
    SSH = r'''ssh() {
    _strict=
    while [ "$#" -gt 0 ]; do
        case $1 in
        -o) _option=$2; shift 2 ;;
        -o?*) _option=${1#-o}; shift ;;
        -*) shift; continue ;;
        *) break ;;
        esac
        case $(printf '%s' "${_option%%[= ]*}" | /usr/bin/tr '[:upper:]' '[:lower:]') in
        stricthostkeychecking)
            [ -n "$_strict" ] || _strict=$(printf '%s' "${_option#*[= ]}" | /usr/bin/tr '[:upper:]' '[:lower:]') ;;
        esac
    done
    _host=${1#*@}
    shift
    _known=new
    while read -r _name _kind _key _rest; do
        [ "$_name" = "$_host" ] || continue
        if [ "$_kind $_key" = "$HOSTKEY" ]; then _known=yes; break; fi
        _known=changed
    done < "$KNOWN"
    case $_known/${_strict:-ask} in
    yes/* | changed/no | changed/off) ;;
    changed/*)
        printf '%s\n' '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@' \
            '@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @' \
            '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@' \
            'IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!' "Offending ED25519 key in $KNOWN" \
            "Host key for $_host has changed and you have requested strict checking." \
            'Host key verification failed.' >&2
        return 255 ;;
    new/accept-new | new/no | new/off)
        printf '%s %s\n' "$_host" "$HOSTKEY" >> "$KNOWN"
        printf "Warning: Permanently added '%s' (ED25519) to the list of known hosts.\n" "$_host" >&2 ;;
    new/yes)
        printf 'No ED25519 host key is known for %s and you have requested strict checking.\n' "$_host" >&2
        echo 'Host key verification failed.' >&2
        return 255 ;;
    *) echo 'Host key verification failed.' >&2; return 255 ;;
    esac
    printf 'ssh sends [%s]\n' "$*" >> "$LOG"
    /usr/bin/env -i PATH="$SERVER_PATH" LC_ALL=C LOG="$LOG" STATE="$STATE" FILES="$FILES" ROOTHOME="$ROOTHOME" \
        SYSTEM="$SYSTEM" TOOLS="$TOOLS" RECORD="$RECORD" PROGRAM_SH="$PROGRAM_SH" ROOT_SH="$ROOT_SH" \
        "$LOGIN_SH" -c "$*"
}
'''

    # Tailscale's command, as far as the steps use it, as Tailscale 1.104.6 did it in a Debian 12 container on 11
    # November 2026 (cmd/tailscale/cli/up.go). `up` takes the key from the file that it names. It keeps the settings
    # that it was given (STATE/settings, one flag a line) before it waits, also when it never comes up. Without
    # `--reset`, an `up` that does not name each kept setting again is refused with Tailscale's words
    # (checkForAccidentalSettingReverts). Without a key it waits for a sign-in; on a tailnet that approves each new
    # machine by hand (`approve_by_hand`) it waits with a key too: the machine then has its address, which `ip` gives,
    # but `status` ends with 1 until an admin approves it (NeedsMachineAuth). It waits up to its `--timeout`
    # (STATE/up-waits), and then ends with Tailscale's words; the real one with no `--timeout` waits for ever, which
    # this one says, and ends at once with 125, so that no test waits.
    TAILSCALE = r'''#!/bin/sh
case $1 in
version) echo 1.90.6 ;;
status) case $(/bin/cat "$STATE/backend" 2>/dev/null) in
        Running) echo "100.101.102.103  server  linux  -" ;;
        NeedsMachineAuth) echo "Machine is not yet approved by tailnet admin." >&2; exit 1 ;;
        *) echo "Logged out." >&2; exit 1 ;;
        esac ;;
up) key= reset= wait= missing=
    for word in "$@"; do
        case $word in
        --auth-key=file:*) key=${word#--auth-key=file:} ;;
        --reset) reset=yes ;;
        --timeout=*) wait=${word#--timeout=} ;;
        esac
    done
    if [ -z "$reset" ] && [ -s "$STATE/settings" ]; then
        while IFS= read -r kept; do
            case " $* " in *" ${kept%%=*} "* | *" ${kept%%=*}="*) ;; *) missing="$missing $kept" ;; esac
        done < "$STATE/settings"
    fi
    if [ -n "$missing" ]; then
        printf "Error: changing settings via 'tailscale up' requires mentioning all\nnon-default flags. To proceed, \
either re-run your command with --reset or\nuse the command below to explicitly mention the current value of\nall \
non-default settings:\n\n\ttailscale %s%s\n\n" "$*" "$missing" >&2
        exit 1
    fi
    : > "$STATE/settings"
    for word in "$@"; do
        case $word in up | --auth-key=* | --reset | --timeout=*) ;; *) echo "$word" >> "$STATE/settings" ;; esac
    done
    [ -z "$wait" ] || echo "$wait" >> "$STATE/up-waits"
    if [ -n "$key" ]; then /bin/cat "$key" > "$STATE/key" || exit 1; fi
    if [ -n "$key" ] && [ ! -e "$STATE/approval" ]; then echo Running > "$STATE/backend"; exit 0; fi
    if [ -n "$key" ]; then
        echo NeedsMachineAuth > "$STATE/backend"
        printf '\nTo approve your machine, visit (as admin):\n\n\thttps://login.tailscale.com/admin/machines\n\n' >&2
    else
        printf '\nTo authenticate, visit:\n\n\thttps://login.tailscale.com/a/0123456789abc\n\n' >&2
    fi
    [ -n "$wait" ] || { echo "tailscale (a stand-in): with no --timeout, it waits here for ever" >&2; exit 125; }
    echo 'timeout waiting for Tailscale service to enter a Running state; check health with "tailscale status"' >&2
    exit 1 ;;
ip) case $(/bin/cat "$STATE/backend" 2>/dev/null) in
    Running | NeedsMachineAuth) echo 100.101.102.103 ;;
    *) echo "no current Tailscale IPs; state: NeedsLogin" >&2; exit 1 ;;
    esac ;;
*) exit 2 ;;
esac
'''

    # git, as far as A3 uses it: a clone keeps the address it was given, and its copy holds hub.sh.
    GIT = r'''#!/bin/sh
{ printf 'git'; printf ' [%s]' "$@"; echo; } >> "$STATE/git"
case $1 in
clone) shift
       while [ "$#" -gt 2 ]; do shift; done
       /bin/mkdir -p "$2/.git" && printf '%s\n' "$1" > "$2/.git/source" && /bin/cp "$FILES/hub.sh" "$2/hub.sh" ;;
-C) [ -d "$2/.git" ] || { echo "fatal: not a git repository: $2" >&2; exit 128; }
    case $3 in pull) ;; rev-parse) echo 1a2b3c4 ;; *) exit 2 ;; esac ;;
*) exit 2 ;;
esac
'''

    # The hub's installer: its plan, or its log.
    HUB = r'''#!/bin/sh
[ "${1:-}" = --check ] && { echo "Founderizer: check only: nothing on this machine changes"; exit 0; }
exec /bin/cat "$FILES/install.log"
'''

    # curl gives Tailscale's install script, whose apt-get puts `tailscale` among the system's programs, and the hub's
    # join script. While STATE/curl-fails has a number of tries that are more than 0 (`fail_curl`), it gets no script
    # from Tailscale's host, as when the network of a new server is not ready yet.
    CURL = r'''#!/bin/sh
for word in "$@"; do url=$word; done
case $url in
https://tailscale.com/install.sh)
    fails=0
    [ -s "$STATE/curl-fails" ] && fails=$(/bin/cat "$STATE/curl-fails")
    if [ "$fails" -gt 0 ]; then
        echo "$((fails - 1))" > "$STATE/curl-fails"
        echo "curl: (6) Could not resolve host: tailscale.com" >&2
        exit 6
    fi
    exec /bin/cat "$FILES/tailscale-install.sh" ;;
http://*/join) exec /bin/cat "$FILES/join.sh" ;;
esac
echo "curl: (6) Could not resolve host: $url" >&2
exit 6
'''

    # Tailscale's install script (https://tailscale.com/install.sh), as far as it uses apt on Ubuntu and Debian: it
    # stops at the first command that fails (`set -eu`), and it runs `apt-get update` and then `apt-get install -y
    # tailscale tailscale-archive-keyring` with no wait for apt's lock.
    TAILSCALE_INSTALL = r'''set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y tailscale tailscale-archive-keyring
'''

    # apt-get puts git and tailscale among the system's programs, and asks nothing only when it is told so. While the
    # first updates of a new server hold the lock of dpkg (`hold_apt_lock`: STATE/apt-lock has the seconds that they
    # still hold it), each apt-get except `update` needs that lock, as apt's own does (apt-pkg/deb/debsystem.cc): when
    # `-o DPkg::Lock::Timeout=` does not let it wait that long, it stops at once with apt's words; else it waits until
    # the updates end, takes the lock, and writes the seconds that it waited to STATE/apt-waited. `update` takes only
    # the lock of the package lists, with one try (apt-pkg/acquire.cc): while the updates read the lists
    # (`hold_lists_lock`: STATE/lists-lock has the number of tries that still find that lock held), it stops at once
    # with apt's words, whatever wait it was told.
    APT_GET = r'''#!/bin/sh
[ "${DEBIAN_FRONTEND:-}" = noninteractive ] || { echo "apt-get: it would ask" >&2; exit 1; }
wait=0 next=
for word in "$@"; do
    if [ -n "$next" ]; then
        next= item=$word
    else
        case $word in -o | --option) next=yes; continue ;; -o?*) item=${word#-o} ;; *) continue ;; esac
    fi
    case $item in [Dd][Pp][Kk][Gg]::[Ll][Oo][Cc][Kk]::[Tt][Ii][Mm][Ee][Oo][Uu][Tt]=*) wait=${item#*=} ;; esac
done
case $wait in -[0-9]*) wait=999999999 ;; '' | *[!0-9]*) wait=0 ;; esac
case " $* " in
*" update "*)
    tries=0
    [ -s "$STATE/lists-lock" ] && tries=$(/bin/cat "$STATE/lists-lock")
    if [ "$tries" -gt 0 ]; then
        echo "$((tries - 1))" > "$STATE/lists-lock"
        echo "E: Could not get lock /var/lib/apt/lists/lock. It is held by process 1234 (apt-get)" >&2
        echo "E: Unable to lock directory /var/lib/apt/lists/" >&2
        exit 100
    fi
    exit 0 ;;
esac
held=0
[ -s "$STATE/apt-lock" ] && held=$(/bin/cat "$STATE/apt-lock")
if [ "$held" -gt 0 ]; then
    if [ "$wait" -lt "$held" ]; then
        echo "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 1234 (unattended-upgr)" >&2
        echo "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), is another process using it?" >&2
        exit 100
    fi
    echo "$held" >> "$STATE/apt-waited" && /bin/rm -f "$STATE/apt-lock"
fi
case " $* " in
*" install "*)
    for word in "$@"; do
        case $word in
        git | tailscale) /bin/cp "$FILES/$word" "$SYSTEM/$word" && /bin/chmod 755 "$SYSTEM/$word" || exit 1 ;;
        esac
    done ;;
esac
'''

    # sleep: it writes the seconds that it got to STATE/slept, and ends at once.
    SLEEP = '#!/bin/sh\necho "$1" >> "$STATE/slept"\n'

    # The hub's join script, which `sh` reads from curl: it keeps the code in root's folder.
    JOIN = r'''[ -n "${FLEET_JOIN:-}" ] || { echo "Founderizer: the join line gave no code" >&2; exit 1; }
printf '%s\n' "$FLEET_JOIN" > "$ROOTHOME/fleet-joined" || exit 1
echo "Founderizer: this machine is the server vps-1"
echo "Founderizer: the server service runs"
echo READY
'''

    class Ran:
        """One line, to its end: its exit status, what it printed on each output, and what the stand-ins logged."""

        def __init__(self, status, out, err, log):
            self.status, self.out, self.err, self.log = status, out, err, log

        def logged(self, label):
            """What the log says after `label`, one entry for each of its lines that starts with it."""
            return [line[len(label):] for line in self.log.splitlines() if line.startswith(label)]

        def errors(self):
            """What it printed on its error output, without the line in which SSH says that it kept the key of a host
            that it did not know (SSH). That line is SSH's own, and it is no error."""
            return re.sub(r"(?m)^Warning: Permanently added '[^'\n]*' \([A-Z0-9-]+\) to the list of known hosts\.\n",
                          "", self.err)

    def __init__(self):
        self.folder = Path(tempfile.mkdtemp(prefix="fleet-prompt-sudo-")).resolve()
        names = ("root", "system", "user", "tools", "files", "state", "local")
        self.root, self.system, self.user, self.tools, self.files, self.state, self.local = (self.folder / name
                                                                                            for name in names)
        for name in names:
            (self.folder / name).mkdir()
        self.log, self.record, self.keyfile = self.folder / "log", self.folder / "record", self.folder / "owner-authkey"
        for path, text in ((self.user / "sudo", self.SUDO), (self.record, self.RECORD), (self.tools / "curl", self.CURL),
                           (self.tools / "apt-get", self.APT_GET), (self.tools / "id", '#!/bin/sh\n[ "$1" = -u ] && echo 0\n'),
                           (self.tools / "setsid", '#!/bin/sh\nexec "$@"\n'), (self.tools / "sleep", self.SLEEP),
                           (self.files / "tailscale", self.TAILSCALE), (self.files / "git", self.GIT),
                           (self.files / "hub.sh", self.HUB)):
            path.write_text(text)
            path.chmod(0o755)
        (self.files / "tailscale-install.sh").write_text(self.TAILSCALE_INSTALL)
        (self.files / "join.sh").write_text(self.JOIN)
        (self.files / "install.log").write_text(self.INSTALL_LOG)
        for tool in ("cat", "rm", "ls", "tail", "head", "sed", "sh", "chmod", "cp", "mkdir", "mktemp"):
            (self.tools / tool).symlink_to(next(path for path in (Path("/bin") / tool, Path("/usr/bin") / tool)
                                                if os.access(path, os.X_OK)))
        (self.local / "sh").symlink_to("/bin/sh")      # on the server itself, the agent's own `sh -c`
        self.keyfile.write_text(self.KEY)
        self.keyfile.chmod(0o600)
        # The agent's known_hosts (SSH): it knows the server at the address that the owner gave, because A1 keeps the
        # key that the server gives there.
        self.known = self.folder / "known_hosts"
        self.known.write_text(f"{self.PUBLIC} {self.HOSTKEY}\n")
        self.root.chmod(0)
        self.system.chmod(0o555)

    @contextlib.contextmanager
    def opened(self):
        """Root's two folders open, as `sudo` opens them for the programs that it runs; then as they were."""
        modes = [os.stat(folder).st_mode & 0o777 for folder in (self.root, self.system)]
        self.root.chmod(0o700)
        self.system.chmod(0o755)
        try:
            yield
        finally:
            self.root.chmod(modes[0])
            self.system.chmod(modes[1])

    def remove(self):
        self.root.chmod(0o700)
        self.system.chmod(0o755)
        shutil.rmtree(self.folder, ignore_errors=True)

    def has(self, program):
        return os.access(self.system / program, os.X_OK)

    def give(self, program):
        """`program` among the system's programs, as its install should have put it there."""
        with self.opened():
            if not self.has(program):
                shutil.copy(self.files / program, self.system / program)

    def read(self, name):
        """A file of the server's /root, or None."""
        with self.opened():
            path = self.root / name
            return path.read_text() if path.exists() else None

    def key_file(self):
        """The key file of the network step, with its mode, if it is there."""
        with self.opened():
            path = self.root / "fleet-authkey"
            return (path.read_text(), os.stat(path).st_mode & 0o777) if path.exists() else None

    def put_key(self):
        """The key file as the network step's second line should have written it."""
        with self.opened():
            (self.root / "fleet-authkey").write_text(self.KEY)
            (self.root / "fleet-authkey").chmod(0o600)

    def given_key(self):
        """The key that `tailscale up` read, or None."""
        path = self.state / "key"
        return path.read_text() if path.exists() else None

    def come_up(self):
        """The server on the private network and the key file gone, as the network step's third line should have left
        them."""
        (self.state / "key").write_text(self.KEY)
        (self.state / "backend").write_text("Running\n")
        with self.opened():
            (self.root / "fleet-authkey").unlink(missing_ok=True)

    def clone(self):
        """The code on the server, as A3's second line should have put it there."""
        with self.opened():
            (self.root / "fleet-kit" / ".git").mkdir(parents=True, exist_ok=True)
            (self.root / "fleet-kit" / ".git" / "source").write_text(self.SOURCE + "\n")
            shutil.copy(self.files / "hub.sh", self.root / "fleet-kit" / "hub.sh")

    def git_calls(self):
        path = self.state / "git"
        return path.read_text().splitlines() if path.exists() else []

    def hold_apt_lock(self, seconds):
        """The first updates of a new server, which hold the lock of dpkg for `seconds` more (APT_GET)."""
        (self.state / "apt-lock").write_text(f"{seconds}\n")

    def apt_waits(self):
        """The seconds that each apt-get waited for the lock of dpkg, in order."""
        path = self.state / "apt-waited"
        return [int(word) for word in path.read_text().split()] if path.exists() else []

    def hold_lists_lock(self, tries):
        """The first updates of a new server read the package lists while the next `tries` runs of `apt-get update`
        try the lock of the lists, which apt-get tries once (APT_GET)."""
        (self.state / "lists-lock").write_text(f"{tries}\n")

    def fail_curl(self, times):
        """curl gets no script from Tailscale's host the next `times` times (CURL)."""
        (self.state / "curl-fails").write_text(f"{times}\n")

    def earlier_up(self, *words):
        """A `tailscale up` with `words` and no key ran on this server before, and it waited for a sign-in that nobody
        gave: Tailscale keeps its settings, and it does not run (TAILSCALE). The settings, one flag a line."""
        ran = subprocess.run([str(self.files / "tailscale"), "up", *words], capture_output=True, text=True,
                             timeout=60, stdin=subprocess.DEVNULL, env=self.env())
        if ran.returncode not in (1, 125) or "To authenticate, visit:" not in ran.stderr:
            raise AssertionError(f"the earlier tailscale up did not wait for a sign-in: {ran.stderr}")
        return (self.state / "settings").read_text()

    def approve_by_hand(self):
        """The owner's tailnet holds each new machine until an admin approves it (TAILSCALE)."""
        (self.state / "approval").write_text("yes\n")

    def up_waits(self):
        """The `--timeout` of each `tailscale up`, in order; a `tailscale up` with none has no entry."""
        path = self.state / "up-waits"
        return path.read_text().split() if path.exists() else []

    def slept(self):
        """The seconds of each `sleep`, in order."""
        path = self.state / "slept"
        return [int(word) for word in path.read_text().split()] if path.exists() else []

    def readable(self):
        """The server as A1 reads it: `id -un` gives root, its /etc/os-release names Ubuntu 24.04 (OS_RELEASE, in
        `files`), and systemd's `systemctl` is among root's programs."""
        programs = {"id": "#!/bin/sh\ncase $1 in -u) echo 0 ;; -un) echo root ;; *) exit 2 ;; esac\n",
                    "systemctl": "#!/bin/sh\nexit 0\n"}
        for name, text in programs.items():
            (self.tools / name).write_text(text)
            (self.tools / name).chmod(0o755)
        (self.files / "os-release").write_text(self.OS_RELEASE)

    def write_install_log(self):
        """The install's log, as the install that A5 starts should have written it."""
        with self.opened():
            (self.root / "fleet-install.log").write_text(self.INSTALL_LOG)

    def known_keys(self):
        """The lines of the agent's known_hosts (SSH), in order."""
        return self.known.read_text().splitlines()

    def know(self, host, key=None):
        """The agent's SSH keeps `key` for `host`, the server's own key when None, as SSH keeps it after the first
        connection that takes it (SSH)."""
        line = f"{host} {key or self.HOSTKEY}"
        if line not in self.known_keys():
            with open(self.known, "a") as kept:
                kept.write(line + "\n")

    def env(self, **more):
        """The environment of the stand-ins, and `more`."""
        return {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LOG": str(self.log), "STATE": str(self.state),
                "FILES": str(self.files), "ROOTHOME": str(self.root), "SYSTEM": str(self.system),
                "TOOLS": str(self.tools), "RECORD": str(self.record), "PROGRAM_SH": "/bin/sh", "ROOT_SH": "/bin/bash",
                **more}

    def execute(self, argv, env, stdin=None):
        """`argv`, to its end and to the end of every program that it started: each holds the write end of a pipe,
        whose read end ends when the last of them is gone. So a `sudo` that the user's shell put in the background has
        ended too, and root's folders are closed again."""
        self.log.write_text("")
        done, held = os.pipe()
        try:
            with open(stdin or os.devnull, "rb") as given:
                child = subprocess.Popen(argv, env=env, stdin=given, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         text=True, pass_fds=(held,))
            os.close(held)
            held = None
            try:
                out, err = child.communicate(timeout=120)
            except subprocess.TimeoutExpired:
                child.kill()
                raise
            deadline = time.monotonic() + 60
            while select.select([done], [], [], max(0.0, deadline - time.monotonic()))[0] and os.read(done, 4096):
                pass
        finally:
            os.close(done)
            if held is not None:
                os.close(held)
        return self.Ran(child.returncode, out, err, self.log.read_text())

    def run(self, line, prefix=None, local=None, program_sh="/bin/sh", login_sh="/bin/bash", host=None):
        """One line of the prompt, as the agent runs it in its own shell, with HOST, SSHUSER, KEYFILE and SOURCE set:
        with `prefix` inside the quotes of its remote command (None: the user is root) and, on the server itself, with
        `local` in place of `ssh`, its options and "$SSHUSER@$HOST". Over ssh, the user's login shell is `login_sh`.
        HOST is `host`, or the address that the owner gave when None, and the agent's SSH checks the server's key there
        against `known` (SSH). /root/ stands for this server's folder, and /etc/os-release for its file in `files`."""
        text = line.replace("/root/", f"{self.root}/").replace("/etc/os-release", f"{self.files}/os-release")
        if prefix is not None:
            text, count = re.subn(r'("\$SSHUSER@\$HOST" )([\'"])', lambda found: found[1] + found[2] + prefix, text)
            if count != 1:
                raise AssertionError(f"no one remote command in quotes: {line}")
        if local is not None:
            text, count = re.subn(r'ssh (?:-o \S+ )*"\$SSHUSER@\$HOST"', lambda _found: local, text)
            if count != 1:
                raise AssertionError(f"no one ssh: {line}")
        server = f"{self.system}:{self.tools}" if prefix is None else str(self.user)
        agent = "/usr/bin:/bin" if local is None else server if prefix is None else f"{self.user}:{self.local}"
        env = self.env(PATH=agent, HOST=host or self.PUBLIC, SSHUSER="root" if prefix is None else "deploy",
                       KEYFILE=str(self.keyfile), SOURCE=self.SOURCE, SERVER_PATH=server, LOGIN_SH=login_sh,
                       PROGRAM_SH=program_sh, KNOWN=str(self.known), HOSTKEY=self.HOSTKEY)
        return self.execute(["/bin/sh", "-c", text if local is not None else self.SSH + text], env)

    def remote(self, command, stdin=None):
        """A remote command, as the login shell (bash) of the user who is not root runs it."""
        return self.execute(["/bin/bash", "-c", command], self.env(PATH=str(self.user)), stdin)


@unittest.skipIf(os.geteuid() == 0, "the stand-in server closes root's folders with file modes, which root ignores")
class PromptThroughSudo(unittest.TestCase):
    """**Each later step of INSTALL-PROMPT.md runs whole as root, also on a server that the agent reaches as a user who
    is not root.** A1 says what the agent puts in front of the remote command of each later step for such a user; this
    test reads it there and does what it says. Until 11 November 2026 that was `sudo -i -- ` in front of commands of
    more than one part: the user's own shell split them at ";", "&&", "||" and "|" before `sudo` ran, so only the first
    part ran as root. Tailscale's install ran as the user, the key file was not written and not removed, the `if` of A3
    was a syntax error, and the join line of B3 ran as the user after its first part.

    The way to the server is played with the shells of this machine, as the app's NetworkPromptRootTests plays it: the
    agent's shell runs the line of the prompt with a stand-in for `ssh`, which gives the user's login shell the remote
    command as `ssh` joins it; a stand-in for `sudo` gives root's login shell (bash) the words with sudo's own
    backslashes (`man sudo`, `-i`); and `/bin/sh` runs the program: this machine's, and dash, which is `/bin/sh` on
    Debian and Ubuntu. The server is a folder (StandInServer): the user has nothing on its PATH but `sudo`, its /root is
    closed to the user, and only root may change the system's programs. So a part of a step that runs outside `sudo`
    finds no program, cannot reach the key file and cannot install. A part that the user's shell runs by itself, such
    as `echo`, needs no program, so `faults` also checks the shape of the words, as the app's test does since
    50a7e432."""

    @classmethod
    def setUpClass(cls):
        cls.prompt = PROMPT.read_text().split("---8<---")[2]
        with patch.object(hub, "hub_address", lambda: (HUB_IP, 8765)):
            cls.join_line = hub.join_line(StandInServer.CODE, "linux", ["tag:fleet", "tag:server"])

    def lines(self, prompt=None):
        """The `ssh` lines of the code blocks of the prompt (or of `prompt`), by step: {"A1": [...], "A2": [...]}."""
        found, step = {}, None
        for line in (prompt or self.prompt).splitlines():
            if line.startswith("#"):
                heading = re.match(r"### ([AB]\d+)\. ", line)
                step = heading[1] if heading else None
            elif step and line.startswith("    ssh "):
                found.setdefault(step, []).append(line[4:])
        return found

    def words(self, start, end, prompt=None):
        """The words of the prompt (or of `prompt`) from `start` to `end`, with its lines joined."""
        return " ".join((prompt or self.prompt).partition(start)[2].partition(end)[0].split())

    def prefix(self, prompt=None):
        """What A1 tells the agent to put in front of the remote command of each later step, for a user who is not
        root, or None."""
        words = self.words("### A1.", "### A2.", prompt)
        end = words.find("` in front of the remote command")
        start = words.rfind("put `", 0, max(end, 0))
        return words[start + len("put `"):end] if end > 0 and start >= 0 else None

    def in_place_of_ssh(self):
        """What the prompt runs in place of `ssh`, its options and "$SSHUSER@$HOST" on the server itself, or None."""
        found = re.search(r"put `([^`]+)` in place of `ssh`", self.words("## What you must have", "## Job A"))
        return found[1] if found else None

    def remote_commands(self, prompt=None):
        """The remote command of each `ssh` line of a step after A1, as the server gets it: the agent's shell reads the
        line with SOURCE and KEYFILE set, and a stand-in for `ssh` prints the words that `ssh` sends. B3's join line is
        the hub's own."""
        lines = [(step, line.replace("<the whole join line from the app>", self.join_line))
                 for step, found in self.lines(prompt).items() if step != "A1" for line in found]
        script = ('ssh() { while [ "$#" -gt 0 ]; do case $1 in -o) shift 2 ;; -*) shift ;; *) break ;; esac; done\n'
                  "    shift; printf '%s\\036' \"$*\"; }\n" + "\n".join(line for _step, line in lines) + "\n")
        done = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=60,
                              stdin=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin", "HOST": "203.0.113.9",
                                                             "SSHUSER": "deploy", "SOURCE": StandInServer.SOURCE,
                                                             "KEYFILE": os.devnull})
        sent = done.stdout.split("\036")[:-1]
        self.assertEqual(len(sent), len(lines), done.stderr)
        return [(step, command) for (step, _line), command in zip(lines, sent)]

    def faults(self, prompt=None):
        """What, in the words of the prompt (or of `prompt`), keeps a later step from running whole as root for a user
        who is not root, and what the walk cannot see: the walk puts the prefix inside the quotes by itself, its `sudo`
        takes any option, and a part of a step outside `sudo` that the user's shell runs by itself, such as `echo`,
        needs no program. So A1 must say to put exactly `sudo -n -i -- ` in front, and show it inside the quotes of a
        remote command. Each later remote command, as the server gets it, must be one `/bin/sh -c "…"` with no `"`, `$`,
        backtick, backslash or new line in its program, or one command with no character that ends, joins or redirects
        a command, and with a `$` only before a space, as in A8. Empty when there is nothing."""
        faults, prefix = [], self.prefix(prompt)
        if prefix != "sudo -n -i -- ":
            faults.append(f"A1 puts {prefix!r} in front of the later remote commands")
        if "'sudo -n -i -- /bin/sh -c \"" not in self.words("### A1.", "### A2.", prompt):
            faults.append("A1 does not show `sudo -n -i -- ` inside the quotes of a remote command")
        for step, command in self.remote_commands(prompt):
            whole = re.fullmatch(r'/bin/sh -c "[^"$`\\\n]*"', command)
            plain = not re.search(r"[;&|<>()`\\\n{}]|\$(?! )", command)
            if not whole and not plain:
                faults.append(f"{step}: `{command}` is more than one command")
        return faults

    def walk(self, job, prefix, local=None, program_sh="/bin/sh", login_sh="/bin/bash"):
        """Every `ssh` line of one job after its first step, on a new server, as the agent runs it: with `prefix` inside
        the quotes of each remote command (None for root), over the stand-in for `ssh` or, with `local` in its place, on
        the server itself. The first updates of the server hold apt's lock (`hold_apt_lock`), so the network step,
        which is the first that installs a package, must wait for it. HOST is the address that the owner gave, and from
        the check of the network step on, the server's new address on the private network, where the agent's SSH does
        not know the server's key before that check. Each step starts where the step before it should have left the
        server and the agent's SSH, so that each one is judged on its own. The issues, in words."""
        server = StandInServer()
        self.addCleanup(server.remove)
        server.hold_apt_lock(540)
        lines, issues, where = self.lines(), [], server.PUBLIC
        who = ("root" if prefix is None else "a user who is not root") + (
            " on the server itself" if local else f" over ssh, with {login_sh} and {program_sh}")

        def run(step, line):
            ran = server.run(line, prefix, local, program_sh, login_sh, host=where)
            if ran.status or ran.errors():
                issues.append(f"{who}: {step} ended with {ran.status}: {ran.err.strip()}")
            if local is None and len(ran.logged("ssh sends")) != 1:
                issues.append(f"{who}: {step} called ssh {len(ran.logged('ssh sends'))} times")
            gets, runs = ran.logged("sudo gets"), ran.logged("root runs")
            if prefix is not None and (len(gets) != 1 or runs != gets):
                issues.append(f"{who}: {step}: sudo got {gets}, and root's login shell ran {runs}")
            return ran

        def network(step):
            nonlocal where
            install, key, up, check = lines[step]
            run(f"{step}, line 1", install)
            if not server.has("tailscale"):
                issues.append(f"{who}: {step} did not install Tailscale")
            if server.apt_waits() != [540]:
                issues.append(f"{who}: {step}'s first line waited {server.apt_waits()} seconds for apt's lock, not 540")
            server.give("tailscale")
            run(f"{step}, line 2", key)
            if server.key_file() != (server.KEY, 0o600):
                issues.append(f"{who}: {step} did not write the key file for root alone: {server.key_file()}")
            server.put_key()
            ran = run(f"{step}, line 3", up)
            if ran.out.splitlines()[-1:] != [server.ADDRESS]:
                issues.append(f"{who}: {step} printed no address: {ran.out!r}")
            if server.given_key() != server.KEY:
                issues.append(f"{who}: {step} gave Tailscale no key")
            if server.key_file() is not None:
                issues.append(f"{who}: {step} left the key file on the server")
            server.come_up()
            where = server.ADDRESS
            if run(f"{step}, the check on the new address", check).out != "0\n":
                issues.append(f"{who}: {step}'s check did not run as root")
            server.know(server.ADDRESS)

        with server.opened() if prefix is None else contextlib.nullcontext():
            if job == "A":
                network("A2")
                git, code, revision = lines["A3"]
                run("A3, line 1", git)
                if not server.has("git"):
                    issues.append(f"{who}: A3 did not install git")
                server.give("git")
                run("A3, line 2", code)
                if server.read("fleet-kit/.git/source") != server.SOURCE + "\n":
                    issues.append(f"{who}: A3 cloned {server.read('fleet-kit/.git/source')!r}, not {server.SOURCE}")
                server.clone()
                run("A3, line 2 on a server that has the code", code)
                if server.git_calls()[-1:] != [f"git [-C] [{server.root}/fleet-kit] [pull] [-q] [--ff-only]"]:
                    issues.append(f"{who}: A3 did not pull the code that the server has: {server.git_calls()[-1:]}")
                ran = run("A3, line 3", revision)
                if ran.out != f"{server.COMMIT}\n{server.root}/fleet-kit/hub.sh\n":
                    issues.append(f"{who}: A3 printed {ran.out!r}")
                [plan] = lines["A4"]
                if "check only" not in run("A4", plan).out:
                    issues.append(f"{who}: A4 printed no plan")
                start, read = lines["A5"]
                run("A5, line 1", start)
                if server.read("fleet-install.log") != server.INSTALL_LOG:
                    issues.append(f"{who}: A5 did not start the install as root")
                server.write_install_log()
                if "FLEET_CLAIM=" not in run("A5, line 2", read).out:
                    issues.append(f"{who}: A5 read no claim line")
                [report] = lines["A8"]
                ran = run("A8", report)
                if ran.out != server.VERIFY:
                    issues.append(f"{who}: A8 printed {ran.out!r}, not the lines of verify")
            else:
                network("B2")
                [join] = lines["B3"]
                ran = run("B3", join.replace("<the whole join line from the app>", self.join_line))
                if "this machine is the server" not in ran.out or server.read("fleet-joined") != server.CODE + "\n":
                    issues.append(f"{who}: B3 did not join the server as root: {ran.out!r}")
        return issues

    def assertNoIssues(self, issues):
        if issues:
            self.fail(f"{len(issues)} issues:\n" + "\n".join(issues))

    def test_every_later_step_runs_whole_as_root_for_a_user_who_is_not_root(self):
        prefix = self.prefix()
        self.assertIsNotNone(prefix, "A1 says nothing to put in front of the remote command")
        self.assertTrue(prefix.startswith("sudo "), prefix)
        issues = []
        for job in ("A", "B"):
            for login_sh, program_sh in (("/bin/bash", "/bin/sh"), ("/bin/dash", "/bin/dash")):
                if os.access(login_sh, os.X_OK):
                    issues += self.walk(job, prefix, program_sh=program_sh, login_sh=login_sh)
        self.assertNoIssues(issues)

    def test_the_same_steps_run_as_they_stand_for_root(self):
        self.assertNoIssues(self.walk("A", None) + self.walk("B", None))

    def test_on_the_server_itself_the_steps_run_the_same_way(self):
        local, prefix = self.in_place_of_ssh(), self.prefix()
        self.assertIsNotNone(local, "the prompt does not say what takes the place of ssh on the server itself")
        self.assertIsNotNone(prefix, "A1 says nothing to put in front of the remote command")
        issues = []
        for job in ("A", "B"):
            issues += self.walk(job, prefix, local=local) + self.walk(job, None, local=local)
        self.assertNoIssues(issues)

    def test_job_b_gives_a_user_who_is_not_root_the_same_prefix(self):
        self.assertIsNotNone(self.prefix(), "A1 says nothing to put in front of the remote command")
        self.assertIn(f"put `{self.prefix()}` in front of the remote command", self.words("### B1.", "### B2."))

    def test_the_words_have_the_shape_that_the_walk_cannot_see(self):
        self.assertEqual(self.faults(), [])

    def test_the_shape_check_finds_a_wrong_prompt(self):
        """`faults` finds each wrong shape of the words that the walk lets pass."""
        wrong = [
            # With no -n, `sudo` can ask for a password, which the agent does not have.
            ("put `sudo -n -i -- ` in front", "put `sudo -i -- ` in front"),
            # With no -i, what A1 says about root's login shell is not true.
            ("put `sudo -n -i -- ` in front", "put `sudo -n -- ` in front"),
            # In front of `ssh`, `sudo` runs on the agent's own machine.
            ("`ssh \"$SSHUSER@$HOST\" 'sudo -n -i -- /bin/sh -c \"…\"'`",
             "`sudo -n -i -- ssh \"$SSHUSER@$HOST\" '/bin/sh -c \"…\"'`"),
            # The user's shell runs `echo` outside `sudo`, and it prints the same.
            ("tailscale ip -4\"'", "tailscale ip -4\" || echo none'"),
            # Root's login shell expands a "$" after `sudo -i`.
            ("cat > /root/fleet-authkey\"'", "cat > $HOME/fleet-authkey\"'"),
            # And a "$" before a letter in a command of one part.
            (",$ p\"", ",$p\""),
        ]
        for old, new in wrong:
            text = self.prompt.replace(old, new)
            self.assertNotEqual(text, self.prompt, f"{old} is not in the prompt")
            self.assertTrue(self.faults(text), f"the check finds nothing wrong with {new}")

    def test_a3_waits_for_apts_lock_while_a_new_server_installs_its_first_updates(self):
        """**A3's first line waits for apt's lock**, as each apt-get of hub.sh and join.sh does: a new server installs
        its first updates for about 9 minutes after its first start, and they hold the lock (hubsetup.py
        APT_LOCK_WAIT). Until 11 November 2026 the line did not wait, so on such a server apt-get stopped at once and
        the agent stopped the install there. The stand-in's apt-get plays the lock of dpkg as apt does, and the line
        runs each way that the walk runs it. `apt-get update` takes the lock of the package lists with one try, so
        the line gives it up to 10 tries, 15 seconds apart, and installs git only after an update that worked: here 1
        or 9 tries find that lock held and a later one does not, or all 10 find it held. The words of A3 say how long
        the line can wait."""
        line, issues = self.lines()["A3"][0], []
        waits = re.findall(r"DPkg::Lock::Timeout=(\d+)", line)
        if waits != [str(hubsetup.APT_LOCK_WAIT)] * line.count("apt-get "):
            issues.append(f"the apt-gets of A3's first line wait {waits} seconds, not {hubsetup.APT_LOCK_WAIT} each")
        if f"apt-get waits up to {hubsetup.APT_LOCK_WAIT // 60} minutes" not in self.words("### A3.", "### A4."):
            issues.append("the words of A3 do not say how long apt-get waits for the lock")
        if "gives `apt-get update` up to 10 tries, 15 seconds apart" not in self.words("### A3.", "### A4."):
            issues.append("the words of A3 do not say that the line tries apt-get update again")
        prefix, local = self.prefix(), self.in_place_of_ssh()
        ways = [("root over ssh", None, None, "/bin/sh", "/bin/bash")] + [
            (f"a user who is not root over ssh, with {login_sh} and {program_sh}", prefix, None, program_sh, login_sh)
            for login_sh, program_sh in (("/bin/bash", "/bin/sh"), ("/bin/dash", "/bin/dash"))
            if os.access(login_sh, os.X_OK)] + [
            ("root on the server itself", None, local, "/bin/sh", "/bin/bash"),
            ("a user who is not root on the server itself", prefix, local, "/bin/sh", "/bin/bash")]
        for (who, given, place, program_sh, login_sh), stops in itertools.product(ways, (0, 1, 9, 10)):
            server = StandInServer()
            self.addCleanup(server.remove)
            server.hold_apt_lock(540)
            server.hold_lists_lock(stops)
            with server.opened() if given is None else contextlib.nullcontext():
                ran = server.run(line, given, place, program_sh, login_sh)
            installs = stops < 10
            if (ran.status != (0 if installs else 100) or (ran.err and not stops) or server.has("git") != installs
                    or server.apt_waits() != ([540] if installs else []) or server.slept() != [15] * min(stops, 9)):
                issues.append(f"{who}: A3's first line, with {stops} tries of `apt-get update` that stop, ended "
                              f"with {ran.status} ({ran.err.strip()}), git is "
                              f"{'there' if server.has('git') else 'not there'}, apt-get waited "
                              f"{server.apt_waits()} seconds and the line slept {server.slept()}")
        self.assertNoIssues(issues)

    def test_a2_and_b2_wait_for_apts_lock_and_try_tailscales_installer_again(self):
        """**The first line of A2 and of B2 waits for apt's lock before each try of Tailscale's installer, and tries it
        three times at most**, in the words of hub.py's join line (TAILSCALE_INSTALL), as the Mac app's install does.
        Tailscale's installer runs apt-get with no wait for apt's lock, and the network step is the first step that
        installs a package: until 11 November 2026 the installer stopped at once on a new server whose first updates
        held the lock, and the agent stopped the install at A2. The walk holds the lock of dpkg. Here the updates also
        read the package lists, and `apt-get update` tries their lock once: so the first try stops, and the second
        one installs Tailscale after 20 seconds. So does a first try that got no script from curl, after which `sh`
        ends with 0: a try counts only when `tailscale` is there after it. When each try stops, the line ends with a
        failure. Each line runs each way that the walk runs it. The words of A2 say how long the line can wait, and B2
        sends the agent to them."""
        lines, issues = self.lines(), []
        if f"DPkg::Lock::Timeout={hubsetup.APT_LOCK_WAIT} " not in hub.TAILSCALE_INSTALL:
            issues.append(f"hub.TAILSCALE_INSTALL does not wait {hubsetup.APT_LOCK_WAIT} seconds for apt's lock")
        if f"the line waits up to {hubsetup.APT_LOCK_WAIT // 60} minutes" not in self.words("### A2.", "### A3."):
            issues.append("the words of A2 do not say how long the line waits for apt's lock")
        if "can take some minutes, as in A2" not in self.words("### B2.", "### B3."):
            issues.append("the words of B2 do not send the agent to the wait of A2")
        prefix, local = self.prefix(), self.in_place_of_ssh()
        ways = [("root over ssh", None, None, "/bin/sh", "/bin/bash")] + [
            (f"a user who is not root over ssh, with {login_sh} and {program_sh}", prefix, None, program_sh, login_sh)
            for login_sh, program_sh in (("/bin/bash", "/bin/sh"), ("/bin/dash", "/bin/dash"))
            if os.access(login_sh, os.X_OK)] + [
            ("root on the server itself", None, local, "/bin/sh", "/bin/bash"),
            ("a user who is not root on the server itself", prefix, local, "/bin/sh", "/bin/bash")]
        for step in ("A2", "B2"):
            line = lines[step][0]
            if hub.TAILSCALE_INSTALL not in line:
                issues.append(f"{step}'s first line does not install Tailscale in the words of hub.TAILSCALE_INSTALL")
            for who, given, place, program_sh, login_sh in ways:
                for stops, misses, installs in ((1, 0, True), (0, 1, True), (3, 0, False)):
                    server = StandInServer()
                    self.addCleanup(server.remove)
                    server.hold_apt_lock(540)
                    server.hold_lists_lock(stops)
                    server.fail_curl(misses)
                    with server.opened() if given is None else contextlib.nullcontext():
                        ran = server.run(line, given, place, program_sh, login_sh)
                    done = (ran.status == 0, server.has("tailscale"), ran.out.splitlines()[-1:] == ["1.90.6"])
                    if (done != (installs,) * 3 or server.apt_waits() != [540]
                            or server.slept() != [20] * (stops + misses)):
                        issues.append(f"{who}: {step}'s first line, with {stops} tries of `apt-get update` and "
                                      f"{misses} of curl that stop, ended with {ran.status} "
                                      f"({ran.err.strip()[-160:]}), printed {ran.out.splitlines()[-1:]}, Tailscale "
                                      f"is {'there' if server.has('tailscale') else 'not there'}, apt-get waited "
                                      f"{server.apt_waits()} seconds and the line slept {server.slept()}")
        self.assertNoIssues(issues)

    def test_a2_and_b2_bring_up_a_server_that_an_earlier_tailscale_up_left_and_wait_five_minutes_at_most(self):
        """**The last line of A2 and of B2 has `--reset`, and waits 300 seconds at most.** The hub's join line runs
        `tailscale up` with its tags and no key when Tailscale does not run, and that `tailscale up` waits for a
        sign-in. Tailscale keeps its settings, its tags too, also after it was stopped. Then it refuses a `tailscale up`
        that does not name each of them again, unless it has `--reset` (Tailscale 1.104.6 in a Debian 12 container, 11
        November 2026): until then the agent that ran B2 after such a join line stopped there, and each new key
        failed in the same way. With no `--timeout`, `tailscale up` waits for ever on a tailnet that holds each new
        machine until an admin approves it: now the line ends after 5 minutes with Tailscale's words, and the key
        file is removed. Such a machine has its address already, but nothing reaches it there until an admin approves
        it, so the line prints no address then, and ends with a failure. The words of A2 and B2 say what the agent
        does then. Each line runs each way that the walk runs it."""
        lines, issues = self.lines(), []
        for step, start, end in (("A2", "### A2.", "### A3."), ("B2", "### B2.", "### B3.")):
            words = self.words(start, end)
            for wanted in ("The last line can wait up to 5 minutes", "`--reset` removes the settings",
                           "ends with `timeout waiting for Tailscale service to enter a Running state`",
                           "approve this server in their Tailscale admin console",
                           "When they say that they approved it, run the last line again"):
                if wanted not in words:
                    issues.append(f"the words of {step} do not say: {wanted}")
        earlier = re.search(r"tailscale up ([^;|&'\"]*)", self.join_line)[1].split()
        prefix, local = self.prefix(), self.in_place_of_ssh()
        ways = [("root over ssh", None, None, "/bin/sh", "/bin/bash")] + [
            (f"a user who is not root over ssh, with {login_sh} and {program_sh}", prefix, None, program_sh, login_sh)
            for login_sh, program_sh in (("/bin/bash", "/bin/sh"), ("/bin/dash", "/bin/dash"))
            if os.access(login_sh, os.X_OK)] + [
            ("root on the server itself", None, local, "/bin/sh", "/bin/bash"),
            ("a user who is not root on the server itself", prefix, local, "/bin/sh", "/bin/bash")]
        for step in ("A2", "B2"):
            up = lines[step][2]
            for (who, given, place, program_sh, login_sh), approval in itertools.product(ways, (False, True)):
                server = StandInServer()
                self.addCleanup(server.remove)
                server.give("tailscale")
                if "--advertise-tags=tag:fleet,tag:server" not in server.earlier_up(*earlier):
                    issues.append(f"the join line's tailscale up left no tags: {earlier}")
                if approval:
                    server.approve_by_hand()
                server.put_key()
                with server.opened() if given is None else contextlib.nullcontext():
                    ran = server.run(up, given, place, program_sh, login_sh)
                case = f"{who}: {step}'s last line" + (" on a tailnet that approves each machine by hand" if approval
                                                       else "")
                if server.key_file() is not None or server.given_key() != server.KEY:
                    issues.append(f"{case} left the key file ({server.key_file()}), or gave Tailscale no key "
                                  f"({server.given_key()!r}): {ran.err.strip()[-200:]}")
                if server.up_waits() != ["300s"]:
                    issues.append(f"{case}: tailscale up waited {server.up_waits()}, not 300s at most")
                if approval:
                    late = "timeout waiting for Tailscale service to enter a Running state"
                    if (ran.status == 0 or late not in ran.err or "waits here for ever" in ran.err
                            or server.ADDRESS in ran.out):
                        issues.append(f"{case} ended with {ran.status}, printed {ran.out!r} and "
                                      f"{ran.err.strip()[-200:]!r}")
                elif ran.status != 0 or ran.out.splitlines()[-1:] != [server.ADDRESS]:
                    issues.append(f"{case} ended with {ran.status}, printed {ran.out.splitlines()[-1:]} and "
                                  f"{ran.err.strip()[-300:]!r}")
        self.assertNoIssues(issues)

    def test_a2_and_b2_check_the_new_address_with_ssh_in_batchmode_and_keep_the_servers_key(self):
        """**The check of A2 and of B2 at the server's new address works for SSH in BatchMode, and after it the next
        step works for SSH that cannot ask on a terminal.** The agent's SSH knows the server's key at the address that
        the owner gave, because A1 reads the server there in BatchMode. It does not know the key at the server's new
        address on the private network. SSH in BatchMode refuses a server whose key it does not know, and so does SSH
        that cannot ask on a terminal, as in the shell of an agent: "Host key verification failed.", with status 255
        (`StrictHostKeyChecking ask`, which this Mac's `ssh -G` gives when nothing sets a value). Until 11 November 2026
        the check was `ssh -o BatchMode=yes "$SSHUSER@$HOST" 'id -u'`. So it failed on each server, its words gave the
        Tailscale access rules as the cause, and the steps after it failed in the same way. Now the check keeps the key
        that the server gives at its new address (`StrictHostKeyChecking=accept-new`), as the Mac app's install does: on
        the private network, only the server that has that address answers there. A key that is not the key that the
        agent's SSH keeps for that address still stops the check with SSH's words, and the agent's known_hosts stays
        as it was. The words of A2 and of B2 give both causes, and no line of the prompt stops SSH's check of the
        server's key. Each line runs each way over ssh that the walk runs it."""
        lines, issues = self.lines(), []
        for step, start, end in (("A2", "### A2.", "### A3."), ("B2", "### B2.", "### B3.")):
            words = self.words(start, end)
            for wanted in ("REMOTE HOST IDENTIFICATION HAS CHANGED", "Do not remove it yourself",
                           "Tailscale access rules must let this machine reach the server's port 22"):
                if wanted not in words:
                    issues.append(f"the words of {step} do not say: {wanted}")
        for line in self.prompt.splitlines():
            if re.search(r"StrictHostKeyChecking[= ](?:no|off)\b|UserKnownHostsFile[= ]/dev/null", line, re.I):
                issues.append(f"a line of the prompt stops SSH's check of the server's key: {line.strip()}")
        prefix = self.prefix()
        ways = [("root", None, "/bin/sh", "/bin/bash")] + [
            (f"a user who is not root, with {login_sh} and {program_sh}", prefix, program_sh, login_sh)
            for login_sh, program_sh in (("/bin/bash", "/bin/sh"), ("/bin/dash", "/bin/dash"))
            if os.access(login_sh, os.X_OK)]
        earlier = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEFuRWFybGllck1hY2hpbmVBdFRoaXNBZGRyZXNzMDE"
        for (step, after), (who, given, program_sh, login_sh), stale in itertools.product(
                (("A2", "A3"), ("B2", "B3")), ways, (False, True)):
            server = StandInServer()
            self.addCleanup(server.remove)
            server.come_up()
            if stale:
                server.know(server.ADDRESS, earlier)
            kept = server.known_keys()
            check, then = lines[step][3], lines[after][0].replace("<the whole join line from the app>", self.join_line)
            with server.opened() if given is None else contextlib.nullcontext():
                ran = server.run(check, given, program_sh=program_sh, login_sh=login_sh, host=server.ADDRESS)
                went = None if stale else server.run(then, given, program_sh=program_sh, login_sh=login_sh,
                                                     host=server.ADDRESS)
            case = f"{who}: {step}'s check on the new address"
            if stale:
                if (ran.status != 255 or "REMOTE HOST IDENTIFICATION HAS CHANGED" not in ran.err
                        or ran.logged("ssh sends") or server.known_keys() != kept):
                    issues.append(f"{case}, where the agent's SSH keeps the key of an earlier machine, ended with "
                                  f"{ran.status}, sent {ran.logged('ssh sends')}, and SSH keeps {server.known_keys()}: "
                                  f"{ran.err.strip()[-200:]!r}")
                continue
            if (ran.status or ran.errors() or ran.out != "0\n"
                    or server.known_keys() != kept + [f"{server.ADDRESS} {server.HOSTKEY}"]):
                issues.append(f"{case} ended with {ran.status}, printed {ran.out!r} and {ran.err.strip()[-200:]!r}, "
                              f"and SSH keeps {server.known_keys()}")
            if went.status or went.errors() or len(went.logged("ssh sends")) != 1:
                issues.append(f"{who}: the first line of {after} on the new address, after {step}'s check, ended "
                              f"with {went.status}: {went.err.strip()[-200:]!r}")
        self.assertNoIssues(issues)

    def test_a1_reads_a_new_server_whose_key_the_agents_ssh_has_never_seen(self):
        """**A1 reads a new server with SSH in BatchMode, also when the agent's SSH has never seen the server's key at
        the address that the owner gave, and after it the steps at that address work for SSH that cannot ask on a
        terminal.** A new server has a key of its own, which the agent's SSH does not know yet. SSH in BatchMode
        refuses a server whose key it does not know, and so does SSH that cannot ask on a terminal, as in the shell of
        an agent: "Host key verification failed.", with status 255 (OpenSSH 10.3p1 on this Mac). Until 12 November
        2026 A1 was `ssh -o BatchMode=yes "$SSHUSER@$HOST" '…'`, and its words said only to give the owner SSH's
        error. So the install stopped at its first command on each new server, and the owner got no words about what
        to do.
        Now A1 keeps the key that the server gives at the first connection (`StrictHostKeyChecking=accept-new`), as the
        Mac app's install does on each SSH (`InstallPlan.arguments`), and the agent's known_hosts keeps it once. A key
        that is not the key that the agent's SSH keeps for that address still stops A1 with SSH's words, the agent's
        known_hosts stays as it was, and the words of A1 say what the owner does then. B1 runs the command of A1. A1
        runs over ssh with each login shell of the walk, and so does the first line of A2 and of B2 after it."""
        lines, issues = self.lines(), []
        [read] = lines["A1"]
        words = self.words("### A1.", "### A2.")
        for wanted in ("REMOTE HOST IDENTIFICATION HAS CHANGED", "`ssh-keygen -R <the address>`",
                       "Do not remove it yourself"):
            if wanted not in words:
                issues.append(f"the words of A1 do not say: {wanted}")
        if "The command of A1, with the same checks and the same stops" not in self.words("### B1.", "### B2."):
            issues.append("B1 does not run the command of A1 with its checks and its stops")
        earlier = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEFuRWFybGllck1hY2hpbmVBdFRoaXNBZGRyZXNzMDE"
        shells = [login_sh for login_sh in ("/bin/bash", "/bin/dash") if os.access(login_sh, os.X_OK)]
        for login_sh, kept in itertools.product(shells, ("no key", "the key of an earlier machine", "its key")):
            server = StandInServer()
            self.addCleanup(server.remove)
            server.readable()
            server.known.write_text({"no key": "", "its key": f"{server.PUBLIC} {server.HOSTKEY}\n",
                                     "the key of an earlier machine": f"{server.PUBLIC} {earlier}\n"}[kept])
            before = server.known_keys()
            case = f"A1 over ssh with {login_sh}, where the agent's SSH keeps {kept} for the owner's address"
            with server.opened():
                ran = server.run(read, login_sh=login_sh)
                if kept == "the key of an earlier machine":
                    if (ran.status != 255 or "REMOTE HOST IDENTIFICATION HAS CHANGED" not in ran.err
                            or ran.logged("ssh sends") or server.known_keys() != before):
                        issues.append(f"{case}, ended with {ran.status}, sent {ran.logged('ssh sends')}, and SSH keeps "
                                      f"{server.known_keys()}: {ran.err.strip()[-200:]!r}")
                    continue
                reading = f"root\n0\n{''.join(server.OS_RELEASE.splitlines(True)[:2])}{server.tools}/systemctl\n"
                if (ran.status or ran.errors() or ran.out != reading or len(ran.logged("ssh sends")) != 1
                        or server.known_keys() != [f"{server.PUBLIC} {server.HOSTKEY}"]):
                    issues.append(f"{case}, ended with {ran.status}, printed {ran.out!r} and "
                                  f"{ran.err.strip()[-200:]!r}, and SSH keeps {server.known_keys()}")
                for step in ("A2", "B2"):
                    went = server.run(lines[step][0], login_sh=login_sh)
                    if went.status or went.errors() or len(went.logged("ssh sends")) != 1:
                        issues.append(f"{case}: the first line of {step} after it ended with {went.status}: "
                                      f"{went.err.strip()[-200:]!r}")
        self.assertNoIssues(issues)

    def test_the_walk_knows_every_ssh_line_of_the_prompt(self):
        """A new `ssh` line in a step after the first one is walked too: the walk takes each one by its place."""
        self.assertEqual({step: len(lines) for step, lines in self.lines().items()},
                         {"A1": 1, "A2": 4, "A3": 3, "A4": 1, "A5": 2, "A8": 1, "B2": 4, "B3": 1})

    def test_the_stand_in_loses_what_sudo_loses(self):
        """The stand-in for `sudo -i` is true where it matters: a "$" before a name reaches root's login shell, which
        expands it; a "$" before a space stays a "$", as in A8; a new line reaches it after a backslash, which joins
        the two lines; and a part after ";" runs as the user, who cannot write in root's folder."""
        server = StandInServer()
        self.addCleanup(server.remove)
        self.assertEqual(server.remote("""sudo -n -i -- /bin/sh -c 'x=kept; echo "[$x]"'""").out, "[]\n")
        self.assertEqual(server.remote("""sudo -n -i -- /bin/sh -c 'printf "%s\\n" one two | sed -n "2,$ p"'""").out,
                         "two\n")
        self.assertEqual(server.remote("sudo -n -i -- /bin/sh -c 'echo one\necho two'").out, "oneecho two\n")
        key = f"{server.root}/fleet-authkey"
        split = server.remote(f"sudo -n -i -- umask 077; cat > {key}", stdin=server.keyfile)
        self.assertNotEqual(split.status, 0)
        self.assertIn("Permission denied", split.err)
        self.assertIsNone(server.key_file())
        whole = server.remote(f"sudo -n -i -- /bin/sh -c 'umask 077; cat > {key}'", stdin=server.keyfile)
        self.assertEqual((whole.status, whole.err, server.key_file()), (0, "", (server.KEY, 0o600)))


class CheckMode(unittest.TestCase):
    """hub.sh --check: the plan it would carry out, read on any machine, against a folder that stands in for /. It
    runs no command that changes anything, as config-ref.sh --check does."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-hub-check-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        (self.tmp / "etc").mkdir()
        (self.tmp / "etc" / "os-release").write_text('ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04 LTS"\n')

    def run_check(self, *args, tree=None, root=None, expect=0, more_env=None):
        env = dict(os.environ, FLEET_CHECK_ROOT=str(root if root is not None else self.tmp))
        env.pop("FLEET_MANAGER_SERVER", None)           # the app's words, only where a test gives them
        env.pop("FLEET_VERIFY", None)
        env.update(more_env or {})
        done = subprocess.run(["sh", str(tree or SCRIPT), "--check", *args], capture_output=True, text=True, env=env,
                              timeout=120, stdin=subprocess.DEVNULL)
        self.assertEqual(done.returncode, expect, done.stdout + done.stderr)
        return done.stdout + done.stderr

    def test_the_plan_gives_the_manager_no_server_only_on_the_apps_word(self):
        out = self.run_check()
        self.assertIn("one manager agent on it with runtime claude", out)
        self.assertNotIn("no server yet", out)
        self.assertNotIn("find none on a new hub", out)
        out = self.run_check(more_env={"FLEET_MANAGER_SERVER": "later"})
        self.assertIn("one manager with no server yet", out)
        self.assertIn("find none on a new hub", out)

    def test_the_plan_leaves_verify_to_the_app_only_on_the_apps_word(self):
        out = self.run_check()
        self.assertIn("fleet.py verify, and print the line of every check it answers", out)
        self.assertNotIn("leave verify to the app", out)
        self.assertIn("--no-selftest (GET /health;", out)
        out = self.run_check(more_env={"FLEET_VERIFY": "caller"})
        self.assertIn("leave verify to the app that started this install", out)
        self.assertNotIn("and print the line of every check it answers", out)

    def test_the_script_is_valid_shell(self):
        subprocess.run(["sh", "-n", str(SCRIPT)], check=True, capture_output=True)

    def test_every_apt_get_of_both_installers_waits_out_the_first_updates_of_a_new_server(self):
        """A new Ubuntu server runs its first updates for about 9 minutes after its first boot, and they hold the
        package lock (the proof run of 5 November 2026, where a wait of 5 minutes stopped a join): each apt-get of
        both installers waits for it as long as hubsetup.py's own, with the words the shell gives apt-get."""
        bin_ = self.tmp / "bin"
        bin_.mkdir()
        (bin_ / "apt-get").write_text('#!/bin/sh\nprintf "[%s]" "$@" >> "$CALLS"\necho >> "$CALLS"\n')
        (bin_ / "apt-get").chmod(0o755)
        for script in (SCRIPT, KIT / "join.sh"):
            text = script.read_text()
            [wait] = re.findall(r"(?m)^APT_LOCK_WAIT=.*$", text)
            lines = [line.strip() for line in text.splitlines() if line.lstrip().startswith("apt-get ")]
            self.assertTrue(lines, script.name)
            calls = self.tmp / f"{script.name}.calls"
            done = subprocess.run(["sh", "-c", "\n".join([wait, "missing=' tmux'", *lines])], capture_output=True,
                                  text=True, stdin=subprocess.DEVNULL, timeout=60,
                                  env=dict(os.environ, PATH=f"{bin_}:/usr/bin:/bin", CALLS=str(calls)))
            self.assertEqual(done.returncode, 0, done.stderr)
            said = calls.read_text().splitlines()
            self.assertEqual(len(said), len(lines), script.name)
            for line, words in zip(lines, said):
                self.assertTrue(words.startswith(f"[-o][DPkg::Lock::Timeout={hubsetup.APT_LOCK_WAIT}]["), line)
        self.assertGreaterEqual(hubsetup.APT_LOCK_WAIT, 1200)

    def test_it_names_every_step_in_the_order_it_takes_them(self):
        out = self.run_check()
        for step in STEPS:
            self.assertIn(step, out)
        at = [out.index(step) for step in STEPS]
        self.assertEqual(at, sorted(at), "the steps are not in the installer's own order")

    def test_the_plan_says_what_it_would_change_and_changes_nothing(self):
        before = sorted(p.relative_to(self.tmp).as_posix() for p in self.tmp.rglob("*"))
        out = self.run_check()
        self.assertIn("check only: nothing on this machine changes", out)
        self.assertIn("check only: nothing on this machine changed", out)
        for wanted in ("would run", "fleet-pilot.git", "config", "vault\": \"none\"",
                       "tailscale up --reset --auth-key=file:", "--accept-dns=false --timeout=300s",
                       "systemctl --user enable --now fleet-hub fleet-git", "hubsetup.py check",
                       "sign in to nothing", "paste in Founderizer"):
            self.assertIn(wanted, out, f"the plan does not mention {wanted}")
        self.assertEqual(sorted(p.relative_to(self.tmp).as_posix() for p in self.tmp.rglob("*")), before)

    def test_roots_own_step_reads_the_hubs_checkout_under_its_real_name(self):
        """kit-clone, which root runs on the hub's machine with no folder named (the app's central vault and TCP
        steps), reads release.json in the hub's own checkout: founderizer on a new hub, fleet-pilot on a hub made
        before. A link of the new name to the folder of before, as step 4 of the rename makes it, is not followed:
        root reads the real folder."""
        home = self.tmp / "home" / "fleet"
        home.mkdir(parents=True)
        self.assertEqual(hubsetup.hub_checkout(str(home)), str(home / "founderizer"))     # nothing there yet
        (home / "fleet-pilot").mkdir()
        self.assertEqual(hubsetup.hub_checkout(str(home)), str(home / "fleet-pilot"))
        (home / "founderizer").symlink_to(home / "fleet-pilot")
        self.assertEqual(hubsetup.hub_checkout(str(home)), str(home / "fleet-pilot"))
        (home / "founderizer").unlink()
        (home / "founderizer").mkdir()
        self.assertEqual(hubsetup.hub_checkout(str(home)), str(home / "founderizer"))

    def test_the_plan_reads_the_system_it_is_given(self):
        self.assertIn("Ubuntu 24.04", self.run_check())
        for system, version in sorted(SYSTEMS):
            (self.tmp / "etc" / "os-release").write_text(
                f'ID={system}\nVERSION_ID="{version}"\nPRETTY_NAME="{system} {version} as its file says"\n')
            out = self.run_check()
            self.assertIn(f"{system} {version} as its file says", out)
            self.assertNotIn("the install needs", out)
        (self.tmp / "etc" / "os-release").write_text('ID=fedora\nVERSION_ID="40"\n')
        out = self.run_check()
        self.assertIn(f"the install needs {SYSTEMS_SAID}", out)

    def test_it_refuses_a_folder_that_is_not_a_copy_of_fleet(self):
        empty = self.tmp / "elsewhere"
        empty.mkdir()
        shutil.copy(SCRIPT, empty / "hub.sh")
        out = self.run_check(tree=empty / "hub.sh", expect=1)
        self.assertIn("is not a copy of the Founderizer repository", out)

    def test_it_refuses_a_copy_without_the_repositorys_history(self):
        """The hub's own repository is made from this copy, so a folder of loose files is not enough."""
        bare = self.tmp / "no-history"
        bare.mkdir()
        shutil.copy(SCRIPT, bare / "hub.sh")
        for name in re.search(r'^NEEDED="([^"]+)"', SCRIPT.read_text(), re.M).group(1).split():
            (bare / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(KIT / name, bare / name)
        out = self.run_check(tree=bare / "hub.sh", expect=1)
        self.assertIn("is not a git checkout with a commit", out)

    def test_it_refuses_what_it_cannot_do(self):
        for args, why in ((["--port", "no"], "--port must be a number"),
                          (["--runtime", "grok"], "--runtime must be claude or codex"),
                          (["--claim-wait", "soon"], "--claim-wait must be seconds"),
                          (["--nonsense"], "unknown option")):
            self.assertIn(why, self.run_check(*args, expect=1))

    def test_the_options_reach_the_plan(self):
        out = self.run_check("--port", "9100", "--runtime", "codex", "--source", "git://example.invalid/fleet.git")
        self.assertIn("9100", out)
        self.assertIn("runtime codex", out)
        self.assertIn("git://example.invalid/fleet.git", out)

    def test_the_plan_of_a_second_claim_says_that_the_hub_is_away_for_its_time(self):
        """--reclaim on a hub that runs stops fleet-hub for the time of the claim, so the plan says it, and the plan
        of an install says nothing of the kind. The claim does the stop itself (hubsetup.HubPause): hub.sh stops no
        service for it, so that an older copy of hub.sh, which runs the hub's own hubsetup.py, gets it too."""
        wanted = "would stop the service fleet-hub of a hub that runs for the time of that claim"
        self.assertNotIn(wanted, self.run_check())
        out = self.run_check("--reclaim")
        self.assertIn(wanted, out)
        self.assertIn("start it again when the claim ends, also when no Mac claims in time", out)
        claim = shell_function(SCRIPT, "first_team")
        self.assertNotRegex(claim, r"systemctl[^\n]*(stop|start|restart)")
        self.assertIn('"$kit/hubsetup.py" claim', claim)


class Systems(unittest.TestCase):
    """The systems a VPS may run. The hub's installer, the join and the setup executor take the same ones, so a server
    that one of them takes is never refused by the next, and every line that names them names all of them."""

    @staticmethod
    def taken(script):
        """The systems of the one `case "${ID:-} ${VERSION_ID:-}"` that the script reads /etc/os-release with."""
        lines = script.read_text().splitlines()
        at = next(i for i, line in enumerate(lines) if line.strip() == 'case "${ID:-} ${VERSION_ID:-}" in')
        patterns = lines[at + 1].strip().split(")")[0]
        return {tuple(p.strip('"').split(" ")) for p in patterns.split("|")}

    def test_both_installers_and_the_setup_executor_take_the_same_systems(self):
        import onboard
        self.assertEqual(self.taken(SCRIPT), SYSTEMS)
        self.assertEqual(self.taken(KIT / "join.sh"), SYSTEMS)
        self.assertEqual(onboard.SUPPORTED_OS, SYSTEMS)

    def test_every_line_that_names_the_systems_names_all_of_them(self):
        for path in (SCRIPT, KIT / "join.sh", KIT / "onboard.py", KIT / "owner_mcp.py", KIT / "HUB-INSTALL.md",
                     KIT / "INSTALL-PROMPT.md"):
            text = re.sub(r"\\\n\s*", "", path.read_text())       # a shell line goes on after a backslash
            text = re.sub(r"\s*\n[#\s]*", " ", text)              # a comment or a paragraph on its next line
            named = re.findall(r"Ubuntu 22\.04(?:[^.]|\.(?=\d))*?Debian 12(?: or 13)?", text)
            self.assertTrue(named, f"{path.name} names no system")
            for words in named:
                self.assertIn("26.04", words, f"{path.name}: {words}")
                self.assertTrue(words.endswith("Debian 12 or 13"), f"{path.name}: {words}")


class NoProviderCredential(unittest.TestCase):
    """The rule that makes this product lawful to sell: the installer never signs in to a model provider, never
    writes, copies or refreshes a provider credential, and makes no vault entry."""

    TEXT = (SCRIPT.read_text(), (KIT / "hubsetup.py").read_text())

    def test_the_installer_runs_no_provider_sign_in(self):
        for text in self.TEXT:
            lines = [line for line in text.splitlines()
                     if not line.lstrip().startswith("#") and re.search(r"\b(claude|codex|grok)\b", line)]
            for line in lines:
                self.assertNotRegex(line, r"\b(claude|codex|grok)\s+(login|auth|setup-token)",
                                    f"a provider sign-in in: {line.strip()}")

    def test_the_installer_names_no_provider_credential(self):
        for text in self.TEXT:
            code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
            for word in ("ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "OPENAI_API_KEY", "XAI_API_KEY",
                         "refresh_token", "access_token", ".credentials.json", "bws ", "save_key", "create_login"):
                self.assertNotIn(word, code, f"the installer names {word}")

    def test_the_installer_says_the_sign_in_is_the_owners_own_step(self):
        """It signs in to nothing: the owner does that from the app, on the manager's own server, and only they can."""
        text = SCRIPT.read_text()
        self.assertIn("never touches that login", text)
        self.assertIn("sign in to your own account of that provider", text)
        self.assertIn("signs you in again when the login expires", text)

    def test_the_claim_asks_for_a_manager_with_no_server_only_on_the_apps_word(self):
        """FLEET_MANAGER_SERVER=later in the installer's environment is the app's word (Founderizer 0.1.112 and
        later): only then does the claim write a manager with no server."""
        body = shell_function(SCRIPT, "first_team") + "first_team\n"
        stubs = ("sshd() { echo 'port 22'; }\nas_user() { echo \"CLAIM $*\"; }\n"
                 "address=100.80.1.2\nport=8765\nruntime=claude\nclaim_wait=1800\ntimezone=\nreclaim=no\n")
        for later, asks in (("no", False), ("yes", True)):
            code, out = run_shell(body, extra=stubs + f"manager_later={later}\n")
            self.assertEqual(code, 0, out)
            claim = next(line for line in out.splitlines() if line.startswith("CLAIM "))
            self.assertEqual("--manager-later" in claim.split(), asks, claim)

    def test_a_new_hub_says_that_no_agent_runs_on_it(self):
        """The agents step of a new hub finds none: it says where the manager goes, and installs nothing."""
        body = shell_function(SCRIPT, "agents") + "agents\n"
        stubs = ("python3() { :; }\n"          # agent-list prints no agent
                 "mktemp() { printf '%s\\n' \"$TMPDIR/agent-list\"; : > \"$TMPDIR/agent-list\"; }\n"
                 "as_agent() { echo 'it installed an agent'; }\nid() { echo 1000; }\n")
        with tempfile.TemporaryDirectory() as tmp:
            code, out = run_shell(body, extra=f"TMPDIR={tmp}\n" + stubs)
        self.assertEqual(code, 0, out)
        self.assertIn("no agent runs on this server: each agent gets a server of its own in Founderizer", out)
        self.assertNotIn("it installed an agent", out)

    def test_the_two_copies_of_the_reserved_names_stay_the_same(self):
        """fleet.py drops a reserved variable at the session start and hub.py refuses the name when the owner sets
        it. Two patterns that differ would let the owner set a name the session then silently drops."""
        self.assertEqual(hub.ENV_RESERVED.pattern, fleet.ENV_RESERVED.pattern)

    def test_a_provider_key_cannot_be_an_api_key_of_an_agent(self):
        for name in ("ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "CODEX_HOME", "XAI_API_KEY", "XAI_TOKEN",
                     "BWS_ACCESS_TOKEN", "FLEET_TASK"):
            self.assertFalse(hub.env_name(name), f"{name} is accepted as an API key name")
        for name in ("OPENAI_API_KEY", "STRIPE_SECRET_KEY", "SHOP_TOKEN", "GITHUB_PAT"):
            self.assertTrue(hub.env_name(name), f"{name} is refused as an API key name")
        # DevOps plan 0.2: only the name of a key, so no setting gives a session a model address or a proxy
        for name in ("HTTPS_PROXY", "ALL_PROXY", "OPENAI_BASE_URL", "GIT_SSH_COMMAND", "SSL_CERT_FILE", "X"):
            self.assertFalse(hub.env_name(name), f"{name} is accepted as an API key name")

    def test_the_session_drops_a_reserved_variable_it_is_given(self):
        kept = {k: v for k, v in {"XAI_API_KEY": "x", "ANTHROPIC_API_KEY": "y", "SHOP_TOKEN": "z"}.items()
                if fleet.ENV_NAME.fullmatch(k) and not fleet.ENV_RESERVED.fullmatch(k)}
        self.assertEqual(kept, {"SHOP_TOKEN": "z"})

    def test_the_three_programs_agree_on_what_a_provider_site_is(self):
        """The hub refuses the request, the vault refuses the login it reads or makes, and the helper refuses the
        sign-in it would type. Three places, because no one of them is on every path. A Mac's vault is the fourth:
        `VaultProviderSites` in the app's repository keeps the same list, and its own test pins it there."""
        self.assertEqual(hub.PROVIDER_SITES, ("claude.ai", "claude.com", "chatgpt.com", "auth.openai.com", "x.ai"))
        self.assertEqual(hub.PROVIDER_KEY_SITES, ("platform.claude.com",))
        for module in (hub, vault, fleet):
            self.assertEqual(module.PROVIDER_SITES, hub.PROVIDER_SITES)
            self.assertEqual(module.PROVIDER_KEY_SITES, hub.PROVIDER_KEY_SITES)
            for host in ("claude.ai", "CLAUDE.AI", "claude.ai.", "app.claude.ai", "claude.com", "www.claude.com",
                         "chatgpt.com", "auth.chatgpt.com", "auth.openai.com", "AUTH.OPENAI.COM.", "x.ai", "api.x.ai"):
                self.assertTrue(module.provider_site(host), f"{module.__name__} allows {host}")
            for host in ("console.anthropic.com", "platform.claude.com", "PLATFORM.CLAUDE.COM.", "platform.openai.com",
                         "api.openai.com", "openai.com", "notclaude.ai", "notclaude.com", "claude.ai.example.com",
                         "auth.openai.com.example.com", "example.com", "", None):
                self.assertFalse(module.provider_site(host), f"{module.__name__} refuses {host}")

    def test_the_vault_neither_reads_nor_makes_a_login_of_a_provider(self):
        for url in ("https://claude.ai/login", "https://claude.com/cai/oauth/authorize", "https://chatgpt.com/auth",
                    "https://x.ai/sign-in"):
            with self.assertRaises(vault.Refused) as refused:
                vault.check_login({"username": "u", "password": "p", "url": url})
            self.assertIn("model provider", str(refused.exception))
        vault.check_login({"username": "u", "password": "p", "url": "https://console.anthropic.com/settings/keys"})
        vault.check_login({"username": "", "password": "p", "url": "https://platform.claude.com/settings/keys"})

    def test_the_vault_refuses_to_make_one_for_a_hub_job(self):
        job = {"request_id": "0b0e7a52-6f0e-4d5e-9d53-1d3a3c1f0a01", "task": "T-1", "attempt": 1,
               "db": "test-generation", "label": "Claude", "username": "owner@example.com",
               "url": "https://claude.ai/account"}
        with self.assertRaises(vault.Refused) as refused:
            vault.creation(job, "seo")
        self.assertIn("model provider", str(refused.exception))
        vault.creation(dict(job, url="https://shop.example.com/keys"), "seo")       # another site is still made

    def test_sign_in_refuses_a_provider_before_it_touches_the_browser(self):
        login = {"label": "Claude", "username": "u", "password": "p", "url": "https://claude.ai/login"}
        with patch.object(fleet, "vault_mode", lambda _a: "file"), patch.object(fleet, "read_login", lambda *a, **k: login), \
                patch.object(fleet, "chrome_tab", lambda *a, **k: self.fail("it opened the browser")), \
                patch.object(sys, "platform", "darwin"):
            with self.assertRaises(fleet.Refused) as refused:
                fleet.do_signin("bws://x", "seo")
        self.assertIn("model provider", str(refused.exception))


class ProviderToolsRefuse(unittest.TestCase):
    """The hub's own tools create_login and save_key: a provider's site is refused in the call itself, before the
    task, the grants or the agent's vault are looked at, so no job is ever made and no vault is ever asked. The
    refusal sits in save_job, which is the body of both tools."""

    @classmethod
    def setUpClass(cls):
        """A records file of its own, so that the one call that gets past the refusal can go on to the next step."""
        cls.kept = hub.DB
        hub.DB = sqlite3.connect(":memory:", check_same_thread=False)
        hub.DB.row_factory = sqlite3.Row
        hub.DB.executescript(hub.SCHEMA)

    @classmethod
    def tearDownClass(cls):
        hub.DB.close()
        hub.DB = cls.kept

    ARGS = {"task_id": "T-1", "request_id": "0b0e7a52-6f0e-4d5e-9d53-1d3a3c1f0a01", "label": "Claude",
            "username": "owner@example.com", "url": "https://shop.example.com/signup"}
    KEY_ARGS = dict(ARGS, selector="#api-key", url="https://shop.example.com/settings/keys")

    def refused(self, tool, **changes):
        with self.assertRaises(hub.ToolError) as error:
            tool("seo", dict(self.KEY_ARGS if tool is hub.t_save_key else self.ARGS, **changes))
        return str(error.exception)

    def test_create_login_refuses_every_provider_site(self):
        for url in ("https://claude.ai/account", "http://CLAUDE.AI/x", "https://app.claude.ai/",
                    "https://claude.com/login", "https://chatgpt.com/#/signup", "https://x.ai/api",
                    "https://api.x.ai/v1"):
            self.assertIn("model provider", self.refused(hub.t_create_login, url=url), url)

    def test_save_key_refuses_a_provider_site_and_a_provider_page(self):
        self.assertIn("model provider", self.refused(hub.t_save_key, url="https://claude.ai/settings/keys"))
        self.assertIn("model provider", self.refused(hub.t_save_key, source_url="https://claude.ai/settings/keys"))

    def test_another_site_gets_past_this_refusal(self):
        """The positive control: an ordinary site is not stopped here. It stops later, at the task, which this test
        has none of — but not with the provider refusal."""
        for tool in (hub.t_create_login, hub.t_save_key):
            self.assertNotIn("model provider", self.refused(tool))

    def test_the_refusal_names_what_the_owner_must_do_themselves(self):
        text = self.refused(hub.t_create_login, url="https://claude.ai/account")
        for site in hub.PROVIDER_SITES:
            self.assertIn(site, text)
        self.assertIn("their own session", text)


if __name__ == "__main__":
    unittest.main()
