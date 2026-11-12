"""Servers (owner feature servers): join codes, POST /join, the server service's routes, an agent on a server, and the
removal of a server. A local hub with a temporary Fleet repository and a test source address for each machine. Also
the hub's own startup on a team.json that does not validate (PRODUCT.md 4.8), in a real hub process."""
import contextlib
import hashlib
import io
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
import sys
import unittest
import urllib.request
import uuid
from pathlib import Path
from unittest.mock import patch

import fleet
import hub
import hubsetup
from test_ui_api import OwnerAPI, parent_pipe

OWNER, HUB, VPS, STUDIO, NEW, OTHER = "127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.5", "127.0.0.9", "127.0.0.10"
KEY = "server-key-of-mini"
TEAM = {
    "hub": {"machine": "hub", "port": 8765},
    "addresses": {"owner": OWNER, "hub": HUB, "vps": VPS, "mac-studio": STUDIO},
    "access": {"vps": {"ssh_user": "claude", "ssh_port": 22}},
    "agents": {
        "manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": ["shell", "web"]},
        "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell", "web"],
                "start": "codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}",
                "runtime_policies": {"claude": {"start": "claude --permission-mode dontAsk {settings} {prompt}",
                                                "allow": ["Bash", "mcp__fleet__*"]}}},
        "studio": {"role": "worker", "runtime": "claude", "machine": "mac-studio", "can": ["shell", "web", "browser"],
                   "start": "claude --permission-mode dontAsk {chrome} {settings} {prompt}",
                   "allow": ["mcp__fleet__*", "mcp__claude-in-chrome__*"],
                   "runtime_policies": {"codex": {"start": "app-server"}}},
        "lead": {"role": "lead", "runtime": "codex", "machine": "vps", "can": ["shell", "web"]},
    },
}
PROFILE = ("# Profile: %s\n\nWritten by the owner. Agents cannot change it.\n\n**Character.** Careful.\n\n"
           "**Responsible for.** Its work.\n\n**May do without asking.** Read files.\n\n**Must ask first.** Spending.\n")


def git(*args, cwd=None):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(cls(name) for cls in (Servers, ServerService, TeamAtStartup, InstallRetries)
                              for name in cls.__dict__ if name.startswith("test_"))


def tailnet_status(names, self_ip=HUB, tags=None, tagged=None):
    """`tailscale status --json` of the hub machine with these {address: name} nodes, as hub.tailnet_status gives it,
    and the hub machine's own tags when it has some; tagged gives other machines theirs, {address: tags}."""
    node = lambda ip, name: dict({"DNSName": f"{name}.tail0000.ts.net.", "HostName": name, "TailscaleIPs": [ip]},
                                 **({"Tags": tagged[ip]} if ip in (tagged or {}) else {}))
    me = dict(node(self_ip, names.get(self_ip, "hub")), **({"Tags": tags} if tags else {}))
    return {"Self": me, "Peer": {f"nodekey:{ip}": node(ip, name) for ip, name in names.items() if ip != self_ip}}


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TeamAtStartup(unittest.TestCase):
    """PRODUCT.md 4.8: the hub starts on a team.json that validate_team refuses, and says which rule it breaks.
    A real hub process, because the decision is about starting: the file is read by main and by nothing else."""

    def hub(self, team):
        """A hub started on this team.json: (its address, the output it printed, the path of its records)."""
        root = Path(tempfile.mkdtemp(prefix="fleet-startup-"))
        self.addCleanup(shutil.rmtree, str(root), ignore_errors=True)
        (root / "team.json").write_text(json.dumps(team, indent=2))
        port = free_port()
        out = open(root / "out.txt", "w+")
        self.addCleanup(out.close)
        pipe, fds = parent_pipe(root)
        started = subprocess.Popen([sys.executable, str(Path(__file__).resolve().parent / "hub.py"),
                                    "--host", "127.0.0.1", "--port", str(port), "--db", str(root / "hub.db"),
                                    "--team", str(root / "team.json"), "--tick", "60", "--parent-pipe", str(pipe)],
                                   pass_fds=fds, stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                   env=dict(os.environ, HOME=str(root)))     # its timer sweeps ~/.fleet/attachments
        self.addCleanup(started.wait)
        self.addCleanup(started.terminate)
        url = f"http://127.0.0.1:{port}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(100):
            self.assertIsNone(started.poll(), f"the hub did not start: {(root / 'out.txt').read_text()}")
            try:
                with opener.open(url + "/health", timeout=5) as answer:
                    self.assertEqual((answer.status, json.loads(answer.read())["ok"]), (200, True))
                break
            except OSError:
                time.sleep(0.1)
        else:
            self.fail(f"the hub never answered /health: {(root / 'out.txt').read_text()}")
        return url, (root / "out.txt").read_text(), root / "hub.db"

    def page(self, url, path="/board"):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url + path, timeout=10) as answer:
            return answer.read().decode()

    def logged(self, db):
        rows = sqlite3.connect(str(db)).execute("SELECT agent, what FROM log ORDER BY id").fetchall()
        return [what for who, what in rows if who == "hub"]

    def test_a_hub_whose_team_json_misses_a_machine_address_starts_and_says_the_rule(self):
        broken = json.loads(json.dumps(TEAM))
        del broken["addresses"]["mac-studio"]       # the rule an installer or a hand edit breaks
        rule = "team.json does not validate: agent studio has no machine address"
        url, printed, db = self.hub(broken)
        self.assertIn(f"WARNING: {rule}", printed)
        self.assertIn("runs this file as it is", printed)
        self.assertEqual(self.logged(db), [rule])
        self.assertIn(rule, self.page(url))                 # the board, for as long as it holds
        self.assertIn("The hub is running a file it would refuse", self.page(url))
        self.assertIn("studio", self.page(url, "/board.txt"))       # and it is a working hub, not a crippled one

    def test_a_hub_whose_team_json_validates_says_nothing_about_it(self):
        url, printed, db = self.hub(TEAM)
        self.assertNotIn("does not validate", printed)
        self.assertNotIn("WARNING", printed)
        self.assertEqual(self.logged(db), [])
        self.assertNotIn("would refuse", self.page(url))

    def test_the_rule_is_the_one_line_hub_team_problem_gives(self):
        """One reading for the hub's output, its log, the board and `fleet.py verify`: hub.team_problem."""
        self.assertIsNone(hub.team_problem(TEAM))
        two = json.loads(json.dumps(TEAM))
        two["agents"]["second"] = dict(two["agents"]["vps"], role="manager")
        self.assertEqual(hub.team_problem(two), "team.json does not validate: team.json needs exactly one manager")
        self.assertEqual(hub.team_problem({}), "team.json does not validate: team.json needs agents")
        # A file broken in a way no rule of validate_team reaches is named by its exception, and never ends the hub
        odd = json.loads(json.dumps(TEAM))
        odd["agents"]["vps"]["reports_to"] = ["manager"]
        self.assertEqual(hub.team_problem(odd), "team.json does not validate: TypeError: unhashable type: 'list'")


class Servers(OwnerAPI):
    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp(prefix="fleet-servers-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        seed = self.root / "seed"
        (seed / "profiles").mkdir(parents=True)
        team = json.loads(json.dumps(TEAM))
        team["agents"]["vps"]["machine"] = "vps"
        (seed / "team.json").write_text(json.dumps(team, indent=2) + "\n")
        for name in TEAM["agents"]:
            (seed / "profiles" / f"{name}.md").write_text(PROFILE % name)
        shutil.copy(Path(hub.__file__).with_name("join.sh"), seed / "join.sh")
        git("init", "-q", str(seed))
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "seed", cwd=seed)
        git("clone", "-q", "--bare", str(seed), str(self.root / "origin.git"))
        git("clone", "-q", str(self.root / "origin.git"), str(self.root / "kit"))
        self.kit = self.root / "kit"
        hub.CFG["team_path"] = str(self.kit / "team.json")
        self.addCleanup(hub.CFG.pop, "team_path", None)
        hub._revision_cache.update(at=0.0, value=None)
        hub.HUB_LOAD.update(at=None, load=None)         # the hub's own measurement of its machine, from another test
        hub.TEAM = team
        hub.CFG.update(offline_after=90)
        for agent, system, runtime in (("vps", "Ubuntu 24.04.1 LTS", "codex"), ("studio", "macOS 15.6", "claude")):
            hub.q("INSERT INTO machine_status(agent,data,reported) VALUES(?,?,?)", (agent, json.dumps(
                {"os": {"name": system}, "runtime": {"name": runtime, "version": "1.0.0", "signed_in": True}}), time.time()))
        # The private network as the hub's `tailscale status --json` gives it: each machine's name in Tailscale is
        # its name in Fleet, and a join takes the joining address's name from here
        self.tailnet = {HUB: "hub", VPS: "vps", STUDIO: "mac-studio", OWNER: "macbook"}
        self.next_name = None
        self.hub_tags = None            # the tags of the hub's own machine in Tailscale
        self.peer_tags = {}             # and of the other machines: {address: tags}
        patcher = patch.object(hub, "tailnet_status", lambda: tailnet_status(
            dict({NEW: self.next_name} if self.next_name else {}, **self.tailnet), tags=self.hub_tags,
            tagged=self.peer_tags))
        patcher.start()
        self.addCleanup(patcher.stop)

    # ---- helpers
    def owner(self, path, **body):
        return self.request(path, dict(dict(request_id=str(uuid.uuid4()), db="test-generation"), **body), source=OWNER)

    def code(self, name="mini", kind="mac"):
        """A join code for the next machine, which is called `name` in Tailscale."""
        status, answer = self.owner("/ui/servers/join", kind=kind)
        self.assertEqual(status, 200, answer)
        self.next_name = name
        return answer

    def join(self, code, source=NEW, key=KEY, kind="mac", user="dana", ssh_port=None):
        if self.next_name and source not in self.tailnet:
            self.tailnet[source] = self.next_name
        return self.request("/join", {"code": code, "key_sha256": sha(key), "kind": kind, "user": user,
                                      "ssh_port": ssh_port}, source=source)

    def service(self, path, body=None, key=KEY, source=NEW):
        headers = {"Content-Type": "application/json", "X-Fleet-Client": "server-test"}
        if key:
            headers["Authorization"] = "Bearer " + key
        return self.request(path, body, headers=headers, source=source)

    def reading(self, name="mini", key=KEY, source=NEW, os_name="macOS 15.6", features=None):
        return self.service(f"/server/{name}/status", {"revision": hub.kit_revision(fresh=True), "os": {"name": os_name},
                                                     "runtimes": {"codex": {"version": None, "signed_in": None},
                                                                  "claude": {"version": "2.1.287", "signed_in": True}},
                                                     "access": {"user": "dana"},
                                                     **({"features": features} if features else {})},
                              key=key, source=source)

    def joined(self, name="mini", kind="mac", source=NEW, user="dana", ssh_port=None):
        answer = self.code(name, kind)
        status, result = self.join(answer["code"], source=source, kind=kind, user=user, ssh_port=ssh_port)
        self.assertEqual(status, 200, result)
        self.assertEqual(self.reading(name, source=source,
                                      os_name="macOS 15.6" if kind == "mac" else "Ubuntu 24.04.1 LTS")[0], 200)
        return result

    def servers(self):
        status, view = self.request("/ui/servers?db=test-generation", source=OWNER)
        self.assertEqual(status, 200, view)
        return view, {s["name"]: s for s in view["servers"]}

    def origin_team(self):
        return json.loads(git("--git-dir", str(self.root / "origin.git"), "show", "main:team.json"))

    def team_sha(self):
        return self.request("/ui/team?db=test-generation", source=OWNER)[1]["sha256"]

    def fresh_fleet(self, placed=True):
        """The fleet a customer has on their first day: the first team.json the hub installer writes, which holds one
        manager and no worker at all (hubsetup.template, through hub.sh). Everything else in this class starts from a
        fleet that has run for a while, so this is the one state that the first `Add agent` meets. `placed=False`: the
        app that installed it gives the manager a server of its own (hub.sh's FLEET_MANAGER_SERVER=later)."""
        team = hubsetup.template(HUB, owner=OWNER, placed=placed)
        (self.kit / "team.json").write_text(json.dumps(team, indent=2) + "\n")
        git("add", "team.json", cwd=self.kit)
        git("commit", "-q", "-m", hubsetup.FIRST_COMMIT, cwd=self.kit)
        git("push", "-q", "origin", "HEAD", cwd=self.kit)
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = team
        return team

    def add_agent(self, server="mini", agent="scout", runtime="claude", role="worker", reports_to=None, base=None):
        return self.owner(f"/ui/servers/{server}/agents", base_sha256=base or self.team_sha(), agent=agent,
                          runtime=runtime, role=role, reports_to=reports_to)

    def helper_reports(self, agent="scout", seen=0.0):
        """That agent's own helper has reached the hub. On a real machine the service step started it one step before
        the sign-in, and it is the process that runs the provider's flow in that agent's own home."""
        hub.q("INSERT OR REPLACE INTO agents(name,last_seen) VALUES(?,?)", (agent, hub.now() - seen))

    def ask_signin(self, server="mini", agent="scout", runtime="claude", **kwargs):
        """The server service's own ask: POST /server/<name>/signin, with its address and its key."""
        return self.service(f"/server/{server}/signin", {"agent": agent, "runtime": runtime}, **kwargs)

    # ---- join codes
    def test_each_server_has_its_load_beside_its_reading(self):
        """The owner, 4 November 2026: CPU, memory and disk for each server on Servers. A server's own service measures
        it (lifecycle.machine_load) and the hub's own machine, where nothing else may run, is measured by the hub."""
        self.joined("mini")
        load = {"cpu_percent": 14.1, "memory_used": 12428394496, "memory_total": 38654705664,
                "disk_used": 273775087616, "disk_total": 494384795648}
        status, _ = self.service("/server/mini/status", {"revision": hub.kit_revision(fresh=True),
                                                         "os": {"name": "macOS 15.6"}, "load": load})
        self.assertEqual(status, 200)
        reported = hub.q1("SELECT reported FROM server_status WHERE server='mini'")["reported"]
        here = {"cpu_percent": 3.0, "memory_used": 1, "memory_total": 2, "disk_used": 3, "disk_total": 4}
        with patch.object(hub.lifecycle, "machine_load", lambda platform: dict(here)):
            _, servers = self.servers()
        self.assertEqual(servers["mini"]["load"], dict(load, at=reported))
        self.assertNotIn("load", servers["mini"]["reading"])
        self.assertEqual({k: v for k, v in servers["hub"]["load"].items() if k != "at"}, here)
        self.assertLess(abs(servers["hub"]["load"]["at"] - hub.now()), 5)
        self.assertIsNone(servers["vps"]["load"], "a reading of its agent's helper carries no load")

    def test_the_hub_keeps_its_own_measurement_ten_seconds(self):
        """A Mac hub runs sysctl and vm_stat for it, under LOCK, and the app reads the servers every 15 seconds."""
        measured = []

        def machine_load(platform):
            measured.append(platform)
            return {"cpu_percent": float(len(measured))}
        t0 = hub.now()
        with patch.object(hub.lifecycle, "machine_load", machine_load):
            loads = [hub.server_load("hub", None, t) for t in (t0, t0 + 5, t0 + 11)]
        self.assertEqual(measured, [sys.platform, sys.platform])
        self.assertEqual(loads, [{"cpu_percent": 1.0, "at": t0}, {"cpu_percent": 1.0, "at": t0},
                                 {"cpu_percent": 2.0, "at": t0 + 11}])

    def test_a_load_figure_of_another_shape_is_none_and_the_reading_stands(self):
        """A figure is an optional field of a newer service: a wrong one never refuses the reading (runtime_update)."""
        self.joined("mini")
        status, _ = self.service("/server/mini/status", {
            "revision": hub.kit_revision(fresh=True), "os": {"name": "macOS 15.6"},
            "load": {"cpu_percent": "high", "memory_used": -5, "memory_total": 4.0e9, "disk_used": True}})
        self.assertEqual(status, 200)
        self.assertEqual({k: v for k, v in self.servers()[1]["mini"]["load"].items() if k != "at"},
                         {"cpu_percent": None, "memory_used": None, "memory_total": 4000000000, "disk_used": None,
                          "disk_total": None})
        self.assertEqual(self.service("/server/mini/status", {"revision": hub.kit_revision(fresh=True),
                                                              "os": {"name": "macOS 15.6"}, "load": "busy"})[0], 200)
        self.assertIsNone(self.servers()[1]["mini"]["load"])

    def test_a_reading_that_differs_only_in_its_load_wakes_no_app(self):
        """The load changes at every reading, and the apps read it on their own clock (live_changes): only `state`
        wakes a waiting app."""
        self.joined("mini")

        def report(cpu):
            self.assertEqual(self.service("/server/mini/status", {
                "revision": hub.kit_revision(fresh=True), "os": {"name": "macOS 15.6"},
                "runtimes": {"codex": {"version": None, "signed_in": None},
                             "claude": {"version": "2.1.287", "signed_in": True}}, "access": {"user": "dana"},
                "load": {"cpu_percent": cpu}})[0], 200)
        report(1.0)
        before = hub.CHANGE["state"]
        report(2.0)
        self.assertEqual(hub.CHANGE["state"], before)
        self.assertEqual(self.servers()[1]["mini"]["load"]["cpu_percent"], 2.0)

    def test_feature_is_offered(self):
        features = self.request(source=OWNER)[1]["ui_features"]
        self.assertIn("servers", features)
        self.assertIn("server_prepare", features)          # POST /ui/servers/<server>/prepare

    def test_join_code_is_given_once_and_kept_only_as_its_sha256(self):
        body = dict(request_id=str(uuid.uuid4()), db="test-generation", kind="mac")
        status, answer = self.request("/ui/servers/join", body, source=OWNER)
        self.assertEqual(status, 200, answer)
        code = answer["code"]
        self.assertRegex(code, r"^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$")
        self.assertEqual(answer["line"], f"curl -fsS http://{HUB}:8765/join | FLEET_JOIN={code} sh")
        self.assertAlmostEqual(answer["expires_at"], time.time() + hub.MAC_JOIN_LIFE, delta=5)
        status, again = self.request("/ui/servers/join", body, source=OWNER)
        self.assertEqual((status, again["replayed"], again["code"], again["line"]), (200, True, None, None))
        row = hub.q1("SELECT * FROM join_codes")
        self.assertEqual(row["sha256"], sha(code.replace("-", "")))
        for table in ("join_codes", "ui_controls", "log"):
            self.assertNotIn(code.replace("-", ""), json.dumps([dict(r) for r in hub.q(f"SELECT * FROM {table}")]))
            self.assertNotIn(code, json.dumps([dict(r) for r in hub.q(f"SELECT * FROM {table}")]))
        view, _ = self.servers()
        self.assertEqual({k: view["join"][k] for k in ("name", "kind", "state", "server")},
                         {"name": "", "kind": "mac", "state": "open", "server": None})
        self.assertNotIn(code, json.dumps(view))

    def test_linux_line_joins_the_private_network_first_with_the_hubs_own_tags(self):
        """A new server joins with the tags of the hub's own machine in Tailscale, by which the owner's policy gives
        the fleet's machines their rights: the product names no tag of one owner's tailnet (the owner, 3 November
        2026: "this app needs to work for ANY user")."""
        self.hub_tags = ["tag:claude-code-dev", "tag:terminal-relay-worker"]
        answer = self.code("box", "linux")
        self.assertEqual(answer["line"], "command -v tailscale >/dev/null || for try in 1 2 3; do "
                         "DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=1200 -q install </dev/null "
                         ">/dev/null 2>&1; curl -fsSL https://tailscale.com/install.sh | sh && "
                         "command -v tailscale >/dev/null && break; sleep 20; done; "
                         "tailscale status >/dev/null 2>&1 || tailscale up --advertise-tags="
                         "tag:claude-code-dev,tag:terminal-relay-worker --accept-dns=false; curl -fsS "
                         f"http://{HUB}:8765/join | FLEET_JOIN={answer['code']} sh")

    def test_a_hub_with_no_tag_asks_for_the_product_tag_only_where_the_tailnet_has_it(self):
        """A hub that the app put on the network carries tag:founderizer already. A hub with no tag asks for it only
        where another machine of the tailnet carries it, which proves that the tailnet's policy defines it, and else
        for no tag: Tailscale refuses a tag that the policy does not define, and a hub that hub.sh put on the network
        with the owner's own key carries none. A tag that the app would not read from the line is left out. A read
        that fails keeps what the last read gave, and with none asks for no tag."""
        hub.TAILNET_NAMES.pop("tags", None)
        self.addCleanup(hub.TAILNET_NAMES.pop, "tags", None)
        tagged = lambda answer: answer["line"].split("--advertise-tags=")[1].split(" ")[0]
        untagged = "tailscale status >/dev/null 2>&1 || tailscale up --accept-dns=false; curl -fsS "
        self.hub_tags = None
        self.assertIn(untagged, self.code("box", "linux")["line"])
        self.peer_tags = {VPS: ["tag:founderizer"]}
        self.assertEqual(tagged(self.code("box", "linux")), "tag:founderizer")
        self.hub_tags = ["tag:Bad Tag", "tag:fleet-a"]
        self.assertEqual(tagged(self.code("box", "linux")), "tag:fleet-a")
        with patch.object(hub, "tailnet_status", lambda: None):
            self.assertEqual(tagged(self.code("box", "linux")), "tag:fleet-a")
            hub.TAILNET_NAMES.pop("tags")
            self.assertIn(untagged, self.code("box", "linux")["line"])
        self.assertNotIn("--advertise-tags", self.code("mini", "mac")["line"])

    def test_code_needs_a_kind_and_takes_no_name(self):
        for kind, status in (("linux", 200), ("mac", 200), ("windows", 400), (None, 400)):
            self.assertEqual(self.owner("/ui/servers/join", kind=kind)[0], status, kind)
        # An older app still sends a name: the code is made, and the name is only its label (the join takes the name
        # in Tailscale, test_machine_names); a label that could be no server's name is none
        for name, label in (("mini", "mini"), ("Mini Typed", ""), ("vps", "vps")):
            status, answer = self.owner("/ui/servers/join", name=name, kind="mac")
            self.assertEqual((status, answer["name"]), (200, label), name)
        self.assertEqual(self.request("/ui/servers/join", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                               kind="mac"), source=VPS)[0], 403)

    def test_a_new_code_cancels_the_open_one(self):
        first, second = self.code("mini"), self.code("mini-2")
        status, answer = self.join(first["code"])
        self.assertEqual(status, 410, answer)
        self.assertIn("newer join code", answer["error"])
        self.assertEqual(self.join(second["code"])[0], 200)

    # ---- POST /join
    def test_join_records_the_server_at_the_address_of_the_call(self):
        answer = self.code()
        status, result = self.join(answer["code"].lower().replace("-", " "))
        self.assertEqual(status, 200, result)
        self.assertEqual({k: result[k] for k in ("server", "hub", "repo", "replayed")},
                         {"server": "mini", "hub": f"http://{HUB}:8765", "repo": f"git://{HUB}/fleet-pilot.git",
                          "replayed": False})
        team = self.origin_team()
        self.assertEqual(team["addresses"]["mini"], NEW)
        self.assertEqual(team["servers"], {"mini": {"kind": "mac", "user": "dana"}})
        self.assertNotIn("mini", team["access"])
        self.assertEqual(hub.TEAM["addresses"]["mini"], NEW)
        self.assertEqual(hub.q1("SELECT sha256 FROM server_keys WHERE server='mini'")["sha256"], sha(KEY))
        view, servers = self.servers()
        self.assertEqual(view["join"]["state"], "joined")
        self.assertEqual({k: servers["mini"][k] for k in ("kind", "address", "user", "joined", "agents", "available", "why")},
                         {"kind": "mac", "address": NEW, "user": "dana", "joined": True, "agents": [], "available": False,
                          "why": ["no_reading"]})
        self.assertNotIn(answer["code"], json.dumps([dict(r) for r in hub.q("SELECT * FROM log")]))

    def test_linux_join_records_root_ssh_access(self):
        answer = self.code("box", "linux")
        self.assertEqual(self.join(answer["code"], kind="linux", user="fleet", ssh_port=2222)[0], 200)
        team = self.origin_team()
        self.assertEqual(team["servers"]["box"], {"kind": "linux", "user": "fleet"})
        self.assertEqual(team["access"]["box"], {"ssh_user": "root", "ssh_port": 2222})

    def test_the_same_server_can_run_the_line_again(self):
        answer = self.code()
        first = self.join(answer["code"])[1]
        status, again = self.join(answer["code"])
        self.assertEqual((status, again["server"], again["replayed"]), (200, "mini", True))
        self.assertEqual(self.origin_team()["addresses"]["mini"], NEW)
        self.assertEqual(git("--git-dir", str(self.root / "origin.git"), "rev-parse", "main"), first["revision"])
        status, other = self.join(answer["code"], key="another key")
        self.assertEqual(status, 410, other)
        self.assertIn("already used", other["error"])
        self.assertEqual(self.join(answer["code"], source=OTHER)[0], 410)

    def test_the_same_server_joins_again_with_a_new_code(self):
        """A later step of join.sh can stop after the join itself (the vault step, in the proof run of 5 November
        2026), and the app's Try again or a new line brings a new code: the same server, with the key it joined with,
        joins again. Another key at that address, and a machine that joined with no key, stay refused."""
        first = self.join(self.code()["code"])[1]
        answer = self.code()
        status, again = self.join(answer["code"])
        self.assertEqual(status, 200, again)
        self.assertEqual((again["server"], again["replayed"]), ("mini", True))
        self.assertEqual(git("--git-dir", str(self.root / "origin.git"), "rev-parse", "main"), first["revision"])
        self.assertEqual(hub.q1("SELECT sha256 FROM server_keys WHERE server='mini'")["sha256"], sha(KEY))
        self.assertEqual({k: self.servers()[0]["join"][k] for k in ("state", "server")},
                         {"state": "joined", "server": "mini"})
        self.assertEqual(self.join(answer["code"])[1]["replayed"], True)    # that code is a used one now
        for key, source, words in (("another key", NEW, "already, as mini"), (KEY, VPS, "already, as vps")):
            status, refused = self.join(self.code()["code"], source=source, key=key)
            self.assertEqual(status, 409, refused)
            self.assertIn(words, refused["error"])
            self.assertEqual(self.servers()[0]["join"]["state"], "open")

    # ---- the restart time of the fleet patch policy (join.sh)
    def reboot_times(self, times):
        status, answer = self.owner("/ui/settings", settings={"servers.reboot_times": times})
        self.assertEqual(status, 200, answer)

    def test_a_linux_server_gets_the_first_restart_time_that_no_server_has(self):
        """The operator gives the hub the times that no host it did not make has (servers.reboot_times); the hub keeps
        one for each server in team.json, and its join answer carries it to join.sh. A Mac takes none."""
        self.reboot_times(["00:04", "00:12"])
        for name, source, want in (("box", NEW, "00:04"), ("box-2", OTHER, "00:12"), ("box-3", "127.0.0.11", None)):
            status, result = self.join(self.code(name, "linux")["code"], source=source, kind="linux", user="fleet")
            self.assertEqual((status, result["server"], result["reboot_time"]), (200, name, want), result)
        servers = self.origin_team()["servers"]
        self.assertEqual(servers["box"], {"kind": "linux", "user": "fleet", "reboot_time": "00:04"})
        self.assertEqual(servers["box-2"]["reboot_time"], "00:12")
        self.assertNotIn("reboot_time", servers["box-3"])          # every time is taken: security updates only
        said = hub.q1("SELECT what FROM log WHERE what LIKE 'server box joined from%'")["what"]
        self.assertTrue(said.endswith(", with the restart time 00:04"), said)
        status, mac = self.join(self.code("mini", "mac")["code"], source="127.0.0.12")
        self.assertEqual((status, mac["reboot_time"]), (200, None))
        self.assertNotIn("reboot_time", self.origin_team()["servers"]["mini"])

    def test_without_the_setting_a_server_gets_no_restart_time(self):
        status, result = self.join(self.code("box", "linux")["code"], kind="linux", user="fleet")
        self.assertEqual((status, result["reboot_time"]), (200, None))
        self.assertEqual(self.origin_team()["servers"]["box"], {"kind": "linux", "user": "fleet"})

    def test_a_server_that_joins_again_keeps_its_restart_time(self):
        """The app's Try again brings a new code: the server is the same, and so is its time. A time that a server
        that left had is free again, because only team.json holds the times."""
        self.reboot_times(["00:04", "00:12"])
        first = self.join(self.code("box", "linux")["code"], kind="linux", user="fleet")[1]
        status, again = self.join(self.code("box", "linux")["code"], kind="linux", user="fleet")
        self.assertEqual((status, again["replayed"], again["reboot_time"]), (200, True, "00:04"))
        self.assertEqual(self.origin_team()["servers"]["box"]["reboot_time"], "00:04")
        self.assertEqual(git("--git-dir", str(self.root / "origin.git"), "rev-parse", "main"), first["revision"])
        team = self.origin_team()
        del team["servers"]["box"], team["addresses"]["box"]
        self.write_team(team)
        status, other = self.join(self.code("crate", "linux")["code"], source=OTHER, kind="linux", user="fleet")
        self.assertEqual((status, other["reboot_time"]), (200, "00:04"))

    def test_the_setting_and_team_json_take_only_hh_mm_times(self):
        for bad in ("00:04", ["0:04"], ["24:00"], ["00:04", "00:04"], [4], ["00:04 "], ["00:60"]):
            status, answer = self.owner("/ui/settings", settings={"servers.reboot_times": bad})
            self.assertEqual(status, 400, (bad, answer))
        self.assertEqual(hub.reboot_times_check(["03:00", "00:04"]), ["03:00", "00:04"])
        self.assertEqual(hub.setting("servers.reboot_times"), [])
        team = json.loads(json.dumps(hub.TEAM))
        team["servers"] = {"vps": {"kind": "linux", "user": "fleet", "reboot_time": "01:34"}}
        hub.validate_team(team)
        for bad in ("1:34", "01:34:00", None, 134):
            team["servers"]["vps"]["reboot_time"] = bad
            with self.assertRaises(ValueError):
                hub.validate_team(team)

    def test_wrong_codes_make_the_address_wait(self):
        answer = self.code()
        for _ in range(5):
            status, refused = self.join("ABCD-EFGH-JKLM")
            self.assertEqual(status, 403, refused)
        status, refused = self.join(answer["code"])
        self.assertEqual(status, 429, refused)
        self.assertIn("Wait 10 minutes", refused["error"])
        self.assertEqual(self.join(answer["code"], source=OTHER)[0], 200)
        hub.q("UPDATE join_failures SET ts=ts-601")
        self.assertEqual(self.join("ABCD-EFGH-JKLM")[0], 403)

    def test_an_expired_code_is_refused(self):
        answer = self.code()
        hub.q("UPDATE join_codes SET expires=?", (time.time() - 1,))
        status, refused = self.join(answer["code"])
        self.assertEqual(status, 410, refused)
        self.assertIn("expired", refused["error"])
        self.assertEqual(self.servers()[0]["join"]["state"], "expired")

    def test_the_owner_the_hub_and_a_known_machine_cannot_join(self):
        answer = self.code()
        for source, status, words in ((OWNER, 403, "your own computer"), (HUB, 403, "the hub"),
                                      (VPS, 409, "already, as vps")):
            code, refused = self.join(answer["code"], source=source)
            self.assertEqual(code, status, refused)
            self.assertIn(words, refused["error"])
        self.assertEqual(self.join(answer["code"])[0], 200)

    def test_a_name_that_was_taken_after_the_code_is_refused(self):
        answer = self.code("mini")
        other = self.code("box", "linux")
        self.assertEqual(self.join(other["code"], source=OTHER, kind="linux", user="fleet")[0], 200)
        hub.q("UPDATE join_codes SET canceled=NULL, name='box' WHERE sha256=?", (sha(answer["code"].replace("-", "")),))
        status, refused = self.join(answer["code"])
        self.assertEqual(status, 409, refused)
        self.assertIn("named box", refused["error"])

    def test_a_hub_behind_its_repository_keeps_the_code_for_another_run(self):
        answer = self.code()
        work = self.root / "work"
        git("clone", "-q", str(self.root / "origin.git"), str(work))
        (work / "elsewhere.py").write_text("# code that the running hub does not serve\n")
        git("add", "elsewhere.py", cwd=work)
        git("commit", "-q", "-m", "a deployment that the hub has not taken", cwd=work)
        git("push", "-q", "origin", "HEAD:main", cwd=work)
        status, refused = self.join(answer["code"])
        self.assertEqual(status, 409, refused)
        self.assertIn("Run the line again in a few minutes", refused["error"])
        self.assertIsNone(hub.q1("SELECT used FROM join_codes")["used"])
        git("pull", "-q", "--ff-only", cwd=self.kit)            # the hub's reload
        hub._revision_cache.update(at=0.0, value=None)
        self.assertEqual(self.join(answer["code"])[0], 200)

    def test_join_checks_its_body(self):
        answer = self.code()
        for change in ({"key_sha256": "abc"}, {"kind": "windows"}, {"user": "bad user"}, {"ssh_port": 22},
                       {"code": 5}):
            body = dict({"code": answer["code"], "key_sha256": sha(KEY), "kind": "mac", "user": "dana", "ssh_port": None},
                        **change)
            self.assertEqual(self.request("/join", body, source=NEW)[0], 400, change)

    # ---- the server service's routes
    def test_server_routes_need_the_address_and_the_key(self):
        self.joined()
        status, answer = self.reading()
        self.assertEqual((status, answer["desired_revision"]), (200, hub.kit_revision(fresh=True)))
        for key, source in (("wrong", NEW), (None, NEW), (KEY, OTHER), (KEY, OWNER)):
            self.assertEqual(self.reading(key=key, source=source)[0], 403, (key, source))
            self.assertEqual(self.service("/server/mini/jobs", key=key, source=source)[0], 403)
            self.assertEqual(self.ask_signin(key=key, source=source)[0], 403, (key, source))
        self.assertEqual(self.reading("vps", key=KEY, source=VPS)[0], 403)
        self.assertNotIn(KEY, json.dumps([dict(r) for r in hub.q("SELECT * FROM log")]))
        self.assertEqual(self.count("signin_jobs"), 0)

    def test_a_server_starts_the_sign_in_of_its_own_agents_only(self):
        """POST /server/<name>/signin is the one way the install and the prepare step reach a sign-in, and it reaches
        the sign-in of this server's own agents and of nothing else."""
        self.joined()
        self.add_agent()
        self.helper_reports()
        for agent, status in (("vps", 404), ("nobody", 404), (None, 404), ("scout", 200)):
            answer = self.ask_signin(agent=agent)
            self.assertEqual(answer[0], status, (agent, answer))
        self.assertEqual(self.ask_signin()[1]["changed"], False)        # the open one, never a second
        self.assertEqual(self.count("signin_jobs"), 1)
        row = hub.q1("SELECT * FROM signin_jobs WHERE agent='scout'")
        self.assertEqual((row["runtime"], row["state"]), ("claude", "starting"))
        # the sign-in the owner finishes is the one on that agent's Machines row, and the link lives only there
        code, state = self.request("/ui/machines?db=test-generation", source=OWNER)
        self.assertEqual(code, 200, state)
        seen = next(m for m in state["machines"] if m["agent"] == "scout")["login"]
        self.assertEqual((seen["id"], seen["state"], seen["runtime"]), (row["id"], "starting", "claude"))

    def test_a_sign_in_waits_for_the_agents_helper_and_refuses_grok(self):
        self.joined()
        self.add_agent()
        answer = self.ask_signin()                          # its helper has not reached the hub yet
        self.assertEqual(answer[0], 503, answer)
        self.assertIn("has not reached the hub yet", answer[1]["error"])
        self.helper_reports(seen=hub.MACHINE_STALE + 60)    # or stopped reaching it
        self.assertEqual(self.ask_signin()[0], 503)
        self.helper_reports()
        self.assertEqual(self.ask_signin(runtime="grok")[0], 409)
        self.assertEqual(self.ask_signin(runtime="gemini")[0], 400)
        self.assertEqual(self.ask_signin(runtime=None)[0], 400)
        self.assertEqual(self.count("signin_jobs"), 0)

    def test_a_sign_in_of_the_other_runtime_is_refused_and_not_handed_back(self):
        """The owner can have started a sign-in on the Machines page. One for the runtime this job wants is that
        job's sign-in; one for the other runtime is refused, because the job waits for its own runtime."""
        self.joined()
        self.add_agent()
        self.helper_reports()
        code, answer = self.request("/ui/machines/scout/signin",
                                    dict(request_id=str(uuid.uuid4()), db="test-generation", runtime="codex"),
                                    source=OWNER)
        self.assertEqual(code, 200, answer)
        refused = self.ask_signin(runtime="claude")
        self.assertEqual(refused[0], 409, refused)
        self.assertIn("open Codex sign-in", refused[1]["error"])
        self.assertEqual(self.ask_signin(runtime="codex")[1]["login"]["id"], answer["login"]["id"])
        self.assertEqual(self.count("signin_jobs"), 1)

    def test_a_current_reading_makes_a_free_server_available(self):
        self.joined()
        _, servers = self.servers()
        mini = servers["mini"]
        self.assertEqual((mini["available"], mini["why"], mini["reading"]["source"]), (True, [], "server"))
        self.assertTrue(mini["reading"]["current"])
        self.assertIsNone(servers["mac-studio"]["reading"]["current"])     # its agent's helper sent no revision
        self.assertEqual(mini["reading"]["runtimes"]["claude"], {"version": "2.1.287", "signed_in": True})
        self.assertEqual(servers["vps"]["why"], ["has_agent", "no_service"])
        self.assertEqual(servers["hub"]["why"], ["hub_machine", "has_agent", "no_service"])
        self.assertNotIn("owner", servers)
        hub.q("UPDATE server_status SET reported=reported-601")
        self.assertEqual(self.servers()[1]["mini"]["why"], ["offline"])

    def test_an_old_machine_shows_the_reading_of_its_agent(self):
        studio = self.servers()[1]["mac-studio"]
        self.assertEqual((studio["kind"], studio["agents"], studio["reading"]["source"]), ("mac", ["studio"], "agent"))
        self.assertEqual(studio["reading"]["runtimes"], {"claude": {"version": "1.0.0", "signed_in": True}})
        self.assertEqual(self.servers()[1]["vps"]["kind"], "linux")

    # ---- an agent on a server
    def test_add_agent_registers_it_with_its_profile_and_gives_the_server_a_job(self):
        self.joined()
        before = git("--git-dir", str(self.root / "origin.git"), "rev-parse", "main")
        status, receipt = self.add_agent()
        self.assertEqual(status, 200, receipt)
        team = self.origin_team()
        self.assertEqual(team["agents"]["scout"], {     # a Mac's agent holds its desktop (hub.with_desktop)
            "start": "claude --permission-mode dontAsk {chrome} {settings} {prompt}",
            "allow": ["mcp__fleet__*", "mcp__claude-in-chrome__*"], "role": "worker", "machine": "mini",
            "runtime": "claude", "can": ["shell", "web", "browser", "screen"], "screen_command": hub.MAC_SCREEN_COMMAND,
            "active": False, "vault": "none"})
        files = git("--git-dir", str(self.root / "origin.git"), "diff", "--name-only", before, "main").split()
        self.assertEqual(sorted(files), ["profiles/scout.md", "team.json"])
        self.assertEqual(git("--git-dir", str(self.root / "origin.git"), "rev-list", "--count", f"{before}..main"), "1")
        profile = git("--git-dir", str(self.root / "origin.git"), "show", "main:profiles/scout.md")
        self.assertIn("**Responsible for.** Research, writing, code and files on its server.", profile)
        self.assertNotIn("browser", profile)
        self.assertEqual(hub.agents()["scout"]["machine"], "mini")
        status, jobs = self.service("/server/mini/jobs")
        self.assertEqual(jobs["jobs"], [{"id": receipt["job"], "kind": "install", "agent": "scout", "runtime": "claude",
                                         "state": "queued"}])
        mini = self.servers()[1]["mini"]
        self.assertEqual((mini["agents"], mini["available"], mini["why"]), (["scout"], False, ["has_agent", "busy"]))
        self.assertEqual(mini["job"]["state"], "queued")

    def test_the_start_settings_come_from_a_server_of_the_same_kind(self):
        self.joined("box", "linux", source=OTHER, user="fleet")
        self.assertEqual(self.add_agent("box", "coder", "claude")[0], 200)
        entry = self.origin_team()["agents"]["coder"]
        self.assertEqual((entry["start"], entry["allow"]), ("claude --permission-mode dontAsk {settings} {prompt}",
                                                            ["Bash", "mcp__fleet__*"]))
        self.assertEqual((entry["can"], "screen_command" in entry), (["shell", "web"], False))     # Linux: no desktop

    def test_the_first_worker_of_a_fleet_is_added_although_there_is_none_to_copy(self):
        """The customer's first day: the hub installer's team.json holds one manager and nothing else, so there is no
        worker whose start settings a new agent can take. It must still be added, or no fleet could ever get its
        first agent."""
        self.fresh_fleet()
        self.joined("box", "linux", source=OTHER, user="fleet")
        status, receipt = self.add_agent("box", "coder", "claude")
        self.assertEqual(status, 200, receipt)
        self.assertEqual(self.origin_team()["agents"]["coder"], {
            "start": hubsetup.WORKER_STARTS["claude"], "allow": hub.FULL_ACCESS["claude"]["allow"], "role": "worker",
            "machine": "box", "runtime": "claude", "can": ["shell", "web"], "active": False, "vault": "none"})

    def test_the_first_worker_has_full_access_and_never_the_manager_s_line(self):
        """Plan C15 (the owner, 26 October 2026: workers act without asking): a fleet's first worker starts in Fleet's
        full-access worker form, as the workers a switch writes do, and never in the manager's own line, which
        bypasses permissions with no Fleet deny list."""
        self.fresh_fleet()
        for server, source, agent, runtime in (("box", OTHER, "coder", "claude"),
                                               ("box2", "127.0.0.11", "runner", "codex")):
            self.joined(server, "linux", source=source, user="fleet")
            self.assertEqual(self.add_agent(server, agent, runtime)[0], 200)
            entry = self.origin_team()["agents"][agent]
            self.assertEqual(entry["start"], hubsetup.WORKER_STARTS[runtime])
            self.assertNotIn("bypassPermissions", entry["start"])
            self.assertNotIn("dangerously-skip-permissions", entry["start"])
            self.assertTrue(hub.full_access(runtime, entry), entry)
        # The one that matters: the manager's Claude line bypasses permissions, and a first worker never takes it.
        self.assertNotEqual(hubsetup.WORKER_STARTS["claude"], hubsetup.STARTS["claude"])
        self.assertIn("bypassPermissions", hubsetup.STARTS["claude"])

    def test_a_worker_of_the_fleet_still_wins_over_the_installers_line(self):
        """The fallback is for the first worker only: a fleet that has one keeps copying it, with its allow list."""
        self.joined("box", "linux", source=OTHER, user="fleet")
        self.assertEqual(self.add_agent("box", "coder", "claude")[0], 200)
        entry = self.origin_team()["agents"]["coder"]
        self.assertEqual(entry["start"], "claude --permission-mode dontAsk {settings} {prompt}")
        self.assertEqual(entry["allow"], ["Bash", "mcp__fleet__*"])

    def test_a_codex_agent_never_takes_the_app_server_policy(self):
        self.joined()
        self.assertEqual(self.add_agent(agent="scout", runtime="codex", role="lead")[0], 200)
        entry = self.origin_team()["agents"]["scout"]
        self.assertEqual((entry["start"], entry["role"]),
                         ("codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}", "lead"))
        self.assertNotIn("allow", entry)

    def test_reports_to_a_lead_is_kept_and_to_the_manager_is_the_default(self):
        self.joined()
        self.assertEqual(self.add_agent(reports_to="lead")[0], 200)
        self.assertEqual(self.origin_team()["agents"]["scout"]["reports_to"], "lead")

    def test_add_agent_refusals(self):
        self.assertEqual(self.add_agent("vps")[0], 409)                     # no server service
        self.assertEqual(self.add_agent("nowhere")[0], 404)
        answer = self.code()
        self.assertEqual(self.join(answer["code"])[0], 200)
        status, refused = self.add_agent()
        self.assertEqual(status, 409, refused)                              # no reading yet
        self.assertIn("no reading", refused["error"])
        self.reading()
        self.assertEqual(self.add_agent(agent="studio")[0], 409)            # the name exists
        self.assertEqual(self.add_agent(reports_to="vps")[0], 400)          # a worker leads nobody
        self.assertEqual(self.add_agent(agent="owner")[0], 400)
        self.assertEqual(self.add_agent(agent="hub")[0], 400)               # the hub signs its own messages
        self.assertEqual(self.add_agent(agent="scout\n")[0], 400)           # `$` let a final newline through
        self.assertEqual(self.add_agent(runtime="grok")[0], 400)
        status, conflict = self.add_agent(base="0" * 64)
        self.assertEqual((status, conflict["sha256"]), (409, self.team_sha()))
        self.assertIsNone(hub.kv_get(hub.AGENT_FIRST_MESSAGE + "scout"))    # no refusal above began anything
        self.assertEqual(self.add_agent()[0], 200)
        self.assertEqual(hub.kv_get(hub.AGENT_FIRST_MESSAGE + "scout"), "wait")     # it writes to the owner first, once
        self.assertEqual(self.add_agent(agent="second")[0], 409)            # busy, and it has an agent

    def job_ends(self, job, server="mini"):
        status, answer = self.service(f"/server/{server}/jobs/{job}", {"state": "done", "step": "sign_in",
                                                                       "detail": "It runs.", "prompt": None})
        self.assertEqual(status, 200, answer)

    def write_team(self, team):
        """team.json as an earlier owner write left it, committed and pushed as the hub's own would be."""
        (self.kit / "team.json").write_text(json.dumps(team, indent=2) + "\n")
        git("add", "team.json", cwd=self.kit)
        git("commit", "-q", "-m", "earlier owner writes", cwd=self.kit)
        git("push", "-q", "origin", "HEAD", cwd=self.kit)
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = team

    def test_a_server_with_an_agent_takes_another_once_its_service_gives_a_new_agent_its_key(self):
        """The owner, 3 November 2026, of "No free server." under Add agent: "this is confusing, since we allow
        multiple agents per server... right?" His fleet runs two agents on one server and five on its Mac Studio."""
        self.joined()
        self.job_ends(self.add_agent()[1]["job"])
        mini = self.servers()[1]["mini"]
        # A service that cannot give a new agent its key: its helper could not register one beside scout
        self.assertEqual((mini["agents"], mini["available"], mini["why"]), (["scout"], False, ["has_agent"]))
        status, refused = self.add_agent(agent="second")
        self.assertEqual(status, 409, refused)
        self.assertIn("older Founderizer", refused["error"])
        self.reading(features=[hub.INSTALL_KEY])
        # scout has no agent key of its own: beside a second agent its helper would be refused (review of the change)
        mini = self.servers()[1]["mini"]
        self.assertEqual((mini["available"], mini["why"]), (False, ["agent_not_ready"]))
        status, refused = self.add_agent(agent="second")
        self.assertEqual(status, 409, refused)
        self.assertIn("Scout on mini cannot share it yet", refused["error"])
        hub.ins("INSERT INTO agent_keys(agent,sha256,created,source) VALUES(?,?,?,'owner')", ("scout", sha("scout"), hub.now()))
        mini = self.servers()[1]["mini"]
        self.assertEqual((mini["agents"], mini["available"], mini["why"]), (["scout"], True, []))
        status, receipt = self.add_agent(agent="second")
        self.assertEqual(status, 200, receipt)
        self.assertEqual({n for n, a in self.origin_team()["agents"].items() if a["machine"] == "mini"},
                         {"scout", "second"})
        self.assertEqual(self.service("/server/mini/jobs")[1]["jobs"],
                         [{"id": receipt["job"], "kind": "install", "agent": "second", "runtime": "claude",
                           "state": "queued"}])
        self.assertEqual(self.servers()[1]["mini"]["why"], ["busy"])

    def test_a_server_where_another_agent_holds_fix_takes_no_agent_and_says_why(self):
        self.joined()
        self.reading(features=[hub.INSTALL_KEY])
        team = self.origin_team()
        team["agents"]["vps"]["servers"] = {"mini": "fix"}      # root there through the door (DevOps plan C4)
        self.write_team(team)
        mini = self.servers()[1]["mini"]
        self.assertEqual((mini["available"], mini["why"]), (False, ["fix_holder"]))
        status, refused = self.add_agent()
        self.assertEqual(status, 409, refused)
        self.assertIn("vps holds Fix on mini", refused["error"])

    def test_an_install_job_gives_its_new_agent_its_first_key_and_no_other(self):
        """On a server with several agents a helper cannot register its own key (Handler.helper_key), so the service
        that installs it does, from the agent's own home, for that job's agent only."""
        self.joined()
        job = self.add_agent()[1]["job"]

        def key(digest, state="running"):
            return self.service(f"/server/mini/jobs/{job}", {"state": state, "step": "service", "detail": "Starting Scout.",
                                                             "prompt": None, "key_sha256": digest})
        self.assertEqual(key("A" * 64)[0], 400)                            # lowercase hex only
        self.assertEqual(key(sha("one"), state="done")[0], 400)             # with a running step only
        self.assertIsNone(hub.agent_key("scout"))
        self.assertEqual(key(sha("one"))[0], 200)
        self.assertEqual((hub.agent_key("scout")["sha256"],
                          hub.q1("SELECT source FROM agent_keys WHERE agent='scout'")["source"]), (sha("one"), "server"))
        self.assertEqual(key(sha("one"))[0], 200)                           # the same key again: a lost answer
        status, refused = key(sha("two"))
        self.assertEqual((status, refused["error"]), (409, "scout already has another key; only the owner replaces it"))
        self.assertEqual(hub.agent_key("scout")["sha256"], sha("one"))
        with self.assertRaises(hub.Refusal):                                # a prepare job gives no key
            hub.install_key({"kind": "prepare", "agent": "scout", "server": "mini", "id": job}, sha("one"))
        with self.assertRaises(hub.Refusal) as moved:                       # nor a server the agent left (review)
            hub.install_key({"kind": "install", "agent": "scout", "server": "elsewhere", "id": job}, sha("one"))
        self.assertEqual((moved.exception.status, str(moved.exception)), (409, "scout does not run on elsewhere any more"))
        self.job_ends(job)
        self.assertEqual(key(sha("one"))[0], 409)                           # an ended job gives nothing any more
        self.assertEqual(self.service(f"/server/mini/jobs/{job + 1}", {"state": "running", "step": "service",
                                      "detail": "x", "prompt": None, "key_sha256": sha("one")})[0], 404)

    def test_a_job_reports_its_steps_and_the_sign_in(self):
        self.joined()
        job = self.add_agent()[1]["job"]
        path = f"/server/mini/jobs/{job}"
        self.assertEqual(self.service(path, {"state": "running", "step": "runtime", "detail": "Installing Claude Code."})[0],
                         200)
        self.helper_reports()
        lid = self.ask_signin()[1]["login"]["id"]
        prompt = {"kind": "signin", "purpose": "claude_login", "agent": "scout", "login": lid}
        self.assertEqual(self.service(path, {"state": "needs_owner", "step": "sign_in", "detail": None,
                                            "prompt": prompt})[0], 200)
        shown = self.servers()[1]["mini"]["job"]
        self.assertEqual((shown["state"], shown["step"], shown["prompt"]), ("needs_owner", "sign_in", prompt))
        for bad in ({"kind": "open_url", "purpose": "codex_login", "url": "http://auth.openai.com/codex/device",
                     "code": "ABCD-1234"},
                    {"kind": "open_url", "purpose": "codex_login", "url": "https://evil.example/codex", "code": "ABCD-1234"},
                    {"kind": "terminal", "purpose": "claude_login", "command": "claude"},
                    {"kind": "signin", "purpose": "other", "agent": "scout", "login": lid},
                    {"kind": "signin", "purpose": "claude_login", "agent": "scout", "login": 0},
                    {"kind": "signin", "purpose": "claude_login", "agent": "scout", "login": lid, "url": "x"}):
            self.assertEqual(self.service(path, {"state": "needs_owner", "step": "sign_in", "prompt": bad})[0], 400, bad)
        # a well-formed prompt that names another agent, or a sign-in that is not this agent's, is refused
        for other in ({"kind": "signin", "purpose": "claude_login", "agent": "vps", "login": lid},
                      {"kind": "signin", "purpose": "claude_login", "agent": "scout", "login": lid + 1000}):
            self.assertEqual(self.service(path, {"state": "needs_owner", "step": "sign_in", "prompt": other})[0], 409, other)
        self.assertEqual(self.service(path, {"state": "running", "step": "sign_in", "prompt": prompt})[0], 400)
        codex = {"kind": "open_url", "purpose": "codex_login", "url": "https://auth.openai.com/codex/device",
                 "code": "ABCD-12345"}
        self.assertEqual(self.service(path, {"state": "needs_owner", "step": "sign_in", "prompt": codex})[0], 200)
        self.assertEqual(self.service(path, {"state": "done", "step": "sign_in", "detail": "scout runs on mini."})[0], 200)
        self.assertIsNone(self.servers()[1]["mini"]["job"]["prompt"])
        self.assertEqual(self.service(path, {"state": "running", "step": "runtime"})[0], 409)
        self.assertEqual(self.service("/server/mini/jobs")[1]["jobs"], [])
        self.assertEqual(self.service("/server/mini/jobs/999", {"state": "running"})[0], 404)

    def test_a_sign_in_step_that_only_waited_for_the_owner_says_so(self):
        """`timed_out` (UI-API.md 1.88) goes with `failed` only, and the app reads it from the job: a sign-in step
        that waited for the owner and got nothing is no fault, and his provider page shows no line for it."""
        self.joined()
        path = f"/server/mini/jobs/{self.add_agent()[1]['job']}"
        self.assertEqual(self.service(path, {"state": "running", "step": "sign_in", "timed_out": True})[0], 400)
        self.assertEqual(self.service(path, {"state": "failed", "step": "sign_in", "timed_out": 1})[0], 400)
        self.assertIs(self.servers()[1]["mini"]["job"]["timed_out"], False)
        self.assertEqual(self.service(path, {"state": "failed", "step": "sign_in", "timed_out": True,
                                             "detail": "Claude Code did not sign in within 15 minutes."})[0], 200)
        self.assertIs(self.servers()[1]["mini"]["job"]["timed_out"], True)

    def test_a_failed_install_can_go_again_without_a_new_commit(self):
        self.joined()
        first = self.add_agent()[1]
        self.service(f"/server/mini/jobs/{first['job']}", {"state": "failed", "step": "checkout", "detail": "No network."})
        status, again = self.add_agent()
        self.assertEqual(status, 200, again)
        self.assertEqual(again["revision"], first["revision"])
        self.assertNotEqual(again["job"], first["job"])
        self.assertEqual(self.add_agent(runtime="codex")[0], 409)          # another agent, not the same install again

    def test_a_silent_job_fails(self):
        self.joined()
        job = self.add_agent()[1]["job"]
        hub.q("UPDATE server_jobs SET updated=updated-1801 WHERE id=?", (job,))
        shown = self.servers()[1]["mini"]["job"]
        self.assertEqual(shown["state"], "failed")
        self.assertIn("stopped answering", shown["detail"])

    # ---- the other runtime of an agent on a server (owner feature runtime_switch)
    def prepare(self, server="mini", agent="scout", runtime="codex", request_id=None):
        return self.request(f"/ui/servers/{server}/prepare", {"request_id": request_id or str(uuid.uuid4()),
                                                              "db": "test-generation", "agent": agent,
                                                              "runtime": runtime}, source=OWNER)

    def installed(self, runtime="claude"):
        """mini with the agent scout, whose install ended."""
        self.joined()
        job = self.add_agent(runtime=runtime)[1]["job"]
        self.assertEqual(self.service(f"/server/mini/jobs/{job}", {"state": "done", "step": "sign_in"})[0], 200)

    def test_prepare_gives_the_server_a_job_and_changes_no_agent(self):
        self.installed()
        before = git("--git-dir", str(self.root / "origin.git"), "rev-parse", "main")
        request_id = str(uuid.uuid4())
        status, receipt = self.prepare(request_id=request_id)
        self.assertEqual(status, 200, receipt)
        self.assertEqual({k: receipt[k] for k in ("agent", "server", "runtime", "replayed")},
                         {"agent": "scout", "server": "mini", "runtime": "codex", "replayed": False})
        status, again = self.prepare(request_id=request_id)           # a lost receipt: the same job
        self.assertEqual((status, again["job"], again["replayed"]), (200, receipt["job"], True))
        self.assertEqual(git("--git-dir", str(self.root / "origin.git"), "rev-parse", "main"), before)
        self.assertEqual(hub.agents()["scout"]["runtime"], "claude")
        self.assertEqual(self.service("/server/mini/jobs")[1]["jobs"], [
            {"id": receipt["job"], "kind": "prepare", "agent": "scout", "runtime": "codex", "state": "queued"}])
        mini = self.servers()[1]["mini"]
        self.assertEqual((mini["job"]["kind"], mini["job"]["state"], mini["why"]), ("prepare", "queued", ["has_agent", "busy"]))
        path = f"/server/mini/jobs/{receipt['job']}"
        self.assertEqual(self.service(path, {"state": "running", "step": "runtime", "detail": "Installing Codex 0.160.0."})[0],
                         200)
        codex = {"kind": "open_url", "purpose": "codex_login", "url": "https://auth.openai.com/codex/device",
                 "code": "ABCD-12345"}
        self.assertEqual(self.service(path, {"state": "needs_owner", "step": "sign_in", "prompt": codex})[0], 200)
        self.assertEqual(self.servers()[1]["mini"]["job"]["prompt"], codex)
        self.assertEqual(self.service(path, {"state": "done", "step": "sign_in", "detail": "Codex is ready."})[0], 200)
        self.assertEqual(self.service("/server/mini/jobs")[1]["jobs"], [])
        self.assertEqual(self.prepare()[0], 200)                       # again: the job checks each step again

    def test_prepare_refusals(self):
        self.assertEqual(self.prepare("nowhere")[0], 404)
        self.assertEqual(self.prepare("vps", agent="vps", runtime="claude")[0], 409)    # no server service
        self.installed()
        for server, agent, runtime, status, words in (("mini", "nobody", "codex", 404, "no such agent"),
                                                      ("mini", "vps", "claude", 409, "Vps is not on mini."),
                                                      ("mini", "scout", "claude", 409, "Scout runs Claude Code already.")):
            code, refused = self.prepare(server, agent, runtime)
            self.assertEqual(code, status, refused)
            self.assertIn(words, refused["error"])
        self.assertEqual(self.prepare(runtime="grok")[0], 400)
        self.assertEqual(self.prepare(agent="owner")[0], 400)
        hub.TEAM["agents"]["scout"]["runtime"] = "grok"
        self.assertIn("Scout cannot switch to Codex.", self.prepare()[1]["error"])
        hub.TEAM["agents"]["scout"]["runtime"] = "claude"
        hub.q("UPDATE server_status SET reported=reported-601")
        status, refused = self.prepare()
        self.assertEqual(status, 409, refused)
        self.assertIn("no reading", refused["error"])
        self.reading()
        self.assertEqual(self.prepare()[0], 200)
        for status, refused in (self.prepare(), self.add_agent(agent="second")):
            self.assertEqual(status, 409, refused)
            self.assertIn("mini prepares a provider for scout now", refused["error"])
        self.assertEqual(self.request("/ui/servers/mini/prepare", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                                   "agent": "scout", "runtime": "codex"}, source=VPS)[0], 403)

    def test_a_failed_preparation_never_installs_the_agent_again(self):
        self.installed()
        job = self.prepare()[1]["job"]
        self.service(f"/server/mini/jobs/{job}", {"state": "failed", "step": "sign_in", "detail": "No sign-in."})
        status, refused = self.add_agent()
        self.assertEqual(status, 409, refused)
        self.assertIn("an agent named scout exists", refused["error"])
        status, again = self.prepare()
        self.assertEqual(status, 200, again)
        self.assertNotEqual(again["job"], job)

    # ---- removal
    def test_a_server_without_agents_can_leave(self):
        self.joined("box", "linux", source=OTHER, user="fleet", ssh_port=22)
        status, receipt = self.owner("/ui/servers/box/remove", base_sha256=self.team_sha())
        self.assertEqual((status, receipt["removed"]), (200, True), receipt)
        team = self.origin_team()
        self.assertNotIn("box", team["addresses"])
        self.assertNotIn("box", team["access"])
        self.assertNotIn("servers", team)
        self.assertNotIn("box", self.servers()[1])
        self.assertEqual(self.reading("box", source=OTHER, os_name="Ubuntu 24.04.1 LTS")[0], 403)
        status, refused = self.owner("/ui/servers/vps/remove", base_sha256=self.team_sha())
        self.assertEqual((status, refused["agents"]), (409, ["vps", "lead"]))
        self.assertEqual(self.owner("/ui/servers/hub/remove", base_sha256=self.team_sha())[0], 409)
        self.assertEqual(self.owner("/ui/servers/owner/remove", base_sha256=self.team_sha())[0], 404)

    # ---- team.json and the join script
    def test_team_json_servers_entries(self):
        good = json.loads(json.dumps(hub.TEAM))
        good["addresses"]["mini"] = NEW
        good["servers"] = {"mini": {"kind": "mac", "user": "dana"}}
        hub.validate_team(good)
        for servers in ({"nowhere": {"kind": "mac", "user": "dana"}}, {"owner": {"kind": "mac", "user": "dana"}},
                        {"mini": {"kind": "bsd", "user": "dana"}}, {"mini": {"kind": "mac"}},
                        {"mini": {"kind": "mac", "user": "dana", "x": 1}}, []):
            bad = dict(good, servers=servers)
            with self.assertRaises(ValueError, msg=servers):
                hub.validate_team(bad)

    def test_the_join_script_names_this_hub_and_holds_no_code(self):
        hub.kv_set("fleet_id", "0123456789abcdef")
        status, text = self.text("/join")
        self.assertEqual(status, 200)
        self.assertIn(f'HUB="http://{HUB}:8765"', text)
        self.assertIn(f'REPO="git://{HUB}/fleet-pilot.git"', text)
        # where a Mac takes its signed vault (join.sh mac_vault)
        self.assertIn('FLEET="0123456789abcdef"', text)
        self.assertIn(f'CHANNEL="{hub.release_channel().rstrip("/")}"', text)
        self.assertIn('TRACK="approved"', text)
        self.assertNotIn("__FLEET_", text)

    def test_the_join_script_of_an_early_fleet_names_the_early_track(self):
        """PRODUCT.md 4.3, "Two tracks": a Mac of a fleet whose setting releases.early is on takes its vault from the
        early track, as the hub takes its releases from it."""
        hub.TEAM["settings"] = {"releases.early": True}
        status, text = self.text("/join")
        self.assertEqual(status, 200)
        self.assertIn('TRACK="early"', text)
        self.assertNotIn("__FLEET_", text)

    def text(self, path):
        import urllib.request
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(self.base + path, timeout=5) as r:
            return r.status, r.read().decode()


if __name__ == "__main__":
    unittest.main()


class FakeLife:
    """The machine reading of the server service, with a sign-in that becomes true after `after` readings."""
    def __init__(self, signed_in=True, after=0):
        self.signed_in, self.after, self.reads = signed_in, after, 0

    def runtime(self, name):
        self.reads += 1
        return {"name": name, "version": "1.0.0", "signed_in": self.signed_in or self.reads > self.after}

    def os_info(self):
        return {"name": "Ubuntu 24.04.1 LTS", "kernel": "6.8.0"}

    def security(self):
        return {"unattended_upgrades": True, "pending_security": 0, "reboot_required": False, "firewall": "active",
                "tailscale": True}

    def private_network(self):
        return True

    def access(self):
        return {"ssh": True, "screen_sharing": None}


class ServerService(Servers):
    """server.py against this hub: the join, the reading, an install job and its sign-in, and the self-update."""

    def setUp(self):
        super().setUp()
        import server
        self.mod = server
        self.home = self.root / "home"
        self.home.mkdir()
        for name, value in (("HOME", str(self.home)), ("FLEET", str(self.home / ".fleet")),
                            ("KEY_FILE", str(self.home / ".fleet" / "server.key")),
                            ("CONF_FILE", str(self.home / ".fleet" / "server.json"))):
            patcher = patch.object(server, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.commands, self.restarts = [], []
        self.own = self.home / "fleet-server"              # the server service's own checkout
        git("clone", "-q", str(self.root / "origin.git"), str(self.own))
        # Each agent of a Linux machine has an OS user of its own, which the root helper of the installers makes
        # (hubsetup.agent_helper): its home holds that agent's checkout, runtime, credential and service, and this
        # service reaches it only as that user. Here the helper is answered, the homes are real folders of the test,
        # and the runtimes both machines already have are the two.
        self.homes = self.root / "homes"
        self.homes.mkdir()
        self.made, self.present, self.no_helper = {}, {"claude", "codex"}, False

    def agent_user_made(self, user):
        """What the root helper of the installers answers: that OS user, with a home of mode 700 of its own."""
        self.assertRegex(user, r"^fleet-[a-z][a-z0-9-]{1,25}$")
        home = self.homes / user
        home.mkdir(mode=0o700, exist_ok=True)
        self.made[user] = str(home)
        return 0, f"fleet-agent-user: {user} is the OS user of that agent\n", ""

    def accounts(self, user):
        """The password database of this machine: the agent users the helper has made, and nothing else."""
        return (4000 + sorted(self.made).index(user), self.made[user]) if user in self.made else None

    def agent_home(self, agent="scout"):
        return Path(self.made.get("fleet-" + agent) or self.home)

    def checkout_of(self, agent="scout"):
        return self.agent_home(agent) / ("fleet-" + agent)

    def exe_of(self, name, home):
        """lifecycle.exe for this test: a runtime that this machine has, or one whose installer has run here."""
        onboard = self.mod.onboard
        script = onboard.runtime_install(name, onboard.RUNTIME_PINS.get(name, ""))
        ran = any(argv[0].endswith("sh") and script in argv[-1] for argv, _cwd, _user in self.commands)
        return f"{home}/.local/bin/{name}" if name in self.present or ran else None

    def becomes(self, argv):
        """(the OS user this command is taken as, the folder it runs from, the command itself). The test unwraps
        what server.py wraps, so each step is proved and the way it becomes the agent is proved with it."""
        user, folder, rest = None, None, [str(a) for a in argv]
        if rest[:3] == ["sudo", "-n", "-u"]:
            self.assertEqual((rest[4], rest[5]), ("--", "env"), argv)
            user, rest = rest[3], rest[6:]
            home = self.made.get(user, "/home/" + user)
            self.assertEqual(rest[:3], [f"HOME={home}", f"XDG_RUNTIME_DIR=/run/user/{(self.accounts(user) or (0,))[0]}",
                                        f"PATH={home}/.local/bin:{self.mod.AGENT_PATH}"], argv)
            rest = rest[3:]
        if rest[:2] in (["sh", "-c"], ["/bin/sh", "-c"]) and rest[2].startswith('cd "$1" && shift'):
            folder, rest = rest[4], rest[5:]
        return user, folder, rest

    def hub_client(self, key=None, source=NEW):
        client = self.mod.Hub(self.base, key)
        client.headers = {"X-Test-Source": source}
        return client

    def runner(self, answers=None):
        """Git and the readings of a folder run for real; every other command is recorded with the user it is taken
        as and answered from `answers` (by its first words). A command taken as a user this machine does not have
        is refused, as sudo refuses it."""
        def run(argv, cwd=None, timeout=120, env=None):
            if [str(a) for a in argv[:3]] == ["sudo", "-n", self.mod.AGENT_HELPER]:
                if self.no_helper:      # a machine whose installer put no root helper in place
                    return 1, "", "sudo: a password is required"
                return self.agent_user_made(str(argv[3]))       # the one root command of the installers
            user, folder, inner = self.becomes(argv)
            if user and user not in self.made:
                return 1, "", f"sudo: a password is required for {user}"
            where = folder or cwd
            if inner[:2] in (["sh", "-c"], ["/bin/sh", "-c"]) and inner[2].startswith("command -v"):
                path = self.exe_of(inner[-1], self.made.get(user) or self.home)
                return (0, path, "") if path else (1, "", "")
            if inner[0] == "git" or inner[0] in ("cat", "test") or inner[:3] == ["rm", "-rf", "--"] or \
                    inner[:2] == ["mv", "--"] or \
                    (inner[:2] in (["sh", "-c"], ["/bin/sh", "-c"]) and inner[2].startswith("printf")):
                return self.mod.Service.command(inner, cwd=where, timeout=timeout)
            self.commands.append((inner, where, user))
            for words, answer in (answers or {}).items():
                if " ".join(inner).startswith(words):
                    return answer
            if inner[1:3] == ["fleet.py", "key"]:
                # `fleet.py key <agent>` as that agent: its key in its own home, and only the SHA-256 on its output
                with patch.object(fleet, "HOME", os.path.join(self.made.get(user) or self.home, ".fleet")):
                    return 0, fleet.make_key(inner[3]) + "\n", ""
            return 0, "", ""
        return run

    def service(self, life=None, platform="linux", answers=None, report=True, **conf):
        conf = dict({"name": "mini", "repo": str(self.root / "origin.git")}, **conf)
        clock = [1000.0]
        svc = self.mod.Service(conf, self.hub_client(self.mod.server_key()), kit=str(self.own), home=str(self.home),
                               run=self.runner(answers), clock=lambda: clock[0], platform=platform,
                               sleep=lambda s: clock.__setitem__(0, clock[0] + s), life=life or FakeLife(),
                               users=self.accounts, lives=lambda user: svc.life)
        svc.restart = lambda: self.restarts.append(svc.desired)
        if report:
            self.assertEqual(svc.report(), 200)              # the loop's first step: a reading
        return svc

    def join_by_script(self, code, kind="mac"):
        class Client(self.mod.Hub):
            def __init__(inner, url, key=None):
                super().__init__(url, key)
                inner.headers = {"X-Test-Source": NEW}
        args = type("Args", (), {"hub": self.base, "kind": kind, "ssh_port": None})()
        with patch.object(self.mod, "Hub", Client), patch.object(self.mod, "install_service", lambda: "unit"), \
                patch("sys.stdin", io.StringIO(code + "\n")):
            self.mod.cmd_join(args)

    def test_the_service_s_reading_carries_its_machine_s_load(self):
        self.join_by_script(self.code()["code"])
        load = {"cpu_percent": 10.5, "memory_used": 783446016, "memory_total": 3999657984, "disk_used": 3186442240,
                "disk_total": 40150417408}
        with patch.object(self.mod.lifecycle, "machine_load", lambda platform: dict(load)):
            self.service()
        reported = hub.q1("SELECT reported FROM server_status WHERE server='mini'")["reported"]
        self.assertEqual(self.servers()[1]["mini"]["load"], dict(load, at=reported))

    def test_the_join_makes_a_key_saves_the_server_and_sends_only_the_sha256(self):
        answer = self.code()
        self.join_by_script(answer["code"])
        key = (self.home / ".fleet" / "server.key").read_text().strip()
        self.assertEqual(oct((self.home / ".fleet" / "server.key").stat().st_mode & 0o777), "0o600")
        self.assertEqual(oct((self.home / ".fleet").stat().st_mode & 0o777), "0o700")
        self.assertEqual(hub.q1("SELECT sha256 FROM server_keys WHERE server='mini'")["sha256"], sha(key))
        conf = json.loads((self.home / ".fleet" / "server.json").read_text())
        self.assertEqual(conf, {"name": "mini", "hub": f"http://{HUB}:8765", "repo": f"git://{HUB}/fleet-pilot.git"})
        self.assertNotIn(answer["code"], (self.home / ".fleet" / "server.json").read_text())
        self.join_by_script(answer["code"])                 # the line again: the same server, the same key
        self.assertEqual(key, (self.home / ".fleet" / "server.key").read_text().strip())
        with self.assertRaises(SystemExit):
            self.join_by_script("ABCD-EFGH-JKLM")

    def test_the_join_keeps_the_restart_time_that_the_hub_gave_for_join_sh(self):
        status, answer = self.owner("/ui/settings", settings={"servers.reboot_times": ["01:34"]})
        self.assertEqual(status, 200, answer)
        self.join_by_script(self.code(kind="linux")["code"], kind="linux")
        conf = json.loads((self.home / ".fleet" / "server.json").read_text())
        self.assertEqual(conf["reboot_time"], "01:34")
        self.assertEqual(self.origin_team()["servers"]["mini"]["reboot_time"], "01:34")

    def test_a_join_line_without_its_code_says_where_to_copy_it(self):
        """What he reads in his terminal names the product and today's place (review B, B10)."""
        said = io.StringIO()
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(said):
            self.join_by_script("")
        self.assertEqual(said.getvalue().strip(), "Founderizer join stopped: No join code. Copy the whole line from "
                                                  "Founderizer: Settings, Servers, Add server.")

    def test_the_service_reports_and_installs_an_agent_that_is_signed_in(self):
        self.join_by_script(self.code()["code"])
        svc = self.service()
        self.assertEqual(svc.desired, hub.kit_revision(fresh=True))
        mini = self.servers()[1]["mini"]
        self.assertEqual((mini["available"], mini["reading"]["runtimes"]["codex"]["signed_in"]), (True, True))
        job = self.add_agent(runtime="codex")[1]["job"]
        svc.loop(rounds=1)
        shown = self.servers()[1]["mini"]["job"]
        self.assertEqual((shown["id"], shown["state"], shown["step"]), (job, "done", "sign_in"), shown)
        folder = self.checkout_of()
        self.assertEqual(folder, self.homes / "fleet-scout" / "fleet-scout")
        self.assertEqual((folder / ".git" / "fleet-server").read_text(), "scout\n")
        self.assertIn("scout", json.loads((folder / "team.json").read_text())["agents"])
        ran = [" ".join(argv[1:] if argv[0] == sys.executable else argv) for argv, _cwd, _user in self.commands]
        self.assertEqual(ran, ["fleet.py key scout",
                               "-c import worker_install; print(worker_install.trust_codex_checkout())",
                               "fleet.py service scout", "systemctl --user enable --now fleet-scout.service"])
        # every step of the agent, and the folder each runs from, is taken as that agent's own OS user
        self.assertEqual({user for _argv, _cwd, user in self.commands}, {"fleet-scout"})
        self.assertTrue(all(cwd == str(folder) for _argv, cwd, _user in self.commands[:3]))
        # its key is in its own home before its helper first starts, and the hub has it from this server
        key = (self.homes / "fleet-scout" / ".fleet" / "agent-scout.key").read_text().strip()
        self.assertEqual(hub.agent_key("scout")["sha256"], sha(key))
        self.assertEqual(hub.q1("SELECT source FROM agent_keys WHERE agent='scout'")["source"], "server")
        svc.loop(rounds=1)                                  # nothing more to do
        self.assertEqual(len(self.commands), 4)

    def test_an_agents_runtime_is_read_as_that_agent_and_never_as_this_service(self):
        """The owner, 19 October 2026: he signed Codex in on the provider's own page, the credential was on the
        machine, its helper was reporting that the runtime was signed in — and the install still said "Sign in to
        Codex with this code" until it gave up fifteen minutes later.

        This service was finding the executable with `lifecycle.exe`, which looks on ITS OWN PATH and in a home it
        may not open. On one of his machines that found nothing and the reading said `signed_in: null`; on the
        other it found this service's own codex and ran it as the agent, which answered for neither of them. So
        every part of an agent's reading is taken as that agent, the look for the executable first of all."""
        self.join_by_script(self.code()["code"])
        answers = {}
        svc = self.service(answers=answers)
        self.add_agent(runtime="codex")
        svc.loop(rounds=1)
        home = self.made["fleet-scout"]
        self.assertNotEqual(home, str(self.home), "the agent's home is its own, at mode 700")
        codex = f"{home}/.local/bin/codex"
        life = svc.agent_lifecycle("fleet-scout")       # the service's own, not the stand-in the other checks pass
        self.assertEqual(life.exe("codex"), codex, "the executable must be the agent's, found as the agent")
        answers[f"{codex} --version"] = (0, "codex-cli 0.160.0", "")
        answers[f"{codex} login status"] = (0, "Logged in", "")
        self.assertEqual(life.runtime("codex"),
                         {"name": "codex", "version": "codex-cli 0.160.0", "signed_in": True})
        taken = [user for argv, _cwd, user in self.commands if argv[:1] == [codex]]
        self.assertEqual(taken, ["fleet-scout", "fleet-scout"], "through that agent's own sudoers line")

    def agent_state(self, home, claude=("2.1.308 (Claude Code)", True), codex=("codex-cli 0.164.0", False)):
        """What the status commands of both runtimes answer in one home: (version, whether it is signed in)."""
        return {f"{home}/.local/bin/claude --version": (0, claude[0] + "\n", ""),
                f"{home}/.local/bin/claude auth status": (0, json.dumps({"loggedIn": claude[1]}) + "\n", ""),
                f"{home}/.local/bin/codex --version": (0, codex[0] + "\n", ""),
                f"{home}/.local/bin/codex login status": (0, "Logged in using ChatGPT\n", "") if codex[1] else
                (1, "", "Not logged in\n")}

    def test_a_linux_servers_reading_is_the_one_its_agents_helper_makes(self):
        """The owner, 27 October 2026: a server's page crossed out Codex and Claude Code while its agent was signed in
        to Claude Code. The server's reading was this service's own, and on Linux each agent has an OS user of its
        own, with its runtime and its credential in a home of mode 700. So the runtimes are read as that agent, in
        its home and on its PATH, with its helper's own status commands, and the reading is the one its helper
        makes. This service's own user speaks for the machine only while none of its agents has a user of its own."""
        self.join_by_script(self.code(kind="linux")["code"], kind="linux")
        self.runtimes("claude", "codex")
        answers = {}
        svc = self.service(answers=answers, life=FakeLife(signed_in=False, after=10 ** 6))
        svc.lives = svc.agent_lifecycle                 # the service's own reading of an agent, not the stand-in
        own = {"version": "1.0.0", "signed_in": False}  # this service's user: a runtime nobody signed in to
        self.assertEqual(self.servers()[1]["mini"]["reading"]["runtimes"], {"claude": own, "codex": own})
        self.add_agent(runtime="claude")                # the hub's record: scout on mini, in team.json
        git("pull", "-q", "--ff-only", cwd=self.own)    # which this checkout takes at its next update
        self.assertEqual(svc.report(), 200)             # an agent from before the move shares this service's user
        self.assertEqual(self.servers()[1]["mini"]["reading"]["runtimes"], {"claude": own, "codex": own})
        self.agent_user_made("fleet-scout")
        home = self.made["fleet-scout"]
        answers.update(self.agent_state(home))
        self.assertEqual(svc.report(), 200)
        said = self.servers()[1]["mini"]["reading"]["runtimes"]
        self.assertEqual(said, {"claude": {"version": "2.1.308 (Claude Code)", "signed_in": True},
                                "codex": {"version": "codex-cli 0.164.0", "signed_in": False}})
        self.assertEqual({user for argv, _cwd, user in self.commands if argv[0].startswith(home)}, {"fleet-scout"},
                         "each status command is taken as the agent, through its own sudoers line")
        # The agent's own helper runs as that user on the same machine: the runtimes it reports are the server's.
        helper = self.mod.lifecycle.Lifecycle(str(self.checkout_of()), "scout", {"runtime": "claude"}, None,
                                              lambda: False, platform_name="linux", home=home,
                                              run=self.runner(answers))
        self.assertEqual(helper.collect()["runtimes"], said)

    def test_a_reading_says_the_private_network_as_it_leaves(self):
        """A report goes over this network, so what its slow reading said of it a moment ago does not go with it."""
        self.join_by_script(self.code(kind="linux")["code"], kind="linux")

        class Life(FakeLife):
            network = True

            def security(self):
                return dict(super().security(), tailscale=False)

            def private_network(self):
                return self.network
        life = Life()
        svc = self.service(life=life)
        self.assertIs(self.servers()[1]["mini"]["reading"]["security"]["tailscale"], True)
        life.network = None
        self.assertEqual(svc.report(), 200)
        self.assertIsNone(self.servers()[1]["mini"]["reading"]["security"]["tailscale"])

    def test_a_mac_servers_reading_is_its_own_user_which_its_agents_share(self):
        """A Mac keeps one user for its agents (PRODUCT.md P2): this service's user is theirs, with the same home, the
        same PATH and the same login keychain. So with an agent on it the reading is still this service's own, it
        takes nothing as another user, and it is the one the agent's helper makes."""
        self.join_by_script(self.code()["code"])
        self.runtimes("claude", "codex")
        home = str(self.home)
        answers = self.agent_state(home, claude=("2.1.311 (Claude Code)", True), codex=("codex-cli 0.158.0", True))

        def life(agent=None):       # as this service makes its own reading, and as the agent's helper makes its
            return self.mod.lifecycle.Lifecycle(str(self.own), agent, {"runtime": "claude"} if agent else {}, None,
                                                lambda: False, platform_name="darwin", home=home,
                                                run=self.runner(answers))
        svc = self.service(answers=answers, platform="darwin", life=life())
        svc.lives = svc.agent_lifecycle
        self.add_agent(runtime="claude")
        git("pull", "-q", "--ff-only", cwd=self.own)
        self.assertEqual(svc.report(), 200)
        said = self.servers()[1]["mini"]["reading"]["runtimes"]
        self.assertEqual(said, {"claude": {"version": "2.1.311 (Claude Code)", "signed_in": True},
                                "codex": {"version": "codex-cli 0.158.0", "signed_in": True}})
        self.assertEqual(life("scout").collect()["runtimes"], said)
        self.assertEqual([argv for argv, _cwd, user in self.commands if user], [], "nothing as another user")

    def test_claude_sign_in_is_the_one_the_owner_finishes_in_the_app(self):
        """The console line is gone. The service asks the hub for this agent's own sign-in, which is machine_signin,
        the same one the Machines page starts; the prompt only says which agent and which sign-in to read, and the
        link, the code and the credential never come near this service."""
        self.join_by_script(self.code()["code"])
        svc = self.service(life=FakeLife(signed_in=False, after=4))
        job = self.add_agent()[1]["job"]
        self.helper_reports()
        prompts = []
        real = svc.post
        def post(job_row, state, step, detail, prompt=None, quiet=False):
            if prompt:
                prompts.append((prompt, self.servers()[1]["mini"]["job"]["state"]))
            return real(job_row, state, step, detail, prompt, quiet)
        svc.post = post
        svc.loop(rounds=1)
        row = hub.q1("SELECT * FROM signin_jobs WHERE agent='scout'")
        self.assertEqual((row["runtime"], row["state"]), ("claude", "starting"))
        self.assertEqual(prompts[0][0], {"kind": "signin", "purpose": "claude_login", "agent": "scout",
                                         "login": row["id"]})
        self.assertEqual(json.loads(hub.q1("SELECT * FROM events WHERE agent='scout' AND kind='login'")["extra"]),
                         {"login": row["id"], "runtime": "claude", "replace": False})
        shown = self.servers()[1]["mini"]["job"]
        self.assertEqual((shown["id"], shown["state"]), (job, "done"))
        # nothing of a terminal is left in what the service said or in what the owner reads
        said = json.dumps([p for p, _ in prompts]) + json.dumps(shown)
        for word in ("terminal", "su - ", "exec ", "/login"):
            self.assertNotIn(word, said)

    def test_the_service_measures_how_long_things_take_on_a_clock_that_cannot_step(self):
        """Its clock measures only elapsed time — the five-minute reading, and the two waits of a sign-in — and
        nothing of it is reported or written down, so it must be the monotonic clock. A wall clock steps: NTP
        corrects a drifted server and a VM's host sets it back. One step backwards measured on that clock would
        stop this service's reading for the whole of the step, while the hub went on showing the last one as the
        server's current state, and would stretch both sign-in waits by the same amount.
        """
        import inspect
        self.assertIs(inspect.signature(self.mod.Service.__init__).parameters["clock"].default, time.monotonic)

    def test_the_sign_in_waits_for_the_new_agents_own_helper(self):
        """The service step started that helper a moment earlier, so a hub that has not heard from it yet says 503
        and the service asks again. Every other refusal is the agent's or the runtime's and fails the step."""
        self.join_by_script(self.code()["code"])
        svc = self.service(life=FakeLife(signed_in=False, after=4))
        self.add_agent()
        asked = []
        call = svc.hub.call
        def hub_call(method, path, body=None, timeout=30):
            if path.endswith("/signin"):
                asked.append(svc.clock())
                if len(asked) < 3:              # the helper has not reached the hub yet
                    return 503, {"error": "scout's helper has not reached the hub yet; ask again in a minute"}
                self.helper_reports()
            return call(method, path, body, timeout)
        svc.hub.call = hub_call
        svc.loop(rounds=1)
        self.assertEqual(len(asked), 3)
        self.assertEqual(asked[2] - asked[0], 20.0)         # two waits of ten seconds, and no more
        self.assertEqual(self.servers()[1]["mini"]["job"]["state"], "done")

    def test_a_hub_that_refuses_the_sign_in_fails_the_step_with_its_own_words(self):
        self.join_by_script(self.code()["code"])
        svc = self.service(life=FakeLife(signed_in=False, after=4))
        self.add_agent()                        # its helper never reports: the hub keeps saying 503
        svc.loop(rounds=1)
        shown = self.servers()[1]["mini"]["job"]
        self.assertEqual((shown["state"], shown["step"], shown["timed_out"]), ("failed", "sign_in", False))
        self.assertEqual(shown["detail"], "The sign-in did not start: Scout has not reached the hub yet. Try again "
                                          "in a minute.")
        self.assertEqual(self.count("signin_jobs"), 0)

    def test_a_sign_in_that_does_not_come_fails_the_job_and_can_go_again(self):
        self.join_by_script(self.code()["code"])
        svc = self.service(life=FakeLife(signed_in=False, after=10 ** 6), platform="darwin",
                           answers={"launchctl print": (1, "", "not loaded")})
        self.add_agent()
        self.helper_reports()
        svc.loop(rounds=1)
        shown = self.servers()[1]["mini"]["job"]
        self.assertEqual((shown["state"], shown["step"], shown["timed_out"]), ("failed", "sign_in", True))
        self.assertIn("did not sign in within 15 minutes", shown["detail"])
        self.assertIn(["launchctl", "bootstrap"], [argv[:2] for argv, _cwd, _user in self.commands])
        self.assertEqual(self.add_agent()[0], 200)
        svc.life = FakeLife()
        svc.loop(rounds=1)
        self.assertEqual(self.servers()[1]["mini"]["job"]["state"], "done")

    def test_codex_sign_in_sends_the_link_and_the_code(self):
        self.join_by_script(self.code()["code"])
        class Login:
            def __init__(inner, argv, stdout=None, **_):
                inner.argv = argv
                __import__("os").write(stdout, b"\x1b[94mhttps://auth.openai.com/codex/device\x1b[0m\nEnter ABCD-12345\n")
                inner.ended = False
            def poll(inner):
                return 0 if inner.ended else None
            def terminate(inner):
                inner.ended = True
        svc = self.service(life=FakeLife(signed_in=False, after=3))
        logins = []
        svc.popen = lambda argv, **kw: logins.append(Login(argv, **kw)) or logins[-1]
        seen = []
        real = svc.post
        svc.post = lambda job_row, state, step, detail, prompt=None, quiet=False: (
            seen.append(prompt) if prompt else None, real(job_row, state, step, detail, prompt, quiet))[1]
        self.add_agent(runtime="codex")
        svc.loop(rounds=1)
        self.assertEqual(seen, [{"kind": "open_url", "purpose": "codex_login", "url": "https://auth.openai.com/codex/device",
                                 "code": "ABCD-12345"}])
        self.assertEqual(self.servers()[1]["mini"]["job"]["state"], "done")
        self.assertFalse((self.home / ".fleet" / "codex-login.log").exists())
        self.assertEqual(self.becomes(logins[0].argv)[0], "fleet-scout")

    def test_a_job_this_server_does_not_know_asks_for_an_update_in_his_words(self):
        """A job's kind is the hub's own id ("archive" here, which no server knows), never his word: a server too old
        for it says to update (the review of 30 October 2026)."""
        self.join_by_script(self.code()["code"])
        svc = self.service()
        posted = []
        with patch.object(svc, "post", lambda job, state, step, detail, **_: posted.append((state, step, detail))):
            svc.work({"id": 7, "kind": "archive", "agent": "scout"})
        self.assertEqual(posted, [("failed", None, "mini runs an older Founderizer that cannot do this. Update "
                                                    "Founderizer, then try again.")])
        # a provider that a newer hub knows and this server does not, in each job that names one
        for kind in ("install", "prepare", "rename"):
            posted.clear()
            with patch.object(svc, "post", lambda job, state, step, detail, **_: posted.append((state, step, detail))):
                svc.work({"id": 8, "kind": kind, "agent": "scout", "was": "echo", "runtime": "gemini"})
            self.assertEqual(posted, [("failed", None, "mini runs an older Founderizer that cannot do this. Update "
                                                        "Founderizer, then try again.")], kind)

    def test_a_folder_that_fleet_did_not_make_stops_the_job(self):
        self.join_by_script(self.code()["code"])
        self.agent_user_made("fleet-scout")                 # the user is there, with a folder of that name in it
        self.checkout_of().mkdir()
        svc = self.service()
        self.add_agent()
        svc.loop(rounds=1)
        shown = self.servers()[1]["mini"]["job"]
        self.assertEqual((shown["state"], shown["step"]), ("failed", "checkout"))
        self.assertEqual(shown["detail"], "Scout's folder on mini was not made by Founderizer, and Founderizer leaves "
                                          "it as it is. Move it aside, then try again.")
        self.assertEqual(self.commands, [])

    def test_a_clone_that_its_timeout_cut_off_is_made_again_at_the_next_try(self):
        """The clone has five minutes. One that its timeout or a stop cut off left a folder with no mark in its
        place, and every later try said that Founderizer had not made it. It is cloned beside the folder and moved
        into place only once it is marked and at this server's own revision, so the next try makes it again."""
        self.join_by_script(self.code()["code"])
        svc = self.service()
        real, cut, moved = svc.run, [], []

        def run(argv, cwd=None, timeout=120, env=None):
            words = [str(a) for a in argv]
            if "clone" in words and not cut:            # the first clone ends at its timeout, half made
                (Path(words[-1]) / ".git").mkdir(parents=True)
                cut.append(words[-1])
                return 1, "", "the command did not end in 300 seconds"
            if "mv" in words:                           # the folder never stands in its place without its mark
                partial = Path(words[words.index("mv") + 2])
                moved.append((partial / ".git" / "fleet-server").read_text())
            return real(argv, cwd=cwd, timeout=timeout, env=env)
        svc.run = run
        self.add_agent()
        svc.loop(rounds=1)
        shown = self.servers()[1]["mini"]["job"]
        self.assertEqual((shown["state"], shown["step"]), ("failed", "checkout"), shown)
        self.assertEqual(self.add_agent()[0], 200)
        svc.loop(rounds=1)
        shown = self.servers()[1]["mini"]["job"]
        self.assertEqual((shown["state"], shown["step"]), ("done", "sign_in"), shown)
        folder = self.checkout_of()
        self.assertEqual((folder / ".git" / "fleet-server").read_text(), "scout\n")
        self.assertIn("scout", json.loads((folder / "team.json").read_text())["agents"])
        self.assertFalse(Path(cut[0]).exists())
        self.assertEqual(moved, ["scout\n"])

    def test_an_agent_without_the_root_helper_of_the_installers_stops_the_job(self):
        """This service has no root of its own, so without the helper no agent is installed and nothing is tried."""
        self.join_by_script(self.code()["code"])
        self.no_helper = True
        svc = self.service()
        self.add_agent()
        with patch("sys.stderr", new_callable=io.StringIO) as log:
            svc.loop(rounds=1)
        shown = self.servers()[1]["mini"]["job"]
        self.assertEqual((shown["state"], shown["step"]), ("failed", "user"))
        self.assertIn("Scout's account on mini", shown["detail"])
        self.assertIn("run the join line again", shown["detail"].lower())
        self.assertNotIn("fleet-scout", shown["detail"])       # the OS user is the log's, never his screen's
        self.assertEqual((self.commands, list(self.homes.iterdir())), ([], []))
        # His words only: sudo's own refusal goes to the service's log, never to his screen (UX fix round 3).
        self.assertNotIn("sudo", shown["detail"])
        self.assertIn("sudo: a password is required", log.getvalue())

    # ---- prepare the other runtime (owner feature runtime_switch)
    def runtimes(self, *present):
        """The runtimes this machine has: in a user's ~/.local/bin, and so is one after its installer ran there."""
        self.present = set(present)
        patcher = patch.object(self.mod.lifecycle, "exe",
                               lambda name, home=None: self.exe_of(name, home or self.home))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_second_agent_installs_beside_the_first_with_a_key_of_its_own(self):
        self.join_by_script(self.code()["code"])
        svc = self.service()
        self.installed_agent(svc, "claude")
        svc.report()                                        # the service says it gives a new agent its key
        self.assertEqual(self.servers()[1]["mini"]["why"], [])
        status, receipt = self.add_agent(agent="second")
        self.assertEqual(status, 200, receipt)
        svc.loop(rounds=1)
        shown = self.servers()[1]["mini"]["job"]
        self.assertEqual((shown["id"], shown["state"]), (receipt["job"], "done"), shown)
        # its own user, checkout and service; nothing of scout's is touched
        self.assertEqual({user for _argv, _cwd, user in self.commands}, {"fleet-second"})
        self.assertTrue((self.checkout_of("second") / ".git").exists())
        keys = {name: (self.homes / f"fleet-{name}" / ".fleet" / f"agent-{name}.key").read_text().strip()
                for name in ("scout", "second")}
        self.assertNotEqual(keys["scout"], keys["second"])
        self.assertEqual({name: hub.agent_key(name)["sha256"] for name in keys}, {n: sha(k) for n, k in keys.items()})
        self.assertTrue(hub.shared_machine("second"))

    def installed_agent(self, svc, runtime):
        """The install of scout on mini, through the service. Its commands are not part of what a test checks."""
        self.add_agent(runtime=runtime)
        svc.loop(rounds=1)
        self.assertEqual(self.servers()[1]["mini"]["job"]["state"], "done")
        self.commands.clear()
        return git("rev-parse", "HEAD", cwd=self.checkout_of())

    def test_prepare_installs_codex_trusts_the_checkout_and_signs_in(self):
        self.join_by_script(self.code()["code"])
        self.runtimes("claude")
        svc = self.service()
        head = self.installed_agent(svc, "claude")
        team = self.origin_team()

        class Login:
            def __init__(inner, argv, stdout=None, **_):
                inner.argv = argv
                __import__("os").write(stdout, b"Open https://auth.openai.com/codex/device\nEnter ABCD-12345\n")
                inner.ended = False
            def poll(inner):
                return 0 if inner.ended else None
            def terminate(inner):
                inner.ended = True
        logins = []
        svc.popen = lambda argv, **kw: logins.append(Login(argv, **kw)) or logins[-1]
        svc.life = FakeLife(signed_in=False, after=3)
        seen = []
        real = svc.post
        svc.post = lambda job_row, state, step, detail, prompt=None, quiet=False: (
            seen.append((state, step, detail, prompt)), real(job_row, state, step, detail, prompt, quiet))[1]
        status, receipt = self.prepare()
        self.assertEqual(status, 200, receipt)
        svc.loop(rounds=1)
        shown = self.servers()[1]["mini"]["job"]
        self.assertEqual((shown["id"], shown["kind"], shown["state"], shown["step"]),
                         (receipt["job"], "prepare", "done", "sign_in"), shown)
        self.assertEqual(shown["detail"], "Codex is installed and signed in on mini. Now switch Scout to it.")
        self.assertIn(("needs_owner", "sign_in", "Sign in to Codex with this code.",
                       {"kind": "open_url", "purpose": "codex_login", "url": "https://auth.openai.com/codex/device",
                        "code": "ABCD-12345"}), seen)
        self.assertIn(("running", "runtime", "Installing Codex.", None), seen)
        folder, home = str(self.checkout_of()), self.agent_home()
        ran = [(" ".join(argv[1:] if argv[0] == sys.executable else argv), cwd, user)
               for argv, cwd, user in self.commands]
        self.assertEqual(ran, [
            ("/bin/sh -c cd \"$HOME\" && mkdir -p \"$HOME/.local/bin\" && "
             + self.mod.onboard.runtime_install("codex", "0.160.0"), None, "fleet-scout"),
            ("-c import worker_install; print(worker_install.trust_codex_checkout())", folder, "fleet-scout"),
            ("/bin/sh -c cd \"$HOME\" && " + self.mod.onboard.STOP_CODEX_LOGIN, None, "fleet-scout")])
        self.assertEqual(self.becomes(logins[0].argv)[2], [f"{home}/.local/bin/codex", "login", "--device-auth"])
        self.assertFalse((self.home / ".fleet" / "codex-login.log").exists())
        # No agent, checkout or service changed: the switch stays the owner's command.
        self.assertEqual((self.origin_team(), hub.agents()["scout"]["runtime"]), (team, "claude"))
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.checkout_of()), head)
        svc.loop(rounds=1)                                  # nothing more to do
        self.assertEqual(len(self.commands), 3)

    def test_prepare_of_claude_signs_the_agent_in_through_the_app(self):
        """The runtime switch takes the same one sign-in as the install does: the agent's own helper, which already
        runs here, and the owner in the app. No console on this path either."""
        self.join_by_script(self.code()["code"])
        self.runtimes("codex", "claude")
        svc = self.service(platform="darwin", answers={"launchctl print": (1, "", "not loaded")})
        self.installed_agent(svc, "codex")
        svc.life = FakeLife(signed_in=False, after=4)
        self.helper_reports()
        prompts = []
        real = svc.post
        svc.post = lambda job_row, state, step, detail, prompt=None, quiet=False: (
            prompts.append(prompt) if prompt else None, real(job_row, state, step, detail, prompt, quiet))[1]
        self.prepare(runtime="claude")
        svc.loop(rounds=1)
        row = hub.q1("SELECT * FROM signin_jobs WHERE agent='scout'")
        self.assertEqual((row["runtime"], row["state"]), ("claude", "starting"))
        self.assertEqual(prompts, [{"kind": "signin", "purpose": "claude_login", "agent": "scout", "login": row["id"]}])
        self.assertEqual(self.servers()[1]["mini"]["job"]["state"], "done")
        self.assertEqual(self.commands, [])                 # found: no installer, no trust, no service

    def test_prepare_needs_the_agents_checkout(self):
        self.join_by_script(self.code()["code"])
        self.runtimes()
        svc = self.service()
        job = self.add_agent()[1]["job"]
        self.request(f"/server/mini/jobs/{job}", {"state": "failed", "step": "checkout", "detail": "No network."},
                     headers={"Content-Type": "application/json", "Authorization": "Bearer " + self.mod.server_key()},
                     source=NEW)
        self.prepare()
        svc.loop(rounds=1)
        shown = self.servers()[1]["mini"]["job"]
        self.assertEqual((shown["kind"], shown["state"], shown["step"]), ("prepare", "failed", None))
        self.assertEqual(shown["detail"], "Scout has no copy of Founderizer on mini. Report a problem from the Help "
                                          "menu.")
        self.assertEqual(self.commands, [])

    def lets_every_move_through(self):
        """These tests measure what the service does with a move, with commits that carry no signed release: the one
        check of every move (lifecycle.may_take, DevOps plan 0.1) refuses those, and test_signed_code.ServerUpdate
        runs it on this mover with real releases."""
        patcher = patch.object(self.mod.lifecycle, "may_take", lambda *args, **kwargs: None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_an_update_restarts_only_for_code(self):
        self.lets_every_move_through()
        self.join_by_script(self.code()["code"])
        svc = self.service()
        work = self.root / "work"
        git("clone", "-q", str(self.root / "origin.git"), str(work))

        def push(path, text):
            (work / path).parent.mkdir(parents=True, exist_ok=True)
            (work / path).write_text(text)
            git("add", path, cwd=work)
            git("commit", "-q", "-m", path, cwd=work)
            git("push", "-q", "origin", "HEAD:main", cwd=work)
            return git("rev-parse", "HEAD", cwd=work)
        git("pull", "-q", "--ff-only", cwd=self.own)
        svc.loaded = git("rev-parse", "HEAD", cwd=self.own)
        svc.desired = push("README.md", "docs\n")
        svc.update()
        self.assertEqual((self.restarts, svc.loaded, git("rev-parse", "HEAD", cwd=self.own)), ([], svc.desired, svc.desired))
        svc.desired = push("outputs/T-124/check.py", "print('a task output')\n")     # 4 November 2026: no code
        svc.update()
        self.assertEqual((self.restarts, svc.loaded), ([], svc.desired))
        svc.desired = push("skills/vps/deploy/check.py", "print('a skill')\n")      # nor an agent's skill
        svc.update()
        self.assertEqual((self.restarts, svc.loaded), ([], svc.desired))
        svc.desired = push("server.py", "# new code\n")
        svc.update()
        self.assertEqual(self.restarts, [svc.desired])
        (self.own / "local.txt").write_text("x")
        git("add", "local.txt", cwd=self.own)
        git("commit", "-q", "-m", "local", cwd=self.own)
        svc.desired = push("other.py", "# more\n")
        svc.update()                                        # diverged: no fast-forward, no second try
        self.assertEqual((len(self.restarts), svc.stuck), (1, svc.desired))

    # ---- the configuration ref (2026-10-17): the fleet runs `config`, the developers push `main`
    def split(self):
        """The repository in the shape the fleet runs after the split: origin carries the code branch and the
        configuration ref, and the hub checkout stands on the ref, so it writes the owner's changes there."""
        branch = self.mod.lifecycle.CONFIG_BRANCH
        git("push", "-q", "origin", "main:" + branch, cwd=self.kit)
        git("fetch", "-q", "origin", cwd=self.kit)
        git("checkout", "-q", "-b", branch, "--track", "origin/" + branch, cwd=self.kit)
        hub._revision_cache.update(at=0.0, value=None)
        return branch

    def pushed(self, branch, path, text):
        """One commit on a branch of the test origin by somebody who is not this server: a developer on the code
        branch, the hub or a deployment on the configuration ref."""
        work = self.root / "pushes"
        if not work.exists():
            git("clone", "-q", str(self.root / "origin.git"), str(work))
        git("fetch", "-q", "origin", cwd=work)
        git("checkout", "-q", "-B", branch, "origin/" + branch, cwd=work)
        (work / path).parent.mkdir(parents=True, exist_ok=True)
        (work / path).write_text(text)
        git("add", path, cwd=work)
        git("commit", "-q", "-m", path, cwd=work)
        git("push", "-q", "origin", "HEAD:" + branch, cwd=work)
        return git("rev-parse", "HEAD", cwd=work)

    def test_an_update_follows_the_configuration_ref(self):
        """The hub's revision is a commit of the ref, so the service's own checkout moves onto that branch instead of
        fast-forwarding the code branch onto a configuration commit. A commit that only the code branch carries
        reaches this server with a deployment, never with an update."""
        self.lets_every_move_through()
        self.join_by_script(self.code()["code"])
        branch = self.split()
        svc = self.service()
        git("pull", "-q", "--ff-only", cwd=self.own)             # the clone stands on main, as the join line leaves it
        code_tip = git("rev-parse", "HEAD", cwd=self.own)
        self.assertEqual(self.mod.lifecycle.checkout_branch(str(self.own)), "main")
        svc.loaded = code_tip
        svc.desired = self.pushed(branch, "knowledge/owner/brand.md", "# Brand\n\nBlue.\n")
        svc.update()
        self.assertEqual(self.mod.lifecycle.checkout_branch(str(self.own)), branch)
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.own), svc.desired)
        self.assertEqual(git("rev-parse", "main", cwd=self.own), code_tip)      # the code branch did not move
        self.assertEqual((svc.loaded, self.restarts), (svc.desired, []))
        svc.desired = self.pushed(branch, "server.py", "# new code\n")         # a deployment onto the ref
        svc.update()
        self.assertEqual((self.restarts, git("rev-parse", "HEAD", cwd=self.own)), ([svc.desired], svc.desired))
        self.assertEqual(self.mod.lifecycle.checkout_branch(str(self.own)), branch)
        ref_tip = svc.desired
        svc.desired = self.pushed("main", "fleet.py", "# a developer\n")       # not on the ref: no fast-forward
        svc.update()
        self.assertEqual((svc.stuck, len(self.restarts)), (svc.desired, 1))
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.own), ref_tip)

    def test_a_new_agent_checkout_starts_on_the_configuration_ref(self):
        """The hub writes the owner's team.json to the ref, so a clone on the code branch does not list the new agent
        yet. The service puts the folder on the ref, and the agent's first session reads the current team.json."""
        self.join_by_script(self.code()["code"])
        branch = self.split()
        self.runtimes("claude")
        svc = self.service()
        job = self.add_agent()[1]["job"]
        self.assertNotIn("scout", self.origin_team()["agents"])                 # the code branch lists it nowhere
        self.assertIn("scout", json.loads(git("--git-dir", str(self.root / "origin.git"), "show",
                                              f"{branch}:team.json"))["agents"])
        svc.loop(rounds=1)
        shown = self.servers()[1]["mini"]["job"]
        self.assertEqual((shown["id"], shown["state"], shown["step"]), (job, "done", "sign_in"), shown)
        folder = self.checkout_of()
        self.assertEqual(self.mod.lifecycle.checkout_branch(str(folder)), branch)
        self.assertIn("scout", json.loads((folder / "team.json").read_text())["agents"])

    def test_an_agent_checkout_on_the_code_branch_moves_onto_the_configuration_ref(self):
        """A folder that an earlier install left on the code branch: the install again brings it onto the ref, in the
        place of its own pull."""
        self.join_by_script(self.code()["code"])
        branch = self.split()
        self.runtimes("claude")
        svc = self.service()
        self.agent_user_made("fleet-scout")                 # an earlier install of this agent made its OS user
        folder = self.checkout_of()
        git("clone", "-q", str(self.root / "origin.git"), str(folder))
        (folder / ".git" / "fleet-server").write_text("scout\n")
        job = self.add_agent()[1]["job"]
        svc.loop(rounds=1)
        shown = self.servers()[1]["mini"]["job"]
        self.assertEqual((shown["id"], shown["state"], shown["step"]), (job, "done", "sign_in"), shown)
        self.assertEqual(self.mod.lifecycle.checkout_branch(str(folder)), branch)
        self.assertIn("scout", json.loads((folder / "team.json").read_text())["agents"])

    def test_an_agent_checkout_that_cannot_follow_the_ref_fails_the_step(self):
        """A folder with its own changes is never moved: the step says so and the install stops there."""
        self.join_by_script(self.code()["code"])
        self.split()
        self.runtimes("claude")
        svc = self.service()
        self.agent_user_made("fleet-scout")                 # an earlier install of this agent made its OS user
        folder = self.checkout_of()
        git("clone", "-q", str(self.root / "origin.git"), str(folder))
        (folder / ".git" / "fleet-server").write_text("scout\n")
        (folder / "team.json").write_text("{}\n")
        self.add_agent()
        svc.loop(rounds=1)
        shown = self.servers()[1]["mini"]["job"]
        self.assertEqual((shown["state"], shown["step"]), ("failed", "checkout"))
        self.assertEqual(shown["detail"], "Scout's copy of Founderizer has changes of its own, and Founderizer "
                                          "leaves it as it is. Put those changes away, then try again.")
        self.assertEqual(self.commands, [])

    # ---- this machine's vault broker onto a release (hubsetup.vault_program_script)

    def broker(self, installed="# the vault, installed\n", checkout="# the vault, released\n"):
        """The broker's installed program and the vault.py of this service's own checkout. The installed copy is
        root-owned and world-readable, as the installer leaves it, so the service reads it with no root at all."""
        one = self.root / "vault-installed.py"
        one.write_text(installed)
        patcher = patch.object(self.mod, "VAULT_PROGRAM", str(one))
        patcher.start()
        self.addCleanup(patcher.stop)
        if checkout is not None:
            (self.own / "vault.py").write_text(checkout)
        return one

    def asked(self):
        """Every time the service asked root to bring the broker up to date, with the whole command."""
        return [inner for inner, _where, _user in self.commands
                if inner[:2] == ["sudo", "-n"] and inner[2:3] == [self.mod.VAULT_HELPER]]

    def test_the_broker_is_asked_to_catch_up_only_when_it_runs_another_vault_py(self):
        """A release reaches every checkout on this machine and never the broker, which runs a root-owned copy
        outside all of them. So the service reads both and asks for nothing while they agree: the whole gate is a
        reading, and it needs no root."""
        self.join_by_script(self.code()["code"])
        svc = self.service()
        self.broker(installed="# the same\n", checkout="# the same\n")
        svc.vault_program()
        self.assertEqual(self.asked(), [])
        self.broker()                                       # the release changed vault.py; the broker has not
        svc.vault_program()
        self.assertEqual(self.asked(), [["sudo", "-n", self.mod.VAULT_HELPER]])

    def test_what_it_asks_for_carries_no_argument_at_all(self):
        """Root fetches the program itself, so this service passes no bytes, no path and no revision: a wrong
        reading here can cost root one fetch that finds nothing to do, and nothing else."""
        self.join_by_script(self.code()["code"])
        svc = self.service()
        self.broker()
        svc.vault_program()
        self.assertEqual(self.asked(), [["sudo", "-n", self.mod.VAULT_HELPER]])

    def test_a_machine_with_no_broker_and_a_mac_are_never_asked(self):
        """A Mac's vault is the signed app, which Founderizer updates itself, and a server the owner gave no broker
        has nothing to bring up to date."""
        self.join_by_script(self.code()["code"])
        svc = self.service()
        self.broker().unlink()                              # no installed program: this machine has no broker
        svc.vault_program()
        self.assertEqual(self.asked(), [])
        mac = self.service(platform="darwin", report=False)
        self.broker()
        mac.vault_program()
        self.assertEqual(self.asked(), [])

    def test_a_try_that_did_not_settle_it_waits_before_it_is_made_again(self):
        """No network, or a broker that did not come up and kept the program that was serving: the machine tries
        again, and not once a round. A broker that stays behind is what `/ui/health` raises `vault_behind` for."""
        self.join_by_script(self.code()["code"])
        refused = "fleet-vault-program: the broker did not come up on the new vault.py"
        svc = self.service(answers={"sudo -n " + self.mod.VAULT_HELPER: (5, "", refused)})
        self.broker()
        with contextlib.redirect_stderr(io.StringIO()) as said:
            svc.vault_program()
            svc.vault_program()
        self.assertEqual(len(self.asked()), 1)
        # What the command itself said, and not the installer line: that one is for sudo refusing the command.
        self.assertIn(refused, said.getvalue())
        self.assertNotIn("run the join line again", said.getvalue())
        svc.clock = lambda: 1000.0 + self.mod.VAULT_EVERY + 1
        with contextlib.redirect_stderr(io.StringIO()):
            svc.vault_program()
        self.assertEqual(len(self.asked()), 2)

    def test_a_machine_whose_installer_put_that_command_nowhere_is_told_to_join_again(self):
        """sudo refusing the command is not the command refusing the work: a machine whose installers are older
        than it needs its join line run again, which is what `/ui/health` says too."""
        self.join_by_script(self.code()["code"])
        svc = self.service(answers={"sudo -n " + self.mod.VAULT_HELPER:
                                    (1, "", "sudo: a password is required")})
        self.broker()
        with contextlib.redirect_stderr(io.StringIO()) as said:
            svc.vault_program()
        self.assertIn("run the join line again on mini", said.getvalue())

    def test_the_loop_asks_when_this_machine_has_no_job(self):
        """It rides the same idle round as the checkout's own update, so a machine that is working is never held up
        by it."""
        self.join_by_script(self.code()["code"])
        svc = self.service()
        self.broker()
        svc.loop(rounds=1)
        self.assertEqual(len(self.asked()), 1)

    def test_a_server_that_left_waits(self):
        self.join_by_script(self.code()["code"])
        self.owner("/ui/servers/mini/remove", base_sha256=self.team_sha())
        slept = []
        svc = self.service(report=False)
        svc.sleep = slept.append
        svc.loop(rounds=1)
        self.assertEqual(slept, [600])


class InstallRetries(unittest.TestCase):
    """T-35: an install that could not reach the internet. The owner saw "Codex did not install: npm could not reach
    the registry (ETIMEDOUT)." with nothing tried again, and an installer's own text as the line. The runtime step now
    runs the vendor installer again by itself, three times, and the job's line says what failed in plain words; the
    installer's own words go to the service's log."""

    OFFLINE = "curl: (6) Could not resolve host: chatgpt.com"

    def service(self, answers):
        """A Linux server service with the hub, the agent's user and the installer stood in for. `answers` are what
        each run of the installer gives, the last one again for every later run."""
        import server
        self.posts, self.sleeps, self.tries = [], [], []

        class Hub:
            def call(inner, method, path, body=None, timeout=30):
                self.posts.append(body)
                return 200, {}

        def run(argv, cwd=None, timeout=120, env=None):
            words = " ".join(map(str, argv))
            if list(argv[:3]) == ["sudo", "-n", server.AGENT_HELPER]:
                return 0, "", ""            # the root helper of the installers: the agent's own user is there
            if "command -v" in words:       # the agent's runtime: there once an installer run ended well
                return (0, "/home/fleet-echo/.local/bin/codex", "") if 0 in self.tries else (1, "", "")
            if "install.sh" in words:
                code, out, err = answers[min(len(self.tries), len(answers) - 1)]
                self.tries.append(code)
                return code, out, err
            return 1, "", ""
        return server.Service({"name": "vps-2"}, Hub(), kit=str(Path(tempfile.gettempdir()) / "no-kit"),
                              home=tempfile.gettempdir(), run=run, sleep=self.sleeps.append, platform="linux",
                              life=FakeLife(), users=lambda user: (4000, "/home/" + user))

    def install(self, answers):
        """One install job's runtime step, through Service.work as the loop runs it: (its log, the job's last post)."""
        svc, log = self.service(answers), io.StringIO()
        with patch.object(svc, "checkout_step", side_effect=AssertionError("the job went on")), \
                contextlib.redirect_stdout(log):
            svc.work({"id": 7, "kind": "install", "agent": "echo", "runtime": "codex"})
        return log.getvalue(), self.posts[-1]

    def test_a_network_error_is_tried_again_until_the_installer_gets_through(self):
        import server
        svc = self.service([(1, "", self.OFFLINE), (1, "", "npm ERR! code ETIMEDOUT"), (0, "installed", "")])
        with contextlib.redirect_stdout(io.StringIO()):
            exe = svc.runtime_step({"id": 7}, "codex", "fleet-echo")
        self.assertEqual(exe, "/home/fleet-echo/.local/bin/codex")
        self.assertEqual(self.tries, [1, 1, 0])
        self.assertEqual(self.sleeps, [server.onboard.NETWORK_WAIT] * 2)
        # one line for every try, without the version: the tries are the log's (T-35)
        self.assertEqual([p["detail"] for p in self.posts], ["Looking for Codex."] + ["Installing Codex."] * 3)
        self.assertEqual({p["state"] for p in self.posts}, {"running"})        # the page stays on its moving words

    def test_three_network_errors_more_and_the_job_says_so_in_plain_words(self):
        import server
        log, last = self.install([(1, "", "npm ERR! code ETIMEDOUT\nnpm ERR! network request failed")])
        self.assertEqual(self.tries, [1, 1, 1, 1])
        self.assertEqual(len(self.sleeps), 3)
        self.assertEqual((last["state"], last["step"], last["detail"]),
                         ("failed", "runtime", "Codex did not install: vps-2 could not reach the internet. Try again when it can."))
        # the installer's own words are in the service's log, once for each try, and never in the job's line
        self.assertEqual([line.split(":")[0] for line in log.splitlines()], ["job 7"] * 4)
        self.assertIn(f"Codex {server.onboard.RUNTIME_PINS['codex']} did not install (try 4 of 4, a network error): "
                      "npm ERR! code ETIMEDOUT", log)

    def test_any_other_failure_is_not_tried_again(self):
        log, last = self.install([(1, "", "error: this system is not supported: linux armv6l")])
        self.assertEqual((self.tries, self.sleeps), ([1], []))
        self.assertEqual((last["state"], last["detail"]), ("failed", "Codex did not install. Try again."))
        self.assertIn("try 1 of 4): error: this system is not supported", log)

    def test_what_reads_as_a_network_error(self):
        import onboard
        for text in (self.OFFLINE, "npm ERR! code EAI_AGAIN", "Error: connect ECONNREFUSED 104.18.0.1:443",
                     "curl: (28) Failed to connect to github.com port 443 after 300000 ms: Couldn't connect to server",
                     "curl: (56) Recv failure: Connection reset by peer",
                     "wget: unable to resolve host address 'downloads.claude.ai'",
                     "ssh: Temporary failure in name resolution"):
            self.assertTrue(onboard.network_failure(text), text)
        for text in ("", None, "error: this system is not supported: linux armv6l", "No space left on device",
                     "curl: (22) The requested URL returned error: 404"):
            self.assertFalse(onboard.network_failure(text), text)


def lifecycle_exe(name, home):
    import lifecycle
    return lifecycle.exe(name, str(home))
