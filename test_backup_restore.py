"""The owner takes one copy of his fleet and puts it back on another machine (owner API 1.5).

A copy nobody has ever put back is not a copy, so this file does the whole thing and not a piece of it: a hub with
real work in it serves `GET /ui/backup`; a second, empty hub on another address takes that file through
`POST /ui/restore`; and then a **real hub process** starts on those records and is asked what it is. What it must
be is the first fleet — the same `fleet_id`, the same tasks, goals and duties, the same profiles and the same
owner knowledge — standing on the new machine's own addresses, with a new generation so that nothing from before
the restore can act on it.

Git is real throughout, because the owner's own configuration lives on the configuration ref and a restore that
did not write it would leave the new machine with a stranger's team. Nothing here reaches the network, and no AI
call is made.
"""
import hashlib
import io
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import uuid
import zipfile
from unittest.mock import patch

import hub
from test_ui_api import OwnerAPI, parent_pipe

KIT = os.path.dirname(os.path.abspath(__file__))
OWNER = {"addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3"},
         "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                    "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"],
                            "vault": "broker", "vault_recipient": "age1" + "q" * 58}},
         "hub": {"machine": "hub", "port": 8765}}
PROFILE = "# Profile: vps\n\n**Character.** Careful.\n"
BRAND = "# Brand\n\nBlue, and the owner's own.\n"


# What a used hub holds in `~/.fleet`, and what no copy of it may ever carry. Every one of these is the shape of
# a real credential, and `HubOnly.test_no_value_of_the_hub_s_own_files_reaches_the_copy` asks the zip, member by
# member, whether it carries one. A later change that decided to be helpful and put these in the copy fails there.
MARKERS = {"google_refresh": "1//0gREFRESHnhdQ0hOdJRKt7Txxxxxxxxxxxxxxxxxxxx",
           "google_secret": "GOCSPX-cLiEnTsEcReTxxxxxxxxxx",
           "github_key": "MIIEowIBAAKCAQEAxPRIVATExKEYxBODYxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
           "mcp_refresh": "mcp-refresh-token-xxxxxxxxxxxxxxxxxxxxxxxx",
           "mcp_secret": "mcp-client-secret-xxxxxxxxxxxx",
           "attachment": "the owner's own file and nobody else's business"}


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (Copy, HubOnly, Restore, ByHand, RecordsFile):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


def git(*args, cwd=None):
    done = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main",
                           *args], cwd=cwd, capture_output=True, text=True, timeout=120)
    if done.returncode:
        raise AssertionError(f"git {' '.join(args)}: {done.stderr}")
    return done.stdout.strip()


def make_checkout(root, name, team, profiles=(("vps", PROFILE),), brand=BRAND):
    """A machine's own checkout on the configuration ref, with the bare repository the hub pushes to."""
    seed, bare, kit = os.path.join(root, name + "-seed"), os.path.join(root, name + ".git"), os.path.join(root, name)
    os.makedirs(os.path.join(seed, "profiles"))
    os.makedirs(os.path.join(seed, "knowledge", "owner"))
    with open(os.path.join(seed, "team.json"), "w") as f:
        json.dump(team, f, indent=2)
    for agent, text in profiles:
        with open(os.path.join(seed, "profiles", agent + ".md"), "w") as f:
            f.write(text)
    with open(os.path.join(seed, "knowledge", "owner", "brand.md"), "w") as f:
        f.write(brand)
    git("init", "-q", seed)
    git("add", "-A", cwd=seed)
    git("commit", "-q", "-m", "the fleet's own configuration", cwd=seed)
    git("branch", hub.CONFIG_BRANCH, cwd=seed)
    git("clone", "-q", "--bare", seed, bare)
    git("clone", "-q", "-b", hub.CONFIG_BRANCH, bare, kit)
    return kit


def read(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as f:
        return f.read()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Fixture(OwnerAPI):
    """The owner's hub, on a checkout of its own, with the restart turned off: a restore asks for one, and in a
    test nothing may run `systemctl`."""

    def setUp(self):
        super().setUp()
        hub.TEAM = json.loads(json.dumps(OWNER))
        self.kit = make_checkout(self.tmp.name, "kit", hub.TEAM)
        hub.CFG["team_path"] = os.path.join(self.kit, "team.json")
        hub.CFG["db_path"] = self.path
        hub.CFG["hub_restart"] = []
        hub._revision_cache.update(at=0.0, value=None)
        self.addCleanup(hub.CFG.pop, "hub_restart", None)
        self.addCleanup(hub.CFG.pop, "team_path", None)
        self.addCleanup(hub.CFG.pop, "db_path", None)
        # A hub machine's own `~/.fleet`, here and never the one this developer is running on: the manifest
        # counts what is on that disk, and a test that read the real folder would count his Google accounts.
        self.fleet_home = os.path.join(self.tmp.name, "fleet-home")
        os.makedirs(self.fleet_home, mode=0o700)
        for key, name in (("google_file", "google.json"), ("mcp_file", "mcp.json"),
                          ("github_app", "github-app.pem"), ("attachment_dir", "attachments")):
            hub.CFG[key] = os.path.join(self.fleet_home, name)
            self.addCleanup(hub.CFG.pop, key, None)

    def hub_that_has_been_used(self, google=2, mcp=1, attachments=3):
        """The three sign-ins and the attachments folder that a hub picks up in use, with a marker where each
        real value would be. Nothing here is in a copy, and these tests are what keeps it that way."""
        if google:
            accounts = {f"owner{n}@example.com": {"refresh_token": MARKERS["google_refresh"] + str(n),
                                                  "scopes": ["https://www.googleapis.com/auth/drive"]}
                        for n in range(google)}
            self.write_hub_file("google.json", json.dumps(
                {"client_id": "9.apps.googleusercontent.com", "client_secret": MARKERS["google_secret"],
                 "accounts": accounts}))
        if mcp:
            servers = {f"crm{n}": {"token_endpoint": "https://crm.example.com/token", "client_id": "fleet",
                                   "client_secret": MARKERS["mcp_secret"],
                                   "refresh_token": MARKERS["mcp_refresh"] + str(n)} for n in range(mcp)}
            self.write_hub_file("mcp.json", json.dumps({"servers": servers}))
        self.write_hub_file("github-app.pem", "app_id=112233\n-----BEGIN RSA PRIVATE KEY-----\n"
                            + MARKERS["github_key"] + "\n-----END RSA PRIVATE KEY-----\n")
        folder = os.path.join(self.fleet_home, "attachments")
        os.makedirs(folder, mode=0o700, exist_ok=True)
        for n in range(attachments):
            with open(os.path.join(folder, f"{n:064x}.txt"), "w", encoding="utf-8") as f:
                f.write(MARKERS["attachment"] + f" ({n})\n")

    def write_hub_file(self, name, text):
        """One of the hub's own files, as the hub writes them: mode 600, in `~/.fleet`."""
        path = os.path.join(self.fleet_home, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(path, 0o600)
        return path

    def work(self):
        """What a fleet that has run for a while holds: tasks and their results, a goal, a duty and its case."""
        hub.q("INSERT INTO tasks(id,title,owner,requester,state,created,done_when) "
              "VALUES(4,'Write the October report','vps','manager','completed',1,'the report is in outputs')")
        hub.q("INSERT INTO notes(task,agent,ts,text) VALUES(4,'vps',2,'the report is written')")
        hub.q("INSERT INTO goals(id,title,text,state,revision,limits,created,updated,request_id) "
              "VALUES(2,'Sell the first ten','text','open',1,'{}',1,1,?)", (str(uuid.uuid4()),))
        hub.q("INSERT INTO responsibilities(id,agent,text,"
              "state,revision,created,updated,created_by,request_id) "
              "VALUES(3,'vps','The shop stays up. Fix what breaks.','active',1,1,1,"
              "'manager',?)", (str(uuid.uuid4()),))

    def download(self, db="test-generation"):
        req = urllib.request.Request(self.base + "/ui/backup?db=" + db,
                                     headers={"X-Fleet-Client": "deterministic-test"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=10) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            with e:
                return e.code, dict(e.headers), e.read()

    def send(self, data, query="", request_id=None, client="deterministic-test"):
        req = urllib.request.Request(self.base + "/ui/restore?db=test-generation" + query, data=data, method="POST",
                                     headers={"Content-Type": "application/zip", "X-Fleet-Client": client,
                                              "X-Fleet-Request-Id": request_id or str(uuid.uuid4())})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=20) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.load(e)


# ---------------------------------------------------------------- what the owner gets

class Copy(Fixture):
    def test_the_copy_is_the_records_and_the_owner_s_own_configuration(self):
        """The database alone is not the fleet: `team.json`, the profiles and the owner's knowledge live only in
        the checkout, whose bare repository is on the same disk."""
        self.work()
        code, headers, data = self.download()
        self.assertEqual(code, 200)
        self.assertEqual(headers["Content-Type"], "application/zip")
        self.assertEqual(headers["X-Fleet-Backup-SHA256"], hashlib.sha256(data).hexdigest())
        zf = zipfile.ZipFile(io.BytesIO(data))
        self.assertEqual(sorted(zf.namelist()),
                         ["RESTORE.md", "config/knowledge/owner/brand.md", "config/profiles/vps.md",
                          "config/team.json", "fleet.json", "fleet.sqlite3"])
        self.assertEqual(zf.read("config/profiles/vps.md").decode(), PROFILE)
        self.assertEqual(json.loads(zf.read("config/team.json")), OWNER)
        records = sqlite3.connect(":memory:")
        self.addCleanup(records.close)
        records.deserialize(zf.read("fleet.sqlite3"))
        self.assertEqual(records.execute("SELECT title FROM tasks").fetchone()[0], "Write the October report")

    def test_the_copy_names_the_machines_whose_vault_it_cannot_carry(self):
        """The one thing a copy cannot hold: each store key is in a folder only that machine's vault user can
        open, and a second key would leave every saved value unreadable. So it is named, not hidden."""
        manifest = json.loads(zipfile.ZipFile(io.BytesIO(self.download()[2])).read("fleet.json"))
        self.assertEqual(manifest["vault"], {"vps": {"machine": "vps", "mode": "broker",
                                                     "recipient": OWNER["agents"]["vps"]["vault_recipient"]}})
        notes = zipfile.ZipFile(io.BytesIO(self.download()[2])).read("RESTORE.md").decode()
        self.assertIn("vault store keys", notes)
        self.assertIn("vps on vps (broker)", notes)
        self.assertIn("python3 hub.py --restore", notes)

    def test_the_copy_says_to_read_the_open_tasks_before_they_run_again(self):
        """Records from an hour ago hold tasks that were open an hour ago, and their agents cannot know what the
        old machine did afterwards. That is rule 9, and after a restore it is the owner's to apply."""
        notes = zipfile.ZipFile(io.BytesIO(self.download()[2])).read("RESTORE.md").decode()
        self.assertIn("rule 9", notes)
        self.assertIn("check before repeating", notes)

    def test_the_copy_carries_no_clock_of_its_own_in_its_entries(self):
        """Every entry has one fixed date, so two copies differ only where the fleet differs, and the zip says
        nothing about the hub machine's time zone."""
        zf = zipfile.ZipFile(io.BytesIO(self.download()[2]))
        self.assertEqual({one.date_time for one in zf.infolist()}, {(1980, 1, 1, 0, 0, 0)})

    def test_a_copy_of_records_in_wal_mode_is_records_that_a_restore_opens(self):
        """The hub keeps its records in WAL mode since 11 November 2026 (hub.wal_on), and DB.serialize() copies the
        header of that mode, which SQLite opens from no image in memory: a restore refused such a copy as records that
        "cannot be opened". The copy has the header of rollback mode, and a restore reads it."""
        self.assertEqual(hub.wal_on(), (True, None))
        self.work()
        with hub.LOCK:
            self.assertEqual(hub.DB.serialize()[18:20], b"\x02\x02")
        code, _headers, data = self.download()
        self.assertEqual(code, 200)
        records = zipfile.ZipFile(io.BytesIO(data)).read("fleet.sqlite3")
        self.assertEqual(records[18:20], b"\x01\x01")
        self.assertEqual(hub.read_bundle(data)["manifest"]["fleet_id"], hub.fleet_id())
        copy = sqlite3.connect(":memory:")
        self.addCleanup(copy.close)
        copy.deserialize(records)
        self.assertEqual(copy.execute("SELECT title FROM tasks").fetchone()[0], "Write the October report")

    def test_a_copy_whose_records_say_wal_mode_is_read_too(self):
        """Records with the header of WAL mode in a copy (a hub's file put in a zip by hand) pass the check of a
        restore all the same, and read_bundle hands them on unchanged: the hub that starts on them opens a file, which
        SQLite opens in either mode."""
        self.work()
        zf = zipfile.ZipFile(io.BytesIO(self.download()[2]))
        members = {name: zf.read(name) for name in zf.namelist()}
        walled = members["fleet.sqlite3"][:18] + b"\x02\x02" + members["fleet.sqlite3"][20:]
        manifest = json.loads(members["fleet.json"])
        manifest["files"]["fleet.sqlite3"] = {"bytes": len(walled), "sha256": hashlib.sha256(walled).hexdigest()}
        members.update({"fleet.sqlite3": walled, "fleet.json": json.dumps(manifest).encode()})
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as out:
            for name, body in members.items():
                out.writestr(name, body)
        self.assertEqual(hub.read_bundle(buffer.getvalue())["records"], walled)


# ---------------------------------------------------------------- what it cannot carry, and what to do then

class HubOnly(Fixture):
    """The copy holds the records and the owner's own configuration. Four things live on the hub machine's own
    disk and go with it: the Google tokens, the GitHub App key, the MCP credentials and the attachments. None of
    them is in a copy and none of them may ever be, so the copy's job is to say so — about this hub, with its
    own counts, and with the step that puts each one back."""

    def manifest(self):
        return json.loads(zipfile.ZipFile(io.BytesIO(self.download()[2])).read("fleet.json"))

    def notes(self):
        return zipfile.ZipFile(io.BytesIO(self.download()[2])).read("RESTORE.md").decode()

    def test_the_manifest_says_what_this_hub_had_on_its_own_disk(self):
        self.hub_that_has_been_used(google=2, mcp=1, attachments=3)
        self.assertEqual(self.manifest()["hub_only"], {
            "google": {"present": True, "accounts": 2, "client": True},
            "github_app": {"present": True},
            "mcp": {"present": True, "servers": 1},
            "attachments": {"present": True, "files": 3, "bytes": 3 * (len(MARKERS["attachment"]) + 5)}})

    def test_the_manifest_of_a_hub_that_has_none_of_them_says_that_too(self):
        """A hub with no Google, no App and no server is the ordinary new fleet, and the copy must not tell its
        owner to go and reconnect four things he never had."""
        self.assertEqual(self.manifest()["hub_only"], {
            "google": {"present": False}, "github_app": {"present": False}, "mcp": {"present": False},
            "attachments": {"present": False, "files": 0, "bytes": 0}})
        notes = self.notes()
        self.assertIn("**Nothing else.**", notes)
        self.assertNotIn("github-app.pem", notes)
        self.assertNotIn("Connect Google again", notes)

    def test_the_manifest_holds_counts_and_nothing_that_could_be_a_value(self):
        """The one property that makes this copy safe to keep beside the owner's own files. A count of accounts
        can never become a token; a name, a path or a fingerprint is the beginning of one, so none is recorded."""
        self.hub_that_has_been_used()
        for name, one in self.manifest()["hub_only"].items():
            for key, value in one.items():
                self.assertIsInstance(value, (bool, int), f"hub_only.{name}.{key} is not a count: {value!r}")

    def test_no_value_of_the_hub_s_own_files_reaches_the_copy(self):
        """**The test that matters.** The owner keeps this copy where he keeps his own files, which is right
        only while there is no credential in it. So: plant a hub with every one of its own files full, take a
        copy, and read every member of it — the manifest, the notes, the records, the configuration, and the
        raw zip under them — looking for anything that was in those files. Nothing may be found.

        A later change that decided it would be kind to carry the Google tokens, the App key or the attachments
        fails here, and should."""
        self.work()
        self.hub_that_has_been_used(google=2, mcp=2, attachments=3)
        data = self.download()[2]
        zf = zipfile.ZipFile(io.BytesIO(data))
        members = {name: zf.read(name) for name in zf.namelist()}
        for name, marker in MARKERS.items():
            self.assertNotIn(marker.encode(), data, f"the {name} of the hub is in the zip itself")
            for member, body in members.items():
                self.assertNotIn(marker.encode(), body, f"the {name} of the hub is in {member}")
        # And no member that is not one of the two things a copy is: the records, and the owner's own files.
        for name in members:
            self.assertTrue(name in ("fleet.json", "RESTORE.md", hub.BACKUP_DB) or name.startswith("config/"),
                            f"{name} is in this copy and is not the records or a file of the owner's")

    def test_the_copy_tells_him_what_stops_working_and_what_to_go_and_find(self):
        """The whole point of the manifest's counts: the file says what *this* hub had, what each loss costs
        him, and the step that puts it back — the GitHub key first, because it is one file and it unblocks
        every task that touches code."""
        self.hub_that_has_been_used(google=2, mcp=1, attachments=3)
        notes = self.notes()
        self.assertIn("`~/.fleet/github-app.pem`", notes)
        self.assertIn("the 2 Google accounts you connected", notes)
        self.assertIn("the one MCP server you connected", notes)
        self.assertIn("held 3 files", notes)
        self.assertIn("no agent reads or writes any repository", notes)      # what it costs him, not what it is
        self.assertIn("github.com/settings/apps", notes)                     # and where he goes for it
        steps = notes[notes.index("## Putting it back"):]
        self.assertLess(steps.index("GitHub App key back"), steps.index("Connect Google again"), steps)
        self.assertIn("6. **Put a GitHub App key back.**", steps)
        # the places the apps have now (D-4): MCP servers are a group of Settings › Apps, and Restore is under Backup
        self.assertIn("in the app under Settings › Apps, MCP servers", steps)
        self.assertIn("afterwards it is in Settings › Backup.", steps)
        for gone in ("Settings > MCPs", "System status", "under Details"):
            self.assertNotIn(gone, notes)

    def test_a_file_that_holds_nothing_yet_asks_him_to_put_nothing_back(self):
        """An `mcp.json` with no server in it is a file that is there and holds nothing. The manifest says both
        — it counts what it finds — and the notes say nothing, because "the 0 MCP servers you connected" is
        the kind of sentence that makes a man stop reading the one file he needs to read."""
        self.write_hub_file("mcp.json", json.dumps({"servers": {}}))
        self.write_hub_file("google.json", json.dumps({"client_id": "9.apps.googleusercontent.com",
                                                       "client_secret": MARKERS["google_secret"], "accounts": {}}))
        found = self.manifest()["hub_only"]
        self.assertEqual(found["mcp"], {"present": True, "servers": 0})
        self.assertEqual(found["google"], {"present": True, "accounts": 0, "client": True})
        notes = self.notes()
        self.assertNotIn("0 MCP servers", notes)
        self.assertNotIn("0 Google accounts", notes)
        self.assertIn("no MCP server connected, so there is nothing of those to put back", notes)
        self.assertIn("no connected account yet", notes)        # the client is there and he would need it

    def test_a_file_the_hub_itself_would_refuse_is_counted_as_there_and_not_counted(self):
        """A `google.json` whose mode is wrong is one the hub will not read either. The copy says it is there,
        because that is true and he needs to know, and claims no number it does not have."""
        self.hub_that_has_been_used()
        os.chmod(os.path.join(self.fleet_home, "google.json"), 0o644)
        found = self.manifest()["hub_only"]
        self.assertEqual(found["google"], {"present": True})
        self.assertIn("holds the Google accounts you connected.", self.notes())


# ---------------------------------------------------------------- putting it back

class Restore(Fixture):
    """Fleet A's copy, onto a second machine that is empty."""

    def copy_of_a_fleet(self):
        """What the owner saved from the hub he no longer has."""
        self.work()
        fleet = hub.fleet_id()
        code, _headers, data = self.download()
        self.assertEqual(code, 200)
        return fleet, data

    def new_machine(self):
        """The hub the owner installed to stand in for the dead one: a fresh database, a fresh checkout and its
        own address, with the owner's Mac already claimed."""
        hub.DB.close()
        self.path = os.path.join(self.tmp.name, "new.db")
        self.connect()
        hub.kv_set("db_id", "test-generation")
        hub.TEAM = {"addresses": {"owner": "127.0.0.1", "hub": "127.0.0.9"},
                    "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []}},
                    "hub": {"machine": "hub", "port": 8765}}
        self.kit = make_checkout(self.tmp.name, "new-kit", hub.TEAM, profiles=(("manager", "# Profile: manager\n"),),
                                 brand="# Brand\n\nNothing yet.\n")
        hub.CFG["team_path"] = os.path.join(self.kit, "team.json")
        hub.CFG["db_path"] = self.path
        hub._revision_cache.update(at=0.0, value=None)

    def start_real_hub(self):
        """The restart the hub asks for, done here: a real process on the staged records."""
        port = free_port()
        pipe, fds = parent_pipe(self.tmp.name)
        proc = subprocess.Popen([sys.executable, os.path.join(KIT, "hub.py"), "--host", "127.0.0.1",
                                 "--port", str(port), "--db", self.path,
                                 "--team", os.path.join(self.kit, "team.json"),
                                 "--chat-apps", os.path.join(self.tmp.name, "chat-apps"), "--parent-pipe", str(pipe)],
                                pass_fds=fds, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=KIT,
                                env=dict(os.environ, HOME=self.tmp.name))     # its timer sweeps ~/.fleet/attachments
        self.addCleanup(self.stop, proc)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(100):
            if proc.poll() is not None:
                self.fail("the restored hub did not start: " + proc.stdout.read())
            try:
                opener.open(f"http://127.0.0.1:{port}/health", timeout=1).read()
                return proc, f"http://127.0.0.1:{port}"
            except (urllib.error.URLError, OSError):
                time.sleep(0.1)
        self.fail("the restored hub never answered")

    @staticmethod
    def stop(proc):
        proc.kill()
        proc.wait(timeout=20)
        proc.stdout.close()

    def records(self):
        opened = sqlite3.connect(self.path)
        self.addCleanup(opened.close)
        opened.row_factory = sqlite3.Row
        return opened

    def test_a_new_machine_becomes_the_fleet_that_was_saved(self):
        fleet, data = self.copy_of_a_fleet()
        self.new_machine()
        code, answer = self.send(data)
        self.assertEqual(code, 200, answer)
        self.assertEqual((answer["ok"], answer["fleet_id"], answer["replayed"]), (True, fleet, False))
        self.assertEqual(answer["files"], ["knowledge/owner/brand.md", "profiles/vps.md", "team.json"])
        self.assertEqual(answer["removed"], ["profiles/manager.md"])     # an agent the saved fleet does not have

        # The configuration ref carries the saved fleet now, standing on this machine's own address.
        self.assertEqual(read(self.kit, "profiles", "vps.md"), PROFILE)
        self.assertFalse(os.path.exists(os.path.join(self.kit, "profiles", "manager.md")))
        self.assertEqual(read(self.kit, "knowledge", "owner", "brand.md"), BRAND)
        team = json.loads(read(self.kit, "team.json"))
        self.assertEqual(sorted(team["agents"]), ["manager", "vps"])
        self.assertEqual(team["addresses"]["hub"], "127.0.0.9")          # this machine, not the dead one
        self.assertEqual(team["addresses"]["owner"], "127.0.0.1")
        self.assertEqual(team["addresses"]["vps"], "127.0.0.3")          # and the other machines as they were
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.kit),
                         git("rev-parse", hub.CONFIG_BRANCH, cwd=os.path.join(self.tmp.name, "new-kit.git")))

        # The records wait beside the database, because they cannot be swapped under a running hub.
        self.assertTrue(os.path.exists(self.path + hub.RESTORE_SUFFIX))
        self.assertEqual(self.records().execute("SELECT count(*) FROM tasks").fetchone()[0], 0)

        proc, base = self.start_real_hub()
        opened = self.records()
        self.assertEqual(opened.execute("SELECT title FROM tasks WHERE id=4").fetchone()[0],
                         "Write the October report")
        self.assertEqual(opened.execute("SELECT title FROM goals WHERE id=2").fetchone()[0], "Sell the first ten")
        self.assertEqual(opened.execute("SELECT text FROM responsibilities WHERE id=3").fetchone()[0],
                         "The shop stays up. Fix what breaks.")
        kv = dict(opened.execute("SELECT k,v FROM kv").fetchall())
        self.assertEqual(kv["fleet_id"], fleet)                     # the fleet's own id came with the copy
        self.assertNotEqual(kv["db_id"], "test-generation")         # and the generation is new
        self.assertTrue(kv.get("restored_at"))
        self.assertFalse(os.path.exists(self.path + hub.RESTORE_SUFFIX))
        self.assertFalse(os.path.exists(self.path + hub.REPLACED_SUFFIX))    # nothing of value was put aside
        said = [r[0] for r in opened.execute("SELECT what FROM log WHERE what LIKE '%took a copy%'")]
        self.assertTrue(any(fleet in one for one in said), said)
        proc.terminate()
        proc.wait(timeout=20)
        self.assertIn("Restored:", proc.stdout.read())

    def test_yesterday_s_copy_goes_back_onto_the_machine_it_came_from(self):
        """The likeliest replacement of all: the records went bad (the six-hourly check says so) and the owner
        puts back the copy he took from this same hub. Its configuration has not moved, so there is nothing to
        commit — and a commit with nothing staged fails, which would have refused exactly this case."""
        _fleet, data = self.copy_of_a_fleet()
        before = git("rev-parse", "HEAD", cwd=self.kit)
        code, answer = self.send(data, query="&replace=yes")
        self.assertEqual(code, 200, answer)
        self.assertEqual(answer["changed"], [])
        self.assertEqual(answer["removed"], [])
        self.assertEqual(answer["files"], ["knowledge/owner/brand.md", "profiles/vps.md", "team.json"])
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.kit), before)
        self.assertTrue(os.path.exists(self.path + hub.RESTORE_SUFFIX))

    def test_a_copy_taken_before_the_hub_knew_what_it_was_missing_still_goes_back(self):
        """The copy on his Mac was made by the hub he had last week, whose manifest has no `hub_only` in it.
        The day he needs it is the wrong day to find out that the format moved, so it did not: the key is new
        information about the hub that made the copy, and a restore neither reads it nor asks for it."""
        _fleet, data = self.copy_of_a_fleet()
        older = self.without_hub_only(data)
        self.assertNotIn("hub_only", json.loads(zipfile.ZipFile(io.BytesIO(older)).read("fleet.json")))
        self.new_machine()
        code, answer = self.send(older)
        self.assertEqual(code, 200, answer)
        self.assertEqual(answer["files"], ["knowledge/owner/brand.md", "profiles/vps.md", "team.json"])
        proc, _base = self.start_real_hub()
        self.assertEqual(self.records().execute("SELECT title FROM tasks WHERE id=4").fetchone()[0],
                         "Write the October report")
        proc.terminate()
        proc.wait(timeout=20)

    @staticmethod
    def without_hub_only(data):
        """The same copy as a hub of last week made it: the manifest with no `hub_only` key. The manifest is
        what describes the other members, so none of their SHA-256s changes."""
        old = zipfile.ZipFile(io.BytesIO(data))
        members = {name: old.read(name) for name in old.namelist()}
        manifest = json.loads(members["fleet.json"])
        manifest.pop("hub_only")
        members["fleet.json"] = json.dumps(manifest, indent=2, sort_keys=True).encode()
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, body in members.items():
                zf.writestr(name, body)
        return out.getvalue()

    def test_records_that_went_bad_while_they_waited_are_not_taken(self):
        """The swap at the next start is the one move that cannot be undone, so it is checked again right before
        it: a half-written or damaged file leaves this hub's own records where they are, and says so."""
        _fleet, data = self.copy_of_a_fleet()
        self.new_machine()
        self.assertEqual(self.send(data)[0], 200)
        staged = self.path + hub.RESTORE_SUFFIX
        with open(staged, "r+b") as f:                  # the disk, between the restore and the restart
            f.seek(4096)
            f.write(b"\xff" * 2048)
        proc, _base = self.start_real_hub()
        said = proc.stdout
        self.assertEqual(self.records().execute("SELECT count(*) FROM tasks").fetchone()[0], 0)
        self.assertTrue(os.path.exists(staged), "the copy was thrown away instead of kept for another try")
        proc.terminate()
        proc.wait(timeout=20)
        out = said.read()
        self.assertIn("was not taken", out)
        self.assertIn("kept its own records", out)
        self.assertNotIn("Restored:", out)      # and the generation did not turn over on a restore that is not one
        self.assertEqual(self.records().execute("SELECT v FROM kv WHERE k='db_id'").fetchone()[0],
                         "test-generation")

    def test_a_write_that_did_not_finish_leaves_nothing_for_the_next_start(self):
        _fleet, _data = self.copy_of_a_fleet()
        self.new_machine()
        with open(self.path + hub.RESTORE_SUFFIX + ".part", "wb") as f:
            f.write(b"half a database")
        self.start_real_hub()
        self.assertFalse(os.path.exists(self.path + hub.RESTORE_SUFFIX + ".part"))
        self.assertEqual(self.records().execute("SELECT count(*) FROM tasks").fetchone()[0], 0)

    def test_a_hub_that_already_holds_work_is_not_overwritten_by_accident(self):
        _fleet, data = self.copy_of_a_fleet()                       # this hub has work: self.work() ran
        code, answer = self.send(data)
        self.assertEqual(code, 409)
        self.assertIn("A restore is for a new server", answer["error"])
        self.assertFalse(os.path.exists(self.path + hub.RESTORE_SUFFIX))

    def test_a_deliberate_replacement_keeps_the_records_it_replaced(self):
        """Putting yesterday's copy over today's records is a real thing to want — it is what the six-hourly
        integrity warning is for — so it is possible, and what it replaces is kept because the owner asked."""
        _fleet, data = self.copy_of_a_fleet()
        hub.q("INSERT INTO tasks(id,title,owner,requester,state,created) "
              "VALUES(9,'later work','vps','manager','submitted',3)")
        code, answer = self.send(data, query="&replace=yes")
        self.assertEqual((code, answer["keep_replaced"]), (200, True), answer)
        proc, _base = self.start_real_hub()
        opened = self.records()
        self.assertIsNone(opened.execute("SELECT title FROM tasks WHERE id=9").fetchone())
        self.assertTrue(os.path.exists(self.path + hub.REPLACED_SUFFIX))
        put_aside = sqlite3.connect(self.path + hub.REPLACED_SUFFIX)
        self.addCleanup(put_aside.close)
        self.assertEqual(put_aside.execute("SELECT title FROM tasks WHERE id=9").fetchone()[0], "later work")
        proc.terminate()
        proc.wait(timeout=20)

    def test_a_repeat_of_the_same_request_restores_once(self):
        _fleet, data = self.copy_of_a_fleet()
        self.new_machine()
        request_id = str(uuid.uuid4())
        first = self.send(data, request_id=request_id)
        again = self.send(data, request_id=request_id)
        self.assertEqual((first[0], again[0]), (200, 200))
        self.assertFalse(first[1]["replayed"])
        self.assertTrue(again[1]["replayed"])
        self.assertEqual(first[1]["fleet_id"], again[1]["fleet_id"])
        self.assertEqual(self.send(data, request_id=request_id, client="another app")[0], 409)
        other = self.with_team(data, dict(OWNER, hub={"machine": "hub", "port": 9999}))
        self.assertEqual(self.send(other, request_id=request_id)[0], 409)    # the same UUID, another copy

    def test_a_copy_whose_team_does_not_fit_this_machine_is_refused_with_the_rule(self):
        """The merged file must be one the hub can run, because a hub with a broken team.json refuses every owner
        write of team.json and the owner could not repair it from the app."""
        self.work()
        data = self.download()[2]
        self.new_machine()
        nowhere = {"agents": {"ghost": {"role": "worker", "machine": "gone"}}, "addresses": {},
                   "hub": {"machine": "hub", "port": 8765}}
        code, answer = self.send(self.with_team(data, nowhere))
        self.assertEqual(code, 422, answer)
        self.assertIn("team.json the hub can run", answer["error"])
        self.assertFalse(os.path.exists(self.path + hub.RESTORE_SUFFIX))
        self.assertEqual(json.loads(read(self.kit, "team.json"))["addresses"]["hub"], "127.0.0.9")

    @staticmethod
    def with_team(data, team):
        """The same copy, carrying another team.json."""
        old = zipfile.ZipFile(io.BytesIO(data))
        members = {name: old.read(name) for name in old.namelist()}
        members["config/team.json"] = json.dumps(team).encode()
        manifest = json.loads(members["fleet.json"])
        manifest["files"]["config/team.json"] = {"bytes": len(members["config/team.json"]),
                                                 "sha256": hashlib.sha256(members["config/team.json"]).hexdigest()}
        members["fleet.json"] = json.dumps(manifest).encode()
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, body in members.items():
                zf.writestr(name, body)
        return buffer.getvalue()

    def test_a_copy_that_is_not_what_it_says_is_refused_and_nothing_is_staged(self):
        _fleet, data = self.copy_of_a_fleet()
        self.new_machine()
        for name, broken in self.damaged(data):
            with self.subTest(name):
                code, answer = self.send(broken)
                self.assertEqual(code, 422, answer)
                self.assertFalse(os.path.exists(self.path + hub.RESTORE_SUFFIX), name)
                self.assertEqual(json.loads(read(self.kit, "team.json"))["addresses"]["hub"], "127.0.0.9")
                self.assertEqual(hub.q1("SELECT count(*) n FROM ui_controls")["n"], 0)

    @staticmethod
    def damaged(data):
        """Every way a copy can be wrong that a restore must catch before it writes anything."""
        def rebuilt(change):
            old = zipfile.ZipFile(io.BytesIO(data))
            members = {name: old.read(name) for name in old.namelist()}
            change(members)
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
                for name, body in members.items():
                    zf.writestr(name, body)
            return buffer.getvalue()

        def changed(members, **fields):
            members["fleet.json"] = json.dumps(dict(json.loads(members["fleet.json"]), **fields)).encode()

        def records_not_as_described(members):
            body = bytearray(members["fleet.sqlite3"])
            body[4096] ^= 0xFF                      # one byte of one page, which the manifest's SHA-256 catches
            members["fleet.sqlite3"] = bytes(body)

        def a_path_a_restore_may_not_write(members):
            members["config/../../etc/passwd"] = b"root"
            changed(members, files=dict(json.loads(members["fleet.json"])["files"],
                                        **{"config/../../etc/passwd": {"bytes": 4, "sha256": "0" * 64}}))

        def no_records(members):
            members.pop("fleet.sqlite3")

        def records_that_are_not_a_database(members):
            body = b"not a database" + b"\x00" * 200
            members["fleet.sqlite3"] = body
            changed(members, files=dict(json.loads(members["fleet.json"])["files"],
                                        **{"fleet.sqlite3": {"bytes": len(body),
                                                             "sha256": hashlib.sha256(body).hexdigest()}}))
        return [("not a zip", b"PK\x03\x04 and then nothing"),
                ("another format", rebuilt(lambda m: changed(m, format=99))),
                ("records that do not match the manifest", rebuilt(records_not_as_described)),
                ("a path outside the owner's own files", rebuilt(a_path_a_restore_may_not_write)),
                ("no records at all", rebuilt(no_records)),
                ("records that are not a database", rebuilt(records_that_are_not_a_database))]


# ---------------------------------------------------------------- without the app

class ByHand(Fixture):
    def test_the_hub_machine_can_take_a_copy_from_a_shell(self):
        """`python3 hub.py --restore <copy>`: the same staging, for a person whose app cannot reach this hub."""
        self.work()
        data = self.download()[2]
        path = os.path.join(self.tmp.name, "copy.zip")
        with open(path, "wb") as f:
            f.write(data)
        fresh = os.path.join(self.tmp.name, "fresh.db")
        done = subprocess.run([sys.executable, os.path.join(KIT, "hub.py"), "--restore", path, "--db", fresh,
                               "--team", os.path.join(self.kit, "team.json")],
                              capture_output=True, text=True, timeout=120, cwd=KIT)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("is staged", done.stdout)
        self.assertIn("systemctl --user restart fleet-hub", done.stdout)
        self.assertTrue(os.path.exists(fresh + hub.RESTORE_SUFFIX))

    def test_a_file_that_is_not_a_copy_is_refused_with_one_line(self):
        path = os.path.join(self.tmp.name, "holiday.jpg")
        with open(path, "wb") as f:
            f.write(b"\xff\xd8\xff\xe0 not a fleet")
        done = subprocess.run([sys.executable, os.path.join(KIT, "hub.py"), "--restore", path,
                               "--db", os.path.join(self.tmp.name, "fresh.db"),
                               "--team", os.path.join(self.kit, "team.json")],
                              capture_output=True, text=True, timeout=120, cwd=KIT)
        self.assertEqual(done.returncode, 1)
        self.assertIn("not a copy of a fleet", done.stdout)


# A process that dies in the middle of a write that has reached the file: what a stop in the middle of a commit leaves.
CRASH = """
import os, sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("PRAGMA cache_size=10")
c.execute("UPDATE t SET x=? || x", ("changed-",))
os._exit(0)
"""

# A hub with its records in WAL mode that is killed after its last commit: those commits are in the WAL beside them.
WAL_KILLED = """
import os, sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("PRAGMA journal_mode=WAL")
c.execute("CREATE TABLE t(x TEXT)")
c.executemany("INSERT INTO t VALUES(?)", [("old-" + "y" * 200,) for _ in range(4000)])
c.commit()
os._exit(0)
"""

# A process that holds a hub's lock on the records for a second, as a hub that still runs does.
HOLD = """
import fcntl, os, sys, time
fd = os.open(sys.argv[1] + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
print("held", flush=True)
time.sleep(1.5)
"""


class RecordsFile(unittest.TestCase):
    """The file of the records belongs to one hub process, and its rollback journal or its WAL belongs to it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "pilot.db")

    @staticmethod
    def records(path, word, n):
        c = sqlite3.connect(path)
        c.execute("CREATE TABLE t(x TEXT)")
        c.executemany("INSERT INTO t VALUES(?)", [(f"{word}-" + "y" * 200,) for _ in range(n)])
        c.commit()
        c.close()

    def stopped_in_a_commit(self):
        """The old records, with the hot journal that a stop in the middle of a commit leaves beside them, and a copy
        staged to take their place."""
        self.records(self.path, "old", 4000)
        subprocess.run([sys.executable, "-I", "-c", CRASH, self.path], check=True)
        self.assertTrue(os.path.exists(self.path + "-journal"), "the stop left no journal: the test proves nothing")
        self.records(self.path + hub.RESTORE_SUFFIX, "restored", 50)

    def read(self, path):
        c = sqlite3.connect(path)
        self.addCleanup(c.close)
        return (c.execute("PRAGMA integrity_check").fetchone()[0],
                c.execute("SELECT substr(x, 1, 9), count(*) FROM t GROUP BY 1").fetchall())

    def test_a_journal_of_the_old_records_is_not_played_back_into_the_copy(self):
        """Left beside the copy, SQLite played the old journal into it at the first read: "database disk image is
        malformed", on the one move that cannot be undone."""
        self.stopped_in_a_commit()
        taken, said = hub.take_restore(self.path)
        self.assertTrue(taken, said)
        self.assertFalse(os.path.exists(self.path + "-journal"))
        self.assertEqual(self.read(self.path), ("ok", [("restored-", 50)]))

    def test_the_records_put_aside_take_their_own_journal_back(self):
        """A deliberate replacement keeps what it replaced, and that copy is whole: its journal went back into it
        before it moved, so it holds what it held before the write that never finished."""
        self.stopped_in_a_commit()
        with open(self.path + hub.RESTORE_SUFFIX + ".json", "w", encoding="utf-8") as f:
            json.dump({"fleet_id": "fleet-a", "keep_replaced": True}, f)
        with open(self.path + hub.REPLACED_SUFFIX + "-journal", "wb") as f:
            f.write(b"a journal of a file an earlier replacement put aside")
        taken, said = hub.take_restore(self.path)
        self.assertTrue(taken, said)
        self.assertEqual(self.read(self.path), ("ok", [("restored-", 50)]))
        self.assertFalse(os.path.exists(self.path + hub.REPLACED_SUFFIX + "-journal"))
        self.assertEqual(self.read(self.path + hub.REPLACED_SUFFIX), ("ok", [("old-yyyyy", 4000)]))

    def test_records_in_wal_mode_are_put_aside_with_their_newest_commits(self):
        """The hub keeps its records in WAL mode (hub.wal_on), and a hub that was killed leaves its newest commits in
        the WAL beside them. A deliberate replacement keeps what it replaced whole, with those commits, and nothing of
        that WAL stays beside the copy that takes the records' place."""
        subprocess.run([sys.executable, "-I", "-c", WAL_KILLED, self.path], check=True)
        self.assertGreater(os.path.getsize(self.path + "-wal"), 400000, "the kill left no WAL: the test proves nothing")
        self.records(self.path + hub.RESTORE_SUFFIX, "restored", 50)
        with open(self.path + hub.RESTORE_SUFFIX + ".json", "w", encoding="utf-8") as f:
            json.dump({"fleet_id": "fleet-a", "keep_replaced": True}, f)
        taken, said = hub.take_restore(self.path)
        self.assertTrue(taken, said)
        self.assertEqual([side for side in hub.SQLITE_SIDE if os.path.exists(self.path + side)], [])
        self.assertEqual(self.read(self.path), ("ok", [("restored-", 50)]))
        self.assertEqual(self.read(self.path + hub.REPLACED_SUFFIX), ("ok", [("old-yyyyy", 4000)]))

    def test_a_second_hub_on_the_same_records_waits_for_the_first(self):
        """Before, it settled the first hub's calls and took a staged restore under it before its own port bind
        failed. Now it starts only when the first has stopped."""
        holder = subprocess.Popen([sys.executable, "-I", "-c", HOLD, self.path], stdout=subprocess.PIPE, text=True)
        self.addCleanup(holder.wait)
        self.addCleanup(holder.stdout.close)
        self.assertEqual(holder.stdout.readline().strip(), "held")
        said, began = io.StringIO(), time.monotonic()
        with patch("sys.stdout", said):
            fd = hub.hub_lock(self.path)
        self.addCleanup(hub.HUB_LOCK.remove, fd)
        self.addCleanup(os.close, fd)
        self.assertGreater(time.monotonic() - began, 0.5, "it took the lock while the first hub held it")
        self.assertEqual(holder.wait(timeout=10), 0)
        self.assertIn("Another hub process holds", said.getvalue())


if __name__ == "__main__":
    unittest.main()
