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
import contextlib
import functools
import hashlib
import http.client
import inspect
import io
import json
import os
import re
import select
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tracemalloc
import unittest
import urllib.error
import urllib.request
import uuid
import zipfile
from unittest.mock import patch

import hub
import releases
from test_ui_api import OwnerAPI, parent_pipe
from leftovers import ROOT

KIT = ROOT
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


def many_entries(count, comment=0, counts=None, zip64=False):
    """A ZIP of a fleet.json of {} whose central directory names it `count` times more, each entry with `comment`
    bytes of comment: entries that zipfile's constructor reads one by one, for some 500 bytes of memory each. counts:
    the two entry counts of its end record. zip64: a Zip64 end record and its locator before an end record that states
    a directory of 46 bytes; zipfile reads the Zip64 one."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as package:
        package.writestr("fleet.json", "{}")
    head = buffer.getvalue()
    at, end = head.find(b"PK\x01\x02"), head.rfind(b"PK\x05\x06")
    entry = bytearray(head[at:end])
    struct.pack_into("<H", entry, 32, comment)
    directory = (bytes(entry) + bytes(comment)) * (count + 1)
    record = bytearray(head[end:])
    struct.pack_into("<HHII", record, 8, *(counts or (min(count + 1, 65535),) * 2), len(directory), at)
    if not zip64:
        return head[:at] + directory + bytes(record)
    struct.pack_into("<HHI", record, 8, 1, 1, 46)
    record64 = struct.pack("<IQHHIIQQQQ", 0x06064B50, 44, 45, 45, 0, 0, count + 1, count + 1, len(directory), at)
    locator = struct.pack("<IIQI", 0x07064B50, 0, at + len(directory), 1)
    return head[:at] + directory + record64 + locator + bytes(record)


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
        # The key of the Google file, outside `~/.fleet` as on a hub machine (UI-API.md 1.202)
        self.google_key = os.path.join(self.tmp.name, "config-home", "google-file.key")
        hub.CFG["google_key"] = self.google_key
        self.addCleanup(hub.CFG.pop, "google_key", None)
        opened = patch.dict(hub.GOOGLE_OPENED, {"last": None, "key": None, "vault": None, "asked_for": None,
                                                "said": None, "dropped_for": None, "before": {}})
        opened.start()
        self.addCleanup(opened.stop)

    def hub_that_has_been_used(self, google=2, mcp=1, attachments=3, sealed=False):
        """The three sign-ins and the attachments folder that a hub picks up in use, with a marker where each
        real value would be. Nothing here is in a copy, and these tests are what keeps it that way. sealed: the
        Google file as a hub of 1.202 and later writes it, sealed with the key of its key file; else as a hub from
        before wrote it, in the plain form."""
        if google:
            accounts = {f"owner{n}@example.com": {"refresh_token": MARKERS["google_refresh"] + str(n),
                                                  "scopes": ["https://www.googleapis.com/auth/drive"]}
                        for n in range(google)}
            saved = {"client_id": "9.apps.googleusercontent.com", "client_secret": MARKERS["google_secret"],
                     "accounts": accounts}
            if sealed:
                hub.google_store(saved)
            else:
                self.write_hub_file("google.json", json.dumps(saved))
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
                                     headers={"X-Fleet-Client": "founderizer-swift/1/test"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=10) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            with e:
                return e.code, dict(e.headers), e.read()

    def bundle(self, data):
        """hub.read_bundle of a copy's bytes, as a restore reads the file that it wrote: the records go to a file of
        this test, whose bytes the answer gives as `records`."""
        path, into = os.path.join(self.tmp.name, "read.zip"), os.path.join(self.tmp.name, "read.records")
        with open(path, "wb") as f:
            f.write(data)
        bundle = hub.read_bundle(path, into)
        with open(into, "rb") as f:
            return dict(bundle, records=f.read())

    def opened(self, records):
        """The records of a copy (the bytes of its member), opened as a restore opens them (hub.records_opened)."""
        fd, path = tempfile.mkstemp(dir=self.tmp.name)
        with os.fdopen(fd, "wb") as f:
            f.write(records)
        opening = hub.records_opened(path)
        conn = opening.__enter__()
        self.addCleanup(opening.__exit__, None, None, None)
        return conn

    def records_of(self, mib):
        """`mib` MiB more of records that do not pack: random bytes, in rows of 64 KiB."""
        hub.DB.execute("CREATE TABLE ballast(x BLOB)")
        for _ in range(mib * 16):
            hub.DB.execute("INSERT INTO ballast VALUES(?)", (os.urandom(64 * 1024),))
        hub.DB.commit()

    def download_in_pieces(self):
        """GET /ui/backup as the Mac app takes it: into a file, in pieces, with its SHA-256 read as it comes.
        (status, headers, bytes, SHA-256, the file)."""
        req = urllib.request.Request(self.base + "/ui/backup?db=test-generation",
                                     headers={"X-Fleet-Client": "founderizer-swift/1/test"})
        path, digest, size = os.path.join(self.tmp.name, "taken.zip"), hashlib.sha256(), 0
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=60) as r, \
                open(path, "wb") as f:
            for piece in iter(lambda: r.read(1 << 20), b""):
                digest.update(piece)
                size += len(piece)
                f.write(piece)
            return r.status, dict(r.headers), size, digest.hexdigest(), path

    @staticmethod
    def room(free, asked=None):
        """The disks of this Mac said to have `free` bytes for this user (os.statvfs), and each folder asked put in
        `asked`."""
        def statvfs(path):
            if asked is not None:
                asked.append(os.path.abspath(path))
            return os.statvfs_result((1, 1, 1 << 40, free, free, 0, 0, 0, 0, 255))
        return patch.object(os, "statvfs", statvfs)

    def copy_files(self):
        """The passing folders of a copy or of an upload beside the records (hub.copy_folder), once the copy that went
        out or came in has ended: none. The client reads the last byte before the hub's thread removes the folder and
        lets BACKUP_LOCK or RESTORE_LOCK go."""
        self.assertTrue(self.copy_ended(), "a copy's answer did not end")
        return sorted(name for name in os.listdir(os.path.dirname(self.path)) if name.startswith(hub.COPY_PART))

    @staticmethod
    def copy_ended(within=30):
        """True once no copy is in the making, on its way out or on its way back (BACKUP_LOCK and RESTORE_LOCK are
        free), within `within` seconds."""
        deadline = time.monotonic() + within
        while (hub.BACKUP_LOCK.locked() or hub.RESTORE_LOCK.locked()) and time.monotonic() < deadline:
            time.sleep(0.02)
        return not (hub.BACKUP_LOCK.locked() or hub.RESTORE_LOCK.locked())

    def send(self, data, query="", request_id=None, client="founderizer-swift/1/test"):
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
        the checkout, whose bare repository is on the same disk. The records are copied page by page, so each row
        keeps its row id: ui_requests is a table whose row id is a key, with no INTEGER PRIMARY KEY, and a copy made
        row by row (a dump, or VACUUM INTO, which SQLite's documentation lets renumber) gives a later row an id of an
        earlier one that was deleted."""
        self.work()
        for n in range(6):
            hub.q("INSERT INTO ui_requests(request_id,kind,event_id,created,client) VALUES(?,'message',?,1,'t')",
                  (f"request-{n}", n))
        hub.q("INSERT INTO ui_requests(rowid,request_id,kind,event_id,created,client) "
              "VALUES(-4,'request-below','message',9,1,'t')")          # some rows have a row id below 0
        hub.q("DELETE FROM ui_requests WHERE request_id IN ('request-0','request-1','request-2')")
        rows = [tuple(r) for r in hub.q("SELECT rowid, request_id FROM ui_requests ORDER BY rowid")]
        self.assertEqual([r[0] for r in rows], [-4, 4, 5, 6])
        code, headers, data = self.download()
        self.assertEqual(code, 200)
        self.assertEqual(headers["Content-Type"], "application/zip")
        self.assertEqual(headers["X-Fleet-Backup-SHA256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(int(headers["Content-Length"]), len(data))
        zf = zipfile.ZipFile(io.BytesIO(data))
        self.assertEqual(sorted(zf.namelist()),
                         ["RESTORE.md", "config/knowledge/owner/brand.md", "config/profiles/vps.md",
                          "config/team.json", "fleet.json", "fleet.sqlite3"])
        self.assertEqual(zf.read("config/profiles/vps.md").decode(), PROFILE)
        self.assertEqual(json.loads(zf.read("config/team.json")), OWNER)
        records = self.opened(zf.read("fleet.sqlite3"))
        self.assertEqual(records.execute("SELECT title FROM tasks").fetchone()[0], "Write the October report")
        self.assertEqual([tuple(r) for r in records.execute("SELECT rowid, request_id FROM ui_requests "
                                                            "ORDER BY rowid")], rows)

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

    def test_each_copy_that_the_hub_serves_is_one_that_a_restore_takes(self):
        """A restore unpacks at most RESTORE_UNPACK of a copy's files, takes at most BACKUP_ENTRIES_MAX entries and
        BACKUP_DIRECTORY_MAX of central directory, and reads at most BACKUP_MANIFEST_MAX of its fleet.json. Records of
        a raw image with secure_delete and no VACUUM pack 8:1 to 30:1, so a fleet could state more in a small copy, and
        the owner would learn it only at the restore, when the old machine is gone. So the backup refuses such a copy
        at once (413), with the limits of the restore, which refuses it too. And records of more than COPY_FORMAT_MAX
        bytes would need Zip64, which the Mac app does not read: refused with its code before anything is written,
        and no other size refuses a copy."""
        self.work()
        code, _headers, data = self.download()
        self.assertEqual(code, 200)
        package = zipfile.ZipFile(io.BytesIO(data))
        files = sum(entry["bytes"] for entry in json.loads(package.read("fleet.json"))["files"].values())
        self.bundle(data)
        for limit, value, words in (
                ("COPY_FORMAT_MAX", package.getinfo("fleet.sqlite3").file_size - 1,
                 r"^This fleet's records are larger than 2 GB\. Founderizer cannot put them into one copy yet\.$"),
                ("RESTORE_UNPACK", files // 2, r"^the copy holds [\d,]+ MiB of files, and a restore unpacks at most "
                                               r"[\d,]+ MiB$"),
                ("BACKUP_ENTRIES_MAX", len(package.infolist()) - 1,
                 r"^the copy holds more than [\d,]+ files, and a restore takes at most [\d,]+$"),
                ("BACKUP_DIRECTORY_MAX", hub.zip_directory_bytes(data) - 1,
                 r"^the copy's list of files is larger than \d+ MiB, and a restore reads at most \d+ MiB$"),
                ("BACKUP_MANIFEST_MAX", package.getinfo("fleet.json").file_size // 2,
                 r"^the copy's fleet.json is larger than \d+ MiB, and a restore reads at most \d+ MiB$")):
            with self.subTest(limit), patch.object(hub, limit, value):
                code, _headers, body = self.download()
                self.assertEqual(code, 413)
                self.assertRegex(json.loads(body)["error"], words)
                if limit == "COPY_FORMAT_MAX":
                    self.assertEqual(json.loads(body)["code"], "copy_over_format")
                    self.assertEqual(self.copy_files(), [])
                else:
                    with self.assertRaises(hub.Refusal):
                        self.bundle(data)
        self.assertEqual(self.copy_files(), [])

    @unittest.skipUnless(os.path.isdir(os.path.join(ROOT, "app")),
                         "the apps' folder app/ is not in this tree (the published repository has none)")
    def test_the_hub_takes_what_the_mac_app_takes_of_a_copy(self):
        """The Mac app reads a copy before it sends it to a restore (FleetRestore.swift), and refuses one of more
        entries or more bytes of central directory than its limits, or with a larger fleet.json. The hub's backup and
        restore have the same three limits, so that each copy that the hub serves is one that both restore: a limit
        that changed on one side alone would serve copies that the other refuses."""
        with open(os.path.join(ROOT, "app", "Sources", "FleetCore", "FleetRestore.swift"), encoding="utf-8") as f:
            source = f.read()
        found = {limit: re.findall(pattern, source) for limit, pattern in (
            ("BACKUP_ENTRIES_MAX", r"size != 0xFFFF_FFFF, count <= ([\d_]+),"),
            ("BACKUP_DIRECTORY_MAX", r"size <= (\d+ << \d+), offset \+ size <= total"),
            ("BACKUP_MANIFEST_MAX", r"FleetManifest\.manifestMember, in: file, limit: (\d+ << \d+)\)"))}
        for limit, values in found.items():
            self.assertEqual(len(values), 1, (limit, values))           # one place in the app's source says it
            first, _, shift = values[0].replace("_", "").partition(" << ")
            self.assertEqual(int(first) << int(shift or 0), getattr(hub, limit), limit)

    def test_the_hub_holds_its_lock_while_it_reads_a_copy_and_not_while_it_packs_it(self):
        """While LOCK is held the hub answers nobody, and the sums and the compression of a copy take seconds: 7.4
        for 358 MB of records (measured on 17 November 2026). So the route holds the lock for the reads only, which
        must be of one moment. And it makes and sends one copy at a time, under a lock of its own (BACKUP_LOCK): two
        requests at the same time hold two copies on the hub's disk.

        Where the records have a read connection (WAL mode, readers_for), that connection holds their moment, and the
        records' file is written from it with LOCK free: on this Mac the file of 420 MB of records took 1.1 s, where
        DB.serialize() under the lock took 0.26 s. A write that comes after the moment is not in the copy, which is
        then of one moment with its configuration. While it is made and sent it is a copy on its way, which holds an
        update's start (copies_going)."""
        calls, folders = [], []     # each call of the parts, in order: a second pack inside the lock is seen too

        def watched(name, then=None):
            real = getattr(hub, name)

            def call(*args):        # LOCK: of the thread that serves the request; BACKUP_LOCK: of this one request
                calls.append((name, hub.LOCK._is_owned(), hub.BACKUP_LOCK.locked(), args[0] is hub.DB) if
                             name == "records_file" else (name, hub.LOCK._is_owned(), hub.BACKUP_LOCK.locked()))
                if name == "records_file":      # a new folder of mode 700 beside the records, and of no other disk
                    folders.append((os.path.dirname(args[1]), os.stat(args[1]).st_mode & 0o777))
                if then:
                    then()
                return real(*args)
            return patch.object(hub, name, call)
        with watched("backup_read"), watched("backup_packed"), watched("records_file"):
            self.assertEqual(self.download()[0], 200)
        self.assertEqual(calls, [("backup_read", True, True), ("records_file", True, True, True),
                                 ("backup_packed", False, True)])
        self.assertTrue(self.copy_ended())
        self.assertEqual(hub.wal_on(), (True, None))
        hub.readers_for(self.path)
        self.addCleanup(hub.readers_for, None)
        calls.clear()
        later = lambda: hub.q("INSERT INTO notes(task,agent,ts,text) VALUES(1,'vps',2,'a write after the moment')")
        with watched("backup_read"), watched("backup_packed", then=later), watched("records_file"):
            code, _headers, data = self.download()
        self.assertEqual(code, 200)
        self.assertEqual(calls, [("backup_read", True, True), ("backup_packed", False, True),
                                 ("records_file", False, True, False)])
        self.assertEqual(hub.q1("SELECT count(*) n FROM notes WHERE text='a write after the moment'")["n"], 1)
        self.assertEqual(folders, [(os.path.dirname(self.path), 0o700)] * 2)
        going = []
        with watched("backup_packed", then=lambda: going.append(hub.copies_going())):
            self.assertEqual(self.download()[0], 200)
        self.assertEqual(going, [["a copy goes to the owner's computer"]])
        self.assertTrue(self.copy_ended())
        self.assertEqual(hub.copies_going(), [])
        records = self.opened(zipfile.ZipFile(io.BytesIO(data)).read("fleet.sqlite3"))
        self.assertEqual(records.execute("SELECT count(*) FROM notes WHERE text='a write after the moment'")
                         .fetchone()[0], 0)
        self.assertEqual(self.copy_files(), [])

    def test_a_copy_of_records_in_wal_mode_is_records_that_a_restore_opens(self):
        """The hub keeps its records in WAL mode since 11 November 2026 (hub.wal_on), and DB.serialize() copies the
        header of that mode, which SQLite opens from no image in memory: a restore refused such a copy as records that
        "cannot be opened". The copy has the header of rollback mode, and a restore reads it."""
        self.assertEqual(hub.wal_on(), (True, None))
        self.work()
        with open(self.path, "rb") as f:
            self.assertEqual(f.read(20)[18:20], b"\x02\x02")       # the hub's own records, in WAL mode
        code, _headers, data = self.download()
        self.assertEqual(code, 200)
        records = zipfile.ZipFile(io.BytesIO(data)).read("fleet.sqlite3")
        self.assertEqual(records[18:20], b"\x01\x01")
        self.assertEqual(self.bundle(data)["manifest"]["fleet_id"], hub.fleet_id())
        # the image itself, in memory, as a hub from before 22 November 2026 reads it where its Python can hold one
        if hasattr(sqlite3.Connection, "deserialize"):
            copy = sqlite3.connect(":memory:")
            self.addCleanup(copy.close)
            copy.deserialize(records)
            self.assertEqual(copy.execute("SELECT title FROM tasks").fetchone()[0], "Write the October report")

    def test_a_copy_made_after_text_was_cleared_does_not_hold_it(self):
        """A person's removal clears their words where they stand and deletes their messages (hub.person_remove), and
        SQLite leaves cleared text in the pages of its file unless secure_delete is on. A copy of the records has
        those pages as they are. So the hub turns the setting on at its start (hub.secure_delete_on), whatever its
        build of SQLite does by itself: a copy that the owner saves after a removal holds none of the removed words."""
        def copy_after_clearing(marker):
            ids = [hub.ins("INSERT INTO notes(task,agent,ts,text) VALUES(1,'vps',?,?)", (hub.now(), "x" * 300 + marker))
                   for _ in range(2)]
            hub.q("UPDATE notes SET text='cleared' WHERE id=?", (ids[0],))
            hub.q("DELETE FROM notes WHERE id=?", (ids[1],))
            code, _headers, data = self.download()
            self.assertEqual(code, 200)
            return zipfile.ZipFile(io.BytesIO(data)).read("fleet.sqlite3")
        hub.DB.execute("PRAGMA secure_delete=OFF")
        self.assertIn(b"Calle-Zafiro-7781", copy_after_clearing("Calle-Zafiro-7781"))      # SQLite, left to itself
        self.assertTrue(hub.secure_delete_on())
        self.assertNotIn(b"Calle-Zafiro-9431", copy_after_clearing("Calle-Zafiro-9431"))
        self.assertIn("secure_delete_on()", inspect.getsource(hub.main))    # each start of the hub turns it on

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
        self.assertEqual(self.bundle(buffer.getvalue())["records"], walled)
        # and its check wrote nothing beside them: no WAL and no shared memory file (hub.records_opened, immutable)
        self.assertEqual([name for name in os.listdir(self.tmp.name) if name.startswith("read.records")],
                         ["read.records"])

    def test_a_copy_goes_out_through_files_and_never_whole_in_memory(self):
        """The hub built a whole copy in its memory and sent it as one block, so it refused one of more than 256 MiB
        (the owner, 22 November 2026: "why is there a backup limit? it shouldn't?"), and the copy of 358 MB of records
        held 950 MB more. Now the records go to a file beside them, are packed as they are read, and the zip goes out
        in pieces: a copy of 24 MiB of records that do not pack is made and sent with a peak of Python's memory of a
        few MiB, to a client that reads it in pieces too, and the folder of its files is gone when the answer ends.
        The bug that it catches: a later change reads the records' file or the zip whole again."""
        self.work()
        self.records_of(24)
        tracemalloc.start()
        try:
            status, headers, size, digest, path = self.download_in_pieces()
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertEqual(status, 200)
        self.assertGreater(size, 24 << 20)
        self.assertEqual((int(headers["Content-Length"]), headers["X-Fleet-Backup-SHA256"]), (size, digest))
        self.assertLess(peak, 8 << 20)
        self.assertEqual(self.copy_files(), [])
        self.assertEqual(json.loads(hub.kv_get("backup_served"))["bytes"], size)
        bundle = hub.read_bundle(path, os.path.join(self.tmp.name, "read.records"))
        self.assertEqual(bundle["records_bytes"], json.loads(zipfile.ZipFile(path).read("fleet.json"))["files"]
                         ["fleet.sqlite3"]["bytes"])
        with hub.records_opened(bundle["records"]) as records:
            self.assertEqual(records.execute("SELECT count(*), sum(length(x)) FROM ballast").fetchone(),
                             (384, 24 << 20))

    def test_no_file_of_a_copy_stays_when_its_client_goes_or_its_hub_was_killed(self):
        """The owner's rule of 18 October 2026: no copy stays on a host. A client that goes in the middle of a copy
        ends its answer, its folder goes with it, and the next copy can start. A hub that was killed while it made or
        sent one leaves its folder, and the next start removes it before it takes its records; a file or a link of
        that name, and any other folder, stay where they are."""
        self.work()
        self.records_of(24)         # more than the two sides of a socket hold on this Mac, so the hub is still sending
        port = self.server.server_port
        with socket.create_connection(("127.0.0.1", port), timeout=30) as s:
            s.sendall(f"GET /ui/backup?db=test-generation HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                      f"X-Fleet-Client: founderizer-swift/1/test\r\n\r\n".encode())
            got = b""
            while len(got) < 1 << 16:
                piece = s.recv(1 << 16)
                self.assertTrue(piece, got[:200])
                got += piece
            self.assertTrue(got.startswith(b"HTTP/1.1 200 "), got[:200])
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))     # a reset: the client is gone
        self.assertEqual(self.copy_files(), [])
        self.assertEqual(self.download()[0], 200)
        # what a hub that was killed in the middle of a copy leaves, and what has a name like it and stays
        here = os.path.dirname(self.path)
        left = os.path.join(here, hub.COPY_PART + "k1ll3d")
        os.makedirs(left, mode=0o700)
        with open(os.path.join(left, hub.COPY_ZIP), "wb") as f:
            f.write(b"PK\x03\x04 half a copy")
        elsewhere = os.path.join(self.tmp.name, "elsewhere")
        os.makedirs(elsewhere)
        with open(os.path.join(elsewhere, "kept.txt"), "w") as f:
            f.write("not a copy")
        os.symlink(elsewhere, os.path.join(here, hub.COPY_PART + "link"))
        with open(os.path.join(here, hub.COPY_PART + "file"), "w") as f:
            f.write("not a folder")
        os.makedirs(os.path.join(here, "founderizer-records-x"))
        self.assertEqual(hub.copy_leftovers_gone(self.path), 1)
        self.assertEqual(self.copy_files(), [hub.COPY_PART + "file", hub.COPY_PART + "link"])
        self.assertTrue(os.path.exists(os.path.join(elsewhere, "kept.txt")))
        self.assertTrue(os.path.isdir(os.path.join(here, "founderizer-records-x")))
        source = inspect.getsource(hub.main)        # each start, after it holds the records and before it takes them
        self.assertLess(source.index("hub_lock(db_path)"), source.index("copy_leftovers_gone(db_path)"))
        self.assertLess(source.index("copy_leftovers_gone(db_path)"), source.index("take_restore(db_path)"))

    def test_a_copy_that_the_hub_s_disk_has_no_room_for_is_refused_before_anything_is_written(self):
        """A copy takes up to two times the records on the hub's disk for a moment, and a full disk stops the hub
        itself, so 256 MiB stay free beside the copy's files. With less room than that on the disk of the records, the
        hub refuses with its code, says the sizes as the Mac app writes them, writes nothing and records no copy as
        served. And with that room it makes the copy, also on a disk with less than DISK_LOW free: the copy was made in
        memory before, with no room on the disk at all, so a reserve of 2 GiB took the daily copy from a hub whose disk
        is nearly full. The bugs that it catches: a copy that fills the hub's disk; a copy refused on a disk that has
        room for it; words that say a copy needs 2 GiB more than it does; words near the bound that say that the disk
        has what the copy needs (free rounded down, need rounded up: the validator's finding W1)."""
        self.work()
        records = hub.q1("PRAGMA page_count")[0] * hub.q1("PRAGMA page_size")[0]
        need, asked = 2 * records + (256 << 20), []      # the copy's two files and its own reserve
        room = functools.partial(self.room, asked=asked)
        with room(need - 1):
            code, _headers, body = self.download()
        self.assertEqual(code, 507)
        self.assertEqual(json.loads(body), {
            "code": "copy_no_room",
            "names": {"free": hub.size_words(need - 1, "down"), "need": hub.size_words(need, "up")},
            "error": f"The hub's server has {hub.size_words(need - 1, 'down')} free. A copy needs "
                     f"{hub.size_words(need, 'up')} there while the hub makes it."})
        self.assertLess(need, 300 << 20)                # some 256 MB for these small records, never 2 GB and more
        self.assertEqual(asked, [os.path.dirname(self.path)])
        self.assertEqual(self.copy_files(), [])
        self.assertIsNone(hub.kv_get("backup_served"))
        with room(need):
            self.assertEqual(self.download()[0], 200)
        with room(int(1.2 * (1 << 30))):                # room for the copy, and less than DISK_LOW: the copy is made
            self.assertLess(int(1.2 * (1 << 30)), hub.DISK_LOW)
            self.assertEqual(self.download()[0], 200)
        self.assertEqual(self.copy_files(), [])
        bound = int(1.13 * (1 << 30))                   # a copy that needs some 1.1 GB, and 1 MiB less free
        with patch.object(hub, "COPY_RESERVE", bound - 2 * records), room(bound - (1 << 20)):
            code, _headers, body = self.download()
        self.assertEqual((code, json.loads(body)["names"]), (507, {"free": "1.1 GB", "need": "1.2 GB"}))

    def test_the_end_record_is_found_as_far_as_python_3_10_finds_it(self):
        """zipfile of Python 3.10 and 3.11 (Ubuntu 22.04's, Debian 12's) looks for a ZIP's end record in its last 65,536
        bytes and 22, one more than 3.12 and later, which refuse a record that stands there. The hub reads a copy's
        directory before zipfile does (zip_end_record, zip_file_shape), so it looks as far as that zipfile: else a copy
        whose end record stands 65,558 bytes from its end reads as no ZIP here, and zipfile of 3.10 then reads its
        directory of 5 MiB whole. The value of the hub's own function is checked, because this Python's zipfile refuses
        such a file by itself (a finding of Fable's read of 22 November 2026). The bug that it catches: a search that
        stops one byte short."""
        data = many_entries(15_000, comment=300) + bytes(1 << 16)
        end = len(data) - (1 << 16) - 22
        stated = struct.unpack_from("<I", data, end + 12)[0]
        self.assertEqual(data[end:end + 4], b"PK\x05\x06")
        self.assertGreater(stated, hub.BACKUP_DIRECTORY_MAX)
        self.assertEqual(hub.zip_end_record(data), (end, stated))
        self.assertEqual(hub.zip_directory_bytes(data), stated)
        self.assertEqual(hub.zip_file_shape(io.BytesIO(data)), (0, stated))     # refused before zipfile reads it

    def test_no_copy_is_asked_for_inside_a_write(self):
        """SQLite's backup answers "busy" to a source that is in a write, and Python asks it again for ever."""
        folder = tempfile.mkdtemp(dir=self.tmp.name)
        with hub.transaction():
            hub.DB.execute("INSERT OR REPLACE INTO kv(k,v) VALUES('a write','that waits')")
            with self.assertRaisesRegex(RuntimeError, "outside a transaction"):
                hub.records_file(hub.DB, folder)
        self.assertEqual(os.listdir(folder), [])


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

    def test_a_sealed_google_file_is_counted_and_neither_its_key_nor_its_tokens_reach_the_copy(self):
        """Since 1.202 the Google file is sealed, and its key is in a file of its own outside `~/.fleet`. The copy
        counts the accounts as before, through the hub's own reader, and carries neither the key nor anything that
        the file holds: a copy and a key would open the file of a disk that somebody kept."""
        self.work()
        self.hub_that_has_been_used(google=2, mcp=0, attachments=0, sealed=True)
        with open(os.path.join(self.fleet_home, "google.json"), "rb") as f:
            self.assertNotIn(MARKERS["google_refresh"].encode(), f.read())
        self.assertEqual(self.manifest()["hub_only"]["google"],
                         {"present": True, "accounts": 2, "client": True, "sealed": True, "vault": False})
        notes = self.notes()
        self.assertIn("the 2 Google accounts you connected", notes)
        self.assertIn("It is sealed with the key in `~/.config/founderizer/google-file.key` on the same machine, which "
                      "this copy does not hold either: the file is of no use without it.", " ".join(notes.split()))
        with open(self.google_key, encoding="ascii") as f:
            key = f.read().strip()
        data = self.download()[2]
        zf = zipfile.ZipFile(io.BytesIO(data))
        for body in [data] + [zf.read(name) for name in zf.namelist()]:
            for value in (key, key.upper(), MARKERS["google_refresh"], MARKERS["google_secret"]):
                self.assertNotIn(value.encode(), body)
            self.assertNotIn(bytes.fromhex(key), body)
        # A copy taken while the key cannot be read counts the file as there, and claims no number.
        os.chmod(self.google_key, 0o644)
        hub.GOOGLE_OPENED.update(last=None, key=None)
        self.assertEqual(self.manifest()["hub_only"]["google"], {"present": True, "sealed": True, "vault": False})
        self.assertIn("holds the Google accounts you connected.", self.notes())
        # Sealed with the central vault's key: the copy says that the vault keeps it, and a plain file has no key.
        os.chmod(self.google_key, 0o600)
        hub.GOOGLE_OPENED["vault"] = bytes(32)
        hub.google_store(hub.google_saved()[0])
        self.assertEqual(self.manifest()["hub_only"]["google"],
                         {"present": True, "accounts": 2, "client": True, "sealed": True, "vault": True})
        self.assertIn("It is sealed with a key that the hub's central vault keeps, which this copy does not hold "
                      "either: the file is of no use without it.", " ".join(self.notes().split()))
        self.hub_that_has_been_used(google=2, mcp=0, attachments=0)         # plain, as a hub from before wrote it
        self.assertNotIn("sealed", self.manifest()["hub_only"]["google"])
        self.assertNotIn("It is sealed", self.notes())

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
        # and where he goes for it, as whole links, also to the Apps of an organization (until 21 November 2026 the
        # step said "github.com/settings/apps", a personal account's page with no https://)
        self.assertIn("make a new one on your App's page on GitHub: https://github.com/settings/apps lists the Apps of "
                      "your own account, and https://github.com/organizations/YOUR-ORGANIZATION/settings/apps, with "
                      "your organization's name in it, those of an organization.", " ".join(notes.split()))
        self.assertIn("https://github.com/organizations/YOUR-ORGANIZATION/settings/apps", notes)    # whole on its line
        self.assertIn("1. **Founderizer for Mac is at https://founderizer.com.**", notes)
        steps = notes[notes.index("## Putting it back"):]
        self.assertLess(steps.index("GitHub App key back"), steps.index("Connect Google again"), steps)
        self.assertIn("6. **Put a GitHub App key back.**", steps)
        # the places the apps have now (D-4): MCP servers are a group of Settings › Apps, and Restore is under Backup
        self.assertIn("in the app under Settings › Apps, MCP servers", steps)
        self.assertIn("**Restore copy**, in the app under Settings › Backup, and give it this file.", steps)
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
        # A client alone is nothing to put back since owner API 1.185: a new hub connects with Founderizer's own
        # Google client (its release brings the ID, founderizer.com the secret), so no step sends him to find a client
        # file. With the empty mcp.json, this hub had nothing at all to put back.
        self.assertIn("**Nothing else.**", notes)
        self.assertNotIn("client file", notes)
        self.assertNotIn("Connect Google again", notes)

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
        proc = subprocess.Popen([sys.executable, "-m", "hub", "--host", "127.0.0.1",
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
        # The fleet that was saved has Founderizer for Teams. Its licence is a bearer for our own services and comes
        # with the copy, so the restore brings Teams back with no claim (teams-design-1-shop-and-licence.md, 3.15).
        # The bug: a later change takes the token out of the copy "because it is a credential", and each restore of
        # a paying fleet then loses Teams with no word.
        seed = bytes(range(96, 128))
        licence = releases.sign_entitlement(seed, {"fleet": hub.fleet_id(), "plan": "teams", "until": 2000000000,
                                                   "machines": 0, "agents": 7})
        with patch.object(hub, "entitlement_keys", return_value=(releases.public_key(seed),)):
            hub.store_entitlement(licence)
        self.assertTrue(hub.teams_on())
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
        hub.DB.close()
        hub.DB = sqlite3.connect(self.path, check_same_thread=False)     # the records of the hub that took the copy
        hub.DB.row_factory = sqlite3.Row
        self.assertEqual((hub.teams_on(), hub.teams_licence()), (True, licence))

    def test_a_new_machine_keeps_the_keys_of_its_own_server(self):
        """The copy's records name the key of the server service of the hub that is gone, the agent key that its
        manager had there, and the vault key of the broker that ran there. The new machine has its own key files and
        its own broker, and its installer and its manager's helper wrote their records before the restore. The start
        that takes the copy keeps those records of its own server, so the hub knows its server's service and its
        manager afterwards, and a worker that ran on the lost hub's server gets its vault from this machine's broker.
        The key of an agent on another server comes with the copy, as before."""
        gone = {"server": "a" * 64, "manager": "b" * 64, "vps": "c" * 64, "store": "age1" + "g" * 58}
        team = json.loads(json.dumps(OWNER))        # the fleet that was saved: one worker ran on its hub's server
        team["agents"]["scout"] = {"role": "worker", "runtime": "codex", "machine": "hub", "can": ["shell"],
                                   "vault": "broker", "vault_recipient": gone["store"]}
        team["vault_stores"] = {"hub": gone["store"]}
        with open(os.path.join(self.kit, "team.json"), "w", encoding="utf-8") as f:
            json.dump(team, f, indent=2)
        git("commit", "-q", "-am", "the owner gave scout the vault of the hub's server", cwd=self.kit)
        git("push", "-q", "origin", "HEAD", cwd=self.kit)
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = team
        hub.q("INSERT INTO server_keys(server,sha256,created) VALUES('hub',?,1)", (gone["server"],))
        hub.q("INSERT INTO server_status(server,data,reported) VALUES('hub',?,1)", (json.dumps({"os": {"name": "x"}}),))
        hub.q("INSERT INTO first_stores(machine, key, at, closed) VALUES('hub',?,1,2)", (gone["store"],))
        hub.kv_set("default_vault:scout", 1)        # the hub gave scout its vault there, and that default ended
        for agent in ("manager", "vps"):
            hub.q("INSERT INTO agent_keys(agent,sha256,created,source) VALUES(?,?,1,'enrolled')", (agent, gone[agent]))
        _fleet, data = self.copy_of_a_fleet()
        self.new_machine()
        here = {"server": "d" * 64, "manager": "e" * 64, "store": "age1" + "h" * 58}
        hub.q("INSERT INTO server_keys(server,sha256,created) VALUES('hub',?,5)", (here["server"],))
        hub.q("INSERT INTO agent_keys(agent,sha256,created,source) VALUES('manager',?,6,'enrolled')", (here["manager"],))
        hub.q("INSERT INTO server_status(server,data,reported) VALUES('hub',?,7)", ('{"os": {"name": "this machine"}}',))
        hub.q("INSERT INTO first_stores(machine, key, at) VALUES('hub',?,8)", (here["store"],))
        code, answer = self.send(data)
        self.assertEqual(code, 200, answer)
        with open(self.path + hub.OWN_SUFFIX, encoding="utf-8") as f:
            own = json.load(f)
        self.assertRegex(own.pop("id"), "^[0-9a-f]{32}$")
        self.assertEqual(own, {"machine": "hub", "server": {"sha256": here["server"], "created": 5.0},
                               "reading": {"data": '{"os": {"name": "this machine"}}', "reported": 7.0},
                               "agents": {"manager": {"sha256": here["manager"], "created": 6.0, "source": "enrolled"}},
                               "first_store": {"key": here["store"], "at": 8.0, "closed": None},
                               "vault_reset": ["scout"]})
        with open(self.path + hub.RESTORE_SUFFIX + ".json", encoding="utf-8") as f:
            self.assertNotIn("own", json.load(f))
        self.assertEqual(os.stat(self.path + hub.OWN_SUFFIX).st_mode & 0o777, 0o600)
        # the copy's team stands on this machine with no pin of the broker that is gone, and scout at no vault
        restored = json.loads(read(self.kit, "team.json"))
        self.assertNotIn("vault_stores", restored)
        self.assertEqual((restored["agents"]["scout"]["vault"], "vault_recipient" in restored["agents"]["scout"]),
                         ("none", False))
        self.assertEqual(restored["agents"]["vps"]["vault_recipient"], OWNER["agents"]["vps"]["vault_recipient"])
        proc, _base = self.start_real_hub()
        for suffix in (hub.OWN_SUFFIX, hub.OWN_TAKEN):                # put back, and gone
            self.assertFalse(os.path.exists(self.path + suffix), suffix)
        opened = self.records()
        self.assertEqual([tuple(r) for r in opened.execute("SELECT server, sha256, created FROM server_keys")],
                         [("hub", here["server"], 5.0)])
        self.assertEqual([tuple(r) for r in opened.execute("SELECT data, reported FROM server_status WHERE server='hub'")],
                         [('{"os": {"name": "this machine"}}', 7.0)])        # this machine's reading, not the copy's
        self.assertEqual({r["agent"]: r["sha256"] for r in opened.execute("SELECT agent, sha256 FROM agent_keys")},
                         {"manager": here["manager"], "vps": gone["vps"]})
        self.assertEqual([tuple(r) for r in opened.execute("SELECT key, at, closed FROM first_stores WHERE machine='hub'")],
                         [(here["store"], 8.0, None)])
        kv = dict(opened.execute("SELECT k,v FROM kv").fetchall())
        self.assertNotIn("default_vault:scout", kv)
        self.assertEqual(len(kv["restore_own"]), 32)
        said = [r[0] for r in opened.execute("SELECT what FROM log WHERE what LIKE 'after the copy,%'")]
        self.assertEqual(said, ["after the copy, the server service of hub is this machine's own again; manager on "
                                "hub has the agent key of this machine again; the first vault key of hub is this "
                                "machine's own again; scout on hub gets its vault again when this machine's vault "
                                "has reported"])
        proc.terminate()
        proc.wait(timeout=20)

    def test_a_start_that_stopped_before_its_own_records_were_back_puts_them_back_at_the_next_start(self):
        """The copy's move into place and the step that puts this machine's own records back are two steps of one
        start. A hub that stops between them (a kill, a power cut) has the copy's records and no staged copy. The
        file with this machine's records has the name of a copy that was taken by then, so the next start reads it,
        whether it took a copy or not. The file of a copy that still waits, or that no start took, is never read: its
        records can be older than what this hub wrote since. A file is read once, also when it could not be
        removed. A file that cannot be read stops no start: the hub says so and keeps it."""
        hub.q("INSERT INTO server_keys(server,sha256,created) VALUES('hub',?,1)", ("a" * 64,))      # the copy's row
        own = {"id": "1" * 32, "machine": "hub", "server": {"sha256": "d" * 64, "created": 5.0}, "reading": None,
               "agents": {}, "first_store": None, "vault_reset": []}
        with open(self.path + hub.OWN_SUFFIX, "w", encoding="utf-8") as f:      # of a copy that no start took
            json.dump(own, f)
        self.assertIsNone(hub.restored_own(self.path))
        self.assertEqual(hub.q1("SELECT sha256 FROM server_keys WHERE server='hub'")["sha256"], "a" * 64)
        self.assertTrue(os.path.exists(self.path + hub.OWN_SUFFIX))
        os.replace(self.path + hub.OWN_SUFFIX, self.path + hub.OWN_TAKEN)       # as take_restore names it
        self.assertEqual(hub.restored_own(self.path),
                         "after the copy, the server service of hub is this machine's own again")
        self.assertEqual(hub.q1("SELECT sha256 FROM server_keys WHERE server='hub'")["sha256"], "d" * 64)
        self.assertFalse(os.path.exists(self.path + hub.OWN_TAKEN))
        self.assertIsNone(hub.restored_own(self.path))              # each later start: no file, nothing to do
        # the same file once more, as after a removal that failed: the owner changed the key since, and it stays
        hub.q("UPDATE server_keys SET sha256=? WHERE server='hub'", ("f" * 64,))
        with open(self.path + hub.OWN_TAKEN, "w", encoding="utf-8") as f:
            json.dump(own, f)
        self.assertIsNone(hub.restored_own(self.path))
        self.assertEqual(hub.q1("SELECT sha256 FROM server_keys WHERE server='hub'")["sha256"], "f" * 64)
        self.assertFalse(os.path.exists(self.path + hub.OWN_TAKEN))
        for broken in ("not json", json.dumps({"id": "2" * 32, "machine": "hub", "server": {"created": 5.0}})):
            with open(self.path + hub.OWN_TAKEN, "w", encoding="utf-8") as f:
                f.write(broken)
            said = hub.restored_own(self.path)
            self.assertIn("could not be put back", said)
            self.assertIn("stays for the next start", said)
            self.assertTrue(os.path.exists(self.path + hub.OWN_TAKEN))
        # and a real start, which took no copy, reads the file that the stopped start left
        with open(self.path + hub.OWN_TAKEN, "w", encoding="utf-8") as f:
            json.dump(dict(own, id="3" * 32), f)
        proc, _base = self.start_real_hub()
        opened = self.records()
        self.assertEqual(opened.execute("SELECT sha256 FROM server_keys WHERE server='hub'").fetchone()[0], "d" * 64)
        self.assertFalse(os.path.exists(self.path + hub.OWN_TAKEN))
        self.assertEqual([r[0] for r in opened.execute("SELECT what FROM log WHERE what LIKE 'after the copy,%'")],
                         ["after the copy, the server service of hub is this machine's own again"])
        proc.terminate()
        proc.wait(timeout=20)

    def test_the_vault_store_of_the_hubs_own_server_is_this_machines_after_a_copy(self):
        """A copy pins the vault key of the broker that ran on its own hub's server. On another machine that broker
        is gone, and the pin would refuse this machine's broker for ever. So the copy's team reaches this hub with
        this hub's own pin for its own server, or with none: then the agents of that server are back at no vault,
        and the hub gives each its vault again when this machine's broker has reported. The pin of each other
        machine is the copy's, as before."""
        gone, here, other = "age1" + "g" * 58, "age1" + "h" * 58, "age1" + "q" * 58
        copy = json.loads(json.dumps(OWNER))
        copy["agents"]["scout"] = {"role": "worker", "runtime": "codex", "machine": "hub", "can": ["shell"],
                                   "vault": "broker", "vault_recipient": gone}
        copy["vault_stores"] = {"hub": gone, "vps": other}
        bundle = {"config": {"team.json": json.dumps(copy).encode()}}
        reset = []
        team = json.loads(hub.restored_team(bundle, reset))        # this hub has no pin for its own server
        self.assertEqual((team["vault_stores"], reset), ({"vps": other}, ["scout"]))
        # the step of the fleet's servers is the owner's choice and comes with the copy; the hub's block is this hub's
        stepped = dict(copy, shape={"step": "one"}, hub=dict(copy["hub"], shared=True))
        team = json.loads(hub.restored_team({"config": {"team.json": json.dumps(stepped).encode()}}, []))
        self.assertEqual((team["shape"], team["hub"]), ({"step": "one"}, hub.TEAM["hub"]))
        self.assertEqual((team["agents"]["scout"]["vault"], "vault_recipient" in team["agents"]["scout"]), ("none", False))
        self.assertEqual((team["agents"]["vps"]["vault"], team["agents"]["vps"]["vault_recipient"]), ("broker", other))
        hub.TEAM["vault_stores"] = {"hub": here}                    # this hub pinned its own server's broker
        reset = []
        team = json.loads(hub.restored_team(bundle, reset))
        self.assertEqual((team["vault_stores"], reset), ({"vps": other, "hub": here}, []))
        self.assertEqual((team["agents"]["scout"]["vault"], team["agents"]["scout"]["vault_recipient"]), ("broker", here))
        hub.TEAM["vault_stores"] = {"hub": gone}                    # the machine that the copy came from: no change
        reset = []
        self.assertEqual(json.loads(hub.restored_team(bundle, reset))["vault_stores"], {"hub": gone, "vps": other})
        self.assertEqual(reset, [])
        del hub.TEAM["vault_stores"]
        # A manager's vault is set at its installation, and nothing gives it one again: where the manager holds a
        # broker vault on the hub's own server and this hub has no pin, the copy's pin stays, as before.
        managed = json.loads(json.dumps(copy))
        managed["agents"]["manager"].update(vault="broker", vault_recipient=gone)
        reset = []
        team = json.loads(hub.restored_team({"config": {"team.json": json.dumps(managed).encode()}}, reset))
        self.assertEqual((team["vault_stores"], reset, team["agents"]["manager"]["vault_recipient"],
                          team["agents"]["scout"]["vault"]), ({"hub": gone, "vps": other}, [], gone, "broker"))
        # the start after such a copy: the mark of a default that ended and the first key of the machine that is
        # gone both go, so this machine's broker gets its first pin as on a new server
        hub.kv_set("default_vault:scout", 1)
        hub.q("INSERT INTO first_stores(machine, key, at, closed) VALUES('hub',?,1,2)", (gone,))
        said = hub.keep_own_server_records({"machine": "hub", "server": None, "reading": None, "agents": {},
                                            "first_store": None, "vault_reset": ["scout"]})
        self.assertEqual(said, "after the copy, the copy's first vault key of hub went: it was of another machine; "
                               "scout on hub gets its vault again when this machine's vault has reported")
        self.assertIsNone(hub.kv_get("default_vault:scout"))
        self.assertIsNone(hub.first_store("hub"))
        kept = {"key": here, "at": 3.0, "closed": None}
        hub.keep_own_server_records({"machine": "hub", "server": None, "reading": None, "agents": {},
                                     "first_store": kept, "vault_reset": []})
        self.assertEqual(dict(hub.q1("SELECT key, at, closed FROM first_stores WHERE machine='hub'")), kept)

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
        # the records were unpacked before the team was read, and they go with the refusal (stage_restore)
        self.assertFalse(os.path.exists(self.path + hub.RESTORE_SUFFIX + ".part"))
        self.assertEqual(self.copy_files(), [])
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

    def send_file(self, path, request_id=None):
        """POST /ui/restore with the copy at `path` as the body, sent from the file in pieces, as the Mac app sends it."""
        with open(path, "rb") as body:
            req = urllib.request.Request(self.base + "/ui/restore?db=test-generation", data=body, method="POST",
                                         headers={"Content-Type": "application/zip",
                                                  "Content-Length": str(os.path.getsize(path)),
                                                  "X-Fleet-Client": "founderizer-swift/1/test",
                                                  "X-Fleet-Request-Id": request_id or str(uuid.uuid4())})
            try:
                with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=60) as r:
                    return r.status, json.load(r)
            except urllib.error.HTTPError as e:
                with e:
                    return e.code, json.load(e)

    def test_a_copy_goes_back_through_files_and_never_whole_in_memory(self):
        """A copy that the hub can make, the hub can take back: a copy that cannot go back is no copy. The restore read
        its whole body into memory and unpacked the records there, and refused a body of more than 256 MiB. Now the body
        goes to a file in pieces with its SHA-256, and the records are unpacked from it into the staged file in pieces:
        a copy of 24 MiB of records that do not pack goes back with a peak of Python's memory of a few MiB, and the
        fleet that starts on it is the fleet that was saved. A disk with no room for the body and 256 MiB besides refuses
        it, with the sizes, and writes nothing, and its words say "at least": the records come beside the body, and the
        head does not know their size (the hub-side second reader's note 2); so does a disk with room for the body and not for the files that the
        copy states, before it unpacks one; a disk with room for the copy and less than DISK_LOW takes it back, as it
        did when the hub needed no room for it. The bugs that it catches: a later change reads the body or the records
        whole again; a restore refused on a disk that has room for it, with words that say 2 GiB more than it needs; a
        copy that unpacks more than the disk holds."""
        self.work()
        self.records_of(24)
        fleet = hub.fleet_id()
        status, _headers, size, _digest, path = self.download_in_pieces()
        self.assertEqual(status, 200)
        self.new_machine()
        need = size + (256 << 20)          # the body, and the reserve that stays free
        with self.room(need - 1):
            code, answer = self.send_file(path)
        self.assertEqual((code, answer["code"]), (507, "restore_no_room"), answer)
        self.assertEqual(answer["error"], f"The hub's server has {hub.size_words(need - 1, 'down')} free. "
                                          f"This copy needs at least {hub.size_words(need, 'up')} there.")
        bound = int(1.13 * (1 << 30))                   # a restore that needs some 1.1 GB, and 1 MiB less free
        with self.room(bound - (1 << 20)), self.assertRaises(hub.Refusal) as near:
            hub.restore_room(os.path.dirname(self.path), bound - (256 << 20))
        self.assertEqual(near.exception.extra["names"], {"free": "1.1 GB", "need": "1.2 GB"})
        self.assertEqual((self.copy_files(), os.path.exists(self.path + hub.RESTORE_SUFFIX + ".part")), ([], False))
        with zipfile.ZipFile(path) as old:              # the same copy, which states its records as 1 GiB
            members = {name: old.read(name) for name in old.namelist()}
        manifest = json.loads(members["fleet.json"])
        manifest["files"]["fleet.sqlite3"]["bytes"] = 1 << 30
        members["fleet.json"] = json.dumps(manifest).encode()
        stated = os.path.join(self.tmp.name, "stated.zip")
        with zipfile.ZipFile(stated, "w", zipfile.ZIP_STORED) as zf:
            for name, body in members.items():
                zf.writestr(name, body)
        del members
        files = sum(says["bytes"] for says in manifest["files"].values()) + (256 << 20)
        with self.room(os.path.getsize(stated) + (256 << 20)):      # room for the body, not for what it states
            code, answer = self.send_file(stated)
        self.assertEqual((code, answer.get("names")), (507, {"free": hub.size_words(os.path.getsize(stated) +
                                                                                    (256 << 20), "down"),
                                                             "need": hub.size_words(files, "up")}), answer)
        self.assertEqual((self.copy_files(), os.path.exists(self.path + hub.RESTORE_SUFFIX + ".part")), ([], False))
        tracemalloc.start()
        try:
            with self.room(int(1.2 * (1 << 30))):       # room for the copy, and less than DISK_LOW: it goes back
                code, answer = self.send_file(path)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLess(int(1.2 * (1 << 30)), hub.DISK_LOW)
        self.assertEqual(code, 200, answer)
        self.assertEqual(answer["fleet_id"], fleet)
        self.assertGreater(answer["records_bytes"], 24 << 20)
        self.assertLess(peak, 8 << 20)
        self.assertEqual(self.copy_files(), [])
        self.assertEqual(os.path.getsize(self.path + hub.RESTORE_SUFFIX), answer["records_bytes"])
        proc, _base = self.start_real_hub()
        self.assertEqual(tuple(self.records().execute("SELECT count(*), sum(length(x)) FROM ballast").fetchone()),
                         (384, 24 << 20))
        proc.terminate()
        proc.wait(timeout=20)

    def test_a_restore_unpacks_its_records_with_the_hub_s_lock_free(self):
        """The unpack of a copy's records (up to 2 GiB), its fsync and SQLite's check of them ran under kit_lock, KIT and
        LOCK: each route, the tick and each agent's call waited for them, for minutes on a slow disk. They hold
        RESTORE_LOCK only now, and the swap is the same: the answer, the staged records, the fleet that the copy holds.
        A reader of LOCK gets in while the records are unpacked. And work that comes during the unpack is still seen:
        a hub that holds a fleet's work by the end of it refuses the restore (409, without replace=yes) and stages
        nothing. The bugs that it catches: an unpack that holds the hub's LOCK again (the hub-side second reader's
        note 1, 22 November 2026), and a restore that puts another fleet over work that came while it unpacked."""
        fleet, data = self.copy_of_a_fleet()
        self.new_machine()
        got, real, going = [], hub.records_unpacked, []

        def unpacked(*args, **kwargs):                  # another thread asks for LOCK while the records are unpacked
            going.append(hub.copies_going())            # a copy on its way: an update waits for it

            def read():
                if hub.LOCK.acquire(timeout=3):
                    hub.LOCK.release()
                    got.append(True)
                else:
                    got.append(False)
            reader = threading.Thread(target=read)
            reader.start()
            reader.join()
            return real(*args, **kwargs)
        with patch.object(hub, "records_unpacked", unpacked):
            code, answer = self.send(data)
        self.assertEqual((code, answer.get("fleet_id")), (200, fleet), answer)
        self.assertEqual(got, [True], "LOCK was held while the records were unpacked")
        self.assertEqual(going, [["a copy comes back from the owner's computer"]])
        self.assertTrue(os.path.exists(self.path + hub.RESTORE_SUFFIX))
        self.assertFalse(os.path.exists(self.path + hub.RESTORE_SUFFIX + ".part"))
        self.assertEqual(self.copy_files(), [])
        staged = os.stat(self.path + hub.RESTORE_SUFFIX).st_ino

        def meanwhile(*args, **kwargs):                 # a task comes while the second copy is unpacked
            hub.q("INSERT INTO tasks(id,title,owner,requester,state,created,done_when) "
                  "VALUES(9,'A task of this hub','manager','manager','open',1,'done')")
            return real(*args, **kwargs)
        with patch.object(hub, "records_unpacked", meanwhile):
            code, answer = self.send(data)
        self.assertEqual(code, 409, answer)
        self.assertIn("already holds a fleet's work", answer["error"])
        self.assertEqual(os.stat(self.path + hub.RESTORE_SUFFIX).st_ino, staged)    # the first copy's, untouched
        self.assertFalse(os.path.exists(self.path + hub.RESTORE_SUFFIX + ".part"))
        self.assertEqual((self.copy_files(), hub.q1("SELECT count(*) n FROM ui_controls")["n"]), ([], 1))

    def test_a_write_of_the_fleet_s_files_during_the_unpack_waits_and_lands_after_the_restore(self):
        """The unpack holds KIT, the turn of the writes of the fleet's files, and not LOCK. So an agent's knowledge that
        comes meanwhile (write_knowledge, which commits in its turn) waits for the restore and lands after it: the
        restore is not refused, and the copy undoes nothing that came during its unpack. A writer that holds LOCK alone,
        which never waits for KIT, is refused meanwhile, as while an owner's write runs its git, with words that say
        why and that it takes minutes (KIT_BUSY_RESTORE, R4-2). The bugs that it catches: a restore refused for an
        agent's note (the hub-side second reader's R3-1, 22 November 2026), a copy that undoes a write that came during
        its unpack (round 2, R2-4), and "try again in a few seconds" during an unpack of minutes."""
        _fleet, data = self.copy_of_a_fleet()
        self.new_machine()
        real, seen, writers, note = hub.records_unpacked, {}, [], "An agent's note, written during the unpack.\n"

        def knowledge():            # an agent's write_knowledge, from a thread that holds no lock
            hub.commit_kit_file("knowledge/during.md", note.encode(), "manager wrote a note", author="manager",
                                allow=hub.KNOWLEDGE_WRITE)

        def under_lock():           # a write of the hub's own that holds LOCK alone
            try:
                with hub.LOCK:
                    hub.commit_kit_file("knowledge/owner/brand.md", b"# Brand\n\nChanged.\n", "the hub's own write")
                seen["under LOCK"] = "written"
            except hub.KitFault as e:
                seen["under LOCK"] = str(e)

        def meanwhile(*args, **kwargs):
            writers.append(threading.Thread(target=knowledge))
            writers[0].start()
            writers[0].join(1)
            seen["the note waits"] = writers[0].is_alive()
            other = threading.Thread(target=under_lock)
            other.start()
            other.join(10)
            return real(*args, **kwargs)
        with patch.object(hub, "records_unpacked", meanwhile):
            code, answer = self.send(data)
        writers[0].join(30)
        self.assertEqual(code, 200, answer)
        self.assertEqual(seen, {"the note waits": True, "under LOCK": hub.KIT_BUSY_RESTORE})     # its own words
        self.assertEqual(read(self.kit, "knowledge", "during.md"), note)      # after the restore, and kept
        self.assertNotIn("knowledge/during.md", answer["files"] + answer["removed"])

    def test_no_write_of_the_hub_s_own_comes_between_the_unpack_and_the_staging(self):
        """The flight of a restore (kit_flying) refuses a writer that holds LOCK alone until the staging holds LOCK:
        between the end of the unpack and that moment, a tick's pass would commit a file of the fleet's, and the copy
        would then go over it with no word. Here such a writer comes at the staging's turn, before it holds LOCK, and
        is refused with the restore's own words. The bug that it catches: a flight that ends before the staging holds
        LOCK (the second validator's H-3, 22 November 2026)."""
        _fleet, data = self.copy_of_a_fleet()
        self.new_machine()
        real, turns, seen = hub.kit_lock, [], []

        def under_lock():           # a tick's pass that commits, as a team plan or a machine's name does
            try:
                with hub.LOCK:
                    hub.commit_kit_file("knowledge/owner/brand.md", b"# Brand\n\nChanged in between.\n",
                                        "the hub's own write")
                seen.append("written")
            except hub.KitFault as e:
                seen.append(str(e))

        @contextlib.contextmanager
        def watched():
            turns.append(threading.get_ident())
            if hub.RESTORE_LOCK.locked() and turns.count(threading.get_ident()) == 2:   # the staging's turn
                writer = threading.Thread(target=under_lock)
                writer.start()
                writer.join(10)
            with real():
                yield
        with patch.object(hub, "kit_lock", watched):
            code, answer = self.send(data)
        self.assertEqual(code, 200, answer)
        self.assertEqual(seen, [hub.KIT_BUSY_RESTORE])
        self.assertNotIn("Changed in between.", read(self.kit, "knowledge", "owner", "brand.md"))

    def test_a_restore_that_moves_holds_the_updates_for_as_long_as_it_moves(self):
        """A copy on its way holds the start of an update for RESTART_COPY_MOST seconds after a piece of it last moved,
        not after its start: a restore of 2 GB on a home uplink of 2 Mbit/s takes some 2.3 hours, and a bound from its
        start let each release cut it after the first hour. A real HTTP client sends the copy in pieces, and the
        copies' clock moves one second at each piece (copy_clock), so the test reads no real time: past the bound from
        its start, each whole MiB that the hub has read moves the mark, and the copy still holds updates. The bug that
        it catches: a restore that moves and that a release cuts (the hub-side second reader's R3-4, 22 November
        2026)."""
        self.work()
        self.records_of(6)
        status, _headers, size, _digest, path = self.download_in_pieces()
        self.assertEqual(status, 200)
        self.new_machine()
        with open(path, "rb") as f:
            data = f.read()
        piece, clock, held = 256 << 10, [0.0], []
        client = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=30)
        try:
            with patch.object(hub, "copy_clock", lambda: clock[0]), patch.object(hub, "RESTART_COPY_MOST", 10.0):
                client.putrequest("POST", "/ui/restore?db=test-generation", skip_accept_encoding=True)
                for name, value in (("Content-Type", "application/zip"), ("Content-Length", str(len(data))),
                                    ("X-Fleet-Client", "founderizer-swift/1/test"),
                                    ("X-Fleet-Request-Id", str(uuid.uuid4()))):
                    client.putheader(name, value)
                client.endheaders()
                for at in range(0, len(data), piece):
                    clock[0] += 1
                    client.send(data[at:at + piece])
                    if (at + piece) % (1 << 20) == 0 and clock[0] > 10:     # a whole MiB, past the bound
                        self.moved_at(clock[0])
                        held.append(hub.copies_going())
                reply = client.getresponse()
                said = json.loads(reply.read())
        finally:
            client.close()
        self.assertEqual(reply.status, 200, said)
        self.assertGreater(size, 6 << 20)
        self.assertEqual(held, [["a copy comes back from the owner's computer"]] * len(held))
        self.assertGreaterEqual(len(held), 3)

    def moved_at(self, t, within=5):
        """Waits, `within` seconds at most, until the mark of the copy on its way reads `t` on the copies' clock (the
        hub read the piece that moved it at that time); False when it did not."""
        deadline = time.monotonic() + within
        while time.monotonic() < deadline:
            with hub.COPIES_LOCK:
                if any(when == t for _what, when in hub.COPIES.values()):
                    return True
            time.sleep(0.01)
        return False

    def test_a_restore_is_refused_from_its_head_and_no_byte_of_a_stranger_s_body_is_read(self):
        """The hub read up to 256 MiB of any caller's body into memory before it asked who sent it. Now the owner's
        computer, the generation, the headers and the room are checked from the head: a caller that is not the owner's
        computer gets its refusal at once, with no byte of its body read or written, and the connection ends, so a
        stranger on the private network cannot fill the hub's memory or its disk. The owner's own computer gets its
        refusal too (here a generation that moved), but only once its whole body is read and dropped: a server that
        answers and ends the connection while an upload still sends gives the upload a lost connection in URLSession
        in place of the answer, and the Mac app then reads an old generation's 409 as a restore that landed. A real HTTP
        client sends the body in pieces over some six seconds, as an upload of a home line does. The bugs that it
        catches: the stranger's body read; the owner's answer before the body's end, or a connection that ends under
        it."""
        self.new_machine()
        port = self.server.server_port
        head = (f"POST /ui/restore?db=test-generation HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                f"Content-Type: application/zip\r\nContent-Length: {100 << 20}\r\n"
                f"X-Fleet-Client: founderizer-swift/1/test\r\nX-Fleet-Request-Id: {uuid.uuid4()}\r\n"
                f"X-Test-Source: 127.0.0.5\r\n\r\n").encode()        # an address that is not the owner's
        with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
            s.sendall(head)
            got = b""
            for piece in iter(lambda: s.recv(1 << 16), b""):    # to the end of the connection, or the socket's time
                got += piece
        self.assertTrue(got.startswith(b"HTTP/1.1 403 "), got[:300])
        piece, pieces, clock = b"PK\x03\x04" + bytes((256 << 10) - 4), 20, [0.0]
        client = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
        moved = patch.object(hub, "copy_clock", lambda: clock[0])     # one second of it at each piece
        moved.start()
        try:
            client.putrequest("POST", "/ui/restore?db=an-old-generation", skip_accept_encoding=True)
            for name, value in (("Content-Type", "application/zip"), ("Content-Length", str(len(piece) * pieces)),
                                ("X-Fleet-Client", "founderizer-swift/1/test"),
                                ("X-Fleet-Request-Id", str(uuid.uuid4()))):
                client.putheader(name, value)
            client.endheaders()
            clock[0] += 1
            client.send(piece)
            for sent in range(1, pieces):
                early = select.select([client.sock], [], [], 0.3)[0]   # the hub still reads: no answer yet
                self.assertEqual(early, [], f"the hub answered the owner's computer after {sent} of {pieces} pieces")
                if sent == 1:       # a body that is read and dropped holds an update too (the second reader's R2-5)
                    self.assertEqual(hub.copies_going(), ["a copy comes back from the owner's computer"])
                if sent == 16:          # 16 s of the copies' clock from its start, with a bound of 10 s (R3-4)
                    self.moved_at(clock[0])
                    with patch.object(hub, "RESTART_COPY_MOST", 10.0):
                        self.assertEqual(hub.copies_going(), ["a copy comes back from the owner's computer"])
                clock[0] += 1
                client.send(piece)
            reply = client.getresponse()
            said = json.loads(reply.read())
        finally:
            client.close()
            moved.stop()
        self.assertEqual((reply.status, said.get("code")), (409, "hub_changed_sending"), said)
        self.assertEqual(self.copy_files(), [])
        for suffix in (hub.RESTORE_SUFFIX, hub.RESTORE_SUFFIX + ".part"):
            self.assertFalse(os.path.exists(self.path + suffix), suffix)
        self.assertEqual(hub.q1("SELECT count(*) n FROM ui_controls")["n"], 0)

    def test_a_copy_that_is_not_what_it_says_is_refused_and_nothing_is_staged(self):
        _fleet, data = self.copy_of_a_fleet()
        self.new_machine()
        for name, broken, *words in self.damaged(data):
            with self.subTest(name):
                code, answer = self.send(broken)
                self.assertEqual(code, 422, answer)
                if words:           # the words that the owner reads, where they are more than "not a copy"
                    self.assertEqual(answer["error"], words[0])
                if name in ("50,000 entries", "a central directory of 5 MiB", "an end record whose counts write its "
                            "signature", "a Zip64 record before an end record of 46 bytes"):  # before zipfile reads one
                    path = os.path.join(self.tmp.name, "broken.zip")
                    with open(path, "wb") as f:
                        f.write(broken)
                    tracemalloc.start()
                    try:
                        with self.assertRaises(hub.Refusal):
                            hub.read_bundle(path, path + ".records")
                        peak = tracemalloc.get_traced_memory()[1]
                    finally:
                        tracemalloc.stop()
                    self.assertLess(peak, 1 << 20, name)
                    self.assertFalse(os.path.exists(path + ".records"), name)
                # nothing of the copy stays: no staged records, no part of them, no folder of the upload, and no
                # flight that would refuse the hub's own writes after it (the validator's N4). The route answers
                # before its cleanup ends, and lets go of RESTORE_LOCK last (the hub reader's round 6 note).
                with hub.RESTORE_LOCK:
                    pass
                self.assertEqual(hub.FLIGHT, {"thread": None, "restore": False}, name)
                self.assertFalse(os.path.exists(self.path + hub.RESTORE_SUFFIX), name)
                self.assertFalse(os.path.exists(self.path + hub.RESTORE_SUFFIX + ".part"), name)
                self.assertEqual(self.copy_files(), [], name)
                self.assertEqual(json.loads(read(self.kit, "team.json"))["addresses"]["hub"], "127.0.0.9")
                self.assertEqual(hub.q1("SELECT count(*) n FROM ui_controls")["n"], 0)

    @staticmethod
    def damaged(data):
        """Every way a copy can be wrong that a restore must catch before it writes anything."""
        def rebuilt(change, method=zipfile.ZIP_DEFLATED):
            old = zipfile.ZipFile(io.BytesIO(data))
            members = {name: old.read(name) for name in old.namelist()}
            change(members)
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", method) as zf:
                for name, body in members.items():
                    zf.writestr(name, body)
            return buffer.getvalue()

        def zstandard(data):
            """The copy with the method of each entry set to Zstandard (93) in each header, which zipfile reads."""
            out = bytearray(data)
            for mark, field in ((b"PK\x03\x04", 8), (b"PK\x01\x02", 10)):
                at = out.find(mark)
                while at >= 0:
                    out[at + field:at + field + 2] = (93).to_bytes(2, "little")
                    at = out.find(mark, at + 4)
            return bytes(out)

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

        def records_stated_as(size):
            def change(members):
                files = json.loads(members["fleet.json"])["files"]
                changed(members, files=dict(files, **{"fleet.sqlite3": dict(files["fleet.sqlite3"], bytes=size)}))
            return change

        def entry_says(name, offset, value):
            """The copy with the bytes at `offset` of the entry `name` in the central directory, which zipfile reads,
            set to `value`: 8 the flags, 16 the CRC-32."""
            out = bytearray(data)
            at = out.find(b"PK\x01\x02")
            while out[at + 46:at + 46 + len(name)] != name.encode():
                at = out.find(b"PK\x01\x02", at + 4)
            out[at + offset:at + offset + len(value)] = value
            return bytes(out)

        def a_local_name_that_is_not_utf8():
            out = bytearray(data)
            at = zipfile.ZipFile(io.BytesIO(data)).getinfo("fleet.sqlite3").header_offset
            out[at + 6:at + 8] = (int.from_bytes(out[at + 6:at + 8], "little") | 0x800).to_bytes(2, "little")
            out[at + 30] = 0xFF                             # the first byte of the records' local name, said to be UTF-8
            return bytes(out)

        def a_broken_manifest_stream():
            out = bytearray(data)
            at = zipfile.ZipFile(io.BytesIO(data)).getinfo("fleet.json").header_offset
            out[at + 30 + sum(struct.unpack_from("<HH", out, at + 26))] = 0xFF    # a block of the reserved type 3
            return bytes(out)

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
                ("records that are not a database", rebuilt(records_that_are_not_a_database)),
                # zipfile unpacks an entry of bzip2 whole at its first read, whatever its size: refused before a read
                ("an entry of bzip2", rebuilt(lambda m: None, zipfile.ZIP_BZIP2)),
                ("an entry of Zstandard", zstandard(rebuilt(lambda m: None, zipfile.ZIP_STORED))),
                # the copy's own manifest gave the bound of each read: 65 KB of copy held 128 MiB (a read of 2^63 bytes
                # raised OverflowError), and a manifest of 64 MiB of spaces held 141 MiB
                ("a stated size that no read can ask", rebuilt(records_stated_as(2 ** 63 - 1))),
                ("records stated as more than a restore unpacks", rebuilt(records_stated_as(hub.RESTORE_UNPACK + 1)),
                 "this copy states 2,049 MiB of files; a restore unpacks at most 2,048 MiB"),
                ("a manifest after 1 MiB of spaces",
                 rebuilt(lambda m: m.update({"fleet.json": b" " * hub.BACKUP_MANIFEST_MAX + m["fleet.json"]}))),
                # zipfile's errors, which were no 422: a wrong CRC-32, a broken stream, an encrypted entry (bit 0),
                # compressed patched data (bit 5) and strong encryption (bit 6)
                ("records with a wrong CRC-32", entry_says("fleet.sqlite3", 16, bytes(4))),
                ("a manifest whose stream is broken", a_broken_manifest_stream()),
                ("an encrypted manifest", entry_says("fleet.json", 8, b"\x01\x00")),
                ("records of compressed patched data", entry_says("fleet.sqlite3", 8, b"\x20\x00")),
                ("records of strong encryption", entry_says("fleet.sqlite3", 8, b"\x40\x00")),
                # and errors that are not zipfile's own: UnicodeDecodeError of a local name, RecursionError of json
                ("records whose local name is not UTF-8", a_local_name_that_is_not_utf8()),
                ("a manifest of 200,000 [", rebuilt(lambda m: m.update({"fleet.json": b"[" * 200_000}))),
                # NotImplementedError of zipfile's constructor, and AttributeError of a manifest that is no object
                ("an entry that needs version 6.4", entry_says("fleet.sqlite3", 6, (64).to_bytes(2, "little"))),
                ("a manifest that is [1]", rebuilt(lambda m: m.update({"fleet.json": b"[1]"}))),
                ("a manifest that is NaN", rebuilt(lambda m: m.update({"fleet.json": b"NaN"}))),
                # zipfile's constructor holds some 500 bytes for each entry (400,000 entries in 32 MiB held 198 MiB)
                ("50,000 entries", many_entries(50_000)),
                ("a central directory of 5 MiB", many_entries(15_000, comment=300)),
                # the end record that zipfile reads: a search for its signature found a later one inside a record
                # whose counts write it, and read no Zip64 record; zipfile read 31.3 MiB of directory (63 MiB held)
                ("an end record whose counts write its signature",
                 many_entries(160, comment=32 * 1024, counts=(0x4B50, 0x0605))),
                ("a Zip64 record before an end record of 46 bytes", many_entries(160, comment=32 * 1024, zip64=True)),
                ("an end record whose comment is not there", data[:-2] + (5).to_bytes(2, "little"))]


# ---------------------------------------------------------------- without the app

class ByHand(Fixture):
    def test_the_hub_machine_can_take_a_copy_from_a_shell(self):
        """`python3 hub.py --restore <copy>`: the same staging, for a person whose app cannot reach this hub. It runs
        hub.py by its path, as UI-API.md and each copy's RESTORE.md tell that person to type; the other tests start
        the hub as a module (`-m hub`), which reads a compiled copy and does not compile hub.py again."""
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
        done = subprocess.run([sys.executable, "-m", "hub", "--restore", path,
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
