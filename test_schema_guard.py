"""An update cannot kill a hub: the schema meets the customer's own rows before the configuration ref moves, and
the hub starts even when it did not.

The hole this closes: a release's checks run in a temporary clone against *fresh* databases, so `selftest.py` and
`fleet.py verify` never see the customer's rows. A migration step that only those rows refuse — a unique index
over a table that already holds a duplicate — passed both, and then met real data for the first time at the
restart, which `hub.finish_release` does **after** the push. The process exited, `Restart=always` brought it back,
and systemd retired the unit in about twenty seconds. The ref had moved, every machine had followed it, and the
customer has no console.

So this file runs the thing itself, not a stand-in for it:

  - the published repository carries **this repository's own code**, so the released `hub.py --check-schema` is
    the real one;
  - the fleet's database is a real hub database with a real duplicate in it;
  - `selftest.py` and `fleet.py verify` are the only two answered from a table, because the real pair takes
    minutes and reads the machine it runs on (`test_releases.py` makes the same trade for the same reason).

Nothing here reaches the network and nothing touches a real fleet. Git is real throughout.
"""
import base64
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

import fleet
import hub
import releases
from test_ui_api import parent_pipe

KIT = os.path.dirname(os.path.abspath(__file__))
SEED = bytes(range(32))
KEY = releases.public_key(SEED)

TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.1"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []}}}
PROFILE = "# Profile: manager\n\n**Character.** Careful.\n"

# What a release adds and this fleet's records refuse. `notes` always has rows in a fleet that has done any work,
# so this is the shape of the real thing and not a contrivance: one unique index, and two rows that break it.
NEW_INDEX = "CREATE UNIQUE INDEX IF NOT EXISTS one_note_per_task ON notes(task)"
MIGRATE_LIST = "    for statement in [\n"       # migrate()'s own list of indexes, where a release adds one

HEALTHY_SELFTEST = (0, "127 of 127 checks passed.", "")
HEALTHY_VERIFY = (0, json.dumps([{"check": "disk", "state": "ok", "says": "40 GiB free", "fix": None}]), "")


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (CheckSchema, StartingHub, Updates, Unit):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


def git(*args, cwd=None):
    done = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main",
                           *args], cwd=cwd, capture_output=True, text=True, timeout=120)
    if done.returncode:
        raise AssertionError(f"git {' '.join(args)}: {done.stderr}")
    return done.stdout.strip()


def manifest(revision, version="2026.10.3"):
    body = {"revision": revision, "version": version, "notes": None, "minimum": None, "hold": False}
    return dict(body, signature=base64.b64encode(releases.sign(SEED, releases.signed_text(body))).decode())


def fleet_database(path, notes=1, db_id="a-fleet"):
    """A hub database as a working fleet has it: this code's own tables, and `notes` rows on one task. Written with
    plain sqlite3 and never through `hub.DB`, so no test here changes the module's own connection."""
    db = sqlite3.connect(path)
    db.executescript(hub.SCHEMA)
    db.execute("INSERT INTO kv(k,v) VALUES('db_id',?)", (db_id,))
    db.execute("INSERT INTO tasks(id,title,state) VALUES(1,'a task','submitted')")
    for n in range(notes):
        db.execute("INSERT INTO notes(task,agent,ts,text) VALUES(1,'manager',?,?)", (n, f"note {n}"))
    db.commit()
    db.close()
    return path


def old_trigger_runs(path):
    """A database from before `trigger_open_run`: two open runs of one trigger, which that index refuses. This is
    the live shape of the finding — five such indexes are in `migrate()` today, and each was, when it arrived, a
    hub that might not start."""
    db = sqlite3.connect(path)
    for state, due in (("waiting", 1.0), ("sent", 2.0)):
        db.execute("INSERT INTO trigger_runs(trigger_id,revision,due,manual,state,created) VALUES(7,1,?,0,?,?)",
                   (due, state, due))
    db.commit()
    db.close()
    return path


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def get(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(urllib.request.Request(url, headers={"X-Fleet-Client": "test"}), timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        with e:
            return e.code, json.loads(e.read())


# ---------------------------------------------------------------- the check itself

class CheckSchema(unittest.TestCase):
    """`python3 hub.py --check-schema <copy>`: this code's schema against a real database, and the one line that
    `releases.schema_summary` reads."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="fleet-schema-check-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)

    def check(self, path):
        done = subprocess.run([sys.executable, os.path.join(KIT, "hub.py"), "--check-schema", str(path)],
                              capture_output=True, text=True, timeout=120, cwd=KIT)
        return done.returncode, done.stdout

    def test_a_database_this_code_fits_refuses_nothing(self):
        code, out = self.check(fleet_database(self.root / "good.db"))
        self.assertEqual((code, releases.schema_summary(out)), (0, (0, [])))

    def test_a_database_with_a_duplicate_names_the_step_it_refuses(self):
        code, out = self.check(old_trigger_runs(fleet_database(self.root / "bad.db")))
        refused, says = releases.schema_summary(out)
        self.assertEqual((code, refused), (1, 1))
        self.assertIn("trigger_open_run", says[0])
        self.assertIn("UNIQUE constraint failed", says[0])

    def test_the_check_writes_the_copy_it_is_given_and_nothing_else(self):
        """It is handed a copy on purpose: the released code never opens the live database."""
        path = fleet_database(self.root / "copy.db")
        before = sorted(os.listdir(self.root))
        self.assertEqual(self.check(path)[0], 0)
        self.assertEqual(sorted(os.listdir(self.root)), before)
        db = sqlite3.connect(path)
        self.addCleanup(db.close)
        names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        self.assertIn("trigger_open_run", names)        # it ran the migration, on the copy


# ---------------------------------------------------------------- the floor under the check

class StartingHub(unittest.TestCase):
    """A hub whose database refuses a schema step starts, answers, and says what it refused. Without this the
    process exits, systemd gives up in about twenty seconds, and nobody can reach the fleet again."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="fleet-schema-start-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        team = json.loads(json.dumps(TEAM))
        (self.root / "team.json").write_text(json.dumps(team))

    @staticmethod
    def stop(proc):
        proc.kill()
        proc.wait(timeout=20)
        proc.stdout.close()

    def start(self, db):
        port = free_port()
        pipe, fds = parent_pipe(self.root)
        proc = subprocess.Popen([sys.executable, os.path.join(KIT, "hub.py"), "--host", "127.0.0.1",
                                 "--port", str(port), "--db", str(db), "--team", str(self.root / "team.json"),
                                 "--chat-apps", str(self.root / "chat-apps"), "--parent-pipe", str(pipe)],
                                pass_fds=fds, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=KIT,
                                env=dict(os.environ, HOME=str(self.root)))     # its timer sweeps ~/.fleet/attachments
        self.addCleanup(self.stop, proc)
        base = f"http://127.0.0.1:{port}"
        for _ in range(100):
            if proc.poll() is not None:
                self.fail("the hub did not start: " + proc.stdout.read())
            try:
                get(base + "/health")
                return proc, base
            except (urllib.error.URLError, OSError):
                time.sleep(0.1)
        self.fail("the hub never answered")

    def test_a_hub_whose_database_refuses_a_step_still_answers_and_says_so(self):
        db = old_trigger_runs(fleet_database(self.root / "bad.db"))
        proc, base = self.start(db)
        self.assertEqual(get(base + "/health")[0], 200)
        code, health = get(base + "/ui/health?db=a-fleet")
        self.assertEqual(code, 200)
        self.assertFalse(health["ok"])
        warning = [w for w in health["warnings"] if w["kind"] == "schema"]
        self.assertEqual(len(warning), 1, health["warnings"])
        self.assertIn("trigger_open_run", warning[0]["detail"])
        self.assertEqual(len(health["hub"]["schema"]), 1)
        proc.terminate()
        proc.wait(timeout=20)
        self.assertIn("WARNING: this database refused 1 schema step", proc.stdout.read())

    def test_the_hub_keeps_every_step_the_database_did_take(self):
        """It is not all or nothing: a refused index is a constraint that is not enforced, and the columns that
        the same migration adds are still there, so the hub runs."""
        db = old_trigger_runs(fleet_database(self.root / "bad.db"))
        self.start(db)
        opened = sqlite3.connect(str(db))
        self.addCleanup(opened.close)
        self.assertIn("check_now", {r[1] for r in opened.execute("PRAGMA table_info(trigger_runs)")})
        self.assertIn("duty_case", {r[1] for r in opened.execute("PRAGMA table_info(tasks)")})
        said = [r[0] for r in opened.execute("SELECT what FROM log WHERE what LIKE '%schema step%'")]
        self.assertTrue(any("trigger_open_run" in one for one in said), said)

    def test_a_hub_on_a_database_this_code_fits_says_nothing(self):
        _, base = self.start(fleet_database(self.root / "good.db"))
        health = get(base + "/ui/health?db=a-fleet")[1]
        self.assertEqual(health["hub"]["schema"], [])
        self.assertEqual([w for w in health["warnings"] if w["kind"] == "schema"], [])


# ---------------------------------------------------------------- the whole update run

class Updates(unittest.TestCase):
    """A fleet in the shape it runs in, carrying this repository's own code: the released `hub.py` that the schema
    check runs is the real one, not a two-line stand-in."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="fleet-schema-update-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        seed = self.root / "seed"
        (seed / "profiles").mkdir(parents=True)
        (seed / "knowledge/owner").mkdir(parents=True)
        for name in sorted(os.listdir(KIT)):         # the kit's own code, so the release carries a real hub.py
            if name.endswith(".py") and not name.startswith("test_"):
                shutil.copyfile(os.path.join(KIT, name), seed / name)
        (seed / "team.json").write_text(json.dumps(TEAM, indent=2) + "\n")
        (seed / "profiles/manager.md").write_text(PROFILE)
        (seed / "knowledge/owner/brand.md").write_text("# Brand\n\nBlue.\n")
        (seed / "RULES.md").write_text("# Rules\n")
        (seed / releases.KEY_FILE).write_text(base64.b64encode(KEY).decode() + "\n")
        git("init", "-q", str(seed))
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "seed", cwd=seed)
        git("branch", hub.CONFIG_BRANCH, cwd=seed)
        git("clone", "-q", "--bare", str(seed), str(self.root / "origin.git"))
        git("clone", "-q", "--bare", str(seed), str(self.root / "upstream.git"))
        git("clone", "-q", "-b", hub.CONFIG_BRANCH, str(self.root / "origin.git"), str(self.root / "kit"))
        self.kit = self.root / "kit"
        self.origin, self.upstream = str(self.root / "origin.git"), str(self.root / "upstream.git")
        self.pinned = git("rev-parse", "HEAD", cwd=self.kit)

    # ---- the three people who write here

    def publish(self, write, message="a release"):
        work = self.root / ("published-" + str(len(list(self.root.iterdir()))))
        git("clone", "-q", "-b", "main", self.upstream, str(work))
        write(work)
        git("add", "-A", cwd=work)
        git("commit", "-q", "-m", message, cwd=work)
        git("push", "-q", "origin", "HEAD:main", cwd=work)
        return git("rev-parse", "HEAD", cwd=work)

    @staticmethod
    def adds_index(statement=NEW_INDEX):
        """A release that adds one unique index to `migrate()`, which is what every schema release does."""
        def write(work):
            text = (work / "hub.py").read_text()
            if text.count(MIGRATE_LIST) != 1:
                raise AssertionError("migrate()'s list of indexes is no longer where this test writes one")
            (work / "hub.py").write_text(text.replace(MIGRATE_LIST, MIGRATE_LIST + f'        "{statement}",\n', 1))
        return write

    def runner(self):
        """Git and the schema check for real; `selftest.py` and `fleet.py verify` from a table."""
        self.ran = []

        def run(argv, timeout=None, cwd=None, input=None):
            self.ran.append(argv)
            if argv[0] == "git" or "--check-schema" in argv:
                return releases._run(argv, timeout=timeout or releases.GIT_WAIT, cwd=cwd, input=input)
            if argv[-1].endswith("selftest.py"):
                return HEALTHY_SELFTEST
            if argv[-2:] == ["verify", "--json"]:
                return HEALTHY_VERIFY
            raise AssertionError("the update ran something unexpected: " + " ".join(argv))
        return run

    def update(self, released, database=None):
        return releases.Update(str(self.kit), releases.check(manifest(released), KEY), upstream=self.upstream,
                               origin=self.origin, database=database, run=self.runner()).apply()

    def unchanged(self):
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.kit), self.pinned)
        self.assertEqual(git("rev-parse", hub.CONFIG_BRANCH, cwd=self.origin), self.pinned)
        self.assertFalse(any("push" in argv for argv in self.ran), "something was pushed")

    # ---- the checks

    def test_a_release_this_fleet_s_own_records_refuse_is_not_taken(self):
        """The finding itself, end to end. Before this, the run published, the ref moved, every machine followed
        it, and the hub died at its restart with nobody able to reach it."""
        database = fleet_database(self.root / "fleet.db", notes=2)      # two notes on one task
        answer = self.update(self.publish(self.adds_index(), "a release with a new unique index"), database)
        self.assertEqual((answer["state"], answer["step"]), (releases.ROLLED_BACK, "schema"), answer["says"])
        self.assertIn("one_note_per_task", answer["says"])
        self.assertIn("this fleet's own records refuse", answer["says"])
        self.assertIn(self.pinned[:12], answer["says"])
        self.assertIsNone(answer["reached"])
        self.unchanged()
        self.assertFalse(any(argv[-1].endswith("selftest.py") for argv in self.ran),
                         "the schema goes first: it takes a second and the other two take minutes")

    def test_the_same_release_is_taken_by_a_fleet_whose_records_fit_it(self):
        database = fleet_database(self.root / "fleet.db", notes=1)      # one note: the new index holds
        answer = self.update(self.publish(self.adds_index(), "a release with a new unique index"), database)
        self.assertEqual((answer["state"], answer["step"]), (releases.DONE, "follow"), answer["says"])
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.kit), answer["reached"])
        self.assertEqual(git("rev-parse", hub.CONFIG_BRANCH, cwd=self.origin), answer["reached"])
        self.assertIn(NEW_INDEX, (self.kit / "hub.py").read_text())

    def test_the_live_database_is_never_opened_by_the_release(self):
        """The hub hands over a copy. A release that changed the schema must not be able to change the records of
        a fleet that then keeps its own revision."""
        database = fleet_database(self.root / "fleet.db", notes=2)
        before = database.read_bytes()
        self.update(self.publish(self.adds_index()), database)
        self.assertEqual(database.read_bytes(), before)

    def test_a_release_whose_schema_check_says_nothing_is_not_taken(self):
        def breaks_the_check(work):
            (work / "hub.py").write_text("raise SystemExit('this release cannot even be read')\n")
        answer = self.update(self.publish(breaks_the_check, "a release whose hub.py does not run"),
                             fleet_database(self.root / "fleet.db"))
        self.assertEqual((answer["state"], answer["step"]), (releases.ROLLED_BACK, "schema"))
        self.assertIn("could not read this fleet's database", answer["says"])
        self.unchanged()

    def test_a_fleet_that_gives_no_database_is_updated_as_before(self):
        """A hub with no records to risk, and every test that only cares about the merge."""
        answer = self.update(self.publish(self.adds_index()), None)
        self.assertEqual(answer["state"], releases.DONE, answer["says"])
        self.assertFalse(any("--check-schema" in argv for argv in self.ran))


# ---------------------------------------------------------------- what systemd is told

class Unit(unittest.TestCase):
    def test_the_hub_unit_has_no_start_limit(self):
        """`Restart=always` with `RestartSec=5` and systemd's default limit is five starts in ten seconds, so a
        hub that cannot start is retired in about twenty seconds and a customer has no console to bring it back."""
        source = Path(os.path.join(KIT, "fleet.py")).read_text()
        self.assertIn("StartLimitIntervalSec=0", source)
        unit = source[source.index('unit = ("[Unit]'):source.index('[Install]\\nWantedBy=default.target')]
        self.assertLess(unit.index("StartLimitIntervalSec=0"), unit.index("[Service]"),
                        "StartLimitIntervalSec belongs in [Unit]")
        self.assertIn("Restart=always", unit)
        self.assertTrue(hasattr(fleet, "cmd_service"))


if __name__ == "__main__":
    unittest.main()
