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
import argparse
import base64
import contextlib
import inspect
import io
import json
import os
import pwd
import shlex
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
from unittest.mock import patch

import fleet
import hub
import lifecycle
import releases
from test_ui_api import parent_pipe
from leftovers import ROOT

KIT = ROOT
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
BEGAN = time.time()         # when this file was taken: the process that runs these tests began before it
HEALTHY_VERIFY = (0, json.dumps([{"check": "disk", "state": "ok", "says": "40 GiB free", "fix": None}]), "")


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (CheckSchema, StartingHub, Updates, Unit, UnitFollowsCode, Compiled):
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
            if "--check-schema" in argv:
                self.schema_in = cwd
            if argv[0] == "git" or "--check-schema" in argv:
                return releases._run(argv, timeout=timeout or releases.GIT_WAIT, cwd=cwd, input=input)
            if argv[-1].endswith("selftest.py"):
                kept = os.path.join(os.path.dirname(argv[-1]), "__pycache__")       # what the schema check left
                self.compiled = sorted(os.listdir(kept)) if os.path.isdir(kept) else []
                return HEALTHY_SELFTEST
            if argv[-3:] == ["verify", "--no-selftest", "--json"]:
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
        """And its schema check runs the released hub as a module in the clone, `python3 -m hub --check-schema`,
        not `python3 <clone>/hub.py`: Python keeps what it compiled only for a module, in the clone's __pycache__,
        and the hubs that selftest.py starts next, as a module in the same clone, read it there. The compile of
        hub.py takes about 190 MB for a moment: by its path it was paid here and again by the self-test's first
        hub, beside the fleet's own hub, on a server that may have 1 GB."""
        database = fleet_database(self.root / "fleet.db", notes=1)      # one note: the new index holds
        answer = self.update(self.publish(self.adds_index(), "a release with a new unique index"), database)
        self.assertEqual((answer["state"], answer["step"]), (releases.DONE, "follow"), answer["says"])
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.kit), answer["reached"])
        self.assertEqual(git("rev-parse", hub.CONFIG_BRANCH, cwd=self.origin), answer["reached"])
        self.assertIn(NEW_INDEX, (self.kit / "hub.py").read_text())
        check = next(argv for argv in self.ran if "--check-schema" in argv)
        self.assertEqual(check[:4], [sys.executable, "-m", "hub", "--check-schema"])
        selftest = next(argv for argv in self.ran if argv[-1].endswith("selftest.py"))
        self.assertEqual(os.path.realpath(self.schema_in), os.path.realpath(os.path.dirname(selftest[-1])),
                         "the schema check ran in the clone, where the self-test starts its hubs")
        if not (os.environ.get("PYTHONDONTWRITEBYTECODE") or os.environ.get("PYTHONPYCACHEPREFIX")
                or sys.flags.optimize):
            self.assertTrue([one for one in self.compiled if one.startswith("hub.") and one.endswith(".pyc")],
                            f"the clone held no compiled hub when the self-test began: {self.compiled}")

    def test_the_live_database_is_never_opened_by_the_release(self):
        """The hub hands over a copy. A release that changed the schema must not be able to change the records of
        a fleet that then keeps its own revision."""
        database = fleet_database(self.root / "fleet.db", notes=2)
        before = database.read_bytes()
        self.update(self.publish(self.adds_index()), database)
        self.assertEqual(database.read_bytes(), before)

    def test_a_release_whose_schema_check_says_nothing_is_not_taken(self):
        """A check that cannot be read is not taken, and one that the system ends says so: in plain words, with the
        word on memory for SIGKILL (what the kernel sends when memory runs out), and with the end of what it printed
        on its standard output, where it stopped, not a warning of its error output (until 19 November 2026 the line
        said only "no output", or the first words, so a small server that could not compile a release looked like any
        other failure)."""
        def breaks_the_check(work):
            (work / "hub.py").write_text("raise SystemExit('this release cannot even be read')\n")
        answer = self.update(self.publish(breaks_the_check, "a release whose hub.py does not run"),
                             fleet_database(self.root / "fleet.db"))
        self.assertEqual((answer["state"], answer["step"]), (releases.ROLLED_BACK, "schema"))
        self.assertIn("could not read this fleet's database", answer["says"])
        self.unchanged()

        def is_killed(work):            # it prints a line for each of 200 checks, and the system ends it
            (work / "hub.py").write_text("import os, signal, sys\nprint('a warning', file=sys.stderr, flush=True)\n"
                                         "print('\\n'.join(f'PASS check {i}' for i in range(200)), flush=True)\n"
                                         "os.kill(os.getpid(), signal.SIGKILL)\n")
        answer = self.update(self.publish(is_killed, "a release whose check the system ends"),
                             fleet_database(self.root / "killed.db"))
        self.assertEqual((answer["state"], answer["step"]), (releases.ROLLED_BACK, "schema"))
        self.assertIn("could not read this fleet's database: the system ended it, for example for lack of memory "
                      "(SIGKILL); the end of what it printed:", answer["says"])
        self.assertIn("PASS check 199. The fleet stays at", answer["says"])     # where it stopped, and the whole line
        self.assertNotIn("PASS check 3 ", answer["says"])
        self.unchanged()

    def test_a_fleet_that_gives_no_database_is_updated_as_before(self):
        """A hub with no records to risk, and every test that only cares about the merge."""
        answer = self.update(self.publish(self.adds_index()), None)
        self.assertEqual(answer["state"], releases.DONE, answer["says"])
        self.assertFalse(any("--check-schema" in argv for argv in self.ran))


# ---------------------------------------------------------------- what systemd is told

# The hub's unit as each release before this text wrote it (fleet.py `service hub` until 16 November 2026), for a
# folder with no space and no percent sign: the hub by its path, and systemd's default for a process that the system
# ends for lack of memory. Written out here a second time, apart from lifecycle.hub_units_before.
def unit_of_before(kit, python, home):
    return ("[Unit]\nDescription=Founderizer hub\nAfter=network-online.target\nStartLimitIntervalSec=0\n"
            "[Service]\nType=simple\nWorkingDirectory=" + kit + "\n"
            'Environment="PATH=' + home + '/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:'
            '/sbin"\n'
            'ExecStart="' + python + '" "' + kit + '/hub.py"\n'
            "Restart=always\nRestartSec=5\nKillMode=process\nTimeoutStopSec=15\n"
            "[Install]\nWantedBy=default.target\n")


class Unit(unittest.TestCase):
    KIT_AT, PYTHON, HOME = "/home/fleet/founderizer", "/usr/bin/python3", "/home/fleet"

    def unit(self):
        """The hub's unit for a folder that is its own real path (lifecycle.hub_unit takes the real path of its
        folder, and /home is a link on some systems that run this test)."""
        return lifecycle.service_unit("hub", lifecycle.hub_start(self.PYTHON), self.KIT_AT,
                                      lifecycle.service_path(self.HOME))

    def service(self, text):
        """The settings of [Service], in the unit's own order."""
        return text[text.index("[Service]\n"):text.index("[Install]\n")].splitlines()[1:]

    def test_the_hub_unit_has_no_start_limit(self):
        """`Restart=always` with `RestartSec=5` and systemd's default limit is five starts in ten seconds, so a
        hub that cannot start is retired in about twenty seconds and a customer has no console to bring it back."""
        unit = self.unit()
        self.assertLess(unit.index("StartLimitIntervalSec=0"), unit.index("[Service]"),
                        "StartLimitIntervalSec belongs in [Unit]")
        self.assertIn("Restart=always", self.service(unit))
        self.assertTrue(hasattr(fleet, "cmd_service"))

    def test_the_self_test_starts_its_hubs_with_the_words_of_the_unit(self):
        """selftest.py starts each of its hubs as `python3 -m hub` in the folder of the code, and a hub takes a
        release only after that self-test passed on its own machine: so a machine whose Python cannot run the
        module form refuses the release, and never comes to a unit that says those words (hub.unit_follows_code
        says that it relies on this). If the self-test's start changes, that sentence is no longer true."""
        source = Path(KIT, "selftest.py").read_text()
        start = source[source.index("def start_hub("):source.index("HUBS.append(proc)")]
        self.assertIn('subprocess.Popen([sys.executable, "-m", "hub", ', start)
        self.assertIn("cwd=KIT,", start)
        self.assertEqual(lifecycle.hub_start(sys.executable), [sys.executable, "-m", "hub"])

    def test_the_hub_starts_as_a_module_in_the_folder_of_its_code(self):
        """`python3 -m hub` with the code's folder as the working directory, and no argument (main() reads the
        team.json beside the code and keeps the records at the default place: hub.installed_hub). A hub that starts
        by its path holds about 135 MB more for its whole life, which a server with 1 GB needs for a release."""
        unit = self.service(self.unit())
        self.assertIn('ExecStart="/usr/bin/python3" "-m" "hub"', unit)
        self.assertIn("WorkingDirectory=/home/fleet/founderizer", unit)
        self.assertEqual(lifecycle.hub_start("python3"), ["python3", "-m", "hub"])
        self.assertNotIn("hub.py", self.unit())

    def test_the_hub_keeps_running_when_the_system_ends_one_of_its_processes(self):
        """OOMPolicy=continue, in [Service], for the hub alone: by systemd's default (stop) the whole service stops
        when the system ends one process of it for lack of memory, and the checks of a release are such processes."""
        self.assertIn("OOMPolicy=continue", self.service(self.unit()))
        for name in ("git", "channels", "dev-lead"):
            other = lifecycle.service_unit(name, [self.PYTHON, "x.py"], self.KIT_AT, lifecycle.service_path(self.HOME))
            self.assertNotIn("OOMPolicy", other, name)

    def test_the_text_is_the_one_of_before_with_those_two_changes(self):
        """Line for line: nothing else of the hub's unit moved, and no other unit moved at all (for a folder with
        no space). When the hub's unit gets a new text, this test fails, and says what the change still needs."""
        new_text = ("The hub's unit has a new text. Add the text that it had until now to lifecycle.hub_units_before, "
                    "written out with its dates, and a function in this file that writes it: a hub that runs writes "
                    "its unit again only over a text of that list (hub.unit_follows_code), so without it no hub "
                    "that runs gets the new text.")
        before = unit_of_before(self.KIT_AT, self.PYTHON, self.HOME).splitlines()
        now = self.unit().splitlines()
        self.assertEqual([line for line in now if line not in before],
                         ['ExecStart="/usr/bin/python3" "-m" "hub"', "OOMPolicy=continue"], new_text)
        self.assertEqual([line for line in before if line not in now],
                         ['ExecStart="/usr/bin/python3" "/home/fleet/founderizer/hub.py"'], new_text)
        path = lifecycle.service_path(self.HOME)
        agent = lifecycle.service_unit("dev-lead", [self.PYTHON, self.KIT_AT + "/fleet.py", "run", "dev-lead"],
                                       self.KIT_AT, path)
        start = '"/home/fleet/founderizer/fleet.py" "run" "dev-lead"'
        self.assertEqual(agent, unit_of_before(self.KIT_AT, self.PYTHON, self.HOME)
                         .replace("Founderizer hub", "Founderizer dev-lead")
                         .replace('"/home/fleet/founderizer/hub.py"', start))
        bridge = lifecycle.service_unit("channels", [self.PYTHON, "channels.py", "run"], self.KIT_AT, path)
        self.assertIn("TimeoutStopSec=15\nUMask=0077\n[Install]", bridge)     # its journal holds the text of messages

    def test_a_folder_with_a_space_is_written_as_systemd_reads_it(self):
        """systemd takes the whole rest of the WorkingDirectory line as the path: a space is a space, and \x20 is
        four characters of a folder that is not there (measured on systemd 255: such a unit did not start). A
        percent sign is doubled, because systemd reads %h and its like in that line."""
        for name, argv in (("hub", ["/opt/100%/python3", "-m", "hub"]), ("dev-lead", ["/opt/100%/python3", "f.py"])):
            unit = lifecycle.service_unit(name, argv, "/srv/my fleet/100%", lifecycle.service_path("/home/50%"))
            self.assertIn("WorkingDirectory=/srv/my fleet/100%%\n", unit)
            self.assertIn('ExecStart="/opt/100%%/python3" ', unit)
            self.assertIn('Environment="PATH=/home/50%%/.local/bin:', unit)
            self.assertNotIn(r"\x20", unit)

    def test_the_texts_of_earlier_releases_are_the_ones_that_the_hub_may_write_over(self):
        """lifecycle.hub_units_before: the text that each release until 16 November 2026 wrote (the same bytes as
        the unit of a hub that ran that day, by its SHA-256), for the folder as that installer named it. The text
        of today is never one of them: the hub would write its own text again at every start."""
        before = lifecycle.hub_units_before(self.KIT_AT, self.PYTHON, self.HOME)
        self.assertEqual(before, [unit_of_before(self.KIT_AT, self.PYTHON, self.HOME)])
        self.assertNotIn(self.unit(), before)
        self.assertNotIn(lifecycle.hub_unit(self.KIT_AT, self.PYTHON, self.HOME), before)
        spaced = lifecycle.hub_units_before("/srv/my fleet/100%", self.PYTHON, self.HOME)[0]
        self.assertIn("WorkingDirectory=/srv/my\\x20fleet/100%%\n", spaced)      # as that release wrote it
        self.assertIn('ExecStart="/usr/bin/python3" "/srv/my fleet/100%%/hub.py"\n', spaced)
        self.assertEqual(hub.hashlib.sha256(lifecycle.hub_units_before(
            "/home/fleet/fleet-pilot", "/usr/bin/python3", "/home/fleet")[0].encode()).hexdigest()[:16],
            "8c70f07f057f508f", "the unit file of a hub that the installer of 15 November 2026 made, by its hash")

    def test_a_text_of_before_is_known_by_its_own_folder_line(self):
        """lifecycle.unit_of_a_release: the folder that the text names leads to this code's folder, and the text is
        an earlier release's for that name, byte for byte."""
        home = tempfile.mkdtemp(prefix="fleet-unit-home-")
        self.addCleanup(shutil.rmtree, home, True)
        real, linked, other = (os.path.join(home, name) for name in ("my code 100%", "link", "other"))
        os.mkdir(real)
        os.mkdir(other)
        os.symlink(real, linked)
        for named in (real, linked):
            text = lifecycle.hub_units_before(named, self.PYTHON, home)[0]
            self.assertTrue(lifecycle.unit_of_a_release(text, real, self.PYTHON, home), named)
            self.assertTrue(lifecycle.unit_of_a_release(text, linked, self.PYTHON, home), named)
            self.assertFalse(lifecycle.unit_of_a_release(text, other, self.PYTHON, home), "another folder's unit")
            self.assertFalse(lifecycle.unit_of_a_release(text + "\n", real, self.PYTHON, home))
            self.assertFalse(lifecycle.unit_of_a_release(text, real, "/usr/bin/python3.12", home))
            self.assertFalse(lifecycle.unit_of_a_release(text, real, self.PYTHON, "/var" + home))
        self.assertFalse(lifecycle.unit_of_a_release(lifecycle.hub_unit(real, self.PYTHON, home), real, self.PYTHON,
                                                     home), "the text of today is no text of before")
        self.assertFalse(lifecycle.unit_of_a_release("", real, self.PYTHON, home))
        self.assertFalse(lifecycle.unit_of_a_release("[Service]\nExecStart=/usr/bin/true\n", real, self.PYTHON, home))
        text = lifecycle.hub_units_before(real, self.PYTHON, home)[0]
        folder = next(line for line in text.split("\n") if line.startswith("WorkingDirectory="))
        for other in (folder + "\nWorkingDirectory=/tmp", "WorkingDirectory=/tmp\n" + folder,     # two folder lines
                      "WorkingDirectory=code", "WorkingDirectory=", "WorkingDirectory=/tmp/a\0b"):
            self.assertFalse(lifecycle.unit_of_a_release(text.replace(folder, other), real, self.PYTHON, home), other)

    def test_the_texts_of_before_are_written_out_and_not_built_with_the_code_of_today(self):
        """The code that writes a unit changes with the next change of a unit. A text of before is a file on
        servers, which does not: so hub_units_before uses none of that code."""
        wanted = lifecycle.hub_units_before("/srv/caf\u00e9 100%/kit", self.PYTHON, self.HOME)
        with patch.object(lifecycle, "_unit", side_effect=AssertionError("built with today's frame")), \
                patch.object(lifecycle, "service_unit", side_effect=AssertionError("built with today's text")), \
                patch.object(lifecycle, "service_path", side_effect=AssertionError("built with today's PATH")):
            self.assertEqual(lifecycle.hub_units_before("/srv/caf\u00e9 100%/kit", self.PYTHON, self.HOME), wanted)
        self.assertIn('ExecStart="/usr/bin/python3" "/srv/caf\\u00e9 100%%/kit/hub.py"\n', wanted[0])

    def test_every_other_service_keeps_the_folder_as_the_installer_names_it(self):
        """Only the hub's unit takes the real path of its folder. The unit of the bridge and of an agent is byte
        for byte what `fleet.py service` wrote before (for a folder with no space), also where the folder is a
        link."""
        home = tempfile.mkdtemp(prefix="fleet-unit-home-")
        self.addCleanup(shutil.rmtree, home, True)
        real, linked = os.path.join(home, "code"), os.path.join(home, "link")
        os.mkdir(real)
        os.symlink(real, linked)

        def run(argv, **_kw):
            return subprocess.CompletedProcess(argv, 0, "yes\n" if argv[0] == "loginctl" else "", "")
        team = {"hub": {"machine": "hub"}, "addresses": {"hub": "127.0.0.1"},
                "agents": {"dev-lead": {"role": "lead", "machine": "hub", "runtime": "claude"}}}
        for name, start in (("channels", f'"{linked}/channels.py" "run"'),
                            ("dev-lead", f'"{linked}/fleet.py" "run" "dev-lead"')):
            with patch.object(fleet.sys, "platform", "linux"), patch.dict(os.environ, {"HOME": home}), \
                    patch.object(fleet, "KIT", linked), patch.object(fleet, "TEAM", team), \
                    patch.object(fleet.subprocess, "run", run), contextlib.redirect_stdout(io.StringIO()):
                fleet.cmd_service(argparse.Namespace(name=name))
            written = Path(home, ".config/systemd/user", f"fleet-{name}.service").read_text()
            wanted = unit_of_before(linked, sys.executable, home).replace("Founderizer hub", "Founderizer " + name) \
                .replace(f'"{linked}/hub.py"', start)
            if name == "channels":
                wanted = wanted.replace("TimeoutStopSec=15\n", "TimeoutStopSec=15\nUMask=0077\n")
            self.assertEqual(written, wanted, name)

    def test_the_installer_writes_the_text_that_the_hub_compares_its_unit_with(self):
        """`fleet.py service hub` writes lifecycle.hub_unit for the folder of its code, by that folder's real path:
        one text for the installer and for the hub's own check at its start, so that a new hub does not start a
        second time to write its unit."""
        home = tempfile.mkdtemp(prefix="fleet-unit-home-")
        self.addCleanup(shutil.rmtree, home, True)
        real, linked, asked = os.path.join(home, "code"), os.path.join(home, "link"), []
        os.mkdir(real)
        os.symlink(real, linked)

        def run(argv, **_kw):
            asked.append(argv)
            return subprocess.CompletedProcess(argv, 0, "yes\n" if argv[0] == "loginctl" else "", "")
        with patch.object(fleet.sys, "platform", "linux"), patch.dict(os.environ, {"HOME": home}), \
                patch.object(fleet, "KIT", linked), patch.object(fleet.subprocess, "run", run), \
                contextlib.redirect_stdout(io.StringIO()):
            fleet.cmd_service(argparse.Namespace(name="hub"))
        written = Path(home, ".config/systemd/user", lifecycle.HUB_UNIT).read_text()
        self.assertEqual(written, lifecycle.hub_unit(real, sys.executable, home))
        self.assertEqual(written, lifecycle.service_unit("hub", [sys.executable, "-m", "hub"], os.path.realpath(real),
                                                         lifecycle.service_path(home)))
        self.assertIn("WorkingDirectory=" + os.path.realpath(real) + "\n", written)
        self.assertEqual(asked[1:], [["systemctl", "--user", "daemon-reload"],
                                     ["systemctl", "--user", "enable", "fleet-hub.service"]])


# ---------------------------------------------------------------- a hub that an earlier release installed

class UnitFollowsCode(unittest.TestCase):
    """hub.unit_follows_code, at the start of a hub: a release moves the code and no installer runs again, so the hub
    writes its own unit over the text of an earlier release, and its service starts again with it. systemctl and
    systemd-run are a table here: what a real systemd does with the unit is the proof on a real server, not this
    file's (16 November 2026, a server with 1 GB: the move, a plain restart, an operator's line, a drop-in file, a
    folder that cannot be written, a unit that systemd did not read, and a start after one that ended in its
    proof)."""

    def setUp(self):
        self.home = os.path.realpath(tempfile.mkdtemp(prefix="fleet-unit-follows-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        self.path = Path(self.home, ".config/systemd/user", lifecycle.HUB_UNIT)
        self.path.parent.mkdir(parents=True)
        Path(self.home, ".fleet").mkdir()
        self.did = Path(self.home, ".fleet", hub.UNIT_STATE)
        self.named = os.path.dirname(os.path.abspath(hub.__file__))     # the folder as this run names it
        self.file = os.path.realpath(hub.__file__)
        self.kit = os.path.dirname(self.file)
        self.wanted = lifecycle.hub_unit(self.kit, sys.executable, self.home)
        self.before = lifecycle.hub_units_before(self.named, sys.executable, self.home)[0]
        self.mark = hub.hashlib.sha256(self.wanted.encode()).hexdigest()
        self.path.write_text(self.before)
        self.asked, self.answers, self.main_pid, self.seen, self.broken = [], {}, os.getpid(), {}, None
        self.check = self.path.with_name(hub.UNIT_CHECK)       # the new text under a name that nothing starts
        self.fragment, self.drop_ins = str(self.path), ""
        # the advice, as a line that works word for word as root (measured: without that folder the command fails)
        try:
            user = pwd.getpwuid(os.getuid()).pw_name
        except KeyError:            # a test run under a number that the system has no name for
            user = os.environ.get("USER") or "fleet"
        as_user = f"runuser -u {user} -- env XDG_RUNTIME_DIR=/run/user/{os.getuid()}"
        self.advice = (f"run as root: {as_user} {shlex.quote(sys.executable)} "
                       f"{shlex.quote(os.path.join(self.kit, 'fleet.py'))} service hub && {as_user} systemctl --user "
                       f"restart fleet-hub")
        self.proof = (0, self.file + "\n", "")          # what the new start line says of itself
        self.by_path()
        for one in (patch.dict(os.environ, {"HOME": self.home}), patch.object(hub.sys, "platform", "linux"),
                    patch.object(hub.sys, "argv", [hub.__file__])):
            one.start()
            self.addCleanup(one.stop)

    def by_path(self):
        """This process as the unit of before starts it."""
        self.words = [sys.executable, os.path.join(self.named, "hub.py")]

    def as_module(self):
        self.words = [sys.executable, "-m", "hub"]

    PROOF = "the proof"
    SHOW = ["show", "-p", "MainPID", "-p", "FragmentPath", "-p", "DropInPaths", "fleet-hub.service"]
    CHECK = ["show", "-p", "LoadState", "--value", "fleet-hub_unit_check.service"]
    DROP_INS = ["show", "-p", "DropInPaths", "--value", "fleet-hub.service"]     # once more, after systemd read
    LOADED = ["show", "-p", "LoadState", "--value", "fleet-hub.service"]         # the unit's own name, after the write
    RELOAD, RESTART = ["daemon-reload"], ["restart", "fleet-hub.service"]
    ASKED = [SHOW, PROOF, RELOAD, CHECK, DROP_INS]      # each question before the unit's file changes
    MOVE = ASKED + [RELOAD, LOADED, RESTART]
    UNREAD = [SHOW, RELOAD, LOADED, RESTART]

    def run_it(self, argv, **kw):
        """The table. The code under test takes every error of a call as "the hub runs as it started", so what this
        table refuses is kept, and started() raises it."""
        try:
            return self.answer(argv, **kw)
        except AssertionError as e:
            self.broken = self.broken or e
            raise

    def answer(self, argv, **kw):
        self.assertEqual((kw.get("stdin"), kw.get("capture_output"), kw.get("text"), kw.get("errors")),
                         (subprocess.DEVNULL, True, True, "replace"))
        if argv[0] == "systemd-run":
            # the new start line with the word of the proof: in a unit of its own (a scope, which needs no D-Bus of
            # the user), in the hub's folder, as the system's first choice when memory runs out
            self.assertEqual(argv[1:], ["--user", "--scope", "--quiet", "--collect", "/bin/sh", "-c",
                                        'echo 1000 > /proc/self/oom_score_adj; exec "$@"', "sh",
                                        sys.executable, "-m", "hub", "--start-check"])
            self.assertEqual((kw.get("cwd"), kw.get("timeout")), (self.kit, hub.START_CHECK_WAIT))
            self.asked.append(self.PROOF)
            self.seen[self.PROOF] = (self.path.read_text(), self.record())
            if isinstance(self.proof, BaseException):
                raise self.proof
            return subprocess.CompletedProcess(argv, *self.proof)
        self.assertEqual(argv[:2], ["systemctl", "--user"])
        self.assertEqual(kw.get("timeout"), hub.UNIT_WAIT)
        words = argv[2:]
        self.asked.append(words)
        if words == self.CHECK:     # does systemd take the new text, which is there under the other name
            self.seen["LoadState"] = (self.path.read_text(), self.record(), self.check.read_text())
            return subprocess.CompletedProcess(argv, *self.answers.get("LoadState", (0, "loaded\n")), "")
        if words == self.DROP_INS:  # what systemd holds after it read its files again
            self.seen["DropIns"] = (self.path.read_text(), self.check.exists())
            return subprocess.CompletedProcess(argv, *self.answers.get("DropIns", (0, self.drop_ins + "\n")), "")
        if words == self.LOADED:    # and does it hold the unit's own file as loaded
            return subprocess.CompletedProcess(argv, *self.answers.get("Loaded", (0, "loaded\n")), "")
        self.seen[words[0]] = (self.path.read_text(), self.record())
        if words == self.RELOAD and isinstance(self.answers.get("daemon-reload"), list):
            code, says = self.answers["daemon-reload"].pop(0)       # an answer for each call, in their order
            return subprocess.CompletedProcess(argv, code, "", says)
        if words[0] == "show":      # systemd prints the three in an order of its own
            code, says = self.answers.get("show", (0, f"FragmentPath={self.fragment}\nDropInPaths={self.drop_ins}\n"
                                                      f"MainPID={self.main_pid}\n"))
            return subprocess.CompletedProcess(argv, code, says, "")
        code, says = self.answers.get(words[0], (0, ""))
        return subprocess.CompletedProcess(argv, code, "", says)

    def started(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()), \
                patch.object(hub, "command_line", lambda: self.words):
            says = hub.unit_follows_code(run=self.run_it)
        if self.broken:
            raise self.broken
        return says, out.getvalue()

    def kept(self):
        return json.loads(self.did.read_text())

    def record(self):
        """The record as it is at this moment: what it says, its text when that is no JSON, None when it is not
        there."""
        try:
            return self.kept()
        except FileNotFoundError:
            return None
        except ValueError:
            return self.did.read_text()

    NOTHING = {"proving": None, "restarted": None}

    def test_the_text_of_before_is_another_text(self):
        self.assertNotEqual(self.before, self.wanted)
        self.assertIn('"-m" "hub"', self.wanted)
        self.assertIn(self.before, lifecycle.hub_units_before(self.named, sys.executable, self.home))
        self.assertTrue(lifecycle.unit_of_a_release(self.before, self.kit, sys.executable, self.home))

    def test_a_hub_that_started_by_its_path_writes_its_unit_and_its_service_starts_again(self):
        """The calls in their order: is this process the unit's own, does the new start line run this hub, read the
        file again, start again. The real restart ends this process; the table answers, so the function says that
        the service did not start."""
        says, printed = self.started()
        self.assertEqual(self.asked, self.MOVE)
        self.assertEqual(self.seen[self.PROOF], (self.before, {"proving": self.mark, "restarted": None}),
                         "the proof comes before the file changes, and its record before the proof")
        self.assertEqual(self.seen["LoadState"], (self.before, None, self.wanted),
                         "systemd says that it takes the new text, under another name, before the unit's file changes")
        self.assertFalse(self.check.exists(), "the file of that question is gone")
        self.assertEqual(self.seen["DropIns"], (self.before, False),
                         "and the drop-ins are asked again before the write")
        self.assertEqual(self.seen["daemon-reload"], (self.wanted, None),
                         "systemd reads the file after it has the new text, and the proof's record ended")
        self.assertEqual(self.seen["restart"], (self.wanted, {"proving": None, "restarted": self.mark}),
                         "no restart without its record")
        self.assertEqual(self.path.read_text(), self.wanted)
        self.assertFalse(Path(str(self.path) + ".new").exists())
        self.assertIn("has the text of this code now", printed)
        self.assertIn("did not restart with its unit", says)

    def test_the_file_keeps_its_mode(self):
        os.chmod(self.path, 0o750)                      # a mode that no new file gets by itself
        self.started()
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o750)

    def test_the_new_text_is_on_the_disk_before_it_takes_the_unit_s_name(self):
        """A stop of the server after the move must find a whole unit: an empty one is a hub that does not start."""
        did, sync, replace = [], os.fsync, os.replace

        def synced(fd):
            did.append("sync")
            return sync(fd)

        def replaced(src, dst):
            did.append(("replace", str(dst)))
            return replace(src, dst)
        with patch.object(hub.os, "fsync", synced), patch.object(hub.os, "replace", replaced):
            self.started()
        self.assertIn("sync", did)
        self.assertLess(did.index("sync"), did.index(("replace", str(self.path))))
        self.assertEqual(did.count(("replace", str(self.path))), 1)

    def test_the_line_about_the_move_leaves_the_process_before_systemd_ends_it(self):
        said = []
        with patch("builtins.print", lambda *words, **kw: said.append((" ".join(map(str, words)), kw))):
            hub.unit_follows_code(run=self.run_it)
        self.assertEqual([kw.get("flush") for words, kw in said if "has the text of this code" in words], [True])

    def test_the_start_by_the_new_unit_ends_the_record_and_each_later_start_asks_nothing(self):
        self.started()
        self.asked.clear()
        self.as_module()
        self.assertEqual(self.started(), (None, ""))
        self.assertEqual(self.asked, [self.SHOW])       # the record is the unit's own process's to end
        self.assertFalse(self.did.exists(), "a start that finds the unit in order ends the record of what was done")
        self.assertEqual(self.path.read_text(), self.wanted)
        self.asked.clear()
        self.assertEqual(self.started(), (None, ""))
        self.assertEqual(self.asked, [], "a start with the unit in order and no record asks systemd nothing")

    def test_a_process_that_is_not_the_main_process_of_the_unit_changes_nothing(self):
        """A test's hub, a hub that somebody starts by hand, on a server whose user has the hub's unit: not the
        unit, and not the record of the hub that is the unit's own."""
        self.main_pid = os.getpid() + 1
        self.assertEqual(self.started(), (None, ""))
        self.assertEqual(self.asked, [self.SHOW])
        self.assertEqual(self.path.read_text(), self.before)
        self.assertFalse(self.did.exists())
        self.path.write_text("[Service]\nExecStart=/usr/bin/true\n")        # also for a text that nobody knows
        self.assertEqual(self.started(), (None, ""))
        record = json.dumps({"proving": None, "restarted": self.mark})
        self.did.write_text(record)
        self.path.write_text(self.wanted)               # in order, started by hand as a module
        self.as_module()
        self.assertEqual(self.started(), (None, ""))
        self.assertEqual(self.did.read_text(), record)

    def test_systemd_that_does_not_answer_changes_nothing(self):
        """An answer with no number of a process, or with another number: not the unit's own process, and nothing
        is said. An answer with a failed status (even with this process's number), no answer in time, no program:
        nothing says whose process this is, so nothing changes, and the hub says that when its unit is not in
        order."""
        mine = f"MainPID={os.getpid()}\nFragmentPath={self.path}\nDropInPaths=\n"
        self.did.write_text("{}")                       # a start with the unit in order asks too, with a record
        for answer in ((0, ""), (0, mine.replace(str(os.getpid()), "0")), (0, str(os.getpid()))):
            with self.subTest(answer=answer):
                self.asked.clear()
                self.answers["show"] = answer
                self.assertEqual(self.started(), (None, ""))
                self.assertEqual(self.asked, [self.SHOW])
        self.asked.clear()
        self.answers["show"] = (1, mine)
        says, printed = self.started()
        self.assertEqual(self.asked, [self.SHOW])
        self.assertIn("systemd did not say if this process is the hub's service", says)
        self.assertEqual(printed, "")
        for error in (subprocess.TimeoutExpired(["systemctl"], hub.UNIT_WAIT), FileNotFoundError(2, "no systemctl")):
            def run(argv, error=error, **kw):
                raise error
            with self.subTest(error=error), contextlib.redirect_stdout(io.StringIO()), \
                    patch.object(hub, "command_line", lambda: self.words):
                self.assertIn("did not change its unit", hub.unit_follows_code(run=run))
        self.assertEqual((self.path.read_text(), self.did.read_text()), (self.before, "{}"))
        self.path.write_text(self.wanted)               # the unit in order: nothing to say
        self.as_module()
        self.assertEqual(self.started(), (None, ""))
        self.assertEqual(self.did.read_text(), "{}")

    def test_a_hub_with_an_argument_keeps_its_unit(self):
        """Somebody wrote that unit for other records or another port: the standard text would move the hub. One
        argument is an argument."""
        for argv in ([hub.__file__, "--port", "9000"], [hub.__file__, "--restore"]):
            with self.subTest(argv=argv), patch.object(hub.sys, "argv", argv):
                self.assertEqual(self.started(), (None, ""))
        self.assertEqual(self.asked, [])
        self.assertEqual(self.path.read_text(), self.before)

    def test_no_unit_or_another_system_asks_nothing(self):
        with patch.object(hub.sys, "platform", "darwin"):
            self.assertEqual(self.started(), (None, ""))
        self.path.write_bytes(b"\xff\xfe[Service]\n")       # a file that is no text
        self.assertEqual(self.started(), (None, ""))
        self.path.unlink()
        self.assertEqual(self.started(), (None, ""))
        self.assertEqual(self.asked, [])
        self.assertFalse(self.path.exists())

    def test_a_unit_that_no_release_wrote_is_left_as_it_is(self):
        """An operator's own line in the unit (a proxy, a memory limit), or one more line break at its end: the
        hub's text would take the setting away, and the hub could then be a hub that reaches nothing. It says so
        and leaves the file. The same for the text of today with another folder, program or home in it."""
        proxy = self.before.replace("Restart=always\n", 'Environment="HTTPS_PROXY=http://proxy.example.com:3128"\n'
                                                        "Restart=always\n")
        other_home = lifecycle.hub_unit(self.kit, sys.executable, "/var/home/fleet")
        for text in (proxy, self.before + "\n", self.before.replace("TimeoutStopSec=15", "TimeoutStopSec=30"),
                     other_home, ""):
            with self.subTest(text=text[-80:]):
                self.asked.clear()
                self.path.write_text(text)
                says, printed = self.started()
                self.assertEqual(self.asked, [self.SHOW])
                self.assertIn("does not have the text that an earlier release of Founderizer wrote", says)
                self.assertIn("Keep a setting of your own in a drop-in file", says)
                self.assertTrue(says.endswith(self.advice), "the commands are the end of the line: nothing after them")
                self.assertIn(self.advice, says)
                self.assertEqual((self.path.read_text(), printed), (text, ""))
                self.assertFalse(self.did.exists())

    def test_a_unit_with_a_drop_in_file_is_left_as_it_is(self):
        """A drop-in file can change the folder or the start line, so the proof would not prove what systemd then
        starts: the unit with the new line could be a hub that never starts. The hub leaves such a unit, also when
        only systemd's read of the file is missing, and says what to do."""
        drop_in = str(self.path) + ".d/own.conf"
        prefix = str(self.path.parent / "fleet-.service.d/all.conf")    # for each service whose name begins so
        every = str(self.path.parent / "service.d/all.conf")            # the operator's, for each service
        for text in (self.before, self.wanted):
            for given in (drop_in, "/usr/lib/systemd/user/service.d/10-timeout-abort.conf " + prefix, every,
                          "/etc/systemd/user/service.d/limits.conf"):
                with self.subTest(text=text[-60:], given=given):
                    self.asked.clear()
                    self.path.write_text(text)
                    self.drop_ins = given
                    says, printed = self.started()
                    self.assertEqual(self.asked, [self.SHOW])
                    self.assertIn("has a drop-in file (" + given.split()[-1] + ")", says)
                    self.assertIn(self.advice, says)
                    self.assertEqual((self.path.read_text(), printed), (text, ""))
                    self.assertFalse(self.did.exists())
        for given in ("/usr/lib/systemd/user/fleet-hub.service.d/x.conf",      # a package's, but for the hub itself
                      "/usr/lib/systemd/user/fleet-.service.d/x.conf", "/usr/local/lib/systemd/user/service.d/a.conf",
                      "/usr/share/systemd/user/service.d/a.conf", "/run/user/1000/systemd/user/service.d/a.conf"):
            with self.subTest(given=given):
                self.asked.clear()
                self.path.write_text(self.before)
                self.drop_ins = given
                self.assertIn("has a drop-in file (" + given + ")", self.started()[0])
                self.assertEqual((self.asked, self.path.read_text()), ([self.SHOW], self.before))
        self.drop_ins = "/usr/lib/systemd/user/service.d/10-timeout-abort.conf /lib/systemd/user/service.d/a.conf"
        self.asked.clear()
        self.path.write_text(self.before)
        self.started()
        self.assertEqual(self.asked, self.MOVE, "a package's drop-in for every service does not count")

    def test_a_drop_in_file_that_systemd_reads_only_now_stops_the_move_too(self):
        """Somebody wrote a drop-in file and ran no daemon-reload: systemd does not hold it, so the first answer
        names none. The hub's own reload, for its question about the new text, makes systemd read it. So the hub
        asks for the drop-ins again, after that reload and before it writes."""
        drop_in = str(self.path) + ".d/override.conf"
        self.answers["DropIns"] = (0, drop_in + "\n")
        says, printed = self.started()
        self.assertEqual(self.asked, self.ASKED)
        self.assertIn("has a drop-in file (" + drop_in + ")", says)
        self.assertEqual((self.path.read_text(), printed, self.record()), (self.before, "", None))
        self.answers["DropIns"] = (1, "")
        self.asked.clear()
        says, _printed = self.started()
        self.assertEqual(self.asked, self.ASKED)
        self.assertIn("systemd did not say which drop-in files the hub's unit has", says)
        self.assertEqual(self.path.read_text(), self.before)

    def test_no_restart_into_a_unit_that_systemd_does_not_hold_as_loaded(self):
        """After the write and the read, the unit's own name: a restart of a unit that systemd refuses fails and
        leaves the process (measured), and the line must not say that the next start uses the unit."""
        for answer, word in (((0, "bad-setting\n"), "(bad-setting)"), ((1, ""), "(1)"), ((1, "loaded\n"), "(loaded)")):
            with self.subTest(answer=answer):
                self.path.write_text(self.before)
                self.asked.clear()
                self.answers["Loaded"] = answer
                says, printed = self.started()
                self.assertEqual(self.asked, self.ASKED + [self.RELOAD, self.LOADED])
                self.assertIn("systemd does not hold the unit", says)
                self.assertIn(word, says)
                self.assertIn("The hub did not restart.", says)
                self.assertEqual((printed, self.record()), ("", None))
        del self.answers["Loaded"]                      # the file has the text: the next start asks for the read
        self.asked.clear()
        self.started()
        self.assertEqual(self.asked, self.UNREAD)

    def test_a_file_of_the_question_that_a_start_left_is_removed_by_the_unit_s_own_process(self):
        """A start that was ended between its write of that file and its removal. The next start of the hub's own
        service removes it, also when the unit is in order by then; another process does not."""
        self.path.write_text(self.wanted)
        self.as_module()
        self.check.write_text(self.wanted)
        self.main_pid = os.getpid() + 1
        self.assertEqual(self.started(), (None, ""))
        self.assertTrue(self.check.exists())
        self.main_pid = os.getpid()
        self.asked.clear()
        self.assertEqual(self.started(), (None, ""))
        self.assertEqual((self.asked, self.check.exists()), ([self.SHOW], False))
        self.asked.clear()
        self.assertEqual(self.started(), (None, ""))
        self.assertEqual(self.asked, [])
        self.path.write_text(self.before + "\n")        # also at a start that ends with a line and changes nothing
        self.by_path()
        self.check.write_text(self.wanted)
        self.assertIn("does not have the text", self.started()[0])
        self.assertFalse(self.check.exists())

    def test_the_file_of_the_question_is_removed_when_its_write_fails(self):
        """The disk is full: the file is there, empty, and the write fails. The file goes, the line is true, and
        nothing is asked of systemd about a text that is not there."""
        real_open = open

        def opened(file, *args, **kw):
            f = real_open(file, *args, **kw)
            if str(file) == str(self.check):
                f.close()
                raise OSError(28, "No space left on device")
            return f
        with patch("builtins.open", opened):
            says, _printed = self.started()
        self.assertEqual(self.asked, [self.SHOW, self.PROOF])
        self.assertIn(f"The hub could not write {self.check}", says)
        self.assertFalse(self.check.exists())
        self.assertEqual(self.path.read_text(), self.before)

    def test_a_unit_that_is_a_link_or_that_systemd_reads_from_another_place_is_left(self):
        self.fragment = "/etc/systemd/user/fleet-hub.service"
        says, _printed = self.started()
        self.assertEqual(self.asked, [self.SHOW])
        self.assertIn("systemd reads the hub's unit from another file", says)
        self.assertIn(self.fragment, says)
        self.assertNotIn("fleet.py service hub", says, "that command writes a file that systemd does not read here")
        self.fragment = ""
        self.assertIn("systemd reads the hub's unit from another file (none)", self.started()[0])
        real = self.path.with_name("the-real-unit")
        self.path.rename(real)
        self.path.symlink_to(real)
        self.fragment = str(real)                       # systemd names the file that the link leads to
        self.asked.clear()
        self.assertIn("is a link", self.started()[0])
        self.assertEqual(self.asked, [self.SHOW])
        self.assertTrue(self.path.is_symlink())
        self.assertEqual(real.read_text(), self.before)

    def test_the_folder_of_a_link_is_the_text_of_before_by_its_name_and_the_new_text_by_its_real_path(self):
        """The installer of before wrote the folder as it named it, and the hub that it starts by that path reads
        the same name. The new text takes the real path, which a start in that folder reads."""
        link = os.path.join(self.home, "kit")
        os.symlink(self.kit, link)
        self.path.write_text(unit_of_before(link, sys.executable, self.home))
        self.words = [sys.executable, os.path.join(link, "hub.py")]
        with patch.object(hub, "__file__", os.path.join(link, "hub.py")):
            self.started()
        self.assertEqual(self.asked, self.MOVE)
        self.assertEqual(self.path.read_text(), self.wanted)
        self.assertIn("WorkingDirectory=" + self.kit + "\n", self.wanted)
        # An installer of before wrote its text again, with the link, while the hub runs as a module, which names
        # its folder by the real path: the text's own folder line says that it is this code's folder.
        self.path.write_text(unit_of_before(link, sys.executable, self.home))
        self.did.unlink()
        self.as_module()
        self.asked.clear()
        self.started()
        self.assertEqual(self.asked, self.MOVE)
        self.assertEqual(self.path.read_text(), self.wanted)

    def test_a_start_line_that_does_not_run_this_hub_leaves_the_unit_of_before(self):
        """The proof, in each way that it can fail: the line ends badly, it runs another file (a package named hub
        in the folder), it says nothing, systemd makes no scope, the program is not there, the system ends it, it
        does not end in its time. A unit whose start line does not run is a hub that is gone, so the file keeps its
        text, nothing is read again and nothing starts again. The next start tries again."""
        other = os.path.join(self.kit, "hub", "__main__.py")
        for proof, word in (((1, "", "No module named hub"), "No module named hub"),
                            ((0, other + "\n", ""), other),
                            ((0, "", ""), "no output"),
                            ((1, "", "Failed to connect to bus: No medium found"), "Failed to connect to bus"),
                            ((127, "", "sh: 1: exec: python3: not found"), "status 127"),
                            ((137, "", ""), "status 137"),
                            ((137, self.file + "\n", ""), "status 137"),        # the right words and a bad end
                            ((-9, "", ""), "status -9: the system ended it, for example for lack of memory"),
                            ((-15, "", ""), "status -15: the system ended it (SIGTERM)"),
                            (subprocess.TimeoutExpired(["systemd-run"], hub.START_CHECK_WAIT), "timed out"),
                            (FileNotFoundError(2, "No such file or directory", "systemd-run"), "No such file")):
            with self.subTest(proof=proof):
                self.asked.clear()
                self.proof = proof
                says, printed = self.started()
                self.assertEqual(self.asked, [self.SHOW, self.PROOF])
                self.assertIn("The test of the new start line", says)
                self.assertIn(word, says)
                self.assertIn("did not change the unit", says)
                self.assertEqual((self.path.read_text(), printed), (self.before, ""))
                self.assertIsNone(self.record(), "this process is here, so the proof ended")
        self.asked.clear()
        self.proof = (0, "a line of an import\n" + self.file + "\n", "")      # its last line is the answer
        self.started()
        self.assertEqual(self.asked, self.MOVE)

    def test_a_start_that_ended_in_its_proof_is_not_followed_by_a_second_proof_at_once(self):
        """The system ended the hub while its proof ran: the record still says that a proof runs. A start that ran
        the proof again could end the same way at every start. So this start runs as it started, and the one after
        it tries again."""
        self.did.write_text(json.dumps({"proving": self.mark, "restarted": None}))
        says, printed = self.started()
        self.assertEqual(self.asked, [self.SHOW])
        self.assertIn("ended before its test of the new start line", says)
        self.assertIn("The next start tests the line again", says)
        self.assertEqual((self.path.read_text(), printed), (self.before, ""))
        self.assertIsNone(self.record())
        self.asked.clear()
        self.started()
        self.assertEqual(self.asked, self.MOVE)

    def test_a_proof_of_another_text_does_not_hold_this_one(self):
        self.did.write_text(json.dumps({"proving": "0" * 64, "restarted": "1" * 64}))
        self.started()
        self.assertEqual(self.asked, self.MOVE)

    def test_a_record_that_cannot_be_read_is_an_empty_one(self):
        for text in ("", "not JSON", "[]", '{"proving": 3}', '"x"', "null"):
            with self.subTest(text=text):
                self.path.write_text(self.before)
                self.did.write_text(text)
                self.asked.clear()
                self.started()
                self.assertEqual(self.asked, self.MOVE)

    def test_a_text_restarts_the_hub_one_time(self):
        """After the restart for a text, a start that is still not as that text says does nothing more: something
        is not as this code reads it (another program wrote the file back, or systemd started the hub another
        way). No start can restart the hub without an end."""
        self.started()
        self.asked.clear()
        for text in (self.before, self.wanted):         # the file written back, and the file in order with this start
            with self.subTest(text=text[-60:]):         # still by the path
                self.path.write_text(text)
                self.asked.clear()
                says, printed = self.started()
                self.assertEqual(self.asked, [self.SHOW])
                self.assertIn("restarted its service one time", says)
                self.assertIn(self.advice, says)
                self.assertEqual((self.path.read_text(), printed), (text, ""))
        own = self.before.replace("Restart=always\n", 'Environment="HTTPS_PROXY=http://proxy.example.com:3128"\n'
                                                      "Restart=always\n")
        self.path.write_text(own)                       # the operator wrote a line meanwhile: the line about that,
        says, _printed = self.started()                 # whose advice keeps the setting, comes first
        self.assertIn("does not have the text that an earlier release of Founderizer wrote", says)
        self.assertIn("drop-in", says)
        self.assertEqual(self.path.read_text(), own)
        self.path.write_text(self.before)               # and so does the line about a drop-in file, and about a link
        self.drop_ins = str(self.path) + ".d/own.conf"
        self.assertIn("has a drop-in file", self.started()[0])
        self.drop_ins, self.fragment = "", "/etc/systemd/user/fleet-hub.service"
        self.assertIn("systemd reads the hub's unit from another file", self.started()[0])
        self.fragment = str(self.path)
        self.path.write_text(self.wanted)
        self.as_module()                                # and a start that finds all in order ends that
        self.assertEqual(self.started(), (None, ""))
        self.by_path()
        self.path.write_text(self.before)
        self.asked.clear()
        self.started()
        self.assertEqual(self.asked, self.MOVE)

    def test_a_unit_that_systemd_did_not_read_is_read_and_the_service_starts_again(self):
        """The file has the text and this start is by the path: a stop came between the write and the
        daemon-reload, so systemd still holds the unit of before. The hub asks for the read and the restart, with
        no proof and no write, one time."""
        self.path.write_text(self.wanted)
        says, printed = self.started()
        self.assertEqual(self.asked, self.UNREAD)
        self.assertEqual(self.seen["restart"][1], {"proving": None, "restarted": self.mark})
        self.assertIn("systemd read it again", printed)
        self.assertEqual(self.path.read_text(), self.wanted)
        self.asked.clear()
        says, _printed = self.started()                 # still by the path after it: no second restart
        self.assertEqual(self.asked, [self.SHOW])
        self.assertIn("restarted its service one time", says)

    def test_a_start_line_that_nothing_says_or_another_name_of_the_program_is_no_reason_to_restart(self):
        self.path.write_text(self.wanted)
        for words in (None, ["python3", "-m", "hub"], ["/usr/bin/python3.12", "-m", "hub"]):
            with self.subTest(words=words):
                self.words = words
                self.assertEqual(self.started(), (None, ""))
        self.assertEqual(self.asked, [])

    def test_the_words_of_this_start_are_the_ones_that_python_keeps(self):
        """Python 3.10 and later keep them, and each system that a hub runs on has such a Python. An older one
        keeps none, and then nothing says that the hub did not start by its unit."""
        with patch.object(hub.sys, "orig_argv", ["/usr/bin/python3", "-m", "hub"], create=True):
            self.assertEqual(hub.command_line(), ["/usr/bin/python3", "-m", "hub"])
        with patch.object(hub.sys, "orig_argv", None, create=True):
            self.assertIsNone(hub.command_line())

    def test_a_reload_that_fails_starts_nothing_again_and_the_next_start_asks_for_the_read(self):
        """The reload after the write: the file keeps this code's text, written whole. systemd holds the unit of
        before, so the next start is by the path again: it asks for the read, with no second proof and no second
        write."""
        self.answers["daemon-reload"] = [(0, ""), (1, "Failed to connect to bus: No medium found")]
        says, printed = self.started()
        self.assertEqual(self.asked, self.ASKED + [self.RELOAD])
        self.assertEqual(self.path.read_text(), self.wanted)
        self.assertIsNone(self.record())
        self.assertIn("systemd did not read the unit", says)
        self.assertIn("No medium found", says)
        self.assertEqual(printed, "")
        del self.answers["daemon-reload"]
        self.asked.clear()
        self.started()
        self.assertEqual(self.asked, self.UNREAD)

    def test_a_text_that_systemd_does_not_take_is_not_written(self):
        """A unit whose text systemd refuses never starts again (LoadState bad-setting; measured: a restart of such
        a unit fails and leaves the process). So systemd says that it takes the new text before the unit's file
        changes: the text is there under another name, which nothing starts. Each other answer, and no answer,
        leaves the unit's file as it is, and the file of the question is gone."""
        for answers, word in (({"LoadState": (0, "bad-setting\n")}, "(bad-setting)"),
                              ({"LoadState": (0, "not-found\n")}, "(not-found)"),
                              ({"LoadState": (0, "")}, "(0)"),
                              ({"LoadState": (1, "loaded\n")}, "(loaded)"),
                              ({"daemon-reload": (1, "Failed to connect to bus")}, "(Failed to connect to bus)")):
            with self.subTest(answers=answers):
                self.asked.clear()
                self.answers = dict(answers)
                says, printed = self.started()
                self.assertEqual(self.asked, [self.SHOW, self.PROOF, self.RELOAD, self.CHECK][:3 + len(
                    [1 for key in answers if key == "LoadState"])], "and no question after the one that failed")
                self.assertIn("systemd did not take the new text of the hub's unit" if "LoadState" in answers
                              else "systemd did not read its units again", says)      # it said nothing of the text
                self.assertIn(word, says)
                self.assertIn(f"The hub did not change the unit {self.path}.", says)
                self.assertEqual((self.path.read_text(), printed, self.record()), (self.before, "", None))
                self.assertFalse(self.check.exists())
        self.answers = {}
        self.check.mkdir()                              # the file of the question cannot be written
        self.asked.clear()
        says, _printed = self.started()
        self.assertEqual(self.asked, [self.SHOW, self.PROOF])
        self.assertIn(f"The hub could not write {self.check}", says)
        self.assertIn("did not ask systemd", says)
        self.assertEqual(self.path.read_text(), self.before)
        self.check.rmdir()
        self.asked.clear()
        self.started()
        self.assertEqual(self.asked, self.MOVE)

    def test_a_unit_that_cannot_be_written_stays_whole_and_the_next_start_tries_again(self):
        """Something is in the way of the new file (here a folder with its name; on a server a full disk or a
        folder that cannot be written): the unit keeps the text of before, whole."""
        in_the_way = Path(str(self.path) + ".new")
        in_the_way.mkdir()
        says, _printed = self.started()
        self.assertEqual(self.asked, self.ASKED)
        self.assertIn("could not write the unit", says)
        self.assertEqual(self.path.read_text(), self.before)
        self.assertIsNone(self.record())
        in_the_way.rmdir()
        self.asked.clear()
        self.started()
        self.assertEqual(self.asked, self.MOVE)

    def test_no_record_no_proof_and_no_restart(self):
        """The record comes first: with no place to write that a proof runs, a start that ends in its proof would
        prove again at the next start; and with no place to write the restart, a second restart could follow."""
        Path(str(self.did) + ".new").mkdir()            # in the way of the record
        says, _printed = self.started()
        self.assertEqual(self.asked, [self.SHOW])
        self.assertIn("It did not change the unit", says)
        self.assertEqual(self.path.read_text(), self.before)
        self.path.write_text(self.wanted)               # the text is there, systemd did not read it
        self.asked.clear()
        says, printed = self.started()
        self.assertEqual(self.asked, [self.SHOW, self.RELOAD, self.LOADED])
        self.assertIn("does not restart by itself", says)
        self.assertEqual(printed, "")

    def test_an_error_in_the_check_never_stops_a_start(self):
        with patch.object(lifecycle, "hub_unit", side_effect=RuntimeError("no")):
            says, _printed = self.started()
        self.assertIn("ended with an error", says)
        self.assertEqual(self.path.read_text(), self.before)
        self.proof = MemoryError()                      # in the middle of the proof: its record ends all the same
        says, _printed = self.started()
        self.assertEqual(self.asked, [self.SHOW, self.PROOF])
        self.assertIn("ended with an error", says)
        self.assertEqual((self.path.read_text(), self.record()), (self.before, None))

    def test_the_new_start_line_says_which_file_it_runs(self):
        """The real thing: `python3 -m hub --start-check` in the code's folder, which is the unit's start line with
        the word of the proof. It names this hub.py and ends well, and it starts no hub."""
        done = subprocess.run([*lifecycle.hub_start(sys.executable), hub.START_CHECK], cwd=self.kit,
                              capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
        self.assertEqual((done.returncode, done.stdout.split("\n")[-2:]), (0, [self.file, ""]), done.stderr[-300:])
        source = inspect.getsource(hub.main)
        check = source[source.index("[START_CHECK]"):source.index("diagnostics.code_id()")]
        self.assertIn("print(os.path.realpath(__file__))", check)
        self.assertIn("return 0", check)
        self.assertLess(source.index("compiled_checked(code_started())"), source.index("[START_CHECK]"))

    def test_the_hub_does_it_first_at_its_start_and_only_as_its_service_starts_it(self):
        """In main(): after the options are read (a hub with --restore or --check-schema is no service start) and
        before the hub takes its records, so that the process that systemd ends holds nothing. What it says goes
        to the journal at once and to the hub's log when the records are open."""
        source = inspect.getsource(hub.main)
        first, lock = source.index("unit_says = unit_follows_code()"), source.index("hub_lock(db_path)")
        self.assertLess(source.index("return restore_by_hand("), first)
        self.assertLess(source.index('sys.argv[1] == "--check-schema"'), first)
        self.assertLess(first, lock)
        self.assertLess(first, source.index("sqlite3.connect(db_path"))
        self.assertLess(first, source.index('print("WARNING: " + unit_says, flush=True)'))
        self.assertLess(source.index("sqlite3.connect(db_path"), source.index('log("hub", unit_says)'))


class Compiled(unittest.TestCase):
    """hub.compiled_checked: a compiled file that Python cannot read makes its import fail at every start, and a hub
    that runs as a module reads the one of hub.py. A start removes such a file when it wrote it itself, so that the
    next start compiles again."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="fleet-compiled-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        (self.root / "good.py").write_text("VALUE = 1\n")
        (self.root / "cut.py").write_text("VALUE = [n for n in range(100)]\n" * 40)
        (self.root / "zeros.py").write_text("VALUE = 3\n")
        import py_compile
        self.folder = self.root / "__pycache__"         # the names that Python gives with no option of its own
        tag = sys.implementation.cache_tag
        self.made = {name: Path(py_compile.compile(str(self.root / (name + ".py")), doraise=True,
                                                   cfile=str(self.folder / f"{name}.{tag}.pyc")))
                     for name in ("good", "cut", "zeros")}

    def cut(self, name="cut"):
        whole = self.made[name].read_bytes()
        self.made[name].write_bytes(whole[:len(whole) // 2])             # the disk was full when Python wrote it

    def test_a_cut_file_is_removed_and_a_whole_one_stays(self):
        self.cut()
        self.made["zeros"].write_bytes(self.made["zeros"].read_bytes()[:16] + b"\0" * 40)
        other = self.folder / "other.cpython-000.pyc"                    # another Python's file is not this one's
        other.write_bytes(self.made["good"].read_bytes()[:16] + b"\0" * 40)
        tag = sys.implementation.cache_tag
        short = self.folder / f"short.{tag}.pyc"
        short.write_bytes(b"\0" * 15)                                    # no whole first bytes: Python compiles again
        bare = self.folder / f"bare.{tag}.pyc"
        bare.write_bytes(self.made["good"].read_bytes()[:16])            # whole first bytes and nothing after them
        (self.folder / "notes.txt").write_text("not a compiled file")
        self.assertEqual(hub.compiled_checked(0, str(self.folder)),
                         [bare.name, self.made["cut"].name, self.made["zeros"].name])
        self.assertEqual(sorted(one.name for one in self.folder.iterdir()),
                         sorted([other.name, self.made["good"].name, "notes.txt", short.name]))
        self.assertEqual(hub.compiled_checked(0, str(self.folder)), [])

    def test_only_the_files_that_this_start_wrote_are_read(self):
        """A file from before this process began was read by this start when it took the module, or no start of
        the hub reads it: the read of every file costs memory that stays (5 MB for a hub's folder, measured)."""
        self.cut()
        self.cut("zeros")
        began = os.stat(self.made["cut"]).st_mtime
        os.utime(self.made["cut"], (began - 60, began - 60))             # written a minute before this start
        with patch("marshal.loads", side_effect=AssertionError("a file from before was read")):
            self.assertEqual(hub.compiled_checked(began + 3600, str(self.folder)), [])
        self.assertEqual(hub.compiled_checked(began - 1, str(self.folder)), [self.made["zeros"].name])
        self.assertTrue(self.made["cut"].exists())
        os.utime(self.made["cut"], (began - 3, began - 3))               # before the two seconds of the margin
        self.assertEqual(hub.compiled_checked(began, str(self.folder)), [])
        os.utime(self.made["cut"], (began - 2, began - 2))               # a clock that was set, or whole seconds
        self.assertEqual(hub.compiled_checked(began, str(self.folder)), [self.made["cut"].name])

    def test_with_no_time_of_the_start_nothing_is_read(self):
        self.cut()
        self.assertEqual(hub.compiled_checked(None, str(self.folder)), [])
        self.assertTrue(self.made["cut"].exists())

    def test_a_file_that_could_not_be_read_for_lack_of_memory_stays(self):
        """Nothing says that such a file is cut, and without it each start compiles again."""
        with patch("marshal.loads", side_effect=MemoryError()):
            self.assertEqual(hub.compiled_checked(0, str(self.folder)), [])
        self.assertEqual(len([one for one in self.folder.iterdir() if one.suffix == ".pyc"]), 3)

    def test_a_folder_that_is_not_there_is_no_error(self):
        self.assertEqual(hub.compiled_checked(0, str(self.root / "none")), [])

    def test_with_no_folder_it_reads_the_one_beside_the_hub_s_own_file(self):
        self.cut()
        with patch.object(hub, "__file__", str(self.root / "hub.py")):
            self.assertEqual(hub.compiled_checked(0), [self.made["cut"].name])

    def test_an_import_works_again_after_the_check(self):
        """Why the check is there: the Python of November 2026 (3.9 to 3.15) does not compile again over a cut
        file, so the import fails at every start (EOFError: marshal data too short). After the check it works.
        A later Python that compiles again by itself passes this test too."""
        self.cut()
        run = [sys.executable, "-c", "import cut; print(len(cut.VALUE))"]
        first = subprocess.run(run, cwd=self.root, capture_output=True, text=True, timeout=60)
        if first.returncode:
            self.assertRegex(first.stderr, "EOFError|marshal")
            self.assertEqual(hub.compiled_checked(0, str(self.folder)), [self.made["cut"].name])
        done = subprocess.run(run, cwd=self.root, capture_output=True, text=True, timeout=60)
        self.assertEqual((done.returncode, done.stdout), (0, "100\n"), done.stderr)

    def test_the_time_of_the_start_is_this_process_s_own(self):
        """On Linux: before now, and before a file that this process writes now. Elsewhere nothing says it, and
        then nothing is read (a hub runs as a service on Linux)."""
        started = hub.process_started()
        if not sys.platform.startswith("linux"):
            self.assertIsNone(started)
            return
        self.assertLessEqual(started, BEGAN, "before this file was taken, so not the time of the call")
        self.assertGreater(started, BEGAN - 6 * 3600)                    # no test process runs for six hours
        self.assertAlmostEqual(hub.process_started(), started, delta=0.5)        # and the same at each call

    def test_the_first_step_of_each_start_reads_back_what_it_wrote(self):
        """In main(), before the words --check-schema and --start-check and before the options: before anything
        that a full disk can stop, because the start after a stopped one would read the cut file. What it says
        goes to the error output, which neither the schema check nor the proof of a start line reads as an
        answer."""
        source = inspect.getsource(hub.main)
        first = source.index("for name in compiled_checked(code_started()):")
        for later in ('sys.argv[1] == "--check-schema"', "[START_CHECK]", "argparse.ArgumentParser", "hub_lock("):
            self.assertLess(first, source.index(later), later)
        self.assertEqual(source.count("compiled_checked("), 1)
        said = source[first:source.index('sys.argv[1] == "--check-schema"')]
        self.assertIn("file=sys.stderr", said)


if __name__ == "__main__":
    unittest.main()
