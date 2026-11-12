"""The configuration ref (2026-10-17): the hub writes the owner's changes to its own branch, so a developer's push
to the code branch cannot refuse an owner write. In-process hub and temporary Git repositories; no fleet or AI calls.

The defect this measures: on 16 and 17 October the owner lost three writes (the Channels pages, his phone
registration) because `commit_kit_file` compared the hub checkout with `origin/main`, which every developer push
moved. `test_the_one_branch_shape_refused_the_write` keeps that behaviour under a test, so the two shapes stand
side by side.
"""
import inspect
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from unittest import mock

import hub
from test_ui_api import OwnerAPI

SCRIPT = Path(__file__).resolve().parent / "config-ref.sh"


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (ConfigRef, Migration):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


def git(*args, cwd=None):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"]}}}
PROFILE = """# Profile: vps

Written by the owner. Agents cannot change it.

**Character.** Careful.

**Responsible for.** Checks.

**May do without asking.** Read files.

**Must ask first.** Spending.
"""


class Stopped(BaseException):
    """The hub process ends here: nothing in the hub catches it, as nothing runs after a kill."""


class ConfigRef(OwnerAPI):
    """A repository in the shape the fleet runs after the split: origin carries `main` (the code) and `config` (what
    the fleet runs), the hub checkout is on `config`."""

    def setUp(self):
        super().setUp()
        hub.TEAM = json.loads(json.dumps(TEAM))
        self.root = Path(tempfile.mkdtemp(prefix="fleet-config-ref-"))
        seed = self.root / "seed"
        (seed / "profiles").mkdir(parents=True)
        (seed / "knowledge/owner").mkdir(parents=True)
        (seed / "team.json").write_text(json.dumps(TEAM, indent=2) + "\n")
        (seed / "profiles/vps.md").write_text(PROFILE)
        (seed / "knowledge/owner/brand.md").write_text("# Brand\n\nSource: brand.pdf · added 2026-10-01\n\nBlue.\n")
        (seed / "hub.py").write_text("# the hub\nVERSION = 1\n")
        (seed / "RULES.md").write_text("# Rules\n")
        git("init", "-q", str(seed))
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "seed", cwd=seed)
        git("branch", hub.CONFIG_BRANCH, cwd=seed)
        git("clone", "-q", "--bare", str(seed), str(self.root / "origin.git"))
        git("clone", "-q", "-b", hub.CONFIG_BRANCH, str(self.root / "origin.git"), str(self.root / "kit"))
        self.kit = self.root / "kit"
        hub.CFG["team_path"] = str(self.kit / "team.json")
        hub._revision_cache.update(at=0.0, value=None)
        hub._code_diffs.clear()
        self.seeded = git("rev-parse", "HEAD", cwd=self.kit)

    def tearDown(self):
        super().tearDown()
        hub.CFG.pop("team_path", None)
        hub._revision_cache.update(at=0.0, value=None)
        hub._code_diffs.clear()
        shutil.rmtree(str(self.root), ignore_errors=True)

    # ---- helpers

    def push(self, branch, write, message):
        """One push to origin by somebody who is not the hub: a developer, or an agent with a task output."""
        work = self.root / ("work-" + branch.replace("/", "-") + str(len(list(self.root.iterdir()))))
        git("clone", "-q", "-b", branch, str(self.root / "origin.git"), str(work))
        write(work)
        git("add", "-A", cwd=work)
        git("commit", "-q", "-m", message, cwd=work)
        git("push", "-q", "origin", "HEAD:" + branch, cwd=work)
        return git("rev-parse", "HEAD", cwd=work)

    def code_change(self, work):
        (work / "hub.py").write_text("# the hub\nVERSION = 2\n")

    def team_bytes(self, **change):
        team = json.loads(json.dumps(TEAM))
        team["agents"]["vps"].update(change)
        return (json.dumps(team, indent=2) + "\n").encode()

    def write_team(self, **change):
        return hub.commit_kit_file("team.json", self.team_bytes(**change), "Owner changed the settings of vps")

    def ref(self, name):
        return git("rev-parse", name, cwd=self.root / "origin.git")

    # ---- what the split is for

    def test_a_code_push_to_main_leaves_an_owner_write_working(self):
        pushed = self.push(hub.CODE_BRANCH, self.code_change, "Developer changed the hub")
        commit = self.write_team(can=["shell", "web"])
        self.assertEqual(self.ref(hub.CONFIG_BRANCH), commit)           # the owner's change is on the configuration ref
        self.assertEqual(self.ref(hub.CODE_BRANCH), pushed)             # the developer's commit stays the code tip
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.kit), commit)
        self.assertEqual(hub.kit_revision(fresh=True), commit)          # kit_revision follows the configuration ref
        self.assertEqual(git("rev-parse", "HEAD~1", cwd=self.kit), self.seeded)   # no code came with it
        self.assertEqual(json.loads((self.kit / "team.json").read_text())["agents"]["vps"]["can"], ["shell", "web"])
        self.assertEqual((self.kit / "hub.py").read_text(), "# the hub\nVERSION = 1\n")

    def test_the_one_branch_shape_refused_the_write(self):
        """The defect, as it was: one branch for code and configuration, and a developer push refuses the write.
        The new code on a pilot that has not split yet behaves exactly like the old code, which is what lets the
        deployment restart the hub before it creates the ref."""
        git("checkout", "-q", hub.CODE_BRANCH, cwd=self.kit)
        git("push", "-q", "origin", "--delete", hub.CONFIG_BRANCH, cwd=self.kit)
        hub._revision_cache.update(at=0.0, value=None)
        self.push(hub.CODE_BRANCH, self.code_change, "Developer changed the hub")
        with self.assertRaises(hub.Refusal) as caught:
            self.write_team(can=["shell", "web"])
        self.assertEqual(caught.exception.status, 409)
        self.assertIn("does not run", str(caught.exception))

    def test_many_code_pushes_leave_every_owner_write_working(self):
        for n in range(3):
            self.push(hub.CODE_BRANCH, lambda work, n=n: (work / "hub.py").write_text(f"VERSION = {n + 2}\n"),
                      f"Developer push {n}")
            self.write_team(can=["shell"] if n % 2 else ["shell", "web"])
        self.assertEqual(hub.kit_revision(fresh=True), self.ref(hub.CONFIG_BRANCH))
        self.assertEqual(len(git("log", "--oneline", hub.CONFIG_BRANCH, cwd=self.root / "origin.git").splitlines()), 4)

    # ---- what still stops a write

    def test_an_output_push_to_the_configuration_ref_is_taken_in(self):
        """An agent's task output on the configuration ref changes no Fleet file, so the hub takes it in and
        commits on top of it instead of refusing the owner."""
        def output(work):
            (work / "outputs/T-1").mkdir(parents=True)
            (work / "outputs/T-1/result.md").write_text("# Done\n")
        pushed = self.push(hub.CONFIG_BRANCH, output, "Worker vps: output of T-1")
        commit = self.write_team(can=["shell", "web"])
        self.assertEqual(git("rev-parse", "HEAD~1", cwd=self.kit), pushed)
        self.assertEqual(self.ref(hub.CONFIG_BRANCH), commit)
        self.assertTrue((self.kit / "outputs/T-1/result.md").exists())

    def test_code_on_the_configuration_ref_refuses_the_write(self):
        """A deployment, and only a deployment, puts code on the configuration ref: the hub refuses to move its
        checkout past the code that it serves, which is what turned every machine "behind" twice on 2026-10-16."""
        pushed = self.push(hub.CONFIG_BRANCH, self.code_change, "A deployment merged the code")
        with self.assertRaises(hub.Refusal) as caught:
            self.write_team(can=["shell", "web"])
        self.assertEqual(caught.exception.status, 409)
        self.assertIn("does not run", str(caught.exception))
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.kit), self.seeded)      # the checkout stayed
        self.assertEqual(self.ref(hub.CONFIG_BRANCH), pushed)                      # and wrote nothing

    def test_a_hub_ahead_of_its_own_ref_refuses_the_write(self):
        git("commit", "-q", "--allow-empty", "-m", "a commit that origin lacks", cwd=self.kit)
        with self.assertRaises(hub.Refusal) as caught:
            self.write_team(can=["shell", "web"])
        self.assertEqual(caught.exception.status, 409)
        self.assertIn("lacks commits that the hub has", str(caught.exception))

    def test_a_checkout_put_back_on_the_code_branch_writes_nothing(self):
        """After the split the hub must never push the owner's change to the branch that the developers hold."""
        git("checkout", "-q", hub.CODE_BRANCH, cwd=self.kit)
        hub._revision_cache.update(at=0.0, value=None)
        with self.assertRaises(hub.Refusal) as caught:
            self.write_team(can=["shell", "web"])
        self.assertEqual(caught.exception.status, 409)
        self.assertIn("which the developers push", str(caught.exception))
        self.assertEqual(self.ref(hub.CODE_BRANCH), self.seeded)
        self.assertEqual(self.ref(hub.CONFIG_BRANCH), self.seeded)

    def test_a_detached_checkout_has_no_configuration_ref(self):
        git("checkout", "-q", "--detach", "HEAD", cwd=self.kit)
        self.assertIsNone(hub.config_branch())
        with self.assertRaises(hub.Refusal) as caught:
            self.write_team(can=["shell", "web"])
        self.assertEqual(caught.exception.status, 409)
        self.assertIn("on no branch", str(caught.exception))

    # ---- a write whose push landed and whose fast-forward did not (7 November 2026)

    def settings(self, **change):
        """The owner's settings write of vps (save_agent_settings) on the team.json that the hub reads now, under LOCK
        as every owner command runs. It commits, then applies the team and asks the machine of vps to follow."""
        with hub.LOCK:
            _, current, _ = hub.team_view(hub.kit_revision(fresh=True))
            return hub.save_agent_settings("vps", dict(change, base_sha256=current))

    def cut_after_push(self, how, write=None, **change):
        """One write of team.json whose push lands, after which the push answers as failed (`answer`), the hub's
        fetch fails (`fetch`), its fast-forward fails (`move`), or the hub stops (`stop`). The write is the owner's
        settings write of vps unless `write` is given. The machine of vps has reported. Gives the commit that reached
        the ref."""
        hub.q("INSERT INTO machine_status(agent,data,reported) VALUES('vps',?,?)",
              (json.dumps({"revision": self.seeded}), hub.now()))
        real_move, real_git, real_run, cut = hub.move_kit, hub.git_kit, subprocess.run, []

        def move_kit(target):
            if how == "move" and not cut:
                cut.append(target)
                return "the fast-forward failed: Unable to create '.git/index.lock': File exists."
            return real_move(target)

        def git_kit(*args, **kwargs):
            if how in ("fetch", "stop") and args[:1] == ("fetch",) and not cut and \
                    self.ref(hub.CONFIG_BRANCH) != self.seeded:
                cut.append(args)
                if how == "stop":
                    raise Stopped()
                return 128, "", "fatal: the remote end hung up unexpectedly"
            return real_git(*args, **kwargs)

        def run(argv, *args, **kwargs):
            done = real_run(argv, *args, **kwargs)
            if how == "answer" and not cut and "push" in argv:
                cut.append(argv)
                return subprocess.CompletedProcess(argv, 128, "", "fatal: the remote end hung up unexpectedly")
            return done
        write = write or (lambda: self.settings(**change))
        with mock.patch.object(hub, "move_kit", move_kit), mock.patch.object(hub, "git_kit", git_kit), \
                mock.patch.object(subprocess, "run", run):
            if how == "stop":
                with self.assertRaises(Stopped):
                    write()
            else:
                with self.assertRaises(hub.Refusal) as caught:
                    write()
                self.assertEqual(caught.exception.status, 502 if how == "answer" else 500)
        self.assertEqual(len(cut), 1)
        pushed = self.ref(hub.CONFIG_BRANCH)
        self.assertEqual(self.ref(hub.CONFIG_BRANCH + "~1"), self.seeded)         # the push landed
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.kit), self.seeded)      # and the checkout stayed
        self.assertEqual(hub.agents()["vps"]["can"], ["shell"])                    # as did the team in memory
        self.assertIsNone(self.asked())                                             # and nobody was asked
        return pushed

    def asked(self):
        row = hub.q1("SELECT state, desired FROM machine_updates WHERE agent='vps'")
        return (row["state"], row["desired"]) if row else None

    def test_a_write_whose_fast_forward_failed_is_taken_back_and_then_made_again(self):
        """The reviewers of the cut-off release run (7 November 2026): the push landed and the hub's own fast-forward
        failed. The commit stood on the ref and not in the checkout, the steps of its write after it never ran, and
        every later write of team.json was refused ("carries changes that the hub does not run") until a reload or a
        release, which took the commit in without those steps. The write was answered as failed, so the next write
        first takes the commit back, and the owner's same change, sent again, is a new write with every step."""
        pushed = self.cut_after_push("move", can=["shell", "web"])
        with mock.patch.object(hub, "apply_team", wraps=hub.apply_team) as applied:
            answer = self.settings(can=["shell", "web"])
        undo = git("rev-parse", "HEAD~1", cwd=self.kit)
        self.assertEqual(git("rev-parse", "HEAD~2", cwd=self.kit), pushed)
        self.assertEqual(git("show", "-s", "--format=%an: %s", undo, cwd=self.kit),
                         'Fleet hub: Revert "Owner changed the settings of vps"')
        self.assertEqual({answer["revision"], self.ref(hub.CONFIG_BRANCH)}, {git("rev-parse", "HEAD", cwd=self.kit)})
        self.assertEqual(applied.call_count, 1)                                     # by the write's own steps
        self.assertEqual(hub.agents()["vps"]["can"], ["shell", "web"])
        self.assertEqual(self.asked(), ("requested", answer["revision"]))
        self.assertIsNone(hub.kv_get(hub.KIT_PUSHED))

    def test_a_write_read_before_it_was_taken_back_goes_on_from_the_team_the_hub_runs(self):
        """Any write takes the commit back first, so a write read before that is no older than the ref: nothing of
        the failed change comes back, and nothing of the new one is lost."""
        pushed = self.cut_after_push("fetch", can=["shell", "web"])
        answer = self.settings(title="Checks")
        vps = json.loads(git("show", f"{answer['revision']}:team.json", cwd=self.kit))["agents"]["vps"]
        self.assertEqual((vps["can"], vps["title"]), (["shell"], "Checks"))
        self.assertEqual(git("rev-parse", "HEAD~2", cwd=self.kit), pushed)
        self.assertEqual(hub.agents()["vps"]["can"], ["shell"])

    def test_a_write_of_another_kind_applies_nothing_of_the_commit_it_takes_back(self):
        """A team.json write that has more steps than apply_team (a removal forgets the agent's key; a rename moves its
        records; a join keeps the server's key) is never half done: a task's output or a knowledge file, which
        agents write all day, takes the commit back and applies nothing of it. A machine that took the commit at a
        task's start meanwhile is asked to follow the ref again."""
        hub.q("INSERT INTO agent_keys(agent,sha256,created,source) VALUES('vps',?,?,'owner')", ("a" * 64, hub.now()))
        team = json.loads(json.dumps(TEAM))
        del team["agents"]["vps"]
        removal = (json.dumps(team, indent=2) + "\n").encode()
        pushed = self.cut_after_push("move", write=lambda: hub.commit_kit_file("team.json", removal,
                                                                               "Owner removed agent vps"))
        hub.q("UPDATE machine_status SET data=? WHERE agent='vps'", (json.dumps({"revision": pushed}),))
        commit = hub.commit_kit_file("knowledge/owner/brand.md", b"# Brand\n\nGreen.\n", "Owner changed brand.md")
        undo = git("rev-parse", "HEAD~1", cwd=self.kit)
        self.assertEqual((git("rev-parse", "HEAD~2", cwd=self.kit), self.ref(hub.CONFIG_BRANCH)), (pushed, commit))
        self.assertIn("vps", json.loads(git("show", f"{commit}:team.json", cwd=self.kit))["agents"])
        self.assertIn("vps", hub.agents())
        self.assertIsNotNone(hub.q1("SELECT 1 FROM agent_keys WHERE agent='vps'"))
        self.assertEqual(self.asked(), ("requested", undo))

    def test_a_push_that_lands_with_no_answer_is_taken_back_too(self):
        """The mark is written before the push: a push that lands and answers as failed is the hub's own as well."""
        pushed = self.cut_after_push("answer", can=["shell", "web"])
        answer = self.settings(can=["shell", "web"])
        self.assertEqual(git("rev-parse", "HEAD~2", cwd=self.kit), pushed)
        self.assertEqual((git("rev-parse", "HEAD", cwd=self.kit), hub.agents()["vps"]["can"]),
                         (answer["revision"], ["shell", "web"]))

    def test_the_hub_start_takes_back_a_write_that_a_stop_cut_off(self):
        """The hub stopped between the push and its fast-forward, so the write's steps never ran: its next start
        takes the commit back before the timers and the server start, and the hub runs what the ref holds."""
        pushed = self.cut_after_push("stop", can=["shell", "web"])
        hub.settle_kit_push()
        undo = self.ref(hub.CONFIG_BRANCH)
        self.assertEqual(self.ref(hub.CONFIG_BRANCH + "~1"), pushed)
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.kit), self.seeded)
        self.assertTrue(hub.same_code(self.seeded, undo))
        self.assertEqual(hub.agents()["vps"]["can"], ["shell"])
        self.assertIsNone(hub.kv_get(hub.KIT_PUSHED))
        self.settings(can=["shell", "web"])                         # sent again: a plain write
        self.assertEqual(git("rev-parse", "HEAD~1", cwd=self.kit), undo)
        self.assertEqual(hub.agents()["vps"]["can"], ["shell", "web"])
        start = inspect.getsource(hub.main)         # the hub's start runs it, before the release asks every machine
        self.assertLess(start.index("settle_kit_push()"), start.index("settle_releases(ask=not restored)"))

    def test_the_hub_start_raises_nothing_and_leaves_what_it_cannot_do_to_the_next_write(self):
        """A step of the hub's start never stops it, because a hub that cannot start cannot be reached."""
        pushed = self.cut_after_push("stop", can=["shell", "web"])
        real = hub.git_kit

        def no_fetch(*args, **kwargs):
            return (128, "", "fatal: unable to access") if args[:1] == ("fetch",) else real(*args, **kwargs)
        with mock.patch.object(hub, "git_kit", no_fetch):
            hub.settle_kit_push()
        with mock.patch.object(hub, "undo_kit_push", side_effect=RuntimeError("a row that raises")):
            hub.settle_kit_push()
        with mock.patch.object(hub, "undo_kit_push", return_value="the push of the commit that undoes it failed"):
            hub.settle_kit_push()
        self.assertEqual((hub.kv_get(hub.KIT_PUSHED), self.ref(hub.CONFIG_BRANCH)), (pushed, pushed))
        self.settings(can=["shell", "web"])
        self.assertEqual(git("rev-parse", "HEAD~2", cwd=self.kit), pushed)
        self.assertEqual(hub.agents()["vps"]["can"], ["shell", "web"])

    def test_a_commit_that_the_checkout_took_in_meanwhile_is_never_taken_back(self):
        """A reload onto the ref's revision (reload_team), or the end of a server's rename (finish_machine_rename),
        takes the commit in with the mark still there. A write without LOCK or a release run that read the checkout
        before that must not take back what the hub runs now (both reviewers of the last round)."""
        pushed = self.cut_after_push("move", can=["shell", "web"])
        with hub.LOCK:
            hub.reload_team(pushed)
        self.assertIsNone(hub.undo_kit_push(pushed))
        self.assertEqual((self.ref(hub.CONFIG_BRANCH), git("rev-parse", "HEAD", cwd=self.kit)), (pushed, pushed))
        self.assertIsNone(hub.kv_get(hub.KIT_PUSHED))
        self.assertEqual(hub.agents()["vps"]["can"], ["shell", "web"])
        answer = self.settings(title="Checks")                     # the next write is a plain one
        self.assertEqual(git("rev-parse", answer["revision"] + "~1", cwd=self.kit), pushed)

    def test_the_hub_start_forgets_a_push_that_never_landed_or_that_it_holds(self):
        commit = self.write_team(can=["shell", "web"])
        self.assertIsNone(hub.kv_get(hub.KIT_PUSHED))           # a write that ended well leaves no mark
        for mark in ("0" * 40, commit, self.seeded):            # not on the ref; the checkout's own; older than it
            hub.kv_set(hub.KIT_PUSHED, mark)
            hub.settle_kit_push()
            self.assertIsNone(hub.kv_get(hub.KIT_PUSHED), mark)
            self.assertEqual((git("rev-parse", "HEAD", cwd=self.kit), self.ref(hub.CONFIG_BRANCH)), (commit, commit))

    # ---- what the hub may write there

    def test_the_hub_writes_configuration_files_and_nothing_else(self):
        # All of knowledge/, and not only knowledge/owner/: an agent writes the knowledge files its profile lists
        # (hub.write_knowledge), and a file the hub can write but a release can replace is drift. test_memory.py
        # holds the other half, lifecycle.data_path.
        for path in ("team.json", "profiles/vps.md", "knowledge/owner/brand.md", "knowledge/services.md"):
            self.assertTrue(hub.CONFIG_FILES.match(path), path)
        for path in ("hub.py", "RULES.md", "CLAUDE.md", "outputs/T-1/result.md",
                     "knowledge/owner/../../hub.py", "profiles/../hub.py"):
            self.assertFalse(hub.CONFIG_FILES.match(path), path)

    def test_an_agent_s_skill_is_a_configuration_file_and_no_code(self):
        """Design v4 D1: skills/<agent>/<name>/SKILL.md and the few small files beside it are the fleet's own, and
        this path admits them a release before the tool that writes them. A script among them is no Fleet code, so
        a machine that has not fetched the skill yet is not behind, and the owner's copy carries every skill."""
        for path in ("skills/vps/deploy-acme/SKILL.md", "skills/vps/deploy-acme/check.py",
                     "skills/vps/deploy-acme/scripts/run.sh", "skills/vps/a/b/c/notes_1.txt", "skills/vps/0/SKILL.md"):
            self.assertTrue(hub.CONFIG_FILES.match(path), path)
        for path in ("skills/vps/deploy-acme/../../../hub.py", "skills/vps/x/a..b", "skills/vps/Deploy/SKILL.md",
                     "skills/vps/-x/SKILL.md", "skills/vps/x/.env", "skills/vps/x/a/.git/config",
                     "skills/vps/x/a/b/c/deep.txt", "skills/vps/SKILL.md", "skills/V/x/SKILL.md", "skills/vps/x/",
                     "skills/vps/x//SKILL.md", "skills/" + "a" * 32 + "/x/SKILL.md", "skills/vps/" + "x" * 65 + "/a"):
            self.assertFalse(hub.CONFIG_FILES.match(path), path)
        commit = hub.commit_kit_file("skills/vps/deploy-acme/SKILL.md", b"---\nname: deploy-acme\n---\n\nSteps.\n",
                                     "vps wrote the skill deploy-acme", author="vps",
                                     more={"skills/vps/deploy-acme/check.py": b"print('smoke')\n"})
        self.assertEqual(self.ref(hub.CONFIG_BRANCH), commit)
        self.assertTrue(hub.same_code(self.seeded, commit))
        self.assertFalse(hub.same_code(self.seeded, self.write_team(can=["shell", "web"])))     # code and team do
        self.assertEqual(sorted(hub.owner_files()), ["knowledge/owner/brand.md", "profiles/vps.md",
                                                     "skills/vps/deploy-acme/SKILL.md",
                                                     "skills/vps/deploy-acme/check.py", "team.json"])
        import fleet
        self.assertIn("skills/**", fleet.PROTECTED)         # and no session edits one by hand

    def test_a_code_file_through_the_owner_path_is_refused(self):
        with self.assertRaises(hub.Refusal) as caught:
            hub.commit_kit_file("hub.py", b"VERSION = 9\n", "Owner changed the hub")
        self.assertEqual(caught.exception.status, 500)
        self.assertIn("not a configuration file", str(caught.exception))
        self.assertEqual(self.ref(hub.CONFIG_BRANCH), self.seeded)

    def test_a_profile_and_team_json_go_in_one_commit(self):
        commit = hub.commit_kit_file("team.json", self.team_bytes(can=["shell", "web"]), "Owner added agent vps",
                                     more={"profiles/vps.md": PROFILE.replace("Careful.", "Quick.").encode()})
        self.assertEqual(self.ref(hub.CONFIG_BRANCH), commit)
        self.assertIn("Quick.", (self.kit / "profiles/vps.md").read_text())

    # ---- the reload follows the same ref

    def test_the_reload_refuses_a_revision_that_is_only_on_the_code_branch(self):
        pushed = self.push(hub.CODE_BRANCH, self.code_change, "Developer changed the hub")
        with self.assertRaises(hub.Refusal) as caught:
            hub.reload_team(pushed)
        self.assertEqual(caught.exception.status, 409)
        self.assertIn("configuration ref", str(caught.exception))
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.kit), self.seeded)

    def test_the_reload_takes_a_revision_of_the_configuration_ref(self):
        def team(work):
            (work / "team.json").write_text(json.dumps(TEAM, indent=2) + "\n")
            (work / "outputs").mkdir()
            (work / "outputs/note.md").write_text("# note\n")
        pushed = self.push(hub.CONFIG_BRANCH, team, "Owner changed the team elsewhere")
        answer = hub.reload_team(pushed)
        self.assertEqual(answer["revision"], pushed)
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.kit), pushed)


class Migration(unittest.TestCase):
    """config-ref.sh: the pilot's one branch becomes two refs, with no history lost, no owner write dropped and no
    machine "behind". Tried here, in scratch clones, and never on the live hub."""

    def setUp(self):
        hub.TEAM = json.loads(json.dumps(TEAM))
        kept = hub.DB                       # records of its own: a write of team.json marks its push (KIT_PUSHED)
        hub.DB = sqlite3.connect(":memory:", check_same_thread=False)
        self.addCleanup(lambda: (hub.DB.close(), setattr(hub, "DB", kept)))
        hub.DB.row_factory = sqlite3.Row
        hub.DB.executescript(hub.SCHEMA)
        self.root = Path(tempfile.mkdtemp(prefix="fleet-migration-"))
        seed = self.root / "seed"
        (seed / "profiles").mkdir(parents=True)
        (seed / "team.json").write_text(json.dumps(TEAM, indent=2) + "\n")
        (seed / "profiles/vps.md").write_text(PROFILE)
        (seed / "hub.py").write_text("# the hub\nVERSION = 1\n")
        for name in ("lifecycle.py", "onboard.py", "releases.py"):      # the one check of every move (plan 0.1)
            shutil.copy(SCRIPT.parent / name, seed / name)
        git("init", "-q", str(seed))
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "the pilot on one branch", cwd=seed)
        git("clone", "-q", "--bare", str(seed), str(self.root / "origin.git"))
        git("clone", "-q", str(self.root / "origin.git"), str(self.root / "hub"))
        git("clone", "-q", str(self.root / "origin.git"), str(self.root / "machine"))
        self.kit, self.machine = self.root / "hub", self.root / "machine"
        hub.CFG["team_path"] = str(self.kit / "team.json")
        hub._revision_cache.update(at=0.0, value=None)
        hub._code_diffs.clear()
        self.before = git("rev-parse", "HEAD", cwd=self.kit)

    def tearDown(self):
        hub.CFG.pop("team_path", None)
        hub._revision_cache.update(at=0.0, value=None)
        hub._code_diffs.clear()
        shutil.rmtree(str(self.root), ignore_errors=True)

    def run_script(self, *args, where=None):
        home = self.root / "home"            # the check keeps a floor in the home of its user: this test's own
        home.mkdir(exist_ok=True)
        done = subprocess.run(["sh", str(SCRIPT), *args, str(where or self.kit)], capture_output=True, text=True,
                              env=dict(os.environ, HOME=str(home)))
        return done.returncode, (done.stdout + done.stderr).strip()

    def write_team(self, **change):
        team = json.loads(json.dumps(TEAM))
        team["agents"]["vps"].update(change)
        hub._revision_cache.update(at=0.0, value=None)
        return hub.commit_kit_file("team.json", (json.dumps(team, indent=2) + "\n").encode(), "Owner changed vps")

    def ref(self, name):
        return git("rev-parse", name, cwd=self.root / "origin.git")

    def branch_of(self, where):
        return git("symbolic-ref", "--short", "HEAD", cwd=where)

    def test_check_says_what_it_would_do_and_changes_nothing(self):
        code, said = self.run_script("--check")
        self.assertEqual(code, 0, said)
        self.assertIn("would run: git push", said)
        self.assertEqual(self.branch_of(self.kit), hub.CODE_BRANCH)
        self.assertEqual(git("branch", "-r", cwd=self.kit).count(hub.CONFIG_BRANCH), 0)

    def test_the_ref_starts_at_the_commit_that_the_fleet_runs(self):
        code, said = self.run_script()
        self.assertEqual(code, 0, said)
        self.assertEqual(self.ref(hub.CONFIG_BRANCH), self.before)      # the same commit: nothing to deploy
        self.assertEqual(self.ref(hub.CODE_BRANCH), self.before)
        self.assertEqual(self.branch_of(self.kit), hub.CONFIG_BRANCH)
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.kit), self.before)
        self.assertEqual(git("log", "--format=%H", hub.CONFIG_BRANCH, cwd=self.root / "origin.git"),
                         git("log", "--format=%H", hub.CODE_BRANCH, cwd=self.root / "origin.git"))
        self.assertEqual(git("diff", "--name-only", hub.CODE_BRANCH, hub.CONFIG_BRANCH, cwd=self.kit), "")

    def test_no_machine_turns_behind(self):
        self.run_script()
        self.assertTrue(hub.same_code(git("rev-parse", "HEAD", cwd=self.machine), hub.kit_revision(fresh=True)))
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.machine), self.before)

    def test_a_machine_moves_itself_onto_the_ref(self):
        self.run_script()
        code, said = self.run_script(where=self.machine)
        self.assertEqual(code, 0, said)
        self.assertEqual(self.branch_of(self.machine), hub.CONFIG_BRANCH)
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.machine), self.before)
        self.assertEqual(self.run_script(where=self.machine)[0], 0)     # and again changes nothing

    def test_the_owner_writes_before_during_and_after_the_migration(self):
        first = self.write_team(can=["shell", "web"])                   # the pilot's one-branch shape
        self.assertEqual(self.ref(hub.CODE_BRANCH), first)
        code, said = self.run_script()
        self.assertEqual(code, 0, said)
        work = self.root / "dev"
        git("clone", "-q", str(self.root / "origin.git"), str(work))
        (work / "hub.py").write_text("# the hub\nVERSION = 2\n")
        git("commit", "-q", "-am", "Developer changed the hub", cwd=work)
        git("push", "-q", "origin", "HEAD:" + hub.CODE_BRANCH, cwd=work)
        second = self.write_team(can=["shell"])                         # the push no longer refuses it
        self.assertEqual(self.ref(hub.CONFIG_BRANCH), second)
        history = git("log", "--format=%H", hub.CONFIG_BRANCH, cwd=self.root / "origin.git").splitlines()
        self.assertEqual(history, [second, first, self.before])         # no owner write dropped, no history lost

    def test_a_machine_s_own_config_branch_is_checked_before_the_checkout_moves_onto_it(self):
        """A branch of that name that changes Fleet's code with no signed release: the checkout stays where it is,
        as lifecycle.follow_config_ref keeps it."""
        self.run_script()
        git("checkout", "-q", "-b", hub.CONFIG_BRANCH, cwd=self.machine)
        (self.machine / "hub.py").write_text("# the hub\nVERSION = 2\n")
        git("commit", "-q", "-am", "code of this machine's own", cwd=self.machine)
        git("checkout", "-q", hub.CODE_BRANCH, cwd=self.machine)
        code, said = self.run_script(where=self.machine)
        self.assertEqual(code, 1, said)
        self.assertIn("has commits that origin/config lacks", said)
        self.assertEqual(self.branch_of(self.machine), hub.CODE_BRANCH)
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.machine), self.before)

    def test_a_machine_s_own_config_branch_that_is_behind_moves_with_it_onto_the_checked_commit(self):
        """A config branch from an earlier clone, behind a code change that this checkout already runs: the checkout
        lands on origin's config, which the one check passed, and never on that older commit on the way, which the
        same check would refuse as a move back."""
        self.run_script()
        git("fetch", "-q", cwd=self.machine)
        git("branch", "-q", hub.CONFIG_BRANCH, "origin/" + hub.CONFIG_BRANCH, cwd=self.machine)     # the old one
        work = self.root / "dev"
        git("clone", "-q", str(self.root / "origin.git"), str(work))
        (work / "hub.py").write_text("# the hub\nVERSION = 2\n")
        git("commit", "-q", "-am", "code that the machine already runs", cwd=work)
        git("push", "-q", "origin", "HEAD:" + hub.CODE_BRANCH, "HEAD:" + hub.CONFIG_BRANCH, cwd=work)
        git("pull", "-q", "--ff-only", "origin", hub.CODE_BRANCH, cwd=self.machine)
        team = json.loads((work / "team.json").read_text())
        team["agents"]["vps"]["can"] = ["shell", "web"]
        (work / "team.json").write_text(json.dumps(team, indent=2) + "\n")
        git("commit", "-q", "-am", "Owner changed vps", cwd=work)
        git("push", "-q", "origin", "HEAD:" + hub.CONFIG_BRANCH, cwd=work)
        code, said = self.run_script(where=self.machine)
        self.assertEqual(code, 0, said)
        self.assertEqual(self.branch_of(self.machine), hub.CONFIG_BRANCH)
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.machine), self.ref(hub.CONFIG_BRANCH))

    def test_a_checkout_with_its_own_changes_is_refused(self):
        (self.kit / "team.json").write_text("{}\n")
        code, said = self.run_script()
        self.assertEqual(code, 1)
        self.assertIn("its own changes", said)
        self.assertEqual(self.branch_of(self.kit), hub.CODE_BRANCH)


if __name__ == "__main__":
    unittest.main()
