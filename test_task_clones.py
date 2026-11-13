"""Each task works in its own clone of each repository (the owner, 4 November 2026: "Build all four"; on 3 November
T-71 changed the lockfile and the node_modules of T-84 in the one clone that they shared). fleet.task_place,
prepare_repos with a place, drop_place, the stop of a task and Helper.sweep_places, with real git against a bare
repository that stands in for GitHub. No hub, no tmux and no network."""
import contextlib
import io
import os
import shutil
import subprocess
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import fleet

GEN, OLD = "0123456789ab", "ba9876543210"


class TaskClones(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-task-clones-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.work = self.tmp / "work"
        patcher = patch.object(fleet, "WORK", str(self.work))
        patcher.start()
        self.addCleanup(patcher.stop)
        # git of this Mac's user reads none of its own settings here, and GitHub's address leads to a bare repository
        # of this test: git's own insteadOf, in the session's variables as the hub's credentials are
        self.github = self.tmp / "github"
        quiet = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "Test",
                 "GIT_AUTHOR_EMAIL": "test@example.com", "GIT_COMMITTER_NAME": "Test",
                 "GIT_COMMITTER_EMAIL": "test@example.com"}
        self.values = dict(quiet, GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0=f"url.{self.github.as_uri()}/.insteadOf",
                           GIT_CONFIG_VALUE_0="https://github.com/")
        patcher = patch.dict(os.environ, quiet)     # drop_place's own git, which reads no session variables
        patcher.start()
        self.addCleanup(patcher.stop)
        self.env = {**os.environ, **self.values}
        self.said = []
        self.remote("acme/web")

    # ---- the stand-in GitHub and the sessions

    def git(self, *args, cwd=None):
        r = subprocess.run(["git", *args], cwd=cwd, env=self.env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, f"git {' '.join(args)}: {r.stderr}")
        return r.stdout.strip()

    def remote(self, repo, branch="trunk"):
        """A repository on the stand-in GitHub whose default branch is not main, with a second branch."""
        seed = self.tmp / "seed" / repo
        seed.mkdir(parents=True)
        self.git("init", "--quiet", "-b", branch, cwd=seed)
        (seed / "README.md").write_text("one\n")
        self.git("add", "README.md", cwd=seed)
        self.git("commit", "--quiet", "-m", "one", cwd=seed)
        self.git("branch", "feature", cwd=seed)
        bare = self.github / f"{repo}.git"
        bare.parent.mkdir(parents=True, exist_ok=True)
        self.git("clone", "--quiet", "--bare", str(seed), str(bare))

    def push_elsewhere(self, repo="acme/web", text="two"):
        """Another machine pushes a commit to the default branch."""
        other = self.tmp / "elsewhere" / text
        self.git("clone", "--quiet", f"https://github.com/{repo}.git", str(other))
        (other / "README.md").write_text(text + "\n")
        self.git("commit", "--quiet", "-am", text, cwd=other)
        self.git("push", "--quiet", cwd=other)
        return self.git("rev-parse", "HEAD", cwd=other)

    def place(self, window, agent="ivy", generation=GEN):
        return fleet.task_place(agent, generation, window)

    def prepare(self, window, agent="ivy", generation=GEN, repos=("acme/web",)):
        place = self.place(window, agent, generation)
        self.assertEqual(fleet.prepare_repos({r: "write" for r in repos}, self.values, place), {})
        return place

    def own(self, place, repo="acme/web"):
        return os.path.join(place, *repo.split("/"))

    def shared(self, repo="acme/web"):
        return os.path.join(self.work, *repo.split("/"))

    # ---- the tests

    def test_a_place_needs_a_generation_a_window_and_an_agent(self):
        self.assertEqual(fleet.task_place("ivy", GEN, "T-3"), os.path.join(self.work, ".tasks", "ivy", GEN, "T-3"))
        self.assertEqual(fleet.task_place("ivy", GEN, "C-12"), os.path.join(self.work, ".tasks", "ivy", GEN, "C-12"))
        for bad in (("ivy", "test-generation", "T-3"), ("ivy", GEN, "T-0"), ("ivy", GEN, "owner-chat"),
                    ("ivy", GEN, "T-3/../x"), ("../ivy", GEN, "T-3"), ("ivy", None, "T-3"), ("ivy", GEN, None)):
            self.assertIsNone(fleet.task_place(*bad), bad)

    def test_a_tasks_clone_is_on_origins_default_branch_with_githubs_address_and_linked_packs(self):
        place = self.prepare("T-3")
        own = self.own(place)
        self.assertEqual(self.git("symbolic-ref", "--short", "HEAD", cwd=own), "trunk")
        self.assertEqual(self.git("rev-parse", "--abbrev-ref", "trunk@{upstream}", cwd=own), "origin/trunk")
        self.assertEqual(self.git("config", "remote.origin.url", cwd=own), "https://github.com/acme/web.git")
        self.assertEqual(self.git("symbolic-ref", "refs/remotes/origin/HEAD", cwd=own), "refs/remotes/origin/trunk")
        self.assertEqual(self.git("for-each-ref", "--format=%(refname)", "refs/heads", "refs/remotes", cwd=own).split(),
                         ["refs/heads/trunk", "refs/remotes/origin/HEAD", "refs/remotes/origin/feature",
                          "refs/remotes/origin/trunk"])
        self.assertEqual(self.git("config", "gc.auto", cwd=own), "0")
        self.assertEqual((Path(own) / "README.md").read_text(), "one\n")
        inodes = {p.stat().st_ino for p in Path(self.shared(), ".git", "objects").rglob("*") if p.is_file()}
        mine = [p.stat().st_ino for p in Path(own, ".git", "objects").rglob("*") if p.is_file()
                and p.parent.name != "info"]
        self.assertTrue(mine and set(mine) <= inodes, "git clone --local links the objects, it copies none")
        self.assertFalse(os.path.exists(os.path.join(place, ".new")))

    def test_what_one_task_leaves_reaches_neither_another_task_nor_the_shared_clone(self):
        own3 = self.own(self.prepare("T-3"))
        Path(own3, "notes.txt").write_text("mine\n")
        Path(own3, "node_modules", "left-pad").mkdir(parents=True)
        Path(own3, "README.md").write_text("changed by T-3\n")
        own4 = self.own(self.prepare("T-4"))
        self.assertEqual(sorted(os.listdir(own4)), [".git", "README.md"])
        self.assertEqual(Path(own4, "README.md").read_text(), "one\n")
        self.assertEqual(sorted(os.listdir(self.shared())), [".git", "README.md"])
        self.assertEqual(self.git("status", "--porcelain", cwd=self.shared()), "")

    def test_a_later_session_of_the_task_only_fetches_its_clone(self):
        own = self.own(self.prepare("T-3"))
        Path(own, "README.md").write_text("work of T-3\n")
        self.git("commit", "--quiet", "-am", "T-3 part one", cwd=own)
        mine = self.git("rev-parse", "HEAD", cwd=own)
        Path(own, "draft.txt").write_text("not yet\n")
        theirs = self.push_elsewhere()
        self.prepare("T-3")             # the session of the next attempt
        self.assertEqual((self.git("rev-parse", "HEAD", cwd=own), Path(own, "draft.txt").read_text()),
                         (mine, "not yet\n"))
        self.assertEqual(self.git("rev-parse", "origin/trunk", cwd=own), theirs)
        own4 = self.own(self.prepare("T-4"))        # another task's first clone: from the shared clone, fetched first
        self.assertEqual(self.git("rev-parse", "HEAD", cwd=own4), theirs)

    def test_a_clone_that_a_start_left_half_made_is_made_again(self):
        place = self.place("T-3")
        Path(place, ".new", "acme", "web").mkdir(parents=True)
        Path(place, ".new", "acme", "web", "junk").write_text("x")
        own = self.own(self.prepare("T-3"))
        self.assertEqual(self.git("symbolic-ref", "--short", "HEAD", cwd=own), "trunk")
        self.assertFalse(os.path.exists(os.path.join(place, ".new", "acme", "web")))

    def test_a_folder_in_the_place_of_a_clone_is_said_and_kept(self):
        place = self.place("T-3")
        Path(self.own(place)).mkdir(parents=True)
        Path(self.own(place), "keep.txt").write_text("someone's\n")
        problems = fleet.prepare_repos({"acme/web": "write"}, self.values, place)
        self.assertIn("is there, but it is not a git clone", problems["acme/web"])
        self.assertTrue(Path(self.own(place), "keep.txt").exists())

    def test_pull_rebase_and_push_reach_the_default_branch_after_another_task_pushed(self):
        own3, own4 = self.own(self.prepare("T-3")), self.own(self.prepare("T-4"))
        Path(own4, "b.txt").write_text("T-4\n")
        self.git("add", "b.txt", cwd=own4)
        self.git("commit", "--quiet", "-m", "T-4", cwd=own4)
        self.git("push", "--quiet", cwd=own4)
        Path(own3, "a.txt").write_text("T-3\n")
        self.git("add", "a.txt", cwd=own3)
        self.git("commit", "--quiet", "-m", "T-3", cwd=own3)
        self.git("pull", "--quiet", "--rebase", cwd=own3)
        self.git("push", "--quiet", cwd=own3)
        log = self.git("log", "--format=%s", "trunk", cwd=str(self.github / "acme/web.git")).split("\n")
        self.assertEqual(log, ["T-3", "T-4", "one"])

    def test_the_end_of_a_task_keeps_its_unpushed_commits_and_deletes_its_clones(self):
        place = self.prepare("T-1")
        own = self.own(place)
        Path(own, "a.txt").write_text("T-1\n")
        self.git("add", "a.txt", cwd=own)
        self.git("commit", "--quiet", "-m", "never pushed", cwd=own)
        mine = self.git("rev-parse", "HEAD", cwd=own)
        Path(own, "scratch.txt").write_text("not committed\n")
        self.assertTrue(fleet.drop_place(place, self.said.append))
        self.assertFalse(os.path.exists(place))
        self.assertEqual(self.git("rev-parse", f"refs/fleet-kept/{GEN}/T-1/trunk", cwd=self.shared()), mine)
        self.assertTrue(any("1 file(s) of acme/web that it did not commit go with the task" in s for s in self.said))
        self.assertTrue(any(f"refs/fleet-kept/{GEN}/T-1/" in s and mine[:12] in s for s in self.said), self.said)
        # a clone whose commits cannot be kept stays, and says so once
        place = self.prepare("T-2")
        own = self.own(place)
        self.git("commit", "--quiet", "--allow-empty", "-m", "T-2", cwd=own)
        shutil.rmtree(self.shared())
        self.assertFalse(fleet.drop_place(place, self.said.append))
        self.assertFalse(fleet.drop_place(place, self.said.append))
        self.assertTrue(os.path.isdir(own))
        self.assertEqual(len([s for s in self.said if "could not be kept" in s]), 1)

    def test_a_stop_deletes_the_clones_only_once_the_window_is_gone(self):
        place = self.prepare("T-1")
        listed = {"windows": ["T-1"]}
        helper = types.SimpleNamespace(agent="ivy", say=self.said.append, look=lambda: [], look_sure=lambda: [],
                                       closing=lambda task: False, look_known=lambda: listed["windows"])
        stop = {"id": 4, "kind": "stop", "task": "T-1", "extra": {"generation": GEN, "needs": "none"}}
        acks = []
        patcher = patch.object(fleet, "http", lambda method, path, data=None, timeout=40: acks.append(path) or (200, {}))
        patcher.start()
        self.addCleanup(patcher.stop)
        for windows in (["T-1"], None):     # still open, or tmux did not answer: the event comes again
            listed["windows"] = windows
            with self.assertRaises(fleet.Refused):
                fleet.Helper.handle(helper, stop)
            self.assertTrue(os.path.isdir(place))
        listed["windows"] = []
        fleet.Helper.handle(helper, stop)
        self.assertFalse(os.path.exists(place))
        self.assertEqual(acks, ["/helper/ack/ivy"])         # acknowledged only once its clones went
        fleet.Helper.handle(helper, dict(stop, extra={"generation": "test-generation", "needs": "none"}))    # no place

    def test_a_new_generation_starts_clean_and_the_sweep_takes_what_no_open_task_holds(self):
        for agent, generation, window in (("ivy", GEN, "T-1"), ("ivy", GEN, "T-2"), ("ivy", GEN, "C-5"),
                                          ("ivy", GEN, "C-6"), ("ivy", GEN, "T-3"), ("ivy", OLD, "T-1"),
                                          ("kai", GEN, "T-2")):
            Path(fleet.task_place(agent, generation, window), "acme").mkdir(parents=True)
        Path(fleet.task_place("ivy", OLD, "T-1"), "acme", "old.txt").write_text("before the wipe\n")
        helper = types.SimpleNamespace(agent="ivy", say=self.said.append, places_at=0.0, poll_db=GEN,
                                       open_tasks=["T-1"], conversations=[5], look_known=lambda: ["T-3"])

        def left():
            root = Path(self.work, ".tasks")
            return sorted(str(p.relative_to(root)) for p in root.glob("*/*/*") if fleet.TASK_WINDOW.fullmatch(p.name))
        everything = left()
        for unknown in (dict(poll_db=None), dict(open_tasks=False, conversations=None)):
            fleet.Helper.sweep_places(types.SimpleNamespace(**dict(vars(helper), **unknown)))
            self.assertEqual(left(), everything if "poll_db" in unknown else
                             [p for p in everything if not p.startswith(f"ivy/{OLD}")])
        fleet.Helper.sweep_places(helper)
        self.assertEqual(left(), [f"ivy/{GEN}/C-5", f"ivy/{GEN}/T-1", f"ivy/{GEN}/T-3", f"kai/{GEN}/T-2"])
        self.assertFalse(os.path.exists(os.path.join(self.work, ".tasks", "ivy", OLD)))
        Path(fleet.task_place("ivy", GEN, "T-9"), "acme").mkdir(parents=True)
        fleet.Helper.sweep_places(helper)           # at most every PLACES_EVERY seconds
        self.assertIn(f"ivy/{GEN}/T-9", left())
        own = self.own(self.prepare("T-1", generation=OLD))     # the T-1 of a new database: a clone of its own
        self.assertEqual(sorted(os.listdir(own)), [".git", "README.md"])

    def test_two_helpers_make_their_first_clones_of_one_repository_at_the_same_time(self):
        results, start = {}, threading.Barrier(2)

        def first(window, agent):
            start.wait()
            results[window] = fleet.prepare_repos({"acme/web": "write"}, self.values,
                                                  fleet.task_place(agent, GEN, window))
        threads = [threading.Thread(target=first, args=(w, a)) for w, a in (("T-1", "ivy"), ("T-2", "kai"))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(results, {"T-1": {}, "T-2": {}})
        for agent, window in (("ivy", "T-1"), ("kai", "T-2")):
            own = self.own(fleet.task_place(agent, GEN, window))
            self.assertEqual(self.git("symbolic-ref", "--short", "HEAD", cwd=own), "trunk")

    # ---- each repository comes when the session asks for it (the owner, 9 November 2026: "fetch on demand")

    def ask(self, *names, place=None, repos="acme/web:write acme/lib:read"):
        """fleet.py repo <names>, as a task session runs it: its own variables, no helper. (status, out, err)."""
        out, err = io.StringIO(), io.StringIO()
        variables = dict(self.values, FLEET_REPOS=repos, **({"FLEET_WORK": place} if place else {}))
        status = 0
        with patch.dict(os.environ, variables), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            if not place:
                os.environ.pop("FLEET_WORK", None)
            try:
                fleet.cmd_repo(types.SimpleNamespace(repos=list(names)))
            except SystemExit as e:
                status = e.code
        return status, out.getvalue(), err.getvalue()

    def test_a_start_fetches_only_the_clones_that_the_task_has_and_the_session_asks_for_the_rest(self):
        self.remote("acme/lib")
        place = self.place("T-3")
        held = {"acme/web": "write", "acme/lib": "read"}
        self.assertEqual(fleet.held_repos(held, place), {})                      # a new task: nothing at its start
        self.assertFalse(os.path.exists(self.shared()) or os.path.exists(self.shared("acme/lib")))
        self.assertEqual(self.ask("Other-Org/nope", "acme/web", place=place)[0], 1)    # one refused: status 1
        status, out, err = self.ask("https://github.com/Acme/Web.git", place=place)
        self.assertEqual((status, out, err), (0, self.own(place) + "\n", ""))
        self.assertEqual(self.git("symbolic-ref", "--short", "HEAD", cwd=self.own(place)), "trunk")
        self.assertFalse(os.path.exists(self.shared("acme/lib")), "only the repository that was asked for")
        self.assertEqual(fleet.held_repos(held, place), {"acme/web": "write"})  # its next start fetches this one
        self.assertEqual(fleet.held_repos(held, None), {})
        pushed = self.push_elsewhere()
        status, out, _ = self.ask("acme/web", place=place)                      # asked again: fetched
        self.assertEqual((status, self.git("rev-parse", "origin/trunk", cwd=self.own(place))), (0, pushed))
        status, out, _ = self.ask("acme/lib")                                   # no place: the shared clone
        self.assertEqual((status, out), (0, self.shared("acme/lib") + "\n"))

    def test_a_repository_that_the_session_does_not_hold_and_a_folder_outside_the_tasks_are_refused(self):
        place = self.place("T-3")
        status, out, err = self.ask("acme/other", "acme/web/../../x", place=place)
        self.assertEqual((status, out), (1, ""))
        self.assertIn('acme/other: not one of your repositories. They are in FLEET_REPOS; for another one, ask your '
                      'requester with needs_access="repo:acme/other".', err)
        self.assertFalse(os.path.exists(os.path.join(place, "acme")) or os.path.exists(self.shared()))
        status, out, err = self.ask("acme/web", place=str(self.tmp / "elsewhere"))
        self.assertEqual((status, out), (1, ""))
        self.assertIn("FLEET_WORK is not a task's folder", err)
        self.assertFalse(os.path.exists(self.tmp / "elsewhere"))

    def test_each_start_fetches_the_shared_clones_that_are_there_in_the_background_and_clones_none(self):
        """A duty's check reads the shared clones outside any session (a scan of their lockfiles): they stay as fresh as
        when every start fetched them all, without a start that waits, and a repository that never came stays away."""
        self.assertIsNone(fleet.refresh_shared({"acme/web": "write"}, self.values))     # no shared clone yet
        self.assertEqual(self.ask("acme/web")[0], 0)
        pushed = self.push_elsewhere()
        thread = fleet.refresh_shared({"acme/web": "write", "acme/lib": "read"}, self.values)
        thread.join(60)
        self.assertEqual(self.git("rev-parse", "origin/trunk", cwd=self.shared()), pushed)
        self.assertFalse(os.path.exists(self.shared("acme/lib")))

    def test_a_first_clone_that_stopped_half_way_leaves_nothing_in_the_way(self):
        """A session's command can run out of time in the middle of a big first clone: the next one starts again."""
        half = Path(fleet.task_work(), ".cloning", "acme", "web")
        half.mkdir(parents=True)
        (half / "junk").write_text("x")
        self.assertEqual(self.ask("acme/web")[:2], (0, self.shared() + "\n"))
        self.assertFalse(half.exists())
        status, _, err = self.ask("acme/lib")                                   # not on the stand-in GitHub
        self.assertEqual(status, 1)
        self.assertIn("acme/lib: ", err)
        self.assertFalse(os.path.lexists(self.shared("acme/lib")) or Path(fleet.task_work(), ".cloning", "acme",
                                                                           "lib").exists())

    # ---- T3 Code idea 4: a snapshot ref and one line of facts at each later attempt
    def clone_state(self, own):
        """Everything of a clone that a snapshot must not change: each file of the work tree with its bytes and its
        time, the index and HEAD with theirs, the branches, and what git status says."""
        files = {}
        for root, dirs, names in os.walk(own):
            dirs[:] = [d for d in dirs if d != ".git"]
            for name in names:
                path = os.path.join(root, name)
                files[os.path.relpath(path, own)] = (Path(path).read_bytes(), os.stat(path).st_mtime_ns)
        meta = {name: (Path(own, ".git", name).read_bytes(), os.stat(os.path.join(own, ".git", name)).st_mtime_ns)
                for name in ("index", "HEAD")}
        return (files, meta, self.git("for-each-ref", "--format=%(refname) %(objectname)", "refs/heads", "refs/remotes",
                                      cwd=own),
                self.git("--no-optional-locks", "status", "--porcelain", "--untracked-files=all", cwd=own))

    def worked(self, place):
        """Attempt 1 of T-3 leaves: one push, one commit that origin does not have, a changed file, a staged new file,
        a new file and an ignored one."""
        own = self.own(place)
        Path(own, ".gitignore").write_text("*.log\n")
        self.git("add", ".gitignore", cwd=own)
        self.git("commit", "--quiet", "-m", "ignore logs", cwd=own)
        self.git("push", "--quiet", cwd=own)
        pushed = self.git("rev-parse", "--short", "HEAD", cwd=own)
        Path(own, "a.txt").write_text("committed, not pushed\n")
        self.git("add", "a.txt", cwd=own)
        self.git("commit", "--quiet", "-m", "not pushed", cwd=own)
        Path(own, "README.md").write_text("changed, not staged\n")
        Path(own, "staged.txt").write_text("staged\n")
        self.git("add", "staged.txt", cwd=own)
        Path(own, "draft.txt").write_text("new, not added\n")
        Path(own, "debug.log").write_text("ignored\n")
        return own, pushed

    def test_integration_env_puts_the_line_of_a_real_clone_in_the_github_note(self):
        place = self.prepare("T-3")
        self.worked(place)
        answer = (200, {"repos": {"acme/web": "write"}, "tokens": []})
        with patch.object(fleet, "checkout_conf", return_value={"repos": {"acme/web": "write"}}), \
                patch.object(fleet, "http", return_value=answer), \
                patch.object(fleet, "prepare_repos", return_value={}), \
                patch.object(fleet, "refresh_shared", return_value=None), \
                contextlib.redirect_stdout(io.StringIO()):
            values = fleet.integration_env("ivy", {"role": "worker", "runtime": "claude"}, None, place, attempt=2)
        self.assertIn("Your clone of acme/web as attempt 2 starts: 1 commit(s) that origin does not have",
                      values["FLEET_GITHUB_NOTE"])

    def test_a_later_attempt_snapshots_its_clone_says_its_facts_and_changes_nothing(self):
        own, pushed = self.worked(self.prepare("T-3"))
        before = self.clone_state(own)
        line = fleet.attempt_note(own, "acme/web", 2, capture=True)
        self.assertEqual(self.clone_state(own), before)             # no file, no index, no HEAD, no branch
        self.assertEqual(line, f"Your clone of acme/web as attempt 2 starts: 1 commit(s) that origin does not have, "
                               f"3 file(s) not committed, 1 push(es) to origin since the task made this clone (the "
                               f"last: {pushed}). refs/fleet-attempt/2 holds all its files as this attempt started (`git "
                               f"diff refs/fleet-attempt/2 -- <path>` compares one with it). Check these before you "
                               f"repeat a commit or a push (rule 9).")
        for path in ("draft", "staged", "README", "debug", "a.txt"):
            self.assertNotIn(path, line)                            # counts and short ids only
        ref = "refs/fleet-attempt/2"
        self.assertEqual(self.git("rev-parse", f"{ref}^", cwd=own), self.git("rev-parse", "HEAD", cwd=own))
        self.assertEqual(self.git("show", f"{ref}:README.md", cwd=own), "changed, not staged")
        self.assertEqual(self.git("show", f"{ref}:draft.txt", cwd=own), "new, not added")
        self.assertEqual(self.git("show", f"{ref}:staged.txt", cwd=own), "staged")
        self.assertNotIn("debug.log", self.git("ls-tree", "--name-only", ref, cwd=own).split())
        self.assertEqual(self.git("diff", "--name-only", ref, "--", "README.md", "staged.txt", cwd=own), "")
        # attempt 3: the pushes since attempt 2 started, and the ref of each attempt
        time.sleep(1.1)                                             # the reflog counts in whole seconds
        self.git("commit", "--quiet", "-am", "attempt 2's work", cwd=own)
        self.git("push", "--quiet", "origin", "HEAD", cwd=own)
        second = self.git("rev-parse", "--short", "HEAD", cwd=own)
        line = fleet.attempt_note(own, "acme/web", 3, capture=True)
        self.assertIn(f"1 push(es) to origin since attempt 2 started (the last: {second})", line)
        self.assertIn("`git diff refs/fleet-attempt/2 refs/fleet-attempt/3` shows what attempt 2 changed", line)
        self.assertEqual(self.git("diff", "--name-only", "refs/fleet-attempt/2", "refs/fleet-attempt/3", cwd=own),
                         "")        # attempt 2 committed and pushed what was there: the files are the same
        self.assertIn("0 commit(s) that origin does not have, 1 file(s) not committed", line)   # draft.txt
        # fleet.py repo gives the same facts later in the session, on stderr, with no new snapshot
        place = self.place("T-3")
        with patch.dict(os.environ, {"FLEET_ATTEMPT": "3"}):
            status, out, err = self.ask("acme/web", place=place)
        self.assertEqual((status, out), (0, own + "\n"))
        self.assertIn("Your clone of acme/web now: 0 commit(s) that origin does not have", err)
        self.assertIn("refs/fleet-attempt/3 holds all its files as this attempt started", err)
        self.assertEqual(self.ask("acme/web", place=place)[2], "")            # attempt 1: no line
        # the end of the task: the refs go with the folder, and none reaches the shared clone
        self.assertTrue(fleet.drop_place(place, self.said.append))
        self.assertFalse(os.path.exists(own))
        self.assertEqual(self.git("for-each-ref", "refs/fleet-attempt", cwd=self.shared()), "")

    def test_the_snapshot_runs_no_program_that_the_clones_own_config_names(self):
        own, _ = self.worked(self.prepare("T-3"))
        ran = os.path.join(str(self.tmp), "ran")
        program = os.path.join(str(self.tmp), "program.sh")
        Path(program).write_text(f"#!/bin/sh\ntouch {ran}\ncat\n")
        os.chmod(program, 0o755)
        for key in ("filter.any.clean", "filter.any.process", "core.fsmonitor"):
            self.git("config", key, program, cwd=own)
        Path(own, ".git", "info", "attributes").write_text("* filter=any\n")
        line = fleet.attempt_note(own, "acme/web", 2, capture=True)
        self.assertIn("refs/fleet-attempt/2 holds all its files", line)
        self.assertFalse(os.path.exists(ran))
        self.assertIn("draft.txt", self.git("ls-tree", "-r", "--name-only", "refs/fleet-attempt/2", cwd=own))

    def test_a_stopped_rebase_is_said_and_files_above_the_limit_make_no_snapshot(self):
        own = self.own(self.prepare("T-3"))
        Path(own, "big.bin").write_bytes(b"x" * 64)
        Path(own, ".git", "MERGE_HEAD").write_text(self.git("rev-parse", "HEAD", cwd=own) + "\n")
        with patch.object(fleet, "ATTEMPT_MOST", 10):
            line = fleet.attempt_note(own, "acme/web", 2, capture=True)
        self.assertIn("1 file(s) not committed, a merge that stopped half way, 0 push(es)", line)
        self.assertIn("too big for a snapshot, so this attempt has no refs/fleet-attempt ref", line)
        self.assertEqual(self.git("for-each-ref", "refs/fleet-attempt", cwd=own), "")
        with patch.object(fleet, "attempt_capture", side_effect=OSError("disk full")):     # a failure: no line
            self.assertIsNone(fleet.attempt_note(own, "acme/web", 2, capture=True))
        self.assertIsNone(fleet.attempt_note(self.own(self.place("T-9")), "acme/web", 2, capture=True))


if __name__ == "__main__":
    unittest.main()
