"""A task's output reaches the configuration ref through the hub (helper feature task_outputs, 25 October 2026): when
an agent delivers, its helper sends the files of outputs/T-<id>/, and the hub commits only those, signed by the agent,
before the task closes. A running task sends its folder the same way before it delivers (report_progress outputs,
helper feature outputs_early, 25 November 2026), and its checkout keeps its newer work over each move. In-process hub,
temporary Git repositories and a helper thread; no fleet or AI calls."""
import base64
import contextlib
import hashlib
import json
import os
import random
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import fleet
import hub
import lifecycle
from leftovers import scratch_home
from test_ui_api import OwnerAPI

TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"]}}}
VPS = TEAM["addresses"]["vps"]


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real ~/.fleet (leftovers.scratch_home)


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (HelperFiles, Checkout, Delivery, Early, BytesSearch, TaskNumbers, Revision):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


def git(*args, cwd=None):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def write(root, files):
    for path, data in files.items():
        full = Path(root) / path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_bytes(data if isinstance(data, bytes) else data.encode())


def repository(root, files):
    """origin.git with `main` and `config` from one seed commit, and a checkout `kit` on `config`."""
    seed = root / "seed"
    write(seed, files)
    git("init", "-q", str(seed))
    git("add", "-A", cwd=seed)
    git("commit", "-q", "-m", "seed", cwd=seed)
    git("branch", hub.CONFIG_BRANCH, cwd=seed)
    git("clone", "-q", "--bare", str(seed), str(root / "origin.git"))
    git("clone", "-q", "-b", hub.CONFIG_BRANCH, str(root / "origin.git"), str(root / "kit"))
    return root / "kit"


class HelperFiles(unittest.TestCase):
    """fleet.collect_outputs: what a helper sends of outputs/T-<id>/."""

    def setUp(self):
        self.kit = Path(tempfile.mkdtemp(prefix="fleet-outputs-kit-"))
        self.addCleanup(shutil.rmtree, str(self.kit), True)

    def collect(self, ref="T-7"):
        files, skipped = fleet.collect_outputs(str(self.kit), ref)
        return [f["path"] for f in files], {s["path"]: s["why"] for s in skipped}

    def test_the_regular_files_of_the_folder_and_nothing_of_another_task(self):
        write(self.kit, {"outputs/T-7/report.md": "# Report\n", "outputs/T-7/data/rows.csv": "a,b\n",
                         "outputs/T-7/shot.png": b"\x89PNG\r\n\x1a\nxx", "outputs/T-8/other.md": "no", "RULES.md": "no"})
        files, skipped = fleet.collect_outputs(str(self.kit), "T-7")
        self.assertEqual([f["path"] for f in files],
                         ["outputs/T-7/report.md", "outputs/T-7/shot.png", "outputs/T-7/data/rows.csv"])
        self.assertEqual(base64.b64decode(files[1]["data"]), b"\x89PNG\r\n\x1a\nxx")
        self.assertEqual(skipped, [])

    def test_the_screen_captures_dot_files_and_pythons_cache_stay_without_a_word(self):
        """Python's cache at any depth: on the configuration ref it would be a tracked file that Python writes again
        in each checkout, and a checkout with a change stops the update at a task's start."""
        write(self.kit, {"outputs/T-7/computer-use/capture-1.png": b"x", "outputs/T-7/.DS_Store": b"x",
                         "outputs/T-7/.hidden/x.md": "x", "outputs/T-7/sub/computer-use/kept.md": "x",
                         "outputs/T-7/__pycache__/tool.cpython-312.pyc": b"\x00",
                         "outputs/T-7/sub/__pycache__/a.pyc": b"\x00"})
        # only the folder of the task itself is Fleet's: one deeper down is the agent's own
        self.assertEqual(self.collect(), (["outputs/T-7/sub/computer-use/kept.md"], {}))

    def test_what_is_not_sent_is_named_with_why(self):
        write(self.kit, {"outputs/T-7/a b.md": "x", "outputs/T-7/-n": "x", "outputs/T-7/ok.md": "x",
                         "outputs/T-7/1/2/3/4/5/deep.md": "x", "outputs/T-7/1/2/3/4/5/6/deeper.md": "x"})
        os.symlink(str(self.kit / "outputs/T-7/ok.md"), str(self.kit / "outputs/T-7/link.md"))
        os.symlink(str(self.kit / "outputs/T-7/1"), str(self.kit / "outputs/T-7/linked"))
        files, skipped = self.collect()
        self.assertEqual(files, ["outputs/T-7/ok.md", "outputs/T-7/1/2/3/4/5/deep.md"])
        self.assertEqual(skipped, {"outputs/T-7/a b.md": fleet.OUTPUT_BAD_NAME, "outputs/T-7/-n": fleet.OUTPUT_BAD_NAME,
                                   "outputs/T-7/link.md": "not a regular file", "outputs/T-7/linked/": "a symbolic link",
                                   "outputs/T-7/1/2/3/4/5/6/": "deeper than 6 names"})

    def test_no_name_is_agents_md_in_any_case_of_its_letters(self):
        """The AI providers spec, section 3.11 item 9: OpenCode gives the model an AGENTS.md of a folder below its
        working folder as instructions, and the outputs reach every agent's checkout. Each folder holds one of the
        names, as a disk that ignores the case of letters can keep them; the names that only look like it go."""
        write(self.kit, {"outputs/T-7/AGENTS.md": "x", "outputs/T-7/sub/agents.md": "x", "outputs/T-7/doc/Agents.Md": "x",
                         "outputs/T-7/AGENTS.md.txt": "x", "outputs/T-7/my-agents.md": "x", "outputs/T-7/agents.mdx": "x",
                         "outputs/T-7/sub/report.md": "x", "outputs/T-7/deep/AGENTS.MD/inside.md": "x"})
        files, skipped = self.collect()
        self.assertEqual(files, ["outputs/T-7/AGENTS.md.txt", "outputs/T-7/agents.mdx", "outputs/T-7/my-agents.md",
                                 "outputs/T-7/sub/report.md"])
        self.assertEqual(skipped, {"outputs/T-7/AGENTS.md": fleet.OUTPUT_BAD_NAME,
                                   "outputs/T-7/deep/AGENTS.MD/": fleet.OUTPUT_BAD_NAME,
                                   "outputs/T-7/doc/Agents.Md": fleet.OUTPUT_BAD_NAME,
                                   "outputs/T-7/sub/agents.md": fleet.OUTPUT_BAD_NAME})
        self.assertIn("AGENTS.md", fleet.OUTPUT_BAD_NAME)       # the reason says it

    def test_the_hubs_limits_of_count_size_and_sum(self):
        write(self.kit, {"outputs/T-7/a.md": "1234", "outputs/T-7/b.md": "12345678", "outputs/T-7/c.md": "12",
                         "outputs/T-7/d.md": "12"})
        with patch.object(fleet, "OUTPUT_FILES", 2):
            self.assertEqual(self.collect(), (["outputs/T-7/a.md", "outputs/T-7/b.md"],
                                              {"outputs/T-7/c.md": "more than 2 files",
                                               "outputs/T-7/d.md": "more than 2 files"}))
        with patch.object(fleet, "OUTPUT_FILE_MAX", 6), patch.object(fleet, "OUTPUT_TOTAL_MAX", 7):
            files, skipped = self.collect()
        self.assertEqual(files, ["outputs/T-7/a.md", "outputs/T-7/c.md"])
        self.assertEqual(sorted(skipped), ["outputs/T-7/b.md", "outputs/T-7/d.md"])
        self.assertTrue(skipped["outputs/T-7/b.md"].startswith("over ") and "in all" not in skipped["outputs/T-7/b.md"])
        self.assertTrue(skipped["outputs/T-7/d.md"].endswith("in all"))

    def test_no_folder_sends_nothing(self):
        self.assertEqual(fleet.collect_outputs(str(self.kit), "T-7"), ([], []))


class Checkout(unittest.TestCase):
    """lifecycle.follow_config_ref and a Fleet update (Lifecycle.apply) once the hub took in a task's files: the copies
    with the same bytes give way, and the agent's newer work stays as it is over the move."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="fleet-outputs-checkout-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        self.kit = repository(self.root, {"RULES.md": "# Rules\n"})

    def hub_commits(self, files):
        """What the hub does with a delivery or a release: one commit of these files on origin's configuration ref.
        Returns that commit."""
        work = self.root / "hub"
        if not work.exists():
            git("clone", "-q", "-b", hub.CONFIG_BRANCH, str(self.root / "origin.git"), str(work))
        write(work, {path: data for path, data in files.items() if data is not None})
        for path in [path for path, data in files.items() if data is None]:
            (work / path).unlink()              # a file that the send no longer holds leaves the ref
        git("add", "-A", cwd=work)
        git("commit", "-q", "-m", "delivered", cwd=work)
        git("push", "-q", "origin", "HEAD:" + hub.CONFIG_BRANCH, cwd=work)
        return git("rev-parse", "HEAD", cwd=work)

    def update(self, desired):
        """The Fleet update that the hub requests of this checkout's helper: (True when it asked for its restart,
        the state, the detail)."""
        home = tempfile.mkdtemp(prefix="fleet-outputs-home-")
        self.addCleanup(shutil.rmtree, home, True)
        lc = lifecycle.Lifecycle(str(self.kit), "vps", TEAM["agents"]["vps"], post=None, busy=lambda: False,
                                 restart=lambda: True, platform_name="linux", home=home,
                                 models=lambda exe: (None, "no model list in this test"))
        lc.report = lambda **_: True                    # the machine's report is not what this checks
        return lc.apply(desired), lc.state, lc.detail

    def test_an_untracked_copy_with_the_same_bytes_gives_way_and_other_work_stays(self):
        write(self.kit, {"outputs/T-3/report.md": "# Report\n", "outputs/T-4/draft.md": "mine"})
        self.hub_commits({"outputs/T-3/report.md": "# Report\n"})
        self.assertIsNone(lifecycle.follow_config_ref(str(self.kit)))
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.kit),
                         git("rev-parse", hub.CONFIG_BRANCH, cwd=self.root / "origin.git"))
        self.assertEqual((self.kit / "outputs/T-3/report.md").read_text(), "# Report\n")
        self.assertEqual(git("status", "--porcelain", cwd=self.kit), "?? outputs/T-4/")

    def test_a_file_with_other_bytes_is_newer_work_that_stays_over_the_move(self):
        """The agent writes on after a send of its folder (report_progress outputs): the move that brings the send
        neither stops at the newer file, as it did, nor writes the sent bytes over it."""
        write(self.kit, {"outputs/T-3/report.md": "my own"})
        head = self.hub_commits({"outputs/T-3/report.md": "# Report\n"})
        self.assertIsNone(lifecycle.follow_config_ref(str(self.kit)))
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.kit), head)
        self.assertEqual((self.kit / "outputs/T-3/report.md").read_text(), "my own")
        self.assertFalse(os.path.exists(self.kit / ".git" / lifecycle.OUTPUTS_ASIDE))

    def test_the_next_fleet_update_after_a_delivery_takes_the_files_back_tracked(self):
        """26 October 2026, release 2026.11.53: the update merged over the untracked copy of a file that its helper
        had sent, and refused (machine_failed) until the copy was removed by hand."""
        write(self.kit, {"outputs/T-1/route-check.md": "# Route\n", "outputs/T-2/draft.md": "mine"})
        self.hub_commits({"outputs/T-1/route-check.md": "# Route\n"})
        # an update of data: code comes only with a signed release (lifecycle.may_take, test_signed_code)
        update = self.hub_commits({"knowledge/services.md": "# Services\n"})
        self.assertEqual(self.update(update), (True, "updating", "Updating Fleet while idle."))
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.kit), update)
        self.assertEqual((self.kit / "outputs/T-1/route-check.md").read_text(), "# Route\n")
        self.assertEqual(git("status", "--porcelain", cwd=self.kit), "?? outputs/T-2/")

    def test_a_fleet_update_keeps_a_tasks_newer_file_and_moves(self):
        """Before, an update over a file with other bytes failed (machine_failed) until the file changed: with a send
        before delivery, that is every update while a task writes on after its send."""
        write(self.kit, {"outputs/T-1/route-check.md": "my own"})
        self.hub_commits({"outputs/T-1/route-check.md": "# Route\n"})
        update = self.hub_commits({"knowledge/services.md": "# Services\n"})
        self.assertEqual(self.update(update), (True, "updating", "Updating Fleet while idle."))
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.kit), update)
        self.assertEqual((self.kit / "outputs/T-1/route-check.md").read_text(), "my own")

    def test_a_sent_folder_that_the_agent_changes_never_stops_the_moves(self):
        """Each send of a running task's folder comes back to its checkout tracked, and the agent changes and removes
        its files after a send. The checkout moves on each time (before, a changed tracked file stopped every later
        move: "the checkout has its own changes"), keeps the agent's newer bytes and its removals (also of a file that
        the move changes and does not remove), and is clean again once the last send holds what the folder holds."""
        out = "outputs/T-5/"
        write(self.kit, {out + "a.md": "one", out + "b.md": "bee", out + "d.md": "dee"})
        self.hub_commits({out + "a.md": "one", out + "b.md": "bee", out + "d.md": "dee"})     # the first send
        self.assertIsNone(lifecycle.follow_config_ref(str(self.kit)))
        self.assertEqual(git("status", "--porcelain", cwd=self.kit), "")
        write(self.kit, {out + "a.md": "two", out + "b.md": "bee two"})
        (self.kit / out / "d.md").unlink()
        self.hub_commits({out + "a.md": "two", out + "b.md": "bee two", out + "d.md": None})   # the second send
        write(self.kit, {out + "a.md": "three", out + "c.md": "sea"})            # the agent writes on after it
        (self.kit / out / "b.md").unlink()
        head = self.hub_commits({"knowledge/services.md": "# Services\n"})     # data: code needs a signed release
        self.assertIsNone(lifecycle.follow_config_ref(str(self.kit)))
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.kit), head)
        self.assertEqual((self.kit / "knowledge/services.md").read_text(), "# Services\n")
        self.assertEqual((self.kit / out / "a.md").read_text(), "three")
        self.assertFalse((self.kit / out / "b.md").exists())
        self.assertFalse((self.kit / out / "d.md").exists())
        self.assertEqual(git("status", "--porcelain", cwd=self.kit),               # git() strips the first space
                         f"M {out}a.md\n D {out}b.md\n?? {out}c.md")
        self.hub_commits({out + "a.md": "three", out + "b.md": None, out + "c.md": "sea"})    # the delivery
        self.assertIsNone(lifecycle.follow_config_ref(str(self.kit)))
        self.assertEqual(git("status", "--porcelain", cwd=self.kit), "")
        self.assertFalse(os.path.exists(self.kit / ".git" / lifecycle.OUTPUTS_ASIDE))

    def test_a_move_that_fails_gives_the_agent_its_files_back(self):
        """A file with the bytes that the move brings leaves its place for the merge too: when the merge then fails
        (here an untracked file outside outputs/ that the move would write over), the agent still finds it, and its
        next send does not take it off the ref."""
        out = "outputs/T-7/"
        write(self.kit, {out + "a.md": "sent", "knowledge/notes.md": "mine"})
        self.hub_commits({out + "a.md": "sent", "knowledge/notes.md": "the hub's"})
        self.assertIn("git merge failed", lifecycle.follow_config_ref(str(self.kit)))
        self.assertEqual((self.kit / out / "a.md").read_text(), "sent")
        self.assertFalse(os.path.exists(self.kit / ".git" / lifecycle.OUTPUTS_ASIDE))

    def test_what_a_stop_left_aside_goes_back_only_where_git_left_the_file(self):
        """A stop of the helper between give_way_to and put_back left the agent's newer file only in the git folder:
        the next move puts it back, but not over a file that the agent wrote again since, and that copy is kept."""
        out = "outputs/T-6/"
        write(self.kit, {out + "a.md": "sent", out + "b.md": "sent"})
        self.hub_commits({out + "a.md": "sent", out + "b.md": "sent"})
        self.assertIsNone(lifecycle.follow_config_ref(str(self.kit)))
        aside = self.kit / ".git" / lifecycle.OUTPUTS_ASIDE / "kept"
        write(aside, {out + "a.md": "newer", out + "b.md": "newer"})
        write(self.kit, {out + "b.md": "written again"})
        self.hub_commits({"knowledge/services.md": "# Services\n"})
        self.assertIsNone(lifecycle.follow_config_ref(str(self.kit)))
        self.assertEqual((self.kit / out / "a.md").read_text(), "newer")
        self.assertEqual((self.kit / out / "b.md").read_text(), "written again")
        left = self.kit / ".git" / lifecycle.OUTPUTS_LEFT / out
        self.assertEqual((left / "b.md.1").read_text(), "newer")
        self.assertFalse(os.path.exists(self.kit / ".git" / lifecycle.OUTPUTS_ASIDE))
        write(aside, {out + "b.md": "newest"})                  # a second stop, and the agent writes again
        write(self.kit, {out + "b.md": "written a third time"})
        lifecycle.put_back_now(str(self.kit))                   # the helper's start, or its next send
        self.assertEqual((left / "b.md.1").read_text(), "newer")
        self.assertEqual((left / "b.md.2").read_text(), "newest")
        self.assertEqual(lifecycle.left_copies(str(self.kit), "T-6"),
                         [f".git/{lifecycle.OUTPUTS_LEFT}/{out}b.md.1", f".git/{lifecycle.OUTPUTS_LEFT}/{out}b.md.2"])

    def test_the_helpers_send_puts_back_what_a_stop_left_and_names_the_left_copies(self):
        """A stop of the helper in the middle of a move left the agent's newer file in the git folder: its next send
        of the folder takes it from its place, not the old bytes, and names the copies that a move could not put
        back."""
        out = "outputs/T-8/"
        write(self.kit, {out + "a.md": "sent"})
        self.hub_commits({out + "a.md": "sent"})
        self.assertIsNone(lifecycle.follow_config_ref(str(self.kit)))
        write(self.kit / ".git" / lifecycle.OUTPUTS_ASIDE / "kept", {out + "a.md": "newer"})
        write(self.kit / ".git" / lifecycle.OUTPUTS_LEFT, {out + "b.md.1": "older"})
        sent = []

        def http(method, path, body, timeout=0):
            sent.append(body)
            return 200, {"taken": True}
        helper = type("Stub", (), {"agent": "vps", "say": lambda self, text: None})()
        with patch.object(fleet, "KIT", str(self.kit)), patch.object(fleet, "http", http):
            fleet.Helper.send_outputs(helper, {"task": "T-8", "outputs": "token"})
        self.assertEqual([(f["path"], base64.b64decode(f["data"])) for f in sent[0]["files"]],
                         [(out + "a.md", b"newer")])
        self.assertEqual((sent[0]["folder"], sent[0]["left"]), (True, [f".git/{lifecycle.OUTPUTS_LEFT}/{out}b.md.1"]))


class Outputs(OwnerAPI):
    """The fixture of Delivery and Early: a hub, its configuration ref, the agent's own checkout and its helper. It
    holds no test of its own."""

    def setUp(self):
        super().setUp()
        hub.TEAM = json.loads(json.dumps(TEAM))
        self.root = Path(tempfile.mkdtemp(prefix="fleet-outputs-"))
        self.kit = repository(self.root, {".gitignore": "*.log\n__pycache__/\n",    # as the published one
                                          "team.json": json.dumps(TEAM, indent=2) + "\n", "RULES.md": "# Rules\n",
                                          "hub.py": "# the hub\n"})
        hub.CFG["team_path"] = str(self.kit / "team.json")
        hub._revision_cache.update(at=0.0, value=None)
        hub._code_diffs.clear()
        self.addCleanup(self.put_back)
        self.checkout = self.root / "vps"           # the agent's own checkout, on its machine
        self.checkout.mkdir()
        self.features(["mcp_program", "task_outputs"])
        self.task = hub.ins("INSERT INTO tasks(title,details,done_when,needs,owner,requester,state,created,attempt) "
                            "VALUES(?,?,?,?,?,?,'working',?,1)",
                            ("Write the report", "For the shop", "the report is there", "none", "vps", "manager",
                             hub.now()))
        self.ref = hub.tref(self.task)
        self.answers = []

    def put_back(self):
        hub.CFG.pop("team_path", None)
        hub._revision_cache.update(at=0.0, value=None)
        hub._code_diffs.clear()
        shutil.rmtree(str(self.root), ignore_errors=True)

    def features(self, names):
        hub.q("INSERT INTO machine_status(agent,data,reported) VALUES('vps',?,?) ON CONFLICT(agent) DO UPDATE SET "
              "data=excluded.data", (json.dumps({"features": names}), hub.now()))

    def helper(self, before=None):
        """The agent's helper: it takes the hub's request for the files and sends the folder through the route."""
        def run():
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                row = hub.q1("SELECT extra FROM events WHERE agent='vps' AND kind='outputs' ORDER BY id DESC LIMIT 1")
                if row:
                    extra = json.loads(row["extra"])
                    if before:
                        before()
                    files, skipped = fleet.collect_outputs(str(self.checkout), extra["task"])
                    self.answers.append(self.request("/helper/outputs/vps", {"outputs": extra["outputs"],
                                        "task": extra["task"], "files": files, "skipped": skipped}, source=VPS))
                    return
                time.sleep(0.05)
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 15)

    def deliver(self, **args):
        args = dict(dict(task_id=self.ref, outcome="completed", what_was_done="Wrote the report.",
                         where_output_is=f"outputs/{self.ref}/report.md", how_checked="Read it back."), **args)
        return hub.call_tool("vps", "deliver_result", args, ("test-generation", self.ref, 1))

    def origin(self, *args):
        return git(*args, cwd=self.root / "origin.git")


class Delivery(Outputs):
    """deliver_result asks the session's helper for the files, and the hub commits them before the task closes."""

    def test_the_files_are_committed_by_the_agent_before_the_task_closes(self):
        """Also a file that .gitignore names (run.log): before, git refused it, and the whole delivery with it."""
        write(self.checkout, {f"outputs/{self.ref}/report.md": "# Report\n", f"outputs/{self.ref}/run.log": "ok\n",
                              f"outputs/{self.ref}/computer-use/capture-1.png": b"x", "RULES.md": "changed"})
        self.helper()
        text, error = self.deliver()
        self.assertFalse(error, text)
        commit = self.origin("rev-parse", hub.CONFIG_BRANCH)
        files = f"outputs/{self.ref}/report.md, outputs/{self.ref}/run.log"
        self.assertEqual(text, f"Delivered. {self.ref} is completed. Its files are on the configuration ref as "
                               f"{commit[:12]}: {files}. You are done with it: stop now and end your turn; your session closes when it ends.")
        self.assertEqual(self.origin("ls-tree", "-r", "--name-only", hub.CONFIG_BRANCH).split(),
                         [".gitignore", "RULES.md", "hub.py", f"outputs/{self.ref}/report.md",
                          f"outputs/{self.ref}/run.log", "team.json"])
        self.assertEqual(self.origin("show", f"{hub.CONFIG_BRANCH}:outputs/{self.ref}/report.md"), "# Report")
        self.assertEqual(self.origin("log", "-1", "--format=%an", hub.CONFIG_BRANCH), "Fleet agent vps")
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.kit), commit)        # the hub checkout took it in
        said = hub.q1("SELECT text FROM events WHERE agent='manager' AND kind='say' ORDER BY id DESC LIMIT 1")["text"]
        self.assertIn(f"Output: outputs/{self.ref}/report.md. Its files are on the configuration ref as "
                      f"{commit[:12]}: {files}. Checked: Read it back.", said)
        self.assertEqual(hub.q1("SELECT state FROM tasks WHERE id=?", (self.task,))["state"], "completed")
        self.assertEqual(self.answers, [(200, {"taken": True})])

    def test_a_delivery_with_no_files_reads_as_before_and_commits_nothing(self):
        before = self.origin("rev-parse", hub.CONFIG_BRANCH)
        self.helper()
        text, error = self.deliver()
        self.assertFalse(error, text)
        self.assertEqual(text, f"Delivered. {self.ref} is completed. You are done with it: stop now and end your turn; your session closes when it ends.")
        self.assertEqual(self.origin("rev-parse", hub.CONFIG_BRANCH), before)

    def test_an_older_helper_is_not_asked_and_the_result_reads_as_before(self):
        self.features(["mcp_program"])
        text, error = self.deliver()
        self.assertFalse(error, text)
        self.assertEqual(text, f"Delivered. {self.ref} is completed. You are done with it: stop now and end your turn; your session closes when it ends.")
        self.assertIsNone(hub.q1("SELECT id FROM events WHERE kind='outputs'"))

    def test_files_that_come_after_the_wait_are_committed_for_the_delivered_task(self):
        """Plan C7: no clock refuses them. The result says that they are on their way, and when they come the hub
        commits them for the delivered task and names the commit to its requester, once."""
        write(self.checkout, {f"outputs/{self.ref}/report.md": "x"})
        before = self.origin("rev-parse", hub.CONFIG_BRANCH)
        with patch.object(hub, "OUTPUTS_WAIT", 0.5):
            text, error = self.deliver()
        self.assertFalse(error, text)
        self.assertIn("Its files are on their way from vps's helper: the hub commits them when they come", text)
        self.assertEqual(hub.q1("SELECT state FROM tasks WHERE id=?", (self.task,))["state"], "completed")
        token = json.loads(hub.q1("SELECT extra FROM events WHERE kind='outputs'")["extra"])["outputs"]
        self.assertTrue(hub.outputs_waiting(token, "vps"))          # the helper is still handed the request
        files, _ = fleet.collect_outputs(str(self.checkout), self.ref)
        answer = {"outputs": token, "task": self.ref, "files": files}
        self.assertEqual(self.request("/helper/outputs/vps", answer, source=VPS), (200, {"taken": True}))
        commit = self.origin("rev-parse", hub.CONFIG_BRANCH)
        self.assertNotEqual(commit, before)
        said = hub.q1("SELECT text FROM events WHERE agent='manager' AND kind='say' ORDER BY id DESC LIMIT 1")["text"]
        self.assertIn(f"came after its delivery. Its files are on the configuration ref as {commit[:12]}", said)
        self.assertEqual(self.request("/helper/outputs/vps", answer, source=VPS), (200, {"taken": False}))
        self.assertFalse(hub.outputs_waiting(token, "vps"))

    def test_a_send_while_the_first_one_is_checked_keeps_no_body_and_takes_its_answer(self):
        """A helper sends the files again after its own 120 s while the first send is still checked, and again: each
        send held the whole delivery while it waited (24 MiB, more than 100 MiB decoded and searched), so a check of
        an hour could take a small hub's memory (a review of 21 November 2026). A send that comes meanwhile reads none
        of its files and answers what the first one answered; after a first one with no answer of 200 it gives none,
        so that its helper sends the files again, to a check of their own."""
        write(self.checkout, {f"outputs/{self.ref}/report.md": "x"})
        with patch.object(hub, "OUTPUTS_WAIT", 0.5):
            self.assertFalse(self.deliver()[1])
        token = json.loads(hub.q1("SELECT extra FROM events WHERE kind='outputs'")["extra"])["outputs"]
        files, _ = fleet.collect_outputs(str(self.checkout), self.ref)
        answer, real, checks = {"outputs": token, "task": self.ref, "files": files}, hub.searched_ahead, []

        def sends(fail):
            started, release, answers = threading.Event(), threading.Event(), []

            @contextlib.contextmanager
            def slow(texts):                    # the first send's search for logins takes long
                checks.append(len(texts))
                started.set()
                self.assertTrue(release.wait(60))
                if fail:
                    raise MemoryError("no room")
                with real(texts):
                    yield

            def send():
                try:
                    answers.append(self.request("/helper/outputs/vps", answer, source=VPS))
                except OSError:                 # no answer: its helper keeps the event, and sends again
                    answers.append("no answer")

            with patch.object(hub, "searched_ahead", slow), patch.object(hub.diagnostics, "record"):
                first = threading.Thread(target=send)
                first.start()
                self.assertTrue(started.wait(60))
                second = threading.Thread(target=send)
                second.start()
                second.join(1)                  # it waits for the first one's answer, and keeps no body
                with hub.CALLS:
                    bodies = sorted(getattr(one, "_raw", None) is not None for one in hub.CONNECTIONS
                                    if getattr(one, "path", "") == "/helper/outputs/vps")
                self.assertEqual(bodies, [False, True])
                release.set()
                for thread in (first, second):
                    thread.join(60)
            return sorted(answers, key=str)

        self.assertEqual(sends(fail=True), [(500, {"error": "hub error"}), "no answer"])
        self.assertEqual(sends(fail=False), [(200, {"taken": True})] * 2)
        self.assertEqual(checks, [1, 1])        # only the first send of each read its files

    def test_a_fault_of_git_keeps_the_delivery_open_once_and_the_next_one_lands_the_files(self):
        """A short fault of git (KitFault) does not close a delivery without its files: deliver_result tells the agent
        to call it again, and the next call lands them. Here the push lands and git answers that it failed (a time
        limit), so the next call finds the files on the ref and makes no second commit."""
        write(self.checkout, {f"outputs/{self.ref}/report.md": "# Report\n"})
        before, real, failed = self.origin("rev-parse", hub.CONFIG_BRANCH), subprocess.run, []

        def run(argv, *args, **kwargs):
            done = real(argv, *args, **kwargs)
            if "push" in argv and not failed:
                failed.append(argv)
                return subprocess.CompletedProcess(argv, 128, "", "fatal: the remote end hung up unexpectedly")
            return done
        self.helper()
        with patch.object(subprocess, "run", run):
            text, error = self.deliver()
        self.assertTrue(error, text)
        self.assertIn(f"{self.ref} is not delivered yet", text)
        self.assertEqual(hub.q1("SELECT state FROM tasks WHERE id=?", (self.task,))["state"], "working")
        landed = self.origin("rev-parse", hub.CONFIG_BRANCH)
        self.assertEqual(self.origin("rev-parse", f"{landed}~1"), before)
        hub.q("DELETE FROM events WHERE kind='outputs'")     # the next helper takes the next request alone
        self.helper()
        text, error = self.deliver()
        self.assertFalse(error, text)
        self.assertIn(f"Its files are on the configuration ref as {landed[:12]}", text)
        self.assertEqual(self.origin("rev-parse", hub.CONFIG_BRANCH), landed)

    def test_a_fault_of_git_that_lasts_refuses_a_delivery_once_in_its_attempt(self):
        """Refused at every call, a git that stays broken would hold the task open for ever."""
        write(self.checkout, {f"outputs/{self.ref}/report.md": "# Report\n"})
        real = subprocess.run
        broken = lambda argv, *a, **k: subprocess.CompletedProcess(argv, 128, "", "fatal: no space left on device") \
            if "push" in argv else real(argv, *a, **k)
        with patch.object(subprocess, "run", broken):
            self.helper()
            self.assertTrue(self.deliver()[1])
            hub.q("DELETE FROM events WHERE kind='outputs'")
            self.helper()
            text, error = self.deliver()
        self.assertFalse(error, text)
        self.assertIn(f"The files of outputs/{self.ref}/ did not reach the configuration ref: the push failed", text)
        self.assertEqual(hub.q1("SELECT state FROM tasks WHERE id=?", (self.task,))["state"], "completed")

    def test_a_refused_delivery_asks_the_helper_for_nothing(self):
        text, error = self.deliver(where_output_is="")
        self.assertTrue(error, text)
        self.assertIsNone(hub.q1("SELECT id FROM events WHERE kind='outputs'"))

    def test_a_cancel_while_the_files_come_commits_nothing_and_ends_the_delivery(self):
        write(self.checkout, {f"outputs/{self.ref}/report.md": "x"})
        before = self.origin("rev-parse", hub.CONFIG_BRANCH)
        self.helper(before=lambda: hub.q("UPDATE tasks SET state='canceled' WHERE id=?", (self.task,)))
        text, error = self.deliver()
        self.assertTrue(error, text)
        self.assertIn("already canceled", text)
        self.assertEqual(self.origin("rev-parse", hub.CONFIG_BRANCH), before)

    def test_a_file_with_a_registered_secret_stays_out_and_is_named(self):
        """A file that holds a registered login stays out, named. The files of a delivery are searched together, in
        one child process (searched_ahead): one by one in the hub, 100 short files were 100 s of its interpreter lock,
        and one delivery of 5.7 MB stalled every call of the hub for 4 minutes (20 November 2026)."""
        salt, value = "salt", "Synthetic-Secret-Value-123"
        hub.ins("INSERT INTO secrets(label,salt,hash,len) VALUES(?,?,?,?)",
                ("Synthetic label", salt, hashlib.sha256((salt + value).encode()).hexdigest(), len(value)))
        parts = {f"outputs/{self.ref}/part{n:02}.txt": f"part {n} " + "y" * 3000 + "\n" for n in range(40)}
        write(self.checkout, {f"outputs/{self.ref}/report.md": "# Report\n",
                              f"outputs/{self.ref}/notes.txt": f"the key is {value}\n", **parts})
        children, child, here = [], hub.login_search_child, hub.secret_spans_here

        def counted(asks):
            children.append(len(asks))
            return child(asks)

        def short_only(text, key):
            self.assertNotIn("yyyy", text)          # no file of the delivery is searched in the hub's own process
            return here(text, key)

        self.helper()
        with patch.object(hub, "login_search_child", counted), patch.object(hub, "secret_spans_here", short_only):
            text, error = self.deliver()
        self.assertFalse(error, text)
        self.assertIn(f"Not sent: outputs/{self.ref}/notes.txt (it holds a registered secret).", text)
        self.assertEqual(self.origin("ls-tree", "-r", "--name-only", hub.CONFIG_BRANCH, f"outputs/{self.ref}").split(),
                         sorted(parts) + [f"outputs/{self.ref}/report.md"])
        self.assertEqual(len(children), 1)

    def test_a_file_that_is_not_utf_8_is_searched_too(self):
        """A file whose bytes were not UTF-8 was committed with no search (a review of 20 November 2026): a UTF-16 file
        with a registered login, as PowerShell's > writes one, reached the configuration ref, which every agent reads.
        Now each file is searched in every text of its bytes (bytes_texts: the euro sign is only in the text of UTF-16,
        the last one), and a picture with no login goes in."""
        salt, euro, latin = "salt", "Pass\u20acword-Synthetic-9", "Contrase\u00f1a-Sint\u00e9tica-2026"
        for label, one in (("Synthetic label", euro), ("Synthetic Latin label", latin)):
            hub.ins("INSERT INTO secrets(label,salt,hash,len) VALUES(?,?,?,?)",
                    (label, salt, hashlib.sha256((salt + one).encode()).hexdigest(), len(one)))
        picture = b"\x89PNG\r\n\x1a\n" + random.Random(7).randbytes(300000)
        write(self.checkout, {f"outputs/{self.ref}/wide.txt": b"\xff\xfe" + f"the key: {euro}\r\n".encode("utf-16-le"),
                              f"outputs/{self.ref}/latin.csv": f"clave;{latin}\n".encode("cp1252"),
                              f"outputs/{self.ref}/picture.png": picture})
        self.helper()
        text, error = self.deliver()
        self.assertFalse(error, text)
        self.assertIn(f"Not sent: outputs/{self.ref}/latin.csv (it holds a registered secret); outputs/{self.ref}/"
                      f"wide.txt (it holds a registered secret).", text)
        self.assertEqual(self.origin("ls-tree", "-r", "--name-only", hub.CONFIG_BRANCH, f"outputs/{self.ref}"),
                         f"outputs/{self.ref}/picture.png")

    def test_the_route_takes_only_files_of_the_tasks_own_folder_from_the_agents_machine(self):
        token = "t" * 22
        hub.OUTPUTS[token] = {"agent": "vps", "task": self.task, "answer": None, "gave_up": False}
        self.addCleanup(hub.OUTPUTS.pop, token, None)
        deep = "/".join("d" * 6)
        for path in ("team.json", "outputs/T-99/x.md", f"outputs/{self.ref}/../x.md", f"outputs/{self.ref}/.git/config",
                     f"outputs/{self.ref}/-n", f"outputs/{self.ref}/", f"outputs/{self.ref}//x.md",
                     f"/outputs/{self.ref}/x.md", f"outputs/{self.ref}/a b.md", f"outputs/{self.ref}/{deep}/x.md"):
            with self.subTest(path=path):
                code, data = self.request("/helper/outputs/vps", {"outputs": token, "task": self.ref,
                                                                  "files": [{"path": path, "data": "eA=="}]}, source=VPS)
                self.assertEqual(code, 400, data)
        code, data = self.request("/helper/outputs/vps", {"outputs": token, "task": self.ref,
                                                          "files": [{"path": f"outputs/{self.ref}/x.md", "data": "%%"}]},
                                  source=VPS)
        self.assertEqual((code, data["error"]), (400, f"outputs/{self.ref}/x.md: data must be base64"))
        # a delivery that is refused is not searched for logins, also not its files before the refused one
        good = {"path": f"outputs/{self.ref}/long.md", "data": base64.b64encode(b"w" * 200000).decode()}
        with patch.object(hub, "searched_ahead", side_effect=AssertionError("searched")), \
                patch.object(hub, "secret_hit", side_effect=AssertionError("searched")):
            code, data = self.request("/helper/outputs/vps", {"outputs": token, "task": self.ref,
                                                              "files": [good, {"path": "team.json", "data": "eA=="}]},
                                      source=VPS)
        self.assertEqual(code, 400, data)
        self.assertEqual(self.request("/helper/outputs/vps", {"outputs": token, "task": self.ref, "files": []},
                                      source=TEAM["addresses"]["hub"])[0], 403)       # another machine
        self.assertEqual(self.request("/helper/outputs/vps", {"outputs": token, "task": "T-99", "files": []},
                                      source=VPS), (200, {"taken": False}))           # another task's delivery
        self.assertIsNone(hub.OUTPUTS[token]["answer"])
        self.assertTrue(hub.outputs_allow(self.ref).match(f"outputs/{self.ref}/{'/'.join('d' * 5)}/x.md"))

    def test_an_older_helpers_agents_md_stays_out_with_its_reason(self):
        """The AI providers build (spec 3.11 item 9; the wave 1 review, R3): the hub takes no file or folder AGENTS.md
        of an output, in any case of its letters, also from a helper of a release before its own rule. Such a file
        stays out with the helper's own reason, and the other files of the delivery go in. Python's cache folder, at
        any depth, stays out without a word, as a helper of this release leaves it out."""
        token = "t" * 22
        hub.OUTPUTS[token] = {"agent": "vps", "task": self.task, "answer": None, "gave_up": False, "late": False}
        self.addCleanup(hub.OUTPUTS.pop, token, None)
        names = [f"outputs/{self.ref}/{name}" for name in ("AGENTS.md", "notes/agents.md", "Agents.MD/plan.md",
                                                            "report.md", "agents.md.txt", "__pycache__/a.pyc",
                                                            "sub/__pycache__/b.pyc")]
        code, data = self.request("/helper/outputs/vps", {"outputs": token, "task": self.ref,
                                                          "files": [{"path": n, "data": "eA=="} for n in names]},
                                  source=VPS)
        self.assertEqual((code, data), (200, {"taken": True}))
        answer = hub.OUTPUTS[token]["answer"]
        self.assertEqual(sorted(answer["files"]), [f"outputs/{self.ref}/agents.md.txt", f"outputs/{self.ref}/report.md"])
        self.assertEqual(answer["skipped"], [{"path": n, "why": fleet.OUTPUT_BAD_NAME} for n in names[:3]])
        allow = hub.outputs_allow(self.ref)
        self.assertEqual([bool(allow.match(n)) for n in names], [False, False, False, True, True, True, True])
        hub.OUTPUTS[token].update(answer=None)
        code, data = self.request("/helper/outputs/vps", {"outputs": token, "task": self.ref,
                                                          "files": [{"path": f"outputs/{self.ref}/../AGENTS.md",
                                                                     "data": "eA=="}]}, source=VPS)
        self.assertEqual(code, 400, data)           # a path outside the folder is refused as before

    def test_the_same_files_twice_make_one_commit(self):
        t = hub.q1("SELECT * FROM tasks WHERE id=?", (self.task,))
        files = {f"outputs/{self.ref}/report.md": b"# Report\n"}
        first = hub.commit_outputs("vps", t, files)
        self.assertEqual(hub.commit_outputs("vps", t, files), first)
        self.assertEqual(self.origin("rev-parse", hub.CONFIG_BRANCH), first)


class Early(Outputs):
    """A running task sends its outputs folder before it delivers (report_progress outputs; gap G3 of the fleet
    workspace review): another agent reads the files on the configuration ref while the task runs, each send replaces
    the folder there, and the delivery sends the last version."""

    def setUp(self):
        super().setUp()
        self.features(["mcp_program", "task_outputs", "outputs_early"])
        for held in (hub.OUTPUTS, hub.OUTPUTS_NEWEST):          # another test's late delivery of a task 1
            keep = patch.dict(held, clear=True)
            keep.start()
            self.addCleanup(keep.stop)
        self.out = f"outputs/{self.ref}/"
        self.copies = []                    # the helper's copies that a move could not put back (lifecycle.left_copies)

    def sender(self, before=None):
        """The agent's helper for the next request of the hub: it sends the folder as it is then, and says whether
        the folder is on its machine, as fleet.Helper.send_outputs does."""
        seen = (hub.q1("SELECT MAX(id) AS n FROM events") or {"n": 0})["n"] or 0

        def run():
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                row = hub.q1("SELECT extra FROM events WHERE agent='vps' AND kind='outputs' AND id>? ORDER BY id DESC "
                             "LIMIT 1", (seen,))
                if row:
                    extra = json.loads(row["extra"])
                    if before:
                        before()
                    self.answers.append(self.request("/helper/outputs/vps", self.body(extra), source=VPS))
                    return
                time.sleep(0.05)
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 15)
        return thread

    def body(self, extra):
        files, skipped = fleet.collect_outputs(str(self.checkout), extra["task"])
        return {"outputs": extra["outputs"], "task": extra["task"], "files": files, "skipped": skipped,
                "folder": fleet.output_folder_held(str(self.checkout), extra["task"]), "left": self.copies}

    def send(self, note="Half of the report."):
        return hub.call_tool("vps", "report_progress", {"task_id": self.ref, "note": note, "outputs": True},
                             ("test-generation", self.ref, 1))

    def sent(self, note="Half of the report."):
        self.sender()
        text, error = self.send(note)
        self.assertFalse(error, text)
        return text

    def held(self):
        return self.origin("ls-tree", "-r", "--name-only", hub.CONFIG_BRANCH, self.out).split()

    def test_a_running_task_sends_its_folder_and_another_agent_reads_it(self):
        """13 November 2026: an agent needed outputs/T-526/gsc-alert-decision.md while T-526 ran, and the manager had
        to tell the other agent to deliver early. The same files again make no commit."""
        out = self.out
        write(self.checkout, {out + "decision.md": "# Decision\n"})
        text = self.sent()
        commit = self.origin("rev-parse", hub.CONFIG_BRANCH)
        self.assertEqual(text, f"Noted. Your helper sent {out} to the configuration ref as {commit[:12]}: "
                               f"{out}decision.md. Others read a file with git fetch origin, then git show "
                               f"origin/config:{out}<file>. Each later send, and your delivery, replaces the folder "
                               f"there.")
        self.assertEqual(self.origin("show", f"{hub.CONFIG_BRANCH}:{out}decision.md"), "# Decision")
        self.assertEqual(self.origin("log", "-1", "--format=%an%n%s", hub.CONFIG_BRANCH),
                         f"Fleet agent vps\nvps sent {self.ref}: 1 file of its output")
        self.assertEqual(hub.q1("SELECT state FROM tasks WHERE id=?", (self.task,))["state"], "working")
        self.assertEqual(hub.q1("SELECT text FROM notes WHERE task=?", (self.task,))["text"], "Half of the report.")
        self.copies = [f".git/{lifecycle.OUTPUTS_LEFT}/{out}decision.md.1"]
        self.assertEqual(self.sent("Again."), f"Noted. Nothing changed since your last send: the configuration ref "
                                              f"holds {out} as {commit[:12]}: {out}decision.md. Your machine keeps "
                                              f"copies that a move of your checkout could not put back, because you "
                                              f"wrote the file again: {self.copies[0]}.")
        self.assertEqual(self.origin("rev-parse", hub.CONFIG_BRANCH), commit)

    def test_a_later_send_replaces_the_folder_and_the_delivery_sends_the_last_version(self):
        """A file that left the folder leaves the configuration ref too, so a reader never takes a stale one; an
        empty folder clears it (a removed draft never reads as delivered output); the delivery's result reads as
        before."""
        out = self.out
        write(self.checkout, {out + "a.md": "one", out + "b.md": "bee"})
        self.sent()
        self.assertEqual(self.held(), [out + "a.md", out + "b.md"])
        write(self.checkout, {out + "a.md": "two"})
        (self.checkout / out / "b.md").unlink()
        self.assertIn(f": {out}a.md. Removed from it: {out}b.md. Others read", self.sent())
        self.assertEqual(self.held(), [out + "a.md"])
        self.assertEqual(self.origin("log", "-1", "--format=%s", hub.CONFIG_BRANCH),
                         f"vps sent {self.ref}: 1 file of its output, 1 removed")
        (self.checkout / out / "a.md").unlink()
        text = self.sent()
        commit = self.origin("rev-parse", hub.CONFIG_BRANCH)
        self.assertEqual(text, f"Noted. The configuration ref holds no file of {out} now ({commit[:12]}). Removed "
                               f"from it: {out}a.md.")
        self.assertEqual(self.held(), [])
        write(self.checkout, {out + "a.md": "three"})
        self.sender()
        text, error = self.deliver(where_output_is=out + "a.md")
        self.assertFalse(error, text)
        commit = self.origin("rev-parse", hub.CONFIG_BRANCH)
        self.assertEqual(text, f"Delivered. {self.ref} is completed. Its files are on the configuration ref as "
                               f"{commit[:12]}: {out}a.md. You are done with it: stop now and end your turn; your "
                               f"session closes when it ends.")
        self.assertEqual(self.origin("show", f"{hub.CONFIG_BRANCH}:{out}a.md"), "three")
        self.assertEqual(self.origin("log", "-1", "--format=%s", hub.CONFIG_BRANCH),
                         f"vps delivered {self.ref}: 1 file of its output")
        text, error = self.send()
        self.assertTrue(error, text)
        self.assertIn("already completed", text)                   # a task that ended takes no send

    def test_a_machine_without_the_folder_keeps_the_earlier_send_and_names_it(self):
        """An agent that moved to another machine: its delivery there finds no folder, and the early files stay on
        the ref, named in the result, instead of leaving it."""
        out = self.out
        write(self.checkout, {out + "a.md": "one"})
        self.sent()
        commit = self.origin("rev-parse", hub.CONFIG_BRANCH)
        shutil.rmtree(self.checkout / "outputs")
        self.sender()
        text, error = self.deliver(where_output_is=out + "a.md")
        self.assertFalse(error, text)
        self.assertIn(f"Delivered. {self.ref} is completed. The agent's machine holds nothing of its own in {out}, so "
                      f"the configuration ref keeps the files of an earlier send: {out}a.md.", text)
        self.assertEqual(self.origin("rev-parse", hub.CONFIG_BRANCH), commit)

    def test_a_send_with_nothing_to_add_or_remove_runs_no_git(self):
        """Before sends before delivery, a delivery with no file used no git: a screen task's folder, which holds only
        the computer-use/ that Fleet makes by itself. A short fault of git must not refuse such a delivery now either."""
        write(self.checkout, {f"{self.out}computer-use/capture-1.png": b"x"})
        with patch.object(hub, "outputs_held", side_effect=AssertionError("git")), \
                patch.object(hub, "commit_outputs", side_effect=AssertionError("git")):
            self.assertEqual(self.sent(), f"Noted. No file of {self.out} was sent, so the configuration ref is as it "
                                          f"was.")
            self.sender()
            text, error = self.deliver(where_output_is="the screen")
        self.assertFalse(error, text)
        self.assertEqual(text, f"Delivered. {self.ref} is completed. You are done with it: stop now and end your turn; "
                               f"your session closes when it ends.")

    def test_a_hub_with_no_mark_of_the_folder_reads_the_ref(self):
        """The marks of what the ref holds go at each start (a restored database would keep stale ones), and with
        none an empty folder of the agent's still takes the files of its earlier send off the ref."""
        out = self.out
        write(self.checkout, {out + "a.md": "one"})
        self.sent()
        hub.settle_task_numbers()                               # the hub's start, after a restore
        self.assertIsNone(hub.kv_get(hub.OUTPUTS_SENT + str(self.task)))
        (self.checkout / out / "a.md").unlink()
        self.assertIn(f"Removed from it: {out}a.md.", self.sent())
        self.assertEqual(self.held(), [])

    def test_an_older_helper_is_asked_for_nothing_and_the_answer_says_so(self):
        """Its checkout would track the sent files and then stop moving at the agent's next change of one."""
        self.features(["mcp_program", "task_outputs"])
        write(self.checkout, {f"{self.out}report.md": "x"})
        before = self.origin("rev-parse", hub.CONFIG_BRANCH)
        text, error = self.send()
        self.assertFalse(error, text)
        self.assertEqual(text, f"Noted. Not sent: your machine's helper cannot send {self.out} before delivery yet. "
                               f"It takes the release that can by itself; until then, deliver_result sends the "
                               f"folder.")
        self.assertIsNone(hub.q1("SELECT id FROM events WHERE kind='outputs'"))
        self.assertEqual(self.origin("rev-parse", hub.CONFIG_BRANCH), before)
        self.assertEqual(hub.q1("SELECT text FROM notes WHERE task=?", (self.task,))["text"], "Half of the report.")

    def test_one_attempt_sends_its_folder_a_counted_number_of_times(self):
        """Each send that commits keeps each changed file in the ref's history for good: a count, no clock, ends them
        in one attempt. A refused send and one that changes nothing do not count, and a waiting delivery of an earlier
        attempt, or one that went late, refuses none."""
        key = hub.OUTPUTS_EARLY_SENDS + str(self.task)
        hub.kv_set(key, f"1:{hub.OUTPUTS_EARLY_MAX - 2}")
        hub.OUTPUTS["now"] = {"agent": "vps", "task": self.task, "attempt": 1, "answer": None, "gave_up": False,
                              "late": False, "early": False}
        self.assertEqual(self.send()[0], f"Noted. Not sent: your delivery of {self.ref} sends {self.out} now.")
        hub.OUTPUTS["now"].update(attempt=0)                     # a delivery of an earlier attempt
        hub.OUTPUTS["late"] = {"agent": "vps", "task": self.task, "attempt": 1, "answer": None, "gave_up": False,
                               "late": True, "early": False}
        write(self.checkout, {f"{self.out}a.md": "one"})
        self.assertIn("Your helper sent", self.sent())
        self.assertIn("Nothing changed since your last send", self.sent())
        self.assertEqual(hub.kv_get(key), f"1:{hub.OUTPUTS_EARLY_MAX - 1}")
        write(self.checkout, {f"{self.out}a.md": "two"})
        self.assertIn("Your helper sent", self.sent())
        text, error = self.send()
        self.assertFalse(error, text)
        self.assertEqual(text, f"Noted. Not sent: this attempt sent {self.out} {hub.OUTPUTS_EARLY_MAX} times already. "
                               f"Send it again with deliver_result.")

    def test_files_that_come_after_the_wait_land_while_the_task_runs_and_its_session_hears(self):
        """Plan C7, as for a delivery: no clock refuses them."""
        out = self.out
        write(self.checkout, {out + "a.md": "one"})
        helper = self.sender(before=lambda: time.sleep(1))
        with patch.object(hub, "OUTPUTS_WAIT", 0.3):
            text, error = self.send()
        self.assertFalse(error, text)
        self.assertEqual(text, f"Noted. Your helper has not sent {out} yet: the hub commits it when it comes, and a "
                               f"message here names the commit.")
        helper.join(15)
        self.assertEqual(self.answers, [(200, {"taken": True})])
        commit = self.origin("rev-parse", hub.CONFIG_BRANCH)
        self.assertEqual(self.held(), [out + "a.md"])
        said = hub.q1("SELECT text, task FROM events WHERE agent='vps' AND kind='say' ORDER BY id DESC LIMIT 1")
        self.assertEqual(said["task"], self.task)
        self.assertIn(f"[hub] The files of {out} that you sent with report_progress came after that call. Your helper "
                      f"sent {out} to the configuration ref as {commit[:12]}: {out}a.md.", said["text"])
        self.assertNotIn(self.task, hub.OUTPUTS_NEWEST)

    def test_a_late_send_lands_nothing_after_a_later_send_attempt_owner_hold_or_end(self):
        """An older folder never lands over a newer one, and files that come after the task moved on (a later
        attempt, another owner, a Stop or a Pause, its end) stay out."""
        out = self.out
        write(self.checkout, {out + "a.md": "old"})
        with patch.object(hub, "OUTPUTS_WAIT", 0.3):
            self.assertFalse(self.send()[1])
        first = json.loads(hub.q1("SELECT extra FROM events WHERE kind='outputs' ORDER BY id LIMIT 1")["extra"])
        old = self.body(first)
        write(self.checkout, {out + "a.md": "new"})
        self.sent()
        commit = self.origin("rev-parse", hub.CONFIG_BRANCH)
        self.assertFalse(hub.outputs_waiting(first["outputs"], "vps"))      # its helper is not asked any more
        self.assertEqual(self.request("/helper/outputs/vps", old, source=VPS), (200, {"taken": False}))
        hub.ins("INSERT INTO holds(task,kind,by,state,created,attempt) VALUES(?,'pause','owner','released',?,1)",
                (self.task, hub.now()))
        moves = (("UPDATE tasks SET attempt=2 WHERE id=?", "UPDATE tasks SET attempt=1 WHERE id=?"),
                 ("UPDATE tasks SET owner='other' WHERE id=?", "UPDATE tasks SET owner='vps' WHERE id=?"),
                 ("UPDATE holds SET state='requested' WHERE task=?", "UPDATE holds SET state='released' WHERE task=?"),
                 ("UPDATE tasks SET state='canceled' WHERE id=?", None))
        for move, back in moves:
            with patch.object(hub, "OUTPUTS_WAIT", 0.3):
                self.assertFalse(self.send()[1], move)
            late = json.loads(hub.q1("SELECT extra FROM events WHERE kind='outputs' ORDER BY id DESC LIMIT 1")["extra"])
            hub.q(move, (self.task,))
            write(self.checkout, {out + "a.md": "after the move"})
            self.assertEqual(self.request("/helper/outputs/vps", self.body(late), source=VPS), (200, {"taken": True}),
                             move)
            self.assertEqual(self.origin("rev-parse", hub.CONFIG_BRANCH), commit, move)
            if back:
                hub.q(back, (self.task,))
        self.assertEqual(self.origin("show", f"{hub.CONFIG_BRANCH}:{out}a.md"), "new")
        self.assertIsNone(hub.q1("SELECT id FROM events WHERE agent='vps' AND kind='say'"))

    def test_the_commits_of_one_folder_land_one_at_a_time_and_in_the_order_of_their_sends(self):
        """A send whose files came first but whose commit waits behind another's (OUTPUTS_COMMIT) lands nothing once
        a newer send of the folder began (OUTPUTS_NEWEST): else the older folder would land over the newer one."""
        out, t = self.out, hub.get_task(self.task)
        before = self.origin("rev-parse", hub.CONFIG_BRANCH)
        answer = {"files": {out + "a.md": b"older"}, "skipped": [], "folder": True}
        said = []
        hub.OUTPUTS_NEWEST[self.task] = "older"
        with hub.OUTPUTS_COMMIT:
            commit = threading.Thread(target=lambda: said.append(hub.outputs_sentence("vps", t, answer, early="older")))
            commit.start()
            commit.join(0.5)
            self.assertTrue(commit.is_alive())                      # it waits for the commit before it
            hub.OUTPUTS_NEWEST[self.task] = "newer"                  # a newer send began meanwhile
        commit.join(15)
        self.assertEqual(said, [None])
        self.assertEqual(self.origin("rev-parse", hub.CONFIG_BRANCH), before)
        hub.OUTPUTS_NEWEST[self.task] = "older"
        self.assertIn("Your helper sent", hub.outputs_sentence("vps", t, answer, early="older"))
        self.assertEqual(self.held(), [out + "a.md"])


class BytesSearch(unittest.TestCase):
    """The search for logins in a file's bytes that are not UTF-8 (bytes_texts), with synthetic logins only. Each test
    names the bytes in which a login was not found before."""

    LOGINS = ("Synthetic-Secret-Value-123", "Contrase\u00f1a-Sint\u00e9tica-2026", "Pass\u20acword-Synthetic-9",
              "\u041f\u0430\u0440\u043e\u043b\u044c-Synthetic-77", "Zq7-Kp2x", "Tok_en.Syn+the=tic/1~{|}",
              "\u00d1and\u00fa-S\u00ed-Est\u00e1-Aqu\u00ed-2026", "\u5bc6\u7801\u5408\u6210\u5bc6\u7801\u4e00\u4e8c")

    def setUp(self):
        key = tuple(("salt", hashlib.sha256(("salt" + value).encode()).hexdigest(), len(value)) for value in self.LOGINS)
        key += (("salt", hashlib.sha256(b"saltSecretToken99").hexdigest(), None),)      # a login with no length
        patcher = patch.object(hub, "secret_key", return_value=key)
        patcher.start()
        self.addCleanup(patcher.stop)

    def found(self, data):
        return hub.secret_hit(*hub.bytes_texts(data))

    def test_a_login_in_utf_16_of_either_byte_order_is_found(self):
        """What PowerShell's > writes, and Notepad's and Excel's "Unicode": each character beside a zero byte, after a
        byte order mark that is not UTF-8. Such a file was not searched at all."""
        line = "the key: Synthetic-Secret-Value-123\r\n"
        self.assertTrue(self.found(b"\xff\xfe" + line.encode("utf-16-le")))
        self.assertTrue(self.found(b"\xfe\xff" + line.encode("utf-16-be")))
        self.assertFalse(self.found(b"\xff\xfe" + "the key: none\r\n".encode("utf-16-le")))

    def test_a_login_in_utf_32_with_a_byte_order_mark_is_found(self):
        """Three zero bytes beside each ASCII character, which the search of the first design did not read; and a
        Cyrillic letter, which only the text of UTF-32 holds (big-endian, whose mark is not UTF-16's)."""
        line = "the key: Synthetic-Secret-Value-123\n"
        self.assertTrue(self.found(b"\xff\xfe\x00\x00" + line.encode("utf-32-le")))
        self.assertTrue(self.found(b"\x00\x00\xfe\xff" + line.encode("utf-32-be")))
        self.assertTrue(self.found(b"\x00\x00\xfe\xff" + "key: \u041f\u0430\u0440\u043e\u043b\u044c-Synthetic-77\n"
                                   .encode("utf-32-be")))

    def test_a_login_in_a_utf_8_text_with_one_bad_byte_is_found_also_with_a_letter_outside_ascii(self):
        """A text cut in the middle of a letter, or with one stray byte, is not UTF-8. Its runs of ASCII alone miss a
        login with a letter outside ASCII and one with a hidden character inside, which the skeleton removes; and the
        removal of its zero bytes joins a login with no length to the next string (C strings)."""
        self.assertTrue(self.found("clave: Contrase\u00f1a-Sint\u00e9tica-2026 fin".encode() + b"\xff\n"))
        self.assertTrue(self.found(b"\xe9 the key: Synthetic-Secret\xe2\x80\x8b-Value-123\n"))
        self.assertTrue(self.found(b"\xff env: SecretToken99\x00name\x00\n"))

    def test_a_letter_across_two_steps_of_the_count_keeps_its_login(self):
        """utf8_text decodes a text a step of BYTES_CHUNK bytes at a time: each step decoded alone would make a bad
        byte of each half of a letter that lies across two steps."""
        with patch.object(hub, "BYTES_CHUNK", 3):
            self.assertTrue(self.found("key: \u041f\u0430\u0440\u043e\u043b\u044c-Synthetic-77 ".encode() + b"\xff\n"))

    def test_a_login_with_a_latin_letter_in_windows_1252_or_in_utf_16_without_a_mark_is_found(self):
        """Latin-1 and Windows text holds a Latin letter as one byte, and UTF-16 as that byte beside a zero byte: also
        in a short file with more bad bytes than one in 8, and after many bad bytes at the file's start."""
        line = "clave: Contrase\u00f1a-Sint\u00e9tica-2026\n"
        self.assertTrue(self.found(line.encode("cp1252")))
        self.assertTrue(self.found(line.encode("utf-16-le")))
        self.assertTrue(self.found("key: Pass\u20acword-Synthetic-9\n".encode("cp1252")))
        self.assertTrue(self.found("\u00d1and\u00fa-S\u00ed-Est\u00e1-Aqu\u00ed-2026\n".encode("cp1252")))
        self.assertTrue(self.found(b"\xe9" * 70000 + line.encode("cp1252") + b"a " * 400000))

    def test_a_login_with_a_letter_beyond_latin_1_in_utf_16_or_utf_32_with_a_mark_is_found(self):
        """The euro sign, Cyrillic and Chinese letters are two bytes of UTF-16 that are not zero: only the text of the
        file's own code holds them, also with no ASCII around them."""
        self.assertTrue(self.found(b"\xff\xfe" + "key: Pass\u20acword-Synthetic-9\r\n".encode("utf-16-le")))
        line = "\u043a\u043b\u044e\u0447: \u041f\u0430\u0440\u043e\u043b\u044c-Synthetic-77 \u0438 \u0432\u0441\u0451\n"
        self.assertTrue(self.found(b"\xfe\xff" + line.encode("utf-16-be")))
        self.assertTrue(self.found(b"\xff\xfe\x00\x00" + line.encode("utf-32-le")))
        self.assertTrue(self.found(b"\xff\xfe" + line.encode("utf-16-le") + b"\x00"))     # a byte too many: U+FFFD
        prose = "\u8fd9\u662f\u6587\u4ef6\u7684\u5185\u5bb9\u3002" * 500
        self.assertTrue(self.found(b"\xff\xfe" + (prose + "\u5bc6\u7801\u5408\u6210\u5bc6\u7801\u4e00\u4e8c" + prose)
                                   .encode("utf-16-le")))

    def test_a_login_in_the_bytes_of_a_picture_is_found_in_ascii_and_in_utf_16(self):
        """A picture's text chunk, an old Word file's UTF-16 text, a login of 8 characters, one of punctuation, one at
        the very end, and one with no length beside the next string (a C string) or after a byte that is not text."""
        noise = random.Random(3).randbytes(200000)
        self.assertTrue(self.found(noise + b"\x00Synthetic-Secret-Value-123\x00" + noise))
        self.assertTrue(self.found(noise + "Synthetic-Secret-Value-123".encode("utf-16-le") + noise))
        self.assertTrue(self.found(noise + b"\xffZq7-Kp2x\xff" + noise))
        self.assertTrue(self.found(noise + b"\xffTok_en.Syn+the=tic/1~{|}\xff" + noise))
        self.assertTrue(self.found(noise + b"\xffSynthetic-Secret-Value-123"))
        self.assertTrue(self.found(b"Synthetic-Secret-Value-123\x80" + noise))
        self.assertTrue(self.found(noise + b"\xff\x00SecretToken99\x00name\x00" + noise))
        self.assertTrue(self.found(noise + b"\xffSecretToken99\x80name0123\x80" + noise))

    def test_a_login_past_the_runs_that_are_read_one_by_one_is_found(self):
        """A file of many short runs is read in one step past BYTES_RUNS_MOST runs (one at a time, 24 MiB of them held
        the request's thread 1.8 s): that step still holds the runs after them, and their punctuation."""
        with patch.object(hub, "BYTES_RUNS_MOST", 4):
            self.assertTrue(self.found(b"\x80abcdefgh" * 10 + b"\x80Tok_en.Syn+the=tic/1~{|}\x80" + b"\xff" * 1000))

    def test_a_picture_with_no_login_is_searched_in_a_short_text(self):
        """A picture's bytes are nearly random: read as text, nearly all of them are one long run, and the search, which
        hashes every window of a run for each login, would take minutes of a child and then leave the picture out.
        Also when the picture starts with the bytes of a UTF-16 mark, or with a text longer than the bytes that tell
        at once."""
        noise = random.Random(5).randbytes(8 * 1024 * 1024)
        for data in (b"\x89PNG\r\n\x1a\n" + noise, b"\xff\xfe" + noise[:1024 * 1024],
                     b"%PDF-1.7\n" + b"<< /Type /Page >>\n" * 5000 + noise):        # a text before the bytes
            texts = hub.bytes_texts(data)
            self.assertLess(sum(map(len, texts)), len(data) // 100)
            self.assertFalse(hub.secret_hit(*texts))


class TaskNumbers(OwnerAPI):
    """A task number is used once (the audit of 7 November 2026). outputs/T-<id>/ stays on the configuration ref when
    the records do not, so a new database or a restored older copy gave its next task the number of a task whose
    folder was there, and the new files went into it."""

    def setUp(self):
        super().setUp()
        hub.TEAM = json.loads(json.dumps(TEAM))
        self.root = Path(tempfile.mkdtemp(prefix="fleet-numbers-"))
        kit = repository(self.root, {"team.json": json.dumps(TEAM, indent=2) + "\n", "RULES.md": "# Rules\n",
                                     "outputs/T-7/notes.md": "an older task's notes\n",
                                     "outputs/T-40/report.md": "# An older task's report\n"})
        hub.CFG["team_path"] = str(kit / "team.json")
        hub._revision_cache.update(at=0.0, value=None)
        self.addCleanup(self.put_back)

    def put_back(self):
        hub.CFG.pop("team_path", None)
        hub._revision_cache.update(at=0.0, value=None)
        shutil.rmtree(str(self.root), ignore_errors=True)

    def create(self):
        text, error = hub.call_tool("manager", "create_task", {"owner": "vps", "title": "Write the note",
                                                               "done_when": "The note exists."})
        self.assertFalse(error, text)
        return hub.q1("SELECT MAX(id) n FROM tasks")["n"]

    def test_a_new_database_numbers_its_tasks_above_the_folders_on_the_configuration_ref(self):
        hub.settle_task_numbers()
        self.assertEqual(self.create(), 41)
        hub.settle_task_numbers()               # at the next start the ref holds T-40 still: the floor stays
        self.assertEqual(self.create(), 42)

    def test_a_restored_copy_whose_tasks_are_past_the_folders_keeps_its_own_numbers(self):
        with hub.LOCK, hub.transaction():
            hub.DB.execute("INSERT INTO tasks(id,title,owner,requester,state,created) "
                           "VALUES(50,'An old task','vps','manager','completed',1)")
        hub.settle_task_numbers()
        self.assertEqual(self.create(), 51)

    def test_a_hub_with_no_checkout_numbers_as_before(self):
        hub.CFG["team_path"] = str(self.root / "nowhere" / "team.json")
        hub._revision_cache.update(at=0.0, value=None)
        hub.settle_task_numbers()
        self.assertEqual(self.create(), 1)


class Revision(unittest.TestCase):
    """kit_revision keeps its reading for 30 seconds, and kept it whatever checkout kit_dir named. A test that read its
    own kit left that commit for the next test's vault page, which then asked this checkout for a commit it does not
    have: test_central_vault failed in every full run, after any test with a kit of its own (7 November 2026)."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="fleet-revision-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        self.addCleanup(hub.CFG.pop, "team_path", None)
        self.kits = [repository(self.root / name, {"team.json": "{}\n", "RULES.md": f"# {name}\n"})
                     for name in ("one", "two")]

    def test_a_reading_of_one_checkout_is_never_the_revision_of_another(self):
        heads = [git("rev-parse", "HEAD", cwd=kit) for kit in self.kits]
        self.assertNotEqual(heads[0], heads[1])
        for kit, head in zip(self.kits + self.kits[:1], heads + heads[:1]):    # one, two, one: no cache reset between
            hub.CFG["team_path"] = str(kit / "team.json")
            self.assertEqual(hub.kit_revision(), head)
        hub.CFG.pop("team_path")                    # and the hub's own checkout reads its own commit, as the vault page
        here = os.path.dirname(os.path.abspath(hub.__file__))
        self.assertEqual(hub.kit_revision(), git("rev-parse", "HEAD", cwd=here))


if __name__ == "__main__":
    unittest.main()
