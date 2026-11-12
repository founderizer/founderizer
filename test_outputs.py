"""A task's output reaches the configuration ref through the hub (helper feature task_outputs, 25 October 2026): when
an agent delivers, its helper sends the files of outputs/T-<id>/, and the hub commits only those, signed by the agent,
before the task closes. In-process hub, temporary Git repositories and a helper thread; no fleet or AI calls."""
import base64
import hashlib
import json
import os
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
from test_ui_api import OwnerAPI

TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"]}}}
VPS = TEAM["addresses"]["vps"]


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (HelperFiles, Checkout, Delivery, TaskNumbers, Revision):
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

    def test_the_screen_captures_and_dot_files_stay_without_a_word(self):
        write(self.kit, {"outputs/T-7/computer-use/capture-1.png": b"x", "outputs/T-7/.DS_Store": b"x",
                         "outputs/T-7/.hidden/x.md": "x", "outputs/T-7/sub/computer-use/kept.md": "x"})
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
    """lifecycle.follow_config_ref and a Fleet update (Lifecycle.apply) once the hub took in a delivered task's files:
    the untracked copies give way."""

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
        write(work, files)
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

    def test_a_file_with_other_bytes_stays_and_the_checkout_says_why(self):
        write(self.kit, {"outputs/T-3/report.md": "my own"})
        self.hub_commits({"outputs/T-3/report.md": "# Report\n"})
        self.assertIn("git merge failed", lifecycle.follow_config_ref(str(self.kit)))
        self.assertEqual((self.kit / "outputs/T-3/report.md").read_text(), "my own")

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

    def test_a_fleet_update_over_a_file_with_other_bytes_fails_and_names_it(self):
        write(self.kit, {"outputs/T-1/route-check.md": "my own"})
        self.hub_commits({"outputs/T-1/route-check.md": "# Route\n"})
        restarted, state, detail = self.update(self.hub_commits({"knowledge/services.md": "# Services\n"}))
        self.assertEqual((restarted, state), (False, "failed"))
        self.assertIn("git merge failed", detail)
        self.assertIn("outputs/T-1/route-check.md", detail)
        self.assertEqual((self.kit / "outputs/T-1/route-check.md").read_text(), "my own")


class Delivery(OwnerAPI):
    """deliver_result asks the session's helper for the files, and the hub commits them before the task closes."""

    def setUp(self):
        super().setUp()
        hub.TEAM = json.loads(json.dumps(TEAM))
        self.root = Path(tempfile.mkdtemp(prefix="fleet-outputs-"))
        self.kit = repository(self.root, {"team.json": json.dumps(TEAM, indent=2) + "\n", "RULES.md": "# Rules\n",
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

    def test_the_files_are_committed_by_the_agent_before_the_task_closes(self):
        write(self.checkout, {f"outputs/{self.ref}/report.md": "# Report\n",
                              f"outputs/{self.ref}/computer-use/capture-1.png": b"x", "RULES.md": "changed"})
        self.helper()
        text, error = self.deliver()
        self.assertFalse(error, text)
        commit = self.origin("rev-parse", hub.CONFIG_BRANCH)
        self.assertEqual(text, f"Delivered. {self.ref} is completed. Its files are on the configuration ref as "
                               f"{commit[:12]}: outputs/{self.ref}/report.md. You are done with it: stop now and end your turn; your session closes when it ends.")
        self.assertEqual(self.origin("ls-tree", "-r", "--name-only", hub.CONFIG_BRANCH).split(),
                         ["RULES.md", "hub.py", f"outputs/{self.ref}/report.md", "team.json"])
        self.assertEqual(self.origin("show", f"{hub.CONFIG_BRANCH}:outputs/{self.ref}/report.md"), "# Report")
        self.assertEqual(self.origin("log", "-1", "--format=%an", hub.CONFIG_BRANCH), "Fleet agent vps")
        self.assertEqual(git("rev-parse", "HEAD", cwd=self.kit), commit)        # the hub checkout took it in
        said = hub.q1("SELECT text FROM events WHERE agent='manager' AND kind='say' ORDER BY id DESC LIMIT 1")["text"]
        self.assertIn(f"Output: outputs/{self.ref}/report.md. Its files are on the configuration ref as "
                      f"{commit[:12]}: outputs/{self.ref}/report.md. Checked: Read it back.", said)
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
        salt, value = "salt", "Synthetic-Secret-Value-123"
        hub.ins("INSERT INTO secrets(label,salt,hash,len) VALUES(?,?,?,?)",
                ("Synthetic label", salt, hashlib.sha256((salt + value).encode()).hexdigest(), len(value)))
        write(self.checkout, {f"outputs/{self.ref}/report.md": "# Report\n",
                              f"outputs/{self.ref}/notes.txt": f"the key is {value}\n"})
        self.helper()
        text, error = self.deliver()
        self.assertFalse(error, text)
        self.assertIn(f"Not sent: outputs/{self.ref}/notes.txt (it holds a registered secret).", text)
        self.assertEqual(self.origin("ls-tree", "-r", "--name-only", hub.CONFIG_BRANCH, f"outputs/{self.ref}"),
                         f"outputs/{self.ref}/report.md")

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
        self.assertEqual(self.request("/helper/outputs/vps", {"outputs": token, "task": self.ref, "files": []},
                                      source=TEAM["addresses"]["hub"])[0], 403)       # another machine
        self.assertEqual(self.request("/helper/outputs/vps", {"outputs": token, "task": "T-99", "files": []},
                                      source=VPS), (200, {"taken": False}))           # another task's delivery
        self.assertIsNone(hub.OUTPUTS[token]["answer"])
        self.assertTrue(hub.outputs_allow(self.ref).match(f"outputs/{self.ref}/{'/'.join('d' * 5)}/x.md"))

    def test_the_same_files_twice_make_one_commit(self):
        t = hub.q1("SELECT * FROM tasks WHERE id=?", (self.task,))
        files = {f"outputs/{self.ref}/report.md": b"# Report\n"}
        first = hub.commit_outputs("vps", t, files)
        self.assertEqual(hub.commit_outputs("vps", t, files), first)
        self.assertEqual(self.origin("rev-parse", hub.CONFIG_BRANCH), first)


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
