"""The fleet manager's runtime switch (owner feature runtime_switch), hub side, through the real routes: it keeps the
manager's full-access form in both directions, needs a helper that closes the previous runtime's standing session and a
recorded conversation, does not count the manager's owner messages as unanswered, and holds the manager's messages
until a status report shows its new session on its recorded conversation. A temporary database and repository and a
stand-in helper status: no AI call, no real runtime, no real session."""
import json
import shutil
import tempfile
import threading
import unittest
import uuid
from unittest.mock import patch
from pathlib import Path

import hub
from test_runtime_switch import git
from test_ui_api import OwnerAPI

CLAUDE = hub.MANAGER_ACCESS["claude"]["start"]
CODEX = hub.MANAGER_ACCESS["codex"]["start"]
TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": ["shell", "web"],
                               "start": CLAUDE},
                   "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"], "start": CODEX}}}
FEATURES = ["trigger_check", "trigger_code", "agent_setup", "agent_key", "runtime_switch", "manager_switch"]
HELD = "No unread messages. Wait for the next signal."


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(ManagerSwitch(name) for name in ManagerSwitch.__dict__ if name.startswith("test_"))


class ManagerSwitch(OwnerAPI):
    def setUp(self):
        super().setUp()
        self.server.machines = True             # each request comes from the machine that its route names
        self.root = Path(tempfile.mkdtemp(prefix="fleet-manager-switch-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        seed = self.root / "seed"
        (seed / "profiles").mkdir(parents=True)
        (seed / "team.json").write_text(json.dumps(TEAM, indent=2) + "\n")
        git("init", "-q", str(seed))
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "seed", cwd=seed)
        git("clone", "-q", "--bare", str(seed), str(self.root / "origin.git"))
        git("clone", "-q", str(self.root / "origin.git"), str(self.root / "kit"))
        self.kit = self.root / "kit"
        hub.CFG["team_path"] = str(self.kit / "team.json")
        self.addCleanup(hub.CFG.pop, "team_path", None)
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = json.loads(json.dumps(TEAM))
        hub.CFG.update(silence=180, question_wait=120, manager_silence=120, stop_after=60, offline_after=90, tick=5)
        for name in hub.TEAM["agents"]:
            hub.touch(name)
        self.assertEqual(self.report()[0], 200)

    # ---- helpers
    def team(self):
        return json.loads(git("show", "HEAD:team.json", cwd=self.kit))

    def report(self, runtime="claude", **changes):
        """The stand-in helper of the manager sends its machine status through the real route."""
        body = dict({"revision": git("rev-parse", "HEAD", cwd=self.kit),
                     "runtime": {"name": runtime, "version": "1", "signed_in": True},
                     "runtimes": {"codex": {"version": "codex-cli 0.160.0", "signed_in": True},
                                  "claude": {"version": "2.1.296 (Claude Code)", "signed_in": True}},
                     "update": {"state": None, "detail": None}, "features": FEATURES,
                     "settings": hub.agent_settings("manager"), "other_runtime_windows": [], "owner_chat_bound": None,
                     "manager_bound": True}, **changes)
        return self.request("/helper/status/manager", body)

    def readiness(self):
        return next(l for l in self.request("/ui/team?db=test-generation")[1]["lines"]
                    if l["agent"] == "manager")["runtime_switch"]

    def switch(self, runtime):
        sha = self.request("/ui/team?db=test-generation")[1]["sha256"]
        return self.request("/ui/team/agents/manager", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                       "base_sha256": sha, "runtime": runtime})

    def say(self, text):
        self.assertEqual(self.request("/ui/messages", self.command(text=text))[0], 200)

    def delivered(self):
        """The `say` events that the manager's helper gets now."""
        code, data = self.request("/events/manager?delivery=1&after=0&wait=0&alive=manager")
        self.assertEqual(code, 200)
        return [e["text"] for e in data["events"] if e["kind"] == "say"]

    # ---- tests
    def test_a_ready_manager_switches_to_codex_and_back_with_its_exact_policies(self):
        self.assertEqual(self.readiness(), {"to": "codex", "ready": True, "missing": [], "busy": None, "rules": []})
        self.say("Earlier goal without a request id in its reply.")    # the manager's replies name none
        self.assertTrue(self.readiness()["ready"])
        loaded = git("rev-parse", "HEAD", cwd=self.kit)                # the revision that the running helper loaded
        code, result = self.switch("codex")
        self.assertEqual((code, result["updates_requested"]), (200, ["manager"]))
        manager = self.team()["agents"]["manager"]
        self.assertEqual((manager["runtime"], manager["start"], manager["runtime_policies"]),
                         ("codex", CODEX, {"claude": {"start": CLAUDE}}))
        self.assertNotIn("allow", manager)
        update = hub.q1("SELECT * FROM events WHERE agent='manager' AND kind='update'")
        self.assertEqual(json.loads(update["extra"])["desired_revision"], git("rev-parse", "HEAD", cwd=self.kit))
        code, answer = self.report("claude", revision=loaded)          # the helper before its restart
        self.assertTrue(answer["update_requested"])                     # the manager's helper loads the switch too
        self.report("codex")                                            # the restarted helper with its new session
        self.assertFalse(hub.manager_held("manager"))
        self.assertTrue(self.readiness()["ready"])
        code, result = self.switch("claude")
        manager = self.team()["agents"]["manager"]
        self.assertEqual((code, manager["runtime"], manager["start"], manager["runtime_policies"]),
                         (200, "claude", CLAUDE, {"codex": {"start": CODEX}}))      # exactly as it was

    def test_the_manager_says_why_it_cannot_switch_yet(self):
        def missing(team=None, **status):
            self.report(**status)
            return hub.runtime_switch("manager", team)["missing"]
        self.assertEqual(missing(features=FEATURES[:-1]), ["helper_without_runtime_switch"])
        self.assertEqual(missing(runtimes={"codex": {"version": "codex-cli 0.160.0", "signed_in": False},
                                           "claude": {"version": "2.1.296", "signed_in": True}}), ["runtime_not_signed_in"])
        self.assertEqual(missing(manager_bound=False), ["manager_not_bound"])
        self.assertEqual(missing(manager_bound=None), [])               # no standing session: nothing to keep
        self.assertEqual(missing(other_runtime_windows=["manager"]), ["settings_pending"])
        team = json.loads(json.dumps(TEAM))
        for policy in ({"start": "claude --permission-mode dontAsk {settings} {prompt}", "allow": ["Bash"]},
                       {"start": CLAUDE, "allow": ["mcp__fleet__*"]}):
            team["agents"]["manager"].update(policy)
            self.assertEqual(missing(team), ["access_not_equivalent"])
        team = json.loads(json.dumps(TEAM))
        team["agents"]["manager"]["runtime_policies"] = {"codex": {"start": "codex --sandbox workspace-write {prompt}"}}
        self.assertEqual(missing(team), ["access_not_equivalent"])      # a stored form that is not full access
        job = hub.ins("INSERT INTO jobs(agent,kind,created) VALUES(?,?,?)", ("manager", "probe", hub.now()))
        self.assertEqual(missing(), ["agent_busy"])
        self.assertEqual(hub.runtime_switch("manager")["busy"]["jobs"], [job])

    def test_the_manager_s_messages_wait_for_its_new_session(self):
        self.say("Before the switch.")
        self.assertEqual(self.delivered(), ["[owner] Before the switch."])
        self.assertEqual(self.switch("codex")[0], 200)
        self.say("During the switch.")
        self.assertEqual(self.delivered(), [])                          # no signal to the closing session
        self.assertEqual(hub.t_read_messages("manager", {}), HELD)      # and no read by it
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM events WHERE agent='manager' AND kind='say' AND read_at IS NOT "
                                "NULL")["n"], 0)
        for status in ({"runtime": "claude"}, {"other_runtime_windows": ["manager"]}, {"manager_bound": None}):
            with self.subTest(status=status):                           # the old helper, the old session, no new one
                self.report(**dict({"runtime": "codex"}, **status))
                self.assertTrue(hub.manager_held("manager"))
        self.assertIsNotNone(hub.kv_get("switching:manager"))           # in the database: a hub restart keeps it
        self.report("codex", manager_bound=False)                       # a new session runs, before its conversation
        self.assertFalse(hub.manager_held("manager"))
        held = self.delivered()
        self.assertEqual(held[0], "[owner] Before the switch.")
        self.assertIn("The owner switched manager from claude to codex", held[1])
        self.assertEqual(held[2], "[owner] During the switch.")
        text = hub.t_read_messages("manager", {})
        self.assertTrue(all(part in text for part in ("Before the switch.", "During the switch.", "switched manager")))
        self.assertEqual(self.delivered(), [])

    def test_the_manager_s_saved_checks_keep_working_on_either_runtime(self):
        hub.ins("INSERT INTO triggers(agent,state,revision,schedule,check_spec,task,late_minutes,max_tasks_per_day,"
                "anchor,created,updated,request_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                ("manager", "active", 1, json.dumps({"kind": "every", "minutes": 15}), json.dumps({"code": "saved"}),
                 json.dumps({"title": "Look"}), 5, 1, hub.now(), hub.now(), hub.now(), str(uuid.uuid4())))
        self.assertTrue(hub.wakeups.execution_grant(hub.agents()["manager"])[0])     # Claude with no deny list
        self.assertEqual((self.readiness()["ready"], self.readiness()["rules"]), (True, []))
        self.assertEqual(self.switch("codex")[0], 200)
        self.report("codex")
        self.assertTrue(hub.wakeups.execution_grant(hub.agents()["manager"])[0])
        self.assertEqual((self.readiness()["ready"], self.readiness()["rules"]), (True, []))   # and back again

    def test_the_owner_sees_a_switch_and_not_a_missing_manager(self):
        self.assertEqual(self.switch("codex")[0], 200)
        self.request("/events/manager?delivery=1&after=0&wait=0&alive=")       # its old window has closed
        hub.tick()
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "switching")
        self.assertEqual(hub.kv_get("mgr_flag"), "The manager switches to Codex. Its messages wait until it runs.")
        self.report("codex")
        self.request("/events/manager?delivery=1&after=0&wait=0&alive=")       # a later list: no new window either
        hub.tick()
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "down")           # down, as before

    def test_the_manager_s_silence_counts_from_the_end_of_its_switch(self):
        """Plan C10: silent is a fact, the line its helper told twice and that it did not take. One that its previous
        session did not take says nothing about the new one."""
        self.say("An old message.")
        hub.q("UPDATE events SET created=? WHERE agent='manager' AND kind='say'", (hub.now() - 1000,))
        hub.kv_set("untaken:manager:manager", hub.now() - 500)        # the previous session did not take its line
        self.assertEqual(self.switch("codex")[0], 200)
        self.report("codex")                                            # the new session runs: its messages go on
        self.request("/events/manager?delivery=1&after=0&wait=0&alive=manager")
        hub.tick()
        self.assertIsNone(hub.kv_get("mgr_flag_kind"))                  # not silent: the new one was not told yet
        hub.kv_set("untaken:manager:manager", float(hub.kv_get("switched:manager")) + 1)
        hub.tick()
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "silent")         # the new session did not take its line

    def test_a_switch_that_cannot_finish_becomes_the_owner_s_warning_and_hides_no_question(self):
        """Plan C10: a switch stalls on a fact -- a question on its previous session's screen, a failed update of
        its machine, a sign-out -- and a long one is still the quiet switching."""
        self.assertEqual(self.switch("codex")[0], 200)
        hub.tick()
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "switching")
        hub.kv_set("switching:manager", hub.now() - 7 * 86400)         # a week: no clock stalls it
        hub.tick()
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "switching")
        hub.kv_set("mgr_screen", hub.now())                             # a question on its session's screen
        hub.tick()
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "switch_stalled")
        self.assertEqual(hub.kv_get("mgr_flag"), "The manager's switch to Codex waits on a question.")
        hub.kv_set("mgr_screen", None)
        hub.tick()
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "switching")
        hub.q("UPDATE machine_updates SET state='failed' WHERE agent='manager'")
        hub.tick()
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "switch_stalled")
        self.assertEqual(hub.kv_get("mgr_flag"), "The manager's switch to Codex stopped: its update failed.")
        hub.q("UPDATE machine_updates SET state='requested' WHERE agent='manager'")
        out = {"codex": {"version": "codex-cli 0.160.0", "signed_in": False},
               "claude": {"version": "2.1.296 (Claude Code)", "signed_in": True}}
        self.report("claude", runtimes=out)                             # the old helper, and codex is signed out
        hub.tick()
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "switch_stalled")
        self.assertEqual(hub.kv_get("mgr_flag"), "The manager's switch to Codex waits for its sign-in.")
        self.assertTrue(hub.manager_held("manager"))                    # its messages still wait

    def test_a_signed_out_manager_is_named_as_that_and_its_state_says_so(self):
        self.say("A message that it cannot read.")
        hub.q("UPDATE events SET created=? WHERE agent='manager' AND kind='say'", (hub.now() - 1000,))
        hub.kv_set("untaken:manager:manager", hub.now())              # told twice, and it took neither (plan C10)
        hub.tick()
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "silent")
        out = {"codex": {"version": "codex-cli 0.160.0", "signed_in": True},
               "claude": {"version": "2.1.296 (Claude Code)", "signed_in": False}}
        self.assertEqual(self.report(runtimes=out)[0], 200)
        hub.tick()
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "signed_out")     # the cause, not the silence it makes
        self.assertEqual(hub.kv_get("mgr_flag"), "The manager is not signed in.")
        self.assertIn("Fleet hub: The manager is not signed in.",
                      [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='owner' AND kind='notify'")])
        line = next(a for a in self.request("/ui/state")[1]["agents"] if a["name"] == "manager")
        self.assertIs(line["signed_in"], False)
        self.request("/events/manager?delivery=1&after=0&wait=0&alive=")       # its window has closed as well
        hub.tick()
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "signed_out")     # a start would not help, a sign-in does
        self.assertEqual(self.report()[0], 200)                         # signed in again
        hub.tick()
        self.assertNotEqual(hub.kv_get("mgr_flag_kind"), "signed_out")
        line = next(a for a in self.request("/ui/state")[1]["agents"] if a["name"] == "manager")
        self.assertIs(line["signed_in"], True)

    def test_the_manager_s_switch_update_can_go_again_and_ends_with_a_later_commit(self):
        # Since 19 October 2026 the route takes the manager at any time, switch or no switch (hub.request_update);
        # what this one is about is a *failed* update of a switch, which can be asked for again.
        self.assertEqual(self.request("/ui/machines/manager/update", {"request_id": str(uuid.uuid4()),
                                                                      "db": "test-generation"})[0], 200)
        old = git("rev-parse", "HEAD", cwd=self.kit)
        self.assertEqual(self.switch("codex")[0], 200)
        hub.q("UPDATE machine_updates SET state='failed' WHERE agent='manager'")    # its update failed
        code, result = self.request("/ui/machines/manager/update", {"request_id": str(uuid.uuid4()),
                                                                    "db": "test-generation"})
        self.assertEqual((code, result["state"]), (200, "requested"))     # while its switch waits: it can go again
        switched = git("rev-parse", "HEAD", cwd=self.kit)
        for name in ("later.py", "latest.py"):                          # the shared checkout moves on two times, with
            (self.kit / name).write_text("# a later owner change\n")     # changes that a helper loads
            git("add", name, cwd=self.kit)
            git("commit", "-q", "-m", name, cwd=self.kit)
            if name == "later.py":
                later = git("rev-parse", "HEAD", cwd=self.kit)
        hub._revision_cache.update(at=0.0, value=None)
        hub.q("UPDATE machine_updates SET desired=? WHERE agent='manager'", (switched,))
        code, answer = self.report("codex", revision=later)            # neither the requested code nor the hub's now
        self.assertFalse(answer["update_requested"])                    # but it has the requested commit
        self.assertEqual(hub.q1("SELECT state FROM machine_updates WHERE agent='manager'")["state"], "current")
        self.assertTrue(hub.contains_revision(later, old))
        self.assertFalse(hub.contains_revision(old, switched))

    def message(self, text):
        """The id of the manager's message with this text."""
        return hub.q1("SELECT id FROM events WHERE agent='manager' AND kind='say' AND text=?", ("[owner] " + text,))["id"]

    def test_the_managers_report_is_linked_to_the_message_that_it_names_and_to_no_other(self):
        """**For a message that the owner wrote in the app, the hub writes no link by a guess.** From 21 October 2026
        a report that the manager posted while a message of the owner's stood read and unanswered was linked to the
        oldest such message, because the manager could name none then. On the first fleet that linked 14 of 190
        reports, each one to a message that the manager had carried out with its tools and no words, and none was the
        answer to it. A report is linked to the message that it names by its M-<id>. A report that names none still
        takes the turn of the oldest message that waits, which keeps the order for the chat apps (test_chat_apps),
        and for a message from the app that turn leaves no link: the message still gets the report that names it."""
        hub.t_tell_owner("manager", {"text": "Nothing to report."})     # nothing of the owner's waits
        self.assertEqual((self.linked("Nothing to report."), self.turns("Nothing to report.")), ([None], [None]))
        self.say("Create one task for Leo, and do nothing else.")       # the manager carries it out with no words
        hub.t_tell_owner("manager", {"text": "Before the read."})       # an unread message has no turn
        self.assertEqual((self.linked("Before the read."), self.turns("Before the read.")), ([None], [None]))
        hub.t_read_messages("manager", {})
        self.say("And one for Mia.")
        hub.t_read_messages("manager", {})
        asked, later = (hub.q1("SELECT request_id FROM ui_requests WHERE recipient='manager' AND text=?", (text,))[0]
                        for text in ("Create one task for Leo, and do nothing else.", "And one for Mia."))
        notice = hub.emit("manager", "say", "[hub] Result for T-12: completed.")        # no word of the owner's:
        elsewhere = hub.emit("leo", "chat", "[owner chat request_id=1] Hello Leo.")     # nor is their word to Leo
        hub.t_read_messages("manager", {})
        hub.t_tell_owner("manager", {"text": "A standing item changed.", "about": f"M-{notice}, T-12"})
        hub.t_tell_owner("manager", {"text": "All tasks run.", "about": f"M-{elsewhere}"})
        hub.t_tell_owner("manager", {"text": "Mia is back.", "about": "T-12, R-3/C-402"})
        texts = ("A standing item changed.", "All tasks run.", "Mia is back.")
        self.assertEqual([self.linked(t) for t in texts], [[None], [None], [None]])
        self.assertEqual([self.turns(t) for t in texts], [[asked], [later], [None]])    # the oldest first, each once
        m1, m2 = (f"M-{self.message(text)}" for text in ("Create one task for Leo, and do nothing else.",
                                                         "And one for Mia."))
        hub.t_tell_owner("manager", {"text": "Leo has the task.", "about": f"{m1}, T-13"})
        self.assertEqual(self.linked("Leo has the task."), [asked])     # the report that names it, after its turn
        self.assertEqual(self.turns("Leo has the task."), [None])
        said = hub.t_tell_owner("manager", {"text": "Mia has hers.", "in_reply_to": m2})
        self.assertEqual(self.linked("Mia has hers."), [later])         # and so with the name in in_reply_to
        self.assertNotIn("has its answer already", said)

    def test_a_report_that_names_a_message_that_the_manager_did_not_read_has_no_link(self):
        """about can name a message of the owner's that the manager has not read (a name that it has from elsewhere):
        the report is not its answer, it is not refused, and it takes no turn of another message."""
        (asked, m1), = self.owner_says("Create one task for Leo, and do nothing else.")
        self.say("And one for Mia.")
        unread = f"M-{self.message('And one for Mia.')}"
        said, error = hub.call_tool("manager", "tell_owner", {"text": "Mia comes next.", "about": f"{unread}, T-14"})
        self.assertFalse(error, said)
        self.assertEqual((self.linked("Mia comes next."), self.turns("Mia comes next.")), ([None], [None]))

    def test_a_report_on_the_owners_answer_to_a_needs_you_item_stands_under_no_chat_message(self):
        """The owner's answer to a Needs-you item reaches the manager as a message with an M-<id>, and the manager's
        report on it names that id. It is no chat message, so no report is linked to it, and the report went under
        the oldest chat message that waited instead: on the first fleet, the word on a GitHub permission under a
        release test of the day before. It has no link."""
        (asked, m1), = self.owner_says("Create one task for Leo, and do nothing else.")
        need = self.need()
        code, answer = self.request(f"/ui/needs/{need}", self.command(answer="Done, the permission is accepted."))
        self.assertEqual(code, 200, answer)
        self.assertIn(f"Message M-{answer['event_id']}:\n[owner] Answer to Needs-you N-{need}",
                      hub.t_read_messages("manager", {}))
        said = hub.t_tell_owner("manager", {"text": "Thanks, the permission is noted.",
                                            "about": f"M-{answer['event_id']}, N-{need}, T-91"})
        self.assertIn("added to the owner's manager chat", said)
        self.assertEqual(self.linked("Thanks, the permission is noted."), [None])
        self.assertEqual(self.turns("Thanks, the permission is noted."), [None])    # the chat message keeps its turn
        # in in_reply_to the same name gives no link either, and the report says why
        said = hub.t_tell_owner("manager", {"text": "Leo goes on with it.", "in_reply_to": f"M-{answer['event_id']}"})
        self.assertIn(f"M-{answer['event_id']} is no chat message of the owner's to you, so this report has no link.",
                      said)
        self.assertEqual(self.linked("Leo goes on with it."), [None])
        # The same for the owner's word in the discussion of an item and for an answer on the hub's own board, which
        # are messages with no receipt of the app's; beside a word of the hub's, in both orders; and for a chat
        # message that has its answer. Each report is about the owner's message that it names: none takes the turn.
        notice = hub.emit("manager", "say", "[hub] Result for T-12: completed.")
        other = self.need()
        self.assertEqual(self.request(f"/ui/needs/{other}/talk", self.command(text="Why this one?"))[0], 200)
        board = self.need()
        code, _ = self.request(f"/needs/{board}", {"answer": "Yes, do it."}, headers={
            "Content-Type": "application/json", "Accept": "application/json"})
        self.assertEqual(code, 200)
        talk, on_board = (hub.q1("SELECT id FROM events WHERE agent='manager' AND text LIKE ? ORDER BY id DESC",
                                 (start + "%",))["id"]
                          for start in ("[owner] About the Needs-you item", f"[owner] Answer to Needs-you N-{board}"))
        hub.t_read_messages("manager", {})
        for n, about in enumerate((f"M-{talk}, N-{other}", f"M-{on_board}", f"M-{notice} and M-{answer['event_id']}",
                                   f"M-{answer['event_id']}, M-{notice}")):
            hub.t_tell_owner("manager", {"text": f"Noted {n}.", "about": about})
            self.assertEqual((self.linked(f"Noted {n}."), self.turns(f"Noted {n}.")), ([None], [None]), about)
        hub.t_tell_owner("manager", {"text": "Leo has the task.", "in_reply_to": m1})
        self.assertEqual(self.linked("Leo has the task."), [asked])     # the chat message still gets its own answer
        (waits, _), = self.owner_says("And one for Mia.")
        hub.t_tell_owner("manager", {"text": "A later word on Leo's task.", "about": f"{m1}, T-13"})
        self.assertEqual((self.linked("A later word on Leo's task."), self.turns("A later word on Leo's task.")),
                         ([None], [None]))                              # about a message that has its answer
        hub.t_tell_owner("manager", {"text": "All tasks run."})
        self.assertEqual(self.turns("All tasks run."), [waits])         # the message that waits kept its turn

    def owner_says(self, *texts):
        """The owner's chat messages to the manager, read: the request id and the M-<id> of each."""
        for text in texts:
            self.say(text)
        hub.t_read_messages("manager", {})
        ids = [r["request_id"] for r in hub.q("SELECT request_id FROM ui_requests WHERE recipient='manager' "
                                              "ORDER BY created, rowid")][-len(texts):]
        return [(rid, f"M-{self.message(text)}") for rid, text in zip(ids, texts)]

    def linked(self, text):
        """The request ids that the reports with this text are linked to, in their order."""
        return [r["in_reply_to"] for r in hub.q("SELECT in_reply_to FROM owner_reports WHERE text=? ORDER BY id", (text,))]

    def turns(self, text):
        """The request ids of the messages whose turn the reports with this text took with no link, in their order."""
        return [r["turn"] for r in hub.q("SELECT turn FROM owner_reports WHERE text=? ORDER BY id", (text,))]

    def test_the_managers_report_answers_the_message_that_about_names(self):
        """about is where tell_owner asks for the message that a report answers, by its M-<id>. With messages of the
        owner's that wait, a report goes under the first one that it names and that still waits, and not under the
        oldest one that waits: that rule alone put 18 of 66 such reports under another message (the first fleet, 14
        days). When none of the named ones waits, the report has no link: the oldest one that waits does not get
        it. The same report again is told as saved."""
        (first, m1), (second, m2), (third, m3) = self.owner_says("What is the status?", "And when is the release?",
                                                               "And who does it?")
        hub.t_tell_owner("manager", {"text": "On Friday.", "about": f"{m2} and {m3}, the release"})
        self.assertEqual(self.linked("On Friday."), [second])           # the first one it names, not the oldest
        again = hub.t_tell_owner("manager", {"text": "On Friday.", "about": f"{m2} and {m3}, the release"})
        self.assertIn("already saved. No duplicate was sent.", again)
        self.assertEqual(self.linked("On Friday."), [second])           # one report, also when the call comes twice
        hub.t_tell_owner("manager", {"text": "Leo does it.", "about": f"about {m2} and {m3}"})
        self.assertEqual(self.linked("Leo does it."), [third])          # the first named one that still waits
        notice = hub.emit("manager", "say", "[hub] A notice of the hub.")
        hub.t_tell_owner("manager", {"text": "It is out now.", "about": f"{m2}, M-{notice}, M-12345678901234567890"})
        self.assertEqual(self.linked("It is out now."), [None])         # none of them waits: no other message gets it
        hub.t_tell_owner("manager", {"text": "All tasks run.", "about": f"{m3}, {m1}"})
        self.assertEqual(self.linked("All tasks run."), [first])        # the first message waited until it was named
        hub.t_tell_owner("manager", {"text": "One more thing.", "about": m3})
        self.assertEqual(self.linked("One more thing."), [None])        # and nothing waits any more

    def test_the_same_report_again_is_one_report_until_the_owner_writes_again(self):
        """tell_owner has no request id, so the manager's newest report again, with the same words and about and no
        message of the owner's read since, is the same call: nothing is saved or sent twice, whatever it names. After
        a message of the owner's that the manager read, the same words are a report of their own."""
        (first, m1), (second, m2) = self.owner_says("What is the status?", "And when is the release?")
        for args in ({"text": "All tasks run."},                                # no name: no link
                     {"text": "On Friday.", "in_reply_to": m2},                 # the named one
                     {"text": "It moved to Monday.", "in_reply_to": m2},        # a later word, with no link
                     {"text": "No news yet.", "about": f"{m1}, G-5"}):          # the one that about names
            self.assertNotIn("already saved", hub.t_tell_owner("manager", args))
            self.assertIn("already saved. No duplicate was sent.", hub.t_tell_owner("manager", args))
        self.assertEqual(self.count("owner_reports"), 4)
        self.assertEqual([self.linked(t) for t in ("All tasks run.", "On Friday.", "It moved to Monday.", "No news yet.")],
                         [[None], [second], [None], [first]])
        (third, m3), = self.owner_says("Any news?")
        said = hub.t_tell_owner("manager", {"text": "No news yet.", "about": f"{m1}, G-5"})
        self.assertNotIn("already saved", said)                         # the owner wrote again: a report of its own,
        self.assertEqual(self.linked("No news yet."), [first, None])    # which names no message that waits
        hub.t_tell_owner("manager", {"text": "No news yet.", "about": f"{m3}, G-5"})
        self.assertEqual(self.linked("No news yet."), [first, None, third])

    def test_the_manager_names_the_owners_message_as_its_read_named_it(self):
        """read_messages calls the owner's message M-<id>, and that is the only name of it that the manager gets. With
        that name in in_reply_to a report is linked to that message, or to none: never to another one. It was refused
        for "an owner request UUID", which the manager never gets (the first fleet, 18 times in ten days), and the
        manager then sent its whole report again."""
        self.say("What is the status?")
        self.say("And when is the release?")
        newest = self.message("And when is the release?")
        unread, error = hub.call_tool("manager", "tell_owner", {"text": "Too early.", "in_reply_to": f"M-{newest}"})
        self.assertTrue(error)                          # unread: nothing answers a message that it did not read
        self.assertIn(f"Read M-{newest} before you answer it", unread)
        first, second = (r["request_id"] for r in hub.q("SELECT request_id FROM ui_requests WHERE recipient='manager' "
                                                         "ORDER BY created, rowid"))
        m2 = f"M-{newest}"
        self.assertIn(f"Message {m2}:", hub.t_read_messages("manager", {}))
        said, error = hub.call_tool("manager", "tell_owner", {"text": "On Friday.", "in_reply_to": f" {m2} "})
        self.assertFalse(error, said)
        self.assertEqual(self.linked("On Friday."), [second])
        again, error = hub.call_tool("manager", "tell_owner", {"text": "On Friday.", "in_reply_to": m2})
        self.assertFalse(error, again)
        self.assertIn("already saved. No duplicate was sent.", again)
        # A message that has its answer takes a later word with no link and no refusal, and no other message takes it.
        said, error = hub.call_tool("manager", "tell_owner", {"text": "It moved to Monday.", "in_reply_to": m2})
        self.assertFalse(error, said)
        self.assertIn(f"{m2} has its answer already, so this report has no link.", said)
        self.assertEqual(self.linked("It moved to Monday."), [None])    # not the first message, which still waits
        # So does a name that is no chat message of the owner's: a word of the hub, and a number that no message has.
        other = hub.emit("manager", "say", "[hub] A notice of the hub.")
        hub.t_read_messages("manager", {})
        for wrong in (f"M-{other}", "M-999999"):
            said, error = hub.call_tool("manager", "tell_owner", {"text": f"Noted {wrong}.", "in_reply_to": wrong})
            self.assertFalse(error, said)
            self.assertIn(f"{wrong} is no chat message of the owner's to you, so this report has no link.", said)
            self.assertEqual(self.linked(f"Noted {wrong}."), [None])
        hub.t_tell_owner("manager", {"text": "All tasks run.", "in_reply_to": " "})     # a blank name is no name,
        self.assertEqual(self.linked("All tasks run."), [None])                         # and the hub guesses none
        said, error = hub.call_tool("manager", "tell_owner", {"text": "Noted.", "in_reply_to": "the last one"})
        self.assertTrue(error)
        self.assertIn("in_reply_to names the owner's message as read_messages gives it, for example M-12", said)
        self.assertEqual(self.count("owner_reports"), 5)

    def test_a_session_that_did_not_finish_its_turn_hands_its_messages_to_the_new_one(self):
        self.say("Answer me, please.")
        self.assertIn("Answer me, please.", hub.t_read_messages("manager", {}))     # read; its usage limit stops it
        unfinished = [self.message("Answer me, please.")]               # what the helper found in its conversation
        self.assertEqual(self.switch("codex")[0], 200)
        code, answer = self.report("codex", manager_handover={"claude": unfinished})
        self.assertEqual((code, answer["handover_done"]), (200, True))  # the helper can forget it now
        handed = hub.t_read_messages("manager", {})                     # the new session's first read
        self.assertIn("did not finish before the switch", handed)
        self.assertIn("rule 9", handed)
        self.assertIn("[owner] Answer me, please.", handed)
        self.assertEqual(hub.t_read_messages("manager", {}), HELD)
        self.assertEqual(self.switch("claude")[0], 200)                 # the next switch hands over only what its
        self.report("claude")                                           # helper reports: here nothing
        self.assertNotIn("did not finish", hub.t_read_messages("manager", {}))

    def test_the_hand_over_shows_what_the_previous_session_already_told_the_owner(self):
        hub.t_tell_owner("manager", {"text": "An earlier answer."})    # before it read the message: not shown
        self.say("What is the status?")
        hub.t_read_messages("manager", {})
        hub.t_tell_owner("manager", {"text": "All tasks run.\nNothing waits."})     # then its usage limit
        ids = [self.message("What is the status?")]
        self.assertEqual(self.switch("codex")[0], 200)
        self.report("codex", manager_handover={"claude": ids})
        reply = hub.q1("SELECT id FROM owner_reports WHERE text LIKE 'All tasks run.%'")["id"]
        text = hub.t_read_messages("manager", {})
        self.assertIn(f'After its first read of them, it sent the owner these reports: R-{reply}: "All tasks run. '
                      f'Nothing waits.". First check', text)
        self.assertNotIn("An earlier answer.", text)
        self.say("Another question.")                                   # the next switch: nothing sent since its read
        hub.t_read_messages("manager", {})
        self.assertEqual(self.switch("claude")[0], 200)
        self.report("claude", manager_handover={"codex": [self.message("Another question.")]})
        self.assertIn("it sent the owner no report.", hub.t_read_messages("manager", {}))

    def test_only_the_reported_messages_of_this_manager_are_handed_over(self):
        self.say("Answered in a finished turn.")                        # its turn ended with no empty read
        self.say("Read by the turn that stopped.")
        hub.t_read_messages("manager", {})
        self.say("Never read.")
        other = hub.emit("vps", "say", "[manager] A worker's message.")
        hub.q("UPDATE events SET read_at=? WHERE id=?", (hub.now(), other))         # read by that worker
        self.assertEqual(self.switch("codex")[0], 200)
        self.report("codex", manager_handover={"claude": [self.message("Read by the turn that stopped."), other,
                                                          self.message("Never read."), 99999]})
        notice = hub.q1("SELECT text FROM events WHERE agent='manager' AND text LIKE '[hub] The previous manager%'")
        self.assertTrue(notice["text"].startswith(
            "[hub] The previous manager session read M-%d, but" % self.message("Read by the turn that stopped.")))
        text = hub.t_read_messages("manager", {})
        self.assertIn("Read by the turn that stopped.", text)
        self.assertNotIn("Answered in a finished turn.", text)          # it stays read: no second answer
        self.assertIn("Never read.", text)                              # unread anyway
        self.assertIsNotNone(hub.q1("SELECT read_at FROM events WHERE id=?", (other,))["read_at"])  # not the manager's

    def test_the_hand_over_waits_for_the_end_of_the_switch_and_is_used_once(self):
        self.say("Unfinished.")
        hub.t_read_messages("manager", {})
        ids = [self.message("Unfinished.")]
        self.assertEqual(self.switch("codex")[0], 200)
        for status in ({"runtime": "claude"}, {"other_runtime_windows": ["manager"]}, {"manager_bound": None}):
            with self.subTest(status=status):                           # not the end yet: the helper keeps it
                code, answer = self.report(**dict({"runtime": "codex", "manager_handover": {"claude": ids}}, **status))
                self.assertEqual((code, answer["handover_done"]), (200, False))
                self.assertEqual(hub.t_read_messages("manager", {}), HELD)
        self.assertTrue(self.report("codex", manager_handover={"claude": ids})[1]["handover_done"])
        self.assertIn("[owner] Unfinished.", hub.t_read_messages("manager", {}))
        code, answer = self.report("codex", manager_handover={"claude": ids})   # its answer got lost: the same again
        self.assertEqual((code, answer["handover_done"]), (200, True))  # no switch is open: nothing uses it
        self.assertEqual(hub.t_read_messages("manager", {}), HELD)      # and nothing is handed over twice
        self.assertNotIn("handover_done", self.report("codex")[1])      # a report without one gets no such answer

    def test_a_long_hand_over_keeps_every_message_and_the_new_session_s_early_read_gets_none(self):
        for n in range(12):                                             # one read gives them all
            self.say(f"Unfinished message {n}.")
        self.assertIn("Unfinished message 11.", hub.t_read_messages("manager", {}))   # then its usage limit
        ids = [self.message(f"Unfinished message {n}.") for n in range(12)]
        self.assertEqual(self.switch("codex")[0], 200)
        self.report("codex", manager_bound=None, manager_handover={"claude": ids})  # the new one is not there yet
        self.assertEqual(hub.t_read_messages("manager", {}), HELD)      # the new session's read at its start
        self.report("codex", manager_bound=True, manager_handover={"claude": ids})
        handed = hub.t_read_messages("manager", {})
        for n in range(12):
            self.assertIn(f"[owner] Unfinished message {n}.", handed)

    def test_a_resumed_conversation_never_hands_over_again_what_another_session_read_since(self):
        self.say("Old.")
        hub.t_read_messages("manager", {})                              # Claude's turn stops at its limit
        old = self.message("Old.")
        self.assertEqual(self.switch("codex")[0], 200)
        self.report("codex", manager_handover={"claude": [old]})        # handed to Codex, which answers it
        self.assertIn("[owner] Old.", hub.t_read_messages("manager", {}))
        self.assertEqual(self.switch("claude")[0], 200)
        self.report("claude")                                           # Codex finished: nothing handed over
        self.say("New.")
        hub.t_read_messages("manager", {})                              # the resumed Claude session reads it, stops
        new = self.message("New.")
        self.assertEqual(self.switch("codex")[0], 200)
        self.report("codex", manager_handover={"claude": [old, new]})   # its conversation still has the old read
        notice = hub.q("SELECT text FROM events WHERE agent='manager' AND text LIKE '[hub] The previous manager%' "
                       "ORDER BY id")[-1]["text"]
        self.assertTrue(notice.startswith(f"[hub] The previous manager session read M-{new}, but"))
        text = hub.t_read_messages("manager", {})
        self.assertIn("[owner] New.", text)
        self.assertNotIn("[owner] Old.", text)                          # Codex read and answered it: once is enough

    def test_a_switch_back_during_an_open_hold_hands_the_resumed_session_its_own_stopped_turn(self):
        """The new runtime's session never ran (its start failed), and the owner switched back: the resumed
        conversation's turn that its usage limit stopped is handed to it, because a resumed session does not go on with
        it by itself. Its helper's start gives the resumed conversation's own list (fleet.start_handover)."""
        self.say("Answer me, please.")
        hub.t_read_messages("manager", {})                              # read by Claude, whose limit stops the turn
        mid = self.message("Answer me, please.")
        self.assertEqual(self.switch("codex")[0], 200)
        self.report("codex", manager_bound=None)                        # the Codex start fails: no window
        self.assertTrue(self.readiness()["ready"])                      # the owner switches back
        self.assertEqual(self.switch("claude")[0], 200)
        self.report("claude", manager_handover={"claude": [mid]})       # the resumed Claude session runs
        self.assertFalse(hub.manager_held("manager"))
        text = hub.t_read_messages("manager", {})
        self.assertIn("[owner] Answer me, please.", text)
        self.assertIn(f"The previous manager session read M-{mid}, but", text)
        self.assertEqual(json.loads(hub.q1("SELECT extra FROM events WHERE id=?", (mid,))["extra"])["read_by"], "claude")

    def test_each_message_counts_in_the_list_of_the_runtime_that_read_it_last(self):
        self.say("Read by Claude.")
        hub.t_read_messages("manager", {})
        first = self.message("Read by Claude.")
        self.assertEqual(self.switch("codex")[0], 200)
        self.report("codex", manager_handover={"claude": [first]})
        hub.t_read_messages("manager", {})                              # read again, now by Codex
        self.say("Read by Codex.")
        hub.t_read_messages("manager", {})
        second = self.message("Read by Codex.")
        self.assertEqual(self.switch("claude")[0], 200)
        # Both conversations stopped with both messages read: each message counts only in its last reader's list.
        self.report("claude", manager_handover={"claude": [second], "codex": [first]})
        notice = hub.q("SELECT text FROM events WHERE agent='manager' AND text LIKE '[hub] The previous manager%' "
                       "ORDER BY id")[-1]["text"]
        self.assertTrue(notice.startswith(f"[hub] The previous manager session read M-{first}, but"))   # only it
        hub.t_read_messages("manager", {})                              # the resumed Claude session reads
        self.say("Third.")
        hub.t_read_messages("manager", {})
        third = self.message("Third.")
        for old in (second, third):                                     # reads from before read_by: the time rule
            hub.q("UPDATE events SET extra='{}' WHERE id=?", (old,))
        self.assertEqual(self.switch("codex")[0], 200)
        self.report("codex", manager_handover={"claude": [second, third]})
        text = hub.t_read_messages("manager", {})
        self.assertIn("[owner] Third.", text)                           # read after the end of the switch before
        self.assertNotIn("[owner] Read by Codex.", text)                # read before it

    def test_a_resumed_conversation_learns_that_the_other_session_handled_its_stopped_read(self):
        """Its conversation still ends with the read that its usage limit stopped: without a word, it would answer an
        owner message that the other session answered already."""
        self.say("Status?")
        hub.t_read_messages("manager", {})                              # read by Claude, whose limit stops the turn
        mid = self.message("Status?")
        self.assertEqual(self.switch("codex")[0], 200)
        self.report("codex", manager_handover={"claude": [mid]})
        hub.t_read_messages("manager", {})                              # Codex reads it again
        hub.t_tell_owner("manager", {"text": "All runs."})              # and answers it
        reply = hub.q1("SELECT id FROM owner_reports WHERE text='All runs.'")["id"]
        self.assertEqual(self.switch("claude")[0], 200)
        self.report("claude", manager_handover={"claude": [mid]})       # Claude's conversation resumes, still stopped
        text = hub.t_read_messages("manager", {})
        self.assertNotIn("[owner] Status?", text)                       # not handed over again
        self.assertIn(f"Your conversation's last turn read M-{mid} and stopped before the switch", text)
        self.assertIn(f'R-{reply}: "All runs."', text)
        self.say("Next.")
        hub.t_read_messages("manager", {})
        self.assertEqual(self.switch("codex")[0], 200)                  # a list of messages that it read itself: no
        self.report("codex", manager_handover={"codex": [mid], "claude": [self.message("Next.")]})     # such notice
        self.assertNotIn("Your conversation's last turn", hub.t_read_messages("manager", {}))

    def test_an_id_that_is_no_message_never_stops_the_end_of_a_switch(self):
        self.say("Unfinished.")
        hub.t_read_messages("manager", {})
        self.assertEqual(self.switch("codex")[0], 200)
        code, answer = self.report("codex", manager_handover={"claude": [self.message("Unfinished."), 2 ** 63, 10 ** 30]})
        self.assertEqual((code, answer["handover_done"]), (200, True))
        self.assertFalse(hub.manager_held("manager"))
        self.assertIn("[owner] Unfinished.", hub.t_read_messages("manager", {}))

    def test_the_manager_s_read_names_its_messages_in_its_first_line(self):
        self.say("One.")
        self.say("Two.")
        text = hub.t_read_messages("manager", {})
        self.assertTrue(text.startswith(f"Unread messages: M-{self.message('One.')}, M-{self.message('Two.')}.\n\n"
                                        "Owner-chat guidance: "))
        self.assertEqual(hub.t_read_messages("manager", {}), HELD)

    def test_a_status_with_a_bad_hand_over_is_refused(self):
        for bad in ("12", [7], {"grok": [1]}, {"claude": "1"}, {"claude": [True]}, {"claude": [0]}, {"codex": ["12"]},
                    {"claude": list(range(1, hub.HANDOVER_MAX + 2))}):
            with self.subTest(bad=bad):
                self.assertEqual(self.report(manager_handover=bad)[0], 400)
        self.assertEqual(self.report(manager_handover={"claude": list(range(1, hub.HANDOVER_MAX + 1)),
                                                       "codex": [1]})[0], 200)

    def test_handed_over_messages_come_back_in_their_own_order_before_later_ones(self):
        self.say("Do X.")
        self.assertIn("Do X.", hub.t_read_messages("manager", {}))      # read; then its usage limit
        old = self.message("Do X.")
        self.assertEqual(self.switch("codex")[0], 200)
        self.say("Cancel X.")                                           # sent during the switch
        self.report("codex", manager_bound=True, manager_handover={"claude": [old]})
        text = hub.t_read_messages("manager", {})
        self.assertLess(text.index(f"Message M-{old}:\n[owner] Do X."), text.index("[owner] Cancel X."))
        self.assertIn(f"The previous manager session read M-{old}, but its turn did not finish", text)
        self.assertEqual(text.count("Do X."), 1)                        # once, in its own place

    def test_a_later_commit_that_only_origin_has_closes_an_update(self):
        """A worker can run a later commit than the requested one, which a task of its own pushed and no hub step
        fetched: the hub fetches it to see that it contains the requested commit, at most each FETCH_EVERY seconds."""
        target = git("rev-parse", "HEAD", cwd=self.kit)
        worker = self.root / "worker"
        git("clone", "-q", str(self.root / "origin.git"), str(worker))
        (worker / "outputs").mkdir()
        (worker / "outputs" / "T-1.txt").write_text("done\n")
        git("add", "-A", cwd=worker)
        git("commit", "-q", "-m", "T-1 output", cwd=worker)
        git("push", "-q", "origin", "HEAD:main", cwd=worker)
        later = git("rev-parse", "HEAD", cwd=worker)
        self.addCleanup(hub._fetch.update, at=0.0, thread=None)
        hub._fetch.update(at=hub.time.time(), thread=None)              # a fetch ended just now: the next one waits
        self.assertFalse(hub.contains_revision(later, target))
        self.assertIsNone(hub._fetch["thread"])
        hub._fetch["at"] = 0.0
        released, real = threading.Event(), hub.git_kit

        def git_kit(*args, **kw):                                       # the fetch waits until the check below ends
            if args[0] == "fetch":
                released.wait(30)
            return real(*args, **kw)
        with patch.object(hub, "git_kit", side_effect=git_kit):
            with hub.LOCK:                                              # as a status report: under LOCK, it does not
                self.assertFalse(hub.contains_revision(later, target))  # wait for the fetch, which runs in a thread
            fetching = hub._fetch["thread"]
            self.assertTrue(fetching.is_alive())
            self.assertIsNone(hub.fetch_soon())                         # one at a time
            released.set()
            fetching.join(30)
        self.assertTrue(hub.contains_revision(later, target))           # the next report finds it
        hub._fetch["at"] = 0.0                                          # its folder is the one of its start: a test
        folders, gate, first = [], threading.Event(), hub.kit_dir()     # that ends meanwhile changes nothing else

        def watch(*args, **kw):
            if args[0] == "fetch":
                gate.wait(30)
                folders.append(kw.get("folder"))
            return real(*args, **kw)
        with patch.object(hub, "git_kit", side_effect=watch):
            started = hub.fetch_soon()
            hub.CFG["team_path"] = str(self.root / "elsewhere" / "team.json")
            gate.set()
            started.join(30)
        hub.CFG["team_path"] = str(self.kit / "team.json")
        self.assertEqual(folders, [first])
        self.assertEqual(git("rev-parse", "refs/fleet/origin-main", cwd=self.kit), later)
        self.assertNotEqual(git("rev-parse", "origin/main", cwd=self.kit), later)   # the hub's own refs stay
        self.assertIsNone(hub.fetch_soon())                             # at most each FETCH_EVERY seconds
        self.assertFalse(hub.contains_revision("f" * 40, target))       # a commit that origin does not have either


    def test_a_hub_without_its_own_team_file_never_fetches(self):
        """As for a late request of a test whose cleanup removed team_path: kit_dir() would be this checkout."""
        hub._fetch.update(at=0.0, thread=None)
        with patch.dict(hub.CFG), patch.object(hub, "git_kit") as git:
            hub.CFG.pop("team_path", None)
            self.assertIsNone(hub.fetch_soon())
        git.assert_not_called()


    def test_a_fetch_goes_to_the_checkout_of_the_team_file_that_its_check_read(self):
        """A test's cleanup can remove team_path between the check and the fetch: the fetch still goes to that
        checkout, never to kit_dir()'s fallback, the checkout that holds hub.py."""
        hub._fetch.update(at=0.0, thread=None)
        calls, real = [], hub._fetch_lock

        class Gone:                     # the cleanup removes team_path while the fetch takes its lock
            def __enter__(self):
                hub.CFG.pop("team_path", None)
                return real.__enter__()

            def __exit__(self, *exc):
                return real.__exit__(*exc)

        def git(*args, folder=None, **kw):
            calls.append((args[0], folder))
            return 1, "", "no origin here"
        with patch.dict(hub.CFG), patch.object(hub, "_fetch_lock", Gone()), patch.object(hub, "git_kit", side_effect=git):
            hub.fetch_soon().join()
        self.assertEqual(calls, [("remote", str(self.kit)), ("symbolic-ref", str(self.kit))])

    def test_a_model_of_the_previous_runtime_is_refused_until_the_helper_loads_the_switch(self):
        """The model list that the hub has is the previous runtime's until the updated helper reports its own: a
        Claude model must not reach a manager that runs Codex now."""
        def models(runtime, model):
            return {"runtime": runtime, "ok": True, "read_at": hub.now(), "source": "test",
                    "options": [{"model": model, "efforts": ["high"], "default": True}]}
        self.report("claude", models=models("claude", "opus"))         # the old helper's list
        self.assertEqual(self.switch("codex")[0], 200)

        def change(model):
            sha = self.request("/ui/team?db=test-generation")[1]["sha256"]
            return self.request("/ui/team/agents/manager", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                           "base_sha256": sha, "model": model})
        code, answer = change("opus")
        self.assertEqual(code, 409)
        self.assertEqual(answer["error"], "Manager has not loaded its switch to Codex yet. Wait for it, then check "
                                          "this server.")
        self.assertNotIn("model", self.team()["agents"]["manager"])
        self.report("codex", models=models("codex", "gpt-6"))           # the updated helper's own list
        self.assertEqual(change("gpt-6")[0], 200)

    def test_a_change_of_the_manager_s_settings_loads_on_its_helper(self):
        sha = self.request("/ui/team?db=test-generation")[1]["sha256"]
        code, result = self.request("/ui/team/agents/manager", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                                "base_sha256": sha, "can": ["shell"]})
        self.assertEqual((code, result["updates_requested"]), (200, ["manager"]))
        self.assertIn("settings_pending", hub.runtime_switch("manager")["missing"])
        self.report("claude")                                           # the updated helper loaded the new settings
        self.assertNotIn("settings_pending", hub.runtime_switch("manager")["missing"])

    def test_the_end_of_the_hold_and_the_hand_over_commit_together(self):
        self.say("Unfinished.")
        hub.t_read_messages("manager", {})
        ids = [self.message("Unfinished.")]
        self.assertEqual(self.switch("codex")[0], 200)
        with patch.object(hub, "event_rows", side_effect=RuntimeError("the hub stops here")):
            code, _ = self.report("codex", manager_bound=True, manager_handover={"claude": ids})
        self.assertNotEqual(code, 200)                                  # no answer: the helper keeps its hand-over
        self.assertTrue(hub.manager_held("manager"))                    # nothing of the end was saved
        self.assertIsNone(hub.kv_get("switched:manager"))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM events WHERE agent='manager' AND kind='say' AND read_at IS NULL")["n"],
                         1)                                             # only the switch notice; nothing marked unread
        self.report("codex", manager_bound=True, manager_handover={"claude": ids})  # the next report ends it, with it
        self.assertIn("[owner] Unfinished.", hub.t_read_messages("manager", {}))

    def test_no_false_down_warning_between_the_end_of_a_switch_and_the_next_window_list(self):
        self.request("/events/manager?delivery=1&after=0&wait=0&alive=")      # the old window had closed
        self.assertEqual(self.switch("codex")[0], 200)
        self.report("codex")                                            # the new session runs: the hold ends
        hub.tick()                                                      # before the helper's next window list
        self.assertNotEqual(hub.kv_get("mgr_flag_kind"), "down")
        self.request("/events/manager?delivery=1&after=0&wait=0&alive=")      # a newer list without it: down
        hub.tick()
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "down")

    def test_only_a_usage_limit_of_the_agent_s_runtime_holds_it(self):
        self.assertEqual(self.switch("codex")[0], 200)                  # the old helper still reads Claude's session
        for runtime, held in (("claude", False), ("codex", True)):
            with self.subTest(runtime=runtime):
                code, _ = self.request("/helper/limit/manager", {"resets_at": hub.now() + 3600, "runtime": runtime})
                self.assertEqual((code, bool(hub.active_limit("manager"))), (200, held))
        hub.q("DELETE FROM agent_limits")
        self.request("/helper/limit/manager", {"resets_at": hub.now() + 3600})     # a helper that names no runtime
        self.assertTrue(hub.active_limit("manager"))

    def test_a_failed_switch_update_closes_when_the_restarted_helper_runs_the_switch(self):
        loaded = git("rev-parse", "HEAD", cwd=self.kit)
        self.assertEqual(self.switch("codex")[0], 200)
        self.report("claude", revision=loaded, update={"state": "failed", "detail": "Updated the checkout; restart "
                                                                                    "the helper service to load it."})
        self.assertEqual(hub.q1("SELECT state FROM machine_updates WHERE agent='manager'")["state"], "failed")
        self.report("claude", revision=loaded)                          # still the old code: it stays failed
        self.assertEqual(hub.q1("SELECT state FROM machine_updates WHERE agent='manager'")["state"], "failed")
        self.report("codex")                                            # the owner restarted it: it runs the switch
        self.assertEqual(hub.q1("SELECT state FROM machine_updates WHERE agent='manager'")["state"], "current")
        health = self.request("/ui/health?db=test-generation")[1]
        self.assertNotIn("machine_failed", [w["kind"] for w in health["warnings"]])

    def test_the_status_carries_manager_bound(self):
        for value in (True, False, None):
            self.assertEqual(hub.validate_status({"manager_bound": value})["manager_bound"], value)
        with self.assertRaises(ValueError):
            hub.validate_status({"manager_bound": "yes"})
        self.report(manager_bound=False)
        rows = self.request("/ui/machines?db=test-generation")[1]["machines"]
        self.assertIs(next(r for r in rows if r["agent"] == "manager")["manager_bound"], False)


if __name__ == "__main__":
    unittest.main()
