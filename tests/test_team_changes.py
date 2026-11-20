"""The manager changes the team on the owner's press (owner API 1.214; the owner's "Yes, as written" of 17 November
2026 to the design of the manager's team changes): a plan of the manager's (change_team) becomes a card whose options
and Details are the hub's own words, and only the owner's press of a yes option, on the Mac or a PC, makes it, after a
second check. Each test names the bug that it catches. In-process hub with a local server and temporary Git
repositories; no helper, vault, fleet or AI calls."""
import json
import os
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
from unittest.mock import patch

import hub
from test_agent_remove import Remove
from test_needs_options import NoRedirect
from test_servers import NEW, OWNER, git


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(TeamChanges(name) for name in TeamChanges.__dict__ if name.startswith("test_"))


SECTIONS = [{"key": "character", "title": "Character", "text": "Calm and exact."},
            {"key": "responsible_for", "title": "Responsible for", "text": "The second half of the support queue."},
            {"key": "may_do", "title": "May do without asking", "text": "Read and answer tickets."},
            {"key": "must_ask", "title": "Must ask first", "text": "Refunds."}]
BOX2_KEY = "server-key-of-box2"


class TeamChanges(Remove):
    """scout is a Codex worker on the Linux server box (Remove's own fixture); vps, studio and lead are the other agents
    of the fleet, and the manager, on the hub's machine in a user account of its own, writes the plans."""

    def setUp(self):
        super().setUp()
        hub.q("INSERT OR REPLACE INTO machine_status(agent,data,reported) VALUES('manager',?,?)",
              (json.dumps({"access": {"uid": os.getuid() + 1}}), hub.now()))

    def plan(self, changes, title="Change the team?", why="The records show the need.", **extra):
        return hub.t_change_team("manager", dict({"request_id": str(uuid.uuid4()), "title": title, "why": why,
                                                  "changes": changes}, **extra))

    def card(self):
        return hub.q1("SELECT * FROM needs WHERE team_plan IS NOT NULL ORDER BY id DESC LIMIT 1")

    def press(self, choice=0):
        return self.owner(f"/ui/needs/{self.card()['id']}", choice=choice)

    def from_device(self, kind):
        """The owner's press from an enrolled device of this kind (iphone or windows): the hub's own mapping of the
        device's row to its class runs, and the request's own sign-in check is the Mac's."""
        hub.q("INSERT OR REPLACE INTO owner_devices(device,sha256,created,kind) VALUES('device-1','x',?,?)",
              (hub.now(), kind))
        real = hub.owner_device_class
        return patch.object(hub, "owner_device_class", lambda device: real("device-1"))

    def board(self, fields):
        """One press on the hub's own page, without following its redirect back to it."""
        req = urllib.request.Request(self.base + f"/needs/{self.card()['id']}",
                                     data=urllib.parse.urlencode(fields).encode(),
                                     headers={"Content-Type": "application/x-www-form-urlencoded",
                                              "X-Test-Source": OWNER})
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect).open(req, timeout=5) as r:
                return r.status
        except urllib.error.HTTPError as r:
            with r:
                return r.code

    def base_of(self, agent):
        return hub.profile_view(agent, hub.kit_revision(fresh=True))["sha256"]

    def commits_of(self, nid):
        return git("--git-dir", str(self.root / "origin.git"), "log", "--format=%H", "-F",
                   f"--grep=on the owner's yes to N-{nid} (", "main").split()

    def told(self, words):
        return hub.q1("SELECT text FROM events WHERE agent='manager' AND text LIKE ? ORDER BY id DESC LIMIT 1",
                      (f"%{words}%",))

    def link_person(self, agent):
        person = hub.ins("INSERT INTO people(name,role,added) VALUES('Bruno','peer',?)", (hub.now(),))
        hub.q("INSERT INTO person_agents(person,agent,added) VALUES(?,?,?)", (person, agent, hub.now()))

    def box2(self, free=7 << 30):
        """A second Linux server with no agent, whose reading shows this much memory free."""
        if "box2" not in hub.server_names():
            answer = self.code("box2", "linux")
            status, result = self.join(answer["code"], source=NEW, key=BOX2_KEY, kind="linux", user="fleet")
            self.assertEqual(status, 200, result)
        status, said = self.service("/server/box2/status", {
            "revision": hub.kit_revision(fresh=True), "os": {"name": "Ubuntu 24.04.1 LTS"},
            "runtimes": {"codex": {"version": "1.0.0", "signed_in": None}}, "access": {"user": "fleet"},
            "load": {"cpu_percent": 5.0, "memory_used": (8 << 30) - free, "memory_total": 8 << 30, "disk_used": 1,
                     "disk_total": 2}}, key=BOX2_KEY, source=NEW)
        self.assertEqual(status, 200, said)

    def add_plan(self):
        self.box2()
        self.plan([{"kind": "add", "server": "box2", "names": ["nova", "lia"], "title": "Customer Support 2",
                    "runtime": "codex", "profile": SECTIONS}], title="Add a second Support agent on box2?")

    def test_only_a_press_of_its_yes_on_the_mac_or_a_pc_makes_the_plan(self):
        """Bug: typed words, a phone, a connected app or the hub's old board, none of which shows the Details, removes
        an agent; or the phone rings for a card that it cannot press, or does not learn that it is one (owner API
        1.244: the iPhone draws a line to the Mac in place of its yes)."""
        with patch.object(hub, "ping_need") as ring:
            said = self.plan([{"kind": "remove", "agent": "scout"}], title="Remove scout?")
        ring.assert_not_called()
        card = self.card()
        options = json.loads(card["options"])
        self.assertEqual(options, ["Yes: remove scout and its service on box", "No"])
        self.assertIn(options[0], said)
        phone = [n for n in hub.mobile_state(hub.kv_get("db_id"))["needs"] if n["id"] == card["id"]]
        self.assertEqual([n["team"] for n in phone], [True])
        self.assertNotIn("team_plan", phone[0])                  # the plan itself stays the hub's
        status, answer = self.owner(f"/ui/needs/{card['id']}", answer=options[0])
        self.assertEqual((status, answer.get("error")), (409, hub.TEAM_PRESS_WORDS))
        with self.from_device("iphone"):
            status, answer = self.press(0)
        self.assertEqual((status, answer.get("error")), (409, hub.TEAM_PRESS_WHERE))
        _rid, (status, answer) = hub.capp_act({"id": 7, "name": "An app"}, "answer_need",
                                              {"need": card["id"], "choice": 0})
        self.assertEqual(status, 409, answer)
        self.assertEqual(self.board({"choice": "0"}), 303)
        self.assertIsNone(self.card()["answer"])
        self.assertIn("scout", self.origin_team()["agents"])
        before = self.head()
        with self.from_device("windows"):
            status, answer = self.press(0)
        self.assertEqual(status, 200, answer)
        self.assertNotIn("scout", self.origin_team()["agents"])
        self.assertEqual(git("--git-dir", str(self.root / "origin.git"), "rev-list", "--count", f"{before}..main"), "1")
        self.assertEqual(len(self.commits_of(card["id"])), 1)
        job = hub.q1("SELECT * FROM server_jobs WHERE agent='scout' AND kind='remove'")
        self.assertEqual((job["server"], job["state"]), ("box", "queued"))
        self.assertIsNone(hub.kv_get(hub.TEAM_PLAN_MARK + str(card["id"])))
        self.assertIn("removed scout", self.told("made your plan")["text"])

    def test_no_closes_the_card_and_changes_nothing(self):
        """Bug: an off-by-one makes No a yes."""
        self.plan([{"kind": "remove", "agent": "scout"}])
        status, answer = self.press(1)
        self.assertEqual(status, 200, answer)
        self.assertEqual(self.card()["answer"], "No")
        self.assertIn("scout", self.origin_team()["agents"])
        self.assertIsNone(hub.kv_get(hub.TEAM_PLAN_MARK + str(self.card()["id"])))

    def test_the_card_shows_the_change_and_its_press_writes_exactly_that(self):
        """Bug: the manager's words describe one change, and the press makes another."""
        self.plan([{"kind": "profile", "agent": "vps", "base_sha256": self.base_of("vps"),
                    "sections": [{"key": "responsible_for", "title": "Responsible for",
                                  "text": "Deploys, and their checks."}]}],
                  title="Make the VPS agent own the deploys?", why="It ran every deploy this month.",
                  words="It ran 12 deploys in 30 days, and nobody else ran one.")
        card = self.card()
        self.assertIn("Before:\n\n> Its work.", card["details"])
        self.assertIn("After:\n\n> Deploys, and their checks.", card["details"])
        self.assertIn("> It ran 12 deploys in 30 days", card["details"])
        self.assertEqual(json.loads(card["options"]), ["Yes: change the profile of vps", "No"])
        status, answer = self.press(0)
        self.assertEqual(status, 200, answer)
        profile = self.show("profiles/vps.md")
        self.assertIn("**Responsible for.** Deploys, and their checks.", profile)
        self.assertIn("**Must ask first.** Spending.", profile)            # the sections that the plan left stay

    def test_a_press_after_the_owner_changed_the_same_profile_writes_nothing_and_closes_the_card(self):
        """Bug: an old plan writes over the owner's own later edit, or the owner sees a yes that did nothing."""
        base = self.base_of("vps")
        self.plan([{"kind": "profile", "agent": "vps", "base_sha256": base,
                    "sections": [{"key": "responsible_for", "title": "Responsible for", "text": "Deploys."}]}])
        sections = hub.profile_view("vps", hub.kit_revision(fresh=True))["sections"]
        hub.save_profile("vps", base, [dict(s, text="The owner's own words.") if s["key"] == "responsible_for" else s
                                       for s in sections])
        status, answer = self.press(0)
        self.assertEqual((status, answer.get("error")), (409, hub.TEAM_PRESS_CHANGED.format(by=hub.shown_role("manager"))))
        self.assertIn("**Responsible for.** The owner's own words.", self.show("profiles/vps.md"))
        self.assertEqual((self.card()["answered_by"], self.card()["answer"]), (hub.NEED_CLOSED_BY, hub.TEAM_CLOSED_WORDS))
        self.assertIn("is not the version that you read", self.told("is closed")["text"])

    def test_a_press_after_a_person_was_linked_to_the_agent_removes_nothing(self):
        """Bug: the press deletes a person's conversation partner that the card did not show."""
        self.plan([{"kind": "remove", "agent": "scout"}])
        self.link_person("scout")
        status, answer = self.press(0)
        self.assertEqual((status, answer.get("error")), (409, hub.TEAM_PRESS_CHANGED.format(by=hub.shown_role("manager"))))
        self.assertIn("scout", self.origin_team()["agents"])
        self.assertEqual(self.card()["answered_by"], hub.NEED_CLOSED_BY)

    def test_a_card_waits_out_what_passes_and_closes_on_what_lasts(self):
        """Bug: a valid card leaves the owner's screen because an agent was busy for a minute, or a stale card stays
        and his press then fails."""
        self.plan([{"kind": "remove", "agent": "scout"}])
        task = hub.ins("INSERT INTO tasks(owner,requester,title,state,created,last_activity) VALUES('scout','manager',"
                       "'Fix it','working',?,?)", (hub.now(), hub.now()))
        hub.team_plan_sweep(hub.now())
        self.assertIsNone(self.card()["answer"])
        status, answer = self.press(0)
        self.assertEqual(status, 409, answer)
        self.assertIn("cannot make this change now: scout has open tasks now", answer["error"])
        self.assertIsNone(self.card()["answer"])
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (task,))
        # a profile that git does not give now passes too (removed_files' 503): the press keeps the card
        with self.not_given("profiles/scout.md"):
            status, answer = self.press(0)
        self.assertEqual(status, 409, answer)
        self.assertIn("cannot make this change now: the hub cannot read its configuration now", answer["error"])
        self.assertIsNone(self.card()["answer"])
        self.link_person("scout")
        hub.kv_set(hub.TEAM_PLAN_SWEEP, None)
        hub.team_plan_sweep(hub.now())
        self.assertEqual(self.card()["answer"], hub.TEAM_CLOSED_WORDS)
        self.assertIn("scout", self.origin_team()["agents"])

    def test_a_busy_server_keeps_an_add_card_for_a_later_press(self):
        """Bug: an add card closes for good because its server had too little memory free for a minute."""
        self.add_plan()
        self.box2(free=1 << 29)
        hub.kv_set(hub.TEAM_PLAN_SWEEP, None)
        hub.team_plan_sweep(hub.now())
        self.assertIsNone(self.card()["answer"])
        status, answer = self.press(0)
        self.assertEqual(status, 409, answer)
        self.assertIn("box2 has too little free memory now", answer["error"])
        self.assertIsNone(self.card()["answer"])

    def test_a_fold_names_its_removal_and_lands_in_one_commit(self):
        """Bug: the yes of a fold reads as a line change while it removes an agent, or the removal comes before the
        move of the agents that report to it, or the two parts land apart."""
        team, sha, lines = hub.team_view(hub.kit_revision(fresh=True))
        hub.save_lines(sha, [dict(line, reports_to="lead") if line["agent"] == "scout" else line for line in lines])
        with self.assertRaises(hub.ToolError) as refused:
            self.plan([{"kind": "remove", "agent": "lead"}])
        self.assertIn("Change the reporting lines first", str(refused.exception))
        self.plan([{"kind": "lines", "lines": [{"agent": "scout", "role": "worker"}]},
                   {"kind": "remove", "agent": "lead"}], title="Fold the lead?")
        self.assertEqual(json.loads(self.card()["options"]), ["Yes: remove lead, and 1 more change", "No"])
        self.assertIn("nothing on vps, which has no server service, so its files there stay", self.card()["details"])
        before = self.head()
        status, answer = self.press(0)
        self.assertEqual(status, 200, answer)
        after = self.origin_team()["agents"]
        self.assertNotIn("lead", after)
        self.assertNotIn("reports_to", after["scout"])           # the manager's line
        self.assertEqual(git("--git-dir", str(self.root / "origin.git"), "rev-list", "--count", f"{before}..main"), "1")

    def test_stops_at_any_step_end_the_plan_once(self):
        """Bug: an agent in team.json with no install, a second commit or a second install, or a stop that nobody
        hears of."""
        self.add_plan()
        nid = self.card()["id"]
        self.assertEqual(json.loads(self.card()["options"]),
                         ["Yes: add nova, Customer Support 2, on box2", "Yes: add lia, Customer Support 2, on box2", "No"])
        real = hub.commit_kit_file

        def commit_then_stop(*args, **kwargs):
            real(*args, **kwargs)
            raise RuntimeError("the hub stopped here")
        with patch.object(hub, "commit_kit_file", side_effect=commit_then_stop):
            status, answer = self.press(1)
        self.assertEqual(status, 200, answer)
        self.assertIn("lia", self.origin_team()["agents"])
        self.assertIsNone(hub.q1("SELECT 1 FROM server_jobs WHERE agent='lia'"))
        self.assertIn("the hub stopped here", self.told("waits")["text"])
        real_kv_set = hub.kv_set

        def stop_after_the_job(key, value):
            if key.startswith(hub.TEAM_PLAN_JOB):       # the write right after the install job's row
                raise RuntimeError("the hub stopped after the job")
            return real_kv_set(key, value)
        with patch.object(hub, "kv_set", side_effect=stop_after_the_job):
            hub.team_plans_pressed()        # the next start, which stops after the install job
        hub.team_plans_pressed()            # and the pass after it
        self.assertEqual([r["kind"] for r in hub.q("SELECT kind FROM server_jobs WHERE agent='lia'")], ["install"])
        self.assertEqual(len(self.commits_of(nid)), 1)
        self.assertIsNone(hub.kv_get(hub.TEAM_PLAN_MARK + str(nid)))
        self.assertNotIn("nova", self.origin_team()["agents"])
        self.assertEqual(self.origin_team()["agents"]["lia"]["title"], "Customer Support 2")

    def test_a_failed_job_of_a_plan_reaches_the_manager(self):
        """Bug: the manager reads that an install runs and never hears that it failed."""
        self.add_plan()
        status, answer = self.press(0)
        self.assertEqual(status, 200, answer)
        job = hub.q1("SELECT id FROM server_jobs WHERE agent='nova'")["id"]
        status, said = self.service(f"/server/box2/jobs/{job}", {"state": "failed", "step": "runtime",
                                                                  "detail": "The disk is full."},
                                    key=BOX2_KEY, source=NEW)
        self.assertEqual(status, 200, said)
        self.assertIn("failed: The disk is full.", self.told("from the plan that the owner pressed")["text"])

    def test_a_cut_plan_meets_its_card_again_before_its_commit(self):
        """Bug: a plan that a stop cut before its commit is made later, after the fleet changed in a way that its card
        did not show."""
        self.plan([{"kind": "remove", "agent": "scout"}])
        nid = self.card()["id"]
        with patch.object(hub, "commit_kit_file", side_effect=RuntimeError("the push failed")):
            status, answer = self.press(0)
        self.assertEqual(status, 200, answer)
        self.link_person("scout")
        hub.team_plans_pressed()
        self.assertIn("scout", self.origin_team()["agents"])
        self.assertEqual(self.commits_of(nid), [])
        self.assertIsNone(hub.kv_get(hub.TEAM_PLAN_MARK + str(nid)))
        self.assertIn("did not make the plan", self.told("pressed yes on")["text"])

    def test_the_steps_after_a_commit_apply_the_team_as_it_stands(self):
        """Bug: a later pass applies the plan's own, older team.json, and the hub forgets what changed since; or the
        timer never tries a waiting plan again."""
        self.add_plan()
        real = hub.commit_kit_file

        def commit_then_stop(*args, **kwargs):
            real(*args, **kwargs)
            raise RuntimeError("the hub stopped here")
        with patch.object(hub, "commit_kit_file", side_effect=commit_then_stop):
            status, answer = self.press(0)
        self.assertEqual(status, 200, answer)
        sha = hub.team_view(hub.kit_revision(fresh=True))[1]
        hub.save_agent_settings("vps", {"title": "Deploys", "base_sha256": sha})
        hub.kv_set(hub.TEAM_PLAN_RETRY, None)
        hub.tick()
        self.assertEqual(hub.agents()["vps"].get("title"), "Deploys")
        self.assertIn("nova", hub.agents())
        self.assertEqual([r["kind"] for r in hub.q("SELECT kind FROM server_jobs WHERE agent='nova'")], ["install"])
        self.assertIsNone(hub.kv_get(hub.TEAM_PLAN_MARK + str(self.card()["id"])))

    def test_the_hubs_own_undo_of_a_plan_is_not_its_commit(self):
        """Bug: the revert that the hub makes of a push that it could not take in is taken for the plan's commit, and
        the steps after it run on a team where the plan never happened."""
        self.plan([{"kind": "remove", "agent": "scout"}])
        nid = self.card()["id"]
        status, answer = self.press(0)
        self.assertEqual(status, 200, answer)
        made = self.commits_of(nid)[0]
        self.assertEqual(hub.team_plan_commit_of(nid), made)
        for made_now in (False, True, False):       # the hub's undo, a person's undo of it, the hub's undo again
            git("revert", "--no-edit", "HEAD", cwd=self.kit)
            hub._revision_cache.update(at=0.0, value=None)
            self.assertEqual(hub.team_plan_commit_of(nid), made if made_now else None)
            self.assertEqual(hub.team_plan_commit_of(nid, made), made if made_now else None)
        self.assertIsNone(hub.team_plan_commit_of(nid, "0" * 40))      # a commit that the ref does not have

    def test_a_committed_plan_is_never_dropped(self):
        """Bug: a plan whose commit is in team.json is dropped after its last try, and its new agent never gets its
        install."""
        self.add_plan()
        nid = self.card()["id"]
        with patch.object(hub, "team_plan_after", side_effect=RuntimeError("the job table is locked")):
            status, answer = self.press(0)
            key = hub.TEAM_PLAN_MARK + str(nid)
            mark = json.loads(hub.kv_get(key))
            self.assertEqual(mark["step"], "committed")
            hub.kv_set(key, json.dumps(dict(mark, tries=hub.TEAM_PLAN_TRIES - 1)))
            hub.team_plans_pressed()
        self.assertEqual(status, 200, answer)
        self.assertEqual(json.loads(hub.kv_get(key))["tries"], hub.TEAM_PLAN_TRIES)
        self.assertIn("its commit is made", self.told("waits")["text"])
        hub.team_plans_pressed()
        self.assertIsNone(hub.kv_get(key))
        self.assertEqual([r["kind"] for r in hub.q("SELECT kind FROM server_jobs WHERE agent='nova'")], ["install"])

    def test_a_plan_whose_commit_can_be_on_the_ref_outlasts_a_git_fault(self):
        """Bug: while git cannot answer, a plan whose commit is on the ref is dropped, at its last try or as undone,
        and its steps never run."""
        self.plan([{"kind": "remove", "agent": "scout"}])
        key = hub.TEAM_PLAN_MARK + str(self.card()["id"])
        real = hub.commit_kit_file

        def commit_then_stop(*args, **kwargs):
            real(*args, **kwargs)
            raise RuntimeError("the hub stopped here")
        with patch.object(hub, "commit_kit_file", side_effect=commit_then_stop):
            self.press(0)
        hub.kv_set(key, json.dumps(dict(json.loads(hub.kv_get(key)), tries=hub.TEAM_PLAN_TRIES - 1)))
        real_git = hub.git_kit
        with patch.object(hub, "git_kit", lambda *args, **kwargs: (1, "", "git timed out") if args[:1] == ("log",)
                          else real_git(*args, **kwargs)):
            hub.team_plans_pressed()        # its last try, while git log cannot answer
        mark = json.loads(hub.kv_get(key))
        self.assertEqual((mark["step"], mark["tries"]), ("committing", hub.TEAM_PLAN_TRIES))
        with patch.object(hub, "team_plan_after", side_effect=RuntimeError("the job table is locked")):
            hub.team_plans_pressed()        # its commit is found: committed, and its steps stop
        self.assertEqual(json.loads(hub.kv_get(key))["step"], "committed")
        with patch.object(hub, "git_kit", lambda *args, **kwargs: (1, "", "git timed out") if "merge-base" in args
                          else real_git(*args, **kwargs)):
            hub.team_plans_pressed()
        self.assertEqual(json.loads(hub.kv_get(key))["step"], "committed")
        hub.team_plans_pressed()
        self.assertIsNone(hub.kv_get(key))
        self.assertEqual(hub.q1("SELECT kind FROM server_jobs WHERE agent='scout' AND kind='remove'")["kind"], "remove")

    def test_a_plan_whose_commit_fails_before_its_push_stops_at_its_last_try(self):
        """Bug: a commit that the hub refuses each time leaves each pass at committing, so the plan tries once a minute
        for ever and every new plan of the manager's is refused."""
        self.plan([{"kind": "remove", "agent": "scout"}])
        key = hub.TEAM_PLAN_MARK + str(self.card()["id"])
        refused = hub.Refusal(409, "the hub checkout has local changes")
        with patch.object(hub, "commit_kit_file", side_effect=refused):
            self.press(0)
            hub.kv_set(key, json.dumps(dict(json.loads(hub.kv_get(key)), tries=hub.TEAM_PLAN_TRIES - 1)))
            hub.team_plans_pressed()
        self.assertIsNone(hub.kv_get(key))
        self.assertIn("could not be made", self.told("pressed on")["text"])
        self.assertIn("scout", self.origin_team()["agents"])

    def test_an_old_plan_of_a_card_number_that_comes_back_is_not_this_plans_commit(self):
        """Bug: after the hub's database comes back from an older backup, a new card gets an old card's number, and
        the commit of the old plan passes for the new one: its steps run, a removal job included, while team.json
        still holds the agent."""
        self.plan([{"kind": "settings", "agent": "vps", "title": "Deploys"}], title="Name the VPS agent Deploys?")
        old = self.card()["id"]
        self.assertEqual(self.press(0)[0], 200)
        hub.q("DELETE FROM needs WHERE id=?", (old,))               # the database of an older backup
        hub.kv_set("row_floor:needs", None)
        self.plan([{"kind": "remove", "agent": "scout"}], title="Remove scout?")
        self.assertEqual(self.card()["id"], old)
        with patch.object(hub, "commit_kit_file", side_effect=RuntimeError("the push failed")):
            self.assertEqual(self.press(0)[0], 200)
        hub.team_plans_pressed()
        self.assertNotIn("scout", self.origin_team()["agents"])
        self.assertEqual(len(self.commits_of(old)), 2)

    def test_no_plan_removes_the_manager_or_changes_its_line(self):
        """Bug: the fleet loses its manager, which every question and result of the fleet waits for."""
        for changes in ([{"kind": "remove", "agent": "manager"}],
                        [{"kind": "lines", "lines": [{"agent": "manager", "role": "worker"}]}]):
            with self.assertRaises(hub.ToolError):
                self.plan(changes)
        self.assertIsNone(self.card())

    def test_no_plan_gives_access_around_the_owner(self):
        """Bug: access that goes around the owner: a login in a changed profile or in a new agent's, which skips
        the owner's pool, or a new agent on a key account, whose key's grant only the owner's Mac signs."""
        login = {"key": "logins", "title": "Logins it may use", "text": "`bws://11111111-2222-4333-8444-55555555555b`"}
        with self.assertRaises(hub.ToolError) as refused:
            self.plan([{"kind": "profile", "agent": "vps", "base_sha256": self.base_of("vps"), "sections": [login]}])
        self.assertIn("Logins it may use", str(refused.exception))
        self.box2()
        with self.assertRaises(hub.ToolError) as refused:
            self.plan([{"kind": "add", "server": "box2", "names": ["nova"], "title": "Customer Support 2",
                        "runtime": "codex", "profile": SECTIONS + [login]}])
        self.assertIn("Logins it may use", str(refused.exception))
        keyed = next(name for name in hub.lifecycle.RUNTIMES if hub.runtime_fact(name, "key_env"))
        with self.assertRaises(hub.ToolError) as refused:
            self.plan([{"kind": "add", "server": "box2", "names": ["nova"], "title": "Customer Support 2",
                        "runtime": keyed, "profile": SECTIONS}])
        self.assertIn("the owner adds in Founderizer", str(refused.exception))
        self.assertIsNone(self.card())

    def test_a_plan_meets_the_owner_profile_saves_own_checks(self):
        """Bug: a plan commits a profile that the owner's own save then refuses, or that lists a file nobody has."""
        files = {"key": "knowledge_files", "title": "Knowledge files", "text": "- knowledge/owner/missing.md"}
        with self.assertRaises(hub.ToolError) as refused:
            self.plan([{"kind": "profile", "agent": "vps", "base_sha256": self.base_of("vps"), "sections": [files]}])
        self.assertIn("knowledge/owner/missing.md is not in the knowledge catalog", str(refused.exception))
        # a catalog that cannot be read now names no file as missing, and the refusal passes by itself, so that a
        # card stays and a pressed plan tries again (lanes/a-knowledge-read-that-fails.md)
        with patch.dict(hub.CFG, {"artifact_repo": str(self.root / "gone")}), \
                self.assertRaises(hub.TeamPassing) as refused:
            self.plan([{"kind": "profile", "agent": "vps", "base_sha256": self.base_of("vps"), "sections": [files]}])
        self.assertEqual((str(refused.exception), refused.exception.owner),
                         ("The hub cannot read its knowledge files now. Try again in a minute.",
                          "the hub cannot read its knowledge files now"))
        self.assertIsNone(self.card())
        # the owner-file step: a catalog that cannot be read, or a file that it lists and git does not give now,
        # passes by itself; only a file that the catalog does not list is not there
        step = {"path": "knowledge/owner/brand.md", "base_sha256": "0" * 64, "text": "# Brand\n\nGreen.\n"}
        listed = [{"path": "knowledge/owner/brand.md", "scope": "owner"}]
        for catalog, blob, passing in ((hub.UnreadCatalog(), b"# Brand\n\nBlue.\n", True), (listed, None, True),
                                       ([], None, False)):
            with self.subTest(catalog=type(catalog).__name__, blob=blob), \
                    patch.object(hub, "knowledge_entries", lambda: catalog), \
                    patch.object(hub, "git_blob", lambda rev, path: blob), \
                    self.assertRaises(hub.ToolError) as refused:
                hub.team_owner_file({"rev": "r" * 40, "team": hub.TEAM}, step)
            self.assertEqual(isinstance(refused.exception, hub.TeamPassing), passing, refused.exception)
            if not passing:
                self.assertEqual(str(refused.exception), "There is no owner file knowledge/owner/brand.md.")
        # the catalog stops being readable after the plan's own read: the 503 of the room check in knowledge_replaced
        # passes by itself too, and closes no card (lanes/knowledge-list-on-a-failed-read.md)
        before = "# Brand\n\nSource: brand.pdf · added 2026-10-01\n\nBlue.\n".encode()
        reads = iter([listed, hub.UnreadCatalog()])
        with patch.object(hub, "knowledge_entries", lambda: next(reads)), \
                patch.object(hub, "git_blob", lambda rev, path: before), self.assertRaises(hub.TeamPassing):
            hub.team_owner_file({"rev": "r" * 40, "team": hub.TEAM},
                                dict(step, base_sha256=hub.hashlib.sha256(before).hexdigest()))
        # every other refusal of knowledge_replaced still ends the plan: here the file has this text already (409)
        same = "# Brand\n\nSource: brand.pdf · added 2026-10-01\n\n# Brand\n\nGreen.\n".encode()
        with patch.object(hub, "knowledge_entries", lambda: listed), \
                patch.object(hub, "git_blob", lambda rev, path: same), self.assertRaises(hub.ToolError) as refused:
            hub.team_owner_file({"rev": "r" * 40, "team": hub.TEAM},
                                dict(step, base_sha256=hub.hashlib.sha256(same).hexdigest()))
        self.assertNotIsInstance(refused.exception, hub.TeamPassing)
        self.assertEqual(str(refused.exception), "knowledge/owner/brand.md has this text already.")

    def test_a_plan_changes_each_thing_once(self):
        """Bug: the card shows two changes of one profile, and the press makes only the last."""
        base = self.base_of("vps")
        with self.assertRaises(hub.ToolError) as refused:
            self.plan([{"kind": "profile", "agent": "vps", "base_sha256": base,
                        "sections": [{"key": "responsible_for", "title": "Responsible for", "text": "Deploys."}]},
                       {"kind": "profile", "agent": "vps", "base_sha256": base,
                        "sections": [{"key": "must_ask", "title": "Must ask first", "text": "Nothing."}]}])
        self.assertIn("twice", str(refused.exception))
        self.assertIsNone(self.card())

    def test_a_plan_that_the_card_cannot_show_whole_is_refused(self):
        """Bug: the owner says yes to a change that the card cut."""
        long = "Every sentence of this text is a rule that the agent follows when it answers. " * 90
        with self.assertRaises(hub.ToolError) as refused:
            self.plan([{"kind": "profile", "agent": "vps", "base_sha256": self.base_of("vps"),
                        "sections": [{"key": "responsible_for", "title": "Responsible for", "text": long},
                                     {"key": "character", "title": "Character", "text": long}]}])
        self.assertIn("cannot show this plan whole", str(refused.exception))
        self.assertIsNone(self.card())

    def test_a_manager_that_could_forge_the_press_writes_no_plan(self):
        """Bug: a manager that can write the hub's records itself, or whose user the hub does not know yet, makes a
        card whose press it could forge."""
        with patch.object(hub, "manager_hub_user", lambda team=None: True):
            with self.assertRaises(hub.ToolError) as refused:
                self.plan([{"kind": "remove", "agent": "scout"}])
        self.assertIn("hub's own user account", str(refused.exception))
        hub.q("DELETE FROM machine_status WHERE agent='manager'")
        with self.assertRaises(hub.ToolError) as refused:
            self.plan([{"kind": "remove", "agent": "scout"}])
        self.assertIn("does not know yet which user account", str(refused.exception))
        self.assertIsNone(self.card())

    def test_one_card_for_one_request_and_a_new_plan_replaces_the_open_one(self):
        """Bug: a repeat of the manager's call, after its answer was lost, makes a second card, or two plans wait side
        by side."""
        args = {"request_id": str(uuid.uuid4()), "title": "Remove scout?", "why": "Its work moved.",
                "changes": [{"kind": "remove", "agent": "scout"}]}
        first = hub.t_change_team("manager", dict(args))
        self.assertEqual(hub.t_change_team("manager", dict(args)), first)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM needs WHERE team_plan IS NOT NULL")["n"], 1)
        old = self.card()["id"]
        self.plan([{"kind": "settings", "agent": "vps", "title": "Deploys"}], title="Name the VPS agent Deploys?")
        self.assertIn("Replaced by manager", hub.q1("SELECT answer FROM needs WHERE id=?", (old,))["answer"])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM needs WHERE team_plan IS NOT NULL AND answer IS NULL")["n"], 1)


if __name__ == "__main__":
    unittest.main()
