"""The manager changes the team on the owner's press (owner API 1.214; the owner's "Yes, as written" of 17 November
2026 to the design of the manager's team changes): a plan of the manager's (change_team) becomes a card whose options
and Details are the hub's own words, and only the owner's press of a yes option, on the Mac or a PC, makes it, after a
second check. Each test names the bug that it catches. In-process hub with a local server and temporary Git
repositories; no helper, vault, fleet or AI calls."""
import contextlib
import json
import os
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
from unittest.mock import patch

import door_targets
import hub
from test_agent_remove import Remove
from test_needs_options import NoRedirect
from test_servers import NEW, OTHER, OWNER, git


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

    def stands(self):
        """Where the newest team card's plan stands (owner API 1.280): the values of the card's own row, which the
        owner's apps read as they are (need_view). They are on the row, and not in kv alone, because a write of an
        answered item's row is what moves the mark of its block, so that an app which kept the item reads it again
        (test_older_rows)."""
        card = self.card()
        view = hub.need_view(card)
        self.assertEqual((view["team_state"], view["team_reason"]), (card["team_state"], card["team_reason"]))
        return card["team_state"], card["team_reason"]

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

    def box2(self, free=7 << 30, total=8 << 30):
        """A second Linux server with no agent, whose reading shows this much memory free, of this much in all."""
        if "box2" not in hub.server_names():
            answer = self.code("box2", "linux")
            status, result = self.join(answer["code"], source=NEW, key=BOX2_KEY, kind="linux", user="fleet")
            self.assertEqual(status, 200, result)
        status, said = self.service("/server/box2/status", {
            "revision": hub.kit_revision(fresh=True), "os": {"name": "Ubuntu 24.04.1 LTS"},
            "runtimes": {"codex": {"version": "1.0.0", "signed_in": None}}, "access": {"user": "fleet"},
            "load": {"cpu_percent": 5.0, "memory_used": total - free, "memory_total": total, "disk_used": 1,
                     "disk_total": 2}}, key=BOX2_KEY, source=NEW)
        self.assertEqual(status, 200, said)

    def add_plan(self):
        self.box2()
        self.plan([{"kind": "add", "server": "box2", "names": ["nova", "lia"], "title": "Customer Support 2",
                    "runtime": "codex", "profile": SECTIONS}], title="Add a second Support agent on box2?")

    def test_only_a_press_of_its_yes_on_the_mac_or_a_pc_makes_the_plan(self):
        """Bug: typed words, a phone, a connected app or the hub's old board, none of which shows the Details, removes
        an agent; or the phone rings for a card that it cannot press, or does not learn that it is one (owner API
        1.244: the iPhone draws a line to the Mac in place of its yes). Owner API 1.280: or the card of a pressed
        plan shows the check until the plan's first pass, which can wait for the turn of the hub's files; or a card
        whose plan the hub made says making for ever, because the plan's end clears its mark and writes nothing on
        the card."""
        with patch.object(hub, "ping_need") as ring:
            said = self.plan([{"kind": "remove", "agent": "scout"}], title="Remove scout?")
        ring.assert_not_called()
        card = self.card()
        self.assertIn("**Remove Scout**\n\n", card["details"])    # F16: its name once, and it has no role to show
        options = json.loads(card["options"])
        self.assertEqual(options, ["Yes: remove Scout and its service on box", "No"])
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
        # the press race (25 November 2026): a PC's or a phone's press that the route checked, whose device the
        # owner removed while it waited for the answer's turn, makes no plan, and never counts as the owner's computer
        with patch.object(hub, "owner_device_at", lambda address: None), \
                patch.object(hub, "owner_device_class", lambda device: {"pc": "Windows", "phone": "iPhone"}.get(device)):
            for device in ("pc", "phone"):
                said = hub.phone_submit({"request_id": str(uuid.uuid4()), "db": hub.kv_get("db_id"), "choice": 0},
                                        "founderizer-swift/1/test", card["id"], address="100.64.0.9", device=device)
                self.assertEqual(said[0], 403, said)
        self.assertIsNone(self.card()["answer"])
        self.assertIn("scout", self.origin_team()["agents"])
        before = self.head()
        first_pass, at_the_answer = hub.team_plans_pressed, []

        def pass_after_the_answer():        # what the answer's own write left on the card, before the plan's first pass
            at_the_answer.append(self.card()["team_state"])
            return first_pass()
        with self.from_device("windows"), patch.object(hub, "team_plans_pressed", pass_after_the_answer):
            status, answer = self.press(0)
        self.assertEqual(status, 200, answer)
        self.assertEqual(at_the_answer, [hub.TEAM_MAKING])
        self.assertNotIn("scout", self.origin_team()["agents"])
        self.assertEqual(git("--git-dir", str(self.root / "origin.git"), "rev-list", "--count", f"{before}..main"), "1")
        self.assertEqual(len(self.commits_of(card["id"])), 1)
        job = hub.q1("SELECT * FROM server_jobs WHERE agent='scout' AND kind='remove'")
        self.assertEqual((job["server"], job["state"]), ("box", "queued"))
        self.assertIsNone(hub.kv_get(hub.TEAM_PLAN_MARK + str(card["id"])))
        self.assertIn("removed scout", self.told("made your plan")["text"])
        self.assertEqual(self.stands(), (hub.TEAM_MADE, None))
        self.assertIn("need_marks", hub.ui_features())

    def test_the_card_marks_the_managers_own_plan_as_the_answer_that_it_recommends(self):
        """Bug: a team card marks no answer, No, or another name than the manager's first as the answer that the
        manager recommends, so the owner's badge stands on a choice that the manager did not make (owner API 1.269)."""
        said = self.plan([{"kind": "remove", "agent": "scout"}], title="Remove scout?")
        self.assertEqual(self.card()["recommended"], "Yes: remove Scout and its service on box")
        self.assertIn("the first marked as the answer that you recommend", said)
        self.add_plan()
        self.assertEqual(self.card()["recommended"], "Yes: add Nova, Customer Support 2, on box2")

    def test_a_yes_names_each_change_in_words_and_never_a_count(self):
        """The owner's card of 26 November 2026 ("Yes: add nico, ..., and 1 more change": "what do you mean by "1 more
        change"??? very confusing!"). Bugs: an add's yes leaves out the plan's other change, or says it as a count; a
        line change that only makes an agent a lead reads as a move that does not happen; a plan whose long words do
        not fit drops the first change's detail before the others', drops the other changes with no word, or says
        one short phrase twice."""
        self.box2()
        self.plan([{"kind": "add", "server": "box2", "names": ["nova", "lia"], "title": "Customer Support 2",
                    "runtime": "codex", "profile": SECTIONS},
                   {"kind": "lines", "lines": [{"agent": "scout", "role": "worker", "reports_to": "lead"}]}],
                  title="Add a second Support agent on box2?")
        self.assertEqual(json.loads(self.card()["options"]),
                         ["Yes: add Nova, Customer Support 2, on box2; also make Scout report to Lead",
                          "Yes: add Lia, Customer Support 2, on box2; also make Scout report to Lead", "No"])
        hub.q("DELETE FROM needs WHERE team_plan IS NOT NULL")
        self.plan([{"kind": "lines", "lines": [{"agent": "scout", "role": "lead"}]}], title="Let Scout lead?")
        self.assertEqual(json.loads(self.card()["options"]), ["Yes: make Scout a lead", "No"])
        # the ladder itself, on a plan that the fixture cannot make: long words, then short words, then the pointer
        long_head = (0, "remove Support and its service on " + "b" * 40, "remove Support")
        files = [(1, f"change the knowledge file {c * 30}.md", "change a knowledge file") for c in "xy"]
        said = hub.team_plan_options({"phrases": [long_head] + files, "names": []})[0]
        self.assertEqual(said, f"Yes: remove Support and its service on {'b' * 40}; also change 2 knowledge files")
        many = [(1, f"change the profile of Agent{i}", f"change the profile of Agent{i}") for i in range(9)]
        said = hub.team_plan_options({"phrases": [long_head] + many, "names": []})[0]
        self.assertEqual(said, f"Yes: remove Support and its service on {'b' * 40}; also more under Details")
        self.assertLessEqual(len(said), hub.NEED_OPTION_CHARS)

    def test_no_closes_the_card_and_changes_nothing(self):
        """Bug: an off-by-one makes No a yes."""
        self.plan([{"kind": "remove", "agent": "scout"}])
        status, answer = self.press(1)
        self.assertEqual(status, 200, answer)
        self.assertEqual(self.card()["answer"], "No")
        self.assertIn("scout", self.origin_team()["agents"])
        self.assertIsNone(hub.kv_get(hub.TEAM_PLAN_MARK + str(self.card()["id"])))

    def test_the_card_shows_the_change_and_its_press_writes_exactly_that(self):
        """Bug: the manager's words describe one change, and the press makes another. And for a long section, the card
        showed it whole twice, past the card's limit, so the hub refused exactly the plan that makes a long profile
        shorter (the design "An agent keeps its own rules", slice 1): the card shows the lines that change. And a plan
        "Shorten ..." that moved words to a file and removed no section made the profile longer, and nobody told the
        manager (the Founderizer team, 21 November 2026): its answer gives each profile's size before and after."""
        def size():
            return len(hub.profile_view("vps", hub.kit_revision(fresh=True))["text"])
        was = size()
        said = self.plan([{"kind": "profile", "agent": "vps", "base_sha256": self.base_of("vps"),
                           "sections": [{"key": "responsible_for", "title": "Responsible for",
                                         "text": "Deploys, and their checks."}]}],
                         title="Make the VPS agent own the deploys?", why="It ran every deploy this month.",
                         words="It ran 12 deploys in 30 days, and nobody else ran one.")
        with hub.LOCK, hub.transaction():           # notes from before the plan: the press marks the profile newer
            hub.notes_save("vps", "Deploy on Fridays.", "what the work taught me", "vps", hub.now() - 3600)
        self.assertFalse(hub.notes_profile_newer("vps"))
        card = self.card()
        self.assertIn("Before:\n\n> Its work.", card["details"])
        self.assertIn("After:\n\n> Deploys, and their checks.", card["details"])
        self.assertIn("> It ran 12 deploys in 30 days", card["details"])
        self.assertEqual(json.loads(card["options"]), ["Yes: change the profile of Vps", "No"])
        status, answer = self.press(0)
        self.assertEqual(status, 200, answer)
        profile = self.show("profiles/vps.md")
        self.assertIn(f"The profile of Vps goes from {was:,} to {size():,} characters. It grows", said)
        self.assertIn("**Responsible for.** Deploys, and their checks.", profile)
        self.assertIn("**Must ask first.** Spending.", profile)            # the sections that the plan left stay
        self.assertTrue(hub.notes_profile_newer("vps"))     # the head of its notes says so (the design's 5.2)
        # a section of about 7,900 characters, which the owner's save made long, and a plan that removes half of it
        lines = [(f"Rule {n:02d}: answer the tickets of kind {n} in full, in the customer's own language, and log "
                  f"each answer in the CRM at once.")[:99].rstrip() for n in range(1, 80)]
        sections = hub.profile_view("vps", hub.kit_revision(fresh=True))["sections"]
        for s in sections:
            if s["key"] == "responsible_for":
                s["text"] = "\n".join(lines)
        hub.save_profile("vps", self.base_of("vps"), sections)
        self.assertGreater(int(hub.kv_get(hub.PROFILE_LONG + "vps")), 7800)
        leave, stay = lines[::2], lines[1::2]
        self.duty("vps", "\n".join(leave))      # F15: a section that the owner decides is never an order (claim C3)
        was = size()
        said = self.plan([{"kind": "profile", "agent": "vps", "base_sha256": self.base_of("vps"),
                           "sections": [{"key": "responsible_for", "title": "Responsible for",
                                         "text": "\n".join(stay)}]}],
                         title="Make the profile of vps shorter?", why="Half of its lines are in its duty's words.")
        self.assertTrue(said.startswith("Raised N-"), said)
        details = self.card()["details"]
        for line in leave:
            self.assertIn(line, details)
        for line in stay:
            self.assertNotIn(line, details)
        self.assertIn("39 lines of this section stay as they are.", details)
        status, answer = self.press(0)
        self.assertEqual(status, 200, answer)
        profile = self.show("profiles/vps.md")
        self.assertIn(f"The profile of Vps goes from {was:,} to {size():,} characters.", said)
        self.assertNotIn("It grows", said)
        self.assertIn(stay[-1], profile)
        self.assertNotIn(leave[0], profile)
        self.assertIsNone(hub.kv_get(hub.PROFILE_LONG + "vps"))        # the count starts from the plan's number

    def duty(self, agent, text, state="active", watch="clock", running="active", reads=0):
        """A duty of `agent` with a watch of this kind in this state, or with none (watch=None), whose words a save of
        this release wrote after `reads` reads of outside text (None: a duty of before, with no count): a duty is a
        place of an order only while a managed watch that runs brings its words to the agent's sessions, and only with
        a count of 0 (F15)."""
        t0 = hub.now()
        duty = hub.ins("INSERT INTO responsibilities(agent,text,state,revision,created,updated,created_by,request_id,"
                       "outside_reads) VALUES(?,?,?,1,?,?,'manager',?,?)",
                       (agent, text, state, t0, t0, str(uuid.uuid4()), reads))
        if watch:
            hub.ins("INSERT INTO triggers(agent,state,revision,schedule,task,late_minutes,max_tasks_per_day,anchor,"
                    "created,updated,request_id,responsibility,watch) VALUES(?,?,1,'{}','Look.',30,4,?,?,?,?,?,?)",
                    (agent, running, t0, t0, t0, str(uuid.uuid4()), duty, watch))
        return duty

    def long_vps(self):
        """F15: vps's profile as the owner's save left it, with a free section "How you work" of 8 lines and one
        "Style" of 3,000 characters (9,700 of free text), and an owner file in its Knowledge files that holds line 4.
        The places of its own work, each under a heading with that section's title: an active duty that holds lines 1
        and 2 as a list (with another mark, in other spaces and quotes), its own skill desk with line 3 and a second
        active duty with line 4, each as a paragraph of its own. Lines 5 to 8 stand in no such place. (duty of lines 1
        and 2, duty of line 4)."""
        lines = [f"- Rule {n} of the desk: " + (f"answer each ticket of kind {n} in the customer's own words, "
                                                f"and log it at once. ") * 10 for n in range(1, 9)]
        lines = [line.rstrip() for line in lines]
        catalog = patch.dict(hub.CFG, {"artifact_repo": hub.kit_dir()})      # the knowledge catalog of this fleet
        catalog.start()
        self.addCleanup(catalog.stop)
        self.write({"skills/vps/desk/SKILL.md": f"---\nname: desk\ndescription: \"The desk.\"\n---\n\n# Desk\n\n"
                                                f"## How you work\n\n{lines[2][2:]}\n",
                    "knowledge/owner/desk-policy.md": f"# Desk policy\n\nSource: the owner\n\n{lines[3]}\n"})
        duty = self.duty("vps", "Answer the support queue.\n\n## How you work\n\n" + "\n".join(
            "* " + line[2:].replace("customer's", "customer’s").replace(" of ", "  of ") for line in lines[:2]))
        closing = self.duty("vps", f"Close the day.\n\n## How you work\n\n{lines[3][2:]}\n\nThen log off.")
        sections = [s for s in hub.profile_view("vps", hub.kit_revision(fresh=True))["sections"]] + [
            {"key": "other", "title": "How you work", "text": "\n".join(lines)},
            {"key": "other", "title": "Style", "text": ("Short and plain. " * 176).strip()},
            {"key": "knowledge_files", "title": "Knowledge files", "text": "- knowledge/owner/desk-policy.md"}]
        hub.save_profile("vps", self.base_of("vps"), sections)
        return lines, (duty, closing)

    def skill_unread(self):
        """git gives no answer for a skill's SKILL.md, and answers every other read."""
        real = hub.kit_file

        def read(rev, path):
            if path.endswith("/SKILL.md"):
                raise hub.KitUnread(path)
            return real(rev, path)
        return patch.object(hub, "kit_file", read)

    def free(self, title, lines):
        return {"kind": "profile", "agent": "vps", "base_sha256": self.base_of("vps"),
                "sections": [{"key": "other", "title": title, "text": "\n".join(lines)}]}

    def test_a_plan_that_only_takes_out_lines_that_stand_in_the_agents_places_is_made_with_no_card(self):
        """F15 pieces 1 and 2 (the owner, 22 November 2026: "This should happen autoamtically under the hood with no
        impact at all for the user"). Bug: the card comes back for a profile that only gets shorter, which is the state
        of before; or the order rings the owner, writes a line in his chat or leaves the other sections and the number
        of its free text behind; or a refusal of its commit (a busy turn) reaches the manager as an error of the
        hub's own; or the owner cannot find where a line of his went, or the way back is a way to add words with no
        press or to change what a line means by its place: a line that no order took out, one that came back already,
        one at another place than just after the line before it, or one that an order took out before the owner's own
        save of the profile, makes a card."""
        lines, (duty, closing) = self.long_vps()

        def profile():
            return hub.profile_view("vps", hub.kit_revision(fresh=True))["text"]

        def asks():
            return hub.q1("SELECT COUNT(*) n FROM events WHERE agent='manager' AND text LIKE '%is long: its free "
                          "text%'")["n"]
        was, notices, asked = profile(), hub.q1("SELECT COUNT(*) n FROM events WHERE agent='owner'")["n"], asks()
        with patch.object(hub, "commit_kit_file", side_effect=hub.KitFault(409, hub.KIT_BUSY)), \
                self.assertRaises(hub.ToolError) as refused:        # a busy turn: the manager's words, no fault
            self.plan([self.free("How you work", lines[4:])], title="Put the profile of Vps in order?", why="A test.")
        self.assertEqual(str(refused.exception), "The hub did not make this order, and nothing changed. "
                         f"{hub.KIT_BUSY.rstrip('.')}. Give the plan again.")
        self.assertEqual((profile(), hub.q1("SELECT COUNT(*) n FROM profile_orders")["n"]), (was, 0))
        said = self.plan([self.free("How you work", lines[4:])], title="Put the profile of Vps in order?",
                         why="Four of its lines stand in its duties and its skill.")
        self.assertIsNone(self.card(), said)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM events WHERE agent='owner'")["n"], notices)
        now_ = profile()
        self.assertEqual(git("--git-dir", str(self.root / "origin.git"), "log", "-1", "--format=%s", "main"),
                         "Fleet manager put the profile of vps in order")
        self.assertEqual(now_, was.replace("\n".join(lines[:4]) + "\n", ""))     # nothing else moved
        self.assertTrue(said.startswith(f"Made at once, with no card, in commit {self.head()[:12]}: the profile of Vps "
                                        f"(profiles/vps.md) goes from {len(was):,} to {len(now_):,} characters: 4 "
                                        f"lines left it, 2 in the duty R-{duty} (Answer the support queue), 1 in the "
                                        f"skill desk, 1 in the duty R-{closing} (Close the day)."), said)
        free = hub.profile_free_text(hub.parse_profile(now_))
        self.assertEqual(hub.kv_get(hub.PROFILE_LONG + "vps"), str(free))      # the new number, and no ask about it
        self.assertGreater(free, hub.PROFILE_LONG_MARK)
        self.assertEqual(asks(), asked)
        self.assertGreater(float(hub.kv_get(hub.PROFILE_CHANGED + "vps")), 0)
        status, read = self.request(f"/ui/profile-orders?agent=vps&db=test-generation")
        self.assertEqual(status, 200, read)
        order, = read["orders"]
        self.assertEqual((order["agent"], order["size_before"], order["size_after"], order["commit_after"],
                          order["owner_saved"]), ("vps", len(was), len(now_), self.head(), None))
        self.assertEqual([(x["section"], x["line"], x["way"], x["after"], x["place"], x["still"])
                          for x in order["lines"]],
                         [("How you work", line, "out", after, place, True) for line, after, place in zip(
                             lines[:4], [None] + lines[:3], [f"the duty R-{duty} (Answer the support queue)"] * 2 +
                             ["the skill desk", f"the duty R-{closing} (Close the day)"])])
        # the way back: a recorded line just after the line before it needs no card; once more, at another place, or
        # a line of no order makes one
        said = self.plan([self.free("How you work", lines[:1] + lines[4:])], title="Put a line of Vps back?",
                         why="Its results got worse.")
        self.assertIsNone(self.card(), said)
        self.assertIn("1 line came back into it", said)
        self.assertIn(lines[0], self.show("profiles/vps.md"))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM profile_orders WHERE agent='vps'")["n"], 2)
        for name, given in (("twice", lines[:1] * 2 + lines[4:]),
                            ("at another place", lines[:1] + lines[4:] + lines[1:2]),
                            ("of no order", lines[:1] + ["- A rule that no order took out."] + lines[4:])):
            with self.subTest(given=name):
                said = self.plan([self.free("How you work", given)], title="Change the profile of Vps?",
                                 why="A test.")
                self.assertTrue(said.startswith("Raised N-"), said)
        self.assertNotIn("A rule that no order took out", self.show("profiles/vps.md"))
        # the owner's own save: the profile is the owner's word again, and line 2 no longer comes back with no press
        sections = hub.profile_view("vps", hub.kit_revision(fresh=True))["sections"]
        hub.save_profile("vps", self.base_of("vps"), [dict(s, text="Short.") if s["title"] == "Style" else s
                                                      for s in sections])
        self.assertIsNotNone(hub.q1("SELECT owner_saved FROM profile_orders WHERE agent='vps' ORDER BY id LIMIT 1")[
            "owner_saved"])
        said = self.plan([self.free("How you work", lines[:2] + lines[4:])], title="Put a line of Vps back?",
                         why="A test.")
        self.assertTrue(said.startswith("Raised N-"), said)
        # a plan that the owner pressed ends the way back too: line 1 leaves again, a press changes the profile
        said = self.plan([self.free("How you work", lines[4:])], title="Put the profile of Vps in order?",
                         why="A test.")
        self.assertTrue(said.startswith("Made at once"), said)
        self.plan([{"kind": "profile", "agent": "vps", "base_sha256": self.base_of("vps"), "sections": [
            {"key": "may_do", "title": "May do without asking", "text": "Read and write files."}]}])
        self.assertEqual(self.press(0)[0], 200)
        self.assertIsNotNone(hub.q1("SELECT owner_saved FROM profile_orders WHERE agent='vps' ORDER BY id DESC "
                                    "LIMIT 1")["owner_saved"])     # the owner reads that the way back ended
        said = self.plan([self.free("How you work", lines[:1] + lines[4:])], title="Put a line of Vps back?",
                         why="A test.")
        self.assertTrue(said.startswith("Raised N-"), said)

    def test_the_record_says_whether_each_place_still_holds_its_line(self):
        """F15 piece 2, GET /ui/profile-orders `still`. Bug: the owner reads that a place still holds a line of his
        that its holder took out or put in another order, that a retired duty holds, or that only another agent's skill
        of the same name holds; or a read that git does not answer says that the line is lost."""
        lines, (duty, closing) = self.long_vps()
        said = self.plan([self.free("How you work", lines[4:])], title="Put vps in order?", why="A test.")
        self.assertTrue(said.startswith("Made at once"), said)
        self.write({"skills/studio/desk/SKILL.md": "---\nname: desk\ndescription: \"The desk.\"\n---\n\nAnother.\n"})
        hub.ins("INSERT INTO profile_orders(agent,at,commit_before,commit_after,size_before,size_after,lines) "
                "VALUES('studio',?,'a','b',2,1,?)", (hub.now(), json.dumps([
                    {"section": "How you work", "line": lines[2], "way": "out", "after": None,
                     "place": "the skill desk", "ref": {"skill": "desk"}}])))

        def still():
            status, read = self.request("/ui/profile-orders?db=test-generation")
            self.assertEqual(status, 200, read)
            return {o["agent"]: [x["still"] for x in o["lines"]] for o in read["orders"]}
        self.assertEqual(still(), {"studio": [False], "vps": [True] * 4})
        with self.skill_unread():
            self.assertEqual(still(), {"studio": [None], "vps": [True, True, None, True]})
        text = hub.q1("SELECT text FROM responsibilities WHERE id=?", (duty,))["text"]
        head, one, two = text.rsplit("\n", 2)
        hub.q("UPDATE responsibilities SET text=? WHERE id=?", ("\n".join([head, two, one]), duty))
        hub.q("UPDATE responsibilities SET state='retired' WHERE id=?", (closing,))
        self.assertEqual(still()["vps"], [False, False, True, False])       # in another order; retired
        hub.q("UPDATE responsibilities SET text=? WHERE id=?", ("\n".join([head, two]), duty))
        self.assertEqual(still()["vps"], [False, True, True, False])        # its holder took line 1 out

    def test_a_stop_of_the_hub_leaves_an_order_its_record_and_the_end_of_its_way_back(self):
        """F15 piece 2. Bug: the hub stops after an order's commit, and the owner's lines are gone with no record, no
        way back and no word to the manager, or the manager's repeat makes a second order; or it stops after the owner's
        save of the profile, and an order puts back, with no press, a line that the owner's save left out; or git
        with no answer is taken for a save; or a mark of an order that cannot be read stops the owner's own save; or
        the next order writes over the mark of an order whose record still waits, which then keeps none."""
        lines, _ = self.long_vps()
        plan = {"changes": [self.free("How you work", lines[4:])], "title": "Put vps in order?", "why": "A test.",
                "request_id": str(uuid.uuid4())}
        started = patch.dict(hub.PROFILE_ORDERS_READ, {"start": True})
        started.start()
        self.addCleanup(started.stop)

        def orders():
            return hub.q("SELECT * FROM profile_orders WHERE agent='vps' ORDER BY id")
        with patch.object(hub, "profile_order_record", side_effect=SystemExit), self.assertRaises(SystemExit):
            self.plan(**plan)
        self.assertNotIn(lines[0], self.show("profiles/vps.md"))
        self.assertEqual(orders(), [])
        hub.profile_orders_repair(hub.now())
        order, = orders()
        self.assertEqual((order["commit_after"], [x["line"] for x in json.loads(order["lines"])]),
                         (self.head(), lines[:4]))
        self.assertIn("Made at once", self.told("The hub stopped while it made your plan")["text"])
        self.assertTrue(self.plan(**plan).startswith("Made at once"))       # the repeat reads the answer
        # a stop before the commit: nothing was made, and nothing is recorded
        back = {"changes": [self.free("How you work", lines[:1] + lines[4:])], "title": "Put a line back?",
                "why": "A test."}
        with patch.object(hub, "commit_kit_file", side_effect=SystemExit), self.assertRaises(SystemExit):
            self.plan(**back)
        hub.profile_orders_repair(hub.now())
        self.assertEqual((len(orders()), hub.kv_get(hub.PROFILE_ORDER_MAKING)), (1, None))
        # the owner's save, stopped after its commit
        base, real = self.base_of("vps"), hub.commit_kit_file
        saved = [dict(s, text="Short.") if s["title"] == "Style" else s
                 for s in hub.profile_view("vps", hub.kit_revision(fresh=True))["sections"]]

        def stop(*args, **kwargs):
            real(*args, **kwargs)
            raise SystemExit
        with patch.object(hub, "commit_kit_file", stop), self.assertRaises(SystemExit):
            hub.save_profile("vps", base, saved)
        self.assertIsNone(orders()[0]["owner_saved"])
        for name, again in (("the owner's retry", lambda: self.assertRaises(hub.Conflict, hub.save_profile, "vps", base,
                                                                            saved)),
                            ("the next start", lambda: (hub.PROFILE_ORDERS_READ.update(start=False),
                                                        hub.profile_orders_repair(hub.now()))),
                            ("the manager's plan", lambda: self.assertTrue(self.plan(
                                [self.free("How you work", lines[:1] + lines[4:])], title="Put a line back?",
                                why="A test.").startswith("Raised N-")))):
            with self.subTest(end=name):
                hub.q("UPDATE profile_orders SET owner_saved=NULL")
                again()
                self.assertIsNotNone(orders()[0]["owner_saved"])
        # git with no answer: nothing is taken for a save, and an order waits
        hub.q("UPDATE profile_orders SET owner_saved=NULL")
        real_git = hub.git_kit
        with patch.object(hub, "git_kit", lambda *a, **k: (1, "", "no answer") if a[0] == "rev-list" else
                          real_git(*a, **k)):
            self.assertIs(hub.profile_orders_ended("vps"), False)
            self.assertIsNone(orders()[0]["owner_saved"])
            with self.assertRaises(hub.TeamPassing):
                self.plan([self.free("How you work", lines[:1] + lines[4:])], title="Put a line back?", why="A test.")
        # a mark that cannot be read stops no save of the owner's
        hub.kv_set(hub.PROFILE_ORDER_MAKING, "{")
        self.assertFalse(hub.save_profile("vps", self.base_of("vps"), [
            dict(s, text="Shorter.") if s["title"] == "Style" else s
            for s in hub.profile_view("vps", hub.kit_revision(fresh=True))["sections"]])["unchanged"])
        self.assertIsNone(hub.kv_get(hub.PROFILE_ORDER_MAKING))
        # an order whose record still waits keeps its mark: the next order waits for it
        self.duty("vps", f"Desk.\n\n## How you work\n\n{lines[4][2:]}")
        hub.kv_set(hub.PROFILE_ORDER_MAKING, json.dumps({"waits": True}))
        with patch.object(hub, "profile_order_land", lambda: None), self.assertRaises(hub.TeamPassing):
            self.plan([self.free("How you work", lines[5:])], title="Put vps in order?", why="A test.")
        self.assertEqual(hub.kv_get(hub.PROFILE_ORDER_MAKING), json.dumps({"waits": True}))

    def test_an_order_moves_only_an_item_of_a_titles_flat_list_or_a_whole_paragraph(self):
        """F15, the two rules of order_pieces, for a line that leaves, one that comes back and one in its place. Bug: a
        line leaves what opens it, a line that stays gets another opener, or a place holds the line under an opener or a
        heading of the opposite sense, so a decision of the owner's changes with no press; or such a plan, which only
        makes the profile shorter, is a card."""
        rev = hub.kit_revision(fresh=True)
        base = hub.profile_view("vps", rev)["sections"]

        def order(before, after, asked=False):
            texts = [hub.render_profile("vps", base + ([{"key": "other", "title": "Refunds", "text": t}] if t else []))
                     for t in (before, after)]
            kind, said = hub.profile_order("manager", {"rev": rev, "profiles": [{
                "agent": "vps", "role": "vps", "text": texts[0], "sections": hub.parse_profile(texts[0]),
                "new": texts[1].encode()}]}, asked)
            return kind if kind != "refuse" else said
        held = ("a refund", "a deploy", "a chargeback", "Ask the owner first.", "A refund.", "A deploy.")
        place = self.duty("vps", "Handle it all.\n\n## Refunds\n\n" + "\n".join(f"- {x}" for x in held) +
                          "\n\n## Refunds\n\nShare the number, and\nsay when it ends.")
        for name, before, after, why in (
                ("•", "Without asking:\n• a deploy\nAsk the owner first:\n• a refund",
                 "Without asking:\n• a deploy\n• a refund", "\"Without asking:\" can open"),
                ("•, each alone", "• A refund.\n\n• A deploy.", "• A refund.", "only an item of a list"),
                ("–", "– A refund.\n\n– A deploy.", "– A deploy.", "only an item of a list"),
                ("a)", "a) A refund.\n\nb) A deploy.", "b) A deploy.", "only an item of a list"),
                ("1)", "1) a refund\n2) a deploy", "1) a refund", "can open"),
                ("an opener in a title's list", "- Ask first:\n- a refund\n- a deploy", "- a refund\n- a deploy",
                 "\"- Ask first:\" can open"),
                ("an item under it", "- Ask first:\n- a refund\n- a deploy", "- Ask first:\n- a deploy",
                 "\"- Ask first:\" can open"),
                ("two lists in a row", "- a refund\n- a deploy\n\n- a chargeback", "- a refund\n- a deploy",
                 "only an item of a list"),
                ("two lists, the first", "- a refund\n- a deploy\n\n- a chargeback", "- a chargeback",
                 "only an item of a list"),
                ("two marks", "- a refund\n* a deploy", "- a refund", "only an item of a list"),
                ("an opener line with bullets", "Ask the owner first:\n- a refund\n- a deploy",
                 "Ask the owner first:\n- a deploy", "\"Ask the owner first:\" can open"),
                ("its opener alone", "Ask the owner first:\n- a refund\n- a deploy", "- a refund\n- a deploy",
                 "\"Ask the owner first:\" can open"),
                ("an opener with no colon", "Ask the owner first.\n\n- a refund", "- a refund",
                 "only an item of a list"),
                ("plain lines under openers", "Without asking:\nA refund.\nAsk the owner first:\nA deploy.",
                 "Without asking:\nA refund.\nA deploy.", "can open"),
                ("a heading", "### Ask the owner first\n\nA refund.", "### Ask the owner first", "can open"),
                ("a bold line", "**Ask the owner first**\n\nA refund.", "**Ask the owner first**", "can open"),
                ("a line that ends no sentence", "Ask the owner first\n\nA refund.", "Ask the owner first",
                 "\"Ask the owner first\" can open"),
                ("a part of a paragraph", "Refund at once,\nbut never above 50 EUR.", "Refund at once,",
                 "a part of a paragraph that stays"),
                ("a nested item", "- a refund\n  - a deploy", "- a refund", "only an item of a list"),
                ("a wrapped item", "- a refund\n  that is large.\n- a deploy", "- a deploy", "only an item"),
                ("a quote", "> - A refund.\n\nA deploy.", "> - A refund.", "only an item of a list"),
                ("code", "```\nA refund.\n\nA deploy.\n```", "```\nA deploy.\n```", "can open"),
                ("the form of what stays", "A refund.\n\nShare it\nnow.\n\nA deploy.", "Share it now.\n\nA deploy.",
                 None),
                ("a paragraph joined to the next", "A refund.\n\nA deploy.\n\nAsk the owner first.",
                 "A deploy.\nAsk the owner first.", "its form"),
                ("a numbered list", "1. a refund\n2. a deploy", "1. a refund", "a numbered item is a step"),
                ("a list numbered again", "1. Check the logs.\n2. A refund.\n3. A deploy.",
                 "1. Check the logs.\n2. A deploy.", "a numbered item is a step"),
                ("a list before a paragraph", "- a refund\n- a deploy\n\nShare it.", "- a deploy\n\nShare it.",
                 "only an item of a list"),
                ("a paragraph that speaks of the list", "- a refund\n- a deploy\n\nNone of the above is for a shop.",
                 "- a refund\n\nNone of the above is for a shop.", "only an item of a list")):
            with self.subTest(out=name):
                said = order(before, after)
                self.assertEqual(said, "card") if why is None else self.assertIn(why, said)
                if why:
                    self.assertEqual(order(before, after, asked=True), "card")
        for name, before, after in (
                ("-", "- a refund\n- a deploy", "- a deploy"), ("*", "* a refund\n* a deploy", "* a refund"),
                ("+", "+ a refund\n+ a deploy", ""), ("end spaces", "- a deploy  \n- a refund", "- a deploy"),
                ("a paragraph", "A refund.\n\nA deploy.", "A deploy."),
                ("a paragraph of two lines", "A refund.\n\nShare the number, and\nsay when it ends.", "A refund.")):
            with self.subTest(order=name):
                self.assertEqual(order(before, after), "order")
        self.assertIn("before a line that it follows", order("- a deploy\n- a refund", ""))
        # the way back: only a piece by the same rules, just after the one line before it
        hub.ins("INSERT INTO profile_orders(agent,at,commit_before,commit_after,size_before,size_after,lines) "
                "VALUES('vps',?,'a','b',2,1,?)", (hub.now(), json.dumps([
                    {"section": "Refunds", "line": line, "way": "out", "after": after} for line, after in (
                        ("- a deploy", "- a refund"), ("• A deploy.", "A refund."), ("Without asking:", None),
                        ("Share the number, and\nsay when it ends.", "A refund."))])))
        for before, after, kind in (
                ("- a refund\n- a chargeback", "- a refund\n- a deploy\n- a chargeback", "order"),
                ("A refund.", "A refund.\n\nShare the number, and\nsay when it ends.", "order"),
                ("A refund.", "A refund.\n\nShare the number, and", "card"),
                ("A refund.", "A refund.\n\n• A deploy.", "card"),
                ("Ask the owner first:\n- a refund", "Ask the owner first:\n- a refund\n- a deploy", "card"),
                ("- a refund\n\nA refund.\n\nShare it.", "Without asking:\n\n- a refund\n\nA refund.\n\nShare it.",
                 "card"),
                ("A refund.\n\nShare it.\n\nA refund.",
                 "A refund.\n\nShare it.\n\nA refund.\n\nShare the number, and\nsay when it ends.", "card")):
            with self.subTest(back=after):
                self.assertEqual(order(before, after), kind)
        # the place: the same two rules, only under that section's own title, which travels with the piece
        hub.q("DELETE FROM profile_orders")
        for text, kind in (("Handle it.\n\n## Refunds\n- a chargeback", "order"),
                           ("Handle it.\n\n**Refunds.**\n\n- a chargeback", "order"),
                           ("# Refunds\n\n- a chargeback", "order"), ("- a chargeback\n- a deploy", None),
                           ("# What you never do\n\n- a chargeback", None), ("Never.\n\n- a chargeback", None),
                           ("# Desk\n\n## Refunds\n\n- a chargeback", None),     # a duty's "# ..." is a heading
                           ("## Refunds\n\n- a chargeback\n\nNever do one of the above.", None),
                           ("Without asking:\n- a chargeback", None), ("Handle it.\n\n## Never\n- a chargeback", None),
                           ("Handle it.\n\n## Never\n\n### Refunds\n- a chargeback", None),
                           ("Never do these:\n\n## Refunds\n- a chargeback", None),
                           ("## Refunds\nAlone:\n- a chargeback", None), ("## Refunds\n• a chargeback", None),
                           ("## Refunds\n- Never:\n- a chargeback", None),
                           ("Handle it.\n\n```\n## Refunds\n- a chargeback\n## More\n```", None),
                           ("We keep no such rule: a chargeback is one.", None)):
            with self.subTest(place=text):
                hub.q("UPDATE responsibilities SET text=? WHERE id=?", (text, place))
                said = order("- a chargeback", "")
                self.assertEqual(said, kind) if kind else self.assertIn("stands in no place", said)
        for text, kind in (("Handle it.\n\n## Refunds\n\nA refund.\n\nShare it.", "order"),
                           ("Handle it.\n\nA refund.\n\nShare it.", None), ("## Refunds\n\nNever:\n\nA refund.", None),
                           ("## Refunds\nHandle it.\nA refund.", None), ("## Refunds\n\nA refund.\n\n- a deploy", None),
                           ("## Never\n\nA refund.", None),
                           ("## Refunds\n\n" + "More of it. " * 440 + "\n\nA refund.", None),     # a start cuts it
                           ("## Refunds\n\nA refund.\n\n" + "More of it. " * 440, "order")):
            with self.subTest(place=text[:40]):
                hub.q("UPDATE responsibilities SET text=? WHERE id=?", (text, place))
                said = order("A refund.\n\nA deploy.", "A deploy.")
                self.assertEqual(said, kind) if kind else self.assertIn("stands in no place", said)

    def test_a_plan_that_changes_a_decision_access_or_a_word_is_a_card_and_one_that_loses_a_line_is_refused(self):
        """F15 claims C2 to C7: each of these plans takes lines 1 to 4 of vps out too, which alone would be an order.
        Bug: a change of what the owner decided, of access or of a word goes out with no press; or a line goes to a
        place that another agent or a release can write (its notes, a shared knowledge file, an owner file, another
        agent's duty), that no session reads (a retired duty, one with no watch, a paused one, only an attached rule or
        typed reports, a skill of an agent whose Shell box is off), that the owner gave, or that was written after reads
        of outside text; or a failed read of a skill is taken for no place; or such a plan rings the owner with a card
        for a shorter profile, or one that the owner's own newest message asks for is refused; or another hand, an older
        message, a card's answer, a task or a stopped message opens the card, or takes the ask of the card before it; or
        a second section with a title of the owner's decisions, or a head that is not the hub's, leaves with no press or
        with one that does not show it; or the manager makes its own rules its own to change."""
        lines, duties = self.long_vps()
        out = self.free("How you work", lines[4:])
        hub.q("UPDATE responsibilities SET state='retired' WHERE agent='vps'")
        notices = hub.q1("SELECT COUNT(*) n FROM events WHERE agent='owner'")["n"]

        def refused_with(why, changes=None, said=None, **extra):
            with self.assertRaises(hub.ToolError) as refused:
                self.plan(changes or [self.free("How you work", lines[4:])], title="Put vps in order?", why="A test.",
                          **extra)
            self.assertNotIsInstance(refused.exception, hub.TeamPassing)
            self.assertEqual(str(refused.exception), hub.PROFILE_ORDER_NONE.format(
                why=why, ask=hub.PROFILE_ORDER_ASK if said is None else said))

        def lost(n, own=" or an own skill"):
            return (f"the line \"{hub.clip(lines[n], 80)}\" of How you work in the profile of Vps stands in no place "
                    f"of that agent: a duty whose running check or clock watch brings its words to it{own}, under a "
                    f"heading \"How you work\", as a paragraph of its own or an item of a list that is the whole part, "
                    f"where no line opens others. A duty's part that a start cuts, a duty whose words no session saved "
                    f"since this release, what was written after reads of outside text" +
                    (" and a skill that the owner gave are none. Move it there word for word first (set_duty, or a "
                     "task that writes a skill)" if own else " and each skill (its sessions read no file) are none. Move it "
                     "there word for word first (set_duty)") + ", or leave it in the profile.")
        paragraphs = "Work the desk.\n\n## How you work\n\n" + "\n\n".join(line[2:] for line in lines[:4])
        for place in ("a retired duty", "a duty with no watch", "a duty whose watch is paused",
                      "a duty with an attached rule only", "a duty with typed reports only",
                      "a duty written after reads of outside text", "a duty of before this release",
                      "a duty with that title only as its first line", "a skill whose first line says the opposite",
                      "notes", "a shared knowledge file",
                      "an owner file that its profile lists", "another agent's duty",
                      "a skill written after reads of outside text", "a skill that the owner gave"):
            with self.subTest(place=place):
                gave = contextlib.nullcontext()
                if place == "a duty with no watch":
                    self.duty("vps", paragraphs, watch=None)
                elif place == "a duty whose watch is paused":
                    self.duty("vps", paragraphs, running="paused")
                elif place == "a duty with an attached rule only":
                    self.duty("vps", paragraphs, watch=hub.DUTY_OWN)
                elif place == "a duty with typed reports only":
                    taker = self.duty("vps", paragraphs, watch=None)
                    hub.q("UPDATE responsibilities SET report_to=? WHERE id=?",
                          (json.dumps([taker]), self.duty("studio", "Report it.")))
                elif place == "a duty written after reads of outside text":
                    self.duty("vps", paragraphs, reads=1)
                elif place == "a duty of before this release":
                    self.duty("vps", paragraphs, reads=None)
                elif place == "a skill whose first line says the opposite":
                    self.write({"skills/vps/never/SKILL.md": "---\nname: never\ndescription: \"Never.\"\n---\n\n"
                                "# Things you never do\n\n## How you work\n\n" +
                                "\n\n".join(line[2:] for line in lines[:4]) + "\n"})
                elif place == "a duty with that title only as its first line":
                    self.duty("vps", paragraphs.replace("Work the desk.\n\n## How you work", "How you work."))
                elif place == "notes":
                    with hub.LOCK, hub.transaction():
                        hub.notes_save("vps", "\n".join(lines[:2]), "my notes", "vps", hub.now())
                elif place == "a shared knowledge file":
                    self.write({"knowledge/desk.md": f"# Desk\n\n{paragraphs}\n"})
                elif place == "an owner file that its profile lists":
                    self.write({"knowledge/owner/desk-policy.md":
                                f"# Desk policy\n\nSource: the owner\n\n{paragraphs}\n"})
                elif place == "another agent's duty":
                    self.duty("studio", paragraphs)
                elif place == "a skill written after reads of outside text":
                    self.write({"skills/vps/weighed/SKILL.md": "---\nname: weighed\ndescription: \"Read.\"\n"
                                f"outside-reads: 2\n---\n\n{paragraphs}\n"})
                elif place == "a skill that the owner gave":
                    self.write({"skills/vps/gift/SKILL.md": f"---\nname: gift\ndescription: \"Read.\"\n---\n\n"
                                f"{paragraphs}\n"})
                    gave = patch.object(hub, "skill_is_given", lambda agent, name, rev=None: name == "gift")
                with gave:
                    refused_with(lost(0))
        self.write({"skills/vps/gift/SKILL.md": "---\nname: gift\ndescription: \"Read.\"\n---\n\nNothing.\n"})
        self.assertIsNone(self.card())
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM events WHERE agent='owner'")["n"], notices)
        for fails in (self.skill_unread(), patch.object(hub, "skill_is_given", lambda *a: None)):
            with fails, self.assertRaises(hub.TeamPassing):     # a read that fails is never taken for no place
                self.plan([self.free("How you work", lines[4:])], title="Put vps in order?", why="A test.")

        def owner_message(hand="app", kind="message", asked="Take the desk rules out", read=True, need=None):
            eid = hub.ins("INSERT INTO events(agent,kind,text,created,read_at) VALUES('manager','owner',?,?,?)",
                          ("Take the desk rules out.", hub.now(), hub.now() if read else None))
            request = str(uuid.uuid4())
            hub.ins("INSERT INTO ui_requests(request_id,kind,need_id,text,event_id,created,client,recipient,hand,"
                    "asked) VALUES(?,?,?,?,?,?,'Founderizer','manager',?,?)",
                    (request, kind, need, "Take the desk rules out.", eid, hub.now(), hand, asked))
            return f"M-{eid}", request

        def not_newest(ref):
            return f" {ref} is not the newest message that the owner typed to you in Founderizer themselves, so your " \
                   f"ask opens no card."
        older, request = owner_message()
        newest, _ = owner_message()
        task = hub.ins("INSERT INTO tasks(title,owner,requester,state,needs,attempt,created,ask) VALUES('Desk',"
                       "'manager','manager','completed','none',1,?,?)", (hub.now(), request))
        need = hub.ins("INSERT INTO needs(title,why,todo,raised,by,options,ask,answer) VALUES('Which?','It waits.',"
                       "'',?,'manager','[]',?,'No')", (hub.now(), request))
        for name, ref in (("an older message", older), ("an AI session's message", owner_message("tool")[0]),
                          ("a chat app's message", owner_message("chat")[0]), ("a task", f"T-{task}"),
                          ("a card", f"N-{need}"),
                          ("the answer of a card", owner_message(kind="answer", asked=None, need=need)[0])):
            with self.subTest(ask=name):
                refused_with(lost(0), ask=ref, said=not_newest(ref))
        self.assertIsNone(self.card())
        owner_message(read=False)                               # a newer one that the manager did not read yet
        said = self.plan([self.free("How you work", lines[4:])], title="Take the desk rules out?",
                         why="The owner asked for it.", ask=newest)
        self.assertTrue(said.startswith("Raised N-"), said)     # the owner's own message: the owner's press decides
        self.assertIsNotNone(self.card()["ask"])
        new, request = owner_message("device", asked=None)      # no work is filed under it: no ask of the old card's
        said = self.plan([self.free("How you work", lines[4:])], title="Take the desk rules out?",
                         why="The owner asked for it.", ask=new)
        self.assertTrue(said.startswith("Raised N-"), said)
        self.assertIsNone(self.card()["ask"])
        hub.q("UPDATE ui_requests SET asked='Take it out' WHERE request_id=?", (request,))
        hub.ins("INSERT INTO chat_stops(agent,request,state,created) VALUES('manager',?,'stopped',?)",
                (request, hub.now()))
        refused_with(lost(0), ask=new, said=not_newest(new))    # a press of Stop closed it
        self.duty("vps", "Work the desk.\n\n## How you work\n\n" +
                  "\n\n".join(line[2:] for line in lines[:2] + lines[3:4]))
        with patch.object(hub, "shell_off", lambda agent: agent == "vps"):
            refused_with(lost(2, own=""))
        decision = {"key": "may_do", "title": "May do without asking", "text": "Read and write files."}
        for name, changes in (
                ("may_do", [dict(out, sections=out["sections"] + [decision])]),
                ("must_ask", [dict(out, sections=out["sections"] + [dict(decision, key="must_ask", title="Must ask "
                                                                                    "first", text="Nothing.")])]),
                ("responsible_for", [dict(out, sections=out["sections"] + [
                    {"key": "responsible_for", "title": "Responsible for", "text": "Its work and more."}])]),
                ("knowledge_files", [dict(out, sections=out["sections"] + [
                    {"key": "knowledge_files", "title": "Knowledge files", "text": ""}])]),
                ("a new line", [self.free("How you work", lines[4:] + ["- A new rule."])]),
                ("a line reworded", [self.free("How you work", lines[4:7] + [lines[7].replace("once", "twice")])]),
                ("a new free section", [dict(out, sections=out["sections"] + [
                    {"key": "other", "title": "Tone", "text": "Warm."}])]),
                ("another change", [out, {"kind": "settings", "agent": "vps", "title": "Desk"}])):
            with self.subTest(change=name):
                said = self.plan(changes, title="Change the profile of Vps?", why="A test.")
                self.assertTrue(said.startswith("Raised N-"), said)
        login = {"key": "logins", "title": "Logins it may use", "text": "`bws://11111111-2222-4333-8444-55555555555b`"}
        with self.assertRaises(hub.ToolError) as refused:
            self.plan([dict(out, base_sha256=self.base_of("vps"), sections=out["sections"] + [login])])
        self.assertIn("Logins it may use", str(refused.exception))
        self.assertIn(lines[0], self.show("profiles/vps.md"))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM profile_orders")["n"], 0)
        # a profile written by hand: a second section with a title of the owner's decisions is a card, and words
        # before the sections that are not the hub's are refused, also when the owner's own message asks
        text = hub.profile_view("vps", hub.kit_revision(fresh=True))["text"]
        self.duty("vps", "Work the queue.\n\nRefunds above 50 EUR.")
        self.write({"profiles/vps.md": text + "\n**What goes to the owner (Needs you).** Refunds above 50 EUR.\n"})
        said = self.plan([{"kind": "profile", "agent": "vps", "base_sha256": self.base_of("vps"), "sections": [
            {"key": "other", "title": "What goes to the owner (Needs you)", "text": ""}]}], title="Change vps?",
            why="A test.")
        self.assertTrue(said.startswith("Raised N-"), said)
        self.write({"profiles/vps.md": text.replace("Agents cannot change it.\n",
                                                    "Agents cannot change it.\n\nAnd a word of the owner's.\n")})
        head = ("the profile of Vps has words before its first section that are not the hub's own, and a write of it "
                "would lose them. Leave this profile as it is.")
        refused_with(head, said="")
        refused_with(head, ask=owner_message()[0], said="")
        self.write({"profiles/vps.md": text})
        # the manager's own profile, whose line stands in the manager's own duty
        self.duty("manager", "Plan the work.\n\nRead the queue first.")
        sections = hub.profile_view("manager", hub.kit_revision(fresh=True))["sections"]
        hub.save_profile("manager", self.base_of("manager"), sections + [
            {"key": "other", "title": "How you work", "text": "- Read the queue first.\n- Then plan."}])
        said = self.plan([{"kind": "profile", "agent": "manager", "base_sha256": self.base_of("manager"),
                           "sections": [{"key": "other", "title": "How you work", "text": "- Then plan."}]}],
                         title="Put my profile in order?", why="A test.")
        self.assertTrue(said.startswith("Raised N-"), said)
        self.assertIn("Read the queue first.", self.show("profiles/manager.md"))

    def test_a_duty_keeps_the_count_of_the_outside_reads_behind_its_words(self):
        """F15, claim C6 (duty_save). Bug: a duty that a session wrote after reads of outside text is a place of an
        order, because the save writes no count, writes 0, or a later save from a clean session clears it; or a save of
        the watches alone vouches for the words of a duty of before this release, which no session saved since."""
        def save(body, duty_id=None, reads=0):
            with patch.object(hub, "save_provenance", lambda by: (7, reads)), hub.LOCK:
                return hub.duty_save(hub.duty_fields(body, duty_id is None), "vps", hub.now(), duty_id=duty_id)

        def count(duty_id):
            return hub.q1("SELECT outside_reads FROM responsibilities WHERE id=?", (duty_id,))["outside_reads"]
        duty = save({"agent": "vps", "text": "Answer the queue."}, reads=3)["id"]
        self.assertEqual(count(duty), 3)
        save({"text": "Answer the queue at once."}, duty)
        self.assertEqual(count(duty), 3)                # a clean session's save keeps the mark
        hub.q("UPDATE responsibilities SET outside_reads=NULL WHERE id=?", (duty,))
        save({"watch": []}, duty)
        self.assertIsNone(count(duty))                  # the watches alone vouch for no words
        save({"text": "Answer the queue."}, duty)
        self.assertEqual(count(duty), 0)

    def test_twenty_finished_tasks_after_an_order_bring_the_manager_its_numbers_once(self):
        """F15 piece 3 (the owner: "a seamless experience that actually GETS better"). Bug: a message at each task,
        before the twentieth, or again after it; numbers of another agent's tasks, or of a task that ran when the
        order came, with the profile of before; a word to the owner; the tasks of an agent that never finishes 20
        read at each pass of the tick, under the hub's lock (MEMORY_COUNT_EVERY); or "it needs no card" for a line
        back after the owner's save, which makes that plan a card, or the other way round."""
        t0 = hub.now()
        hub.ins("INSERT INTO profile_orders(agent,at,commit_before,commit_after,size_before,size_after,lines) "
                "VALUES('vps',?,?,?,9000,6000,?)", (t0, "a" * 40, self.head(), json.dumps([
                    {"section": "How you work", "line": "- Rule 1.", "way": "out", "after": None,
                     "place": "the duty R-1 (Desk)"}])))

        def task(owner, at, accepted=1, started=None):
            return hub.ins("INSERT INTO tasks(title,owner,requester,state,needs,attempt,created,delivered,accepted) "
                           "VALUES('Work',?,'manager','completed','none',1,?,?,?)",
                           (owner, at - 60 if started is None else started, at, accepted))
        before = [task("vps", t0 - 1000 + n, accepted=0 if n < 3 else 1) for n in range(25)]
        counted = patch.dict(hub.PROFILE_ORDER_COUNTED, clear=True)
        counted.start()
        self.addCleanup(counted.stop)
        hub.ins("INSERT INTO questions(task,asker,requester,text,asked) VALUES(?,'vps','manager','Which?',?)",
                (before[-1], t0 - 900))
        hub.ins("INSERT INTO tasks(title,owner,requester,state,needs,attempt,created,follows) "
                "VALUES('Again','vps','manager','completed','none',1,?,?)", (t0 - 500, before[-2]))
        for n in range(5):
            task("studio", t0 + 65 + n, accepted=0)
        for n in range(3):          # each ran when the order came, so it read the profile of before
            task("vps", t0 + 70 + n, accepted=0, started=t0 - 30)
        for n in range(19):
            task("vps", t0 + 70 + n, accepted=0 if n == 0 else 1)
        owner_events = hub.q1("SELECT COUNT(*) n FROM events WHERE agent='owner'")["n"]

        def said():
            return [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND text LIKE "
                                             "'%after the order that put its profile in order%'")]
        at = hub.now()
        hub.profile_orders_measure(at)
        self.assertEqual(said(), [])
        task("vps", t0 + 100)
        hub.profile_orders_measure(at + 10)         # the 20th, 10 seconds after a count: the next count comes later
        self.assertEqual(said(), [])
        for n in (1, 2):
            hub.profile_orders_measure(at + n * hub.MEMORY_COUNT_EVERY)
        task("vps", t0 + 101)
        hub.profile_orders_measure(at + 3 * hub.MEMORY_COUNT_EVERY)
        message, = said()
        self.assertIn("finished 20 tasks that started after the order", message)
        self.assertIn("Its 20 finished tasks before the order, and its 20 after it: results that their requester "
                      "refused: 0 before, 1 after; tasks that needed doing again: 1 before, 0 after; questions that it "
                      "asked up: 1 before, 0 after;", message)
        self.assertIn("\"- Rule 1.\" (How you work, then put in the duty R-1 (Desk))", message)
        way = "put a line back with a plan that gives its section with that line again, just after the line that " \
              "stood before it: "
        self.assertTrue(message.endswith(way + "it needs no card."), message)
        sections = hub.profile_view("vps", hub.kit_revision(fresh=True))["sections"]
        hub.save_profile("vps", self.base_of("vps"), sections + [{"key": "other", "title": "Style", "text": "Short."}])
        hub.q("UPDATE profile_orders SET measured=NULL")
        hub.profile_orders_measure(at + 4 * hub.MEMORY_COUNT_EVERY)
        self.assertTrue(said()[-1].endswith(way + "a write of the profile since the order, a save or a press of the "
                                            "owner's, makes that plan a card."), said()[-1])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM events WHERE agent='owner'")["n"], owner_events)

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
        """Bug: a valid card leaves the owner's screen because an agent was busy for a minute or git gave no answer
        for a file, or a stale card stays and his press then fails."""
        self.plan([{"kind": "remove", "agent": "scout"}])
        task = hub.ins("INSERT INTO tasks(owner,requester,title,state,created,last_activity) VALUES('scout','manager',"
                       "'Fix it','working',?,?)", (hub.now(), hub.now()))
        hub.team_plan_sweep(hub.now())
        self.assertIsNone(self.card()["answer"])
        status, answer = self.press(0)
        self.assertEqual(status, 409, answer)
        self.assertIn("cannot make this change now: Scout has open tasks now", answer["error"])
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
        # a profile that git does not give now is no other version of it (team_profile): the sweep and the press
        # keep its card, and do not say that the manager read another version
        self.plan([{"kind": "profile", "agent": "vps", "base_sha256": self.base_of("vps"),
                    "sections": [{"key": "responsible_for", "title": "Responsible for", "text": "Deploys."}]}])
        with self.not_given("profiles/vps.md"):
            hub.kv_set(hub.TEAM_PLAN_SWEEP, None)
            hub.team_plan_sweep(hub.now())
            self.assertIsNone(self.card()["answer"])
            status, answer = self.press(0)
        self.assertEqual(status, 409, answer)
        self.assertIn("cannot make this change now: the hub cannot read its configuration now", answer["error"])
        self.assertIsNone(self.card()["answer"])

    def test_a_busy_server_keeps_an_add_card_for_a_later_press(self):
        """Bug: an add card closes for good because its server had too little memory free for a minute. And the other
        way: a plan for a server that can never have the room, a 2 GB server that runs an agent already (a customer
        of 21 November 2026, whose one team server ran the manager), waits for ever, and nobody hears that the owner
        must choose a bigger server or another one."""
        self.add_plan()
        self.box2(free=1 << 29)
        hub.kv_set(hub.TEAM_PLAN_SWEEP, None)
        hub.team_plan_sweep(hub.now())
        self.assertIsNone(self.card()["answer"])
        status, answer = self.press(0)
        self.assertEqual(status, 409, answer)
        self.assertIn("box2 has too little free memory now", answer["error"])
        self.assertIsNone(self.card()["answer"])

        def box(total, free):           # scout runs on box
            status, said = self.service("/server/box/status", {
                "revision": hub.kit_revision(fresh=True), "os": {"name": "Ubuntu 24.04.1 LTS"},
                "runtimes": {"codex": {"version": "1.0.0", "signed_in": True}}, "access": {"user": "fleet"},
                "load": {"cpu_percent": 5.0, "memory_used": total - free, "memory_total": total, "disk_used": 1,
                         "disk_total": 2}}, source=OTHER)
            self.assertEqual(status, 200, said)
        add = {"kind": "add", "server": "box", "names": ["nova"], "title": "Customer Support 2", "runtime": "codex",
               "profile": SECTIONS}
        box(1946 << 20, 1 << 30)        # what a server of 2 GB shows in all
        with self.assertRaises(hub.ToolError) as refused:
            self.plan([add])
        self.assertNotIsInstance(refused.exception, hub.TeamPassing)
        self.assertIn("box can never take one more agent", str(refused.exception))
        self.assertIn("raise_needs_you (reason money)", str(refused.exception))
        box(2048 << 20, 1 << 30)        # exactly 2 GiB in all, as a container can show it: no room either
        with self.assertRaises(hub.ToolError) as refused:
            self.plan([add])
        self.assertIn("box can never take one more agent", str(refused.exception))
        self.box2(free=1 << 30, total=1946 << 20)     # a server of 2 GB that runs no agent yet can have the room
        with self.assertRaises(hub.TeamPassing) as waits:
            self.plan([dict(add, server="box2")])
        self.assertEqual(waits.exception.owner, "box2 has too little free memory now")
        box(3820 << 20, 1 << 30)        # 4 GB: it can have the room later, so it waits as before
        with self.assertRaises(hub.TeamPassing) as waits:
            self.plan([add])
        self.assertEqual(waits.exception.owner, "box has too little free memory now")
        box(1946 << 20, 1640 << 20)     # a reading that shows the room now: its free memory decides, as before
        try:
            self.plan([add])
        except hub.ToolError as e:
            self.assertNotIn("memory", str(e))

    MAIL = "support@example.com"

    def allows(self, services=("gmail", "drive"), bad=None):
        """The Google file as the hub reads it now: the mailbox's account allows these services."""
        return patch.object(hub, "google_services_now", lambda: ({self.MAIL: tuple(services)}, bad))

    @contextlib.contextmanager
    def reaches(self, *repos, read=True, whole=None):
        """The fleet's GitHub App, and its reading now (none yet, with read False): it reaches these repositories of
        acme, whose installation page is the one that a refusal names, and each repository of the accounts of whole
        ({account: its repositories}), whose list the hub read a moment ago too (github_repo_known)."""
        whole = whole or {}
        reach = {"pages": {"acme": "https://github.com/organizations/acme/settings/installations/7"}, "all": set(whole),
                 "repos": set(repos), "install": "https://github.com/apps/fleet/installations/new"}
        with patch.object(hub, "github_app", lambda: ("7", "key")), \
                patch.dict(hub.GITHUB_REACH, {"at": hub.now(), "reach": reach if read else None, "reading": False}), \
                patch.dict(hub.GITHUB_REPOS, {"at": hub.now(), "list": {
                    a: {"name": a, "repos": sorted(r)} for a, r in whole.items()}}):
            yield

    def mailbox_plan(self):
        """An add whose new agent gets, with the press, each kind that a plan gives: a Gmail mailbox, a Drive, an MCP
        server that needs no sign-in and no key, and a repository at deploy, which the App reaches."""
        self.box2()
        crm = {"title": "Acme CRM", "url": "https://mcp.example.org/", "auth": "none"}
        status, answer = self.owner("/ui/team/mcp", base_sha256=self.team_sha(), name="crm", server=crm)
        self.assertEqual(status, 200, answer)
        with self.allows(), self.reaches("acme/web"):
            self.plan([{"kind": "add", "server": "box2", "names": ["nova"], "title": "Customer Support 2",
                        "runtime": "codex", "profile": SECTIONS,
                        "access": [{"resource": f"gmail:{self.MAIL}", "level": "send"},
                                   {"resource": f"drive:{self.MAIL}", "level": "read"},
                                   {"resource": "tool:crm", "level": "use"},
                                   {"resource": "repo:acme/web", "level": "deploy"}]}],
                      title="Add Support for the mailbox?")

    def test_a_press_reads_the_list_of_an_all_repositories_account_first(self):
        """The coordinator's validator, P2: a plan's repository of an account whose installation has all of its
        repositories passes only when the hub's list of the last minute names it, and the owner's press checks it
        again. Bug: after a quiet minute each press answers that the hub has not listed the repositories yet, and
        nothing lists them, so the card never goes through."""
        self.box2()
        whole = {"pages": {}, "all": {"acme"}, "repos": set(), "install": None}
        listed = {"acme": {"name": "acme", "repos": ["acme/web"]}}

        def listing():
            hub.GITHUB_REPOS.update(at=hub.now(), list=listed)
            return listed, None
        with patch.object(hub, "github_app", lambda: ("7", "key")), patch.object(hub, "github_repo_list", listing), \
                patch.dict(hub.GITHUB_REACH, {"at": hub.now(), "reach": whole, "reading": False}):
            with patch.dict(hub.GITHUB_REPOS, {"at": hub.now(), "list": listed}):
                self.plan([{"kind": "add", "server": "box2", "names": ["nova"], "title": "Customer Support 2",
                            "runtime": "codex", "profile": SECTIONS,
                            "access": [{"resource": "repo:acme/web", "level": "read"}]}])
            with patch.dict(hub.GITHUB_REPOS, {"at": 0.0, "list": None, "failed": 0.0, "reading": None}), \
                    patch.object(hub, "team_plan_end"):
                status, answer = self.press(0)          # a minute later: the list is old
        self.assertEqual(status, 200, answer)
        self.assertEqual(self.origin_team()["agents"]["nova"]["repos"], {"acme/web": "read"})

    def test_an_add_gives_its_new_agent_the_access_of_its_plan_with_the_press(self):
        """Bug: the owner presses yes on an agent for a mailbox, and the agent comes without it, so the owner must find
        the Access card again (a customer of 21 November 2026, whose one agent was the manager); or the card and its
        yes do not show that the press gives it; or the grant lands in a second commit, or with no record that names
        the owner's press and the plan's commit, so the owner's Access page cannot say who gave it; or a second run of
        the steps after the commit writes a grant's record again, also after the owner took the grant back."""
        mail = self.MAIL
        self.mailbox_plan()
        card = self.card()
        self.assertEqual(json.loads(card["options"])[0], "Yes: add Nova, Customer Support 2, on box2, with Gmail, "
                                                         "Drive, an MCP server and a repository")
        for line in (f"Gmail of {mail} (send)", f"Google Drive of {mail} (read)", "the MCP server Acme CRM (use)",
                     "the GitHub repository acme/web (write and deploy)"):
            self.assertIn(f"- The new agent gets {line}, which your yes gives it.", card["details"])
        before = self.head()
        with self.allows(), self.reaches("acme/web"), patch.object(hub, "team_plan_end"):   # its mark stays: the
            # steps after the commit run again below
            status, answer = self.press(0)
        self.assertEqual(status, 200, answer)
        nova = self.origin_team()["agents"]["nova"]
        self.assertEqual((nova["google"], nova["repos"], nova["tools"]),
                         ({"drive": {"account": mail, "level": "read"}, "gmail": {"account": mail, "level": "send"}},
                          {"acme/web": "deploy"}, ["crm"]))
        self.assertEqual(git("--git-dir", str(self.root / "origin.git"), "rev-list", "--count", f"{before}..main"), "1")
        commit = self.commits_of(card["id"])[0]
        given = [(f"gmail:{mail}", "send", "owner", commit), (f"drive:{mail}", "read", "owner", commit),
                 ("tool:crm", "use", "owner", commit), ("repo:acme/web", "deploy", "owner", commit)]
        rows = "SELECT resource, level, by, revision FROM resource_grants WHERE agent='nova' ORDER BY id"
        self.assertEqual([tuple(r) for r in hub.q(rows)], given)
        made = self.told("made your plan")["text"]
        self.assertIn(f"It holds Gmail of {mail}, Google Drive of {mail}, the MCP server Acme CRM, the GitHub "
                      f"repository acme/web from its first task session", made)
        self.assertIn(hub.DEPLOY_APP_NOTE[1:], made)       # deploy also needs the owner's step on GitHub
        status, answer = self.owner("/ui/resources/take", resource=f"gmail:{mail}", agent="nova")
        self.assertEqual(status, 200, answer)
        hub.team_plans_pressed()            # the steps after the commit once more, as after a stop
        self.assertEqual([tuple(r) for r in hub.q(rows)],
                         given + [(f"gmail:{mail}", None, "owner", answer["revision"])])
        self.assertEqual(self.stands(), (hub.TEAM_MADE, None))

    def test_no_access_lands_when_the_press_cannot_make_the_plan(self):
        """Bug: the press gives the new agent's mailbox although the account no longer allows Gmail, or although the
        add itself is not made, so an agent holds what no card of the owner's made, or a grant's record stands for a
        hold that nobody has. And a Google file that the hub cannot read for a minute closes the owner's card for
        good, as if the account had gone."""
        self.mailbox_plan()
        before = self.head()
        with self.allows(bad="unreadable"), self.reaches("acme/web"):
            status, answer = self.press(0)
        self.assertEqual(status, 409, answer)
        self.assertIn("cannot make this change now: the hub cannot read its Google file now", answer["error"])
        self.assertIsNone(self.card()["answer"])
        with self.allows(services=("drive",)), self.reaches("acme/web"):
            status, answer = self.press(0)
        self.assertEqual(status, 409, answer)
        self.assertEqual(self.head(), before)
        self.assertNotIn("nova", self.origin_team()["agents"])
        self.assertIsNone(hub.q1("SELECT 1 FROM resource_grants WHERE agent='nova'"))
        self.assertEqual(self.card()["answer"], hub.TEAM_CLOSED_WORDS)

    def test_the_manager_hears_what_to_do_with_an_app_only_while_no_agent_can_hold_it(self):
        """Bug: the hub's line of a Connect says nothing in a fleet whose one agent is the manager, which holds no app,
        so a connected mailbox waits for nobody (a customer of 21 November 2026); or it tells the manager to add an
        agent although a worker could hold it; or it repeats at each change of a server. And the same dead end at the
        other doors: a grant to the manager, the owner's standing of a resource, and an access card that the owner
        could give to nobody, also one in plain words, end with no step; or a step names what a plan then refuses
        (one of the product's own repositories, a repository with no App that reaches it), so the manager is sent
        between two refusals; or a login or an MCP server with a key, which no plan gives, gets no step at all."""
        alone = {"agents": {"manager": {"role": "manager"}}}
        said = hub.team_no_holder_words(["gmail:a@example.com", "drive:a@example.com"], alone)
        self.assertEqual(said, " You cannot use it, and the fleet has no agent yet that can: propose an agent for its "
                               "work with change_team, with what the work needs of gmail:a@example.com and "
                               "drive:a@example.com in the new agent's access. Ask the owner what the work is first "
                               "only when the owner's words do not say it.")
        login = "secret:bws://11111111-2222-4333-8444-55555555555d"
        self.assertIn(f"change_team; once it is there, give it {login} with grant_access, or, when the pool does not "
                      f"hold it, ask the owner with raise_needs_you (needs_access {login}), whose Mac signs that grant.",
                      hub.team_no_holder_for(login, dict(alone, logins={login[7:]: {"title": "Shop"}})))
        self.assertEqual(hub.team_no_holder_words(["gmail:a@example.com"]), "")      # scout and vps are workers
        # the owner's own route of a new MCP server says it once, with the access that a plan can give; a server that
        # signs in says it at its Connect instead, and a change of a server repeats nothing
        nobody = patch.object(hub, "grant_fits", lambda agent, entry, team=None: False)
        local = {"title": "Notes", "command": "notes-mcp", "runtimes": ["codex"]}
        oauth = {"title": "Acme CRM", "url": "https://mcp.example.org/", "auth": "oauth"}
        with nobody:
            for name, server in (("notes", local), ("crm", oauth), ("notes", dict(local, title="Notes 2"))):
                status, answer = self.owner("/ui/team/mcp", base_sha256=self.team_sha(), name=name, server=server)
                self.assertEqual(status, 200, answer)
        lines = [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND text LIKE "
                                          "'%changed the MCP server%' ORDER BY id")]
        self.assertEqual([("You cannot use it" in x, "with what the work needs of tool:notes in" in x) for x in lines],
                         [(True, True), (False, False), (False, False)])
        step = "You cannot use it, and the fleet has no agent yet that can: propose an agent for its work with " \
               "change_team, with what the work needs of {} in the new agent's access."
        with nobody, self.allows(services=("gmail",)), self.reaches("acme/new"):
            # a grant to the manager, an access card that nobody could take, in plain words too, and the standing
            with self.assertRaises(hub.ToolError) as refused:
                hub.grant_check("manager", f"gmail:{self.MAIL}", "read")
            self.assertIn("You never grant to yourself. " + step.format(f"gmail:{self.MAIL}"), str(refused.exception))
            # the App reaches acme/new, so the pool default covers it: the words end in a step only where no agent
            # could take it, which grant_check says as grant_fits does in a real fleet
            with patch.object(hub, "grant_check", side_effect=hub.ToolError("no agent can take it")):
                self.assertIn("Not raised: no agent of the fleet can hold the GitHub repository acme/new "
                              "(repo:acme/new). " + step.format("repo:acme/new"),
                              hub.card_access("repo:acme/new", "write") or "")
            # a repository that only the App reaches: the default gives read (DEFAULT_TOP), so read is the manager's
            self.assertIn('is yours to give: grant_access(agent="<the agent that needs it>", resource="repo:acme/new", '
                          'level="read")', hub.card_access("repo:acme/new", "read") or "")
            self.assertIn(f"needs_access names gmail:{self.MAIL} in words. Give it as gmail:{self.MAIL}",
                          hub.card_access(f"Gmail of {self.MAIL} for the support work", None) or "")
            # the service that the words say, though the account allows only the other one: card_dead then sends it
            # to the owner, who connects that service
            self.assertIn(f"needs_access names drive:{self.MAIL} in words",
                          hub.card_access(f"the Drive of {self.MAIL}", None) or "")
            status, answer = self.owner("/ui/resources", base_sha256=self.team_sha(),
                                        resource=f"gmail:{self.MAIL}", policy={"max": "read"})
            self.assertEqual(status, 200, answer)
            self.assertIn(step.format(f"gmail:{self.MAIL}"), self.told("changed the standing")["text"])
            # what a plan refuses names no step: the product's own repository; and a repository that the App does
            # not reach sends its card up, the owner's step first
            with self.assertRaises(hub.ToolError) as refused:
                hub.grant_check("manager", f"repo:{door_targets.VENDOR_REPOS[0]}", "read")
            self.assertNotIn("You cannot use it", str(refused.exception))
            self.assertIsNone(hub.card_access("repo:acme/other", "write"))
        with nobody:                    # no GitHub App: the card goes up, for the owner to connect GitHub
            self.assertIsNone(hub.card_access("repo:acme/new", "write"))
        with nobody, patch.object(hub, "google_services_now", lambda: ({"drive@example.com": ("gmail",)}, None)):
            self.assertIn("needs_access names gmail:drive@example.com in words",       # "drive" in the address
                          hub.card_access("the inbox of drive@example.com", None) or "")
        # with workers too: a repository that the App's reading does not reach goes up, though the pool would let
        # the manager give it, because no holder could use it
        status, answer = self.owner("/ui/resources", base_sha256=self.team_sha(), resource="repo:acme/other",
                                    policy={"max": "write"})
        self.assertEqual(status, 200, answer)
        with self.reaches("acme/other"):
            self.assertIn("is yours to give", hub.card_access("repo:acme/other", "write") or "")
        with self.reaches("acme/new"):
            self.assertIsNone(hub.card_access("repo:acme/other", "write"))
        self.assertIsNone(hub.card_access("repo:acme/other", "write"))     # and with no GitHub App at all
        # a GitHub App file that the hub cannot read never breaks a card or a grant of a fleet with workers
        def broken():
            raise hub.GitHubError("the App's file has the wrong mode")
        with patch.object(hub, "github_app", broken):
            self.assertIn("is yours to give", hub.card_access("repo:acme/other", "write") or "")
            with self.assertRaises(hub.ToolError) as refused:
                hub.grant_check("manager", "repo:acme/other", "read")
            self.assertNotIn("You cannot use it", str(refused.exception))

    def test_a_fold_names_its_removal_and_lands_in_one_commit(self):
        """Bug: the yes of a fold reads as a line change while it removes an agent, or it says the line change as a
        count ("and 1 more change", which the owner could not read on 26 November 2026), or the removal comes before
        the move of the agents that report to it, or the two parts land apart."""
        team, sha, lines = hub.team_view(hub.kit_revision(fresh=True))
        hub.save_lines(sha, [dict(line, reports_to="lead") if line["agent"] == "scout" else line for line in lines])
        with self.assertRaises(hub.ToolError) as refused:
            self.plan([{"kind": "remove", "agent": "lead"}])
        self.assertIn("Change the reporting lines first", str(refused.exception))
        self.plan([{"kind": "lines", "lines": [{"agent": "scout", "role": "worker"}]},
                   {"kind": "remove", "agent": "lead"}], title="Fold the lead?")
        self.assertEqual(json.loads(self.card()["options"]), ["Yes: remove Lead; also make Scout report to Manager", "No"])
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
        hears of. Owner API 1.280: or the card of a plan that a stop cut says made, or nothing, while the hub still
        tries it; or a stop between the two writes of the plan's end takes its mark away and leaves its card at
        making, which no later pass can end."""
        self.add_plan()
        nid = self.card()["id"]
        self.assertEqual(json.loads(self.card()["options"]),
                         ["Yes: add Nova, Customer Support 2, on box2", "Yes: add Lia, Customer Support 2, on box2", "No"])
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
        self.assertEqual(self.stands(), (hub.TEAM_MAKING, None))
        real_kv_set = hub.kv_set

        def stop_after_the_job(key, value):
            if key.startswith(hub.TEAM_PLAN_JOB):       # the write right after the install job's row
                raise RuntimeError("the hub stopped after the job")
            return real_kv_set(key, value)
        with patch.object(hub, "kv_set", side_effect=stop_after_the_job):
            hub.team_plans_pressed()        # the next start, which stops after the install job
        self.assertEqual(self.stands(), (hub.TEAM_MAKING, None))
        hub.q("CREATE TRIGGER stop_at_the_end BEFORE UPDATE OF team_state ON needs WHEN NEW.team_state='made' "
              "BEGIN SELECT RAISE(ABORT, 'the hub stopped at the end'); END")
        hub.team_plans_pressed()            # a stop in the write of the plan's end: the mark stays with its card
        self.assertEqual(self.stands(), (hub.TEAM_MAKING, None))
        self.assertEqual(json.loads(hub.kv_get(hub.TEAM_PLAN_MARK + str(nid)) or "{}").get("step"), "committed")
        hub.q("DROP TRIGGER stop_at_the_end")
        hub.team_plans_pressed()            # and the pass after it
        self.assertEqual(self.stands(), (hub.TEAM_MADE, None))
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
        did not show. Owner API 1.280: or the card of the plan that the hub then drops stays at making, or says made;
        or the owner reads the manager's words for the reason, with its codes."""
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
        self.assertEqual(self.stands(), (hub.TEAM_NOT_MADE, "The hub did not make this change: the fleet changed after "
                                                             "your yes. Nothing changed, and Manager knows."))

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
        the steps after it run on a team where the plan never happened. Owner API 1.280: or the end of such a plan
        clears its mark and leaves its card at making, which then turns for ever, or the card says made for a change
        that is not in the fleet."""
        self.plan([{"kind": "remove", "agent": "scout"}])
        nid = self.card()["id"]
        with patch.object(hub, "team_plan_after", side_effect=RuntimeError("the job table is locked")):
            status, answer = self.press(0)          # its commit is made, and the steps after it wait
        self.assertEqual(status, 200, answer)
        self.assertEqual(self.stands(), (hub.TEAM_MAKING, None))
        made = self.commits_of(nid)[0]
        self.assertEqual(hub.team_plan_commit_of(nid), made)
        for made_now in (False, True, False):       # the hub's undo, a person's undo of it, the hub's undo again
            git("revert", "--no-edit", "HEAD", cwd=self.kit)
            hub._revision_cache.update(at=0.0, value=None)
            self.assertEqual(hub.team_plan_commit_of(nid), made if made_now else None)
            self.assertEqual(hub.team_plan_commit_of(nid, made), made if made_now else None)
        self.assertIsNone(hub.team_plan_commit_of(nid, "0" * 40))      # a commit that the ref does not have
        hub.team_plans_pressed()                    # the next pass finds the plan undone, and stops it
        self.assertIsNone(hub.kv_get(hub.TEAM_PLAN_MARK + str(nid)))
        self.assertIsNone(hub.q1("SELECT 1 FROM server_jobs WHERE agent='scout' AND kind='remove'"))
        self.assertIn("is not in the configuration any more", self.told("The commit of the plan")["text"])
        self.assertEqual(self.stands(), (hub.TEAM_NOT_MADE, "The hub did not finish this change: it was undone in the "
                                                             "fleet's configuration, and Manager knows."))

    def test_a_committed_plan_is_never_dropped(self):
        """Bug: a plan whose commit is in team.json is dropped after its last try, and its new agent never gets its
        install. Owner API 1.280: or its card says not made at that try, while the hub goes on; or the card of a plan
        that was pressed under the release before, and still waits, shows the check while the hub makes it."""
        self.add_plan()
        nid = self.card()["id"]
        with patch.object(hub, "team_plan_after", side_effect=RuntimeError("the job table is locked")):
            status, answer = self.press(0)
            key = hub.TEAM_PLAN_MARK + str(nid)
            mark = json.loads(hub.kv_get(key))
            self.assertEqual(mark["step"], "committed")
            hub.kv_set(key, json.dumps(dict(mark, tries=hub.TEAM_PLAN_TRIES - 1)))
            hub.q("UPDATE needs SET team_state=NULL WHERE id=?", (nid,))    # as the release before left its card
            hub.team_plans_pressed()
        self.assertEqual(status, 200, answer)
        self.assertEqual(json.loads(hub.kv_get(key))["tries"], hub.TEAM_PLAN_TRIES)
        self.assertIn("its commit is made", self.told("waits")["text"])
        self.assertEqual(self.stands(), (hub.TEAM_MAKING, None))
        hub.team_plans_pressed()
        self.assertIsNone(hub.kv_get(key))
        self.assertEqual(self.stands(), (hub.TEAM_MADE, None))
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
        for ever and every new plan of the manager's is refused. Owner API 1.280: or the card of the plan that the hub
        stops there turns for ever; or the owner reads a program's words for the fault ("Refusal: ..."), or reads no
        cause where the hub has words of its own for the owner."""
        self.plan([{"kind": "remove", "agent": "scout"}])
        key = hub.TEAM_PLAN_MARK + str(self.card()["id"])
        refused = hub.Refusal(409, "the hub checkout has local changes")
        with patch.object(hub, "commit_kit_file", side_effect=refused):
            self.press(0)
            hub.kv_set(key, json.dumps(dict(json.loads(hub.kv_get(key)), tries=hub.TEAM_PLAN_TRIES - 1)))
            self.assertEqual(self.stands(), (hub.TEAM_MAKING, None))
            hub.team_plans_pressed()
        self.assertIsNone(hub.kv_get(key))
        self.assertIn("could not be made", self.told("pressed on")["text"])
        self.assertIn("scout", self.origin_team()["agents"])
        self.assertEqual(self.stands(), (hub.TEAM_NOT_MADE, f"The hub did not make this change: it stopped after "
                                                             f"{hub.TEAM_PLAN_TRIES} tries. Nothing changed, and "
                                                             f"Manager knows."))
        # a fault that can pass by itself has the hub's own words for the owner: the card says them, and none of the
        # words that the manager reads
        self.plan([{"kind": "remove", "agent": "scout"}], title="Remove scout now?")
        key = hub.TEAM_PLAN_MARK + str(self.card()["id"])
        with patch.object(hub, "commit_kit_file", side_effect=refused):
            self.press(0)
        hub.kv_set(key, json.dumps(dict(json.loads(hub.kv_get(key)), tries=hub.TEAM_PLAN_TRIES - 1)))
        busy = hub.TeamPassing("A job runs on box (job 4): wait for it.", "box runs another job now")
        with patch.object(hub, "team_plan_effect", side_effect=busy):
            hub.team_plans_pressed()
        self.assertIsNone(hub.kv_get(key))
        self.assertEqual(self.stands(), (hub.TEAM_NOT_MADE, f"The hub did not make this change: it stopped after "
                                                             f"{hub.TEAM_PLAN_TRIES} tries, the last time because box "
                                                             f"runs another job now. Nothing changed, and Manager "
                                                             f"knows."))

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
        the owner's pool, or a new agent on a key account, whose key's grant only the owner's Mac signs. And a new
        agent's access (team_add_access) that gives what the fleet does not hold: a mailbox that nobody connected for
        Gmail, an MCP server that the fleet does not have, one whose key only the owner's Mac grants, a login or a
        server, which only the owner's own routes give, one of the product's own repositories, or a level that its
        kind has not."""
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

        def refused_access(access):
            with self.assertRaises(hub.ToolError) as refused:
                self.plan([{"kind": "add", "server": "box2", "names": ["nova"], "title": "Customer Support 2",
                            "runtime": "codex", "profile": SECTIONS, "access": access}])
            self.assertNotIsInstance(refused.exception, hub.TeamPassing)
            return str(refused.exception)
        with patch.object(hub, "google_services_now", lambda: ({"support@example.com": ("drive",)}, None)):
            self.assertIn("The Google account support@example.com does not allow Gmail now",
                          refused_access([{"resource": "gmail:support@example.com", "level": "read"}]))
        self.assertIn("The fleet does not hold the MCP server ghost",
                      refused_access([{"resource": "tool:ghost", "level": "use"}]))
        # a key server, also before the catalog holds its key: its holder would start without the server
        shop = {"title": "Shop", "url": "https://shop.example.com/mcp", "auth": "key", "key": "SHOP_KEY"}
        status, answer = self.owner("/ui/team/mcp", base_sha256=self.team_sha(), name="shop", server=shop)
        self.assertEqual(status, 200, answer)
        self.assertIn("The MCP server Shop needs a key, whose grant the owner's Mac signs",
                      refused_access([{"resource": "tool:shop", "level": "use"}]))
        for rid in ("secret:bws://11111111-2222-4333-8444-55555555555b", "server:box"):
            self.assertIn("Give a login with grant_access once the agent is there",
                          refused_access([{"resource": rid, "level": "use"}]))
        self.assertIn("The door refuses", refused_access([{"resource": f"repo:{door_targets.VENDOR_REPOS[0]}",
                                                           "level": "read"}]))
        self.assertIn("The fleet has no GitHub App, so no agent can use acme/web",
                      refused_access([{"resource": "repo:acme/web", "level": "read"}]))
        with self.reaches("acme/web"):
            self.assertIn("The fleet's GitHub App does not reach acme/typo. Ask the owner with raise_needs_you "
                          "(needs_access repo:acme/typo) to add it at "
                          "https://github.com/organizations/acme/settings/installations/7",
                          refused_access([{"resource": "repo:acme/typo", "level": "read"}]))
        # an account whose installation has all of its repositories: only a name that the hub's list holds, so a plan
        # carries no invented name, whose token request would fail for each repository of the account there (the
        # coordinator's validator). Bug: acme/typo passes by its account alone
        whole = {"pages": {}, "all": {"acme"}, "repos": set(), "install": None}
        with patch.object(hub, "github_app", lambda: ("7", "key")), \
                patch.object(hub, "github_repo_list", lambda: ({}, "not now")), \
                patch.dict(hub.GITHUB_REACH, {"at": hub.now(), "reach": whole, "reading": False}):
            with patch.dict(hub.GITHUB_REPOS, {"at": hub.now(), "list": {"acme": {"name": "acme", "repos": ["acme/web"]}}}):
                self.assertIn("GitHub lists no repository acme/typo of acme, whose every repository the fleet's GitHub "
                              "App reaches: it does not exist, or it is archived",
                              refused_access([{"resource": "repo:acme/typo", "level": "read"}]))
            # with no list of the last minute (a door that cannot list), only a missing name is refused: a plan never
            # waits for a list that may not come (the rule agreed with the Needs-you area)
            with patch.dict(hub.GITHUB_REPOS, {"at": 0.0, "list": None}):
                self.assertIsNone(hub.team_repo_refusal("acme/web"))
        # A name that the list of an account that the App reaches whole does not hold does not exist, and the call reads
        # that list first (github_repo_ahead). Bug: a guessed name goes up on the owner's plan card (the owner's card
        # N-327, 26 November 2026), and their Yes grants a repository that does not exist.
        listed = ({"beta": {"name": "beta", "repos": ["beta/site"]}}, [])
        with self.reaches(whole={"beta": ["beta/site"]}), \
                patch.dict(hub.GITHUB_REPOS, {"at": 0.0, "failed": 0.0, "reading": None}), \
                patch.object(hub, "github_repos_read", return_value=listed):
            said, error = hub.call_tool("manager", "change_team", {
                "request_id": str(uuid.uuid4()), "title": "Change the team?", "why": "The records show the need.",
                "changes": [{"kind": "add", "server": "box2", "names": ["nova"], "title": "Customer Support 2",
                             "runtime": "codex", "profile": SECTIONS,
                             "access": [{"resource": "repo:beta/ghost", "level": "read"}]}]})
        self.assertTrue(error, said)
        self.assertIn("GitHub lists no repository beta/ghost of beta, whose every repository the fleet's GitHub App "
                      "reaches: it does not exist, or it is archived. Check its name, then write the plan again.", said)
        with self.reaches(read=False), self.assertRaises(hub.TeamPassing) as waits:     # before its first reading
            self.plan([{"kind": "add", "server": "box2", "names": ["nova"], "title": "Customer Support 2",
                        "runtime": "codex", "profile": SECTIONS,
                        "access": [{"resource": "repo:acme/web", "level": "read"}]}])
        self.assertEqual(waits.exception.owner, "the hub has not read its GitHub App yet")
        crm = {"title": "Acme CRM", "url": "https://mcp.example.org/", "auth": "oauth"}
        status, answer = self.owner("/ui/team/mcp", base_sha256=self.team_sha(), name="crm", server=crm)
        self.assertEqual(status, 200, answer)
        self.assertIn("The MCP server Acme CRM is not connected, so no session gets it",
                      refused_access([{"resource": "tool:crm", "level": "use"}]))
        # what the hub cannot read now passes by itself, and keeps a card: its file of MCP connections, and a GitHub
        # App file that it cannot read
        def broken():
            raise hub.GitHubError("the App's file has the wrong mode")
        for patched, owner in ((patch.object(hub, "mcp_saved", lambda: ({}, "unreadable")), "tool:crm"),
                               (patch.object(hub, "github_app", broken), "repo:acme/web"),
                               (patch.dict(hub.TEAM, {"door": {"address": "100.64.0.9"}}), "repo:acme/web")):
            with patched, self.assertRaises(hub.TeamPassing):
                self.plan([{"kind": "add", "server": "box2", "names": ["nova"], "title": "Customer Support 2",
                            "runtime": "codex", "profile": SECTIONS, "access": [{"resource": owner, "level":
                                                                                  "use" if owner[0] == "t" else "read"}]}])
        with patch.object(hub, "google_services_now", lambda: ({"a@example.com": ("gmail",),
                                                                "b@example.com": ("gmail",)}, None)):
            self.assertIn("access names two accounts for Gmail", refused_access(
                [{"resource": "gmail:a@example.com", "level": "read"},
                 {"resource": "gmail:b@example.com", "level": "read"}]))
        catalog = {"minted": {"custom": True, "auth": "mint"}, "program": {"custom": True, "auth": "none",
                                                                           "env": {"API_KEY": "SHOP_KEY"}},
                   "plain": {"custom": True, "auth": "none"}, "fleet": {"custom": False, "auth": "none"}}
        with patch.object(hub, "tool_catalog", lambda team, refused=None: catalog):
            self.assertEqual([hub.team_tool_keyed(n) for n in catalog], [True, True, False, False])
        self.assertIn("is one of read, write", refused_access([{"resource": "repo:acme/web", "level": "admin"}]))
        with self.reaches("acme/web"):
            self.assertIn("access names repo:acme/web twice", refused_access(
                [{"resource": "repo:acme/web", "level": "read"}, {"resource": "repo:acme/web", "level": "write"}]))
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
        # a key in the manager's new text: every agent that reads the file would read it (owner API 1.335)
        before = "# Brand\n\nSource: brand.pdf · added 2026-10-01\n\nBlue.\n".encode()
        with patch.object(hub, "knowledge_entries", lambda: listed), patch.object(hub, "git_blob", lambda rev, path: before), \
                self.assertRaises(hub.ToolError) as refused:
            hub.team_owner_file({"rev": "r" * 40, "team": hub.TEAM},
                                dict(step, base_sha256=hub.hashlib.sha256(before).hexdigest(),
                                     text="# Brand\n\nThe key: sk-proj-" + "Q3vT9xLm2NpR7sKw4YbZ8cHj6FdA1eGu\n"))
        self.assertIn("holds what looks like a key", str(refused.exception))
        # and one that a control character hides in an address's path: the hub saves it as a space, so the saved
        # file holds the run as a word of its own (the three-copy validator, 25 November 2026)
        hidden = "# Brand\n\nhttps://example.com/files/" + chr(0x1F) + "Xk7Qp2Lm9Rt4Vb8Nc3Wz6Hd1Jf5Gs0Ya\n"
        with patch.object(hub, "knowledge_entries", lambda: listed), \
                patch.object(hub, "git_blob", lambda rev, path: before), self.assertRaises(hub.ToolError) as refused:
            hub.team_owner_file({"rev": "r" * 40, "team": hub.TEAM},
                                dict(step, base_sha256=hub.hashlib.sha256(before).hexdigest(), text=hidden))
        self.assertIn("holds what looks like a key", str(refused.exception))
        # the catalog stops being readable after the plan's own read: the 503 of the room check in knowledge_replaced
        # passes by itself too, and closes no card (lanes/knowledge-list-on-a-failed-read.md)
        before = "# Brand\n\nSource: brand.pdf · added 2026-10-01\n\nBlue.\n".encode()
        reads = iter([listed, hub.UnreadCatalog()])
        with patch.object(hub, "knowledge_entries", lambda: next(reads)), \
                patch.object(hub, "git_blob", lambda rev, path: before), self.assertRaises(hub.TeamPassing):
            hub.team_owner_file({"rev": "r" * 40, "team": hub.TEAM},
                                dict(step, base_sha256=hub.hashlib.sha256(before).hexdigest()))
        # a reader's profile that git does not give now passes by itself too: it would drop that agent from the
        # readers, and so change the digest that the press compares (knowledge_readers, strict)
        with patch.object(hub, "knowledge_entries", lambda: [dict(listed[0], bytes=len(before))]), \
                patch.object(hub, "git_blob", lambda rev, path: before), self.not_given("profiles/vps.md"), \
                self.assertRaises(hub.TeamPassing):
            hub.team_owner_file({"rev": "r" * 40, "team": hub.TEAM, "files": {}, "access": [], "parts": [],
                                 "facts": [], "said": [], "phrases": []},
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
        """Bug: the owner says yes to a change that the card cut. Or a reason over 140 characters (P7 section 5)
        reaches the card, or its refusal sends the manager to details, which change_team does not take."""
        long = "Every sentence of this text is a rule that the agent follows when it answers. " * 90
        with self.assertRaises(hub.ToolError) as refused:
            self.plan([{"kind": "profile", "agent": "vps", "base_sha256": self.base_of("vps"),
                        "sections": [{"key": "responsible_for", "title": "Responsible for", "text": long},
                                     {"key": "character", "title": "Character", "text": long}]}])
        self.assertIn("cannot show this plan whole", str(refused.exception))
        self.assertIsNone(self.card())
        with self.assertRaises(hub.ToolError) as refused:
            self.plan([{"kind": "profile", "agent": "vps", "base_sha256": self.base_of("vps"),
                        "sections": [{"key": "character", "title": "Character", "text": "Careful."}]}],
                      why="w " * 70 + "w")
        self.assertIn("why is at most 140 characters", str(refused.exception))
        self.assertIn("Put the evidence in words, which the card shows under the hub's Details. This one has 141.",
                      str(refused.exception))
        self.assertNotIn("in details", str(refused.exception))
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
        by side, or the card that a new plan replaced does not name it, so an app draws it, or the owner's talk stays
        on that card, which no app draws (owner API 1.274)."""
        args = {"request_id": str(uuid.uuid4()), "title": "Remove scout?", "why": "Its work moved.",
                "changes": [{"kind": "remove", "agent": "scout"}]}
        first = hub.t_change_team("manager", dict(args))
        self.assertEqual(hub.t_change_team("manager", dict(args)), first)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM needs WHERE team_plan IS NOT NULL")["n"], 1)
        old = self.card()["id"]
        hub.q("INSERT INTO need_talk(need, ts, who, text) VALUES(?, ?, 'owner', 'Why scout?')", (old, hub.now()))
        self.plan([{"kind": "settings", "agent": "vps", "title": "Deploys"}], title="Name the VPS agent Deploys?")
        self.assertEqual([t["text"] for t in hub.need_talk(self.card()["id"])], ["Why scout?"])    # his talk moves
        self.assertIn(f"Replaced by {hub.shown_role('manager')}", hub.q1("SELECT answer FROM needs WHERE id=?", (old,))["answer"])
        self.assertEqual(hub.q1("SELECT replaced_by FROM needs WHERE id=?", (old,))["replaced_by"], self.card()["id"])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM needs WHERE team_plan IS NOT NULL AND answer IS NULL")["n"], 1)


if __name__ == "__main__":
    unittest.main()
