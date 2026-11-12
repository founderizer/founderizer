"""Who can take work now: one authority function, the owner's accounts and the secret catalog, and the capacity
view that the owner's route and see_capacity both answer. In-process hub and temporary Git repositories; no helper,
vault, fleet or AI calls."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.parse
import uuid

import hub
from test_ui_api import OwnerAPI

LOGIN_A = "bws://11111111-2222-4333-8444-55555555555b"
LOGIN_B = "bws://21111111-2222-4333-8444-55555555555b"
ARMORED = "-----BEGIN AGE ENCRYPTED FILE-----\nlocked\n-----END AGE ENCRYPTED FILE-----\n"
SHARED, DEVA, SEO, MANAGER = ("openai:" + "a" * 32, "openai:" + "b" * 32, "anthropic:" + "c" * 32, "anthropic:" + "d" * 32)
CODEX = "codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}"
TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3", "w2": "127.0.0.9",
                      "pa": "127.0.0.6", "pb": "127.0.0.7", "w4": "127.0.0.8"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   "pma": {"role": "lead", "runtime": "codex", "machine": "pa", "can": ["shell"], "start": CODEX},
                   "pmb": {"role": "lead", "runtime": "codex", "machine": "pb", "can": ["shell"], "start": CODEX},
                   "seo": {"role": "worker", "runtime": "claude", "machine": "vps", "can": ["shell", "web", "browser"],
                           "vault": "broker", "vault_recipient": "age1" + "q" * 58, "title": "SEO Expert",
                           "reports_to": "pma", "expertise": ["seo"]},
                   "deva": {"role": "worker", "runtime": "codex", "machine": "w2", "can": ["shell"], "start": CODEX,
                            "reports_to": "pma", "expertise": ["development"], "vault": "broker",
                            "vault_recipient": "age1" + "d" * 58},
                   "big": {"role": "worker", "runtime": "codex", "machine": "w4", "can": ["shell", "web"], "start": CODEX}}}


def profile(name, logins):
    return (f"# Profile: {name}\n\nWritten by the owner. Agents cannot change it.\n\n**Character.** Careful.\n\n"
            f"**Responsible for.** Its own work.\n\n**May do without asking.** Read files.\n\n"
            f"**Must ask first.** Spending.\n\n**Logins it may use.** " + ", ".join(f"`{x}`" for x in logins) + ".\n")


def git(*args, cwd=None):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(Capacity(name) for name in Capacity.__dict__ if name.startswith("test_"))


class Capacity(OwnerAPI):
    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp(prefix="fleet-capacity-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        seed = self.root / "seed"
        (seed / "profiles").mkdir(parents=True)
        (seed / "team.json").write_text(json.dumps(TEAM, indent=2) + "\n")
        (seed / "profiles" / "seo.md").write_text(profile("seo", [LOGIN_A, LOGIN_B]))
        (seed / "profiles" / "deva.md").write_text(profile("deva", [LOGIN_A]))
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
        hub.CFG.update(silence=180, question_wait=120, manager_silence=120, stop_after=60, offline_after=90, tick=5,
                       ask_wait=1, ask_max=1, hook_wait=0.2, job_wait=0.05)
        allowed = patch.object(hub.Handler, "allowed", lambda handler, who, broker=False: True)   # all call from here
        allowed.start()
        self.addCleanup(allowed.stop)

    # ---- helpers
    def call(self, agent, name, args, task=None):
        context = ("test-generation", f"T-{task}", hub.q1("SELECT attempt FROM tasks WHERE id=?", (task,))["attempt"]) \
            if task else None
        return hub.call_tool(agent, name, args, context)

    def create(self, agent, owner, task=None, **fields):
        text, error = self.call(agent, "create_task", dict({"owner": owner, "title": f"Work for {owner}",
                                                            "done_when": "Done.", "why": "Its expertise."}, **fields), task)
        self.assertFalse(error, text)
        return hub.q1("SELECT MAX(id) id FROM tasks")["id"]

    def refused(self, agent, name, args, task=None):
        text, error = self.call(agent, name, args, task)
        self.assertTrue(error, text)
        return text

    def sha(self):
        return self.request("/ui/team?db=test-generation")[1]["sha256"]

    def parents(self):
        """Two task sessions of the lead pma, each with a subtask of its worker seo: (first, its subtask, second, its
        subtask). The tests that build on this fixture need one agent with two open tasks under one lead."""
        first = self.create("manager", "pma", why="pma leads seo")
        second = self.create("manager", "pma", why="pma leads seo")
        return first, self.create("pma", "seo", first), second, self.create("pma", "seo", second)

    # ---- authority
    def test_a_task_follows_the_reporting_line_and_only_the_agent_or_the_manager_sets_its_rules(self):
        cases = [(("pma", "deva", "task"), True, None),                           # deva reports to pma
                 (("pma", "seo", "task"), True, None),                            # and so does seo
                 (("pmb", "seo", "task"), False, "seo reports to pma"),
                 (("pma", "pma", "task"), False, "pma reports to manager"),       # never itself
                 (("manager", "big", "task"), True, None),
                 (("manager", "pma", "task"), True, None),
                 (("manager", "deva", "task"), False, "deva reports to pma"),
                 (("ghost", "seo", "task"), False, "not an agent of this team"),
                 (("seo", "seo", "rule"), True, None),
                 (("deva", "deva", "rule"), True, None),
                 (("seo", "deva", "rule"), False, "Only deva itself or manager"),
                 (("pma", "deva", "rule"), False, "Only deva itself or manager"),   # its lead is not its rule-setter
                 (("manager", "seo", "rule"), True, None),
                 (("manager", "ghost", "rule"), False, "There is no agent ghost")]
        for args, allowed, reason in cases:
            with self.subTest(args=args):
                ok, why = hub.authority(*args)
                self.assertEqual(ok, allowed, why)
                if reason:
                    self.assertIn(reason, why)
        with self.assertRaises(ValueError):
            hub.authority("manager", "seo", "code")

    def test_a_lead_acts_on_its_own_subtasks_while_it_still_has_authority(self):
        parent = self.create("manager", "pma")
        child = self.create("pma", "deva", parent)
        rows = {r["id"]: r for r in hub.q("SELECT * FROM tasks")}
        self.assertEqual((rows[child]["parent"], rows[child]["requester"], rows[child]["why"]),
                         (parent, "pma", "Its expertise."))
        self.assertIn("big reports to manager", self.refused("pma", "create_task", {
            "owner": "big", "title": "x", "done_when": "y", "why": "z"}, parent))
        other = self.create("manager", "big")
        self.assertIn("was not requested by you", self.refused("pma", "check_result", {
            "task_id": f"T-{other}", "accepted": True}, parent))
        overview = hub.lead_overview("pma", parent)
        self.assertIn("YOUR TEAM (pma)", overview)
        self.assertIn("deva: worker", overview)
        self.assertIn("seo: worker", overview)       # both of pma's workers
        self.assertNotIn("big:", overview)
        hub.TEAM["agents"]["deva"]["reports_to"] = "pmb"          # deva leaves pma's team
        self.assertIn("You can no longer act on", self.refused("pma", "cancel_task", {
            "task_id": f"T-{child}", "reason": "no longer needed"}, parent))
        self.assertEqual(hub.q1("SELECT state FROM tasks WHERE id=?", (child,))["state"], "submitted")

    # ---- remembered permissions
    def test_a_remembered_permission_lasts_while_its_decider_can_still_give_the_agent_work(self):
        parent = self.create("manager", "pma")
        child = self.create("pma", "deva", parent)
        pid = hub.ins("INSERT INTO prompts(task,agent,tool,input,key,created) VALUES(?,?,?,?,?,?)",
                      (child, "deva", "Bash", "make deploy", "k1", hub.now()))
        text, error = self.call("pma", "decide_permission", {"prompt_id": f"P-{pid}", "decision": "allow",
                                                             "always": True}, parent)
        self.assertFalse(error, text)
        rule = hub.q1("SELECT * FROM rules")
        self.assertEqual((rule["by"], rule["decision"]), ("pma", "allow"))
        self.assertEqual(hub.remembered("deva", "Bash", "k1")["id"], rule["id"])
        hub.TEAM["agents"]["deva"]["reports_to"] = "pmb"          # pma lost its authority over deva
        self.assertIsNone(hub.remembered("deva", "Bash", "k1"))
        legacy = hub.ins("INSERT INTO rules(agent,tool,key,input,decision) VALUES('deva','Bash','k2','ls','allow')")
        self.assertEqual(hub.remembered("deva", "Bash", "k2")["id"], legacy)       # no decider: it always applies

    # ---- credentials
    def test_a_login_needs_the_profile_or_the_owners_grant_on_a_machine_with_the_broker(self):
        parent = self.create("manager", "pma")
        child = self.create("pma", "deva", parent)
        task = lambda tid: hub.q1("SELECT * FROM tasks WHERE id=?", (tid,))
        self.assertIsNone(hub.login_refusal("deva", task(child), LOGIN_A))         # deva's profile has LOGIN_A
        self.assertIn("not in your profile", hub.login_refusal("deva", task(child), LOGIN_B))
        hub.TEAM["agents"]["deva"].pop("vault")                                    # file mode: the vault decides there
        self.assertIsNone(hub.login_refusal("deva", task(child), LOGIN_B))
        hub.TEAM["agents"]["deva"]["vault"] = "none"
        self.assertIn("no credential access", hub.login_refusal("deva", task(child), LOGIN_A))
        hub.TEAM["agents"]["deva"]["vault"] = "broker"
        hub.TEAM["agents"]["deva"]["can"] = ["shell", "browser"]            # the tool path says the same
        self.assertIn("not in your profile", self.refused("deva", "sign_in", {"login": LOGIN_B}, child))
        hub.TEAM["agents"]["big"]["vault"] = "none"
        self.assertIn("has no credential access", hub.login_refusal(
            "deva", task(child), LOGIN_A, "handover", "big"))                      # big may use no login

    def test_a_sealed_copy_is_bound_to_its_job_and_to_one_task(self):
        parent = self.create("manager", "pma")
        child = self.create("pma", "deva", parent)
        job = hub.ins("INSERT INTO jobs(agent,task,kind,login,target,created) VALUES('deva',?,?,?,'seo',?)",
                      (child, "handover", LOGIN_A, hub.now()))
        upload = dict(sender="deva", recipient="seo", task=f"T-{child}", label="a login", ciphertext=ARMORED)
        self.assertEqual(self.request("/sealed", upload)[0], 400)                  # no job: nothing is guessed
        self.assertEqual(self.request("/sealed", dict(upload, job=job + 1))[0], 404)
        code, data = self.request("/sealed", dict(upload, job=job))
        self.assertEqual(code, 200, data)
        sid = data["id"]
        row = hub.q1("SELECT login, job, task FROM sealed WHERE id=?", (sid,))
        self.assertEqual(tuple(row), (LOGIN_A, job, f"T-{child}"))
        self.assertEqual(self.request("/sealed", dict(upload, job=job))[0], 409)   # one copy for each job
        mine = self.create("pma", "seo", parent)
        code, data = self.request(f"/sealed/{sid}?agent=seo&task=T-{mine}")
        self.assertEqual((code, data["ciphertext"]), (200, ARMORED))
        self.assertEqual(hub.q1("SELECT bound_task FROM sealed WHERE id=?", (sid,))["bound_task"], mine)
        other = self.create("pma", "seo", parent)
        self.assertEqual(self.request(f"/sealed/{sid}?agent=seo&task=T-{other}")[0], 403)   # one task only
        self.assertEqual(self.request(f"/sealed/{sid}?agent=deva&task=T-{child}")[0], 403)  # not the recipient

    def test_a_sealed_copy_for_an_agent_that_left_meanwhile_is_not_kept(self):
        """deva hands a login over to seo, and seo leaves the fleet while that call waits for the hub's lock: the call
        looked both names up before it waited. The copy is refused as for any name that no agent has. It was kept,
        for the next agent of that name. A call that wrote its copy before seo left was in time."""
        parent = self.create("manager", "pma")
        child = self.create("pma", "deva", parent)
        job = hub.ins("INSERT INTO jobs(agent,task,kind,login,target,created) VALUES('deva',?,?,?,'seo',?)",
                      (child, "handover", LOGIN_A, hub.now()))
        upload = dict(sender="deva", recipient="seo", task=f"T-{child}", label="a login", ciphertext=ARMORED, job=job)
        back, written, seen = self.kept(), [], []

        def leaves():                       # as the owner's command leaves it: one new team, under the lock
            with hub.LOCK:
                written.append(self.count("sealed"))
                hub.TEAM["agents"] = {name: a for name, a in hub.agents().items() if name != "seo"}
        for n, answer in self.lock_waits(lambda: self.request("/sealed", upload), leaves, back):
            seen.append(written.pop())
            if seen[-1]:
                self.assertEqual(answer[0], 200, n)
            else:
                self.assertEqual((answer, self.count("sealed")), ((404, {"error": "unknown agent"}), 0), n)
        self.assertEqual(seen[:1], [0])     # seo left before the copy was written, at one moment or more

    # ---- owner routes and goals
    def test_a_team_json_that_still_names_a_project_is_read_and_its_projects_are_ignored(self):
        """The owner removed projects on 18 October 2026. A running fleet's file keeps working, and nothing reads it."""
        team = json.loads(json.dumps(TEAM))
        team["projects"] = {"shop": {"title": "Shop relaunch", "manager": "pma", "members": ["seo"],
                                     "logins": [LOGIN_A]}}
        self.assertIs(hub.validate_team(team), team)             # read as it is, never refused
        team["projects"] = {"anything": "the hub does not look"}
        self.assertIs(hub.validate_team(team), team)
        hub.TEAM = team
        code, view = self.request("/ui/team?db=test-generation")
        self.assertEqual(code, 200)
        self.assertNotIn("projects", view)                       # not answered
        self.assertNotIn("projects", next(l for l in view["lines"] if l["agent"] == "seo"))
        self.assertNotIn("projects", self.request("/ui/resources?db=test-generation")[1])
        self.assertNotIn("projects", self.request()[1]["ui_features"])
        self.assertEqual(self.request("/ui/team/projects", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                                base_sha256=self.sha(), project="shop"))[0], 404)
        tid = self.create("manager", "big")                      # work goes on, with no project anywhere
        self.assertIsNone(hub.q1("SELECT * FROM tasks WHERE id=?", (tid,)).keys().__contains__("project") or None)

    def test_owner_routes_keep_accounts_and_identity_valid(self):
        code, team = self.request("/ui/team?db=test-generation")
        self.assertEqual(code, 200)
        seo = next(l for l in team["lines"] if l["agent"] == "seo")
        self.assertEqual((seo["title"], seo["expertise"], seo["account"], seo["placement"]),
                         ("SEO Expert", ["seo"], None, {"machine": "vps", "runtime": "claude", "address": "127.0.0.3",
                                                        "shared_with": []}))
        account = dict(request_id=str(uuid.uuid4()), db="test-generation", base_sha256=self.sha(), account="codex-main",
                       provider="openai", title="Codex Pro (owner)")
        self.assertEqual(self.request("/ui/team/accounts", account)[0], 200)
        agent = dict(request_id=str(uuid.uuid4()), db="test-generation", base_sha256=self.sha(), account="codex-main",
                     title="Generalist", expertise=["development", "seo"])
        code, data = self.request("/ui/team/agents/big", agent)
        self.assertEqual(code, 200, data)
        self.assertEqual((hub.agents()["big"]["account"], hub.agents()["big"]["expertise"]), ("codex-main", ["development", "seo"]))
        code, data = self.request("/ui/team/accounts", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                            base_sha256=self.sha(), account="codex-main", delete=True))
        self.assertEqual((code, data["agents"]), (409, ["big"]))
        self.assertEqual(self.request("/ui/team/agents/big", dict(agent, request_id=str(uuid.uuid4()), base_sha256=self.sha(),
                                                                  account="nobody"))[0], 400)
        text, error = hub.call_tool("manager", "update_goal", dict(request_id=str(uuid.uuid4()), title="Launch ads",
                                                                   text="Run the launch."))
        self.assertFalse(error, text)
        self.assertNotIn("project", self.request()[1]["goals"][0])


    # ---- Add secret: the hub parts, without a value (owner feature secrets)
    def test_the_owner_labels_a_login_and_protects_its_value_without_sending_it(self):
        fresh = "bws://31111111-2222-4333-8444-55555555555b"
        shouted = fresh.upper().replace("BWS", "bws")              # one spelling for each reference
        digest = lambda salt, value: hashlib.sha256((salt + value).encode()).hexdigest()

        def label(login, **fields):
            body = dict(dict(request_id=str(uuid.uuid4()), db="test-generation", base_sha256=self.sha(), login=login),
                        **fields)
            return self.request("/ui/team/logins", body)

        self.assertIn("secrets", self.request()[1]["ui_features"])
        self.assertEqual(self.request("/ui/team?db=test-generation")[1]["logins"], {})
        for login, fields in ((fresh, {"title": ""}), (fresh, {"title": "x" * 61}), (fresh, {"title": "two\nlines"}),
                              (fresh, {}), (fresh, {"title": "Shop", "password": "x"}), ("bws://nope", {"title": "Shop"}),
                              ("sealed:4", {"title": "Shop"}), (7, {"title": "Shop"})):
            with self.subTest(login=login, fields=fields):
                self.assertEqual(label(login, **fields)[0], 400)
        code, receipt = label(shouted, title=" Shop admin ")
        self.assertEqual((code, receipt["login"], receipt["changed"], receipt["deleted"]), (200, fresh, True, False), receipt)
        self.assertEqual(json.loads((self.kit / "team.json").read_text())["logins"], {fresh: {"title": "Shop admin"}})
        self.assertEqual(self.request("/ui/team?db=test-generation")[1]["logins"],
                         {fresh: {"title": "Shop admin", "kind": "login", "protected": False, "grants": {},
                                  "deliveries": {}}})       # owner feature secret_deliveries: none yet
        self.assertEqual(label(fresh, title="Shop admin")[1]["changed"], False)       # the same label again
        renamed = dict(request_id=str(uuid.uuid4()), db="test-generation", base_sha256=self.sha(), login=fresh, title="Shop")
        self.assertEqual(self.request("/ui/team/logins", renamed)[1]["changed"], True)
        self.assertEqual(self.request("/ui/team/logins", renamed)[1]["replayed"], True)
        code, data = self.request("/ui/team/logins", dict(renamed, request_id=str(uuid.uuid4()), base_sha256="0" * 64))
        self.assertEqual((code, data["sha256"]), (409, self.sha()))
        self.assertNotIn(fresh, hub.granted_logins("seo"))                            # a label grants nothing
        # Protection: the salts of this reference, then fingerprints only. The value itself is never sent.
        code, salts = self.request("/ui/secrets/salts?db=test-generation&login=" + shouted)
        self.assertEqual((code, salts["login"], len(salts["password"]), len(salts["totp"])), (200, fresh, 32, 32))
        self.assertNotEqual(salts["password"], salts["totp"])
        self.assertEqual(self.request("/ui/secrets/salts?db=old&login=" + fresh)[0], 409)
        self.assertEqual(self.request("/ui/secrets/salts?db=test-generation&login=sealed:4")[0], 400)
        value, seed = "Pr4ct!ce-Login#2026", "JBSWY3DPEHPK3PXP"
        prints = [{"kind": "password", "hash": digest(salts["password"], value), "len": len(value)},
                  {"kind": "totp", "hash": digest(salts["totp"], seed), "len": len(seed)}]
        body = dict(request_id=str(uuid.uuid4()), db="test-generation", login=shouted, fingerprints=prints)
        for bad in (dict(body, value=value), dict(body, fingerprints=[]), dict(body, fingerprints=prints * 2),
                    dict(body, fingerprints=[dict(prints[0], len=7)]), dict(body, fingerprints=[dict(prints[0], hash="x")]),
                    dict(body, fingerprints=[prints[0], prints[0]]), dict(body, fingerprints=[dict(prints[0], salt="s")]),
                    dict(body, login="sealed:4")):
            self.assertEqual(self.request("/ui/secrets/fingerprints", dict(bad, request_id=str(uuid.uuid4())))[0], 400)
        self.assertFalse(hub.secret_hit("the password is " + value))
        code, receipt = self.request("/ui/secrets/fingerprints", body)
        self.assertEqual((code, receipt["login"], receipt["stored"], receipt["known"]), (200, fresh, 2, 0), receipt)
        self.assertEqual(self.request("/ui/secrets/fingerprints", body)[1]["replayed"], True)
        again = self.request("/ui/secrets/fingerprints", dict(body, request_id=str(uuid.uuid4())))[1]
        self.assertEqual((again["stored"], again["known"]), (0, 2))
        self.assertEqual(hub.register_fingerprints(shouted, prints), (0, 2))          # a vault's later registration
        self.assertTrue(hub.secret_hit("the password is " + value))
        self.assertNotIn(value, hub.mask_secrets("it is " + value + " today"))
        self.assertTrue(self.request("/ui/team?db=test-generation")[1]["logins"][fresh]["protected"])
        self.assertEqual(label(fresh, title=value)[0], 422)                           # nor as a label afterwards
        stored = json.dumps([dict(r) for r in hub.q("SELECT * FROM ui_controls")] + [dict(r) for r in hub.q("SELECT * FROM secrets")])
        self.assertNotIn(value, stored)
        self.assertNotIn(seed, stored)
        # A label stays while a profile or a grant lists the reference. Removing a label removes no protection.
        self.assertEqual(label(LOGIN_A, title="Shop login")[0], 200)
        code, data = label(LOGIN_A, delete=True)
        self.assertEqual((code, data["agents"]), (409, ["deva", "seo"]), data)
        # Also when a profile spells the reference with upper-case letters.
        loud = "bws://" + LOGIN_B[6:].upper()
        self.assertEqual(label(LOGIN_B, title="Blog login")[0], 200)
        (self.kit / "profiles" / "seo.md").write_text(profile("seo", [LOGIN_A, loud]))
        git("commit", "-q", "-am", "loud", cwd=self.kit)
        git("push", "-q", "origin", "HEAD:main", cwd=self.kit)         # the hub's checkout stays equal to its origin
        hub._revision_cache.update(at=0.0, value=None)
        code, data = self.request("/ui/team/logins", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                          base_sha256=self.sha(), login=loud, delete=True))
        self.assertEqual((code, data["agents"]), (409, ["seo"]), data)
        code, data = label(fresh, delete=True)
        self.assertEqual((code, data["deleted"]), (200, True), data)
        self.assertEqual(set(self.request("/ui/team?db=test-generation")[1]["logins"]), {LOGIN_A, LOGIN_B})
        self.assertTrue(hub.secret_hit(value))
        self.assertEqual(label(fresh, delete=True)[0], 404)
        for bad in ({shouted: {"title": "Shop"}}, {fresh: {"title": "Shop", "value": "x"}}, {fresh: {"title": ""}},
                    {"shop": {"title": "Shop"}}, [fresh]):
            with self.subTest(logins=bad), self.assertRaises(ValueError):
                hub.validate_team(dict(json.loads(json.dumps(TEAM)), logins=bad))

    def test_the_import_page_asks_whether_a_value_is_the_one_the_hub_holds(self):
        """GET /ui/secrets/same (UI-API.md 1.129): "Changed in 1Password" from salted fingerprints, with no value out."""
        login = "bws://31111111-2222-4333-8444-55555555555c"
        digest = lambda salt, value: hashlib.sha256((salt + value).encode()).hexdigest()
        salts = self.request(f"/ui/secrets/salts?db=test-generation&login={login}")[1]
        words = lambda *items: ",".join(f"{kind}:{digest(salts[kind], text)}:{len(text)}" for kind, text in items)
        same = lambda prints, **query: self.request("/ui/secrets/same?" + urllib.parse.urlencode(
            dict(dict(db="test-generation", login=login, fingerprints=prints), **query)))
        value, seed = "Pr4ct!ce-Login#2026", "JBSWY3DPEHPK3PXP"
        self.assertIn("secret_compare", self.request()[1]["ui_features"])
        self.assertEqual(same(words(("password", value))), (200, {"login": login, "same": None}))   # it holds none
        hub.register_fingerprints(login, [{"kind": "password", "hash": digest(salts["password"], value), "len": len(value)},
                                          {"kind": "totp", "hash": digest(salts["totp"], seed), "len": len(seed)}])
        before = hub.q1("SELECT COUNT(*) n FROM secrets")["n"]
        self.assertEqual(same(words(("password", value), ("totp", seed)))[1]["same"], True)
        self.assertEqual(same(words(("password", "An0ther-Value#2026"), ("totp", seed)))[1]["same"], False)
        self.assertEqual(same(words(("password", value), ("totp", "KRSXG5CTMVRXEZLU")))[1]["same"], False)
        self.assertEqual(same(words(("password", value)))[1]["same"], False)          # the seed that it had is gone
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM secrets")["n"], before)       # a question writes nothing
        good = words(("password", value))
        for bad in ({"fingerprints": ""}, {"fingerprints": "password:abc:20"}, {"fingerprints": good.replace(":19", ":7")},
                    {"fingerprints": good + ":1"}, {"fingerprints": ",".join([good] * 2)}, {"login": "sealed:4"}):
            with self.subTest(bad=bad):
                self.assertEqual(same(good, **bad)[0], 400)
        self.assertEqual(same(good, db="old")[0], 409)

    # ---- capacity
    def reading(self, name, primary=None, screen=None):
        data = {"tokens": None, "limits": primary}
        if screen is not None:
            data["screen"] = {"tokens": None, "limits": screen}
        hub.q("INSERT INTO agent_usage(name,data) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET data=excluded.data",
              (name, json.dumps(data)))

    @staticmethod
    def limits(key, used, reset, age=0, error=None, label="codex / 7 days", windows=True, minutes=10080):
        return {"collected_at": hub.now() - age, "source": "test", "plan": "pro", "account_key": key, "error": error,
                "windows": [{"id": "w", "label": label, "used_percent": used, "resets_at": reset,
                             "window_minutes": minutes}] if windows else []}

    def baseline(self):
        """The live shape of 10 October 2026: five readings, four provider accounts. big's primary and seo's screen
        share one Codex account at 100%; deva's Codex is another account; seo's Claude and the manager's are two more."""
        later = hub.now() + 86400
        hub.TEAM["agents"]["seo"]["screen_command"] = "codex app-server"
        for name in hub.agents():
            hub.touch(name)
        self.reading("big", self.limits(SHARED, 100, later))
        self.reading("seo", self.limits(SEO, 0, None, label="5 hours"), self.limits(SHARED, 40, later, age=7200))
        self.reading("deva", self.limits(DEVA, 1, later))
        self.reading("manager", self.limits(MANAGER, 0, None, label="5 hours"))
        return later

    def test_a_shared_account_counts_once_and_its_newest_reading_decides_for_every_route(self):
        later = self.baseline()
        view = hub.capacity_view()
        groups = {g["group"]: g for g in view["accounts"]}
        self.assertEqual(set(groups), {SHARED, SEO, DEVA, MANAGER, "unknown:pma:primary", "unknown:pmb:primary"})
        shared = groups[SHARED]
        self.assertEqual(shared["routes"], [{"agent": "big", "route": "primary"}, {"agent": "seo", "route": "screen"}])
        self.assertEqual((shared["state"], shared["until"], [w["used_percent"] for w in shared["windows"]]),
                         ("limited", later, [100]))                         # the newest reading, never a sum
        self.assertEqual([(x["agent"], x["stale"]) for x in shared["samples"]], [("big", False), ("seo", True)])
        seo = next(a for a in view["agents"] if a["agent"] == "seo")
        self.assertEqual(set(seo["routes"][0]), {"route", "runtime", "group", "account_email", "account_email_read_at",
                                                 "read_at", "stale", "state", "reason", "until", "retry_at"})
        primary, screen = seo["routes"]
        self.assertEqual((primary["group"], primary["state"]), (SEO, "available"))
        self.assertEqual((screen["group"], screen["state"], screen["until"], screen["stale"]), (SHARED, "limited", later, False))
        self.assertIsNone(seo["hold"])
        self.assertEqual(groups["unknown:pma:primary"]["state"], "unknown")    # no identity: never merged
        hub.TEAM.setdefault("accounts", {})["codex-main"] = {"provider": "openai", "title": "Codex"}
        hub.TEAM["agents"]["big"]["account"] = hub.TEAM["agents"]["deva"]["account"] = "codex-main"
        groups = {g["group"]: g for g in hub.capacity_view()["accounts"]}
        self.assertEqual((groups[SHARED]["label"], groups[DEVA]["label"]), ("codex-main", "codex-main"))
        self.assertIn("also names", groups[SHARED]["mismatch"])                # counting follows the provider

    def test_the_account_email_is_for_the_owner_and_never_decides_a_group(self):
        later = self.baseline()
        mail = lambda reading, email: dict(reading, account_email=email)
        # big and seo's screen share one provider account. deva's other account gives the same email (for example
        # another organization of the same person): it stays a group of its own.
        self.reading("big", mail(self.limits(SHARED, 100, later), "owner@example.com"))
        self.reading("seo", mail(self.limits(SEO, 0, None, label="5 hours"), "claude@example.com"),
                     mail(self.limits(SHARED, 40, later, age=7200), "owner@example.com"))
        self.reading("deva", mail(self.limits(DEVA, 1, later), "owner@example.com"))
        view = hub.capacity_view()
        groups = {g["group"]: g for g in view["accounts"]}
        self.assertEqual(set(groups), {SHARED, SEO, DEVA, MANAGER, "unknown:pma:primary", "unknown:pmb:primary"})
        self.assertEqual((groups[SHARED]["emails"], groups[DEVA]["emails"], groups[MANAGER]["emails"]),
                         (["owner@example.com"], ["owner@example.com"], []))
        self.assertEqual(groups[SHARED]["routes"], [{"agent": "big", "route": "primary"}, {"agent": "seo", "route": "screen"}])
        rows = {a["agent"]: a for a in view["agents"]}
        self.assertEqual([r["account_email"] for r in rows["seo"]["routes"]], ["claude@example.com", "owner@example.com"])
        self.assertIsNone(rows["manager"]["routes"][0]["account_email"])        # its helper sent none: unknown
        self.assertIsNone(rows["pma"]["routes"][0]["account_email"])            # no reading: unknown
        self.assertEqual((rows["manager"]["routes"][0]["account_email_read_at"], rows["pma"]["routes"][0]["account_email_read_at"]),
                         (None, None))
        # Each email has the time of its own reading. seo's screen read the shared account two hours ago and big read
        # it now: the group's reading is big's, but seo's email keeps its own old time, and an old email of another
        # sign-in is not in the group's current list.
        screen = rows["seo"]["routes"][1]
        self.assertAlmostEqual(screen["account_email_read_at"], hub.now() - 7200, delta=5)
        self.assertAlmostEqual(screen["read_at"], hub.now(), delta=5)
        self.assertFalse(screen["stale"])
        self.reading("seo", mail(self.limits(SEO, 0, None, label="5 hours"), "claude@example.com"),
                     mail(self.limits(SHARED, 40, later, age=7200), "old@example.com"))
        again = hub.capacity_view()
        self.assertEqual({g["group"]: g for g in again["accounts"]}[SHARED]["emails"], ["owner@example.com"])
        old = next(a for a in again["agents"] if a["agent"] == "seo")["routes"][1]
        self.assertEqual(old["account_email"], "old@example.com")
        self.assertAlmostEqual(old["account_email_read_at"], hub.now() - 7200, delta=5)
        members = lambda found: {key: g["routes"] for key, g in found.items()}
        hub.TEAM.setdefault("accounts", {})["codex-main"] = {"provider": "openai", "title": "Codex"}
        hub.TEAM["agents"]["big"]["account"] = hub.TEAM["agents"]["deva"]["account"] = "codex-main"
        self.assertEqual(members({g["group"]: g for g in hub.capacity_view()["accounts"]}), members(groups))  # nor a label
        self.reading("big", mail(self.limits(SHARED, 100, later), "second@example.com"))     # two sign-ins, one account,
        self.reading("seo", mail(self.limits(SEO, 0, None, label="5 hours"), "claude@example.com"),     # both read now
                     mail(self.limits(SHARED, 40, later), "owner@example.com"))
        shared = {g["group"]: g for g in hub.capacity_view()["accounts"]}[SHARED]
        self.assertEqual((shared["emails"], len(shared["routes"])), (["owner@example.com", "second@example.com"], 2))
        text, error = self.call("manager", "see_capacity", {})                   # no agent tool gives it
        self.assertFalse(error, text)
        self.assertNotIn("@example.com", text + hub.overview_text())

    def test_a_signed_out_route_is_not_available_through_another_routes_reading_of_the_same_account(self):
        later = self.baseline()
        # big reads the shared account now, with allowance left. seo's screen runtime uses the same account, but it said
        # that it is signed out: its kept reading has no email and the sign-in error.
        self.reading("big", self.limits(SHARED, 40, later))
        signed_out = dict(self.limits(SHARED, 40, later, age=600, error="CLI sign-in is required."), account_email=None)
        self.reading("seo", self.limits(SEO, 0, None, label="5 hours"), signed_out)
        stored = hub.q1("SELECT data FROM agent_usage WHERE name='seo'")["data"]
        view = hub.capacity_view()
        rows = {a["agent"]: a for a in view["agents"]}
        primary, screen = rows["seo"]["routes"]
        self.assertEqual((screen["state"], screen["group"], screen["until"], screen["retry_at"]), ("unknown", SHARED, None, None))
        self.assertIn("signed out: CLI sign-in is required.", screen["reason"])
        self.assertEqual((primary["state"], rows["big"]["routes"][0]["state"]), ("available", "available"))
        shared = {g["group"]: g for g in view["accounts"]}[SHARED]      # the account, its routes and its windows stay
        self.assertEqual((shared["state"], shared["routes"], [w["used_percent"] for w in shared["windows"]]),
                         ("available", [{"agent": "big", "route": "primary"}, {"agent": "seo", "route": "screen"}], [40]))
        self.assertEqual([(x["agent"], x["error"]) for x in shared["samples"]],
                         [("big", None), ("seo", "CLI sign-in is required.")])
        self.assertEqual(hub.q1("SELECT data FROM agent_usage WHERE name='seo'")["data"], stored)
        hub.TEAM["agents"]["seo"]["can"] = ["shell", "web", "browser", "screen"]
        text, error = self.call("manager", "see_capacity", {"needs": "screen"})         # no screen task goes to it
        self.assertFalse(error, text)
        self.assertNotIn("  seo", text[:text.index("ELIGIBLE, BUT NOT AVAILABLE NOW")])
        text, error = self.call("manager", "see_capacity", {})                         # its primary route still works
        self.assertIn("  seo", text[:text.index("ELIGIBLE, BUT NOT AVAILABLE NOW")])
        # The same for a route whose runtime named another account than its kept reading (also one without an email):
        # the earlier subscription's allowance is not this route's.
        changed = dict(self.limits(SHARED, 40, later, age=600, error="The signed-in account changed."), account_email=None)
        self.reading("seo", self.limits(SEO, 0, None, label="5 hours"), changed)
        view = hub.capacity_view()
        screen = next(a for a in view["agents"] if a["agent"] == "seo")["routes"][1]
        self.assertEqual((screen["state"], screen["group"]), ("unknown", SHARED))
        self.assertIn("changed; its own allowance is not known yet", screen["reason"])
        shared = {g["group"]: g for g in view["accounts"]}[SHARED]
        self.assertEqual((shared["state"], len(shared["routes"]), len(shared["samples"])), ("available", 2, 2))
        # An ordinary refresh that failed, for the same account, is neither: the account's newest reading decides.
        failed = dict(self.limits(SHARED, 40, later, age=600, error="Account limits could not be refreshed."),
                      account_email="owner@example.com")
        self.reading("seo", self.limits(SEO, 0, None, label="5 hours"), failed)
        self.assertEqual(hub.capacity_view(["seo"])["agents"][0]["routes"][1]["state"], "available")
        self.reading("seo", self.limits(SEO, 0, None, label="5 hours"), self.limits(SHARED, 40, later, age=600))
        self.assertEqual(hub.capacity_view(["seo"])["agents"][0]["routes"][1]["state"], "available")   # signed in again

    def test_availability_is_never_invented(self):
        later, earlier = hub.now() + 3600, hub.now() - 60
        hub.touch("big")
        cases = [(self.limits(SHARED, 100, None, age=3600), ("unknown", None)),          # stale, no reset time
                 (self.limits(SHARED, 0, None, error="Provider unavailable", windows=False), ("unknown", None)),
                 (self.limits(SHARED, 0, None, windows=False), ("unknown", None)),
                 (self.limits(SHARED, 100, earlier), ("unknown", None)),                 # a reset that passed
                 (self.limits(SHARED, 50, earlier), ("unknown", None)),
                 (self.limits(SHARED, 30, later, error="Account limits could not be refreshed."), ("unknown", None)),
                 (self.limits(SHARED, 100, later, age=3600), ("limited", later)),        # certain until the reset
                 (self.limits(SHARED, 100, None), ("limited", None)),
                 (self.limits(SHARED, 30, later), ("available", None)),
                 (None, ("unknown", None))]
        for primary, expected in cases:
            with self.subTest(reading=primary):
                self.reading("big", primary)
                route = next(a for a in hub.capacity_view(["big"])["agents"])["routes"][0]
                self.assertEqual((route["state"], route["until"], route["retry_at"]), expected + (None,))
        self.reading("big", self.limits(SHARED, 30, later))
        tid = self.create("manager", "big")
        hub.start_limit("big", None, tid)                    # no reset time: the hub's estimate stays apart
        big = hub.capacity_view(["big"])["agents"][0]
        self.assertEqual((big["routes"][0]["state"], big["routes"][0]["until"]), ("limited", None))
        self.assertIsNotNone(big["routes"][0]["retry_at"])
        self.assertEqual((big["hold"]["until"], big["hold"]["route"], big["hold"]["task"]), (None, "primary", tid))
        hub.q("UPDATE agents SET last_seen=? WHERE name='big'", (hub.now() - 600,))
        self.assertEqual(hub.capacity_view(["big"])["agents"][0]["routes"][0]["state"], "offline")
        self.assertEqual(hub.capacity_view(["pma"])["agents"][0]["routes"][0]["state"], "unknown")    # never seen

    def test_a_hold_limits_the_account_that_hit_it_and_holds_the_agents_work(self):
        later = self.baseline()
        self.reading("big", self.limits(SHARED, 30, later))
        hub.TEAM["agents"]["seo"]["reports_to"] = "pma"
        shop = self.create("manager", "pma", why="pma leads seo")
        screen = self.create("pma", "seo", shop, needs="none")
        hub.q("UPDATE tasks SET needs='screen' WHERE id=?", (screen,))
        hub.start_limit("seo", later, screen)
        view = hub.capacity_view()
        seo = next(a for a in view["agents"] if a["agent"] == "seo")
        self.assertEqual([(r["route"], r["state"]) for r in seo["routes"]], [("primary", "available"), ("screen", "limited")])
        self.assertEqual((seo["hold"]["route"], seo["hold"]["until"]), ("screen", later))
        # account_limits: a hold belongs to one agent, an allowance to one account. big spends the same Codex
        # allowance through its primary route, so seo's report holds big as well -- with the same reset, and with
        # seo named as where it came from, which is what big's own session and the manager read.
        big = next(a for a in view["agents"] if a["agent"] == "big")
        self.assertEqual(big["routes"][0]["state"], "limited")                  # the same account, also for big
        self.assertEqual((big["hold"]["route"], big["hold"]["until"], big["hold"]["source"], big["hold"]["task"]),
                         ("primary", later, "seo", None))
        self.assertIn("A session of seo on the provider account they share", big["hold"]["reason"])
        text = hub.capacity_text(view, "", "none")
        self.assertIn("HOLD until", text)

    def test_an_available_high_quota_worker_without_the_expertise_or_access_is_no_choice(self):
        later = self.baseline()
        self.reading("big", self.limits(DEVA.replace("b", "e"), 1, later))     # big: its own account, 1% used
        self.reading("seo", self.limits(SEO, 100, later, label="5 hours"))     # the specialist waits for its reset
        view = hub.capacity_view(expertise="seo", login=LOGIN_A)
        rows = {a["agent"]: a for a in view["agents"]}
        self.assertEqual(rows["big"]["routes"][0]["state"], "available")
        self.assertFalse(rows["big"]["eligible"])
        self.assertEqual(rows["big"]["why_not"], ["no expertise seo", f"may not use {LOGIN_A}"])
        self.assertTrue(rows["seo"]["eligible"])
        self.assertEqual((rows["seo"]["routes"][0]["state"], rows["seo"]["routes"][0]["until"]), ("limited", later))
        self.assertEqual(rows["seo"]["logins"]["eligible"], [LOGIN_A, LOGIN_B])          # its profile's two logins
        text, error = self.call("manager", "see_capacity", {"expertise": "seo", "login": LOGIN_A})
        self.assertFalse(error, text)
        waiting = text.index("ELIGIBLE, BUT NOT AVAILABLE NOW")
        self.assertGreater(text.index("  seo (SEO Expert)"), waiting)
        self.assertIn("  big: available, but no expertise seo", text[text.index("NOT ELIGIBLE"):])
        text, error = self.call("manager", "see_capacity", {"expertise": "seo"})
        self.assertIn("  big: available, but no expertise seo.", text)

    def test_see_capacity_names_each_secret_and_says_which_api_key_an_agent_reads(self):
        self.baseline()
        key = "bws://31111111-2222-4333-8444-55555555555b"
        hub.TEAM["logins"] = {LOGIN_A: {"title": "shop.example · seo-bot"},
                              key: {"title": "OPENAI_API_KEY", "kind": "api_key", "env": "OPENAI_API_KEY"}}
        hub.TEAM["agents"]["big"]["secrets"] = {key: "read"}
        hub.TEAM["agents"]["deva"]["secrets"] = {key: "use"}
        text, error = self.call("manager", "see_capacity", {})
        self.assertFalse(error, text)
        self.assertNotIn("logins it may use here", text)
        # seo: its profile's two logins; LOGIN_B has no catalog entry, so it stays a bare reference
        self.assertIn(f"secrets it may use here: shop.example · seo-bot (login) {LOGIN_A}, {LOGIN_B}.", text)
        self.assertIn(f"secrets it may use here: shop.example · seo-bot (login) {LOGIN_A}, OPENAI_API_KEY (API key) {key}.", text)
        self.assertIn(f"secrets it may use here: OPENAI_API_KEY (API key, it reads it in its sessions) {key}.", text)   # big


    def test_one_unknown_reset_keeps_the_accounts_reset_unknown(self):
        t, known = 2000000000, 2000003600
        window = lambda label, reset: {"label": label, "used_percent": 100, "resets_at": reset, "window_minutes": 300}
        reading = {"collected_at": t - 10, "windows": [window("5 hours", known), window("7 days", None)], "error": None}
        self.assertEqual(hub.account_state(reading, [], t)["state"], "limited")
        self.assertEqual((hub.account_state(reading, [], t)["until"], hub.account_state(reading, [], t)["retry_at"]),
                         (None, None))
        hold = lambda until, known_: {"agent": "seo", "until": until, "reset_known": known_, "task": None}
        mixed = hub.account_state(None, [hold(known, 1), hold(t + 1800, 0)], t)
        self.assertEqual((mixed["state"], mixed["until"], mixed["retry_at"]), ("limited", None, t + 1800))
        both = hub.account_state(None, [hold(known, 1), hold(t + 1800, 1)], t)
        self.assertEqual((both["until"], both["retry_at"]), (known, None))
        stale = dict(reading, collected_at=t - 7200, windows=[window("7 days", None)])
        self.assertEqual(hub.account_state(stale, [], t)["state"], "unknown")


    def test_the_owner_capacity_route_and_one_name_for_each_machine_address(self):
        self.baseline()
        code, data = self.request("/ui/capacity?db=test-generation&needs=screen")
        self.assertEqual(code, 200, data)
        self.assertEqual(data["filters"], {"expertise": None, "needs": "screen", "login": None})
        # The junction: this key set is asserted exactly. Change it and every assertion of it in the same commit.
        self.assertEqual(set(data["agents"][0]), {"agent", "title", "role", "active", "expertise", "can",
                                                  "reports_to", "account", "responsible_for", "looks_after",
                                                  "knowledge_files", "logins",
                                                  "seen_at", "hold", "routes", "workload", "eligible", "why_not",
                                                  "desktop_busy", "duties", "google"})
        self.assertEqual(self.request("/ui/capacity?db=test-generation&needs=fly")[0], 400)
        self.assertEqual(self.request("/ui/capacity?db=old")[0], 409)
        team = json.loads(json.dumps(TEAM))
        team["agents"]["big"]["machine"] = "vps"
        hub.validate_team(team)                 # owner API 1.12: agents may share a machine
        team["addresses"]["spare"] = team["addresses"]["vps"]
        team["agents"]["big"]["machine"] = "spare"
        with self.assertRaises(ValueError) as refused:
            hub.validate_team(team)
        self.assertIn("have one address", str(refused.exception))
        team["agents"]["big"]["machine"] = "vps"
        team["addresses"]["vps"] = team["addresses"]["owner"]
        with self.assertRaises(ValueError) as refused:
            hub.validate_team(team)
        self.assertIn("the owner's address", str(refused.exception))

    # ---- an allowance that is seen before it is spent
    def week(self, used, hours_left, agent="manager", key=MANAGER, label="7 days"):
        """One weekly window of one agent's account, that many hours from its reset."""
        self.reading(agent, self.limits(key, used, hub.now() + hours_left * 3600, label=label))

    def said(self, agent="manager"):
        return [r["text"] for r in hub.q("SELECT text FROM events WHERE agent=? AND kind='say' ORDER BY id", (agent,))]

    def test_the_pace_of_a_window_and_not_its_percentage_decides_whether_it_is_worth_saying(self):
        """92% of a weekly window with 42 hours still to run is a fleet that stops before Thursday; 92% with one
        hour to run is a window that is almost reset. So the measure is the share of the allowance that is gone
        against the share of the window that is gone."""
        t0 = hub.now()
        week = lambda used, hours: {"id": "w", "label": "7 days", "used_percent": used,
                                    "resets_at": t0 + hours * 3600, "window_minutes": 10080}
        self.assertEqual(round(hub.window_pace(week(92, 42.7), t0), 1), 123.4)       # his live manager, 20 Oct
        self.assertEqual(round(hub.window_pace(week(92, 1), t0), 1), 92.6)
        self.assertIsNone(hub.window_pace(dict(week(92, 42), window_minutes=None), t0))  # the fleet invents nothing
        self.assertIsNone(hub.window_pace(dict(week(92, 42), resets_at=None), t0))
        self.assertIsNone(hub.window_pace(week(92, 400), t0))        # a reset further off than the window is lasts

    def test_the_manager_is_told_its_own_allowance_once_a_window_while_it_can_still_act(self):
        self.week(92, 42.7)
        hub.tick()
        said = self.said()[-1]
        self.assertIn("[hub] YOUR OWN ALLOWANCE:", said)
        self.assertIn('the claude window "7 days" of your account is 92% used and resets at', said)
        self.assertIn("At the pace of this window so far it is gone before then (123% of it by the reset)", said)
        self.assertIn("when it is gone the fleet stops with you", said)
        # A warning for the manager, never a page to the owner (22 October 2026): it names tell_owner instead.
        self.assertNotIn("raise_needs_you", said)
        self.assertIn("tell_owner, which posts it with no notification", said)
        self.assertIn("fewer and bigger steps", said)
        self.assertIn("not a reason to move work to an agent with more left: suitability comes first", said)
        # Once per window instance. A second tick says nothing; a worse stage says it again.
        hub.kv_set("allowance_sweep_at", 0)
        hub.tick()
        self.assertEqual(len(self.said()), 1)
        self.week(96, 20)
        hub.kv_set("allowance_sweep_at", 0)
        hub.tick()
        self.assertIn("Almost nothing is left of it", self.said()[-1])
        self.assertEqual(len(self.said()), 2)

    def test_it_says_nothing_about_a_window_that_recovers_resets_itself_or_is_already_gone(self):
        for used, hours, why in ((40, 100, "a slow week"), (92, 1, "nearly reset"), (65, 20, "under the floor")):
            with self.subTest(why=why):
                hub.q("DELETE FROM events")
                hub.kv_set("allowance_sweep_at", 0)
                hub.kv_set("allowance_sweep_sig", None)
                self.week(used, hours)
                hub.tick()
                self.assertEqual(self.said(), [], why)
        # A five-hour window resets itself long before advice about it is worth a turn of the manager's.
        self.reading("manager", self.limits(MANAGER, 99, hub.now() + 600, label="5 hours", minutes=300))
        hub.kv_set("allowance_sweep_at", 0)
        hub.tick()
        self.assertEqual(self.said(), [])
        # Nor about a window that is used up. That one is not this agent's own pacing: there is nothing left to
        # pace, and what to do about it is the owner's (allowance_spent on his health screen).
        self.week(100, 20)
        hub.kv_set("allowance_sweep_at", 0)
        hub.tick()
        self.assertEqual([t for t in self.said() if "YOUR OWN ALLOWANCE" in t], [])
        # Nor about a reading it cannot trust.
        self.reading("manager", self.limits(MANAGER, 92, hub.now() + 42 * 3600, age=99999))
        hub.kv_set("allowance_sweep_at", 0)
        hub.tick()
        self.assertEqual([t for t in self.said() if "YOUR OWN ALLOWANCE" in t], [])

    def test_the_one_reader_of_the_numbers_separates_a_spent_window_from_one_that_has_reset(self):
        """allowance_worth_saying is the one reader, so the owner's health screen and the manager's own line cannot
        disagree about what the numbers say. It says what the reading says and nothing about a hold: the hold is
        written only when a session is actually refused, and whether one exists is not in a reading."""
        t0 = hub.now()
        week = lambda used, hours: {"id": "w", "label": "7 days", "used_percent": used, "window_minutes": 10080,
                                    "resets_at": None if hours is None else t0 + hours * 3600}
        read = lambda w: {"collected_at": t0, "error": None, "windows": [w]}
        self.assertEqual(hub.allowance_worth_saying(read(week(100, 31)), t0)[2], "spent")   # his live manager, 21 Oct
        self.assertEqual(hub.allowance_worth_saying(read(week(101, 31)), t0)[2], "spent")   # over its allowance
        self.assertEqual(hub.allowance_worth_saying(read(week(100, None)), t0)[2], "spent")  # no reset time given
        self.assertEqual(hub.allowance_worth_saying(read(week(96, 31)), t0)[2], "last")
        self.assertEqual(hub.allowance_worth_saying(read(week(92, 42.7)), t0)[2], "pace")
        # A window whose reset has passed has reset: the reading is simply behind it, and awaiting a new one says
        # nothing. account_state calls the same thing "passed", and the two must not disagree.
        self.assertIsNone(hub.allowance_worth_saying(read(week(100, -2)), t0))
        self.assertIsNone(hub.allowance_worth_saying(read(week(96, -2)), t0))
        self.assertEqual(hub.account_state(read(week(100, -2)), [], t0)["state"], "unknown")
        # A window the account does not report is not a window at zero: only what it reported is read. His Studio
        # reports no week of its own, so nothing here says anything about its week.
        studio = {"collected_at": t0, "error": None, "windows": [
            {"id": "s", "label": "5 hours", "used_percent": 0, "resets_at": None, "window_minutes": 300},
            {"id": "f", "label": "7 days (Fable)", "used_percent": 0, "resets_at": t0 + 55 * 3600,
             "window_minutes": 10080}]}
        self.assertIsNone(hub.allowance_worth_saying(studio, t0))
        # The spent window is the news, so it wins over another window of the same account that is merely pacing.
        both = {"collected_at": t0, "error": None, "windows": [week(97, 31), dict(week(100, 31), id="x")]}
        w, _, why = hub.allowance_worth_saying(both, t0)
        self.assertEqual((w["id"], why), ("x", "spent"))

    def test_a_reset_that_is_more_than_a_day_off_cannot_be_read_as_this_afternoon(self):
        """clock() carries no date. His manager's week reset 31 hours out rendered "at 14:00 UTC", which reads as
        today, and the answer to "wait, or sign in elsewhere?" is exactly that missing day."""
        t0 = 1792564736.0                                   # 06:38 UTC, the moment his hub was read
        self.assertEqual(hub.until_clock(t0 + 31 * 3600, t0), "in 31 hours, at 13:38 UTC")
        self.assertEqual(hub.until_clock(t0 + 40 * 60, t0), "in 40 minutes, at 07:18 UTC")
        self.assertEqual(hub.until_clock(t0 - 600, t0), "in 0 minutes, at 06:28 UTC")   # never a negative wait
        # It floors, so it never promises the allowance back sooner than it comes.
        self.assertEqual(hub.until_clock(t0 + 31 * 3600 - 3, t0), "in 30 hours, at 13:38 UTC")

    def test_see_capacity_shows_the_caller_its_own_account_which_no_block_of_it_lists(self):
        """It reads the capacity of the agents it may give work to, and it is not one of them -- so the one
        allowance every placement costs a turn of was in the hub and in front of nobody."""
        self.week(92, 42.7)
        self.week(2, 42.7, agent="seo", key=SEO, label="claude / 7 days")
        text, error = hub.call_tool("manager", "see_capacity", {})
        self.assertFalse(error, text)
        self.assertIn("YOUR OWN ALLOWANCE:", text)
        self.assertIn("is 92% used", text)
        self.assertIn("Fewer and bigger turns until the reset. A warning, not a Needs-you item: tell_owner", text)
        self.assertIn("no reason to pass work to an agent that does not suit it", text)
        self.assertIn("Choose by suitability first", text)            # the order it always had, unchanged
        self.assertNotIn("manager:", text.split("ACCOUNTS")[0])       # still not one of the agents it may choose
        # A worker's allowance is its own business and stays out of what the manager reads about itself.
        self.assertEqual(text.count("YOUR OWN ALLOWANCE"), 1)
        self.week(2, 42.7)
        self.assertNotIn("YOUR OWN ALLOWANCE", hub.call_tool("manager", "see_capacity", {})[0])

    def test_see_capacity_gives_each_agent_s_own_use_and_each_server_s_load_once(self):
        """The owner, 4 November 2026: the servers' figures are "information that's good to know to the manager to
        make decisions or to see if there are issues". A lead reads the servers of its own team."""
        gib = 1024 ** 3
        hub.q("INSERT INTO machine_status(agent,data,reported) VALUES(?,?,?)",
              ("seo", json.dumps({"use": {"cpu_percent": 2.5, "memory": 3 * gib // 2}}), hub.now()))
        hub.q("INSERT INTO server_status(server,data,reported) VALUES(?,?,?)", ("vps", json.dumps({
            "os": {"name": "Ubuntu 24.04.1 LTS"}, "load": {"cpu_percent": 12.0, "memory_used": 3 * gib,
                                                           "memory_total": 4 * gib, "disk_used": 10 * gib,
                                                           "disk_total": 40 * gib}}), hub.now() - 180))
        hub.TEAM["agents"]["big"]["machine"] = "vps"     # a server that pma's team shares with an agent of no team
        hub.HUB_LOAD.update(at=None)                    # the hub's own measurement, kept from another test
        with patch.object(hub.lifecycle, "machine_load", lambda platform: dict.fromkeys(hub.lifecycle.LOAD_KEYS)):
            text, error = self.call("manager", "see_capacity", {})
            parent = self.create("manager", "pma", why="pma leads seo")
            lead, lead_error = self.call("pma", "see_capacity", {}, parent)
        self.assertFalse(error or lead_error, text + lead)
        self.assertIn("its own processes use CPU 2.5% and 1.5 GB of memory", text)
        servers = text.split("\nSERVERS")[1]
        self.assertIn(f"  vps (seo, big): CPU 12%, memory 3.0 of 4.0 GB (75%), disk 10.0 of 40.0 GB (25%). Read "
                      f"{hub.span(180)} ago.\n", servers)
        self.assertIn("  hub (manager): no reading.\n", servers)
        self.assertIn("  w4 (no agent): no reading.", servers)
        # A lead names the agents of its own scope, and counts the others, as its ACCOUNTS block does.
        self.assertEqual(lead.split("\nSERVERS")[1].split("\n")[1:3], [
            f"  vps (seo and 1 other agent(s)): CPU 12%, memory 3.0 of 4.0 GB (75%), disk 10.0 of 40.0 GB (25%). Read "
            f"{hub.span(180)} ago.", "  w2 (deva): no reading."])
        self.assertNotIn("big", lead.split("\nSERVERS")[1])

    def test_a_lead_reads_its_own_allowance_in_the_words_of_the_tools_it_has(self):
        """A lead has no raise_needs_you: its route is its requester. So the same line ends differently."""
        parent = self.create("manager", "pma", why="pma leads seo")
        self.week(93, 40, agent="pma", key=DEVA)
        text, error = self.call("pma", "see_capacity", {}, parent)
        self.assertFalse(error, text)
        self.assertIn("YOUR OWN ALLOWANCE:", text)
        self.assertIn("tell your requester what will not get done", text)
        self.assertNotIn("raise_needs_you", text)

    def test_the_resume_brief_carries_it_so_a_cold_manager_does_not_plan_a_week_it_cannot_pay_for(self):
        self.week(92, 42.7)
        self.assertIn("YOUR OWN ALLOWANCE:", hub.manager_resume_text())
        self.week(10, 42.7)
        self.assertNotIn("YOUR OWN ALLOWANCE", hub.manager_resume_text())

    def test_agents_that_share_one_account_are_named_because_they_share_one_allowance(self):
        self.reading("deva", self.limits(SHARED, 10, hub.now() + 42 * 3600, age=600))
        self.reading("big", self.limits(SHARED, 92, hub.now() + 42 * 3600))
        said, w, why = hub.allowance_ahead("big")
        self.assertIn("deva spend the same allowance", said)
        self.assertEqual((w["used_percent"], why), (92, "pace"))
        groups = hub.account_groups()
        self.assertEqual(groups[SHARED]["agents"], ["big", "deva"])
        self.assertEqual(groups[SHARED]["reading"]["windows"][0]["used_percent"], 92)  # the newest, never a sum
        self.assertEqual(hub.account_group("big")["sharers"], ["deva"])
        # deva reads the same thing, because the allowance belongs to the account and not to either agent.
        self.assertIn("big spend the same allowance", hub.allowance_ahead("deva")[0])
        self.assertIsNone(hub.account_group("pma"))                   # no reading, so no account identity


if __name__ == "__main__":
    unittest.main()
