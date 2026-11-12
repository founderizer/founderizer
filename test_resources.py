"""Owner feature resource_grants: the grantable pool, the manager's grant_access, the record of every grant and the
owner's one step that takes a hold back. The grant is the authorization (the owner, 17 October 2026), so no action is
held back for the owner afterwards and the record is the control. In-process hub and temporary Git repositories; no
helper, vault, GitHub, Google or AI call. No secret value anywhere: a secret is its bws:// reference and
its name."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid

import hub
from test_setup import git
from test_ui_api import OwnerAPI

LOGIN = "bws://11111111-2222-4333-8444-55555555555b"       # a login: the shop admin, which an agent signs in with
KEY = "bws://21111111-2222-4333-8444-55555555555b"         # an API key: the deploy route that an agent reads
SPEND = "bws://31111111-2222-4333-8444-55555555555b"       # the key that pays: grantable like any other
TEAM = {
    "hub": {"machine": "hub", "port": 8765},
    "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "box": "127.0.0.3", "shopbox": "127.0.0.4"},
    "agents": {
        "manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
        "lead": {"role": "lead", "runtime": "claude", "machine": "box", "can": ["shell"]},
        "dev": {"role": "worker", "runtime": "claude", "machine": "box", "can": ["shell"]},
        "shopper": {"role": "worker", "runtime": "codex", "machine": "shopbox", "can": ["shell"],
                    "repos": {"acme/web": "read"}}},
    "logins": {LOGIN: {"title": "shop.test · admin", "kind": "login"},
               KEY: {"title": "DEPLOY_KEY", "kind": "api_key", "env": "DEPLOY_KEY"},
               SPEND: {"title": "STRIPE_KEY", "kind": "api_key", "env": "STRIPE_KEY"}},
    "mcp": {"crm": {"title": "CRM", "url": "https://crm.test/mcp", "auth": "oauth"},
            "jobs": {"title": "Failed jobs", "url": "https://jobs.test/mcp", "auth": "key", "key": "DEPLOY_KEY"}},
    "resources": {}}


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(Resources(name) for name in Resources.__dict__ if name.startswith("test_"))


class Resources(OwnerAPI):
    """The owner sets the standing of each resource through the real route, and the manager grants through the real
    tool: every write is a real commit of a real team.json."""
    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp(prefix="fleet-resources-"))
        self.addCleanup(subprocess.run, ["rm", "-rf", str(self.root)])
        seed = self.root / "seed"
        seed.mkdir()
        (seed / "team.json").write_text(json.dumps(TEAM, indent=2) + "\n")
        git("init", "-q", str(seed))
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "seed", cwd=seed)
        git("clone", "-q", "--bare", str(seed), str(self.root / "origin.git"))
        git("clone", "-q", str(self.root / "origin.git"), str(self.root / "kit"))
        hub.CFG["team_path"] = str(self.root / "kit" / "team.json")
        self.addCleanup(hub.CFG.pop, "team_path", None)
        hub.CFG["google_file"] = str(self.root / "no-google.json")
        self.addCleanup(hub.CFG.pop, "google_file", None)
        hub.CFG["github_app"] = str(self.root / "no-github-app")       # no GitHub call from a helper's session start
        self.addCleanup(hub.CFG.pop, "github_app", None)
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = json.loads(json.dumps(TEAM))
        hub.CFG.update(silence=180, question_wait=120, manager_silence=120, stop_after=60, offline_after=90, tick=5)

    # ---- helpers

    def committed(self):
        return json.loads((self.root / "kit" / "team.json").read_text())

    def commits(self):
        return int(git("rev-list", "--count", "HEAD", cwd=self.root / "kit"))

    def pool(self, db="test-generation"):
        code, result = self.request(f"/ui/resources?db={db}")
        self.assertEqual(code, 200, result)
        return result

    def entry(self, rid):
        return next(r for r in self.pool()["resources"] if r["id"] == rid)

    def stand(self, resource, policy, request_id=None, base=None):
        """The owner's standing for one resource, through POST /ui/resources."""
        return self.request("/ui/resources", {"request_id": request_id or str(uuid.uuid4()), "db": "test-generation",
                                              "base_sha256": base or self.pool()["sha256"],
                                              "resource": resource, "policy": policy})

    def take(self, agent, resource, request_id=None):
        """The owner's one step: one agent's hold of one resource ends."""
        return self.request("/ui/resources/take", {"request_id": request_id or str(uuid.uuid4()),
                                                   "db": "test-generation", "resource": resource, "agent": agent})

    def history(self, resource):
        return [(h["agent"], h["level"], h["by"]) for h in self.entry(resource)["history"]]

    def agent_line(self, text, agent):
        """The one line of see_capacity that is this agent's own facts."""
        return next(l for l in text.splitlines() if l.startswith(f"  {agent}: "))

    def call(self, agent, name, args):
        """One tool call outside a task session, as the manager's own session makes it."""
        return hub.call_tool(agent, name, args)

    def grant(self, agent, resource, level, by="manager", request_id=None):
        """The manager's own grant, through the real tool."""
        return hub.call_tool(by, "grant_access", {"request_id": request_id or str(uuid.uuid4()), "agent": agent,
                                                  "resource": resource, "level": level})

    def granted(self, agent, resource, level, **kw):
        text, error = self.grant(agent, resource, level, **kw)
        self.assertFalse(error, text)
        return text

    def refused(self, agent, resource, level, **kw):
        text, error = self.grant(agent, resource, level, **kw)
        self.assertTrue(error, text)
        return text

    # ---- the pool that the owner's page reads

    def test_the_page_lists_what_a_duty_can_need_with_its_secrets_and_its_holders(self):
        self.assertIn("resource_grants", self.request()[1]["ui_features"])
        pool = self.pool()
        self.assertEqual(pool["db"], "test-generation")
        self.assertEqual(pool["audience"], "workers")
        self.assertEqual([k["kind"] for k in pool["kinds"]], ["secret", "repo", "drive", "gmail", "tool"])
        self.assertEqual(next(k for k in pool["kinds"] if k["kind"] == "gmail")["levels"], ["read", "write", "send"])
        self.assertEqual(next(k for k in pool["kinds"] if k["kind"] == "repo")["levels"], ["read", "write", "deploy"])
        self.assertNotIn("guards", pool)                         # no mark: the grant is the authorization
        ids = [r["id"] for r in pool["resources"]]
        for rid in (f"secret:{LOGIN}", f"secret:{KEY}", "repo:acme/web", "tool:crm", "tool:jobs", "tool:github"):
            self.assertIn(rid, ids, ids)
        # The repository that an agent already has is in the list, with that agent as its holder.
        repo = self.entry("repo:acme/web")
        self.assertEqual((repo["kind"], repo["credential"], repo["uses"]), ("repo", "github_app", []))
        self.assertEqual(repo["holders"], [{"agent": "shopper", "level": "read"}])
        self.assertIsNone(repo["grant"])                        # nothing is grantable until the owner says so
        self.assertEqual(repo["history"], [])                   # nothing has been given through this feature yet
        # An MCP server says which secret of the catalog it needs, and Fleet's own tool needs none of the owner's.
        self.assertEqual(self.entry("tool:jobs")["uses"], [KEY])
        self.assertEqual(self.entry("tool:jobs")["credential"], "key")
        self.assertEqual(self.entry("tool:crm")["credential"], "oauth")
        self.assertEqual((self.entry("tool:github")["uses"], self.entry("tool:github")["credential"]), ([], "fleet"))
        # A secret is its reference and its name, never a value.
        key = self.entry(f"secret:{KEY}")
        self.assertEqual((key["title"], key["uses"], key["credential"]), ("DEPLOY_KEY", [KEY], "vault"))
        self.assertEqual(key["levels"], ["use", "read"])
        self.assertNotIn("value", json.dumps(pool))
        self.assertEqual(self.request("/ui/resources?db=other")[0], 409)

    # ---- the owner sets the standing, and nothing is grantable before that

    def test_nothing_is_grantable_until_the_owner_opens_the_pool(self):
        before = self.commits()
        text = self.refused("dev", "repo:acme/web", "write")
        self.assertIn("not in the grantable pool", text)
        self.assertIn("raise_needs_you", text)
        self.assertEqual(self.commits(), before)
        self.assertNotIn("repos", self.committed()["agents"]["dev"])
        code, receipt = self.stand("repo:acme/web", {"max": "write", "to": "workers"})
        self.assertEqual((code, receipt["changed"], receipt["policy"]),
                         (200, True, {"max": "write", "to": "workers"}), receipt)
        self.assertEqual(self.committed()["resources"], {"repo:acme/web": {"max": "write", "to": "workers"}})
        self.assertEqual(self.entry("repo:acme/web")["grant"], {"max": "write", "to": "workers"})
        self.assertEqual(self.stand("repo:acme/web", {"max": "write", "to": "workers"})[1]["changed"], False)
        # An entry of the pool grants nothing by itself: no agent has the repository yet.
        self.assertEqual(self.entry("repo:acme/web")["holders"], [{"agent": "shopper", "level": "read"}])

    def test_the_owner_takes_the_standing_back_and_the_grant_that_was_made_stays(self):
        self.stand("repo:acme/web", {"max": "write"})
        self.granted("dev", "repo:acme/web", "write")
        code, receipt = self.stand("repo:acme/web", None)
        self.assertEqual((code, receipt["changed"], receipt["policy"]), (200, True, None), receipt)
        self.assertNotIn("resources", self.committed())
        self.assertEqual(self.committed()["agents"]["dev"]["repos"], {"acme/web": "write"})   # the owner removes it
        self.assertIn("not in the grantable pool", self.refused("lead", "repo:acme/web", "write"))
        self.assertEqual(self.stand("repo:acme/web", None)[1]["changed"], False)

    # ---- the whole loop

    def test_the_whole_loop_from_the_owners_standing_to_the_agents_next_task_session(self):
        """What the owner's side of the pool is for, from end to end. Before he opens anything the manager has
        nothing to give and the refusal sends it to him; after he opens it, the manager grants, the agent reads the
        resource in the task session that starts next, and he ends the hold in one step. shopper is alone on its
        machine, so its own helper asks the hub for that session as a real one does."""
        def session():
            """What the helper gives this agent's next task session (POST /helper/integrations)."""
            code, data = self.request("/helper/integrations/shopper", {}, source="127.0.0.4")
            self.assertEqual(code, 200, data)
            return data

        # The refusal names the resource as the owner's page names it: only its first letter is made a capital.
        self.assertIn("The MCP server Failed jobs is not in the grantable pool",
                      self.refused("shopper", "tool:jobs", "use"))
        self.assertIn("The secret DEPLOY_KEY is not in the grantable pool",
                      self.refused("shopper", f"secret:{KEY}", "read"))
        self.assertEqual(session()["tools"], [])
        self.assertEqual(hub.read_secrets("shopper"), [])
        # The one thing that was missing: the owner says that the manager may hand these two out.
        self.stand("tool:jobs", {"max": "use", "to": "workers"})
        self.stand(f"secret:{KEY}", {"max": "read"})
        self.granted("shopper", "tool:jobs", "use")
        self.granted("shopper", f"secret:{KEY}", "read")
        # The next task session of that agent carries both: the MCP server in its tools, the API key by its name.
        self.assertEqual(session()["tools"], ["jobs"])
        self.assertEqual(hub.read_secrets("shopper"), [(KEY, "DEPLOY_KEY")])
        # And the owner ends either hold in one step, from the same page, whoever gave it.
        self.assertEqual(self.take("shopper", "tool:jobs")[1]["had"], "use")
        self.assertEqual(self.take("shopper", f"secret:{KEY}")[1]["had"], "read")
        self.assertEqual(session()["tools"], [])
        self.assertEqual(hub.read_secrets("shopper"), [])
        self.assertEqual(self.history("tool:jobs"), [("shopper", None, "owner"), ("shopper", "use", "manager")])

    # ---- the manager grants

    def test_the_manager_grants_a_repository_in_one_commit_and_the_hub_logs_it(self):
        self.stand("repo:acme/web", {"max": "write", "to": "workers"})
        before = self.commits()
        rid = str(uuid.uuid4())
        text = self.granted("dev", "repo:acme/web", "write", request_id=rid)
        self.assertIn("dev now has the GitHub repository acme/web at level write", text)
        self.assertIn("next task session", text)
        self.assertEqual(self.commits(), before + 1)
        self.assertEqual(self.committed()["agents"]["dev"]["repos"], {"acme/web": "write"})
        self.assertEqual(hub.agents()["dev"]["repos"], {"acme/web": "write"})     # applied at once
        self.assertEqual(self.committed()["agents"]["shopper"]["repos"], {"acme/web": "read"})   # nobody else changed
        self.assertEqual(self.entry("repo:acme/web")["holders"],
                         [{"agent": "dev", "level": "write"}, {"agent": "shopper", "level": "read"}])
        subject = git("log", "-1", "--format=%s", cwd=self.root / "kit")
        self.assertEqual(subject, "Manager gave dev the GitHub repository acme/web (write)")
        self.assertTrue(hub.q1("SELECT id FROM log WHERE agent='manager' AND what LIKE '%acme/web%'"))
        # The same request_id again gives the first answer and commits nothing.
        self.assertEqual(self.granted("dev", "repo:acme/web", "write", request_id=rid), text)
        self.assertEqual(self.commits(), before + 1)
        self.assertIn("already had", self.granted("dev", "repo:acme/web", "write"))
        self.assertEqual(self.commits(), before + 1)

    def test_the_manager_grants_a_secret_through_the_owners_own_grant_route(self):
        self.stand(f"secret:{KEY}", {"max": "read"})
        before = self.commits()
        self.assertIn("dev now has the secret DEPLOY_KEY at level use", self.granted("dev", f"secret:{KEY}", "use"))
        self.assertEqual(self.committed()["agents"]["dev"]["secrets"], {KEY: "use"})
        self.assertEqual(self.commits(), before + 1)
        self.assertEqual(git("log", "-1", "--format=%s", cwd=self.root / "kit"), "Manager gave DEPLOY_KEY to dev")
        self.granted("dev", f"secret:{KEY}", "read")                  # the owner allowed read of this API key
        self.assertEqual(self.committed()["agents"]["dev"]["secrets"], {KEY: "read"})
        self.assertEqual(self.team_login(KEY)["grants"], {"dev": "read"})
        # read is only for an API key, and the owner's own rules still hold.
        self.stand(f"secret:{LOGIN}", {"max": "read"})
        self.assertIn("The hub refused", self.refused("dev", f"secret:{LOGIN}", "read"))
        self.granted("dev", f"secret:{LOGIN}", "use")
        self.assertEqual(self.committed()["agents"]["dev"]["secrets"], {KEY: "read", LOGIN: "use"})

    def test_the_manager_grants_an_mcp_server_and_a_google_service(self):
        self.stand("tool:crm", {"max": "use"})
        self.stand("gmail:support@shop.test", {"max": "write"})
        self.stand("drive:support@shop.test", {"max": "write_shared"})
        self.assertIn("dev now has the MCP server CRM at level use", self.granted("dev", "tool:crm", "use"))
        self.assertEqual(self.committed()["agents"]["dev"]["tools"], ["crm"])
        self.assertIn("Gmail of support@shop.test", self.granted("dev", "gmail:support@shop.test", "write"))
        self.granted("dev", "drive:support@shop.test", "write_shared")
        self.assertEqual(self.committed()["agents"]["dev"]["google"],
                         {"drive": {"account": "support@shop.test", "level": "write_shared"},
                          "gmail": {"account": "support@shop.test", "level": "write"}})
        self.assertEqual(self.entry("gmail:support@shop.test")["holders"], [{"agent": "dev", "level": "write"}])
        self.assertFalse(self.entry("gmail:support@shop.test")["connected"])      # no Google account is connected here
        self.assertIn("already had", self.granted("dev", "tool:crm", "use"))

    def test_a_policy_reaches_every_worker_and_lead_and_never_the_manager(self):
        self.stand(f"secret:{LOGIN}", {"max": "use"})
        self.granted("shopper", f"secret:{LOGIN}", "use")
        self.granted("dev", f"secret:{LOGIN}", "use")
        self.granted("lead", f"secret:{LOGIN}", "use")
        self.assertEqual(self.committed()["agents"]["shopper"]["secrets"], {LOGIN: "use"})
        text, error = self.call("manager", "grant_access", {"agent": "manager", "resource": f"secret:{LOGIN}",
                                                            "level": "use"})
        self.assertTrue(error)
        self.assertIn("You never grant to yourself", text)

    # ---- the one limit: the level that the owner allows

    def test_the_manager_never_grants_above_the_level_the_owner_allows(self):
        self.stand("repo:acme/web", {"max": "read"})
        text = self.refused("dev", "repo:acme/web", "write")
        self.assertIn("allows at most read", text)
        self.assertNotIn("repos", self.committed()["agents"]["dev"])
        self.granted("dev", "repo:acme/web", "read")
        self.assertIn("level must be one of read, write", self.refused("dev", "repo:acme/web", "admin"))

    def test_the_grant_is_the_authorization_so_sending_mail_and_paying_are_grantable(self):
        """The owner, 17 October 2026: no preapproval of sending email or deploying to production. A level that a
        credential has is part of what the owner grants, so the manager may give it when the policy allows it."""
        self.stand("gmail:support@shop.test", {"max": "send"})
        self.assertEqual(self.entry("gmail:support@shop.test")["grant"], {"max": "send", "to": "workers"})
        self.assertIn("dev now has Gmail of support@shop.test at level send",
                      self.granted("dev", "gmail:support@shop.test", "send"))
        self.assertEqual(self.committed()["agents"]["dev"]["google"],
                         {"gmail": {"account": "support@shop.test", "level": "send"}})
        # A key that pays is a resource like any other, and no step of this feature asks the owner again.
        self.stand(f"secret:{SPEND}", {"max": "read"})
        self.granted("dev", f"secret:{SPEND}", "read")
        self.assertEqual(self.committed()["agents"]["dev"]["secrets"], {SPEND: "read"})
        hub.validate_team(dict(json.loads(json.dumps(TEAM)),
                               resources={"gmail:support@shop.test": {"max": "send", "to": "workers"}}))
        # The tool says whose responsibility it is, because nothing holds the agent back afterwards.
        text = self.granted("shopper", "gmail:support@shop.test", "write")
        self.assertIn("The grant is the authorization", text)
        self.assertIn("answers for it", text)

    def test_every_grant_is_recorded_and_the_owner_takes_a_hold_back_in_one_step(self):
        self.stand("repo:acme/web", {"max": "write"})
        self.granted("dev", "repo:acme/web", "write")
        self.assertEqual(self.history("repo:acme/web"), [("dev", "write", "manager")])
        row = self.entry("repo:acme/web")["history"][0]
        self.assertTrue(row["ts"] > 0 and len(row["revision"]) == 40, row)
        # One step of the owner ends a hold, whoever gave it, and the record says who ended it.
        before = self.commits()
        code, receipt = self.take("dev", "repo:acme/web")
        self.assertEqual((code, receipt["changed"], receipt["had"]), (200, True, "write"), receipt)
        self.assertEqual(self.commits(), before + 1)
        self.assertNotIn("repos", self.committed()["agents"]["dev"])
        self.assertEqual(self.entry("repo:acme/web")["holders"], [{"agent": "shopper", "level": "read"}])
        self.assertEqual(self.history("repo:acme/web"), [("dev", None, "owner"), ("dev", "write", "manager")])
        self.assertEqual(git("log", "-1", "--format=%s", cwd=self.root / "kit"),
                         "Owner took the GitHub repository acme/web back from dev")
        # The same step again changes nothing, and the record gets no second row.
        self.assertEqual(self.take("dev", "repo:acme/web")[1]["changed"], False)
        self.assertEqual(len(self.history("repo:acme/web")), 2)
        # It reaches a hold that the owner gave itself, outside this feature, and every kind.
        self.assertEqual(self.take("shopper", "repo:acme/web")[1]["had"], "read")
        self.assertEqual(self.entry("repo:acme/web")["holders"], [])
        for rid, level in ((f"secret:{KEY}", "use"), ("tool:crm", "use"), ("gmail:support@shop.test", "write")):
            with self.subTest(rid=rid):
                self.stand(rid, {"max": level})
                self.granted("dev", rid, level)
                self.assertEqual(self.take("dev", rid)[1]["had"], level)
                self.assertEqual(self.entry(rid)["holders"], [])
                self.assertEqual(self.history(rid)[0], ("dev", None, "owner"))
        agent = self.committed()["agents"]["dev"]
        for gone in ("repos", "tools", "secrets", "google"):
            self.assertNotIn(gone, agent)                 # an empty field is not stored
        self.assertEqual(self.take("ghost", "repo:acme/web")[0], 404)
        self.assertEqual(self.take("dev", "tool:nope")[0], 404)              # the fleet holds no such server
        self.assertEqual(self.take("dev", "vpn:acme")[0], 400)
        # A repository has no catalog, so its form is the check: a hold that is not there ends as nothing to do.
        code, receipt = self.take("dev", "repo:nope/none")
        self.assertEqual((code, receipt["changed"], receipt["had"]), (200, False, None), receipt)

    def test_the_manager_grants_to_a_worker_or_a_lead_only_and_never_to_itself(self):
        self.stand("repo:acme/web", {"max": "write"})
        self.assertIn("You never grant to yourself", self.refused("manager", "repo:acme/web", "write"))
        self.assertIn("There is no agent ghost", self.refused("ghost", "repo:acme/web", "write"))
        self.assertNotIn("repos", self.committed()["agents"]["manager"])
        # No worker and no lead has the tool at all: a grant is the manager's own authority.
        self.assertIn("no tool named grant_access", self.refused("dev", "repo:acme/web", "write", by="dev"))
        self.assertIn("no tool named grant_access", self.refused("dev", "repo:acme/web", "write", by="lead"))
        self.assertIn("grant_access", [t["name"] for t in hub.tools_for("manager")])
        self.assertNotIn("grant_access", [t["name"] for t in hub.tools_for("lead")])
        self.assertNotIn("grant_access", [t["name"] for t in hub.tools_for("dev")])

    # ---- the manager reads the pool in see_capacity

    def test_see_capacity_carries_the_pool_so_the_manager_reads_what_it_may_give(self):
        self.stand("repo:acme/web", {"max": "write"})
        self.stand(f"secret:{LOGIN}", {"max": "use"})
        view = hub.capacity_view()
        pool = {p["resource"]: p for p in view["resources"]}
        self.assertEqual(sorted(pool), ["repo:acme/web", f"secret:{LOGIN}"])
        repo = pool["repo:acme/web"]
        self.assertEqual((repo["max"], repo["to"], repo["kind"]), ("write", "workers", "repo"))
        self.assertEqual(repo["levels"], ["read", "write", "deploy"])
        self.assertEqual(repo["held_by"], {"shopper": "read"})
        self.assertEqual(repo["eligible"], ["lead", "dev", "shopper"])     # never the manager: no grant to yourself
        self.assertEqual(pool[f"secret:{LOGIN}"]["eligible"], ["lead", "dev", "shopper"])
        # What the manager reads. Each eligible agent's own line says what it may be given, with what it has.
        text, error = self.call("manager", "see_capacity", {})
        self.assertFalse(error, text)
        self.assertIn("GRANTABLE POOL (what you may give with grant_access", text)
        self.assertIn("repo:acme/web (acme/web): up to write, to any worker or lead. Held by shopper read. "
                      "You may give it to: lead, dev, shopper.", text)
        self.assertIn(f"secret:{LOGIN} (shop.test · admin): up to use, to any worker or lead", text)
        self.assertIn("you may give it: repo:acme/web up to write (has read)", text)       # shopper's own line
        self.assertIn("you may give it: repo:acme/web up to write", text)                  # dev's, with nothing yet
        # Nothing left to give is not offered: the agent that holds the level the owner allows drops off that line.
        self.granted("dev", "repo:acme/web", "write")
        text, _ = self.call("manager", "see_capacity", {})
        self.assertNotIn("repo:acme/web", self.agent_line(text, "dev"))          # dev holds write, the most allowed
        self.assertIn("repo:acme/web up to write (has read)", self.agent_line(text, "shopper"))
        self.assertIn("Held by dev write, shopper read", text)                   # the pool block keeps both holders
        self.assertIn("grant it from the pool above instead of asking the owner", text)
        # It is the same fact that grant_access acts on: what the pool says is eligible, the tool takes.
        for agent in pool["repo:acme/web"]["eligible"]:
            with self.subTest(agent=agent):
                self.assertIsNone(hub.grant_check(agent, "repo:acme/web", "write"))

    def test_an_empty_pool_says_so_and_a_lead_reads_no_pool_at_all(self):
        text, error = self.call("manager", "see_capacity", {})
        self.assertFalse(error, text)
        self.assertIn("none. Every resource is the owner's to give until it makes one grantable", text)
        self.assertNotIn("you may give it:", text)
        self.assertEqual(hub.capacity_view()["resources"], [])
        # A lead has no grant_access, so its own reading names no pool and no grant.
        self.stand("repo:acme/web", {"max": "write"})
        self.assertTrue(hub.capacity_view()["resources"])
        lead = hub.capacity_text(hub.capacity_view(["shopper"]), "", "none", restricted=True, parent=1)
        self.assertNotIn("GRANTABLE POOL", lead)
        self.assertNotIn("you may give it:", lead)
        self.assertNotIn("grant it from the pool", lead)
        self.assertIn("  shopper", lead)                        # it still reads the agent itself
        # The owner's own route carries the pool too, for the app.
        code, data = self.request("/ui/capacity?db=test-generation")
        self.assertEqual(code, 200, data)
        self.assertEqual([p["resource"] for p in data["resources"]], ["repo:acme/web"])
        self.assertEqual(data["resources"][0]["eligible"], ["lead", "dev", "shopper"])   # the manager is not one

    def test_the_pool_is_answered_at_each_call_so_a_running_session_needs_no_restart(self):
        """What a deployment has to know: grant_access is a new tool, so it reaches an agent only in a session that
        starts after it (the tool list is fetched at start; listChanged is false). The pool is not a tool but an
        answer, which the hub computes when see_capacity is called, so a session that is already running reads a new
        standing at its next call. Nothing here caches it."""
        before = [t["name"] for t in hub.tools_for("manager")]
        first, error = self.call("manager", "see_capacity", {})
        self.assertFalse(error, first)
        self.assertIn("none. Every resource is the owner's to give", first)
        self.stand("repo:acme/web", {"max": "write"})            # the owner, while that session is open
        again, error = self.call("manager", "see_capacity", {})
        self.assertFalse(error, again)
        self.assertIn("repo:acme/web (acme/web): up to write", again)
        self.assertNotIn("none. Every resource is the owner's to give", again)
        # The tool list did not change, which is why no new session is needed: the same tool, a new answer.
        self.assertEqual([t["name"] for t in hub.tools_for("manager")], before)
        self.assertIn("grant_access", before)
        # And a grant in that same session shows up in the next call too, without anything restarting.
        self.granted("dev", "repo:acme/web", "write")
        third, _ = self.call("manager", "see_capacity", {})
        self.assertIn("Held by dev write", third)

    # ---- what the file takes

    def test_validate_team_takes_only_a_resource_that_this_team_has(self):
        def bad(pool):
            with self.assertRaises(ValueError, msg=pool) as got:
                hub.validate_team(dict(json.loads(json.dumps(TEAM)), resources=pool))
            return str(got.exception)
        self.assertIn("with a kind of", bad({"vpn:acme": {"max": "use"}}))
        self.assertIn("is no secret that this team has", bad({"secret:bws://" + "0" * 8 + "-0000-0000-0000-" +
                                                              "0" * 12: {"max": "use"}}))
        self.assertIn("is no MCP server that this team has", bad({"tool:nope": {"max": "use"}}))
        self.assertIn("in lower case", bad({"REPO:Acme/Web": {"max": "read"}}))
        self.assertIn("is no email address", bad({"gmail:not-an-email": {"max": "read"}}))
        self.assertIn("max must be one of", bad({"repo:acme/web": {"max": "admin"}}))
        self.assertIn('to is "workers"', bad({"repo:acme/web": {"max": "read", "to": "nosuch"}}))
        self.assertIn("needs max", bad({"repo:acme/web": {}}))
        self.assertIn("needs max", bad({"repo:acme/web": {"max": "read", "extra": 1}}))
        self.assertIn("needs max", bad({"repo:acme/web": {"guard": "money"}}))     # no mark: the grant authorizes
        self.assertIn("up to 256", bad({f"tool:crm{i}": {"max": "use"} for i in range(257)}))
        # The good ones, including a resource that no agent holds yet.
        for pool in ({}, {"repo:acme/other": {"max": "write"}}, {f"secret:{KEY}": {"max": "read", "to": "workers"}},
                     {"drive:a@b.test": {"max": "write_shared"}}, {"tool:github": {"max": "use"}},
                     {"gmail:a@b.test": {"max": "send"}}, {f"secret:{SPEND}": {"max": "read"}}):
            with self.subTest(pool=pool):
                hub.validate_team(dict(json.loads(json.dumps(TEAM)), resources=pool))
        self.assertEqual(self.stand("repo:acme/web", {"max": "read", "to": "nosuch"})[0], 400)
        self.assertEqual(self.stand("vpn:acme", {"max": "use"})[0], 400)
        self.assertEqual(self.stand("repo:acme/web", "open")[0], 400)

    def test_the_owners_route_keeps_the_command_rules_of_every_other_write(self):
        base = self.pool()["sha256"]
        rid = str(uuid.uuid4())
        first = self.stand("repo:acme/web", {"max": "read"}, request_id=rid, base=base)
        self.assertEqual(first[0], 200, first[1])
        again = self.stand("repo:acme/web", {"max": "read"}, request_id=rid, base=base)
        self.assertEqual((again[0], again[1]["replayed"]), (200, True))
        other = self.stand("repo:acme/web", {"max": "write"}, request_id=rid, base=self.pool()["sha256"])
        self.assertEqual(other[0], 409, other[1])
        self.assertEqual(self.stand("repo:acme/web", {"max": "write"}, base=base)[0], 409)      # the old version
        self.assertEqual(self.request("/ui/resources", {"request_id": str(uuid.uuid4()), "db": "other",
                                                        "base_sha256": self.pool()["sha256"],
                                                        "resource": "repo:acme/web", "policy": None})[0], 409)
        self.assertEqual(self.committed()["resources"], {"repo:acme/web": {"max": "read", "to": "workers"}})

    def team_login(self, ref):
        code, team = self.request("/ui/team?db=test-generation")
        self.assertEqual(code, 200, team)
        return team["logins"][ref]
