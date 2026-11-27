"""Owner feature resource_grants: the grantable pool, the manager's grant_access, the record of every grant and the
owner's one step that takes a hold back. The grant is the authorization (the owner, 17 October 2026), so no action is
held back for the owner afterwards and the record is the control. In-process hub and temporary Git repositories; no
helper, vault, GitHub, Google or AI call. No secret value anywhere: a secret is its bws:// reference and
its name."""
from contextlib import ExitStack
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
from unittest.mock import patch

import hub
from test_setup import git
from test_ui_api import OwnerAPI

LOGIN = "bws://11111111-2222-4333-8444-55555555555b"       # a login: the shop admin, which an agent signs in with
KEY = "bws://21111111-2222-4333-8444-55555555555b"         # an API key: the deploy route that an agent reads
SPEND = "bws://31111111-2222-4333-8444-55555555555b"       # the key that pays: grantable like any other
ACME_PAGE = "https://github.com/organizations/acme/settings/installations/7"    # where the owner adds one to the App


class Reading:
    """A read of the list of repositories that runs now (GITHUB_REPOS "reading", the Event of github_repo_list_ahead):
    a call waits for it, and it does not end in the test."""
    def wait(self, timeout=None):
        return False
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
        hub.CFG["google_file"] = str(self.root / "google.json")
        self.addCleanup(hub.CFG.pop, "google_file", None)
        self.google("drive", "gmail.modify")
        hub.CFG["github_app"] = str(self.root / "no-github-app")       # no GitHub call from a helper's session start
        self.addCleanup(hub.CFG.pop, "github_app", None)
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = json.loads(json.dumps(TEAM))
        hub.CFG.update(silence=180, question_wait=120, manager_silence=120, stop_after=60, offline_after=90, tick=5)

    # ---- helpers

    def google(self, *scopes, email="support@shop.test"):
        """The hub's Google file: one account connected, with these services' scopes (short names). The plain form of a
        hub from before 1.202, which the hub reads as it is; no Google call reads it."""
        path = Path(hub.CFG["google_file"])
        path.write_text(json.dumps({"accounts": {email: {
            "refresh_token": "not-a-token", "scopes": [f"https://www.googleapis.com/auth/{s}" for s in scopes]}}}))
        path.chmod(0o600)

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

    def reaches(self, *repos, whole=None):
        """The fleet's GitHub App, read a moment ago (github_repo_known): it reaches these repositories of acme, and
        each repository of the accounts of whole ({account: its repositories}), whose list the hub read a moment ago
        too. Until the test ends, or until the next call."""
        whole = whole or {}
        listed = {a: {"name": a, "repos": sorted(r)} for a, r in whole.items()}
        for held in (patch.object(hub, "github_app", lambda: ("7", "key")),
                     patch.dict(hub.GITHUB_REACH, {"at": hub.now(), "reading": False, "reach": {
                         "pages": {"acme": ACME_PAGE}, "all": set(whole), "repos": set(repos), "install": None}}),
                     patch.dict(hub.GITHUB_REPOS, {"at": hub.now(), "list": listed, "failed": 0.0, "reading": None,
                                                   "part": None, "again": 0.0}),
                     patch.object(hub, "github_repos_read", return_value=(listed, []))):     # no GitHub call
            held.start()
            self.addCleanup(held.stop)

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
        self.assertEqual(repo["grant"], {"max": "read", "to": "workers", "by": "default"})      # the default (1.328)
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

    def test_each_resource_that_the_fleet_holds_is_grantable_by_default(self):
        """Owner feature pool_default (the owner, 24 November 2026: "I think the manager should be able to do that!",
        "the goal is to minimize Needs you cards"): the manager gives each resource that the fleet holds, up to its
        kind's top level, and the owner's standing only narrows it; a repository only up to read (the supervisor's
        decision of 26 November 2026, after the Door area's read A4: a write token's push runs the repository's jobs
        beside their secrets). Bugs: a give of a held secret or repository comes to the owner as a card again; the
        default reaches a repository that no record of the fleet names; the default gives write or deploy of a
        repository, also one that an agent holds by the owner's own grant; or the owner's "Only you" or own level no
        longer counts."""
        self.assertIn("pool_default", self.request()[1]["ui_features"])
        self.assertEqual(self.entry("repo:acme/web")["grant"], {"max": "read", "to": "workers", "by": "default"})
        self.assertEqual(self.entry("gmail:support@shop.test")["grant"], {"max": "write", "to": "workers", "by": "default"})
        # the outward levels come only with their own level: a repository's write and deploy push code that its jobs
        # run beside their secrets and runners, and send mails as the owner to anyone
        for level in ("write", "deploy"):
            said = self.refused("dev", "repo:acme/web", level)
            self.assertIn("The default gives at most read", said)
            # no agent holds it at that level, so the route is the owner's card for dev (the coordinator's validator)
            self.assertIn(f'raise_needs_you(needs_access="repo:acme/web", needs_level="{level}", needs_agent="dev")',
                          said)
        self.assertIn("The default gives at most write", self.refused("dev", "gmail:support@shop.test", "send"))
        self.assertEqual(self.entry(f"secret:{LOGIN}")["grant"], {"max": "read", "to": "workers", "by": "default"})
        self.granted("dev", "repo:acme/web", "read")            # shopper holds it, so the fleet holds it
        self.assertEqual(self.committed()["agents"]["dev"]["repos"], {"acme/web": "read"})
        self.assertFalse(self.committed().get("resources"))     # no entry of the owner's was needed
        self.assertIn("not in the grantable pool", self.refused("dev", "repo:acme/other", "read"))   # no record names it
        # A repository that the fleet's GitHub App reaches is the fleet's too (the owner's card N-327 of 26 November
        # 2026, a read of a repository that the App reached and no agent held): by its name, or by an account whose
        # installation has all of its repositories; never one of the product's own, and none with no reading of the
        # App. Its default stops at read (DEFAULT_TOP), as every repository's does, and a read that the default gave is
        # no step to write (the Door area's read). Bugs: such a give comes to the owner as a card; the default reaches
        # the product's own repositories or its private source (the supervisor, 26 November 2026), a repository of an
        # account that the App does not reach or that has more repositories than the hub read, a name of an account
        # with all of its repositories that the hub's list does not name, or write of one that only the App reaches,
        # at once or after a read that it gave.
        reach = {"pages": {}, "all": {"wholeorg", "bigorg"}, "many": {"bigorg"}, "install": None,
                 "repos": {"acme/other", "founderizer/founderizer", "acme/founderizer-source", "bigorg/listed",
                           "founderizer-gate/founderizer-source"}}
        listed = {"wholeorg": {"name": "WholeOrg", "repos": ["wholeorg/docs", "wholeorg/site"]},
                  "bigorg": {"name": "BigOrg", "repos": ["bigorg/site"]}}     # "many": only what the reading holds
        with patch.dict(hub.GITHUB_REACH, {"at": hub.now(), "reading": False, "reach": reach}), \
                patch.dict(hub.GITHUB_REPOS, {"at": hub.now(), "list": listed}):
            self.assertEqual(hub.resource_standing("repo:acme/other"), {"max": "read", "to": "workers", "by": "default"})
            self.granted("dev", "repo:acme/other", "read")
            self.granted("dev", "repo:wholeorg/site", "read")
            # of an account with all of its repositories, only one that the hub's list names: an invented name would
            # get the agent's read tokens of that account refused at GitHub (the validator's P1)
            self.assertIn("not in the grantable pool", self.refused("dev", "repo:wholeorg/invented", "read"))
            with patch.dict(hub.GITHUB_REPOS, {"at": 0.0, "list": None}):       # no list of the last minute
                self.assertIn("not in the grantable pool", self.refused("lead", "repo:wholeorg/docs", "read"))
            for agent in ("dev", "lead"):            # dev holds it now, by the default's own grant: still read at most
                self.assertIn("The default gives at most read", self.refused(agent, "repo:acme/other", "write"))
            self.refused("dev", "repo:founderizer/founderizer", "read")
            for source in ("acme/founderizer-source", "founderizer-gate/founderizer-source"):
                self.assertIn("the product's own private source", self.refused("dev", f"repo:{source}", "read"))
            self.assertIn("not in the grantable pool", self.refused("dev", "repo:elsewhere/app", "read"))
            self.assertIn("not in the grantable pool", self.refused("dev", "repo:bigorg/site", "read"))
            self.granted("dev", "repo:bigorg/listed", "read")       # one that the hub read, of that account
            # one that an agent holds by the owner's own grant: read at most too, for the holder and for another
            self.assertIn("The default gives at most read", self.refused("lead", "repo:acme/web", "write"))
            self.assertIn("The default gives at most read", self.refused("shopper", "repo:acme/web", "write"))
        with patch.dict(hub.GITHUB_REACH, {"at": hub.now(), "reading": False, "reach": None}):
            self.assertIn("not in the grantable pool", self.refused("lead", "repo:acme/third", "read"))
            # with no reading, one that an agent holds only by the manager's grant stays the fleet's (the coordinator's
            # validator, M2). Bug: it leaves the pool, and the next give of it goes to the owner as a card
            self.granted("lead", "repo:acme/other", "read")
        # the first grant after a start, before any reading, waits for one before LOCK, as change_team and
        # raise_needs_you do (the Door area's and the validator's read). Bug: it is refused as not in the pool
        with patch.dict(hub.GITHUB_REACH, {"at": None, "reading": False, "reach": None}), \
                patch.object(hub, "github_reach_read", return_value=dict(reach, repos={"acme/fourth"})):
            self.granted("dev", "repo:acme/fourth", "read")
        # a raise for read of an all-repositories account's repository reads the hub's list before LOCK too, so no card
        # goes up for one that the default gives (the validator's S1). Bug: with a list older than a minute, the
        # manager's card for it goes to the owner
        def listing():
            hub.GITHUB_REPOS.update(at=hub.now(), list=listed)
            return listed, None
        with patch.dict(hub.GITHUB_REACH, {"at": hub.now(), "reading": False, "reach": reach}), \
                patch.dict(hub.GITHUB_REPOS, {"at": 0.0, "list": None, "failed": 0.0, "reading": None}), \
                patch.object(hub, "github_repo_list", listing), \
                patch.object(hub, "github_app", lambda: ("7", "key")):        # a fleet with its App
            said, error = hub.call_tool("manager", "raise_needs_you", {
                "title": "Let Lead read wholeorg/docs", "why": "Its work reads wholeorg/docs.", "reason": "access",
                "needs_access": "repo:wholeorg/docs", "needs_level": "read",
                "what_to_do": "Give Lead read access to wholeorg/docs."})
            self.assertTrue(error, said)
            self.assertIn("yours to give", said)
        self.assertEqual(self.committed()["agents"]["dev"]["repos"],
                         {"acme/fourth": "read", "acme/other": "read", "acme/web": "read", "bigorg/listed": "read",
                          "wholeorg/site": "read"})
        # the owner's own level opens it (their "At most" on the row), then "Only you", then the default again
        code, receipt = self.stand("repo:acme/web", {"max": "deploy", "to": "workers"})
        self.assertEqual((code, receipt["policy"]), (200, {"max": "deploy", "to": "workers", "by": "owner"}), receipt)
        self.granted("lead", "repo:acme/web", "deploy")         # their own level opens deploy
        code, receipt = self.stand("repo:acme/web", None)
        self.assertEqual((code, receipt["changed"], receipt["policy"]), (200, True, None), receipt)
        self.assertEqual(self.committed()["resources"], {"repo:acme/web": {"owner": True}})
        self.assertEqual((self.entry("repo:acme/web")["grant"], self.entry("repo:acme/web")["kept"]), (None, "owner"))
        self.assertIn("dev, shopper hold it: give that part of the work to dev", self.refused("lead", "repo:acme/web", "read"))
        code, receipt = self.stand("repo:acme/web", "default")
        self.assertEqual((code, receipt["policy"]["by"]), (200, "default"), receipt)
        self.assertNotIn("resources", self.committed())
        self.assertEqual(self.entry("repo:acme/web")["holders"], [{"agent": "dev", "level": "read"},
                                                                  {"agent": "lead", "level": "deploy"},
                                                                  {"agent": "shopper", "level": "read"}])

    def test_what_the_fleet_runs_on_stays_the_owners_by_a_list_in_the_code(self):
        """pool_default's list (resource_kept): a secret whose variable is one of Fleet's own keys and a secret that an
        account names stay the owner's to give, and see_capacity says why. Bugs: the default gives the fleet's own
        GitHub token or an AI account's key to any worker."""
        import lifecycle
        token = "bws://41111111-2222-4333-8444-55555555555b"
        hub.TEAM["logins"][token] = {"title": "GH_TOKEN", "kind": "api_key", "env": "GH_TOKEN"}
        hub.TEAM["accounts"] = {"team-claude": {"kind": lifecycle.ACCOUNT_KINDS[0], "secret": SPEND}}
        for ref in (token, SPEND):
            with self.subTest(ref=ref):
                self.assertIsNone(hub.resource_standing(f"secret:{ref}"))
                self.assertIn("the fleet runs on it, so only the owner gives it",
                              self.refused("dev", f"secret:{ref}", "use"))
        kept = {k["resource"]: k["kept"] for k in hub.capacity_view()["resource_default"]["kept"]}
        self.assertEqual(kept, {f"secret:{token}": "fleet", f"secret:{SPEND}": "fleet"})     # an OAuth app is the default's
        text, _ = self.call("manager", "see_capacity", {})
        self.assertIn(f"secret:{token} (GH_TOKEN): the fleet runs on it, so only the owner gives it. Give the work to "
                      f"an agent that holds it, else ask with raise_needs_you", text)
        self.assertIn("By default: each resource that the fleet holds, to any worker or lead", text)
        # the default's own words say what the owner keeps: a sentence that names deploy alone sends the manager to
        # grant_access at write, which refuses it (the Door area's read of 26 November 2026)
        self.assertIn("for write or deploy of a repository and send of a Gmail", text)
        self.assertIsNone(hub.resource_kept(f"secret:{LOGIN}"))
        # a key of the door's (its providers, a production app's settings) and a GitHub App's key: no agent's box
        hub.TEAM["door"] = {"secrets": [LOGIN]}
        self.assertEqual(hub.resource_kept(f"secret:{LOGIN}"), "fleet")
        hub.TEAM.pop("door")
        hub.TEAM["logins"][token]["env"] = "GITHUB_APP_ACME_KEY"
        self.assertEqual(hub.resource_kept(f"secret:{token}"), "fleet")
        # a secret that the vault holds out of its pool, with no level of theirs: theirs, so no give waits with no word
        self.addCleanup(hub.CENTRAL.update, status=hub.CENTRAL.get("status"))
        hub.CENTRAL["status"] = {"ok": True, "unpooled": [LOGIN]}
        self.assertEqual((hub.resource_kept(f"secret:{LOGIN}"), self.entry(f"secret:{LOGIN}")["kept"]),
                         ("owner", "owner"))

    def test_a_key_that_moves_money_stays_the_owners_until_his_own_level_opens_it(self):
        """The supervisor's decision of 24 November 2026: a secret whose value the central vault reads as a key that
        moves money (its status's "money") is kept as the owner's, with the reason, and their own level on its row opens
        it. Bugs: the default lets the manager give a key that charges and refunds; or the mark outlives their level."""
        self.addCleanup(hub.CENTRAL.update, status=hub.CENTRAL.get("status"))
        hub.CENTRAL["status"] = {"ok": True, "money": [KEY.upper().replace("BWS", "bws")]}
        self.assertEqual((self.entry(f"secret:{KEY}")["grant"], self.entry(f"secret:{KEY}")["kept"]), (None, "owner"))
        self.assertIn("it moves money, so only the owner gives it", self.refused("dev", f"secret:{KEY}", "read"))
        text, _ = self.call("manager", "see_capacity", {})
        self.assertIn(f"secret:{KEY} (DEPLOY_KEY): it moves money, so only the owner gives it", text)
        self.stand(f"secret:{KEY}", {"max": "use"})
        self.assertEqual(self.entry(f"secret:{KEY}")["grant"], {"max": "use", "to": "workers", "by": "owner"})
        self.assertIsNone(self.entry(f"secret:{KEY}")["kept"])
        # their replace of that value with such a key took it out of the vault's pool: kept until they set its level again
        hub.CENTRAL["status"] = dict(hub.CENTRAL["status"], unpooled=[KEY])
        self.assertEqual(self.entry(f"secret:{KEY}")["kept"], "owner")
        self.assertEqual(self.entry(f"secret:{LOGIN}")["grant"]["by"], "default")      # another secret: the default

    def test_the_defaults_words_and_reach_stay_inside_what_the_work_asked(self):
        """The Door area's read of the pool default, 24 November 2026: the words name the level that the work asked
        for, else the lowest, never the top by itself; the door's GitOps repository stays the owner's (a direct token
        would go around the door's rules); and a session that reads strangers' text loads no MCP server that the
        manager gave by the default alone. Bugs: a worker that asked to read is told grant_access(..., level="deploy");
        the default gives a GitOps repository; a manager's grant reaches a closed session with no duty that names it."""
        # the fleet's GitHub App reaches acme's repositories: with none, a repository's card is the owner's step
        reached = patch.object(hub, "team_repo_owner_step", lambda what: False)
        reached.start()
        self.addCleanup(reached.stop)
        said = hub.need_is_yours("manager", "dev needs repo:acme/web for its work")
        self.assertIn('resource="repo:acme/web", level="read")', said)
        # a level above the default (a repository's write and deploy) is the owner's own, so the card for it is
        # raised, not refused as the manager's
        for level in ("write", "deploy"):
            self.assertIsNone(hub.need_is_yours("manager", "dev needs repo:acme/web", level=level))
        # under the owner's own level up to deploy, an ask names its own level, never the top by itself
        hub.TEAM["resources"] = {"repo:acme/web": {"max": "deploy"}}
        self.assertIn('resource="repo:acme/web", level="read")',
                      hub.need_is_yours("manager", "dev needs repo:acme/web for its work"))
        self.assertIn('level="write")', hub.need_is_yours("manager", "dev needs repo:acme/web", level="write"))
        del hub.TEAM["resources"]
        hub.TEAM["door"] = {"gitops": {"acme/web": {"sync": "argocd", "agents": ["shopper"]}}}
        self.assertEqual(hub.resource_kept("repo:acme/web"), "fleet")
        hub.TEAM.pop("door")
        # and an Operator's repository, a commit target of the door, whose commits it checks (NEVER_PATHS)
        hub.TEAM["agents"]["shopper"]["servers"] = {"web-1": "fix"}
        self.assertEqual(hub.resource_kept("repo:acme/web"), "fleet")
        self.refused("dev", "repo:acme/web", "read")       # its words send the work to shopper, which holds it
        hub.TEAM["agents"]["shopper"].pop("servers")
        self.assertTrue(hub.owner_gave("dev", "jobs"))                  # a hold from before the records
        self.granted("dev", "tool:jobs", "use")
        self.assertFalse(hub.owner_gave("dev", "jobs"))                 # the manager's, by the default alone
        # and a session that reads strangers' text gets an explicit list without it: a helper with no list loads each
        # server that needs no session token (fleet.py), so null would load the manager's grant after all
        hub.TEAM["agents"]["dev"]["can"] = []                           # its Shell box off
        servers = hub.closed_extra("dev")["shell_off"]["servers"]
        self.assertIsInstance(servers, list)
        self.assertNotIn("jobs", servers)
        self.stand("tool:jobs", {"max": "use"})
        self.assertTrue(hub.owner_gave("dev", "jobs"))                  # the owner set its level themselves
        hub.TEAM["agents"]["dev"]["can"] = []                           # the stand read the team file again
        self.assertIn("jobs", hub.closed_extra("dev")["shell_off"]["servers"])
        # an MCP server with an OAuth sign-in is in the default too (the owner, 26 November 2026: "it should be the
        # same for apps and other resources!"), and their "Only you" keeps it. Bug: each connected app goes to the
        # owner as a card again, or their "Only you" no longer keeps it
        self.assertEqual((hub.resource_kept("tool:crm"), self.entry("tool:crm")["grant"]),
                         (None, {"max": "use", "to": "workers", "by": "default"}))
        self.granted("dev", "tool:crm", "use")
        # and a hold that the default gave before the app's Connect showed whose account it reaches gives its session no
        # token once the app is kept (the Door area's read, M1). Bug: the worker's next session gets the owner's
        # GitHub user token from a hold that the manager gave at once
        self.assertIsNone(hub.mcp_hold_kept("dev", "crm"))
        with patch.dict(hub.CFG, {"mcp_file": str(self.root / "mcp-crm" / "servers.json")}):
            hub.mcp_store({"servers": {"crm": {"client_id": "c", "refresh_token": "r", "scopes": [],
                                               "token_endpoint": "https://github.com/login/oauth/access_token",
                                               "issuer": "https://github.com/login/oauth"}}})
            self.assertIn("the owner did not give it to this agent", hub.mcp_hold_kept("dev", "crm") or "")
            # and such a hold is no hold for a card or a question, so the ask goes up, and the owner's Give writes the
            # owner's record, which opens the token (the coordinator's validator, K1). Bug: the question says
            # restart_task, the card is refused as held, and the agent asks again and again
            self.assertNotIn("holds the MCP server", hub.card_access("tool:crm", "use", "dev") or "")
            self.assertNotIn("restart_task starts this task again", hub.access_route("dev", "tool:crm", "manager", "use"))
            nid = self.give_card(title="Let Dev use the CRM", why="Its work reads the CRM.", needs_access="tool:crm",
                                 needs_level="use", options=["No: not now"])
            self.assertIsInstance(nid, int, nid)
            code, said = self.request(f"/ui/needs/{nid}", self.command(choice=0))
            self.assertEqual(code, 200, said)
            self.assertIsNone(hub.mcp_hold_kept("dev", "crm"))
        code, receipt = self.stand("tool:crm", None)
        self.assertEqual((code, self.entry("tool:crm")["kept"]), (200, "owner"), receipt)
        # but some apps stay the owner's (the Door area's read and the supervisor's choice of 26 November 2026): one of
        # a payment, code, cloud or DNS host, by its url or by the issuer or token endpoint that its connection named at
        # Connect (a host and its subdomains, never a name that only starts or ends with one), a hosted gateway's, and
        # one connected with an administrator's scope. Bugs: the manager gives Stripe's, GitHub's, Vercel's or Zapier's
        # app, an app that signs in through GitHub, or a Slack admin's app at use; or it keeps an app whose host only
        # looks like one of them
        hub.TEAM["mcp"].update({
            "pay": {"title": "Payments", "url": "https://mcp.stripe.com/", "auth": "oauth"},
            "copilot": {"title": "Code", "url": "https://api.githubcopilot.com/mcp/", "auth": "oauth"},
            "hosting": {"title": "Hosting", "url": "https://mcp.vercel.com/", "auth": "oauth"},
            "gateway": {"title": "Gateway", "url": "https://mcp.gateway.test/mcp", "auth": "oauth"},
            "chat": {"title": "Chat", "url": "https://mcp.chat.test/mcp", "auth": "oauth"},
            "tenant": {"title": "Office", "url": "https://mcp.office.test/mcp", "auth": "oauth"},
            "reader": {"title": "Files", "url": "https://mcp.files.test/mcp", "auth": "oauth"},
            "gateway2": {"title": "Gateway 2", "url": "https://mcp.gateway2.test/mcp", "auth": "oauth"},
            "proxy": {"title": "Proxy", "url": "https://mcp.proxy.test/mcp", "auth": "oauth"},
            "keys": {"title": "Keys", "url": "https://mcp.doppler.com/", "auth": "oauth"},
            "teams": {"title": "Teams", "url": "https://mcp.teams.test/mcp", "auth": "oauth"},
            "notes": {"title": "Notes", "url": "https://mcp.notes.test/mcp", "auth": "oauth"},
            "enterprise": {"title": "Enterprise", "url": "https://api.acme.ghe.com/mcp", "auth": "oauth"},
            "relay": {"title": "Relay", "url": "https://mcp.zapier.com/api/mcp", "auth": "oauth"},
            "lookalike": {"title": "Look", "url": "https://stripe.com.shop.test/mcp", "auth": "oauth"},
            "prefix": {"title": "Prefix", "url": "https://evilstripe.com/mcp", "auth": "oauth"}})
        connection = {"client_id": "c", "refresh_token": "r", "token_endpoint": "https://auth.shop.test/token",
                      "issuer": "https://auth.shop.test", "scopes": ["notes:read", "notes:write"]}
        with patch.dict(hub.CFG, {"mcp_file": str(self.root / "mcp" / "servers.json")}):
            hub.mcp_store({"servers": {
                "gateway": dict(connection, issuer="https://github.com/login/oauth"),       # each of the two alone
                "gateway2": dict(connection, token_endpoint="https://github.com/login/oauth/access_token"),
                "proxy": dict(connection, token_kind="code"),   # its own server passed GitHub's token back
                "teams": dict(connection, scopes=["ChannelMessage.Read.All"]),     # every channel message of a tenant
                "chat": dict(connection, scopes=["channels:read", "admin.users:write"]),
                "tenant": dict(connection, scopes=["User.Read", "https://graph.microsoft.com/Directory.ReadWrite.All"]),
                "reader": dict(connection, scopes=["Files.Read.All", "User.ReadBasic.All"]),     # one user's own reach
                "notes": connection, "lookalike": dict(connection, scopes=["admins_list:read"])}})
            self.assertEqual([hub.resource_kept(f"tool:{t}") for t in ("pay", "copilot", "hosting", "gateway", "chat",
                                                                        "tenant", "enterprise", "relay", "notes",
                                                                        "reader", "lookalike", "prefix",
                                                                        "gateway2", "proxy", "keys", "teams")],
                             ["money", "code", "cloud", "code", "admin", "admin", "code", "gateway", None, None, None,
                              None, "code", "code", "secrets", "admin"])
            self.assertEqual([hub.token_kind(t) for t in ("gho_x", "github_pat_x", "sk_live_x", "sk_test_x", "ya29.x")],
                             ["code", "code", "money", None, None])
            with patch.object(hub, "mcp_saved", lambda: ({}, "the MCP file of the hub cannot be read")):
                self.assertEqual(hub.resource_kept("tool:notes"), "owner")      # kept until the hub can read it
            self.assertEqual({hub.kept_word(w) for w in ("money", "code", "cloud", "admin", "gateway", "secrets")},
                             {"owner"})
            self.assertIn("only the owner", hub.grant_check("dev", "tool:pay", "use") or "")
            self.assertIn("repositories", hub.grant_check("dev", "tool:gateway", "use") or "")
            self.assertIn("administrator", hub.grant_check("dev", "tool:chat", "use") or "")
            self.assertIsNone(hub.grant_check("dev", "tool:notes", "use"))
            self.assertIsNone(hub.grant_check("dev", "tool:lookalike", "use"))

    def test_the_vault_is_owed_a_pool_statement_for_each_secret_of_the_default(self):
        """GET /ui/vault's standing.due (pool_default): the owner's app signs a default_pool for each secret of the
        default that the vault's pool lacks, and an unpool for each pooled one that is the owner's now, an end first;
        none for a secret that the owner took out ("unpooled"), and no pool at all for a vault that does not serve
        default_pool. Bugs: the app pools the owner's "Only you" again under the hood, or sends a statement that an
        older vault refuses at each round."""
        import lifecycle
        hub.TEAM["accounts"] = {"team-claude": {"kind": lifecycle.ACCOUNT_KINDS[0], "secret": SPEND}}
        status = {"pool": [SPEND], "unpooled": [KEY], "default_pools": True}
        self.assertEqual(hub.central_pool_due(status), [{"login": SPEND, "in": False}, {"login": LOGIN, "in": True}])
        self.assertEqual(hub.central_pool_due(dict(status, default_pools=None)), [{"login": SPEND, "in": False}])
        # a name with no value in the vault is owed no pool (the vault refuses it, and it would hold the round), and its
        # unpool is reckoned from the whole wish
        self.assertEqual(hub.central_pool_due(dict(status, stored=[KEY, SPEND])), [{"login": SPEND, "in": False}])
        self.assertEqual(hub.central_pool_due(dict(status, stored=[LOGIN, KEY, SPEND])),
                         [{"login": SPEND, "in": False}, {"login": LOGIN, "in": True}])
        # a pooled secret that is out of the catalog (their removal) is unpooled, so that the vault can remove its value
        gone = "bws://51111111-2222-4333-8444-55555555555b"
        self.assertEqual(hub.central_pool_due(dict(status, pool=[SPEND, gone])),
                         [{"login": SPEND, "in": False}, {"login": gone, "in": False}, {"login": LOGIN, "in": True}])
        # but not while the hub runs on a team.json that breaks its own rules: it can lack secrets never removed
        self.addCleanup(hub.CFG.pop, "team_problem", None)
        hub.CFG["team_problem"] = "agents.x: a rule that this file breaks"
        self.assertEqual(hub.central_pool_due(dict(status, pool=[SPEND, gone])), [{"login": SPEND, "in": False}])
        self.assertEqual(hub.central_removals({gone}, (set(), [])), [])

    def test_the_owners_only_you_from_before_the_default_stays_his(self):
        """The coordinator's validator, 24 November 2026: before 1.328 their "Only you" took the entry out, because no
        entry meant theirs; under the default no entry means the manager's. At the first start, each resource whose
        standing they changed and that has no entry now gets {"owner": true}, once. Bug: the release gives the manager
        every repository, mailbox and server that they had kept."""
        def old_standing(entry, rid="repo:acme/web"):
            def change(team):
                pool = dict(team.get("resources") or {})
                if entry is None:
                    pool.pop(rid, None)
                else:
                    pool[rid] = entry
                team["resources"] = pool
                return True
            hub.save_integration(None, change, f"Owner changed the standing of {rid}")
        old_standing({"max": "write", "to": "workers"})
        old_standing(None)                                      # their "Only you" of before
        old_standing({"max": "read", "to": "workers"}, "repo:acme/other")
        old_standing(None, "repo:acme/other")                   # no agent holds it: no default, so no row comes back
        self.assertEqual(self.entry("repo:acme/web")["grant"]["by"], "default")
        self.addCleanup(hub.POOL_KEPT_TRIED.update, start=hub.POOL_KEPT_TRIED["start"])
        hub.POOL_KEPT_TRIED["start"] = False
        hub.pool_default_keep_seed(hub.now())
        self.assertEqual(self.committed()["resources"], {"repo:acme/web": {"owner": True}})
        self.assertEqual(self.entry("repo:acme/web")["kept"], "owner")
        before = self.commits()
        hub.POOL_KEPT_TRIED["start"] = False
        hub.pool_default_keep_seed(hub.now())                   # once for each database
        self.assertEqual(self.commits(), before)

    def test_the_owner_takes_the_standing_back_and_the_grant_that_was_made_stays(self):
        self.stand("repo:acme/web", {"max": "write"})
        self.granted("dev", "repo:acme/web", "write")
        code, receipt = self.stand("repo:acme/web", None)
        self.assertEqual((code, receipt["changed"], receipt["policy"]), (200, True, None), receipt)
        self.assertEqual(self.committed()["resources"], {"repo:acme/web": {"owner": True}})     # "Only you" keeps it
        self.assertEqual(self.committed()["agents"]["dev"]["repos"], {"acme/web": "write"})   # the owner removes it
        self.assertIn("dev holds it: give that part of the work to dev", self.refused("lead", "repo:acme/web", "write"))
        self.assertIn("the owner keeps it, so only the owner gives it", self.refused("lead", "repo:acme/web", "deploy"))
        self.assertEqual(self.stand("repo:acme/web", None)[1]["changed"], False)

    # ---- the whole loop

    def test_the_whole_loop_from_the_owners_standing_to_the_agents_next_task_session(self):
        """What the owner's side of the pool is for, from end to end. With their "Only you" the manager has nothing to
        give and the refusal says why; after they open it, the manager grants, the agent reads the resource in the task
        session that starts next, and they end the hold in one step. shopper is alone on its machine, so its own helper
        asks the hub for that session as a real one does."""
        def session():
            """What the helper gives this agent's next task session (POST /helper/integrations)."""
            code, data = self.request("/helper/integrations/shopper", {}, source="127.0.0.4")
            self.assertEqual(code, 200, data)
            return data

        # The refusal names the resource as the owner's page names it, and says why it is theirs.
        self.stand("tool:jobs", None)
        self.stand(f"secret:{KEY}", None)
        self.assertIn("You cannot give the MCP server Failed jobs: the owner keeps it, so only the owner gives it",
                      self.refused("shopper", "tool:jobs", "use"))
        self.assertIn("You cannot give the secret DEPLOY_KEY: the owner keeps it, so only the owner gives it",
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
        """A Google service only of an account that allows it now. A Connect asks Google for one service (owner API
        1.185), so an account connected for Gmail is no Drive account: its Drive is not the manager's to give, and the
        owner's page shows it as not connected (the owner, 17 November 2026, read such a Drive row as a Drive that the
        Gmail Connect had linked). The owner's Connect for Drive makes it the manager's to give."""
        self.stand("tool:crm", {"max": "use"})
        self.stand("gmail:support@shop.test", {"max": "write"})
        self.stand("drive:support@shop.test", {"max": "write_shared"})
        self.assertIn("dev now has the MCP server CRM at level use", self.granted("dev", "tool:crm", "use"))
        self.assertEqual(self.committed()["agents"]["dev"]["tools"], ["crm"])
        self.google("gmail.modify")
        self.assertEqual([self.entry(f"{s}:support@shop.test")["connected"] for s in ("gmail", "drive")], [True, False])
        self.assertIn("does not allow Drive now", self.refused("dev", "drive:support@shop.test", "write_shared"))
        capacity = self.call("manager", "see_capacity", {})[0]
        self.assertIn("gmail:support@shop.test", capacity)
        self.assertNotIn("drive:support@shop.test", capacity)
        # The manager's card for that Connect reaches the owner, also when it names the Gmail that is there and the
        # Drive that the pool holds, which no grant gives while the account does not allow it; a card for the Gmail
        # that it may give does not.
        text, error = self.call("manager", "raise_needs_you", {
            "title": "Connect Google Drive of support@shop.test",
            "why": "It is connected for Gmail only, and the shop's files are on Drive.", "what_to_do": "Connect account",
            "reason": "access", "needs_access": "drive:support@shop.test"})
        self.assertFalse(error, text)
        self.assertIsNone(hub.need_is_yours("manager", "Gmail of support@shop.test is there: connect "
                                                       "drive:support@shop.test"))
        for words in ("dev needs the inbox of support@shop.test", "the drivers' mail at support@shop.test"):
            self.assertIn("yours to give", hub.need_is_yours("manager", words))
        self.assertIn("Gmail of support@shop.test", self.granted("dev", "gmail:support@shop.test", "write"))
        self.google("drive", "gmail.modify")            # the owner's Connect for Drive
        self.granted("dev", "drive:support@shop.test", "write_shared")
        self.assertEqual(self.committed()["agents"]["dev"]["google"],
                         {"drive": {"account": "support@shop.test", "level": "write_shared"},
                          "gmail": {"account": "support@shop.test", "level": "write"}})
        self.assertEqual(self.entry("gmail:support@shop.test")["holders"], [{"agent": "dev", "level": "write"}])
        self.assertTrue(self.entry("drive:support@shop.test")["connected"])
        # A later Connect that kept Gmail only: dev's Drive stays, as not connected, and the manager's line for dev's
        # ask sends it to the owner, not to a restart that meets the same refusal.
        self.google("gmail.modify")
        self.assertEqual([self.entry(f"{s}:support@shop.test")["connected"] for s in ("gmail", "drive")], [True, False])
        line = hub.access_route("dev", "drive:support@shop.test", "manager")
        self.assertIn("does not allow Drive now", line)
        self.assertNotIn("its next session has it", line)
        # A Google file that the hub cannot read is said as that, and is no Connect of the owner's.
        Path(hub.CFG["google_file"]).chmod(0o644)
        self.assertIn("cannot read its Google file now", self.refused("dev", "gmail:support@shop.test", "send"))
        Path(hub.CFG["google_file"]).unlink()           # named only in team.json now
        self.assertEqual([self.entry(f"{s}:support@shop.test")["connected"] for s in ("gmail", "drive")], [False, False])
        # An address is no service word: Drive of support@gmail.test, which allows Drive only, is the manager's.
        self.google("drive", email="support@gmail.test")
        self.stand("drive:support@gmail.test", {"max": "read"})
        self.assertIn("yours to give", hub.need_is_yours("manager", "dev needs Drive of support@gmail.test"))
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
        self.assertEqual(self.entry("gmail:support@shop.test")["grant"], {"max": "send", "to": "workers", "by": "owner"})
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
        self.assertIn("GRANTABLE POOL (what you may give with grant_access: each thing that the fleet holds, by the "
                      "owner's default; their own level on a row only widens or narrows it)", text)
        self.assertIn("repo:acme/web (acme/web): the owner's own level, up to write, to any worker or lead. Held by "
                      "shopper read. "
                      "You may give it to: lead, dev, shopper.", text)
        self.assertIn(f"secret:{LOGIN} (shop.test · admin): the owner's own level, up to use, to any worker or lead",
                      text)
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
        self.assertIn("By default: each resource that the fleet holds, to any worker or lead", text)
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
        self.assertNotIn("repo:acme/web (acme/web): the owner's own level", first)
        self.stand("repo:acme/web", {"max": "write"})            # the owner, while that session is open
        again, error = self.call("manager", "see_capacity", {})
        self.assertFalse(error, again)
        self.assertIn("repo:acme/web (acme/web): the owner's own level, up to write", again)
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
        self.assertIn("up to 1024", bad({f"tool:crm{i}": {"max": "use"} for i in range(1025)}))
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

    def test_no_grant_of_the_products_own_repositories_is_kept_because_the_door_refuses_them(self):
        """The door refuses a token for the product's own repositories in every fleet (door_targets.VENDOR_REPOS), so a
        grant of one was kept with no word and never worked: the agent's clone failed (20 November 2026). Every way
        to give one refuses a new hold or a new level with the same words, the line of an access question sends
        nobody to a grant, a holder or the owner, and a grant from before still leaves: a take-back, and a write that
        names another holder as it is (the owner MCP's grant_access), pass."""
        import door_targets

        def repos(**fields):
            return self.request("/ui/team/repos", dict({"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                        "base_sha256": self.pool()["sha256"]}, **fields))
        words = "The door refuses acme/web in every fleet, so no grant of it works: leave it out."
        plain = {"title": "Let Dev read acme/web", "why": "Its work reads acme/web.", "reason": "access",
                 "needs_access": "repo:acme/web", "what_to_do": "Give Dev read access to acme/web."}
        # before acme/web is one of them: a Give card for it, lead holds it beside shopper, and the pool may give it
        self.reaches("acme/web", "acme/storefront")
        nid = self.give_card()
        self.assertIsInstance(nid, int, nid)
        self.assertEqual(repos(repo="acme/web", agent="lead", level="write")[0], 200)
        self.assertEqual(repos(repo="acme/storefront", agent="lead", level="read")[0], 200)
        self.assertEqual(self.stand("repo:acme/web", {"max": "write"})[0], 200)
        with patch.object(door_targets, "VENDOR_REPOS", door_targets.VENDOR_REPOS + ("acme/web", "acme/storefront")):
            before = self.commits()
            # a word that is only the short name of one that lead holds is no item about it: the old hint stays
            said, error = hub.call_tool("manager", "raise_needs_you", dict(plain, needs_access="the storefront's "
                                                                                                "database login"))
            self.assertTrue(error, said)
            self.assertIn("Give it as repo:acme/storefront", said)
            self.assertNotIn("The door refuses", said)
            code, said = self.request(f"/ui/needs/{nid}", self.command(choice=0))      # the card closes, and gives none
            self.assertEqual((code, said.get("code")), (409, "request_answered"), said)
            self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"],
                             "Closed by the hub: the door refuses acme/web in every fleet, so Give gives nothing.")
            line = hub.access_route("dev", "repo:acme/web", "manager")
            self.assertIn(words, line)
            self.assertNotIn("create_task", line)           # lead and shopper hold it, and their clones fail too
            said, error = hub.call_tool("manager", "raise_needs_you", plain)
            self.assertTrue(error, said)
            self.assertIn(words, said)                      # no holder to give the work to, and no owner's grant
            for fields in (dict(agent="dev", level="read"), dict(agent="shopper", level="write"),
                           dict(access={"shopper": "read", "lead": "write", "dev": "read"}),
                           dict(repo=["acme/api", "acme/web"], agent="dev", level="read")):
                with self.subTest(fields=fields):
                    code, said = repos(**dict({"repo": "acme/web"}, **fields))
                    self.assertEqual((code, said.get("code"), said.get("names"), said.get("error")),
                                     (400, "repo_vendor", {"repo": "acme/web"}, words))
            self.assertEqual(self.commits(), before)
            code, said = self.stand("repo:acme/web", {"max": "read"})
            self.assertEqual((code, said.get("code")), (400, "repo_vendor"))
            self.assertNotIn("repo:acme/web", [p["resource"] for p in hub.capacity_view()["resources"]])
            text, _ = self.call("manager", "see_capacity", {})      # a hold from before is no capability
            self.assertIn("acme/web (read; the door refuses it in every fleet, so this agent cannot use it)",
                          self.agent_line(text, "shopper"))
            page = "https://github.com/apps/fleet/installations/new"      # and no GitHub step makes it one
            with patch.object(hub, "github_reach", return_value={"pages": {}, "all": set(), "repos": set(),
                                                                 "install": page}):
                self.assertEqual(hub.github_unreached(["acme/web", "acme/api"]), {"acme/api": page})
            self.assertIn(words, self.refused("dev", "repo:acme/web", "read"))
            self.assertIn(words, self.give_card(needs_access="repo:acme/web"))
            self.assertEqual(self.commits(), before)
            # what was given before leaves: lead by a write that keeps shopper as it is, then shopper, then the pool
            self.assertEqual(repos(repo="acme/web", access={"shopper": "read"})[0], 200)
            self.assertEqual(repos(repo="acme/web", agent="shopper", level=None)[0], 200)
            self.assertEqual(repos(repo="acme/storefront", agent="lead", level=None)[0], 200)
            self.assertEqual(self.stand("repo:acme/web", "default")[0], 200)
            self.assertEqual([a.get("repos") for a in self.committed()["agents"].values()], [None] * 4)
            self.assertNotIn("resources", self.committed())
            # with no standing and no holder, still no route to the owner for it
            self.assertIn(words, self.refused("dev", "repo:acme/web", "read"))
            line = hub.access_route("dev", "repo:acme/web", "manager")
            self.assertIn(words, line)
            self.assertNotIn("Needs-you", line)
            for thing in ("repo:acme/web", "acme/web", "https://github.com/acme/web", "acme/web.git"):   # also in
                # plain words, held by nobody, as a link or as a clone's error writes it
                said, error = hub.call_tool("manager", "raise_needs_you", dict(plain, needs_access=thing))
                self.assertTrue(error, said)
                self.assertIn(words, said)
        # the real list, in any case
        code, said = repos(repo="Founderizer/Founderizer-Apps", agent="dev", level="read")
        self.assertEqual((code, said.get("code"), said.get("names")),
                         (400, "repo_vendor", {"repo": "founderizer/founderizer-apps"}))

    def team_login(self, ref):
        code, team = self.request("/ui/team?db=test-generation")
        self.assertEqual(code, 200, team)
        return team["logins"][ref]

    # ---- Give on a card (the lane "Give on a card", 19 November 2026): an item for access carries its grant

    def keep(self, rid):
        """The owner's "Only you" on one resource, which keeps it theirs under the default (pool_default)."""
        code, receipt = self.stand(rid, None)
        self.assertEqual(code, 200, receipt)

    def give_card(self, **fields):
        """The manager's item for access that names the agent that needs it: its id, or the refusal's words. Under the
        default a card is raised only for what stays the owner's (need_is_yours), so each named resource that the
        default gives the manager is first kept as the owner's ("Only you")."""
        fields = dict({"title": "Let Dev write to acme/web", "why": "Its fix needs a push to acme/web.",
                       "reason": "access", "needs_access": "repo:acme/web", "needs_level": "write",
                       "needs_agent": "dev", "options": ["No: keep it read-only"]}, **fields)
        for rid in (r.strip() for r in str(fields["needs_access"]).split(",")):
            if (hub.resource_standing(rid) or {}).get("by") == "default":
                self.keep(rid)
        said, error = hub.call_tool("manager", "raise_needs_you", fields)
        return said if error else int(said.split("N-")[1].split(".")[0])

    def test_give_on_a_card_gives_its_repository_at_the_press_and_never_lowers_a_level(self):
        """The owner's press of Give is the grant: one real commit of team.json before his answer, and the manager
        reads what it gave. No gives nothing, a replay gives nothing twice, and a level that the agent holds already,
        higher than the card's, stays. Since pool_default a Give card is for what stays the owner's: what he keeps, a
        level above his own, also of a thing that another agent holds; and the manager's own give is no card."""
        self.reaches("acme/web", "acme/api", "acme/docs")
        nid = self.give_card()
        self.assertIsInstance(nid, int, nid)
        need = hub.need_view(hub.q1("SELECT * FROM needs WHERE id=?", (nid,)))
        self.assertEqual(need["options"], ["Give Dev write", "No: keep it read-only"])
        self.assertEqual(need["give"], {"agent": "dev", "level": "write", "repos": ["acme/web"], "resources": []})
        # the hub writes Give, so the manager's recommendation "Give" is that option (owner API 1.269), and a word
        # that is no option is refused
        hub.q("DELETE FROM needs WHERE id=?", (nid,))
        given = self.give_card(recommended="Give")
        self.assertEqual(hub.q1("SELECT recommended FROM needs WHERE id=?", (given,))["recommended"], "Give Dev write")
        hub.q("DELETE FROM needs WHERE id=?", (given,))
        self.assertIn("recommended is one of options", self.give_card(recommended="Yes"))
        self.assertIn("recommended is one of options", self.give_card(recommended="Give no access yet"))
        nid = self.give_card()
        self.assertEqual(need["todo"], "Press Give: it gives Dev write access to acme/web.")
        self.assertNotIn("give_agent", need)
        self.assertIn("need_give", self.request()[1]["ui_features"])
        before = self.commits()
        press = self.command(choice=0)
        code, receipt = self.request(f"/ui/needs/{nid}", press)
        self.assertEqual(code, 200, receipt)
        self.assertEqual(self.committed()["agents"]["dev"]["repos"], {"acme/web": "write"})
        self.assertEqual(self.commits(), before + 1)
        # the owner's record of the repository that the press gave, as each other kind gets one: so the door makes no
        # commit target of a Give at read (door_commit_holds). Bug: a Give writes no row, and reads as a page grant.
        row = hub.q1("SELECT level, by FROM resource_grants WHERE resource='repo:acme/web' AND agent='dev' "
                     "ORDER BY id DESC LIMIT 1")
        self.assertEqual((row["level"], row["by"]), ("write", "owner"))
        self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"], "Give Dev write")
        self.assertIn("The hub gave it at this press",
                      hub.q1("SELECT text FROM events WHERE id=?", (receipt["event_id"],))["text"])
        told = hub.q1("SELECT text FROM events WHERE agent='manager' AND text LIKE '[hub] The owner pressed Give%'")
        self.assertIn(f"N-{nid} (Let Dev write to acme/web): dev has write access to acme/web now", told["text"])
        code, again = self.request(f"/ui/needs/{nid}", press)
        self.assertEqual((code, again["replayed"], self.commits()), (200, True, before + 1))
        # No: nothing changes, and its words go to the manager as every answer's do
        other = self.give_card(title="Let Lead write to acme/api", why="Its fix needs acme/api.",
                               needs_access="repo:acme/api", needs_agent="lead")
        kept = self.commits()       # with the owner's "Only you" on acme/api, which the App reaches (github_reaches)
        self.assertEqual(self.request(f"/ui/needs/{other}", self.command(choice=1))[0], 200)
        self.assertEqual((self.commits(), self.committed()["agents"]["lead"].get("repos")), (kept, None))
        # deploy that came another way after the card stays deploy at the press of Give write
        third = self.give_card(title="Let Lead write to acme/docs", why="Its fix needs acme/docs.",
                               needs_access="repo:acme/docs", needs_agent="lead")
        code, given = self.request("/ui/team/repos", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                      "base_sha256": self.pool()["sha256"], "repo": "acme/docs",
                                                      "agent": "lead", "level": "deploy"})
        self.assertEqual(code, 200, given)
        self.assertEqual(self.request(f"/ui/needs/{third}", self.command(choice=0))[0], 200)
        self.assertEqual(self.committed()["agents"]["lead"]["repos"], {"acme/docs": "deploy"})
        # what one press cannot give is refused before it reaches the owner
        for fields, words in ((dict(needs_access=f"secret:{KEY}"), "needs_level must be one of use, read"),
                              (dict(needs_agent="nobody"), "there is no agent nobody"),
                              (dict(needs_agent="manager"), "manager is not one now"),
                              (dict(needs_level="admin"), "the level that Give gives"),
                              (dict(title="Let Dev push its fix", why="Its fix needs a push to acme-ops/web."),
                               "names the repository that Give gives as acme/web"),
                              (dict(options=["Give Dev read", "No"]), "your options are only the no"),
                              (dict(multi=True), "leave multi out")):
            with self.subTest(fields=fields):
                said = self.give_card(**fields)
                self.assertIsInstance(said, str)
                self.assertIn(words, said)
        def raw(**fields):      # the manager's own item, with no "Only you" before it, which give_card presses
            said, error = hub.call_tool("manager", "raise_needs_you", dict(
                {"title": "Let Dev write to acme/web", "why": "Its fix needs a push to acme/web.", "reason": "access",
                 "needs_access": "repo:acme/web", "needs_level": "write", "needs_agent": "dev", "options": ["No"]},
                **fields))
            return said if error else int(said.split("N-")[1].split(".")[0])
        # A key that the default gives is the manager's own give to the agent that the card names. Bug: the refusal
        # sends the manager to write the owner's steps, also for a key that it gives itself (N-300, N-313).
        self.assertIn(f'is yours to give: grant_access(agent="dev", resource="secret:{LOGIN}", level="use")',
                      raw(needs_access=f"secret:{LOGIN}", needs_level="use"))
        # A key that the owner keeps (give_card kept DEPLOY_KEY above): the central vault seals it only by the owner's
        # Mac's signed grant, and a press of Give signs nothing. Bug: a Give of a key that answers as given while no session of the
        # agent gets it.
        self.assertIn("The secret DEPLOY_KEY is a key or a login, whose grant the owner's Mac signs, so Give does not "
                      "give it: leave needs_agent out.",
                      self.give_card(needs_access=f"secret:{KEY}", needs_level="read"))
        # The owner's own level, write, keeps deploy theirs: a Give card for deploy, whose press gives exactly that
        # level.
        self.stand("repo:acme/web", {"max": "write"})
        deploy = self.give_card(title="Let Dev deploy acme/web", why="Its release deploys acme/web.",
                                needs_level="deploy")
        self.assertIsInstance(deploy, int, deploy)
        self.assertEqual(self.request(f"/ui/needs/{deploy}", self.command(choice=0))[0], 200)
        self.assertEqual(self.committed()["agents"]["dev"]["repos"], {"acme/web": "deploy"})
        # What the owner keeps and another agent holds at the needed level is no card: that agent does that part of the
        # work (the owner, 29 October 2026: asked only for what no agent holds), and so does the named agent with its
        # own hold. Bug: a Give card goes up while dev holds deploy, a card that the owner need not answer.
        self.keep("repo:acme/web")
        self.assertIn("Not raised: dev (deploy) holds the GitHub repository acme/web",
                      self.give_card(title="Let Shopper write to acme/web", needs_agent="shopper"))
        self.assertIn("Not raised: dev (deploy) holds the GitHub repository acme/web", self.give_card())
        # A repository whose commits the door checks. Bug: Give writes a grant that lets a session commit around the
        # door's checks (.github/**, policy.hujson): of one that an Operator holds (lead, with a server), raised before
        # or after that, or of one that the door made, at deploy or to an Operator (new-projects plan N3).
        api = dict(title="Let Dev write to acme/api", why="Its fix needs acme/api.", needs_access="repo:acme/api")
        early = raw(**api)
        self.assertIsInstance(early, int, early)
        hub.TEAM["agents"]["lead"].update(servers={"web-1": "fix"}, repos={"acme/api": "write"})
        words = ("The door checks each commit to acme/api, which it syncs to a server or which an Operator holds, so "
                 "Give does not give it")
        self.assertIn(words, raw(**api))
        code, said = self.request(f"/ui/needs/{early}", self.command(choice=0))
        self.assertEqual((code, said.get("code")), (409, "request_answered"), said)
        self.assertIn(words, hub.q1("SELECT answer FROM needs WHERE id=?", (early,))["answer"])
        self.assertNotIn("acme/api", self.committed()["agents"]["dev"]["repos"])
        with patch.object(hub, "door_made", lambda repo: repo == "acme/new"):
            new = dict(title="Let Dev deploy acme/new", why="Its release needs acme/new.", needs_access="repo:acme/new")
            self.assertIn("The door made acme/new: nobody gets deploy there", raw(**new, needs_level="deploy"))
            self.assertIn("Lead holds a server through the door, so Give does not give it",
                          raw(**dict(new, title="Let Lead write to acme/new", needs_agent="lead")))
        # A repository that the hub does not read in what its GitHub App reaches (the owner's card N-327, 26 November
        # 2026: Give on a name that an agent made up). Bugs: a Give card goes up that gives no token, or nothing at
        # all; a card from before for a name that does not exist, which the press or the sweep gives anyway; one that
        # they close on a reading that can miss a page (a door's); a refusal that guesses while the hub cannot tell; or
        # a list check that refuses each repository of an account that the App reaches whole.
        old = dict(title="Let Dev write to acme/old", why="Its fix needs acme/old.", needs_access="repo:acme/old")
        self.reaches("acme/web", "acme/api", "acme/docs", "acme/old")
        pressed, swept = raw(**old), raw(**dict(old, needs_agent="lead", title="Let Lead write to acme/old"))
        self.assertTrue(all(isinstance(x, int) for x in (pressed, swept)), (pressed, swept))
        self.reaches("acme/web", "acme/api", "acme/docs")      # a reading of a moment ago does not name it
        gone = ("The fleet's GitHub App does not reach acme/old, so Give gives no token for it: it may not exist, or "
                "the owner did not add it to the App.")
        self.assertIn(f"{gone} Ask the agent where it saw that name, and check it first. A card for it goes up only "
                      f"as the owner's step to add it to the App at {ACME_PAGE}, without Give: leave needs_agent out.",
                      raw(**old))
        before = self.commits()             # a card from before: "unreached" can be a page that a door missed
        code, said = self.request(f"/ui/needs/{pressed}", self.command(choice=0))
        self.assertEqual((code, self.commits()), (200, before + 1), said)
        self.assertEqual(self.committed()["agents"]["dev"]["repos"].get("acme/old"), "write")
        answer = lambda nid: hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"]  # noqa: E731
        t0 = hub.now()
        for t in (t0, t0 + hub.NEED_GIVE_WAIT + 1):
            hub.need_look_sweep(t)
        self.assertIsNone(answer(swept))
        # the App reaches each repository of acme now, and its list does not hold acme/old: the sweep closes the card
        self.reaches("acme/web", whole={"acme": ["acme/api", "acme/docs", "acme/web"]})
        for t in (t0 + 2 * hub.NEED_GIVE_WAIT + 2, t0 + 3 * hub.NEED_GIVE_WAIT + 3):
            hub.need_look_sweep(t)
        self.assertEqual(answer(swept), "Closed by the hub: acme/old does not exist: the fleet's GitHub App reaches "
                                        "each repository of acme, and acme/old is not one of them, or it is archived, "
                                        "so Give gives nothing.")
        # an account that the App reaches whole: the hub's list of it names what exists, and the raise reads that list
        # again first when it is older than a minute (github_repo_ahead). Bugs: each Give for such an account is refused
        # while nothing else reads the list; a press gives a repository that is gone since
        self.reaches("acme/web", whole={"beta": ["beta/site"]})
        typo = dict(title="Let Dev write to beta/sight", why="Its fix needs beta/sight.",
                    needs_access="repo:beta/sight")
        missing = ("beta/sight does not exist: the fleet's GitHub App reaches each repository of beta, and beta/sight "
                   "is not one of them, or it is archived, so Give gives nothing.")
        self.assertIn(f"{missing} Check the name with the agent that gave it, and raise no card for this name.",
                      raw(**typo))
        made = ({"beta": {"name": "beta", "repos": ["beta/sight", "beta/site"]}}, [])      # beta/sight is made now
        with patch.dict(hub.GITHUB_REPOS, {"at": 0.0, "failed": 0.0}), \
                patch.object(hub, "github_repos_read", return_value=made):
            sight = raw(**typo)
        self.assertIsInstance(sight, int, sight)
        gone = {"beta": {"name": "beta", "repos": ["beta/site"]}}           # and it is gone again: a list that a raise
        before = self.commits()                                             # read a moment ago (the press reads none)
        with patch.dict(hub.GITHUB_REPOS, {"at": hub.now(), "list": gone}):
            code, said = self.request(f"/ui/needs/{sight}", self.command(choice=0))
        self.assertEqual((code, said.get("code"), self.commits()), (409, "request_answered", before), said)
        self.assertEqual(answer(sight), f"Closed by the hub: {missing}")
        site = raw(title="Let Dev write to beta/site", why="Its fix needs beta/site.", needs_access="repo:beta/site")
        self.assertIsInstance(site, int, site)
        # a problem in one source does not stop the list of an account that a source read whole. Bug: each Give of
        # such an account waits while the door does not answer
        part = ({"beta": {"name": "beta", "repos": ["beta/site"]}}, ["the door does not answer"])
        with patch.dict(hub.GITHUB_REPOS, {"at": 0.0, "failed": 0.0}), \
                patch.object(hub, "github_repos_read", return_value=part):
            self.assertIn(missing, raw(**typo))
            door = {"address": "100.64.0.9", "port": 8766, "token": "t" * 43, "record": "r" * 43}
            with patch.object(hub, "door_conf", return_value=door):     # two sources: the other can hold more of beta
                self.assertIn("The hub cannot tell whether beta/sight exists (its last list of the repositories of "
                              "beta had a problem: the door does not answer)", raw(**typo))
        # a saved list that does not hold a name is read again once. Bug: a repository made a moment ago is refused
        # as one that does not exist
        made = ({"beta": {"name": "beta", "repos": ["beta/new", "beta/site"]}}, [])
        with patch.dict(hub.GITHUB_REPOS, {"again": 0.0}), patch.object(hub, "github_repos_read", return_value=made):
            new = raw(title="Let Dev write to beta/new", why="Its fix needs beta/new.", needs_access="repo:beta/new")
        self.assertIsInstance(new, int, new)
        hub.q("DELETE FROM needs WHERE id=?", (new,))
        # a Give of several repositories reads before LOCK for each of them. Bug: only the first, so a second one of an
        # account that the App reaches whole waits for a list that no call reads
        self.reaches("acme/web", "acme/free", whole={"beta": ["beta/site"]})
        with patch.dict(hub.GITHUB_REPOS, {"at": 0.0}):
            both = raw(title="Let Dev write to two repositories", why="Its fix needs acme/free and beta/site.",
                       needs_access="repo:acme/free, repo:beta/site")
        self.assertIsInstance(both, int, both)
        hub.q("DELETE FROM needs WHERE id=?", (both,))
        # While a read that can tell is still to come, the refusal says only to try again; after a read that ended with
        # a fault, which can last, it names the fault, and the plain card keeps its checks (test_card_reasons). Bugs:
        # a Give on a guess; a manager that waits for ever for a read that failed
        web = dict(title="Let Lead write to acme/web", needs_agent="lead")
        reach = hub.GITHUB_REACH["reach"]
        untold = "try again in a minute, and raise no card for this name until it can tell."
        fault = "so Give does not give it. Check the name with the agent that gave it, and leave needs_agent out."
        for held, words in (
                ((patch.dict(hub.GITHUB_REPOS, {"at": 0.0, "reading": Reading(), "part": None, "failed": 0.0}),),
                 "The hub cannot tell yet whether beta/sight exists (it has no list from the last minute of the "
                 f"repositories of beta, all of which its GitHub App reaches): {untold}"),
                ((patch.dict(hub.GITHUB_REPOS, {"at": 0.0, "reading": Reading(), "failed": hub.now() - 70, "part": {
                    "at": hub.now() - 70, "list": {}, "problem": "the door does not answer"}}),),   # the next read runs
                 "The hub cannot tell whether beta/sight exists (its last list of the repositories of beta had a "
                 f"problem: the door does not answer), {fault}"),
                ((patch.dict(hub.GITHUB_REPOS, {"at": 0.0, "reading": None, "part": None, "failed": hub.now()}),),
                 "The hub cannot tell whether beta/sight exists (its last read of the list of the repositories of beta "
                 f"failed), {fault}"),
                ((patch.dict(hub.GITHUB_REACH, {"at": hub.now() - hub.GITHUB_REACH_FRESH}),
                  patch.object(hub, "github_reach", lambda wait=0: reach)),     # its next read did not come yet
                 "The hub cannot tell yet whether acme/old exists (its newest reading of what its GitHub App reaches "
                 f"is older than a minute): {untold}"),
                ((patch.dict(hub.GITHUB_REACH, {"reach": None, "error": None}),),
                 "The hub cannot tell yet whether acme/web exists (it has no reading yet of what its GitHub App "
                 f"reaches): {untold}"),
                ((patch.dict(hub.GITHUB_REACH, {"reach": None, "error": "GitHub did not answer"}),),
                 "The hub cannot tell whether acme/web exists (its last reading of what its GitHub App reaches failed: "
                 f"GitHub did not answer), {fault}"),
                ((patch.dict(hub.GITHUB_REPOS, {"at": 0.0, "part": None, "failed": 0.0, "reading": None}),
                  patch.object(hub, "github_repos_read", return_value=({}, ["the door does not answer"]))),
                 "The hub cannot tell whether beta/sight exists (its last list of the repositories of beta had a "
                 f"problem: the door does not answer), {fault}"),
                ((patch.dict(hub.GITHUB_REACH["reach"], {"many": {"beta"}}),),      # more than the hub reads
                 "The hub cannot tell whether beta/sight exists (its GitHub App reaches more repositories of beta "
                 f"than it reads), {fault}"),
                ((patch.object(hub, "github_app", side_effect=hub.GitHubError("mode 644")),),
                 f"The hub cannot tell whether acme/web exists (it cannot read its GitHub App file now), {fault}"),
                ((patch.object(hub, "github_app", lambda: None),
                  patch.dict(hub.TEAM, {"door": {"address": "100.64.0.9"}})),
                 f"The hub cannot tell whether acme/web exists (it cannot read its door's file now), {fault}"),
                ((patch.object(hub, "github_app", lambda: None),),
                 "The fleet has no GitHub App, so Give gives no token for acme/web. Ask the agent where it saw that "
                 "name, and check it first. A card for it goes up only as the owner's step to connect GitHub in "
                 "Founderizer and choose acme/web, without Give")):
            with self.subTest(words=words), ExitStack() as stack:
                for one in held:
                    stack.enter_context(one)
                self.assertIn(words, raw(**(typo if "beta" in words else old if "acme/old" in words else web)))
        # A list read that ends with a problem after the call's wait (a door that times out): no read starts again for
        # a minute, so the next raise names the fault. Bug: each raise starts a read, waits, and the manager is told to
        # try again for ever (M4)
        # And the read's end is signalled before its log line, which takes LOCK (M5). Bug: a read thread that waits
        # for LOCK, which the minute's tick holds while it waits for this read, so the tick waits its full time.
        gate, seen, real_log = threading.Event(), [], hub.log

        def slow():
            gate.wait(5)
            return {}, ["the door does not answer"]

        def logged(agent, what):
            if "the list of the repositories" in what:
                seen.append((hub.GITHUB_REPOS["reading"] is None, running.is_set()))
            return real_log(agent, what)
        with patch.dict(hub.GITHUB_REPOS, {"at": 0.0, "part": None, "failed": 0.0, "reading": None, "told": None}), \
                patch.object(hub, "github_repos_read", slow), patch.object(hub, "GITHUB_REACH_WAIT", 0.2), \
                patch.object(hub, "log", logged):
            self.assertIn("The hub cannot tell yet whether beta/sight exists", raw(**typo))
            running = hub.GITHUB_REPOS["reading"]       # Vault's Event: the read still runs
            gate.set()
            self.assertTrue(running.wait(5))
            self.assertIn("The hub cannot tell whether beta/sight exists (its last list of the repositories of beta "
                          "had a problem: the door does not answer)", raw(**typo))
            for _ in range(100):        # the thread writes its log line just after the end that it signalled
                if seen:
                    break
                time.sleep(0.01)
            self.assertEqual(seen, [(True, True)])
        # One wait for all the repositories of a Give (S5). Bug: each waits its own GITHUB_REACH_WAIT, so a Give of
        # 50 repositories waits 200 seconds before LOCK.
        gate = threading.Event()
        with patch.dict(hub.GITHUB_REPOS, {"at": 0.0, "part": None, "failed": 0.0, "reading": None}), \
                patch.object(hub, "github_repos_read", slow), patch.object(hub, "GITHUB_REACH_WAIT", 0.3):
            t0 = time.monotonic()
            raw(title="Let Dev write to five repositories", why="Its fix needs them.",
                needs_access=", ".join(f"repo:beta/part{i}" for i in range(5)))
            self.assertLess(time.monotonic() - t0, 1.2)
            running = hub.GITHUB_REPOS["reading"]
            gate.set()
            self.assertTrue(running is None or running.wait(5))
        # and a card from before stays while the hub cannot tell: its press gives, as before. Bug: a press that closes
        # the owner's card on a guess while GitHub does not answer
        with patch.dict(hub.GITHUB_REACH, {"reach": None}):
            self.assertEqual(self.request(f"/ui/needs/{site}", self.command(choice=0))[0], 200)
        self.assertEqual(self.committed()["agents"]["dev"]["repos"].get("beta/site"), "write")

    def test_a_give_card_for_several_repositories_closes_by_itself_once_given_another_way(self):
        """And a card for a mailbox, once the owner gave it on its own page (F6 piece 2). Believable bug: a card that
        stays open, so that its press gives what the agent holds already, or that closes before the agent holds it."""
        self.reaches("acme/api", "acme/docs")
        nid = self.give_card(title="Let Lead read the shop's repositories", why="Its review reads them.",
                             needs_access="repo:acme/api, repo:acme/docs", needs_level="read", needs_agent="lead",
                             options=None)
        mail = self.give_card(title="Let Lead read support@shop.test", why="Its review reads that mail.",
                              needs_access="gmail:support@shop.test", needs_level="read", needs_agent="lead",
                              options=None)
        need = hub.need_view(hub.q1("SELECT * FROM needs WHERE id=?", (nid,)))
        self.assertEqual(need["options"], ["Give Lead read on 2 repositories", "No"])
        self.assertIn("Give gives Lead read access to these repositories:\n- acme/api\n- acme/docs", need["details"])
        code, given = self.request("/ui/team/repos", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                      "base_sha256": self.pool()["sha256"],
                                                      "repo": ["acme/api", "acme/docs"], "agent": "lead",
                                                      "level": "write"})
        self.assertEqual(code, 200, given)
        t0 = hub.now()
        hub.need_look_sweep(t0)             # held now: the card waits a moment for a press that answers it
        self.assertIsNone(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"])
        code, given = self.request("/ui/team/google", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                       "base_sha256": self.pool()["sha256"], "service": "gmail",
                                                       "account": "support@shop.test", "access": {"lead": "write"}})
        self.assertEqual(code, 200, given)
        hub.need_look_sweep(t0 + hub.NEED_GIVE_WAIT + 1)
        self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"],
                         "Closed by the hub: Lead has read access to the 2 repositories now, given another way.")
        self.assertIsNone(hub.q1("SELECT answer FROM needs WHERE id=?", (mail,))["answer"])     # seen a moment ago
        hub.need_look_sweep(t0 + 2 * hub.NEED_GIVE_WAIT + 2)
        self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (mail,))["answer"],
                         "Closed by the hub: Lead has read access to the Gmail mailbox support@shop.test now, given "
                         "another way.")
        told = [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' ORDER BY id DESC LIMIT 2")]
        self.assertIn(f"N-{nid} (Let Lead read the shop's repositories)", told[1])
        self.assertIn(f"N-{mail} (Let Lead read support@shop.test)", told[0])

    def test_only_a_press_of_give_on_the_mac_or_a_pc_gives(self):
        """A phone shows no Details, so its press gives nothing and answers nothing; Give's words typed give nothing
        either; and a card whose agent left the fleet closes, at a press and by itself."""
        self.reaches("acme/web")
        nid = self.give_card()
        mail = self.give_card(title="Let Lead answer support@shop.test", why="It answers that mail.", options=None,
                              needs_access="gmail:support@shop.test", needs_level="send", needs_agent="lead")
        before = self.commits()
        with patch.object(hub, "owner_device_at", lambda address: "phone" if address == "100.64.0.9" else None), \
                patch.object(hub, "owner_device_class", lambda device: "iPhone" if device == "phone" else None):
            for card in (nid, mail):        # a repository, and a mailbox (F6 piece 2)
                code, said = hub.phone_submit(self.command(choice=0), "a phone", card, address="100.64.0.9",
                                              device="phone")
                self.assertEqual((code, said["error"]), (409, hub.TEAM_PRESS_WHERE))
        # the press race (25 November 2026): the route checked the device (ui_allowed), and the owner removed it while
        # the press waited for the hub's writes. Its address maps to no device then, which a lookup reads as the
        # owner's computer: neither a PC's press nor a phone's gives
        with patch.object(hub, "owner_device_at", lambda address: None), \
                patch.object(hub, "owner_device_class", lambda device: {"pc": "Windows", "phone": "iPhone"}.get(device)):
            for device in ("pc", "phone"):
                for card in (nid, mail):
                    said = hub.phone_submit(self.command(choice=0), "a device", card, address="100.64.0.9",
                                            device=device)
                    self.assertEqual((said[0], said[1].get("code")), (403, "not_owner_device"), said)
        self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (mail,))["answer"], None)
        self.assertNotIn("google", self.committed()["agents"]["lead"])
        code, said = self.request(f"/ui/needs/{nid}", self.command(answer="give dev write"))
        self.assertEqual((code, said["error"]), (409, hub.TEAM_PRESS_WORDS))
        self.assertEqual((self.commits(), hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"]),
                         (before, None))
        del hub.TEAM["agents"]["dev"]
        self.assertEqual(self.request(f"/ui/needs/{nid}", self.command(choice=0))[0], 409)
        self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"],
                         "Closed by the hub: Dev cannot take this access any more, so Give gives nothing.")
        self.assertIn(f"N-{nid} (Let Dev write to acme/web), but Dev cannot take this access any more, so Give gives "
                      f"nothing. The hub closed the card.",
                      hub.q1("SELECT text FROM events WHERE agent='manager' ORDER BY id DESC LIMIT 1")["text"])
        self.assertEqual(self.commits(), before)

    def test_a_press_of_give_on_a_pc_keeps_the_pc_in_its_second_call(self):
        """A press of Give runs phone_submit again in the turn of the hub's writes (kit_lock), and that second call
        keeps the device that the route found: an enrolled PC's press, through the real route, gives and keeps the
        PC's hand and place (UI-API.md 1.351). A second call that drops the device fails here (its device is a required
        keyword, and None would write the computer's hand); one that reads the address again after Remove device is the
        press race of test_only_a_press_of_give_on_the_mac_or_a_pc_gives."""
        self.reaches("acme/web")    # Give goes up only for a repository that the App reaches (need_give_reach)
        nid = self.give_card()      # first: since the pool default it keeps the repository as the owner's, a commit
        # the PC in team.json by the hub's own save, so that the Give's commit, which reads team.json again, keeps it
        hub.save_owner_device({"device": "pc", "label": "PC", "address": "127.0.0.6", "base_sha256": None})
        key = hub.enroll_device("pc", hub.new_device_code("pc")["code"], kind="windows")["key"]
        before = self.commits()
        press = self.command(choice=0)
        code, receipt = self.request(f"/ui/needs/{nid}", press, {
            "Content-Type": "application/json", "X-Fleet-Client": "founderizer-windows/1/test",
            "Authorization": "Bearer " + key, "X-Test-Source": "127.0.0.6"})
        self.assertEqual(code, 200, receipt)
        self.assertEqual(self.committed()["agents"]["dev"]["repos"], {"acme/web": "write"})
        self.assertEqual(self.commits(), before + 1)
        self.assertEqual(tuple(hub.q1("SELECT hand, device FROM ui_requests WHERE request_id=?",
                                      (press["request_id"],))), ("device", "pc"))

    def test_give_on_a_card_gives_one_mailbox_drive_or_mcp_server_and_takes_none_away(self):
        """F6 piece 2: Give on a card for a mailbox gives that level of that mailbox to that agent at the owner's press,
        and nothing before it. Believable bugs: a press that gives more than the card named (the account's Drive, a
        higher level, another agent); an option that does not say what it gives, which on the Mac, where the card
        draws no step, lets a card about mail give the Drive of the same address; a card for a thing that the fleet
        does not hold or whose grant the owner's Mac signs (an MCP server with a key); a Give that takes the place of
        the agent's Drive of another account; a press that lowers a level given another way, or gives after a fact
        that the card checked changed; and more open items with Give than the hub counts."""
        mail = dict(title="Let Dev read support@shop.test", why="Its triage reads the mail of support@shop.test.",
                    needs_access="gmail:support@shop.test", needs_level="read", options=None)
        nid, before, team = self.give_card(**mail), self.commits(), self.committed()
        self.assertIsInstance(nid, int, nid)
        need = hub.need_view(hub.q1("SELECT * FROM needs WHERE id=?", (nid,)))
        self.assertEqual((need["options"], need["todo"], need["give"]),
                         (["Give Dev read access to the Gmail mailbox support@shop.test", "No"],
                          "Press Give: it gives Dev read access to the Gmail mailbox support@shop.test.",
                          {"agent": "dev", "level": "read", "repos": [], "resources": ["gmail:support@shop.test"]}))
        self.assertEqual(self.commits(), before)
        code, receipt = self.request(f"/ui/needs/{nid}", self.command(choice=0))
        self.assertEqual(code, 200, receipt)
        gmail = {"gmail": {"account": "support@shop.test", "level": "read"}}
        self.assertEqual(self.committed(), dict(team, agents=dict(team["agents"], dev=dict(team["agents"]["dev"],
                                                                                            google=gmail))))
        self.assertEqual((self.commits(), self.history("gmail:support@shop.test")),
                         (before + 1, [("dev", "read", "owner")]))
        self.assertIn("The hub gave it at this press", hub.q1("SELECT text FROM events WHERE id=?",
                                                              (receipt["event_id"],))["text"])
        self.assertIn(f"N-{nid} (Let Dev read support@shop.test): dev has read access to the Gmail mailbox "
                      f"support@shop.test (gmail:support@shop.test) now",
                      hub.q1("SELECT text FROM events WHERE agent='manager' AND text LIKE '[hub] The owner pressed%' "
                             "ORDER BY id DESC LIMIT 1")["text"])
        # what one press cannot give makes no item, and no refusal sends the manager to write the owner's steps; the
        # owner keeps what the default gives first (give_card), since that write reads the team file again
        for rid in ("tool:jobs", "tool:crm", "drive:support@shop.test"):
            self.keep(rid)
        hub.TEAM["agents"]["shopper"]["google"] = {"drive": {"account": "old@shop.test", "level": "read"}}
        rows = hub.q1("SELECT COUNT(*) n FROM needs")["n"]
        for fields, words in (
                (dict(needs_access="gmail:other@shop.test", title="Let Dev read other@shop.test"),
                 "only the owner can connect it for Gmail, with Connect account in Settings › Apps › Gmail"),
                (dict(needs_access="tool:jobs", needs_level="use", title="Let Dev read Failed jobs"),
                 "The MCP server Failed jobs needs a key, whose grant the owner's Mac signs, so Give does not give it"),
                (dict(needs_access="tool:crm", needs_level=None, title="Let Dev use the CRM"),
                 "The MCP server CRM is not connected, so no session gets it: the owner connects it in Founderizer"),
                (dict(needs_agent="shopper", needs_access="drive:support@shop.test",
                      title="Let Shopper read the Drive of support@shop.test"),
                 "Give only adds access, and Shopper has Drive of old@shop.test"),
                (dict(needs_level="send", title="Let Dev answer mail", why="Its triage answers the support mail."),
                 "The title or the why names the Gmail mailbox support@shop.test, which Give gives"),
                (dict(needs_level="admin"),
                 "the level that Give gives on Gmail of support@shop.test: read, write, send"),
                (dict(needs_access="gmail:support@shop.test, repo:acme/api", needs_level="send"),
                 "goes alone in needs_access")):
            with self.subTest(fields=fields):
                said = self.give_card(**dict(mail, **fields))
                self.assertIsInstance(said, str)
                self.assertIn(words, said)
                self.assertNotIn("steps", said)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM needs")["n"], rows)
        # a fact that the card checked changes before the press: the card closes, and nothing changes
        drive = self.give_card(**dict(mail, needs_agent="lead", needs_access="drive:support@shop.test",
                                      needs_level="write_shared", title="Let Lead share files of support@shop.test"))
        need = hub.need_view(hub.q1("SELECT * FROM needs WHERE id=?", (drive,)))
        self.assertEqual((need["options"][0], need["todo"]),
                         ("Give Lead write access, shared files too, to the whole Drive of support@shop.test",
                          "Press Give: it gives Lead write access, shared files too, to the whole Drive of "
                          "support@shop.test."))
        self.google("gmail.modify")                     # the account no longer allows Drive
        before = self.commits()
        code, said = self.request(f"/ui/needs/{drive}", self.command(choice=0))
        self.assertEqual((code, said.get("error")), (409, hub.TEAM_PRESS_CHANGED.format(by=hub.shown_role("manager"))))
        self.assertEqual((hub.q1("SELECT answer FROM needs WHERE id=?", (drive,))["answer"], self.commits()),
                         (hub.TEAM_CLOSED_WORDS, before))
        self.assertNotIn("google", self.committed()["agents"]["lead"])
        self.assertIn("but the hub gave nothing: The Google account support@shop.test does not allow Drive now",
                      hub.q1("SELECT text FROM events WHERE agent='manager' ORDER BY id DESC LIMIT 1")["text"])
        # an MCP server with no key, at its one level
        tool = self.give_card(**dict(mail, needs_agent="lead", needs_access="tool:github", needs_level=None,
                                     title="Let Lead use GitHub's MCP server"))
        before = self.commits()                 # give_card kept it as the owner's first, a commit of its own
        need = hub.need_view(hub.q1("SELECT * FROM needs WHERE id=?", (tool,)))
        self.assertEqual((need["options"][0], need["todo"]), ("Give Lead use of the MCP server GitHub",
                                                              "Press Give: it gives Lead use of the MCP server "
                                                              "GitHub."))
        self.assertEqual(self.request(f"/ui/needs/{tool}", self.command(choice=0))[0], 200)
        self.assertEqual((self.committed()["agents"]["lead"].get("tools"), self.commits()), (["github"], before + 1))
        # an option that would be longer than a row names the kind alone
        long = {"agent": "dev", "level": "read", "repos": [], "resources": [f"gmail:{'a' * 100}@shop.test"]}
        self.assertEqual(hub.need_give_words(long), "Give Dev read access to Gmail")
        # a level that the agent got another way after the card stays at the press: never lowered
        lower = self.give_card(**dict(mail, needs_agent="lead", needs_level="write",
                                      title="Let Lead file the mail of support@shop.test"))
        self.assertIsInstance(lower, int, lower)
        code, given = self.request("/ui/team/google", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                       "base_sha256": self.pool()["sha256"], "service": "gmail",
                                                       "account": "support@shop.test", "access": {"lead": "send"}})
        self.assertEqual(code, 200, given)
        before, grants = self.commits(), self.history("gmail:support@shop.test")
        code, receipt = self.request(f"/ui/needs/{lower}", self.command(choice=0))
        self.assertEqual(code, 200, receipt)
        self.assertEqual((self.committed()["agents"]["lead"]["google"]["gmail"], self.commits(),
                          self.history("gmail:support@shop.test")),
                         ({"account": "support@shop.test", "level": "send"}, before, grants))
        self.assertIn("The agent held that access already", hub.q1("SELECT text FROM events WHERE id=?",
                                                                    (receipt["event_id"],))["text"])
        # the hub counts the open items with Give, and one that replaces another takes its place
        self.reaches("acme/web")
        with patch.object(hub, "NEED_GIVE_OPEN", 1):
            first = self.give_card()
            self.assertIsInstance(first, int, first)
            self.assertIn("1 items with Give wait for the owner already", self.give_card())
            self.assertIsInstance(self.give_card(replaces=f"N-{first}"), int)

    def test_a_give_card_closes_at_the_press_when_its_words_its_kind_or_the_shell_box_no_longer_hold(self):
        """F6 piece 2: the press checks the card again. Believable bugs: a press that gives under words that name
        another agent or thing now (the owner reads "Give Dev", and the press gives the agent that is now called
        otherwise); Gmail at write or send, or a whole Drive, for an agent whose Shell box is off, whose sessions have
        no Gmail or Drive tools; a card of a kind that this hub cannot read, whose press would answer as given with
        nothing given, and which would never close; a sweep that leaves open a card that its press would close; and a
        stop of the hub between the grant's commit and its record, after which the same press again says "held
        already" and no record ever says who gave the hold."""
        def settings(agent, **fields):
            code, said = self.request(f"/ui/team/agents/{agent}", dict(
                request_id=str(uuid.uuid4()), db="test-generation", base_sha256=self.pool()["sha256"], **fields))
            self.assertEqual(code, 200, said)

        def closed(nid):
            before = self.commits()
            code, said = self.request(f"/ui/needs/{nid}", self.command(choice=0))
            self.assertEqual((code, said.get("error")),
                             (409, hub.TEAM_PRESS_CHANGED.format(by=hub.shown_role("manager"))))
            self.assertEqual((hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"], self.commits()),
                             (hub.TEAM_CLOSED_WORDS, before))
            return hub.q1("SELECT text FROM events WHERE agent='manager' ORDER BY id DESC LIMIT 1")["text"]
        mail = dict(title="Let Dev read support@shop.test", why="Its triage reads the mail of support@shop.test.",
                    needs_access="gmail:support@shop.test", needs_level="read", options=None)
        nid = self.give_card(**mail)
        settings("dev", title="Dev Triage")         # the label that the card names is now another one (F16)
        self.assertIn('The card\'s first option, "Give Dev read access to the Gmail mailbox support@shop.test", no '
                      'longer says what Give gives now, "Give Dev Triage read access to the Gmail mailbox '
                      'support@shop.test".', closed(nid))
        self.assertNotIn("google", self.committed()["agents"]["dev"])
        # Gmail that writes or sends, and a whole Drive, reach no session of an agent whose Shell box is off
        lead = dict(mail, needs_agent="lead", title="Let Lead answer support@shop.test")
        card = self.give_card(**dict(lead, needs_level="write"))
        whole = self.give_card(**dict(lead, needs_access="drive:support@shop.test"))
        self.assertTrue(all(isinstance(x, int) for x in (card, whole)), (card, whole))
        with patch.object(hub, "helper_features", lambda agent: [hub.SHELL_BOX]):  # its helper starts it closed
            settings("lead", can=[])
        self.assertIn("Lead's Shell box is off, so no session of it has the Gmail tools", closed(card))
        self.assertNotIn("google", self.committed()["agents"]["lead"])
        for fields, words in ((dict(needs_level="send"), "Lead's Shell box is off, so no session of it has the Gmail "
                                                         "tools: give the work to an agent whose Shell box is on."),
                              (dict(needs_access="drive:support@shop.test"), "has the Drive tools")):
            with self.subTest(fields=fields):
                self.assertIn(words, self.give_card(**dict(lead, **fields)))
        reads = self.give_card(**lead)      # read: a wake-up rule reads its mail
        self.assertIsInstance(reads, int, reads)
        # the sweep closes what a press would close: the Drive of an agent whose Shell box went off, then a card whose
        # words are no longer its change; a step that no longer names the thing is stale too
        answer = lambda nid: hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"]  # noqa: E731
        t0 = hub.now()
        hub.need_look_sweep(t0)
        hub.need_look_sweep(t0 + hub.NEED_GIVE_WAIT + 1)
        self.assertEqual((answer(whole), answer(reads)), (hub.TEAM_CLOSED_WORDS, None))
        row = hub.q1("SELECT * FROM needs WHERE id=?", (reads,))
        self.assertIn('The card\'s step, "Press Give.", no longer says what Give gives now, "Press Give: it gives Lead '
                      'read access to the Gmail mailbox support@shop.test."',
                      hub.need_give_stale(dict(row, todo="Press Give."), hub.need_view(row)["give"]))
        settings("lead", title="Support Lead")     # a role that holds its name: a new label
        hub.need_look_sweep(t0 + 2 * hub.NEED_GIVE_WAIT + 2)
        hub.need_look_sweep(t0 + 3 * hub.NEED_GIVE_WAIT + 3)
        self.assertEqual(answer(reads), hub.TEAM_CLOSED_WORDS)
        # a card of a kind that this code does not read closes, and its press gives nothing
        other = hub.ins("INSERT INTO needs(title,why,todo,raised,by,options,give_agent,give_level,give_repos,"
                        "give_resource) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        ("Let Lead use the key", "Its deploy needs it.", "Press Give.", hub.now(), "manager",
                         json.dumps(["Give Lead use", "No"]), "lead", "use", "[]", f"secret:{KEY}"))
        words = "Closed by the hub: this hub cannot give what this card gives, so Give gives nothing."
        self.assertEqual(hub.need_give_closes(hub.q1("SELECT * FROM needs WHERE id=?", (other,))), words)
        before = self.commits()
        code, said = self.request(f"/ui/needs/{other}", self.command(choice=0))
        self.assertEqual((code, said.get("code"), self.commits()), (409, "request_answered", before))
        self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (other,))["answer"], words)
        # a stop between the grant's commit and its record: the same press again writes the record (grant_access's
        # repeat rule), one commit in all
        card = self.give_card(**dict(mail, needs_agent="shopper", title="Let Shopper read support@shop.test"))
        self.assertIsInstance(card, int, card)
        real, stopped = hub.resource_record, []

        def stops(*args, **kw):
            if not stopped:
                stopped.append(args)
                raise RuntimeError("the hub stopped")
            return real(*args, **kw)
        press, before = self.command(choice=0), self.commits()
        with patch.object(hub, "resource_record", stops), self.assertRaises(RuntimeError):
            hub.phone_submit(press, "founderizer-swift/1/test", card, device=None)
        self.assertEqual((self.commits(), self.history("gmail:support@shop.test"), answer(card)),
                         (before + 1, [], None))
        code, receipt = self.request(f"/ui/needs/{card}", press)
        self.assertEqual(code, 200, receipt)
        self.assertEqual((self.commits(), self.history("gmail:support@shop.test")),
                         (before + 1, [("shopper", "read", "owner")]))
        self.assertIn("The hub gave it at this press", hub.q1("SELECT text FROM events WHERE id=?",
                                                              (receipt["event_id"],))["text"])
