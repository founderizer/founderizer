"""The door's provider targets (DevOps plan steps C6 and C8), in the plan's order: Backblaze, Cloudflare, GitHub,
Hetzner, AWS, Azure and Tailscale. Done when the stub tests pass: each provider answers from a stub that records what
the door sends, so the tests read the exact requests of each rule call, own call and listed read, and check that no
answer and no request of an agent's carries the door's tokens or a key that the door minted. One real call of each
comes later, at the plan's step X3."""
import base64
import calendar
import json
import unittest
from unittest.mock import patch

import door_providers
import door_targets
from test_door import ACCESS, TUNNEL, ZONE

SUB = "00000000-0000-4000-8000-000000000000"


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(cls(name) for cls in (Backblaze, Cloudflare, GitHub, Hetzner, AWS, Azure, Tailscale,
                                                         NotListed)
                              for name in cls.__dict__ if name.startswith("test_"))


class Stub:
    """The provider: the answers by (method, URL start), and every request in order."""

    def __init__(self, answers):
        self.answers, self.calls, self.kept, self.hosts, self.runs = answers, [], [], [], []

    def http(self, method, url, headers, data):
        self.calls.append({"method": method, "url": url, "headers": headers,
                           "body": None if data is None else data.decode()})
        for (m, start), answer in self.answers:
            if m == method and url.startswith(start):
                return answer
        return 404, {"message": "not stubbed"}

    def ctx(self, target, secret="token-of-the-door"):
        credentials = dict((ACCESS["credentials"]).get(target) or {}, owner=target.partition(":")[2])
        return {"credentials": credentials, "http": self.http, "secret": lambda ref: secret,
                "keep": lambda kind, answer: self.kept.append(answer),
                "minted_secret": lambda key: "id-new:secret-new",
                "host": lambda host, op, args, stdin: (self.hosts.append((host, op, args, stdin)), (0, "placed"))[1],
                "run": lambda argv, stdin, env: (self.runs.append((argv, stdin, env)), (0, ""))[1],
                "aws_token": lambda: "jwt-of-the-bot", "aws_sessions": {}}


class Provider(unittest.TestCase):
    target = None

    def decide(self, op, *args, content=None, lookups=None, target=None):
        return door_targets.decide(ACCESS, "ops-one", target or self.target, op, list(args), content,
                                   dict({"minted": lambda key: key == "k-minted"}, **(lookups or {})))

    def run_plan(self, d, answers, secret="token-of-the-door"):
        stub = Stub(answers)
        out = door_providers.execute(d.plan, stub.ctx(d.target, secret))
        return stub, out

    def no_secret_in(self, stub, out, *values):
        for value in values:
            self.assertNotIn(value, out)
            for call in stub.calls:
                self.assertNotIn(value, call["url"])


class Backblaze(Provider):
    target = "backblaze:one"
    AUTH = (("GET", "https://api.backblazeb2.com/b2api/v3/b2_authorize_account"),
            (200, {"accountId": "acct1", "authorizationToken": "tok-b2",
                   "apiInfo": {"storageApi": {"apiUrl": "https://api005.example.com"}}}))

    def test_a_listed_read(self):
        d = self.decide("buckets")
        self.assertEqual(d.kind, "read")
        stub, out = self.run_plan(d, [self.AUTH, (("POST", "https://api005.example.com/b2api/v3/b2_list_buckets"),
                                                  (200, {"buckets": []}))], secret="keyid:appkey")
        self.assertEqual(stub.calls[0]["headers"]["Authorization"],
                         "Basic " + base64.b64encode(b"keyid:appkey").decode())
        self.assertEqual(json.loads(stub.calls[1]["body"]), {"accountId": "acct1"})
        self.assertEqual(stub.calls[1]["headers"]["Authorization"], "tok-b2")

    def test_a_key_for_one_host_with_its_name_as_the_prefix_and_no_delete_right(self):
        d = self.decide("key-mint", "web-1", "bucket-1")
        self.assertEqual(d.kind, "rule")
        stub, out = self.run_plan(d, [self.AUTH, (("POST", "https://api005.example.com/b2api/v3/b2_create_key"),
                                                  (200, {"applicationKeyId": "k-new", "applicationKey": "SECRET-NEW",
                                                         "keyName": "web-1"}))], secret="keyid:appkey")
        body = json.loads(stub.calls[1]["body"])
        self.assertEqual((body["keyName"], body["namePrefix"], body["bucketId"]), ("web-1", "web-1/", "bucket-1"))
        self.assertNotIn("deleteFiles", body["capabilities"])
        self.assertEqual(stub.kept[0]["applicationKey"], "SECRET-NEW")         # the door keeps it
        self.assertEqual(out, "minted k-new: the door keeps its secret, and the new key works")
        self.assertEqual(stub.calls[2]["headers"]["Authorization"],             # the new key signs in first
                         "Basic " + base64.b64encode(b"k-new:SECRET-NEW").decode())
        self.no_secret_in(stub, out, "SECRET-NEW")
        self.assertEqual(self.decide("key-mint", "web-2", "bucket-1").kind, "refused")     # not this agent's host

    def test_a_new_key_that_does_not_sign_in_stops_and_stays_kept_for_its_revoke(self):
        d = self.decide("key-mint", "web-1", "bucket-1")
        stub = Stub([self.AUTH, (("POST", "https://api005.example.com/b2api/v3/b2_create_key"),
                                 (200, {"applicationKeyId": "k-new", "applicationKey": "SECRET-NEW"}))])
        signed_in = []

        def http(method, url, headers, data):
            if url.endswith("b2_authorize_account"):
                signed_in.append(headers["Authorization"])
                if len(signed_in) > 1:
                    return 401, {"code": "bad_auth_token"}
            return Stub.http(stub, method, url, headers, data)
        stub.http = http
        with self.assertRaisesRegex(door_providers.Stop, "k-new does not sign in .*key-revoke"):
            door_providers.execute(d.plan, stub.ctx(d.target, "keyid:appkey"))
        self.assertEqual(stub.kept[0]["applicationKeyId"], "k-new")

    def test_revoke_is_a_rule_call_only_for_a_key_the_door_minted(self):
        self.assertEqual(self.decide("key-revoke", "k-minted").kind, "rule")
        self.assertEqual(self.decide("key-revoke", "k-other").kind, "own")

    def test_a_minted_key_goes_where_the_old_value_is_through_ops_root(self):
        d = self.decide("key-place", "web-1", "/etc/restic/b2.env", "k-minted",
                        "B2_ACCOUNT_ID=id:" + "1" * 64, "B2_ACCOUNT_KEY=key:" + "2" * 64)
        self.assertEqual(d.kind, "rule")
        stub, out = self.run_plan(d, [])
        self.assertEqual(stub.hosts, [("web-1", "place", ["/etc/restic/b2.env", "B2_ACCOUNT_ID", "1" * 64], b"id-new"),
                                      ("web-1", "place", ["/etc/restic/b2.env", "B2_ACCOUNT_KEY", "2" * 64],
                                       b"secret-new")])
        self.assertNotIn("secret-new", out)
        self.assertEqual(self.decide("key-place", "fleet-1", "/etc/x.env", "k-minted",
                                     "X=key:" + "2" * 64).kind, "refused")          # never on a Fleet machine
        self.assertEqual(self.decide("key-place", "web-1", "/etc/x.env", "k-other", "X=key:" + "2" * 64).kind,
                         "refused")


class Cloudflare(Provider):
    target = "cloudflare:one"
    BASE = "https://api.cloudflare.com/client/v4"

    def test_a_new_cname_to_a_tunnel_of_the_account(self):
        d = self.decide("cname", ZONE, "app.example.com", TUNNEL)
        self.assertEqual(d.kind, "rule")
        answers = [(("GET", f"{self.BASE}/accounts/{'b' * 32}/cfd_tunnel/{TUNNEL}"), (200, {"result": {}})),
                   (("GET", f"{self.BASE}/zones/{ZONE}/dns_records"), (200, {"result": []})),
                   (("POST", f"{self.BASE}/zones/{ZONE}/dns_records"), (200, {"success": True}))]
        stub, out = self.run_plan(d, answers)
        self.assertEqual([c["method"] for c in stub.calls], ["GET", "GET", "POST"])
        self.assertEqual(stub.calls[0]["headers"]["Authorization"], "Bearer token-of-the-door")
        self.assertEqual(json.loads(stub.calls[2]["body"]),
                         {"type": "CNAME", "name": "app.example.com", "content": f"{TUNNEL}.cfargotunnel.com",
                          "proxied": True, "comment": "the door"})
        self.no_secret_in(stub, out, "token-of-the-door")

    def test_a_record_that_exists_is_a_change_which_goes_through_change(self):
        d = self.decide("cname", ZONE, "app.example.com", TUNNEL)
        answers = [(("GET", f"{self.BASE}/accounts/"), (200, {"result": {}})),
                   (("GET", f"{self.BASE}/zones/{ZONE}/dns_records"), (200, {"result": [{"id": "x"}]}))]
        with self.assertRaisesRegex(door_providers.Stop, "a change of it goes through change"):
            self.run_plan(d, answers)
        self.assertEqual(self.decide("change", "PATCH", f"/zones/{ZONE}/dns_records/{'f' * 32}",
                                     content=b'{"content": "x"}').kind, "own")

    def test_a_new_tunnel_hostname_goes_before_the_catch_all(self):
        d = self.decide("tunnel-route", TUNNEL, "app.example.com", "3000")
        self.assertEqual(d.kind, "rule")
        config = {"result": {"config": {"ingress": [{"hostname": "old.example.com", "service": "http://localhost:80"},
                                                    {"service": "http_status:404"}]}}}
        answers = [(("GET", f"{self.BASE}/accounts/{'b' * 32}/cfd_tunnel/{TUNNEL}/configurations"), (200, config)),
                   (("PUT", f"{self.BASE}/accounts/{'b' * 32}/cfd_tunnel/{TUNNEL}/configurations"), (200, {}))]
        stub, _ = self.run_plan(d, answers)
        ingress = json.loads(stub.calls[1]["body"])["config"]["ingress"]
        self.assertEqual(ingress, [{"hostname": "old.example.com", "service": "http://localhost:80"},
                                   {"hostname": "app.example.com", "service": "http://localhost:3000"},
                                   {"service": "http_status:404"}])

    def test_purge_and_the_products_that_are_own_calls(self):
        d = self.decide("purge", ZONE, "cdn.example.com", "https://cdn.example.com/sdk.js")
        stub, _ = self.run_plan(d, [(("POST", f"{self.BASE}/zones/{ZONE}/purge_cache"), (200, {}))])
        self.assertEqual(json.loads(stub.calls[0]["body"]),
                         {"files": ["https://cdn.example.com/sdk.js"], "hosts": ["cdn.example.com"]})
        for path in (f"/zones/{ZONE}/rulesets/{'e' * 32}", f"/accounts/{'b' * 32}/r2/buckets/media",
                     f"/accounts/{'b' * 32}/challenges/widgets/abc", f"/accounts/{'b' * 32}/workers/scripts/edge",
                     f"/zones/{ZONE}/email/routing/rules"):
            with self.subTest(path=path):
                self.assertEqual(self.decide("change", "PUT", path, content=b"{}").kind, "own")
        # D25 (plan v55, "Not listed"): a write that is not listed is the agent's own call, new access for a person
        # too since 11 November 2026; a token's answer is a secret, which the door never sends
        self.assertEqual(self.decide("change", "POST", f"/accounts/{'b' * 32}/access/apps", content=b"{}").kind,
                         "own")
        self.assertEqual(self.decide("change", "POST", "/user/tokens", content=b"{}").kind, "refused")


class GitHub(Provider):
    target = "github:one-org"
    API = "https://api.github.com"

    def setUp(self):
        patcher = patch.object(door_providers, "app_jwt", lambda app_id, pem, sign=None: "jwt-of-the-app")
        patcher.start()
        self.addCleanup(patcher.stop)

    def answers(self, *more, repo="one-org/shop"):
        return [(("GET", f"{self.API}/repos/{repo}/installation"), (200, {"id": 9})),
                (("POST", f"{self.API}/app/installations/9/access_tokens"), (201, {"token": "ghs_door"})), *more]

    def test_a_health_workflow_is_a_rule_call_and_a_bootstrap_one_is_an_own_call(self):
        branch = {"default_branch": lambda repo: {"one-org/cluster": "master"}.get(repo)}
        d = self.decide("workflow", "cluster", "cluster-health.yml", "app=shop", lookups=branch)
        self.assertEqual(d.kind, "rule")
        stub, _ = self.run_plan(d, self.answers((("POST", f"{self.API}/repos/one-org/cluster/actions/workflows/"
                                                          f"cluster-health.yml/dispatches"), (204, {})),
                                                repo="one-org/cluster"))
        self.assertEqual(json.loads(stub.calls[2]["body"]), {"ref": "master", "inputs": {"app": "shop"}})
        self.assertEqual(stub.calls[2]["headers"]["Authorization"], "Bearer ghs_door")
        self.assertEqual(self.decide("workflow", "cluster", "velero-bootstrap.yml", lookups=branch).kind, "own")
        self.assertEqual(self.decide("workflow", "cluster", "dns-records.yml", lookups=branch).kind, "refused")
        self.assertEqual(self.decide("workflow", "cluster", "cluster-health.yml", "app=$(id)", lookups=branch).kind,
                         "refused")
        self.assertIn("could not read the default branch",
                      self.decide("workflow", "cluster", "cluster-health.yml").why)
        self.assertEqual(self.decide("runs", "agents", target="github:SomeUser").kind, "refused")

    def test_a_rotated_value_goes_into_a_secret_through_gh_and_its_stdin(self):
        d = self.decide("secret", "shop", "B2_KEY", "k-minted", "key")
        self.assertEqual(d.kind, "rule")
        stub, out = self.run_plan(d, self.answers())
        argv, stdin, env = stub.runs[0]
        self.assertEqual(argv, ["gh", "secret", "set", "B2_KEY", "--repo", "one-org/shop"])
        self.assertEqual((stdin, env), (b"secret-new", {"GH_TOKEN": "ghs_door"}))
        self.assertNotIn("secret-new", out)
        stub, out = self.run_plan(self.decide("secret", "shop", "B2_KEY_ID", "k-minted", "id"), self.answers())
        self.assertEqual(stub.runs[0][1], b"id-new")
        self.assertEqual(self.decide("secret", "shop", "B2_KEY", "k-other", "key").kind, "refused")
        self.assertEqual(self.decide("secret", "shop", "B2_KEY", "k-minted").kind, "refused")

    def test_reads_of_alerts_failed_jobs_and_runners_and_a_pull_request(self):
        for op in ("runs", "failed", "alerts", "code-alerts", "secret-alerts", "runners"):
            self.assertEqual(self.decide(op, "shop").kind, "read")
        d = self.decide("secret-alerts", "shop")
        self.assertEqual(d.plan["steps"][0]["query"]["hide_secret"], "true")
        self.assertEqual(self.decide("pull-request", "shop", "door/fix", "main", "Fix", "the", "lockfile").kind,
                         "rule")

    def test_a_token_of_the_door_asks_for_its_permissions_by_name_as_far_as_the_installation_holds_them(self):
        """New-projects plan N2: no token of the door carries all of the App's permissions. Its own tokens ask for
        Administration at read only, and only a one-call token asks for it at write."""
        held = {"contents": "write", "metadata": "read", "administration": "write", "actions": "read"}
        stub = Stub([(("GET", f"{self.API}/repos/one-org/shop/installation"), (200, {"id": 9, "permissions": held})),
                     (("POST", f"{self.API}/app/installations/9/access_tokens"), (201, {"token": "ghs_door"}))])
        ctx = stub.ctx("github:one-org")
        self.assertEqual(door_providers.github_token(ctx["credentials"], ctx, "one-org/shop"), "ghs_door")
        self.assertEqual(json.loads(stub.calls[-1]["body"]), {"permissions": {
            "metadata": "read", "contents": "write", "actions": "read", "administration": "read"}})
        door_providers.github_token(ctx["credentials"], ctx, "one-org/shop",
                                    {"administration": "write", "metadata": "read"})
        self.assertEqual(json.loads(stub.calls[-1]["body"]),
                         {"permissions": {"administration": "write", "metadata": "read"}})
        self.assertEqual(door_providers.named_permissions({"administration": "write"}, {"administration": "read"}),
                         {"administration": "read"})
        # an installation that holds Administration at read only: the one-call token names GitHub's two pages
        stub = Stub([(("GET", f"{self.API}/repos/one-org/shop/installation"),
                      (200, {"id": 9, "app_slug": "door-app", "account": {"login": "One-Org", "type": "Organization"},
                             "permissions": {"administration": "read", "metadata": "read"}}))])
        ctx = stub.ctx("github:one-org")
        with self.assertRaises(door_providers.Stop) as said:
            door_providers.github_token(ctx["credentials"], ctx, "one-org/shop",
                                        {"administration": "write", "metadata": "read"})
        self.assertIn("does not hold administration", str(said.exception))
        self.assertIn("https://github.com/organizations/One-Org/settings/apps/door-app/permissions", str(said.exception))
        self.assertIn("https://github.com/organizations/One-Org/settings/installations/9", str(said.exception))
        self.assertEqual([c["method"] for c in stub.calls], ["GET"])               # no token was asked for

    def test_a_github_write_reaches_only_a_repository_that_the_agent_holds(self):
        """New-projects plan N2: a GitHub write of an Operator reaches only the repositories that it holds; its reads
        stay as they are."""
        for op, args in (("pull-request", ["other", "door/fix", "main", "Fix"]),
                         ("secret", ["other", "B2_KEY", "k-minted", "key"]),
                         ("workflow", ["other", "cluster-health.yml"])):
            with self.subTest(op=op):
                d = self.decide(op, *args)
                self.assertEqual(d.kind, "refused")
                self.assertIn("no repository that this agent holds", d.why)
        self.assertEqual(self.decide("runs", "other").kind, "read")
        self.assertEqual(self.decide("pull-request", "Shop", "door/fix", "main", "Fix").kind, "rule")   # any case

    def repo_ctx(self, answers, record=None):
        stub = Stub(answers)
        ctx = stub.ctx("github:one-org")
        book = record if record is not None else {}

        def repos(kind, full, **fields):
            if not fields and kind in ("pending", "made"):
                return book.get((kind, full.lower()))
            book[(kind, full.lower())] = dict(fields, at=fields.get("at", 1793900000))
            if kind == "made":
                book.pop(("pending", full.lower()), None)
        ctx["repos"] = repos
        return stub, ctx, book

    INSTALL = {"id": 9, "app_slug": "door-app", "account": {"login": "one-org", "type": "User"},
               "permissions": {"administration": "write", "repository_creation": "write", "metadata": "read"}}

    def test_repo_new_makes_one_private_repository_in_an_account_where_the_agent_holds_one(self):
        """New-projects plan N3: a rule call; the name follows N4's rule, never a product's or the never list's,
        and only in an account where the agent already holds a repository."""
        for name in ("Bad", "1app", "a" * 25, "app_x"):
            self.assertEqual(self.decide("repo-new", name).kind, "refused", name)
        self.assertEqual(self.decide("repo-new", "agents", target="github:miguelpieras").kind, "refused")
        lean = json.loads(json.dumps(ACCESS))
        lean["agents"]["ops-one"]["github"] = {"other/x": "read"}
        self.assertIn("holds none of", door_targets.decide(lean, "ops-one", "github:one-org", "repo-new", ["newapp"],
                                                           None, {}).why)
        d = self.decide("repo-new", "newapp")
        self.assertEqual((d.kind, d.plan["repo"], d.plan["repo_new"]),
                         ("rule", "one-org/ops", {"name": "one-org/newapp", "agent": "ops-one"}))
        answers = [(("GET", f"{self.API}/repos/one-org/ops/installation"), (200, self.INSTALL)),
                   (("POST", f"{self.API}/app/installations/9/access_tokens"), (201, {"token": "ghs_once"})),
                   (("POST", f"{self.API}/user/repos"), (201, {"id": 501, "full_name": "one-org/newapp"}))]
        stub, ctx, book = self.repo_ctx(answers)
        missing = iter([(404, {}), (200, {"id": 501})])
        http = stub.http

        def answer(method, url, headers, data):
            if method == "GET" and url == f"{self.API}/repos/one-org/newapp":
                stub.calls.append({"method": method, "url": url, "headers": headers, "body": None})
                return next(missing)
            return http(method, url, headers, data)
        ctx["http"] = answer
        out = door_providers.execute(d.plan, ctx)
        self.assertIn("made one-org/newapp", out)
        self.assertEqual(book[("made", "one-org/newapp")]["id"], 501)
        made = next(c for c in stub.calls if c["url"].endswith("/user/repos"))
        self.assertEqual(json.loads(made["body"]), {"name": "newapp", "private": True, "auto_init": True,
                                                    "description": "made by the door for ops-one"})
        token = next(c for c in stub.calls if c["url"].endswith("/access_tokens"))
        self.assertEqual(json.loads(token["body"]), {"permissions": door_providers.REPO_NEW})
        org = dict(self.INSTALL, account={"login": "one-org", "type": "Organization"})
        stub, ctx, book = self.repo_ctx([(("GET", f"{self.API}/repos/one-org/ops/installation"), (200, org)),
                                         (("POST", f"{self.API}/app/installations/9/access_tokens"),
                                          (201, {"token": "ghs_once"})),
                                         (("POST", f"{self.API}/orgs/one-org/repos"), (201, {"id": 7, "full_name": "x"}))])
        with self.assertRaisesRegex(door_providers.Stop, "made no repository"):     # GitHub answered another name
            door_providers.execute(d.plan, ctx)
        self.assertEqual(book[("pending", "one-org/newapp")]["agent"], "ops-one")

    def test_repo_new_completes_only_its_own_pending_repository(self):
        d = self.decide("repo-new", "newapp")
        base = [(("GET", f"{self.API}/repos/one-org/ops/installation"), (200, self.INSTALL)),
                (("POST", f"{self.API}/app/installations/9/access_tokens"), (201, {"token": "ghs_once"}))]
        at = calendar.timegm((2026, 11, 4, 12, 0, 0))
        there = (200, {"id": 501, "created_at": "2026-11-04T12:00:30Z"})
        one = [{"sha": "a", "author": {"login": "door-app[bot]"}}]
        stub, ctx, book = self.repo_ctx(base + [(("GET", f"{self.API}/repos/one-org/newapp/commits"), (200, one)),
                                                (("GET", f"{self.API}/repos/one-org/newapp"), there)])
        with self.assertRaisesRegex(door_providers.Stop, "does not show that the door made it"):
            door_providers.execute(d.plan, ctx)                         # no pending record: someone else made it
        book[("made", "one-org/newapp")] = {"agent": "ops-two", "id": 501, "repo": "one-org/newapp"}
        with self.assertRaisesRegex(door_providers.Stop, "does not show that the door made it"):
            door_providers.execute(d.plan, ctx)                         # the door made it, for another agent
        del book[("made", "one-org/newapp")]
        book[("pending", "one-org/newapp")] = {"agent": "ops-one", "app": "newapp", "at": at}
        self.assertIn("record now says so", door_providers.execute(d.plan, ctx))
        self.assertEqual(book[("made", "one-org/newapp")]["id"], 501)
        stub, ctx, book = self.repo_ctx(base + [(("GET", f"{self.API}/repos/one-org/newapp/commits"),
                                                 (200, one + [{"sha": "b", "author": {"login": "someone"}}])),
                                                (("GET", f"{self.API}/repos/one-org/newapp"), there)])
        book[("pending", "one-org/newapp")] = {"agent": "ops-one", "app": "newapp", "at": at}
        with self.assertRaisesRegex(door_providers.Stop, "does not show"):
            door_providers.execute(d.plan, ctx)                         # a second commit: not the door's first one
        poor = dict(self.INSTALL, permissions={"administration": "read", "metadata": "read"})
        stub, ctx, book = self.repo_ctx([(("GET", f"{self.API}/repos/one-org/ops/installation"), (200, poor))])
        with self.assertRaisesRegex(door_providers.Stop, "settings/apps/door-app/permissions"):
            door_providers.execute(d.plan, ctx)
        self.assertEqual([c["method"] for c in stub.calls], ["GET"])

    def test_repo_delete_only_for_a_repository_that_the_door_made_with_no_runner(self):
        made = {"one-org/newapp": {"id": 501, "agent": "ops-one"}}
        look = {"made_repo": lambda name: made.get(name.lower())}
        self.assertIn("no repository that the door made", self.decide("repo-delete", "shop", lookups=look).why)
        d = self.decide("repo-delete", "newapp", lookups=look)
        self.assertEqual(d.kind, "own")
        base = [(("GET", f"{self.API}/repos/one-org/newapp/installation"), (200, self.INSTALL)),
                (("POST", f"{self.API}/app/installations/9/access_tokens"), (201, {"token": "ghs_once"})),
                (("GET", f"{self.API}/repos/one-org/newapp/actions/runners"), (200, {"total_count": 0})),
                (("GET", f"{self.API}/repos/one-org/newapp"), (200, {"id": 501})),
                (("DELETE", f"{self.API}/repos/one-org/newapp"), (204, {}))]
        stub, ctx, book = self.repo_ctx(base)
        self.assertIn("deleted one-org/newapp", door_providers.execute(d.plan, ctx))
        token = next(c for c in stub.calls if c["url"].endswith("/access_tokens"))
        self.assertEqual(json.loads(token["body"]), {"permissions": door_providers.REPO_DELETE, "repositories": ["newapp"]})
        base[2] = (("GET", f"{self.API}/repos/one-org/newapp/actions/runners"), (200, {"total_count": 1}))
        stub, ctx, book = self.repo_ctx(base)
        with self.assertRaisesRegex(door_providers.Stop, "has a runner"):
            door_providers.execute(d.plan, ctx)
        self.assertFalse(any(c["method"] == "DELETE" for c in stub.calls))

    def test_a_personal_account_s_installation_is_its_repository_s(self):
        """Plan N1: the owner's own account is a user, and GitHub answers 404 to /orgs/<user>/installation. The door
        asks the installation of the call's repository, which GitHub gives for a user and an organization alike, and
        the credential needs no field that says which one it is."""
        access = json.loads(json.dumps(ACCESS))
        access["credentials"]["github:one-user"] = {"secret": "bws://00000011-0000-4000-8000-000000000000",
                                                    "app_id": "777"}
        access["agents"]["ops-one"]["providers"].append("github:one-user")
        d = door_targets.decide(access, "ops-one", "github:one-user", "runs", ["site"], None, {})
        self.assertEqual(d.kind, "read")
        stub = Stub([(("GET", f"{self.API}/orgs/one-user/installation"), (404, {"message": "Not Found"})),
                     (("GET", f"{self.API}/repos/one-user/site/installation"), (200, {"id": 31})),
                     (("POST", f"{self.API}/app/installations/31/access_tokens"), (201, {"token": "ghs_user"})),
                     (("GET", f"{self.API}/repos/one-user/site/actions/runs"), (200, {"workflow_runs": []}))])
        ctx = dict(stub.ctx("github:one-org"), credentials=dict(access["credentials"]["github:one-user"],
                                                                 owner="one-user"))
        out = door_providers.execute(d.plan, ctx)
        self.assertEqual(json.loads(out), {"workflow_runs": []})
        self.assertEqual([(c["method"], c["url"]) for c in stub.calls],
                         [("GET", f"{self.API}/repos/one-user/site/installation"),
                          ("POST", f"{self.API}/app/installations/31/access_tokens"),
                          ("GET", f"{self.API}/repos/one-user/site/actions/runs?per_page=50")])
        self.assertEqual(stub.calls[2]["headers"]["Authorization"], "Bearer ghs_user")


class Hetzner(Provider):
    target = "hetzner:one"
    API = "https://api.hetzner.cloud/v1"

    def test_a_power_cycle_of_a_held_server(self):
        d = self.decide("power-cycle", "web-1")
        self.assertEqual((d.kind, d.reboot, d.window), ("rule", True, "reboot"))
        stub, _ = self.run_plan(d, [(("GET", f"{self.API}/servers"), (200, {"servers": [{"id": 42}]})),
                                    (("POST", f"{self.API}/servers/42/actions/reset"), (201, {"action": {}}))])
        self.assertEqual(stub.calls[0]["url"], f"{self.API}/servers?name=web-1")
        self.assertEqual(stub.calls[1]["url"], f"{self.API}/servers/42/actions/reset")
        for name in ("web-2", "logs-1", "ci-1", "fleet-1", "site-1"):       # another agent's, held at Read, two
            self.assertEqual(self.decide("power-cycle", name).kind, "refused", name)     # rule-only hosts, never

    def test_firewall_protection_and_name_are_own_calls_and_rescue_is_never(self):
        self.assertEqual(self.decide("change", "POST", "/servers/42/actions/change_protection", "web-1",
                                     content=b'{"delete": true}').kind, "own")
        self.assertEqual(self.decide("change", "POST", "/firewalls/7/actions/set_rules", "web-1",
                                     content=b'{"rules": []}').kind, "own")
        self.assertEqual(self.decide("change", "POST", "/servers/42/actions/enable_rescue", "web-1",
                                     content=b"{}").why, "Rescue is never booted")
        self.assertEqual(self.decide("change", "POST", "/servers/42/actions/poweroff", "web-1",
                                     content=b"{}").kind, "refused")

    def test_an_own_change_names_its_server(self):
        d = self.decide("change", "PUT", "/servers/43", "web-1", content=b'{"labels": {"env": "x"}}')
        with self.assertRaisesRegex(door_providers.Stop, "not the named server's"):
            self.run_plan(d, [(("GET", f"{self.API}/servers"), (200, {"servers": [{"id": 42}]}))])
        d = self.decide("change", "PUT", "/servers/421", "web-1", content=b'{"labels": {"env": "x"}}')   # 42, not 421
        with self.assertRaisesRegex(door_providers.Stop, "not the named server's"):
            self.run_plan(d, [(("GET", f"{self.API}/servers"), (200, {"servers": [{"id": 42}]}))])

    def stopped(self, d, answers, words):
        """The plan stops with these words, and the door sent reads only."""
        stub = Stub(answers)
        with self.assertRaisesRegex(door_providers.Stop, words):
            door_providers.execute(d.plan, stub.ctx(d.target))
        self.assertEqual({c["method"] for c in stub.calls}, {"GET"})

    def server(self, name, number=42):
        return ("GET", f"{self.API}/servers/{number}"), (200, {"server": {"id": number, "name": name}})

    def test_a_write_on_a_server_passes_only_for_a_server_that_the_agent_holds_at_fix(self):
        """A server's disk holds its keys. The two-argument change names a server by its id only, so the door reads
        that server's name first: an image, a backup, an ISO, a new type, the power and the name of a server that
        the agent does not hold at Fix are not its own call."""
        writes = [("POST", f"/servers/42/actions/{action}") for action in (
            "create_image", "enable_backup", "attach_iso", "change_type", "poweroff", "shutdown", "reset",
            "detach_from_network", "change_protection")] + [("PUT", "/servers/42")]
        for method, path in writes:
            with self.subTest(path=path):
                d = self.decide("change", method, path, content=b'{"type": "snapshot"}')
                self.assertEqual(d.kind, "own", d.why)
                stub, out = self.run_plan(d, [self.server("web-1"), ((method, self.API + path), (201, {"action": 1}))])
                self.assertEqual([(c["method"], c["url"]) for c in stub.calls],
                                 [("GET", f"{self.API}/servers/42"), (method, self.API + path)])
                self.assertEqual(out, '{"action": 1}')              # the write's answer, and not the door's read
                # not held, held at Read, on the never list, and a machine of the fleet (rule-only), whose disk
                # holds the keys of the whole fleet
                for name in ("hub-1", "logs-1", "site-1", "fleet-1", "ci-1"):
                    self.stopped(d, [self.server(name)], "none that this agent holds at Fix")
                self.stopped(d, [(("GET", f"{self.API}/servers/42"), (200, {}))], "holds at Fix")
        d = door_providers.decide({"agents": {"reader": {"servers": {"logs-1": "read"}}}}, "reader", "hetzner", "one",
                                  "change", ["POST", "/servers/42/actions/create_image"], None, {})
        self.assertEqual(d.kind, "refused")
        self.assertIn("it holds none", d.why)

    def test_no_write_changes_a_server_s_name_and_each_form_takes_the_same_held_servers(self):
        """The door knows which server a write is on by the server's name at the provider. So a rename is no form's,
        and the three-argument change and the power cycle take a server of the same set as the two-argument change:
        held at Fix, not on the never list, and no rule-only host. Else a rename of a server held at Read, or of a
        machine of the fleet, to a held name would let the two-argument change copy its disk."""
        rename = "how the door knows which server it is"
        for name in ("fleet-1", "ci-1", "logs-1", "site-1", "web-2"):
            for path, body in (("/servers/99", b'{"name": "web-1"}'), ("/servers/99", b'{"labels": {}}'),
                               ("/servers/99/actions/change_protection", b'{"delete": false}'),
                               ("/firewalls/7/actions/set_rules", b'{"rules": []}')):
                d = self.decide("change", "PUT" if path == "/servers/99" else "POST", path, name, content=body)
                self.assertEqual(d.kind, "refused", (name, path))
                self.assertIn("which this agent holds at Fix", d.why)
        for args in (("PUT", "/servers/42", "web-1"), ("PUT", "/servers/42"), ("POST", "/servers/42"),
                     ("POST", "/servers/42/actions/change_protection", "web-1"),
                     ("POST", "/servers/42/actions/change_type")):
            d = self.decide("change", *args, content=b'{"name": "web-1", "labels": {}}')
            self.assertEqual(d.kind, "refused", args)
            self.assertIn(rename, d.why)
        d = self.decide("change", "PUT", "/servers/42", "web-1", content=b'{"labels": {"env": "prod"}}')
        self.assertEqual(d.kind, "own", d.why)
        stub, _ = self.run_plan(d, [(("GET", f"{self.API}/servers?name=web-1"), (200, {"servers": [{"id": 42}]})),
                                    (("PUT", f"{self.API}/servers/42"), (200, {"server": {"id": 42}}))])
        self.assertEqual([c["method"] for c in stub.calls], ["GET", "PUT"])
        # and so the server of a machine of the fleet keeps its name, and its image is not this agent's to make
        d = self.decide("change", "POST", "/servers/99/actions/create_image", content=b'{"type": "snapshot"}')
        self.stopped(d, [self.server("fleet-1", 99)], "none that this agent holds at Fix")

    def test_a_delete_of_a_server_keeps_its_own_rule(self):
        """A delete is the owner's unless an agent made its target (deletes): no read of the server comes first."""
        for method, path in (("DELETE", "/servers/42"), ("POST", "/servers/42/actions/disable_backup"),
                             ("DELETE", "/images/7"), ("DELETE", "/volumes/5")):
            d = self.decide("change", method, path)
            self.assertEqual((d.kind, [s["method"] for s in d.plan["steps"]]), ("own", [method]), path)
            self.assertEqual(len(door_providers.deletes(d.plan, {})), 1, path)

    def test_a_new_server_starts_from_a_system_image_with_nothing_of_the_project(self):
        """A snapshot or a backup is a copy of a server's disk: a new server from it, with the caller's SSH key, gives
        root on that copy, and so does a volume that joins a new server. The door's record of what agents made is by
        account and not by agent, so no image passes by it: the real door gives this check no such record."""
        def new(**more):
            return self.decide("change", "POST", "/servers", content=json.dumps(
                dict({"name": "web-9", "ssh_keys": ["ops"]}, **more)).encode())
        for more in ({"image": "ubuntu-24.04"}, {"image": "debian-13"}, {"image": "docker-ce"}, {},
                     {"image": "ubuntu-24.04", "firewalls": [{"firewall": 7}], "placement_group": 3,
                      "user_data": "#cloud-config", "labels": {"env": "x"}, "volumes": [], "networks": [],
                      "public_net": {"enable_ipv4": True, "enable_ipv6": False, "ipv4": None}}):
            self.assertEqual((new(**more).kind, len(new(**more).plan["steps"])), ("own", 1), more)
        for image in (4711, "4711", "0", True, ["ubuntu-24.04"], {"id": 4711}, "Ubuntu", ""):
            with self.subTest(image=image):
                self.assertEqual(new(image=image).kind, "refused")
                self.assertIn("a copy of a server's disk, and is never the door's", new(image=image).why)
                self.assertNotIn("an agent made", new(image=image).why)
        for more, words in (({"volumes": [777]}, "a new server takes no volume"),
                            ({"volumes": [777], "automount": True}, "a new server takes no volume"),
                            ({"networks": [5]}, "a new server joins no private network"),
                            ({"public_net": {"ipv4": 12}}, "a new server takes no address"),
                            ({"public_net": {"enable_ipv4": True, "ipv6": 13}}, "a new server takes no address")):
            with self.subTest(more=more):
                d = new(image="ubuntu-24.04", **more)
                self.assertEqual(d.kind, "refused")
                self.assertIn(words, d.why)

    def test_no_write_changes_an_image(self):
        for method, path, body in (("PUT", "/images/8", b'{"type": "snapshot"}'),
                                   ("POST", "/images/8/actions/change_protection", b'{"delete": false}')):
            d = self.decide("change", method, path, content=body)
            self.assertEqual(d.kind, "refused", path)
            self.assertIn("a copy of a server's disk: a change of one is never the door's", d.why)

    def test_a_volume_moves_only_between_servers_that_the_agent_holds(self):
        """A volume is a disk too: it leaves a held server, it joins a held server when it is on none, and a new one
        is made on a held server."""
        volume = ("GET", f"{self.API}/volumes/5")
        attach = self.decide("change", "POST", "/volumes/5/actions/attach", content=b'{"server": 42}')
        self.assertEqual(attach.kind, "own", attach.why)
        stub, _ = self.run_plan(attach, [(volume, (200, {"volume": {"id": 5, "server": None}})), self.server("web-1"),
                                         (("POST", f"{self.API}/volumes/5/actions/attach"), (201, {}))])
        self.assertEqual([c["url"].removeprefix(self.API) for c in stub.calls],
                         ["/volumes/5", "/servers/42", "/volumes/5/actions/attach"])
        self.assertEqual(json.loads(stub.calls[2]["body"]), {"server": 42})
        self.stopped(attach, [(volume, (200, {"volume": {"id": 5, "server": 99}})), self.server("web-1")],
                     "that volume is on a server")
        self.stopped(attach, [(volume, (200, {})), self.server("web-1")], "the project did not say")
        self.stopped(attach, [(volume, (200, {"volume": {"id": 5, "server": None}})), self.server("hub-1")],
                     "holds at Fix")
        detach = self.decide("change", "POST", "/volumes/5/actions/detach")
        self.assertEqual(detach.kind, "own", detach.why)
        stub, _ = self.run_plan(detach, [(volume, (200, {"volume": {"id": 5, "server": 42}})), self.server("web-1"),
                                         (("POST", f"{self.API}/volumes/5/actions/detach"), (201, {}))])
        self.assertEqual([c["url"].removeprefix(self.API) for c in stub.calls],
                         ["/volumes/5", "/servers/42", "/volumes/5/actions/detach"])
        self.stopped(detach, [(volume, (200, {"volume": {"id": 5, "server": 99}})), self.server("hub-1", 99)],
                     "holds at Fix")
        self.stopped(detach, [(volume, (200, {"volume": {"id": 5, "server": None}}))], "on no server")
        new = self.decide("change", "POST", "/volumes", content=b'{"name": "data", "size": 10, "server": 42}')
        stub, _ = self.run_plan(new, [self.server("web-1"), (("POST", f"{self.API}/volumes"), (201, {}))])
        self.assertEqual([c["url"].removeprefix(self.API) for c in stub.calls], ["/servers/42", "/volumes"])
        self.stopped(new, [self.server("hub-1")], "holds at Fix")
        for path, body in (("/volumes/5/actions/attach", b'{"server": "42"}'), ("/volumes/5/actions/attach", None),
                           ("/volumes", b'{"name": "data", "size": 10, "server": true}')):
            self.assertIn("by its id", self.decide("change", "POST", path, content=body).why)
        for path, body in (("/volumes", b'{"name": "data", "size": 10, "location": "fsn1"}'),     # they name no server
                           ("/volumes/5/actions/resize", b'{"size": 20}'), ("/firewalls", b'{"name": "web"}'),
                           ("/floating_ips", b'{"type": "ipv4", "home_location": "fsn1"}'),
                           ("/primary_ips", b'{"type": "ipv4", "assignee_type": "server", "datacenter": "fsn1-dc14"}'),
                           ("/ssh_keys", b'{"name": "ops", "public_key": "ssh-ed25519 AAAA"}')):
            d = self.decide("change", "POST", path, content=body)
            self.assertEqual((d.kind, len(d.plan["steps"])), ("own", 1), path)

    def test_an_address_moves_only_between_servers_that_the_agent_holds(self):
        """An address is how the outside reaches a server: it leaves a held server, and joins a held server when it
        is on none, as a volume does."""
        for kind, thing, field in (("floating_ips", "floating_ip", "server"),
                                   ("primary_ips", "primary_ip", "assignee_id")):
            with self.subTest(kind=kind):
                one = ("GET", f"{self.API}/{kind}/5")

                def on(server):
                    return one, (200, {thing: {"id": 5, field: server}})
                body = json.dumps({field: 42, "assignee_type": "server"}).encode()
                assign = self.decide("change", "POST", f"/{kind}/5/actions/assign", content=body)
                self.assertEqual(assign.kind, "own", assign.why)
                stub, _ = self.run_plan(assign, [on(None), self.server("web-1"),
                                                 (("POST", f"{self.API}/{kind}/5/actions/assign"), (201, {}))])
                self.assertEqual([c["url"].removeprefix(self.API) for c in stub.calls],
                                 [f"/{kind}/5", "/servers/42", f"/{kind}/5/actions/assign"])
                self.stopped(assign, [on(99), self.server("web-1")], "is on a server")
                self.stopped(assign, [on(None), self.server("fleet-1")], "holds at Fix")
                unassign = self.decide("change", "POST", f"/{kind}/5/actions/unassign")
                stub, _ = self.run_plan(unassign, [on(42), self.server("web-1"),
                                                   (("POST", f"{self.API}/{kind}/5/actions/unassign"), (201, {}))])
                self.assertEqual([c["url"].removeprefix(self.API) for c in stub.calls],
                                 [f"/{kind}/5", "/servers/42", f"/{kind}/5/actions/unassign"])
                self.stopped(unassign, [on(99), self.server("hub-1", 99)], "holds at Fix")
                self.stopped(unassign, [on(None)], "on no server")
                new = self.decide("change", "POST", f"/{kind}", content=body)
                self.stopped(new, [self.server("hub-1")], "holds at Fix")
                self.assertIn("by its id", self.decide("change", "POST", f"/{kind}/5/actions/assign",
                                                       content=b'{"server": "42", "assignee_id": "42"}').why)

    def test_a_load_balancer_s_target_is_a_server_that_the_agent_holds(self):
        """A load balancer shows the ports of its targets to the internet. A target is a held server by its id; a
        label, an address and the targets of a new load balancer are refused."""
        target = json.dumps({"type": "server", "server": {"id": 42}}).encode()
        for action in ("add_target", "remove_target"):
            d = self.decide("change", "POST", f"/load_balancers/5/actions/{action}", content=target)
            self.assertEqual((d.kind, [s.get("need") for s in d.plan["steps"]]), ("own", ["held_server", None]), d.why)
            self.stopped(d, [self.server("hub-1")], "holds at Fix")
        for body in ({"type": "label_selector", "label_selector": {"selector": "x"}}, {"type": "ip", "ip": {"ip": "1.1.1.1"}},
                     {"type": "server", "server": {"id": "42"}}, {"type": "server"}, {}):
            with self.subTest(body=body):
                d = self.decide("change", "POST", "/load_balancers/5/actions/add_target",
                                content=json.dumps(body).encode())
                self.assertEqual(d.kind, "refused", d)
        d = self.decide("change", "POST", "/load_balancers", content=json.dumps(
            {"name": "lb", "targets": [{"type": "server", "server": {"id": 99}}]}).encode())
        self.assertEqual(d.kind, "refused", d)
        self.assertIn("a new load balancer has no target", d.why)
        self.assertEqual(self.decide("change", "POST", "/load_balancers", content=b'{"name": "lb"}').kind, "own")

    def test_a_body_key_in_another_case_is_refused(self):
        """Each check reads a key as the provider's documents spell it, and none depends on how the provider reads a
        key in another case."""
        for method, path, body in (("PUT", "/servers/42", {"Name": "web-1"}),
                                   ("POST", "/servers", {"ssh_keys": ["ops"], "Volumes": [5]}),
                                   ("POST", "/servers", {"ssh_keys": ["ops"], "public_net": {"IPv4": 7}}),
                                   ("POST", "/servers", {"ssh_keys": ["ops"], "Image": 4711}),
                                   ("POST", "/volumes/5/actions/attach", {"Server": 99}),
                                   ("POST", "/load_balancers/5/actions/add_target",
                                    {"type": "server", "server": {"id": 42, "ID": 99}}),
                                   ("POST", "/load_balancers/5/actions/add_target",
                                    {"type": "server", "server": {"id": 42}, "\u017ferver": {"id": 99}}),
                                   ("POST", "/load_balancers", {"name": "lb", "target\u017f": [{"type": "ip"}]}),
                                   ("POST", "/firewalls/7/actions/apply_to_resources",
                                    {"apply_to": [{"type": "server", "server": {"id": 42, "Id": 99}}]})):
            with self.subTest(path=path, body=body):
                d = self.decide("change", method, path, content=json.dumps(body).encode())
                self.assertEqual(d.kind, "refused", d)
                self.assertRegex(d.why, "is written|plain ASCII")
        labelled = {"name": "web-9", "ssh_keys": ["ops"], "image": "ubuntu-24.04", "labels": {"Name": "web", "Env": "x"}}
        self.assertEqual(self.decide("change", "POST", "/servers", content=json.dumps(labelled).encode()).kind, "own")

    def test_a_firewall_changes_only_on_servers_that_the_agent_holds(self):
        """A firewall of the hub's server is not this agent's to open. A firewall goes on and off held servers, which
        the body names by their ids, and its rules change when every server that it is on is held, in both forms."""
        servers = (("GET", f"{self.API}/servers?per_page=50"),
                   (200, {"servers": [{"id": 42, "name": "web-1"}, {"id": 43, "name": "db-1"},
                                      {"id": 99, "name": "hub-1"}]}))

        def firewall(*on):
            return ("GET", f"{self.API}/firewalls/7"), (200, {"firewall": {"id": 7, "applied_to": list(on)}})

        def server(number):
            return {"type": "server", "server": {"id": number}}
        rules = (("POST", f"{self.API}/firewalls/7/actions/set_rules"), (201, {"actions": []}))
        named = (("GET", f"{self.API}/servers?name=web-1"), (200, {"servers": [{"id": 42}]}))
        label = {"type": "label_selector", "label_selector": {"selector": "env=prod"},
                 "applied_to_resources": [server(42)]}
        for args, more in ((("POST", "/firewalls/7/actions/set_rules"), []),
                           (("POST", "/firewalls/7/actions/set_rules", "web-1"), [named])):
            with self.subTest(args=args):
                d = self.decide("change", *args, content=b'{"rules": [{"direction": "in", "port": "22"}]}')
                self.assertEqual(d.kind, "own", d.why)
                for on in ((server(42), server(43)), ()):
                    stub, _ = self.run_plan(d, [*more, servers, firewall(*on), rules])
                    self.assertEqual([c["url"].removeprefix(self.API) for c in stub.calls][len(more):],
                                     ["/servers?per_page=50", "/firewalls/7", "/firewalls/7/actions/set_rules"])
                for on in ((server(42), server(99)), (server(7000),), (label,), ("x",)):
                    self.stopped(d, [*more, servers, firewall(*on)], "its rules are not this agent's to set")
                self.stopped(d, [*more, servers, (("GET", f"{self.API}/firewalls/7"), (200, {}))], "not this agent's")
        for action, field in (("apply_to_resources", "apply_to"), ("remove_from_resources", "remove_from")):
            with self.subTest(action=action):
                path = f"/firewalls/7/actions/{action}"
                d = self.decide("change", "POST", path, content=json.dumps({field: [server(42), server(43)]}).encode())
                self.assertEqual(d.kind, "own", d.why)
                stub, _ = self.run_plan(d, [self.server("web-1"), self.server("db-1", 43),
                                            (("POST", self.API + path), (201, {}))])
                self.assertEqual([c["url"].removeprefix(self.API) for c in stub.calls],
                                 ["/servers/42", "/servers/43", path])
                self.stopped(d, [self.server("web-1"), self.server("hub-1", 43)], "holds at Fix")
                d = self.decide("change", "POST", path, "web-1", content=json.dumps({field: [server(99)]}).encode())
                self.stopped(d, [named, self.server("hub-1", 99)], "holds at Fix")
                for bad in ([label], [{"type": "server", "server": {"id": "42"}}], {"type": "server"},
                            [server(42)] * 11):
                    d = self.decide("change", "POST", path, content=json.dumps({field: bad}).encode())
                    self.assertEqual(d.kind, "refused", bad)
                    self.assertIn("never by a label", d.why)
        d = self.decide("change", "POST", "/firewalls", content=json.dumps({"name": "open", "apply_to": [server(99)],
                                                                            "rules": []}).encode())
        self.stopped(d, [self.server("hub-1", 99)], "holds at Fix")


STS = (("POST", "https://sts.eu-central-1.amazonaws.com/"),
       (200, "<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>"
             "<SessionToken>session-token</SessionToken><SecretAccessKey>session-secret</SecretAccessKey>"
             "<Expiration>2099-01-01T00:00:00Z</Expiration><AccessKeyId>ASIASESSION</AccessKeyId></Credentials>"
             "</AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>"))
SIGNED = r"^AWS4-HMAC-SHA256 Credential=ASIASESSION/\d{8}/eu-central-1/%s/aws4_request, " \
         r"SignedHeaders=%s;host;x-amz-date;x-amz-security-token, Signature=[0-9a-f]{64}$"


class AWS(Provider):
    """No AWS key: the door assumes the account's role with its own bot's JWT-SVID, and signs with that session."""
    target = "aws:one"

    def test_start_of_a_tagged_instance_signed_with_the_role_s_session(self):
        d = self.decide("start", "i-0123456789abcdef0")
        self.assertEqual(d.kind, "rule")
        stub, out = self.run_plan(d, [STS, (("POST", "https://ec2.eu-central-1.amazonaws.com/"),
                                            (200, "<instanceId>i-0123456789abcdef0</instanceId>"))])
        trade, first, second = stub.calls
        self.assertIn("Action=AssumeRoleWithWebIdentity", trade["body"])
        self.assertIn("RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Ffleet-door-aws", trade["body"])
        self.assertIn("WebIdentityToken=jwt-of-the-bot", trade["body"])
        self.assertNotIn("Authorization", trade["headers"])
        self.assertIn("Action=DescribeInstances", first["body"])
        self.assertIn("Filter.1.Value.1=door", first["body"])
        self.assertIn("Action=StartInstances", second["body"])
        self.assertRegex(second["headers"]["Authorization"], SIGNED % ("ec2", "content-type"))
        self.assertEqual(second["headers"]["X-Amz-Security-Token"], "session-token")
        self.assertNotIn("session-secret", json.dumps(stub.calls) + out)
        self.assertNotIn("session-token", out)
        self.assertNotIn("jwt-of-the-bot", json.dumps(stub.calls[1:]) + out)

    def test_one_session_serves_its_hour_and_a_refusal_of_sts_says_why(self):
        stub = Stub([STS, (("POST", "https://sts.eu-central-1.amazonaws.com/"), (200, "<Arn>x</Arn>")),
                     (("POST", "https://cloudformation."), (200, "<DescribeStacksResult/>"))])
        ctx = stub.ctx(self.target)
        for _ in range(2):
            door_providers.execute(self.decide("stacks").plan, ctx)
        self.assertEqual([c["url"] for c in stub.calls].count("https://sts.eu-central-1.amazonaws.com/"), 1)
        stub = Stub([(("POST", "https://sts."), (403, "<Error><Code>InvalidIdentityToken</Code><Message>Incorrect "
                                                      "token audience</Message></Error>"))])
        with self.assertRaisesRegex(door_providers.Stop, "no session of arn:aws:iam::123456789012:role/fleet-door-aws "
                                                         r"\(403, InvalidIdentityToken: Incorrect token audience\)"):
            door_providers.execute(self.decide("instances").plan, stub.ctx(self.target))

    def test_the_identity_read_names_the_role_s_session(self):
        d = self.decide("identity")
        self.assertEqual(d.kind, "read")
        stub, out = self.run_plan(d, [STS])
        self.assertIn("Action=GetCallerIdentity", stub.calls[1]["body"])
        self.assertRegex(stub.calls[1]["headers"]["Authorization"], SIGNED % ("sts", "content-type"))

    def test_an_untagged_instance_is_not_the_door_s(self):
        d = self.decide("reboot", "i-0123456789abcdef0")
        with self.assertRaisesRegex(door_providers.Stop, "door's tag"):
            self.run_plan(d, [STS, (("POST", "https://ec2."), (200, "<reservationSet/>"))])

    def test_the_own_calls(self):
        self.assertEqual(self.decide("ingress", "add", "sg-0123abcd", "tcp", "443", "10.0.0.0/8").kind, "own")
        self.assertEqual(self.decide("change-set", "web", "fix-1", content=b"{}").kind, "own")
        d = self.decide("key-off", "deploy-user", "AKIAABCDEFGHIJKLMNOP")
        self.assertEqual(d.kind, "own")
        with self.assertRaisesRegex(door_providers.Stop, "shows use"):
            self.run_plan(d, [STS, (("POST", "https://iam.amazonaws.com/"),
                                    (200, "<LastUsedDate>2026-10-01</LastUsedDate>"))])
        self.assertEqual(self.decide("terminate", "i-0123456789abcdef0").kind, "refused")

    def test_a_new_eks_public_endpoint_list_is_an_own_call(self):
        d = self.decide("eks-allowlist", "prod", "203.0.113.37/32", "10.1.0.0/16")
        self.assertEqual(d.kind, "own")
        stub, _ = self.run_plan(d, [STS, (("GET", "https://eks.eu-central-1.amazonaws.com/clusters/prod"),
                                          (200, {"cluster": {"name": "prod"}})),
                                    (("POST", "https://eks.eu-central-1.amazonaws.com/clusters/prod/update-config"),
                                     (200, {"update": {"status": "InProgress"}}))])
        read, change = stub.calls[1:]
        self.assertIsNone(read["body"])
        self.assertRegex(read["headers"]["Authorization"], (SIGNED % ("eks", "")).replace("=;", "="))
        self.assertEqual(json.loads(change["body"]),
                         {"resourcesVpcConfig": {"publicAccessCidrs": ["203.0.113.37/32", "10.1.0.0/16"]}})
        self.assertRegex(change["headers"]["Authorization"], SIGNED % ("eks", "content-type"))
        for args, why in ((("prod", "0.0.0.0/0"), "every address"), (("prod", "10.1.0.0/33"), "IPv4 ranges"),
                          (("prod",), "IPv4 ranges"), (("prod", "2001:db8::/32"), "IPv4 ranges")):
            d = self.decide("eks-allowlist", *args)
            self.assertEqual(d.kind, "refused", args)
            self.assertIn(why, d.why)

    def test_any_other_call_inside_the_role_s_rights_is_an_own_call_in_its_protocol(self):
        d = self.decide("call", "ec2", "DescribeVolumes", content=b'{"Filter.1.Name": "tag-key", "MaxResults": 5}')
        self.assertEqual(d.kind, "own")
        stub, _ = self.run_plan(d, [STS, (("POST", "https://ec2.eu-central-1.amazonaws.com/"), (200, "<volumeSet/>"))])
        self.assertIn("Action=DescribeVolumes", stub.calls[1]["body"])
        self.assertIn("MaxResults=5", stub.calls[1]["body"])
        d = self.decide("call", "ecr", "DescribeImages", "eu-west-1", content=b'{"repositoryName": "api"}')
        stub, _ = self.run_plan(d, [STS, (("POST", "https://api.ecr.eu-west-1.amazonaws.com/"), (200, {}))])
        headers = stub.calls[1]["headers"]
        self.assertEqual(headers["X-Amz-Target"], "AmazonEC2ContainerRegistry_V20150921.DescribeImages")
        self.assertEqual(headers["Content-Type"], "application/x-amz-json-1.1")
        self.assertRegex(headers["Authorization"], r"/eu-west-1/ecr/aws4_request, SignedHeaders=content-type;host;"
                                                   r"x-amz-date;x-amz-security-token;x-amz-target, ")
        d = self.decide("call", "eks", "GET", "/clusters?maxResults=10")
        self.assertEqual(d.kind, "own")
        stub, _ = self.run_plan(d, [STS, (("GET", "https://eks.eu-central-1.amazonaws.com/clusters?maxResults=10"),
                                          (200, {"clusters": []}))])
        self.assertEqual(stub.calls[1]["method"], "GET")

    def test_a_call_whose_answer_is_a_secret_or_a_shell_or_access_is_never_the_door_s(self):
        for args in (("secretsmanager", "GetSecretValue"), ("sts", "AssumeRole"), ("iam", "CreateAccessKey"),
                     ("ecr", "GetAuthorizationToken"), ("ecr", "UploadLayerPart"), ("ec2", "GetPasswordData"), ("ec2", "CreateKeyPair"),
                     ("ec2", "DescribeInstanceAttribute"), ("ec2", "ModifyInstanceAttribute"),
                     ("eks", "POST", "/clusters/prod/access-entries"), ("ssm", "SendCommand"), ("s3", "GET", "/b"),
                     ("lambda", "Invoke"), ("ec2", "describeVolumes"), ("eks", "GET", "/clusters/../x"),
                     ("eks", "PATCH", "/clusters/prod"), ("ec2", "DescribeVolumes", "Mars")):
            with self.subTest(args=args):
                self.assertEqual(self.decide("call", *args).kind, "refused")
        for content in (b"[1]", b"{", b'{"Filter": {"Name": "x"}}'):
            self.assertEqual(self.decide("call", "ec2", "DescribeVolumes", content=content).kind, "refused")


class Azure(Provider):
    target = "azure:one"
    SQL = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Sql/servers/db"
    SITE = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Web/sites/shop"
    TOKEN = (("POST", "https://login.microsoftonline.com/t/oauth2/v2.0/token"), (200, {"access_token": "az-tok"}))

    def test_a_listed_read_and_metrics(self):
        d = self.decide("get", f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Web/sites/shop/providers/"
                               f"Microsoft.Insights/metrics")
        self.assertEqual(d.kind, "read")
        stub, _ = self.run_plan(d, [self.TOKEN, (("GET", "https://management.azure.com/"), (200, {"value": []}))])
        self.assertIn("client_secret=token-of-the-door", stub.calls[0]["body"])
        self.assertEqual(stub.calls[1]["headers"]["Authorization"], "Bearer az-tok")
        self.assertIn("api-version=", stub.calls[1]["url"])
        self.assertEqual(self.decide("get", self.SITE + "/config/appsettings/list").kind, "refused")
        self.assertEqual(self.decide("get", f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.KeyVault/"
                                            f"vaults/kv/secrets").kind, "refused")

    def test_a_firewall_rule_on_a_listed_sql_server_is_an_own_call(self):
        d = self.decide("sql-firewall", self.SQL, "office", "203.0.113.1", "203.0.113.1")
        self.assertEqual(d.kind, "own")
        stub, _ = self.run_plan(d, [self.TOKEN, (("PUT", "https://management.azure.com/"), (200, {}))])
        self.assertTrue(stub.calls[1]["url"].startswith(f"https://management.azure.com{self.SQL}/firewallRules/office?"))
        self.assertEqual(self.decide("sql-firewall", self.SQL + "x", "office", "1.2.3.4", "1.2.3.4").kind, "refused")

    def test_an_app_service_setting_keeps_the_others(self):
        d = self.decide("app-setting", self.SITE, "FEATURE_X", "on")
        self.assertEqual(d.kind, "own")
        stub, _ = self.run_plan(d, [self.TOKEN, (("POST", f"https://management.azure.com{self.SITE}/config/"
                                                          f"appsettings/list"), (200, {"properties": {"A": "1"}})),
                                    (("PUT", f"https://management.azure.com{self.SITE}/config/appsettings"),
                                     (200, {}))])
        self.assertEqual(json.loads(stub.calls[2]["body"]), {"properties": {"A": "1", "FEATURE_X": "on"}})


class Tailscale(Provider):
    target = "tailscale:net"
    API = "https://api.tailscale.com/api/v2"
    CLIENT = "tskey-client-kD00r1CNTRL-0123456789abcdef"
    TOKEN = (("POST", f"{API}/oauth/token"), (200, {"access_token": "tskey-api-hour", "token_type": "Bearer",
                                                     "expires_in": 3600, "scope": "devices:core"}))

    def run_plan(self, d, answers, secret=CLIENT):
        return super().run_plan(d, [self.TOKEN, *answers], secret)

    def test_the_oauth_client_is_exchanged_for_a_token_before_a_call(self):
        """Tailscale takes an OAuth client's secret only at its token address (client credentials): the calls carry
        the access token of an hour, and the client's secret goes nowhere else."""
        stub, _ = self.run_plan(self.decide("devices"), [(("GET", f"{self.API}/tailnet/-/devices"),
                                                          (200, {"devices": []}))])
        token, devices = stub.calls
        self.assertEqual((token["method"], token["url"], token["headers"]["Content-Type"]),
                         ("POST", f"{self.API}/oauth/token", "application/x-www-form-urlencoded"))
        self.assertEqual(dict(p.split("=") for p in token["body"].split("&")),
                         {"client_id": "kD00r1CNTRL", "client_secret": self.CLIENT})
        self.assertEqual(devices["headers"]["Authorization"], "Bearer tskey-api-hour")
        self.no_secret_in(stub, "", self.CLIENT)
        stub = Stub([(("POST", f"{self.API}/oauth/token"), (401, {"message": "API token invalid"}))])
        with self.assertRaisesRegex(door_providers.Stop, "refused the door's OAuth client \\(401\\)"):
            door_providers.execute(self.decide("devices").plan, stub.ctx(self.target, self.CLIENT))
        self.assertEqual(len(stub.calls), 1)

    def test_key_expiry_off_and_a_rename_for_a_device_of_the_fleet(self):
        d = self.decide("key-expiry-off", "n123")
        self.assertEqual(d.kind, "rule")
        stub, _ = self.run_plan(d, [(("GET", f"{self.API}/device/n123"), (200, {"tags": ["tag:fleet"]})),
                                    (("POST", f"{self.API}/device/n123/key"), (200, {}))])
        self.assertEqual(json.loads(stub.calls[2]["body"]), {"keyExpiryDisabled": True})
        d = self.decide("rename", "n123", "web-1")
        with self.assertRaisesRegex(door_providers.Stop, "no tag of the fleet"):
            self.run_plan(d, [(("GET", f"{self.API}/device/n123"), (200, {"tags": ["tag:other"]}))])

    def test_a_revoked_oauth_client_leaves_the_door_s_list(self):
        """As a Backblaze key that key-revoke ended: the id of the client that the provider ended reaches keep."""
        d = self.decide("oauth-client", "revoke", "kC1234")
        stub = Stub([self.TOKEN, (("DELETE", f"{self.API}/tailnet/-/keys/kC1234"), (200, {}))])
        ctx, kept = stub.ctx(d.target, self.CLIENT), []
        ctx["keep"] = lambda kind, value: kept.append((kind, value))
        door_providers.execute(d.plan, ctx)
        self.assertEqual(kept, [("revoked", "kC1234")])
        stub = Stub([self.TOKEN, (("DELETE", f"{self.API}/tailnet/-/keys/kC1234"), (404, {"message": "not found"}))])
        ctx, kept = stub.ctx(d.target, self.CLIENT), []
        ctx["keep"] = lambda kind, value: kept.append((kind, value))
        with self.assertRaises(door_providers.Stop):
            door_providers.execute(d.plan, ctx)
        self.assertEqual(kept, [])                  # a client that the provider did not end stays the door's

    def test_delete_and_an_oauth_client_are_own_calls_and_tags_never(self):
        self.assertEqual(self.decide("delete", "n123").kind, "own")
        d = self.decide("oauth-client", "make", "tag:fleet")
        self.assertEqual(d.kind, "own")
        stub, out = self.run_plan(d, [(("POST", f"{self.API}/tailnet/-/keys"),
                                       (200, {"id": "kC1", "key": "tskey-client-SECRET"}))])
        self.assertEqual(stub.kept[0]["key"], "tskey-client-SECRET")
        self.assertNotIn("tskey-client-SECRET", out)
        self.assertEqual(self.decide("tags", "n123").kind, "refused")
        self.assertEqual(self.decide("acl").kind, "refused")

    def test_change_passes_a_device_s_name_its_key_expiry_and_its_delete_and_no_other_write(self):
        """The door knows a caller by its Tailscale address alone. A write of a device's address, routes or approval,
        or of the tailnet's settings, lets its sender become another agent to the door, so change passes none."""
        for method, path, body in (("POST", "/device/n1234567/name", b'{"name": "web-9"}'),
                                   ("POST", "/device/n1234567/key", b'{"keyExpiryDisabled": false}'),
                                   ("DELETE", "/device/n1234567", None)):
            d = self.decide("change", method, path, content=body)
            self.assertEqual((d.kind, [(s["method"], s["path"]) for s in d.plan["steps"]]),
                             ("own", [(method, path)]), d.why)
        device = [("POST", f"/device/n1234567/{part}") for part in (
            "ip", "routes", "authorized", "expire", "attributes/custom.owner", "name/x", "key/x", "posture")] + \
            [("PUT", "/device/n1234567/name"), ("PATCH", "/device/n1234567/key"), ("DELETE", "/device/n1234567/key"),
             ("POST", "/device/n1234567"), ("DELETE", "/device/n1234567/routes")]
        for method, path in device:
            with self.subTest(method=method, path=path):
                d = self.decide("change", method, path, content=b'{"ipv4": "100.64.0.9"}')
                self.assertEqual(d.kind, "refused")
                self.assertIn("decide who a caller is on the private network: never the door's", d.why)
        tailnet = [("PATCH", "/tailnet/-/settings"), ("POST", "/tailnet/-/dns/nameservers"),
                   ("POST", "/tailnet/-/dns/preferences"), ("POST", "/tailnet/-/dns/searchpaths"),
                   ("PUT", "/tailnet/-/dns/split-dns"), ("POST", "/tailnet/-/posture/integrations"),
                   ("PATCH", "/tailnet/-/contacts/security"), ("PUT", "/tailnet/-/logging/network/stream"),
                   ("PUT", "/tailnet/-/services/svc.web"), ("PATCH", "/tailnet/-/device-attributes"),
                   ("POST", "/tailnet/-/devices"), ("DELETE", "/tailnet/-/dns/nameservers"), ("POST", "/tailnet/-")]
        for method, path in tailnet:
            with self.subTest(method=method, path=path):
                d = self.decide("change", method, path, content=b"{}")
                self.assertEqual(d.kind, "refused")
                self.assertIn("who reaches what and who is who on the private network: never the door's", d.why)
        self.assertEqual([self.decide(*form).kind for form in (                 # the listed forms stay as they were
            ("devices",), ("device", "n123"), ("rename", "n123", "web-1"), ("key-expiry-off", "n123"),
            ("delete", "n123"), ("oauth-client", "make", "tag:fleet"), ("oauth-client", "revoke", "kC1234"))],
            ["read", "read", "rule", "rule", "own", "own", "own"])


class NotListed(Provider):
    """The owner, 6 November 2026 (DevOps D25: "Yes, as for AWS"): for every provider, a write that is not listed is
    one write inside the key's own rights, and since 11 November 2026 it is the agent's own call; a delete of what no
    agent made comes to the owner as a Needs-you item with the exact call (deletes). An unlisted read stays refused,
    and a write whose answer is a secret is never sent, because the door gives the agent the answer."""
    SUB = "/subscriptions/" + "0" * 8 + "-0000-4000-8000-" + "0" * 12

    def kinds(self, cases):
        for target, args, content, kind, words in cases:
            with self.subTest(target=target, args=args):
                d = self.decide("change", *args, content=content, target=target)
                self.assertEqual(d.kind, kind, d.why)
                if words:
                    self.assertIn(words, d.why)

    def test_a_write_that_is_not_listed_is_the_agent_s_own_call_for_each_provider(self):
        account = "b" * 32
        self.kinds([
            ("cloudflare:one", ["POST", f"/accounts/{account}/workers/domains"], b'{"hostname": "x"}', "own", None),
            ("cloudflare:one", ["DELETE", f"/zones/{ZONE}/dns_records/{'c' * 32}"], None, "own", None),
            ("hetzner:one", ["POST", "/firewalls"], b'{"name": "web"}', "own", None),
            ("hetzner:one", ["POST", "/servers"], b'{"name": "web-9", "ssh_keys": ["ops"]}', "own", None),
            ("hetzner:one", ["DELETE", "/servers/42"], None, "own", None),
            ("azure:one", ["PUT", f"{self.SUB}/resourceGroups/web/providers/Microsoft.Web/sites/shop", "2023-01-01"],
             b'{"location": "westeurope"}', "own", None),
            ("tailscale:net", ["POST", "/device/n1234567/name"], b'{"name": "web-9"}', "own", None)])
        d = self.decide("change", "b2_update_bucket", content=b'{"bucketId": "x", "bucketType": "allPrivate"}',
                        target="backblaze:one")
        self.assertEqual((d.kind, d.plan["steps"][0]["path"]), ("own", "b2_update_bucket"))
        d = self.decide("change", "PUT", f"{self.SUB}/resourceGroups/web", "2021-04-01", content=b"{}",
                        target="azure:one")
        self.assertEqual(d.plan["steps"][0]["query"], {"api-version": "2021-04-01"})

    def test_an_unlisted_read_stays_refused(self):
        self.kinds([
            ("cloudflare:one", ["GET", f"/zones/{ZONE}/settings"], None, "refused", "stays refused"),
            ("hetzner:one", ["GET", "/servers/42/metrics"], None, "refused", "stays refused"),
            ("azure:one", ["GET", f"{self.SUB}/resourceGroups", "2021-04-01"], None, "refused", "stays refused"),
            ("tailscale:net", ["GET", "/tailnet/-/acl"], None, "refused", "stays refused")])
        for name in ("b2_list_buckets", "b2_get_upload_url", "b2_get_download_authorization", "b2_authorize_account"):
            self.assertEqual(self.decide("change", name, target="backblaze:one").kind, "refused", name)

    def test_a_write_whose_answer_is_a_secret_is_never_sent(self):
        account = "b" * 32
        self.kinds([
            ("cloudflare:one", ["POST", f"/accounts/{account}/tokens"], b"{}", "refused", "secret"),
            ("cloudflare:one", ["GET", f"/accounts/{account}/cfd_tunnel/{TUNNEL}/token"], None, "refused", None),
            ("cloudflare:one", ["POST", f"/accounts/{account}/r2/temp-access-credentials"], b"{}", "refused", "secret"),
            ("cloudflare:one", ["POST", f"/accounts/{account}/access/service_tokens"], b"{}", "refused", "secret"),
            ("hetzner:one", ["POST", "/servers"], b'{"name": "web-9"}', "refused", "root password"),
            ("hetzner:one", ["POST", "/servers/42/actions/reset_password"], None, "refused", "password"),
            ("hetzner:one", ["POST", "/servers/42/actions/enable_rescue"], None, "refused", "Rescue"),
            ("azure:one", ["POST", f"{self.SUB}/resourceGroups/web/providers/Microsoft.Storage/storageAccounts/s/listKeys",
                           "2023-01-01"], None, "refused", "key"),
            ("azure:one", ["POST", f"{self.SUB}/resourceGroups/web/providers/Microsoft.Web/sites/shop/config/appsettings/List",
                           "2023-01-01"], None, "refused", "never the door's"),
            ("tailscale:net", ["POST", "/tailnet/-/keys"], b"{}", "refused", "secret"),
            ("cloudflare:one", ["POST", f"/accounts/{account}/cfd_tunnel"], b'{"name": "t"}', "refused", "token"),
            ("cloudflare:one", ["POST", f"/accounts/{account}/stream/keys"], b"{}", "refused", "private part"),
            ("hetzner:one", ["POST", "/servers/42/actions/rebuild"], b'{"image": "ubuntu-24.04"}', "refused",
             "password"),
            ("azure:one", ["POST", f"{self.SUB}/resourceGroups/web/providers/Microsoft.ContainerRegistry/registries/r/"
                           "generateCredentials", "2023-01-01"], b"{}", "refused", "never the door's"),
            ("azure:one", ["POST", f"{self.SUB}/resourceGroups/web/providers/Microsoft.Compute/disks/d/beginGetAccess",
                           "2023-01-01"], b"{}", "refused", "never the door's"),
            ("azure:one", ["PUT", f"{self.SUB}/resourceGroups/web/providers/Microsoft.Web/sites/shop/functions/f/keys/"
                           "k", "2023-01-01"], b"{}", "refused", "secret"),
            ("tailscale:net", ["POST", "/tailnet/-/webhooks"], b'{"endpointUrl": "https://x"}', "refused", "secret"),
            ("tailscale:net", ["POST", "/tailnet/-/user-invites"], b"[]", "refused", "link")])
        self.assertEqual(self.decide("change", "b2_create_key", content=b"{}", target="backblaze:one").kind, "refused")

    def test_a_write_that_gives_a_shell_or_a_disk_s_copy_away_is_never_sent(self):
        """The same two faults in the other providers' own calls: a login on a machine, and a copy of a disk or of a
        bucket's files that leaves the account."""
        vm = f"{self.SUB}/resourceGroups/web/providers/Microsoft.Compute/virtualMachines/vm"
        aks = f"{self.SUB}/resourceGroups/web/providers/Microsoft.ContainerService/managedClusters/k"
        self.kinds([
            ("azure:one", ["POST", f"{vm}/runCommand", "2024-03-01"], b'{"commandId": "RunShellScript"}', "refused",
             "a shell there"),
            ("azure:one", ["PUT", f"{vm}/runCommands/one", "2024-03-01"], b"{}", "refused", "a shell there"),
            ("azure:one", ["POST", f"{aks}/runCommand", "2024-03-01"], b'{"command": "kubectl get secrets"}',
             "refused", "a shell there"),
            ("azure:one", ["PUT", f"{vm}/extensions/VMAccess", "2024-03-01"], b"{}", "refused", "sets its login"),
            ("azure:one", ["PUT", f"{vm.replace('virtualMachines/vm', 'virtualMachineScaleSets/set')}/extensions/x",
                           "2024-03-01"], b"{}", "refused", "code as root"),
            ("azure:one", ["PUT", f"{vm.replace('Compute/virtualMachines', 'HybridCompute/machines')}/extensions/x",
                           "2024-03-01"], b"{}", "refused", "code as root"),
            ("azure:one", ["POST", f"{vm}/restart", "2024-03-01"], None, "own", None),
            ("azure:one", ["PUT", vm, "2024-03-01"], b'{"location": "westeurope"}', "own", None)])
        for service, action in (("ec2", "ModifySnapshotAttribute"), ("ec2", "ModifyImageAttribute"),
                                ("ec2", "ExportImage"), ("ec2", "CreateInstanceExportTask"),
                                ("ec2", "CreateStoreImageTask"), ("rds", "ModifyDBSnapshotAttribute"),
                                ("rds", "ModifyDBClusterSnapshotAttribute"), ("rds", "StartExportTask")):
            d = self.decide("call", service, action, content=b"{}", target="aws:one")
            self.assertEqual((d.kind, "never the door's" in d.why), ("refused", True), action)
        for service, action in (("ec2", "CreateVolume"), ("ec2", "ModifyVolume"), ("rds", "CreateDBSnapshot"),
                                ("rds", "ModifyDBInstance"), ("ec2", "RunInstances")):
            self.assertEqual(self.decide("call", service, action, content=b"{}", target="aws:one").kind, "own", action)
        for name, body, kind in (
                ("b2_update_bucket", {"bucketId": "bk1", "bucketType": "allPublic"}, "refused"),
                ("b2_create_bucket", {"bucketName": "open", "bucketType": "allPublic"}, "refused"),
                ("b2_update_bucket", {"bucketId": "bk1", "bucketType": "snapshot"}, "refused"),
                ("b2_update_bucket", {"bucketId": "bk1", "replicationConfiguration": {"asReplicationSource": {
                    "replicationRules": [{"destinationBucketId": "theirs"}], "sourceApplicationKeyId": "k1"}}},
                 "refused"),
                ("b2_update_bucket", {"bucketId": "bk1", "replicationConfiguration": "x"}, "refused"),
                ("b2_update_bucket", {"bucketId": "bk1", "bucketType": "allPrivate"}, "own"),
                ("b2_create_bucket", {"bucketName": "logs", "bucketType": "allPrivate"}, "own"),
                ("b2_update_bucket", {"bucketId": "bk1", "lifecycleRules": []}, "own"),
                ("b2_update_bucket", {"bucketId": "bk1", "replicationConfiguration": {
                    "asReplicationSource": None, "asReplicationDestination": None}}, "own")):
            with self.subTest(call=name, body=body):
                d = self.decide("change", name, content=json.dumps(body).encode(), target="backblaze:one")
                self.assertEqual(d.kind, kind, d.why)
                if kind == "refused":
                    self.assertIn("no read of the door gives a file", d.why)

    def test_a_write_that_is_right_only_for_a_held_server_is_not_sent_where_the_door_knows_no_holder(self):
        """AWS and Azure have no record of which machine an agent holds. So the door sends no call there that copies a
        disk, puts one on another machine, runs code at start-up or sets a login, and none that makes many resources
        from a template or gives access."""
        for service, action, params, words in (
                ("ec2", "CreateImage", {"InstanceId": "i-0123456789abcdef0", "Name": "copy"}, "a copy of"),
                ("ec2", "CreateSnapshot", {"VolumeId": "vol-0123456789abcdef0"}, "a copy of"),
                ("ec2", "CreateSnapshots", {"InstanceSpecification.InstanceId": "i-0123456789abcdef0"}, "a copy of"),
                ("ec2", "AttachVolume", {"VolumeId": "vol-0123456789abcdef0", "InstanceId": "i-0123456789abcdef0",
                                         "Device": "/dev/sdf"}, "a disk on another instance"),
                ("ec2", "CreateReplaceRootVolumeTask", {"InstanceId": "i-0123456789abcdef0"}, "a disk on another"),
                ("ec2", "RunInstances", {"ImageId": "ami-0123456789abcdef0", "MinCount": 1, "MaxCount": 1,
                                         "UserData": "IyEvYmluL3No"}, "code that runs as root"),
                ("ec2", "RequestSpotInstances", {"LaunchSpecification.UserData": "IyEvYmluL3No"}, "code that runs"),
                ("rds", "ModifyDBInstance", {"DBInstanceIdentifier": "shop", "MasterUserPassword": "x" * 16},
                 "a login to a database"),
                ("rds", "ModifyDBCluster", {"DBClusterIdentifier": "shop", "masterUserPassword": "x" * 16},
                 "a login to a database")):
            with self.subTest(call=f"{service}:{action}"):
                d = self.decide("call", service, action, content=json.dumps(params).encode(), target="aws:one")
                self.assertEqual(d.kind, "refused")
                self.assertIn(f"{service}:{action} is never the door's here: ", d.why)
                self.assertIn(words, d.why)
        for service, action, params in (
                ("ec2", "RunInstances", {"ImageId": "ami-0123456789abcdef0", "MinCount": 1, "MaxCount": 1}),
                ("rds", "ModifyDBInstance", {"DBInstanceIdentifier": "shop", "AllocatedStorage": 200}),
                ("rds", "CreateDBInstance", {"DBInstanceIdentifier": "new", "ManageMasterUserPassword": True}),
                ("ec2", "CreateVolume", {"Size": 100, "AvailabilityZone": "eu-central-1a"})):
            d = self.decide("call", service, action, content=json.dumps(params).encode(), target="aws:one")
            self.assertEqual(d.kind, "own", action)
        open_to_all = b'{"resourcesVpcConfig": {"endpointPublicAccess": true, "publicAccessCidrs": ["0.0.0.0/0"]}}'
        d = self.decide("call", "eks", "POST", "/clusters/prod/update-config", content=open_to_all, target="aws:one")
        self.assertEqual(d.kind, "refused")
        self.assertIn("change through eks-allowlist", d.why)
        self.assertEqual(self.decide("call", "eks", "POST", "/clusters/prod/update-config", target="aws:one",
                                     content=b'{"logging": {"clusterLogging": []}}').kind, "own")
        self.assertEqual(self.decide("eks-allowlist", "prod", "203.0.113.7/32", target="aws:one").kind, "own")
        rg = f"{self.SUB}/resourceGroups/web/providers"
        vm, sets = f"{rg}/Microsoft.Compute/virtualMachines/vm", f"{rg}/Microsoft.Compute/virtualMachineScaleSets/s"
        login = {"location": "westeurope", "properties": {"osProfile": {"adminUsername": "x", "linuxConfiguration": {
            "ssh": {"publicKeys": [{"keyData": "ssh-ed25519 AAAA"}]}}}}}
        template, access, code = "a deployment makes whatever its template says", "access is never", "at start-up"
        self.kinds([
            ("azure:one", ["PUT", f"{rg}/Microsoft.Resources/deployments/all", "2024-03-01"],
             b'{"properties": {"mode": "Incremental", "template": {"resources": []}}}', "refused", template),
            ("azure:one", ["PUT", f"{self.SUB}/providers/microsoft.resources/deployments/all", "2024-03-01"], b"{}",
             "refused", template),
            ("azure:one", ["POST", f"{rg}/Microsoft.Resources/deployments/all/validate", "2024-03-01"], b"{}",
             "refused", template),
            ("azure:one", ["PUT", f"{rg}/Microsoft.Resources/deploymentScripts/run", "2023-08-01"],
             b'{"kind": "AzureCLI", "properties": {"scriptContent": "az vm list"}}', "refused", "runs code"),
            ("azure:one", ["PUT", f"{rg}/Microsoft.Resources/deploymentStacks/all", "2024-03-01"], b"{}", "refused",
             template),
            ("azure:one", ["PUT", f"{self.SUB}/providers/Microsoft.Authorization/roleAssignments/{SUB}",
                           "2022-04-01"], b'{"properties": {"principalId": "p"}}', "refused", access),
            ("azure:one", ["PUT", f"{vm}/providers/Microsoft.Authorization/roleAssignments/{SUB}", "2022-04-01"],
             b"{}", "refused", access),
            ("azure:one", ["PUT", f"{self.SUB}/providers/Microsoft.Authorization/roleDefinitions/{SUB}",
                           "2022-04-01"], b"{}", "refused", access),
            ("azure:one", ["PUT", vm, "2024-03-01"], json.dumps(login).encode(), "refused", code),
            ("azure:one", ["PATCH", vm, "2024-03-01"], b'{"properties": {"userData": "IyEvYmluL3No"}}', "refused",
             code),
            ("azure:one", ["PATCH", vm, "2024-03-01"], b'{"Properties": {"OSProfile": {"customData": "x"}}}',
             "refused", code),
            ("azure:one", ["PUT", sets, "2024-03-01"], b'{"properties": {"virtualMachineProfile": {"extensionProfile": '
             b'{"extensions": [{"name": "x"}]}}}}', "refused", code),
            ("azure:one", ["PATCH", f"{sets}/virtualMachines/0", "2024-03-01"],
             b'{"properties": {"osProfile": {"adminPassword": "x"}}}', "refused", code),
            ("azure:one", ["PUT", f"{rg}/Microsoft.Compute/disks/data", "2024-03-01"],
             b'[{"properties": [{"customData": 1}]}]', "refused", code),
            ("azure:one", ["PATCH", vm, "2024-03-01"], b'{"properties": {"hardwareProfile": {"vmSize": "B2s"}}}',
             "own", None),
            ("azure:one", ["PUT", f"{rg}/Microsoft.Web/sites/shop", "2023-01-01"],
             b'{"location": "westeurope", "tags": {"userData": "x"}}', "own", None),
            ("azure:one", ["PUT", f"{self.SUB}/resourceGroups/web", "2021-04-01"], b'{"location": "westeurope"}',
             "own", None)])

    def test_the_policy_file_and_tags_stay_never_the_door_s(self):
        for path in ("/tailnet/-/acl", "/device/n1234567/tags"):
            d = self.decide("change", "POST", path, content=b"{}", target="tailscale:net")
            self.assertEqual(d.kind, "refused", path)
            self.assertIn("policy file", d.why)

    def test_each_delete_form_names_its_target_and_other_writes_name_none(self):
        """The coordinator's change to D25: a delete of what no agent made is a code check. deletes() names what each
        provider's delete forms remove, as made_keys() names what a write made."""
        account, zone, rg = "b" * 32, ZONE, f"{self.SUB}/resourceGroups/Web/providers/Microsoft.Web/sites/Shop"
        conf = ACCESS["credentials"]["cloudflare:one"]
        cases = [
            ("cloudflare:one", ["DELETE", f"/zones/{zone}/dns_records/r1"], None, [f"/zones/{zone}/dns_records/r1"]),
            ("cloudflare:one", ["DELETE", "/accounts/{account_id}/r2/buckets/logs"], None,
             [f"/accounts/{account}/r2/buckets/logs"]),
            ("cloudflare:one", ["POST", f"/zones/{zone}/dns_records/batch"],
             b'{"deletes": [{"id": "r1"}, "r2"], "posts": [{"type": "A"}]}',
             [f"/zones/{zone}/dns_records/r1", f"/zones/{zone}/dns_records/?"]),
            ("cloudflare:one", ["POST", f"/accounts/{account}/storage/kv/namespaces/ns1/bulk/delete"], b"[]",
             [f"/accounts/{account}/storage/kv/namespaces/ns1"]),
            ("hetzner:one", ["DELETE", "/servers/42"], None, ["/servers/42"]),
            ("hetzner:one", ["POST", "/servers/42/actions/disable_backup"], None, ["/servers/42"]),
            ("azure:one", ["DELETE", rg, "2023-01-01"], None, [rg.lower()]),
            ("azure:one", ["POST", rg.replace("Microsoft.Web/sites/Shop", "Microsoft.Compute/virtualMachines/vm/"
                                              "reimage"), "2023-01-01"], b"{}",
             [rg.replace("Microsoft.Web/sites/Shop", "Microsoft.Compute/virtualMachines/vm").lower()]),
            ("tailscale:net", ["DELETE", "/device/n1234567"], None, ["/device/n1234567"])]
        for target, args, content, names in cases:
            with self.subTest(target=target, args=args):
                d = self.decide("change", *args, content=content, target=target)
                self.assertEqual(d.kind, "own", d.why)
                self.assertEqual(door_providers.deletes(d.plan, conf if target == "cloudflare:one" else {}), names)
        for name, body, names in (("b2_delete_bucket", {"bucketId": "bk1"}, ["bucket:bk1"]),
                                  ("b2_delete_file_version", {"fileId": "f1", "fileName": "a"}, ["file:f1"]),
                                  ("b2_cancel_large_file", {"fileId": "f2"}, ["file:f2"]),
                                  ("b2_hide_file", {"bucketId": "bk1", "fileName": "a/b"}, ["name:bk1/a/b"]),
                                  ("b2_delete_key", {"applicationKeyId": "k1"}, ["key:k1"]),
                                  ("b2_delete_other", {}, ["b2_delete_other:?"]),
                                  ("b2_update_bucket", {"bucketId": "bk1"}, [])):
            with self.subTest(call=name):
                d = self.decide("change", name, content=json.dumps(body).encode(), target="backblaze:one")
                self.assertEqual(door_providers.deletes(d.plan, {}), names)
        self.assertEqual(door_providers.deletes(self.decide("key-revoke", "k9", target="backblaze:one").plan, {}),
                         ["key:k9"])
        self.assertEqual(door_providers.deletes(self.decide("delete", "n123", target="tailscale:net").plan, {}),
                         ["/device/n123"])
        self.assertEqual(door_providers.deletes(self.decide("oauth-client", "revoke", "kC1234",
                                                            target="tailscale:net").plan, {}), ["key:kC1234"])
        for target, args, content in (("hetzner:one", ["POST", "/firewalls"], b'{"name": "web"}'),
                                      ("cloudflare:one", ["PATCH", f"/zones/{zone}/dns_records/r1"], b"{}"),
                                      ("azure:one", ["POST", rg + "/restart", "2023-01-01"], b"{}")):
            self.assertEqual(door_providers.deletes(self.decide("change", *args, content=content, target=target).plan,
                                                    conf), [], args)
        self.assertEqual(door_providers.named("bucket:bk1"), "the bucket bk1")
        self.assertEqual(door_providers.named("/servers/42"), "/servers/42")

    def test_every_aws_delete_is_the_owner_s_by_its_name(self):
        """The coordinator's word of 6 November 2026: every AWS delete goes to the owner, decided by the action's name,
        with no record of what an agent made in AWS."""
        names = [("ec2", "DeleteSnapshot", {"SnapshotId": "snap-0123456789abcdef0"}),
                 ("ecr", "BatchDeleteImage", {"repositoryName": "shop", "imageIds": [{"imageTag": "old"}]}),
                 ("ec2", "TerminateInstances", {"InstanceId.1": "i-0123456789abcdef0"}),
                 ("rds", "RemoveTagsFromResource", {"ResourceName": "arn:aws:rds:x", "TagKeys.member.1": "a"}),
                 ("ec2", "DeregisterImage", {"ImageId": "ami-0123456789abcdef0"}),
                 ("ec2", "RevokeSecurityGroupEgress", {"GroupId": "sg-0123456789abcdef0"}),
                 ("ec2", "PurgeExample", {}),        # no listed service has a Purge action today; the name rule holds
                 ("ec2", "ReleaseAddress", {"AllocationId": "eipalloc-0123456789abcdef0"}),
                 ("ec2", "CancelSpotFleetRequests", {"SpotFleetRequestId.1": "sfr-1", "TerminateInstances": "true"}),
                 ("logs", "PutRetentionPolicy", {"logGroupName": "app", "retentionInDays": 1}),
                 ("ecr", "PutLifecyclePolicy", {"repositoryName": "shop", "lifecyclePolicyText": "{}"}),
                 ("cloudformation", "ExecuteChangeSet", {"ChangeSetName": "c", "StackName": "s"}),
                 ("logs", "DeleteLogGroup", {"logGroupName": "app"})]
        for service, action, params in names:
            with self.subTest(call=f"{service}:{action}"):
                d = self.decide("call", service, action, content=json.dumps(params).encode(), target="aws:one")
                self.assertEqual(d.kind, "own", d.why)
                self.assertEqual(door_providers.deletes(d.plan, {}), [f"aws:{service}:{action}"])
        d = self.decide("call", "eks", "DELETE", "/clusters/web/node-groups/old", target="aws:one")
        self.assertEqual(door_providers.deletes(d.plan, {}), ["aws:eks:DELETE /clusters/web/node-groups/old"])
        for service, action in (("ec2", "CreateVolume"), ("ec2", "CreateSnapshot"), ("logs", "PutLogEvents"),
                                ("cloudformation", "CreateChangeSet")):
            d = self.decide("call", service, action, content=b"{}", target="aws:one")
            self.assertEqual(door_providers.deletes(d.plan, {}), [], action)
        for way in ("remove", "add"):          # the listed form stays an own call: removing a rule closes access
            d = self.decide("ingress", way, "sg-0123456789abcdef0", "tcp", "22", "10.0.0.0/8", target="aws:one")
            self.assertEqual((d.kind, door_providers.deletes(d.plan, {})), ("own", []), way)
        d = self.decide("call", "ec2", "RevokeSecurityGroupIngress", content=b'{"GroupId": "sg-0123456789abcdef0"}',
                        target="aws:one")
        self.assertEqual(door_providers.deletes(d.plan, {}), ["aws:ec2:RevokeSecurityGroupIngress"])
        self.assertEqual(door_providers.delete_refusal("aws:ec2:TerminateInstances"),
                         "this call is an AWS delete (ec2:TerminateInstances), and every AWS delete is the owner's.")

    def test_an_app_key_that_the_vault_holds_as_one_line_signs_as_its_pem(self):
        """The app gives the central vault an App key as "pem:" and base64, because the vault fingerprints no value
        with white space; the door signs with the PEM itself."""
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx\n-----END RSA PRIVATE KEY-----\n"
        seen = []
        door_providers.app_jwt("42", "pem:" + base64.b64encode(pem.encode()).decode(),
                               sign=lambda text, key: (seen.append(key), b"sig")[1])
        door_providers.app_jwt("42", pem, sign=lambda text, key: (seen.append(key), b"sig")[1])
        self.assertEqual(seen, [pem, pem])
        with self.assertRaisesRegex(door_providers.Stop, "not one PEM"):
            door_providers.app_jwt("42", "pem:not base64!", sign=lambda text, key: b"sig")

    def test_a_write_names_what_it_made_and_a_change_of_what_was_there_names_nothing(self):
        made = door_providers.made_keys
        zone = ZONE
        self.assertEqual(made("cloudflare", "POST", f"/zones/{zone}/dns_records", 200, {"result": {"id": "r1"}}),
                         [f"/zones/{zone}/dns_records/r1"])
        self.assertEqual(made("cloudflare", "POST", "/accounts/acc/r2/buckets", 200,
                              {"result": {"name": "logs", "creation_date": "x"}}), ["/accounts/acc/r2/buckets/logs"])
        self.assertEqual(made("cloudflare", "POST", f"/zones/{zone}/dns_records/batch", 200,
                              {"result": {"posts": [{"id": "r2"}], "deletes": [{"id": "r3"}]}}),
                         [f"/zones/{zone}/dns_records/r2"])
        self.assertEqual(made("cloudflare", "PATCH", f"/zones/{zone}/dns_records/r9", 200, {"result": {"id": "r9"}}),
                         [])
        self.assertEqual(made("hetzner", "POST", "/servers", 201, {"server": {"id": 42}, "root_password": None}),
                         ["/servers/42"])
        self.assertEqual(made("hetzner", "POST", "/servers/42/actions/create_image", 201,
                              {"image": {"id": 7}, "action": {"id": 1}}), ["/images/7"])
        self.assertEqual(made("hetzner", "PUT", "/servers/42", 200, {"server": {"id": 42}}), [])
        self.assertEqual(made("hetzner", "POST", "/servers/42/actions/poweroff", 201, {"action": {"id": 2}}), [])
        self.assertEqual(made("azure", "PUT", f"{self.SUB}/resourceGroups/Web", 201, {}),
                         [f"{self.SUB}/resourcegroups/web"])
        self.assertEqual(made("azure", "PUT", f"{self.SUB}/resourceGroups/Web", 200, {}), [])
        self.assertEqual(made("backblaze", "POST", "b2_create_bucket", 200, {"bucketId": "bk1"}), ["bucket:bk1"])
        self.assertEqual(made("backblaze", "POST", "b2_copy_file", 200,
                              {"fileId": "f1", "bucketId": "bk1", "fileName": "a"}), ["file:f1", "name:bk1/a"])
        self.assertEqual(made("backblaze", "POST", "b2_hide_file", 200,
                              {"fileId": "h1", "bucketId": "bk1", "fileName": "a"}), [])
        self.assertEqual(made("cloudflare", "POST", f"/zones/{zone}/dns_records", 400, {"result": {"id": "r1"}}), [])
        d = self.decide("change", "POST", "/firewalls", content=b'{"name": "web"}', target="hetzner:one")
        stub = Stub([(("POST", "https://api.hetzner.cloud/v1/firewalls"), (201, {"firewall": {"id": 5}}))])
        kept = []
        door_providers.execute(d.plan, dict(stub.ctx(d.target), made=kept.append))
        self.assertEqual(kept, ["/firewalls/5"])

    def test_the_tunnel_rule_holds_also_behind_an_escape_of_json(self):
        path = f"/accounts/{'b' * 32}/cfd_tunnel/{TUNNEL}/configurations"
        for body in (b'{"config": {"ingress": [{"service": "ssh://localhost:22"}]}}',
                     b'{"config": {"ingress": [{"service": "\\u0073sh://localhost:22"}]}}'):
            with self.subTest(body=body):
                self.assertEqual(self.decide("change", "PUT", path, content=body, target="cloudflare:one").kind, "refused")


if __name__ == "__main__":
    unittest.main()
