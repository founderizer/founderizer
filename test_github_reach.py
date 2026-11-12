"""What the hub's GitHub App reaches (owner feature integrations): a repository grant that the App's installations do
not include is kept and marked, with the GitHub page where the owner adds it, in GET /ui/team, GET /ui/resources and
the receipt of POST /ui/team/repos. A fake GitHub API, a throwaway RSA key and temporary folders only; no real GitHub,
hub, ~/.fleet or AI call."""
import http.server
import json
from pathlib import Path
import subprocess
import threading
import time
import unittest
from unittest.mock import patch
import urllib.parse
import uuid

import hub
from test_integrations import APP_ID, HubSide, unpad

SLUG = "fleet-test-app"
# Acme is an organisation with two selected repositories, owner a user with one, wide a user whose installation has
# all its repositories, and held an organisation whose installation is suspended. GitHub's own html_url is never used.
INSTALLS = [{"id": 11, "account": {"login": "Acme", "type": "Organization"}, "repository_selection": "selected",
             "html_url": "https://example.com/not-github"},
            {"id": 22, "account": {"login": "owner", "type": "User"}, "repository_selection": "selected"},
            {"id": 33, "account": {"login": "wide", "type": "User"}, "repository_selection": "all"},
            {"id": 44, "account": {"login": "held", "type": "Organization"}, "repository_selection": "selected",
             "suspended_at": "2026-11-01T00:00:00Z"}]
ACME = "https://github.com/organizations/Acme/settings/installations/11"
OWNER = "https://github.com/settings/installations/22"
HELD = "https://github.com/organizations/held/settings/installations/44"
INSTALL = f"https://github.com/apps/{SLUG}/installations/new"


def reach_github(folder, public_key, repos, slow=0.0, broken=()):
    """A fake GitHub API for what an App reaches: GET /app, GET /app/installations (INSTALLS), a token for an
    installation, and GET /installation/repositories with that token, in pages. It records (method, path, who, body):
    who is "jwt" for a JWT signed with the App's key, the installation's id for its token, else "unknown".
    repos: {installation id: [owner/name]}, which a test changes as the owner would on GitHub. slow: seconds that
    each answer waits. broken: the paths that answer 500. A JWT is checked once: the hub signs one for each reading."""
    calls, tokens, checked = [], {}, {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def answer(self, code, body):
            time.sleep(slow)
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def who(self):
            auth = (self.headers.get("Authorization") or "")[len("Bearer "):]
            if auth in tokens:
                return tokens[auth]
            if auth in checked:
                return checked[auth]
            parts = auth.split(".")
            if len(parts) != 3:
                return "unknown"
            signed = Path(folder) / f"signature-{uuid.uuid4()}"
            signed.write_bytes(unpad(parts[2]))
            verified = subprocess.run(["openssl", "dgst", "-sha256", "-verify", public_key, "-signature", str(signed)],
                                      input=f"{parts[0]}.{parts[1]}".encode(), capture_output=True).returncode == 0
            checked[auth] = "jwt" if verified and json.loads(unpad(parts[1]))["iss"] == int(APP_ID) else "unknown"
            return checked[auth]

        def do_GET(self):
            who, (path, _, query) = self.who(), self.path.partition("?")
            calls.append(("GET", self.path, who, None))
            if path in broken:
                return self.answer(500, {"message": "Server Error"})
            if path == "/app" and who == "jwt":
                return self.answer(200, {"slug": SLUG, "html_url": "https://example.com/not-github"})
            if path == "/app/installations" and who == "jwt":
                return self.answer(200, INSTALLS)
            if path == "/installation/repositories" and isinstance(who, int):
                asked = urllib.parse.parse_qs(query)
                page, size = int(asked["page"][0]), int(asked["per_page"][0])
                names = repos.get(who, [])
                return self.answer(200, {"total_count": len(names), "repositories": [
                    {"full_name": n, "private": True} for n in names[(page - 1) * size:page * size]]})
            return self.answer(404, {"message": "Not Found"})

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            who = self.who()
            calls.append(("POST", self.path, who, body))
            parts = self.path.strip("/").split("/")
            if who != "jwt" or len(parts) != 4 or parts[3] != "access_tokens":
                return self.answer(404, {"message": "Not Found"})
            token = f"ghs_{parts[2]}" + "m" * 36
            tokens[token] = int(parts[2])
            return self.answer(201, {"token": token, "expires_at": "2026-11-02T13:00:00Z",
                                     "permissions": body["permissions"]})

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, calls


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(Reach(name) for name in Reach.__dict__ if name.startswith("test_"))


class Reach(HubSide):
    def setUp(self):
        super().setUp()
        self.repos = {11: ["Acme/Web", "Acme/api"], 22: ["owner/site"], 44: ["held/x"]}
        self.github_at()

    def github_at(self, **fake):
        """The fake GitHub of this test, with what each installation reaches now."""
        server, self.reach_calls = reach_github(self.root, str(self.keys / "public.pem"), self.repos, **fake)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        hub.CFG["github_api"] = f"http://127.0.0.1:{server.server_port}"

    def grant(self, repo, **access):
        code, data = self.save("/ui/team/repos", repo=repo, access=access)
        self.assertEqual(code, 200, data)
        return data

    def unreached(self):
        team = self.request("/ui/team?db=test-generation")[1]["github"]["unreached"]
        resources = self.request("/ui/resources?db=test-generation")[1]["github"]["unreached"]
        self.assertEqual(team, resources)
        return team

    def test_a_grant_outside_the_apps_installations_is_kept_and_marked_with_the_page_that_adds_it(self):
        self.assertNotIn("unreached", self.grant("acme/web", dev="write"))     # Acme selected it
        self.assertEqual(self.grant("acme/hidden", dev="read")["unreached"], ACME)
        self.assertEqual(self.grant("owner/app", ops="read")["unreached"], OWNER)
        self.assertNotIn("unreached", self.grant("owner/site", ops="write"))
        self.assertNotIn("unreached", self.grant("wide/anything", dev="read"))  # an installation with them all
        self.assertEqual(self.grant("held/x", dev="read")["unreached"], HELD)   # suspended: it reaches nothing
        self.assertEqual(self.grant("stranger/tool", ops="write")["unreached"], INSTALL)    # no installation there
        # Kept, not refused: every grant is a commit of team.json, the unreached ones too.
        team = self.origin_team()
        self.assertEqual(team["agents"]["dev"]["repos"], {"acme/hidden": "read", "acme/web": "write",
                                                          "held/x": "read", "wide/anything": "read"})
        self.assertEqual(team["agents"]["ops"]["repos"], {"owner/app": "read", "owner/site": "write",
                                                          "stranger/tool": "write"})
        self.assertEqual(self.unreached(), {"acme/hidden": ACME, "held/x": HELD, "owner/app": OWNER,
                                            "stranger/tool": INSTALL})
        # A grant taken back is no mark any more, and taking one back waits for nothing.
        self.assertNotIn("unreached", self.grant("stranger/tool"))
        self.assertNotIn("stranger/tool", self.unreached())

    def test_the_hub_reads_the_installations_with_the_apps_own_tokens_for_metadata_only(self):
        self.grant("acme/hidden", dev="read")
        self.assertEqual([(c[0], c[1].split("?")[0], c[2]) for c in self.reach_calls], [
            ("GET", "/app", "jwt"), ("GET", "/app/installations", "jwt"),
            ("POST", "/app/installations/11/access_tokens", "jwt"), ("GET", "/installation/repositories", 11),
            ("POST", "/app/installations/22/access_tokens", "jwt"), ("GET", "/installation/repositories", 22)])
        # A token of the installation as a whole, for metadata only: no repository list, no contents.
        self.assertEqual([c[3] for c in self.reach_calls if c[0] == "POST"],
                         [{"permissions": {"metadata": "read"}}] * 2)
        answers = json.dumps([self.request("/ui/team?db=test-generation")[1],
                              self.request("/ui/resources?db=test-generation")[1]])
        self.assertNotIn("ghs_", answers)
        self.assertFalse([r for r in hub.q("SELECT what FROM log") if "ghs_" in r["what"]])     # never logged

    def test_a_reading_counts_a_minute_and_the_next_one_drops_the_mark_of_a_repository_the_owner_added(self):
        self.assertEqual(self.grant("acme/hidden", dev="read")["unreached"], ACME)
        asked = len(self.reach_calls)
        for _ in range(3):
            self.assertEqual(self.unreached(), {"acme/hidden": ACME})
        self.assertEqual(len(self.reach_calls), asked)          # inside the minute: no call to GitHub
        self.repos[11].append("acme/hidden")                    # the owner adds it on the installation's page
        with patch.object(hub, "now", lambda: time.time() + hub.GITHUB_REACH_FRESH + 1):
            self.request("/ui/team?db=test-generation")         # it starts the next reading, and waits for none
            hub.github_reach(5)
            self.assertEqual(self.unreached(), {})
        self.assertGreater(len(self.reach_calls), asked)

    def test_no_answer_waits_for_github_and_a_grant_waits_only_a_few_seconds(self):
        self.assertEqual(self.grant("acme/hidden", dev="read")["unreached"], ACME)
        self.github_at(slow=0.5)                                # six answers: a reading of three seconds
        with patch.object(hub, "now", lambda: time.time() + hub.GITHUB_REACH_FRESH + 1):
            team = self.request("/ui/team?db=test-generation")[1]
            self.assertTrue(hub.GITHUB_REACH["reading"])        # it answered while the next reading runs
            self.assertEqual(team["github"]["unreached"], {"acme/hidden": ACME})       # from the last reading
            hub.github_reach(10)
        with patch.object(hub, "GITHUB_REACH_WAIT", 0.5), \
                patch.object(hub, "now", lambda: time.time() + 2 * (hub.GITHUB_REACH_FRESH + 1)):
            t0 = time.monotonic()
            receipt = self.grant("owner/app", ops="read")       # its reading is old, and the next one is slow
            self.assertLess(time.monotonic() - t0, 3)
            self.assertEqual((receipt["changed"], receipt["unreached"]), (True, OWNER))

    def test_a_read_that_failed_marks_nothing_and_refuses_nothing(self):
        self.github_at(broken=("/app/installations",))
        receipt = self.grant("acme/hidden", dev="read")
        self.assertEqual(receipt["changed"], True)
        self.assertNotIn("unreached", receipt)
        self.assertEqual(self.unreached(), {})
        self.assertEqual(self.origin_team()["agents"]["dev"]["repos"], {"acme/hidden": "read"})

    def test_without_an_app_nothing_is_marked_and_github_is_not_asked(self):
        hub.CFG["github_app"] = str(self.root / "no-github-app")
        self.assertNotIn("unreached", self.grant("acme/hidden", dev="read"))
        self.assertEqual(self.request("/ui/team?db=test-generation")[1]["github"],
                         {"app": False, "app_id": None, "problem": None, "unreached": {}, "door": False,
                          "renew": False})
        self.assertEqual(self.request("/ui/resources?db=test-generation")[1]["github"], {"unreached": {}})
        self.assertEqual(self.reach_calls, [])

    def test_the_hub_reads_every_page_of_an_installation_and_marks_none_past_what_it_reads(self):
        self.repos[22] = [f"owner/r{i:03}" for i in range(150)]
        self.assertNotIn("unreached", self.grant("owner/r149", dev="read"))         # on the second page
        self.assertEqual(self.grant("owner/site", dev="read")["unreached"], OWNER)
        self.assertEqual([c[1] for c in self.reach_calls if c[2] == 22],
                         ["/installation/repositories?per_page=100&page=1",
                          "/installation/repositories?per_page=100&page=2"])
        # More full pages than the hub reads: it cannot tell, so it marks no repository of that account.
        with patch.object(hub, "GITHUB_REACH_PAGES", 1), \
                patch.object(hub, "now", lambda: time.time() + hub.GITHUB_REACH_FRESH + 1):
            hub.github_reach(5)
            self.assertEqual(self.unreached(), {})


if __name__ == "__main__":
    unittest.main()
