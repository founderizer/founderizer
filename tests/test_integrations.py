"""GitHub repositories and tools for agents (owner feature integrations): the owner's routes, the hub's GitHub App
tokens from a fake GitHub API, and the helper's session environment, clones and git credentials. Temporary folders, a
throwaway RSA key and local git repositories only; no real GitHub, hub, ~/.fleet or AI call."""
import base64
import http.server
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import uuid

import fleet
from leftovers import scratch_home
import hub
from test_ui_api import OwnerAPI

CODEX = "codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}"
TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "w1": "127.0.0.3", "w2": "127.0.0.4"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   "dev": {"role": "worker", "runtime": "claude", "machine": "w1", "can": ["shell"]},
                   "ops": {"role": "worker", "runtime": "codex", "machine": "w2", "can": ["shell"], "start": CODEX}}}
APP_ID = "4242"
SESSION = "11111111-2222-4333-8444-555555555555"
TAIL = "." + "y-z" * 110            # GitHub's current installation tokens: about 400 characters, with - and .
WRITE, READ = "ghs_" + "w" * 36 + TAIL, "ghs_" + "r" * 36 + TAIL
NEW_WRITE, NEW_READ = "ghs_" + "W" * 36 + TAIL, "ghs_" + "R" * 36 + TAIL      # the tokens of a renewal
CLAUDE = {"role": "worker", "runtime": "claude", "machine": "w1", "can": ["shell"], "allow": ["mcp__fleet__*"],
          "start": "claude --permission-mode dontAsk {chrome} {settings} {prompt}"}
CODEX_CONF = {"role": "worker", "runtime": "codex", "machine": "w2", "can": ["shell"], "start": CODEX}
PROGRAM = "/opt/fleet-test/bin/github-mcp-server"


def start_text(words):
    """A task's start text, from its mode-600 file: a Claude task's appended system prompt, after this checkout's rules
    (fleet.system_file), or the first prompt that a Codex task's window reads (fleet.file_prompt)."""
    if "--append-system-prompt-file" in words:
        text, core, rules = Path(words[words.index("--append-system-prompt-file") + 1]).read_text(), fleet.rules_file(), ""
        if core:
            with open(core, encoding="utf-8") as f:
                rules = re.sub(r"\r?\n\Z", "", f.read()) + "\n\n"
        return text[len(rules):] if rules and text.startswith(rules) else text
    read = re.fullmatch(r"\$\(cat (\S+); rm -f \1\)", words[-1])
    return Path(shlex.split(read.group(1))[0]).read_text()


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real ~/.fleet (leftovers.scratch_home)


def at(seconds):
    """A time this many seconds from now, as GitHub writes a token's expires_at."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + seconds))


def git(*args, cwd=None, env=None):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", *args],
                          cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout.strip()


def unpad(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def fake_github(folder, public_key, installs, carries=None, holds=None):
    """A fake GitHub API on 127.0.0.1: the installation of each account in `installs`, and new tokens. It checks each
    JWT with the App's public key and records (method, path, verified, claims, body).

    carries: the permissions the App itself has, when the test is about an App that lacks one. A token request for a
    permission outside it is answered as GitHub answers it, 422, which is the whole of what the hub can see when the
    owner has not added the Workflows and Actions permissions and accepted them on the installation.

    holds: the permissions that GitHub's answer for an installation names, as GitHub gives them with it (`permissions`);
    without it the answer names none, as the answers of these tests did before Actions at read and write."""
    calls = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def answer(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def record(self, body=None):
            head, claims, signature = (self.headers.get("Authorization") or "")[len("Bearer "):].split(".")
            signed = Path(folder) / f"signature-{uuid.uuid4()}"
            signed.write_bytes(unpad(signature))
            verified = subprocess.run(["openssl", "dgst", "-sha256", "-verify", public_key, "-signature", str(signed)],
                                      input=f"{head}.{claims}".encode(), capture_output=True).returncode == 0
            calls.append((self.command, self.path, verified and json.loads(unpad(head))["alg"] == "RS256",
                          json.loads(unpad(claims)), body))

        def do_GET(self):
            self.record()
            parts = self.path.strip("/").split("/")
            if len(parts) == 4 and parts[0] == "repos" and parts[3] == "installation" and parts[1] in installs:
                return self.answer(200, dict({"id": installs[parts[1]], "account": {"login": parts[1]}},
                                             **({"permissions": holds} if holds is not None else {})))
            return self.answer(404, {"message": "Not Found"})

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            self.record(body)
            iid = self.path.split("/")[3]
            if carries is not None and set(body["permissions"]) - set(carries):
                return self.answer(422, {"message": "The permissions requested are not granted to this installation."})
            return self.answer(201, {"token": f"ghs_{iid}{body['permissions']['contents']}" + "x" * 30 + TAIL,
                                     "expires_at": "2026-10-14T13:00:00Z", "permissions": body["permissions"]})

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    # a short poll: the cleanup's shutdown() waits for the loop's next look, which was up to 0.5 s in each test
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
    return server, calls


def settle_github_reach(test):
    """A reading of what the App reaches (hub.github_reach) is one test's own: none runs on into the next test's fake
    GitHub, and no test starts with one that another test kept."""
    def settle():
        with hub.GITHUB_REACH_DONE:
            hub.GITHUB_REACH_DONE.wait_for(lambda: not hub.GITHUB_REACH["reading"], 10)
            hub.GITHUB_REACH.update(at=None, reach=None)
    settle()
    test.addCleanup(settle)


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite(HubSide(name) for name in HubSide.__dict__ if name.startswith("test_"))
    suite.addTests(loader.loadTestsFromTestCase(HelperSide))
    return suite


class HubSide(OwnerAPI):
    @classmethod
    def setUpClass(cls):
        cls.keys = Path(tempfile.mkdtemp(prefix="fleet-github-key-"))
        raw = cls.keys / "raw.pem"
        subprocess.run(["openssl", "genrsa", "-out", str(raw), "2048"], check=True, capture_output=True)
        subprocess.run(["openssl", "rsa", "-in", str(raw), "-pubout", "-out", str(cls.keys / "public.pem")], check=True,
                       capture_output=True)
        cls.app = cls.keys / "github-app.pem"
        fd = os.open(cls.app, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"app_id={APP_ID}\n" + raw.read_text())
        raw.unlink()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.keys, ignore_errors=True)

    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp(prefix="fleet-integrations-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        seed = self.root / "seed"
        seed.mkdir()
        (seed / "team.json").write_text(json.dumps(TEAM, indent=2) + "\n")
        git("init", "-q", str(seed))
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "seed", cwd=seed)
        git("clone", "-q", "--bare", str(seed), str(self.root / "origin.git"))
        git("clone", "-q", str(self.root / "origin.git"), str(self.root / "kit"))
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = json.loads(json.dumps(TEAM))
        self.github, self.calls = fake_github(self.root, str(self.keys / "public.pem"), {"acme": 11, "other": 22})
        self.addCleanup(self.github.server_close)
        self.addCleanup(self.github.shutdown)
        for key, value in (("team_path", str(self.root / "kit" / "team.json")), ("github_app", str(self.app)),
                           ("github_api", f"http://127.0.0.1:{self.github.server_port}")):
            hub.CFG[key] = value
            self.addCleanup(hub.CFG.pop, key, None)
        allowed = patch.object(hub.Handler, "allowed", lambda handler, who, broker=False: True)
        allowed.start()
        self.addCleanup(allowed.stop)
        settle_github_reach(self)

    # ---- helpers
    def sha(self):
        return self.request("/ui/team?db=test-generation")[1]["sha256"]

    def save(self, route, **fields):
        return self.request(route, dict(request_id=str(uuid.uuid4()), db="test-generation", base_sha256=self.sha(),
                                        **fields))

    def origin_team(self):
        return json.loads(git("--git-dir", str(self.root / "origin.git"), "show", "main:team.json"))

    def agents(self, **fields):
        for name, values in fields.items():
            hub.TEAM["agents"][name].update(values)

    def tokens(self, agent="dev"):
        return self.request(f"/helper/integrations/{agent}", {})

    # ---- team.json
    def test_team_json_takes_lower_case_repositories_with_read_or_write_and_catalog_tools(self):
        def team(**fields):
            t = json.loads(json.dumps(TEAM))
            t["agents"]["dev"].update(fields)
            return t
        hub.validate_team(team(repos={"acme/web": "write", "acme/.github": "read"}, tools=["github"]))
        # 500: GitHub's most for one App token (hub.REPOS_MOST); 64 until 9 November 2026
        hub.validate_team(team(repos={f"acme/r{i}": "read" for i in range(500)}))
        refused = [({"repos": {"Acme/Web": "write"}}, "repos must map"), ({"repos": {"acme/web": "admin"}}, "repos must map"),
                   ({"repos": {"acme": "read"}}, "repos must map"), ({"repos": {"acme/..": "read"}}, "repos must map"),
                   ({"repos": {f"acme/r{i}": "read" for i in range(501)}}, "repos must map up to 500 GitHub"),
                   ({"repos": ["acme/web"]}, "repos must map"), ({"tools": ["nope"]}, "tools must be"),
                   ({"tools": ["github", "github"]}, "tools must be"), ({"tools": "github"}, "tools must be"),
                   ({"tools": [["github"]]}, "tools must be")]
        for fields, words in refused:
            with self.subTest(fields=fields), self.assertRaisesRegex(ValueError, words):
                hub.validate_team(team(**fields))
        t = json.loads(json.dumps(TEAM))
        t["agents"]["manager"]["repos"] = {"acme/web": "read"}
        with self.assertRaisesRegex(ValueError, "the manager has no repos or tools"):
            hub.validate_team(t)

    # ---- owner routes
    def test_the_owner_gives_changes_and_removes_the_access_to_a_repository(self):
        code, data = self.save("/ui/team/repos", repo=" Acme/Web ", access={"ops": "read", "dev": "write"})
        self.assertEqual(code, 200, data)
        self.assertEqual((data["repo"], data["access"], data["changed"]), ("acme/web", {"dev": "write", "ops": "read"}, True))
        team = self.origin_team()
        self.assertEqual((team["agents"]["dev"]["repos"], team["agents"]["ops"]["repos"]),
                         ({"acme/web": "write"}, {"acme/web": "read"}))
        self.assertEqual(hub.agents()["dev"]["repos"], {"acme/web": "write"})          # applied at once
        self.assertNotIn("repos", team["agents"]["manager"])
        said = hub.q1("SELECT text FROM events WHERE agent='manager' AND kind='say' ORDER BY id DESC")["text"]
        self.assertIn("acme/web: dev write, ops read", said)
        code, view = self.request("/ui/team?db=test-generation")
        lines = {line["agent"]: line for line in view["lines"]}
        self.assertEqual((lines["dev"]["repos"], lines["ops"]["repos"], lines["manager"]["repos"]),
                         ({"acme/web": "write"}, {"acme/web": "read"}, {}))
        self.assertEqual(lines["dev"]["tools"], [])
        self.assertEqual(view["tools"]["github"], {"title": "GitHub", "command": "github-mcp-server", "args": ["stdio"],
                                                   "runtimes": ["claude", "codex", "grok", "opencode"],
                                                   "custom": False, "auth": "none",
                                                   "needs": ["GH_TOKEN"]})
        self.assertEqual(view["github"], {"app": True, "app_id": APP_ID, "problem": None, "unreached": {},
                                          "door": False, "renew": False})

        code, data = self.save("/ui/team/repos", repo="acme/web", access={"dev": "write", "ops": "read"})
        self.assertEqual((code, data["changed"]), (200, False))
        code, data = self.save("/ui/team/repos", repo="acme/web", access={"dev": "read"})
        self.assertEqual((code, data["changed"]), (200, True))
        team = self.origin_team()
        self.assertEqual(team["agents"]["dev"]["repos"], {"acme/web": "read"})
        self.assertNotIn("repos", team["agents"]["ops"])                # an agent that is not named loses it
        code, data = self.save("/ui/team/repos", repo="acme/web", access={})
        self.assertEqual((code, data["changed"]), (200, True))
        self.assertFalse(any("repos" in a for a in self.origin_team()["agents"].values()))

        for fields, status, words in (({"repo": "acme/web", "access": {"manager": "read"}}, 400, "the manager has no repos"),
                                      ({"repo": "acme/web", "access": {"ghost": "read"}}, 400, "no such agent: ghost"),
                                      ({"repo": "acme", "access": {}}, 400, "owner/name"),
                                      ({"repo": "acme/web", "access": {"dev": "admin"}}, 400,
                                       '"read", "write" or "deploy"'),
                                      ({"repo": "acme/web", "access": {}, "extra": 1}, 400, "unknown field extra")):
            with self.subTest(fields=fields):
                code, data = self.save("/ui/team/repos", **fields)
                self.assertEqual(code, status, data)
                self.assertIn(words, data["error"])
        code, data = self.request("/ui/team/repos", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                         base_sha256="0" * 64, repo="acme/web", access={}))
        self.assertEqual(code, 409, data)

    def test_one_agent_gets_many_repositories_and_every_other_agent_keeps_its_own(self):
        """Owner feature repo_picker: agent and level change only that agent's access to each repository, in one commit
        and one message; level null takes them away from it. The list form with access would take a repository away
        from every agent it does not name."""
        self.assertEqual(self.save("/ui/team/repos", repo="acme/web", access={"ops": "write"})[0], 200)
        count = hub.q1("SELECT count(*) AS n FROM events WHERE agent='manager' AND kind='say'")["n"]
        code, data = self.save("/ui/team/repos", repo=["Acme/Web", "acme/lib"], agent="dev", level="read")
        self.assertEqual((code, data["changed"], data["agent"], data["level"]), (200, True, "dev", "read"), data)
        team = self.origin_team()
        self.assertEqual((team["agents"]["dev"]["repos"], team["agents"]["ops"]["repos"]),
                         ({"acme/lib": "read", "acme/web": "read"}, {"acme/web": "write"}))
        texts = [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND kind='say' ORDER BY id")]
        self.assertEqual(texts[count:], ["[hub] The owner gave dev read access to 2 GitHub repositories (acme/web, "
                                         "acme/lib). An agent gets the change in its next task session."])
        self.assertEqual(self.save("/ui/team/repos", repo=["acme/web", "acme/lib"], agent="dev", level="read")[1]
                         ["changed"], False)
        code, data = self.save("/ui/team/repos", repo=["acme/web", "acme/lib"], agent="dev", level=None)
        self.assertEqual((code, data["changed"]), (200, True), data)
        team = self.origin_team()
        self.assertEqual(("repos" in team["agents"]["dev"], team["agents"]["ops"]["repos"]), (False, {"acme/web": "write"}))
        for fields, words in (({"agent": "dev", "level": "read", "access": {}}, "not both"),
                              ({"agent": "dev"}, "not both"), ({"level": "read"}, "not both"),
                              ({"agent": "dev", "level": "admin"}, "level one of"),
                              ({"agent": "ghost", "level": "read"}, "no such agent: ghost")):
            with self.subTest(fields=fields):
                code, data = self.save("/ui/team/repos", repo=["acme/web"], **fields)
                self.assertEqual(code, 400, data)
                self.assertIn(words, data["error"])

    def test_the_list_to_choose_from_names_every_repository_that_the_apps_reach(self):
        """Owner feature repo_picker: GET /ui/github/repos, from the hub's own App and the door's Apps, kept a minute;
        what could not be read is a problem in words and is read again next time."""
        hub.GITHUB_REPOS.update(at=0.0, list=None)
        self.addCleanup(hub.GITHUB_REPOS.update, at=0.0, list=None)
        found = {"acme": {"name": "Acme", "repos": ["acme/lib", "acme/web"]}}
        with patch.object(hub, "github_repos_read", return_value=(found, [])) as read:
            code, data = self.request("/ui/github/repos?db=test-generation")
            self.assertEqual((code, data["accounts"], data["problem"]),
                             (200, [{"account": "Acme", "repos": ["acme/lib", "acme/web"]}], None), data)
            self.assertEqual(self.request("/ui/github/repos?db=test-generation")[1]["accounts"], data["accounts"])
            self.assertEqual(read.call_count, 1)                                # a minute's reading, read once
        hub.GITHUB_REPOS.update(at=0.0, list=None)
        with patch.object(hub, "github_repos_read", return_value=({}, ["the door does not answer"])) as read:
            for _ in range(2):
                code, data = self.request("/ui/github/repos?db=test-generation")
                self.assertEqual((code, data["accounts"], data["problem"]), (200, [], "the door does not answer"))
            self.assertEqual(read.call_count, 2)
        self.assertEqual(self.request("/ui/github/repos?db=old")[0], 409)
        self.assertIn("repo_picker", hub.ui_features())

    def test_the_door_s_list_keeps_only_each_account_s_own_repositories(self):
        """The list to choose from has no product repository either (door_targets.VENDOR_REPOS), which no grant gives
        (20 November 2026), and no account that has only those: the owner never picks a grant that is refused."""
        import door_targets
        door = {"address": "100.64.0.9", "port": 8766, "token": "t" * 43}
        answer = {"accounts": {"one-org": {"name": "One-Org", "repos": ["one-org/shop", "Other/stray", "bad name",
                                                                         "One-Org/Core"]},
                               "two-org": {"name": "Two-Org", "repos": ["two-org/core"]},
                               "x y": {"name": "x", "repos": ["x/y"]}}}
        with patch.object(hub, "github_app", return_value=None), patch.object(hub, "door_conf", return_value=door), \
                patch.object(hub, "door_call", return_value=(200, answer)) as call, \
                patch.object(door_targets, "VENDOR_REPOS", ("one-org/core", "two-org/core")):
            self.assertEqual(hub.github_repos_read(), ({"one-org": {"name": "One-Org", "repos": ["one-org/shop"]}}, []))
        self.assertEqual(call.call_args.args[1:4], ("GET", "/github/repos", "t" * 43))
        with patch.object(hub, "github_app", return_value=None), patch.object(hub, "door_conf", return_value=door), \
                patch.object(hub, "door_call", return_value=(404, {"error": "no such route"})):
            self.assertEqual(hub.github_repos_read(), ({}, ["the door's code does not list repositories yet"]))

    def test_one_change_gives_many_repositories_with_one_message_to_the_manager(self):
        """9 November 2026: an agent may hold up to hub.REPOS_MOST repositories, so repo may be a list: one commit and
        one message, not one of each for every repository."""
        code, data = self.save("/ui/team/repos", repo="acme/old", access={"ops": "write"})
        self.assertEqual(code, 200, data)
        said = hub.q1("SELECT count(*) AS n FROM events WHERE agent='manager' AND kind='say'")["n"]
        names = [f"Acme/R{i:03}" for i in range(150)] + ["acme/old"]
        code, data = self.save("/ui/team/repos", repo=names, access={"dev": "read"})
        self.assertEqual((code, data["changed"]), (200, True), data)
        self.assertEqual(data["repo"], [n.lower() for n in names])
        team = self.origin_team()
        self.assertEqual(team["agents"]["dev"]["repos"], {n.lower(): "read" for n in names})
        self.assertNotIn("repos", team["agents"]["ops"])         # not named for acme/old: it loses that one
        texts = [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND kind='say' ORDER BY id")]
        self.assertEqual(len(texts), said + 1)
        self.assertIn("[hub] The owner changed who may use 151 GitHub repositories (acme/r000, acme/r001", texts[-1])
        self.assertIn("): dev read. An agent gets them in its next task session.", texts[-1])
        code, data = self.save("/ui/team/repos", repo=names, access={"dev": "read"})
        self.assertEqual((code, data["changed"]), (200, False))
        for repo, words in ((["acme/a", "Acme/A"], "different ones"), ([], "a list of up to 500"),
                            ([f"acme/r{i}" for i in range(501)], "a list of up to 500"), (["acme"], "owner/name")):
            with self.subTest(repo=repo[:3]):
                code, data = self.save("/ui/team/repos", repo=repo, access={"dev": "read"})
                self.assertEqual(code, 400, data)
                self.assertIn(words, data["error"])

    def test_the_owner_chooses_the_agents_of_a_catalog_tool(self):
        code, data = self.save("/ui/team/tools", tool="github", agents=["ops", "dev"])
        self.assertEqual((code, data["agents"], data["changed"]), (200, ["dev", "ops"], True), data)
        team = self.origin_team()
        self.assertEqual((team["agents"]["dev"]["tools"], team["agents"]["ops"]["tools"]), (["github"], ["github"]))
        code, data = self.save("/ui/team/tools", tool="github", agents=["ops"])
        self.assertEqual((code, data["changed"]), (200, True))
        team = self.origin_team()
        self.assertNotIn("tools", team["agents"]["dev"])
        self.assertEqual(self.request("/ui/team?db=test-generation")[1]["lines"][2]["tools"], ["github"])
        for fields, words in (({"tool": "nope", "agents": []}, "tool must be one of the catalog"),
                              ({"tool": "github", "agents": ["manager"]}, "the manager has no repos or tools"),
                              ({"tool": "github", "agents": ["dev", "dev"]}, "different agent names")):
            with self.subTest(fields=fields):
                code, data = self.save("/ui/team/tools", **fields)
                self.assertEqual(code, 400, data)
                self.assertIn(words, data["error"])

    # ---- tokens for a task session
    def test_a_task_session_gets_one_scoped_token_for_each_account_and_access(self):
        self.agents(dev={"repos": {"acme/web": "write", "acme/api": "write", "acme/lib": "read", "other/tool": "write"},
                         "tools": ["github"]})
        before = time.time()
        code, data = self.tokens()
        self.assertEqual(code, 200, data)
        self.assertEqual((data["repos"], data["tools"], data["errors"]),
                         (hub.agents()["dev"]["repos"], ["github"], []))
        self.assertEqual([(t["access"], t["repos"], t["token"]) for t in data["tokens"]],
                         [("write", ["acme/api", "acme/web"], "ghs_11write" + "x" * 30 + TAIL),
                          ("write", ["other/tool"], "ghs_22write" + "x" * 30 + TAIL),
                          ("read", ["acme/lib"], "ghs_11read" + "x" * 30 + TAIL)])
        self.assertEqual([(c[0], c[1], c[4]) for c in self.calls], [
            ("GET", "/repos/acme/api/installation", None),
            ("POST", "/app/installations/11/access_tokens", {"repositories": ["api", "web"], "permissions": {
                "contents": "write", "pull_requests": "write", "metadata": "read"}}),
            ("GET", "/repos/other/tool/installation", None),
            ("POST", "/app/installations/22/access_tokens", {"repositories": ["tool"], "permissions": {
                "contents": "write", "pull_requests": "write", "metadata": "read"}}),
            ("POST", "/app/installations/11/access_tokens", {"repositories": ["lib"], "permissions": {
                "contents": "read", "pull_requests": "read", "metadata": "read"}})])
        for _, _, verified, claims, _ in self.calls:
            self.assertTrue(verified)                       # signed with the App's key
            self.assertEqual(claims["iss"], int(APP_ID))
            self.assertLessEqual(claims["exp"] - claims["iat"], 600)
            self.assertLessEqual(claims["iat"], before)
        self.assertFalse([r for r in hub.q("SELECT what FROM log") if "ghs_" in r["what"]])     # never logged

    def test_a_deploy_repository_gets_the_workflows_and_actions_permissions_and_the_first_token(self):
        """deploy is write and the repository's own deployment, so its token carries two permissions more. It is also
        the token GH_TOKEN gets: the hub sends the highest access first (fleet.integration_env takes the first
        group), and a deploy token does everything a write token does, so no repository loses what its level
        allows."""
        self.agents(dev={"repos": {"acme/web": "deploy", "acme/api": "write", "acme/lib": "read"}})
        code, data = self.tokens()
        self.assertEqual(code, 200, data)
        self.assertEqual([(t["access"], t["repos"]) for t in data["tokens"]],
                         [("deploy", ["acme/web"]), ("write", ["acme/api"]), ("read", ["acme/lib"])])
        self.assertEqual(data["errors"], [])
        asked = [c[4]["permissions"] for c in self.calls if c[0] == "POST"]
        self.assertEqual(asked[0], {"contents": "write", "pull_requests": "write", "metadata": "read",
                                    "workflows": "write", "actions": "write"})
        self.assertEqual(asked[1], {"contents": "write", "pull_requests": "write", "metadata": "read"})
        self.assertEqual(asked[2], {"contents": "read", "pull_requests": "read", "metadata": "read"})

    def test_a_read_or_write_token_reads_the_actions_runs_only_where_the_installation_holds_actions(self):
        """As the door's tokens do since 10 November 2026 (door.token_permissions): a read or write token also asks
        actions: read where GitHub's answer for the installation names Actions, so that a session reads the runs of
        GitHub Actions with gh run list. An installation that does not name it gets exactly the tokens of before (the
        test above), because GitHub refuses a whole token that asks for a permission the installation lacks. deploy
        does not change."""
        holding = fake_github(self.root, str(self.keys / "public.pem"), {"acme": 11},
                              holds={"actions": "write", "contents": "write", "metadata": "read",
                                     "pull_requests": "write", "workflows": "write"})
        server, calls = holding
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        hub.CFG["github_api"] = f"http://127.0.0.1:{server.server_port}"
        self.agents(dev={"repos": {"acme/web": "deploy", "acme/api": "write", "acme/lib": "read"}})
        code, data = self.tokens()
        self.assertEqual(code, 200, data)
        self.assertEqual(([(t["access"], t["repos"]) for t in data["tokens"]], data["errors"]),
                         ([("deploy", ["acme/web"]), ("write", ["acme/api"]), ("read", ["acme/lib"])], []))
        self.assertEqual([c[4]["permissions"] for c in calls if c[0] == "POST"], [
            {"contents": "write", "pull_requests": "write", "metadata": "read", "workflows": "write", "actions": "write"},
            {"contents": "write", "pull_requests": "write", "metadata": "read", "actions": "read"},
            {"contents": "read", "pull_requests": "read", "metadata": "read", "actions": "read"}])
        self.assertEqual([c[1] for c in calls if c[0] == "GET"], ["/repos/acme/web/installation"])   # one read
        for held, asked in (({"actions": "read"}, {"actions": "read"}), ({"actions": "none"}, {}), ({}, {}), (None, {}),
                            (["actions"], {})):
            with self.subTest(held=held):
                self.assertEqual(hub.github_permissions("write", held), dict(hub.GITHUB_ACCESS["write"], **asked))
                self.assertEqual(hub.github_permissions("deploy", held), hub.GITHUB_ACCESS["deploy"])
        self.assertIsNot(hub.github_permissions("read", None), hub.GITHUB_ACCESS["read"])     # never the table itself

    def test_a_token_reads_the_issues_and_from_write_comments_on_them_only_where_the_installation_holds_issues(self):
        """As the door's tokens do since 12 November 2026 (door.token_permissions): where GitHub's answer for the
        installation names Issues, a read token also asks issues: read, and a write or deploy token issues: write, or
        read where the installation holds Issues only at read, so that a session reads the issues of its repositories
        and, from write, opens them and comments on them (gh issue list, gh issue comment). An installation that does
        not name Issues gets exactly the tokens of before, because GitHub refuses a whole token that asks for a
        permission the installation lacks."""
        server, calls = fake_github(self.root, str(self.keys / "public.pem"), {"acme": 11},
                                    holds={"contents": "write", "issues": "write", "metadata": "read",
                                           "pull_requests": "write"})
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        hub.CFG["github_api"] = f"http://127.0.0.1:{server.server_port}"
        self.agents(dev={"repos": {"acme/web": "deploy", "acme/api": "write", "acme/lib": "read"}})
        code, data = self.tokens()
        self.assertEqual(code, 200, data)
        self.assertEqual(([(t["access"], t["repos"]) for t in data["tokens"]], data["errors"]),
                         ([("deploy", ["acme/web"]), ("write", ["acme/api"]), ("read", ["acme/lib"])], []))
        self.assertEqual([c[4]["permissions"] for c in calls if c[0] == "POST"], [
            dict(hub.GITHUB_ACCESS["deploy"], issues="write"), dict(hub.GITHUB_ACCESS["write"], issues="write"),
            dict(hub.GITHUB_ACCESS["read"], issues="read")])
        for held, read, write in (({"issues": "write"}, "read", "write"), ({"issues": "read"}, "read", "read"),
                                  ({"issues": "none"}, None, None), ({}, None, None), (None, None, None),
                                  (["issues"], None, None), ({"issues": ["write"]}, None, None)):
            with self.subTest(held=held):
                self.assertEqual(hub.github_permissions("read", held),
                                 dict(hub.GITHUB_ACCESS["read"], **({"issues": read} if read else {})))
                for access in ("write", "deploy"):
                    self.assertEqual(hub.github_permissions(access, held),
                                     dict(hub.GITHUB_ACCESS[access], **({"issues": write} if write else {})))
        self.assertEqual(hub.github_permissions("write", {"actions": "write", "issues": "write"}),
                         dict(hub.GITHUB_ACCESS["write"], actions="read", issues="write"))      # the two together
        self.assertNotIn("issues", json.dumps(hub.GITHUB_ACCESS))       # the table itself never changes

    def test_a_deploy_token_the_app_cannot_mint_says_which_permissions_the_owner_must_accept(self):
        """The one thing the hub cannot do for the owner. GitHub answers 422 and says nothing about which permission
        is missing or who adds it, so the error the agent and its manager read says both, and says that write still
        works. Every other refusal keeps the installation hint."""
        short = fake_github(self.root, str(self.keys / "public.pem"), {"acme": 11},
                            carries=("contents", "pull_requests", "metadata"))[0]
        self.addCleanup(short.server_close)
        self.addCleanup(short.shutdown)
        hub.CFG["github_api"] = f"http://127.0.0.1:{short.server_port}"
        self.agents(dev={"repos": {"acme/web": "deploy", "acme/api": "write"}})
        code, data = self.tokens()
        self.assertEqual([(t["access"], t["repos"]) for t in data["tokens"]], [("write", ["acme/api"])])
        self.assertEqual([e["repos"] for e in data["errors"]], [["acme/web"]])
        said = data["errors"][0]["error"]
        self.assertIn("GitHub answered 422", said)
        self.assertIn("Workflows and Actions permissions on the hub's GitHub App", said)
        self.assertIn("accept them on the App's installation page", said)
        self.assertIn("acme/web works at write and not at deploy", said)
        self.assertNotIn("must be installed on", said)       # it is installed: this is the App's own permissions
        # The same 422 on a write group is still about the installation, which is what it was before deploy existed.
        self.agents(dev={"repos": {"nobody/x": "write"}})
        self.assertIn("the GitHub App must be installed on nobody/x", self.tokens()[1]["errors"][0]["error"])

    def test_refusals_reach_the_session_as_errors_and_other_tokens_still_come(self):
        self.agents(dev={"repos": {"acme/web": "write", "nobody/x": "read"}})
        code, data = self.tokens()
        self.assertEqual([t["repos"] for t in data["tokens"]], [["acme/web"]])
        self.assertEqual(data["errors"], [{"repos": ["nobody/x"], "error": "GitHub answered 404: Not Found; the GitHub "
                                                                          "App must be installed on nobody/x"}])
        self.calls.clear()
        self.agents(dev={"repos": {}, "tools": ["github"]})
        self.assertEqual(self.tokens()[1], {"repos": {}, "tools": ["github"], "tokens": [], "errors": [],
                                            "mcp": {}, "mcp_problems": []})
        self.assertEqual(self.calls, [])                    # no repository, no GitHub call
        self.agents(dev={"repos": {"acme/web": "write"}})
        hub.CFG["github_app"] = str(self.root / "missing.pem")
        self.assertEqual(self.tokens()[1]["errors"], [{"repos": ["acme/web"], "error": "the hub has no GitHub App yet: "
                                                       "the owner puts its file in place first"}])
        loose = self.root / "loose.pem"
        loose.write_text(self.app.read_text())
        loose.chmod(0o644)
        hub.CFG["github_app"] = str(loose)
        self.assertIn("mode 600", self.tokens()[1]["errors"][0]["error"])
        self.assertEqual(self.request("/ui/team?db=test-generation")[1]["github"]["app"], False)
        self.assertEqual(self.tokens("manager")[0], 409)
        self.assertEqual(self.tokens("ghost")[0], 404)
        self.assertFalse([c for c in self.calls if c[0] == "POST"])

    def test_a_renewal_gets_github_tokens_only_for_the_grants_of_now_and_logs_no_token(self):
        """A helper renews the tokens of its live task sessions before their hour ends (fleet.Helper.renew_tokens)
        with {"renew": true} (owner API 1.276). The hub decides again from the agent's grants of that moment (the rule
        of the area "Vault, keys and access", 20 November 2026): a repository taken back gets no token, and an agent
        whose Shell box is off, that is not active or that the hub holds gets none. The answer has GitHub tokens only,
        and its log line counts them and holds no token."""
        self.agents(dev={"repos": {"acme/web": "write", "acme/lib": "read"}, "tools": ["github"]})
        code, data = self.request("/helper/integrations/dev", {"renew": True})
        self.assertEqual(code, 200, data)
        self.assertEqual(sorted(data), ["errors", "renew", "repos", "tokens"])      # no tools, no MCP access token
        self.assertEqual([(t["access"], t["repos"]) for t in data["tokens"]],
                         [("write", ["acme/web"]), ("read", ["acme/lib"])])
        lines = [r["what"] for r in hub.q("SELECT what FROM log WHERE agent='dev' ORDER BY id")]
        self.assertEqual(lines[-1], "GitHub tokens renewed for a task session: 2")
        self.assertFalse([line for line in lines if "ghs_" in line])
        self.agents(dev={"repos": {"acme/web": "write"}})          # the owner took acme/lib back
        code, data = self.request("/helper/integrations/dev", {"renew": True})
        self.assertEqual((data["repos"], [t["repos"] for t in data["tokens"]]), ({"acme/web": "write"}, [["acme/web"]]))
        self.calls.clear()
        for fields in ({"can": []}, {"can": ["shell"], "active": False}):
            with self.subTest(fields=fields):
                self.agents(dev=fields)
                code, data = self.request("/helper/integrations/dev", {"renew": True})
                self.assertEqual((code, data["repos"], data["tokens"]), (200, {}, []))
        self.assertEqual(self.calls, [])                            # and GitHub was not asked
        self.agents(dev={"active": True})
        with patch.object(hub, "os_user_held", return_value=True):
            self.assertEqual(self.request("/helper/integrations/dev", {"renew": True})[0], 403)


class HelperSide(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-integrations-helper-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.home = self.tmp / ".fleet"
        for p in (patch.object(fleet, "HOME", str(self.home)), patch.object(fleet, "SESSIONS", str(self.home / "sessions")),
                  patch.object(fleet, "HUB", "http://hub:8765"), patch.object(fleet, "AGENT", None),
                  patch.object(fleet, "WORK", str(self.tmp / "work"))):
            p.start()
            self.addCleanup(p.stop)
        self.asked = []

    def answer(self, **changes):
        body = dict({"repos": {"acme/web": "write", "acme/lib": "read"}, "tools": ["github"], "errors": [],
                     "tokens": [{"token": WRITE, "access": "write", "repos": ["acme/web"], "expires_at": "x"},
                                {"token": READ, "access": "read", "repos": ["acme/lib"], "expires_at": "x"}]}, **changes)

        def http(method, path, data=None, timeout=40):
            self.asked.append((method, path, data))
            return 200, body
        return http

    def command(self, conf, token="s" * 43, answer=None, program=PROGRAM, **kw):
        with patch.object(fleet, "checkout_conf", return_value={"repos": {"acme/web": "write"}}), \
                patch.object(fleet, "http", answer or self.answer()), \
                patch.object(fleet, "prepare_repos", return_value={}) as prepared, \
                patch.object(fleet, "exe", side_effect=lambda name, home=None: program if name == "github-mcp-server" else None):
            command = fleet.session_command("dev", conf, "Do T-3.", task="T-3", generation="g", session=SESSION,
                                            token=token, env=fleet.session_env("dev", conf, "task"), **kw)
        self.prepared = prepared.call_args.args if prepared.call_args else None
        return command

    def env_file(self, command):
        words = shlex.split(command)
        self.assertEqual((words[0], words[2:5]), (".", ["&&", "rm", "-f"]))
        path = Path(words[1])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        values = {}
        for line in path.read_text().splitlines():
            if line.startswith("set -- "):     # the program's words from this file, which the command names as "$@"
                values["$@"] = shlex.split(line[len("set -- "):])
                continue
            name, _, value = line.removeprefix("export ").partition("=")
            values[name] = shlex.split(value)[0] if value else ""
        return values

    def start_tokens(self, answer, window="T-3"):
        """A task start in this window with this answer of the hub: the values of its environment, and the path of the
        file of its tokens (fleet.tokens_file), or None when it has none."""
        with patch.object(fleet, "checkout_conf", return_value={"repos": {"acme/web": "write"}}), \
                patch.object(fleet, "http", answer), patch.object(fleet, "prepare_repos", return_value={}), \
                patch.object(fleet, "exe", return_value=None):
            values = fleet.integration_env("dev", CLAUDE, window=window)
        return values, Path(values["FLEET_GIT_TOKENS_FILE"]) if "FLEET_GIT_TOKENS_FILE" in values else None

    def renewing(self, windows):
        """A helper of dev whose tmux lists these windows (the test may change the dict), and the lines it says."""
        helper, said = fleet.Helper("dev", CLAUDE), []
        helper.started, helper.say = (lambda: windows), said.append
        return helper, said

    def stand_in(self, *answers):
        """A stand-in hub that gives these answers in turn: (code, body), an exception that it raises, or a function
        that gives (code, body). Each call goes into self.asked."""
        answers = list(answers)

        def http(method, path, data=None, timeout=40):
            self.asked.append((method, path, data))
            answer = answers.pop(0)
            if isinstance(answer, BaseException):
                raise answer
            return answer() if callable(answer) else answer
        return http

    def round_at(self, helper, clock, *answers):
        """One round of the helper's renewal at this time of the clock, with these answers of the stand-in hub."""
        with patch.object(fleet.time, "time", lambda: clock), patch.object(fleet, "http", self.stand_in(*answers)):
            return helper.renew_tokens()

    def test_a_claude_task_gets_github_only_through_its_env_file_and_strict_mcp_configuration(self):
        command = self.command(CLAUDE)
        for secret in (WRITE, READ, "s" * 43):
            self.assertNotIn(secret, command)
        self.assertEqual(self.asked, [("POST", "/helper/integrations/dev", {})])
        values = self.env_file(command)
        self.assertNotIn("FLEET_SESSION_TOKEN", values)         # a Claude credential stays in its MCP file
        self.assertEqual((values["GH_TOKEN"], values["GITHUB_PERSONAL_ACCESS_TOKEN"], values["FLEET_TOOLS"]),
                         (WRITE, WRITE, "github"))
        self.assertEqual(json.loads(values["FLEET_GIT_TOKENS"]), {"acme/web": WRITE, "acme/lib": READ})
        self.assertEqual((values["FLEET_REPOS"], values["GIT_TERMINAL_PROMPT"], values["GIT_CONFIG_COUNT"]),
                         ("acme/lib:read acme/web:write", "0", "3"))
        # gh's telemetry and its daily look for a newer gh are off in a session with repositories (11 November 2026)
        self.assertEqual((values["GH_TELEMETRY"], values["GH_NO_UPDATE_NOTIFIER"]), ("0", "1"))
        self.assertEqual(self.prepared[0], {})     # a new task: each repository comes when it asks for it (held_repos)
        words = fleet.launch_words(command)
        self.assertEqual(words[0], "claude")
        self.assertIn("--strict-mcp-config", words)
        servers = json.loads(Path(words[words.index("--mcp-config") + 1]).read_text())["mcpServers"]
        self.assertEqual(servers["fleet"]["headers"], {"Authorization": "Bearer " + "s" * 43})
        self.assertEqual(servers["github"], {"type": "stdio", "command": PROGRAM, "args": ["stdio"],
                                             "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_PERSONAL_ACCESS_TOKEN}"}})
        settings = json.loads(words[words.index("--settings") + 1])
        # and no Workflow: a task session has none (AUTONOMY.md decision 50)
        self.assertEqual(settings["permissions"]["allow"], ["mcp__fleet__*", "mcp__github__*"])
        prompt = start_text(words)
        self.assertTrue(prompt.startswith("Do T-3.\n\nYour GitHub repositories (2), by access: write: acme/web; read: "
                                          "acme/lib. Before you work in one, run `"), prompt)
        for words_ in ("work on the default branch of origin: git pull --rebase", "do not open a pull request",
                       "Give your commit in where_output_is", "one hour", "Your MCP servers besides Fleet's: github (GitHub).",
                       # not "use git only" (19 November 2026): each other repository has its own token, and the
                       # start says how gh gets it
                       "GH_TOKEN (plain gh and the GitHub tool) works for acme/web; for acme/lib run gh as the start "
                       "says (fleet.py gh).",
                       "gh holds one token, GH_TOKEN, and yours covers only some of your repositories. For each other "
                       "one, run gh as `", "fleet.py gh <gh arguments>`: it gives gh the token of the repository that "
                       "the call is for"):
            self.assertIn(words_, prompt)
        # a session whose GH_TOKEN covers each of its repositories reads nothing about a second way to run gh
        whole = fleet.github_text({"FLEET_REPOS": "acme/web:write", "GH_TOKEN": WRITE,
                                   "FLEET_GIT_TOKENS": json.dumps({"acme/web": WRITE})}, [])
        self.assertIn("GH_TOKEN and git's credentials", whole)
        self.assertNotIn("fleet.py gh", whole)
        # with the file that the helper renews (fleet.tokens_file), only GH_TOKEN stops after its hour
        old = "GH_TOKEN and git's credentials for these repositories stop working one hour after this start."
        gh = shlex.join([sys.executable, os.path.join(fleet.KIT, "fleet.py"), "gh"]) + " <gh arguments>"
        renewing = fleet.github_text(dict(values, FLEET_GIT_TOKENS_FILE=str(self.tmp / "dev.T-3.aa.tokens")), [])
        self.assertIn(old, prompt)
        self.assertNotIn(old, renewing)
        self.assertIn("GH_TOKEN (plain gh and the GitHub tool) stops working one hour after this start; git and gh run "
                      f"as `{gh}` get new tokens while this window is open.", renewing)
        # a start whose every group GitHub refused learns that its tokens can still come, without a restart
        none = dict({k: v for k, v in values.items() if k != "GH_TOKEN"}, FLEET_GIT_TOKENS="{}")
        later = ("This session has no GitHub token yet. The helper asks again within about an hour; git and gh run as "
                 f"`{gh}` then get the tokens, so a restart is not needed for this.")
        self.assertEqual((later in fleet.github_text(dict(none, FLEET_GIT_TOKENS_FILE="/x/dev.T-3.aa.tokens"), []),
                          later in fleet.github_text(none, [])), (True, False))

    def test_a_codex_task_gets_the_tool_as_options_and_a_runner_gets_no_tool(self):
        command = self.command(CODEX_CONF)
        for secret in (WRITE, READ, "s" * 43):
            self.assertNotIn(secret, command)
        values = self.env_file(command)
        self.assertEqual((values["FLEET_SESSION_TOKEN"], values["GH_TOKEN"]), ("s" * 43, WRITE))
        words = fleet.launch_words(command)
        # its catalog servers' options come from its env file, where the command names them ("$@", fleet.env_prefix)
        self.assertEqual(words[words.index("$@") - 2:words.index("$@")], ["-c", fleet.CODEX_BEARER_OPTION])
        options = values["$@"]
        for option in (f'mcp_servers.github.command="{PROGRAM}"', 'mcp_servers.github.args=["stdio"]',
                       'mcp_servers.github.env_vars=["GITHUB_PERSONAL_ACCESS_TOKEN"]',
                       'mcp_servers.github.default_tools_approval_mode="approve"'):
            self.assertEqual(options[options.index(option) - 1], "-c")
            self.assertNotIn(option, words)
        self.assertIn("Your MCP servers besides Fleet's: github (GitHub).", start_text(words))
        runner = self.command(dict(CODEX_CONF, start="app-server"))
        self.assertNotIn("mcp_servers.github", runner)
        self.assertNotIn("$@", fleet.launch_words(runner))
        self.assertEqual(self.env_file(runner)["GH_TOKEN"], WRITE)
        self.assertNotIn("Your MCP servers besides Fleet's", Path(fleet.launch_words(runner)[-1]).read_text())

    def test_an_agent_without_repos_or_tools_asks_the_hub_nothing(self):
        def http(*args, **kw):
            raise AssertionError("no hub call")
        for conf in (CLAUDE, CODEX_CONF):
            with patch.object(fleet, "checkout_conf", return_value={"repos": {}}), patch.object(fleet, "http", http):
                command = fleet.session_command("dev", conf, "Do T-3.", task="T-3", generation="g", session=SESSION,
                                                env=fleet.session_env("dev", conf, "task"))
            if conf is CLAUDE:
                self.assertTrue(command.startswith("env FLEET_ATTEMPT="))   # no env file without a variable
            else:       # a Codex session's env file holds its rules (fleet.codex_rules) and no variable
                self.assertEqual(self.env_file(command), {"$@": fleet.codex_rules()})
            self.assertNotIn("github", command.lower())
            self.assertEqual("--strict-mcp-config" in command, conf is CLAUDE)    # only Fleet's MCP servers
        with patch.object(fleet, "checkout_conf", return_value={"repos": {"acme/web": "read"}}), \
                patch.object(fleet, "http", return_value=(404, {"error": "not found"})):
            self.assertEqual(fleet.integration_env("dev", CLAUDE), {})     # a hub without the route
            self.assertEqual(fleet.integration_env("manager", dict(CLAUDE, role="manager")), {})

    def test_a_later_attempt_gets_the_facts_of_each_clone_that_the_task_has_in_its_note(self):
        """T3 Code idea 4: the route of the helper's repository notes (FLEET_GITHUB_NOTE, "In this session:") carries
        one line for each clone that the task has, at each attempt after the first, and none at the first."""
        place = str(self.tmp / "work/.tasks/dev/0123456789ab/T-3")
        os.makedirs(os.path.join(place, "acme", "web", ".git"))
        asked = []
        with patch.object(fleet, "checkout_conf", return_value={"repos": {"acme/web": "write"}}), \
                patch.object(fleet, "http", self.answer()), \
                patch.object(fleet, "prepare_repos", return_value={}), \
                patch.object(fleet, "exe", return_value=None), \
                patch.object(fleet, "attempt_note", lambda own, repo, attempt, capture=False:
                             asked.append((own, repo, attempt, capture)) or f"Your clone of {repo}: 2 facts."):
            first = fleet.integration_env("dev", CLAUDE, None, place)
            later = fleet.integration_env("dev", CLAUDE, None, place, attempt=3)
        self.assertEqual(asked, [(os.path.join(place, "acme", "web"), "acme/web", 3, True)])
        self.assertNotIn("Your clone of", first.get("FLEET_GITHUB_NOTE", ""))
        self.assertIn("Your clone of acme/web: 2 facts.", later["FLEET_GITHUB_NOTE"])
        self.assertIn("In this session: ", fleet.github_text(later, []))

    def test_a_task_with_its_own_clones_gets_fleet_work_and_one_text_for_every_task(self):
        """4 November 2026: each task works in its own clone of each repository, which FLEET_WORK names. The start text
        says $FLEET_WORK and not its path, so the cached start stays the same from one task to the next. Since
        9 November 2026 a start fetches only the clones that the task has already, and the text lists the repositories
        and names the command that brings one (fleet.py repo)."""
        place = str(self.tmp / "work/.tasks/dev/0123456789ab/T-3")
        os.makedirs(os.path.join(place, "acme", "web", ".git"))          # an earlier attempt of this task used acme/web
        missing = {"acme/web": "the default branch of origin is not known"}
        with patch.object(fleet, "checkout_conf", return_value={"repos": {"acme/web": "write"}}), \
                patch.object(fleet, "http", self.answer()), \
                patch.object(fleet, "prepare_repos", return_value=missing) as prepared, \
                patch.object(fleet, "exe", return_value=None):
            values = fleet.integration_env("dev", CLAUDE, None, place)
            plain = fleet.integration_env("dev", CLAUDE)
        self.assertEqual([(c.args[0], c.args[2]) for c in prepared.call_args_list],
                         [({"acme/web": "write"}, place), ({}, None)])       # acme/lib waits until it is asked for
        self.assertEqual((values["FLEET_WORK"], "FLEET_WORK" in plain), (place, False))
        self.assertIn("acme/web was not fetched: the default branch of origin is not known.", values["FLEET_GITHUB_NOTE"])
        text = fleet.github_text(values, [])
        command = shlex.join([sys.executable, os.path.join(fleet.KIT, "fleet.py"), "repo"]) + " <owner/name>"
        self.assertTrue(text.lstrip().startswith(
            "Your GitHub repositories (2), by access: write: acme/web; read: acme/lib. None of them is on this machine "
            f"for this task until you ask for it. Before you work in one, run `{command}`: it clones the repository, "
            "or fetches it, into $FLEET_WORK/<owner>/<name>"), text)
        for words in ("every attempt of this task finds what the last one left", "Work, install and build only in "
                      "$FLEET_WORK", "never change the shared clones in ~/fleet-work", "give the command time",
                      "work on the default branch of origin: git pull --rebase", "do not open a pull request"):
            self.assertIn(words, text)
        self.assertEqual(text, fleet.github_text(dict(values, FLEET_WORK=place.replace("T-3", "T-4")), []))
        self.assertNotIn(place, text)
        self.assertIn("into ~/fleet-work/<owner>/<name>", fleet.github_text(plain, []))   # the shared clones of before

    def test_the_start_says_what_each_level_does_with_github_actions(self):
        """10 November 2026: a read or write token reads the runs where the App holds Actions (hub.github_permissions,
        door.token_permissions), deploy adds the workflow files and the start of runs, and no token reads check runs
        or commit statuses. The start of a task and rules/github.md say that, and neither promises gh pr checks."""
        write = fleet.github_text({"FLEET_REPOS": "acme/web:write acme/lib:read", "GH_TOKEN": WRITE}, [])
        deploy = fleet.github_text({"FLEET_REPOS": "acme/web:deploy", "GH_TOKEN": WRITE}, [])    # deploy alone
        reads = ("Where the hub's GitHub App has the Actions permission, read, write and deploy can all read the "
                 "GitHub Actions runs of a repository, with their jobs and logs (gh run list, gh run view).")
        for text in (write, deploy):
            self.assertIn(reads, text)
            self.assertIn("No token reads check runs or commit statuses, so gh pr checks does not work. Read the runs "
                          "of the commit instead (gh run list --commit <sha>).", text)
        starts = "and the start of its GitHub Actions runs (gh workflow run, gh run rerun)."
        self.assertIn(starts, deploy)
        self.assertNotIn(starts, write)         # deploy's sentence is for an agent with a deploy repository only
        self.assertEqual(fleet.github_text({}, []), "")
        rules = Path(fleet.KIT, "rules", "github.md").read_text()
        for words in ("`read`, `write` and `deploy` can all read the GitHub Actions runs of a repository",
                      "the start of its runs (`gh workflow run`, `gh run rerun`)", "`gh pr checks` does not work"):
            self.assertIn(words, rules)
        for text in (write, deploy, rules):
            self.assertNotIn("(gh workflow, gh run)", text)
            self.assertNotIn("holds Actions", text)
        # what the manager reads where it grants a level, and a worker where it asks for one
        levels = {name: tool for _, name, _, _, tool in hub.TOOLS if name in ("grant_access", "ask_my_requester")}
        self.assertIn("the start of its GitHub Actions runs; every level reads the runs where the App has the "
                      "Actions permission", levels["grant_access"]["properties"]["level"]["description"])
        self.assertIn("must change a workflow file or start a GitHub Actions run asks for the same repository at "
                      "deploy", levels["ask_my_requester"]["properties"]["needs_level"]["description"])

    def test_the_start_says_what_each_level_does_with_github_issues(self):
        """12 November 2026: where the App holds Issues, every level reads the issues of a repository, and write and
        deploy also open them and comment on them where it holds Issues at write (hub.github_permissions,
        door.token_permissions). The start of a task and rules/github.md say that, with the commands of gh."""
        words = ("Where the hub's GitHub App has the Issues permission, read, write and deploy can all read the issues "
                 "of a repository and their comments (gh issue list, gh issue view); where it has Issues at write, "
                 "write and deploy can also open an issue and comment on one (gh issue create, gh issue comment).")
        for repos in ("acme/lib:read", "acme/web:write acme/lib:read", "acme/web:deploy"):
            with self.subTest(repos=repos):
                self.assertIn(words, fleet.github_text({"FLEET_REPOS": repos, "GH_TOKEN": WRITE}, []))
        rules = Path(fleet.KIT, "rules", "github.md").read_text()
        self.assertIn("Where the hub's GitHub App has the Issues permission, `read`, `write` and `deploy` can all read "
                      "the issues of a repository and their comments (`gh issue list`, `gh issue view`); where it has "
                      "Issues at write, `write` and `deploy` can also open an issue and comment on one "
                      "(`gh issue create`, `gh issue comment`).", rules)

    def test_hundreds_of_repositories_make_short_notes(self):
        """An agent may hold up to 500 repositories (hub.REPOS_MOST): a note names a few and counts the rest."""
        many = {f"acme/r{i:03}": "read" for i in range(300)}
        answer = self.answer(repos=dict(many, **{"acme/web": "write"}), tokens=[
            {"token": WRITE, "access": "write", "repos": ["acme/web"], "expires_at": "x"},
            {"token": READ, "access": "read", "repos": sorted(many)[:200], "expires_at": "x"}],
            errors=[{"repos": sorted(many)[200:], "error": "not in the App's installation"}])
        with patch.object(fleet, "checkout_conf", return_value={"repos": {"acme/web": "write"}}), \
                patch.object(fleet, "http", answer), patch.object(fleet, "prepare_repos", return_value={}), \
                patch.object(fleet, "exe", return_value=None):
            note = fleet.integration_env("dev", CLAUDE)["FLEET_GITHUB_NOTE"]
        self.assertIn("No GitHub token for acme/r200, acme/r201, acme/r202, acme/r203 and 96 more: not in the App's "
                      "installation.", note)
        self.assertIn("GH_TOKEN (plain gh and the GitHub tool) works for acme/web; for your other 200 repositories run "
                      "gh as the start says (fleet.py gh).", note)
        self.assertLess(len(note), 400)

    def test_the_one_hook_gives_a_task_its_read_keys_and_its_github_and_a_chat_only_its_keys(self):
        with patch.object(fleet, "read_env", return_value={"OPENAI_API_KEY": "k"}), \
                patch.object(fleet, "integration_env", return_value={"GH_TOKEN": WRITE}) as github:
            self.assertEqual(fleet.session_env("dev", CLAUDE, "task"), {"OPENAI_API_KEY": "k", "GH_TOKEN": WRITE})
            self.assertEqual(fleet.session_env("dev", CLAUDE, "chat"), {"OPENAI_API_KEY": "k"})
            self.assertEqual(fleet.session_env("manager", dict(CLAUDE, role="manager"), "manager"), {"OPENAI_API_KEY": "k"})
        self.assertEqual(github.call_count, 1)

    def test_what_the_session_lacks_is_in_its_start_text(self):
        refused = self.answer(tokens=[], errors=[{"repos": ["acme/lib", "acme/web"], "error": "GitHub answered 404"}])
        prompt = start_text(shlex.split(self.command(CLAUDE, answer=refused)))
        self.assertIn("In this session: No GitHub token for acme/lib, acme/web: GitHub answered 404. The tool github is "
                      "not loaded: this session has no GH_TOKEN. If that blocks your task, ask your requester.", prompt)
        self.assertNotIn("Your MCP servers besides Fleet's", prompt)
        self.assertIn("The tool github is not loaded: github-mcp-server is not installed on this machine.",
                      start_text(fleet.launch_words(self.command(CLAUDE, program=None))))
        with patch.object(fleet, "checkout_conf", return_value={"tools": ["github"]}), \
                patch.object(fleet, "http", side_effect=OSError("down")):
            self.assertEqual(fleet.integration_env("dev", CLAUDE),
                             {"FLEET_GITHUB_NOTE": "The hub gave no GitHub access at this start."})

    def test_git_uses_only_the_session_token_for_github_never_the_machines_own(self):
        machine = self.tmp / "machine.gitconfig"
        machine.write_text('[credential]\n\thelper = "!f() { echo username=owner; echo password=machine-secret; }; f"\n')
        env = dict(os.environ, GIT_CONFIG_GLOBAL=str(machine), GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0",
                   FLEET_GIT_TOKENS=json.dumps({"acme/web": WRITE}), **fleet.git_credentials())

        def fill(url):
            return subprocess.run(["git", "credential", "fill"], input=f"url={url}\n\n", env=env, capture_output=True,
                                  text=True, timeout=60)
        got = fill("https://github.com/acme/web.git")
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertIn(f"username=x-access-token\npassword={WRITE}\n", got.stdout)
        other = fill("https://github.com/acme/other.git")          # no token for it: no credentials at all
        self.assertNotEqual(other.returncode, 0)
        self.assertNotIn("machine-secret", other.stdout + other.stderr)
        self.assertIn("password=machine-secret", fill("https://example.com/x.git").stdout)    # other hosts: as before

    def test_the_helper_clones_then_fetches_each_repository_and_leaves_its_working_tree(self):
        remotes, config = self.tmp / "remotes", self.tmp / "offline.gitconfig"
        config.write_text(f'[url "file://{remotes}/"]\n\tinsteadOf = https://github.com/\n')
        seed = self.tmp / "seed"
        seed.mkdir()
        git("init", "-q", str(seed))
        (seed / "README").write_text("one\n")
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "one", cwd=seed)
        git("clone", "-q", "--bare", str(seed), str(remotes / "acme" / "web.git"))
        values = dict(fleet.git_credentials(), FLEET_GIT_TOKENS="{}", GIT_TERMINAL_PROMPT="0")   # as integration_env
        with patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(config), "GIT_CONFIG_NOSYSTEM": "1"}):
            self.assertEqual(fleet.prepare_repos({"acme/web": "write"}, values), {})
            clone = self.tmp / "work" / "acme" / "web"
            first = git("-C", str(clone), "rev-parse", "HEAD")
            (seed / "README").write_text("two\n")
            git("commit", "-q", "-am", "two", cwd=seed)
            git("push", "-q", str(remotes / "acme" / "web.git"), "main", cwd=seed)
            self.assertEqual(fleet.prepare_repos({"acme/web": "write"}, values), {})
            self.assertEqual(git("-C", str(clone), "rev-parse", "origin/main"), git("-C", str(seed), "rev-parse", "HEAD"))
            self.assertEqual(git("-C", str(clone), "rev-parse", "HEAD"), first)        # fetched, not checked out
            (self.tmp / "work" / "acme" / "lib").mkdir()
            problems = fleet.prepare_repos({"acme/lib": "read", "acme/none": "read"}, values)
        self.assertIn("is there, but it is not a git clone", problems["acme/lib"])
        self.assertTrue(problems["acme/none"])

    def test_a_task_command_is_built_after_the_checkout_is_up_to_date(self):
        helper, order = fleet.Helper("dev", CLAUDE), []
        event = {"id": 9, "kind": "task", "task": "T-3", "text": "Do T-3.", "extra": {"generation": "g", "attempt": 1}}
        attempt = subprocess.CompletedProcess([], 0, "g:1\n", "")
        with patch.object(helper, "look", return_value=[]), patch.object(helper, "say"), \
                patch.object(helper, "sync_checkout", side_effect=lambda: order.append("sync")), \
                patch("fleet.session_credential", return_value=None), \
                patch("fleet.session_env",
                      side_effect=lambda agent, conf, kind, place=None, closed=False, attempt=None, window=None:
                      order.append(kind) or {}), \
                patch("fleet.session_command", side_effect=lambda *a, **kw: order.append("command") or "true"), \
                patch("fleet.start_window", side_effect=lambda session, name, command: order.append(command)), \
                patch("fleet.tmux", return_value=attempt):
            helper.handle(event)
        self.assertEqual(order, ["sync", "task", "command", "true"])         # team.json is current for session_env

    def test_a_failed_task_start_waits_before_its_next_try(self):
        """Each start of a task session can ask GitHub for new tokens: a start that fails is tried again after 15
        seconds, then 30, and so on up to 5 minutes, not at every poll. Other events are tried at every poll."""
        helper, clock = fleet.Helper("dev", CLAUDE), [1000.0]
        task = {"id": 9, "kind": "task", "task": "T-3", "text": "Do T-3.", "extra": {"generation": "g", "attempt": 1}}
        stop = {"id": 10, "kind": "stop", "task": "T-2", "extra": {}}
        with patch.object(helper, "handle", side_effect=TypeError("x")) as handle, patch.object(helper, "say") as say, \
                patch("fleet.time.monotonic", side_effect=lambda: clock[0]):
            for later, tried in ((0, [9, 10]), (14, [10]), (1, [9, 10]), (29, [10]), (1, [9, 10])):
                clock[0] += later
                handle.reset_mock()
                helper.handle_events([task, stop])
                self.assertEqual([c.args[0]["id"] for c in handle.call_args_list], tried)
            self.assertEqual([c.args[0] for c in say.call_args_list[-2:]],
                             ["event 9 remains pending: TypeError; next try in 60 s", "event 10 remains pending: TypeError"])
            for _ in range(6):
                clock[0] += 300
                helper.handle_events([task])
            self.assertEqual(helper.start_waits[9][0], 300)                 # 5 minutes at most
            handle.side_effect = None                                       # the start works: its wait goes
            clock[0] += 300
            helper.handle_events([task])
            self.assertEqual(helper.start_waits, {})
            handle.side_effect = TypeError("x")
            helper.handle_events([task])
            helper.handle_events([])                                        # the hub gives it no more: its wait goes
            self.assertEqual(helper.start_waits, {})

    def test_the_credential_helper_answers_only_get_for_github_with_a_token(self):
        """git's credential helper gives the session's token for the github.com repository that git names, and
        nothing else. It reads the file that the helper renews (FLEET_GIT_TOKENS_FILE, fleet.tokens_file) before
        FLEET_GIT_TOKENS of the start, which the session keeps for its whole life: a session past its hour pushes with
        the renewed token. A file that is missing or cannot be read leaves the start's tokens, as for a session of an
        older helper."""
        def ask(action, text, tokens, held=None):
            env = dict(os.environ, FLEET_GIT_TOKENS=tokens)
            env.pop("FLEET_GIT_TOKENS_FILE", None)
            env.update({"FLEET_GIT_TOKENS_FILE": str(held)} if held else {})
            return subprocess.run([sys.executable, os.path.join(fleet.KIT, "fleet.py"), "git-credential", action],
                                  input=text, capture_output=True, text=True, timeout=60, env=env).stdout
        tokens = json.dumps({"acme/web": WRITE})
        self.assertEqual(ask("get", "protocol=https\nhost=github.com\npath=Acme/Web.git\n", tokens),
                         f"username=x-access-token\npassword={WRITE}\n")
        for action, text in (("store", "protocol=https\nhost=github.com\npath=acme/web.git\n"),
                             ("get", "protocol=http\nhost=github.com\npath=acme/web.git\n"),
                             ("get", "protocol=https\nhost=github.com.evil\npath=acme/web.git\n"),
                             ("get", "protocol=https\nhost=github.com\npath=acme/lib.git\n")):
            self.assertEqual(ask(action, text, tokens), "", (action, text))
        self.assertEqual(ask("get", "protocol=https\nhost=github.com\npath=acme/web.git\n", "not json"), "")
        web, lib = ("protocol=https\nhost=github.com\npath=acme/web.git\n",
                    "protocol=https\nhost=github.com\npath=acme/lib.git\n")
        both = json.dumps({"acme/web": WRITE, "acme/lib": READ})
        held = self.tmp / "dev.T-3.0123456789abcdef.tokens"
        held.write_text(json.dumps({"tokens": {"acme/web": NEW_WRITE}, "first": NEW_WRITE}))
        self.assertEqual(ask("get", web, both, held), f"username=x-access-token\npassword={NEW_WRITE}\n")
        self.assertEqual(ask("get", lib, both, held), "")           # the file holds what the session has now
        (self.tmp / "broken.tokens").write_text('{"tokens": ')
        (self.tmp / "list.tokens").write_text("[]")
        for name in ("missing.tokens", "broken.tokens", "list.tokens"):
            with self.subTest(file=name):
                self.assertEqual(ask("get", web, both, self.tmp / name), f"username=x-access-token\npassword={WRITE}\n")

    def test_a_start_writes_its_tokens_into_a_file_that_the_helper_renews_before_they_end(self):
        """A session that works past its hour, or that a reminder or an answer wakes in its window, keeps the
        environment of its start: until 20 November 2026 its git push then failed, and agents asked for a restart.
        The start also writes its tokens, with their ends, into a mode-600 file that FLEET_GIT_TOKENS_FILE names
        (fleet.tokens_file); FLEET_GIT_TOKENS and GH_TOKEN stay for an older reader. When a token of a live task
        window ends within ten minutes, the helper asks the hub once, with {"renew": true}, and writes the file again
        whole with the new tokens (Helper.renew_tokens); the next round asks nothing. A new start in the same window
        removes the file of the start before. A start whose every group GitHub refused gets the file too, with no
        token, and an hour later a renewal brings its tokens (until the review of 21 November 2026 it got no file and
        never renewed); a start with no repository gets none."""
        soon = self.answer(tokens=[{"token": WRITE, "access": "write", "repos": ["acme/web"], "expires_at": at(300)},
                                   {"token": READ, "access": "read", "repos": ["acme/lib"], "expires_at": at(300)}])
        _, before = self.start_tokens(soon)
        values, path = self.start_tokens(soon)
        self.assertFalse(before.exists())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual((values["GH_TOKEN"], json.loads(values["FLEET_GIT_TOKENS"])),
                         (WRITE, {"acme/web": WRITE, "acme/lib": READ}))
        held = json.loads(path.read_text())
        self.assertEqual((held["tokens"], held["first"], held["repos"]),
                         ({"acme/web": WRITE, "acme/lib": READ}, WRITE, {"acme/web": "write", "acme/lib": "read"}))
        self.assertAlmostEqual(held["ends"], time.time() + 300, delta=10)
        renewed = {"repos": {"acme/web": "write", "acme/lib": "read"}, "errors": [], "renew": True, "tokens": [
            {"token": NEW_WRITE, "access": "write", "repos": ["acme/web"], "expires_at": at(3600)},
            {"token": NEW_READ, "access": "read", "repos": ["acme/lib"], "expires_at": at(3600)}]}
        windows = {"T-3": "claude"}
        helper, said = self.renewing(windows)
        self.asked.clear()
        with patch.object(fleet, "http", self.stand_in((200, renewed))):
            self.assertEqual(helper.renew_tokens(), 1)
            self.assertEqual(helper.renew_tokens(), 0)          # an hour left: no call
        self.assertEqual(self.asked, [("POST", "/helper/integrations/dev", {"renew": True})])
        session = {"FLEET_GIT_TOKENS_FILE": str(path), "FLEET_GIT_TOKENS": values["FLEET_GIT_TOKENS"]}
        self.assertEqual(fleet.session_tokens(session), ({"acme/web": NEW_WRITE, "acme/lib": NEW_READ}, NEW_WRITE))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(os.listdir(fleet.SESSIONS), [path.name])          # and no other file beside it
        self.assertEqual(said, ["GitHub tokens of dev renewed for 1 task window(s)"])
        windows.clear()
        windows["T-7"] = "claude"                       # alone: no other window's time helps it
        values, empty = self.start_tokens(self.answer(tokens=[], errors=[
            {"repos": ["acme/lib", "acme/web"], "error": "GitHub answered 502"}]), window="T-7")
        held = json.loads(empty.read_text())
        self.assertEqual((held["tokens"], held["first"], held["ends"], "GH_TOKEN" in values), ({}, None, None, False))
        self.assertAlmostEqual(held["asks"], time.time() + 3600, delta=10)
        start, asked = time.time(), len(self.asked)
        self.assertEqual(self.round_at(helper, start + 3000), 0)        # not before its hour
        self.assertEqual(self.round_at(helper, start + 3600, lambda: (200, dict(renewed, tokens=[
            dict(t, expires_at=at(3600)) for t in renewed["tokens"]]))), 1)
        self.assertEqual(len(self.asked), asked + 1)
        self.assertEqual(json.loads(empty.read_text())["tokens"], {"acme/web": NEW_WRITE, "acme/lib": NEW_READ})
        self.assertIsNone(self.start_tokens(self.answer(repos={}), window="T-8")[1])

    def test_a_renewal_that_fails_keeps_the_old_file_and_only_a_refusal_waits_ten_rounds(self):
        """No hub, a refusal (403), a fault of the hub (500) and an answer that is no answer write nothing: the session
        keeps its old tokens, never an empty or half file. After the refusal the next nine rounds ask nothing, and the
        tenth asks again, so an agent that the hub holds, or whose key it refuses, costs one call in ten minutes and
        not one each minute. After each other failure the next round asks again: the first ask comes ten minutes
        before the first token ends, so ten rounds of waiting after one fault would let it end (the reviews of 21
        November 2026). The log line counts the windows and gives the hub's code, never a token."""
        _, path = self.start_tokens(self.answer(tokens=[
            {"token": WRITE, "access": "write", "repos": ["acme/web"], "expires_at": at(120)}]))
        kept = path.read_bytes()
        helper, said = self.renewing({"T-3": "claude"})
        failures = [OSError("no hub"), (403, {"error": "held", "auth": "os_user_shared"}), (500, {"error": "fault"}),
                    (200, {"tokens": []}), (200, ["not an answer"])]
        self.asked.clear()
        with patch.object(fleet, "http", self.stand_in(*failures)):
            for failure in failures:
                with self.subTest(failure=failure):
                    asked, refusal = len(self.asked), isinstance(failure, tuple) and failure[0] == 403
                    for _ in range(fleet.TOKENS_FAILED_ROUNDS if refusal else 1):   # a refusal: nine rounds with none
                        self.assertEqual(helper.renew_tokens(), 0)
                    self.assertEqual((path.read_bytes(), len(self.asked)), (kept, asked + 1))
        self.assertEqual(os.listdir(fleet.SESSIONS), [path.name])
        line = "GitHub tokens of dev: 1 task window(s) not renewed ({}); {}"
        self.assertEqual(said[:3], [line.format("OSError", "the next round asks again"),
                                    line.format(403, "the helper asks again in 10 minutes"),
                                    line.format(500, "the next round asks again")])
        self.assertFalse([line for line in said if "ghs_" in line])

    def test_a_renewal_gives_new_tokens_only_for_the_grants_and_the_windows_of_now(self):
        """The rule of the area "Vault, keys and access" for a renewal (20 November 2026): it decides again from the
        agent's grants of that moment, and the old file's token is not refreshed. A repository taken back loses its
        token at once; a window that ended, and a file that the sweep removed while the hub answered, get nothing. A
        repository that GitHub refused this time keeps its old token while that one lives, and the window asks again
        at its end, not at each round. A window that an answer left with no token (an agent whose Shell box is off, or
        that is not active) asks again about an hour later, not at each round, and its tokens come back with its
        grants: until the review of 21 November 2026 such a window never asked again."""
        three = self.answer(repos={"acme/web": "write", "acme/api": "write", "acme/lib": "read"}, tokens=[
            {"token": WRITE, "access": "write", "repos": ["acme/api", "acme/web"], "expires_at": at(300)},
            {"token": READ, "access": "read", "repos": ["acme/lib"], "expires_at": at(300)}])
        _, path = self.start_tokens(three)
        _, ended = self.start_tokens(three, window="T-4")
        _, swept = self.start_tokens(three, window="T-5")
        untouched = ended.read_bytes()
        helper, said = self.renewing({"T-3": "claude", "T-5": "claude"})
        refused = {"repos": {"acme/web": "write", "acme/lib": "read"}, "renew": True,     # acme/api taken back
                   "tokens": [{"token": NEW_WRITE, "access": "write", "repos": ["acme/web"], "expires_at": at(3600)}],
                   "errors": [{"repos": ["acme/lib"], "error": "GitHub answered 502"}]}
        given = dict(refused, errors=[], tokens=refused["tokens"] + [
            {"token": NEW_READ, "access": "read", "repos": ["acme/lib"], "expires_at": at(3600)}])
        start = time.time()
        self.asked.clear()
        self.assertEqual(self.round_at(helper, start, lambda: swept.unlink() or (200, refused)), 1)     # T-3
        held = json.loads(path.read_text())
        self.assertEqual((held["tokens"], held["first"], held["waits"]),
                         ({"acme/web": NEW_WRITE, "acme/lib": READ}, NEW_WRITE, ["acme/lib"]))
        self.assertTrue(start + 290 < held["asks"] == held["ends"] <= start + 300, held)    # acme/lib's old end
        self.assertEqual((ended.read_bytes(), swept.exists()), (untouched, False))
        self.assertEqual(self.round_at(helper, start + 60), 0)          # not at each round
        self.assertEqual(self.round_at(helper, start + 301, (200, given)), 1)
        held = json.loads(path.read_text())
        self.assertEqual((held["tokens"], held["waits"]), ({"acme/web": NEW_WRITE, "acme/lib": NEW_READ}, []))
        empty = {"repos": {}, "tokens": [], "errors": [], "renew": True}

        def back():                 # the grants again, with tokens of an hour from the clock of that round
            return 200, dict(given, tokens=[dict(t, expires_at=at(3600)) for t in given["tokens"]])
        self.assertEqual(self.round_at(helper, start + 3100, (200, empty)), 1)
        held = json.loads(path.read_text())
        self.assertEqual((held["tokens"], held["first"], held["waits"]), ({}, None, []))
        self.assertAlmostEqual(held["asks"], start + 3100 + 3600, delta=1)          # an hour later
        self.assertEqual(self.round_at(helper, start + 3160), 0)
        self.assertEqual(self.round_at(helper, start + 6700, back), 1)
        self.assertEqual(json.loads(path.read_text())["tokens"], {"acme/web": NEW_WRITE, "acme/lib": NEW_READ})
        self.assertEqual((len(self.asked), said), (4, ["GitHub tokens of dev renewed for 1 task window(s)"] * 4))

    def test_a_token_that_github_refuses_at_its_end_is_asked_for_again_every_five_minutes(self):
        """A refusal of GitHub or the door at the end of a token must not stop the renewal for long (the review of 21
        November 2026): a repository that had a token in the window and that the hub still grants waits in the file,
        and the window asks again five minutes later, and every five minutes until a token comes, also when no other
        window or token is due. A repository that GitHub refused since the start does not wait: it costs one ask an
        hour, not one each five minutes."""
        ended_at = time.time() - 5
        late = Path(fleet.tokens_file("dev", "T-6", {"tokens": {"acme/lib": READ}, "first": READ, "ends": ended_at,
                                                     "repos": {"acme/lib": "read"}, "until": {"acme/lib": ended_at},
                                                     "waits": [], "asks": ended_at - 600}))
        windows = {"T-6": "claude"}                     # alone: no other window's time helps it
        helper, _ = self.renewing(windows)
        refused = {"repos": {"acme/web": "write", "acme/lib": "read"}, "renew": True, "tokens": [],
                   "errors": [{"repos": ["acme/lib", "acme/web"], "error": "GitHub answered 502"}]}
        given = dict(refused, errors=[], tokens=[
            {"token": NEW_READ, "access": "read", "repos": ["acme/lib"], "expires_at": at(3600)}])
        start = time.time()
        self.asked.clear()
        for later, answer in ((0, (200, refused)), (60, None), (300, (200, refused)), (360, None), (600, (200, given))):
            self.assertEqual(self.round_at(helper, start + later, *([answer] if answer else [])), 1 if answer else 0,
                             later)
            held = json.loads(late.read_text())
            if later < 600:                             # its old token had ended: it waits, and asks again in five
                self.assertEqual((held["tokens"], held["waits"]), ({}, ["acme/lib"]), later)
                self.assertAlmostEqual(held["asks"], start + (later // 300) * 300 + 300, delta=1, msg=later)
        self.assertEqual((held["tokens"], held["waits"], len(self.asked)), ({"acme/lib": NEW_READ}, [], 3))
        windows.clear()
        windows["T-7"] = "claude"
        _, never = self.start_tokens(self.answer(tokens=[], errors=refused["errors"]), window="T-7")
        start = time.time()
        self.assertEqual(self.round_at(helper, start + 3600, (200, refused)), 1)
        held = json.loads(never.read_text())
        self.assertEqual((held["tokens"], held["waits"]), ({}, []))
        self.assertAlmostEqual(held["asks"], start + 3600 + 3600, delta=1)          # an hour, not five minutes
        asked = len(self.asked)                         # its start asked the hub too
        self.assertEqual((self.round_at(helper, start + 3900), len(self.asked)), (0, asked))

if __name__ == "__main__":
    unittest.main()
