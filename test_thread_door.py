"""Tests of thread_door.py: the repository calls of a narrowed conversation, against a GitHub that lives in memory.
No network and no hub: the fake `req` serves one repository and records every request, so each test reads what the
door asked GitHub and what it told the thread."""
import base64
import hashlib
import json
import re
import unittest
import urllib.parse

import door_targets
import thread_door as td

REPO, CID, MINE = "acme/web", 7, "fleet/c7/fix"
SECRET = "GITHUB-OWN-TEXT ghs_abcdefghijklmnopqrstuvwxyz0123456789"
BIG = b"x" * (td.FILE_MAX + 1)


def sha(*parts):
    return hashlib.sha1(repr(parts).encode()).hexdigest()


class GitHub:
    """One repository: trees of {path: (type, bytes)}, commits, refs, pull requests, runs and search results. Every
    answer carries the fields a real one does and the door must drop: urls with a token, and a message on a failure."""

    def __init__(self):
        self.calls, self.fail, self.trees, self.commits = [], {}, {}, {}
        start = {"README.md": ("file", b"# Web\n\nhello world\nhello again\n"),
                 "src/app.py": ("file", b"def main():\n    return 1\n"),
                 "src/long.txt": ("file", "".join(f"line {i}\n" for i in range(1, 1001)).encode()),
                 "src/fat.txt": ("file", "".join(f"row {i} {'z' * 60}\n" for i in range(1, 1001)).encode()),
                 "src/wide.txt": ("file", b"y" * 40000 + b"\nsecond\n"),
                 "src/link": ("symlink", b"app.py"), "vendor/lib": ("submodule", b""),
                 "big.bin": ("file", BIG), "logo.png": ("file", b"\xff\xfe\x00png")}
        self.refs = {"main": self.commit(self.tree(start), None)}
        self.refs["release"] = self.refs["fleet/c7/kept"] = self.refs["fleet/c7/locked"] = self.refs["main"]
        self.protected = {"main", "fleet/c7/locked"}
        self.pulls, self.runs, self.items = [], [], []

    def tree(self, files):
        key = sha(sorted(files.items()))
        self.trees[key] = dict(files)
        return key

    def commit(self, tree, parent, message=""):
        key = sha(tree, parent, message)
        self.commits[key] = {"tree": tree, "parent": parent, "message": message}
        return key

    def files(self, ref):
        return self.trees[self.commits[self.refs.get(ref, ref)]["tree"]]

    def req(self, method, path, body=None, accept=None):
        self.calls.append((method, path, body, accept))
        for (m, piece), status in self.fail.items():
            if m == method and piece in path:
                return status, {"message": SECRET, "documentation_url": "https://docs.github.com/" + SECRET}
        route, _, query = path.partition("?")
        q = dict(urllib.parse.parse_qsl(query))
        if route == "/search/code":
            return 200, {"total_count": len(self.items), "items": self.items}
        assert route.startswith("/repos/acme/web"), path
        answer = self.serve(method, urllib.parse.unquote(route[len("/repos/acme/web"):]), q, body)
        return answer if answer else (404, {"message": SECRET})

    def serve(self, method, route, q, body):
        if route == "":
            return 200, {"default_branch": "main", "url": "https://api.github.com/" + SECRET}
        if route.startswith("/contents"):
            return self.contents(route[len("/contents"):].strip("/"), q.get("ref", "main"))
        if route.startswith("/git/ref/heads/") and route[15:] in self.refs:
            return 200, {"ref": "refs/heads/" + route[15:], "object": {"sha": self.refs[route[15:]], "url": SECRET}}
        if route.startswith("/branches/") and route[10:] in self.refs:
            return 200, {"name": route[10:], "protected": route[10:] in self.protected}
        if method == "GET" and route.startswith("/git/commits/") and route[13:] in self.commits:
            return 200, {"sha": route[13:], "tree": {"sha": self.commits[route[13:]]["tree"]}}
        if (method, route) == ("POST", "/git/trees"):
            files = dict(self.trees[body["base_tree"]])
            for e in body["tree"]:
                assert e["mode"] == "100644" and e["type"] == "blob", e
                if "content" in e:
                    files[e["path"]] = ("file", e["content"].encode())
                elif e["path"] not in files:
                    return 422, {"message": SECRET}
                else:
                    assert e["sha"] is None
                    del files[e["path"]]
            return 201, {"sha": self.tree(files), "url": SECRET}
        if (method, route) == ("POST", "/git/commits"):
            return 201, {"sha": self.commit(body["tree"], body["parents"][0], body["message"])}
        if (method, route) == ("POST", "/git/refs"):
            name = body["ref"][len("refs/heads/"):]
            if name in self.refs:
                return 422, {"message": SECRET}
            self.refs[name] = body["sha"]
            return 201, {"ref": body["ref"]}
        if method == "PATCH" and route.startswith("/git/refs/heads/"):
            name = route[16:]
            if body["force"] is not False or self.commits[body["sha"]]["parent"] != self.refs[name]:
                return 422, {"message": SECRET}
            self.refs[name] = body["sha"]
            return 200, {"ref": "refs/heads/" + name}
        if (method, route) == ("GET", "/pulls"):
            return 200, self.pulls                # like GitHub with a head it cannot read: every open one
        if (method, route) == ("POST", "/pulls"):
            self.pulls.append({"number": 40 + len(self.pulls), "state": "open", "html_url": SECRET,
                               "head": {"ref": body["head"].split(":")[1]}, "base": {"ref": body["base"]}})
            return 201, self.pulls[-1]
        if method == "PATCH" and re.fullmatch(r"/pulls/\d+", route):
            return 200, {"number": int(route[7:])}
        if route == "/actions/runs":
            return 200, {"workflow_runs": self.runs}
        return None

    def contents(self, path, ref):
        if ref not in self.refs and ref not in self.commits:
            return None
        files = self.files(ref)

        def entry(p, full):
            kind, data = files[p]
            e = {"type": kind, "name": p.rsplit("/", 1)[-1], "path": p, "size": len(data), "sha": sha(data),
                 "url": SECRET, "git_url": SECRET, "download_url": "https://raw.example/?token=" + SECRET}
            if full:
                e.update(encoding="base64", content="" if len(data) > td.FILE_MAX else base64.b64encode(data).decode())
            return e
        if path in files:
            return 200, entry(path, True)
        under, out = path + "/" if path else "", {}
        for p in files:
            if p.startswith(under):
                name = p[len(under):].split("/")[0]
                out[name] = entry(p, False) if under + name == p else \
                    {"type": "dir", "name": name, "path": under + name, "size": 0, "download_url": None, "url": SECRET}
        return (200, list(out.values())) if out else None


class Case(unittest.TestCase):
    def setUp(self):
        self.hub = GitHub()
        self.said = []                           # every answer and every refusal that a thread would read
        self.rechecks = 0

    def tearDown(self):
        """No answer holds a url, a header, a token or GitHub's own words."""
        for text in self.said:
            for bad in ("download_url", "git_url", "http", "token", "GITHUB-OWN-TEXT", "ghs_", "Authorization",
                        "X-GitHub", "documentation_url"):
                self.assertNotIn(bad, text)

    def recheck(self):
        self.rechecks += 1

    def call(self, fn, *args, **more):
        try:
            out = fn(self.hub.req, *args, **more)
        except td.Refused as e:
            self.said.append(str(e))
            raise
        self.assertIsInstance(out, str)
        self.said.append(out)
        return out

    def refused(self, fn, *args, **more):
        with self.assertRaises(td.Refused) as caught:
            self.call(fn, *args, **more)
        return str(caught.exception)

    def change(self, changes, branch=MINE, message="Fix it", cid=CID):
        return self.call(td.repo_change, REPO, branch, changes, message, cid, self.recheck)

    def no_change(self, changes, branch=MINE, cid=CID, requests=None):
        """A refused change: its sentence, with nothing written and, when the rule needs no read, nothing asked."""
        refs = dict(self.hub.refs)
        why = self.refused(td.repo_change, REPO, branch, changes, "Fix it", cid, self.recheck)
        self.assertEqual(self.hub.refs, refs)
        self.assertFalse([c for c in self.hub.calls if c[0] == "PATCH" or c[1].endswith("/git/refs")])
        if requests is not None:
            self.assertEqual(len(self.hub.calls), requests)
        return why

    def sent(self, method, piece):
        return [c for c in self.hub.calls if c[0] == method and piece in c[1]]


class Reads(Case):
    def test_files_lists_one_folder(self):
        out = self.call(td.repo_files, REPO)
        self.assertIn("dir src", out.split("\n"))
        self.assertIn("file README.md 31", out.split("\n"))
        out = self.call(td.repo_files, REPO, "src/", "main").split("\n")
        self.assertIn("symlink link", out)
        self.assertIn("file app.py 25", out)
        self.assertEqual(self.hub.calls[-1][1], "/repos/acme/web/contents/src?ref=main")
        self.assertIn("submodule lib", self.call(td.repo_files, REPO, "vendor"))

    def test_files_refuses_a_file_and_a_missing_folder(self):
        self.assertIn("repo_read", self.refused(td.repo_files, REPO, "README.md"))
        self.assertIn("not there", self.refused(td.repo_files, REPO, "nowhere"))

    def test_read_whole_small_file(self):
        self.assertEqual(self.call(td.repo_read, REPO, "src/app.py"), "def main():\n    return 1")

    def test_read_caps_and_ranges(self):
        out = self.call(td.repo_read, REPO, "src/long.txt").split("\n")
        self.assertEqual((len(out), out[0], out[399]), (401, "line 1", "line 400"))
        self.assertEqual(out[400], '[lines 1-400 of 1000; ask for more with lines="401-800"]')
        self.assertEqual(self.call(td.repo_read, REPO, "src/long.txt", "main", "401-403"),
                         "line 401\nline 402\nline 403")
        self.assertEqual(self.call(td.repo_read, REPO, "src/long.txt", lines="999-2000"), "line 999\nline 1000")
        wide = self.call(td.repo_read, REPO, "src/fat.txt", lines="1-1000")
        self.assertLessEqual(len(wide), td.READ_BYTES + 100)
        self.assertRegex(wide, r'\[lines 1-\d+ of 1000; ask for more with lines="\d+-\d+"\]$')
        one = self.call(td.repo_read, REPO, "src/wide.txt")
        self.assertLessEqual(len(one), td.READ_BYTES + 100)
        self.assertIn("longer than 32 KiB", one)
        self.assertEqual(self.call(td.repo_read, REPO, "src/wide.txt", lines="2-2"), "second")

    def test_read_refuses_bad_ranges(self):
        for lines in ("0-5", "5-1", "5", "a-b", "1-2-3", 5, "-1-2"):
            self.assertIn("range", self.refused(td.repo_read, REPO, "src/long.txt", lines=lines))
        self.assertIn("1000 lines", self.refused(td.repo_read, REPO, "src/long.txt", lines="1001-1100"))

    def test_read_refuses_what_is_no_text_file(self):
        self.assertIn("symlink", self.refused(td.repo_read, REPO, "src/link"))
        self.assertIn("symlink", self.refused(td.repo_read, REPO, "vendor/lib"))
        self.assertIn("1 MiB", self.refused(td.repo_read, REPO, "big.bin"))
        self.assertIn("UTF-8", self.refused(td.repo_read, REPO, "logo.png"))
        self.assertIn("repo_files", self.refused(td.repo_read, REPO, "src"))
        self.assertIn("not there", self.refused(td.repo_read, REPO, "none.txt"))

    def test_a_symlink_that_github_followed_is_refused(self):
        files = dict(self.hub.files("main"))
        real = self.hub.contents
        self.hub.contents = lambda path, ref: (200, dict(real("src/app.py", ref)[1])) if path == "alias" \
            else real(path, ref)
        self.assertIn("symlink", self.refused(td.repo_read, REPO, "alias"))
        self.assertEqual(files, self.hub.files("main"))

    def test_inputs_never_reach_a_url(self):
        for path in ("../x", "a/../b", "/etc/passwd", "a//b", "a b", "a?ref=x", "a#b", "a%2e%2e", "é.txt",
                     "é.txt", "a\\b", "a/", "./a", "a/./b", "", None, 5):
            self.refused(td.repo_read, REPO, path)
        for ref in ("a..b", "/main", "x//y", "ma in", "main&x=1", ".hidden", "a/.b", "x.lock", "a.lock/b", "x:y", 5):
            self.refused(td.repo_read, REPO, "README.md", ref)
            self.refused(td.repo_files, REPO, "", ref)
            self.refused(td.repo_checks, REPO, ref)
        for repo in ("acme", "acme/web/x", "acme/web?x", "../web", "acme/..", "acme/ web", "", None, "a/b#c"):
            self.refused(td.repo_files, repo)
            self.refused(td.repo_search, repo, "x")
            self.refused(td.repo_change, repo, MINE, [{"path": "a", "content": "b"}], "m", CID, self.recheck)
            self.refused(td.repo_pull_request, repo, MINE, "t", "b", CID)
        self.assertEqual(self.hub.calls, [])

    def test_search_adds_its_own_repo_and_clips(self):
        self.hub.items = [{"path": f"src/f{i}.py", "repository": {"full_name": "Acme/Web"}, "html_url": SECRET,
                           "text_matches": [{"fragment": "def hello():\n    pass " + "z" * 500, "object_url": SECRET},
                                            {"fragment": "two"}, {"fragment": "three"}, {"fragment": "four"}]}
                          for i in range(30)] + [{"path": "late.py"}]
        self.hub.items.insert(0, {"path": "other/secret.py", "repository": {"full_name": "acme/other"}})
        out = self.call(td.repo_search, REPO, "hello path:src")
        method, path, _, accept = self.hub.calls[-1]
        self.assertEqual(accept, "application/vnd.github.text-match+json")
        self.assertEqual(urllib.parse.parse_qs(path.partition("?")[2])["q"], ["hello path:src repo:acme/web"])
        self.assertNotIn(" ", path)
        rows = out.split("\n")
        self.assertEqual([r for r in rows if not r.startswith(" ")], [f"src/f{i}.py" for i in range(20)])
        self.assertIn("    def hello():", rows)
        self.assertNotIn("four", out)
        self.assertNotIn("other/secret.py", out)
        self.assertLess(max(map(len, rows)), td.FRAGMENT_MAX + 10)
        self.hub.items = []
        self.assertEqual(self.call(td.repo_search, REPO, "nothing"), "No match.")

    def test_search_refuses_its_own_scope(self):
        for query in ("x repo:acme/other", "REPO:acme/other x", "org:acme x", "Org:acme", "user:bob", "(user:bob)",
                      "", "   ", "a\nb", "q" * 257, None):
            self.refused(td.repo_search, REPO, query)
        self.assertEqual(self.hub.calls, [])
        self.call(td.repo_search, REPO, "def f(user: str)")     # code, not a qualifier
        self.assertTrue(self.hub.calls)

    def test_search_rate_is_a_fixed_sentence(self):
        for status in (403, 429):
            self.hub.fail = {("GET", "/search/code"): status}
            self.assertIn("Do not retry", self.refused(td.repo_search, REPO, "x"))
        self.assertEqual(len(self.hub.calls), 2)

    def test_checks(self):
        self.hub.runs = [{"name": "CI", "status": "completed", "conclusion": "success", "html_url": SECRET},
                         {"name": "Lint", "status": "in_progress", "conclusion": None, "logs_url": SECRET},
                         {"name": "Odd", "status": SECRET, "conclusion": "failure"}]
        out = self.call(td.repo_checks, REPO, MINE).split("\n")
        self.assertEqual(out[:3], ["CI: completed, conclusion success", "Lint: in_progress, conclusion none",
                                   "Odd: none, conclusion failure"])
        self.assertEqual(out[3], td.NO_OTHER_CHECK)
        self.assertEqual(self.hub.calls[-1][1], "/repos/acme/web/actions/runs?branch=fleet%2Fc7%2Ffix&per_page=10")
        self.call(td.repo_checks, REPO, "a" * 40)
        self.assertEqual(self.hub.calls[-1][1], f"/repos/acme/web/actions/runs?head_sha={'a' * 40}&per_page=10")
        self.hub.runs = []
        out = self.call(td.repo_checks, REPO, "main")
        self.assertTrue(out.startswith("No GitHub Actions run for main.") and out.endswith(td.NO_OTHER_CHECK))

    def test_checks_fallback(self):
        for status in (403, 404):
            self.hub.fail = {("GET", "/actions/runs"): status}
            self.assertEqual(self.refused(td.repo_checks, REPO, "main"),
                             "This repository's access cannot read its CI runs.")

    def test_every_failure_is_a_fixed_sentence(self):
        want = {404: td.SENTENCES[404], 403: td.SENTENCES[403], 409: td.SENTENCES[409], 422: td.SENTENCES[422],
                500: "GitHub refused the call.", 401: "GitHub refused the call.", 302: "GitHub refused the call."}
        for status, sentence in want.items():
            self.hub.fail = {("GET", "/repos/acme/web"): status}
            self.assertEqual(self.refused(td.repo_change, REPO, MINE, [{"path": "a", "content": "b"}], "m", CID,
                                          self.recheck), sentence)
            self.assertEqual(self.refused(td.repo_pull_request, REPO, MINE, "t", "b", CID), sentence)
        for status in (403, 500):
            self.hub.fail = {("GET", "/contents"): status}
            self.assertEqual(self.refused(td.repo_read, REPO, "README.md"), want[status])
            self.assertEqual(self.refused(td.repo_files, REPO), want[status])


class Rules(unittest.TestCase):
    def test_branch_prefix(self):
        self.assertEqual(td.branch_prefix(7), "fleet/c7/")
        for cid in (0, -1, None, "7", True, 7.0):
            self.assertRaises(td.Refused, td.branch_prefix, cid)

    def test_other_tools_instruction_and_self_running_files_are_refused(self):
        for path in (".windsurfrules", ".windsurf/rules.md", ".clinerules", ".clinerules/a.md", ".roomodes",
                     ".roo/rules.md", ".continue/config.json", ".aider.conf.yml", ".zed/settings.json",
                     ".idea/workspace.xml", "mise.toml", ".mise.toml", ".pre-commit-config.yaml", "lefthook.yml",
                     ".npmrc", "web/.NPMRC", "CODEOWNERS", "docs/CODEOWNERS"):
            self.assertIsNotNone(td.path_refused(path), path)
        self.assertIsNone(td.path_refused("src/settings.py"))

    def test_each_commit_rule_and_its_case_variants(self):
        refused = {".claude/settings.json": ".claude/**", ".Claude/x": ".claude/**", "a/b/.CLAUDE/hooks/x": ".claude/**",
                   ".codex/config.toml": ".codex/**", ".gemini/x": ".gemini/**", ".cursor/rules/a": ".cursor/**",
                   ".cursorrules": ".cursorrules", "pkg/.CursorRules": ".cursorrules", ".mcp.json": ".mcp.json",
                   "sub/.MCP.json": ".mcp.json", "AGENTS.md": "AGENTS.md", "docs/agents.md": "AGENTS.md",
                   "CLAUDE.md": "CLAUDE.md", "claude.md": "CLAUDE.md", "x/Claude.MD": "CLAUDE.md",
                   "CLAUDE.local.md": "CLAUDE.local.md", "claude.LOCAL.md": "CLAUDE.local.md",
                   "GEMINI.md": "GEMINI.md", "gemini.md": "GEMINI.md", ".github/workflows/ci.yml": ".github/**",
                   ".GitHub/CODEOWNERS": ".github/**", ".husky/pre-commit": ".husky/**",
                   ".vscode/tasks.json": ".vscode/**", ".devcontainer/devcontainer.json": ".devcontainer/**",
                   ".envrc": ".envrc", "app/.ENVRC": ".envrc", ".gitmodules": ".gitmodules",
                   ".gitattributes": ".gitattributes", "src/.GitAttributes": ".gitattributes",
                   ".git/hooks/pre-commit": ".git/**", "x/.GIT/config": ".git/**", ".git": ".git/**",
                   "policy.hujson": "policy.hujson"}
        for path, rule in refused.items():
            self.assertEqual(td.path_refused(path), rule, path)
        refused.update({".windsurf/a": ".windsurf/**", ".windsurfrules": ".windsurfrules", ".clinerules": ".clinerules",
                        ".clinerules/a": ".clinerules/**", ".roomodes": ".roo*", ".continue/a": ".continue/**",
                        ".aider.conf.yml": ".aider*", ".zed/a": ".zed/**", ".idea/a": ".idea/**",
                        "mise.toml": "mise.toml", ".mise.toml": ".mise.toml",
                        ".pre-commit-config.yaml": ".pre-commit-config.yaml", "lefthook.yml": "lefthook*",
                        ".lefthook.yml": ".lefthook*", ".npmrc": ".npmrc", "CODEOWNERS": "CODEOWNERS"})
        for rule in door_targets.NEVER_PATHS + td.EXTRA_NEVER:
            self.assertIn(rule, refused.values() if rule != "scripts/security/check-tailnet-policy.mjs" else [rule])
        for path in ("README.md", "src/app.py", "package.json", "docs/claude.md.txt", "src/claude/x.py", ".gitignore",
                     "github/x", "my.github/x", ".env.example", "notes/AGENTS.md.bak"):
            self.assertIsNone(td.path_refused(path), path)


class Changes(Case):
    def test_a_new_branch_takes_one_commit_from_the_default_branch(self):
        main = self.hub.refs["main"]
        out = self.change([{"path": "README.md", "edit": {"old": "hello world", "new": "hello there"}},
                           {"path": "docs/new.md", "content": "# New\n"}, {"path": "src/app.py", "delete": True}])
        head = self.hub.refs[MINE]
        self.assertEqual(out, f"acme/web {MINE} is at {head}: 3 files in one commit, on a new branch.")
        commit = self.hub.commits[head]
        self.assertEqual(commit["parent"], main)
        self.assertEqual(commit["message"], "Fix it\n\nNarrowed-conversation: C-7")
        files = self.hub.files(MINE)
        self.assertEqual(files["README.md"][1], b"# Web\n\nhello there\nhello again\n")
        self.assertEqual(files["docs/new.md"], ("file", b"# New\n"))
        self.assertNotIn("src/app.py", files)
        self.assertEqual(self.hub.refs["main"], main)
        self.assertEqual(self.rechecks, 1)
        tree = self.sent("POST", "/git/trees")[0][2]
        self.assertEqual({e["mode"] for e in tree["tree"]}, {"100644"})
        self.assertIn({"path": "src/app.py", "mode": "100644", "type": "blob", "sha": None}, tree["tree"])
        self.assertEqual(self.sent("POST", "/git/refs")[0][2], {"ref": "refs/heads/" + MINE, "sha": head})
        self.assertEqual([c[0] for c in self.hub.calls].count("GET"), 4 + 1)       # one read for the one edit
        self.assertTrue(all(c[1].startswith("/repos/acme/web") for c in self.hub.calls))
        self.assertFalse(self.sent("GET", "/branches/"))

    def test_an_existing_branch_moves_without_force(self):
        self.change([{"path": "a.txt", "content": "one\n"}])
        first = self.hub.refs[MINE]
        self.hub.calls.clear()
        out = self.change([{"path": "a.txt", "edit": {"old": "one", "new": "two"}},
                           {"path": "a.txt", "edit": {"old": "two", "new": "three"}}])
        head = self.hub.refs[MINE]
        self.assertEqual(out, f"acme/web {MINE} is at {head}: 1 file in one commit.")
        self.assertEqual(self.hub.commits[head]["parent"], first)
        self.assertEqual(self.hub.files(MINE)["a.txt"][1], b"three\n")
        self.assertEqual(self.sent("PATCH", "/git/refs/heads/" + MINE)[0][2], {"sha": head, "force": False})
        self.assertTrue(self.sent("GET", "/branches/" + MINE))
        self.assertIn(f"/contents/a.txt?ref={first}", self.sent("GET", "/contents/")[0][1])
        self.assertEqual(len(self.sent("GET", "/contents/")), 1)

    def test_nothing_changed_commits_nothing(self):
        change = [{"path": "a.txt", "content": "one\n"}]
        self.change(change)
        head, commits = self.hub.refs[MINE], len(self.hub.commits)
        self.hub.calls.clear()
        self.assertEqual(self.change(change), "Nothing changed.")
        self.assertEqual((self.hub.refs[MINE], len(self.hub.commits), self.rechecks), (head, commits, 1))
        self.assertFalse(self.sent("POST", "/git/commits") + self.sent("PATCH", "/git/refs"))
        self.hub.calls.clear()
        same = self.hub.files("main")["README.md"][1].decode()
        self.assertEqual(self.change([{"path": "README.md", "content": same}], MINE + "2"), "Nothing changed.")
        self.assertNotIn(MINE + "2", self.hub.refs)

    def test_recheck_refuses_before_the_ref_write(self):
        def gone():
            self.assertTrue(self.sent("POST", "/git/commits"))
            raise td.Refused("This conversation may no longer write this repository.")
        for branch in (MINE, "fleet/c7/kept"):
            with self.assertRaises(td.Refused) as caught:
                td.repo_change(self.hub.req, REPO, branch, [{"path": "a.txt", "content": "x"}], "m", CID, gone)
            self.assertEqual(str(caught.exception), "This conversation may no longer write this repository.")
        self.assertNotIn(MINE, self.hub.refs)
        self.assertEqual(self.hub.refs["fleet/c7/kept"], self.hub.refs["main"])
        self.assertFalse(self.sent("POST", "/git/refs") + self.sent("PATCH", "/git/refs"))

    def test_branches_that_are_not_this_conversations(self):
        change = [{"path": "a.txt", "content": "x"}]
        for branch in ("main", "release", "fix", "fleet/c8/fix", "fleet/c70/fix", "fleet/c7", "fleet/c7/", "fleet/c7x/a",
                       "Fleet/c7/fix", "fleet/c7/a..b", "fleet/c7/.a", "fleet/c7/a.lock", "fleet/c7/a.lock/b",
                       "fleet/c7/a b", "fleet/c7//a", "fleet/c7/a:b", "acme:fleet/c7/a", "refs/heads/fleet/c7/a",
                       "fleet/c7/a~1", "fleet/c7/a^", "fleet/c7/a?", "fleet/c7/a*", "fleet/c7/é", None, 7):
            self.no_change(change, branch, requests=0)
            self.refused(td.repo_pull_request, REPO, branch, "t", "b", CID)
        self.assertEqual(self.hub.calls, [])
        self.assertIn("fleet/c8/", self.no_change(change, MINE, cid=8, requests=0))

    def test_the_default_and_a_protected_branch_by_githubs_answer(self):
        change = [{"path": "a.txt", "content": "x"}]
        real = self.hub.serve
        self.hub.serve = lambda m, route, q, b: (200, {"default_branch": MINE}) if route == "" else real(m, route, q, b)
        self.assertIn("default branch", self.no_change(change))
        self.assertIn("default branch", self.refused(td.repo_pull_request, REPO, MINE, "t", "b", CID))
        self.hub.serve = real
        self.assertIn("protected", self.no_change(change, "fleet/c7/locked"))
        self.assertFalse(self.sent("POST", "/git/"))

    def test_a_moved_branch_is_refused_by_github(self):
        self.hub.fail = {("PATCH", "/git/refs/"): 422}
        why = self.refused(td.repo_change, REPO, "fleet/c7/kept", [{"path": "a.txt", "content": "x"}], "m", CID,
                           self.recheck)
        self.assertIn("moved meanwhile", why)
        self.assertEqual(self.hub.refs["fleet/c7/kept"], self.hub.refs["main"])

    def test_commit_rule_paths_are_refused_before_any_request(self):
        for path in (".claude/settings.json", ".Claude/x", "claude.md", "docs/AGENTS.md", ".github/workflows/ci.yml",
                     ".GITHUB/workflows/x.yml", ".cursorrules", ".envrc", ".gitmodules", "a/.gitattributes",
                     ".git/config", ".devcontainer/x", ".gemini/x", "GEMINI.md", "CLAUDE.local.md", ".mcp.json",
                     ".husky/pre-push", ".vscode/settings.json", ".codex/x", ".cursor/x"):
            for change in ({"path": path, "content": "x"}, {"path": path, "delete": True},
                           {"path": path, "edit": {"old": "a", "new": "b"}}):
                self.assertIn("commit rules", self.no_change([{"path": "ok.txt", "content": "x"}, change], requests=0))

    def test_a_commit_message_closes_no_issue(self):
        for message in ("Fixes #12", "this closes acme/web#3", "Resolved: #4", "fixes GH-6",
                        "Closes https://github.com/acme/web/issues/7"):
            refs = dict(self.hub.refs)
            why = self.refused(td.repo_change, REPO, MINE, [{"path": "a.txt", "content": "x"}], message, CID,
                               self.recheck)
            self.assertIn("closes no issue", why)
            self.assertEqual(self.hub.refs, refs)
        self.assertEqual(self.hub.calls, [])
        self.change([{"path": "a.txt", "content": "x"}], message="See issue #12")

    def test_change_forms_and_paths(self):
        for change in ("x", {}, {"path": "a"}, {"content": "x"}, {"path": "a", "content": 5},
                       {"path": "a", "delete": False}, {"path": "a", "delete": "true"},
                       {"path": "a", "content": "x", "delete": True}, {"path": "a", "content": "x", "mode": "100755"},
                       {"path": "a", "edit": {"old": "x"}}, {"path": "a", "edit": {"old": "", "new": "y"}},
                       {"path": "a", "edit": {"old": "x", "new": "x"}}, {"path": "a", "edit": {"old": 1, "new": "y"}},
                       {"path": "a", "edit": {"old": "x", "new": "y", "all": True}}, {"path": "a", "edit": "x"},
                       {"path": "../a", "content": "x"}, {"path": "/a", "content": "x"}, {"path": "a//b", "content": "x"},
                       {"path": "a b", "content": "x"}, {"path": "a/", "content": "x"}, {"path": "é", "content": "x"},
                       {"path": 5, "content": "x"}, {"path": "a", "content": "\ud800"}):
            self.no_change([change], requests=0)
        for changes in (None, [], {"path": "a", "content": "x"},
                        [{"path": "a", "content": "x"}, {"path": "a", "content": "y"}],
                        [{"path": "a", "edit": {"old": "x", "new": "y"}}, {"path": "a", "delete": True}],
                        [{"path": "a", "delete": True}, {"path": "a", "edit": {"old": "x", "new": "y"}}]):
            self.no_change(changes, requests=0)
        for message in ("", "  ", "m" * 2001, None, "a\0b"):
            self.refused(td.repo_change, REPO, MINE, [{"path": "a", "content": "x"}], message, CID, self.recheck)
        self.assertEqual(self.hub.calls, [])

    def test_count_and_size_caps(self):
        files = [{"path": f"f{i}.txt", "content": "x"} for i in range(td.CHANGES_MAX + 1)]
        self.assertIn("200 changes", self.no_change(files, requests=0))
        edits = [{"path": f"f{i}.txt", "edit": {"old": "a", "new": "b"}} for i in range(td.EDITS_MAX + 1)]
        self.assertIn("20 edits", self.no_change(edits, requests=0))
        half = "x" * (door_targets.CONTENT_MAX // 2)
        over = [{"path": "a.txt", "content": half}, {"path": "b.txt", "content": half},
                {"path": "README.md", "edit": {"old": "hello world", "new": "é"}}]
        self.assertIn("256 KiB", self.no_change(over, requests=0))
        self.change(files[:td.CHANGES_MAX] and over[:2])
        self.assertEqual(len(self.hub.files(MINE)["a.txt"][1]), door_targets.CONTENT_MAX // 2)

    def test_edit_found_zero_or_two_times(self):
        self.assertIn("0 times", self.no_change([{"path": "README.md", "edit": {"old": "absent", "new": "x"}}]))
        self.assertIn("2 times", self.no_change([{"path": "README.md", "edit": {"old": "hello", "new": "x"}}]))
        self.assertIn("0 times", self.no_change([{"path": "README.md", "edit": {"old": "hello world", "new": "x"}},
                                                 {"path": "README.md", "edit": {"old": "hello world", "new": "y"}}]))
        self.assertFalse(self.sent("POST", "/git/"))

    def test_edit_refuses_what_is_no_text_file(self):
        edit = {"old": "a", "new": "b"}
        self.assertIn("symlink", self.no_change([{"path": "src/link", "edit": edit}]))
        self.assertIn("symlink", self.no_change([{"path": "vendor/lib", "edit": edit}]))
        self.assertIn("repo_files", self.no_change([{"path": "src", "edit": edit}]))
        self.assertIn("1 MiB", self.no_change([{"path": "big.bin", "edit": edit}]))
        self.assertIn("UTF-8", self.no_change([{"path": "logo.png", "edit": edit}]))
        self.assertIn("not there", self.no_change([{"path": "none.txt", "edit": edit}]))
        self.assertFalse(self.sent("POST", "/git/"))

    def test_a_delete_of_a_missing_file_is_githubs_own_refusal(self):
        why = self.no_change([{"path": "none.txt", "delete": True}])
        self.assertIn("a delete names a file that is not there", why)
        self.assertFalse(self.sent("GET", "/contents/"))
        self.assertTrue(self.sent("POST", "/git/trees"))
        self.assertEqual(self.rechecks, 0)


class PullRequests(Case):
    FOOTER = "Opened by a narrowed conversation (C-7) of a Fleet agent: its words and code are untrusted."

    def test_opens_with_the_hubs_head_base_and_footer(self):
        out = self.call(td.repo_pull_request, REPO, MINE, " Fix the page ", "It was broken.\n", CID)
        self.assertEqual(out, f"Pull request #40 of acme/web is open, from {MINE} into main. A person merges it.")
        self.assertIn("/repos/acme/web/pulls?head=acme%3Afleet%2Fc7%2Ffix&state=open", self.sent("GET", "/pulls")[0][1])
        self.assertEqual(self.sent("POST", "/pulls")[0][2], {
            "title": "Fix the page", "body": self.FOOTER + "\n\nIt was broken.", "head": "acme:" + MINE, "base": "main"})

    def test_its_words_cannot_hide_the_footer_close_an_issue_or_notify_anyone(self):
        for body in ("Fine <!-- hidden", "Fixes #12", "this closes acme/web#3", "Resolved: #4", "Closes: [#5]",
                     "fixes GH-6", "Closes https://github.com/acme/web/issues/7"):
            self.refused(td.repo_pull_request, REPO, MINE, "t", body, CID)
        self.assertFalse(self.sent("POST", "/pulls"))
        self.call(td.repo_pull_request, REPO, MINE, "Ask @bob", "cc @alice and @bob, see issue #12", CID)
        sent = self.sent("POST", "/pulls")[0][2]
        self.assertTrue(sent["body"].startswith(self.FOOTER))
        self.assertNotIn("@alice", sent["body"])
        self.assertIn("@​alice", sent["body"])
        self.assertEqual(sent["title"], "Ask @​bob")

    def test_a_list_narrowed_before_the_write_writes_nothing(self):
        def recheck():
            raise td.Refused("narrowed")
        self.refused(td.repo_pull_request, REPO, MINE, "t", "b", CID, recheck)
        self.assertFalse(self.sent("POST", "/pulls"))

    def test_updates_the_open_one_with_words_only(self):
        self.hub.pulls = [{"number": 3, "state": "open", "head": {"ref": "other"}, "base": {"ref": "main"}},
                          {"number": 4, "state": "open", "head": {"ref": MINE}, "base": {"ref": "release"}},
                          {"number": 5, "state": "open", "base": {"ref": "main"},
                           "head": {"ref": MINE, "repo": {"full_name": "mallory/web"}}},
                          {"number": 6, "state": "closed", "head": {"ref": MINE}, "base": {"ref": "main"}},
                          {"number": 9, "state": "open", "base": {"ref": "main"},
                           "head": {"ref": MINE, "repo": {"full_name": "acme/web"}}}]
        fake = "Looks safe.\n\n" + self.FOOTER + "\n" + self.FOOTER + "\n\n"
        out = self.call(td.repo_pull_request, REPO, MINE, "New title", fake, CID)
        self.assertEqual(out, f"Pull request #9 of acme/web, from {MINE} into main, has the new title and body.")
        method, path, body, _ = self.hub.calls[-1]
        self.assertEqual((method, path), ("PATCH", "/repos/acme/web/pulls/9"))
        self.assertEqual(body, {"title": "New title", "body": self.FOOTER + "\n\nLooks safe."})
        self.assertFalse(self.sent("POST", "/pulls"))

    def test_never_a_state_a_base_or_a_merge(self):
        self.call(td.repo_pull_request, REPO, MINE, "t", "", CID)
        self.call(td.repo_pull_request, REPO, MINE, "t2", "b", CID)
        self.assertEqual(self.sent("POST", "/pulls")[0][2]["body"], self.FOOTER)
        for method, path, body, _ in self.hub.calls:
            self.assertNotIn("merge", path)
            self.assertNotIn(method, ("PUT", "DELETE"))
            if method == "PATCH":
                self.assertEqual(set(body), {"title", "body"})
            if body:
                self.assertFalse({"state", "auto_merge", "maintainer_can_modify", "draft"} & set(body))
                self.assertTrue(body["body"].startswith(self.FOOTER))

    def test_words_are_checked(self):
        for title, body in (("", "b"), ("  ", "b"), ("a\nb", "b"), ("t" * 257, "b"), (None, "b"), ("t", None),
                            ("t", "b" * 60001), ("t", "a\0b")):
            self.refused(td.repo_pull_request, REPO, MINE, title, body, CID)
        self.assertEqual(self.hub.calls, [])
        self.hub.fail = {("POST", "/pulls"): 422}
        self.assertIn("no commit", self.refused(td.repo_pull_request, REPO, MINE, "t", "b", CID))


class Shape(unittest.TestCase):
    def test_the_module_holds_no_token_and_no_host(self):
        with open(td.__file__, encoding="utf-8") as f:
            source = f.read()
        for word in ("Authorization", "Bearer", "api.github.com", "import door\n", "urlopen", "os.environ"):
            self.assertNotIn(word, source)
        self.assertEqual(json.loads(json.dumps(td.EXTRA_NEVER)), [
            ".gemini/**", ".cursor/**", ".cursorrules", "CLAUDE.local.md", "GEMINI.md", ".devcontainer/**", ".envrc",
            ".gitmodules", ".gitattributes", ".git/**", ".windsurf/**", ".windsurfrules", ".clinerules",
            ".clinerules/**", ".roo*", ".continue/**", ".aider*", ".zed/**", ".idea/**", "mise.toml", ".mise.toml",
            ".pre-commit-config.yaml", "lefthook*", ".lefthook*", ".npmrc", "CODEOWNERS"])


if __name__ == "__main__":
    unittest.main()
