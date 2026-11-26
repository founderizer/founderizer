"""The owner's own MCP server (`owner_mcp.py`), against a fixture hub and never against a real fleet.

The whole claim of that server is that an agent with nothing but it can take a fleet from nothing to a machine with
an agent on it, and then read every check. `FromNothing` proves exactly that, end to end: a real MCP client over
standard input and output, the real claim listener of `hubsetup.py`, the real owner API of `hub.py` in process, and
the real join route for the machine that joins. `Install` proves the install path with a stand-in `ssh` that answers
as a machine does, because no test provisions a server, and `RootThroughSudo` runs the install and the join on the
stand-in server of test_hub_install, also as a user who is not root. `Refusals` and `NoSecret` prove what the server
must not do.
"""
import base64
import contextlib
import io
import json
import os
import pathlib
import re
import shlex
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tracemalloc
import types
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zlib
from unittest.mock import patch

import hashlib

import hub
import hubsetup
import owner_mcp
import test_servers
from test_hub_install import StandInServer
from test_servers import NEW, OWNER, STUDIO, Servers
from leftovers import ROOT

HERE = pathlib.Path(ROOT)
SHELLS = [sh for sh in ("/bin/sh", "/bin/dash") if os.access(sh, os.X_OK)]     # this machine's, Debian's and Ubuntu's
# A test that reads a file of the apps skips where their folder is not: this checkout has app/ beside the hub, and the
# published repository, which a person clones to run these tests, never has it (publish.py publishes no file of it).
needs_the_apps = unittest.skipUnless((HERE / "app").is_dir(),
                                     "the apps' folder app/ is not in this tree (the published repository has none)")


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(cls(name) for cls in (Admin, Boundary, FromNothing, McpServers, Refusals,
                                                    Install, Progress, RootThroughSudo, NoSecret, Shape, Table,
                                                    Parity, SecretGive, ShareStanding, ShareStandingNoWorker,
                                                    SignedGrantWords, SignedPoolWords, VaultReading, GoogleConnect,
                                                    FolderGrant, Cloud, CompanyLogoFile)
                              for name in cls.__dict__ if name.startswith("test_"))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Refused(Exception):
    """A tool that answered with `isError`: the hub's own words, or the server's."""


class Client:
    """One MCP client of `owner_mcp.py`, over standard input and output, as the owner's agent is. Its home is this
    test's own, so the server's saved hub address and client label are the test's and not this Mac's. A thread reads
    the server's output all the time, as Claude Code's client does, so that a test can send a request while a call
    runs: each message that came is in `said`, in its order, the notifications are in `notices` too, and `answer` takes
    the answer to one request. `every`: the seconds between two progress notifications of the server
    (owner_mcp.PROGRESS_EVERY), for a test that cannot wait 30 seconds."""

    def __init__(self, test, hub_base=None, path=None, every=None, session=None):
        self.home = pathlib.Path(tempfile.mkdtemp(prefix="fleet-owner-mcp-"))
        test.addCleanup(shutil.rmtree, str(self.home), True)
        env = dict(os.environ, HOME=str(self.home))
        env.pop("FOUNDERIZER_HUB", None)
        # the AI session that runs the server (owner_mcp.session_label): the test's own, never the one of the Claude
        # Code session that runs these tests
        env.pop("CLAUDE_CODE_SESSION_ID", None)
        if session:
            env["CLAUDE_CODE_SESSION_ID"] = session
        if hub_base:
            env["FOUNDERIZER_HUB"] = hub_base
        if path:
            env["PATH"] = path + os.pathsep + env.get("PATH", "")
        server = [sys.executable, str(HERE / "owner_mcp.py")]
        if every is not None:                       # the same server, with its own main
            server = [sys.executable, "-c", f"import sys; sys.path.insert(0, {str(HERE)!r}); import owner_mcp; "
                                            f"owner_mcp.PROGRESS_EVERY = {every!r}; sys.exit(owner_mcp.main())"]
        self.proc = subprocess.Popen(server, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, env=env, cwd=str(HERE))
        self.number = 0
        self.said, self.notices, self.answers = [], [], {}
        self.came = threading.Condition()
        self.ended = None                           # why the output of the server ended
        self.listener = threading.Thread(target=self.listen, name="mcp-client", daemon=True)
        self.listener.start()
        test.addCleanup(self.close)

    def listen(self):
        ended = "the server said nothing more and stopped"
        for line in self.proc.stdout:
            try:
                said = json.loads(line)
            except ValueError:
                ended = f"the server wrote a line that is not JSON: {line[:300]!r}"
                break
            with self.came:
                self.said.append(said)
                if isinstance(said, dict) and "method" in said and "id" not in said:
                    self.notices.append(said)
                else:
                    self.answers[said.get("id") if isinstance(said, dict) else tuple(a.get("id") for a in said)] = said
                self.came.notify_all()
        with self.came:
            self.ended = ended
            self.came.notify_all()

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=10)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            self.proc.kill()
            self.proc.wait(timeout=5)
        self.listener.join(5)
        for pipe in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            try:
                pipe.close()
            except (OSError, ValueError):
                pass

    def write(self, message):
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()

    def post(self, method, params=None, progress=False):
        """One request to the server, and its id, without its answer. `progress`: the request asks for progress, with
        its own id as the token, as Claude Code's client asks for each tool call (the MCP SDK's `onprogress`)."""
        self.number += 1
        message = {"jsonrpc": "2.0", "id": self.number, "method": method, "params": dict(params or {})}
        if progress:
            message["params"]["_meta"] = {"progressToken": self.number}
        self.write(message)
        return self.number

    def answer(self, mid, wait=None):
        """The answer to request `mid`. The notifications that came before it are in `notices` when this returns.
        `wait`: the seconds to wait for it, or None for as long as the server runs."""
        with self.came:
            self.came.wait_for(lambda: mid in self.answers or self.ended, wait)
            if mid in self.answers:
                return self.answers.pop(mid)
            ended = self.ended
        if not ended:
            raise AssertionError(f"no answer to request {mid} in {wait} seconds")
        raise AssertionError(f"{ended}: {self.proc.stderr.read()[-2000:]}")

    def send(self, method, params=None, notify=False, progress=False):
        """One message to the server, and its answer: `post` and `answer`. A notification has no answer."""
        if notify:
            self.write({"jsonrpc": "2.0", "method": method, "params": dict(params or {})})
            return None
        return self.answer(self.post(method, params, progress))

    def cancel(self, mid):
        """notifications/cancelled of request `mid`, as the MCP SDK sends it when its client ends a call: the user's
        Esc, or the client's own time limit."""
        self.send("notifications/cancelled", {"requestId": mid, "reason": "the client ended the call"}, notify=True)

    def progress(self, token):
        """The progress values that came for `token`, in their order."""
        return [n["params"]["progress"] for n in list(self.notices)
                if n.get("method") == "notifications/progress" and n.get("params", {}).get("progressToken") == token]

    def after_answer(self, mid):
        """The progress notifications for token `mid` that came after the answer to request `mid`: none, always."""
        said = list(self.said)
        at = next((n for n, m in enumerate(said) if isinstance(m, dict) and "method" not in m and m.get("id") == mid),
                  len(said))
        return [m for m in said[at + 1:] if isinstance(m, dict) and m.get("method") == "notifications/progress"
                and m.get("params", {}).get("progressToken") == mid]

    def start(self):
        answer = self.send("initialize", {"protocolVersion": owner_mcp.PROTOCOL, "capabilities": {},
                                          "clientInfo": {"name": "deterministic-test", "version": "1"}})
        self.send("notifications/initialized", notify=True)
        return answer["result"]

    def tools(self):
        return {t["name"]: t for t in self.send("tools/list")["result"]["tools"]}

    def call(self, _tool, /, _progress=False, **args):
        answer = self.send("tools/call", {"name": _tool, "arguments": args}, progress=_progress)
        result = answer["result"]
        text = result["content"][0]["text"]
        if result.get("isError"):
            raise Refused(text)
        return json.loads(text)


class WithServer(Servers):
    """A fixture hub that an MCP client can reach: `Servers` gives the git-backed team.json, the join route and the
    server service's routes, and its owner address is 127.0.0.1, which a local subprocess calls from."""

    def setUp(self):
        super().setUp()
        self.assertEqual(OWNER, "127.0.0.1")        # the subprocess is the owner only because it calls from here
        self.hub_base = self.base

    def client(self, **kw):
        return Client(self, **dict({"hub_base": self.hub_base}, **kw))

    def started(self, **kw):
        client = self.client(**kw)
        client.start()
        return client

    def direct(self, _tool, **args):
        """The same tool, called in this process instead of over standard input and output. The test process calls
        the fixture hub from 127.0.0.1 too, so it is the owner in exactly the same way. It is here for the one
        thing a subprocess cannot show: what the server does when a patched read gives it a stale team.json."""
        owner_mcp.TOOLS.update({t["name"]: t for t in owner_mcp.tools()})
        owner_mcp.GENERATION["db"] = None
        with patch.dict(os.environ, {"FOUNDERIZER_HUB": self.hub_base}), \
                patch.object(owner_mcp, "HOME", pathlib.Path(tempfile.mkdtemp(prefix="fleet-direct-"))) as home:
            self.addCleanup(shutil.rmtree, str(home), True)
            with patch.object(owner_mcp, "CLIENT_FILE", home / "client"), \
                    patch.object(owner_mcp, "HUB_FILE", home / "hub"):
                text, bad = owner_mcp.call_tool(_tool, args)
        if bad:
            raise Refused(text)
        return json.loads(text)


class Shape(WithServer):
    """What the server is before it does anything: a server an MCP client can list, and one hub to read."""

    def test_an_mcp_client_lists_the_tools_and_each_one_is_a_route_of_the_owner_api(self):
        client = self.client()
        hello = client.start()
        self.assertEqual(hello["serverInfo"]["name"], "founderizer-owner")
        self.assertEqual(hello["protocolVersion"], owner_mcp.PROTOCOL)
        self.assertEqual(hello["capabilities"]["tools"], {"listChanged": False})
        self.assertIn("owner API", hello["instructions"])
        tools = client.tools()
        self.assertEqual(set(tools), {t["name"] for t in owner_mcp.tools()})
        for name, t in tools.items():
            self.assertTrue(t["description"].strip(), name)
            self.assertEqual(t["inputSchema"]["type"], "object", name)
            self.assertFalse(t["inputSchema"]["additionalProperties"], name)
            for needed in t["inputSchema"]["required"]:
                self.assertIn(needed, t["inputSchema"]["properties"], f"{name}.{needed}")
        self.assertEqual(client.send("ping")["result"], {})
        self.assertEqual(client.send("resources/list")["result"], {"resources": []})
        self.assertEqual(client.send("prompts/list")["result"], {"prompts": []})
        self.assertIn("Method not found", client.send("nothing/here")["error"]["message"])

    def test_trigger_state_says_what_run_now_does(self):
        """Owner API 1.83: Run now of an agent's rule with a check runs the check first, and the tool says so."""
        text = {t["name"]: t["description"] for t in owner_mcp.tools()}["trigger_state"]
        for words in ("runs the check now", "only for what is new", "starts the rule's task now",
                      "check_now runs the check once and wakes nobody"):
            self.assertIn(words, text)

    # One hub route whose ui_command label is not its path: the label names the idempotency row, the path is this.
    LABEL_PATHS = {"/ui/attachment_keep": "/ui/attachments/{}/keep"}

    @staticmethod
    def norm(route):
        return re.sub(r"\{[^}]*\}", "{}", route).rstrip("/")

    @classmethod
    def hub_routes(cls):
        """Every owner command route of hub.py, by the label its own `ui_command` call gives, with the fields that
        route accepts and the handler's name. The hub is the list; nothing here is kept by hand."""
        src = (HERE / "hub.py").read_text()
        found = {}
        for m in re.finditer(r"\n    def (ui_\w+)\(self[^)]*\):(.*?)(?=\n    def |\Z)", src, re.S):
            name, body = m.group(1), m.group(2)
            label = re.search(r'ui_command\(\s*f?"([^"]+)"', body)
            if not label:
                continue
            fields = set()
            for pattern in (r"self\.only\(data,\s*\(([^)]*)\)", r"self\.integration_base\(data,\s*\(([^)]*)\)",
                            r"set\(data\)\s*-\s*\{([^}]*)\}"):
                for got in re.finditer(pattern, body):
                    fields |= {x.strip().strip("\"'") for x in got.group(1).split(",") if x.strip()}
            fields -= {"request_id", "db", "base_sha256"}
            route = cls.norm("/ui/" + label.group(1))
            found[cls.LABEL_PATHS.get(route, route)] = (name, {f for f in fields if f and " " not in f})
        return found

    def test_every_owner_command_route_is_a_tool_here_or_is_left_out_for_a_reason(self):
        """Does this server have all the admin actions? The hub's own `ui_command` calls are the list of owner
        command routes, so the answer is read from hub.py and not from a list kept by hand. A new owner route makes
        this fail until somebody decides whether it belongs here, which is the only way the answer stays true."""
        routes = self.hub_routes()
        mine = {self.norm(m.group(1)) for m in re.finditer(r'"(/ui/[^"]*)"', (HERE / "owner_mcp.py").read_text())}
        self.assertGreater(len(routes), 50, "the owner API should have more routes than this: check the pattern")
        missing = sorted(set(routes) - mine - set(owner_mcp.NOT_TOOLS))
        self.assertEqual(missing, [], f"owner routes that are neither a tool nor in NOT_TOOLS: {missing}")
        src = (HERE / "hub.py").read_text()
        for route, why in owner_mcp.NOT_TOOLS.items():      # and a reason that names no real route is stale
            self.assertTrue(why.strip(), route)
            if route in routes:
                continue
            # /ui/restore and /ui/owner/enroll read their own bodies instead of going through ui_command, so they
            # are found in the dispatch itself. A route in NOT_TOOLS that is in neither place is gone from the hub.
            parts = ", ".join(f'"{p}"' for p in route.strip("/").split("/") if p != "{}")
            whole = r"parts(?:\[:\d\])?\s*==\s*\[" + re.escape(parts) + r"\]"
            segs = route.strip("/").split("/")      # an id in the middle: its fixed parts around it, on one line
            middle = "{}" in segs[:-1] and r"parts\[:%d\]\s*==\s*\[%s\]" % (
                segs.index("{}"), re.escape(", ".join(f'"{p}"' for p in segs[:segs.index("{}")]))) + "".join(
                r".*parts\[%d\]\s*==\s*\"%s\"" % (i, re.escape(p)) for i, p in enumerate(segs)
                if i > segs.index("{}") and p != "{}")
            self.assertRegex(src, whole + (f"|{middle}" if middle else ""),
                             f"{route} is in NOT_TOOLS but is not an owner route any more")

    def test_every_field_an_owner_route_takes_can_be_sent_by_some_tool(self):
        """The drift a route list cannot see. A tool built with `plain` or `with_base` sends exactly the fields its
        own tuple names, so a field the hub gains is dropped in silence: the route still answers, and the setting
        the owner asked for is simply not there. This found `screen`, `runtime`, `vault` and `vault_create` on
        /ui/team/agents, four powers `agent_settings` named in its own words and could not send."""
        own = (HERE / "owner_mcp.py").read_text()
        sent = {}
        for m in re.finditer(r'(?:plain|with_base)\(\s*"(/ui/[^"]*)",\s*\(([^)]*)\)', own):
            route = self.norm(m.group(1))
            sent.setdefault(route, set()).update(
                {x.strip().strip("\"'") for x in m.group(2).split(",") if x.strip()})
            sent[route] |= set(re.findall(r"\{(\w+)\}", m.group(1)))     # a path variable rides in the path
        checked, gaps = 0, {}
        for route, (name, fields) in sorted(self.hub_routes().items()):
            if route in owner_mcp.NOT_TOOLS:
                continue
            if route in sent:                       # built from a field tuple: the tuple is the whole body
                missing = fields - sent[route]
            else:                                   # built by a run function of its own: the name must appear
                missing = {f for f in fields if f'"{f}"' not in own}
            checked += 1
            if missing:
                gaps[route] = (name, sorted(missing))
        self.assertGreater(checked, 40, "too few routes compared: check the patterns")
        self.assertEqual(gaps, {}, f"fields of an owner route that no tool can send: {gaps}")

    def test_what_this_server_repeats_from_the_hub_is_what_the_hub_says(self):
        """`owner_mcp.py` runs on the owner's Mac with the standard library alone, so it cannot import the hub's
        own names: it repeats them as text in `FROM_THE_HUB`, and the schemas are built from that one copy. This is
        what keeps the copy honest. It found `repo: read|write` after the hub gained `deploy`."""
        import lifecycle
        for name, repeated in owner_mcp.FROM_THE_HUB.items():
            module, _, attribute = name.partition(".")
            real = getattr({"hub": hub, "lifecycle": lifecycle}[module], attribute)
            self.assertEqual(tuple(repeated), tuple(real),
                             f"owner_mcp.FROM_THE_HUB[{name!r}] is not {name} any more")
        levels = dict(hub.RESOURCE_LEVELS)          # grant_access says every level in its own words
        words = next(t["description"] for t in owner_mcp.tools() if t["name"] == "grant_access")
        for kind, allowed in levels.items():
            for level in allowed:
                self.assertIn(level, words, f"grant_access does not name the {kind} level {level}")

    def test_every_page_of_fleet_read_is_a_get_route_the_hub_really_serves(self):
        """The one list this server keeps of the owner API. A page that names a route the hub does not serve would
        read as an empty fleet instead of a mistake, so the dispatch itself is the check: the GET dispatch only
        (`Handler.get`), and in it one condition with the route's length, every fixed part before its subject (three
        for /ui/mobile/chat/{agent}) and each fixed part after it (a page under /ui/mobile/ or /ui/tasks/<id>/ with a
        wrong part passed because another route had the same first two parts, or a POST route had the path). **And
        each page offers the words that its route reads, and no other** (PAGE_TAKES): a hub that records each word
        that a route reads gets every word of PAGE_QUERY. A word that a route did not read changed nothing, and the
        agent took the whole page for the narrowed one (`machines` read no `agent`, point 2 of the review of 20
        November 2026); a word left out is refused, and the agent cannot narrow the page. The schema offers those
        words and no other (it has no `name` for chat_link; its `since` is owner_chat's). A route that refuses its
        item before it reads its words, or reads one word only when another is absent, needs its own case here: the
        knowledge list has one file, so that the route reads `path` whether git gave the list in time or not."""
        dispatch = re.search(r"\n    def get\(self\):\n(.*?)\n    def ", (HERE / "hub.py").read_text(), re.S).group(1)
        read, page_now = {}, [None]

        class Recorded(dict):
            def get(self, key, default=None):
                read.setdefault(page_now[0], set()).add(key)
                return super().get(key, default)

            def __getitem__(self, key):
                read.setdefault(page_now[0], set()).add(key)
                return super().__getitem__(key)

            def __contains__(self, key):
                read.setdefault(page_now[0], set()).add(key)
                return super().__contains__(key)
        route = hub.Handler.route

        def recorded(handler):
            parts, words = route(handler)
            return parts, Recorded(words)
        query = {word: "1" if word in ("after", "before", "since", "limit") else "manager"
                 for word in owner_mcp.PAGE_QUERY}
        listed = [{"path": "knowledge/owner/none.md", "scope": "owner"}]
        with patch.object(hub.Handler, "route", recorded), patch.object(hub, "knowledge_entries", lambda: listed):
            for page, (path, about) in owner_mcp.PAGES.items():
                parts = [p for p in path.split("/") if p]
                self.assertTrue(about.strip(), page)
                subject = next((i for i, p in enumerate(parts) if p.startswith("{")), None)
                if subject is None:
                    found = re.search(r'parts == \[' + ", ".join(f'"{p}"' for p in parts) + r'\]', dispatch)
                else:
                    head = re.escape(f"len(parts) == {len(parts)} and parts[:{subject}] == [") + \
                        ", ".join(f'"{p}"' for p in parts[:subject]) + r"\]"
                    tail = "".join(rf'(?=.*parts\[{i}\] (== "{p}"|in \([^)]*"{p}"))' for i, p in enumerate(parts)
                                   if i > subject)
                    found = re.search(head + tail, dispatch)
                self.assertTrue(found, f"{page}: the hub has no GET route {path}")
                page_now[0] = page
                address = path.replace("{id}", "1").replace("{agent}", "manager").replace("{name}", "nobody")
                with contextlib.suppress(urllib.error.HTTPError):
                    urllib.request.urlopen(self.base + address + "?" + urllib.parse.urlencode(
                        dict(query, db="test-generation")), timeout=30).close()
                self.assertEqual(sorted(read.get(page, set()) & set(owner_mcp.PAGE_QUERY)),
                                 sorted(owner_mcp.PAGE_TAKES.get(page, ())), f"{page}: the words that {path} reads")
        self.assertLessEqual(set(owner_mcp.PAGE_TAKES), set(owner_mcp.PAGES))
        # The schema has no `name` in this release: see PAGE_QUERY's comment.
        schema = next(t for t in owner_mcp.tools() if t["name"] == "fleet_read")["inputSchema"]["properties"]
        self.assertEqual(set(schema), {"page"} | {w for page in owner_mcp.PAGES for w in owner_mcp.page_words(page)} - {"name"})
        self.assertEqual(schema["since"], {"type": "number"})       # owner_chat's cursor is a time: an integer cuts it

    def test_without_a_hub_every_tool_says_how_to_get_one(self):
        client = self.client(hub_base=None)
        client.start()
        self.assertIsNone(client.call("which_hub")["hub"])
        for name, args in (("fleet_overview", {}), ("fleet_read", {"page": "state"}), ("send_message", {"text": "x"}),
                           ("take_release", {})):
            with self.assertRaises(Refused) as caught:          # each with its own words: fleet_read refuses others
                client.call(name, **args)
            self.assertIn("does not know a hub yet", str(caught.exception))
            self.assertIn("install_hub", str(caught.exception))


class FromNothing(WithServer):
    """Nothing to a machine with an agent on it, and then every check — with one MCP server and nothing else."""

    def claim_listener(self):
        """The real claim listener of `hubsetup.py`, on a port of its own, with one code. It answers once and stops,
        exactly as it does at the end of a hub install."""
        raw, shown = hubsetup.new_code()
        port = free_port()
        # The listener binds here, and says the hub's own address, which is another machine: the claim refuses a
        # code that comes from the hub itself, so the owner's Mac and the hub are never the same address.
        server = hubsetup.ClaimServer(("127.0.0.1", port), "127.0.0.2", port,
                                      hashlib.sha256(raw.encode()).hexdigest())
        server.timeout = 1
        self.addCleanup(server.server_close)

        def serve():
            end = time.monotonic() + 30
            while server.owner is None and time.monotonic() < end:
                server.handle_request()
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        return shown, port, server

    def test_an_agent_with_only_this_server_claims_a_hub_adds_a_machine_and_puts_an_agent_on_it(self):
        client = self.started()
        code, claim_port, listener = self.claim_listener()

        # 1. The claim: the one-time code goes back from this Mac, and the address of that call is the owner's.
        claimed = client.call("claim_hub", address="127.0.0.1", claim_code=code, claim_port=claim_port,
                              port=int(self.base.rsplit(":", 1)[1]))
        self.assertEqual(listener.owner, "127.0.0.1")
        self.assertEqual(claimed["hub"], self.base)
        self.assertEqual(claimed["generation"], "test-generation")
        self.assertEqual((client.home / ".founderizer" / "hub").read_text().strip(), self.base)
        self.assertEqual(client.call("which_hub")["reads_owner_api"], True)

        # 2. It reads the fleet it now owns.
        seen = client.call("fleet_overview")
        self.assertEqual(seen["hub"], self.base)
        self.assertEqual({a["name"] for a in seen["agents"]}, {"manager", "vps", "studio", "lead"})
        self.assertEqual(seen["health"]["db"], "test-generation")
        self.assertIn("servers", seen["features"])

        # 3. Add a machine: the hub's own one-time join line, which that machine then runs.
        line = client.call("add_machine", kind="mac")
        self.assertEqual((line["name"], line["kind"]), ("", "mac"))
        self.next_name = "mini"                 # the machine's name in Tailscale, which the join takes
        self.assertIn("FLEET_JOIN=", line["line"])
        self.assertRegex(line["code"], r"^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$")
        self.assertEqual(self.join(line["code"], source=NEW, kind="mac", user="dana")[0], 200)
        self.assertEqual(self.reading("mini", source=NEW)[0], 200)

        after = client.call("fleet_read", page="servers")
        mini = {s["name"]: s for s in after["servers"]}["mini"]
        self.assertEqual((mini["kind"], mini["address"], mini["available"]), ("mac", NEW, True))
        self.assertEqual(mini["agents"], [])

        # 4. An agent on it: one commit of team.json and its profile, and the install job.
        made = client.call("add_agent", server="mini", agent="scout", runtime="claude", role="worker",
                           reports_to="manager", spelling="ScOut")
        self.assertEqual((made["agent"], made["server"], made["runtime"]), ("scout", "mini", "claude"))
        self.assertEqual(self.origin_team()["agents"]["scout"]["machine"], "mini")
        # the name as the owner typed it reaches the hub (owner feature agent_spelling), and the overview gives it, so
        # that the client names the agent as the owner reads it. Bugs: the tool drops the field, or the overview does
        self.assertEqual(self.origin_team()["agents"]["scout"]["spelling"], "ScOut")
        listed = {a["name"]: a for a in client.call("fleet_overview")["agents"]}
        self.assertEqual((listed["scout"].get("spelling"), "spelling" in listed["manager"]), ("ScOut", False))
        self.assertEqual(self.origin_team()["agents"]["scout"]["active"], False)
        self.assertIn("scout", [p["agent"] for p in client.call("fleet_read", page="profiles")["profiles"]])
        with_agent = {s["name"]: s for s in client.call("fleet_read", page="servers")["servers"]}["mini"]
        self.assertEqual(with_agent["agents"], ["scout"])
        self.assertEqual(with_agent["job"]["kind"], "install")
        self.assertEqual(with_agent["job"]["agent"], "scout")

        # 5. Turning it on is the owner's own last step, and the hub holds it until that machine has checked
        #    itself. The refusal says what is still missing, so the agent can see it and act on it.
        with self.assertRaises(Refused) as caught:
            client.call("activate_agent", agent="scout", active=True)
        self.assertIn("ScOut cannot be activated yet.", str(caught.exception))     # by the owner's spelling
        left = json.loads(str(caught.exception).split("\n", 1)[1])["missing"]
        self.assertEqual({item["kind"] for item in left}, {"machine", "check"})
        self.assertIn("Check this server", " ".join(item["detail"] for item in left))
        self.assertEqual(self.origin_team()["agents"]["scout"]["active"], False)

        # And an agent that is already on is turned off through the same route, in one commit of team.json.
        off = client.call("activate_agent", agent="studio", active=False)
        self.assertEqual([c["field"] for c in off["changed"]], ["active"])
        self.assertEqual(self.origin_team()["agents"]["studio"]["active"], False)
        self.assertEqual([a["active"] for a in client.call("fleet_read", page="state")["agents"]
                          if a["name"] == "studio"], [False])

    def test_it_reads_every_check_afterwards(self):
        """Every page of the owner API this server names, on a fleet that has a machine, an agent, a goal, a duty
        and a Needs-you item. A page about a thing that does not exist must still reach its route and come back with
        the hub's own words, never with a transport failure or a 403."""
        client = self.started()
        self.joined("mini", kind="mac", source=NEW)
        client.call("add_agent", server="mini", agent="scout", runtime="claude", role="worker")
        goal, duty, need = self.some_work()
        reached, missing = {}, {}
        for page, (path, _) in owner_mcp.PAGES.items():
            args = {"page": page}
            if "{id}" in path:
                args["id"] = {"goal": goal, "responsibility": duty}.get(page, 1)
            if "{agent}" in path:
                args["agent"] = "manager"
            if "{name}" in path:
                args["name"] = "nothing"        # no chat app account on this fleet: the hub's own 404
            if page == "knowledge":
                args["path"] = "knowledge/owner/none.md"
            if page in ("agent_messages", "kpis"):
                args["agent"] = "manager"
            try:
                reached[page] = client.call("fleet_read", **args)
            except Refused as e:
                missing[page] = str(e)
        for page, words in missing.items():                 # a route that answered, about a thing that is not there
            self.assertRegex(words, r"\((400|404)\)", f"{page}: {words}")
        # Only a page about one named thing may be missing on this fleet, and every list must come back.
        self.assertLessEqual(set(missing), {"trigger", "conversation", "events", "artifacts", "knowledge",
                                            "chat_link"}, missing)
        self.assertEqual(set(reached) | set(missing), set(owner_mcp.PAGES))
        self.assertLessEqual({"state", "machines", "servers", "team", "capacity", "health", "releases", "checks",
                              "triggers", "responsibilities", "resources", "profiles", "people", "conversations",
                              "chat_apps", "devices", "goal", "responsibility", "agent_messages", "notes", "homes",
                              "owner_chat"},
                             set(reached))
        self.assertEqual(reached["state"]["db"], "test-generation")
        self.assertEqual(reached["goal"]["goal"]["id"], goal)
        self.assertEqual(reached["responsibility"]["responsibility"]["id"], duty)
        self.assertEqual([n["id"] for n in reached["state"]["needs"]], [need])
        self.assertEqual({s["name"] for s in reached["servers"]["servers"]}, {"hub", "vps", "mac-studio", "mini"})
        self.assertTrue(reached["capacity"]["agents"])
        self.assertIn("scout", {line["agent"] for line in reached["team"]["lines"]})
        self.assertEqual(reached["health"]["db"], "test-generation")
        self.assertIn("releases", reached["releases"])
        self.assertEqual(reached["machines"]["db"], "test-generation")
        self.assertIn("resources", reached["resources"])
        self.assertIn("roles", reached["people"])
        self.assertIn("limit", reached["devices"])

    def some_work(self):
        """A goal, a duty and a Needs-you item, written by the agents that write them: version 1.20 took the owner's
        own writers out, so the owner says what he wants and the manager records it."""
        said, error = hub.call_tool("manager", "update_goal", {
            "title": "One paying customer", "text": "Get the first customer to pay.",
            "request_id": str(uuid.uuid4())})
        self.assertFalse(error, said)
        made, error = hub.call_tool("manager", "set_duty", {
            "agent": "vps", "text": "Watch the shop and put its failures right.",
            "request_id": str(uuid.uuid4())})
        self.assertFalse(error, made)
        raised, error = hub.call_tool("manager", "raise_needs_you", {
            "title": "Which card", "why": "the shop needs one", "what_to_do": "name the card", "reason": "money"})
        self.assertFalse(error, raised)
        return (hub.q1("SELECT id FROM goals ORDER BY id DESC")["id"],
                hub.q1("SELECT id FROM responsibilities ORDER BY id DESC")["id"],
                hub.q1("SELECT id FROM needs ORDER BY id DESC")["id"])

    def test_it_sets_a_goal_by_saying_it_hands_out_access_and_answers_a_needs_you_item(self):
        client = self.started()
        goal, duty, need = self.some_work()

        receipt = client.call("send_message", text="I want one paying customer this month.")
        self.assertTrue(receipt["ok"])
        self.assertFalse(receipt["replayed"])
        self.assertIn("founderizer-mcp/1/", receipt["client"])
        # The review of 20 November 2026, issue 4: the hub keeps that an AI session sent it through the owner tools,
        # and the agent reads so
        self.assertIn("[owner via ai-session] I want one paying customer this month.",
                      hub.t_read_messages("manager", {}))
        self.assertEqual(tuple(hub.q1("SELECT hand, session FROM ui_requests WHERE request_id=?",
                                      (receipt["request_id"],))), ("tool", None))
        # a server that runs in a Claude Code session names that session on each command (X-Fleet-Session)
        named = self.started(session="0d8aa41c-95ba")
        sent = named.call("send_message", text="Go on with the export.")
        self.assertEqual(tuple(hub.q1("SELECT hand, session FROM ui_requests WHERE request_id=?",
                                      (sent["request_id"],))), ("tool", "claude-code/0d8aa41c-95ba"))
        with patch.dict(os.environ, {"CLAUDE_CODE_SESSION_ID": "not a name"}):
            self.assertIsNone(owner_mcp.session_label())

        # The answer carries a file, as a file that the owner drops on the item in the app does.
        source = pathlib.Path(tempfile.mkdtemp(prefix="fleet-answer-")) / "card.txt"
        self.addCleanup(shutil.rmtree, str(source.parent), True)
        source.write_bytes(b"Notes for the answer.\n")
        sent = client.call("attach_file", path=str(source))
        answered = client.call("answer_needs_you", need=need, answer="The company card.", attachments=[sent["id"]])
        self.assertTrue(answered["ok"])
        self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (need,))["answer"], "The company card.")
        self.assertEqual(hub.q1("SELECT r.need_id FROM attachments a JOIN ui_requests r ON r.request_id = a.message "
                                "WHERE a.id=?", (sent["id"],))["need_id"], need)
        # Both are on the page owner_chat, the owner's own chat with the agent, where its reply comes too. Bug: the
        # page names a wrong route, or there is none, and an agent that reads conversations (people on chat apps)
        # does not find its message and sends it again.
        chat = client.call("fleet_read", page="owner_chat", agent="manager")
        said = {i["id"]: i for i in chat["items"] if i["kind"] == "message"}
        self.assertEqual((said[receipt["request_id"]]["text"], said[receipt["request_id"]]["answer_to"]),
                         ("I want one paying customer this month.", None))
        self.assertEqual((said[answered["request_id"]]["text"], said[answered["request_id"]]["answer_to"]),
                         ("The company card.", need))
        # The review of 20 November 2026, issue 4: words to an item that has options are the hub's refusal, word
        # for word, and the item stays open; the option that the owner chose goes
        raised, error = hub.call_tool("manager", "raise_needs_you", {
            "title": "Window 80?", "why": "UK checks", "what_to_do": "press one", "reason": "money",
            "options": ["Go to 80", "Stay at 70"]})
        self.assertFalse(error, raised)
        nid = hub.q1("SELECT id FROM needs ORDER BY id DESC")["id"]
        with self.assertRaises(Refused) as caught:
            client.call("answer_needs_you", need=nid, answer="Not my decision: go ahead.")
        self.assertIn(hub.refusal_words.WORDS["card_words_from_tool"], str(caught.exception))
        self.assertIsNone(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"])
        self.assertTrue(client.call("answer_needs_you", need=nid, choice=1)["ok"])
        self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (nid,))["answer"], "Stay at 70")

        self.assertEqual(client.call("goal_state", id=goal, action="pause", note="later")["goal"]["state"], "paused")
        self.assertEqual(client.call("duty_state", id=duty, action="pause")["responsibility"]["state"], "paused")

        held = client.call("grant_access", resource="repo:acme/web", agent="vps", level="write")
        self.assertTrue(held["changed"])
        self.assertEqual(self.origin_team()["agents"]["vps"]["repos"], {"acme/web": "write"})
        client.call("grant_access", resource="repo:acme/web", agent="studio", level="read")
        self.assertEqual(self.origin_team()["agents"]["vps"]["repos"], {"acme/web": "write"})     # left as it stands
        self.assertEqual(self.origin_team()["agents"]["studio"]["repos"], {"acme/web": "read"})
        client.call("grant_access", resource="repo:acme/web", agent="vps", level=None)
        self.assertNotIn("repos", self.origin_team()["agents"]["vps"])
        self.assertEqual(self.origin_team()["agents"]["studio"]["repos"], {"acme/web": "read"})

        pooled = client.call("share_resource", resource="repo:acme/web", max="read")
        self.assertEqual(self.origin_team()["resources"]["repo:acme/web"], {"max": "read", "to": "workers"})
        self.assertTrue(pooled["ok"])
        self.assertEqual(client.call("take_resource", resource="repo:acme/web", agent="studio")["agent"], "studio")
        self.assertNotIn("repos", self.origin_team()["agents"]["studio"])

    def test_it_declines_a_secret_request_and_no_value_passes(self):
        """A secret request takes no words (a key typed there would reach the asker's conversation), but its decline
        carries no value, so the owner's agent sends it, and the asker reads "Not given" with his reason."""
        client = self.started()
        asked, error = hub.call_tool("manager", "request_secret", {
            "kind": "api_key", "env": "SHOP_API_KEY", "why": "the shop's orders", "give_to": {"vps": "use"},
            "details": "1. Open https://shop.example.com/keys. 2. Click New key, and copy it into the card."})
        self.assertFalse(error, asked)
        need = hub.q1("SELECT id FROM needs ORDER BY id DESC")["id"]
        with self.assertRaises(Refused) as words:
            client.call("answer_needs_you", need=need, answer="sk-in-words")
        self.assertIn("takes no answer in words", str(words.exception))
        declined = client.call("decline_secret_request", need=need, reason="Not this one")
        self.assertTrue(declined["ok"])
        self.assertIsNotNone(hub.q1("SELECT answered FROM needs WHERE id=?", (need,))["answered"])
        self.assertIn("Not given: Not this one", hub.t_read_messages("manager", {}))
        with self.assertRaises(Refused) as again:
            client.call("decline_secret_request", need=need)
        self.assertIn("already answered", str(again.exception))

    def test_it_takes_a_backup_to_this_mac_and_tells_the_hub_it_is_saved(self):
        """The copy goes into a file on this Mac as it arrives, in parts, and that file has the hub's own SHA-256 before
        the hub is told that the copy is kept: a copy of 12 MiB of records that do not pack is kept with a peak of
        Python's memory of a few MiB, the hub's side of this process included, and no passing file stays beside it.
        A copy that does not arrive within COPY_TOTAL gets the words that send the owner to Save copy in the app, the
        hub is not told, and nothing stays. The tool never adds the fleet's access key, so it tells the hub that its copy
        has none, and its result says so (the audit's finding 1, 24 November 2026). The bugs that it catches: the tool
        reads the whole copy into memory again, under a limit of its size, which a fleet passes (the owner, 22 November
        2026: "why is there a backup limit? it shouldn't?"); a copy past the time of one tool call that the agent reads
        as a lost call, with no way on; a copy with no key that clears the hub's warning, or that the agent takes for
        one that gives a new Mac the servers back."""
        client = self.started()
        where = pathlib.Path(tempfile.mkdtemp(prefix="fleet-copy-"))
        self.addCleanup(shutil.rmtree, str(where), True)
        confirmed = lambda: json.loads(hub.kv_get("backup_makers"))["command"]["sha256"]     # noqa: E731
        taken = client.call("take_backup", path=str(where))
        first = pathlib.Path(taken["path"])
        self.assertTrue(first.exists())
        self.assertEqual(first.stat().st_size, taken["bytes"])
        self.assertEqual(hashlib.sha256(first.read_bytes()).hexdigest(), taken["sha256"])
        self.assertEqual((taken["keyed"], taken["note"]), (False, owner_mcp.COPY_NO_KEY))
        health = client.call("fleet_read", page="health")
        self.assertEqual((health["copies"]["command"]["sha256"], health["copies"]["command"]["keyed"]),
                         (taken["sha256"], False))
        self.assertIsNone(health["backup"])                             # no copy with the key answers the warning
        self.assertIn("backup_missing", [w["kind"] for w in health["warnings"]])
        hub.q("CREATE TABLE ballast(x BLOB)")
        for _ in range(12 * 16):
            hub.q("INSERT INTO ballast VALUES(?)", (os.urandom(64 * 1024),))
        parts, real = [], owner_mcp.one_read

        def counted(answer, size):          # the length of each part of a copy's body, and not the part
            part = real(answer, size)
            if size == 1 << 20:
                parts.append(len(part))
            return part
        tracemalloc.start()
        try:
            with patch.object(owner_mcp, "one_read", counted):
                taken = self.direct("take_backup", path=str(where / "larger.zip"))
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        saved = where / "larger.zip"
        self.assertEqual((taken["path"], saved.stat().st_size), (str(saved), taken["bytes"]))
        self.assertGreater(taken["bytes"], 12 << 20)
        self.assertGreater(len([n for n in parts if n]), 1)       # the body came in more than one part
        digest = hashlib.sha256()
        with open(saved, "rb") as f:
            for piece in iter(lambda: f.read(1 << 20), b""):
                digest.update(piece)
        self.assertEqual((digest.hexdigest(), confirmed()), (taken["sha256"], taken["sha256"]))
        self.assertLess(peak, 6 << 20)
        with patch.object(owner_mcp, "COPY_TOTAL", 0), self.assertRaises(Refused) as slow:     # past its time
            self.direct("take_backup", path=str(where))
        self.assertEqual(str(slow.exception), owner_mcp.COPY_SLOW)
        self.assertIn("has no such limit of time.", owner_mcp.COPY_SLOW)    # and no claim of size: 2 GB is a bound
        self.assertEqual(confirmed(), taken["sha256"])
        self.assertEqual(sorted(path.name for path in where.iterdir()), sorted([first.name, "larger.zip"]))
        self.assertLess(owner_mcp.COPY_TOTAL, 30 * 60)          # under the 30 minutes of one tool call

    def test_a_machine_check_and_an_update_reach_the_machine_and_the_release_channel_is_asked(self):
        client = self.started()
        asked = client.call("check_machine", agent="vps")
        self.assertTrue(asked["changed"])
        self.assertEqual(asked["agent"], "vps")
        self.assertEqual(client.call("update_machine", agent="vps")["agent"], "vps")
        with patch("hub.start_release_work", return_value={"started": False, "why": "no channel"}) as channel:
            self.assertEqual(client.call("check_releases")["why"], "no channel")
            self.assertEqual(client.call("take_release")["why"], "no channel")
        self.assertEqual([c.args[0] for c in channel.call_args_list], [False, True])
        self.assertTrue(client.call("automatic_releases", automatic=True)["automatic"])

    def test_claim_teams_gives_the_key_to_the_hubs_claim_and_says_the_platforms_refusal(self):
        """claim_teams (Teams design 1, piece A1) gives the key of a purchase of Founderizer for Teams to the hub's
        POST /ui/teams/claim, which trades it with this fleet's id (here a stand-in of releases.claim: no account at
        the platform) and keeps the token; a refusal of the platform comes back in the platform's words, and the key is
        in no answer. Bug: an owner with no app on this computer has no way to turn Teams on, or the agent cannot tell
        a used key from a hub that does not answer."""
        client = self.started()
        key = "FZ-7QK2-M9XP-4RTB"
        refusal = {"token": None, "renews": None, "status": 409, "error": "used_key",
                   "says": "This key was used for another fleet."}
        with patch("hub.releases.claim", return_value=refusal) as claim, self.assertRaises(Refused) as said:
            client.call("claim_teams", claim_key=key)
        self.assertIn("This key was used for another fleet.", str(said.exception))
        self.assertEqual(claim.call_args.args[1:], (key, hub.fleet_id()))
        taken = dict(refusal, token="a.token", status=200, error=None, says=None)
        on = {"teams": {"on": True, "until": 1795000000, "renews": None, "ended": None}}
        with patch("hub.releases.claim", return_value=taken), patch("hub.teams_token", return_value=True), \
                patch("hub.store_entitlement") as stored, patch("hub.teams_state", return_value=on):
            answer = client.call("claim_teams", claim_key=key)
        stored.assert_called_once_with("a.token", None)
        self.assertEqual(answer["teams"], on["teams"])
        self.assertNotIn(key, json.dumps(answer))


class Refusals(WithServer):
    """What the server does when the hub refuses: the hub's own words, and never a way round them."""

    def test_a_mac_that_is_not_the_owner_is_told_what_that_means(self):
        hub.TEAM["addresses"]["owner"] = "127.0.0.2"
        client = self.started()
        with self.assertRaises(Refused) as caught:
            client.call("fleet_overview")
        self.assertIn("is not owner's machine", str(caught.exception))
        self.assertIn("the Mac whose address is", str(caught.exception))
        with self.assertRaises(Refused):
            client.call("send_message", text="Anything")
        self.assertEqual(self.count("ui_requests"), 0)

    def test_a_generation_that_moved_is_read_again_once_and_the_command_still_lands_once(self):
        client = self.started()
        self.assertEqual(client.call("fleet_read", page="machines")["db"], "test-generation")
        hub.kv_set("db_id", "second-generation")
        self.assertEqual(client.call("fleet_read", page="machines")["db"], "second-generation")
        receipt = client.call("send_message", text="After the restart.")
        self.assertFalse(receipt["replayed"])
        self.assertEqual(self.count("ui_requests"), 1)

    def test_the_same_request_id_sends_the_command_once(self):
        client = self.started()
        rid = str(uuid.uuid4())
        first = client.call("send_message", text="Only once.", request_id=rid)
        again = client.call("send_message", text="Only once.", request_id=rid)
        self.assertEqual(first["event_id"], again["event_id"])
        self.assertTrue(again["replayed"])
        self.assertEqual(self.count("events"), 1)
        with self.assertRaises(Refused) as caught:
            client.call("send_message", text="Something else.", request_id=rid)
        self.assertIn("already used", str(caught.exception))
        self.assertEqual(self.count("events"), 1)
        with self.assertRaises(Refused) as caught:
            client.call("send_message", text="x", request_id="not-a-uuid")
        self.assertIn("must be a UUID", str(caught.exception))

    def test_a_team_json_that_moved_under_a_command_is_the_hubs_own_conflict(self):
        with patch.object(owner_mcp, "team", return_value={"sha256": "0" * 64}):
            with self.assertRaises(Refused) as caught:
                self.direct("activate_agent", agent="vps", active=False)
        self.assertIn("team.json changed meanwhile; reload it", str(caught.exception))
        self.assertIn(owner_mcp.MOVED, str(caught.exception))
        self.assertNotIn("active", self.origin_team()["agents"]["vps"])

    def test_a_field_the_hub_refuses_comes_back_in_the_hubs_own_words(self):
        client = self.started()
        for name, args, words in (
                ("add_agent", {"server": "mini", "agent": "scout", "runtime": "grok", "role": "worker"},
                 "runtime must be codex or claude"),
                ("add_machine", {"kind": "pi"}, "kind must be linux or mac"),
                ("grant_access", {"resource": "repo:acme/web", "agent": "nobody", "level": "read"},
                 "no such agent"),
                ("sign_in_machine", {"agent": "vps", "runtime": "grok"}, "no Grok sign-in"),
                ("control_task", {"task": 999, "action": "pause"}, "no such task"),
                ("answer_needs_you", {"need": 999, "answer": "x"}, "does not exist"),
                ("clarify_needs_you", {"need": 999, "text": "x"}, "does not exist"),
                ("restore_notes", {"agent": "vps", "revision": 999}, "vps's notes have no revision 999"),
                ("forget_lesson", {"agent": "vps", "lesson": 999, "why": "x"}, "vps has no lesson M-999")):
            with self.assertRaises(Refused) as caught:
                client.call(name, **args)
            self.assertIn(words, str(caught.exception), name)

    def test_a_resource_of_a_kind_the_pool_does_not_have_is_refused_before_any_call(self):
        client = self.started()
        for rid in ("web", "database:prod", ":x", "repo:"):
            with self.assertRaises(Refused) as caught:
                client.call("grant_access", resource=rid, agent="vps", level="read")
            self.assertIn("resource must be <kind>:<what>", str(caught.exception))
        self.assertEqual(self.count("ui_controls"), 0)

    def test_a_hub_that_does_not_answer_is_said_plainly_and_nothing_is_repeated(self):
        client = self.client(hub_base="http://127.0.0.1:%d" % free_port())
        client.start()
        with self.assertRaises(Refused) as caught:
            client.call("fleet_overview")
        self.assertIn("did not answer", str(caught.exception))
        self.assertIn("private network", str(caught.exception))


class NoSecret(WithServer):
    """No password, no API key and no provider token through a tool, in or out."""

    SECRET_WORDS = ("password", "api_key", "apikey", "token", "secret", "key_value", "entitlement", "authkey",
                    "auth_key", "private_key", "client_secret")

    def test_no_tool_takes_a_secret_as_an_argument(self):
        for t in owner_mcp.tools():
            for field in t["inputSchema"]["properties"]:
                low = field.lower()
                if low == "authkey_file":               # the path of a file, which the tool never reads
                    self.assertIn("path", t["inputSchema"]["properties"][field]["description"].lower())
                    continue
                for word in self.SECRET_WORDS:
                    self.assertNotIn(word, low, f"{t['name']}.{field}")

    def test_the_routes_that_carry_a_credential_are_not_tools_of_this_server(self):
        """The owner API has routes that take a credential: the subscription token, the GitHub App key, a chat bot
        token, Google's client secret and the owner's own secret catalog. None of them is a tool here, because this
        server would be the thing that carried the value."""
        routes = [r for t in owner_mcp.tools() for r in [getattr(t["run"], "__name__", "")]]
        whole = (HERE / "owner_mcp.py").read_text()
        # NOT_TOOLS names these routes on purpose, to say they are left out and why, so that block is not a way to
        # reach one: the check is about the rest of the file, which is where a route would be called.
        start = whole.index("NOT_TOOLS = {")
        text = whole[:start] + whole[whole.index("\n}\n", start):]
        # The chat-app routes are named one by one, not by their prefix: the credential is the bot token and the
        # account is not one, so POST /ui/team/chat-apps, /pause, /link and /unlink are tools here and /token is
        # not (OWNER-MCP-BOUNDARY.md section 6).
        # Google's Connect is not among them since owner API 1.185: it carries no client secret any more, and its
        # code goes to connect_google's own listener and on to the hub, never into a field (class GoogleConnect).
        for route in ("/ui/releases/entitlement", "/ui/github-app", "/ui/secrets/add", "/ui/secrets/fingerprints",
                      "/ui/mcp/connect", "/ui/mcp/finish",
                      "/ui/chat-apps/{account}/token", "/token", "/ui/restore", "/ui/owner/enroll"):
            self.assertNotIn(f'"{route}"', text, route)
            self.assertNotIn(f"'{route}'", text, route)
        for t in owner_mcp.tools():         # and no nested field of a tool is one either, only its own prose
            for field in self.field_names(t["inputSchema"]):
                if field == "authkey_file":         # the path of a mode-600 file, which the tool never opens
                    continue
                for word in self.SECRET_WORDS:
                    self.assertNotIn(word, field.lower(), f"{t['name']}.{field}")
        self.assertTrue(routes)

    @classmethod
    def field_names(cls, schema):
        """Every property name of a schema, at any depth: a secret must not be a field of a nested object either."""
        out = []
        if isinstance(schema, dict):
            for name, under in (schema.get("properties") or {}).items():
                out.append(name)
                out += cls.field_names(under)
            out += cls.field_names(schema.get("items"))
        return out

    def test_a_registered_login_in_a_message_is_refused_by_the_hub_and_stored_nowhere(self):
        client = self.started()
        password, salt = "SyntheticPassword123", "synthetic-salt"
        hub.ins("INSERT INTO secrets(salt,hash,len) VALUES(?,?,?)",
                (salt, hashlib.sha256((salt + password).encode()).hexdigest(), len(password)))
        with self.assertRaises(Refused) as caught:
            client.call("send_message", text=password)
        self.assertIn("registered login", str(caught.exception))
        self.assertEqual(self.count("ui_requests"), 0)
        self.assertEqual(hub.leak_scan(), [])

    def test_the_sign_in_code_is_the_one_short_lived_code_it_carries_and_the_hub_keeps_no_copy(self):
        client = self.started()
        hub.touch("vps")                        # its helper has just reported, as a machine that can sign in has
        started = client.call("sign_in_machine", agent="vps", runtime="claude")
        self.assertTrue(started["changed"])
        lid = started["login"]["id"]
        # The machine's own helper has run the provider's flow and left the sign-in waiting for the owner's code,
        # which is the one state that takes one (test_machine_signin.py sets a parked job the same way).
        hub.q("UPDATE signin_jobs SET state='needs_owner' WHERE id=?", (lid,))
        hub.LIVE_LOGINS[lid] = {"wants_code": True, "url": "https://claude.ai/oauth/authorize?x=1"}
        self.addCleanup(hub.LIVE_LOGINS.pop, lid, None)
        given = client.call("sign_in_code", agent="vps", code="ABCD-EFGHJ")
        self.assertEqual(given["agent"], "vps")
        records = json.dumps([dict(r) for r in hub.q("SELECT * FROM ui_controls")])
        self.assertNotIn("ABCD-EFGHJ", records)
        self.assertIn(hashlib.sha256(b"ABCD-EFGHJ").hexdigest(), records)
        self.assertNotIn("ABCD-EFGHJ", json.dumps([dict(r) for r in hub.q("SELECT * FROM log")]))


class Install(unittest.TestCase):
    """The install over the owner's own SSH, with a stand-in `ssh` that answers as a machine does. No server is
    provisioned, so what is proved is the commands the server sends, in order, and that the Tailscale auth key
    travels on standard input and nowhere else."""

    MACHINE = {
        "id -un; id -u; sed": "root\n0\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nNAME=\"Ubuntu\"\n/usr/bin/systemctl",
        "id -un; id -u": "root\n0",
        "command -v git": "",
        "git clone": "",
        "rev-parse --short HEAD": "a1b2c3d\n/root/fleet-kit/hub.sh",
        "hub.sh --check": "Founderizer step 1 of 15: the system\nFounderizer step 15 of 15: verify\n",
        # No install runs. The read of the network has no entry, so it fails: the server is not on the private network
        # yet. The network step prints the port and the key of the server's SSH, and the server's address there.
        "ps -A -o args=": "",
        "cat > /root/fleet-authkey": "port 2222\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEhvc3RLZXlPZlRoZUh1Yg root@hub\n"
                                     "100.64.0.1\n",
        "setsid": "",
        "tail -n": "Founderizer: the owner claim is open on http://100.64.0.1:8765 for 30 minutes.\n"
                   "    FLEET_CLAIM=ABCD-EFGH-JKLM sh -c \"$(curl -fsS http://100.64.0.1:8765/claim)\"\n",
    }

    def setUp(self):
        self.MACHINE = dict(self.MACHINE)   # a test that changes a line changes its own copy, so the order of the tests counts for nothing
        self.calls = pathlib.Path(tempfile.mkdtemp(prefix="fleet-ssh-"))
        self.addCleanup(shutil.rmtree, str(self.calls), True)
        table = self.calls / "table.json"
        table.write_text(json.dumps(self.MACHINE))
        fake = self.calls / "ssh"
        # slow.json: by a part of a command, the seconds that it takes, or the name of a gate: a file in this folder
        # that the command waits for (at most 120 seconds), so that a test says when it ends. Each command that ends
        # writes a line in ended.jsonl.
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys, time\n"
            f"where = {str(self.calls)!r}\n"
            "table = json.load(open(os.path.join(where, 'table.json')))\n"
            "body = sys.stdin.buffer.read()\n"
            "args = sys.argv[1:]\n"
            "with open(os.path.join(where, 'calls.jsonl'), 'a') as log:\n"
            "    log.write(json.dumps({'args': args, 'stdin': body.decode('utf-8', 'replace')}) + '\\n')\n"
            "line = args[-1] if args else ''\n"
            "slow = os.path.join(where, 'slow.json')\n"
            "for key, seconds in (json.load(open(slow)) if os.path.exists(slow) else {}).items():\n"
            "    if key in line and isinstance(seconds, str):\n"
            "        end = time.time() + 120\n"
            "        while not os.path.exists(os.path.join(where, seconds)) and time.time() < end:\n"
            "            time.sleep(0.02)\n"
            "    elif key in line:\n"
            "        time.sleep(seconds)\n"
            "with open(os.path.join(where, 'ended.jsonl'), 'a') as log:\n"
            "    log.write(json.dumps({'args': args}) + '\\n')\n"
            "for key, says in table.items():\n"
            "    if key in line:\n"
            "        sys.stdout.write(says)\n"
            "        sys.exit(0)\n"
            "sys.stderr.write('no table entry for: ' + line)\n"
            "sys.exit(9)\n")
        fake.chmod(0o755)
        self.key = self.calls / "authkey"
        self.key.write_text("tskey-auth-SYNTHETIC-NOT-A-REAL-KEY\n")
        self.key.chmod(0o600)

    def sent(self):
        path = self.calls / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def ended(self):
        path = self.calls / "ended.jsonl"
        return len(path.read_text().splitlines()) if path.exists() else 0

    def ran(self, part):
        return sum(part in c["args"][-1] for c in self.sent())

    def client(self, hub_base=None):
        client = Client(self, hub_base=hub_base, path=str(self.calls))
        client.start()
        return client

    def gated(self, part):
        """A started client with 0.1 seconds between two progress notifications, whose commands that hold `part` wait
        until the test opens the gate (`release`). A test that stops early opens it before the client closes, so that
        no command waits after the test."""
        (self.calls / "slow.json").write_text(json.dumps({part: "gate"}))
        client = Client(self, path=str(self.calls), every=0.1)
        self.addCleanup(self.release)
        client.start()
        return client

    def release(self):
        (self.calls / "gate").touch()

    def until(self, test, what, wait=20):
        end = time.monotonic() + wait
        while not test():
            if time.monotonic() > end:
                self.fail(f"not in {wait} seconds: {what}")
            time.sleep(0.02)

    def test_it_installs_a_hub_with_the_steps_of_the_install_prompt_and_the_key_on_standard_input(self):
        """The steps of INSTALL-PROMPT.md A1 to A5, in order: the read of the machine, the code, the plan, the network
        step with the key on standard input, a read at the server's address on the private network, and the start
        there, which the server's own SSH keys check."""
        client = self.client()
        done = client.call("install_hub", host="203.0.113.9", ssh_user="root", servers=2,
                           source="https://example.invalid/founderizer.git", authkey_file=str(self.key))
        self.assertEqual((done["host"], done["address"]), ("203.0.113.9", "100.64.0.1"))
        self.assertIn("step 15 of 15: verify", done["plan"])
        self.assertIn("install_log", done["next"])
        lines = [" ".join(c["args"]) for c in self.sent()]
        self.assertTrue(all("BatchMode=yes" in line for line in lines), lines)
        self.assertTrue(all("root@203.0.113.9" in line for line in lines), lines)
        order = [next((k for k in ("id -u", "ps -A", "install git", "git clone", "rev-parse", "--check", "cat >",
                                   "tailscale status", "setsid") if k in line), None) for line in lines]
        self.assertEqual([k for k in order if k], ["id -u", "ps -A", "install git", "git clone", "rev-parse",
                                                   "--check", "tailscale status", "cat >", "id -u", "setsid"])
        known = client.home / ".founderizer" / "known_hosts"
        self.assertEqual(known.read_text(), "203.0.113.9@100.64.0.1 ssh-ed25519 "
                                            "AAAAC3NzaC1lZDI1NTE5AAAAIEhvc3RLZXlPZlRoZUh1Yg port=2222\n")
        for line in lines[-2:]:                     # the read at the private address, and the start there
            for option in ("-o HostName=100.64.0.1", "-o HostKeyAlias=203.0.113.9@100.64.0.1",
                           f'-o UserKnownHostsFile="{known}"', "-o StrictHostKeyChecking=yes", "-p 2222"):
                self.assertIn(f"{option} ", line)
        self.assertFalse(any("HostName=" in line or "-p " in line for line in lines[:-2]), lines)
        key = self.key.read_text()
        self.assertEqual([c["stdin"] for c in self.sent() if c["stdin"]], [key])    # on standard input, once
        self.assertTrue(all(key.strip() not in " ".join(c["args"]) for c in self.sent()))
        self.assertNotIn(key.strip(), json.dumps(done))

    def test_a_long_command_keeps_the_call_open_with_progress_when_the_client_asks_for_it(self):
        """**While a tool call runs, the server sends a progress notification for it every PROGRESS_EVERY seconds,
        when the request gave a progressToken** (MCP "Progress"), as Claude Code's client gives one with each tool
        call. Claude Code ends a call to a stdio MCP server that sends no answer and no progress for
        30 minutes (CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT). Then the agent gets the client's error and not this server's
        words, and the steps still run on the server. Until 11 November 2026 this server sent no progress, and the
        steps of one install_hub, or one join line, can be silent for longer than that. Here the server has 0.1
        seconds between two notifications, and the git step and the plan take 0.6 seconds each. Each notification has
        the token of the request, a progress that increases through both commands, and no words of its own. All of them
        come before the answer, and none after it. A request without a token gets none, as the specification says. And
        each SSH asks the server for a sign of life every 30 seconds, as the Mac app's install SSH does."""
        (self.calls / "slow.json").write_text(json.dumps({"command -v git": 0.6, "hub.sh --check": 0.6}))
        client = Client(self, path=str(self.calls), every=0.1)
        client.start()
        install = {"host": "203.0.113.9", "ssh_user": "root", "source": "https://example.invalid/f.git",
                   "authkey_file": str(self.key), "servers": 2}
        done = client.call("install_hub", _progress=True, **install)
        token, heard = client.number, list(client.notices)          # the token is the id of the request
        self.assertIn("step 15 of 15: verify", done["plan"])
        self.assertGreaterEqual(len(heard), 3, heard)
        self.assertEqual([(n["method"], sorted(n["params"]), n["params"]["progressToken"]) for n in heard],
                         [("notifications/progress", ["progress", "progressToken"], token)] * len(heard))
        values = [n["params"]["progress"] for n in heard]
        self.assertEqual(values, sorted(set(values)), "the progress increases with each notification")
        client.send("ping")                                         # no notification of that call after its answer
        self.assertEqual(client.notices, heard)
        client.notices.clear()
        again = client.call("install_hub", **install)
        self.assertIn("step 15 of 15: verify", again["plan"])
        self.assertEqual(client.notices, [], "a request without a token gets no progress")
        lines = [" ".join(c["args"]) for c in self.sent()]
        self.assertTrue(lines and all("-o ServerAliveInterval=30 " in line for line in lines), lines)

    LOG = {"name": "install_log", "arguments": {"host": "203.0.113.9", "ssh_user": "root"}}

    def test_a_call_that_the_agent_sends_while_another_runs_waits_with_progress_and_runs_after_it(self):
        """**The server reads its input also while a call runs, and it runs one call at a time.** Claude Code moves a
        call that runs longer than 2 minutes to the background, and then the agent can call a tool of this server
        again. Until 11 November 2026 `serve` read one message, answered it and then read the next. So that second call
        waited in the pipe with no progress, Claude Code ended it after 30 minutes, and the server still ran it later. A
        write tool could then run two times when the agent sent it again. Now the second call waits in the server, with
        progress from its reading, and it runs when the first one ends, never beside it. A request that is not a tool
        call, here a ping, gets its answer at once. At the end of the input, the calls that the server read still run
        and get their answers, as before. Here the command of install_log waits on a gate until the test opens it."""
        client = self.gated("tail -n")
        first = client.post("tools/call", self.LOG, progress=True)                 # two commands: id, then tail
        self.until(lambda: self.ran("tail -n") == 1, "the tail of the first call runs")
        second = client.post("tools/call", self.LOG, progress=True)
        self.assertEqual(client.answer(client.post("ping"), 10)["result"], {})
        self.until(lambda: len(client.progress(second)) >= 3, "progress for the call that waits")
        self.assertEqual((len(self.sent()), first in client.answers), (2, False), "a call ran beside the first one")
        client.proc.stdin.close()                                   # the end of the input
        self.release()
        for mid in (first, second):
            read = json.loads(client.answer(mid, 30)["result"]["content"][0]["text"])
            self.assertEqual(read["claim_code"], "ABCD-EFGH-JKLM")
            values = client.progress(mid)
            self.assertEqual(values, list(range(1, len(values) + 1)), "the progress of a call increases by one")
            self.assertEqual(client.after_answer(mid), [], "progress after the answer")
        self.assertEqual((len(self.sent()), self.ended()), (4, 4))
        answered = [m["id"] for m in client.said if "method" not in m]
        self.assertEqual(answered[-2:], [first, second])

    def test_a_cancel_drops_a_call_that_waits_so_that_it_never_runs(self):
        """**A cancel (notifications/cancelled) of a call that waits drops it: it never runs, its progress ends, and it
        gets no answer.** The MCP SDK sends a cancel when its client ends a call: the user's Esc, or the client's own
        time limit. So the agent can send the call again, and it runs once. Until 11 November 2026 the server read a
        cancel only after it had run the call that the cancel named."""
        client = self.gated("tail -n")
        first = client.post("tools/call", self.LOG)                                # two commands: id, then tail
        self.until(lambda: self.ran("tail -n") == 1, "the tail of the first call runs")
        second = client.post("tools/call", self.LOG, progress=True)
        self.until(lambda: client.progress(second), "progress for the call that waits")
        client.cancel(second)
        client.answer(client.post("ping"), 10)                      # the server reads in order: it read the cancel
        heard = len(client.progress(second))
        time.sleep(0.5)                                             # five periods of progress
        self.assertEqual(len(client.progress(second)), heard, "progress after the cancel")
        third = client.post("tools/call", self.LOG)
        self.release()
        client.answer(first, 30)
        client.answer(third, 30)
        self.assertNotIn(second, client.answers)
        self.assertEqual(len(self.sent()), 4, "the call that the client cancelled ran")

    def test_a_cancel_of_the_call_that_runs_lets_its_command_end_and_starts_no_other_step(self):
        """**A cancel of the call that runs ends its progress at once, and the call gets no answer. Its command over
        SSH goes on to its end**, because a join line works once and must not stop part way. **Then the call starts no
        other step**: here the read of the log never runs after the cancel of install_log during its first command. So
        a cancelled add_machine does not go on to its join line, and the agent can send it again without a second
        join. The next call runs when the command ends. Until 11 November 2026 the progress went on until the command
        ended, Claude Code logged each notification as an error for an unknown token, and the answer came."""
        client = self.gated("id -un")
        first = client.post("tools/call", self.LOG, progress=True)                 # two commands: id, then tail
        self.until(lambda: self.ran("id -un") == 1 and len(client.progress(first)) >= 2,
                   "progress for the call whose first command runs")
        client.cancel(first)
        client.answer(client.post("ping"), 10)                      # the server reads in order: it read the cancel
        heard = len(client.progress(first))
        time.sleep(0.5)                                             # five periods of progress
        self.assertEqual(len(client.progress(first)), heard, "progress after the cancel")
        self.assertEqual((len(self.sent()), self.ended()), (1, 0), "the first command of the call ended early")
        second = client.post("tools/call", self.LOG)
        self.release()
        read = json.loads(client.answer(second, 30)["result"]["content"][0]["text"])
        self.assertEqual(read["claim_code"], "ABCD-EFGH-JKLM")
        self.assertNotIn(first, client.answers)
        self.assertEqual((self.ran("id -un"), self.ran("tail -n")), (2, 1), "the cancelled call started a step")
        self.assertEqual(self.ended(), 3, "the command of the call that the client cancelled stopped part way")

    def test_it_takes_the_owners_choice_of_servers_and_gives_hub_sh_its_word(self):
        """**How many servers a fleet starts with is the owner's choice, and install_hub takes no default.** Until 14
        November 2026 it gave hub.sh no word, so the manager ran on the hub's own server with no question. Without
        `servers` it sends no command, and its refusal has both layouts and tells the agent to ask. With 2, both runs
        of hub.sh (the plan and the install) have the word FLEET_MANAGER_SERVER=later in front, which the Mac app sets
        too: the hub then has a manager with no server yet. With 1 neither has it, and `runtime` gives hub.sh the
        manager's provider."""
        client, reach = self.client(), {"host": "203.0.113.9", "ssh_user": "root",
                                        "source": "https://example.invalid/f.git", "authkey_file": str(self.key)}
        for bad in ({}, {"servers": 3}, {"servers": "2"}, {"servers": True}):
            with self.assertRaises(Refused) as caught:
                client.call("install_hub", **reach, **bad)
            said = str(caught.exception)
            self.assertEqual([part for part in ("servers must be 1 or 2", "1 server: the hub and the manager run on "
                                                "this one server", "2 servers: this server runs the hub and no agent",
                                                "Ask the owner which one", "Never choose for them",
                                                "Nothing on 203.0.113.9 was changed") if part not in said], [], said)
        for bad in ({"servers": 2, "runtime": "codex"}, {"servers": 1, "runtime": "grok"}):
            with self.assertRaises(Refused) as caught:
                client.call("install_hub", **reach, **bad)
            self.assertIn("only with servers 1", str(caught.exception))
        self.assertEqual(self.sent(), [])

        def hub_sh():
            return [" ".join(c["args"]).rpartition("root@203.0.113.9 ")[2] for c in self.sent()
                    if "sh /root/fleet-kit/hub.sh" in " ".join(c["args"]) and "ps -A" not in " ".join(c["args"])]
        done = client.call("install_hub", **reach, servers=2)
        ran = hub_sh()
        self.assertEqual(len(ran), 2, ran)
        self.assertIn("FLEET_MANAGER_SERVER=later sh /root/fleet-kit/hub.sh --check", ran[0])
        self.assertIn('setsid sh -c "FLEET_MANAGER_SERVER=later sh /root/fleet-kit/hub.sh < /dev/null', ran[1])
        self.assertEqual(done["servers"], 2)
        self.assertIn("move_agent", done["next"])
        plan = self.MACHINE["hub.sh --check"]           # the stand-in's plan, for the plan with an option too
        (self.calls / "table.json").write_text(json.dumps(dict(
            self.MACHINE, **{"hub.sh --runtime codex --check": plan, "hub.sh --port 9000 --check": plan})))
        done = client.call("install_hub", **reach, servers=1, runtime="codex")
        ran = hub_sh()[2:]
        self.assertEqual(len(ran), 2, ran)
        self.assertEqual([one for one in ran if "FLEET_MANAGER_SERVER" in one], [])
        self.assertIn("sh /root/fleet-kit/hub.sh --runtime codex --check", ran[0])     # the plan says the same provider
        self.assertIn('setsid sh -c "sh /root/fleet-kit/hub.sh --runtime codex < /dev/null', ran[1])
        self.assertEqual(done["servers"], 1)
        self.assertIn("NOT READY: runtime_signed_in", done["next"])
        self.assertIn("counts at a hub's first install", done["next"])
        client.call("install_hub", **reach, servers=1, port=9000)
        self.assertIn("sh /root/fleet-kit/hub.sh --port 9000 --check", hub_sh()[4])
        self.assertIn('setsid sh -c "sh /root/fleet-kit/hub.sh --port 9000 < /dev/null', hub_sh()[5])
        # The providers of `runtime` are hub.sh's own list, and no other.
        self.assertIn('case "$runtime" in ' + "|".join(owner_mcp.HUB_SH_RUNTIMES) + ") ;;",
                      (HERE / "hub.sh").read_text())
        listed = {one["name"]: one for one in owner_mcp.tools()}["install_hub"]
        self.assertIn("servers", listed["inputSchema"]["required"])
        self.assertEqual(listed["inputSchema"]["properties"]["servers"]["enum"], [1, 2])
        self.assertIn("Never choose for them", listed["description"])

    def test_it_gives_hub_sh_the_owners_name_for_the_manager(self):
        """**The manager's name is the owner's choice at a hub's first install.** The Mac app's first run asks for it on
        "Name your manager" and gives it to hub.sh as `--manager-name` (15 November 2026), so install_hub takes it too,
        as `manager_name`: both runs of hub.sh (the plan and the install) get the option, behind the other options and
        with the layout's word still in front. A name that hub.sh would refuse sends no command at all, because the
        hub renames a manager only while it has no server yet, and the refusal says the rule and repeats nothing of
        the name.
        Without the field the line is the line of before. The rule is hub.sh's own and hubsetup.py's."""
        client, reach = self.client(), {"host": "203.0.113.9", "ssh_user": "root", "servers": 1,
                                        "source": "https://example.invalid/f.git", "authkey_file": str(self.key)}
        for bad in ("j", "9lives", "-juno", "j" * 27, "ju no", "Ju No", "juno;id", "juno\nid", "$(id)", "owner", "Hub",
                    "vault", "work", "login-x", "vault-2", "", "  ", 7, True, ["juno"]):
            with self.assertRaises(Refused, msg=repr(bad)) as caught:
                client.call("install_hub", **reach, manager_name=bad)
            said = str(caught.exception)
            self.assertEqual([part for part in ("manager_name is the name that the owner chose for the fleet's manager",
                                                "2 to 26 characters a-z 0-9 -, a letter first", "login- or vault-",
                                                "renames a manager only while it has no server yet",
                                                "Nothing on 203.0.113.9 was changed") if part not in said], [], said)
            if isinstance(bad, str) and len(bad) > 3 and bad not in owner_mcp.MANAGER_NAMES_TAKEN:
                self.assertNotIn(bad.strip(), said)
        self.assertEqual(self.sent(), [])

        def hub_sh():
            return [" ".join(c["args"]).rpartition("root@203.0.113.9 ")[2] for c in self.sent()
                    if "sh /root/fleet-kit/hub.sh" in " ".join(c["args"]) and "ps -A" not in " ".join(c["args"])]
        plan = self.MACHINE["hub.sh --check"]           # the stand-in's plan, for the plan with the option too
        (self.calls / "table.json").write_text(json.dumps(dict(self.MACHINE, **{
            "hub.sh --manager-name juno --check": plan, "hub.sh --port 9000 --manager-name a-9 --check": plan,
            "hub.sh --runtime codex --manager-name " + "m" * 26 + " --check": plan})))
        # As the Mac app's page does, capital letters and spaces around the name do not count: the owner's "Juno".
        done = client.call("install_hub", **reach, manager_name=" Juno\n")
        ran = hub_sh()
        self.assertEqual(len(ran), 2, ran)
        self.assertIn("sh /root/fleet-kit/hub.sh --manager-name juno --check", ran[0])     # the plan names it too
        self.assertIn('setsid sh -c "sh /root/fleet-kit/hub.sh --manager-name juno < /dev/null', ran[1])
        self.assertIn("on a new hub the manager is juno", done["next"])
        self.assertIn("A hub that was there keeps the name that its manager has", done["next"])
        self.assertIn("is older than this option, the install stops and install_log says so", done["next"])
        done = client.call("install_hub", **dict(reach, servers=2), manager_name="a-9", port=9000)
        ran = hub_sh()[2:]
        self.assertIn("FLEET_MANAGER_SERVER=later sh /root/fleet-kit/hub.sh --port 9000 --manager-name a-9 --check", ran[0])
        self.assertIn('setsid sh -c "FLEET_MANAGER_SERVER=later sh /root/fleet-kit/hub.sh --port 9000 --manager-name a-9 '
                      '< /dev/null', ran[1])
        self.assertIn("the manager is a-9", done["next"])
        client.call("install_hub", **reach, runtime="codex", manager_name="m" * 26)
        self.assertIn("sh /root/fleet-kit/hub.sh --runtime codex --manager-name " + "m" * 26 + " --check", hub_sh()[4])
        self.assertIn('setsid sh -c "sh /root/fleet-kit/hub.sh --runtime codex --manager-name ' + "m" * 26
                      + " < /dev/null", hub_sh()[5])
        # Without the field: the line of before, and no word of a name.
        done = client.call("install_hub", **reach)
        self.assertEqual([one for one in hub_sh()[6:] if "--manager-name" in one], [])
        self.assertEqual(len(hub_sh()[6:]), 2)
        self.assertNotIn("manager's name", done["next"])

        # The rule is hub.sh's own, and hubsetup.py's manager_name takes and refuses the same names.
        script = (HERE / "hub.sh").read_text()
        self.assertIn("|".join((*owner_mcp.MANAGER_NAMES_TAKEN,
                                *(start + "*" for start in owner_mcp.MANAGER_NAME_STARTS_TAKEN)))
                      + ') stop "$name_rule" ;;', script)
        self.assertIn('[!a-z]*|*[!a-z0-9-]*) stop "$name_rule" ;;', script)
        self.assertIn('if [ "${#manager_name}" -lt 2 ] || [ "${#manager_name}" -gt 26 ]; then stop "$name_rule"; fi', script)
        self.assertEqual(owner_mcp.MANAGER_NAME.pattern, "[a-z][a-z0-9-]{1,25}")
        self.assertEqual(owner_mcp.MANAGER_NAMES_TAKEN, (*hub.RESERVED_AGENT_NAMES, *hubsetup.FLEET_OWN_NAMES))
        self.assertEqual(owner_mcp.MANAGER_NAME_STARTS_TAKEN, hubsetup.FLEET_OWN_STARTS)

        def takes(name):
            return bool(owner_mcp.MANAGER_NAME.fullmatch(name)) and name not in owner_mcp.MANAGER_NAMES_TAKEN \
                and not name.startswith(owner_mcp.MANAGER_NAME_STARTS_TAKEN)

        def installer_takes(name):
            try:
                return hubsetup.manager_name(name) == name
            except hubsetup.Stop:
                return False
        for name in ("juno", "a-9", "manager", "m" * 26, "m" * 27, "j", "ju", "Juno", "9lives", "-juno", "ju no",
                     "juno\n", "owner", "hub", "agents", "vault", "work", "login-x", "vault-2", "logins", "vaults", ""):
            self.assertEqual(takes(name), installer_takes(name), repr(name))
        listed = {one["name"]: one for one in owner_mcp.tools()}["install_hub"]
        self.assertNotIn("manager_name", listed["inputSchema"]["required"])
        # No pattern in the schema: the tool takes "Juno" as the app's page does, and a client that holds a call to
        # its schema must not refuse that.
        self.assertNotIn("pattern", listed["inputSchema"]["properties"]["manager_name"])
        self.assertIn("Juno names the manager juno", listed["inputSchema"]["properties"]["manager_name"]["description"])
        self.assertIn("Never choose it for them", listed["inputSchema"]["properties"]["manager_name"]["description"])

    def test_only_the_tools_that_read_say_that_they_read(self):
        """A client that asks its user before a tool that can write (Codex) reads each tool's readOnlyHint. Without
        one, Codex asked before each call, also before a read (14 November 2026). Five tools say that they only read:
        the four reads of the owner API, none of whose pages is a GET route that the hub counts as a write, and
        which_hub. Each other tool says false, install_log too: it opens the owner's SSH to a host that the agent
        names."""
        listed = [one for one in self.client().tools().values() if "annotations" in one]
        self.assertEqual(len(listed), len(owner_mcp.tools()))        # each tool that a client lists has them
        reads = sorted(one["name"] for one in listed if one["annotations"]["readOnlyHint"])
        self.assertEqual(reads, ["fleet_overview", "fleet_read", "search_history", "see_costs", "which_hub"])
        self.assertEqual([one["name"] for one in listed if set(one["annotations"]) != {"readOnlyHint"}
                          or not isinstance(one["annotations"]["readOnlyHint"], bool)], [])
        writes = [route for route, _what in owner_mcp.PAGES.values()
                  if hub.get_writes([part for part in route.split("/") if part])]
        self.assertEqual(writes, [])
        # No tool that reaches a server over SSH, writes a file on this Mac or sends a command says that it reads.
        self.assertEqual([name for name in ("install_hub", "install_log", "claim_hub", "add_machine", "use_hub",
                                            "read_attachment", "take_backup", "attach_file", "check_releases",
                                            "check_machine", "check_mcp_server") if name in reads], [])

    def test_it_refuses_an_auth_key_file_that_other_users_can_read_and_never_opens_it(self):
        client = self.client()
        self.key.chmod(0o644)
        with self.assertRaises(Refused) as caught:
            client.call("install_hub", host="203.0.113.9", ssh_user="root", servers=2,
                        source="https://example.invalid/f.git", authkey_file=str(self.key))
        self.assertIn("chmod 600", str(caught.exception))
        self.assertEqual(self.sent(), [])
        self.key.unlink()
        with self.assertRaises(Refused) as caught:
            client.call("install_hub", host="203.0.113.9", ssh_user="root", servers=2,
                        source="https://example.invalid/f.git", authkey_file=str(self.key))
        self.assertIn("cannot read", str(caught.exception))
        self.assertEqual(self.sent(), [])

    def test_a_host_or_user_that_would_not_be_one_argument_is_refused_before_any_command(self):
        client = self.client()
        for host, user in (("203.0.113.9; rm -rf /", "root"), ("203.0.113.9", "root; id"), ("", "root"),
                           ("203.0.113.9", "")):
            with self.assertRaises(Refused):
                client.call("install_log", host=host, ssh_user=user)
        self.assertEqual(self.sent(), [])

    def test_it_reads_the_claim_code_and_the_hub_address_out_of_the_install_log(self):
        client = self.client()
        read = client.call("install_log", host="203.0.113.9", ssh_user="root")
        self.assertEqual(read["claim_code"], "ABCD-EFGH-JKLM")
        self.assertEqual(read["hub_address"], "100.64.0.1")
        self.assertEqual(read["claim_port"], 8765)
        self.assertFalse(read["ready"])
        self.assertIsNone(read["stopped"])
        self.assertIn("claim_hub", read["next"])

    def test_a_hub_that_has_its_owner_makes_no_code_and_the_log_read_says_so(self):
        """**A user's report of 15 November 2026**: an install that runs again on a hub that has its owner waits for a
        claim code that the hub no longer makes. `hubsetup.py` says "this hub belongs to the Mac at <owner> already,
        so no code was made and nothing changed." and prints no FLEET_CLAIM= line. Until that day install_log
        answered "Read the log again in 20 seconds" for ever. Now it gives the owner's address as `owned_already`,
        tells the agent to call no claim_hub and to read fleet_overview, and says what a refusal there means. The
        same holds when the install ended and the sentence is above the lines that were read."""
        said = "Founderizer: this hub belongs to the Mac at 100.64.0.7 already, so no code was made and nothing changed.\n"
        table = dict(self.MACHINE, **{"tail -n": "Founderizer step 7 of 15: the owner claim\n" + said})
        (self.calls / "table.json").write_text(json.dumps(table))
        client = self.client()
        read = client.call("install_log", host="203.0.113.9", ssh_user="root")
        self.assertEqual(read["owned_already"], "100.64.0.7")
        self.assertIsNone(read["claim_code"])
        self.assertIsNone(read["stopped"])
        for part in ("has its owner already, the computer at 100.64.0.7", "Do not call claim_hub",
                     "read the log until it says READY, and then call use_hub with the hub's address",
                     "use_hub reads exactly that hub from this Mac", "refuses this Mac there (403)",
                     "another computer owns the hub, or this Mac's key for it is gone", "do not start the install again",
                     "No answer at all is no refusal"):
            self.assertIn(part, read["next"])
        self.assertNotIn("Read the log again in 20 seconds", read["next"])
        # fleet_overview reads the hub that this server knows already, which can be another one: it proves nothing here.
        self.assertNotIn("fleet_overview", read["next"])
        # Only an address of four numbers goes into the tool's own words; another text there stays in the log.
        odd = dict(self.MACHINE, **{"tail -n": said.replace("100.64.0.7", "$(reboot);x")})
        (self.calls / "table.json").write_text(json.dumps(odd))
        read = client.call("install_log", host="203.0.113.9", ssh_user="root")
        self.assertIs(read["owned_already"], True)
        self.assertNotIn("reboot", read["next"])
        self.assertIn("This hub has its owner already, so this install made no claim code", read["next"])
        # The install ended, and the sentence is above these lines: still no wait for a code.
        (self.calls / "table.json").write_text(json.dumps(dict(self.MACHINE, **{"tail -n": "READY\n"})))
        read = client.call("install_log", host="203.0.113.9", ssh_user="root")
        self.assertIsNone(read["owned_already"])
        self.assertTrue(read["ready"])
        self.assertIn("The install ended, and these lines of its log hold no claim code", read["next"])
        self.assertIn("Do not call claim_hub. Now call use_hub", read["next"])
        self.assertNotIn("read the log until it says READY", read["next"])
        # A code in the log comes first, as before, and a log with neither waits, as before.
        code = "Founderizer: the owner claim is open on http://100.64.0.1:8765 for 30 minutes.\n" \
               "    FLEET_CLAIM=ABCD-EFGH-JKLM sh -c \"$(curl -fsS http://100.64.0.1:8765/claim)\"\n"
        (self.calls / "table.json").write_text(json.dumps(dict(self.MACHINE, **{"tail -n": code})))
        self.assertIn("claim_hub with hub_address", client.call("install_log", host="203.0.113.9", ssh_user="root")["next"])
        (self.calls / "table.json").write_text(json.dumps(dict(self.MACHINE, **{"tail -n": "Founderizer step 3 of 15\n"})))
        self.assertIn("Read the log again in 20 seconds",
                      client.call("install_log", host="203.0.113.9", ssh_user="root")["next"])
        # The sentence is the installer's own: a change of its words there fails here.
        self.assertIn('say(f"this hub belongs to the Mac at {already} already, so no code was made and nothing changed.")',
                      (HERE / "hubsetup.py").read_text())
        self.assertTrue(owner_mcp.OWNED_ALREADY.search(said))
        self.assertIn("call no claim_hub", client.call(
            "install_hub", host="203.0.113.9", ssh_user="root", source="https://example.invalid/f.git",
            authkey_file=str(self.key), servers=2)["next"])

    def test_an_install_that_stopped_is_given_to_the_owner_and_nothing_is_tried_round_it(self):
        self.MACHINE["tail -n"] = "Founderizer install stopped: port 8765 is in use by another program.\n"
        (self.calls / "table.json").write_text(json.dumps(self.MACHINE))
        read = self.client().call("install_log", host="203.0.113.9", ssh_user="root")
        self.assertIn("port 8765 is in use", read["stopped"])
        self.assertIsNone(read["claim_code"])
        self.assertIn("Give the owner the reason", read["next"])

    def test_a_machine_that_is_not_one_of_the_three_systems_stops_the_install_before_it_changes_anything(self):
        self.MACHINE["id -un; id -u; sed"] = "root\n0\nPRETTY_NAME=\"Alpine Linux\"\nNAME=\"Alpine\""
        (self.calls / "table.json").write_text(json.dumps(self.MACHINE))
        with self.assertRaises(Refused) as caught:
            self.client().call("install_hub", host="203.0.113.9", ssh_user="root", servers=2,
                               source="https://example.invalid/f.git", authkey_file=str(self.key))
        self.assertIn("no systemctl", str(caught.exception))
        self.assertEqual(len(self.sent()), 1)

    def test_a_claim_code_that_is_not_one_is_refused_without_a_call(self):
        client = self.client()
        for code in ("", "short", "abcd-efgh-jklm!!", "A" * 40):
            with self.assertRaises(Refused) as caught:
                client.call("claim_hub", address="100.64.0.1", claim_code=code)
            self.assertIn("claim_code must be", str(caught.exception))


class Lines:
    """An output in place of the client's pipe, for `Calls` in this process: each message that the server writes is in
    `said`. `broken`: each write fails as on a pipe that the client closed, and `tries` counts the writes."""

    def __init__(self, broken=False):
        self.said, self.broken, self.tries = [], broken, 0

    def write(self, text):
        self.tries += 1
        if self.broken:
            raise BrokenPipeError(32, "Broken pipe")
        self.said.append(json.loads(text))

    def flush(self):
        pass


class Progress(unittest.TestCase):
    """`Calls` in this process, with `Lines` in place of the client and 0.02 seconds between two progress
    notifications: the shapes of a token, the progress of a call from its reading to its answer, one call at a time, a
    cancel, a batch, a client that closed its end, and `serve` at the end of its input. The tool `slow` waits until the
    test opens its gate. Install proves the same over standard input and output."""

    def setUp(self):
        self.gate, self.ran = threading.Event(), []

        def slow(args):
            self.ran.append(("start", args.get("n")))
            self.gate.wait(10)
            self.ran.append(("end", args.get("n")))
            return {"n": args.get("n")}

        folder = pathlib.Path(tempfile.mkdtemp(prefix="fleet-known-hosts-"))
        self.addCleanup(shutil.rmtree, str(folder), True)
        for keep in (patch.object(owner_mcp, "PROGRESS_EVERY", 0.02),
                     patch.dict(owner_mcp.TOOLS, {"slow": {"run": slow}}),
                     patch.object(owner_mcp, "KNOWN_HOSTS", folder / "known_hosts")):
            keep.start()
            self.addCleanup(keep.stop)

    def calls(self, out):
        calls = owner_mcp.Calls(out)
        self.addCleanup(calls.finish)
        self.addCleanup(self.gate.set)                  # before the finish: no call waits after the test
        return calls

    @staticmethod
    def call(n, token=None):
        params = {"name": "slow", "arguments": {"n": n}}
        if token is not None:
            params["_meta"] = {"progressToken": token}
        return {"jsonrpc": "2.0", "id": n, "method": "tools/call", "params": params}

    @staticmethod
    def cancel(mid):
        return {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": mid, "reason": "Esc"}}

    def until(self, test, what, wait=10):
        end = time.monotonic() + wait
        while not test():
            if time.monotonic() > end:
                self.fail(f"not in {wait} seconds: {what}")
            time.sleep(0.005)

    @staticmethod
    def progress(out, token):
        return [m["params"]["progress"] for m in list(out.said)
                if isinstance(m, dict) and m.get("method") == "notifications/progress"
                and m["params"]["progressToken"] == token]

    @staticmethod
    def answered(out):
        """The ids of the answers, in their order; a list of ids for the answer to a batch."""
        return [[a["id"] for a in m] if isinstance(m, list) else m["id"] for m in list(out.said)
                if isinstance(m, list) or "method" not in m]

    def test_only_a_string_or_an_integer_token_of_a_tool_call_asks_for_progress(self):
        """The token of the specification is a string or an integer, and this server takes it from a tools/call only."""
        shapes = ({"progressToken": "abc"}, {"progressToken": 0}, {"progressToken": 2 ** 70}, {"progressToken": True},
                  {"progressToken": 1.5}, {"progressToken": None}, {"progressToken": {"a": 1}}, {}, "abc", None)
        tokens = [owner_mcp.progress_token({"id": 9, "method": "tools/call", "params": dict(
            {"name": "slow"}, **({} if meta is None else {"_meta": meta}))}) for meta in shapes]
        self.assertEqual(tokens, ["abc", 0, 2 ** 70] + [None] * 7)
        self.assertEqual([owner_mcp.progress_token(m) for m in (
            {"id": 9, "method": "ping", "params": {"_meta": {"progressToken": 9}}},
            {"id": 9, "method": "tools/call", "params": ["slow"]}, {"id": 9, "method": "tools/call"})], [None] * 3)

    def test_a_call_has_progress_from_its_reading_to_its_answer_and_the_next_call_runs_after_it(self):
        """A call with a token gets progress while it waits and while it runs, with values that increase by one, and
        none after its answer. A call with no token gets none. The calls run one at a time, in the order of reading,
        and a ping gets its answer at once while a call runs."""
        out = Lines()
        calls = self.calls(out)
        calls.take(self.call(1, token="one"))
        self.until(lambda: self.ran, "the first call starts")
        calls.take(self.call(2, token=2))
        calls.take(self.call(3))
        self.until(lambda: len(self.progress(out, 2)) >= 3, "progress for a call that waits")
        calls.take({"jsonrpc": "2.0", "id": 4, "method": "ping"})
        self.until(lambda: self.answered(out), "the answer to a ping while a call runs")
        self.assertEqual((self.ran, self.answered(out)), ([("start", 1)], [4]))
        self.gate.set()
        self.until(lambda: len(self.answered(out)) == 4, "the answers to the three calls")
        self.assertEqual(self.answered(out), [4, 1, 2, 3])
        self.assertEqual(self.ran, [("start", 1), ("end", 1), ("start", 2), ("end", 2), ("start", 3), ("end", 3)])
        time.sleep(0.1)                                 # five periods of progress
        for token, mid in (("one", 1), (2, 2)):
            values = self.progress(out, token)
            self.assertEqual(values, list(range(1, len(values) + 1)))
            at = next(n for n, m in enumerate(out.said) if "method" not in m and m["id"] == mid)
            self.assertNotIn(token, [m["params"]["progressToken"] for m in out.said[at:] if "method" in m])
        self.assertEqual({m["params"]["progressToken"] for m in out.said if "method" in m}, {"one", 2})

    def test_a_cancel_drops_a_call_that_waits_and_silences_the_call_that_runs_without_a_stop(self):
        """A cancel of a call that waits drops it: it never runs. A cancel of the call that runs ends its progress and
        its answer, and the step that runs goes on to its end, because a command over SSH must not stop part way. A
        cancel of a request that the server does not hold changes nothing, also one with the id "2" for the request 2:
        the type of an id counts (JSON-RPC)."""
        out = Lines()
        calls = self.calls(out)
        calls.take(self.call(1, token=1))
        self.until(lambda: self.ran, "the first call starts")
        calls.take(self.call(2, token=2))
        self.until(lambda: self.progress(out, 1) and self.progress(out, 2), "progress for both calls")
        for mid in ("2", 99):
            calls.take(self.cancel(mid))
        heard = len(self.progress(out, 2))
        self.until(lambda: len(self.progress(out, 2)) > heard, "progress after a cancel that names no request")
        for mid in (2, 1):
            calls.take(self.cancel(mid))
        heard = list(out.said)
        time.sleep(0.1)                                 # five periods of progress
        self.assertEqual(out.said, heard, "a message after the cancel")
        calls.take(self.call(3))
        self.gate.set()
        self.until(lambda: self.answered(out), "the answer to the call after them")
        self.assertEqual(self.answered(out), [3])
        self.assertEqual(self.ran, [("start", 1), ("end", 1), ("start", 3), ("end", 3)])

    def test_a_cancelled_call_starts_no_other_step(self):
        """After a cancel, the call that runs starts no other step: no command over SSH and no call to the hub, also in
        a tool that catches Refused. The step that ran at the cancel goes on to its end, and the call gets no answer."""
        out, steps, refused = Lines(), [], []

        def run(line, **_kw):
            steps.append(line[-1])
            if line[-1] == "first":
                self.gate.wait(10)
            return subprocess.CompletedProcess(line, 0, "", "")

        def opened(request, timeout=None):
            steps.append(request.full_url)
            raise urllib.error.URLError("no hub here")

        def three(_args):
            owner_mcp.ssh("203.0.113.9", "root", "first")
            for step in (lambda: owner_mcp.ssh("203.0.113.9", "root", "second"),
                         lambda: owner_mcp.call("GET", "/ui/state", base="http://127.0.0.1:9")):
                try:
                    step()
                except owner_mcp.Refused as e:
                    refused.append(str(e))
            return {}

        played = types.SimpleNamespace(run=run, DEVNULL=subprocess.DEVNULL, TimeoutExpired=subprocess.TimeoutExpired)
        with patch.object(owner_mcp, "subprocess", played), patch.object(owner_mcp.OPENER, "open", opened), \
                patch.dict(owner_mcp.TOOLS, {"three": {"run": three}}):
            calls = self.calls(out)
            calls.take({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "three", "arguments": {}}})
            self.until(lambda: steps, "the first step starts")
            calls.take(self.cancel(1))
            self.gate.set()
            calls.finish()
        self.assertEqual((steps, refused, out.said), (["first"], [], []))

    def test_a_claim_that_went_through_keeps_the_hub_address_also_after_a_cancel(self):
        """claim_hub saves the hub's address as soon as the claim went through, before it waits for the owner API. A
        cancel during the claim stops the call before that wait, and the address stays saved: a claim code works once,
        so the agent could not claim the hub again."""
        home = pathlib.Path(tempfile.mkdtemp(prefix="fleet-claim-"))
        self.addCleanup(shutil.rmtree, str(home), True)
        posted = []

        def claim(listener, code, base):
            posted.append(listener)
            self.gate.wait(10)
            return owner_mcp.Answer(200, None, b"claimed", {})

        args = {"address": "100.64.0.1", "claim_code": "ABCD-EFGH-JKLM"}
        with patch.object(owner_mcp, "HOME", home), patch.object(owner_mcp, "HUB_FILE", home / "hub"), \
                patch.object(owner_mcp, "_claim_post", claim), \
                patch.dict(owner_mcp.TOOLS, {"claim_hub": {"run": owner_mcp.claim_hub}}):
            calls = self.calls(Lines())
            calls.take({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "claim_hub", "arguments": args}})
            self.until(lambda: posted, "the claim goes")
            calls.take(self.cancel(1))
            self.gate.set()
            calls.finish()
        self.assertEqual((home / "hub").read_text().strip(), "http://100.64.0.1:8765")

    def test_a_batch_with_a_tool_call_gets_one_list_of_answers_after_its_calls(self):
        """A batch (JSON-RPC, protocol version 2025-03-26) with a tools/call waits as one piece of work and gets one
        list of answers, in its order. A batch with no tools/call gets its list at once. A cancel of a request of a
        batch, also in the same batch, takes that request and its answer out."""
        out = Lines()
        calls = self.calls(out)
        calls.take([self.call(1, token=1), {"jsonrpc": "2.0", "id": 2, "method": "ping"}, self.call(3), self.cancel(3)])
        calls.take([{"jsonrpc": "2.0", "id": 4, "method": "ping"},
                    {"jsonrpc": "2.0", "method": "notifications/initialized"}])
        self.until(lambda: self.answered(out), "the answer to the batch with no tool call")
        self.gate.set()
        self.until(lambda: len(self.answered(out)) == 2, "the answer to the batch with a tool call")
        self.assertEqual(self.answered(out), [[4], [1, 2]])
        self.assertEqual(self.ran, [("start", 1), ("end", 1)])

    def test_a_client_that_closed_its_end_stops_the_progress_and_not_the_call_and_no_other_call_starts(self):
        """A write that fails (the client closed its end of the pipe) ends every write. The call that runs goes on to
        its end, and the calls that wait never start: no answer can reach the client."""
        out = Lines(broken=True)
        calls = self.calls(out)
        calls.take(self.call(1, token=1))
        self.until(lambda: self.ran, "the first call starts")
        calls.take(self.call(2, token=2))
        self.until(lambda: out.tries, "a notification that finds the closed pipe")
        time.sleep(0.1)                                 # five periods of progress
        self.gate.set()
        calls.finish()
        self.assertEqual((self.ran, out.tries), ([("start", 1), ("end", 1)], 1))

    def test_serve_answers_a_line_that_is_not_json_and_ends_after_the_work_that_it_read(self):
        """`serve` gives a line that is not JSON the parse error of JSON-RPC, skips an empty line, and returns at the
        end of its input only after the calls that it read have their answers."""
        out = Lines()
        self.gate.set()
        owner_mcp.serve(iter(["not json\n", json.dumps(self.call(1, token=1)) + "\n", "\n",
                              json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}) + "\n"]), out)
        self.assertEqual(out.said[0], {"jsonrpc": "2.0", "id": None,
                                       "error": {"code": -32700, "message": "Parse error"}})
        self.assertEqual(sorted(self.answered(out)[1:]), [1, 2])
        self.assertEqual(self.ran, [("start", 1), ("end", 1)])

    def test_the_tools_of_a_long_call_say_that_another_call_waits_for_it(self):
        """install_hub and add_machine say that this server runs one call at a time (ONE_CALL): another call that the
        agent sends meanwhile waits for theirs to end."""
        said = {t["name"]: t["description"] for t in owner_mcp.tools()}
        self.assertEqual([name for name in ("install_hub", "add_machine") if owner_mcp.ONE_CALL not in said[name]], [])


@unittest.skipIf(os.geteuid() == 0, "the stand-in server closes root's folders with file modes, which root ignores")
class RootThroughSudo(unittest.TestCase):
    """**Each program that this server runs as root reaches `/bin/sh` unchanged, also on a server that the owner's SSH
    reaches as a user who is not root**, and the install and the join run there as they run for root. `install_hub`,
    `install_log` and `add_machine` run in this process with `ssh` played by test_hub_install's StandInServer, as
    PromptThroughSudo plays it for INSTALL-PROMPT.md: the user's login shell (bash) reads the remote command with only
    `sudo` on its PATH, a stand-in for `sudo` gives root's login shell (bash) the words with sudo's own backslashes
    (`man sudo`, `-i`), and `/bin/sh` runs the program: this machine's, and dash, which is `/bin/sh` on Debian and
    Ubuntu. The server's /root is a folder that only that `sudo` opens. Until 11 November 2026 the code step went as
    `sudo -i -- sh -c '…'`, and root's login shell expanded take_line's "$t" to nothing before `sh` read it: on a
    server that had the code already, `may-take` and `merge --ff-only` got "", and the code did not move.

    The same server also says no: a `sudo` that does not let the user in stops install_hub before anything on the
    server changes, a code step that fails stops it before the install starts, and a Mac joins as its own user and
    never as root."""

    HOST = "203.0.113.9"
    COMMIT = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d"      # the commit of the upstream of the server's checkout

    # git, as far as the install uses it: a clone keeps the address that it was given and its copy holds hub.sh, and a
    # checkout moves only onto the commit of its upstream.
    GIT = r'''#!/bin/sh
{ printf 'git'; printf ' [%s]' "$@"; echo; } >> "$STATE/git"
case $1 in
clone) shift
       while [ "$#" -gt 2 ]; do shift; done
       /bin/mkdir -p "$2/.git" && printf '%s\n' "$1" > "$2/.git/source" && /bin/cp "$FILES/hub.sh" "$2/hub.sh" ;;
-C) [ -d "$2/.git" ] || { echo "fatal: not a git repository: $2" >&2; exit 128; }
    case $3 in
    fetch) ;;
    rev-parse) case $4 in --short) echo 1a2b3c4 ;; --verify) echo COMMIT ;; *) exit 2 ;; esac ;;
    merge) [ "$6" = COMMIT ] || { echo "merge: '$6' - not something we can merge" >&2; exit 1; } ;;
    *) exit 2 ;;
    esac ;;
*) exit 2 ;;
esac
'''

    # `python3 lifecycle.py may-take KIT TARGET`, which lets a checkout move only onto a commit.
    PYTHON3 = r'''#!/bin/sh
{ printf 'python3'; printf ' [%s]' "$@"; echo; } >> "$STATE/python3"
[ "$2" = may-take ] && [ "$4" = COMMIT ] || { echo "lifecycle.py may-take: '$4' is not a commit" >&2; exit 1; }
'''

    # `sudo -n` when it does not let the user in, with its exit status and its words on standard error: to a user who
    # must type a password, and to a user who may not use it. And a sudo that runs the program as a user who is not
    # root, as a sudoers file with another runas_default does, which ends well.
    REFUSALS = ((1, "sudo: a password is required"), (1, "Sorry, user deploy may not run sudo on server-1."),
                (0, "1000"))

    # `lifecycle.py may-take` when it keeps the checkout where it is: its one reason, on standard error.
    HELD = "lifecycle.py may-take: release 2026.11.400 is held: no fleet takes it"

    # join.sh's Mac part, as far as add_machine reaches it (join.sh `mac`): as root it stops, unless FLEET_MAC_USER
    # names the Mac user, as the line of the Founderizer installer does; as that user it joins, and keeps the code in
    # that user's home.
    MAC_JOIN = r'''[ -n "${FLEET_JOIN:-}" ] || { echo "Founderizer: the join line gave no code" >&2; exit 1; }
if [ "$(id -u)" = 0 ] && [ -z "${FLEET_MAC_USER:-}" ]; then
    echo "Founderizer join stopped: Run the line in Terminal as the Mac user that will run the agents, not as root." >&2
    exit 1
fi
/bin/mkdir -p "$HOME/.fleet" && printf '%s %s\n' "$(id -un)" "$FLEET_JOIN" > "$HOME/.fleet/joined" || exit 1
echo "Founderizer: this machine is the server mini"
echo "Founderizer: the server service runs"
echo READY
'''

    # `id` of the Mac user that the owner's SSH reaches.
    MAC_ID = '#!/bin/sh\ncase $1 in -u) echo 501 ;; -un) echo dana ;; *) exit 2 ;; esac\n'

    # The public key of the SSH server of each stand-in server (`server`), as /etc/ssh/ssh_host_ed25519_key.pub holds it.
    HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtleU9mVGhlU3RhbmRJblNlcnZlck9mVGhpc1Rlc3Q root@vps-1"

    # The read of the machine, which install_hub sends first (INSTALL-PROMPT.md A1).
    READ = 'id -un; id -u; sed -n "1,2p" /etc/os-release; command -v systemctl'

    # `ps -A -o args=`, as far as install_hub reads it: the line of an install that runs (STATE/installing), or none.
    PS = '#!/bin/sh\n[ -s "$STATE/installing" ] && /bin/cat "$STATE/installing"\nexit 0\n'

    def setUp(self):
        """The known_hosts file of this server is a file of this test, never the owner's (`owner_mcp.KNOWN_HOSTS`)."""
        folder = pathlib.Path(tempfile.mkdtemp(prefix="fleet-known-hosts-"))
        self.addCleanup(shutil.rmtree, str(folder), True)
        keep = patch.object(owner_mcp, "KNOWN_HOSTS", folder / "known_hosts")
        keep.start()
        self.addCleanup(keep.stop)

    def server(self, mac=False):
        """A new stand-in server, whose install puts this test's git among the system's programs. A Mac (`mac`) gives
        MAC_JOIN as its join script, and its user a home, and the programs of the join line on its PATH."""
        server = StandInServer()
        self.addCleanup(server.remove)
        for path, text in ((server.files / "git", self.GIT), (server.tools / "python3", self.PYTHON3),
                           (server.tools / "ps", self.PS)):
            path.write_text(text.replace("COMMIT", self.COMMIT))
            path.chmod(0o755)
        (server.tools / "grep").symlink_to(next(path for path in (pathlib.Path("/usr/bin/grep"),
                                                                  pathlib.Path("/bin/grep")) if os.access(path, os.X_OK)))
        with server.opened():
            (server.root / "ssh").mkdir()
            (server.root / "ssh" / "ssh_host_ed25519_key.pub").write_text(self.HOST_KEY + "\n")
        if mac:
            (server.files / "join.sh").write_text(self.MAC_JOIN)
            programs = server.folder / "mac-user"
            programs.mkdir()
            (server.folder / "home").mkdir()
            (programs / "id").write_text(self.MAC_ID)
            (programs / "id").chmod(0o755)
            (programs / "curl").symlink_to(server.tools / "curl")
            (programs / "sh").symlink_to("/bin/sh")
        return server

    @staticmethod
    def join_lines():
        """The hub's own join line of each kind, with the code of StandInServer."""
        with patch.object(hub, "hub_address", lambda: ("100.80.1.2", 8765)):
            return {kind: hub.join_line(StandInServer.CODE, kind, ["tag:fleet", "tag:server"])
                    for kind in ("linux", "mac")}

    @contextlib.contextmanager
    def reached(self, server, user, run, system="Linux"):
        """owner_mcp as it reaches `server` as `user`: its `ssh` answers the machine's reads as Ubuntu 24.04 does for
        `user`, or as a Mac does (`system` "Darwin"), and gives each other command to `run(remote, stdin)`, whose answer
        is that command's; root's files are the server's; and the hub's join route gives its own line of each kind. It
        gives the commands that `run` got, each with what it gave, and the bodies that the join route got. What `run`
        gave also holds the time that `ssh` had for the command (`limit`), its words for a time-out (`late`), and
        whether a connection that SSH loses is said with them (`lost`)."""
        uid = "0" if user == "root" else "1000"
        reads = {'id -un; id -u; sed -n "1,2p" /etc/os-release; command -v systemctl':
                 f'{user}\n{uid}\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\nNAME="Ubuntu"\n/usr/bin/systemctl',
                 "id -un; id -u": f"{user}\n{uid}", "id -un; id -u; uname -s": f"{user}\n{uid}\n{system}"}
        lines, sent, made = self.join_lines(), [], []

        def ssh(_host, _user, remote, stdin=None, timeout=120, late="", lost=False, via=None):
            if remote in reads:
                return {"exit": 0, "out": reads[remote], "error": ""}
            ran = run(remote, stdin.name if stdin else None)
            ran.limit, ran.late, ran.lost = timeout, late, lost
            sent.append((remote, ran))
            return {"exit": ran.status, "out": ran.out.strip(), "error": ran.err.strip()}

        def command(_route, body, *_rest):
            made.append(body)
            return {"line": lines[body["kind"]]}

        with patch.object(owner_mcp, "ssh", ssh), patch.object(owner_mcp, "command", command), \
                self.on_server(server):
            yield sent, made

    @contextlib.contextmanager
    def on_server(self, server):
        """The paths of the steps on `server`: root's files, and the keys of its SSH server, are the stand-in's."""
        with patch.object(owner_mcp, "KIT", f"{server.root}/fleet-kit"), \
                patch.object(owner_mcp, "LOG", f"{server.root}/fleet-install.log"), \
                patch.object(owner_mcp, "AUTHKEY", f"{server.root}/fleet-authkey"), \
                patch.object(owner_mcp, "SSH_KEYS", f"{server.root}/ssh/ssh_host_*_key.pub"):
            yield

    def tools(self, server, user, run):
        """install_hub on a new server and again on that server, install_log, and add_machine for a Linux server, as
        `user` reaches `server` (`reached`): the remote command of each step with what `run` gave, and the tools'
        answers."""
        install = {"host": self.HOST, "ssh_user": user, "source": StandInServer.SOURCE,
                   "authkey_file": str(server.keyfile), "servers": 2}
        reach = {"host": self.HOST, "ssh_user": user}
        with self.reached(server, user, run) as (sent, _made):
            answers = {"new": owner_mcp.install_hub(install), "again": owner_mcp.install_hub(install),
                       "log": owner_mcp.install_log(reach)}
            # On the private network, with Tailscale, as the network step leaves a server.
            server.give("tailscale")
            server.come_up()
            answers["linux"] = owner_mcp.add_machine(dict(reach, kind="linux"))
        return sent, answers

    def one(self, server, user, run, name, args, system="Linux"):
        """The tool `name` once, with `args`, as `user` reaches `server` (`reached`): the commands that `run` got, the
        bodies that the hub's join route got, and the tool's answer or its refusal."""
        with self.reached(server, user, run, system) as (sent, made):
            try:
                answer = getattr(owner_mcp, name)(dict(args, host=self.HOST, ssh_user=user))
            except owner_mcp.Refused as refused:
                answer = refused
        return sent, made, answer

    def install(self, server):
        """The arguments of install_hub on `server`, beside the host and the user."""
        return {"source": StandInServer.SOURCE, "authkey_file": str(server.keyfile), "servers": 2}

    @staticmethod
    def as_root(server, remote, stdin):
        """A remote command as root's login shell (bash) runs it over SSH: no `sudo`, and root's folders open."""
        with server.opened():
            return server.execute(["/bin/bash", "-c", remote], server.env(PATH=f"{server.system}:{server.tools}"),
                                  stdin)

    @staticmethod
    def through_sudo(server, remote, sh, stdin):
        """A remote command as the login shell of the user who is not root runs it (`server.remote`), with `sh` as
        root's /bin/sh."""
        if sh == "/bin/sh":
            return server.remote(remote, stdin)
        return server.execute(["/bin/bash", "-c", remote], server.env(PATH=str(server.user), PROGRAM_SH=sh), stdin)

    @staticmethod
    def as_mac_user(server, remote, login, stdin):
        """A remote command as the login shell (`login`) of the Mac user runs it over SSH: with `sudo` and that user's
        own programs on its PATH, in that user's home, and with root's folders closed."""
        return server.execute([login, "-c", remote], server.env(PATH=f"{server.user}:{server.folder / 'mac-user'}",
                                                                HOME=str(server.folder / "home")), stdin)

    @staticmethod
    def words_for_sudo(remote):
        """The words that the user's login shell gives `sudo` after its options and "--"."""
        printed = subprocess.run(["/bin/bash", "-c", 'sudo() { while [ "$#" -gt 0 ] && [ "$1" != -- ]; do shift; '
                                  "done; shift; printf '%s\\0' \"$@\"; }; " + remote], capture_output=True,
                                 timeout=30, stdin=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        return printed.stdout.decode().split("\0")[:-1]

    @staticmethod
    def program_that_sh_runs(words, sh):
        """The words that run the program, with the program that `sh` runs as the last one: as it is, or what the
        `printf` of its `eval` prints."""
        if len(words) != 3 or words[1] != "-c" or not words[2].startswith("eval "):
            return words
        printed = subprocess.run([sh, "-c", "printf %s " + words[2][len("eval "):]], capture_output=True, timeout=30,
                                 stdin=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        return words[:2] + [printed.stdout.decode()]

    @staticmethod
    def machine_says(remote, user, uid, mac):
        """What a machine prints for a command of install_hub, install_log or add_machine that ends well: its reads as
        Ubuntu 24.04 or macOS gives them for `user` (`uid`), root's `id -u`, and the steps that print."""
        return next((out for part, out in (
            ("; uname -s", f"{user}\n{uid}\n{'Darwin' if mac else 'Linux'}"),
            ("; sed", f'{user}\n{uid}\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\nNAME="Ubuntu"\n/usr/bin/systemctl'),
            ("id -un; id -u", f"{user}\n{uid}"), ("'id -u'", "0"),
            ("rev-parse --short HEAD", "1a2b3c4\n/root/fleet-kit/hub.sh"),
            ("hub.sh --check", "Founderizer: check only: nothing on this machine changes"),
            ("tailscale ip -4", StandInServer.ADDRESS)) if part in remote), "")

    def effects(self, server, answers, who):
        """What the tools did on the server, in words: nothing when each step ran as root."""
        issues, kit = [], f"{server.root}/fleet-kit"
        if "check only" not in answers["new"]["plan"]:
            issues.append(f"{who}: install_hub printed no plan: {answers['new']['plan']!r}")
        if server.read("fleet-kit/.git/source") != server.SOURCE + "\n":
            issues.append(f"{who}: install_hub did not clone the code as root")
        took = server.state / "python3"
        took = took.read_text().splitlines() if took.exists() else []
        if took != [f"python3 [{kit}/lifecycle.py] [may-take] [{kit}] [{self.COMMIT}]"]:
            issues.append(f"{who}: on a server that has the code, may-take got {took}")
        if f"git [-C] [{kit}] [merge] [-q] [--ff-only] [{self.COMMIT}]" not in server.git_calls():
            issues.append(f"{who}: on a server that has the code, the code did not move: {server.git_calls()[-2:]}")
        if server.read("fleet-install.log") != server.INSTALL_LOG or server.key_file() is not None:
            issues.append(f"{who}: install_hub did not start the install as root, or left the key file: "
                          f"{answers['again']['steps']['started']}")
        log = answers["log"]
        if (log["claim_code"], log["hub_address"], log["claim_port"]) != (server.CODE, server.ADDRESS, 8765):
            issues.append(f"{who}: install_log read no claim code: {log['log']!r} {log['error']!r}")
        join = answers["linux"]["join"]
        if join["exit"] or "this machine is the server" not in join["out"]:
            issues.append(f"{who}: add_machine did not join a Linux server as root: {join}")
        if server.read("fleet-joined") != server.CODE + "\n":
            issues.append(f"{who}: the join did not keep its code in root's folder")
        return issues

    def assertNoIssues(self, issues):
        if issues:
            self.fail(f"{len(issues)} issues:\n" + "\n".join(issues))

    def test_each_root_program_reaches_sh_unchanged_for_a_user_who_is_not_root(self):
        issues, check = [], owner_mcp.as_root("sudo -n -i -- ", "id -u")     # become_root's step; root needs none
        for sh in SHELLS:
            who = f"a user who is not root, with {sh}"
            server = self.server()
            meant, _ = self.tools(server, "root", lambda remote, _stdin: StandInServer.Ran(
                0, StandInServer.ADDRESS if "tailscale ip -4" in remote else "", "", ""))
            sent, answers = self.tools(server, "deploy",
                                       lambda remote, stdin: self.through_sudo(server, remote, sh, stdin))
            checks = [ran for remote, ran in sent if remote == check]
            if [ran.out.strip() for ran in checks] != ["0"] * 3 or any(
                    ran.logged("root runs") != ran.logged("sudo gets") for ran in checks):
                issues.append(f"{who}: before the root steps of each install and of the join, root did not answer "
                              f"`id -u` with 0 three times: {[(ran.out, ran.err) for ran in checks]}")
            steps = [(remote, ran) for remote, ran in sent if remote != check]
            self.assertEqual(len(steps), len(meant))
            for (remote, ran), (for_root, _ran) in zip(steps, meant):
                if not remote.startswith("sudo "):
                    issues.append(f"{who}: `{remote}` runs without sudo")
                    continue
                if not remote.startswith("sudo -n -i -- /bin/sh -c "):
                    issues.append(f"{who}: `{remote[:40]}…` is not one `sudo -n -i -- /bin/sh -c` command, as "
                                  f"INSTALL-PROMPT.md A1 says")
                words = self.words_for_sudo(remote)
                gets, runs = ran.logged("sudo gets"), ran.logged("root runs")
                if gets != ["".join(f" [{word}]" for word in words)] or runs != gets:
                    issues.append(f"{who}: sudo got {gets}, and root's login shell ran {runs}")
                if self.program_that_sh_runs(words, sh) != shlex.split(for_root):
                    issues.append(f"{who}: /bin/sh runs {self.program_that_sh_runs(words, sh)}, not {for_root}")
            issues += self.effects(server, answers, who)
        self.assertNoIssues(issues)

    def test_for_root_each_program_goes_as_it_is_and_the_tools_do_the_same(self):
        server = self.server()
        sent, answers = self.tools(server, "root", lambda remote, stdin: self.as_root(server, remote, stdin))
        # The first install_hub: the read of the installs that run, git, code, revision, plan, the read of the network,
        # the network step with the key, and the start; the second the same, without the network step, because the
        # server is on the network; the tail of install_log; and the read of the network and the join line of
        # add_machine. The reads of the machine are not here (`reached`).
        self.assertEqual(len(sent), 18)
        self.assertNoIssues([f"root: `{remote}` goes through sudo" for remote, _ran in sent
                             if remote.startswith("sudo")] + self.effects(server, answers, "root"))

    def test_a_sudo_that_says_no_stops_the_install_and_the_join_in_its_own_words_before_anything_changes(self):
        """**When `sudo` does not let the user become root, install_hub stops at its first root step with sudo's own
        words** (INSTALL-PROMPT.md A1), says what the owner can do, and nothing on the server has changed; add_machine
        stops the same way for a Linux server, before the hub makes a code (B1), and install_log stops instead of a
        read again and again. A sudo that runs the program as a user who is not root stops them too, and an SSH that
        fails at that step is said as an SSH failure. Until 11 November 2026 install_hub went on through each root
        step, and the agent read that the code was not on the server and that the repository needed a credential."""
        issues = []
        for status, said in self.REFUSALS:
            server = self.server()
            (server.user / "sudo").write_text('#!/bin/sh\n{ printf "sudo gets"; printf " [%s]" "$@"; echo; } >> '
                                              f'"$LOG"\necho {shlex.quote(said)}{" >&2" if status else ""}\n'
                                              f"exit {status}\n")
            run, words = (lambda remote, stdin: self.through_sudo(server, remote, "/bin/sh", stdin),
                          said if status else f"`id -u` through sudo gave {said}, not 0")
            sent, _made, answer = self.one(server, "deploy", run, "install_hub", self.install(server))
            refused = str(answer)
            if not isinstance(answer, owner_mcp.Refused):
                issues.append(f"{said}: install_hub did not stop: {answer['steps']}")
            elif words not in refused or "with sudo and no password" not in refused or "ssh_user root" not in refused:
                issues.append(f"{said}: install_hub stopped without sudo's words and what the owner can do: {refused}")
            elif "the Founderizer code is not on" in refused or "credential" in refused:
                issues.append(f"{said}: install_hub gave another cause: {refused}")
            if len(sent) != 1 or not sent[0][1].logged("sudo gets"):
                issues.append(f"{said}: install_hub sent {[remote[:60] for remote, _ran in sent]} after the machine's "
                              f"read, not one root step")
            if (server.git_calls() or server.has("git") or server.read("fleet-kit/.git/source") is not None
                    or server.key_file() is not None or server.read("fleet-install.log") is not None):
                issues.append(f"{said}: install_hub changed the server before it stopped")
            sent, made, answer = self.one(server, "deploy", run, "add_machine", {"kind": "linux"})
            if not isinstance(answer, owner_mcp.Refused) or words not in str(answer) or made or len(sent) != 1:
                issues.append(f"{said}: add_machine made {made} and sent {len(sent)} commands for a Linux server: "
                              f"{answer if isinstance(answer, owner_mcp.Refused) else answer['join']}")
            if status:                          # the tail fails, and then the check of sudo says why
                sent, _made, answer = self.one(server, "deploy", run, "install_log", {})
                if not isinstance(answer, owner_mcp.Refused) or said not in str(answer) or len(sent) != 2:
                    issues.append(f"{said}: install_log sent {len(sent)} commands and did not stop with sudo's words: "
                                  f"{answer if isinstance(answer, owner_mcp.Refused) else answer['next']}")
        server = self.server()
        lost = "ssh: connect to host 203.0.113.9 port 22: Operation timed out"
        sent, _made, answer = self.one(server, "deploy", lambda _remote, _stdin: StandInServer.Ran(255, "", lost, ""),
                                       "install_hub", self.install(server))
        if (not isinstance(answer, owner_mcp.Refused) or f"SSH to deploy@{self.HOST} failed" not in str(answer)
                or lost not in str(answer) or "did not let" in str(answer) or len(sent) != 1):
            issues.append(f"an SSH that failed at the check of sudo: "
                          f"{answer if isinstance(answer, owner_mcp.Refused) else answer['steps']}")
        self.assertNoIssues(issues)

    def test_a_step_of_the_code_that_fails_stops_the_install_in_its_own_words_before_it_starts(self):
        """**A step of the code that fails stops install_hub with that step's own words**, before the plan, the key
        file and the start, on a server that has the code already: a move that `lifecycle.py may-take` refuses, a
        fetch that git cannot make, and git that apt-get cannot install. Until 11 November 2026 install_hub did not
        read the exit status of those steps, so it went on and started the install with the old code, or gave the
        words of a later step."""
        fetch = ("fatal: unable to access 'https://example.com/owner/founderizer-fleet.git/': Could not resolve host: "
                 "example.com")
        lock = "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 1234 (unattended-upgr)"
        issues = []
        for user in ("root", "deploy"):
            for said in (self.HELD, fetch, lock):
                who, server = f"{user}, when {said[:30]}…", self.server()
                if said == self.HELD:
                    (server.tools / "python3").write_text(
                        "#!/bin/sh\n{ printf 'python3'; printf ' [%s]' \"$@\"; echo; } >> \"$STATE/python3\"\n"
                        f"echo {shlex.quote(said)} >&2\nexit 1\n")
                elif said == fetch:
                    (server.files / "git").write_text(self.GIT.replace("COMMIT", self.COMMIT).replace(
                        "    fetch) ;;", f"    fetch) echo {shlex.quote(said)} >&2; exit 128 ;;"))
                else:
                    (server.tools / "apt-get").write_text(f"#!/bin/sh\necho {shlex.quote(said)} >&2\nexit 100\n")
                server.clone()                  # the code of an earlier install
                run = (lambda remote, stdin: self.as_root(server, remote, stdin)) if user == "root" else (
                    lambda remote, stdin: self.through_sudo(server, remote, "/bin/sh", stdin))
                sent, _made, answer = self.one(server, user, run, "install_hub", self.install(server))
                if not isinstance(answer, owner_mcp.Refused) or said not in str(answer):
                    issues.append(f"{who}: install_hub did not stop with the words of the step that failed: "
                                  f"{answer if isinstance(answer, owner_mcp.Refused) else answer['steps']['code']}")
                if any("[merge]" in call for call in server.git_calls()):
                    issues.append(f"{who}: the code moved: {server.git_calls()}")
                if (any("hub.sh --check" in remote for remote, _ran in sent) or server.key_file() is not None
                        or server.read("fleet-install.log") is not None):
                    issues.append(f"{who}: install_hub went on after the step that failed: "
                                  f"{[remote[-40:] for remote, _ran in sent]}")
        self.assertNoIssues(issues)

    def test_the_git_step_waits_for_apts_lock_while_a_new_server_installs_its_first_updates(self):
        """**install_hub's git step waits for apt's lock, and its SSH time-out is longer than that wait**, as
        INSTALL-PROMPT.md A3 and each apt-get of hub.sh and join.sh: a new server installs its first updates for about
        9 minutes after its first start, and they hold the lock (hubsetup.py APT_LOCK_WAIT). Until 11 November 2026 the
        step did not wait, and it had 600 seconds, so on such a server apt-get stopped at once and install_hub stopped
        with apt's words. StandInServer's apt-get plays the lock of dpkg as apt does. Only `apt-get install` waits for
        that lock, one time in all for its locks (apt's debsystem.cc), so the time-out is that wait and 300 seconds of
        work at least. It is shorter than 1800 seconds: Claude Code ends a call to a stdio MCP server that gave no
        answer and no progress for 30 minutes (CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT), and then the agent would not get
        this server's words from a client that asks for no progress. The program of the step is A3's first line, word
        for word."""
        a3 = (HERE / "INSTALL-PROMPT.md").read_text().partition("### A3.")[2].partition("### A4.")[0]
        [line] = [line for line in a3.splitlines() if "command -v git" in line]
        program = line.partition("'/bin/sh -c \"")[2].rpartition("\"'")[0]
        issues = []
        for user, sh in [("root", "/bin/sh")] + [("deploy", sh) for sh in SHELLS]:
            who, server = f"{user}, with {sh}", self.server()
            server.hold_apt_lock(540)
            run = (lambda remote, stdin: self.as_root(server, remote, stdin)) if user == "root" else (
                lambda remote, stdin: self.through_sudo(server, remote, sh, stdin))
            sent, _made, answer = self.one(server, user, run, "install_hub", self.install(server))
            if isinstance(answer, owner_mcp.Refused) or not server.has("git") or server.apt_waits() != [540]:
                issues.append(f"{who}: install_hub said {answer if isinstance(answer, owner_mcp.Refused) else 'yes'}, "
                              f"git is {'there' if server.has('git') else 'not there'}, and apt-get waited "
                              f"{server.apt_waits()} seconds")
            elif server.read("fleet-install.log") != server.INSTALL_LOG:
                issues.append(f"{who}: install_hub did not start the install after the wait")
            for remote, ran in sent:
                if "apt-get" in remote and "command -v git" in remote:
                    waits = [int(seconds) for seconds in re.findall(r"DPkg::Lock::Timeout=(\d+)", remote)]
                    if (waits != [hubsetup.APT_LOCK_WAIT] * remote.count("apt-get ")
                            or not hubsetup.APT_LOCK_WAIT + 300 <= ran.limit < 1800):
                        issues.append(f"{who}: the apt-gets of the git step wait {waits} seconds, and its SSH has "
                                      f"{ran.limit}")
                    if shlex.split(remote)[-1] != program:
                        issues.append(f"{who}: the git step is not A3's first line: {shlex.split(remote)[-1]}")
        self.assertNoIssues(issues)

    def test_a_network_step_or_a_start_step_that_fails_stops_the_install_in_its_own_words(self):
        """**The network step and the start step of install_hub read their exit status**, as each step before them
        does. A key file that root cannot write stops the install with the words of the network step, before the start;
        a start that SSH lost stops it with SSH's words, and sends the agent to install_log first. Until 11 November
        2026 a check of the key file's mode caught a key step that failed in other words ("did not reach … as a file
        only root can read"), and a start that failed went on as if the install ran."""
        lost = f"Connection to {self.HOST} closed by remote host."
        issues = []
        for user in ("root", "deploy"):
            server = self.server()
            with server.opened():
                (server.root / "fleet-authkey").mkdir()        # a key file that `cat >` cannot write

            def on(server, remote, stdin):
                return self.as_root(server, remote, stdin) if user == "root" else self.through_sudo(
                    server, remote, "/bin/sh", stdin)

            sent, _made, answer = self.one(server, user, lambda remote, stdin: on(server, remote, stdin),
                                           "install_hub", self.install(server))
            if (not isinstance(answer, owner_mcp.Refused) or "Is a directory" not in str(answer)
                    or "did not go on the fleet's private network. The install did not start." not in str(answer)):
                issues.append(f"{user}: a network step that failed gave "
                              f"{answer if isinstance(answer, owner_mcp.Refused) else answer['steps']['network']}")
            if any("setsid" in remote for remote, _ran in sent):
                issues.append(f"{user}: install_hub went on after the network step: "
                              f"{[remote[-40:] for remote, _ in sent]}")
            server = self.server()
            _sent, _made, answer = self.one(
                server, user, lambda remote, stdin: StandInServer.Ran(255, "", lost, "") if "setsid" in remote else
                on(server, remote, stdin), "install_hub", self.install(server))
            if (not isinstance(answer, owner_mcp.Refused) or lost not in str(answer) or "exit 255" not in str(answer)
                    or "Read install_log" not in str(answer)):
                issues.append(f"{user}: a start that SSH lost gave "
                              f"{answer if isinstance(answer, owner_mcp.Refused) else answer['next']}")
        self.assertNoIssues(issues)

    def test_a_command_that_does_not_finish_is_said_in_the_words_of_the_tool_that_sent_it(self):
        """**A command that does not finish in its time says what the agent does next in the words of the tool that
        sent it** (`ssh`'s `late`): each command of install_hub, install_log and add_machine, as root and as a user who
        is not root. Until 11 November 2026 each such answer sent the agent to install_log, also for a join line, which
        writes no install log, and for each step of install_hub before the start, which writes none either. The real
        `ssh` runs here with `subprocess.run` played: the machine's reads are answered as Ubuntu 24.04 or macOS answers
        them, root answers `id -u` with 0, each other command ends well, and the command under test does not finish."""
        key = pathlib.Path(tempfile.mkdtemp(prefix="fleet-late-")) / "authkey"
        self.addCleanup(shutil.rmtree, str(key.parent), True)
        key.write_text(StandInServer.KEY)
        key.chmod(0o600)
        lines = self.join_lines()
        step = ("The install did not start", "send install_hub again")
        join, made, log = ("Do not run the join line again", "fleet_read"), ("No join line was made.",), (
            "send install_log again",)
        cases = []
        for user in ("root", "deploy"):
            reach = {"host": self.HOST, "ssh_user": user}
            install = dict(reach, source=StandInServer.SOURCE, authkey_file=str(key), servers=2)
            become = ["'id -u'"] if user != "root" else []      # become_root's step, for a user who is not root
            cases += [("install_hub", install, stop, step, ("install_log",)) for stop in
                      ["; sed", *become, "ps -A", "apt-get", "if test -d", "rev-parse --short HEAD",
                       "hub.sh --check", "tailscale status"]]
            cases.append(("install_hub", install, "cat > ", (*step, "fleet-authkey"), ("install_log",)))
            cases += [("install_hub", install, "setsid", ("install_log before",), ()),
                      ("install_log", reach, "id -un; id -u", log, ("install_hub",)),
                      ("install_log", reach, "tail -n", log, ("install_hub",))]
            cases += [("add_machine", dict(reach, kind="linux"), stop, made, ("install_log",))
                      for stop in ["; uname -s", *become, "tailscale status"]]
            cases.append(("add_machine", dict(reach, kind="linux", authkey_file=str(key)), "cat > ",
                          (*made, "fleet-authkey", "send add_machine again"), ("install_log", "install_hub")))
            cases.append(("add_machine", dict(reach, kind="linux"), "FLEET_JOIN", join, ("install_log", "install_hub")))
        cases.append(("add_machine", {"host": self.HOST, "ssh_user": "dana", "kind": "mac"}, "FLEET_JOIN", join,
                      ("install_log", "install_hub")))
        issues = []
        for name, args, stop, said, unsaid in cases:
            user, mac, sent = args["ssh_user"], args.get("kind") == "mac", []
            uid = "0" if user == "root" else "501" if mac else "1000"

            def run(line, stdin=None, capture_output=False, text=False, timeout=None, env=None, stop=stop, user=user, uid=uid,
                    mac=mac, off="authkey_file" in args):
                remote = line[-1]
                sent.append(remote)
                if stop in remote:
                    raise subprocess.TimeoutExpired(line, timeout)
                # With a key file, the server is not on the private network yet, so the network step runs.
                status = 1 if off and any(remote.endswith(shlex.quote(read)) for read in (
                    owner_mcp.network_read(), owner_mcp.through_sudo(owner_mcp.network_read()))) else 0
                return subprocess.CompletedProcess(line, status, self.machine_says(remote, user, uid, mac), "")

            played = types.SimpleNamespace(run=run, DEVNULL=subprocess.DEVNULL,
                                           TimeoutExpired=subprocess.TimeoutExpired)
            with patch.object(owner_mcp, "subprocess", played), patch.object(
                    owner_mcp, "command", lambda _route, body, *_rest: {"line": lines[body["kind"]]}):
                try:
                    answer = getattr(owner_mcp, name)(args)
                except owner_mcp.Refused as refused:
                    answer = refused
            words = str(answer) if isinstance(answer, owner_mcp.Refused) else None
            if words is None or any(part not in words for part in ("did not finish in", *said)) or any(
                    part in words for part in unsaid):
                issues.append(f"{name} as {user}, when {stop} does not finish: {words or answer}")
            if not sent or stop not in sent[-1]:
                issues.append(f"{name} as {user} went on after {stop} did not finish: "
                              f"{[remote[-40:] for remote in sent]}")
        self.assertNoIssues(issues)

    def test_a_connection_that_ssh_loses_while_a_step_runs_is_said_in_the_words_of_the_tool(self):
        """**When SSH loses the connection while a step that can change the server runs (status 255, SSH's own
        failure), the tool says so in its words for a command that did not finish** (`ssh`'s `lost`): the git step,
        the code step, the revision, the plan and the network steps of install_hub, and the network steps and the join
        line of add_machine. With ServerAliveInterval, SSH ends a connection to a server that gives no sign of
        life after about two minutes; before, such a connection waited for the time of the command. The own words of
        these steps for a failure give another cause: that git could not be installed, that the code is not on the
        server, that the installer refused the machine, that the server is not on the private network, or that a join
        ended with a failure, and on a Mac that the owner runs the line again in Terminal, while the join can still
        run. The real `ssh` runs here with `subprocess.run` played, as in the test of a command that does not
        finish."""
        key = pathlib.Path(tempfile.mkdtemp(prefix="fleet-lost-")) / "authkey"
        self.addCleanup(shutil.rmtree, str(key.parent), True)
        key.write_text(StandInServer.KEY)
        key.chmod(0o600)
        lines, lost = self.join_lines(), f"Timeout, server {self.HOST} not responding."
        step = ("The install did not start", "send install_hub again")
        join = ("Do not run the join line again", "fleet_read")
        own = ("git could not be installed", "the code step", "is not on", "refused this machine", "did not reach",
               "The join ended", "Terminal", "did not go on")
        cases = []
        for user in ("root", "deploy"):
            reach = {"host": self.HOST, "ssh_user": user}
            install = dict(reach, source=StandInServer.SOURCE, authkey_file=str(key), servers=2)
            cases += [("install_hub", install, stop, step) for stop in
                      ["apt-get", "if test -d", "rev-parse --short HEAD", "hub.sh --check", "tailscale status"]]
            cases.append(("install_hub", install, "cat > ", (*step, "fleet-authkey")))
            cases += [("add_machine", dict(reach, kind="linux"), "tailscale status", ("No join line was made",)),
                      ("add_machine", dict(reach, kind="linux", authkey_file=str(key)), "cat > ",
                       ("No join line was made", "fleet-authkey")),
                      ("add_machine", dict(reach, kind="linux"), "FLEET_JOIN", join)]
        cases.append(("add_machine", {"host": self.HOST, "ssh_user": "dana", "kind": "mac"}, "FLEET_JOIN", join))
        issues = []
        for name, args, stop, said in cases:
            user, mac, sent = args["ssh_user"], args.get("kind") == "mac", []
            uid = "0" if user == "root" else "501" if mac else "1000"

            def run(line, stdin=None, capture_output=False, text=False, timeout=None, env=None, stop=stop, user=user, uid=uid,
                    mac=mac, off="authkey_file" in args):
                remote = line[-1]
                sent.append(remote)
                if stop in remote:
                    return subprocess.CompletedProcess(line, 255, "", lost + "\n")
                # With a key file, the server is not on the private network yet, so the network step runs.
                status = 1 if off and any(remote.endswith(shlex.quote(read)) for read in (
                    owner_mcp.network_read(), owner_mcp.through_sudo(owner_mcp.network_read()))) else 0
                return subprocess.CompletedProcess(line, status, self.machine_says(remote, user, uid, mac), "")

            played = types.SimpleNamespace(run=run, DEVNULL=subprocess.DEVNULL,
                                           TimeoutExpired=subprocess.TimeoutExpired)
            with patch.object(owner_mcp, "subprocess", played), patch.object(
                    owner_mcp, "command", lambda _route, body, *_rest: {"line": lines[body["kind"]]}):
                try:
                    answer = getattr(owner_mcp, name)(args)
                except owner_mcp.Refused as refused:
                    answer = refused
            words = str(answer) if isinstance(answer, owner_mcp.Refused) else None
            if words is None or any(part not in words for part in ("status 255", lost, "can still run", *said)) or any(
                    part in words for part in own):
                issues.append(f"{name} as {user}, when SSH loses {stop}: {words or answer}")
            if not sent or stop not in sent[-1]:
                issues.append(f"{name} as {user} went on after SSH lost {stop}: {[remote[-40:] for remote in sent]}")
        self.assertNoIssues(issues)

    def test_a_join_line_has_the_time_of_each_wait_of_the_join_for_apts_lock(self):
        """**add_machine gives a join line the time of each wait of the join for apt's lock, one after the other, and
        ten minutes of work at least**: each apt-get of join.sh that installs waits for the lock of dpkg (an `update`
        does not, apt's pkgAcquire::GetLock), and the age install of the vault broker (`hubsetup.py vault`) has
        hubsetup.py's AGE_INSTALL_TIME. A new server installs its first updates for about 9 minutes after its first
        start, and they hold the lock. Until 11 November 2026 a join had 1800 seconds, less than these waits, so
        add_machine could stop a join that still waited, and the code of a join line works once. A long join keeps
        the call open with progress (Install). A Mac's join has no wait for apt's lock, and has MAC_JOIN_TIME."""
        join = (HERE / "join.sh").read_text()
        [wait] = re.findall(r"^APT_LOCK_WAIT=(\d+)$", join, re.M)
        installs = [line for line in join.splitlines() if "apt-get" in line and "Lock::Timeout=$APT_LOCK_WAIT" in line
                    and " install" in line and not line.lstrip().startswith("#")]
        self.assertTrue(installs and 'hubsetup.py" vault' in join, "join.sh waits for apt's lock as this test reads")
        self.assertEqual(int(wait), hubsetup.APT_LOCK_WAIT, "join.sh waits as long as hubsetup.py")
        waits = len(installs) * int(wait) + hubsetup.AGE_INSTALL_TIME
        issues = []
        for user in ("root", "deploy"):
            server = self.server()
            sent, _made, answer = self.one(server, user, lambda remote, _stdin: StandInServer.Ran(
                0, "0\n" if remote.endswith("'id -u'") else "Founderizer: this machine is the server vps-1\nREADY\n",
                "", ""), "add_machine", {"kind": "linux"})
            joins = [ran.limit for remote, ran in sent if "FLEET_JOIN=" in remote]
            if isinstance(answer, owner_mcp.Refused) or len(joins) != 1 or joins[0] < waits + 600:
                issues.append(f"{user}: the join line has {joins} seconds, and the waits of the join for apt's lock "
                              f"take up to {waits} seconds: {answer}")
        self.assertNoIssues(issues)

    def joined(self, server, user, sh, args, system="Linux"):
        """add_machine once with `args` (HOST and `user` unless `args` names them), as `user` reaches `server`
        (`reached`), with `sh` as root's /bin/sh: its answer or its refusal; each command that is not a read of the
        machine, with the path of the file on its standard input and the number of codes that the hub made before it;
        the commands with what they gave; and the bodies that the join route got."""
        seen, codes = [], {}

        def run(remote, stdin):
            seen.append((remote, stdin, len(codes["made"])))
            return (self.as_root(server, remote, stdin) if user == "root" else
                    self.through_sudo(server, remote, sh, stdin))

        with self.reached(server, user, run, system) as (sent, made):
            codes["made"] = made
            try:
                answer = owner_mcp.add_machine({"host": self.HOST, "ssh_user": user, **args})
            except owner_mcp.Refused as refused:
                answer = refused
        return answer, seen, sent, made

    def test_a_linux_server_off_the_private_network_goes_on_it_with_the_owners_key_before_the_hub_makes_a_code(self):
        """**add_machine puts a Linux server that is not on the fleet's private network on it first, with the owner's
        Tailscale auth key file, as INSTALL-PROMPT.md B2 does. Only then does the hub make a code, and the join line
        runs (B3).** The key goes on the standard input of one root step, and in no argument: `tailscale up` reads it
        from a file that only root can read, and the step removes that file. Tailscale's own installer runs apt-get
        with no wait for apt's lock, so each try of it waits for the lock first, and the step has the time of three such
        waits. On a server that is on the network already, the key stays on this Mac. Until 11 November 2026
        add_machine ran B1 and B3, but not B2. On such a server the hub's line ran `tailscale up` with no key, which
        waits for a sign-in, and the agent could not show its link, because `ssh` gives the output only at the end.
        StandInServer's `tailscale up` comes up only with a key file."""
        issues = []
        for user, sh in [("root", "/bin/sh")] + [("deploy", sh) for sh in SHELLS]:
            who, server = f"{user}, with {sh}", self.server()
            server.hold_apt_lock(540)                       # the first updates of a new server
            keyed = {"kind": "linux", "authkey_file": str(server.keyfile)}
            answer, seen, sent, made = self.joined(server, user, sh, keyed)
            if isinstance(answer, owner_mcp.Refused):
                issues.append(f"{who}: add_machine stopped: {answer}")
                continue
            given = [(remote, stdin, codes) for remote, stdin, codes in seen if stdin]
            if [stdin for _remote, stdin, _codes in given] != [str(server.keyfile)] or given[0][2]:
                issues.append(f"{who}: the key file went on the standard input of {len(given)} commands, or after the "
                              f"hub made a code: {[(remote[-50:], codes) for remote, _stdin, codes in given]}")
            if any(server.KEY.strip() in remote for remote, _stdin, _codes in seen):
                issues.append(f"{who}: the key is in a command line")
            if server.given_key() != server.KEY or server.key_file() is not None:
                issues.append(f"{who}: tailscale up read {server.given_key()!r}, and the key file on the server is "
                              f"{server.key_file()}")
            limits = [ran.limit for remote, ran in sent if given and remote == given[0][0]]
            if (server.apt_waits() != [540] or not server.has("tailscale") or not limits
                    or limits[0] < 3 * hubsetup.APT_LOCK_WAIT):
                issues.append(f"{who}: apt-get waited {server.apt_waits()} seconds, Tailscale is "
                              f"{'there' if server.has('tailscale') else 'not there'}, and the step had {limits} "
                              f"seconds")
            join = answer.get("join") or {}
            if (made != [{"kind": "linux"}] or [codes for remote, _stdin, codes in seen if "FLEET_JOIN=" in remote]
                    != [1] or join.get("exit") or "this machine is the server" not in join.get("out", "")
                    or "key file only" in join.get("error", "")):
                issues.append(f"{who}: the hub made {made}, and the join line gave {join}")
            if (answer.get("network") or {}).get("address") != server.ADDRESS:
                issues.append(f"{who}: add_machine did not give the server's address on the private network: "
                              f"{answer.get('network')}")
            name = f"{self.HOST}@{server.ADDRESS}"
            if (not answer["network"]["keys_kept"] or owner_mcp.kept(name=name) != (name, None)
                    or name not in answer["next"]):
                issues.append(f"{who}: add_machine did not keep the keys of the server's SSH, or did not say where: "
                              f"{answer['network']} {answer['next']}")
            again, seen, _sent, made = self.joined(server, user, sh, keyed)
            if (isinstance(again, owner_mcp.Refused) or any(stdin for _remote, stdin, _codes in seen)
                    or made != [{"kind": "linux"}] or (again.get("join") or {}).get("exit") != 0):
                issues.append(f"{who}: on a server on the network already, add_machine sent the key, or did not join: "
                              f"{again if isinstance(again, owner_mcp.Refused) else again.get('join')}")
        self.assertNoIssues(issues)

    def test_without_a_key_a_linux_server_off_the_private_network_is_refused_before_the_hub_makes_a_code(self):
        """**Without authkey_file, add_machine stops for a Linux server that is not on the fleet's private network, with
        the words of INSTALL-PROMPT.md B2, before the hub makes a code**, and nothing on the server changes: the hub's
        line would run `tailscale up` there with no key, which waits for a sign-in that nobody sees. A key file for a
        Mac, a key file with no host, and a key file that other users of this Mac can read stop add_machine before the
        hub makes a code, and no command gets the key."""
        issues = []
        for user, sh in [("root", "/bin/sh")] + [("deploy", sh) for sh in SHELLS]:
            who, server = f"{user}, with {sh}", self.server()
            answer, seen, _sent, made = self.joined(server, user, sh, {"kind": "linux"})
            words = str(answer)
            if (not isinstance(answer, owner_mcp.Refused) or "not on the fleet's private network" not in words
                    or "authkey_file" not in words or "chmod 600" not in words or "No join line was made" not in words):
                issues.append(f"{who}: add_machine did not stop with the words of B2: "
                              f"{answer if isinstance(answer, owner_mcp.Refused) else answer.get('join')}")
            if made or any("FLEET_JOIN=" in remote for remote, _stdin, _codes in seen):
                issues.append(f"{who}: the hub made {made}, and add_machine sent "
                              f"{[remote[-40:] for remote, _stdin, _codes in seen]}")
            if server.has("tailscale") or server.given_key() is not None:
                issues.append(f"{who}: the server changed before add_machine stopped")
        server = self.server()
        server.give("tailscale")                    # Tailscale is there, but it is not on the network
        answer, seen, _sent, made = self.joined(server, "root", "/bin/sh", {"kind": "linux"})
        if (not isinstance(answer, owner_mcp.Refused) or "not on the fleet's private network" not in str(answer)
                or made or any("FLEET_JOIN=" in remote for remote, _stdin, _codes in seen)):
            issues.append(f"with Tailscale that is not on the network: add_machine made {made}: "
                          f"{answer if isinstance(answer, owner_mcp.Refused) else answer.get('join')}")
        server = self.server()
        key = str(server.keyfile)
        for user, args, system, said in (
                ("dana", {"kind": "mac", "authkey_file": key}, "Darwin", "only for a Linux server"),
                ("root", {"kind": "linux", "host": "", "authkey_file": key}, "Linux", "only for a Linux server"),
                ("root", {"kind": "linux", "authkey_file": str(server.folder)}, "Linux", "not a file that this Mac")):
            answer, seen, _sent, made = self.joined(server, user, "/bin/sh", args, system)
            if not isinstance(answer, owner_mcp.Refused) or said not in str(answer) or made or seen:
                issues.append(f"a key file with {args}: add_machine made {made} and sent {len(seen)} commands: "
                              f"{answer if isinstance(answer, owner_mcp.Refused) else answer.get('join')}")
        server.keyfile.chmod(0o644)
        answer, seen, _sent, made = self.joined(server, "root", "/bin/sh",
                                                {"kind": "linux", "authkey_file": str(server.keyfile)})
        if not isinstance(answer, owner_mcp.Refused) or "chmod 600" not in str(answer) or made or seen:
            issues.append(f"a key file that other users can read: add_machine made {made} and sent {len(seen)} "
                          f"commands: {answer if isinstance(answer, owner_mcp.Refused) else answer.get('join')}")
        self.assertNoIssues(issues)

    # Tailscale's command on a server where it is installed but not on the network, as far as the network step uses
    # it. `up` needs tailscaled to run (STATE/daemon). It refuses to drop the settings that an earlier `tailscale up`
    # left (STATE/prefs), as Tailscale's own check of the settings does, unless it has --reset. With no --timeout, it
    # waits for ever (here it ends with a status of 3). It comes up only with a key file.
    TAILSCALE_OFF = r'''#!/bin/sh
case $1 in
status) [ -s "$STATE/backend" ] || { echo "Logged out."; exit 1; }
        echo "100.101.102.103  vps-1  linux  -" ;;
up) [ -s "$STATE/daemon" ] || { echo "failed to connect to local tailscaled (sudo systemctl start tailscaled ?)" >&2
                                exit 1; }
    key= reset= limit=
    for word in "$@"; do
        case $word in --auth-key=file:*) key=${word#--auth-key=file:} ;; --reset) reset=yes ;;
                      --timeout=*) limit=${word#--timeout=} ;; esac
    done
    if [ -s "$STATE/prefs" ] && [ -z "$reset" ]; then
        echo "Error: changing settings via 'tailscale up' requires mentioning all non-default flags." >&2
        echo "    tailscale up --accept-dns=false --advertise-tags=tag:fleet,tag:server" >&2
        exit 1
    fi
    [ -n "$limit" ] || { echo "tailscale: this stand-in waits for ever with no --timeout" >&2; exit 3; }
    [ -n "$key" ] || { echo "tailscale: this stand-in comes up with a key file only" >&2; exit 2; }
    /bin/cat "$key" > "$STATE/key" && echo Running > "$STATE/backend" ;;
ip) [ -s "$STATE/backend" ] || { echo "no current Tailscale IPs; state: NeedsLogin" >&2; exit 1; }
    echo 100.101.102.103 ;;
*) exit 2 ;;
esac
'''

    # systemd's `systemctl`, as far as the network step uses it: it starts tailscaled.
    SYSTEMCTL = '#!/bin/sh\n[ "$*" = "enable --now tailscaled" ] && echo running > "$STATE/daemon"\nexit 0\n'

    def test_the_network_step_starts_tailscaled_and_drops_the_settings_of_an_earlier_tailscale_up(self):
        """**The network step of add_machine starts tailscaled when it does not run, and its `tailscale up` has
        --reset and a time limit.** A server that an earlier join line left waiting for a sign-in keeps the settings of
        that `tailscale up`, its tags too, and Tailscale refuses a `tailscale up` that does not name each of them again,
        unless it has --reset: without it, each new try fails in the same way. A tailscaled that does not run refuses
        each `tailscale up`. And `tailscale up` with no --timeout waits for ever on a tailnet that approves each new
        machine by hand. TAILSCALE_OFF plays each of these, and SYSTEMCTL starts tailscaled."""
        issues = []
        for user in ("root", "deploy"):
            for why in ("tailscaled does not run", "an earlier tailscale up left its settings"):
                who, server = f"{user}, when {why}", self.server()
                (server.files / "tailscale").write_text(self.TAILSCALE_OFF)
                server.give("tailscale")
                (server.tools / "systemctl").write_text(self.SYSTEMCTL)
                (server.tools / "systemctl").chmod(0o755)
                if why.startswith("an earlier"):
                    (server.state / "daemon").write_text("running\n")
                    (server.state / "prefs").write_text("--advertise-tags=tag:fleet,tag:server\n")
                answer, seen, _sent, made = self.joined(server, user, "/bin/sh",
                                                        {"kind": "linux", "authkey_file": str(server.keyfile)})
                if (isinstance(answer, owner_mcp.Refused) or server.given_key() != server.KEY
                        or made != [{"kind": "linux"}] or (answer.get("join") or {}).get("exit") != 0):
                    issues.append(f"{who}: tailscale up read {server.given_key()!r}, the hub made {made}, and "
                                  f"add_machine said "
                                  f"{answer if isinstance(answer, owner_mcp.Refused) else answer.get('join')}")
                if server.key_file() is not None:
                    issues.append(f"{who}: the key file stays on the server")
        self.assertNoIssues(issues)

    def test_a_key_that_tailscale_refuses_stops_add_machine_in_tailscales_words_before_the_hub_makes_a_code(self):
        """**When `tailscale up` refuses the owner's key, add_machine stops with Tailscale's words before the hub makes
        a code**, and no key file stays on the server: a key works one time unless the owner made it reusable, and a
        tag of the key must be in the owner's Tailscale policy (INSTALL-PROMPT.md B2)."""
        said = "backend error: invalid key: API key does not exist"
        issues = []
        for user in ("root", "deploy"):
            server = self.server()
            (server.files / "tailscale").write_text(
                "#!/bin/sh\ncase $1 in\nstatus) echo 'Logged out.'; exit 1 ;;\n"
                f"up) echo {shlex.quote(said)} >&2; exit 1 ;;\n"
                "ip) echo 'no current Tailscale IPs; state: NeedsLogin' >&2; exit 1 ;;\n*) exit 2 ;;\nesac\n")
            answer, seen, _sent, made = self.joined(server, user, "/bin/sh",
                                                    {"kind": "linux", "authkey_file": str(server.keyfile)})
            if (not isinstance(answer, owner_mcp.Refused) or said not in str(answer)
                    or "No join line was made" not in str(answer)):
                issues.append(f"{user}: add_machine did not stop with Tailscale's words: "
                              f"{answer if isinstance(answer, owner_mcp.Refused) else answer.get('join')}")
            if made or any("FLEET_JOIN=" in remote for remote, _stdin, _codes in seen) or server.key_file() is not None:
                issues.append(f"{user}: the hub made {made}, add_machine sent "
                              f"{[remote[-40:] for remote, _stdin, _codes in seen]}, and the key file on the server "
                              f"is {server.key_file()}")
        self.assertNoIssues(issues)

    # hub.sh, as far as install_hub and install_log reach it: its plan; its network step, which installs Tailscale and
    # reads the auth key on standard input only when the server is not on the private network; its firewall step, after
    # which a new SSH session comes in over the private network only (STATE/firewall); and its log with the claim code.
    FIREWALL_HUB = r'''#!/bin/sh
[ "${1:-}" = --check ] && { echo "Founderizer: check only: nothing on this machine changes"; exit 0; }
echo "Founderizer step 4: the private network (Tailscale)"
if tailscale status >/dev/null 2>&1; then
    echo "Founderizer:   this machine is on the private network already"
else
    command -v tailscale >/dev/null 2>&1 || { /bin/cp "$FILES/tailscale" "$SYSTEM/tailscale" && /bin/chmod 755 "$SYSTEM/tailscale"; }
    IFS= read -r key || { echo "Founderizer install stopped: No Tailscale auth key came in." >&2; exit 1; }
    ( umask 077; printf '%s\n' "$key" > "$ROOTHOME/hub-authkey" ) && tailscale up --auth-key="file:$ROOTHOME/hub-authkey" \
        || { echo "Founderizer install stopped: Tailscale did not join with that auth key." >&2; exit 1; }
    /bin/rm -f "$ROOTHOME/hub-authkey"
    echo "Founderizer:   this machine joined the private network"
fi
echo "Founderizer step 5: the firewall: the private network only"
echo on > "$STATE/firewall"
exec /bin/cat "$FILES/install.log"
'''

    @contextlib.contextmanager
    def private_network(self, server, user, sh="/bin/sh", private=True):
        """**SSH from the owner's Mac to `server` at two addresses**, as owner_mcp runs it (its `subprocess.run` is
        played): at HOST until the firewall step of the install (FIREWALL_HUB writes STATE/firewall), and at the server's
        address on the private network while the server is on that network. With `private` False, that address does not
        answer, as for a Mac that is not on the private network. SSH runs in BatchMode, so it connects only to a server
        whose key it knows: the owner's own known_hosts knows HOST only, and a connection that names its own known_hosts
        file (UserKnownHostsFile, with StrictHostKeyChecking=yes) finds the key there under the name that it looks up
        (HostKeyAlias, else the address). The machine's reads are answered as Ubuntu 24.04 answers them for `user`, and
        each other command runs on the server as `user` (`as_root`, or `through_sudo` with `sh`). It gives each command
        with the address that it went to, the file on its standard input, and SSH's own failure or None."""
        uid = "0" if user == "root" else "1000"
        reads = {self.READ: f'{user}\n{uid}\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\nNAME="Ubuntu"\n/usr/bin/systemctl',
                 "id -un; id -u": f"{user}\n{uid}"}
        sent = []

        def knows(options, address):
            if "userknownhostsfile" not in options:
                return address == self.HOST
            name = options.get("hostkeyalias", address)
            known = pathlib.Path(options["userknownhostsfile"].strip('"'))
            lines = known.read_text().splitlines() if known.exists() else []
            return options.get("stricthostkeychecking") == "yes" and any(
                line.split()[:3] == [name, *self.HOST_KEY.split()[:2]] for line in lines)

        def run(line, stdin=None, capture_output=False, text=False, timeout=None, env=None):
            options, at = {}, 1
            while line[at].startswith("-"):
                if line[at] == "-o":
                    name, _, value = line[at + 1].partition("=")
                    options.setdefault(name.lower(), value)         # as in ssh, the first value of an option counts
                at += 2
            address, remote = options.get("hostname", line[at].partition("@")[2]), line[-1]
            on_network = (server.state / "backend").exists()
            failed = (f"ssh: Could not resolve hostname {address}: Name or service not known"
                      if address not in (self.HOST, server.ADDRESS) else
                      f"ssh: connect to host {address} port 22: Operation timed out"
                      if (address == self.HOST and (server.state / "firewall").exists())
                      or (address == server.ADDRESS and not (on_network and private)) else
                      None if knows(options, address) else "Host key verification failed.")
            given = getattr(stdin, "name", None)
            sent.append((address, remote, given, failed))
            if failed:
                return subprocess.CompletedProcess(line, 255, "", failed + "\n")
            if remote in reads:
                return subprocess.CompletedProcess(line, 0, reads[remote] + "\n", "")
            ran = (self.as_root(server, remote, given) if user == "root" else
                   self.through_sudo(server, remote, sh, given))
            return subprocess.CompletedProcess(line, ran.status, ran.out, ran.err)

        played = types.SimpleNamespace(run=run, DEVNULL=subprocess.DEVNULL, TimeoutExpired=subprocess.TimeoutExpired)
        with patch.object(owner_mcp, "subprocess", played), self.on_server(server):
            yield sent

    def test_after_the_firewall_of_the_install_the_log_and_the_install_reach_the_server_on_the_private_network(self):
        """**After the firewall step of the install, the server lets SSH in over the fleet's private network only, and
        install_log and a second install_hub still reach it when the agent gives its public address.** hub.sh turns
        its firewall on right after its network step, long before it prints the claim code: a session that is open
        stays open, but each new SSH session to the public address is refused. So install_hub puts the server on the
        private network itself (INSTALL-PROMPT.md A2), with the owner's key on standard input, before it starts the
        install, and keeps the keys of the server's SSH for its address on that network. Then hub.sh needs no key, and
        each later command of install_hub and install_log goes to that address, also when the agent gives that address.
        The owner's own known_hosts does not know the address, and SSH in BatchMode refuses a server that it does not
        know. Until 11 November 2026 install_hub gave the key to hub.sh on standard input, and each install_log after
        the firewall step could not connect: the agent could not read the claim code, and the claim time went by.
        FIREWALL_HUB plays hub.sh up to the claim, and `private_network` plays SSH to the two addresses."""
        issues = []
        for user, sh in [("root", "/bin/sh")] + [("deploy", sh) for sh in SHELLS]:
            who, server = f"{user}, with {sh}", self.server()
            (server.files / "hub.sh").write_text(self.FIREWALL_HUB)
            install, answers = dict(self.install(server), host=self.HOST, ssh_user=user), {}
            with self.private_network(server, user, sh) as sent:
                for name, tool, args in (("install", "install_hub", install),
                                         ("log", "install_log", {"host": self.HOST, "ssh_user": user}),
                                         ("log at the address", "install_log",
                                          {"host": server.ADDRESS, "ssh_user": user}),
                                         ("again", "install_hub", install)):
                    try:
                        answers[name] = getattr(owner_mcp, tool)(args)
                    except owner_mcp.Refused as refused:
                        answers[name] = refused
            said = {name: str(answer) if isinstance(answer, owner_mcp.Refused) else None
                    for name, answer in answers.items()}
            if said["install"] or server.ADDRESS not in answers["install"]["next"]:
                issues.append(f"{who}: install_hub said {said['install'] or answers['install']['next']}")
            if not (server.state / "firewall").exists():
                issues.append(f"{who}: the install did not get to its firewall step")
            for name in ("log", "log at the address"):
                if said[name] or (answers[name]["claim_code"], answers[name]["hub_address"]) != (server.CODE,
                                                                                                server.ADDRESS):
                    issues.append(f"{who}: the {name} gave no claim code: {said[name] or answers[name]['log']}")
            if said["again"]:
                issues.append(f"{who}: install_hub again said {said['again']}")
            # Each first read goes to the public address first. After the firewall step it waits there for SSH's
            # ConnectTimeout, and then it goes to the private address: in install_log, and in install_hub again.
            failed = [(address, remote, failure) for address, remote, _given, failure in sent if failure]
            timed_out = f"ssh: connect to host {self.HOST} port 22: Operation timed out"
            if failed != [(self.HOST, "id -un; id -u", timed_out), (self.HOST, self.READ, timed_out)]:
                issues.append(f"{who}: SSH could not connect: {failed}")
            given = [(address, remote[-60:]) for address, remote, stdin, _failed in sent if stdin]
            if len(given) != 1 or server.given_key() != server.KEY or server.key_file() is not None:
                issues.append(f"{who}: the key went on the standard input of {given}, tailscale up read "
                              f"{server.given_key()!r}, and the key file on the server is {server.key_file()}")
            if "on the private network already" not in (server.read("fleet-install.log") or ""):
                issues.append(f"{who}: hub.sh put the server on the private network itself: "
                              f"{server.read('fleet-install.log')!r}")
        self.assertNoIssues(issues)

    def test_install_hub_starts_no_install_whose_server_this_mac_cannot_reach_on_the_private_network(self):
        """**install_hub starts the install only when this Mac reaches the server over the fleet's private network**,
        because the firewall of the install lets SSH in only there. When the server's address on that network does not
        answer (here this Mac is not on the network), install_hub stops before the start, says where it could not
        connect and what the owner checks, and the server's firewall stays as it is. Until 11 November 2026 install_hub
        started the install, and after its firewall step nobody could read its log over SSH. And when a firewall
        refuses the public address and the private address does not answer either, install_log gives SSH's words at
        each address; with no private address kept for the host, its words name the firewall as a cause; and for a
        private address as the host, they say to check that this Mac is on the private network."""
        issues = []
        for user in ("root", "deploy"):
            server = self.server()
            (server.files / "hub.sh").write_text(self.FIREWALL_HUB)
            reach = {"host": self.HOST, "ssh_user": user}
            answers = {}
            with self.private_network(server, user, private=False):
                for name, tool, args in (("install", "install_hub", dict(self.install(server), **reach)),
                                         ("log", "install_log", reach), ("log with no address", "install_log", reach),
                                         ("log at the address", "install_log", dict(reach, host=server.ADDRESS))):
                    if name == "log":
                        (server.state / "firewall").write_text("on\n")         # an install of another kind
                    elif name == "log with no address":
                        owner_mcp.KNOWN_HOSTS.unlink()
                    try:
                        answers[name] = getattr(owner_mcp, tool)(args)
                    except owner_mcp.Refused as refused:
                        answers[name] = refused
            words = {name: str(answer) if isinstance(answer, owner_mcp.Refused) else None
                     for name, answer in answers.items()}
            if not words["install"] or any(part not in words["install"] for part in (
                    "did not start", server.ADDRESS, "this Mac", "Operation timed out", "tailscale ip -4")):
                issues.append(f"{user}: install_hub said {words['install'] or answers['install']['next']}")
            if server.read("fleet-install.log") is not None or server.key_file() is not None:
                issues.append(f"{user}: install_hub started the install, or left the key file on the server")
            both = (f"ssh: connect to host {self.HOST} port 22: Operation timed out. At {server.ADDRESS}, its address "
                    f"on the fleet's private network, SSH said: ssh: connect to host {server.ADDRESS} port 22: "
                    f"Operation timed out.")
            if not words["log"] or both not in words["log"] or "If an install turned on the firewall" in words["log"]:
                issues.append(f"{user}: install_log at two addresses that do not answer said "
                              f"{words['log'] or answers['log']['log']}")
            if not words["log with no address"] or "If an install turned on the firewall" not in words[
                    "log with no address"] or server.ADDRESS in words["log with no address"]:
                issues.append(f"{user}: install_log with no private address kept said {words['log with no address']}")
            at = words["log at the address"]
            if not at or "check that this Mac is on that network" not in at or "If an install turned on" in at:
                issues.append(f"{user}: install_log at a private address that does not answer said {at}")
        self.assertNoIssues(issues)

    def test_the_first_read_goes_to_the_kept_private_address_only_when_ssh_gets_no_connection_to_the_host(self):
        """**The first read of install_hub and install_log goes to the address that the owner gave, and to the server's
        kept address on the private network only when SSH gets no connection there** (`first_read`). The address that
        the owner gave names the server that the owner means: a kept address can belong to a server that the owner
        replaced and that still runs, and a read there would send the install to the wrong machine. A refusal of SSH
        that is not a missing connection, such as a host key that changed, goes to the agent as it came. A command to
        the private address checks the server against the keys of that host only, on the port that its SSH said, with
        no jump host and no proxy command. A host with no kept address gets no second read."""
        private = "100.101.102.103"
        owner_mcp.pin(self.HOST, private, f"port 2222\n{self.HOST_KEY}\n{private}\n")
        timed_out = f"ssh: connect to host {self.HOST} port 22: Operation timed out"
        no_route = f"ssh: connect to host {private} port 22: No route to host"
        pinned = ["-o HostName=100.101.102.103", "-o ProxyJump=none", "-o ProxyCommand=none",
                  f"-o HostKeyAlias={self.HOST}@{private}", f'-o UserKnownHostsFile="{owner_mcp.KNOWN_HOSTS}"',
                  "-o StrictHostKeyChecking=yes", "-o UpdateHostKeys=no", "-p 2222"]
        issues = []
        for why, host, at_host, at_private, went, via in (
                ("the host answers", self.HOST, (0, ""), (0, ""), ["host"], None),
                ("the host's key changed", self.HOST, (255, "Host key verification failed."), (0, ""), ["host"], None),
                ("no connection to the host", self.HOST, (255, timed_out), (0, ""), ["host", private], private),
                ("no connection at both", self.HOST, (255, timed_out), (255, no_route), ["host", private], None),
                ("no address kept for the host", "198.51.100.7", (255, timed_out), (0, ""), ["host"], None)):
            lines = []

            def run(line, stdin=None, capture_output=False, text=False, timeout=None, env=None, at_host=at_host,
                    at_private=at_private, lines=lines):
                lines.append(" ".join(line))
                status, error = at_private if f"HostName={private}" in line else at_host
                return subprocess.CompletedProcess(line, status, "root\n0\n" if status == 0 else "", error + "\n")

            played = types.SimpleNamespace(run=run, DEVNULL=subprocess.DEVNULL, TimeoutExpired=subprocess.TimeoutExpired)
            with patch.object(owner_mcp, "subprocess", played):
                got = owner_mcp.first_read(host, "root", "id -un; id -u", "late")
            where = [private if f"HostName={private}" in line else "host" for line in lines]
            if (where, got[0]) != (went, via):
                issues.append(f"{why}: the read went to {where}, and the tool goes on at {got[0]}")
            if why == "no connection at both" and (got[1]["error"] != timed_out or no_route not in got[2]):
                issues.append(f"{why}: the tool gets {got[1]['error']!r} and {got[2]!r}")
            for line, place in zip(lines, where):
                wrong = [option for option in pinned if (option in line) != (place == private)]
                if wrong or not line.endswith(f"root@{host} id -un; id -u"):
                    issues.append(f"{why}: the command to {place} is {line!r}: {wrong}")
        self.assertNoIssues(issues)

    def test_the_first_ssh_keeps_the_key_of_a_new_server_and_a_changed_key_stops_with_the_owners_step(self):
        """**The first read of install_hub, install_log and add_machine works for a new server whose key the owner's
        SSH has never seen, and a key that changed still stops it, with words that say what the owner does.** SSH in
        BatchMode refuses a server whose key it does not know: "Host key verification failed.", with status 255. Until
        12 November 2026 `ssh` gave SSH no value of StrictHostKeyChecking at the address that the owner gave. So
        install_hub and add_machine stopped at their first read on each new server, and the agent could give the
        owner only SSH's error. Now SSH keeps the key that the server gives at the first connection (accept-new), in
        the owner's own known_hosts, as the Mac app's install and INSTALL-PROMPT.md A1 do. `run` plays SSH's check as
        OpenSSH does it with the first value of StrictHostKeyChecking that it gets: against the owner's known_hosts (a
        file of this test), or against the file that UserKnownHostsFile names, under the name of HostKeyAlias. A key
        that it keeps goes on, another key stops it, and an unknown key goes on only with accept-new, which keeps it.
        A command to the private address with the keys that the network step kept still checks them strictly."""
        folder = pathlib.Path(tempfile.mkdtemp(prefix="fleet-owner-known-hosts-"))
        self.addCleanup(shutil.rmtree, str(folder), True)
        owner, key, sent = folder / "known_hosts", " ".join(self.HOST_KEY.split()[:2]), []
        owner.write_text("")                                        # the owner's SSH has never seen a server
        earlier = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEFuRWFybGllck1hY2hpbmVBdFRoaXNBZGRyZXNzMDE"
        changed = ("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
                   "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n"
                   "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
                   "Host key verification failed.\n")

        def run(line, stdin=None, capture_output=False, text=False, timeout=None, env=None):
            options, at = {}, 1
            while line[at].startswith("-"):
                if line[at] == "-o":
                    name, _, value = line[at + 1].partition("=")
                    options.setdefault(name.lower(), value)         # as in ssh, the first value of an option counts
                at += 2
            known = pathlib.Path(options.get("userknownhostsfile", str(owner)).strip('"'))
            name = options.get("hostkeyalias", options.get("hostname", line[at].partition("@")[2]))
            sent.append((name, options.get("stricthostkeychecking", "ask")))
            keys = [" ".join(entry.split()[1:3]) for entry in (known.read_text().splitlines() if known.exists() else [])
                    if entry.split()[:1] == [name]]
            if keys and key not in keys:
                return subprocess.CompletedProcess(line, 255, "", changed)
            if not keys and sent[-1][1] != "accept-new":
                return subprocess.CompletedProcess(line, 255, "", "Host key verification failed.\n")
            if not keys:
                with open(known, "a") as kept:
                    kept.write(f"{name} {key}\n")
            return subprocess.CompletedProcess(line, 0, "root\n0\nLinux\n", "" if keys else (
                f"Warning: Permanently added '{name}' (ED25519) to the list of known hosts.\n"))

        played = types.SimpleNamespace(run=run, DEVNULL=subprocess.DEVNULL, TimeoutExpired=subprocess.TimeoutExpired)
        issues, private = [], "100.101.102.103"
        with patch.object(owner_mcp, "subprocess", played):
            for read in ("the first read of a new server", "the read after it"):
                _via, said, _tried = owner_mcp.first_read(self.HOST, "root", "id -un; id -u", "late")
                if (said["exit"], sent[-1], owner.read_text().splitlines()) != (
                        0, (self.HOST, "accept-new"), [f"{self.HOST} {key}"]):
                    issues.append(f"{read} ended with {said['exit']} ({said['error']!r}), SSH got {sent[-1]}, and the "
                                  f"owner's known_hosts holds {owner.read_text().splitlines()}")
            owner.write_text(f"{self.HOST} {earlier}\n")
            _via, said, tried = owner_mcp.first_read(self.HOST, "root", "id -un; id -u", "late")
            words = str(owner_mcp.ssh_failed(self.HOST, "root", said, tried))
            try:
                owner_mcp.add_machine({"kind": "linux", "host": self.HOST, "ssh_user": "root"})
                joined = "no refusal"
            except owner_mcp.Refused as refused:
                joined = str(refused)
            for tool, said_words in (("install_hub", words), ("add_machine", joined)):
                if (f"`ssh-keygen -R {self.HOST}`" not in said_words or "Do not remove it yourself" not in said_words
                        or "REMOTE HOST IDENTIFICATION HAS CHANGED" not in said_words):
                    issues.append(f"{tool}, where the owner's known_hosts keeps the key of an earlier machine for the "
                                  f"address, said: {said_words}")
            if said["exit"] != 255 or owner.read_text() != f"{self.HOST} {earlier}\n":
                issues.append(f"the read where the owner's known_hosts keeps the key of an earlier machine ended with "
                              f"{said['exit']}, and the owner's known_hosts holds {owner.read_text().splitlines()}")
            owner_mcp.pin(self.HOST, private, f"{self.HOST_KEY}\n{private}\n")
            pinned = owner_mcp.KNOWN_HOSTS.read_text()
            said = owner_mcp.ssh(self.HOST, "root", "id -u", via=private)
            if (said["exit"], sent[-1], owner_mcp.KNOWN_HOSTS.read_text()) != (
                    0, (f"{self.HOST}@{private}", "yes"), pinned):
                issues.append(f"the command to the private address ended with {said['exit']} ({said['error']!r}), "
                              f"and SSH got {sent[-1]}")
        self.assertNoIssues(issues)

    def test_the_keys_that_a_server_gives_count_for_its_own_host_and_change_no_other(self):
        """**`pin` keeps only lines of keys, under "<host>@<address>", and it changes no line of another host.** A
        server that a hostile owner of it controls can say that it has the hub's address, and print lines of
        known_hosts of its own: a marker, the name of another host. None of that reaches the file, and the hub's lines
        stay as they were. But the keys for the hub's address count for a command whose host is that address itself
        no more, because the two hosts that found it do not agree. The keys of the hub at a new address replace its
        old lines. A file that this Mac cannot read as text gets no write, so no line of it is lost, and no temporary
        file stays."""
        other = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE90aGVyU2VydmVyS2V5T2ZUaGlzVGVzdA root@vps-2"
        hub, other_key = " ".join(self.HOST_KEY.split()[:2]), " ".join(other.split()[:2])
        self.assertTrue(owner_mcp.pin(self.HOST, "100.101.102.103", f"port 22\n{self.HOST_KEY}\n100.101.102.103\n"))
        self.assertEqual(owner_mcp.kept(address="100.101.102.103"), (f"{self.HOST}@100.101.102.103", "22"))
        self.assertTrue(owner_mcp.pin("hub.example.com", "100.101.102.103", f"port 22\n{self.HOST_KEY}\n"))
        self.assertEqual(owner_mcp.kept(address="100.101.102.103"), ("hub.example.com@100.101.102.103", "22"))
        self.assertTrue(owner_mcp.pin("hub.example.com", "100.101.102.150", f"{self.HOST_KEY}\n"))
        said = (f"{other}\n@cert-authority * {other_key}\n{self.HOST} {other_key}\n100.101.102.103 {other_key}\n"
                f"@revoked {self.HOST}@100.101.102.103 {hub}\n100.101.102.103\n")
        self.assertTrue(owner_mcp.pin("198.51.100.7", "100.101.102.103", said))
        self.assertEqual(owner_mcp.KNOWN_HOSTS.read_text().splitlines(),
                         [f"{self.HOST}@100.101.102.103 {hub} port=22", f"hub.example.com@100.101.102.150 {hub}",
                          f"198.51.100.7@100.101.102.103 {other_key}"])
        self.assertEqual(owner_mcp.kept(name=f"{self.HOST}@100.101.102.103"), (f"{self.HOST}@100.101.102.103", "22"))
        self.assertIsNone(owner_mcp.kept(address="100.101.102.103"))
        self.assertTrue(owner_mcp.pin(self.HOST, "100.101.102.200", f"{self.HOST_KEY}\n100.101.102.200\n"))
        self.assertEqual(owner_mcp.KNOWN_HOSTS.read_text().splitlines(),
                         [f"hub.example.com@100.101.102.150 {hub}", f"198.51.100.7@100.101.102.103 {other_key}",
                          f"{self.HOST}@100.101.102.200 {hub}"])
        self.assertEqual((owner_mcp.kept_address(self.HOST), owner_mcp.kept_address("198.51.100")),
                         ("100.101.102.200", None))
        self.assertFalse(owner_mcp.pin(self.HOST, "100.101.102.103", "no key here\n100.101.102.103\n"))
        owner_mcp.KNOWN_HOSTS.write_bytes(b"\xff\xfe not text\n")
        self.assertFalse(owner_mcp.pin(self.HOST, "100.101.102.103", f"{self.HOST_KEY}\n"))
        self.assertEqual(owner_mcp.KNOWN_HOSTS.read_bytes(), b"\xff\xfe not text\n")
        self.assertEqual(sorted(path.name for path in owner_mcp.KNOWN_HOSTS.parent.iterdir()),
                         ["known_hosts", "known_hosts.lock"])

    # hub.sh, as far as the owner's choice of servers reaches it: what it reads in FLEET_MANAGER_SERVER and its
    # arguments, for the plan and for the install (STATE/hub-sh).
    WORD_HUB = r'''#!/bin/sh
echo "${FLEET_MANAGER_SERVER:-no word} [$*]" >> "$STATE/hub-sh"
case " $* " in *" --check "*) echo "Founderizer: check only: nothing on this machine changes"; exit 0 ;; esac
exec /bin/cat "$FILES/install.log"
'''

    def test_the_word_of_the_owners_choice_reaches_hub_sh_as_root_and_through_sudo(self):
        """**FLEET_MANAGER_SERVER=later stands in front of `sh <kit>/hub.sh` inside the one `/bin/sh -c` of a root
        step, so hub.sh reads it in its own environment**, for root and for a user who becomes root through `sudo -n
        -i`, with each shell that root can have. With servers 1 it reads no word, and it gets the manager's provider
        as an argument."""
        issues = []
        for user, sh in [("root", "/bin/sh")] + [("deploy", sh) for sh in SHELLS]:
            for more, want in (({"servers": 2}, ["later [--check]", "later []"]),
                               ({"servers": 1, "runtime": "codex"},
                                ["no word [--runtime codex --check]", "no word [--runtime codex]"])):
                who, server = f"{user}, with {sh}, {more}", self.server()
                (server.files / "hub.sh").write_text(self.WORD_HUB)
                run = (lambda remote, stdin: self.as_root(server, remote, stdin)) if user == "root" else (
                    lambda remote, stdin: self.through_sudo(server, remote, sh, stdin))
                _sent, _made, answer = self.one(server, user, run, "install_hub", dict(self.install(server), **more))
                read, tries = [], 0
                while len(read) < 2 and tries < 1200:       # the start step runs the install in the background
                    read = (server.state / "hub-sh").read_text().splitlines() \
                        if (server.state / "hub-sh").exists() else []
                    tries += 1
                    time.sleep(0.05)
                if isinstance(answer, owner_mcp.Refused) or read != want:
                    issues.append(f"{who}: install_hub said {answer if isinstance(answer, owner_mcp.Refused) else 'yes'}"
                                  f", and hub.sh read {read}, not {want}")
        self.assertNoIssues(issues)

    def test_install_hub_changes_nothing_on_a_server_where_an_install_runs(self):
        """**install_hub stops before it changes anything when an install runs on the server already** (`sh
        <kit>/hub.sh`, which PS plays). A second install would empty the log of the first one, with its claim code, and
        the first one would then wait for a claim that nobody can make. Before 11 November 2026 the install's firewall
        refused such a call at its first read, but the private address does not. A plan that still runs (`--check`,
        after a plan step that did not finish) is not an install, and it does not stop install_hub."""
        issues = []
        for user in ("root", "deploy"):
            server = self.server()
            (server.state / "installing").write_text(f"sh {server.root}/fleet-kit/hub.sh --check\n")
            run = (lambda remote, stdin: self.as_root(server, remote, stdin)) if user == "root" else (
                lambda remote, stdin: self.through_sudo(server, remote, "/bin/sh", stdin))
            _sent, _made, answer = self.one(server, user, run, "install_hub", self.install(server))
            if isinstance(answer, owner_mcp.Refused):
                issues.append(f"{user}: a plan that still runs stopped install_hub: {answer}")
            server = self.server()
            server.write_install_log()
            (server.state / "installing").write_text(f"sh {server.root}/fleet-kit/hub.sh --port 8765\n")
            run = (lambda remote, stdin: self.as_root(server, remote, stdin)) if user == "root" else (
                lambda remote, stdin: self.through_sudo(server, remote, "/bin/sh", stdin))
            sent, _made, answer = self.one(server, user, run, "install_hub", self.install(server))
            words = str(answer) if isinstance(answer, owner_mcp.Refused) else None
            if not words or "an install runs on" not in words or "install_log" not in words:
                issues.append(f"{user}: install_hub said {words or answer['next']}")
            if (server.git_calls() or server.given_key() is not None or server.key_file() is not None
                    or server.read("fleet-install.log") != server.INSTALL_LOG):
                issues.append(f"{user}: install_hub changed the server: {[remote[-40:] for remote, _ran in sent]}")
        self.assertNoIssues(issues)

    # `sshd -T`, as far as the network step reads it: its port, and a host key in a folder of its own.
    SSHD = '#!/bin/sh\n[ "$1" = -T ] || exit 2\necho "port 2222"\necho "hostkey $ROOTHOME/ssh/own/host_key"\n'

    def test_the_network_step_keeps_the_keys_and_the_port_that_the_servers_ssh_names(self):
        """**The network step keeps the keys of the files that `sshd -T` names, and the port of the server's SSH**, as
        root and through sudo: the keys of a server whose SSH does not use the files of Debian and Ubuntu, and a port
        that is not the one of the owner's SSH configuration. Its answer has the address, and no key and no port."""
        own = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE93bktleU9mVGhlU3NoZE9mVGhpc1Rlc3Q root@vps-1"
        issues = []
        for user, sh in [("root", "/bin/sh")] + [("deploy", sh) for sh in SHELLS]:
            who, server = f"{user}, with {sh}", self.server()
            server.give("tailscale")
            server.come_up()
            with server.opened():
                (server.root / "ssh" / "own").mkdir()
                (server.root / "ssh" / "own" / "host_key.pub").write_text(own + "\n")
            (server.tools / "sshd").write_text(self.SSHD)
            (server.tools / "sshd").chmod(0o755)
            owner_mcp.KNOWN_HOSTS.unlink(missing_ok=True)
            run = (lambda remote, stdin: self.as_root(server, remote, stdin)) if user == "root" else (
                lambda remote, stdin: self.through_sudo(server, remote, sh, stdin))
            with self.reached(server, user, run):
                network = owner_mcp.join_network(self.HOST, user, "" if user == "root" else "sudo -n -i -- ", None)
            lines = owner_mcp.KNOWN_HOSTS.read_text().splitlines() if owner_mcp.KNOWN_HOSTS.exists() else []
            if lines != [f"{self.HOST}@{server.ADDRESS} {' '.join(own.split()[:2])} port=2222"]:
                issues.append(f"{who}: the network step kept {lines}")
            if (network["address"], network["with_key"], network["keys_kept"], network["out"]) != (
                    server.ADDRESS, False, True, server.ADDRESS):
                issues.append(f"{who}: the network step gave {network}")
        self.assertNoIssues(issues)

    def test_a_mac_joins_as_the_user_that_ssh_reaches_and_never_as_root(self):
        """**add_machine runs a Mac's join line as the Mac user that will run its agents**, as a line in Terminal runs
        (UI-API.md, "Add server: the join line"). join.sh stops a Mac's line that runs as root, except the line of the
        Founderizer installer, which names that user in FLEET_MAC_USER, and MAC_JOIN plays that rule. Until 11 November
        2026 add_machine ran a Mac's line as root through sudo, as a Linux server's, so it joined no Mac. Now the user's
        login shell gets the hub's line whole in one `/bin/sh -c`; a user who is root, and a kind that is not the
        machine's, are refused before the hub makes a code; and `next` follows what the join did: a line that printed
        nothing did not join, and the vault that sudo could not install goes to Terminal on that Mac."""
        self.assertIn('stop "Run the line in Terminal as the Mac user that will run the agents, not as root."',
                      (HERE / "join.sh").read_text(), "MAC_JOIN plays the rule of join.sh")
        line, issues = self.join_lines()["mac"], []

        def mac_user(server, login):
            return lambda remote, stdin: self.as_mac_user(server, remote, login, stdin)

        for login in [shell for shell in ("/bin/zsh", "/bin/bash") if os.access(shell, os.X_OK)]:
            who, server = f"a Mac user whose login shell is {login}", self.server(mac=True)
            sent, made, answer = self.one(server, "dana", mac_user(server, login), "add_machine", {"kind": "mac"},
                                          "Darwin")
            if made != [{"kind": "mac"}] or [remote for remote, _ran in sent] != ["/bin/sh -c " + shlex.quote(line)]:
                issues.append(f"{who}: the join route got {made}, and add_machine sent "
                              f"{[remote for remote, _ran in sent]}, not the hub's line whole in one /bin/sh -c")
            if any(ran.logged("sudo gets") for _remote, ran in sent):
                issues.append(f"{who}: the line went through sudo")
            if (isinstance(answer, owner_mcp.Refused) or answer["join"]["exit"]
                    or "this machine is the server" not in answer["join"]["out"]
                    or not answer["next"].startswith("Read servers")):
                issues.append(f"{who}: add_machine did not join the Mac, or did not say so: "
                              f"{answer if isinstance(answer, owner_mcp.Refused) else answer}")
            joined = server.folder / "home" / ".fleet" / "joined"
            if (joined.read_text() if joined.exists() else None) != f"dana {StandInServer.CODE}\n" or server.read(
                    "fleet-joined") is not None:
                issues.append(f"{who}: the join did not keep its code in the home of the Mac user, and only there")
        no_script = "curl: (7) Failed to connect to 100.80.1.2 port 8765 after 3 ms: Could not connect to server"
        for why, then in (("curl brings no script", "The join did not run"),
                          ("the vault is not installed", "Terminal")):
            server = self.server(mac=True)
            if why.startswith("curl"):
                (server.folder / "mac-user" / "curl").unlink()
                (server.folder / "mac-user" / "curl").write_text(f"#!/bin/sh\necho {shlex.quote(no_script)} >&2\n"
                                                                 "exit 7\n")
                (server.folder / "mac-user" / "curl").chmod(0o755)
            else:
                (server.files / "join.sh").write_text(self.MAC_JOIN.replace("echo READY\n", "echo \"Founderizer: this "
                                                      "Mac's vault was not installed: the lines above say why.\"\n"
                                                      "exit 1\n"))
            _sent, _made, answer = self.one(server, "dana", mac_user(server, "/bin/bash"), "add_machine",
                                            {"kind": "mac"}, "Darwin")
            if (isinstance(answer, owner_mcp.Refused) or then not in answer["next"]
                    or "add_agent on it" in answer["next"]):
                issues.append(f"when {why}: add_machine says "
                              f"{answer if isinstance(answer, owner_mcp.Refused) else answer['next']!r}")
        for user, kind, system, said in (("root", "mac", "Darwin", "the Mac user that will run its agents"),
                                         ("dana", "linux", "Darwin", "kind mac"),
                                         ("deploy", "mac", "Linux", "kind linux")):
            server = self.server(mac=True)
            sent, made, answer = self.one(server, user, lambda remote, stdin: self.as_root(server, remote, stdin),
                                          "add_machine", {"kind": kind}, system)
            if not isinstance(answer, owner_mcp.Refused) or said not in str(answer) or made or sent:
                issues.append(f"{user}, with kind {kind} on {system}: add_machine made {made} and sent "
                              f"{[remote for remote, _ran in sent]}: "
                              f"{answer if isinstance(answer, owner_mcp.Refused) else answer['join']}")
        self.assertNoIssues(issues)

    def test_a_program_of_any_character_runs_through_sudo_as_it_runs_itself(self):
        """`through_sudo` keeps each character that root's login shell would change, and a "-" first, so that `/bin/sh`
        runs the program through `sudo -n -i` as it runs it itself: the same output, exit status and standard input."""
        programs = ['said=kept; printf "[%s]" "$said"', 'set -- one two; printf "%s|" "$1" "$2" "$#"',
                    'case $- in *c*) echo c ;; *) echo other ;; esac', 'x=1; echo one\necho "two $x"',
                    """x='a\\b'; printf '%s %s %s\\n' "$x" "c\\"d" 'e'"'"'f'""", 'x=100; printf "%s%%\\n" "$x"',
                    "x=in; echo `echo $x` $(echo out)", "x=ü; printf '%s\\n' \"naïve – $x\"",
                    '-v 2>/dev/null; x=1; echo "$x"', 'read line; echo "got $line"', 'x=3; exit "$x"',
                    'x=end; echo "$x"\n', 'x=whole; echo "${x} $(echo sub) $?"']
        server = self.server()
        given = server.folder / "given"
        given.write_text("hello\n")
        issues = []
        for sh in SHELLS:
            for program in programs:
                with open(given) as stdin:
                    itself = subprocess.run([sh, "-c", "--", program], capture_output=True, text=True, timeout=30,
                                            stdin=stdin, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
                ran = self.through_sudo(server, owner_mcp.as_root("sudo -n -i -- ", program), sh, given)
                if (ran.status, ran.out, ran.err) != (itself.returncode, itself.stdout, itself.stderr):
                    issues.append(f"{sh}: {program!r} gave {(ran.status, ran.out, ran.err)} through sudo, and "
                                  f"{(itself.returncode, itself.stdout, itself.stderr)} itself")
                if len(ran.logged("sudo gets")) != 1 or ran.logged("root runs") != ran.logged("sudo gets"):
                    issues.append(f"{sh}: {program!r}: sudo got {ran.logged('sudo gets')}, and root's login shell "
                                  f"ran {ran.logged('root runs')}")
        self.assertNoIssues(issues)
        self.assertEqual(owner_mcp.through_sudo("tail -n 40 /root/fleet-install.log"),
                         "tail -n 40 /root/fleet-install.log", "a program that arrives whole goes as it is")


class McpServers(WithServer):
    """The owner's own MCP servers through this server: ask whether one answers, save it, change it, remove it."""

    URL = {"title": "The CRM", "url": "https://admin.example.com/mcp", "auth": "oauth"}

    def saved(self):
        return json.loads((self.kit / "team.json").read_text()).get("mcp") or {}

    def test_it_checks_a_command_server_against_a_machine_before_anything_is_saved(self):
        """The check writes nothing, and a machine that cannot answer is said to be unasked instead of green."""
        client = self.started()
        answer = client.call("check_mcp_server", name="notes", agent="studio",
                             server={"title": "Notes", "command": "notes-mcp"})
        self.assertEqual((answer["name"], answer["kind"], answer["checked"]), ("notes", "command", False))
        self.assertEqual([row["state"] for row in answer["machines"]], ["not_asked"])
        self.assertIn("has not checked in", answer["machines"][0]["says"])
        self.assertEqual(self.saved(), {})

    @staticmethod
    def team_base(client):
        """The SHA-256 of team.json in the client's own read, which a change of a record that is there goes with."""
        return client.call("fleet_read", page="team")["sha256"]

    def test_it_saves_a_server_changes_it_and_removes_it_from_the_fleet(self):
        client = self.started()
        receipt = client.call("save_mcp_server", name="crm", server=self.URL)     # a new one: no base is needed
        self.assertEqual(receipt["name"], "crm")
        self.assertEqual(self.saved()["crm"]["url"], self.URL["url"])
        self.assertEqual(self.saved()["crm"]["title"], "The CRM")

        client.call("save_mcp_server", name="crm", server=dict(self.URL, title="The CRM, renamed"),
                    base_sha256=self.team_base(client))
        self.assertEqual(self.saved()["crm"]["title"], "The CRM, renamed")

        gone = client.call("save_mcp_server", name="crm", delete=True)
        self.assertTrue(gone["deleted"])
        self.assertEqual(self.saved(), {})

    def test_an_entry_the_hub_refuses_comes_back_in_the_hubs_own_words_and_saves_nothing(self):
        client = self.started()
        for server, says in (({"title": "Both", "url": "https://a.example.com/mcp", "command": "x"}, "not both"),
                             ({"title": "No place"}, "needs a url"),
                             ({"title": "Bad address", "url": "ftp://a.example.com"}, "must be an https address"),
                             # Python's url reader puts a backslash in the host, a runtime's reads it as a slash
                             ({"title": "Two hosts", "url": "https://mcp.stripe.com\\shop.example.com/mcp"},
                              "must be an https address"),
                             # a host in fullwidth letters, which IDNA reads as mcp.stripe.com
                             ({"title": "Wide", "url": "https://mcp.\uff53tripe.com/mcp"},
                              "must be an https address"),
                             ({"url": "https://a.example.com/mcp"}, "needs a title")):
            with self.assertRaises(Refused) as caught:
                client.call("save_mcp_server", name="crm", server=server)
            self.assertIn(says, str(caught.exception), server)
        with self.assertRaises(Refused) as caught:
            client.call("save_mcp_server", name="fleet", server=self.URL)
        self.assertIn("Fleet's own", str(caught.exception))
        self.assertEqual(self.saved(), {})

    def test_a_server_made_from_an_older_read_of_the_team_is_the_hubs_own_conflict(self):
        """It carries the SHA-256 of the team.json that the client read before it made the entry, so a change that
        arrived after that read is a 409 and never a silent overwrite of somebody else's entry. A base that the tool
        read itself at the time of the write held that change already (the review of 20 November 2026)."""
        client = self.started()
        client.call("save_mcp_server", name="crm", server=self.URL)
        read = self.team_base(client)
        client.call("save_mcp_server", name="crm", server=dict(self.URL, title="The CRM, renamed"), base_sha256=read)
        with self.assertRaises(Refused) as caught:
            client.call("save_mcp_server", name="crm", server=dict(self.URL, title="Made from the older read"),
                        base_sha256=read)
        self.assertIn("changed meanwhile", str(caught.exception))
        self.assertEqual(self.saved()["crm"]["title"], "The CRM, renamed")


class Admin(WithServer):
    """The admin actions beside the ones FromNothing already walks: the shape of the team, the owner's words about an
    agent, the entries of team.json, his own knowledge, the people who may write to an agent, and a file."""

    def team_file(self):
        return json.loads((self.kit / "team.json").read_text())

    def test_it_writes_a_profile_as_the_owner_and_reads_the_agents_own_notes_without_writing_them(self):
        client = self.started()
        page = client.call("fleet_read", page="profiles")
        before = next(p for p in page["profiles"] if p["agent"] == "studio")
        sections = [dict(s, text="Careful, and quick.") if s["key"] == "character" else s
                    for s in before["sections"]]
        receipt = client.call("save_profile", agent="studio", sections=sections, base_sha256=before["sha256"])
        self.assertNotEqual(receipt.get("sha256"), before["sha256"])
        after = next(p for p in client.call("fleet_read", page="profiles")["profiles"] if p["agent"] == "studio")
        self.assertIn("Careful, and quick.", after["text"])

        notes = client.call("fleet_read", page="notes", agent="studio")
        self.assertEqual(notes["agent"], "studio")
        self.assertNotIn("save_notes", {t["name"] for t in owner_mcp.tools()})      # the agent's own, never written
        with self.assertRaises(Refused) as caught:
            client.call("fleet_read", page="notes", agent="nobody")
        self.assertIn("(404)", str(caught.exception))

    def test_a_profile_made_from_an_older_read_is_the_hubs_refusal_and_the_newer_words_stay(self):
        """The review of 20 November 2026: the tool read the base itself at the time of the write, so sections made
        from a read before the owner changed the profile in the app went over that change with no refusal. The base
        is the client's own read now, and the hub refuses sections made from an older one."""
        client = self.started()
        before = next(p for p in client.call("fleet_read", page="profiles")["profiles"] if p["agent"] == "studio")

        def edited(words):
            return [dict(s, text=words) if s["key"] == "character" else s for s in before["sections"]]
        client.call("save_profile", agent="studio", sections=edited("The newer words, from the app."),
                    base_sha256=before["sha256"])
        with self.assertRaises(Refused) as caught:
            client.call("save_profile", agent="studio", sections=edited("Made from the older read."),
                        base_sha256=before["sha256"])
        self.assertIn("the profile changed meanwhile; reload it", str(caught.exception))
        self.assertIn(owner_mcp.MOVED, str(caught.exception))
        after = next(p for p in client.call("fleet_read", page="profiles")["profiles"] if p["agent"] == "studio")
        self.assertIn("The newer words, from the app.", after["text"])
        self.assertNotIn("Made from the older read.", after["text"])

    def test_it_sets_the_reporting_lines_so_a_worker_reports_to_a_lead(self):
        client = self.started()
        team = client.call("fleet_read", page="team")
        lines = [{"agent": l["agent"], "role": l["agent"] == "lead" and "lead" or l["role"],
                  "reports_to": "lead" if l["agent"] == "vps" else l.get("reports_to")}
                 for l in team["lines"]]
        client.call("set_reporting_lines", lines=lines, base_sha256=team["sha256"])
        self.assertEqual(self.team_file()["agents"]["vps"]["reports_to"], "lead")
        self.assertEqual(self.team_file()["agents"]["lead"]["role"], "lead")

    def test_a_null_that_the_hub_takes_reaches_it(self):
        """A field whose schema takes null sends its null (the tool's `nulls`): a chat app account is removed with
        account null, and an agent's title is taken away with title null. Until 20 November 2026 the tools left every
        null out, so the hub refused the removal (account absent) and kept the title."""
        client = self.started()
        account = {"app": "discord", "label": "The bot", "agents": ["vps"], "unknown": "ignore", "enabled": True}
        client.call("save_chat_account", id="discord-vps", account=account)
        self.assertIn("discord-vps", self.team_file().get("chat_apps") or {})
        client.call("save_chat_account", id="discord-vps", account=None)
        self.assertNotIn("discord-vps", self.team_file().get("chat_apps") or {})
        client.call("agent_settings", agent="vps", title="Night shift")
        self.assertEqual(self.team_file()["agents"]["vps"].get("title"), "Night shift")
        client.call("agent_settings", agent="vps", title=None)
        self.assertIsNone(self.team_file()["agents"]["vps"].get("title"))
        # a role's set taken away (Founderizer for Teams, design 3): the null reaches the hub, which has no Teams here
        # and so refuses it with teams_off; a null left out would be a write of nothing, refused with other words
        with self.assertRaises(Refused) as caught:
            client.call("save_role", name="peer", access=None)
        self.assertIn("This needs Founderizer for Teams, which this fleet does not have.", str(caught.exception))

    def test_a_whole_value_made_from_an_older_read_of_the_team_is_the_hubs_refusal_and_the_change_stays(self):
        """with_base's `whole` (the review of 20 November 2026): the reporting lines and an agent's lists go with the
        base of the client's own read, so lines or boxes made from a read before somebody else's change are the hub's
        409, and that change stays. A base that the tool read at the time of the write held that change already."""
        client = self.started()
        team = client.call("fleet_read", page="team")
        older = [{"agent": l["agent"], "role": l["role"], "reports_to": l.get("reports_to")} for l in team["lines"]]
        client.call("agent_settings", agent="vps", expertise=["sales"], base_sha256=team["sha256"])
        with self.assertRaises(Refused) as caught:
            client.call("agent_settings", agent="vps", expertise=["support"], base_sha256=team["sha256"])
        self.assertIn("team.json changed meanwhile; reload it", str(caught.exception))
        self.assertEqual(self.team_file()["agents"]["vps"]["expertise"], ["sales"])

        newer = client.call("fleet_read", page="team")
        lines = [dict(l, reports_to="lead") if l["agent"] == "vps" else dict(l, role="lead") if l["agent"] == "lead"
                 else l for l in older]
        client.call("set_reporting_lines", lines=lines, base_sha256=newer["sha256"])
        with self.assertRaises(Refused) as caught:
            client.call("set_reporting_lines", lines=older, base_sha256=newer["sha256"])
        self.assertIn("team.json changed meanwhile; reload the reporting lines", str(caught.exception))
        self.assertEqual(self.team_file()["agents"]["vps"]["reports_to"], "lead")

    def test_an_account_with_a_kind_and_an_agent_on_it_go_through_the_two_tools(self):
        """Lane 5H (owner API 1.186): save_account gives the hub kind, address and model, and add_agent gives it
        account with no runtime, so the hub's own rules and words decide (here a Mac, sentence 7 of round 2)."""
        client = self.started()
        client.call("save_account", account="spark", provider="own", title="Spark", kind="server",
                    address="http://127.0.0.1:11434", model="own/qwen3.8-max")
        self.assertEqual(self.team_file()["accounts"]["spark"],
                         {"provider": "own", "title": "Spark", "kind": "server", "address": "http://127.0.0.1:11434/v1",
                          "model": "own/qwen3.8-max"})
        self.joined("mini", kind="mac", source=NEW)
        with self.assertRaises(Refused) as caught:
            client.call("add_agent", server="mini", agent="scout", account="spark", role="worker")
        self.assertIn("mini is a Mac. An agent on Model server needs a Linux server: choose another one.",
                      str(caught.exception))
        self.assertNotIn("scout", self.team_file()["agents"])
        # A key's reference goes as `login` (no tool field is named like a value): the hub's own rule refuses one
        # that logins does not have, in its own words.
        with self.assertRaises(Refused) as caught:
            client.call("save_account", account="gemini", provider="google", title="Gemini", kind="key",
                        login="bws://5b0c1d2e-0000-4000-8000-000000000001")
        self.assertIn("account gemini: secret is the reference of an API key in logins", str(caught.exception))

    def test_it_writes_the_entries_of_team_json_and_the_owners_own_knowledge(self):
        client = self.started()
        client.call("save_account", account="openai-main", provider="openai", title="The main account")
        self.assertEqual(self.team_file()["accounts"]["openai-main"],
                         {"provider": "openai", "title": "The main account"})
        client.call("save_login", login="bws://" + ("a" * 8 + "-" + "b" * 4 + "-" + "4" + "c" * 3 + "-" +
                                                    "8" + "d" * 3 + "-" + "e" * 12), title="The CRM login")
        self.assertEqual(len(self.team_file()["logins"]), 1)
        client.call("machine_access", machine="mac-studio", ssh_user="alex", screen_sharing=True)
        self.assertEqual(self.team_file()["access"]["mac-studio"],
                         {"ssh_user": "alex", "ssh_port": 22, "screen_sharing": True})
        client.call("save_account", account="openai-main", delete=True)
        self.assertNotIn("openai-main", self.team_file().get("accounts") or {})

        # The receipt and the commit are the proof here: this fixture's knowledge catalog is read from the test
        # process's own checkout and not from the kit, so the file is checked where the hub committed it.
        made = client.call("save_knowledge", title="The suppliers", text="Acme ships on Tuesdays.", source="owner")
        self.assertEqual((made["ok"], made["path"], made["scope"]), (True, "knowledge/owner/the-suppliers.md", "owner"))
        self.assertTrue(re.fullmatch(r"[0-9a-f]{40}", made["commit"]))
        self.assertIn("Acme ships on Tuesdays.", (self.kit / made["path"]).read_text())
        changed = client.call("save_knowledge", path=made["path"], text="Acme ships on Wednesdays.")
        self.assertEqual((changed["ok"], changed["path"]), (True, made["path"]))
        self.assertIn("Acme ships on Wednesdays.", (self.kit / made["path"]).read_text())
        client.call("save_knowledge", path=made["path"], delete=True)
        self.assertFalse((self.kit / made["path"]).exists())

    def test_it_adds_a_person_with_a_handle_blocks_them_and_removes_them(self):
        client = self.started()
        made = client.call("save_person", name="Ana Ruiz", role="customer", agents=["studio"])
        pid = made["person"]["id"]
        client.call("person_handle", person=pid, app="whatsapp", handle="34600111222", name="Ana")
        people = client.call("fleet_read", page="people")
        person = next(p for p in people["people"] if p["id"] == pid)
        self.assertEqual((person["name"], person["role"]), ("Ana Ruiz", "customer"))
        self.assertEqual([a["agent"] for a in person["agents"]], ["studio"])
        self.assertEqual([h["handle"] for h in person["handles"]], ["34600111222"])
        client.call("save_person", id=pid, blocked=True)
        self.assertTrue(next(p for p in client.call("fleet_read", page="people")["people"]
                             if p["id"] == pid)["blocked"])
        client.call("save_person", id=pid, delete=True)
        self.assertEqual([p for p in client.call("fleet_read", page="people")["people"] if p["id"] == pid], [])

    def test_it_writes_a_role_and_a_setting(self):
        """AUTONOMY.md P1 and section 4: the roles a person holds and the fleet's settings, each one owner route and
        one tool here, refusals in the hub's own words."""
        client = self.started()
        roles = {r["name"]: r for r in client.call("fleet_read", page="roles")["roles"]}
        self.assertEqual(list(roles), ["customer", "peer", "manager"])
        made = client.call("save_role", name="supplier", prompt="A supplier of the shop.", tools=False, daily=10)
        self.assertEqual((made["role"]["tools"], made["role"]["daily"], "changed" in made), (False, 10, False))
        # null is the hub's "no limit", so it goes and is not left out (the reviews of 20 November 2026)
        self.assertEqual(client.call("save_role", name="supplier", daily=None)["role"]["daily"], None)
        self.assertEqual(client.call("save_role", name="supplier", tools=True)["role"]["daily"], None)
        with self.assertRaises(Refused) as caught:
            client.call("save_role", name="supplier", daily=5)
        self.assertIn("(400): a role with tools has no daily limit", str(caught.exception))
        self.assertEqual(client.call("save_role", name="supplier", rename="vendor")["role"]["name"], "vendor")
        self.assertTrue(client.call("save_role", name="vendor", delete=True)["deleted"])
        self.assertEqual([r["name"] for r in client.call("fleet_read", page="roles")["roles"]],
                         ["customer", "peer", "manager"])

        self.assertEqual(client.call("fleet_read", page="settings")["settings"]["contacts.v2"]["value"], False)
        self.assertEqual(client.call("save_settings", settings={"contacts.v2": True})["changed"], ["contacts.v2"])
        self.assertEqual(self.team_file()["settings"], {"contacts.v2": True})
        self.assertTrue(client.call("fleet_read", page="settings")["settings"]["contacts.v2"]["value"])
        with self.assertRaises(Refused) as caught:
            client.call("save_settings", settings={"contacts.v2": "on"})
        self.assertIn("(400): contacts.v2 must be true or false", str(caught.exception))
        client.call("save_settings", settings={"contacts.v2": None})
        self.assertNotIn("settings", self.team_file())

    def test_a_file_goes_to_the_hub_comes_back_whole_and_is_kept(self):
        client = self.started()
        source = pathlib.Path(tempfile.mkdtemp(prefix="fleet-attach-")) / "note.txt"
        self.addCleanup(shutil.rmtree, str(source.parent), True)
        source.write_bytes(b"One page of notes.\n")
        sent = client.call("attach_file", path=str(source))
        self.assertEqual((sent["name"], sent["size"]), ("note.txt", 19))
        self.assertEqual(sent["sha256"], hashlib.sha256(b"One page of notes.\n").hexdigest())

        back = source.parent / "came-back.txt"
        got = client.call("read_attachment", attachment=sent["id"], path=str(back))
        self.assertEqual(back.read_bytes(), b"One page of notes.\n")
        self.assertEqual(got["sha256"], sent["sha256"])
        self.assertTrue(client.call("keep_attachment", attachment=sent["id"], keep=True)["kept"])

    def test_the_hand_on_each_switch_the_app_has(self):
        """The small controls: Pause all, a conversation, the manager session, and a reload the hub refuses."""
        client = self.started()
        self.assertTrue(client.call("pause_chat_apps", paused=True)["paused"])
        self.assertFalse(client.call("pause_chat_apps", paused=False)["paused"])
        self.assertEqual(client.call("start_manager_session", agent="manager")["state"], "requested")
        with self.assertRaises(Refused) as caught:
            client.call("start_manager_session", agent="studio")
        self.assertIn("only the manager has a standing session", str(caught.exception))
        with self.assertRaises(Refused) as caught:
            client.call("reload_team", revision="not-a-revision")
        self.assertIn("revision must be a commit id", str(caught.exception))


class Boundary(WithServer):
    """OWNER-MCP-BOUNDARY.md. This server carries the owner's whole authority, so the one thing it must never become
    is a tool the manager can grant to an agent. Nothing refuses it by name, and nothing should: what makes a grant
    of it inert is the hub's address gate, and above all the one line of validate_team that keeps an agent off the
    owner's machine. That line is asserted here, beside the server it protects, because nothing else tied the two
    together and a later change could have taken it out with every check still passing."""

    # A command server takes no args (plan 0.2), and no interpreter is a command (lifecycle.MCP_RUNNERS, 15 November
    # 2026), so the stand-in is a launcher program of this server, as a person would put one on the PATH.
    ADMIN = {"title": "Founderizer admin", "command": "founderizer-admin"}

    def live(self):
        """The team.json the hub has now, which validates as it stands: then one changed field is the whole cause of
        a refusal below."""
        team = json.loads(json.dumps(hub.TEAM))
        hub.validate_team(team)
        return team

    def test_no_agent_can_be_put_on_the_owners_address_or_on_an_owner_devices_address(self):
        """The invariant the whole boundary rests on. An agent that reached the owner's address would hold the owner's
        authority outright: ui_allowed knows the owner by the address alone."""
        team = self.live()
        team["addresses"]["mac-studio"] = team["addresses"]["owner"]
        with self.assertRaises(ValueError) as caught:
            hub.validate_team(team)
        self.assertIn("would be on the owner's address", str(caught.exception))

        # The owner's phones are trusted by their own address too (device_allowed), so the same invariant holds
        # there. The hub refuses that collision from the device's side, which comes first in validate_team: no
        # device may take a machine's address at all, the owner's machine included. The agent-side refusal
        # ("would be on an owner device's address") is the second guard on the one invariant.
        for machine in ("mac-studio", "owner"):
            team = self.live()
            team["owner_devices"] = {"phone": {"label": "The owner's phone",
                                               "address": team["addresses"][machine]}}
            with self.assertRaises(ValueError) as caught:
                hub.validate_team(team)
            self.assertIn("has the address of a machine", str(caught.exception), machine)

    def test_no_agent_gets_the_hubs_own_public_address_as_a_server(self):
        """The connected apps (the build specification of the MCP address): the hub's own MCP address is the owner's,
        at the level of the owner's code. An agent that held it as a server could connect itself."""
        names = dict(hub.TAILNET_NAMES)
        self.addCleanup(lambda: (hub.TAILNET_NAMES.clear(), hub.TAILNET_NAMES.update(names)))
        hub.TAILNET_NAMES["names"] = ("hub-1.tail0000.ts.net", "hub-1")
        for url in ("https://hub-1.tail0000.ts.net/mcp", "https://HUB-1.tail0000.ts.net./mcp",
                    "https://hub-1.tail0000.ts.net/other", "https://hub-1.tail0000.ts.net:443/mcp",
                    "HTTPS://hub-1.tail0000.ts.net/mcp?x=1"):
            with self.subTest(url=url):
                team = self.live()
                team["mcp"] = {"x": {"title": "X", "url": url}}
                with self.assertRaisesRegex(ValueError, "this hub's own public MCP address"):
                    hub.validate_team(team)
        # The owner's own MCP server on the hub machine is no connected app: another port, the short name, or http on
        # the hub's own loopback (lifecycle.mcp_address takes http only there)
        for url in ("https://mcp.example.com/mcp", "https://hub-1:9000/mcp", "https://hub-1/mcp",
                    "https://hub-1.tail0000.ts.net:9000/mcp", "https://hub-1.tail0000.ts.net:8443/mcp",
                    "http://127.0.0.1:9000/mcp"):
            with self.subTest(url=url):
                team = self.live()
                team["mcp"] = {"x": {"title": "X", "url": url}}
                hub.validate_team(team)

    def test_a_connected_apps_token_is_no_credential_of_the_hubs_own_port(self):
        """A connection's access token, replayed on the hub's own port: the owner's Mac takes no bearer token, a phone
        takes only its own key, any other address is no owner, and an agent's MCP route takes only a session
        credential. So the token never reaches an owner route."""
        token, sha = "example-connected-app-token-0123456789", None
        connection = hub.ins("INSERT INTO capp_connections(client,name,redirect_host,level,resource,created) "
                             "VALUES('c','Claude','claude.ai','act','https://hub-1.tail0000.ts.net/mcp',?)", (hub.now(),))
        hub.ins("INSERT INTO capp_tokens(sha256,connection,kind,created,expires) VALUES(?,?,'access',?,?)",
                (hashlib.sha256(token.encode()).hexdigest(), connection, hub.now(), hub.now() + 3600))
        bearer = {"Content-Type": "application/json", "X-Fleet-Client": "test", "Authorization": "Bearer " + token}
        code, answer = self.request("/ui/mobile", headers=bearer, source=OWNER)
        self.assertEqual((code, answer.get("auth")), (403, "key_not_expected"))
        hub.TEAM["owner_devices"] = {"iphone": {"label": "iPhone", "address": "127.0.0.6"}}
        made = hub.new_device_code("iphone")
        hub.enroll_device("iphone", made["code"])
        code, answer = self.request("/ui/mobile", headers=bearer, source="127.0.0.6")
        self.assertEqual((code, answer.get("auth")), (403, "device_key_mismatch"))
        code, answer = self.request("/ui/mobile", headers=bearer, source="127.0.0.10")
        self.assertEqual(code, 403)
        code, answer = self.request("/mcp/studio", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                                    headers=bearer, source=STUDIO)
        self.assertEqual((code, answer.get("auth")), (403, "credential_invalid"))

    def test_the_owners_own_computer_cannot_join_the_fleet_as_a_machine(self):
        """The other half of it: the owner's Mac never becomes a machine that an agent could be placed on."""
        with self.assertRaises(hub.Refusal) as caught:
            hub.join_server(OWNER, {"code": "AAAA-BBBB-CCCC", "key_sha256": "0" * 64, "kind": "mac",
                                    "user": "owner", "ssh_port": None})
        self.assertIn("your own computer", str(caught.exception))

    def test_grant_access_does_not_refuse_this_server_by_name_and_is_not_asked_to(self):
        """Deliberately asserts that the hole exists. An MCP server is a grantable kind, and grant_check knows one
        server from another no better than it knows one repository from another. If this ever starts refusing, the
        mechanism has been swapped for a blocklist of one file name, which renaming the file walks round: read
        OWNER-MCP-BOUNDARY.md section 4 before making that change."""
        client = self.started()
        client.call("save_mcp_server", name="founderizer", server=self.ADMIN)
        client.call("share_resource", resource="tool:founderizer", max="use")
        self.assertEqual(hub.resource_pool().get("tool:founderizer", {}).get("max"), "use")
        self.assertIsNone(hub.grant_check("studio", "tool:founderizer", "use"),
                          "grant_check refuses this server now: see OWNER-MCP-BOUNDARY.md section 4")
        client.call("grant_access", resource="tool:founderizer", agent="studio", level="use")
        self.assertIn("founderizer", hub.agents()["studio"].get("tools") or [])

    def test_the_grant_it_makes_is_inert_because_the_authority_is_the_address(self):
        """What the agent that holds it actually gets: a program that starts and every owner route refused. The
        granted tools are the dangerous ones on purpose."""
        client = self.started()
        client.call("save_mcp_server", name="founderizer", server=self.ADMIN)
        hub.TEAM["addresses"]["owner"] = NEW          # this process is now at an address that names no owner
        for name, args in (("grant_access", {"resource": "repo:acme/web", "agent": "studio", "level": "write"}),
                           ("share_resource", {"resource": "repo:acme/web", "max": "write"}),
                           ("fleet_read", {"page": "resources"}),
                           ("save_mcp_server", {"name": "founderizer", "delete": True})):
            with self.assertRaises(Refused) as caught:
                client.call(name, **args)
            self.assertIn("is not owner's machine", str(caught.exception), name)
            self.assertIn("the Mac whose address is", str(caught.exception), name)
        self.assertEqual(hub.agents()["studio"].get("repos") or {}, {})


class SecretGive(WithServer):
    """**A give of a secret that would reach no server is not sent** (`owner_mcp.secret_reaches`), against the real
    owner API of hub.py. The page of the vault is the hub's own (`vault_view`), from a status of the central vault
    that the test gives the hub as its timer keeps one (`hub.CENTRAL`). The team's page is the hub's own too. A copy
    on a machine is a real row of the hub's `deposits`, and a secret that an agent made a real row of its `jobs`. A
    give that is sent is the hub's own grant, read back from team.json. Only four tests answer the route of the
    vault's page themselves: a hub with no such page, a read that it refuses, no answer, and a generation that moved
    two times. `routes` has each request of the three routes in its order, and `pages` each page of the vault that
    the hub gave.

    The team is the one of `test_servers`, with a catalog of three secrets and with one worker more, on the hub's own
    machine: the workers vps and lead on the machine vps, studio on mac-studio, and aide beside the manager on hub.
    Each of the three machines has a vault that takes deliveries: an agent with broker access whose helper reports its
    broker, a store key in `vault_stores`, and that same key as the machine's pin in the central vault."""

    REF = "bws://aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"          # an API key of the catalog
    LOGIN = "bws://bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee"        # a login of the catalog
    MADE = "bws://cccccccc-bbbb-4ccc-8ddd-eeeeeeeeeeee"         # a login of the catalog, which an agent made
    ABSENT = "bws://dddddddd-bbbb-4ccc-8ddd-eeeeeeeeeeee"       # no secret of the catalog
    KEYS = {"vps": "age1" + "q" * 58, "mac-studio": "age1" + "r" * 58, "hub": "age1" + "s" * 58}    # the store keys
    OTHER = "age1" + "t" * 58
    BROKERS = {"vps": "vps", "lead": "vps", "studio": "mac-studio", "aide": "hub"}       # each agent's machine
    ONE = ["ui_vault", "ui_secret_grant"]                       # a give that the page of the vault settles
    TWO = ["ui_vault", "ui_team", "ui_secret_grant"]            # and one that needs the team too
    ROUTED = ("ui_vault", "ui_team", "ui_secret_grant")         # the routes whose requests go into `routes`

    def setUp(self):
        catalog = {self.REF: {"title": "SHOP_API_KEY", "kind": "api_key", "env": "SHOP_API_KEY"},
                   self.LOGIN: {"title": "shop.example.com · ops", "kind": "login"},
                   self.MADE: {"title": "mail.example.com · ops", "kind": "login"}}
        agents = dict(test_servers.TEAM["agents"],
                      aide={"role": "worker", "runtime": "codex", "machine": "hub", "can": ["shell", "web"]})
        agents = {name: dict(a, vault="broker", vault_recipient=self.KEYS[self.BROKERS[name]])
                  if name in self.BROKERS else a for name, a in agents.items()}
        with patch.dict(test_servers.TEAM, {"logins": catalog, "vault_stores": dict(self.KEYS), "agents": agents}):
            super().setUp()
        for agent, machine in self.BROKERS.items():         # each one's key, and its helper's report of the broker
            hub.q("INSERT INTO agent_keys(agent,sha256,created,source) VALUES(?,?,?,?)",
                  (agent, hashlib.sha256(agent.encode()).hexdigest(), hub.now(), "test"))
            row = hub.q1("SELECT data FROM machine_status WHERE agent=?", (agent,))
            data = dict(json.loads(row["data"]) if row else {}, features=["secret_deposits", "secret_withdrawals"],
                        security={"vault": {"broker_recipient": self.KEYS[machine], "callers": True, "deposits": True,
                                            "withdrawals": True, "replaces": True, "broker_read_at": hub.now(),
                                            "mode": "broker"}})
            hub.q("INSERT INTO machine_status(agent,data,reported) VALUES(?,?,?) ON CONFLICT(agent) DO UPDATE SET "
                  "data=excluded.data, reported=excluded.reported", (agent, json.dumps(data), hub.now()))
        self.routes, self.pages = [], []
        for name in self.ROUTED:
            self.route(name)
        view = hub.vault_view
        self.patched(hub, "vault_view", lambda *args, **kw: self.pages.append(view(*args, **kw)) or self.pages[-1])
        state = patch.dict(hub.CENTRAL, hub.CENTRAL_START, clear=True)      # no central vault, until `central`
        state.start()
        self.addCleanup(state.stop)

    def patched(self, where, name, value):
        change = patch.object(where, name, value)
        change.start()
        self.addCleanup(change.stop)

    def route(self, name, instead=None):
        """Each request of this route goes into `routes`, and then the hub's own handler answers it, or `instead`."""
        real = getattr(hub.Handler, name)

        def seen(handler, *args):
            self.routes.append(name)
            return instead(handler) if instead else real(handler, *args)
        self.patched(hub.Handler, name, seen)

    def central(self, pool=(), grants=(), pins=None, **changes):
        """The hub's last good reading of the central vault, as `hub.central_read` keeps it: the owner pinned each
        machine's own store key (or `pins`), and signed what `pool` and `grants` say."""
        pins = self.KEYS if pins is None else pins
        status = dict({"ok": True, "v": 2, "central": True, "fleet": hub.fleet_id(), "owner_keys": 1,
                       "pins": {machine: {"recipient": key, "at": 1} for machine, key in pins.items()},
                       "recovery": None, "grants": list(grants), "pool": list(pool), "items": 3}, **changes)
        with hub.CENTRAL_LOCK:
            hub.CENTRAL.update(status=status, read_at=hub.now(), tried_at=hub.now(), error=None)

    def signed(self, agent, machine):
        """One grant of the secret that the owner signed, as the central vault's status lists it."""
        return {"login": self.REF, "agent": agent, "machine": machine}

    def holds(self, machine, agent):
        """The hub's own record that this machine's vault took a copy of the secret, sealed to its pinned key."""
        hub.q("INSERT INTO deposits(login,machine,agent,recipient,sha256,ciphertext,request_id,created,finished,ok) "
              "VALUES(?,?,?,?,?,NULL,?,?,?,1)",
              (self.REF, machine, agent, self.KEYS[machine], "0" * 64, str(uuid.uuid4()), hub.now(), hub.now()))

    def machine(self, name):
        """One machine's entry of the newest page of the vault that the hub gave."""
        return next(m for m in self.pages[-1]["machines"] if m["machine"] == name)

    def given(self, agent):
        """The secrets that the fleet's list gives this agent now, from team.json as the hub committed it."""
        return self.origin_team()["agents"][agent].get("secrets") or {}

    def give(self, client, agent="vps", level="use", ref=None):
        return client.call("grant_access", resource="secret:" + (ref or self.REF), agent=agent, level=level)

    def sent(self, client, routes, agent="vps", level="use", ref=None):
        """The give goes after exactly these requests, and the hub's own grant is in the fleet's list."""
        self.routes.clear()
        self.assertTrue(self.give(client, agent=agent, level=level, ref=ref)["changed"])
        self.assertEqual(self.routes, routes)
        self.assertEqual(self.given(agent).get((ref or self.REF).lower()), level)

    def refused(self, client, agent="vps", level="use", ref=None):
        """The give is refused in the one fixed sentence, which names no secret and no agent, after the two reads, and
        no command reached the hub: its list did not change."""
        before = self.count("ui_controls"), self.given(agent)
        self.routes.clear()
        with self.assertRaises(Refused) as caught:
            self.give(client, agent=agent, level=level, ref=ref)
        self.assertEqual(str(caught.exception), owner_mcp.GRANT_NOT_SIGNED)
        self.assertNotIn("bws://", str(caught.exception))
        self.assertEqual(self.routes, ["ui_vault", "ui_team"])
        self.assertEqual((self.count("ui_controls"), self.given(agent)), before)

    # ---- step 1: the page of the vault cannot judge, so the give goes as before, after that one read
    def test_a_hub_with_no_page_of_the_vault_gets_the_give_as_before(self):
        self.route("ui_vault", lambda handler: handler.json(404, {"error": "not found"}))
        self.sent(self.started(), self.ONE)

    def test_a_read_of_the_vault_that_the_hub_refuses_does_not_stop_the_give(self):
        self.route("ui_vault", lambda handler: handler.json(500, {"error": "the hub could not read its records"}))
        self.sent(self.started(), self.ONE)

    def test_a_fleet_with_no_central_vault_gets_the_give_as_before(self):
        with hub.CENTRAL_LOCK:              # what hub.central_read keeps when no socket of a central vault is there
            hub.CENTRAL.update(tried_at=hub.now(), error="no central vault answers on this hub")
        self.sent(self.started(), self.ONE, level="read")
        self.assertEqual((self.pages[-1]["central"], self.pages[-1]["error"]),
                         (None, "no central vault answers on this hub"))

    def test_a_vault_with_no_good_reading_gets_the_give(self):
        client = self.started()
        self.central(ok=False)
        self.sent(client, self.ONE, agent="vps")
        self.assertIs(self.pages[-1]["central"]["ok"], False)
        # The hub's newest read failed: the page still has the last good status, which shows nothing signed.
        self.central()
        with hub.CENTRAL_LOCK:
            hub.CENTRAL.update(error="the central vault did not answer in 5 seconds")
        self.sent(client, self.ONE, agent="lead")
        page = self.pages[-1]
        self.assertEqual((page["central"]["ok"], page["central"]["pool"], page["central"]["grants"], page["error"]),
                         (True, [], [], "the central vault did not answer in 5 seconds"))

    def test_a_hub_that_does_not_answer_the_read_of_the_vault_stops_the_give(self):
        self.central()
        self.route("ui_vault", lambda handler: setattr(handler, "close_connection", True))      # no answer at all
        with self.assertRaises(Refused) as caught:
            self.give(self.started())
        self.assertRegex(str(caught.exception), r"\AThe (call to the hub at \S+ was lost|hub at \S+ did not answer)")
        self.assertEqual((self.routes, self.given("vps"), self.count("ui_controls")), (["ui_vault"], {}, 0))

    def test_a_generation_that_moved_two_times_at_the_read_of_the_vault_stops_the_give(self):
        self.central()
        self.route("ui_vault", lambda handler: handler.json(409, {"error": "hub generation changed; refresh state"}))
        with self.assertRaises(Refused) as caught:
            self.give(self.started())
        self.assertEqual(str(caught.exception),
                         "The hub refused a read of the vault (409): hub generation changed; refresh state")
        self.assertEqual((self.routes, self.given("vps"), self.count("ui_controls")),
                         (["ui_vault", "ui_vault"], {}, 0))

    # ---- step 2: the pool
    def test_a_secret_of_the_pool_is_given_with_no_read_of_the_team(self):
        self.central(pool=[self.REF])
        self.sent(self.started(), self.ONE, ref="bws://" + self.REF[6:].upper())    # compared in lower case
        self.assertEqual(self.pages[-1]["central"]["pool"], [self.REF])

    # ---- step 3: what the team's page says, each in the state that refuses a give of REF to a worker
    def test_a_secret_that_the_catalog_does_not_have_and_a_level_that_does_not_fit_get_the_hubs_own_words(self):
        self.central()
        client = self.started()
        for ref, level, words in ((self.ABSENT, "use", "no such secret"),
                                  (self.LOGIN, "read", "only an API key can be read"),
                                  ("bws://no-reference", "use", "login must be a bws://<uuid> reference"),
                                  (self.REF, "write", "grant must be use, read or null")):
            self.routes.clear()
            with self.assertRaises(Refused) as caught:
                self.give(client, ref=ref, level=level)
            self.assertIn(words, str(caught.exception), ref)
            self.assertNotIn("central vault", str(caught.exception), ref)
            self.assertEqual(self.routes, self.TWO, ref)
        self.assertEqual(self.given("vps"), {})
        self.refused(client, ref=self.LOGIN)        # a login of the catalog at `use` is judged, and refused

    def test_a_secret_that_an_agent_made_is_not_judged(self):
        self.central()
        hub.ins("INSERT INTO jobs(agent,task,kind,login,created,finished,ok) VALUES('lead',1,'create',?,?,?,1)",
                (self.MADE, hub.now(), hub.now()))          # as the hub keeps a create_login that ended well
        made = self.request("/ui/team?db=test-generation", source=OWNER)[1]["created_logins"]
        self.assertEqual([(m["login"], m["agent"], m["state"]) for m in made], [(self.MADE, "lead", "created")])
        client = self.started()
        self.sent(client, self.TWO, agent="vps", ref=self.MADE)     # on the maker's server
        self.sent(client, self.TWO, agent="studio", ref=self.MADE)  # and on another one: it is not judged at all
        self.assertEqual((self.pages[-1]["central"]["pool"], self.pages[-1]["held"]["vps"]), ([], []))
        self.refused(client, agent="vps", ref=self.LOGIN)           # a login that no agent made is judged

    def test_a_give_to_an_agent_that_the_list_does_not_have_gets_the_hubs_own_answer(self):
        self.central()
        client = self.started()
        for agent, words in (("ghost", "no such agent"), ("door", "this fleet has no door")):
            self.routes.clear()
            with self.assertRaises(Refused) as caught:
                self.give(client, agent=agent)
            self.assertIn(words, str(caught.exception), agent)
            self.assertEqual(self.routes, self.TWO, agent)

    def test_a_give_to_the_manager_is_not_judged_also_on_a_server_with_a_worker(self):
        self.central()
        client = self.started()
        self.sent(client, self.TWO, agent="manager")
        self.assertEqual((hub.TEAM["agents"]["manager"]["machine"], hub.TEAM["agents"]["aide"]["machine"]),
                         ("hub", "hub"))
        self.assertEqual(self.machine("hub")["missing"], [])        # the manager's server takes deliveries
        self.refused(client, agent="aide")                          # and the worker beside the manager is judged

    def test_a_server_that_takes_no_deliveries_now_is_not_judged(self):
        client = self.started()
        self.central(pins={machine: key for machine, key in self.KEYS.items() if machine != "vps"})
        self.sent(client, self.TWO, agent="vps")                    # the owner's pin of vps is not there
        self.assertEqual(self.machine("vps")["missing"], ["not_pinned"])
        self.central(pins=dict(self.KEYS, **{"mac-studio": self.OTHER}))
        self.sent(client, self.TWO, agent="studio")                 # the pin is another key than its vault's
        self.assertEqual(self.machine("mac-studio")["missing"], ["pin_mismatch"])
        self.assertEqual(self.machine("vps")["missing"], [])
        self.refused(client, agent="lead")                          # vps has its pin again, so it is judged

    # ---- steps 4 and 5: what the owner signed for the machine, and what its vault holds already
    def test_a_grant_signed_for_another_agent_of_the_same_machine_is_enough(self):
        self.central(grants=[self.signed("lead", "vps")])
        self.sent(self.started(), self.TWO, agent="vps")
        self.assertEqual(self.pages[-1]["central"]["grants"], [self.signed("lead", "vps")])

    def test_a_grant_signed_only_for_another_machine_is_refused(self):
        self.central(grants=[self.signed("studio", "mac-studio"), self.signed("vps", "mac-studio")])
        client = self.started()
        self.refused(client, agent="vps")
        self.sent(client, self.TWO, agent="studio")         # and it is enough for the machine that it names

    def test_a_copy_that_the_machines_vault_holds_is_enough(self):
        self.central()
        self.holds("vps", "lead")
        self.sent(self.started(), self.TWO, agent="vps")
        self.assertEqual(self.pages[-1]["held"], {"hub": [], "mac-studio": [], "vps": [self.REF]})

    def test_a_copy_only_in_the_vault_of_another_machine_is_refused(self):
        self.central()
        self.holds("mac-studio", "studio")
        self.refused(self.started(), agent="vps")
        self.assertEqual(self.pages[-1]["held"], {"hub": [], "mac-studio": [self.REF], "vps": []})

    # ---- step 6, and what the rule never touches
    def test_a_give_that_the_reading_shows_as_never_delivered_is_refused_and_nothing_reaches_the_hub(self):
        """A worker on a server that takes deliveries, a secret of the catalog that no agent made, nothing signed and
        no copy: the one give that is refused, at each level."""
        self.central()
        client = self.started()
        for level in ("use", "read"):
            self.refused(client, agent="vps", level=level)
        page = self.pages[-1]
        self.assertEqual((page["central"]["pool"], page["central"]["grants"], page["held"]["vps"], page["error"],
                          self.machine("vps")["missing"]), ([], [], [], None, []))
        team = self.request("/ui/team?db=test-generation", source=OWNER)[1]
        self.assertEqual((team["logins"][self.REF]["kind"], team["created_logins"]), ("api_key", []))
        self.assertEqual([(line["role"], line["machine"]) for line in team["lines"] if line["agent"] == "vps"],
                         [("worker", "vps")])
        self.assertEqual(self.count("ui_controls"), 0)

    def test_a_take_back_goes_with_no_read_in_the_state_that_refuses_a_give(self):
        self.central()
        # The grant is in the list by the hub's own route, which takes it from each process of the owner's computer:
        # the program's check is no gate (OWNER-MCP-BOUNDARY.md section 7).
        status, receipt = self.owner("/ui/secrets/grant", login=self.REF, agent="vps", grant="use")
        self.assertEqual((status, receipt.get("changed"), self.given("vps")), (200, True, {self.REF: "use"}))
        client = self.started()
        self.refused(client, agent="lead")
        self.routes.clear()
        self.pages.clear()
        self.assertTrue(self.give(client, agent="vps", level=None)["changed"])
        self.assertEqual((self.routes, self.pages, self.given("vps")), (["ui_secret_grant"], [], {}))

    def test_a_give_of_a_repository_a_tool_and_a_google_service_reads_no_page_of_the_vault(self):
        self.central()                      # the state that refuses a give of a secret
        client = self.started()
        for resource, level in (("repo:acme/web", "write"), ("tool:github", "use"),
                                ("gmail:ada@example.com", "read"), ("drive:ada@example.com", "read")):
            self.routes.clear()
            try:
                client.call("grant_access", resource=resource, agent="vps", level=level)
            except Refused:
                pass                        # the hub's own words for a tool or an account that it does not have
            self.assertEqual(self.routes[:1], ["ui_team"], resource)
            self.assertNotIn("ui_vault", self.routes, resource)
        self.assertEqual(self.pages, [])
        self.assertEqual(self.origin_team()["agents"]["vps"]["repos"], {"acme/web": "write"})


class ShareStanding(SecretGive):
    """**A standing for a secret from which no give could reach a server is not sent** (`owner_mcp.standing_reaches`),
    against the real owner API of hub.py, on the fleet of `SecretGive` (whose own tests do not run here again: the
    suite takes the tests of each class's own body). A standing that is sent is the hub's own entry of team.json
    "resources", read back from the commit. `routes` has each request of the vault's page, the team's page and
    `POST /ui/resources`, in its order."""

    ROUTED = ("ui_vault", "ui_team", "ui_resource")
    JUDGED = ["ui_vault", "ui_team", "ui_resource"]     # a standing for a secret: the vault's page, the team, the command
    UNJUDGED = ["ui_team", "ui_resource"]               # an end, and a standing of another kind

    def share(self, client, ref=None, most="use", resource=None):
        return client.call("share_resource", resource=resource or "secret:" + (ref or self.REF), max=most)

    def standing(self):
        """team.json "resources", as the hub committed it."""
        return self.origin_team().get("resources") or {}

    def sent(self, client, routes, most="use", ref=None, resource=None):
        """The standing goes after exactly these requests, and the hub's own entry is in team.json."""
        self.routes.clear()
        rid = resource or "secret:" + (ref or self.REF)
        self.assertTrue(self.share(client, ref=ref, most=most, resource=resource)["changed"])
        self.assertEqual(self.routes, routes)
        self.assertEqual(self.standing().get(rid.strip().lower()), {"max": most, "to": "workers"})

    def refused(self, client, most="use", ref=None, resource=None):
        """The standing is refused in the one fixed sentence, which names no secret, after the two reads, and no command
        reached the hub: team.json did not change."""
        before = self.count("ui_controls"), self.standing()
        self.routes.clear()
        with self.assertRaises(Refused) as caught:
            self.share(client, ref=ref, most=most, resource=resource)
        self.assertEqual(str(caught.exception), owner_mcp.SHARE_NOT_SIGNED)
        self.assertNotIn("bws://", str(caught.exception))
        self.assertEqual(self.routes, ["ui_vault", "ui_team"])
        self.assertEqual((self.count("ui_controls"), self.standing()), before)

    # ---- step 1: the page of the vault cannot judge, so the standing goes as before, after that one read more
    def test_a_hub_with_no_page_of_the_vault_gets_the_standing(self):
        self.route("ui_vault", lambda handler: handler.json(404, {"error": "not found"}))
        self.sent(self.started(), self.JUDGED)

    def test_a_read_of_the_vault_that_the_hub_refuses_does_not_stop_the_standing(self):
        self.route("ui_vault", lambda handler: handler.json(500, {"error": "the hub could not read its records"}))
        self.sent(self.started(), self.JUDGED)

    def test_a_fleet_with_no_central_vault_gets_the_standing(self):
        with hub.CENTRAL_LOCK:
            hub.CENTRAL.update(tried_at=hub.now(), error="no central vault answers on this hub")
        self.sent(self.started(), self.JUDGED, most="read")
        self.assertEqual((self.pages[-1]["central"], self.pages[-1]["error"]),
                         (None, "no central vault answers on this hub"))

    def test_a_vault_with_no_good_reading_gets_the_standing(self):
        client = self.started()
        self.central(ok=False)
        self.sent(client, self.JUDGED, most="read")
        self.assertIs(self.pages[-1]["central"]["ok"], False)
        self.central()
        with hub.CENTRAL_LOCK:
            hub.CENTRAL.update(error="the central vault did not answer in 5 seconds")
        self.sent(client, self.JUDGED, most="use")
        self.assertEqual((self.pages[-1]["central"]["pool"], self.pages[-1]["error"]),
                         ([], "the central vault did not answer in 5 seconds"))

    def test_a_hub_that_does_not_answer_the_read_of_the_vault_stops_the_standing(self):
        self.central()
        self.route("ui_vault", lambda handler: setattr(handler, "close_connection", True))      # no answer at all
        with self.assertRaises(Refused) as caught:
            self.share(self.started())
        self.assertRegex(str(caught.exception), r"\AThe (call to the hub at \S+ was lost|hub at \S+ did not answer)")
        self.assertEqual((self.routes, self.standing(), self.count("ui_controls")), (["ui_vault"], {}, 0))

    def test_a_generation_that_moved_two_times_at_the_read_of_the_vault_stops_the_standing(self):
        self.central()
        self.route("ui_vault", lambda handler: handler.json(409, {"error": "hub generation changed; refresh state"}))
        with self.assertRaises(Refused) as caught:
            self.share(self.started())
        self.assertEqual(str(caught.exception),
                         "The hub refused a read of the vault (409): hub generation changed; refresh state")
        self.assertEqual((self.routes, self.standing(), self.count("ui_controls")),
                         (["ui_vault", "ui_vault"], {}, 0))

    # ---- step 2: the pool, with the resource as the hub reads it
    def test_a_secret_of_the_pool_gets_the_standing(self):
        self.central(pool=[self.REF])
        self.sent(self.started(), self.JUDGED, resource="  Secret:bws://" + self.REF[6:].upper() + " ")
        self.assertEqual(self.pages[-1]["central"]["pool"], [self.REF])
        self.assertEqual(self.standing(), {"secret:" + self.REF: {"max": "use", "to": "workers"}})

    # ---- step 3: what the team's page says, each in the state that refuses a standing of REF
    def test_a_secret_that_the_catalog_does_not_have_and_a_max_that_does_not_fit_get_the_hubs_own_words(self):
        self.central()
        client = self.started()
        for ref, most, words in ((self.ABSENT, "use", "is no secret that this team has"),
                                 (self.REF, "write", "max must be one of use, read"),
                                 (self.REF, 7, "max must be one of use, read"),
                                 (self.REF, "", "max must be one of use, read")):
            self.routes.clear()
            with self.assertRaises(Refused) as caught:
                self.share(client, ref=ref, most=most)
            self.assertIn(words, str(caught.exception), (ref, most))
            self.assertNotIn("central vault", str(caught.exception), (ref, most))
            self.assertEqual(self.routes, self.JUDGED, (ref, most))
        self.assertEqual(self.standing(), {})
        self.refused(client, ref=self.LOGIN, most="read")       # a login of the catalog is judged at each level

    def test_a_secret_that_an_agent_made_is_not_judged(self):
        self.central()
        hub.ins("INSERT INTO jobs(agent,task,kind,login,created,finished,ok) VALUES('lead',1,'create',?,?,?,1)",
                (self.MADE, hub.now(), hub.now()))          # as the hub keeps a create_login that ended well
        made = self.request("/ui/team?db=test-generation", source=OWNER)[1]["created_logins"]
        self.assertEqual([(m["login"], m["agent"], m["state"]) for m in made], [(self.MADE, "lead", "created")])
        client = self.started()
        self.sent(client, self.JUDGED, ref=self.MADE)
        self.assertEqual((self.pages[-1]["central"]["pool"], self.pages[-1]["held"]["vps"]), ([], []))
        self.refused(client, ref=self.LOGIN)                # a login that no agent made is judged

    # ---- steps 4, 5 and 6: what the owner signed for any server, what any server's vault holds, and a server that
    # takes no deliveries now
    def test_a_grant_signed_for_any_server_is_enough(self):
        self.central(grants=[self.signed("studio", "mac-studio")])
        self.sent(self.started(), self.JUDGED)
        self.assertEqual(self.pages[-1]["central"]["grants"], [self.signed("studio", "mac-studio")])

    def test_a_grant_signed_only_for_the_door_does_not_count(self):
        """The door is no server that an agent works on: its grant stands under the hub's own name for it, and no
        give of the manager reaches it."""
        self.assertEqual(owner_mcp.DOOR_MACHINE, hub.DOOR_PIN)
        self.central(grants=[self.signed("door", hub.DOOR_PIN)])
        client = self.started()
        self.refused(client)
        self.central(grants=[self.signed("door", hub.DOOR_PIN), self.signed("studio", "mac-studio")])
        self.sent(client, self.JUDGED)      # and a grant for a server beside it is enough

    def test_a_copy_in_the_vault_of_any_server_is_enough(self):
        self.central()
        self.holds("mac-studio", "studio")
        self.sent(self.started(), self.JUDGED, most="read")
        self.assertEqual(self.pages[-1]["held"], {"hub": [], "mac-studio": [self.REF], "vps": []})

    def test_a_server_that_takes_no_deliveries_now_is_not_judged(self):
        self.central(pins={machine: key for machine, key in self.KEYS.items() if machine != "vps"})
        client = self.started()
        self.sent(client, self.JUDGED)                      # the owner's pin of vps is not there
        self.assertEqual(self.machine("vps")["missing"], ["not_pinned"])
        self.central()
        self.refused(client, ref=self.LOGIN)                # every server takes deliveries again, so it is judged

    # ---- step 7, and what the rule never touches
    def test_a_standing_that_the_reading_shows_as_useless_is_refused_and_nothing_reaches_the_hub(self):
        """A secret of the catalog that no agent made, nothing signed, no copy, and every server takes deliveries:
        the one standing that is refused, at each level, and also for a resource with spaces and capitals."""
        self.central()
        client = self.started()
        for most in ("use", "read"):
            self.refused(client, most=most)
        self.refused(client, resource=" SECRET:" + self.REF.upper() + "  ")
        page = self.pages[-1]
        self.assertEqual((page["central"]["pool"], page["central"]["grants"], page["error"],
                          [m["missing"] for m in page["machines"]], page["held"]),
                         ([], [], None, [[], [], []], {"hub": [], "mac-studio": [], "vps": []}))
        team = self.request("/ui/team?db=test-generation", source=OWNER)[1]
        self.assertEqual((team["logins"][self.REF]["kind"], team["created_logins"]), ("api_key", []))
        self.assertNotIn("resources", self.origin_team())
        self.assertEqual(self.count("ui_controls"), 0)

    def test_taking_the_entry_back_goes_with_no_read_of_the_vault_in_the_state_that_refuses_a_standing(self):
        self.central()
        # The standing is in team.json by the hub's own route, which takes it from each process of the owner's
        # computer: the program's check is no gate (OWNER-MCP-BOUNDARY.md section 7).
        status, receipt = self.owner("/ui/resources", resource="secret:" + self.REF,
                                     policy={"max": "use", "to": "workers"}, base_sha256=self.team_sha())
        self.assertEqual((status, receipt.get("changed")), (200, True), receipt)
        client = self.started()
        self.refused(client, ref=self.LOGIN)
        self.routes.clear()
        self.pages.clear()
        self.assertTrue(self.share(client, most=None)["changed"])
        # null: only the owner gives it again, which the hub keeps as their "Only you" under the default (pool_default)
        self.assertEqual((self.routes, self.pages, self.standing()),
                         (self.UNJUDGED, [], {"secret:" + self.REF: {"owner": True}}))

    def test_a_standing_for_a_repository_a_tool_and_a_google_service_reads_no_page_of_the_vault(self):
        self.central()                      # the state that refuses a standing for a secret
        client = self.started()
        for resource, most in (("repo:acme/web", "write"), ("tool:github", "use"),
                               ("gmail:ada@example.com", "read"), ("drive:ada@example.com", "read")):
            self.routes.clear()
            try:
                self.share(client, resource=resource, most=most)
            except Refused:
                pass                        # the hub's own words for a tool that it does not have
            self.assertEqual(self.routes, self.UNJUDGED, resource)
        self.assertEqual(self.pages, [])
        self.assertEqual(self.standing()["repo:acme/web"], {"max": "write", "to": "workers"})


class ShareStandingNoWorker(ShareStanding):
    """The fleet of a customer's first day (`fresh_fleet`: one manager, no worker and no lead), with the catalog of
    `SecretGive`: the page of the vault lists no server, so with nothing signed a standing for a secret is refused.
    The real check on the test network runs on such a fleet."""

    def setUp(self):
        super().setUp()
        team = self.fresh_fleet()
        team["logins"] = {self.REF: {"title": "SHOP_API_KEY", "kind": "api_key", "env": "SHOP_API_KEY"}}
        (self.kit / "team.json").write_text(json.dumps(team, indent=2) + "\n")
        test_servers.git("commit", "-q", "-am", "the catalog", cwd=self.kit)
        test_servers.git("push", "-q", "origin", "HEAD", cwd=self.kit)
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = team

    def test_a_fleet_with_no_worker_and_no_lead_and_nothing_signed_is_refused(self):
        self.central()
        client = self.started()
        self.refused(client)
        self.assertEqual((self.pages[-1]["machines"], self.pages[-1]["held"]), ([], {}))
        self.assertEqual([a.get("role") for a in self.origin_team()["agents"].values()], ["manager"])
        self.central(pool=[self.REF])       # once the owner signed it into the pool, it goes
        self.sent(client, self.JUDGED)


class SignedGrantWords(unittest.TestCase):
    """The words that send the owner's agent to `grant_secret`, the tool of the app's program with which the app
    signs a grant (16 November 2026). This server has no such tool, because only the app holds the owner key: it
    names the tool in the refusal of a give, in the description of `grant_access` and in the reason of the route
    that takes a signed statement. The program inside the app says the same refusal and the same description (the
    parity fixture and the table hold the two programs to each other). The pool's words name `share_secret`, its
    own signed tool (`SignedPoolWords`), and never `grant_secret`."""

    GIVE = ("On this fleet the central vault sends a secret's value to a server only for a grant that the owner's app "
            "signed for an agent on that server, or for a secret that the owner signed into the grantable pool. By the "
            "hub's last reading, this secret is not in the pool, the owner signed no grant of it for this agent's "
            "server, and that server's vault holds no copy of it. A grant from here would show the secret as given in "
            "the fleet's list and, by that reading, bring its value to no server, so nothing was sent. On the Mac "
            "where the Founderizer app runs, its program gives the secret with the owner's signature "
            "(~/.founderizer/cli write grant_secret): the app signs the grant with the owner's key and writes it into "
            "the list, as the owner's own Give on Secrets does, and the owner can also give it there. After either, "
            "grant_access needs no second call. If the owner put the secret into the grantable pool a moment ago, "
            "call grant_access again in a minute: the hub reads the vault at least once a minute.")

    @staticmethod
    def words(name):
        return next(t["description"] for t in owner_mcp.tools() if t["name"] == name)

    def test_the_refusal_of_a_give_names_grant_secret_and_keeps_each_other_sentence(self):
        self.assertEqual(owner_mcp.GRANT_NOT_SIGNED, self.GIVE)
        self.assertNotIn("The owner gives the secret to the agent in the Founderizer app", owner_mcp.GRANT_NOT_SIGNED)
        self.assertNotIn("bws://", owner_mcp.GRANT_NOT_SIGNED)
        # The same words are the app's program's, which has the tool: they say where it is, and no "from here" that
        # would be untrue there. The one "from here" that stays is of a grant from `grant_access`, true in both.
        self.assertNotIn("has grant_secret for this", owner_mcp.GRANT_NOT_SIGNED)
        self.assertNotIn("needed from here", owner_mcp.GRANT_NOT_SIGNED)
        self.assertEqual(owner_mcp.GRANT_NOT_SIGNED.count("from here"), 1)
        self.assertIn("A grant from here would show the secret as given", owner_mcp.GRANT_NOT_SIGNED)
        self.assertIn("(~/.founderizer/cli write grant_secret)", owner_mcp.GRANT_NOT_SIGNED)

    def test_the_description_of_grant_access_names_grant_secret(self):
        words = self.words("grant_access")
        self.assertIn("a give that the hub's reading of the vault shows as neither, for a server whose vault holds no "
                      "copy of it, is refused and nothing is sent: on the Mac where the Founderizer app runs, "
                      "grant_secret of its program (~/.founderizer/cli) gives that secret with the owner's signature, "
                      "as the owner does in the app, on Secrets. A give that the reading cannot judge is sent, and an "
                      "end of a hold (level null) always goes.", words)
        self.assertNotIn("and the owner gives that secret in the Founderizer app", words)
        self.assertEqual(words.count("grant_secret"), 1)

    def test_the_route_of_a_signed_statement_names_grant_secret_and_this_server_has_no_such_tool(self):
        self.assertEqual(owner_mcp.NOT_TOOLS["/ui/vault/grant"],
                         "a statement signed with the owner's own key, which only their app on their Mac holds; for a "
                         "grant of a secret to an agent, or its end, the app's program on the owner's Mac has "
                         "grant_secret (~/.founderizer/cli write grant_secret), and for a secret into the grantable "
                         "pool or out of it, share_secret (~/.founderizer/cli write share_secret); the app then signs "
                         "the statement")
        self.assertNotIn("grant_secret", [t["name"] for t in owner_mcp.tools()])
        # The other routes of a signed statement keep their reason: these tools sign a grant, the pool and their ends
        # only.
        for route in ("/ui/vault/pin", "/ui/vault/recovery"):
            self.assertEqual(owner_mcp.NOT_TOOLS[route],
                             "a statement signed with the owner's own key, which only their app on their Mac holds")

    def test_the_route_of_a_secret_requests_answer_names_answer_secret_request(self):
        """The answer of a secret request with a login is no tool of this server: the app's form gives it, and since
        16 November 2026 `answer_secret_request` of the app's program, which makes the app sign the gives first. The
        decline stays this server's own tool."""
        self.assertEqual(owner_mcp.NOT_TOOLS["/ui/needs/{}/secret"],
                         "a secret request's answer with a login, which the app's secure form gives once the value "
                         "is in a vault, and for a secret that the fleet's list has, the app's program on the "
                         "owner's Mac has answer_secret_request (~/.founderizer/cli write answer_secret_request): "
                         "the app then signs the gives of the call and answers; its decline carries no value, and "
                         "decline_secret_request sends that")
        names = [t["name"] for t in owner_mcp.tools()]
        self.assertNotIn("answer_secret_request", names)
        self.assertIn("decline_secret_request", names)

    def test_the_words_of_the_pool_do_not_name_grant_secret(self):
        self.assertNotIn("grant_secret", owner_mcp.SHARE_NOT_SIGNED)
        self.assertNotIn("grant_secret", self.words("share_resource"))
        self.assertIn("on Secrets", owner_mcp.SHARE_NOT_SIGNED)


class SignedPoolWords(unittest.TestCase):
    """The words that send the owner's agent to `share_secret`, the tool of the app's program with which the app
    signs a secret into the grantable pool and writes the owner's standing (16 November 2026), as `SignedGrantWords`
    holds the words of `grant_secret`. This server has no such tool, because only the app holds the owner key: it
    names the tool in the refusal of a standing, in the description of `share_resource` and in the reason of the
    route that takes a signed statement. The program inside the app says the same refusal and the same description
    (the parity fixture and the table hold the two programs to each other)."""

    SHARE = ("On this fleet the central vault sends a secret's value to a server only for a grant that the owner's app "
             "signed for an agent on that server, or for a secret that the owner signed into the grantable pool. By "
             "the hub's last reading, this secret is not in the signed pool, the owner signed no grant of it for a "
             "server, and no server's vault holds a copy of it. A standing from here would let the fleet manager give "
             "the secret and, by that reading, bring its value to no server, so nothing was sent. On the Mac where "
             "the Founderizer app runs, its program sets it with the owner's signature (~/.founderizer/cli write "
             "share_secret): the app signs the secret into the grantable pool and writes the standing, as the owner's "
             "own Who may give it on Secrets does, and the owner can also set it there. After either, share_resource "
             "needs no second call.")

    words = staticmethod(SignedGrantWords.words)

    def test_the_refusal_of_a_standing_names_share_secret_and_keeps_each_other_sentence(self):
        self.assertEqual(owner_mcp.SHARE_NOT_SIGNED, self.SHARE)
        # The sentences before the last two stay as they were.
        self.assertTrue(owner_mcp.SHARE_NOT_SIGNED.startswith(
            "On this fleet the central vault sends a secret's value to a server only for a grant that the owner's app "
            "signed for an agent on that server, or for a secret that the owner signed into the grantable pool. By the "
            "hub's last reading, this secret is not in the signed pool, the owner signed no grant of it for a server, "
            "and no server's vault holds a copy of it. A standing from here would let the fleet manager give the "
            "secret and, by that reading, bring its value to no server, so nothing was sent. "))
        # What was true until `share_secret`: only the owner's own control signed a secret into the pool.
        for gone in ("The owner sets who may give the secret in the Founderizer app", "nothing more is needed from here",
                     "The app signs that and writes the standing"):
            self.assertNotIn(gone, owner_mcp.SHARE_NOT_SIGNED)
        self.assertNotIn("bws://", owner_mcp.SHARE_NOT_SIGNED)
        # The same words are the app's program's, which has the tool: they say where it is. The one "from here" that
        # stays is of a standing from `share_resource`, true in both.
        self.assertEqual(owner_mcp.SHARE_NOT_SIGNED.count("from here"), 1)
        self.assertIn("A standing from here would let the fleet manager give the secret", owner_mcp.SHARE_NOT_SIGNED)
        self.assertIn("(~/.founderizer/cli write share_secret)", owner_mcp.SHARE_NOT_SIGNED)
        self.assertTrue(owner_mcp.SHARE_NOT_SIGNED.endswith(" After either, share_resource needs no second call."))

    def test_the_description_of_share_resource_names_share_secret(self):
        words = self.words("share_resource")
        self.assertIn("a standing for a secret is refused, and nothing is sent, when the hub's reading of the vault "
                      "shows that no give of the manager from it could bring the value to a server (the secret is not "
                      "in the signed pool, the owner signed no grant of it for a server, and no server's vault holds a "
                      "copy of it): on the Mac where the Founderizer app runs, share_secret of its program "
                      "(~/.founderizer/cli) sets it with the owner's signature, as the owner does in the app, on "
                      "Secrets (Who may give it). A standing that the reading cannot judge is sent, and taking the "
                      "entry back always goes; for a secret, the owner's signed pool statement then stays in the vault "
                      "until the app ends it.", words)
        self.assertNotIn("where the app signs", words)
        self.assertEqual(words.count("share_secret"), 1)

    def test_the_route_of_a_signed_statement_names_share_secret_and_this_server_has_no_such_tool(self):
        why = owner_mcp.NOT_TOOLS["/ui/vault/grant"]
        self.assertIn("and for a secret into the grantable pool or out of it, share_secret (~/.founderizer/cli write "
                      "share_secret); the app then signs the statement", why)
        self.assertTrue(why.startswith("a statement signed with the owner's own key, which only their app on their "
                                       "Mac holds; "))
        self.assertNotIn("share_secret", [t["name"] for t in owner_mcp.tools()])
        self.assertNotIn("share_secret", owner_mcp.GRANT_NOT_SIGNED)
        self.assertNotIn("share_secret", self.words("grant_access"))

    def test_the_vault_is_a_page_of_fleet_read(self):
        """The words of `grant_secret` and `share_secret` send the agent to `fleet_read` with the page `vault`: the
        hub's `GET /ui/vault`, which has no value and no title (hub.py `vault_view`, vault.py `central_status`)."""
        route, what = owner_mcp.PAGES["vault"]
        self.assertEqual(route, "/ui/vault")
        self.assertIn("with no value and no title", what)
        self.assertIn("vault —", self.words("fleet_read"))
        self.assertIn("vault", next(t for t in owner_mcp.tools()
                                    if t["name"] == "fleet_read")["inputSchema"]["properties"]["page"]["enum"])
        source = (HERE / "vault.py").read_text()
        self.assertIn('"""What the hub reads of the central vault: its keys, the owner\'s records and how many items it '
                      'holds. Never a\n    value and never a title."""', source)


class VaultReading(unittest.TestCase):
    """`owner_mcp.vault_reading` and `lower_reference`, with no hub: the hub's page of the vault is data, so a page
    that does not say what the rule reads is no reading (None, and the give is sent), never an error of Python."""

    PAGE = {"db": "g1", "fleet": "0123456789abcdef", "read_at": 1.0, "error": None, "program": None, "hub": None,
            "central": {"ok": True, "central": True, "pool": ["bws://AA"],
                        "grants": [{"login": "bws://BB", "agent": "worker-1", "machine": "web-1"}]},
            "machines": [{"machine": "web-1", "carrier": "worker-1", "missing": []},
                         {"machine": "web-2", "carrier": None, "missing": ["not_pinned"]}],
            "held": {"web-1": ["bws://CC"], "web-2": []}}

    def test_a_page_of_the_shape_gives_what_the_rule_reads_with_each_reference_in_lower_case(self):
        self.assertEqual(owner_mcp.vault_reading(json.loads(json.dumps(self.PAGE))),
                         (["bws://aa"], [("bws://bb", "web-1")], [("web-1", True), ("web-2", False)],
                          {"web-1": ["bws://cc"], "web-2": []}))
        # Only A to Z change: Python's own lower() would make the last letter here a final sigma.
        greek = "\N{GREEK CAPITAL LETTER ALPHA}\N{GREEK CAPITAL LETTER SIGMA}"
        self.assertEqual(owner_mcp.lower_reference("bws://AbC-" + greek), "bws://abc-" + greek)
        self.assertEqual(greek.lower(), "\N{GREEK SMALL LETTER ALPHA}\N{GREEK SMALL LETTER FINAL SIGMA}")

    def test_a_page_that_does_not_say_it_is_no_reading(self):
        def page(**changes):
            return dict(self.PAGE, **changes)

        def central(**changes):
            return page(central=dict(self.PAGE["central"], **changes))
        cases = {
            "no answer in JSON": None, "a list": [self.PAGE], "a text": "central",
            "no central": {k: v for k, v in self.PAGE.items() if k != "central"},
            "central null": page(central=None), "central a text": page(central="ok"),
            "ok false": central(ok=False), "ok 1": central(ok=1), "ok a text": central(ok="true"),
            "the hub's newest read of the vault failed": page(error="the central vault does not answer"),
            "an error that is no text": page(error=False),
            "no ok": page(central={k: v for k, v in self.PAGE["central"].items() if k != "ok"}),
            "no pool": page(central={k: v for k, v in self.PAGE["central"].items() if k != "pool"}),
            "a pool that is a text": central(pool="bws://aa"), "a reference that is a number": central(pool=[7]),
            "no grants": page(central={k: v for k, v in self.PAGE["central"].items() if k != "grants"}),
            "grants an object": central(grants={}), "a grant that is a text": central(grants=["bws://bb"]),
            "a grant with no machine": central(grants=[{"login": "bws://bb", "agent": "worker-1"}]),
            "a grant whose machine is null": central(grants=[{"login": "bws://bb", "machine": None}]),
            "a grant whose login is a number": central(grants=[{"login": 7, "machine": "web-1"}]),
            "no machines": {k: v for k, v in self.PAGE.items() if k != "machines"},
            "machines an object": page(machines={"web-1": {}}), "a machine that is a text": page(machines=["web-1"]),
            "a machine with no name": page(machines=[{"carrier": None, "missing": []}]),
            "a machine with no list of what it lacks": page(machines=[{"machine": "web-1"}]),
            "a machine whose list of what it lacks is a text": page(machines=[{"machine": "web-1", "missing": ""}]),
            "a machine whose list of what it lacks is null": page(machines=[{"machine": "web-1", "missing": None}]),
            "no held": {k: v for k, v in self.PAGE.items() if k != "held"}, "held a list": page(held=[]),
            "copies that are a text": page(held={"web-1": "bws://cc"}),
            "a copy that is a number": page(held={"web-1": [7]}),
        }
        for what, value in cases.items():
            self.assertIsNone(owner_mcp.vault_reading(value), what)


# ---- the parity check of the two programs (plan 3.3): owner_mcp.py and the program inside the Founderizer app

PARITY_FIXTURE = HERE / "app" / "Tests" / "FleetOwnerAPITests" / "Fixtures" / "owner-parity.json"
PARITY_REMAKE = "python3 test_owner_mcp.py --parity-fixture"
PARITY_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
PARITY_TEAM = {"sha256": "team-sha-1", "lines": [
    {"agent": "manager", "repos": {}, "tools": [], "google": {}},
    {"agent": "worker-1", "repos": {"acme/web": "read"}, "tools": ["github"],
     "google": {"gmail": {"account": "ada@example.com", "level": "read"}}},
    {"agent": "worker-2", "repos": {"acme/web": "write", "acme/api": "deploy"}, "tools": ["github", "linear"],
     "google": {"drive": {"account": "ada@example.com", "level": "write"}}}]}
PARITY_PROFILES = {"profiles": [{"agent": "worker-1", "sha256": "profile-sha-1", "sections": []},
                                {"agent": "ops lead", "sha256": "profile-sha-2", "sections": []}]}
PARITY_FILE = b"hello attachment\n"
PARITY_COPY = b"PK\x03\x04 a stand-in copy of a fleet\n"
PARITY_RID = "6F1C2A3B-0000-4000-8000-00000000000A"
PARITY_SECRET = "bws://aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"       # an API key of the catalog
PARITY_LOGIN = "bws://bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee"        # a login of the catalog
PARITY_MADE = "bws://cccccccc-bbbb-4ccc-8ddd-eeeeeeeeeeee"         # a login of the catalog, which an agent made
PARITY_ABSENT = "bws://dddddddd-bbbb-4ccc-8ddd-eeeeeeeeeeee"       # no secret of the catalog
# The team's page of a hub with a central vault (hub.py ui_team), with the parts that grant_access reads for a give of
# a secret: the catalog (`logins`), the logins that agents made (`created_logins`: one whose job has no reference yet,
# and one that names PARITY_MADE, in upper case), and each agent's role and machine. web-1 has two workers and web-2
# has a lead; the manager is on a server of its own; worker-4 has no machine, worker-5 is on a server that the vault's
# page does not list, and worker-6 has no role.
PARITY_SERVERS = {
    "sha256": "team-sha-1",
    "logins": {PARITY_SECRET: {"title": "SHOP_API_KEY", "kind": "api_key", "env": "SHOP_API_KEY"},
               PARITY_LOGIN: {"title": "shop.example.com ops", "kind": "login"},
               PARITY_MADE: {"title": "mail.example.com ops", "kind": "login"}},
    "created_logins": [{"login": None, "agent": "worker-2", "state": "waiting"},
                       {"login": "bws://" + PARITY_MADE[6:].upper(), "agent": "worker-2", "state": "created"}],
    "lines": [{"agent": "manager", "role": "manager", "machine": "hub-1"},
              {"agent": "worker-1", "role": "worker", "machine": "web-1"},
              {"agent": "worker-2", "role": "worker", "machine": "web-1"},
              {"agent": "worker-3", "role": "lead", "machine": "web-2"},
              {"agent": "worker-4", "role": "worker"},
              {"agent": "worker-5", "role": "worker", "machine": "web-3"},
              {"agent": "worker-6", "machine": "web-1"}]}
# The one read whose 404 "not found" is no refusal: grant_access takes a hub with no page of the vault as a fleet whose
# reading cannot judge the give, and sends the grant. So the program inside the app adds no sentence of an older hub
# for it (`parity_older`).
PARITY_NO_REFUSAL = ("/ui/vault",)


def parity_state(db):
    return {"db": db, "time": 1763078400, "ui_features": sorted(set(owner_mcp.FEATURES.values()) |
                                                                set(owner_mcp.FIELD_FEATURES.values())),
            "manager_warning": None,
            "agents": [{"name": "manager", "role": "manager", "runtime": "claude", "active": True, "secret": "x"}],
            "tasks": [{"id": 1, "title": "Write the page", "state": "working", "owner": "worker-1"},
                      {"id": 2, "title": "Old", "state": "completed"}],
            "needs": [{"id": 5, "answered": False}, {"id": 6, "answered": True}],
            "goals": [{"id": 3, "title": "Launch", "state": "active"}],
            "responsibilities": [{"id": 4, "title": "Watch the site", "agent": "worker-1"}],
            "reports": list(range(1, 8))}


def parity_json(status, value):
    return status, {"Content-Type": "application/json"}, json.dumps(value).encode()


def parity_answer(state, req):
    """The stand-in hub's own answer, from the fixed facts above. A case can answer a request itself first."""
    method, path, query = req["method"], req["path"], urllib.parse.parse_qs(req["query"], keep_blank_values=True)
    db = state["db"]
    stale = parity_json(409, {"error": "hub generation changed; refresh state"})
    if method == "POST":
        if path == "/ui/attachments":
            if query.get("db") != [db]:
                return parity_json(409, {"error": "hub generation changed; refresh state before sending"})
            rid = req["headers"].get("x-fleet-request-id", "")
            if not PARITY_UUID.fullmatch(rid):
                return parity_json(400, {"error": "X-Fleet-Request-Id must be a UUID"})
            return parity_json(200, {"ok": True, "replayed": False, "id": 11, "name": req["headers"].get("x-fleet-name"),
                                     "mime": req["headers"].get("content-type"), "size": len(req["body"]),
                                     "sha256": hashlib.sha256(req["body"]).hexdigest()})
        body = json.loads(req["body"] or b"{}")
        if body.get("db") != db:
            return stale
        if path == "/ui/backups/confirm":
            return parity_json(200, {"ok": True, "backup": {"sha256": body.get("sha256"), "bytes": body.get("bytes")}})
        if path == "/ui/company":           # the hub's two values (owner API 1.349): the name, and a value of the logo
            png = body.get("png")
            return parity_json(200, {"ok": True, "replayed": False, "name": body.get("name"),
                                     "logo": hashlib.sha256(png.encode()).hexdigest()[:16] if png else None})
        return parity_json(200, {"ok": True, "route": path})
    if path == "/ui/state" and query.get("head") == ["1"]:
        # Owner API 1.256: the read of the generation and the features asks for the head, which holds no list.
        head = parity_state(db)
        return parity_json(200, {"db": db, "time": head["time"], "ui_features": head["ui_features"], "head": True})
    if path == "/ui/state":
        # Owner API 1.254: a read that asks for the window of the tasks gets the ended tasks that it leaves out as a
        # number, which fleet_overview adds to its finished tasks; the whole snapshot (fleet_read state) has none.
        older = {"older_tasks": {"before": 100, "block": 100, "mark": "100.3", "tasks": 40}} \
            if query.get("tasks") == ["window"] else {}
        return parity_json(200, dict(parity_state(db), **older))
    if query.get("db") != [db]:
        return stale
    parts = path.strip("/").split("/")
    if path == "/ui/team":
        return parity_json(200, PARITY_TEAM)
    if path == "/ui/profiles":
        return parity_json(200, PARITY_PROFILES)
    if len(parts) == 3 and parts[1] in ("goals", "responsibilities", "triggers"):
        thing = {"goals": "goal", "responsibilities": "responsibility", "triggers": "trigger"}[parts[1]]
        return parity_json(200, {thing: {"id": int(parts[2]), "revision": 12}})
    if path == "/ui/attachments/3":
        return 200, {"Content-Type": "text/plain; charset=utf-8", "X-Fleet-SHA256": hashlib.sha256(PARITY_FILE).hexdigest(),
                     "Content-Disposition": 'attachment; filename="notes.txt"'}, PARITY_FILE
    if path == "/ui/attachments/4":                 # no digest and no name
        return 200, {"Content-Type": "text/plain"}, PARITY_FILE
    if path == "/ui/attachments/5":
        return 200, {"Content-Type": "text/plain", "X-Fleet-SHA256": "0" * 64}, PARITY_FILE
    if parts[:2] == ["ui", "attachments"]:
        return parity_json(404, {"error": "no such attachment"})
    if path == "/ui/backup":
        return 200, {"Content-Type": "application/zip", "X-Fleet-DB": db,
                     "X-Fleet-Backup-SHA256": hashlib.sha256(PARITY_COPY).hexdigest(),
                     "Content-Disposition": 'attachment; filename="founderizer-fleet-20261114T000000Z.zip"'}, PARITY_COPY
    return parity_json(200, {"page": path})


def parity_vault(pool=(), grants=(), held=None, machines=("web-1", "web-2"), missing=None, **central):
    """`GET /ui/vault` of a hub with a central vault (hub.py vault_view), with the parts that grant_access reads: what
    the owner signed (`pool`, `grants`), each machine with a worker or a lead and what keeps deliveries from it
    (`missing`, by its name; nothing for a machine that takes them), and what each machine's vault holds."""
    return {"fleet": "0123456789abcdef", "read_at": PARITY_NOW, "error": None, "program": None, "hub": None,
            "central": dict({"ok": True, "central": True, "pool": list(pool), "grants": list(grants)}, **central),
            "machines": [{"machine": name, "missing": list((missing or {}).get(name, ()))} for name in machines],
            "held": dict({name: [] for name in machines}, **(held or {}))}


def parity_sample(name, schema):
    """One value of a property, from its schema alone: the same arguments every time."""
    if "enum" in schema:
        return schema["enum"][0]
    kind = schema.get("type")
    if isinstance(kind, list):
        kind = next(k for k in kind if k != "null")
    if kind == "object":
        props = schema.get("properties") or {}
        return {k: parity_sample(k, v) for k, v in sorted(props.items())} if props else {"key": "value"}
    if kind == "array":
        return [parity_sample(name, schema.get("items") or {"type": "string"})]
    return {"string": f"{name}-1", "integer": 7, "boolean": True, "number": 1.5}.get(kind, f"{name}-1")


def png_chunk(kind, body):
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))


def company_png(red=1, extra=b"", after=b"", size=64):
    """A PNG of `size` x `size` RGBA pixels, each clear but the first, whose red is `red`: a logo as a picture program
    writes one, which save_company sends as it is. `extra`: chunks before the data; `after`: bytes after IEND."""
    rows = bytearray(size * (1 + size * 4))
    rows[1], rows[4] = red, 255
    return owner_mcp.PNG_SIGNATURE + png_chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)) + extra + \
        png_chunk(b"IDAT", zlib.compress(bytes(rows))) + png_chunk(b"IEND", b"") + after


def parity_cases():
    """The fixed script: each tool that both programs have, once with arguments from its schema, and the cases of the
    shared part and the nine writes. `answer(state, request)` answers a request before the stand-in hub's own."""
    cases = []

    def case(name, tool, arguments=None, answer=None, files=None, folders=(), links=None, app_lists=False,
             programs=None):
        """`links`: a symbolic link of the work folder, by its path there, to a path there (made absolute).
        `app_lists`: the one place where the two programs read the hub differently. Before an answer with a choice
        of 0 or 1 the program inside the app reads the item of the state, to see whether it is a door card
        (`AnswerDoor.press`), and that read gives it the generation too; this server, which hands no press to the
        app, reads only the head of the state for the generation (owner API 1.256). The fixture of such a case holds
        the app's read, the state with its lists, and the stand-in hub's answer to it (parity_fixture). Only for a
        case with no answer of its own: the stand-in's answer to that read is then the same at any moment.
        `programs`: a case of design 9's tools of a cloud, which call no hub but the cloud's own program
        (`parity_cloud_cases`)."""
        cases.append({"name": name, "tool": tool, "arguments": arguments or {}, "answer": answer,
                      "app_lists": app_lists, "programs": programs,
                      "setup": {"files": files or {}, "folders": list(folders), "links": links or {}}})

    for t in owner_mcp.dump_tools()["tools"]:
        if t["kind"] in ("plain", "with_base", "with_revision"):
            props = t["inputSchema"]["properties"]
            case(f"{t['name']}: every field", t["name"],
                 {k: parity_sample(k, v) for k, v in sorted(props.items()) if k != "request_id"})
    case("with_revision: no revision", "goal_state", {"id": 3, "action": "pause"},
         lambda s, r: parity_json(200, {"goal": {"id": 3}}) if r["path"] == "/ui/goals/3" else None)
    case("plain: the agent's own request id", "control_task", {"task": 7, "action": "pause", "request_id": PARITY_RID})
    case("plain: a part that the arguments do not give", "check_machine", {})
    case("plain: a part that is null", "check_machine", {"agent": None})
    case("plain: a part that is empty", "check_machine", {"agent": ""})
    case("plain: a part that is two dots", "check_machine", {"agent": ".."})
    case("plain: a part with / ? and %", "check_machine", {"agent": "a/b?c%d"})
    case("with_revision: no id", "duty_state", {"action": "pause"})
    case("with_base: a part that the arguments do not give", "activate_agent", {"active": True})
    # A field that replaces a whole value goes only with the client's own base; null is no base for team.json, and a
    # call with no such field reads the base, as before.
    case("with_base: a whole value with no base", "agent_settings", {"agent": "worker-1", "model": "m", "can": ["web"]})
    case("with_base: two whole values with a base of null", "agent_settings",
         {"agent": "worker-1", "expertise": ["sales"], "screen": {"model": None, "effort": None}, "base_sha256": None})
    case("with_base: no whole value and a base of null", "agent_settings",
         {"agent": "worker-1", "model": "m", "base_sha256": None})
    case("with_base: the whole lines with the client's base", "set_reporting_lines",
         {"lines": [{"agent": "manager", "role": "manager", "reports_to": None}], "base_sha256": "team-sha-0"})
    case("with_base: the whole lines with no base, on a tool with a feature", "set_reporting_lines",
         {"lines": [{"agent": "manager", "role": "manager", "reports_to": None}]})
    case("with_base: the client's base and a part that the arguments do not give", "rename_agent",
         {"name": "new-name", "base_sha256": "team-sha-0"})
    case("with_base: the client's base and a part that is two dots", "rename_agent",
         {"agent": "..", "name": "new-name", "base_sha256": "team-sha-0"})
    case("with_base: a new record with no base", "save_mcp_server", {"name": "crm", "server": {"title": "CRM"}})
    # A null that the hub takes goes as null; a null of a field whose schema takes none is left out.
    case("nulls: an agent's model and title back to the default", "agent_settings",
         {"agent": "worker-1", "model": None, "effort": None, "title": None, "account": None})
    case("nulls: a chat app account removed", "save_chat_account", {"id": "discord-worker-1", "account": None})
    case("nulls: a role with no daily limit", "save_role", {"name": "supplier", "daily": None})
    case("nulls: a role's set of access taken away", "save_role", {"name": "supplier", "access": None})
    case("nulls: a person's own note and limit taken away", "save_person", {"id": 3, "note": None, "daily": None})
    case("nulls: an agent that reports to the manager", "add_agent",
         {"server": "server-1", "agent": "scout", "runtime": "claude", "role": "worker", "reports_to": None})
    case("nulls: a null of a field that takes none is left out", "save_person",
         {"id": 3, "name": None, "blocked": None})
    # A request id that is not a UUID is refused before any request where owner_mcp.py makes none before its command.
    case("plain: a request id that is no UUID, on a tool with a feature", "check_releases", {"request_id": "not-one"})
    case("with_base: the client's base and a request id that is no UUID", "rename_agent",
         {"agent": "worker-1", "name": "new-name", "base_sha256": "team-sha-0", "request_id": "not-one"})
    # The four reads.
    case("fleet_overview", "fleet_overview")
    case("fleet_overview: a page refused", "fleet_overview", None,
         lambda s, r: parity_json(403, {"error": "is not owner's machine"}) if r["path"] == "/ui/servers" else None)
    # A word that the page does not read is refused before any request (PAGE_TAKES): notes' limit, trigger's after,
    # and machines' agent and id; standing reads both of its words; owner_chat sends its time cursor whole (a since
    # that the program cut or dropped reads the wrong page), and takes no after.
    for args in ({"page": "health"}, {"page": "notes", "agent": "a b", "limit": 5},
                 {"page": "trigger", "id": 2, "after": 9}, {"page": "knowledge", "path": "a/b.md"},
                 {"page": "chat_link", "name": "wa 1"}, {"page": "goal"}, {"page": "nothing"},
                 {"page": "notes", "agent": "a/b"}, {"page": "machines", "agent": "worker-1", "id": 3},
                 {"page": "standing", "agent": "a b", "limit": 5}, {"page": "machines", "agent": None, "limit": 0},
                 {"page": "machines", "limit": False}, {"page": "chat_link", "name": "wa 1", "agent": "x"},
                 {"page": "events", "id": 5, "since": 100, "after": 2, "machine": None},
                 {"page": "owner_chat", "agent": "manager", "since": 1792134000.25},
                 {"page": "owner_chat", "agent": "manager", "after": 3}):
        case(f"fleet_read: {json.dumps(args, sort_keys=True)}", "fleet_read", args)
    case("search_history", "search_history", {"agent": "worker-1", "query": "a b", "limit": 3})
    case("see_costs", "see_costs", {"from": "2026-11-01", "minimum": 3})
    # The shared part of a command.
    case("send_message", "send_message", {"text": "Launch the site.", "recipient": "manager"})
    case("send_message: the agent's own request id", "send_message", {"text": "Again.", "request_id": PARITY_RID})
    case("send_message: a request id that is no UUID", "send_message", {"text": "x", "request_id": "not-one"})
    case("send_message: with attachments", "send_message",
         {"text": "See this.", "attachments": [11], "replaces_request_id": PARITY_RID.lower()})

    def moved_once(state, req):
        if req["method"] == "POST" and state.setdefault("moved", 0) == 0:
            state["moved"], state["db"] = 1, "g2"
            return parity_json(409, {"error": "hub generation changed; refresh state"})
        return None
    case("send_message: a new generation, read again once", "send_message", {"text": "x"}, moved_once)
    case("send_message: a second new generation is given back", "send_message", {"text": "x"},
         lambda s, r: parity_json(409, {"error": "hub generation changed; refresh state"})
         if r["method"] == "POST" else None)
    case("send_message: team.json moved", "send_message", {"text": "x"},
         lambda s, r: parity_json(409, {"error": "team.json changed", "sha256": "team-sha-2"})
         if r["method"] == "POST" else None)
    case("send_message: the owner address", "send_message", {"text": "x"},
         lambda s, r: parity_json(403, {"error": "is not owner's machine"}) if r["method"] == "POST" else None)
    case("send_message: a hub in trouble", "send_message", {"text": "x"},
         lambda s, r: (502, {"Content-Type": "text/html"}, b"<html>Bad gateway</html>")
         if r["method"] == "POST" else None)
    case("send_message: no text", "send_message", {})
    case("answer_needs_you: a choice", "answer_needs_you", {"need": 4, "choice": 1}, app_lists=True)
    case("answer_needs_you: choices", "answer_needs_you", {"need": 4.0, "choices": [0, 2]})
    case("answer_needs_you: words", "answer_needs_you", {"need": "5", "answer": "Yes, but later."})
    # Files go with words or alone, as in the app; beside a choice or choices they are refused before any request, and
    # an empty list is no file (Python's truth, which the program inside the app copies).
    case("answer_needs_you: words with files", "answer_needs_you",
         {"need": 5, "answer": "Here it is.", "attachments": [11, 12]})
    case("answer_needs_you: files alone", "answer_needs_you", {"need": 5, "attachments": [11]})
    case("answer_needs_you: a choice with a file", "answer_needs_you", {"need": 4, "choice": 0, "attachments": [11]})
    case("answer_needs_you: choices with a file", "answer_needs_you",
         {"need": 4, "choices": [0, 2], "attachments": [11]})
    case("answer_needs_you: a choice with an empty list", "answer_needs_you",
         {"need": 4, "choice": 1, "attachments": []}, app_lists=True)
    # A file id that is no list is a file too (truth, not form), a choice of null is no choice, and the refusal of a
    # file beside a choice comes before the refusal of a need that is no number.
    case("answer_needs_you: a choice with a file id that is no list", "answer_needs_you",
         {"need": 4, "choice": 0, "attachments": 11})
    case("answer_needs_you: words with files and a choice of null", "answer_needs_you",
         {"need": 5, "answer": "Here.", "choice": None, "attachments": [11]})
    case("answer_needs_you: a need that is no number, with a choice and a file", "answer_needs_you",
         {"need": "five", "choice": 0, "attachments": [11]})
    case("answer_needs_you: a need that is no number", "answer_needs_you", {"need": "five", "answer": "x"})
    case("decline_secret_request", "decline_secret_request", {"need": 6, "reason": "Not now."})
    case("decline_secret_request: no reason", "decline_secret_request", {"need": 6})
    # save_profile.
    sections = [{"key": "responsible", "title": "Responsible for", "text": "The site."}]
    read = "profile-sha-0"         # the client's own read, older than the stand-in hub's page
    case("save_profile", "save_profile", {"agent": "worker-1", "sections": sections, "base_sha256": read})
    case("save_profile: a name with a space", "save_profile",
         {"agent": " ops lead ", "sections": sections, "base_sha256": read})
    case("save_profile: an agent that does not exist", "save_profile",
         {"agent": "ghost", "sections": sections, "base_sha256": read})
    case("save_profile: no agent", "save_profile", {"sections": sections, "base_sha256": read})
    case("save_profile: a part that is two dots", "save_profile", {"agent": "..", "sections": sections})
    # The base is the client's read, and null is the base of an agent with no profile yet; with none, no request.
    case("save_profile: no base", "save_profile", {"agent": "worker-1", "sections": sections})
    case("save_profile: a base of null", "save_profile",
         {"agent": "worker-1", "sections": sections, "base_sha256": None})
    # grant_access, each kind.
    for name, args in (("repo", {"resource": "repo:acme/web", "agent": "worker-1", "level": "write"}),
                       ("repo, null ends a hold", {"resource": "repo:acme/web", "agent": "worker-2", "level": None}),
                       ("repo, a new holder", {"resource": "repo:acme/new", "agent": "manager", "level": "read"}),
                       ("tool", {"resource": "tool:github", "agent": "manager", "level": "use"}),
                       ("tool, null ends a hold", {"resource": "tool:github", "agent": "worker-2", "level": None}),
                       ("secret", {"resource": "secret:bws://0000-test", "agent": "worker-1", "level": "read"}),
                       ("secret, null", {"resource": "secret:bws://0000-test", "agent": "worker-1", "level": None}),
                       ("drive", {"resource": "drive:ada@example.com", "agent": "worker-1", "level": "write"}),
                       ("gmail", {"resource": "gmail:ada@example.com", "agent": "worker-2", "level": "send"}),
                       ("gmail, null", {"resource": "gmail:ada@example.com", "agent": "worker-1", "level": None}),
                       ("server is refused", {"resource": "server:web-1", "agent": "worker-1", "level": "fix"}),
                       ("a bad kind", {"resource": "disk:one", "agent": "worker-1", "level": "read"}),
                       ("no what", {"resource": "repo:", "agent": "worker-1", "level": "read"}),
                       ("no agent", {"resource": "repo:acme/web", "level": "read"}),
                       ("the agent's own request id", {"resource": "repo:acme/web", "agent": "worker-1",
                                                       "level": "read", "request_id": PARITY_RID})):
        case(f"grant_access: {name}", "grant_access", args)
    folders = {"sha256": "x", "resources": [{"id": "drive:ada@example.com", "kind": "drive", "folders": [
        {"id": "Abc-Folder_01", "holders": [{"agent": "worker-2", "level": "read"}]}]}]}
    case("grant_access: a folder of a Drive account", "grant_access",
         {"resource": "drive:Ada@example.com", "agent": "worker-1", "level": "write",
          "folder": "https://drive.google.com/drive/folders/Abc-Folder_01?usp=sharing"},
         lambda s, r: parity_json(200, folders) if r["path"] == "/ui/resources" else None)
    case("grant_access: a folder with another kind", "grant_access",
         {"resource": "gmail:ada@example.com", "agent": "worker-1", "level": "read", "folder": "Abc-Folder_01"})
    case("grant_access: a team read with no lines", "grant_access",
         {"resource": "repo:acme/web", "agent": "worker-1", "level": "read"},
         lambda s, r: parity_json(200, {"sha256": "x"}) if r["path"] == "/ui/team" else None)
    # grant_access, a give of a secret: each step of its rule (owner_mcp.secret_reaches). The cases above run on a
    # stand-in hub whose page of the vault has no `central`, so their grant goes as before, after one read. The
    # stand-in takes each grant that reaches it, so a give that is sent ends in its answer to the POST.
    give = {"resource": "secret:" + PARITY_SECRET, "agent": "worker-1", "level": "use"}

    def vault(team=PARITY_SERVERS, **page):
        """A hub with a central vault: its page of the vault (`parity_vault`), and its page of the team."""
        page = parity_vault(**page)
        return lambda s, r: parity_json(200, page) if r["path"] == "/ui/vault" else \
            parity_json(200, team) if r["path"] == "/ui/team" else None

    def vault_page(page):
        return lambda s, r: page if r["path"] == "/ui/vault" else None

    def team_without(key):
        return {k: v for k, v in PARITY_SERVERS.items() if k != key}

    def signed(agent, machine):
        return {"login": PARITY_SECRET, "agent": agent, "machine": machine}
    # Step 1: the page of the vault cannot judge the give, so it is sent after the one read.
    case("grant_access: a secret, a hub with no page of the vault", "grant_access", give,
         vault_page(parity_json(404, {"error": "not found"})))
    case("grant_access: a secret, a hub that refuses the read of the vault", "grant_access", give,
         vault_page(parity_json(403, {"error": "is not owner's machine"})))
    case("grant_access: a secret, a fleet with no central vault", "grant_access", give,
         vault_page(parity_json(200, dict(parity_vault(), central=None,
                                          error="no central vault answers on this hub"))))
    case("grant_access: a secret, a vault with no good reading", "grant_access", give, vault(ok=False))
    case("grant_access: a secret, a page whose newest read of the vault failed", "grant_access", give,
         vault_page(parity_json(200, dict(parity_vault(), error="the central vault does not answer"))))
    for what, page in (
            ("no object", parity_json(200, ["central"])),
            ("no JSON", (200, {"Content-Type": "text/html"}, b"<html>The vault</html>")),
            ("a pool that is a text", parity_json(200, dict(parity_vault(), central={
                "ok": True, "pool": PARITY_SECRET, "grants": []}))),
            ("a reference that is a number", parity_json(200, parity_vault(pool=[7]))),
            ("grants that are an object", parity_json(200, dict(parity_vault(), central={
                "ok": True, "pool": [], "grants": {PARITY_SECRET: "web-1"}}))),
            ("a grant with no machine", parity_json(200, parity_vault(
                grants=[{"login": PARITY_SECRET, "agent": "worker-1"}]))),
            ("machines that are an object", parity_json(200, dict(parity_vault(), machines={"web-1": {}}))),
            ("a machine with no name", parity_json(200, dict(parity_vault(), machines=[
                {"carrier": None, "missing": []}]))),
            ("a machine with no list of what it lacks", parity_json(200, dict(parity_vault(), machines=[
                {"machine": "web-1"}, {"machine": "web-2", "missing": []}]))),
            ("a machine whose list of what it lacks is a text", parity_json(200, dict(parity_vault(), machines=[
                {"machine": "web-1", "missing": "not_pinned"}, {"machine": "web-2", "missing": []}]))),
            ("no list of what the vaults hold", parity_json(200, dict(parity_vault(), held=None))),
            ("copies that are a text", parity_json(200, parity_vault(held={"web-1": PARITY_SECRET})))):
        case(f"grant_access: a secret, a page of the vault with {what}", "grant_access", give, vault_page(page))
    # Step 2: a secret of the pool goes with no read of the team. References are compared in lower case.
    case("grant_access: a secret of the pool", "grant_access", give, vault(pool=[PARITY_SECRET]))
    case("grant_access: a secret of the pool, with its reference in upper case", "grant_access",
         dict(give, resource="secret:bws://" + PARITY_SECRET[6:].upper()), vault(pool=[PARITY_SECRET]))
    case("grant_access: a secret of the pool, which the hub names in upper case", "grant_access", give,
         vault(pool=["bws://" + PARITY_SECRET[6:].upper()]))
    # Step 3a: the hub answers in its own words for a secret that its catalog does not have, and for a level that
    # does not fit the secret. A team's page with no catalog cannot judge, so the give is sent too.
    case("grant_access: a secret that the catalog does not have", "grant_access",
         dict(give, resource="secret:" + PARITY_ABSENT), vault())
    case("grant_access: a secret, a reference of a wrong form", "grant_access",
         dict(give, resource="secret:sealed:3"), vault())
    case("grant_access: a secret at read that is a login", "grant_access",
         dict(give, resource="secret:" + PARITY_LOGIN, level="read"), vault())
    case("grant_access: a secret at read whose entry has no kind", "grant_access", dict(give, level="read"),
         vault(team=dict(PARITY_SERVERS, logins={PARITY_SECRET: {"title": "SHOP_API_KEY"}})))
    for what, level in (("a word that is no level of a secret", "write"), ("an empty text", ""), ("a number", 7),
                        ("true", True)):
        case(f"grant_access: a secret, a level that is {what}", "grant_access", dict(give, level=level), vault())
    for what, team in (("no catalog", team_without("logins")),
                       ("a catalog that is a list", dict(PARITY_SERVERS, logins=[PARITY_SECRET])),
                       ("an entry of the catalog that is no object",
                        dict(PARITY_SERVERS, logins={PARITY_SECRET: "SHOP_API_KEY"})),
                       ("no object", ["lines"])):
        case(f"grant_access: a secret, a team's page with {what}", "grant_access", give, vault(team=team))
    # Step 3b: a secret that an agent made is not judged. A team's page with no list of them cannot judge.
    case("grant_access: a secret that an agent made", "grant_access",
         dict(give, resource="secret:" + PARITY_MADE), vault())
    for what, team in (("no list of the logins that agents made", team_without("created_logins")),
                       ("such a list that is an object", dict(PARITY_SERVERS, created_logins={})),
                       ("an entry of that list that is no object",
                        dict(PARITY_SERVERS, created_logins=[PARITY_LOGIN]))):
        case(f"grant_access: a secret, a team's page with {what}", "grant_access", give, vault(team=team))
    case("grant_access: a secret, entries of that list that name no reference", "grant_access", give,
         vault(team=dict(PARITY_SERVERS, created_logins=[{"login": 7}, {"agent": "worker-2"}, {"login": None}])))
    # Step 3c: the hub answers for an agent that its lines do not have, and it writes the grant for one with no
    # machine. The door is no agent of the lines.
    for what, agent in (("an agent that the list does not have", "ghost"), ("the door", "door"),
                        ("an agent with no server", "worker-4")):
        case(f"grant_access: a secret, {what}", "grant_access", dict(give, agent=agent), vault())
    case("grant_access: a secret, a server that is an empty text", "grant_access", give,
         vault(team=dict(PARITY_SERVERS, lines=[{"agent": "worker-1", "role": "worker", "machine": ""}])))
    # Step 3d: only a worker and a lead are judged.
    case("grant_access: a secret, the manager on a server of its own", "grant_access", dict(give, agent="manager"),
         vault())
    case("grant_access: a secret, the manager on a server that it shares with workers", "grant_access",
         dict(give, agent="manager"),
         vault(team=dict(PARITY_SERVERS, lines=[{"agent": "manager", "role": "manager", "machine": "web-1"},
                                                {"agent": "worker-1", "role": "worker", "machine": "web-1"}])))
    case("grant_access: a secret, an agent with no role", "grant_access", dict(give, agent="worker-6"), vault())
    case("grant_access: a secret, a role that is no text", "grant_access", give,
         vault(team=dict(PARITY_SERVERS, lines=[{"agent": "worker-1", "role": ["worker"], "machine": "web-1"}])))
    case("grant_access: a secret, a lead with nothing signed and no copy", "grant_access",
         dict(give, agent="worker-3"), vault())
    # Step 3e: a server that the vault's page does not list, and one that takes no deliveries now.
    case("grant_access: a secret, a worker on a server that the page of the vault does not list", "grant_access",
         dict(give, agent="worker-5"), vault())
    for what, lacks in (("without its pin", ["not_pinned"]), ("with another pin", ["pin_mismatch"]),
                        ("whose vault no agent can reach", ["no_broker_access", "not_pinned"])):
        case(f"grant_access: a secret, a server {what}", "grant_access", give, vault(missing={"web-1": lacks}))
    # Steps 4 and 5: a grant signed for the agent's server, and a copy that its vault holds.
    case("grant_access: a secret, a grant signed for another agent on the same server", "grant_access", give,
         vault(grants=[signed("worker-2", "web-1")]))
    case("grant_access: a secret, a grant signed only for another server", "grant_access", give,
         vault(grants=[signed("worker-3", "web-2"), signed("worker-1", "web-2")]))
    case("grant_access: a secret, a copy in the vault of the agent's server", "grant_access", give,
         vault(held={"web-1": ["bws://" + PARITY_SECRET[6:].upper()]}))
    case("grant_access: a secret, a copy only in the vault of another server", "grant_access", give,
         vault(held={"web-2": [PARITY_SECRET]}))
    # Step 6, and an end of a hold in the same state.
    case("grant_access: a secret, nothing signed and no copy", "grant_access", give, vault())
    case("grant_access: a secret at read, nothing signed and no copy", "grant_access", dict(give, level="read"),
         vault())
    case("grant_access: a secret that is a login, nothing signed and no copy", "grant_access",
         dict(give, resource="secret:" + PARITY_LOGIN), vault())
    case("grant_access: a secret, null in the state that refuses a give", "grant_access", dict(give, level=None),
         vault())
    # Text as Python reads it. Only A to Z are lowered, so a reference with a Greek capital sigma at its end is neither
    # of the two forms that a whole lower() can give it: the catalog has it as it is, and the pool has those two. And a
    # server's name is compared by code points: the team's name with one composed letter is not the vault's name with
    # that letter in two code points, so the page of the vault does not list the agent's server.
    sigma = "bws://\N{GREEK CAPITAL LETTER ALPHA}\N{GREEK CAPITAL LETTER SIGMA}"
    case("grant_access: a secret, a reference with letters that are not ASCII", "grant_access",
         dict(give, resource="secret:" + sigma),
         vault(team=dict(PARITY_SERVERS, logins={sigma: {"title": "A login", "kind": "login"}}),
               pool=["bws://\N{GREEK SMALL LETTER ALPHA}\N{GREEK SMALL LETTER FINAL SIGMA}",
                     "bws://\N{GREEK SMALL LETTER ALPHA}\N{GREEK SMALL LETTER SIGMA}"]))
    case("grant_access: a secret, a server's name in another Unicode form", "grant_access", give,
         vault(team=dict(PARITY_SERVERS, lines=[
             {"agent": "worker-1", "role": "worker", "machine": "caf\N{LATIN SMALL LETTER E WITH ACUTE}"}]),
               machines=("cafe\N{COMBINING ACUTE ACCENT}",)))
    # The two reads, when they fail: a new generation is read again once, a second one is the program's own error, and
    # a read of the team that is refused, or whose lines have another shape, stops the give in the words of that read.
    case("grant_access: a secret, a new generation at the read of the vault, read again once", "grant_access", give,
         lambda s, r: (s.update(db="g2", moved=1), parity_json(409, {"error": "hub generation changed; refresh "
                                                                              "state"}))[1]
         if r["path"] == "/ui/vault" and not s.get("moved") else None)
    case("grant_access: a secret, a second new generation at the read of the vault", "grant_access", give,
         vault_page(parity_json(409, {"error": "hub generation changed; refresh state"})))
    case("grant_access: a secret, a hub that refuses the read of the team", "grant_access", give,
         lambda s, r: parity_json(200, parity_vault()) if r["path"] == "/ui/vault" else
         parity_json(403, {"error": "is not owner's machine"}) if r["path"] == "/ui/team" else None)
    for what, team in (("no lines", team_without("lines")),
                       ("a server that is no text",
                        dict(PARITY_SERVERS, lines=[{"agent": "worker-1", "role": "worker", "machine": 7}]))):
        case(f"grant_access: a secret, a team read with {what}", "grant_access", give, vault(team=team))
    # share_resource.
    case("share_resource: with max", "share_resource", {"resource": "repo:acme/web", "max": "write"})
    case("share_resource: with max and to", "share_resource", {"resource": "tool:github", "max": "use", "to": "workers"})
    case("share_resource: without max", "share_resource", {"resource": "repo:acme/web"})
    # share_resource, a standing for a secret: each step of its rule (owner_mcp.standing_reaches). A standing that is
    # judged makes two reads (the vault's page, the team, whose one read also gives the command its base) and the
    # command; the stand-in takes each command that reaches it.
    share = {"resource": "secret:" + PARITY_SECRET, "max": "use"}
    # Step 1: the page of the vault cannot judge the standing, so it is sent.
    case("share_resource: a secret, a hub with no page of the vault", "share_resource", share,
         vault_page(parity_json(404, {"error": "not found"})))
    case("share_resource: a secret, a hub that refuses the read of the vault", "share_resource", share,
         vault_page(parity_json(403, {"error": "is not owner's machine"})))
    case("share_resource: a secret, a fleet with no central vault", "share_resource", share,
         vault_page(parity_json(200, dict(parity_vault(), central=None, error="no central vault answers on this hub"))))
    case("share_resource: a secret, a vault with no good reading", "share_resource", share, vault(ok=False))
    case("share_resource: a secret, a page whose newest read of the vault failed", "share_resource", share,
         vault_page(parity_json(200, dict(parity_vault(), error="the central vault does not answer"))))
    case("share_resource: a secret, a page of the vault with no object", "share_resource", share,
         vault_page(parity_json(200, ["central"])))
    # Step 2: the pool. The resource is read as the hub reads it: with spaces around it and in capitals.
    case("share_resource: a secret of the pool", "share_resource", share, vault(pool=[PARITY_SECRET]))
    case("share_resource: a secret of the pool, a resource with spaces and capitals", "share_resource",
         dict(share, resource=" \tSECRET:bws://" + PARITY_SECRET[6:].upper() + " "), vault(pool=[PARITY_SECRET]))
    case("share_resource: a secret of the pool, which the hub names in upper case", "share_resource", share,
         vault(pool=["bws://" + PARITY_SECRET[6:].upper()]))
    # Step 3a: the hub answers in its own words.
    case("share_resource: a secret that the catalog does not have", "share_resource",
         dict(share, resource="secret:" + PARITY_ABSENT), vault())
    case("share_resource: a secret with no reference", "share_resource", dict(share, resource="secret:"), vault())
    for what, most in (("a word that is no level of a secret", "write"), ("an empty text", ""), ("a number", 7),
                       ("true", True), ("a list", ["use"])):
        case(f"share_resource: a secret, a max that is {what}", "share_resource", dict(share, max=most), vault())
    for what, team in (("no catalog", team_without("logins")),
                       ("a catalog that is a list", dict(PARITY_SERVERS, logins=[PARITY_SECRET])),
                       ("an entry of the catalog that is no object",
                        dict(PARITY_SERVERS, logins={PARITY_SECRET: "SHOP_API_KEY"}))):
        case(f"share_resource: a secret, a team's page with {what}", "share_resource", share, vault(team=team))
    # Step 3b: a secret that an agent made is not judged, and a team's page with no list of them cannot judge.
    case("share_resource: a secret that an agent made", "share_resource",
         dict(share, resource="secret:" + PARITY_MADE), vault())
    for what, team in (("no list of the logins that agents made", team_without("created_logins")),
                       ("such a list that is an object", dict(PARITY_SERVERS, created_logins={})),
                       ("an entry of that list that is no object",
                        dict(PARITY_SERVERS, created_logins=[PARITY_LOGIN]))):
        case(f"share_resource: a secret, a team's page with {what}", "share_resource", share, vault(team=team))
    # Steps 4, 5 and 6: for any server.
    case("share_resource: a secret, a grant signed for any server", "share_resource", share,
         vault(grants=[signed("worker-3", "web-2")]))
    case("share_resource: a secret, a grant signed only for the door", "share_resource", share,
         vault(grants=[signed("door", "door")]))
    case("share_resource: a secret, a grant for the door and one for a server", "share_resource", share,
         vault(grants=[signed("door", "door"), signed("worker-3", "web-2")]))
    case("share_resource: a secret, a copy in the vault of any server", "share_resource", share,
         vault(held={"web-2": ["bws://" + PARITY_SECRET[6:].upper()]}))
    for what, lacks in (("without its pin", ["not_pinned"]), ("with another pin", ["pin_mismatch"])):
        case(f"share_resource: a secret, a server {what}", "share_resource", share, vault(missing={"web-2": lacks}))
    # Step 7: refused. A fleet with no worker and no lead has no server in the page of the vault.
    case("share_resource: a secret, nothing signed and no copy", "share_resource", share, vault())
    case("share_resource: a secret at read, nothing signed and no copy", "share_resource", dict(share, max="read"),
         vault())
    case("share_resource: a secret that is a login, nothing signed and no copy", "share_resource",
         dict(share, resource="secret:" + PARITY_LOGIN), vault())
    case("share_resource: a secret, a resource with spaces and capitals, nothing signed", "share_resource",
         dict(share, resource=" Secret:BWS://" + PARITY_SECRET[6:].upper()), vault())
    case("share_resource: a secret, a fleet with no worker and no lead", "share_resource", share, vault(machines=()))
    case("share_resource: a secret, entries of the list of made logins that name no reference", "share_resource",
         share, vault(team=dict(PARITY_SERVERS, created_logins=[{"login": 7}, {"agent": "worker-2"}])))
    # What the rule never touches, in the state that refuses a standing: taking the entry back, another kind, and a
    # resource that is no text.
    case("share_resource: a secret, no max in the state that refuses a standing", "share_resource",
         {"resource": share["resource"]}, vault())
    case("share_resource: a secret, null max in the state that refuses a standing", "share_resource",
         dict(share, max=None), vault())
    for resource, most in (("repo:acme/web", "write"), ("tool:github", "use"), ("drive:ada@example.com", "read"),
                           ("gmail:ada@example.com", "read"), ("secrets:" + PARITY_SECRET, "use")):
        case(f"share_resource: {resource.partition(':')[0]} in the state that refuses a standing", "share_resource",
             {"resource": resource, "max": most}, vault())
    case("share_resource: a resource that is no text", "share_resource", {"resource": 7, "max": "use"}, vault())
    # The two reads, when they fail, and a team's page with no base.
    case("share_resource: a secret, a new generation at the read of the vault, read again once", "share_resource",
         share, lambda s, r: (s.update(db="g2", moved=1), parity_json(409, {"error": "hub generation changed; "
                                                                                     "refresh state"}))[1]
         if r["path"] == "/ui/vault" and not s.get("moved") else None)
    case("share_resource: a secret, a second new generation at the read of the vault", "share_resource", share,
         vault_page(parity_json(409, {"error": "hub generation changed; refresh state"})))
    case("share_resource: a secret, a hub that refuses the read of the team", "share_resource", share,
         lambda s, r: parity_json(200, parity_vault()) if r["path"] == "/ui/vault" else
         parity_json(403, {"error": "is not owner's machine"}) if r["path"] == "/ui/team" else None)
    case("share_resource: a secret of the pool, a team's page with no base", "share_resource", share,
         vault(pool=[PARITY_SECRET], team=team_without("sha256")))
    # attach_file.
    files = {"note.txt": "hello\n", "a.png": "png", "b.PNG": "png", "c.jpg": "jpg", "d.jpeg": "jpeg", "e.gif": "gif",
             "f.pdf": "pdf", "g.md": "# md\n", "h.csv": "a,b\n", "i.json": "{}", "j.zip": "zip", "k.qqq": "qqq",
             "noext": "x", ".png": "hidden", "résumé 日本.txt": "name"}
    for name in files:
        case(f"attach_file: {name}", "attach_file", {"path": f"<tmp>/{name}"}, files=files)
    case("attach_file: a media type given", "attach_file", {"path": "<tmp>/k.qqq", "mime": " text/plain "}, files=files)
    case("attach_file: the agent's own request id", "attach_file", {"path": "<tmp>/note.txt", "request_id": PARITY_RID},
         files=files)
    case("attach_file: a request id that is no UUID", "attach_file", {"path": "<tmp>/note.txt", "request_id": "nope"},
         files=files)
    case("attach_file: a new generation, read again once", "attach_file", {"path": "<tmp>/note.txt"},
         lambda s, r: (s.update(db="g2", moved=1), parity_json(409, {"error": "hub generation changed; refresh state "
                                                                              "before sending"}))[1]
         if r["method"] == "POST" and not s.get("moved") else None, files=files)
    case("attach_file: a file that is not there", "attach_file", {"path": "<tmp>/missing.txt"})
    case("attach_file: a folder", "attach_file", {"path": "<tmp>/dl"}, folders=["dl"])
    case("attach_file: too large", "attach_file", {"path": "<tmp>/big.bin"},
         files={"big.bin": {"sparse": owner_mcp.ATTACH_MAX + 1}})
    case("attach_file: no path", "attach_file", {"path": "  "})
    case("attach_file: the hub refuses the type", "attach_file", {"path": "<tmp>/k.qqq"},
         lambda s, r: parity_json(415, {"error": "this type cannot be attached"}) if r["method"] == "POST" else None,
         files=files)
    # save_company (owner API 1.349). No case makes a picture, which needs macOS's sips here and the system's picture
    # code there: those have tests of their own (test_teams_company.Picture with no sips, test_teams_company_sips with
    # it, OwnerCompanyTests).
    company = {"logo.png": {"base64": base64.b64encode(company_png()).decode()}}
    case("save_company: a name", "save_company", {"name": "Example Labs"})
    case("save_company: no name", "save_company", {"name": None})
    case("save_company: a logo that is a PNG of 64 x 64 already", "save_company", {"logo_file": "<tmp>/logo.png"},
         files=company)
    case("save_company: the name and the logo, with the agent's own request id", "save_company",
         {"name": " Example Labs ", "logo_file": "<tmp>/logo.png", "request_id": PARITY_RID}, files=company)
    case("save_company: no logo", "save_company", {"logo_file": None, "name": "Example Labs"})
    case("save_company: nothing", "save_company", {})
    case("save_company: a file that is not there", "save_company", {"logo_file": "<tmp>/missing.png"})
    case("save_company: a folder", "save_company", {"logo_file": "<tmp>/dl"}, folders=["dl"])
    case("save_company: a path that is no text", "save_company", {"logo_file": 7})
    case("save_company: an empty path", "save_company", {"logo_file": "  "})
    case("save_company: a NUL in the path", "save_company", {"logo_file": "<tmp>/logo.png\u0000x"}, files=company)
    case("save_company: a file too large", "save_company", {"logo_file": "<tmp>/big.bin"},
         files={"big.bin": {"sparse": owner_mcp.ATTACH_MAX + 1}})
    case("save_company: a request id that is no UUID", "save_company", {"name": "x", "request_id": "nope"})
    case("save_company: a hub of an older release", "save_company", {"name": "Example Labs"},
         lambda s, r: parity_json(404, {"error": "not found"}) if r["method"] == "POST" else None)
    case("save_company: a fleet with no Teams", "save_company", {"name": "Example Labs"},
         lambda s, r: parity_json(409, {"error": "This needs Founderizer for Teams, which this fleet does not have.",
                                        "code": "teams_off"}) if r["method"] == "POST" else None)
    case("save_company: a new generation, read again once", "save_company", {"logo_file": "<tmp>/logo.png"},
         lambda s, r: (s.update(db="g2", moved=1), parity_json(409, {"error": "hub generation changed; refresh "
                                                                              "state"}))[1]
         if r["method"] == "POST" and not s.get("moved") else None, files=company)
    # read_attachment.
    case("read_attachment: into a file", "read_attachment", {"attachment": 3, "path": "<tmp>/out/a.txt"})
    case("read_attachment: into a folder", "read_attachment", {"attachment": 3, "path": "<tmp>/dl/"}, folders=["dl"])
    case("read_attachment: into a folder, no name", "read_attachment", {"attachment": 4, "path": "<tmp>/dl"},
         folders=["dl"])
    case("read_attachment: under the home", "read_attachment", {"attachment": 3, "path": "~/dl/./a.txt"})
    case("read_attachment: a digest that does not match", "read_attachment", {"attachment": 5, "path": "<tmp>/x.txt"})
    case("read_attachment: not there", "read_attachment", {"attachment": 9, "path": "<tmp>/x.txt"})
    case("read_attachment: no number", "read_attachment", {"attachment": 0, "path": "<tmp>/x.txt"})
    case("read_attachment: a number as text", "read_attachment", {"attachment": "3", "path": "<tmp>/x.txt"})
    case("read_attachment: no path", "read_attachment", {"attachment": 3})
    case("read_attachment: a place that cannot be written", "read_attachment",
         {"attachment": 3, "path": "<tmp>/note.txt/sub/a.txt"}, files={"note.txt": "a file, not a folder"})
    case("read_attachment: a new generation", "read_attachment", {"attachment": 3, "path": "<tmp>/a.txt"},
         lambda s, r: (s.update(db="g2", moved=1), parity_json(409, {"error": "hub generation changed; refresh "
                                                                              "state"}))[1]
         if r["path"] == "/ui/attachments/3" and not s.get("moved") else None)
    # take_backup.
    case("take_backup: into a folder", "take_backup", {"path": "<tmp>/copies"}, folders=["copies"])
    case("take_backup: into a file", "take_backup", {"path": "<tmp>/copies/one.zip", "request_id": PARITY_RID})
    case("take_backup: a digest that does not match", "take_backup", {"path": "<tmp>/c.zip"},
         lambda s, r: (200, {"Content-Type": "application/zip", "X-Fleet-Backup-SHA256": "0" * 64}, PARITY_COPY)
         if r["path"] == "/ui/backup" else None)
    case("take_backup: copies turned off", "take_backup", {"path": "<tmp>/c.zip"},
         lambda s, r: parity_json(403, {"error": "owner backups are turned off on this hub"})
         if r["path"] == "/ui/backup" else None)
    case("take_backup: the confirmation refused", "take_backup", {"path": "<tmp>/c.zip"},
         lambda s, r: parity_json(400, {"error": "the copy is not the one this hub served last"})
         if r["method"] == "POST" else None)
    case("take_backup: a place that cannot be written", "take_backup", {"path": "<tmp>/note.txt/c.zip"},
         files={"note.txt": "a file"})
    case("take_backup: no path", "take_backup", {})
    # The hub's name of a file counts only as one file name in the folder that the agent named (F1).
    names = {"a parent's part": "../../.zshrc", "a whole path": "/Library/LaunchAgents/a.plist",
             "a dot": ".", "two dots": "..", "nothing": "", "a folder in it": "dl2/a.txt",
             "a control character": "a\x01b.txt", "a NUL": "safe.txt\x00../../x", "a DEL": "a\x7fb.txt",
             "a plain name": "kept name.txt", "a dot file": ".zshenv",
             "a composed letter": "été.txt", "a decomposed letter": "été.txt",
             "a backslash": "a\\b.txt", "a NUL first": "\x00x.txt", "a C1 control character": "\u0085x.txt",
             "no quotes": None}
    for what, name in names.items():
        disposition = {"Content-Disposition": "attachment; filename=plain-name.txt" if name is None
                       else f'attachment; filename="{name}"'}
        case(f"read_attachment: the hub names {what}", "read_attachment", {"attachment": 3, "path": "<tmp>/dl"},
             lambda s, r, d=disposition: (200, dict({"Content-Type": "text/plain"}, **d), PARITY_FILE)
             if r["path"] == "/ui/attachments/3" else None, folders=["dl"])
        case(f"take_backup: the hub names {what}", "take_backup", {"path": "<tmp>/copies"},
             lambda s, r, d=disposition: (200, dict({"Content-Type": "application/zip"}, **d), PARITY_COPY)
             if r["path"] == "/ui/backup" else None, folders=["copies"])
    # A file whose name the hub gave is made new and only new, and follows no link (K1).
    notes = {"Content-Disposition": 'attachment; filename="notes.txt"'}
    case("read_attachment: the hub's name is there already as a file", "read_attachment",
         {"attachment": 3, "path": "<tmp>/dl"}, files={"dl/notes.txt": "the owner's own notes"})
    case("read_attachment: the hub's name is there already as a link to a file outside", "read_attachment",
         {"attachment": 3, "path": "<tmp>/dl"}, files={"outside/target.txt": "keep me"},
         folders=["dl"], links={"dl/notes.txt": "outside/target.txt"})
    case("read_attachment: the hub's name is there already as a folder", "read_attachment",
         {"attachment": 3, "path": "<tmp>/dl"}, folders=["dl/notes.txt"])
    case("read_attachment: the agent's own file is replaced", "read_attachment",
         {"attachment": 3, "path": "<tmp>/dl/notes.txt"}, files={"dl/notes.txt": "the old text"})
    case("take_backup: the hub's name is there already, so no confirmation", "take_backup",
         {"path": "<tmp>/copies"},
         lambda s, r: (200, dict({"Content-Type": "application/zip"}, **notes), PARITY_COPY)
         if r["path"] == "/ui/backup" else None, files={"copies/notes.txt": "an old copy"})
    case("take_backup: the agent's own file is replaced", "take_backup", {"path": "<tmp>/copies/one.zip"},
         files={"copies/one.zip": "an old copy"})
    # A root as the folder (K3): the name "tmp" is there in "/", so nothing is written into it.
    for root in ("/", "//", "///"):
        case(f"read_attachment: the folder {root}", "read_attachment", {"attachment": 3, "path": root},
             lambda s, r: (200, {"Content-Type": "text/plain", "Content-Disposition": 'attachment; filename="tmp"'},
                           PARITY_FILE) if r["path"] == "/ui/attachments/3" else None)
    # int() as Python strips (K4).
    case("duty_state: an id with U+001C", "duty_state", {"id": "\u001c5", "action": "pause"})
    case("answer_needs_you: a need with U+001F", "answer_needs_you", {"need": "5\u001f", "answer": "x"})
    case("answer_needs_you: a need in spaces", "answer_needs_you", {"need": " 5 ", "answer": "x"})
    case("answer_needs_you: a need in Unicode spaces", "answer_needs_you", {"need": "\u20035\u0085", "answer": "x"})
    # A NUL in a local path (K5).
    case("attach_file: a NUL in the path", "attach_file", {"path": "<tmp>/note.txt\u0000x"}, files=files)
    case("read_attachment: a NUL in the path", "read_attachment", {"attachment": 3, "path": "<tmp>/a\u0000x"})
    case("take_backup: a NUL in the path", "take_backup", {"path": "<tmp>/a\u0000x"})
    # A NUL is the first check on a path, before "~" is expanded (L1).
    case("attach_file: a NUL in a user's home", "attach_file", {"path": "~root\u0000x/y"})
    case("attach_file: a NUL after ~", "attach_file", {"path": "~\u0000x"})
    case("read_attachment: a NUL after ~", "read_attachment", {"attachment": 3, "path": "~\u0000x/a.txt"})
    case("take_backup: a NUL in a user's home", "take_backup", {"path": "~root\u0000x"})
    # One rule for a whole number in both programs (L2).
    for what, value in (("300 letters", "a" * 300), ("a lone surrogate", "\ud800"), ("an underscore", "1_000"),
                        ("an Arabic-Indic digit", "٥"), ("3.0", 3.0), ("3.7", 3.7), ("true", True),
                        ("30 digits", 123456789012345678901234567890), ("spaces", " 5 "), ("U+001C", "\u001c5"),
                        ("a plus", "+5"), ("minus zero", "-0"), ("a list", [5]), ("2^63", 9223372036854775808),
                        ("1e19", 1e19), ("an empty text", ""), ("spaces alone", "  ")):
        case(f"answer_needs_you: a need of {what}", "answer_needs_you", {"need": value, "answer": "x"})
    for what, value in (("3.7", 3.7), ("a lone surrogate", "\ud800"), ("an Arabic-Indic digit", "٥"),
                        ("3.0", 3.0)):
        case(f"decline_secret_request: a need of {what}", "decline_secret_request", {"need": value})
        case(f"goal_state: an id of {what}", "goal_state", {"id": value, "action": "pause"})
    # Text as Python reads it: by code points, not by characters (F5).
    case("grant_access: a combining mark after the colon", "grant_access",
         {"resource": "repo:́x", "agent": "worker-1", "level": "read"})
    case("save_profile: Unicode spaces around the name", "save_profile",
         {"agent": "\u3000ops lead\u0085", "sections": sections, "base_sha256": "profile-sha-0"})
    case("attach_file: a media type with Unicode spaces", "attach_file",
         {"path": "<tmp>/note.txt", "mime": "\u2003text/plain\u3000"}, files=files)
    # A read of the team of another shape: nothing is sent (F6).
    for what, team, kind in (("an element that is no object", {"sha256": "x", "lines": ["worker-1"]}, "repo"),
                             ("an agent that is no text", {"sha256": "x", "lines": [{"agent": 7}]}, "repo"),
                             ("repos a list", {"sha256": "x", "lines": [{"agent": "worker-1", "repos": ["acme/web"]}]},
                              "repo"),
                             ("tools a text", {"sha256": "x", "lines": [{"agent": "worker-1", "tools": "github"}]},
                              "tool"),
                             ("google a list", {"sha256": "x", "lines": [{"agent": "worker-1", "google": ["x"]}]},
                              "gmail"),
                             ("a service with no level", {"sha256": "x", "lines": [
                                 {"agent": "worker-1", "google": {"gmail": {"account": "ada@example.com"}}}]}, "gmail"),
                             ("lines missing", {"sha256": "x"}, "tool")):
        resource = {"repo": "repo:acme/web", "tool": "tool:github", "gmail": "gmail:ada@example.com"}[kind]
        case(f"grant_access: a team read with {what}", "grant_access",
             {"resource": resource, "agent": "worker-1", "level": "read"},
             lambda s, r, t=team: parity_json(200, t) if r["path"] == "/ui/team" else None)
    # The sentence that a hub older than the app gets (G2): only for what hub.py answers to a route or a field that it
    # does not know, and not for another 404.
    case("send_message: the hub does not know the route", "send_message", {"text": "x"},
         lambda s, r: parity_json(404, {"error": "not found"}) if r["method"] == "POST" else None)
    case("check_machine: the hub does not know a field", "check_machine", {"agent": "worker-1"},
         lambda s, r: parity_json(400, {"error": "unknown field foo"}) if r["method"] == "POST" else None)
    case("fleet_overview: the hub does not know a page", "fleet_overview", None,
         lambda s, r: parity_json(404, {"error": "not found"}) if r["path"] == "/ui/servers" else None)
    case("take_backup: the hub has no such route", "take_backup", {"path": "<tmp>/c.zip"},
         lambda s, r: parity_json(404, {"error": "no such route here"}) if r["path"] == "/ui/backup" else None)
    parity_cloud_cases(case)
    return cases


PARITY_KEY = "<tmp>/id_ed25519.pub"


def parity_cloud_cases(case):
    """**The cases of design 9's three tools of a cloud** (piece B2): the same calls of the two programs against the
    same stand-in program of each cloud (`Cloud.STAND_IN`, with `Cloud.cloud_rules`), which answers by the commands
    before it. `before`: the calls that make the cloud's state first, whose commands the fixture does not keep. Each
    cloud has a `proved` date in these cases, but where a case says not."""
    key = {"id_ed25519.pub": Cloud.KEY + " admin@example.invalid\n"}
    for cloud, recipe in owner_mcp.CLOUD_RECIPES["clouds"].items():
        account, place = Cloud.WHERE[cloud]
        base = {"cloud": cloud, "name": Cloud.NAME, "account": account, "place": place}
        rules = Cloud.cloud_rules(cloud)
        journey = []
        for step in recipe["steps"]:
            if step["kind"] in ("make", "check", "close"):
                more = {"server": {"ssh_public_key_file": PARITY_KEY},
                        "open_ssh": {"ssh_from": "203.0.113.9"}}.get(step["id"], {})
                journey.append(("cloud_step", dict(base, step=step["id"], **more)))
        journey += [("cloud_remove", dict(base, step=removal["id"])) for removal in recipe["removals"]]

        def cloud_case(name, tool, args, before=(), rules=rules, proved=True, missing=False):
            case(f"{cloud}: {name}", tool, args, files=key,
                 programs={"rules": rules, "before": [list(b) for b in before], "proved": proved, "missing": missing})
        cloud_case("the recipe", "cloud_look", {"cloud": cloud})
        cloud_case("a look before anything", "cloud_look", base)
        for at, (tool, args) in enumerate(journey):
            cloud_case(f"{tool} {args['step']}", tool, args, before=journey[:at])
            cloud_case(f"{tool} {args['step']} again", tool, args, before=journey[:at + 1])
        opened = [j for j in journey if j[0] == "cloud_step" and j[1]["step"] in ("group", "firewall", "server",
                                                                                   "open_ssh")]
        cloud_case("a look with SSH open", "cloud_look", base, before=opened)
        cloud_case("an unproved cloud", "cloud_look", base, proved=False)
        cloud_case("no program", "cloud_look", base, missing=True)
        signed_out = {"aws": {"exit": 253, "err": "Unable to locate credentials."},
                      "azure": {"exit": 1, "err": "ERROR: Please run 'az login' to setup account."},
                      "google": {"out": []}}[cloud]
        reads = {"aws": "sts get-caller-identity", "azure": "account show", "google": "auth list"}
        cloud_case("signed out", "cloud_step", dict(base, step=journey[0][1]["step"]),
                   rules=[dict(signed_out, has=[reads[cloud]])] + rules)
        cloud_case("a value with a space", "cloud_step", dict(base, step="open_ssh", ssh_from="203.0.113.9 x"))
        if cloud in ("aws", "azure"):
            other = {"aws": {"Account": "999999999999", "Arn": "arn:aws:iam::999999999999:user/x"},
                     "azure": {"id": "99999999-1111-2222-3333-444444444444", "user": {"name": "x"}}}[cloud]
            cloud_case("another account", "cloud_step", dict(base, step=journey[0][1]["step"]),
                       rules=Cloud.cloud_rules(cloud, identity=other))
    aws = {"cloud": "aws", "name": Cloud.NAME, "account": Cloud.WHERE["aws"][0], "place": Cloud.WHERE["aws"][1]}
    role = {"Reservations": [{"Instances": [{"State": {"Name": "running"}, "PublicIpAddress": "198.51.100.30",
                                             "IamInstanceProfile": {"Arn": "arn:aws:iam::123456789012:x/web"}}]}]}
    case("aws: a server that exists", "cloud_look", {"cloud": "aws", "instance": "i-0123456789abcdef0",
                                                     "account": aws["account"], "place": aws["place"]},
         programs={"rules": [{"has": ["--instance-ids i-0123456789abcdef0"], "out": role}] + Cloud.cloud_rules("aws"),
                   "before": [], "proved": True, "missing": False})
    group = {"GroupId": "sg-0a1b2c3d4e5f67890", "GroupName": f"founderizer-{Cloud.NAME}",
             "Tags": [{"Key": "founderizer-server", "Value": Cloud.NAME}]}
    case("aws: a read that fails after run-instances", "cloud_step",
         dict(aws, step="server", ssh_public_key_file=PARITY_KEY), files={"id_ed25519.pub": Cloud.KEY + "\n"},
         programs={"rules": Cloud.cloud_rules("aws", groups=[group], made={"exit": 254, "err": "Throttling"}),
                   "before": [], "proved": True, "missing": False})
    case("aws: an instance of the name with another token", "cloud_remove", dict(aws, step="server"),
         programs={"rules": Cloud.cloud_rules("aws", reservations=[{"Instances": [{
             "InstanceId": "i-0fedcba987654321f", "ClientToken": "someone-else", "State": {"Name": "running"}}]}]),
             "before": [], "proved": True, "missing": False})
    goog = {"cloud": "google", "name": Cloud.NAME, "account": Cloud.WHERE["google"][0],
            "place": Cloud.WHERE["google"][1]}
    opened = [["cloud_step", dict(goog, step="firewall")],
              ["cloud_step", dict(goog, step="server", ssh_public_key_file=PARITY_KEY)],
              ["cloud_step", dict(goog, step="open_ssh", ssh_from="203.0.113.9")]]
    for at, (tool, step) in enumerate((("cloud_remove", "server"), ("cloud_step", "close_ssh"),
                                       ("cloud_remove", "firewall"))):
        chain = [["cloud_remove", dict(goog, step="server")], ["cloud_step", dict(goog, step="close_ssh")]][:at]
        case(f"google: the removal with SSH open, {tool} {step}", tool, dict(goog, step=step),
             files={"id_ed25519.pub": Cloud.KEY + "\n"},
             programs={"rules": Cloud.cloud_rules("google"), "before": opened + chain, "proved": True,
                       "missing": False})
    parity_cloud_paths(case, aws, goog)
    azure = {"cloud": "azure", "name": Cloud.NAME, "account": Cloud.WHERE["azure"][0],
             "place": Cloud.WHERE["azure"][1]}
    case("azure: a group that still shows after its delete", "cloud_remove", dict(azure, step="group"),
         programs={"rules": Cloud.cloud_rules("azure", group_stays=True),
                   "before": [["cloud_step", dict(azure, step="group")], ["cloud_step", dict(azure, step="firewall")]],
                   "proved": True, "missing": False})


class ParityHub:
    """A stand-in hub on 127.0.0.1 that records each request and answers it with `answer(index, request)`."""

    def __init__(self):
        import http.server
        hub_self = self
        self.requests, self.answer = [], None

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def handle_one(self):
                path, _, query = self.path.partition("?")
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                req = {"method": self.command, "path": path, "query": query, "body": body,
                       "headers": {k.lower(): v for k, v in self.headers.items()}}
                hub_self.requests.append(req)
                status, headers, data = hub_self.answer(len(hub_self.requests) - 1, req)
                # A header goes out as the UTF-8 bytes of its text, which http.server writes as Latin-1: a header of
                # the hub can hold any bytes, and a reader reads them as it reads them. The fixture keeps the text
                # that a reader of Latin-1 gets.
                headers = {k: v.encode("utf-8").decode("latin-1") for k, v in headers.items()}
                req["answer"] = (status, headers, data)
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            do_GET = do_POST = handle_one

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        # a short poll: tearDown's shutdown() waits for the loop's next look, which was up to 0.5 s in each test
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def parity_requests(requests, given):
    """The requests as the two programs are compared: method, path, the parsed query, the headers that carry meaning,
    and the parsed body, with each request id that this program made named by its order (`<rid1>`)."""
    given = str(given).lower() if given else None
    ids = {}

    def rid(value):
        if not isinstance(value, str) or value == given or not PARITY_UUID.fullmatch(value):
            return value
        return ids.setdefault(value, f"<rid{len(ids) + 1}>")
    out = []
    for req in requests:
        headers = req["headers"]
        kind = (headers.get("content-type") or "").split(";")[0].strip()
        body = None
        if req["body"]:
            if kind == "application/json":
                body = json.loads(req["body"])
                if isinstance(body, dict) and "request_id" in body:
                    body["request_id"] = rid(body["request_id"])
            else:
                body = {"bytes": len(req["body"]), "sha256": hashlib.sha256(req["body"]).hexdigest()}
        out.append({"method": req["method"], "path": req["path"],
                    "query": urllib.parse.parse_qs(req["query"], keep_blank_values=True),
                    "headers": {"content-type": headers.get("content-type"),
                                "x-fleet-request-id": rid(headers.get("x-fleet-request-id")),
                                "x-fleet-name": headers.get("x-fleet-name"),
                                "x-fleet-client": "x-fleet-client" in headers,
                                "authorization": "authorization" in headers, "origin": "origin" in headers},
                    "body": body})
    return out


# The clock of both programs in the parity check, so that take_backup's fallback name is the same with no placeholder
# (the Swift test gives the same time to OwnerContext.now).
PARITY_NOW = 1763078400
# The files of a home that the comparison leaves out, each by its name: the lock, and each program's own label.
PARITY_OWN = (".founderizer/lock", ".founderizer/client", ".founderizer/cli-client")


def parity_places(value, places):
    """Each local folder and the hub's address in a value, as its placeholder."""
    if isinstance(value, str):
        for real, mark in places:
            value = value.replace(real, mark)
        return value
    if isinstance(value, list):
        return [parity_places(v, places) for v in value]
    if isinstance(value, dict):
        return {k: parity_places(v, places) for k, v in value.items()}
    return value


def parity_older(answer):
    """True for an answer that hub.py gives to a route or a field that it does not know (`Parity` holds these words to
    hub.py): 404 "not found" of its dispatch, and 400 "unknown field ..." of a route's `only`. The program inside the
    app adds one sentence to such a refusal (`OwnerHub.olderHub`), and only to such a one."""
    status, _headers, data = answer
    try:
        error = (json.loads(data) or {}).get("error") or ""
    except (ValueError, AttributeError):
        return False
    if not isinstance(error, str):                  # an error that is no text is no such answer
        return False
    return (status == 404 and error == "not found") or (status == 400 and error.startswith("unknown field "))


def parity_after(work, home, places):
    """Every file (with its SHA-256) and every folder under the two folders after the call, setup ones included, and
    each own file of a program in the home left out by its name (PARITY_OWN)."""
    files, folders = {}, []
    for root, mark in ((work, "<tmp>"), (home, "<home>")):
        for f in sorted(root.rglob("*")):
            rel = f.relative_to(root).as_posix()
            if mark == "<home>" and rel in PARITY_OWN:
                continue
            if f.is_dir():
                folders.append(parity_places(f"{mark}/{rel}", places))
            elif f.is_file():
                files[parity_places(f"{mark}/{rel}", places)] = hashlib.sha256(f.read_bytes()).hexdigest()
    return {"files": files, "folders": sorted(folders)}


def parity_cloud_paths(case, aws, goog):
    """More cases of design 9's tools, one for each path of the code that the journeys of `parity_cloud_cases` do not
    walk (the second read of piece B2): a subnet, a profile, a size, a disk and a hub, the floor of memory, a memory
    that is no whole number, a change that fails, reads that fail after close_ssh and after a removal, an answer that
    is not JSON, two answers, an ended client token, no default VPC, close_ssh after the firewall is gone, Azure's
    restriction of a place and of a zone, a foreign resource and an unmarked group at Azure, an unmarked rule and
    instance at Google Cloud, and a server that exists at Azure and at Google Cloud."""
    key = {"id_ed25519.pub": Cloud.KEY + " admin@example.invalid\n"}
    azure = {"cloud": "azure", "name": Cloud.NAME, "account": Cloud.WHERE["azure"][0],
             "place": Cloud.WHERE["azure"][1]}
    group = {"GroupId": "sg-0a1b2c3d4e5f67890", "GroupName": f"founderizer-{Cloud.NAME}",
             "Tags": [{"Key": "founderizer-server", "Value": Cloud.NAME}]}

    def one(name, tool, args, rules, before=()):
        case(name, tool, args, files=key,
             programs={"rules": rules, "before": [list(b) for b in before], "proved": True, "missing": False})

    def steps(base, ids, **more):
        fields = {"server": {"ssh_public_key_file": PARITY_KEY}, "open_ssh": {"ssh_from": "203.0.113.9"}}
        return [("cloud_step", dict(base, step=i, **fields.get(i, {}), **more)) for i in ids]
    # AWS
    sub = {"subnet": "subnet-0a1b2c3d4e5f67890"}
    no_vpc = Cloud.cloud_rules("aws", vpcs={"Vpcs": []})
    one("aws: firewall in a subnet", "cloud_step", dict(aws, step="firewall", **sub), no_vpc)
    one("aws: server in a subnet", "cloud_step", dict(aws, step="server", ssh_public_key_file=PARITY_KEY, **sub),
        no_vpc, steps(aws, ["firewall"], **sub))
    one("aws: removal of a firewall in a subnet", "cloud_remove", dict(aws, step="firewall", **sub), no_vpc,
        steps(aws, ["firewall", "server"], **sub) + [("cloud_remove", dict(aws, step="server", **sub))])
    one("aws: no default VPC", "cloud_step", dict(aws, step="firewall"), no_vpc)
    hub = {"profile": "admin", "size": "t4g.small", "disk_gb": 40, "use": "hub"}
    one("aws: a profile, a size, a disk and a hub", "cloud_step",
        dict(aws, step="server", ssh_public_key_file=PARITY_KEY, **hub), Cloud.cloud_rules("aws"),
        steps(aws, ["firewall"], profile="admin"))
    one("aws: the floor of memory", "cloud_step", dict(aws, step="server", ssh_public_key_file=PARITY_KEY),
        Cloud.cloud_rules("aws", groups=[group], memory=1024))
    one("aws: a memory that is no whole number", "cloud_step",
        dict(aws, step="server", ssh_public_key_file=PARITY_KEY),
        Cloud.cloud_rules("aws", groups=[group], memory="2048"))
    one("aws: a change that fails", "cloud_step", dict(aws, step="firewall"),
        [{"has": ["create-security-group"], "exit": 254, "err": "An error occurred (UnauthorizedOperation)"}] +
        Cloud.cloud_rules("aws"))
    one("aws: a read that fails after close_ssh", "cloud_step", dict(aws, step="close_ssh"),
        [{"has": ["describe-security-group-rules"], "after": ["revoke-security-group-ingress"], "exit": 254,
          "err": "Throttling"}] + Cloud.cloud_rules("aws"), steps(aws, ["firewall", "server", "open_ssh"]))
    one("aws: a read that fails after a removal", "cloud_remove", dict(aws, step="server"),
        [{"has": ["describe-instances"], "after": ["terminate-instances"], "exit": 254, "err": "Throttling"}] +
        Cloud.cloud_rules("aws"), steps(aws, ["firewall", "server"]))
    one("aws: an answer that is not JSON", "cloud_step", dict(aws, step="firewall"),
        [{"has": ["describe-vpcs"], "out": "<html>Bad gateway</html>"}] + Cloud.cloud_rules("aws"))
    two = [{"Instances": [{"InstanceId": f"i-0a1b2c3d4e5f6789{n}", "ClientToken": f"founderizer-{Cloud.NAME}"}]}
           for n in (0, 1)]
    one("aws: two instances of the name", "cloud_look", aws, Cloud.cloud_rules("aws", reservations=two))
    one("aws: an ended client token", "cloud_step", dict(aws, step="server", ssh_public_key_file=PARITY_KEY),
        [{"has": ["run-instances"], "out": {"Instances": [{"InstanceId": "i-0a1b2c3d4e5f67890",
                                                           "State": {"Name": "terminated"}}]}}] +
        Cloud.cloud_rules("aws", groups=[group]))
    one("aws: close_ssh after the firewall is gone", "cloud_step", dict(aws, step="close_ssh"),
        Cloud.cloud_rules("aws"), steps(aws, ["firewall", "server", "open_ssh"]) +
        [("cloud_remove", dict(aws, step="server")), ("cloud_remove", dict(aws, step="firewall"))])
    # Azure
    for kind, stops in (("Location", "a place"), ("Zone", "a zone")):
        one(f"azure: a restriction of {stops}", "cloud_step",
            dict(azure, step="server", ssh_public_key_file=PARITY_KEY),
            Cloud.cloud_rules("azure", restrictions=[{"type": kind, "reasonCode": "NotAvailableForSubscription"}]),
            steps(azure, ["group", "firewall"]))
    base = f"/subscriptions/{Cloud.WHERE['azure'][0]}/resourceGroups/founderizer-{Cloud.NAME}"
    one("azure: a foreign resource in the group", "cloud_remove", dict(azure, step="group"),
        Cloud.cloud_rules("azure", group_now={"id": base, "tags": {"founderizer-server": Cloud.NAME}},
                          resources=[{"name": f"{Cloud.NAME}-nsg"}, {"name": "billing-db"}]))
    one("azure: a group with no mark", "cloud_step", dict(azure, step="group"),
        Cloud.cloud_rules("azure", group_now={"id": base, "tags": {}}))
    vm = "/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/apps/providers/Microsoft.Compute/" \
         "virtualMachines/web-1"
    one("azure: a server that exists", "cloud_look", {"cloud": "azure", "instance": vm, "account": azure["account"]},
        [{"has": ["vm show --ids"], "out": {"powerState": "VM running", "publicIps": "198.51.100.40",
                                            "osProfile": {"adminUsername": "web"},
                                            "identity": {"type": "SystemAssigned"},
                                            "hardwareProfile": {"vmSize": "Standard_B2s"}}}] +
        Cloud.cloud_rules("azure"))
    # Google Cloud
    gsub = {"subnet": "servers"}
    one("google: firewall in a subnet", "cloud_step", dict(goog, step="firewall", **gsub), Cloud.cloud_rules("google"))
    one("google: server in a subnet", "cloud_step", dict(goog, step="server", ssh_public_key_file=PARITY_KEY, **gsub),
        Cloud.cloud_rules("google"), steps(goog, ["firewall"], **gsub))
    other = {"name": f"founderizer-{Cloud.NAME}-closed", "description": "the network team's rule"}
    one("google: a rule with no mark", "cloud_step", dict(goog, step="firewall"),
        Cloud.cloud_rules("google", rules_now=[other]))
    one("google: an instance with no mark", "cloud_remove", dict(goog, step="server"),
        Cloud.cloud_rules("google", instance_now={"name": Cloud.NAME, "labels": {}}))
    one("google: a server that exists", "cloud_look", {"cloud": "google", "instance": "web-1",
                                                       "account": goog["account"], "place": goog["place"]},
        [{"has": ["instances describe web-1"], "out": {
            "status": "RUNNING", "machineType": "https://www.googleapis.com/compute/v1/projects/p/zones/z/machineTypes/"
                                                "e2-medium",
            "networkInterfaces": [{"networkIP": "10.0.0.4", "accessConfigs": [{"natIP": "198.51.100.41"}]}],
            "serviceAccounts": [{"email": "web@example-project-1.iam.gserviceaccount.com"}]}}] +
        Cloud.cloud_rules("google"))


# The folder of the files of one cloud command

# The folder of the files of one cloud command (`CloudRun.change`: user data, a key file), as both programs make it in
# the folder of temporary files: in the fixture it is <files>, for the Swift test makes its own.
PARITY_CALL_FILES = re.compile(r"(?:/[^/\s\"']+)*/founderizer-cloud-[^/\s\"']+")


def parity_cloud_placed(value):
    """Each folder of the files of a cloud command in a value, as <files>."""
    if isinstance(value, str):
        return PARITY_CALL_FILES.sub("<files>", value)
    if isinstance(value, list):
        return [parity_cloud_placed(v) for v in value]
    if isinstance(value, dict):
        return {parity_cloud_placed(k): parity_cloud_placed(v) for k, v in value.items()}
    return value


@contextlib.contextmanager
def parity_programs(programs, scratch, work):
    """**The cloud's programs of one case of design 9** (`parity_cloud_cases`): a folder `bin` of the scratch with the
    stand-in of each program and the case's rules, on the PATH alone; each cloud with a `proved` date unless the case
    says not; the words of the program inside the app (`CLOUD_AS_APP`); and the calls of `before` run first. It gives
    a function that reads the commands of the case's own call, each with the files that it named and the answer that
    it got. A case with no `programs` gets None and changes nothing."""
    if not programs:
        yield None
        return
    folder = scratch / "bin"
    folder.mkdir()
    if not programs["missing"]:
        for program in ("aws", "az", "gcloud"):
            (folder / program).write_text(f"#!{sys.executable}\n" + Cloud.STAND_IN)
            (folder / program).chmod(0o755)
    (folder / "rules.json").write_text(json.dumps(programs["rules"]))
    recipes = json.loads(json.dumps(owner_mcp.CLOUD_RECIPES))
    for recipe in recipes["clouds"].values():
        recipe["proved"] = "2026-12-01" if programs["proved"] else None
    log = folder / "calls.jsonl"
    lines = (lambda: log.read_text().splitlines() if log.exists() else [])
    with patch.dict(os.environ, {"PATH": str(folder)}), patch.object(owner_mcp, "CLOUD_RECIPES", recipes), \
            patch.object(owner_mcp, "CLOUD_AS_APP", True):
        for tool, args in programs["before"]:
            owner_mcp.call_tool(tool, json.loads(json.dumps(args).replace("<tmp>", str(work))))
        mark = len(lines())
        yield lambda: [json.loads(line) for line in lines()[mark:]]


def parity_fixture():
    """Run each case on owner_mcp.py against the stand-in hub, and give the fixture that the Swift test replays."""
    owner_mcp.TOOLS.update({t["name"]: t for t in owner_mcp.tools()})
    hub_ = ParityHub()
    out = []
    try:
        for c in parity_cases():
            scratch = pathlib.Path(tempfile.mkdtemp(prefix="fleet-parity-"))
            work, home = scratch / "work", scratch / "home"
            work.mkdir()
            home.mkdir()
            try:
                for folder in c["setup"]["folders"]:
                    (work / folder).mkdir(parents=True, exist_ok=True)
                for name, content in c["setup"]["files"].items():
                    (work / name).parent.mkdir(parents=True, exist_ok=True)
                    if isinstance(content, dict) and "base64" in content:      # a file that is no text: a picture
                        (work / name).write_bytes(base64.b64decode(content["base64"]))
                    elif isinstance(content, dict):
                        with open(work / name, "wb") as f:
                            f.truncate(content["sparse"])
                    else:
                        (work / name).write_text(content, encoding="utf-8")
                for name, target in c["setup"]["links"].items():
                    os.symlink(work / target, work / name)
                state = {"db": "g1"}
                hub_.requests = []
                hub_.answer = lambda _i, req, c=c, state=state: (c["answer"] and c["answer"](state, req)) or \
                    parity_answer(state, req)
                places = [(str(work), "<tmp>"), (str(home), "<home>"), (str(scratch / "bin"), "<bin>"),
                          (hub_.base, "<hub>")]
                args = json.loads(json.dumps(c["arguments"]).replace("<tmp>", str(work)))
                owner_mcp.GENERATION["db"] = None
                with patch.dict(os.environ, {"FOUNDERIZER_HUB": hub_.base, "HOME": str(home)}), \
                        patch.object(owner_mcp, "HOME", home / ".founderizer"), \
                        patch.object(owner_mcp, "CLIENT_FILE", home / ".founderizer" / "client"), \
                        patch.object(owner_mcp, "HUB_FILE", home / ".founderizer" / "hub"), \
                        patch.object(owner_mcp.time, "time", lambda: float(PARITY_NOW)), \
                        parity_programs(c["programs"], scratch, work) as commands:
                    text, bad = owner_mcp.call_tool(c["tool"], args)
                    called = commands() if commands else None
                older = sum(parity_older(req["answer"]) for req in hub_.requests
                            if req["path"] not in PARITY_NO_REFUSAL)
                if bad and "\n" + owner_mcp.OLDER_HUB in text:
                    # save_company says the sentence of an older hub itself, as the program inside the app says it
                    # for each such answer (OwnerHub.olderHub): as many times, and the Swift test takes it out of both
                    assert text.count("\n" + owner_mcp.OLDER_HUB) == older, (c["name"], text)
                    text = text.replace("\n" + owner_mcp.OLDER_HUB, "")
                owner_mcp.GENERATION["db"] = None
                if c["app_lists"]:
                    # the app's read in place of this server's read of the head, with the hub's answer to it (case())
                    assert c["answer"] is None, c["name"]
                    first = hub_.requests[0]
                    words = first["query"].split("&")
                    assert first["path"] == owner_mcp.STATE_ROUTE and "head=1" in words, (c["name"], first["query"])
                    first["query"] = "&".join(word for word in words if word != "head=1")
                    assert first["path"] + "?" + first["query"] == owner_mcp.STATE_READ, first["query"]
                    status, headers, data = hub_.answer(0, first)
                    first["answer"] = (status, {k: v.encode("utf-8").decode("latin-1") for k, v in headers.items()},
                                       data)
                answers = []
                for req in hub_.requests:
                    status, headers, data = req["answer"]
                    try:
                        body = {"text": data.decode("utf-8")}
                    except UnicodeDecodeError:
                        body = {"base64": __import__("base64").b64encode(data).decode()}
                    answers.append(dict(body, status=status, headers=headers))
                one = {"name": c["name"], "tool": c["tool"], "arguments": c["arguments"], "setup": c["setup"],
                       "answers": answers,
                       "requests": parity_requests(hub_.requests, c["arguments"].get("request_id")),
                       "outcome": parity_cloud_placed({"refusal": parity_places(text, places)} if bad else
                                                      {"result": parity_places(json.loads(text), places)}),
                       "older_hub": older,
                       "after": parity_after(work, home, places)}
                if called is not None:      # design 9's tools of a cloud: each command, its files and its answer
                    one["cloud"] = {"proved": c["programs"]["proved"], "missing": c["programs"]["missing"],
                                    "commands": [parity_cloud_placed(parity_places(
                                        {"argv": x["argv"], "files": x["files"], "exit": x["answer"]["exit"],
                                         "out": x["answer"]["out"], "error": x["answer"]["err"]}, places))
                                        for x in called]}
                out.append(one)
            finally:
                shutil.rmtree(scratch, True)
    finally:
        hub_.close()
    return {"about": "The parity check of owner_mcp.py and the program inside the Founderizer app (OWNER-MCP.md, "
                     "\"The program inside the app\"): each case's arguments, the stand-in hub's answers in order, "
                     "the requests that owner_mcp.py made and its outcome. In the two cases of an answer with a "
                     "choice of 0 or 1 the first request is the app's program's read of the state with its lists, "
                     "where owner_mcp.py reads the head. The Swift test OwnerParityTests replays it. Remake it "
                     "with: " + PARITY_REMAKE,
            "now": PARITY_NOW, "cases": out}


def parity_text():
    return json.dumps(parity_fixture(), indent=1, sort_keys=True) + "\n"


class Parity(unittest.TestCase):
    """**The parity check** (plan 3.3): the fixture that the Swift tests replay against the program inside the app is
    what `owner_mcp.py` does now, case by case, and it covers each tool that both programs have."""

    @needs_the_apps
    def test_the_committed_parity_fixture_is_what_owner_mcp_does_now(self):
        made = parity_text()
        self.assertEqual(PARITY_FIXTURE.read_text() if PARITY_FIXTURE.exists() else "", made,
                         f"the parity fixture is not what owner_mcp.py does now: remake it with `{PARITY_REMAKE}`, "
                         f"read its diff, and run the Swift tests (OwnerParityTests)")

    def test_the_script_covers_each_tool_that_both_programs_have(self):
        named = {c["tool"] for c in parity_cases()}
        both = {t["name"] for t in owner_mcp.dump_tools()["tools"] if t["kind"] != "absent"}
        self.assertEqual(both - named, set())
        self.assertEqual(len(both), 58 + 4 + 13)

    def test_the_older_hub_rule_is_what_hub_py_answers(self):
        """`parity_older` is read from the hub, not from the program: its dispatch answers an unknown route with 404
        "not found", and a route's `only` an unknown field with ValueError "unknown field <name>", which ui_command
        gives as 400. It writes the exception with `refusal_body(e)` (UI-API.md 1.181): the words as `error`, and the
        code and names that a coded refusal has beside them; a plain ValueError has none, so its answer is `error`
        alone, as the program here reads it."""
        src = (HERE / "hub.py").read_text()
        self.assertIn('self.json(404, {"error": "not found"})', src)
        self.assertIn('raise ValueError(f"unknown field {extra[0]}")', src)
        self.assertIn('return self.json(400, refusal_body(e))', src)
        self.assertEqual(hub.refusal_body(ValueError("unknown field foo")), {"error": "unknown field foo"})
        self.assertTrue(parity_older((404, {}, b'{"error": "not found"}')))
        self.assertTrue(parity_older((400, {}, b'{"error": "unknown field foo"}')))
        self.assertFalse(parity_older((404, {}, b'{"error": "no such attachment"}')))
        self.assertFalse(parity_older((409, {}, b'{"error": "unknown field foo"}')))


class CompanyLogoFile(unittest.TestCase):
    """save_company's file (owner API 1.349): what of it leaves this computer, and which PNG goes as it is. No hub: the
    command is a stand-in that records what would go. Each test here runs the same on every computer: sips is a path
    that is not there. What sips does (the fit, the turn, a document that it reads) is test_teams_company_sips."""

    def test_a_file_that_is_no_picture_never_leaves_this_computer(self):
        """A text, a private key, a file that only starts as a PNG, a PNG with bytes after its end and one of more than
        12,288 bytes are refused before any request with no sips; a PDF, a PostScript file and an SVG are refused as no
        picture before sips would run (the program inside the app reads none of them); a whole PNG of 64 x 64 goes,
        as it is. Bug: logo_file names a wrong file, and its bytes go to the hub (the area's rule for both copies)."""
        folder = pathlib.Path(tempfile.mkdtemp(prefix="fleet-logo-"))
        self.addCleanup(shutil.rmtree, str(folder), True)
        start = owner_mcp.PNG_SIGNATURE + b"\x00\x00\x00\x0dIHDR" + struct.pack(">IIBBBBB", 32, 32, 8, 6, 0, 0, 0)
        no_sips = {"plan.txt": b"The launch plan: the price is still open.\n",
                   # a key file's shape, its marker in two parts so that no scanner takes this file for a key
                   "id_ed25519": ("-----BEGIN OPENSSH " + "PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n"
                                  "-----END OPENSSH " + "PRIVATE KEY-----\n").encode(),
                   "start.png": start + b"not the rest of a picture",
                   "after.png": company_png(after=b"\x00"),
                   "large.png": company_png(extra=png_chunk(b"tEXt", b"Comment\x00" + b"x" * 12288))}
        documents = {"contract.pdf": b"\x00\x01 a header %PDF-1.7\n1 0 obj << >> endobj\n%%EOF\n",
                     "page.eps": b"%!PS-Adobe-3.0 EPSF-3.0\n%%BoundingBox: 0 0 10 10\n",
                     "logo.svg": b"\xef\xbb\xbf\n  <svg xmlns='http://www.w3.org/2000/svg' width='10' height='10'/>"}
        sent = []
        tools = {t["name"]: t for t in owner_mcp.tools()}
        with patch.dict(owner_mcp.TOOLS, tools, clear=True), patch.object(owner_mcp, "SIPS", str(folder / "no-sips")), \
                patch.object(owner_mcp, "command", lambda *a, **k: sent.append(a) or {"name": None, "logo": None}):
            for files, words in ((no_sips, owner_mcp.LOGO_NO_SIPS), (documents, owner_mcp.LOGO_NOT_A_PICTURE)):
                for name, data in files.items():
                    (folder / name).write_bytes(data)
                    with self.subTest(file=name):
                        self.assertEqual(owner_mcp.call_tool("save_company", {"logo_file": str(folder / name)}),
                                         (words, True))
            self.assertEqual(sent, [])
            (folder / "logo.png").write_bytes(company_png())
            text, bad = owner_mcp.call_tool("save_company", {"logo_file": str(folder / "logo.png")})
        self.assertFalse(bad, text)
        self.assertEqual(json.loads(text), {"name": None, "logo": None, "picture": owner_mcp.LOGO_AS_IS})
        self.assertEqual([(route, base64.b64decode(body["png"])) for route, body, *_ in sent],
                         [("/ui/company", company_png())])

    def test_a_sips_that_fails_or_a_copy_that_fails_says_so_and_sends_nothing(self):
        """With a stand-in for the run of sips and for the folder of the copy (no real sips, so this runs everywhere): a
        sips that takes too long, one that a signal stops, and a copy that the disk refuses each say what happened,
        in words that name no path of this computer, and nothing is sent. Bug: the catch of a timeout moves under
        the general one, and a slow sips says "not a picture", or a full disk shows the temporary folder's path."""
        folder = pathlib.Path(tempfile.mkdtemp(prefix="fleet-logo-"))
        self.addCleanup(shutil.rmtree, str(folder), True)
        (folder / "small.png").write_bytes(company_png(size=32))           # no ready logo: it goes to sips
        sent, place = [], str(folder / "small.png")

        def late(argv, **_kw):
            raise subprocess.TimeoutExpired(argv, owner_mcp.SIPS_WAIT)

        def stopped(argv, **_kw):
            return subprocess.CompletedProcess(argv, -9, b"", b"")

        def full(**_kw):
            raise OSError(28, "No space left on device")
        tools = {t["name"]: t for t in owner_mcp.tools()}
        with patch.dict(owner_mcp.TOOLS, tools, clear=True), patch.object(owner_mcp, "SIPS", sys.executable), \
                patch.object(owner_mcp, "command", lambda *a, **k: sent.append(a) or {"name": None, "logo": None}):
            for name, stand_in, words in (("late", patch.object(owner_mcp.subprocess, "run", late),
                                           owner_mcp.LOGO_SIPS_LATE),
                                          ("stopped", patch.object(owner_mcp.subprocess, "run", stopped),
                                           owner_mcp.LOGO_SIPS_STOPPED.format(9)),
                                          ("full", patch.object(owner_mcp.tempfile, "mkdtemp", full),
                                           owner_mcp.LOGO_NOT_COPIED.format("No space left on device"))):
                with self.subTest(name), stand_in:
                    self.assertEqual(owner_mcp.call_tool("save_company", {"logo_file": place}), (words, True))
        self.assertEqual(sent, [])
        self.assertEqual(owner_mcp.LOGO_SIPS_LATE, "sips did not finish reading logo_file in 60 seconds. Nothing was "
                                                   "sent.")

    def test_a_hub_that_does_not_serve_the_route_is_said_to_be_older(self):
        """A hub of a release before owner API 1.349 answers 404 "not found" to POST /ui/company: the tool says, in the
        words of the program inside the app (OwnerHub.olderHub, which the table carries), that the hub can be older
        and gets the route with its next update. Bug: the owner's AI session reads only "not found" and looks for a
        fault of the tool."""
        refused = owner_mcp.Refused("The hub refused the company's name and logo (404): not found")
        with patch.dict(owner_mcp.TOOLS, {t["name"]: t for t in owner_mcp.tools()}, clear=True), \
                patch.object(owner_mcp, "command", side_effect=refused):
            self.assertEqual(owner_mcp.call_tool("save_company", {"name": "Example Labs"}),
                             (f"{refused}\n{owner_mcp.OLDER_HUB}", True))
        self.assertEqual(owner_mcp.dump_tools()["COMPANY_LOGO"]["older_hub"], owner_mcp.OLDER_HUB)

    def test_only_a_whole_png_that_the_hub_takes_goes_as_it_is(self):
        """A PNG of 64 x 64 goes as it is only when a walk of its chunks agrees with the hub's own rules: each CRC,
        IEND last with no byte after it, no critical chunk but IHDR, PLTE, IDAT and IEND, not both sRGB and iCCP, at
        most 12,288 bytes; a text chunk or a profile alone keeps it whole. Each other one is drawn again. Bugs: the
        hub refuses with a 400 a file that the tool sent as it is; a large ready PNG goes, and the hub refuses it."""
        profile = png_chunk(b"iCCP", b"P3\x00\x00" + zlib.compress(b"a profile"))
        whole = (company_png(), company_png(extra=png_chunk(b"tEXt", b"Author\x00Example Labs")),
                 company_png(extra=profile))
        broken = company_png()[:-1] + bytes([company_png()[-1] ^ 1])                    # IEND's CRC is wrong
        drawn = (company_png(after=b"\x00"), broken, company_png()[:-12],
                 company_png(extra=png_chunk(b"sRGB", b"\x00") + profile),
                 company_png(extra=png_chunk(b"ABCD", b"")),                            # a critical chunk of nobody
                 company_png(extra=png_chunk(b"tEXt", b"Comment\x00" + b"x" * 12288)),
                 company_png(size=32))
        self.assertEqual([owner_mcp.logo_as_is(one) for one in whole], [True] * 3)
        self.assertEqual([owner_mcp.logo_as_is(one) for one in drawn], [False] * 7)


class Table(unittest.TestCase):
    """The table of the program inside the Founderizer app (`owner_mcp.py --dump-tools`, OWNER-MCP.md "The program
    inside the app"): read from the same objects that `tools()` gives, so it cannot drift from them, and the copy that
    the app's Swift tests read is this file's own output. No hub and no network."""

    FIXTURE = HERE / "app" / "Tests" / "FleetOwnerAPITests" / "Fixtures" / "owner-tools.json"
    TABLE_KINDS = ("plain", "with_base", "with_revision")
    # The commands on team.json that replace one record, new or there (the hub's create or replace): the client's
    # base goes with a change of a record that it read, and a new record, which replaces nothing, needs none. A new
    # tool of with_base is here, or its lists are `whole`, or it takes no base of the client's.
    RECORDS = ("save_chat_account", "save_mcp_server", "save_account", "save_login", "machine_access", "owner_device")

    def test_the_table_is_every_tool_with_its_own_schema_and_annotations(self):
        listed = owner_mcp.tools()
        table = owner_mcp.dump_tools()
        self.assertEqual([t["name"] for t in table["tools"]], [t["name"] for t in listed])
        for t, entry in zip(listed, table["tools"]):
            for key in ("description", "inputSchema", "annotations"):
                self.assertEqual(entry[key], t[key], f"{t['name']}.{key}")
            run = t["run"]
            if entry["kind"] in self.TABLE_KINDS:
                self.assertEqual((entry["kind"], entry["route"], tuple(entry["fields"]), entry["what"]),
                                 (run.kind, run.route, run.fields, run.what), t["name"])
                self.assertTrue(entry["route"].startswith("/ui/"), t["name"])
                self.assertEqual(entry["revision_page"] is not None, entry["kind"] == "with_revision", t["name"])
                self.assertIsInstance(entry["request_id_from_args"], bool, t["name"])
                for word in re.findall(r"\{(\w+)\}", entry["route"]):     # a path part is a property of the tool
                    self.assertIn(word, entry["inputSchema"]["properties"], f"{t['name']}: {word}")
                # with_base's `whole`, which the program inside the app reads from here (the reviews of 20 November
                # 2026): a value that is always there and that a call replaces whole goes only with the base of the
                # client's own read. Each list or record of a command on team.json is such a value, but in a tool of
                # RECORDS, whose base the client gives only for a record that is there, as for its scalar fields.
                self.assertEqual(tuple(entry["whole"]), run.whole, t["name"])
                kinds = {name: set(v["type"] if isinstance(v["type"], list) else [v["type"]])
                         for name, v in entry["inputSchema"]["properties"].items() if "type" in v}
                lists = [name for name in entry["fields"] if kinds.get(name, set()) & {"array", "object"}]
                if entry["kind"] != "with_base" or t["name"] in self.RECORDS:
                    self.assertEqual(entry["whole"], [], t["name"])
                else:
                    self.assertEqual(entry["whole"], lists, t["name"])
                takes = entry["kind"] == "with_base" and (entry["whole"] or t["name"] in self.RECORDS)
                self.assertEqual("base_sha256" in entry["inputSchema"]["properties"], bool(takes), t["name"])
                # `nulls`, which the program inside the app reads too: the fields whose schema takes null, whose
                # null goes to the hub as a value of its own.
                self.assertEqual(entry["nulls"], [name for name in entry["fields"] if "null" in kinds.get(name, ())],
                                 t["name"])
            else:
                self.assertFalse(hasattr(run, "kind"), t["name"])
                self.assertNotIn("route", entry, t["name"])
            if t["name"] in ("send_message", "steer_task"):     # attach_file's ids, in a schema that names its fields
                self.assertEqual((entry["inputSchema"]["additionalProperties"], entry["inputSchema"]["properties"].get(
                    "attachments")), (False, {"type": "array", "items": {"type": "integer"}}), t["name"])

    def test_the_kinds_are_complete_and_the_counts_are_the_plans(self):
        table = owner_mcp.dump_tools()
        kinds = {}
        for entry in table["tools"]:
            kinds.setdefault(entry["kind"], []).append(entry["name"])
        self.assertEqual(sorted(kinds["swift"]), sorted(owner_mcp.SWIFT_READS + owner_mcp.SWIFT_WRITES))
        self.assertNotIn("later", kinds)
        self.assertEqual(sorted(kinds["absent"]), sorted(owner_mcp.ABSENT))
        built = sum(1 for t in owner_mcp.tools() if getattr(t["run"], "kind", None))
        self.assertEqual(sum(len(kinds.get(k, [])) for k in self.TABLE_KINDS), built)
        self.assertEqual((len(owner_mcp.SWIFT_READS), len(owner_mcp.SWIFT_WRITES), len(owner_mcp.ABSENT), built),
                         (4, 13, 7, 58))
        # A tool of no kind stops the dump: somebody decides which it is. And a tool of no category stops the program:
        # it would stand in no line of the map, so a client with tool search would not learn of it.
        stray = owner_mcp.tool("Read", "stray", "A tool of no kind.", {}, (), lambda _args: {})
        with self.assertRaises(ValueError) as caught:
            owner_mcp.dump_tools(owner_mcp.tools() + [stray])
        self.assertIn("stray", str(caught.exception))
        with self.assertRaises(ValueError) as caught:
            owner_mcp.tool("Other", "stray", "A tool of no category.", {}, (), lambda _args: {})
        self.assertIn("stray", str(caught.exception))

    def test_each_feature_is_a_name_that_every_hub_lists_and_names_a_table_tool(self):
        table = {t["name"]: t for t in owner_mcp.dump_tools()["tools"]}
        for name, feature in owner_mcp.FEATURES.items():
            self.assertIn(feature, hub.UI_FEATURES, name)
            self.assertIn(table[name]["kind"], self.TABLE_KINDS, name)
            self.assertEqual(table[name]["feature"], feature)
        # and each field's feature (field_ready): a name that no hub lists refuses that field on every hub
        for field, feature in owner_mcp.FIELD_FEATURES.items():
            self.assertIn(feature, hub.UI_FEATURES, field)
        self.assertEqual({name: t["field_features"] for name, t in table.items() if "field_features" in t},
                         {"add_agent": {"spelling": "agent_spelling"}, "rename_agent": {"spelling": "agent_spelling"}})

    def test_the_marked_reads_are_the_reads(self):
        for t in owner_mcp.dump_tools()["tools"]:
            self.assertEqual(t["annotations"], {"readOnlyHint": t["name"] in owner_mcp.READ_ONLY}, t["name"])

    def test_the_reads_of_the_programs_call_are_the_marked_reads_that_it_has(self):
        """`founderizer-cli call` takes each tool of the table that is marked as a read and that the program has (not
        `absent`), and `write` each other tool that it has (OwnerTools.verb): the plan's four reads, and no tool that
        the table builds or that writes."""
        table = owner_mcp.dump_tools()["tools"]
        # The program's rule (OwnerTools.verb): call takes a marked read whose kind is swift, write each unmarked tool
        # that it has, and a table tool marked as a read gets no verb, so none may exist.
        reads = {t["name"] for t in table if t["annotations"]["readOnlyHint"] and t["kind"] == "swift"}
        self.assertEqual(reads, set(owner_mcp.SWIFT_READS))
        self.assertEqual([t["name"] for t in table if t["annotations"]["readOnlyHint"] and t["kind"] in self.TABLE_KINDS],
                         [])
        writes = {t["name"] for t in table if not t["annotations"]["readOnlyHint"] and t["kind"] != "absent"}
        self.assertEqual(len(writes), 58 + 13)
        self.assertTrue(set(owner_mcp.SWIFT_WRITES) <= writes)

    def test_a_lost_error_answer_says_that_the_request_can_have_arrived(self):
        """The read of an error answer's body is inside `except HTTPError`, outside the `except OSError` of the same
        `try`: an OSError there (a wait that took too long, the total time) must give the same words as the other
        path, and not an error of the protocol."""
        scratch = pathlib.Path(tempfile.mkdtemp(prefix="fleet-lost-"))
        self.addCleanup(shutil.rmtree, str(scratch), True)

        import http.client

        class Broken:
            """A body whose read breaks as `raised` says: an OSError, http.client's IncompleteRead (a chunked answer
            that closes inside a chunk) or a ValueError (a bad chunk size)."""
            closed, status, headers = False, 200, {"Content-Type": "application/json"}

            def __init__(self, raised):
                self.raised = raised

            def read(self, *_args):
                raise self.raised

            def close(self):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False
        lost = "The call to the hub at http://127.0.0.1:9 was lost: {}. The request can have arrived: read the fleet " \
               "before you send it again."
        for raised, said in ((TimeoutError("timed out"), "timed out"),
                             (http.client.IncompleteRead(b"x", 5), "the answer broke off (IncompleteRead)"),
                             (ValueError("invalid literal for int() with base 16: b'zz'"),
                              "the answer broke off (ValueError)")):
            def failing(request, timeout=None, raised=raised):     # an error answer whose body breaks
                raise urllib.error.HTTPError(request.full_url, 500, "broken", {"Content-Type": "text/plain"},
                                             Broken(raised))

            def broken(request, timeout=None, raised=raised):      # a success whose body breaks
                return Broken(raised)
            for opener in (failing, broken):
                for total in (None, owner_mcp.FILE_TOTAL):
                    with patch.object(owner_mcp.OPENER, "open", opener), patch.object(owner_mcp, "HOME", scratch), \
                            patch.object(owner_mcp, "CLIENT_FILE", scratch / "client"):
                        with self.assertRaises(owner_mcp.Refused) as caught:
                            owner_mcp.call("POST", "/ui/messages", body={"text": "x"}, base="http://127.0.0.1:9",
                                           total=total)
                    self.assertEqual(str(caught.exception), lost.format(said), (said, opener.__name__, total))

    def test_a_snapshot_larger_than_a_call_is_still_read(self):
        """19 November 2026: a fleet's whole snapshot (/ui/state) passed READ_MAX, and each tool refused at its first
        read, the one of the hub's generation: "The hub's answer is larger than this server reads." The snapshot is
        an answer that holds a fleet's whole history, so it has a limit of its own; every other answer keeps
        READ_MAX."""
        scratch = pathlib.Path(tempfile.mkdtemp(prefix="fleet-state-"))
        self.addCleanup(shutil.rmtree, str(scratch), True)
        big = json.dumps({"db": "g1", "pad": "a" * owner_mcp.READ_MAX}).encode()

        class Body(io.BytesIO):
            status, headers = 200, {"Content-Type": "application/json"}

        def opened(request, timeout=None):
            return Body(big)
        with patch.object(owner_mcp.OPENER, "open", opened), patch.object(owner_mcp, "HOME", scratch), \
                patch.object(owner_mcp, "CLIENT_FILE", scratch / "client"):
            for path in ("/ui/state", "/ui/state?since=7", owner_mcp.STATE_READ, owner_mcp.STATE_HEAD):
                self.assertEqual(owner_mcp.call("GET", path, base="http://127.0.0.1:9").data["db"], "g1", path)
            with self.assertRaises(owner_mcp.Refused) as caught:
                owner_mcp.call("GET", "/ui/health", base="http://127.0.0.1:9")
        # The refusal says what to do (point 6 of the review of 20 November 2026): it said only that it was too large.
        # A command's answer can come after its work, and a page can be read in smaller parts.
        self.assertEqual(str(caught.exception), "The hub's answer is larger than this server reads, so it was not read.")
        with patch.object(owner_mcp.OPENER, "open", opened), patch.object(owner_mcp, "HOME", scratch), \
                patch.object(owner_mcp, "CLIENT_FILE", scratch / "client"):
            with self.assertRaises(owner_mcp.Refused) as sent:
                owner_mcp.call("POST", "/ui/servers/join", {"kind": "linux"}, base="http://127.0.0.1:9")
            with patch.dict(os.environ, {"FOUNDERIZER_HUB": "http://127.0.0.1:9"}), self.assertRaises(owner_mcp.Refused) as page:
                owner_mcp.read_page({"page": "health"})
        self.assertEqual(str(sent.exception), "The hub's answer is larger than this server reads, so it was not read. "
                                              "The request can have arrived: read the fleet before you send it again.")
        self.assertEqual(str(page.exception), "The hub's answer is larger than this server reads, so it was not read. "
                                              "Read less at a time: one item by its id, or a page with a word that "
                                              "narrows it.")

    def test_a_file_from_the_hub_is_new_and_follows_no_link(self):
        """write_here with the agent's folder: an exclusive create, which leaves a file, a link and its target as they
        are; with the agent's own file path it replaces that file."""
        scratch = pathlib.Path(tempfile.mkdtemp(prefix="fleet-new-"))
        self.addCleanup(shutil.rmtree, str(scratch), True)
        (scratch / "target").write_text("keep me")
        (scratch / "dl").mkdir()
        os.symlink(scratch / "target", scratch / "dl" / "a.txt")
        with self.assertRaises(owner_mcp.Refused) as caught:
            owner_mcp.write_here(scratch / "dl" / "a.txt", b"new", scratch / "dl")
        self.assertEqual(str(caught.exception), f"a.txt is there already in {scratch / 'dl'}, so nothing was written. "
                         "Name the file itself in path to replace it, or name another folder.")
        self.assertEqual((scratch / "target").read_text(), "keep me")
        owner_mcp.write_here(scratch / "target", b"replaced")
        self.assertEqual((scratch / "target").read_text(), "replaced")

    def test_the_media_types_are_the_hubs_own(self):
        """MEDIA_TYPES, which both programs read, gives only types that the hub takes, each of them, and each with the
        ending that the hub gives it: its own types and, since owner API 1.251, Word, Excel and PowerPoint."""
        self.assertEqual(set(owner_mcp.MEDIA_TYPES.values()), set(hub.ATTACH_TYPES) | set(hub.ATTACH_OFFICE))
        endings = {**{mime: ending for mime, (ending, _magic) in hub.ATTACH_TYPES.items()}, **hub.ATTACH_OFFICE}
        for mime, ending in endings.items():
            self.assertEqual(owner_mcp.MEDIA_TYPES[ending.lstrip(".")], mime)
        self.assertEqual(owner_mcp.dump_tools()["MEDIA_TYPES"], owner_mcp.MEDIA_TYPES)
        for name, mime in (("a.PNG", "image/png"), (".png", "application/octet-stream"), ("a..jpg", "image/jpeg"),
                           ("noext", "application/octet-stream"), ("a.exe", "application/octet-stream"),
                           ("Plan.DOCX", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")):
            self.assertEqual(owner_mcp.media_type(name), mime, name)

    @needs_the_apps
    def test_the_dump_prints_the_table_and_the_apps_copy_is_that_print(self):
        """`--dump-tools` is what release.sh and run.sh put in the app, and the Swift tests read a committed copy of
        it: when this fails, write the copy again with `python3 owner_mcp.py --dump-tools > <the fixture>`."""
        printed = subprocess.run([sys.executable, "-B", str(HERE / "owner_mcp.py"), "--dump-tools"], cwd=str(HERE),
                                 capture_output=True, text=True, timeout=60, check=True).stdout
        self.assertEqual(json.loads(printed), owner_mcp.dump_tools())
        table = json.loads(printed)
        rest = {k: v for k, v in table.items() if k != "version"}
        self.assertEqual(table["version"], hashlib.sha256(
            json.dumps(rest, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
        self.assertEqual(self.FIXTURE.read_text(), printed, "the Swift tests' copy of the table is not the table")

    def test_a_path_part_from_an_argument_is_escaped(self):
        sent = []
        with patch.object(owner_mcp, "generation", lambda fresh=False: "g1"), \
                patch.object(owner_mcp, "call", lambda method, path, body=None, **kw: (
                    sent.append((method, path, body)), owner_mcp.Answer(200, {"ok": True}, b"", {}))[1]), \
                patch.object(owner_mcp, "HOME", pathlib.Path(tempfile.mkdtemp(prefix="fleet-table-"))) as home:
            self.addCleanup(shutil.rmtree, str(home), True)
            run = {t["name"]: t["run"] for t in owner_mcp.tools()}
            run["check_machine"]({"agent": "a/b?c%d"})
            run["link_chat_app"]({"account": "wa 1", "action": "link"})
        self.assertEqual([path for _m, path, _b in sent],
                         ["/ui/machines/a%2Fb%3Fc%25d/check", "/ui/chat-apps/wa%201/link"])
        self.assertEqual(owner_mcp.route_for("/ui/tasks/{task}/control", {"task": 7}), "/ui/tasks/7/control")

    def test_a_command_holds_the_lock_for_its_one_request_and_a_read_never_does(self):
        scratch = pathlib.Path(tempfile.mkdtemp(prefix="fleet-lock-"))
        self.addCleanup(shutil.rmtree, str(scratch), True)
        home, held = scratch / ".founderizer", []

        def taken():
            import fcntl
            with open(home / "lock", "a") as other:
                try:
                    fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    return True
                fcntl.flock(other, fcntl.LOCK_UN)
                return False

        def call(method, path, body=None, **_kw):
            held.append((method, (home / "lock").exists() and taken()))
            data = {"db": "g1"} if path == owner_mcp.STATE_HEAD else {"ok": True}
            return owner_mcp.Answer(200, data, b"", {})
        owner_mcp.GENERATION["db"] = None
        with patch.object(owner_mcp, "call", call), patch.object(owner_mcp, "HOME", home):
            owner_mcp.command("/ui/releases/check", {}, "the release check")
            owner_mcp.get("/ui/health", "health")
        owner_mcp.GENERATION["db"] = None
        self.assertEqual(held, [("GET", False), ("POST", True), ("GET", False)])
        self.assertEqual(stat.S_IMODE(home.stat().st_mode) & 0o077, 0)

    def test_a_field_that_an_older_hub_would_drop_is_refused_before_any_command(self):
        """The spelling of a name (owner feature agent_spelling): a hub from before it drops the field from Add agent
        with a 200 and no word, so the tool says so first, in plain words, and sends nothing. The hub's features come
        with the read of its generation, read again once before a refusal. Bugs: the tool sends the add, and the agent
        shows the name with a capital where the owner typed another spelling; or a hub that took the release while
        this server ran is still refused."""
        sent, features = [], [[], []]

        def call(method, path, body=None, **_kw):
            sent.append((method, path))
            if path == owner_mcp.STATE_HEAD:
                return owner_mcp.Answer(200, {"db": "g1", "ui_features": features.pop(0)}, b"", {})
            return owner_mcp.Answer(200, {"ok": True}, b"", {})
        add = {t["name"]: t for t in owner_mcp.tools()}["add_agent"]["run"]
        args = {"server": "mini", "agent": "scout", "runtime": "claude", "role": "worker", "spelling": "ScOut",
                "base_sha256": "0" * 64}
        owner_mcp.GENERATION.update(db=None, features=None)
        with patch.object(owner_mcp, "call", call), \
                patch.object(owner_mcp, "HOME", pathlib.Path(tempfile.mkdtemp(prefix="fleet-field-"))) as home:
            self.addCleanup(shutil.rmtree, str(home), True)
            with self.assertRaises(owner_mcp.Refused) as caught:
                add(args)
            self.assertIn("This hub keeps no spelling of an agent's name yet", str(caught.exception))
            self.assertEqual(sent, [("GET", owner_mcp.STATE_HEAD)] * 2)       # read again once, and no command
            features[:] = [["agent_spelling"]]                                 # the hub took the release
            self.assertEqual(add(args), {"ok": True})
        owner_mcp.GENERATION.update(db=None, features=None)
        self.assertEqual([m for m, _ in sent], ["GET", "GET", "GET", "POST"])

    def test_a_folder_that_cannot_lock_sends_the_command_with_no_lock(self):
        scratch = pathlib.Path(tempfile.mkdtemp(prefix="fleet-nolock-"))
        self.addCleanup(shutil.rmtree, str(scratch), True)
        sent = []

        def flock(_handle, _how):
            raise OSError(45, "Operation not supported")          # EOPNOTSUPP, as on a network folder

        def call(method, path, body=None, **_kw):
            sent.append(method)
            return owner_mcp.Answer(200, {"db": "g1"} if path == owner_mcp.STATE_HEAD else {"ok": True}, b"", {})
        owner_mcp.GENERATION["db"] = None
        with patch.object(owner_mcp, "call", call), patch.object(owner_mcp, "HOME", scratch / ".founderizer"), \
                patch.object(owner_mcp.fcntl, "flock", flock):
            self.assertEqual(owner_mcp.command("/ui/releases/check", {}, "the release check"), {"ok": True})
        owner_mcp.GENERATION["db"] = None
        self.assertEqual(sent, ["GET", "POST"])

    def test_a_command_with_a_client_of_its_own_sends_that_label_and_each_other_header_as_before(self):
        """command(..., client=...): the release job sends its own X-Fleet-Client through this module (owner API
        1.325), so that the hub gives its message the hand job and no bubble of the owner's. Bugs: the installation's
        label still goes (the client is not passed on, or the label is set after it), or the job's request loses the
        session, the content type or another header that the hub reads."""
        scratch = pathlib.Path(tempfile.mkdtemp(prefix="fleet-client-"))
        self.addCleanup(shutil.rmtree, str(scratch), True)
        sent = []

        class Body(io.BytesIO):
            status, headers = 200, {"Content-Type": "application/json"}

        def opened(request, timeout=None):
            sent.append((request.get_method(), dict(request.header_items())))
            return Body(json.dumps({"db": "g1", "ok": True}).encode())
        owner_mcp.GENERATION["db"] = None
        self.addCleanup(owner_mcp.GENERATION.update, db=None)
        with patch.object(owner_mcp.OPENER, "open", opened), patch.object(owner_mcp, "HOME", scratch), \
                patch.object(owner_mcp, "CLIENT_FILE", scratch / "client"), \
                patch.dict(os.environ, {"FOUNDERIZER_HUB": "http://127.0.0.1:9", "CLAUDE_CODE_SESSION_ID": "0d8aa41c"}):
            owner_mcp.command("/ui/messages", {"text": "Customers wait."}, "the message")
            owner_mcp.command("/ui/messages", {"text": "Customers wait."}, "the message",
                              client="founderizer-release/1/test")
            label = owner_mcp.client_label()
        own, job = [headers for method, headers in sent if method == "POST"]
        self.assertTrue(label.startswith("founderizer-mcp/"), label)
        self.assertEqual((own["X-fleet-client"], own["X-fleet-session"]), (label, "claude-code/0d8aa41c"))
        self.assertEqual(job, dict(own, **{"X-fleet-client": "founderizer-release/1/test"}))

    def test_attach_file_takes_the_lock_for_its_upload(self):
        scratch = pathlib.Path(tempfile.mkdtemp(prefix="fleet-attach-lock-"))
        self.addCleanup(shutil.rmtree, str(scratch), True)
        home, held = scratch / ".founderizer", []
        (scratch / "note.txt").write_text("hello")

        def call(method, path, body=None, **_kw):
            import fcntl
            locked = False
            if (home / "lock").exists():
                with open(home / "lock", "a") as other:
                    try:
                        fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.flock(other, fcntl.LOCK_UN)
                    except BlockingIOError:
                        locked = True
            held.append((method, path.split("?")[0], locked))
            return owner_mcp.Answer(200, {"db": "g1"} if path == owner_mcp.STATE_HEAD else {"attachment": 1}, b"", {})
        owner_mcp.GENERATION["db"] = None
        with patch.object(owner_mcp, "call", call), patch.object(owner_mcp, "HOME", home):
            owner_mcp.attach_file({"path": str(scratch / "note.txt")})
        owner_mcp.GENERATION["db"] = None
        self.assertEqual(held, [("GET", "/ui/state", False), ("POST", "/ui/attachments", True)])

    def test_a_path_part_that_is_a_dot_or_two_is_refused_before_any_request(self):
        words = 'agent cannot be "..": a part of a route is never "." or "..".'
        with patch.object(owner_mcp, "call", lambda *a, **k: self.fail("a request was made")):
            run = {t["name"]: t["run"] for t in owner_mcp.tools()}
            for tool, args in (("check_machine", {"agent": ".."}), ("save_profile", {"agent": "..", "sections": []}),
                               ("fleet_read", {"page": "notes", "agent": ".."})):
                with self.assertRaises(owner_mcp.Refused) as caught:
                    run[tool](args)
                self.assertEqual(str(caught.exception), words, tool)
            with self.assertRaises(owner_mcp.Refused) as caught:
                owner_mcp.route_for("/ui/chat-apps/{account}/{action}", {"account": ".", "action": "link"})
            self.assertEqual(str(caught.exception), 'account cannot be ".": a part of a route is never "." or "..".')
        self.assertEqual(owner_mcp.route_for("/ui/tasks/{task}/control", {"task": 7, "note": ".."}),
                         "/ui/tasks/7/control")

    def test_a_whole_value_with_no_base_of_the_clients_own_read_is_refused_before_any_request(self):
        """A field that replaces a whole value that is always there (with_base's `whole`) and a profile's sections go
        only with the base of the read that the client made them from: a base that the tool read at the time of the
        write would hold the change that must not be lost. For team.json a null base is no base; for a profile null is
        the base of an agent with no profile yet, so it goes to the hub."""
        run = {t["name"]: t["run"] for t in owner_mcp.tools()}
        with patch.object(owner_mcp, "call", lambda *a, **k: self.fail("a request was made")):
            for tool, args, named in (("set_reporting_lines", {"lines": []}, ["lines"]),
                                      ("agent_settings", {"agent": "a", "model": "m", "can": ["web"]}, ["can"]),
                                      ("agent_settings", {"agent": "a", "expertise": [], "screen": {}},
                                       ["expertise", "screen"]),
                                      ("agent_settings", {"agent": "a", "web_hosts": [], "base_sha256": None},
                                       ["web_hosts"])):
                with self.assertRaises(owner_mcp.Refused) as caught:
                    run[tool](args)
                self.assertEqual(str(caught.exception), owner_mcp.team_base_needed(named), tool)
            with self.assertRaises(owner_mcp.Refused) as caught:
                run["save_profile"]({"agent": "a", "sections": []})
            self.assertEqual(str(caught.exception), owner_mcp.PROFILE_BASE_NEEDED)
        sent = []
        page = owner_mcp.Answer(200, {"profiles": [{"agent": "a"}]}, b"", {})
        with patch.object(owner_mcp, "get", lambda *a: page), \
                patch.object(owner_mcp, "command", lambda route, body, *a: sent.append((route, body))):
            run["save_profile"]({"agent": "a", "sections": [], "base_sha256": None})
        self.assertEqual(sent, [("/ui/profiles/a", {"sections": [], "base_sha256": None})])
        # A record, new or there, goes with the client's base when it gives one, else with the tool's own read.
        sent.clear()
        with patch.object(owner_mcp, "team", lambda: {"sha256": "read-here"}), \
                patch.object(owner_mcp, "command", lambda route, body, *a: sent.append((route, body["base_sha256"]))):
            run["save_mcp_server"]({"name": "x", "server": {"title": "X"}})
            run["save_mcp_server"]({"name": "x", "server": {"title": "X"}, "base_sha256": "the-clients"})
        self.assertEqual(sent, [("/ui/team/mcp", "read-here"), ("/ui/team/mcp", "the-clients")])

    def test_a_grant_goes_with_the_base_of_the_read_that_its_map_is_made_from(self):
        """grant_access takes the team's holds of a repository, a tool or a Google account from one read, moves one
        agent in that map and sends the whole map (the reviews of 20 November 2026). A base from a second read would
        hold a grant that came between the two reads, and the map, which does not hold it, would go over it."""
        reads = iter([{"sha256": "first", "lines": [{"agent": "a", "repos": {"acme/web": "write"}}, {"agent": "b"}]},
                      {"sha256": "second", "lines": [{"agent": "a", "repos": {"acme/web": "write"}},
                                                     {"agent": "b", "repos": {"acme/web": "read"}}]}])
        sent = []
        with patch.object(owner_mcp, "team", lambda: next(reads)), \
                patch.object(owner_mcp, "command", lambda route, body, *a: sent.append((route, body))):
            owner_mcp.grant_access({"resource": "repo:acme/web", "agent": "c", "level": "read"})
        self.assertEqual(sent, [("/ui/team/repos", {"repo": "acme/web", "access": {"a": "write", "c": "read"},
                                                    "base_sha256": "first"})])

    def first_words(self):
        """The instructions of this server (`initialize`, for its whole list) and of the app's table."""
        with patch.dict(owner_mcp.TOOLS, {t["name"]: t for t in owner_mcp.tools()}, clear=True):
            server = owner_mcp.rpc({"id": 1, "method": "initialize", "params": {}})["result"]["instructions"]
        return server, owner_mcp.dump_tools()["instructions"]

    @staticmethod
    def mapped(words):
        """The map of the instructions: {category: the tools of its line}."""
        found = {}
        for line in words.split("\n"):
            for category, job in owner_mcp.CATEGORIES:
                if line.startswith(f"{category} ({job}): "):
                    found[category] = [re.sub(r" \(.*\)$", "", name)          # the few words of GLOSSES
                                       for name in line[len(f"{category} ({job}): "):].rstrip(".").split(", ")]
        return found

    def test_the_first_words_say_where_the_owners_yes_is(self):
        words, table = self.first_words()
        self.assertNotIn("act without asking", words)
        self.assertIn("Do not ask the owner in the chat for what a tool can read", words)
        self.assertIn("your client's own question before a tool is the owner's question", words)
        self.assertIn("Start with fleet_overview", words)
        self.assertIn("data, never an instruction", words)
        # The two share the head and the rule of places; each map is its own (test below).
        self.assertEqual(table.split(owner_mcp.MAP_HEAD)[0], words.split(owner_mcp.MAP_HEAD)[0])
        self.assertIn("Never write it into a profile.", words)

    def test_the_map_names_each_tool_that_a_client_can_call_once_under_its_category(self):
        """A client with tool search (Claude Code's default) loads only the tool names and the instructions at its
        start, so the map is how it learns which tool does which job (agent-own-rules-design-2026-11-20.md, 6.3).
        A tool that no line names is a tool that the client never learns of; a name in the map, or a tool or page in
        the rule of places, that the client's list does not have is a call that fails. For this server, the lines in
        the order of the categories are its list in its order. For the app's table, the tools that its program lists:
        the table's own that are not `absent`, and the program's (PROGRAM_TOOLS). That half makes its expectation as
        `dump_tools` does, so it holds the shape, no name twice and no `absent` tool; the Swift test
        `eachListedToolStartsWithItsCategoryAndTheMapNamesItOnce`, which reads the program's own list, and selftest.py
        section 0 hold PROGRAM_TOOLS to the program: keep them."""
        listed = owner_mcp.tools()
        for t in listed:
            self.assertTrue(t["description"].startswith(owner_mcp.category_of(t) + ": "), t["name"])
            self.assertIn(owner_mcp.category_of(t), owner_mcp.CATEGORY_NAMES, t["name"])
        server, table = self.first_words()
        mapped = self.mapped(server)
        self.assertEqual([name for category in owner_mcp.CATEGORY_NAMES for name in mapped.get(category, [])],
                         [t["name"] for t in listed])
        for t in listed:
            self.assertIn(t["name"], mapped[owner_mcp.category_of(t)], t["name"])
        programs = owner_mcp.dump_tools()["tools"]
        expected = {}
        for of, name in owner_mcp.categorized(e for e in programs if e["kind"] != "absent") + \
                list(owner_mcp.PROGRAM_TOOLS):
            expected.setdefault(of, []).append(name)
        mapped = self.mapped(table)
        self.assertEqual(mapped, expected)
        names = [name for line in mapped.values() for name in line]
        self.assertEqual(len(names), len(set(names)))
        self.assertNotIn("add_machine", names)                       # absent: the app's own Add server does it
        # **No words of the app's table name a tool that its program does not have** (F3, piece 1, 22 November 2026:
        # add_agent sent an agent of the program to add_machine). Read here: a tool's own words and the words of its
        # fields. Whole words only, so a field such as authkey_file does not count.
        absent = {e["name"] for e in programs if e["kind"] == "absent"}
        for entry in programs:
            if entry["kind"] != "absent":
                words = entry["description"] + " " + json.dumps(entry["inputSchema"])
                named = set(re.findall(r"\b[a-z]+(?:_[a-z]+)+\b", words)) & absent
                self.assertEqual(named, set(), entry["name"])
        self.assertEqual(owner_mcp.dump_tools()["categories"], [list(c) for c in owner_mcp.CATEGORIES])
        for words, callable_ in ((server, {t["name"] for t in listed}), (table, set(names))):
            # and the pages of fleet_read, which a line of the rule of places names too (F15: profile_orders)
            self.assertLessEqual(set(re.findall(r"\b[a-z]+(?:_[a-z]+)+\b", words)), callable_ | set(owner_mcp.PAGES))
            shown = re.search(r"read with fleet_read: ([^.]*)\.", words).group(1).replace(" and ", ", ").split(", ")
            self.assertLessEqual(set(shown), set(owner_mcp.PAGES), shown)

    def test_the_instructions_fit_a_clients_cut_and_the_rule_of_places_comes_first(self):
        """Claude Code cuts a server's instructions at 4,096 characters, and before its version 2.1.296 at 2,048: a
        later line that pushes the rule of places past that cut leaves it unread, and a client then writes the owner's
        "from now on" into a profile again."""
        for words in self.first_words():
            self.assertLessEqual(len(words), 4096)
            self.assertLess(words.index(owner_mcp.MAP_HEAD), 2048)
            self.assertLess(words.index("Where a rule for an agent goes:"), words.index(owner_mcp.MAP_HEAD))

    def test_the_devices_page_says_that_it_gives_no_code(self):
        what = owner_mcp.PAGES["devices"][1]
        self.assertNotIn("their open enrollment codes", what)
        self.assertIn("never a code", what)


class FolderGrant(unittest.TestCase):
    """grant_access with a folder (owner API 1.255, the owner's "Yes, as drawn" of 20 November 2026 to Drive access to
    some folders only): the owner's own MCP gives one folder of a Drive account, as his app does."""

    def test_a_folder_grant_moves_only_the_named_agent_of_that_folder(self):
        """Bug: the folder's other agents lose it, another folder's agents are read for it, the grant writes the
        account's whole Drive in place of the folder, or its base is a second read of the team, so an agent given the
        folder between the two reads loses it."""
        page = {"sha256": "page-sha", "resources": [{"id": "drive:ada@example.com", "folders": [
            {"id": "Abc-Folder_01", "holders": [{"agent": "ops", "level": "read"}]},
            {"id": "Other-Fold-02", "holders": [{"agent": "boss", "level": "write"}]}]}]}
        sent, link = [], "https://drive.google.com/drive/folders/Abc-Folder_01?usp=sharing"
        with patch.object(owner_mcp, "get", lambda route, what, *a, **q: types.SimpleNamespace(data=page)), \
                patch.object(owner_mcp, "team", lambda: {"sha256": "a second read, which the grant must not take"}), \
                patch.object(owner_mcp, "command",
                                  lambda route, body, what, request_id=None, **k: sent.append((route, body)) or {}):
            owner_mcp.grant_access({"resource": "drive:Ada@example.com", "agent": "dev", "level": "write",
                                    "folder": f" {link} "})
            owner_mcp.grant_access({"resource": "drive:ada@example.com", "agent": "ops", "level": None,
                                    "folder": "Abc-Folder_01"})
        self.assertEqual(sent, [
            ("/ui/team/google", {"account": "Ada@example.com", "service": "drive", "folder": link,
                                 "access": {"ops": "read", "dev": "write"}, "base_sha256": "page-sha"}),
            ("/ui/team/google", {"account": "ada@example.com", "service": "drive", "folder": "Abc-Folder_01",
                                 "access": {}, "base_sha256": "page-sha"})])
        for rid, folder in (("gmail:ada@example.com", "Abc-Folder_01"), ("drive:ada@example.com", " ")):
            with self.assertRaisesRegex(owner_mcp.Refused, "folder goes with drive:<email> only"):
                owner_mcp.grant_access({"resource": rid, "agent": "dev", "level": "read", "folder": folder})


class GoogleConnect(unittest.TestCase):
    """`connect_google` (UI-API.md 1.185): the app's Connect, from the admin MCP. A stand-in hub answers its two
    commands, and a stand-in browser follows Google's redirect to the tool's own listener on 127.0.0.1. No hub, no
    Google and no real browser."""

    STATE, CODE = "state-" + "s" * 37, "4/0Acode-" + "c" * 30
    URL = "https://accounts.google.com/o/oauth2/v2/auth?client_id=456-x.apps.googleusercontent.com&state=" + "s" * 43

    def connect(self, args, redirects=None, url=URL, early=False, dropped=(), mac=True):
        """(the tool's result or its Refused, the commands it sent, the pages it opened, the browser's answers).
        early: a program of the Mac calls the listener before the hub's answer. dropped: what the finish says. mac:
        whether the computer that the tool runs on is a Mac, whatever system runs the test: its platform, which the
        tool's own check (on_a_mac) reads."""
        sent, opened, answers = [], [], []
        self.waits = {}

        def command(route, body, what, request_id=None, timeout=None):
            sent.append((route, dict(body)))
            self.waits[route] = timeout
            if route == "/ui/google/connect":
                if early:
                    get(body["redirect_uri"], "", {"state": "x", "code": "y"})
                return {"url": url, "state": self.STATE, "expires_at": 1, "app": "founderizer", "verified": False}
            return {"email": "ana@example.com", "scopes": ["gmail.modify"], "connected": True, "replaced": True,
                    "dropped": list(dropped)}

        def get(where, path, query):
            try:
                with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
                        where + path + "?" + urllib.parse.urlencode(query), timeout=10) as r:
                    answers.append((r.status, r.read().decode()))
            except urllib.error.HTTPError as e:
                answers.append((e.code, e.read().decode()))

        def browser(address):
            opened.append(address)
            for path, query in redirects or [("", {"state": self.STATE, "code": self.CODE})]:
                get(sent[0][1]["redirect_uri"], path, query)

        with patch.object(owner_mcp, "command", command), patch.object(owner_mcp, "open_in_browser", browser), \
                patch.object(owner_mcp.sys, "platform", "darwin" if mac else "linux"):
            try:
                result = owner_mcp.connect_google(args)
            except owner_mcp.Refused as e:
                result = e
        return result, sent, opened, answers

    def test_it_connects_through_the_hub_and_gives_back_no_code_and_no_state(self):
        with contextlib.redirect_stderr(io.StringIO()) as said:     # the MCP client can log the server's stderr
            result, sent, opened, answers = self.connect({"service": "gmail"})
        self.assertNotIn(self.CODE, said.getvalue())
        self.assertNotIn(self.STATE, said.getvalue())
        self.assertEqual((result["dropped"], self.waits["/ui/google/finish"]), ([], owner_mcp.GOOGLE_FINISH_WAIT))
        self.assertEqual((result["email"], result["scopes"], result["replaced"]), ("ana@example.com", ["gmail.modify"],
                                                                                   True))
        self.assertIn("grant_access", result["next"])
        self.assertIn("gmail:ana@example.com", result["next"])
        (route, body), (route2, body2) = sent
        self.assertEqual((route, set(body), body["service"]),
                         ("/ui/google/connect", {"redirect_uri", "service"}, "gmail"))
        port = int(re.fullmatch(r"http://127\.0\.0\.1:(\d+)/", body["redirect_uri"]).group(1))
        self.assertTrue(1024 <= port <= 65535, port)
        self.assertEqual((route2, body2), ("/ui/google/finish", {"state": self.STATE, "code": self.CODE}))
        self.assertEqual(opened, [self.URL])
        self.assertEqual(answers, [(200, answers[0][1])])
        self.assertIn("Founderizer is connected. You can close this tab.", answers[0][1])
        for value in (self.CODE, self.STATE):
            self.assertNotIn(value, json.dumps(result))
        with self.assertRaises(OSError):                     # the listener is gone once the Connect ended
            socket.create_connection(("127.0.0.1", port), timeout=2).close()
        # An account to connect again: its email in lower case, as Google's login hint; Drive is a Connect of its own.
        result, sent, _, _ = self.connect({"service": "drive", "account": " Ana@Example.com "})
        self.assertEqual({k: sent[0][1][k] for k in ("service", "account")}, {"service": "drive",
                                                                             "account": "ana@example.com"})
        self.assertIn("Google Drive", result["next"])

    def test_the_finish_has_its_own_wait_down_to_the_hubs_request(self):
        """The hub's finish calls Google up to three times, so it waits longer than a command's usual wait: the real
        command gives that wait to the request itself (the other tests here stand in for command)."""
        scratch = pathlib.Path(tempfile.mkdtemp(prefix="fleet-google-wait-"))
        self.addCleanup(shutil.rmtree, str(scratch), True)
        waits, sent = {}, {}

        def call(method, path, body=None, timeout=owner_mcp.TIMEOUT, **_kw):
            waits[path], sent[path] = timeout, body
            if path == owner_mcp.STATE_HEAD:
                return owner_mcp.Answer(200, {"db": "g1"}, b"", {})
            if path == "/ui/google/connect":
                return owner_mcp.Answer(200, {"url": self.URL, "state": self.STATE, "expires_at": 1,
                                              "app": "founderizer", "verified": False}, b"", {})
            return owner_mcp.Answer(200, {"email": "ana@example.com", "scopes": ["gmail.modify"], "connected": True,
                                          "replaced": False, "dropped": []}, b"", {})

        def browser(_address):
            where = sent["/ui/google/connect"]["redirect_uri"] + "?" + urllib.parse.urlencode(
                {"state": self.STATE, "code": self.CODE})
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(where, timeout=10) as r:
                r.read()
        owner_mcp.GENERATION["db"] = None
        self.addCleanup(owner_mcp.GENERATION.update, db=None)
        with patch.object(owner_mcp, "call", call), patch.object(owner_mcp, "HOME", scratch / ".founderizer"), \
                patch.object(owner_mcp, "on_a_mac", lambda: True), patch.object(owner_mcp, "open_in_browser", browser):
            result = owner_mcp.connect_google({"service": "gmail"})
        self.assertEqual(result["email"], "ana@example.com")
        self.assertEqual((waits["/ui/google/connect"], waits["/ui/google/finish"]),
                         (owner_mcp.TIMEOUT, owner_mcp.GOOGLE_FINISH_WAIT))
        self.assertGreater(owner_mcp.GOOGLE_FINISH_WAIT, owner_mcp.TIMEOUT)

    def test_another_request_waits_on_and_a_wrong_state_or_googles_error_connects_nothing(self):
        result, sent, _, answers = self.connect({"service": "gmail"}, redirects=[
            ("favicon.ico", {}), ("", {"state": self.STATE}), ("", {"state": self.STATE, "code": self.CODE})])
        self.assertEqual([a[0] for a in answers], [404, 404, 200])
        self.assertEqual(result["email"], "ana@example.com")
        result, sent, _, answers = self.connect({"service": "gmail"}, redirects=[("", {"state": "other", "code": "x"})])
        self.assertIsInstance(result, owner_mcp.Refused)
        self.assertIn("not for this Connect", str(result))
        self.assertEqual(([r for r, _ in sent], answers[0][0]), (["/ui/google/connect"], 400))
        result, sent, _, answers = self.connect({"service": "gmail"}, redirects=[
            ("", {"state": self.STATE, "error": "access_denied<script>"})])
        self.assertIn("The access was not given (access_deniedscript)", str(result))
        self.assertIn("access_deniedscript", answers[0][1])
        self.assertNotIn("<script>", answers[0][1])
        self.assertEqual([r for r, _ in sent], ["/ui/google/connect"])

    def test_it_opens_only_a_consent_page_of_google_and_takes_one_service(self):
        for url in ("https://accounts.google.com.example.com/x", "http://accounts.google.com/o/oauth2/v2/auth",
                    "https://example.com/?https://accounts.google.com/", None):
            with self.subTest(url=url):
                result, sent, opened, _ = self.connect({"service": "gmail"}, url=url)
                self.assertIsInstance(result, owner_mcp.Refused)
                self.assertEqual((opened, [r for r, _ in sent]), ([], ["/ui/google/connect"]))
        for args in ({}, {"service": "calendar"}, {"service": "gmail", "account": ""},
                     {"service": "drive", "account": 7}):
            with self.subTest(args=args):
                result, sent, opened, _ = self.connect(args)
                self.assertIsInstance(result, owner_mcp.Refused)
                self.assertEqual((sent, opened), ([], []))

    def test_it_sends_nothing_off_a_mac_or_after_an_early_call_and_says_what_was_dropped(self):
        result, sent, opened, _ = self.connect({"service": "gmail"}, mac=False)
        self.assertIsInstance(result, owner_mcp.Refused)
        self.assertEqual((sent, opened), ([], []))          # the app's waiting Connect is not replaced
        result, sent, opened, answers = self.connect({"service": "gmail"}, early=True)
        self.assertIsInstance(result, owner_mcp.Refused)
        self.assertIn("before Google's page opened", str(result))
        self.assertEqual(([r for r, _ in sent], opened, answers[0][0]), (["/ui/google/connect"], [], 400))
        result, _, _, _ = self.connect({"service": "gmail"}, dropped=["drive"])
        self.assertEqual(result["dropped"], ["drive"])
        self.assertIn("Its drive stopped with this Connect", result["next"])
        # A request that sends nothing holds no other: each has its own thread and 10 seconds, and the port is new.
        self.assertTrue(owner_mcp.GoogleLoopback.daemon_threads)
        self.assertFalse(owner_mcp.GoogleLoopback.block_on_close)
        self.assertFalse(owner_mcp.GoogleLoopback.allow_reuse_address)
        self.assertEqual(owner_mcp.GoogleLoopback.Page.timeout, 10)
        loop = owner_mcp.GoogleLoopback()
        try:
            loop.state = self.STATE
            idle = socket.create_connection(("127.0.0.1", loop.server_address[1]), timeout=5)     # sends nothing
            self.addCleanup(idle.close)
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
                    loop.redirect_uri + "?" + urllib.parse.urlencode({"state": self.STATE, "code": self.CODE}),
                    timeout=10) as r:
                self.assertEqual(r.status, 200)
            self.assertEqual(loop.code(limit=5), self.CODE)
        finally:
            loop.close()

    def test_no_answer_within_the_time_limit_connects_nothing(self):
        loop = owner_mcp.GoogleLoopback()
        try:
            loop.state = self.STATE
            with self.assertRaises(owner_mcp.Refused) as caught:
                loop.code(limit=0)
            self.assertIn("within 10 minutes", str(caught.exception))
        finally:
            loop.close()

    def test_the_tool_takes_no_code_and_no_secret_and_the_programs_copy_is_absent(self):
        tool = next(t for t in owner_mcp.tools() if t["name"] == "connect_google")
        self.assertEqual((set(tool["inputSchema"]["properties"]), tool["inputSchema"]["required"]),
                         ({"service", "account"}, ["service"]))
        self.assertFalse(tool["annotations"]["readOnlyHint"])
        self.assertIn("Advanced, then Go to Founderizer", tool["description"])
        self.assertIn("connect_google", owner_mcp.ABSENT)
        entry = next(t for t in owner_mcp.dump_tools()["tools"] if t["name"] == "connect_google")
        self.assertEqual(entry["kind"], "absent")
        self.assertNotIn("/ui/google/connect", owner_mcp.NOT_TOOLS)
        self.assertNotIn("/ui/google/finish", owner_mcp.NOT_TOOLS)

    @needs_the_apps
    def test_the_description_says_the_apps_notice_before_googles_page(self):
        """The notice before Google's page (the owner's "Yes, both as drawn" of 16 November 2026), which Google's policy
        asks for before each consent: the owner's agent says it before the call, word for word as the app shows it
        (`GoogleService.notice` in FleetCore), because the tool's answer comes only after Google's page."""
        tool = next(t for t in owner_mcp.tools() if t["name"] == "connect_google")
        swift = (HERE / "app" / "Sources" / "FleetCore" / "Google.swift").read_text()
        self.assertEqual(set(owner_mcp.GOOGLE_NOTICE), set(owner_mcp.GOOGLE_SERVICES))
        for service, words in owner_mcp.GOOGLE_NOTICE.items():
            self.assertIn(f'"{words}"', tool["description"], service)
            self.assertIn(f'String(l10n: "{words}")', swift, service)       # the app's words, not a copy that drifts
        self.assertIn("call this tool when the owner says to go on", tool["description"])


class Cloud(unittest.TestCase):
    """**Servers at AWS, Azure and Google Cloud** (design 9, piece B1): `cloud_look`, `cloud_step` and `cloud_remove`,
    with stand-in programs `aws`, `az`, `gcloud` and `ssh` on the test's own PATH, which answer as the clouds do by a
    table of the test and write down each command with the files that it names. No cloud account and no network: what
    is proved is which commands the tools send, in which order, with which words, and which they never send."""

    NAME = "agents-1"
    KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEhvc3RLZXlPZlRoZUh1Yg"
    WHERE = {"aws": ("123456789012", "eu-central-1"), "azure": ("00000000-1111-2222-3333-444444444444", "westeurope"),
             "google": ("example-project-1", "europe-west1-b")}
    # **The closed list of commands** (design 9, 6.1), the test's own second copy: the first words of each command
    # that the tools may run. `{name}` is the server's name.
    READS = (("aws", "--version"), ("aws", "sts", "get-caller-identity"), ("aws", "ssm", "get-parameters"),
             ("aws", "ec2", "describe-instance-types"), ("aws", "ec2", "describe-images"),
             ("aws", "ec2", "describe-vpcs"), ("aws", "ec2", "describe-subnets"),
             ("aws", "ec2", "describe-security-groups"), ("aws", "ec2", "describe-security-group-rules"),
             ("aws", "ec2", "describe-instances"), ("aws", "ec2", "describe-instance-status"),
             ("az", "version"), ("az", "account", "show"), ("az", "vm", "list-skus"), ("az", "group", "show"),
             ("az", "network", "nsg", "show"), ("az", "vm", "show"), ("az", "resource", "list"),
             ("gcloud", "version"), ("gcloud", "auth", "list"), ("gcloud", "compute", "machine-types", "describe"),
             ("gcloud", "compute", "networks", "subnets", "describe"), ("gcloud", "compute", "firewall-rules", "list"),
             ("gcloud", "compute", "instances", "describe"))
    CHANGES = (("aws", "ec2", "create-security-group"), ("aws", "ec2", "run-instances"),
               ("aws", "ec2", "authorize-security-group-ingress"), ("aws", "ec2", "revoke-security-group-ingress"),
               ("az", "group", "create"), ("az", "network", "nsg", "create"), ("az", "vm", "create"),
               ("az", "network", "nsg", "rule", "create"), ("az", "network", "nsg", "rule", "delete"),
               ("gcloud", "compute", "firewall-rules", "create"), ("gcloud", "compute", "instances", "create"),
               ("gcloud", "compute", "firewall-rules", "delete", "founderizer-{name}-ssh"))
    DELETES = (("aws", "ec2", "terminate-instances"), ("aws", "ec2", "delete-security-group"),
               ("az", "group", "delete"), ("gcloud", "compute", "instances", "delete"),
               ("gcloud", "compute", "firewall-rules", "delete", "founderizer-{name}-closed"))
    # Words that no command of a recipe has (design 9, 6.2): an identity, a role, a key or a setting of the cloud, a
    # sign-in, a credential printed, a key pair made.
    NEVER = ("iam", "configure", "login", "logout", "sso", "set", "role", "assignment", "get-access-token",
             "print-access-token", "print-identity-token", "export-credentials", "--assign-identity",
             "--iam-instance-profile", "--service-account", "--scopes", "create-key-pair", "--key-name",
             "--generate-ssh-keys", "billing", "budget")
    READING = ("user=ubuntu\nuid=1000\nsudo=nopasswd\nos_id=ubuntu\nos_version=24.04\nos_name=Ubuntu\narch=x86_64\n"
               "memory_mb=1967\ndisk_free_mb=27000\nsystemd=yes\nipv4_route=yes\nreach=github.com yes\n"
               "reach=tailscale.com yes\nreach=claude.ai yes\nreach=chatgpt.com yes\ncloud_init=done\ndpkg_lock=no\n"
               "listen=tcp/22/sshd\nlisten=tcp/80/nginx\nlisten=tcp/443/nginx\nufw=inactive\ntailscale=none\n"
               "end=yes\n")
    # The stand-in of each program: the first rule of rules.json whose `has` words are all in the command, whose
    # `after` words were each in an earlier command and whose `before` words were in none, gives its exit status, its
    # output and its words on standard error. Each command goes into calls.jsonl, with the text of each file that it
    # names (`file://<path>`, `ssh-keys=<path>`, or a path as a word) and its standard input.
    STAND_IN = (
        "import json, os, sys\n"
        "where = os.path.dirname(os.path.abspath(__file__))\n"
        "argv = [os.path.basename(sys.argv[0])] + sys.argv[1:]\n"
        "line = ' '.join(argv)\n"
        "stdin = sys.stdin.read() if argv[0] == 'ssh' else ''\n"
        "log = os.path.join(where, 'calls.jsonl')\n"
        "earlier = [json.loads(x)['line'] for x in open(log)] if os.path.exists(log) else []\n"
        "files = {}\n"
        "for word in argv[1:]:\n"
        "    for start in ('file://', 'ssh-keys=', ''):\n"
        "        if word.startswith(start) and os.path.isfile(word[len(start):]):\n"
        "            files[word[len(start):]] = open(word[len(start):]).read()\n"
        "            break\n"
        "answer = {'exit': 99, 'out': '', 'err': 'no rule for: ' + line}\n"
        "for rule in json.load(open(os.path.join(where, 'rules.json'))):\n"
        "    if all(w in line for w in rule.get('has', [])) and \\\n"
        "            all(any(w in e for e in earlier) for w in rule.get('after', [])) and \\\n"
        "            not any(w in e for w in rule.get('before', []) for e in earlier):\n"
        "        out = rule.get('out', '')\n"
        "        answer = {'exit': rule.get('exit', 0), 'out': out if isinstance(out, str) else json.dumps(out),\n"
        "                  'err': rule.get('err', '')}\n"
        "        break\n"
        "with open(log, 'a') as out:\n"
        "    out.write(json.dumps({'argv': argv, 'line': line, 'files': files, 'stdin': stdin,\n"
        "                          'answer': answer}) + '\\n')\n"
        "sys.stdout.write(answer['out'])\n"
        "sys.stderr.write(answer['err'])\n"
        "sys.exit(answer['exit'])\n")

    def setUp(self):
        self.folder = pathlib.Path(tempfile.mkdtemp(prefix="fleet-cloud-"))
        self.addCleanup(shutil.rmtree, str(self.folder), True)
        for program in ("aws", "az", "gcloud", "ssh"):
            path = self.folder / program
            path.write_text(f"#!{sys.executable}\n" + self.STAND_IN)
            path.chmod(0o755)
        self.key_file = self.folder / "id_ed25519.pub"
        self.key_file.write_text(self.KEY + " admin@example.invalid\n")
        self.recipes = json.loads(json.dumps(owner_mcp.CLOUD_RECIPES))
        for recipe in self.recipes["clouds"].values():
            recipe["proved"] = "2026-12-01"                 # a proved cloud; test 7 holds what an unproved one does
        for patcher in (patch.dict(os.environ, {"PATH": str(self.folder)}),
                        patch.object(owner_mcp, "CLOUD_RECIPES", self.recipes),
                        patch.object(owner_mcp, "KNOWN_HOSTS", self.folder / "known_hosts")):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.rules(self.cloud_rules("aws") + self.cloud_rules("azure") + self.cloud_rules("google") +
                   [{"has": ["sh -s"], "out": self.READING}])

    # -- the stand-ins

    def rules(self, rules):
        (self.folder / "rules.json").write_text(json.dumps(rules))

    def sent(self):
        log = self.folder / "calls.jsonl"
        return [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []

    @classmethod
    def cloud_rules(cls, cloud, name=NAME, **changed):
        """The stand-in answers of one cloud for the server `name`, from nothing to a server and back: each read
        answers by the commands that came before it. `changed`: answers of the test in place of the usual ones."""
        if cloud == "aws":
            group = {"GroupId": "sg-0a1b2c3d4e5f67890", "GroupName": f"founderizer-{name}",
                     "Tags": [{"Key": "founderizer-server", "Value": name}, {"Key": "founderizer", "Value": "agent"}]}
            instance = {"InstanceId": "i-0a1b2c3d4e5f67890", "ClientToken": f"founderizer-{name}",
                        "State": {"Name": "running"}, "PublicIpAddress": "198.51.100.7"}
            egress = {"SecurityGroupRuleId": "sgr-0000000000000000a", "IsEgress": True, "IpProtocol": "-1",
                      "FromPort": -1, "ToPort": -1, "CidrIpv4": "0.0.0.0/0"}
            ssh_rule = {"SecurityGroupRuleId": "sgr-0a1b2c3d4e5f67890", "IsEgress": False, "IpProtocol": "tcp",
                        "FromPort": 22, "ToPort": 22, "CidrIpv4": "203.0.113.9/32"}
            return [
                {"has": ["aws --version"], "out": "aws-cli/2.42.1 Python/3.13.9 Darwin/25.1.0 source/arm64\n"},
                {"has": ["sts get-caller-identity"], "out": changed.get("identity", {
                    "Account": "123456789012", "Arn": "arn:aws:sts::123456789012:assumed-role/Admin/pat"})},
                {"has": ["describe-instance-types"], "out": {"InstanceTypes": [
                    {"MemoryInfo": {"SizeInMiB": changed.get("memory", 2048)},
                     "ProcessorInfo": {"SupportedArchitectures": ["x86_64"]}}]}},
                {"has": ["ssm get-parameters"], "out": {"Parameters": [{"Value": "ami-0a1b2c3d4e5f67890"}]}},
                {"has": ["describe-images"], "out": {"Images": [changed.get("image", {
                    "RootDeviceName": "/dev/sda1", "OwnerId": "099720109477"})]}},
                {"has": ["describe-subnets"], "out": {"Subnets": [{"VpcId": "vpc-0fedcba987654321f"}]}},
                {"has": ["describe-vpcs"], "out": changed.get("vpcs", {"Vpcs": [{"VpcId": "vpc-0a1b2c3d4e5f67890"}]})},
                {"has": ["describe-security-groups"], "after": ["create-security-group"],
                 "before": ["delete-security-group"], "out": {"SecurityGroups": [changed.get("group", group)]}},
                {"has": ["describe-security-groups"], "out": {"SecurityGroups": changed.get("groups", [])}},
                {"has": ["describe-security-group-rules"], "after": ["authorize-security-group-ingress"],
                 "before": ["revoke-security-group-ingress"], "out": {"SecurityGroupRules": [egress, ssh_rule]}},
                {"has": ["describe-security-group-rules"], "out": {"SecurityGroupRules": [egress]}},
                dict({"has": ["describe-instances"], "after": ["run-instances"], "before": ["terminate-instances"]},
                     **changed.get("made", {"out": {"Reservations": [{"Instances": [instance]}]}})),
                {"has": ["describe-instances"], "out": {"Reservations": changed.get("reservations", [])}},
                {"has": ["create-security-group"], "out": {"GroupId": group["GroupId"]}},
                {"has": ["run-instances"], "out": {"Instances": [{"InstanceId": instance["InstanceId"],
                                                                  "State": {"Name": "pending"}}]}},
                {"has": ["authorize-security-group-ingress"], "out": {"Return": True}},
                {"has": ["revoke-security-group-ingress"], "out": {"Return": True}},
                {"has": ["terminate-instances"], "out": {"TerminatingInstances": []}},
                {"has": ["delete-security-group"], "out": {"Return": True}}]
        if cloud == "azure":
            sub = cls.WHERE["azure"][0]
            base = f"/subscriptions/{sub}/resourceGroups/founderizer-{name}"
            group = {"id": base, "tags": {"founderizer-server": name, "founderizer": "agent"}}
            nsg = {"id": base + f"/providers/Microsoft.Network/networkSecurityGroups/{name}-nsg",
                   "tags": {"founderizer-server": name}, "securityRules": []}
            rule = {"name": "founderizer-ssh", "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
                    "priority": 1000, "sourceAddressPrefix": "203.0.113.9/32", "destinationPortRange": "22"}
            vm = {"id": base + f"/providers/Microsoft.Compute/virtualMachines/{name}", "powerState": "VM running",
                  "tags": {"founderizer-server": name, "founderizer": "agent"}, "publicIps": "198.51.100.8"}
            gone = {"exit": 3, "err": "ERROR: (ResourceNotFound) The Resource was not found."}
            return [
                {"has": ["az version"], "out": {"azure-cli": "2.93.0"}},
                {"has": ["az account show"], "out": changed.get("identity", {"id": sub,
                                                                              "user": {"name": "pat@example.com"}})},
                {"has": ["vm list-skus"], "out": [{"name": "Standard_B2als_v2",
                                                   "restrictions": changed.get("restrictions", []), "capabilities": [
                    {"name": "MemoryGB", "value": "4"}, {"name": "CpuArchitectureType", "value": "x64"}]}]},
                {"has": ["group show"], "after": ["group create"],
                 "before": [] if changed.get("group_stays") else ["group delete"], "out": group},
                {"has": ["group show"], "out": changed["group_now"]} if "group_now" in changed else
                dict(gone, has=["group show"]),
                {"has": ["nsg show"], "after": ["nsg rule create"], "before": ["nsg rule delete"],
                 "out": dict(nsg, securityRules=[rule])},
                {"has": ["nsg show"], "after": ["nsg create"], "before": ["group delete"], "out": nsg},
                dict(gone, has=["nsg show"]),
                {"has": ["vm show"], "after": ["vm create"], "before": ["group delete"], "out": vm},
                dict(gone, has=["vm show"]),
                {"has": ["resource list"], "out": changed.get("resources", [
                    {"name": f"{name}-nsg"}, {"name": name}, {"name": f"{name}VMNic"}, {"name": f"{name}PublicIP"},
                    {"name": f"{name}VNET"}, {"name": f"{name}_OsDisk_1_0a1b2c3d"}])},
                {"has": ["group create"], "out": group}, {"has": ["nsg rule create"], "out": rule},
                {"has": ["nsg rule delete"], "out": ""}, {"has": ["nsg create"], "out": {"NewNSG": nsg}},
                {"has": ["vm create"], "out": ""}, {"has": ["group delete"], "out": ""}]
        closed = {"name": f"founderizer-{name}-closed", "description": f"founderizer-server={name}",
                  "direction": "INGRESS", "priority": 1000, "sourceRanges": ["0.0.0.0/0"],
                  "denied": [{"IPProtocol": "all"}], "targetTags": [f"founderizer-{name}"]}
        ssh_rule = {"name": f"founderizer-{name}-ssh", "description": f"founderizer-server={name}",
                    "direction": "INGRESS", "priority": 900, "sourceRanges": ["203.0.113.9/32"],
                    "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], "targetTags": [f"founderizer-{name}"]}
        default = {"name": "default-allow-ssh", "direction": "INGRESS", "priority": 65534,
                   "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}
        instance = {"name": name, "status": "RUNNING", "labels": {"founderizer-server": name, "founderizer": "agent"},
                    "networkInterfaces": [{"networkIP": "10.128.0.5", "accessConfigs": [{"natIP": "198.51.100.9"}]}]}
        made = {"closed": f"firewall-rules create founderizer-{name}-closed",
                "ssh": f"firewall-rules create founderizer-{name}-ssh"}
        ended = {"closed": f"firewall-rules delete founderizer-{name}-closed",
                 "ssh": f"firewall-rules delete founderizer-{name}-ssh"}
        lists = []
        for kinds in (("closed", "ssh"), ("closed",), ("ssh",)):    # in this order, the first that holds answers
            lists.append({"has": ["firewall-rules list"], "after": [made[k] for k in kinds],
                          "before": [ended[k] for k in kinds],
                          "out": [default] + [{"closed": closed, "ssh": ssh_rule}[k] for k in kinds]})
        lists.append({"has": ["firewall-rules list"], "out": changed.get("rules_now", [default])})
        return [
            {"has": ["gcloud version"], "out": {"Google Cloud SDK": "594.0.0"}},
            {"has": ["auth list"], "out": changed.get("identity", [{"account": "pat@example.com",
                                                                     "status": "ACTIVE"}])},
            {"has": ["machine-types describe"], "out": {"memoryMb": 2048, "guestCpus": 2}},
            {"has": ["subnets describe"],
             "out": {"network": "https://www.googleapis.com/compute/v1/projects/p/global/networks/company-net"}}] + \
            lists + [
            {"has": ["instances describe"], "after": ["instances create"], "before": ["instances delete"],
             "out": instance},
            {"has": ["instances describe"], "out": changed["instance_now"]} if "instance_now" in changed else
            {"has": ["instances describe"], "exit": 1,
             "err": "ERROR: (gcloud.compute.instances.describe) Could not fetch resource:\n - The resource "
                    f"'projects/p/zones/z/instances/{name}' was not found\n"},
            {"has": ["firewall-rules create"], "out": []}, {"has": ["instances create"], "out": []},
            {"has": ["firewall-rules delete"], "out": []}, {"has": ["instances delete"], "out": []}]

    # -- the calls

    def call(self, tool, **args):
        """One call of a tool, as the server gives it to the client: its answer, or Refused with its words."""
        with patch.dict(owner_mcp.TOOLS, {t["name"]: t for t in owner_mcp.tools()}):
            text, error = owner_mcp.call_tool(tool, args)
        if error:
            raise Refused(text)
        return json.loads(text)

    def base(self, cloud):
        account, place = self.WHERE[cloud]
        return {"cloud": cloud, "name": self.NAME, "account": account, "place": place}

    def journey(self, cloud, **more):
        """The calls of one new server at `cloud`, from the look to its removal, in the recipe's order. `more`: fields
        of each call."""
        recipe = self.recipes["clouds"][cloud]
        calls = [("cloud_look", dict(self.base(cloud), **more))]
        for step in recipe["steps"]:
            if step["kind"] == "make":
                fields = {"server": {"ssh_public_key_file": str(self.key_file)},
                          "open_ssh": {"ssh_from": "203.0.113.9"}}.get(step["id"], {})
                calls.append(("cloud_step", dict(self.base(cloud), step=step["id"], **fields, **more)))
            elif step["kind"] in ("check", "close"):
                calls.append(("cloud_step", dict(self.base(cloud), step=step["id"], **more)))
        calls += [("cloud_remove", dict(self.base(cloud), step=r["id"], **more)) for r in recipe["removals"]]
        return calls

    def walk(self, cloud, **more):
        """Each call of `journey`, run, with its answer and the commands that it sent."""
        done = []
        for tool, args in self.journey(cloud, **more):
            before = len(self.sent())
            done.append((tool, args, self.call(tool, **args), self.sent()[before:]))
        return done

    @staticmethod
    def starts(argv, prefixes, name):
        return any(tuple(argv[:len(p)]) == tuple(w.replace("{name}", name) for w in p) for p in prefixes)

    def recipe_commands(self, cloud):
        """Each command of the data of one cloud: its reads, the version, its steps and its removals."""
        recipe = self.recipes["clouds"][cloud]
        commands = [recipe["version"]["argv"]] + [r["argv"] for r in recipe["reads"].values() if r.get("argv")]
        commands += [s["argv"] for s in recipe["steps"] if s.get("argv")]
        return commands + [r["argv"] for r in recipe["removals"]]

    # -- the tests

    def test_each_command_is_in_the_closed_list(self):
        """Test 1 of design 9: each command of the data, and each command that a run of each step sends, starts with
        the words of the closed list that this test holds itself, and no word of a command is one of NEVER. Bug: a new
        step runs `aws iam ...`, a delete of another kind, or a server command that gives the server a role."""
        allowed = self.READS + self.CHANGES + self.DELETES
        for cloud in self.recipes["clouds"]:
            recipe = self.recipes["clouds"][cloud]
            words = [w for c in self.recipe_commands(cloud) for w in c] + list(recipe["tail"]) + \
                [w for one in recipe.get("tail_if", ()) for w in one["argv"]] + list(recipe["tail_change"]) + \
                [w for s in recipe["steps"] for one in s.get("extra", ()) for w in one["argv"]]
            for argv in self.recipe_commands(cloud):
                self.assertTrue(self.starts(argv, allowed, "{name}"), argv)
            # Two reads of one fact exclude each other by a value (when / unless): a reader of the app's table, which
            # keeps no order of its keys, then finds the same read as this one.
            for fact in {f for r in recipe["reads"].values() for f in r["gives"]}:
                givers = [r for r in recipe["reads"].values() if fact in r["gives"]]
                for one, other in ((a, b) for a in givers for b in givers if a is not b):
                    self.assertTrue(set(one.get("when", ())) & set(other.get("unless", ())) or
                                    set(one.get("unless", ())) & set(other.get("when", ())), (cloud, fact))
            self.assertEqual([w for w in words if w.split("=")[0] in self.NEVER], [], cloud)
            for tool, args, _answer, sent in self.walk(cloud):
                for one in sent:
                    argv = one["argv"]
                    if argv[0] == "ssh":
                        self.assertEqual((argv[-1], one["stdin"]), ("sh -s", owner_mcp.SERVER_CHECK), args)
                    else:
                        self.assertTrue(self.starts(argv, allowed, self.NAME), (tool, args, argv))
                        self.assertEqual([w for w in argv if w.split("=")[0] in self.NEVER], [], argv)
        # A read that the data gains outside the list is found too: the test reads the data, not a list of its own.
        self.recipes["clouds"]["aws"]["reads"]["roles"] = {"argv": ["aws", "iam", "list-roles"], "gives": {}}
        self.assertFalse(all(self.starts(c, allowed, "{name}") for c in self.recipe_commands("aws")))

    def test_a_value_cannot_become_an_option_or_a_second_command(self):
        """Test 2 of design 9: for each field, a value with a first "-", a space, a quote, "$", ";", "|", "&", a
        backslash or a new line is refused before a program runs; ssh_from 0.0.0.0/0 and a /23 are refused; a private
        key file is refused. And a fact of the cloud that does not match its pattern stops the step before its change
        (rule 3). Bug: a pattern that was made wider, or a fact that reaches a command unchecked."""
        bad = ("-", " ", "'", '"', "$", ";", "|", "&", "\\", "\n", "`")
        for cloud, recipe in self.recipes["clouds"].items():
            for field, rule in owner_mcp.cloud_value_rules(recipe).items():
                if "pattern" not in rule:
                    continue
                example = rule["example"]
                self.assertRegex(example, f"^(?:{rule['pattern']})$", (cloud, field))
                self.assertIsNone(re.fullmatch(rule["pattern"], "-" + example), (cloud, field))
                for mark in bad[1:]:
                    for value in (mark + example, example[:1] + mark + example[1:], example + mark):
                        self.assertIsNone(re.fullmatch(rule["pattern"], value), (cloud, field, value))
        for field, value in (("name", "-agents"), ("name", "agents 1"), ("name", "door"), ("account", "1234; rm"),
                             ("place", "eu-central-1\n"), ("size", "--t3.small"), ("subnet", "subnet-$x"),
                             ("profile", "-p"), ("ssh_from", "0.0.0.0/0"), ("ssh_from", "198.51.100.0/23"),
                             ("ssh_from", "203.0.113.9/24"), ("ssh_from", "100.64.0.7"), ("ssh_from", "10.0.0.0/24"),
                             ("ssh_from", "192.168.1.5"), ("ssh_from", "172.20.0.0/24"), ("disk_gb", "30"),
                             ("disk_gb", 4096), ("use", "agent;")):
            args = dict(self.base("aws"), step="open_ssh", ssh_from="203.0.113.9")
            args[field] = value
            with self.assertRaises(Refused, msg=(field, value)) as caught:
                self.call("cloud_step", **args)
            self.assertIn("Nothing ran", str(caught.exception), (field, value))
        # The range has two guards, the pattern of the data and the code: each one alone refuses a range wider than /24.
        self.assertIsNone(re.fullmatch(owner_mcp.CLOUD_RECIPES["values"]["ssh_from"]["pattern"], "198.51.100.0/23"))
        for wide in ("198.51.100.0/23", "0.0.0.0/0", "100.64.0.0/24"):
            with self.assertRaises(owner_mcp.Refused, msg=wide):
                owner_mcp.ssh_from_value(wide)
        self.assertEqual(owner_mcp.ssh_from_value("203.0.113.9"), "203.0.113.9/32")
        private = self.folder / "id_ed25519"
        private.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n"
                           "-----END OPENSSH PRIVATE KEY-----\n")
        two = self.folder / "two.pub"
        two.write_text(self.KEY + "\n" + self.KEY + "\n")
        for path, said in ((private, "holds a private key"), (two, "not one line"),
                           (self.folder / "none.pub", "not a public key file")):
            with self.assertRaisesRegex(Refused, said):
                self.call("cloud_step", **self.base("aws"), step="server", ssh_public_key_file=str(path))
        with self.assertRaisesRegex(Refused, "has no field"):
            self.call("cloud_step", **self.base("aws"), step="firewall", command="aws iam list-roles")
        self.assertEqual(self.sent(), [])
        # rule 3: a VPC ID that is no VPC ID stops the firewall step before create-security-group
        self.rules(self.cloud_rules("aws", vpcs={"Vpcs": [{"VpcId": "vpc-0a1b2c3d; rm -rf /"}]}))
        with self.assertRaisesRegex(Refused, "not a value that the recipe takes"):
            self.call("cloud_step", **self.base("aws"), step="firewall")
        self.assertFalse(any("create-security-group" in one["line"] for one in self.sent()))
        # an image with no owner in AWS's answer is no image of Canonical's: a fact that must be there
        group = {"GroupId": "sg-0a1b2c3d4e5f67890", "GroupName": f"founderizer-{self.NAME}",
                 "Tags": [{"Key": "founderizer-server", "Value": self.NAME}]}
        self.rules(self.cloud_rules("aws", groups=[group], image={"RootDeviceName": "/dev/sda1"}))
        with self.assertRaisesRegex(Refused, "did not give the owner of the image"):
            self.call("cloud_step", **self.base("aws"), step="server", ssh_public_key_file=str(self.key_file))
        self.assertFalse(any("run-instances" in one["line"] for one in self.sent()))

    def test_one_step_sends_at_most_one_change(self):
        """Test 3 of design 9: each call of a whole new server and its removal, at each cloud, sends at most one
        command that changes or deletes, and the steps that change send exactly one. Bug: a step that makes two
        things."""
        for cloud in self.recipes["clouds"]:
            for tool, args, answer, sent in self.walk(cloud):
                changes = [one["argv"][:5] for one in sent if self.starts(one["argv"], self.CHANGES + self.DELETES,
                                                                          self.NAME)]
                expected = 0 if tool == "cloud_look" or args.get("step") == "check" else 1
                self.assertEqual(len(changes), expected, (cloud, tool, args, changes))
                if tool != "cloud_look" and args.get("step") != "check":
                    self.assertIn("did", answer, (cloud, args))
                if tool == "cloud_remove":                  # no read of a step that makes in a removal's answer
                    self.assertFalse([one["line"] for one in sent if any(w in one["line"] for w in (
                        "describe-instance-types", "ssm get-parameters", "describe-images", "list-skus",
                        "machine-types"))], (cloud, args))
                    self.assertEqual({s["tool"] for s in answer["steps"]}, {"cloud_remove"}, (cloud, args))
                if tool == "cloud_remove":                  # never a step that makes the removed thing again
                    order = [r["id"] for r in self.recipes["clouds"][cloud]["removals"]]
                    after = order[order.index(args["step"]) + 1:]
                    wanted = after[0] if after else None
                    self.assertEqual((answer["next"] or {}).get("arguments", {}).get("step"), wanted, (cloud, args))
                    self.assertNotIn("after_join", answer, (cloud, args))

    def test_the_next_of_a_removal_never_makes_the_server_again(self):
        """An agent that follows `next` from the removal of a server ends with nothing of the recipe left, also when
        the SSH rule is still there (a check that stopped, a join that did not run): at Google Cloud the chain is
        cloud_remove server, cloud_step close_ssh, cloud_remove firewall, and then nothing; at AWS a close_ssh after the
        server is gone gives the removal of the firewall as next, and one after the firewall has nothing to remove; and
        an Azure group that still shows while Azure deletes it gives cloud_look, not the same delete again. Bug: an
        agent that follows `next` rents the server again and lets SSH in to it, or is told to make a firewall."""
        for step in ("firewall", "server", "open_ssh"):
            self.call("cloud_step", **self.base("google"), step=step,
                      **{"server": {"ssh_public_key_file": str(self.key_file)},
                         "open_ssh": {"ssh_from": "203.0.113.9"}}.get(step, {}))
        chain, call = [], {"tool": "cloud_remove", "arguments": dict(self.base("google"), step="server")}
        while call:
            chain.append((call["tool"], call["arguments"]["step"]))
            self.assertLess(len(chain), 6, chain)
            call = self.call(call["tool"], **call["arguments"])["next"]
        self.assertEqual(chain, [("cloud_remove", "server"), ("cloud_step", "close_ssh"), ("cloud_remove", "firewall")])
        found = self.call("cloud_look", **self.base("google"))["found"]
        self.assertEqual([k for k, v in found.items() if v["there"]], [])
        for step in ("firewall", "server", "open_ssh"):
            self.call("cloud_step", **self.base("aws"), step=step,
                      **{"server": {"ssh_public_key_file": str(self.key_file)},
                         "open_ssh": {"ssh_from": "203.0.113.9"}}.get(step, {}))
        self.call("cloud_remove", **self.base("aws"), step="server")
        closed = self.call("cloud_step", **self.base("aws"), step="close_ssh")
        self.assertEqual((closed["next"]["tool"], closed["next"]["arguments"]["step"]), ("cloud_remove", "firewall"))
        self.assertIn("call cloud_look before that removal", closed["did"])     # a server not shown yet
        # After the firewall, a close_ssh has nothing to remove: the rule went with it, and no step makes the firewall.
        self.call("cloud_remove", **self.base("aws"), step="firewall")
        gone = self.call("cloud_step", **self.base("aws"), step="close_ssh")
        self.assertIn("nothing to remove", gone["did"])
        self.assertIsNone(gone["next"])
        self.rules(self.cloud_rules("azure", group_stays=True))
        for step in ("group", "firewall"):
            self.call("cloud_step", **self.base("azure"), step=step)
        gone = self.call("cloud_remove", **self.base("azure"), step="group")
        self.assertIn("still shows", gone["did"])
        self.assertEqual((gone["next"]["tool"], gone["next"]["arguments"].get("step")), ("cloud_look", None))

    def test_a_repeat_makes_no_second_server(self):
        """Test 4 of design 9: `server` twice (a retry after a lost answer) sends the command that makes a server
        once, and the second call says that it is there already; so does each other step. Bug: a retry rents
        twice."""
        makes = {"aws": "run-instances", "azure": "vm create", "google": "instances create"}
        for cloud, recipe in self.recipes["clouds"].items():
            for tool, args in self.journey(cloud)[1:]:
                if args.get("step") == "check":
                    break
                first = self.call(tool, **args)
                again = self.call(tool, **args)
                self.assertIn("there already", again["did"], (cloud, args))
                self.assertNotIn("there already", first["did"], (cloud, args))
            self.assertEqual(sum(makes[cloud] in one["line"] for one in self.sent()), 1, cloud)

    def test_a_removal_takes_only_a_marked_thing(self):
        """Test 5 of design 9: an AWS instance with the name's tag and another client token, an AWS security group
        with no tag of the recipe, an Azure resource group that holds one resource of another name or has no tag, a
        Google Cloud rule with another description, and a Google Cloud instance with no label: each removal is refused
        by name, and no delete is sent. Bug: a delete by name."""
        other = {"InstanceId": "i-0fedcba987654321f", "ClientToken": "someone-else", "State": {"Name": "running"}}
        untagged = {"GroupId": "sg-0fedcba987654321f", "GroupName": f"founderizer-{self.NAME}", "Tags": []}
        group = {"id": f"/subscriptions/{self.WHERE['azure'][0]}/resourceGroups/founderizer-{self.NAME}",
                 "tags": {"founderizer-server": self.NAME}}
        rule = {"name": f"founderizer-{self.NAME}-closed", "description": "the network team's rule"}
        for cloud, step, changed, said in (
                ("aws", "server", {"reservations": [{"Instances": [other]}]}, "i-0fedcba987654321f"),
                ("aws", "firewall", {"groups": [untagged]}, "sg-0fedcba987654321f"),
                ("azure", "group", {"group_now": group, "resources": [{"name": f"{self.NAME}-nsg"},
                                                                      {"name": "billing-db"}]}, "billing-db"),
                ("azure", "group", {"group_now": dict(group, tags={})}, "without this recipe's mark"),
                ("google", "firewall", {"rules_now": [rule]}, "without this recipe's mark"),
                ("google", "server", {"instance_now": {"name": self.NAME, "labels": {}}},
                 "without this recipe's mark")):
            self.rules(self.cloud_rules(cloud, **changed))
            (self.folder / "calls.jsonl").unlink(missing_ok=True)
            with self.assertRaisesRegex(Refused, said, msg=(cloud, step)):
                self.call("cloud_remove", **self.base(cloud), step=step)
            self.assertFalse([one["argv"] for one in self.sent() if self.starts(one["argv"], self.DELETES, self.NAME)],
                             (cloud, step))

    def test_a_missing_program_a_sign_out_and_another_account_stop_before_any_change(self):
        """Test 6 of design 9: the program is not there, its sign-in ended (AWS's status 253, Azure's words, an empty
        list of gcloud), or it is signed in to another account: the refusal has the admin's own step, no later
        command is sent, and no refusal asks for a key or a token. Bug: the step goes on."""
        for cloud, program in (("aws", "aws"), ("azure", "az"), ("google", "gcloud")):
            recipe = self.recipes["clouds"][cloud]
            cases = [({"identity": None}, "signed_out")]
            if cloud == "aws":
                cases.append(({"identity": {"Account": "999999999999", "Arn": "arn:aws:iam::999999999999:user/x"}},
                              "999999999999"))
            if cloud == "azure":
                cases.append(({"identity": {"id": "99999999-1111-2222-3333-444444444444", "user": {"name": "x"}}},
                              "99999999-1111-2222-3333-444444444444"))
            for changed, said in cases:
                rules = self.cloud_rules(cloud, **({k: v for k, v in changed.items() if v is not None}))
                if changed["identity"] is None:                 # the program's own sign-out
                    signed_out = {"aws": {"exit": 253, "err": "Unable to locate credentials."},
                                  "azure": {"exit": 1, "err": "ERROR: Please run 'az login' to setup account."},
                                  "google": {"out": []}}[cloud]
                    rules.insert(1, dict(signed_out, has=[{"aws": "sts get-caller-identity", "azure": "account show",
                                                           "google": "auth list"}[cloud]]))
                self.rules(rules)
                (self.folder / "calls.jsonl").unlink(missing_ok=True)
                with self.assertRaises(Refused) as caught:
                    self.call("cloud_step", **self.base(cloud), step=recipe["steps"][0]["id"])
                words = str(caught.exception)
                self.assertIn(recipe["signed_out"] if said == "signed_out" else said, words, cloud)
                self.assertIsNone(re.search(r"access key|secret|token|password", words, re.I), words)
                self.assertEqual(len(self.sent()), 2, (cloud, [one["line"] for one in self.sent()]))
            (self.folder / program).unlink()
            (self.folder / "calls.jsonl").unlink(missing_ok=True)
            with self.assertRaises(Refused) as caught:
                self.call("cloud_look", **self.base(cloud))
            self.assertIn(recipe["missing"], str(caught.exception))
            self.assertEqual(self.sent(), [])

    def test_an_unproved_cloud_is_refused_and_a_proved_one_is_not(self):
        """Test 7 of design 9: a cloud with no `proved` date is refused by each tool before any program runs, and the
        same cloud with a date is read. Bug: a recipe reaches the admins before its live proof."""
        for cloud in self.recipes["clouds"]:
            (self.folder / "calls.jsonl").unlink(missing_ok=True)
            self.recipes["clouds"][cloud]["proved"] = None
            for tool, args in self.journey(cloud) + [("cloud_look", {"cloud": cloud})]:
                with self.assertRaisesRegex(Refused, "does not offer servers", msg=(cloud, tool)):
                    self.call(tool, **args)
            self.assertEqual(self.sent(), [])
            self.recipes["clouds"][cloud]["proved"] = "2026-12-01"
            self.assertEqual(self.call("cloud_look", cloud=cloud)["recipe"]["proved"], "2026-12-01")
            self.assertEqual(self.call("cloud_look", **self.base(cloud))["next"]["arguments"]["step"],
                             self.recipes["clouds"][cloud]["steps"][0]["id"])

    def test_the_check_gives_stop_wait_or_ready_as_the_apps_check_does(self):
        """Test 8 of design 9: readings give stop (Debian 11, a sudo that asks for a password, 1 GB for agents),
        wait (cloud-init runs) or ready, by the rules of the app's `ServerCheck.verdict`; the check runs the script on
        standard input over the admin's own SSH; and a ready server is joined next by add_machine, or install_hub for
        a hub. Bug: the two checks say different things of one server, or the check sends the agent to a wrong
        tool."""
        good = owner_mcp.server_reading(self.READING)
        self.assertEqual(owner_mcp.server_verdict(good), ("ready", "Ubuntu 24.04 · 2 GB · x86"))
        for change, use, verdict in (({"os_id": "debian", "os_version": "11"}, "agent", "stop"),
                                     ({"sudo": "password"}, "agent", "stop"), ({"sudo": "none"}, "agent", "stop"),
                                     ({"memory_mb": "980"}, "agent", "stop"), ({"memory_mb": "980"}, "hub", "stop"),
                                     ({"memory_mb": "1800"}, "hub", "ready"),
                                     ({"disk_free_mb": "9000"}, "agent", "stop"), ({"arch": "armv7l"}, "agent", "stop"),
                                     ({"systemd": "no"}, "agent", "stop"), ({"cloud_init": "running"}, "agent", "wait"),
                                     ({"dpkg_lock": "yes"}, "agent", "wait")):
            text = self.READING
            for key, value in change.items():
                text = re.sub(rf"^{key}=.*$", f"{key}={value}", text, flags=re.M)
            self.assertEqual(owner_mcp.server_verdict(owner_mcp.server_reading(text), use)[0], verdict, (change, use))
        unreached = self.READING.replace("reach=claude.ai yes", "reach=claude.ai no").replace(
            "reach=chatgpt.com yes", "reach=chatgpt.com no")
        self.assertEqual(owner_mcp.server_verdict(owner_mcp.server_reading(unreached), "agent")[0], "stop")
        self.assertEqual(owner_mcp.server_verdict(owner_mcp.server_reading(unreached), "hub")[0], "ready")
        self.assertIsNone(owner_mcp.server_reading(self.READING.replace("end=yes", "")))
        done = self.call("cloud_step", cloud="aws", step="check", host="203.0.113.20", ssh_user="ubuntu")
        self.assertEqual((done["verdict"], done["next"]["tool"], done["next"]["arguments"]["host"]),
                         ("ready", "add_machine", "203.0.113.20"))
        self.assertIn("Ports 80 and 443 stay open as they are.", done["changes"])
        self.assertIn("EC2 Instance Connect", done["changes"])          # a server that the company has already
        hub_check = self.call("cloud_step", cloud="aws", step="check", host="203.0.113.20", ssh_user="ubuntu",
                              use="hub")
        self.assertEqual(hub_check["next"]["tool"], "install_hub")
        sent = self.sent()[-1]
        self.assertEqual((sent["argv"][0], sent["argv"][-2:], sent["stdin"]),
                         ("ssh", ["ubuntu@203.0.113.20", "sh -s"], owner_mcp.SERVER_CHECK))
        self.rules([{"has": ["sh -s"], "out": self.READING.replace("cloud_init=done", "cloud_init=running")}])
        waits = self.call("cloud_step", cloud="aws", step="check", host="203.0.113.20", ssh_user="ubuntu")
        self.assertEqual((waits["verdict"], waits["next"]["arguments"]["step"]), ("wait", "check"))
        # The same floor stops the step server before it rents a size that the check would stop later.
        self.rules(self.cloud_rules("aws", memory=1024, groups=[{
            "GroupId": "sg-0a1b2c3d4e5f67890", "GroupName": f"founderizer-{self.NAME}",
            "Tags": [{"Key": "founderizer-server", "Value": self.NAME}]}]))
        with self.assertRaisesRegex(Refused, "1024 MB of memory, and a server for agents needs about 2 GB"):
            self.call("cloud_step", **self.base("aws"), step="server", size="t3.micro",
                      ssh_public_key_file=str(self.key_file))
        self.assertFalse(any("run-instances" in one["line"] for one in self.sent()))
        # At Azure a restriction of the place stops the step server before its cost; one of a zone does not, because
        # the recipe's VM has no zone (Microsoft's list-skus with --all shows both).
        for restrictions, stops in (([{"type": "Location", "reasonCode": "NotAvailableForSubscription"}], True),
                                    ([{"type": "Zone", "reasonCode": "NotAvailableForSubscription"}], False)):
            (self.folder / "calls.jsonl").unlink(missing_ok=True)
            self.rules(self.cloud_rules("azure", restrictions=restrictions))
            for step in ("group", "firewall"):
                self.call("cloud_step", **self.base("azure"), step=step)
            server = dict(self.base("azure"), step="server", ssh_public_key_file=str(self.key_file))
            if stops:
                with self.assertRaisesRegex(Refused, "NotAvailableForSubscription"):
                    self.call("cloud_step", **server)
            else:
                self.call("cloud_step", **server)
            self.assertEqual(any("vm create" in one["line"] for one in self.sent()), not stops, restrictions)
            self.assertTrue(all("--all" in one["argv"] for one in self.sent() if "list-skus" in one["line"]))

    @needs_the_apps
    def test_the_check_script_is_the_apps_word_for_word(self):
        """Test 8 of design 9, its second half: SERVER_CHECK is `ServerCheck.script` of the Mac app, so that the
        check before a join through these tools and the app's own check read a server with the same script. Bug: one
        of the two changes and the other does not."""
        swift = (HERE / "app" / "Sources" / "FleetCore" / "ServerCheck.swift").read_text()
        start = swift.index('public static let script = #"""\n') + len('public static let script = #"""\n')
        body = swift[start:swift.index('\n    """#', start)]
        self.assertEqual("\n".join(line[4:] if line.startswith("    ") else line.strip()
                                   for line in body.split("\n")), owner_mcp.SERVER_CHECK)
        self.assertEqual(tuple(re.findall(r'"([a-z]+\.(?:com|ai))"', swift.split("static let hosts =")[1]
                                          .split("\n")[0])), owner_mcp.CHECK_HOSTS)
        # and the rules of the verdict that stand as values in Swift: the floors, the machines and the systems
        floors = {name: (int(eval(mb, {})), words) for name, mb, words in re.findall(
            r'static let (\w+) = \(megabytes: ([0-9 *]+), words: "([^"]+)"\)', swift)}
        self.assertEqual(floors, {"hubMemory": owner_mcp.CHECK_MEMORY["hub"],
                                  "agentMemory": owner_mcp.CHECK_MEMORY["agent"], "freeDisk": owner_mcp.CHECK_DISK})
        self.assertEqual(dict(re.findall(r'"(\w+)": "(\w+)"', swift.split("static let architectures =")[1]
                                         .split("\n")[0])), owner_mcp.CHECK_ARCHITECTURES)
        install = (HERE / "app" / "Sources" / "FleetCore" / "MachineInstall.swift").read_text()
        takes = install.split("public static let joinTakes =")[1].split("public static let hubTakes")[0]
        self.assertEqual(tuple(re.findall(r'System\(id: "(\w+)", version: "([0-9.]+)", name: "(\w+)"\)', takes)),
                         owner_mcp.CHECK_SYSTEMS)
        self.assertIn("public static let hubTakes = joinTakes", install)

    def test_no_secret_goes_into_a_cloud_command(self):
        """Test 9 of design 9: no tool of the three has a field for the Tailscale key or any other credential, and the
        file of each server command holds only the server's name and the type and the key of the one public key (not
        its comment); the file is gone after the command. Bug: the key in the cloud's metadata, or a key's comment
        (often a person's address) sent to the cloud."""
        for t in owner_mcp.tools():
            if t["name"].startswith("cloud_"):
                fields = set(t["inputSchema"]["properties"])
                self.assertEqual({f for f in fields if re.search(r"key|token|secret|password|auth", f)},
                                 {"ssh_public_key_file"} & fields, t["name"])
        expected = {"aws": f"#cloud-config\nhostname: {self.NAME}\nssh_authorized_keys:\n  - {self.KEY}\n",
                    "azure": f"{self.KEY}\n", "google": f"ubuntu:{self.KEY}\n"}
        for cloud in self.recipes["clouds"]:
            for _tool, args, _answer, sent in self.walk(cloud):
                for one in sent:
                    self.assertNotIn("admin@example.invalid", json.dumps(one), cloud)
                    self.assertNotIn(str(self.key_file), one["argv"], cloud)
                    if args.get("step") == "server" and one["files"]:
                        self.assertEqual(list(one["files"].values()), [expected[cloud]], cloud)
                        self.assertFalse(any(os.path.exists(path) for path in one["files"]), cloud)
            self.assertTrue(any(one["files"] for one in self.sent()), cloud)

    def test_the_new_server_has_no_identity_and_no_open_ssh(self):
        """Test 10 of design 9: the server command of Azure has --nsg-rule NONE, of Google Cloud --no-service-account
        and --no-scopes, and of AWS no instance profile; the one rule that lets anything in is TCP 22 from ssh_from,
        and the only rule for 0.0.0.0/0 denies. Bug: a flag lost in an edit, which leaves SSH open to every address or
        gives each program on the server the cloud's credentials."""
        servers = {c: next(s["argv"] for s in r["steps"] if s["id"] == "server")
                   for c, r in self.recipes["clouds"].items()}
        self.assertNotIn("--iam-instance-profile", servers["aws"])
        self.assertIn("HttpTokens=required,HttpEndpoint=enabled", servers["aws"])
        nsg = servers["azure"].index("--nsg-rule")
        self.assertEqual(servers["azure"][nsg + 1], "NONE")
        self.assertNotIn("--assign-identity", servers["azure"])
        self.assertTrue({"--no-service-account", "--no-scopes"} <= set(servers["google"]))
        for cloud in self.recipes["clouds"]:
            for argv in self.recipe_commands(cloud):
                if "0.0.0.0/0" in " ".join(argv):
                    self.assertIn("--action=DENY", argv, argv)
            lets_in = 0
            for _tool, args, _answer, sent in self.walk(cloud):
                for one in sent:
                    argv, line = one["argv"], one["line"]
                    if argv[:3] == ["aws", "ec2", "authorize-security-group-ingress"] or \
                            argv[:5] == ["az", "network", "nsg", "rule", "create"] or "--action=ALLOW" in argv:
                        lets_in += 1
                        self.assertIn("203.0.113.9/32", line)
                        self.assertNotIn("0.0.0.0/0", line)
                        self.assertTrue({"22", "--rules=tcp:22"} & set(argv), argv)
                    if args.get("step") == "server" and self.starts(argv, self.CHANGES, self.NAME):
                        literal = {w for w in servers[cloud] if not owner_mcp.CLOUD_PLACE.search(w)}
                        self.assertEqual(literal - set(argv), set(), cloud)
            self.assertEqual(lets_in, 1, cloud)

    def test_the_look_shows_the_state_and_next_and_runs_no_change(self):
        """cloud_look with cloud alone needs no program; with name it gives next the call of the first step that is
        not done, with its command as it would run; and after the SSH rule, next is the check and after_join is
        close_ssh. Bug: the look sends a command that changes, or next skips a step."""
        recipe = self.call("cloud_look", cloud="azure")
        self.assertEqual([s["id"] for s in recipe["steps"]], ["group", "firewall", "server", "open_ssh", "check",
                                                              "join", "close_ssh"])
        self.assertEqual(self.sent(), [])
        for cloud in self.recipes["clouds"]:
            for tool, args, answer, sent in self.walk(cloud):
                if tool == "cloud_look":
                    first = self.recipes["clouds"][cloud]["steps"][0]
                    self.assertEqual(answer["next"]["arguments"]["step"], first["id"])
                    self.assertTrue(self.starts(answer["next"]["command"], self.CHANGES, self.NAME), answer["next"])
                    self.assertFalse([1 for one in sent if self.starts(one["argv"], self.CHANGES + self.DELETES,
                                                                       self.NAME)], cloud)
                if args.get("step") == "open_ssh":
                    self.assertEqual(answer["next"]["arguments"]["step"], "check", cloud)
                    self.assertEqual(answer["after_join"]["arguments"]["step"], "close_ssh", cloud)

    def test_a_read_that_fails_after_a_change_says_that_the_change_was_sent(self):
        """When the step's command ended with 0 and a read after it fails, the answer says that the cloud took the
        change, gives the read's words, and for a server that it costs money; and a make command whose thing the cloud
        does not show yet sends the agent to cloud_look, not to the same step. Bug: a server runs and costs money, and
        the agent reads "Nothing was changed" or sends the step again."""
        group = {"GroupId": "sg-0a1b2c3d4e5f67890", "GroupName": f"founderizer-{self.NAME}",
                 "Tags": [{"Key": "founderizer-server", "Value": self.NAME}]}
        server = dict(self.base("aws"), step="server", ssh_public_key_file=str(self.key_file))
        self.rules(self.cloud_rules("aws", groups=[group], made={"exit": 254, "err": "RequestLimitExceeded"}))
        with self.assertRaises(Refused) as caught:
            self.call("cloud_step", **server)
        words = str(caught.exception)
        for said in ("ran and ended with 0", "RequestLimitExceeded", "costs money", "Call cloud_look"):
            self.assertIn(said, words)
        self.assertNotIn("Nothing was changed", words)
        (self.folder / "calls.jsonl").unlink()
        self.rules(self.cloud_rules("aws", groups=[group], made={"out": "<html>Bad gateway</html>"}))
        with self.assertRaises(Refused) as caught:
            self.call("cloud_step", **server)
        self.assertIn("not JSON", str(caught.exception))
        self.assertNotIn("nothing was changed", str(caught.exception).lower())
        (self.folder / "calls.jsonl").unlink()
        self.rules(self.cloud_rules("aws", groups=[group], made={"out": {"Reservations": []}}))
        answer = self.call("cloud_step", **server)
        self.assertIn("does not show", answer["did"])
        self.assertEqual((answer["next"]["tool"], answer["next"]["arguments"].get("step")), ("cloud_look", None))
        # close_ssh and cloud_remove: a read after their command fails
        (self.folder / "calls.jsonl").unlink()
        self.rules(self.cloud_rules("aws"))
        for step in ("firewall", "server", "open_ssh"):
            self.call("cloud_step", **self.base("aws"), step=step,
                      **{"server": {"ssh_public_key_file": str(self.key_file)},
                         "open_ssh": {"ssh_from": "203.0.113.9"}}.get(step, {}))
        failing = [{"has": [read], "after": [command], "exit": 254, "err": "ThrottlingException"}
                   for read, command in (("describe-security-group-rules", "revoke-security-group-ingress"),
                                         ("describe-instances", "terminate-instances"))]
        self.rules(failing + self.cloud_rules("aws"))
        for tool, step in (("cloud_step", "close_ssh"), ("cloud_remove", "server")):
            with self.assertRaises(Refused, msg=step) as caught:
                self.call(tool, **self.base("aws"), step=step)
            self.assertIn("ran and ended with 0", str(caught.exception), step)
            self.assertNotIn("nothing was changed", str(caught.exception).lower(), step)
        # a removal whose command fails: the same removal again when its cause is gone
        self.rules([{"has": ["delete-security-group"], "exit": 254, "err": "DependencyViolation"}] +
                   self.cloud_rules("aws"))
        with self.assertRaisesRegex(Refused, "DependencyViolation.*When the cause is gone, send the same "
                                             "cloud_remove again\\.$"):
            self.call("cloud_remove", **self.base("aws"), step="firewall")

    def test_a_server_in_a_subnet_is_read_and_removed_in_that_subnet(self):
        """A server made with subnet has its firewall in the subnet's network, so each call, cloud_remove too, reads
        that network and not the default one. Bug: the firewall in the company's network is "not there" for its
        removal and stays, or a region with no default VPC refuses each removal."""
        self.rules(self.cloud_rules("aws", vpcs={"Vpcs": []}) + self.cloud_rules("google") +
                   [{"has": ["sh -s"], "out": self.READING}])
        for cloud, subnet, network in (("aws", "subnet-0a1b2c3d4e5f67890", "Values=vpc-0fedcba987654321f"),
                                       ("google", "servers", "network~/company-net$")):
            done = self.walk(cloud, subnet=subnet)
            sent = [one for _t, _a, _r, calls in done for one in calls]
            self.assertFalse([one["line"] for one in sent if "describe-vpcs" in one["line"]], cloud)
            reads = [one for one in sent if "describe-security-groups" in one["line"] or "rules list" in one["line"]]
            self.assertTrue(reads and all(network in one["line"] for one in reads), cloud)
            self.assertTrue(any(self.starts(one["argv"], self.DELETES, self.NAME) and
                                ("delete-security-group" in one["line"] or "-closed" in one["line"]) for one in sent),
                            cloud)
            make = next(one["argv"] for one in sent if self.starts(one["argv"], self.CHANGES, self.NAME) and
                        ("run-instances" in one["line"] or "instances create" in one["line"]))
            self.assertIn(subnet, make, cloud)
        # a removal with no subnet finds nothing in the default network, and says to give the server's subnet
        self.rules(self.cloud_rules("aws"))
        self.assertIn("with the same subnet",
                      self.call("cloud_remove", **self.base("aws"), step="firewall")["did"])
        self.assertNotIn("same subnet", self.call("cloud_remove", **self.base("aws"), step="firewall",
                                                  subnet="subnet-0a1b2c3d4e5f67890")["did"])
        tool = next(t for t in owner_mcp.tools() if t["name"] == "cloud_remove")
        self.assertIn("Give the subnet that the server was made with", tool["description"])

    def test_the_program_is_found_in_absolute_folders_only(self):
        """`cloud_which` takes the cloud's program from an absolute folder of the PATH only: no PATH, an empty one, an
        empty part and a relative part are not the working folder, where `shutil.which` would find it. Bug: a file named
        aws in the AI client's working folder, which an agent or a cloned repository can write, runs with the admin's
        cloud login."""
        work = self.folder / "work"
        work.mkdir()
        (work / "aws").write_text("#!/bin/sh\necho x\n")
        (work / "aws").chmod(0o755)
        here = os.getcwd()
        os.chdir(work)
        self.addCleanup(os.chdir, here)
        for path in ("", ":", ".", "bin", "./"):
            with patch.dict(os.environ, {"PATH": path}):
                self.assertIsNone(owner_mcp.cloud_which("aws"), path)
        with patch.dict(os.environ, {"PATH": "."}):
            self.assertIsNotNone(shutil.which("aws"))           # the place that cloud_which does not take
        environment = {k: v for k, v in os.environ.items() if k != "PATH"}
        with patch.dict(os.environ, environment, clear=True):
            self.assertIsNone(owner_mcp.cloud_which("aws"))
        with patch.dict(os.environ, {"PATH": f"/no/such/folder::.:{self.folder}"}):
            self.assertEqual(owner_mcp.cloud_which("aws"), os.path.join(str(self.folder), "aws"))

    def test_ssh_is_found_in_absolute_folders_only(self):
        """`ssh` starts the ssh of an absolute folder of the PATH (`cloud_which`): an empty or a relative part before it
        is not the working folder, and with no absolute folder that holds ssh nothing starts. ssh gets the absolute
        folders of the PATH only (`absolute_path`). Bug: an empty or a relative part of the PATH before /usr/bin, and a
        program named ssh in the AI client's working folder, which an agent or a cloned repository can write, gets
        add_machine's Tailscale key on its standard input; or ssh gets that PATH, and the shell of a ProxyCommand of
        the owner's SSH configuration runs a program of that folder."""
        work = self.folder / "work"
        work.mkdir()
        took = work / "took"
        (work / "ssh").write_text(f"#!/bin/sh\ncat > '{took}'\n")
        (work / "ssh").chmod(0o755)
        secret = self.folder / "auth-key"
        secret.write_text("tskey-auth-example-only\n")
        here = os.getcwd()
        os.chdir(work)
        self.addCleanup(os.chdir, here)
        for path in (f":{self.folder}", f".:{self.folder}", f"./:{self.folder}"):
            with patch.dict(os.environ, {"PATH": path}), open(secret) as stdin:
                owner_mcp.ssh("server.example.invalid", "admin", "sh -s", stdin=stdin)
        for path in ("", ":", ".", "./"):
            with patch.dict(os.environ, {"PATH": path}), open(secret) as stdin, \
                    self.assertRaises(owner_mcp.Refused) as said:
                owner_mcp.ssh("server.example.invalid", "admin", "sh -s", stdin=stdin)
            self.assertIn("ssh is in no folder of the PATH", str(said.exception), path)
        self.assertFalse(took.exists(), "the ssh of the working folder got the key")
        calls = [json.loads(line) for line in open(self.folder / "calls.jsonl")]
        self.assertEqual([call["stdin"] for call in calls], ["tskey-auth-example-only\n"] * 3)
        # ssh's own PATH, which its shell searches for a ProxyCommand or a Match exec: the absolute folders only
        seen = self.folder / "seen"
        seen.mkdir()
        (seen / "ssh").write_text(f"#!/bin/sh\nprintf '%s' \"$PATH\" > '{seen / 'path'}'\n")
        (seen / "ssh").chmod(0o755)
        with patch.dict(os.environ, {"PATH": f":.:./bin:{seen}::{self.folder}:"}):
            owner_mcp.ssh("server.example.invalid", "admin", "sh -s")
        self.assertEqual((seen / "path").read_text(), f"{seen}:{self.folder}")

    def test_the_look_names_what_lets_any_cloud_program_in(self):
        """The notes of a look name what the recipe does not change and the admin must know: a Google Cloud rule that
        lets SSH in from every address before the recipe's rule that denies, and a role of AWS on a server that the
        company has already, which each program there can use. Bug: the server is open to everybody, or an agent there
        reaches the company's cloud, and nothing says so."""
        closed = {"name": f"founderizer-{self.NAME}-closed", "description": f"founderizer-server={self.NAME}"}
        wide = {"name": "allow-ssh-all", "direction": "INGRESS", "priority": 100, "sourceRanges": ["0.0.0.0/0"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["20-25"]}]}
        self.rules(self.cloud_rules("google", rules_now=[closed, wide]))
        notes = self.call("cloud_look", **self.base("google"))["notes"]
        self.assertTrue([n for n in notes if "allow-ssh-all" in n and "It wins over" in n], notes)
        role = "arn:aws:iam::123456789012:instance-profile/web"
        self.rules([{"has": ["describe-instances --instance-ids i-0123456789abcdef0"], "out": {"Reservations": [
            {"Instances": [{"State": {"Name": "running"}, "PublicIpAddress": "198.51.100.30",
                            "IamInstanceProfile": {"Arn": role}}]}]}}] + self.cloud_rules("aws"))
        seen = self.call("cloud_look", cloud="aws", instance="i-0123456789abcdef0", account="123456789012",
                         place="eu-central-1")
        self.assertTrue(any(role in n for n in seen["notes"]), seen["notes"])
        self.assertEqual((seen["next"]["arguments"]["step"], seen["next"]["arguments"]["host"]),
                         ("check", "198.51.100.30"))
        self.assertFalse([1 for one in self.sent() if self.starts(one["argv"], self.CHANGES + self.DELETES,
                                                                   self.NAME)])


if __name__ == "__main__":
    if sys.argv[1:] == ["--parity-fixture"]:
        PARITY_FIXTURE.write_text(parity_text())
        print(f"wrote {PARITY_FIXTURE.relative_to(HERE)}")
    else:
        unittest.main()
