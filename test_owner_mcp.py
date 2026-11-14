"""The owner's own MCP server (`owner_mcp.py`), against a fixture hub and never against a real fleet.

The whole claim of that server is that an agent with nothing but it can take a fleet from nothing to a machine with
an agent on it, and then read every check. `FromNothing` proves exactly that, end to end: a real MCP client over
standard input and output, the real claim listener of `hubsetup.py`, the real owner API of `hub.py` in process, and
the real join route for the machine that joins. `Install` proves the install path with a stand-in `ssh` that answers
as a machine does, because no test provisions a server, and `RootThroughSudo` runs the install and the join on the
stand-in server of test_hub_install, also as a user who is not root. `Refusals` and `NoSecret` prove what the server
must not do.
"""
import contextlib
import json
import os
import pathlib
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
import urllib.error
import uuid
from unittest.mock import patch

import hashlib

import hub
import hubsetup
import owner_mcp
from test_hub_install import StandInServer
from test_servers import NEW, OWNER, STUDIO, Servers

HERE = pathlib.Path(__file__).resolve().parent
SHELLS = [sh for sh in ("/bin/sh", "/bin/dash") if os.access(sh, os.X_OK)]     # this machine's, Debian's and Ubuntu's


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(cls(name) for cls in (Admin, Boundary, FromNothing, McpServers, Refusals,
                                                    Install, Progress, RootThroughSudo, NoSecret, Shape)
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

    def __init__(self, test, hub_base=None, path=None, every=None):
        self.home = pathlib.Path(tempfile.mkdtemp(prefix="fleet-owner-mcp-"))
        test.addCleanup(shutil.rmtree, str(self.home), True)
        env = dict(os.environ, HOME=str(self.home))
        env.pop("FOUNDERIZER_HUB", None)
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
            self.assertRegex(src, r"parts(?:\[:\d\])?\s*==\s*\[" + re.escape(parts) + r"\]",
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
        read as an empty fleet instead of a mistake, so the dispatch itself is the check."""
        dispatch = (HERE / "hub.py").read_text()
        for page, (path, about) in owner_mcp.PAGES.items():
            parts = [p for p in path.replace("{id}", "1").split("/") if p]
            self.assertTrue(about.strip(), page)
            found = re.search(r'parts == \[' + ", ".join(f'"{p}"' for p in parts) + r'\]', dispatch) or \
                re.search(r'parts\[:\d\] == \[' + ", ".join(f'"{p}"' for p in parts[:2]) + r'\]', dispatch)
            self.assertTrue(found, f"{page}: the hub has no GET route {path}")

    def test_without_a_hub_every_tool_says_how_to_get_one(self):
        client = self.client(hub_base=None)
        client.start()
        self.assertIsNone(client.call("which_hub")["hub"])
        for name in ("fleet_overview", "fleet_read", "send_message", "take_release"):
            with self.assertRaises(Refused) as caught:
                client.call(name, page="state", text="x", need=1)
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
                           reports_to="manager")
        self.assertEqual((made["agent"], made["server"], made["runtime"]), ("scout", "mini", "claude"))
        self.assertEqual(self.origin_team()["agents"]["scout"]["machine"], "mini")
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
        self.assertIn("Scout cannot be activated yet.", str(caught.exception))
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
            if page == "agent_messages":
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
                              "chat_apps", "devices", "goal", "responsibility", "agent_messages", "notes"},
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
            "title": "Which card", "why": "the shop needs one", "what_to_do": "name the card"})
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
        self.assertIn("one paying customer this month", hub.t_read_messages("manager", {}))

        answered = client.call("answer_needs_you", need=need, answer="The company card.")
        self.assertTrue(answered["ok"])
        self.assertEqual(hub.q1("SELECT answer FROM needs WHERE id=?", (need,))["answer"], "The company card.")

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
            "kind": "api_key", "env": "SHOP_API_KEY", "why": "the shop's orders", "give_to": {"vps": "use"}})
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
        client = self.started()
        where = pathlib.Path(tempfile.mkdtemp(prefix="fleet-copy-"))
        self.addCleanup(shutil.rmtree, str(where), True)
        taken = client.call("take_backup", path=str(where))
        saved = pathlib.Path(taken["path"])
        self.assertTrue(saved.exists())
        self.assertEqual(saved.stat().st_size, taken["bytes"])
        self.assertEqual(hashlib.sha256(saved.read_bytes()).hexdigest(), taken["sha256"])
        self.assertEqual(hub.kv_get("backup_sha256"), taken["sha256"])
        self.assertEqual(client.call("fleet_read", page="health")["backup"]["sha256"], taken["sha256"])

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
        self.assertIn("Read the fleet again", str(caught.exception))
        self.assertIn("team.json", str(caught.exception))
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
                ("answer_needs_you", {"need": 999, "answer": "x"}, "does not exist")):
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
        for route in ("/ui/releases/entitlement", "/ui/github-app", "/ui/secrets/add", "/ui/secrets/fingerprints",
                      "/ui/google/connect", "/ui/google/finish", "/ui/mcp/connect", "/ui/mcp/finish",
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

        def claim(listener, code):
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

            def run(line, stdin=None, capture_output=False, text=False, timeout=None, stop=stop, user=user, uid=uid,
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

            def run(line, stdin=None, capture_output=False, text=False, timeout=None, stop=stop, user=user, uid=uid,
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

        def run(line, stdin=None, capture_output=False, text=False, timeout=None):
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

            def run(line, stdin=None, capture_output=False, text=False, timeout=None, at_host=at_host,
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

        def run(line, stdin=None, capture_output=False, text=False, timeout=None):
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

    def test_it_saves_a_server_changes_it_and_removes_it_from_the_fleet(self):
        client = self.started()
        receipt = client.call("save_mcp_server", name="crm", server=self.URL)
        self.assertEqual(receipt["name"], "crm")
        self.assertEqual(self.saved()["crm"]["url"], self.URL["url"])
        self.assertEqual(self.saved()["crm"]["title"], "The CRM")

        client.call("save_mcp_server", name="crm", server=dict(self.URL, title="The CRM, renamed"))
        self.assertEqual(self.saved()["crm"]["title"], "The CRM, renamed")

        gone = client.call("save_mcp_server", name="crm", delete=True)
        self.assertTrue(gone["deleted"])
        self.assertEqual(self.saved(), {})

    def test_an_entry_the_hub_refuses_comes_back_in_the_hubs_own_words_and_saves_nothing(self):
        client = self.started()
        for server, says in (({"title": "Both", "url": "https://a.example.com/mcp", "command": "x"}, "not both"),
                             ({"title": "No place"}, "needs a url"),
                             ({"title": "Bad address", "url": "ftp://a.example.com"}, "must be an https address"),
                             ({"url": "https://a.example.com/mcp"}, "needs a title")):
            with self.assertRaises(Refused) as caught:
                client.call("save_mcp_server", name="crm", server=server)
            self.assertIn(says, str(caught.exception), server)
        with self.assertRaises(Refused) as caught:
            client.call("save_mcp_server", name="fleet", server=self.URL)
        self.assertIn("Fleet's own", str(caught.exception))
        self.assertEqual(self.saved(), {})

    def test_a_server_that_moved_under_the_command_is_the_hubs_own_conflict(self):
        """It carries the SHA-256 of the team.json it was built on, so a change that arrived meanwhile is a 409 and
        never a silent overwrite of somebody else's entry."""
        client = self.started()
        client.call("save_mcp_server", name="crm", server=self.URL)
        with patch.object(owner_mcp, "team", lambda: dict(owner_mcp.get("/ui/team", "x").data, sha256="0" * 64)):
            with self.assertRaises(Refused) as caught:
                self.direct("save_mcp_server", name="notes",
                            server={"title": "Notes", "command": "notes-mcp"})
        self.assertIn("changed meanwhile", str(caught.exception))
        self.assertEqual(list(self.saved()), ["crm"])


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
        receipt = client.call("save_profile", agent="studio", sections=sections)
        self.assertNotEqual(receipt.get("sha256"), before["sha256"])
        after = next(p for p in client.call("fleet_read", page="profiles")["profiles"] if p["agent"] == "studio")
        self.assertIn("Careful, and quick.", after["text"])

        notes = client.call("fleet_read", page="notes", agent="studio")
        self.assertEqual(notes["agent"], "studio")
        self.assertNotIn("save_notes", {t["name"] for t in owner_mcp.tools()})      # the agent's own, never written
        with self.assertRaises(Refused) as caught:
            client.call("fleet_read", page="notes", agent="nobody")
        self.assertIn("(404)", str(caught.exception))

    def test_it_sets_the_reporting_lines_so_a_worker_reports_to_a_lead(self):
        client = self.started()
        lines = [{"agent": l["agent"], "role": l["agent"] == "lead" and "lead" or l["role"],
                  "reports_to": "lead" if l["agent"] == "vps" else l.get("reports_to")}
                 for l in client.call("fleet_read", page="team")["lines"]]
        client.call("set_reporting_lines", lines=lines)
        self.assertEqual(self.team_file()["agents"]["vps"]["reports_to"], "lead")
        self.assertEqual(self.team_file()["agents"]["lead"]["role"], "lead")

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

    ADMIN = {"title": "Founderizer admin", "command": "python3"}     # an owner server takes no args (plan 0.2)

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


if __name__ == "__main__":
    unittest.main()
