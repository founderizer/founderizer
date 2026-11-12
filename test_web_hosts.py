"""The host list of an agent whose Shell box is off (team.json "web_hosts"): the form of an entry, the hook that stops
a page read on a host that is not listed, the closed start that carries the list, and the hub's side: the owner's
write, its refusals, the start event and the start text. The proof in a real Claude Code session is
test_web_hosts_live.

The helper side builds real commands in a temporary folder; the hub side runs an in-process hub with its HTTP server,
a temporary database and a repository of its own for team.json. No AI, no network."""
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import fleet
import hook_hosts
import hub
import lifecycle
import test_shell_box
from test_release_turns import helper_reports
from test_setup import git

HOSTS = ["docs.example.com", "*.example.org"]
RULES = ["WebFetch(domain:docs.example.com)", "WebFetch(domain:example.org)", "WebFetch(domain:*.example.org)"]
PROVED = lifecycle.HOST_LIST_VERSIONS[0]
WORDS = "docs.example.com; example.org and every host below it"


def load_tests(loader, _tests, _pattern):
    """Only the cases that each class of this file defines itself: Start and Hub take their fixtures from
    test_shell_box, whose own cases run there."""
    suite = unittest.TestSuite()
    for cls in (Form, Hook, Start, Hub):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class Form(unittest.TestCase):
    def test_an_entry_is_a_host_name_or_a_host_with_every_host_below_it(self):
        for host in ("docs.example.com", "example.com", "*.example.com", "a-b.example.co.uk", "*.a.b.example.org",
                     "xn--bcher-kva.example", "1password.example", "0x7f.example.com", "docs.example.b9"):
            with self.subTest(host):
                self.assertEqual(lifecycle.web_hosts([host]), [host])
        for host in ("*", "*.com", "com", "example", "Example.com", "example.com.", "example.com:443",
                     "https://example.com", "example.com/path", "10.0.0.5", "*.10.0.0.5", "a..example.com",
                     "-a.example.com", "a-.example.com", "*.*.example.com", "*example.com", "ex ample.com",
                     "exa_mple.com", "", "*.", ".example.com", "example.com\n", "a." + "b" * 80 + ".com", None, 5,
                     # an address in numbers as a browser also reads one: 127.0.0.1, 1.0.0.0, 127.0.0.1
                     "127.0x1", "1.0x0", "0x7f.0x1", "example.0x1", "example.1a", "d\u00f6cs.example.com"):
            with self.subTest(host), self.assertRaises(ValueError):
                lifecycle.web_hosts([host])

    def test_a_list_has_one_to_twenty_different_hosts(self):
        most = [f"h{n}.example.com" for n in range(lifecycle.WEB_HOSTS_MOST)]
        self.assertEqual(lifecycle.web_hosts(most), most)
        for value in ([], most + ["one-more.example.com"], ["a.example.com", "a.example.com"], "a.example.com", None,
                      {"a.example.com": True}):
            with self.subTest(value), self.assertRaises(ValueError) as refused:
                lifecycle.web_hosts(value)
            self.assertEqual(str(refused.exception), lifecycle.WEB_HOSTS_FORM)


class Hook(unittest.TestCase):
    """hook_hosts.py reads one address as plain text. Each form that a browser's reading could give another host than
    this one is stopped, because Claude Code reads the address as a browser does."""

    def call(self, url, tool="WebFetch"):
        return hook_hosts.refusal({"hook_event_name": "PreToolUse", "tool_name": tool,
                                   "tool_input": {"url": url, "prompt": "What is the heading?"}}, HOSTS)

    def test_a_page_on_a_listed_host_passes(self):
        for url in ("https://docs.example.com", "https://docs.example.com/", "https://docs.example.com/a/b?c=d#e",
                    "http://docs.example.com/a", "HTTPS://DOCS.Example.COM/a", "https://docs.example.com:8443/a",
                    "https://docs.example.com./a", "https://docs.example.com?x=1", "https://docs.example.com#top",
                    "https://example.org/", "https://a.example.org/", "https://a.b.example.org/x",
                    "https://docs.example.com/back\\@other.example.net", "https://docs.example.com/?u=@other.example.net"):
            with self.subTest(url):
                self.assertIsNone(self.call(url))

    def test_a_page_on_another_host_is_stopped(self):
        for url, host in (("https://other.example.net/", "other.example.net"),
                          ("https://example.com/", "example.com"),                  # the list has only docs.
                          ("https://a.docs.example.com/", "a.docs.example.com"),    # an exact entry covers no host below
                          ("https://notexample.org/", "notexample.org"),            # not below example.org
                          ("https://example.org.other.example.net/", "example.org.other.example.net"),
                          ("https://docs.python.org/3/", "docs.python.org"),        # one of Claude Code's own hosts
                          ("https://OTHER.example.net/", "other.example.net")):
            with self.subTest(url):
                self.assertEqual(self.call(url), f"{host} is not on the list")

    def test_an_address_that_two_readers_can_read_as_two_hosts_is_stopped(self):
        plain = "its address does not have the plain form https://<host>/<path>"
        for url in ("https://other.example.net\\@docs.example.com/",       # a browser: host other.example.net
                    "https://docs.example.com@other.example.net/",          # a user name, then the host
                    "https://docs.example.com:443@other.example.net/",
                    "https://docs.example.com\\.other.example.net/",
                    "https://docs.example.com%2eother.example.net/", "https://docs%2eexample.com/",
                    "https://docs.example.com\t.other.example.net/", "https://docs.example.com\n.other.example.net/",
                    "https:docs.example.com/", "https:/docs.example.com/", "https:///docs.example.com/",
                    " https://docs.example.com/", "ftp://docs.example.com/", "//docs.example.com/",
                    "docs.example.com/", "https://docs.example.com../", "https://[::1]/", "https://döcs.example.com/",
                    # letters that "ignore case" takes for s, k and i when it is not held to ASCII
                    "https://doc\u017f.example.com/", "https://doc\u017f.example.org/", "https://\u212a.example.org/",
                    "https://\u0131.example.org/", "https://\u0130.example.org/", "http\u017f://docs.example.com/",
                    "https://docs.example.com:port/", "", None, 5, ["https://docs.example.com/"]):
            with self.subTest(url):
                self.assertEqual(self.call(url), plain)

    def test_input_that_is_no_page_read_is_not_its_own_and_input_that_it_cannot_read_is_stopped(self):
        self.assertIsNone(self.call("https://other.example.net/", tool="WebSearch"))
        for data in (None, [], "WebFetch", {}, {"tool_name": 5}, {"tool_input": {"url": "https://docs.example.com/"}}):
            with self.subTest(data):
                self.assertEqual(hook_hosts.refusal(data, HOSTS), "the call could not be read")
        self.assertEqual(hook_hosts.refusal({"tool_name": "WebFetch"}, HOSTS),
                         "its address does not have the plain form https://<host>/<path>")
        self.assertEqual(hook_hosts.refusal({"tool_name": "WebFetch", "tool_input": "https://docs.example.com/"}, HOSTS),
                         "its address does not have the plain form https://<host>/<path>")

    def test_the_command_of_the_hook_stops_with_2_and_any_fault_of_it_stops_too(self):
        """The command as the helper writes it into a session's settings, run as Claude Code runs it: by a shell, with
        the call on its input. 0 lets the call go on to the session's rules; 2 stops it with the words on stderr."""
        root = Path(tempfile.mkdtemp(prefix="fleet-web-hosts-"))
        self.addCleanup(shutil.rmtree, root, True)
        entry = fleet.hosts_hook(HOSTS)
        self.assertEqual((entry["matcher"], len(entry["hooks"])), ("WebFetch", 1))
        self.assertEqual({k: v for k, v in entry["hooks"][0].items() if k != "command"},
                         {"type": "command", "timeout": 60, "onFailure": "block"})     # no "async": it must decide
        command = entry["hooks"][0]["command"]
        self.assertIn(os.path.join(fleet.KIT, "hook_hosts.py"), command)
        self.assertTrue(command.endswith(" docs.example.com '*.example.org' || exit 2"), command)
        call = lambda url: json.dumps({"tool_name": "WebFetch", "tool_input": {"url": url}})
        run = lambda command, text: subprocess.run(["sh", "-c", command], input=text, capture_output=True, text=True,
                                                   cwd=root, timeout=60)
        passed = run(command, call("https://a.example.org/page"))
        self.assertEqual((passed.returncode, passed.stdout, passed.stderr), (0, "", ""))
        stopped = run(command, call("https://other.example.net/page"))
        self.assertEqual((stopped.returncode, stopped.stdout), (2, ""))
        self.assertEqual(stopped.stderr, hook_hosts.STOPPED.format(why="other.example.net is not on the list",
                                                                   hosts="docs.example.com, *.example.org"))
        for text in ("", "not json", "[]", "\xff"):
            with self.subTest(text):
                self.assertEqual(run(command, text).returncode, 2)
        with patch.object(fleet, "KIT", str(root / "no-checkout")):          # a checkout without the program
            missing = fleet.hosts_hook(HOSTS)["hooks"][0]["command"]
        self.assertEqual(run(missing, call("https://a.example.org/page")).returncode, 2)
        self.assertEqual(run(command.replace(shlex.quote(fleet.sys.executable), "no-such-python-here", 1),
                             call("https://a.example.org/page")).returncode, 2)
        self.assertEqual(os.listdir(root), [])

    def test_the_hook_is_a_file_that_no_session_edits(self):
        self.assertIn("hook_hosts.py", fleet.PROTECTED)
        self.assertIn("web_hosts", lifecycle.FEATURES)


class Start(test_shell_box.Helper):
    """The closed start of a task session (fleet.closed_task_command), with the host list that the hub's start names."""

    def setUp(self):
        super().setUp()
        self.proved = self.kept / f"claude-{PROVED}"
        self.proved.write_text("#!/bin/sh\n")
        self.proved.chmod(0o755)

    def start(self, conf=test_shell_box.DESK, **closed):
        words = shlex.split(self.build(conf, closed=dict({"version": PROVED, "built_ins": ["WebSearch", "WebFetch"],
                                                          "web_hosts": HOSTS}, **closed)))
        option = lambda name: words[words.index(name) + 1]
        return words, option, json.loads(option("--settings"))

    def test_a_start_with_a_host_list_reads_pages_only_on_its_hosts(self):
        words, option, settings = self.start()
        self.assertIn(str(self.proved), words)
        self.assertEqual(option("--tools"), "WebSearch,WebFetch")
        self.assertEqual(option("--permission-mode"), "dontAsk")        # what no rule names is refused
        allow = settings["permissions"]["allow"]
        self.assertEqual([rule for rule in allow if "WebFetch" in rule], RULES)
        self.assertNotIn("WebFetch", allow)                 # the bare name would open every host
        self.assertIn("WebSearch", allow)
        self.assertEqual(settings["hooks"]["PreToolUse"], [fleet.hosts_hook(HOSTS)])
        self.assertEqual(settings["hooks"]["PreToolUse"][0]["matcher"], "WebFetch")
        self.assertIs(settings["skipWebFetchPreflight"], True)
        self.assertEqual(len(settings["hooks"]["PostToolUse"]), 2)      # the activity hook and the clean hook, as before

    def test_a_start_without_a_host_list_has_no_page_read_as_before(self):
        for closed in ({"built_ins": ["WebSearch"]}, {"built_ins": ["WebSearch", "WebFetch"]}, None,
                       {"built_ins": ["WebSearch", "WebFetch"], "web_hosts": None}):
            with self.subTest(closed):
                _, args, option = self.parts(self.build(closed=closed))
                settings = json.loads(option("--settings"))
                self.assertEqual(option("--tools"), "WebSearch")
                self.assertEqual([rule for rule in settings["permissions"]["allow"] if "WebFetch" in rule], [])
                self.assertEqual(sorted(settings["hooks"]), ["PostToolUse", "PostToolUseFailure"])
                self.assertNotIn("skipWebFetchPreflight", settings)
        # the hosts alone give no page read: the hub's start names the tool too, and this checkout's Web box is on
        for conf, closed in ((test_shell_box.DESK, {"built_ins": ["WebSearch"]}),
                             (test_shell_box.DESK, {"built_ins": []}),
                             (dict(test_shell_box.DESK, can=[]), {})):
            with self.subTest(conf=conf, closed=closed):
                _, option, settings = self.start(conf, **closed)
                self.assertNotIn("WebFetch", option("--tools"))
                self.assertEqual([rule for rule in settings["permissions"]["allow"] if "WebFetch" in rule], [])
                self.assertNotIn("PreToolUse", settings["hooks"])
                self.assertNotIn("skipWebFetchPreflight", settings)

    def test_a_start_that_this_helper_cannot_hold_to_its_hosts_starts_nothing(self):
        for hosts in ([], ["*"], ["*.com"], ["https://docs.example.com"], "docs.example.com", ["Docs.example.com"],
                      ["docs.example.com", "docs.example.com"], [f"h{n}.example.com" for n in range(21)], [5], {}):
            with self.subTest(hosts), self.assertRaises(fleet.Refused) as refused:
                self.start(web_hosts=hosts)
            self.assertIn(lifecycle.WEB_HOSTS_FORM, str(refused.exception))
        self.assertNotIn("2.1.308", lifecycle.HOST_LIST_VERSIONS)
        for closed in ({"version": "2.1.308"}, {"version": None}):      # None: the first version of closed sessions
            with self.subTest(closed), self.assertRaises(fleet.Refused) as refused:
                self.start(**closed)
            self.assertIn("passed the host list's test", str(refused.exception))
            self.assertIn("2.1.308", str(refused.exception))
        with self.assertRaises(fleet.Refused) as refused:   # a task from before the list, with the Browser box on
            shlex.split(self.build(dict(test_shell_box.DESK, can=["web", "browser"]), needs="browser",
                                   closed={"version": PROVED, "built_ins": ["WebSearch", "WebFetch"],
                                           "web_hosts": HOSTS}))
        self.assertEqual(str(refused.exception),
                         "a session with a host list has no browser task: its browser would open every host")
        self.assertFalse(self.sessions.exists())            # and no file of a session that did not start

    def test_the_longest_host_list_fits_a_tmux_command(self):
        longest = ["*." + f"h{n:02d}." + "a" * 36 + "." + "b" * 35 + ".com" for n in range(lifecycle.WEB_HOSTS_MOST)]
        self.assertEqual({len(h) for h in longest}, {82})   # "*." and a name of 80 characters, the longest entry
        words, option, settings = self.start(web_hosts=longest)
        self.assertEqual(len([rule for rule in settings["permissions"]["allow"] if "WebFetch" in rule]), 40)
        self.assertLess(len(shlex.join(words)), 12000)      # tmux refuses 16 KiB and more


TEAM = dict(json.loads(json.dumps(test_shell_box.TEAM)), hub={"machine": "hub"})
for entry in TEAM["agents"].values():       # no vault here: a broker's entry needs its key, which this file does not test
    entry.pop("vault", None)


class Hub(test_shell_box.Fleet):
    """The hub: the owner's write through its route, team.json in a repository of this test, and the starts."""

    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp(prefix="fleet-web-hosts-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        seed = self.root / "seed"
        seed.mkdir()
        (seed / "team.json").write_text(json.dumps(TEAM, indent=2) + "\n")
        git("init", "-q", str(seed))
        git("add", "-A", cwd=seed)
        git("-c", "commit.gpgsign=false", "commit", "-q", "-m", "seed", cwd=seed)
        git("clone", "-q", "--bare", str(seed), str(self.root / "origin.git"))
        git("clone", "-q", str(self.root / "origin.git"), str(self.root / "kit"))
        self.kit = self.root / "kit"
        hub.CFG["team_path"] = str(self.kit / "team.json")
        self.addCleanup(hub.CFG.pop, "team_path", None)
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = json.loads(json.dumps(TEAM))
        for name in hub.TEAM["agents"]:
            helper_reports(name, *test_shell_box.FEATURES, "web_hosts")

    def write(self, agent="desk", **body):
        sha = self.request("/ui/team?db=test-generation")[1]["sha256"]
        return self.request(f"/ui/team/agents/{agent}", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                             base_sha256=sha, **body))

    def stored(self, agent="desk"):
        return json.loads(git("show", "HEAD:team.json", cwd=self.kit))["agents"][agent]

    def line(self, agent="desk"):
        return next(l for l in self.request("/ui/team?db=test-generation")[1]["lines"] if l["agent"] == agent)

    def started(self, agent="desk", **fields):
        tid, _ = self.task(agent, **fields)
        event = json.loads(hub.q1("SELECT extra FROM events WHERE kind='task' AND task=?", (tid,))["extra"])
        return event.get("shell_off"), hub.start_text(agent, tid)

    def test_the_owner_gives_an_agent_whose_shell_box_is_off_a_host_list(self):
        before, text = self.started()
        self.assertEqual(before, {"runtime": "claude", "version": hub.CLOSED_TESTED, "built_ins": ["WebSearch"],
                                  "servers": None})
        self.assertNotIn("host list", text)
        self.assertFalse(any("web pages" in fact for fact in hub.colleague_facts("desk")))
        # a conversation of such an agent is always closed: it has no web tool, so no start of one names a list
        with patch.object(hub, "person_access", lambda person: {"tools": True}):     # a role with its tools on
            self.assertFalse(hub.conversation_works({"name": "Ana"}, "desk"))
            self.assertTrue(hub.conversation_works({"name": "Ana"}, "ops"))
        self.assertEqual(self.line()["web_hosts"], [])
        code, data = self.write(web_hosts=HOSTS)
        self.assertEqual(code, 200, data)
        self.assertEqual(data["changed"], [{"field": "web_hosts", "before": [], "after": HOSTS}])
        self.assertNotIn("also_changed", data)
        self.assertEqual(data["updates_requested"], [])     # the list comes with each start: its helper loads nothing
        self.assertEqual(self.stored()["web_hosts"], HOSTS)
        self.assertEqual(self.line()["web_hosts"], HOSTS)
        told = [e["text"] for e in hub.q("SELECT text FROM events WHERE agent='manager' AND kind='say'")]
        self.assertIn(f"[hub] The owner changed desk: its page reads now open only on: {WORDS}.", told)
        # each start names the hosts and the page tool, at a version that passed the host list's own test
        self.assertNotIn(hub.CLOSED_TESTED, lifecycle.HOST_LIST_VERSIONS)
        shell_off, text = self.started()
        self.assertEqual(shell_off, {"runtime": "claude", "version": PROVED, "built_ins": ["WebSearch", "WebFetch"],
                                     "servers": None, "web_hosts": HOSTS})
        self.assertIn(f" Your page reads (WebFetch) open only on the hosts of your host list: {WORDS}. A page on "
                      f"another host does not open, also when a web search names it or a listed page sends you to it "
                      f"(only a listed host's own www. name opens that way): do not try another address for it. Web "
                      f"search itself is not limited by the list.", text)
        other = lifecycle.HOST_LIST_VERSIONS[1]
        hub.TEAM["settings"]["conversations.closed_version"] = other    # the owner's version, where it passed too
        self.assertEqual(self.started()[0]["version"], other)
        # what the manager and each colleague read about this agent in every later start, and about no other agent
        self.assertIn("reads web pages only on docs.example.com, *.example.org", hub.colleague_facts("desk"))
        self.assertFalse(any("web pages" in fact for fact in hub.colleague_facts("ops")))
        self.assertIn("reads web pages only on docs.example.com, *.example.org", hub.team_start_text("manager"))
        # a duty that names its tools and no web search: no page read either, and the version of closed sessions
        review = self.duty(watch=[{"kind": "clock", "schedule": test_shell_box.EVERY}], tools=["remember"])
        shell_off, text = self.started(responsibility=review["id"])
        self.assertEqual(shell_off, {"runtime": "claude", "version": other, "built_ins": [], "servers": None})
        self.assertNotIn("host list", text)
        ticket = self.duty(watch=[{"kind": "clock", "schedule": test_shell_box.EVERY}], tools=["WebSearch"])
        self.assertEqual(self.started(responsibility=ticket["id"])[0]["built_ins"], ["WebSearch", "WebFetch"])
        # the same list again changes nothing, and [] removes it
        self.assertEqual(self.write(web_hosts=HOSTS)[1]["changed"], [])
        code, data = self.write(web_hosts=[])
        self.assertEqual((code, data["changed"]), (200, [{"field": "web_hosts", "before": HOSTS, "after": []}]))
        self.assertNotIn("web_hosts", self.stored())
        self.assertEqual(self.started()[0], {"runtime": "claude", "version": hub.CLOSED_TESTED,     # as before
                                             "built_ins": ["WebSearch"], "servers": None})
        self.assertFalse(any("web pages" in fact for fact in hub.colleague_facts("desk")))

    def test_a_host_list_is_refused_where_no_session_can_be_held_to_it(self):
        sha = self.request("/ui/team?db=test-generation")[1]["sha256"]
        for agent, body, why in (
                ("ops", {}, "has its Shell box on: its shell reaches every host, so a host list would limit nothing."),
                ("cx", {}, "runs on Codex, which cannot be held to a fixed list of tools, so no session of it can be "
                           "held to a list of hosts."),
                ("manager", {}, "is the fleet manager, whose session is not closed: only a worker or a lead gets a "
                                "host list."),
                ("desk", {"can": []}, "has its Web box off: its sessions have no web tool, so there is nothing for a "
                                      "host list to limit."),
                ("desk", {"can": ["shell", "web"]}, "has its Shell box on: its shell reaches every host, so a host "
                                                    "list would limit nothing."),
                ("desk", {"can": ["web", "browser"]}, "has its Browser box on: a browser task of it opens every host, "
                                                      "so a host list would not hold.")):
            with self.subTest(agent=agent, body=body):
                code, data = self.write(agent, web_hosts=HOSTS, **body)
                self.assertEqual((code, data["error"]), (409, f"{hub.shown_role(agent)} {why}"))
        helper_reports("desk", *test_shell_box.FEATURES)            # a helper from before this release
        code, data = self.write(web_hosts=HOSTS)
        self.assertEqual((code, data["error"]), (409, f"{hub.shown_role('desk')} cannot hold a host list yet. Update "
                                                      f"Founderizer on its server first."))
        for bad in (["*"], ["*.com"], ["https://docs.example.com"], ["Docs.example.com"], ["10.0.0.5"], "docs.example.com",
                    ["docs.example.com", "docs.example.com"], [f"h{n}.example.com" for n in range(21)], {}, 5):
            with self.subTest(bad):
                code, data = self.write(web_hosts=bad)
                self.assertEqual((code, data["error"]), (400, f"web_hosts must be {lifecycle.WEB_HOSTS_FORM}, or [] "
                                                              f"for none"))
        self.assertEqual(self.request("/ui/team?db=test-generation")[1]["sha256"], sha)      # nothing was written
        self.assertNotIn("web_hosts", self.stored())

    def test_an_open_browser_task_from_before_holds_the_list_back(self):
        """A task that was made while the Browser box was on keeps its browser: its next attempt would start with
        Chrome, which no list holds. So the list waits until that task has ended."""
        hub.TEAM["agents"]["desk"]["can"] = ["web", "browser"]      # the Browser box was on when the task was made
        tid, _ = self.task("desk", needs="browser")
        hub.TEAM["agents"]["desk"]["can"] = ["web"]                 # and the owner turned it off, as team.json has it
        code, data = self.write(web_hosts=HOSTS)
        self.assertEqual((code, data["error"], data["open_tasks"]),
                         (409, f"{hub.shown_role('desk')} has an open browser task, whose browser opens every host; "
                               f"finish or cancel it first.", [tid]))
        self.assertNotIn("web_hosts", self.stored())
        with hub.transaction():
            hub.DB.execute("UPDATE tasks SET state='canceled' WHERE id=?", (tid,))
        self.assertEqual(self.write(web_hosts=HOSTS)[0], 200)
        self.assertEqual(self.stored()["web_hosts"], HOSTS)

    def test_the_default_access_of_a_mac_gives_no_browser_to_an_agent_with_a_list(self):
        """A Mac's browser by default would end the list, and team.json would refuse the commit whole: the agent's
        default vault with it. So the desktop is left out for such an agent, and its vault is given."""
        self.assertEqual(self.write(web_hosts=HOSTS)[0], 200)
        key = "age1" + "q" * 58
        with patch.object(hub, "server_kind_of", lambda team, machine: "mac"), \
                patch.object(hub, "mac_chatgpt", lambda machine: True), \
                patch.object(hub, "vault_grant", lambda name, team: {"ready": True}), \
                patch.object(hub, "offered_store", lambda team, machine: key):
            hub.give_defaults("desk", True, True)
            self.assertEqual((self.stored()["vault"], self.stored()["can"], self.stored()["web_hosts"]),
                             ("broker", ["web"], HOSTS))
            # and an agent with no list gets its Mac's desktop as before
            self.assertEqual(self.write(web_hosts=[])[0], 200)
            hub.give_defaults("desk", False, True)
            self.assertIn("browser", self.stored()["can"])

    def test_a_box_that_leaves_nothing_for_the_list_to_limit_removes_it_in_the_same_write(self):
        for can in (["shell", "web"], [], ["web", "browser"]):
            with self.subTest(can):
                self.assertEqual(self.write(web_hosts=HOSTS)[0], 200)
                code, data = self.write(can=can)
                self.assertEqual(code, 200, data)
                # the app of today checks `changed` against the boxes that it sent, so the removal is said apart
                self.assertEqual(data["changed"], [{"field": "can", "before": ["web"], "after": can}])
                self.assertEqual(data["also_changed"], [{"field": "web_hosts", "before": HOSTS, "after": []}])
                self.assertNotIn("web_hosts", self.stored())
                self.assertEqual(self.stored()["can"], can)
                told = [e["text"] for e in hub.q("SELECT text FROM events WHERE agent='manager' AND kind='say'")]
                self.assertIn(f"[hub] The owner changed desk: it can now: {', '.join(can) or 'nothing'}; its host list "
                              f"is removed.", told)
                self.assertEqual(self.write(can=["web"])[0], 200)       # the Shell box off again: no list comes back
                self.assertNotIn("web_hosts", self.stored())
        # a change of the boxes that leaves the list its conditions keeps the list
        self.assertEqual(self.write(web_hosts=HOSTS)[0], 200)
        code, data = self.write(can=["web", "screen"])
        self.assertEqual(data["changed"], [{"field": "can", "before": ["web"], "after": ["web", "screen"]}])
        self.assertNotIn("also_changed", data)
        self.assertEqual(self.stored()["web_hosts"], HOSTS)
        # a write that names the list says its change in `changed`, as every field that a write names
        code, data = self.write(web_hosts=[], can=["web"])
        self.assertEqual(sorted(c["field"] for c in data["changed"]), ["can", "web_hosts"])
        self.assertNotIn("also_changed", data)

    def test_team_json_takes_a_host_list_only_in_its_form_and_only_where_it_limits_something(self):
        def team(agent="desk", **changes):
            t = json.loads(json.dumps(TEAM))
            t["agents"][agent].update(changes)
            return t
        hub.validate_team(team(web_hosts=HOSTS))
        for changes, why in ((dict(web_hosts=[]), "agent desk: web_hosts must be " + lifecycle.WEB_HOSTS_FORM + ", or absent"),
                             (dict(web_hosts=["*"]), "agent desk: web_hosts must be " + lifecycle.WEB_HOSTS_FORM + ", or absent"),
                             (dict(web_hosts=None), "agent desk: web_hosts must be " + lifecycle.WEB_HOSTS_FORM + ", or absent"),
                             (dict(web_hosts=HOSTS, can=["shell", "web"]), "agent desk has its Shell box on: its shell "
                              "reaches every host, so a host list would limit nothing"),
                             (dict(web_hosts=HOSTS, can=[]), "agent desk has its Web box off: its sessions have no web "
                              "tool, so there is nothing for a host list to limit"),
                             (dict(web_hosts=HOSTS, can=["web", "browser"]), "agent desk has its Browser box on: a "
                              "browser task of it opens every host, so a host list would not hold")):
            with self.subTest(changes), self.assertRaises(ValueError) as refused:
                hub.validate_team(team(**changes))
            self.assertEqual(str(refused.exception), why)
        no_boxes = team(web_hosts=HOSTS)
        del no_boxes["agents"]["desk"]["can"]               # an entry with no boxes keeps full access: Shell on
        for bad, start in ((no_boxes, "agent desk has its Shell box on"),
                           (team("cx", web_hosts=HOSTS, can=["web"]), "agent cx runs on Codex, which cannot be held"),
                           (team("manager", web_hosts=HOSTS), "agent manager is the fleet manager")):
            with self.subTest(start), self.assertRaises(ValueError) as refused:
                hub.validate_team(bad)
            self.assertTrue(str(refused.exception).startswith(start), refused.exception)

    def test_the_owner_feature_and_the_helper_feature_have_one_name(self):
        self.assertIn("web_hosts", hub.UI_FEATURES)
        self.assertEqual(hub.WEB_HOSTS, "web_hosts")
        self.assertEqual((fleet.CLOSED_PAGE_TOOL, hub.WEB_PAGES), ("WebFetch", "WebFetch"))


if __name__ == "__main__":
    unittest.main()
