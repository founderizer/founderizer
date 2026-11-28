"""Chat apps, phases 1 and 2 (CHAT-APPS.md section 15): the hub's bridge routes, the owner path from Discord and
WhatsApp, link codes, replies and delivery, and the owner routes. An in-process hub with a temporary database, a
temporary git repository and a temporary chat-apps folder; no bridge, no platform, no live hub, no ~/.fleet."""
import hashlib
import http.client
import base64
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tracemalloc
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
import zlib

import hub
from test_ui_api import OwnerAPI

BRIDGE = "127.0.0.2"            # the hub machine's address: the bridge runs there
OWNER_DISCORD, OWNER_WA, OWNER_LID = "100200300", "34600111222@s.whatsapp.net", "777888999@lid"
TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": BRIDGE, "studio-host": "127.0.0.3", "vps-host": "127.0.0.4",
                      "grok-host": "127.0.0.5"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   "studio": {"role": "worker", "runtime": "claude", "machine": "studio-host", "can": ["shell"]},
                   "vps": {"role": "worker", "runtime": "codex", "machine": "vps-host", "can": ["shell"], "title": "VPS"},
                   "grok": {"role": "worker", "runtime": "grok", "machine": "grok-host", "can": ["shell"]}},
        "chat_apps": {"discord-studio": {"app": "discord", "label": "Studio", "agents": ["studio"], "unknown": "ignore"},
                      "whatsapp-main": {"app": "whatsapp", "label": "Fleet", "agents": ["manager"], "unknown": "ignore"}}}
WHATSAPP_STUDIO = {"app": "whatsapp", "label": "Studio WA", "agents": ["studio"], "unknown": "ignore"}
CHAT = ("test-generation", "owner-chat", "1")
# a PNG of 4 x 3 pixels as its header says (picture_side), which read_attachment shows in its answer
PICTURE = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + (4).to_bytes(4, "big") + (3).to_bytes(4, "big") + bytes(40)


def png_with(*chunks):
    """PICTURE's header with more chunks, (kind, body) each, and its end."""
    def chunk(name, data):
        return len(data).to_bytes(4, "big") + name + data + zlib.crc32(name + data).to_bytes(4, "big")
    return PICTURE[:33] + b"".join(chunk(kind, body) for kind, body in chunks) + chunk(b"IEND", b"")


def office_file(text, parts=(), stored=False, part="word/document.xml"):
    """A Word document whose one paragraph is `text`, with more parts (name, bytes) before it; `part` names the part
    that holds the paragraph."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED) as package:
        package.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/'
                         'content-types"><Default Extension="xml" ContentType="application/xml"/></Types>')
        for name, data in parts:
            package.writestr(name, data)
        package.writestr(part, f"<w:document><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>")
    return out.getvalue()


def pdf_page(content, trailer=b"", code="flate"):
    """A PDF of one page that draws `content`: packed with FlateDecode, also written in hex digits (code "hex", a PDF
    in plain ASCII), or as it is (None)."""
    stream, filters = content, b""
    if code:
        stream, filters = zlib.compress(content), b"/Filter/FlateDecode"
    if code == "hex":
        stream, filters = stream.hex().encode() + b">", b"/Filter[/ASCIIHexDecode/FlateDecode]"
    return (b"%PDF-1.4\n1 0 obj <</Type/Catalog/Pages 2 0 R>> endobj\n2 0 obj <</Type/Pages/Kids[3 0 R]/Count 1>> "
            b"endobj\n3 0 obj <</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>> endobj\n4 0 obj "
            b"<</Length " + str(len(stream)).encode() + filters + b">>\nstream\n" + stream +
            b"\nendstream\nendobj\ntrailer <</Root 1 0 R" + trailer + b">>\n%EOF\n")


def git(*args, cwd=None):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class ChatApps(OwnerAPI):
    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp(prefix="fleet-chat-apps-"))
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
        for key, value in (("team_path", str(self.root / "kit" / "team.json")),
                           ("chat_apps_dir", str(self.root / "home" / ".fleet" / "chat-apps"))):
            hub.CFG[key] = value
            self.addCleanup(hub.CFG.pop, key, None)
        hub.ensure_bridge_key()
        self.key = (self.root / "home" / ".fleet" / "chat-apps" / "bridge.key").read_text()
        self.n = 0

    # ---- helpers
    def bridge(self, path, body=None, key=None, source=BRIDGE, auth=None):
        headers = {"Content-Type": "application/json", "X-Test-Source": source,
                   "Authorization": auth if auth is not None else f"Bearer {key or self.key}"}
        return self.request(path, body, headers)

    def inbound(self, text="How is the scrape going?", account="discord-studio", sender=OWNER_DISCORD, **changes):
        self.n += 1
        body = dict(account=account, id=f"m{self.n}", chat="dm-1" if account == "discord-studio" else OWNER_WA,
                    group=False, sender=sender, sender_alt=None, sender_name="miguel", bot=False, from_me=False,
                    kind="text", text=text, ts=1792134000.5)
        body.update(changes)
        code, data = self.bridge("/bridge/inbound", body)
        self.assertEqual(code, 200, data)
        self.assertEqual(data["db"], "test-generation")
        return data["result"], body

    def bridge_upload(self, data, message, n=1, account="discord-studio", sender=OWNER_DISCORD, mime="image/png",
                      name="screenshot.png", **extra):
        """POST /bridge/files (CHAT-APPS.md 8.1): one file of a message, as the bridge sends it up before the
        message, with the bridge's key from the hub machine."""
        query = urllib.parse.urlencode(dict(account=account, message=message, n=n, name=name, mime=mime,
                                            sender=sender, **extra))
        req = urllib.request.Request(f"{self.base}/bridge/files?{query}", data=data, method="POST",
                                     headers={"Content-Type": "application/octet-stream", "X-Test-Source": BRIDGE,
                                              "Authorization": f"Bearer {self.key}"})
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=30) as answer:
                return answer.status, json.load(answer)
        except urllib.error.HTTPError as answer:
            with answer:
                return answer.code, json.load(answer)

    def own(self, app="discord", ident=OWNER_DISCORD, alias=None):
        hub.q("INSERT INTO owner_handles(app,id,alias,name,linked) VALUES(?,?,?,?,?)", (app, ident, alias, "miguel", hub.now()))

    def out(self, files=True):
        """The queued items, as a bridge that sends files asks for them (files=1, CHAT-APPS.md 20)."""
        code, data = self.bridge("/bridge/out?wait=0" + ("&files=1" if files else ""))
        self.assertEqual(code, 200, data)
        self.assertEqual(data["version"], hub.chat_version())
        return data["items"]

    def texts(self):
        return [i["text"] for i in self.out() if i["kind"] == "message"]

    def post(self, path, **fields):
        return self.request(path, dict(request_id=str(uuid.uuid4()), db="test-generation", **fields))

    def last_request(self):
        return hub.q1("SELECT * FROM ui_requests ORDER BY created DESC LIMIT 1")

    def read(self, agent="studio"):
        text, error = hub.call_tool(agent, "read_messages", {}, None if agent == "manager" else CHAT)
        self.assertFalse(error, text)
        return text

    def tell(self, agent="studio", context=CHAT, **args):
        text, error = hub.call_tool(agent, "tell_owner", dict(dict(text="On it. T-9 is 80% done.", about="scrape"), **args),
                                    context)
        self.assertFalse(error, text)
        return text

    def report(self, item, **fields):
        code, data = self.bridge(f"/bridge/out/{item}", dict(dict(state="sent", parts=1, platform_ids=[f"p{item}"],
                                                                  error=None), **fields))
        self.assertEqual((code, data), (200, {"db": "test-generation", "ok": True}))

    # ---- files and auth
    def test_the_hub_makes_the_bridge_key_once_and_keeps_only_its_sha256(self):
        folder = self.root / "home" / ".fleet" / "chat-apps"
        self.assertEqual(stat.S_IMODE(os.stat(folder).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(folder / "bridge.key").st_mode), 0o600)
        self.assertGreaterEqual(len(self.key), 43)
        self.assertEqual(hub.kv_get("bridge_key_sha256"), hashlib.sha256(self.key.encode()).hexdigest())
        hub.ensure_bridge_key()             # a restart keeps the key
        self.assertEqual((folder / "bridge.key").read_text(), self.key)
        self.assertNotIn(self.key, json.dumps([dict(r) for r in hub.q("SELECT * FROM kv")]))

    def test_bridge_routes_need_the_hub_machine_and_the_bridge_key(self):
        refusals = [dict(source="127.0.0.1"), dict(source="127.0.0.3"), dict(key="wrong-key"), dict(auth=""),
                    dict(auth="Basic abc"), dict(auth="Bearer ")]
        for how in refusals:
            for path, body in (("/bridge/config", None), ("/bridge/out?wait=0", None), ("/bridge/inbound", {}),
                               ("/bridge/out/1", {}), ("/bridge/receipt", {}), ("/bridge/status", {}),
                               ("/bridge/link", {})):
                with self.subTest(how=how, path=path):
                    code, data = self.bridge(path, body, **how)
                    self.assertEqual(code, 403, data)
                    self.assertEqual(data["db"], "test-generation")
        self.assertEqual(self.count("chat_in"), 0)
        hub.kv_set("bridge_key_sha256", None)           # no key made: nothing is accepted
        self.assertEqual(self.bridge("/bridge/config")[0], 403)
        hub.ensure_bridge_key()
        code, data = self.bridge("/bridge/config")
        self.assertEqual(code, 200, data)
        self.assertIsNotNone(hub.kv_get("bridge_seen"))
        # a body of more than 1 MiB: refused before it is read
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        conn.putrequest("POST", "/bridge/inbound")
        for k, v in (("Content-Type", "application/json"), ("Content-Length", str(hub.MIB + 1)),
                     ("X-Test-Source", BRIDGE), ("Authorization", f"Bearer {self.key}")):
            conn.putheader(k, v)
        conn.endheaders()
        response = conn.getresponse()
        self.assertEqual((response.status, json.loads(response.read())["db"]), (413, "test-generation"))
        conn.close()

    def test_inbound_bad_bodies_and_unknown_accounts(self):
        good = dict(account="discord-studio", id="m1", chat="dm-1", group=False, sender=OWNER_DISCORD, sender_alt=None,
                    sender_name="miguel", bot=False, from_me=False, kind="text", text="hi", ts=1.5)
        for change in ({"id": ""}, {"id": 5}, {"chat": None}, {"sender": "a\nb"}, {"group": "no"}, {"bot": None},
                       {"kind": "sticker"}, {"text": 5}, {"ts": "now"}, {"sender_alt": 7}, {"sender_name": 3}):
            with self.subTest(change=change):
                code, data = self.bridge("/bridge/inbound", dict(good, **change))
                self.assertEqual(code, 400, data)
                self.assertNotIn("hi", data["error"])
        self.assertEqual(self.bridge("/bridge/inbound", [1])[0], 400)
        code, data = self.bridge("/bridge/inbound", dict(good, account="discord-gone"))
        self.assertEqual((code, data["db"]), (409, "test-generation"))
        self.assertEqual(self.count("chat_in"), 0)

    # ---- inbound rules
    def test_a_repeated_message_is_a_duplicate_and_makes_nothing_more(self):
        self.own()
        result, body = self.inbound()
        self.assertEqual(result, "stored")
        code, data = self.bridge("/bridge/inbound", body)
        self.assertEqual((code, data["result"]), (200, "duplicate"))
        self.assertEqual((self.count("events"), self.count("ui_requests"), self.count("chat_in")), (1, 1, 1))
        result, _ = self.inbound(id=body["id"], account="whatsapp-main", sender=OWNER_WA)     # the key is (account, id)
        self.assertEqual(result, "ignored")                 # another account: not a duplicate (not an owner there)

    def test_an_unknown_sender_is_ignored_counted_and_kept_short(self):
        self.own()
        value, salt = "SYNTHETICCHATSECRET123", "test-salt"
        hub.ins("INSERT INTO secrets(label,salt,hash,len) VALUES(?,?,?,?)",
                ("Synthetic", salt, hashlib.sha256((salt + value).encode()).hexdigest(), len(value)))
        for i in range(21):
            result, _ = self.inbound(f"hello {i} " + "x" * 300 if i < 20 else f"my key {value}", sender="555",
                                     sender_name="Stranger")
            self.assertEqual(result, "ignored")
        self.assertEqual((self.count("events"), self.count("ui_requests"), self.out()), (0, 0, []))
        code, people = self.request("/ui/people?db=test-generation")
        self.assertEqual(code, 200, people)
        ignored = {x["account"]: x for x in people["ignored"]}
        self.assertEqual(ignored["discord-studio"]["today"], 21)
        self.assertEqual(ignored["whatsapp-main"], {"account": "whatsapp-main", "today": 0, "last": []})
        last = ignored["discord-studio"]["last"]
        self.assertEqual(len(last), 20)
        self.assertEqual((last[0]["sender"], last[0]["name"], last[0]["preview"]), ("555", "Stranger",
                                                                                    "my key " + hub.MASK))
        self.assertEqual(last[1]["preview"], "hello 19")       # the 300 x's: a run across the cut, which could hold a login
        self.assertNotIn(value, json.dumps(people))
        self.assertEqual(hub.leak_scan(), [])
        self.assertEqual(self.request("/ui/chat-apps?db=test-generation")[1]["accounts"][0]["ignored_today"], 21)

    def test_paused_disabled_group_bot_and_own_messages_are_ignored(self):
        self.own()
        for change in ({"group": True}, {"bot": True}, {"from_me": True}):
            with self.subTest(change=change):
                self.assertEqual(self.inbound(**change)[0], "ignored")
        hub.TEAM["chat_apps"]["discord-studio"]["enabled"] = False
        self.assertEqual(self.inbound()[0], "ignored")
        hub.TEAM["chat_apps"]["discord-studio"].pop("enabled")
        code, data = self.post("/ui/chat-apps/pause", paused=True)
        self.assertEqual((code, data["paused"]), (200, True), data)
        self.assertEqual(self.inbound()[0], "ignored")
        self.assertEqual(self.inbound("link ABCD-EFGH")[0], "ignored")
        self.assertEqual(self.count("events"), 0)
        self.assertEqual(self.count("ui_requests"), 0)

    def test_owner_message_from_discord_reaches_the_worker_chat(self):
        self.own()
        result, body = self.inbound()
        self.assertEqual(result, "stored")
        req = self.last_request()
        event = hub.q1("SELECT * FROM events WHERE id=?", (req["event_id"],))
        self.assertEqual((event["agent"], event["kind"]), ("studio", "chat"))
        self.assertEqual(event["text"], f"[owner chat request_id={req['request_id']} via=Discord] How is the scrape going?")
        self.assertEqual(json.loads(event["extra"]), {"generation": "test-generation"})
        self.assertEqual((req["kind"], req["recipient"], req["client"], req["text"]),
                         ("message", "studio", "fleet-channels/1/discord-studio", "How is the scrape going?"))
        self.assertEqual(json.loads(req["origin"]), {"app": "discord", "account": "discord-studio", "chat": "dm-1",
                                                     "id": body["id"], "sender": OWNER_DISCORD, "sender_alt": None})
        self.assertEqual(hub.q1("SELECT request_id FROM chat_in")["request_id"], req["request_id"])
        state = self.request()[1]
        self.assertEqual(state["messages"][0]["origin"], {"app": "discord", "account": "discord-studio", "label": "Studio"})
        self.assertEqual(state["messages"][0]["recipient"], "studio")
        self.assertIn(req["request_id"], self.read())
        # the app's own messages do not change: no origin, the same event text
        code, receipt = self.request("/ui/messages", self.command(recipient="studio"))
        self.assertEqual(code, 200, receipt)
        mine = hub.q1("SELECT * FROM events WHERE id=?", (receipt["event_id"],))
        self.assertEqual(mine["text"], f"[owner chat request_id={receipt['request_id']}] Write a test label.")
        self.assertIsNone(self.request()[1]["messages"][1]["origin"])

    def test_the_hub_finds_the_tags_in_a_chat_app_message(self):
        """Owner feature agent_tags (CHAT-APPS.md 21): a chat app sends the owner's words as they are, so the hub finds
        the @ tags itself: a whole role (spaces as one run, the longest role first), a name, one word that starts the
        role or the name of one other agent. Words that fit two agents are no tag, and the line names both; an email, a
        URL, a "." before a letter, code, a fenced block, the chat's own agent (also by a role that it shares with
        another agent) and an unknown word are never tags, so a tag never opens work for the wrong agent. A role that is
        another agent's name is that agent's name, as its label says, so the Mac draws the badge of the agent that the
        hub tagged. The name of an agent that has a role is its agent too, because a pick in the Mac's @ list writes
        the name (the owner's answer of 22 November 2026). The table of rules 1 and 2 is the same as the one of
        FleetCore's AgentTagsTests (`theTagsAreTheHubsRulesOneAndTwo`), by hand."""
        self.own()
        for name, title in (("nova", "Customer Support"), ("kai", "Customer Support Lead"),
                            ("atlas", "Growth Marketing Lead"), ("juno", "Grok"), ("mia", "Studio Ops")):
            hub.TEAM["agents"][name] = {"role": "worker", "runtime": "codex", "machine": "vps-host", "can": ["shell"],
                                        "title": title}
        hub.TEAM["agents"]["studio"]["title"] = "Studio Ops"    # a hand-written team.json: the chat's agent shares it
        for text, tags in (("@Customer Support, look at it", [("nova", 0, 17)]),
                           ("Ask @Customer Support Lead?", [("kai", 4, 22)]),
                           ("@Growth  Marketing\tLead now", [("atlas", 0, 23)]),
                           ("@VPS and @vps", [("vps", 0, 4), ("vps", 9, 4)]),
                           ("(@grok) then @marketing.", [("grok", 1, 5), ("atlas", 13, 10)]),
                           ("pat@marketing.example", []), ("https://example.com/@marketing", []),
                           ("see @marketing.example", []), ("run `@marketing` now", []),
                           ("```\n@marketing\n```\nok", []), ("@studio, you", []), ("@nobody here", []),
                           ("@Grok, then", [("grok", 0, 5)]), ("@Studio Ops now", []),
                           ("@Nova and @kai.", [("nova", 0, 5), ("kai", 10, 4)]),      # a name that has a role
                           ("@support, then", [])):
            self.assertEqual(self.inbound(text)[0], "stored", text)
            req = self.last_request()
            self.assertEqual([(m["agent"], m["start"], m["length"]) for m in hub.mentions_read(req["mentions"])],
                             tags, text)
            said = hub.q1("SELECT text FROM events WHERE id=?", (req["event_id"],))["text"]
            self.assertEqual(("\n[The owner tagged " in said, "\n[The owner wrote " in said),
                             (bool(tags), text.startswith("@support")), text)
        self.assertTrue(said.endswith('\n[The owner wrote "@support", which fits Customer Support (nova) and Customer '
                                      'Support Lead (kai). The hub took neither as a tag: ask the owner which one, '
                                      'when it matters.]'), said)

    def test_a_chat_app_message_that_starts_with_a_skill_s_name_uses_that_skill(self):
        """Owner feature message_skills (CHAT-APPS.md 22): a chat app sends the owner's words as they are, so the hub
        reads "/" and the name of a skill of the account's agent at their start, after the commands, as that skill to
        use, and the agent reads the hub's line. A command stays a command, a skill named like a command is never used,
        and a name in the middle of the words or of another agent's skill is plain words. Bug: a skill named "help"
        or "stop" takes the owner's command."""
        self.own()
        kit = self.root / "kit"
        for agent, name in (("studio", "seo-radar"), ("studio", "help"), ("studio", "stop"), ("vps", "deploy")):
            folder = kit / "skills" / agent / name
            folder.mkdir(parents=True)
            (folder / "SKILL.md").write_text(f"---\nname: {name}\ndescription: The {name} steps.\n---\n\nSteps.\n")
        git("add", "-A", cwd=kit)
        git("commit", "-q", "-m", "skills", cwd=kit)
        hub._revision_cache.update(at=0.0, value=None)
        self.addCleanup(hub.SKILL_NAMES.clear)
        line = ("[The owner asked you to use your skill seo-radar for this message: read skills/studio/seo-radar/"
                "SKILL.md and follow it. If it does not fit the work, say why in your reply.]")
        for text, used in (("/seo-radar check the shop", True), ("/seo-radar", True), ("/stop the scrape", False),
                           ("Please /seo-radar it", False), ("/deploy it", False), ("/seo-radar, now", False)):
            self.assertEqual(self.inbound(text)[0], "stored", text)
            req = self.last_request()
            self.assertEqual(hub.message_skills_read(req["skills"]), [{"use": "seo-radar"}] if used else [], text)
            said = hub.q1("SELECT text FROM events WHERE id=?", (req["event_id"],))["text"]
            self.assertEqual(said.endswith("\n" + line), used, said)
        rows = self.count("ui_requests")
        self.assertEqual([self.inbound(text)[0] for text in ("/help", "/whoami")], ["stored", "stored"])
        self.assertEqual(self.count("ui_requests"), rows)           # the hub answered both, and no agent reads them
        self.assertTrue(self.texts()[-2].startswith("Commands:\n"))

    def test_owner_message_from_whatsapp_reaches_the_manager_on_its_number(self):
        self.own("whatsapp", OWNER_LID, alias=OWNER_WA)
        result, body = self.inbound("Start the Acme goal.", account="whatsapp-main", sender=OWNER_LID,
                                    sender_alt=OWNER_WA)
        self.assertEqual(result, "stored")
        req = self.last_request()
        event = hub.q1("SELECT * FROM events WHERE id=?", (req["event_id"],))
        self.assertEqual((event["agent"], event["kind"], event["text"]), ("manager", "say", "[owner via WhatsApp] Start "
                                                                                           "the Acme goal."))
        self.assertIn("[owner via WhatsApp] Start the Acme goal.", self.read("manager"))
        # the alias is an owner handle too
        self.assertEqual(self.inbound("Next one.", account="whatsapp-main", sender=OWNER_WA)[0], "stored")

    def test_commands_answer_without_an_ai_turn_and_agents_and_to_are_gone(self):
        self.own("whatsapp", OWNER_WA)

        def say(text, account="whatsapp-main", **changes):
            self.inbound(text, account=account, sender=OWNER_WA, **changes)
            return self.texts()
        self.assertEqual(say("/whoami"), ["You are the owner."])
        self.assertEqual(say("/HELP me"), ["Commands:\n/whoami: who you are in Founderizer\n/help: this list"])
        self.assertEqual(self.count("events"), 0)
        # 17.5: /agents and /to are normal messages to the account's one agent, as any other text that starts with /
        for text in ("/agents", "/TO studio", "/to", "/unknown thing"):
            self.assertEqual(say(text), [])
            req = self.last_request()
            self.assertEqual((req["text"], req["recipient"]), (text, "manager"))
        self.assertEqual(self.count("events"), 4)
        self.assertEqual(hub.q("SELECT name FROM sqlite_master WHERE name='chat_selections'"), [])
        self.assertEqual(say(" "), ["I can read text only for now."])        # a text message with no words
        self.assertEqual(say("x" * 4001), ["This message is too long. The limit is 4,000 characters."])
        hub.TEAM["chat_apps"]["whatsapp-grok"] = {"app": "whatsapp", "label": "Grok", "agents": ["grok"],
                                                  "unknown": "ignore"}
        self.assertEqual(say("Hello Grok", "whatsapp-grok"), ["Grok cannot chat now."])
        hub.TEAM["chat_apps"]["whatsapp-studio"] = WHATSAPP_STUDIO
        hub.TEAM["agents"]["studio"]["active"] = False
        self.assertEqual(say("Hello", "whatsapp-studio"), ["Studio cannot chat now."])
        self.assertEqual(self.count("events"), 4)
        items = hub.q("SELECT * FROM chat_out WHERE kind='message'")
        self.assertTrue(all(i["prefix"] is None and i["reply_to"] is None for i in items))
        # the same on Discord
        hub.TEAM["agents"]["studio"]["active"] = True
        self.own()
        self.inbound("/help")
        self.assertEqual(self.texts(), ["Commands:\n/whoami: who you are in Founderizer\n/help: this list"])
        self.inbound("/to vps")
        self.assertEqual((self.last_request()["text"], self.last_request()["recipient"]), ("/to vps", "studio"))

    def test_an_owner_message_with_a_picture_reaches_the_agent_with_its_words(self):
        """The owner's message from a chat app that carries a picture, a file or a voice note goes on with its words,
        and the hub's line under them tells the agent what came, which the fleet does not pass on yet, and where it can
        get it. Until 20 November 2026 such a message got the fixed reply "I can read text only for now." and its
        words never reached the agent."""
        self.own("whatsapp", OWNER_WA)
        self.assertEqual(self.inbound("Is this the right invoice?", account="whatsapp-main", sender=OWNER_WA,
                                      kind="image")[0], "stored")
        self.assertEqual(self.inbound("", account="whatsapp-main", sender=OWNER_WA, kind="audio")[0], "stored")
        self.own()
        self.assertEqual(self.inbound("Why does the scrape stop here?", kind="file")[0], "stored")
        self.assertEqual(self.texts(), [])          # no fixed reply: the agent answers
        said = [r["text"] for r in hub.q("SELECT text FROM ui_requests ORDER BY created, rowid")]
        self.assertEqual(said, ["Is this the right invoice?", "", "Why does the scrape stop here?"])  # his words alone
        events = {a: [e["text"] for e in hub.q("SELECT text FROM events WHERE agent=? ORDER BY id", (a,))]
                  for a in ("manager", "studio")}
        self.assertEqual(events["manager"], [
            "[owner via WhatsApp] Is this the right invoice?\n[The owner sent a picture with this message on WhatsApp, "
            "which the fleet does not pass on to you yet. If you need it, ask the owner for it in words, or as a file "
            "in the Founderizer app, where read_attachment opens it.]",
            "[owner via WhatsApp]\n[The owner sent a voice note or a sound file with this message on WhatsApp, which "
            "the fleet does not pass on to you yet. If you need it, ask the owner for it in words, or as a file in the "
            "Founderizer app, where read_attachment opens it.]"])
        self.assertEqual(len(events["studio"]), 1)
        self.assertTrue(events["studio"][0].endswith(
            "via=Discord] Why does the scrape stop here?\n[The owner sent a file with this message on Discord, which "
            "the fleet does not pass on to you yet. If you need it, ask the owner for it in words, or as a file in the "
            "Founderizer app, where read_attachment opens it.]"), events["studio"])
        self.assertIn("[The owner sent a picture with this message on WhatsApp", self.read("manager"))   # its read

    def test_a_file_of_a_chat_app_message_reaches_the_agent_as_its_file(self):
        """CHAT-APPS.md 8.1 (the owner, 20 November 2026: "pictures and files sohuld be allowed!"): the bridge sends
        the owner's picture up before its message, past the 1 MiB of every other bridge body, and the message's
        route makes it a file of that message, which the agent opens with read_attachment. The same upload again is
        the same file; a sender whose message the hub would not store gets no byte stored; a file that holds a
        registered login in any text that it gives or packs, or in its name, is refused; a file that did not come
        up is named, with why in the hub's own words."""
        self.own()
        big = PICTURE + bytes(2 * 1024 * 1024)
        code, first = self.bridge_upload(big, "m-up")
        self.assertEqual(code, 200, first)
        # a chat app's file has no place of the owner's (UI-API.md 1.351): an app of his that sends the bridge's own
        # label takes it into no message of his, and it waits for the message of the chat app
        code, refused = self.request("/ui/messages", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                      "text": "See this.", "attachments": [first["id"]]},
                                     {"Content-Type": "application/json",
                                      "X-Fleet-Client": "fleet-channels/1/discord-studio"})
        self.assertEqual((code, refused.get("error")), (409, "an attachment was sent up by another client"))
        self.assertEqual(self.bridge_upload(big, "m-up")[1], dict(first, replayed=True))     # again: the same one file
        code, refused = self.bridge_upload(PICTURE, "m-x", sender="999000111")              # a stranger: nothing kept
        self.assertEqual((code, refused["code"], refused["error"]),
                         (403, "not_welcome", "not taken: the sender may not write to this account's agent"))
        self.assertEqual(self.bridge_upload(b"", "m-e")[0], 415)          # empty: never a 400, which the bridge tries again
        self.assertEqual(self.bridge_upload(b"not a png", "m-f")[0], 415)     # a known type keeps its check of the bytes
        # the sender's type is a type token or application/octet-stream: nothing else reaches a Content-Type
        for mime, kept in (("text/plain\r\nX-A: 1", "application/octet-stream"), ("Image/PNG; q=1", "image/png")):
            code, odd = self.bridge_upload(PICTURE, f"m-{len(mime)}", mime=mime)
            self.assertEqual((code, hub.q1("SELECT mime FROM attachments WHERE id=?", (odd["id"],))["mime"]),
                             (200, kept))
        # a text with a registered login is refused, also when its type says nothing of text (a .env)
        value, salt = "SYNTHETICFILELOGIN4471", "test-salt"
        hub.ins("INSERT INTO secrets(label,salt,hash,len) VALUES(?,?,?,?)",
                ("Synthetic", salt, hashlib.sha256((salt + value).encode()).hexdigest(), len(value)))
        # and when its bytes are not UTF-8: a .env in UTF-16 with its byte order mark, a Windows text with one letter
        # that is no UTF-8, and a picture with the login in a text chunk of its own (until 21 November 2026 none of
        # these was searched: the area Hub core's review); a control character that the skeleton takes away splits
        # no login. And in the text that a file packs, read by its first bytes whatever type its sender names, a PDF
        # in plain ASCII and a .env that starts as a picture too: a PDF's page, a Word document, a spreadsheet, a
        # PNG's packed text chunk; and in the bytes that a reader does not read: a part of an Office file that is no
        # XML, or after a part that does not unpack, a PDF's stream that starts as binary, a PNG's private chunk, and
        # what follows a picture's end
        line = f"KEY={value}\n"
        broken = office_file(f"KEY={value}", stored=True).replace(b"<w:document>", b"<w:documenX>", 1)
        crc = office_file(f"KEY={value}", [("a.xml", "<a>first part</a>")])
        entry = crc.find(b"a.xml", crc.find(b"a.xml") + 1) - 46          # a.xml's entry in the central directory
        crc = crc[:entry + 16] + bytes(4) + crc[entry + 20:]              # a wrong CRC-32 of a.xml
        moved = office_file(f"KEY={value}", [("a.xml", "<a>first part</a>")])
        entry = central_entry(moved, "a.xml")                             # a.xml's entry names no local header
        moved = moved[:entry + 42] + (int.from_bytes(moved[entry + 42:entry + 46], "little") + 1).to_bytes(4, "little") + \
            moved[entry + 46:]
        page, packed = f"BT /F1 12 Tf 72 720 Td ({line}) Tj ET".encode(), zlib.compress(line.encode())
        sheet = office_file(f"KEY={value}", [("xl/workbook.xml", "<workbook/>")], part="xl/sharedStrings.xml")
        stored = office_file("Budget", [("word/notes.txt", line)], stored=True)
        raw = pdf_page(bytes(range(256)) * 16 + line.encode(), code=None)
        private = png_with((b"prVt", line.encode()), (b"tEXt", b"Comment\x00a"))
        hexed = "0123456789abcdef0123456789abcdef01234567"             # a login of hex digits, as in a PDF's hex string
        hub.ins("INSERT INTO secrets(label,salt,hash,len) VALUES(?,?,?,?)",
                ("Hexed", salt, hashlib.sha256((salt + hexed).encode()).hexdigest(), len(hexed)))
        # a JPEG comment whose two length bytes are the login's first two letters: 21,337 bytes for "SY"
        size = int.from_bytes(value[:2].encode(), "big")
        comment = b"\xff\xd8\xff\xfe" + value.encode() + b"\n" + b" " * (size - len(value) - 1)
        commented = pdf_page(b"BT ET").replace(b"%PDF-1.4\n", b"%PDF-1.4\n% <" + hexed.encode() + b">\n")
        titled = pdf_page(b"BT ET", b"/Title <" + hexed.encode() + b">")
        # and in a page's comment, also one that ends in Tj or lies in an array of TJ, in a literal string that the page
        # does not show, after a parenthesis inside a hex string, and after a comment that says stream, where it is
        # syntax: a stream follows a dictionary, and only the hex strings that a page shows are glyph codes, which a
        # comment or a string never shows
        noted = pdf_page(b"BT ET\n% <" + hexed.encode() + b"> Tj\n", code=None)
        arrayed = pdf_page(b"BT /F1 12 Tf [ (x)\n% <" + hexed.encode() + b">\n] TJ ET", code=None)
        actual = pdf_page(b"BT /Span <</ActualText (<" + hexed.encode() + b"> Tj)>> BDC (x) Tj EMC ET", code=None)
        opened = pdf_page(b"BT ET\n<(>\n% <" + hexed.encode() + b"> Tj\n)\n", code=None)
        fake = pdf_page(b"BT ET").replace(b"%PDF-1.4\n",
                                          b"%PDF-1.4\n% stream\n% <" + hexed.encode() + b"> Tj\n% endstream\n")
        # the page view reads a page once: a copy of the rest of the page for each comment took time by the square of
        # the comments (20,000 before 4 MiB: 8.4 s; a crafted 25 MiB page: some 40 minutes), and one person's PDF held
        # the hub's check of every chat app's file that long
        began = time.monotonic()
        hub.pdf_page_view(b"%\n" * 50000 + b"x" * (4 << 20))
        self.assertLess(time.monotonic() - began, 5)
        photo = (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xda\x00\x08" +
                 bytes(range(256)) * 4 + b"\xff\xd9")
        for mime, name, data in (("text/plain", "notes.txt", line.encode()),
                                 ("application/octet-stream", ".env", line.encode()),
                                 ("application/octet-stream", "wide.env", line.encode("utf-16")),
                                 ("application/octet-stream", "old.env", f"# café\n{line}".encode("cp1252")),
                                 ("image/png", "shot.png", png_with((b"tEXt", b"Comment\x00" + line.encode()))),
                                 ("application/octet-stream", "tab.env", f"KEY={value[:9]}\x0b{value[9:]}\n".encode()),
                                 ("application/pdf", "page.pdf", pdf_page(page)),
                                 ("application/octet-stream", "page", pdf_page(page)),
                                 ("text/plain", "ascii.pdf", pdf_page(page, code="hex")),
                                 ("application/octet-stream", "jpeg.env", b"\xff\xd8\xff" + line.encode()),
                                 ("application/octet-stream", "png.env", b"\x89PNG\r\n\x1a\n" + line.encode()),
                                 (hub.DOCX, "notes.docx", office_file(f"KEY={value}")),
                                 ("application/zip", "notes.zip", office_file(f"KEY={value}")),
                                 (hub.XLSX, "sheet.xlsx", sheet),
                                 ("image/png", "packed.png", png_with((b"zTXt", b"Comment\x00\x00" + packed))),
                                 (hub.DOCX, "broken.docx", broken),
                                 (hub.DOCX, "stored.docx", stored),
                                 (hub.DOCX, "crc.docx", crc),
                                 (hub.DOCX, "moved.docx", moved),
                                 ("application/pdf", "raw.pdf", raw),
                                 ("image/png", "private.png", private),
                                 ("image/png", "after.png", png_with((b"tEXt", b"Comment\x00a")) + line.encode()),
                                 ("image/jpeg", "after.jpg", photo + line.encode()),
                                 ("application/pdf", "comment.pdf", commented),
                                 ("application/pdf", "title.pdf", titled),
                                 ("application/pdf", "noted.pdf", noted),
                                 ("application/pdf", "arrayed.pdf", arrayed),
                                 ("application/pdf", "actual.pdf", actual),
                                 ("application/pdf", "opened.pdf", opened),
                                 ("application/pdf", "fake.pdf", fake),
                                 ("image/jpeg", "comment.jpg", comment)):
            code, refused = self.bridge_upload(data, f"m-{name}", mime=mime, name=name)
            self.assertEqual((code, refused.get("code")), (422, "login_as_file"), name)
        # a person's Office file with a part of bzip2 or LZMA is refused before a part is unpacked: zipfile unpacks such
        # a part whole at its first read (a few KB held GB), and no Office app writes one
        for method in (zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA, ZSTANDARD):
            for mime in (hub.XLSX, "application/octet-stream"):
                code, refused = self.bridge_upload(office_packed(method), f"m-packed-{method}-{mime[-4:]}", mime=mime,
                                                   name="packed.xlsx")
                self.assertEqual((code, refused.get("error")), (415, "these bytes are not a spreadsheet"), (method, mime))
        # a piece of a file's text ends at a space or a line break, never inside a login: here pieces of 16 bytes, where
        # pieces of a fixed size would cut the login in two
        with patch.object(hub, "CHAT_FILE_CHUNK", 16), patch.object(hub, "BYTES_CHUNK", 16):
            for name, data in (("long.env", f"# notes {'x ' * 20}{line}".encode()),
                               ("long.bin", b"\xff" * 300 + line.encode())):     # bytes that are no text
                at = data.find(value.encode())
                self.assertNotEqual(at // 16, (at + len(value)) // 16)
                code, refused = self.bridge_upload(data, f"m-{name}", mime="application/octet-stream", name=name)
                self.assertEqual((code, refused.get("code")), (422, "login_as_file"), name)
        # a reader that fails on odd bytes is no fault of the hub, and the file's bytes are still read
        with patch.object(hub, "inflate_pieces", side_effect=zlib.error("odd bytes")):
            odd = png_with((b"zTXt", b"Comment\x00\x00" + packed)) + line.encode()
            code, refused = self.bridge_upload(odd, "m-odd", name="odd.png")
        self.assertEqual((code, refused.get("code")), (422, "login_as_file"))
        # the name that the agent's download line gives is a text of the file too: nothing of it is kept
        code, refused = self.bridge_upload(PICTURE, "m-n", name=f"{value}.png")
        self.assertEqual((code, refused.get("code")), (422, "login_as_file"))
        # a login with no length is a whole token, which a zero byte of C strings joins to the next one: only the
        # text that ends a run at each zero byte holds it alone, so each text of the bytes is searched, not the first
        whole = "SYNTHETICWHOLETOKEN7"
        hub.ins("INSERT INTO secrets(label,salt,hash,len) VALUES(?,?,?,?)",
                ("Whole", salt, hashlib.sha256((salt + whole).encode()).hexdigest(), None))
        code, refused = self.bridge_upload(b"\xff" + whole.encode() + b"\0next", "m-z", mime="application/octet-stream",
                                           name="dump.bin")
        self.assertEqual((code, refused.get("code")), (422, "login_as_file"))
        self.assertEqual(self.bridge_upload("# café, no key\n".encode("utf-16"), "m-w", mime="application/octet-stream",
                                            name="clean.env")[0], 200)      # bytes with no login still come
        self.assertEqual(self.bridge_upload(PICTURE + b"tEXtComment\x00a plain line", "m-p")[0], 200)
        # a person's file is data that the hub never opens or runs: the rules of an agent's own file refuse none of it
        # (a macro, an encrypted PDF), and bytes that do not parse as their kind are no fault of the hub
        macro = office_file("Budget", [("word/vbaProject.bin", b"\xd0\xcf\x11\xe0" + bytes(64))])
        secret = pdf_page(b"BT (Budget) Tj ET", b"/Encrypt <</Filter/Standard/V 1/R 2/O(o)/U(u)/P -4>>")
        torn = office_file("Budget", stored=True).replace(b"<w:document>", b"<w:documenX>", 1)
        for mime, name, data in ((hub.DOCX, "macro.docx", macro), ("application/pdf", "locked.pdf", secret),
                                 (hub.DOCX, "torn.docx", torn)):
            self.assertEqual(self.bridge_upload(data, f"m-{name}", mime=mime, name=name)[0], 200, name)
        # the bridge's question before it fetches a byte: a stranger's answer is the 403, the owner's a welcome
        self.assertEqual(self.bridge_upload(b"", "m-x", sender="999000111", check=1)[0], 403)
        self.assertEqual(self.bridge_upload(b"", "m-c", check=1), (200, {"db": "test-generation", "welcome": True}))
        self.assertEqual(self.count("attachments"), 8)          # the big picture, two of odd types and five clean ones
        self.assertEqual(self.inbound("Why does it stop here?", kind="image", id="m-up")[0], "stored")
        req = self.last_request()
        self.assertEqual(hub.q1("SELECT message FROM attachments WHERE id=?", (first["id"],))["message"],
                         req["request_id"])
        event = hub.q1("SELECT text FROM events WHERE id=?", (req["event_id"],))["text"]
        self.assertIn(f"[The owner attached 1 file: A-{first['id']} screenshot.png (image/png, 2.0 MB).", event)
        self.assertNotIn("does not pass on", event)
        text, error = hub.call_tool("studio", "read_attachment", {"attachment_id": f"A-{first['id']}"}, CHAT)
        self.assertFalse(error, text)
        self.assertIn("The picture follows", text)
        # every file that the app lets a person send in one message, of any type (the owner, 20 November 2026: "does
        # it accept multiple files, images etc? it should"): ten in their order, a video kept as data, no eleventh
        for n in range(1, 11):
            mime, name = ("video/mp4", "clip.mp4") if n == 10 else ("image/png", f"f{n}.png")
            code, got = self.bridge_upload(PICTURE if n < 10 else b"\x00\x00\x00\x18ftypmp42", "m-ten", n=n, mime=mime,
                                    name=name)
            self.assertEqual(code, 200, (n, got))
        self.assertEqual(self.bridge_upload(PICTURE, "m-ten", n=11)[0], 400)
        self.assertEqual(self.inbound("All of them.", kind="image", id="m-ten")[0], "stored")
        ten = hub.q1("SELECT text FROM events WHERE id=?", (self.last_request()["event_id"],))["text"]
        self.assertEqual(re.findall(r"A-\d+ (\S+) \(", ten), [f"f{n}.png" for n in range(1, 10)] + ["clip.mp4"])
        self.assertIn('clip.mp4 ("video/mp4", 1 KB)', ten)     # a type of no table of the hub's, in quotes
        # a file that did not come up: its reason, in the hub's words; a code that the hub does not know is left out
        self.assertEqual(self.inbound("And this one?", kind="image", missed=["size", "nonsense"])[0], "stored")
        self.assertIn("[The owner sent a picture on Discord, which did not reach the fleet: it is larger than 25 MiB.",
                      hub.q1("SELECT text FROM events WHERE id=?", (self.last_request()["event_id"],))["text"])

    def test_a_registered_secret_in_an_inbound_message_is_not_stored(self):
        self.own()
        value, salt = "SYNTHETICCHATSECRET123", "test-salt"
        hub.ins("INSERT INTO secrets(label,salt,hash,len) VALUES(?,?,?,?)",
                ("Synthetic", salt, hashlib.sha256((salt + value).encode()).hexdigest(), len(value)))
        self.assertEqual(self.inbound(f"the key is {value}")[0], "stored")
        self.assertEqual((self.count("events"), self.count("ui_requests")), (0, 0))
        self.assertEqual(self.texts(), ["That message held a saved secret. It was not stored."])
        self.assertEqual(hub.leak_scan(), [])

    def test_the_days_count_of_people_grows_with_the_counted_people_and_the_owner_is_outside_it(self):
        """B9's piece 0d (the coordinator's D124, 26 November 2026): the day's count of people's messages over all
        chat apps' accounts has room for 100 for each person whom the licence counts, and never less than 500; the
        owner's own messages and files are in no such count. A customer (a role with tools off) is no counted person:
        their messages count in it, and they add no room. A file of a person's message past the count is not taken,
        as the message is not. Bugs: a company's people who used up the day stop the owner's own chat; a company of
        20 colleagues gets the 500 of a fleet of one; each customer buys room; the owner's messages use the people's
        room."""
        self.own()
        self.day(600)
        self.assertEqual(self.inbound()[0], "stored")                  # the owner, past the 500 of the people
        self.assertEqual(self.bridge_upload(PICTURE, "m-own")[0], 200)
        self.assertEqual(self.inbound("See it.", kind="image", id="m-own")[0], "stored")
        self.assertEqual(self.request("/ui/chat-apps?db=test-generation")[1]["inbound_today"], 600)
        self.assertEqual(self.count("events"), 2)
        # a person's message counts in the same count of all accounts, and its number stops it too (person_route), also
        # when the account's entry names a count of its own, which only the built-in account may (a team.json written
        # by hand that does not validate, Teams design 4, S4)
        hub.TEAM["agents"]["studio"]["can"] = []        # an outsider reaches only an agent whose Shell box is off
        hub.TEAM["chat_apps"]["discord-studio"].update(day_count="discord-studio", day_least=10 ** 6)
        self.assertEqual(self.post("/ui/people", name="Ana Ruiz", role="customer", agents=["studio"],
                                   handles=[{"app": "discord", "handle": "500600700"}])[0], 200)
        self.day(-101)
        self.assertEqual(self.inbound("Hello", sender="500600700", chat="dm-ana")[0], "stored")
        self.assertEqual((self.count("conversations"), hub.chat_count("*", "inbound", hub.now())), (1, 500))
        self.assertEqual(self.inbound("Hello again", sender="500600700", chat="dm-ana")[0], "ignored")
        code, refused = self.bridge_upload(PICTURE, "m-ana", sender="500600700")
        self.assertEqual((code, refused.get("error")), (403, "not taken: the day's inbound messages are all in"))
        # five colleagues are counted, room for 500, and a sixth gives room for 600; the customer gives none
        for n in range(6):
            if n == 5:
                self.assertEqual(self.inbound("Still full?", sender="500600700", chat="dm-ana")[0], "ignored")
            self.assertEqual(self.post("/ui/people", name=f"Colleague {n}", role="employee", agents=["studio"],
                                       handles=[{"app": "discord", "handle": f"50060080{n}"}])[0], 200)
        self.assertEqual(self.inbound("Hello again", sender="500600700", chat="dm-ana")[0], "stored")
        self.assertEqual(self.bridge_upload(PICTURE, "m-ana-2", sender="500600700")[0], 200)
        self.day(600 - 501)
        self.assertEqual(self.inbound("And now?", sender="500600700", chat="dm-ana")[0], "ignored")

    def day(self, n):
        """Add n to today's count of the people's messages of all accounts."""
        with hub.LOCK, hub.transaction():
            hub.chat_count("*", "inbound", hub.now(), n)

    # ---- link codes and handles
    def test_link_codes_bind_the_owner_once_and_refuse_wrong_expired_and_repeated_codes(self):
        code, data = self.post("/ui/people/codes", purpose="owner", app="whatsapp")
        self.assertEqual(code, 200, data)
        self.assertRegex(data["code"], r"^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$")
        self.assertAlmostEqual(data["expires"], hub.now() + 600, delta=5)
        self.assertEqual(data["targets"], [{"account": "whatsapp-main", "label": "Fleet", "url": None}])
        self.assertNotIn(data["code"], json.dumps([dict(r) for r in hub.q("SELECT * FROM ui_controls")]))
        self.assertNotIn(data["code"].replace("-", ""), json.dumps([dict(r) for r in hub.q("SELECT * FROM link_codes")]))
        self.assertEqual(self.request("/ui/people?db=test-generation")[1]["codes"],
                         [{"app": "whatsapp", "expires": data["expires"]}])
        # wrong codes: a fixed reply each, then the sender's codes are ignored for the hour, the right one too
        for i in range(5):
            self.assertEqual(self.inbound("link AAAA-BBBB", account="whatsapp-main", sender="stranger")[0], "stored")
        self.assertEqual(self.texts(), ["That code is not valid."] * 5)
        self.assertEqual(self.inbound(f"link {data['code']}", account="whatsapp-main", sender="stranger")[0], "ignored")
        self.assertEqual(self.out(), [])
        # the right code, in lower case and without the dash, from the owner's phone
        result, _ = self.inbound(f"  LINK {data['code'].replace('-', '').lower()} ", account="whatsapp-main",
                                 sender=OWNER_LID, sender_alt=OWNER_WA, sender_name="Alex P")
        self.assertEqual(result, "stored")
        self.assertEqual(self.texts(), ["Linked. You are the owner in Founderizer."])
        people = self.request("/ui/people?db=test-generation")[1]
        self.assertEqual([{k: h[k] for k in ("app", "id", "alias", "name")} for h in people["owner"]["handles"]],
                         [{"app": "whatsapp", "id": OWNER_LID, "alias": OWNER_WA, "name": "Alex P"}])
        self.assertEqual(people["codes"], [])
        self.assertEqual(self.count("events"), 0)
        # once only
        self.assertEqual(self.inbound(f"link {data['code']}", account="whatsapp-main", sender="other")[0], "stored")
        self.assertEqual(self.texts(), ["That code is not valid."])
        # a code of WhatsApp does not work on Discord, a new code replaces the open one, an expired code is refused
        _, first = self.post("/ui/people/codes", purpose="owner", app="discord")
        _, second = self.post("/ui/people/codes", purpose="owner", app="discord")
        for text in (f"link {first['code']}",):
            self.inbound(text, sender="d1")
        hub.q("UPDATE link_codes SET expires=? WHERE app='discord'", (hub.now() - 1,))
        self.inbound(f"link {second['code']}", sender="d1")
        self.assertEqual(self.texts(), ["That code is not valid."] * 2)
        self.assertEqual(self.count("owner_handles"), 1)
        # a Discord bot that reported its user ID gives the profile address; a repeat of the command gives no code
        hub.q("INSERT INTO chat_status(account,state,user,name,application_id,error,at) VALUES('discord-studio',"
              "'connected','4444','Fleet Studio','5555',NULL,1)")
        body = dict(request_id=str(uuid.uuid4()), db="test-generation", purpose="owner", app="discord")
        code, third = self.request("/ui/people/codes", body)
        self.assertEqual(third["targets"], [{"account": "discord-studio", "label": "Studio",
                                             "url": "https://discord.com/users/4444"}])
        code, again = self.request("/ui/people/codes", body)
        self.assertEqual((code, again["replayed"], again["code"]), (200, True, None))
        self.assertEqual(again["targets"], third["targets"])
        # WhatsApp: the address of the linked number with the text in it
        hub.q("INSERT INTO chat_status(account,state,user,name,application_id,error,at) VALUES('whatsapp-main',"
              "'connected','34911222333:4@s.whatsapp.net','+34 911 222 333',NULL,NULL,1)")
        _, wa = self.post("/ui/people/codes", purpose="owner", app="whatsapp")
        self.assertEqual(wa["targets"][0]["url"], f"https://wa.me/34911222333?text=link%20{wa['code']}")
        for fields, words in (({"purpose": "invite", "app": "discord"}, "an invite is for Telegram"),
                              ({"purpose": "other", "app": "discord"}, "purpose"), ({"purpose": "owner", "app": "sms"},
                              "app must be"), ({"purpose": "owner", "app": "discord", "x": 1}, "unknown field x")):
            code, data = self.post("/ui/people/codes", **fields)
            self.assertEqual(code, 400, data)
            self.assertIn(words, data["error"])
        hub.TEAM["chat_apps"]["discord-studio"]["enabled"] = False
        self.assertEqual(self.post("/ui/people/codes", purpose="owner", app="discord")[0], 409)

    def test_the_owner_removes_a_handle(self):
        self.own()
        self.assertEqual(self.inbound()[0], "stored")
        code, data = self.post("/ui/people/handles", app="discord", id=OWNER_DISCORD, delete=True)
        self.assertEqual((code, data["deleted"]), (200, True), data)
        self.assertEqual(self.inbound()[0], "ignored")
        self.assertEqual(self.post("/ui/people/handles", app="discord", id=OWNER_DISCORD, delete=True)[0], 404)
        self.assertEqual(self.post("/ui/people/handles", app="discord", id=OWNER_DISCORD)[0], 400)

    # ---- replies and delivery
    def test_a_worker_reply_goes_back_to_the_chat_with_its_delivery(self):
        self.own()
        _, body = self.inbound()
        req = self.last_request()
        self.read()
        items = self.out()
        self.assertEqual([i["kind"] for i in items], ["typing"])           # Discord: typing only
        self.assertEqual(items[0], {"id": items[0]["id"], "kind": "typing", "account": "discord-studio", "chat": "dm-1",
                                    "seconds": 120})
        self.read()
        self.assertEqual(self.out(), [])                                     # only the first read
        self.assertIn("queued for Studio", self.tell(in_reply_to=req["request_id"]))
        state = self.request()[1]
        delivery = state["reports"][0]["delivery"]
        self.assertEqual((delivery["app"], delivery["account"], delivery["state"]), ("discord", "discord-studio", "queued"))
        items = self.out()
        self.assertEqual(items, [{"id": delivery["outbound"], "kind": "message", "account": "discord-studio",
                                  "chat": "dm-1", "recipient": None, "text": "On it. T-9 is 80% done.",
                                  "reply_to": body["id"], "prefix": None}])
        self.assertEqual(self.request()[1]["reports"][0]["delivery"]["state"], "sending")
        self.assertEqual(self.out(), [])
        self.report(items[0]["id"], parts=2, platform_ids=["p1", "p2"])
        self.report(items[0]["id"], parts=2, platform_ids=["p1", "p2"])         # a repeat changes nothing
        self.assertEqual(self.request()[1]["reports"][0]["delivery"]["state"], "sent")
        self.assertEqual(self.request("/ui/chat-apps?db=test-generation")[1]["accounts"][0]["sent_today"], 2)
        for kind in ("read", "delivered"):          # never a step back
            self.assertEqual(self.bridge("/bridge/receipt", {"account": "discord-studio", "ids": ["p2"], "type": kind})[0],
                             200)
        self.assertEqual(self.request()[1]["reports"][0]["delivery"]["state"], "read")
        code, data = self.bridge(f"/bridge/out/{items[0]['id']}", {"state": "failed", "parts": 0, "platform_ids": []})
        self.assertEqual(code, 409, data)
        self.assertEqual(self.bridge("/bridge/out/999", {"state": "sent"})[0], 404)
        # an owner message from the app gets its reply in the app only
        _, receipt = self.request("/ui/messages", self.command(recipient="studio"))
        self.read()
        self.assertIn("No notification was sent", self.tell(in_reply_to=receipt["request_id"]))
        self.assertEqual(self.out(), [])
        self.assertIsNone(self.request()[1]["reports"][1]["delivery"])

    def test_a_whatsapp_reply_has_no_prefix_and_the_message_is_marked_read(self):
        self.own("whatsapp", OWNER_WA)
        hub.TEAM["chat_apps"]["whatsapp-studio"] = WHATSAPP_STUDIO
        _, body = self.inbound("Status?", account="whatsapp-studio", sender=OWNER_WA)
        req = self.last_request()
        self.assertEqual(req["recipient"], "studio")
        self.read()
        items = self.out()
        self.assertEqual([i["kind"] for i in items], ["typing", "read"])
        self.assertEqual(items[1], {"id": items[1]["id"], "kind": "read", "account": "whatsapp-studio", "chat": OWNER_WA,
                                    "sender": OWNER_WA, "ids": [body["id"]]})
        self.tell(in_reply_to=req["request_id"])
        item = self.out()[0]
        self.assertEqual((item["prefix"], item["reply_to"], item["chat"]), (None, body["id"], OWNER_WA))
        # an item that an older hub queued with a prefix goes out without it (17.5)
        hub.q("UPDATE chat_out SET state='queued', prefix='Studio' WHERE id=?", (item["id"],))
        self.assertIsNone(self.out()[0]["prefix"])

    def test_the_manager_reply_links_by_in_reply_to_or_by_the_event_in_about(self):
        self.own("whatsapp", OWNER_WA)
        self.inbound("Start the Acme goal.", account="whatsapp-main", sender=OWNER_WA)
        first = self.last_request()
        self.inbound("And the Beta goal.", account="whatsapp-main", sender=OWNER_WA)
        second = self.last_request()
        self.read("manager")
        self.out()
        self.tell("manager", None, text="Started G-1.", about=f"Goal for M-999 and M-{first['event_id']}")
        self.tell("manager", None, text="Started G-2.", in_reply_to=second["request_id"])
        self.tell("manager", None, text="Nothing to link.", about="routine")
        items = self.out()
        self.assertEqual([(i["text"], i["prefix"]) for i in items], [("Started G-1.", None), ("Started G-2.", None)])
        origin = json.loads(first["origin"])
        self.assertEqual(items[0]["reply_to"], origin["id"])
        reports = self.request()[1]["reports"]
        self.assertEqual([r["delivery"] is not None for r in reports], [True, True, False])
        self.assertEqual(reports[1]["in_reply_to"], second["request_id"])

    def test_the_manager_reply_goes_to_the_chat_of_the_message_that_about_names(self):
        """Two messages of the owner's wait, each from its own chat app. A report whose about names the newer one is
        the answer to it and goes to its chat. It went to the chat of the oldest message that waited."""
        self.own("whatsapp", OWNER_WA)
        self.inbound("Start the Acme goal.", account="whatsapp-main", sender=OWNER_WA)
        first = self.last_request()
        self.inbound("And the Beta goal.", account="whatsapp-main", sender=OWNER_WA)
        second = self.last_request()
        self.read("manager")
        self.out()
        self.tell("manager", None, text="Started the Beta goal.", about=f"M-{second['event_id']}")
        items = self.out()
        self.assertEqual([(i["text"], i["reply_to"]) for i in items],
                         [("Started the Beta goal.", json.loads(second["origin"])["id"])])
        reports = self.request()[1]["reports"]
        self.assertEqual(reports[0]["in_reply_to"], second["request_id"])
        self.assertNotEqual(json.loads(first["origin"])["id"], json.loads(second["origin"])["id"])
        # The same report again sends nothing a second time (the manager's call can come twice).
        self.assertIn("already saved", self.tell("manager", None, text="Started the Beta goal.",
                                                 about=f"M-{second['event_id']}"))
        self.assertEqual(self.out(), [])
        # A later word that names that message in in_reply_to has no link, because the message has its answer, and it
        # goes to that message's chat all the same; the first message still waits, and no later word takes it.
        said = self.tell("manager", None, text="Its first task runs.", about="G-2",
                         in_reply_to=f"M-{second['event_id']}")
        self.assertIn("has its answer already, so this report has no link", said)
        self.assertEqual([(i["text"], i["reply_to"]) for i in self.out()],
                         [("Its first task runs.", json.loads(second["origin"])["id"])])
        reports = self.request()[1]["reports"]
        self.assertEqual([r["in_reply_to"] for r in reports], [second["request_id"], None])

    def sent_to_whatsapp(self):
        """(text, the id of the WhatsApp message that it answers) of each report that the bridge is given now."""
        return [(i["text"], i["reply_to"]) for i in self.out() if i["kind"] == "message"]

    def test_a_report_without_a_name_takes_its_turn_as_before(self):
        """A report of the manager's that names no message of the owner's takes the turn of the oldest message that
        waits, from the app or from a chat app, as before 10 November 2026. When that message came from a chat app,
        the report is linked to it and goes to that chat. A message from the app takes its turn too, now with no
        link. So in a row of messages from both, each answer still goes where its message came from."""
        self.own("whatsapp", OWNER_WA)
        self.inbound("How far is the Acme goal?", account="whatsapp-main", sender=OWNER_WA)
        first = self.last_request()
        self.tell("manager", None, text="Too early.", about="G-1")          # not read yet: it has no turn
        self.assertEqual(self.sent_to_whatsapp(), [])
        code, sent = self.post("/ui/messages", text="And create one task for Leo.")
        self.assertEqual(code, 200, sent)
        self.inbound("And the Beta goal?", account="whatsapp-main", sender=OWNER_WA)
        second = self.last_request()
        self.read("manager")
        self.out()
        answers = ("Two of its three tasks are done.", "Leo has his task.", "Beta starts on Monday.", "No more news.")
        for text in answers:
            self.tell("manager", None, text=text, about="G-1, T-4")
        self.assertEqual(self.sent_to_whatsapp(), [(answers[0], json.loads(first["origin"])["id"]),     # the oldest
                                                   (answers[2], json.loads(second["origin"])["id"])])
        rows = {r["text"]: (r["in_reply_to"], r["turn"]) for r in hub.q("SELECT * FROM owner_reports")}
        self.assertEqual([rows[text] for text in answers],
                         [(first["request_id"], None), (None, sent["request_id"]), (second["request_id"], None),
                          (None, None)])
        # What the apps read: the links, and the turn only as its own field (owner API 1.190), which places the row
        # of what the owner asked for and is never the link of a reply.
        reports = self.request()[1]["reports"]
        self.assertEqual([(r["in_reply_to"], r["turn"]) for r in reports],
                         [(None, None), (first["request_id"], None), (None, sent["request_id"]),
                          (second["request_id"], None), (None, None)])
        code, chat = self.request("/ui/mobile/chat/manager?db=test-generation")
        self.assertEqual(code, 200, chat)
        self.assertEqual([(i["in_reply_to"], i["turn"]) for i in chat["items"] if i["kind"] == "report"],
                         [(r["in_reply_to"], r["turn"]) for r in reports])

    def test_a_report_that_names_a_chat_app_message_that_was_not_read_goes_to_no_chat(self):
        """about can name a message that the manager has not read. The report is not its answer, so it does not go
        to that message's chat as one: after the read the owner would get a second answer there."""
        self.own("whatsapp", OWNER_WA)
        self.inbound("How far is the Acme goal?", account="whatsapp-main", sender=OWNER_WA)
        unread = self.last_request()
        self.tell("manager", None, text="Too early.", about=f"M-{unread['event_id']}")
        self.assertEqual(self.sent_to_whatsapp(), [])
        self.read("manager")
        self.out()
        self.tell("manager", None, text="Two of its three tasks are done.", about=f"M-{unread['event_id']}")
        self.assertEqual(self.sent_to_whatsapp(),
                         [("Two of its three tasks are done.", json.loads(unread["origin"])["id"])])

    def test_a_report_on_a_needs_you_answer_is_no_answer_to_a_chat_app_message_that_waits(self):
        """A message from WhatsApp waits, and the owner answers a Needs-you item in the app. The manager's report on
        that answer names it: it is about that answer. The hub took it as the answer to the WhatsApp message and sent
        it there. Now the WhatsApp message keeps its turn, for the next report that names no message."""
        self.own("whatsapp", OWNER_WA)
        self.inbound("How far is the Acme goal?", account="whatsapp-main", sender=OWNER_WA)
        asked = self.last_request()
        need = self.need()
        code, answer = self.post(f"/ui/needs/{need}", answer="Done, the permission is accepted.")
        self.assertEqual(code, 200, answer)
        self.read("manager")
        self.out()
        self.tell("manager", None, text="Thanks, the permission is noted.", about=f"M-{answer['event_id']}, N-{need}")
        self.assertEqual(self.sent_to_whatsapp(), [])
        self.tell("manager", None, text="Two of its three tasks are done.", about="G-1, T-4")
        self.assertEqual(self.sent_to_whatsapp(),
                         [("Two of its three tasks are done.", json.loads(asked["origin"])["id"])])
        self.assertEqual([r["in_reply_to"] for r in self.request()[1]["reports"]], [None, asked["request_id"]])

    def remove_handle(self, app="whatsapp", ident=OWNER_WA):
        """The owner removes one of their handles on the People page."""
        code, data = self.post("/ui/people/handles", app=app, id=ident, delete=True)
        self.assertEqual(code, 200, data)

    def test_no_report_goes_to_the_chat_of_a_handle_that_the_owner_removed(self):
        """The owner removes a handle: the number is no longer theirs, or Founderizer must not write there. A message
        that came from it before can still get its report by its name, and the report then stays in the app. It went
        to that chat as the answer to the old message, and so did a later word. A report that names no message went
        there too, by the turn of such a message: that message has no turn now."""
        self.own("whatsapp", OWNER_WA)
        self.inbound("How far is the Acme goal?", account="whatsapp-main", sender=OWNER_WA)
        first = self.last_request()
        self.inbound("And the Beta goal?", account="whatsapp-main", sender=OWNER_WA)
        second = self.last_request()
        self.read("manager")
        self.out()
        self.remove_handle()
        name = f"M-{first['event_id']}"
        said = [self.tell("manager", None, text="Two of its three tasks are done.", about=name),
                self.tell("manager", None, text="Beta starts on Monday.", about="G-2"),         # it names no message
                self.tell("manager", None, text="Acme is done now.", in_reply_to=name),         # a later word
                self.tell("manager", None, text="Acme is closed.", about=name)]                 # one by about alone
        for answer in said:
            self.assertIn("No notification was sent.", answer)
        self.assertEqual(self.sent_to_whatsapp(), [])
        reports = self.request()[1]["reports"]
        self.assertEqual([r["delivery"] for r in reports], [None] * 4)
        self.assertEqual([r["in_reply_to"] for r in reports], [first["request_id"], None, None, None])
        self.assertEqual([r["turn"] for r in hub.q("SELECT turn FROM owner_reports ORDER BY id")], [None] * 4)
        self.assertEqual(self.count("chat_out"), 4)         # the typing and read items of the read, and no more
        self.own("whatsapp", OWNER_WA)                      # the owner links that handle again: its chat is theirs
        self.tell("manager", None, text="And Beta is done too.", in_reply_to=f"M-{second['event_id']}")
        self.assertEqual(self.sent_to_whatsapp(), [("And Beta is done too.", json.loads(second["origin"])["id"])])
        self.assertEqual(self.request()[1]["reports"][4]["in_reply_to"], second["request_id"])

    def test_after_a_new_number_a_report_that_names_no_message_goes_to_the_chat_that_the_owner_has_now(self):
        """The owner changes their number: they remove the old handle and link the new one. A message from the old
        number that the manager carried out with no words still waits. A report that names no message was the answer
        to it, by its turn, so that report reached the old number. With the old chat closed and that turn kept, the
        owner would get it in no chat. A message whose chat can take no report has no turn, so the report is the
        answer to the message from the new number."""
        new = "34600999888@s.whatsapp.net"
        self.own("whatsapp", OWNER_WA)
        self.inbound("Start the Acme goal.", account="whatsapp-main", sender=OWNER_WA)
        self.read("manager")
        self.remove_handle()
        self.own("whatsapp", new)
        self.inbound("How far is the Acme goal?", account="whatsapp-main", sender=new, chat=new)
        asked = self.last_request()
        self.read("manager")
        self.out()
        self.tell("manager", None, text="Two of its three tasks are done.", about="G-1")
        self.tell("manager", None, text="No more news.", about="G-1")
        self.assertEqual([(i["text"], i["chat"], i["reply_to"]) for i in self.out()],
                         [("Two of its three tasks are done.", new, json.loads(asked["origin"])["id"])])
        self.assertEqual([r["in_reply_to"] for r in self.request()[1]["reports"]], [asked["request_id"], None])

    def test_a_message_of_a_chat_app_account_that_is_gone_has_no_turn_either(self):
        """The owner deletes a chat app account. A message that came through it gets no report in a chat app. It kept
        its turn for a report that names no message all the same, and the message that the owner then wrote through
        another account got its answer one report late."""
        hub.TEAM["chat_apps"]["discord-main"] = {"app": "discord", "label": "Fleet DC", "agents": ["manager"],
                                                 "unknown": "ignore"}
        self.own("whatsapp", OWNER_WA)
        self.own()
        self.inbound("Start the Acme goal.", account="whatsapp-main", sender=OWNER_WA)
        self.read("manager")
        self.out()
        hub.TEAM["chat_apps"].pop("whatsapp-main")
        self.inbound("How far is the Acme goal?", account="discord-main", chat="dm-7")
        asked = self.last_request()
        self.read("manager")
        self.out()
        self.tell("manager", None, text="Two of its three tasks are done.", about="G-1")
        self.assertEqual([(i["account"], i["chat"], i["text"], i["reply_to"]) for i in self.out()],
                         [("discord-main", "dm-7", "Two of its three tasks are done.", json.loads(asked["origin"])["id"])])

    def test_a_later_word_goes_to_the_first_message_in_about_whose_chat_can_take_it(self):
        """about names two messages that have their answers, and the owner has removed the handle of the first one.
        The later word goes to the chat of the second one. It went to the chat of the first one."""
        new = "34600999888@s.whatsapp.net"
        self.own("whatsapp", OWNER_WA)
        self.own("whatsapp", new)
        self.inbound("How far is the Acme goal?", account="whatsapp-main", sender=OWNER_WA)
        first = self.last_request()
        self.inbound("And the Beta goal?", account="whatsapp-main", sender=new, chat=new)
        second = self.last_request()
        self.read("manager")
        for asked in (first, second):
            self.tell("manager", None, text=f"An answer to M-{asked['event_id']}.", in_reply_to=f"M-{asked['event_id']}")
        self.out()
        self.remove_handle()
        self.tell("manager", None, text="Both goals are done.", about=f"M-{first['event_id']} and M-{second['event_id']}")
        self.assertEqual([(i["text"], i["chat"], i["reply_to"]) for i in self.out()],
                         [("Both goals are done.", new, json.loads(second["origin"])["id"])])

    def test_a_report_that_names_two_waiting_messages_answers_the_first_whose_chat_can_take_it(self):
        """about names two messages that wait for their answers, and the owner has removed the handle of the first.
        The report is the answer to the second one and goes to its chat. It was the answer to the first one and
        reached no chat, while the second one, from the number that the owner uses now, waited on. When no named
        message's chat can take it, the report is the answer to the first one, as before."""
        new = "34600999888@s.whatsapp.net"
        self.own("whatsapp", OWNER_WA)
        self.own("whatsapp", new)
        self.inbound("How far is the Acme goal?", account="whatsapp-main", sender=OWNER_WA)
        first = self.last_request()
        self.inbound("And the Beta goal?", account="whatsapp-main", sender=new, chat=new)
        second = self.last_request()
        self.read("manager")
        self.out()
        self.remove_handle()
        both = f"M-{first['event_id']} and M-{second['event_id']}"
        self.assertIn("queued for Fleet", self.tell("manager", None, text="Both goals move.", about=both))
        self.assertEqual([(i["text"], i["chat"], i["reply_to"]) for i in self.out()],
                         [("Both goals move.", new, json.loads(second["origin"])["id"])])
        self.tell("manager", None, text="Beta starts on Monday.", about="G-2")      # nothing has a turn now
        self.assertEqual(self.out(), [])
        self.tell("manager", None, text="Acme is late.", about=both)                # the first still waits
        self.assertEqual(self.out(), [])
        self.assertEqual([r["in_reply_to"] for r in self.request()[1]["reports"]],
                         [second["request_id"], None, first["request_id"]])

    def test_after_a_new_link_of_a_handle_a_message_from_before_it_has_no_turn(self):
        """The owner removes a handle and links it again later. A message that came from it before still waits.
        A report that names no message is not its answer: it is for the message that the owner wrote since, in the
        app. It took the old message's turn and went to WhatsApp as the answer to that old message, and the new
        message got its answer one report late. The old message gets its report by its name, in its chat, and a
        message that comes after the new link has its turn."""
        self.own("whatsapp", OWNER_WA)
        self.inbound("How far is the Acme goal?", account="whatsapp-main", sender=OWNER_WA)
        old = self.last_request()
        self.read("manager")
        self.out()
        self.remove_handle()
        self.own("whatsapp", OWNER_WA)
        code, sent = self.post("/ui/messages", text="And create one task for the Beta goal.")
        self.assertEqual(code, 200, sent)
        self.read("manager")
        self.tell("manager", None, text="The Beta task is open.", about="G-2")
        self.assertEqual(self.sent_to_whatsapp(), [])
        self.assertEqual(hub.q1("SELECT turn FROM owner_reports ORDER BY id DESC LIMIT 1")["turn"], sent["request_id"])
        self.tell("manager", None, text="Acme is done.", in_reply_to=f"M-{old['event_id']}")
        self.assertEqual(self.sent_to_whatsapp(), [("Acme is done.", json.loads(old["origin"])["id"])])
        self.inbound("And the Gamma goal?", account="whatsapp-main", sender=OWNER_WA)
        new = self.last_request()
        self.read("manager")
        self.out()
        self.tell("manager", None, text="Gamma starts on Monday.", about="G-3")
        self.assertEqual(self.sent_to_whatsapp(), [("Gamma starts on Monday.", json.loads(new["origin"])["id"])])

    def test_a_phone_with_two_handles_keeps_the_turn_of_a_message_by_the_older_one(self):
        """Two link messages from one phone, one under each form of its ID, make two handles. A message that came
        between the two links keeps its turn by the older handle. When the owner removes the older one, that message
        has no turn: no handle had its sender since before it came. A message after both links keeps its turn, and a
        report that names the first message still goes to its chat, because the phone is still the owner's."""
        self.own("whatsapp", OWNER_LID, alias=OWNER_WA)
        sent = []
        for text in ("How far is the Acme goal?", "And the Beta goal?"):
            self.inbound(text, account="whatsapp-main", chat=OWNER_LID, sender=OWNER_LID, sender_alt=OWNER_WA)
            sent.append(self.last_request())
        self.own("whatsapp", OWNER_WA, alias=OWNER_LID)
        self.inbound("And the Gamma goal?", account="whatsapp-main", chat=OWNER_LID, sender=OWNER_LID,
                     sender_alt=OWNER_WA)
        sent.append(self.last_request())
        self.read("manager")
        self.out()
        first, between, after = (json.loads(r["origin"])["id"] for r in sent)
        self.tell("manager", None, text="Acme is done.", about="G-1")               # the oldest that waits
        self.assertEqual(self.sent_to_whatsapp(), [("Acme is done.", first)])
        self.remove_handle("whatsapp", OWNER_LID)                                   # the older handle
        self.tell("manager", None, text="Gamma starts on Monday.", about="G-3")     # not Beta's turn now
        self.assertEqual(self.sent_to_whatsapp(), [("Gamma starts on Monday.", after)])
        self.tell("manager", None, text="Beta waits for its budget.", in_reply_to=f"M-{sent[1]['event_id']}")
        self.assertEqual(self.sent_to_whatsapp(), [("Beta waits for its budget.", between)])

    def test_a_handle_of_the_other_chat_app_with_the_same_id_does_not_keep_the_chat(self):
        """A handle is one ID on one app. The same text as a handle of the other app says nothing about this chat."""
        self.own("whatsapp", OWNER_WA)
        self.inbound("How far is the Acme goal?", account="whatsapp-main", sender=OWNER_WA)
        asked = self.last_request()
        self.read("manager")
        self.out()
        self.remove_handle()
        self.own("discord", OWNER_WA)
        said = self.tell("manager", None, text="Two of its three tasks are done.", about=f"M-{asked['event_id']}")
        self.assertIn("No notification was sent.", said)
        self.assertEqual(self.out(), [])

    def test_a_workers_reply_goes_to_no_chat_of_a_removed_handle_either(self):
        """On Discord too: a reply that is written after the removal stays in the app, and a reply that waited for
        the bridge at the removal fails."""
        self.own()
        self.inbound()
        first = self.last_request()
        self.inbound("And the proxies?")
        second = self.last_request()
        self.read()
        self.out()
        self.assertIn("queued for Studio", self.tell(in_reply_to=first["request_id"]))
        self.remove_handle("discord", OWNER_DISCORD)
        self.assertIn("No notification was sent.", self.tell(text="They hold.", in_reply_to=second["request_id"]))
        self.assertEqual(self.out(), [])
        delivery = [r["delivery"] for r in self.request()[1]["reports"]]
        self.assertEqual((delivery[0]["state"], delivery[0]["error"], delivery[1]),
                         ("failed", "this chat is no longer known as the owner's", None))

    def test_a_report_that_waits_for_the_bridge_is_not_sent_after_its_handle_was_removed(self):
        """A report can wait for the bridge: here the owner turns on Pause all. The owner removes the handle
        meanwhile. The bridge is not given that report after Pause all ends, and the app shows why."""
        self.own("whatsapp", OWNER_WA)
        self.inbound("How far is the Acme goal?", account="whatsapp-main", sender=OWNER_WA)
        asked = self.last_request()
        self.read("manager")
        self.out()
        self.tell("manager", None, text="Two of its three tasks are done.", about=f"M-{asked['event_id']}")
        self.assertEqual(self.post("/ui/chat-apps/pause", paused=True)[0], 200)
        self.remove_handle()
        self.assertEqual(self.out(), [])
        queued = self.request()[1]["reports"][0]["delivery"]
        self.assertEqual((queued["state"], queued["error"]), ("queued", None))     # Pause all holds every item
        self.assertEqual(self.post("/ui/chat-apps/pause", paused=False)[0], 200)
        self.assertEqual(self.out(), [])
        delivery = self.request()[1]["reports"][0]["delivery"]
        self.assertEqual((delivery["state"], delivery["error"]), ("failed", "this chat is no longer known as the owner's"))
        self.assertGreater(delivery["at"], queued["at"])    # the time of that change, as for every state
        self.assertEqual(self.out(), [])                    # and not at the bridge's next call
        code, again = self.post(f"/ui/outbound/{delivery['outbound']}/again")       # Send again, while it is gone
        self.assertEqual((code, again["outbound"]["state"]), (200, "queued"), again)
        self.assertEqual(self.out(), [])
        delivery = self.request()[1]["reports"][0]["delivery"]
        self.assertEqual((delivery["state"], delivery["error"], delivery["outbound"]),
                         ("failed", "this chat is no longer known as the owner's", again["outbound"]["id"]))

    def test_a_read_sends_no_signal_to_the_chat_of_a_removed_handle(self):
        self.own("whatsapp", OWNER_WA)
        self.inbound("How far is the Acme goal?", account="whatsapp-main", sender=OWNER_WA)
        self.remove_handle()
        self.assertIn("How far is the Acme goal?", self.read("manager"))
        self.assertEqual(self.out(), [])                    # no typing item and no read item
        self.assertEqual(self.count("chat_out"), 0)

    def test_the_signals_of_a_read_that_wait_for_the_bridge_are_not_sent_after_the_handle_was_removed(self):
        """The typing and read items of a read wait for the bridge as a report does. The owner removes the handle
        meanwhile: the bridge is given neither, and each ends as expired."""
        self.own("whatsapp", OWNER_WA)
        self.inbound("How far is the Acme goal?", account="whatsapp-main", sender=OWNER_WA)
        self.read("manager")
        self.remove_handle()
        self.assertEqual(self.out(), [])
        self.assertEqual([(r["kind"], r["state"], r["error"]) for r in hub.q("SELECT * FROM chat_out ORDER BY id")],
                         [("typing", "expired", None), ("read", "expired", None)])

    def test_a_message_with_two_ids_gets_its_answer_while_either_one_is_a_handle(self):
        """WhatsApp gives a sender two IDs, a number and a hidden ID, and a message comes under one with the other
        beside it. The hub takes the message as the owner's when either is a handle, and it keeps both with the
        message, so the check of the handle at the answer is the check of the arrival: first with the number as the
        handle and the message under the hidden ID, then with the hidden ID as the handle and the number beside it."""
        for handle in (OWNER_WA, OWNER_LID):
            with self.subTest(handle=handle):
                self.own("whatsapp", handle)
                self.inbound("How far is the Acme goal?", account="whatsapp-main", chat=OWNER_LID, sender=OWNER_LID,
                             sender_alt=OWNER_WA)
                asked = self.last_request()
                self.assertEqual(asked["recipient"], "manager")
                self.read("manager")
                self.assertEqual([i["kind"] for i in self.out()], ["typing", "read"])
                self.tell("manager", None, text=f"An answer under {handle}.", about=f"M-{asked['event_id']}")
                self.assertEqual(self.sent_to_whatsapp(),
                                 [(f"An answer under {handle}.", json.loads(asked["origin"])["id"])])
                # a first word of the manager's takes the chat of that message too, with its request (owner_route)
                route = hub.owner_route("manager")
                self.assertEqual((route["chat"], route.get("request")), (OWNER_LID, asked["request_id"]))
                self.remove_handle("whatsapp", handle)
                self.assertIsNone(hub.owner_route("manager"))
                self.tell("manager", None, text=f"A later word under {handle}.", in_reply_to=f"M-{asked['event_id']}")
                self.assertEqual(self.sent_to_whatsapp(), [])

    def test_a_message_from_before_the_second_id_was_kept_is_checked_by_its_first_id(self):
        """A message that arrived before this rule has one ID in its record. Its answer goes to its chat while that ID
        is a handle of the owner's, and stays in the app when it is not."""
        self.own("whatsapp", OWNER_WA)
        for sender, sent in ((OWNER_WA, True), (OWNER_LID, False)):
            self.inbound(f"A question from {sender}", account="whatsapp-main", sender=OWNER_WA)
            asked = self.last_request()
            old = dict(json.loads(asked["origin"]), sender=sender)
            old.pop("sender_alt", None)
            hub.q("UPDATE ui_requests SET origin=? WHERE request_id=?", (json.dumps(old), asked["request_id"]))
            self.read("manager")
            self.out()
            self.tell("manager", None, text=f"An answer for {sender}", about=f"M-{asked['event_id']}")
            self.assertEqual(self.sent_to_whatsapp(), [(f"An answer for {sender}", old["id"])] if sent else [], sender)

    def inbound_while(self, command):
        """The owner's Discord message to studio, with the owner's `command` about studio at each lock wait of the
        bridge's call in turn (lock_waits): (the answer, whether the message was stored when the command came) of
        each moment. The command is what a delete and a rename leave: one transaction of its records and one new team,
        under the lock. The message waits for it, after its route looked the account up."""
        self.own()
        self.patience = max(self.patience, 60)      # the command, with its reads of the repository, runs in one call
        back, stored = self.kept(), []
        message = dict(account="discord-studio", id="m1", chat="dm-1", group=False, sender=OWNER_DISCORD,
                       sender_alt=None, sender_name="miguel", bot=False, from_me=False, kind="text",
                       text="How is the scrape going?", ts=1792134000.5)

        def land():
            with hub.LOCK:
                stored.append(self.count("chat_in"))
                hub.apply_team(command())
        for _, answer in self.lock_waits(lambda: self.bridge("/bridge/inbound", message), land, back):
            yield answer, stored.pop()

    def test_a_message_that_waited_for_the_delete_of_its_agent_is_refused_as_for_an_account_that_is_gone(self):
        """The owner's message from Discord to studio waits in the hub while the owner's delete of studio runs: the
        delete takes studio's account with it. The bridge reads "unknown chat app account", as for every message to
        an account that the fleet does not have, and nothing is written. It was taken as stored, with the reply that
        Studio cannot chat now. A message that was stored before the delete was in time, and left with the agent."""
        def delete():
            with hub.transaction():
                hub.remove_rows("studio", hub.now())
            return hub.removed_team(hub.TEAM, "studio")
        before = []
        for (code, data), was_stored in self.inbound_while(delete):     # each moment, with the records as it left them
            before.append(was_stored)
            if was_stored:
                self.assertEqual((code, data.get("result")), (200, "stored"))
            else:
                self.assertEqual((code, data.get("error")), (409, "unknown chat app account"))
                self.assertEqual([self.count(table) for table in ("chat_in", "chat_out")], [0, 0])
            self.assertIsNone(hub.q1("SELECT 1 FROM ui_requests WHERE recipient='studio'"))
            self.assertIsNone(hub.q1("SELECT 1 FROM events WHERE agent='studio'"))
        self.assertEqual(before[:1], [0])   # the delete came before the message was stored, at one moment or more

    def test_a_message_that_waited_for_the_rename_of_its_agent_goes_to_it_under_its_new_name(self):
        """The same wait, and the owner renames studio to nova: its account stays, with the new name. The message is
        nova's. It went on for the name studio, which no agent had any more: the owner got the reply that Studio
        cannot chat now, the bridge was told "stored", and the message reached nobody."""
        def rename():
            with hub.transaction():
                hub.rename_rows("studio", "nova", hub.now())
            return hub.renamed_team(hub.TEAM, "studio", "nova")
        before = []
        for (code, data), was_stored in self.inbound_while(rename):
            before.append(was_stored)
            self.assertEqual((code, data.get("result")), (200, "stored"))
            self.assertEqual(self.last_request()["recipient"], "nova")
            self.assertEqual(self.count("chat_out"), 0)                 # no reply that it cannot chat now
            self.assertIn("How is the scrape going?", hub.call_tool("nova", "read_messages", {}, CHAT)[0])
        self.assertEqual(before[:1], [0])

    def test_a_worker_names_the_owners_message_by_its_request_id_as_before(self):
        """A worker's chat message carries its request id, and its reply names that. The M-<id> of read_messages is the
        manager's name for a message, because the manager's messages carry no other: a worker's call is as before."""
        self.own()
        self.inbound()
        req = self.last_request()
        self.read()
        text, error = hub.call_tool("studio", "tell_owner", {"text": "On it.", "in_reply_to": f"M-{req['event_id']}"},
                                    CHAT)
        self.assertEqual((error, text), (True, "in_reply_to must be an owner request UUID."))
        self.assertIn("queued for Studio", self.tell(in_reply_to=req["request_id"]))

    def test_a_message_without_a_report_becomes_unknown_and_goes_again(self):
        self.own()
        self.inbound()
        req = self.last_request()
        self.read()
        self.tell(in_reply_to=req["request_id"])
        item = [i for i in self.out() if i["kind"] == "message"][0]
        hub.chat_sweep(hub.now() + 119)
        self.assertEqual(self.request()[1]["reports"][0]["delivery"]["state"], "sending")
        hub.chat_sweep(hub.now() + 121)
        delivery = self.request()[1]["reports"][0]["delivery"]
        self.assertEqual((delivery["state"], delivery["outbound"]), ("unknown", item["id"]))
        code, data = self.post(f"/ui/outbound/{item['id']}/again")
        self.assertEqual(code, 200, data)
        self.assertEqual((data["outbound"]["again_of"], data["outbound"]["state"]), (item["id"], "queued"))
        self.assertEqual(hub.q1("SELECT state FROM chat_out WHERE id=?", (item["id"],))["state"], "unknown")
        delivery = self.request()[1]["reports"][0]["delivery"]
        self.assertEqual((delivery["state"], delivery["outbound"]), ("queued", data["outbound"]["id"]))
        again = self.out()
        self.assertEqual((again[0]["text"], again[0]["reply_to"]), (item["text"], item["reply_to"]))
        self.report(again[0]["id"])
        self.assertEqual(self.post(f"/ui/outbound/{again[0]['id']}/again")[0], 409)          # it was sent
        self.assertEqual(self.post("/ui/outbound/999/again")[0], 404)
        typing = hub.q1("SELECT id FROM chat_out WHERE kind='typing'")["id"]
        self.assertEqual(self.post(f"/ui/outbound/{typing}/again")[0], 404)
        # the bridge's late report of the unknown item is still accepted
        self.report(item["id"], state="failed", parts=0, platform_ids=[], error="x" * 400)
        row = hub.q1("SELECT state, error FROM chat_out WHERE id=?", (item["id"],))
        self.assertEqual((row["state"], len(row["error"])), ("failed", 300))

    def test_the_long_poll_waits_without_the_lock_and_wakes_for_a_new_item(self):
        self.own()
        result = {}
        poll = threading.Thread(target=lambda: result.update(answer=self.bridge("/bridge/out?wait=4")))
        start = time.time()
        poll.start()
        time.sleep(0.5)
        self.assertEqual(self.inbound("/whoami")[0], "stored")         # the hub's lock is free while the poll waits
        poll.join(5)
        code, data = result["answer"]
        self.assertEqual((code, [i["text"] for i in data["items"]]), (200, ["You are the owner."]))
        self.assertLess(time.time() - start, 3)
        self.assertEqual(self.bridge("/bridge/out?wait=x")[0], 400)

    def test_a_stop_of_the_hub_answers_the_long_poll_at_once(self):
        """The owner's "Yes, build both" of 16 November 2026: a restart of the hub in its own process waits for the
        open requests, so the bridge's poll answers as soon as the hub stops (hub.STOPPING), as at the end of its
        wait, and the bridge asks again on a new connection, which the new code takes."""
        self.own()
        self.addCleanup(hub.STOPPING.clear)
        result = {}
        poll = threading.Thread(target=lambda: result.update(answer=self.bridge("/bridge/out?wait=20")))
        poll.start()
        time.sleep(0.5)
        self.assertEqual(result, {})                        # it waits
        hub.STOPPING.set()
        poll.join(5)
        code, data = result["answer"]
        self.assertEqual((code, data["items"]), (200, []))

    def test_pause_all_holds_the_outbound_queue(self):
        self.own()
        self.inbound("/whoami")
        self.post("/ui/chat-apps/pause", paused=True)
        self.assertEqual(self.out(), [])
        self.assertTrue(self.bridge("/bridge/config")[1]["paused"])
        state = self.request()[1]
        self.assertEqual(state["chat_apps"], {"paused": True, "problems": 2})
        self.assertTrue(self.request("/ui/chat-apps?db=test-generation")[1]["paused"])
        self.post("/ui/chat-apps/pause", paused=False)
        self.assertEqual(self.texts(), ["You are the owner."])
        self.assertEqual(self.post("/ui/chat-apps/pause", paused="yes")[0], 400)

    def test_the_whatsapp_daily_limit_fails_new_messages(self):
        self.own("whatsapp", OWNER_WA)
        with hub.LOCK, hub.transaction():
            hub.chat_count("whatsapp-main", "parts", hub.now(), 199)
        self.inbound("/whoami", account="whatsapp-main", sender=OWNER_WA)
        item = self.out()[0]
        self.report(item["id"], parts=1)
        self.inbound("Status?", account="whatsapp-main", sender=OWNER_WA)
        req = self.last_request()
        self.read("manager")
        self.out()
        self.tell("manager", None, text="All good.", in_reply_to=req["request_id"])
        self.assertEqual(self.out(), [])
        delivery = self.request()[1]["reports"][0]["delivery"]
        self.assertEqual((delivery["state"], delivery["error"]), ("failed", "daily WhatsApp limit"))
        code, data = self.post(f"/ui/outbound/{delivery['outbound']}/again")
        self.assertEqual((code, data["outbound"]["state"]), (200, "failed"))
        self.assertEqual(self.request("/ui/chat-apps?db=test-generation")[1]["accounts"][1]["sent_today"], 200)
        # Discord has no such limit
        with hub.LOCK, hub.transaction():
            hub.chat_count("discord-studio", "parts", hub.now(), 500)
        self.own()
        self.inbound("/whoami")
        self.assertEqual(self.texts(), ["You are the owner."])

    def test_stale_typing_items_expire_and_other_items_are_done_when_given_out(self):
        self.own("whatsapp", OWNER_WA)
        self.inbound("Status?", account="whatsapp-main", sender=OWNER_WA)
        self.read("manager")
        hub.q("UPDATE chat_out SET created=created-200 WHERE kind='typing'")
        self.assertEqual([i["kind"] for i in self.out()], ["read"])
        self.assertEqual({r["kind"]: r["state"] for r in hub.q("SELECT kind, state FROM chat_out")},
                         {"typing": "expired", "read": "done"})
        read = hub.q1("SELECT id FROM chat_out WHERE kind='read'")["id"]
        self.assertEqual(self.bridge(f"/bridge/out/{read}", {"state": "sent"})[0], 409)

    # ---- team.json and owner routes
    def test_team_json_takes_only_the_chat_apps_of_this_round(self):
        def team(**accounts):
            t = json.loads(json.dumps(TEAM))
            t["chat_apps"] = accounts
            return t
        good = {"app": "whatsapp", "label": "Fleet", "agents": ["manager"], "unknown": "ignore", "enabled": False}
        hub.validate_team(team(**{"w-1": good, "0x": dict(good, agents=["vps"]), "w-2": dict(good, agents=["vps"])}))
        hub.validate_team(team(**{"d": {"app": "discord", "label": "S", "agents": ["studio"], "unknown": "ignore"}}))
        refused = [({"W": good}, "needs an ID"), ({"a" * 41: good}, "needs an ID"), ({"-a": good}, "needs an ID"),
                   ({"w": dict(good, extra=1)}, "unknown field extra"), ({"w": dict(good, app="sms")}, "app must be"),
                   ({"w": dict(good, label="")}, "label must be"), ({"w": dict(good, label="a\nb")}, "label must be"),
                   ({"w": dict(good, label="x" * 41)}, "label must be"),
                   ({"w": dict(good, agents=[])}, "exactly one configured agent"),
                   ({"w": dict(good, agents=["ghost"])}, "exactly one configured agent"),
                   ({"w": dict(good, agents="manager")}, "exactly one configured agent"),
                   ({"w": dict(good, agents=[5])}, "exactly one configured agent"),
                   ({"w": dict(good, agents=["manager", "studio"])}, "exactly one configured agent"),     # 17.5
                   ({"w": dict(good, agents=["studio", "studio"])}, "exactly one configured agent"),
                   ({"d": dict(good, app="discord", agents=["manager", "studio"])}, "exactly one configured agent"),
                   ({"w": dict(good, default="manager")}, "default is gone"),
                   ({"w": dict(good, agents=["manager", "studio"], default="studio")}, "default is gone"),
                   ({"w": dict(good, unknown="ask")}, "unknown must be ignore"),
                   ({"w": {k: v for k, v in good.items() if k != "unknown"}}, "unknown must be ignore"),
                   ({"w": dict(good, enabled="yes")}, "enabled must"),
                   ({f"a{i}": good for i in range(17)}, "up to 16")]
        for accounts, words in refused:
            with self.subTest(words=words), self.assertRaisesRegex(ValueError, words):
                hub.validate_team(team(**accounts))
        bad = json.loads(json.dumps(TEAM))
        bad["chat_apps"] = []
        with self.assertRaisesRegex(ValueError, "chat_apps must map"):
            hub.validate_team(bad)

    def test_the_owner_adds_changes_and_removes_a_chat_app_account(self):
        def sha():
            return self.request("/ui/team?db=test-generation")[1]["sha256"]

        def save(**fields):
            return self.post("/ui/team/chat-apps", base_sha256=sha(), **fields)

        def origin_team():
            return json.loads(git("--git-dir", str(self.root / "origin.git"), "show", "main:team.json"))
        version = self.bridge("/bridge/config")[1]["version"]
        account = {"app": "discord", "label": " VPS bot ", "agents": ["vps"], "unknown": "ignore"}
        code, data = save(id="discord-vps", account=account)
        self.assertEqual(code, 200, data)
        self.assertEqual((data["id"], data["account"]["label"], data["changed"]), ("discord-vps", "VPS bot", True))
        self.assertEqual(origin_team()["chat_apps"]["discord-vps"], dict(account, label="VPS bot"))
        self.assertEqual(hub.chat_apps()["discord-vps"]["label"], "VPS bot")              # applied at once
        config = self.bridge("/bridge/config")[1]
        self.assertNotEqual(config["version"], version)
        self.assertEqual(config["version"], hub.chat_version())
        self.assertIn({"id": "discord-vps", "app": "discord", "label": "VPS bot", "enabled": True, "removed": None},
                      config["accounts"])
        self.assertEqual(save(id="discord-vps", account=dict(account, label="VPS bot"))[1]["changed"], False)
        for fields, status, words in (({"id": "Bad", "account": None}, 400, "id must be"),
                                      ({"id": "x", "account": "no"}, 400, "account must be"),
                                      ({"id": "x"}, 400, "account must be"),
                                      ({"id": "x", "account": dict(account, agents=["vps", "studio"])}, 400,
                                       "exactly one configured agent"),
                                      ({"id": "x", "account": dict(account, app="whatsapp", agents=["vps", "studio"],
                                                                   default="vps")}, 400, "default is gone"),
                                      ({"id": "x", "account": dict(account, unknown="anyone")}, 400, "unknown must be"),
                                      ({"id": "x", "account": None, "extra": 1}, 400, "unknown field extra")):
            with self.subTest(fields=fields):
                code, data = save(**fields)
                self.assertEqual(code, status, data)
                self.assertIn(words, data["error"])
        code, data = self.post("/ui/team/chat-apps", base_sha256="0" * 64, id="discord-vps", account=None)
        self.assertEqual(code, 409, data)
        code, data = save(id="discord-vps", account=None)
        self.assertEqual((code, data["changed"]), (200, True), data)
        self.assertNotIn("discord-vps", origin_team()["chat_apps"])
        self.assertEqual(save(id="discord-vps", account=None)[1]["changed"], False)
        for aid in ("discord-studio", "whatsapp-main"):
            self.assertEqual(save(id=aid, account=None)[0], 200)
        self.assertNotIn("chat_apps", origin_team())

    def test_a_removed_account_leaves_nothing_for_an_account_added_again_under_its_id(self):
        """CHAT-APPS.md 18.4: a number that the owner removed and connected again read the old account's report, its
        link and its last message until the bridge reported the new one."""
        def sha():
            return self.request("/ui/team?db=test-generation")[1]["sha256"]

        def save(**fields):
            return self.post("/ui/team/chat-apps", base_sha256=sha(), **fields)

        def view(aid):
            return next((a for a in self.request("/ui/chat-apps?db=test-generation")[1]["accounts"] if a["id"] == aid), None)

        def config():
            return self.bridge("/bridge/config")[1]
        account = dict(TEAM["chat_apps"]["whatsapp-main"])
        self.bridge("/bridge/status", {"accounts": [{"id": "whatsapp-main", "state": "connected", "name": "34911222333",
                                                     "user": "34911222333:4@s.whatsapp.net"}]})
        self.bridge("/bridge/link", {"account": "whatsapp-main", "state": "linked", "qr": None, "expires": None})
        hub.q("INSERT INTO chat_in(account,msg_id,chat,sender,result,request_id,created) VALUES(?,?,?,?,?,NULL,?)",
              ("whatsapp-main", "old-1", "34600111222@s.whatsapp.net", "34600111222@s.whatsapp.net", "ignored", hub.now() - 60))
        hub.q("INSERT INTO chat_ignored(account,sender,name,preview,ts) VALUES('whatsapp-main','34699000000@s.whatsapp.net',"
              "'Unknown','Hello',?)", (hub.now() - 30,))
        with hub.LOCK, hub.transaction():
            waiting = hub.chat_queue("message", "whatsapp-main", hub.now(), chat="34600111222@s.whatsapp.net", text="soon")
            typing = hub.chat_queue("typing", "whatsapp-main", hub.now(), chat="34600111222@s.whatsapp.net", seconds=600)
            other = hub.chat_queue("message", "discord-studio", hub.now(), chat="700", text="stays")
        before = view("whatsapp-main")
        self.assertEqual((before["state"], before["user"], before["link"]["state"]),
                         ("connected", "34911222333:4@s.whatsapp.net", "linked"))
        self.assertIsNotNone(before["last_event"])
        self.assertEqual((config()["removed"], [a["removed"] for a in config()["accounts"]]), ([], [None, None]))
        version = hub.chat_version()
        started = hub.now()

        self.assertEqual(save(id="whatsapp-main", account=None)[0], 200)
        for table in ("chat_status", "chat_link", "chat_ignored"):
            self.assertIsNone(hub.q1(f"SELECT 1 FROM {table} WHERE account='whatsapp-main'"), table)
        # The bridge reads the configuration again for the hub's word of the account that left: the version counts it.
        plain = hashlib.sha256(json.dumps(hub.chat_apps(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertNotEqual(hub.chat_version(), plain)
        self.assertEqual(hub.q1("SELECT state, error FROM chat_out WHERE id=?", (waiting,))["state"], "failed")
        self.assertEqual(hub.q1("SELECT error FROM chat_out WHERE id=?", (waiting,))["error"], hub.REMOVED_ACCOUNT)
        self.assertEqual(hub.q1("SELECT state FROM chat_out WHERE id=?", (typing,))["state"], "expired")
        self.assertEqual(hub.q1("SELECT state FROM chat_out WHERE id=?", (other,))["state"], "queued")   # another account's
        self.assertIsNotNone(hub.q1("SELECT 1 FROM chat_in WHERE account='whatsapp-main'"), "the messages are history")
        gone = config()
        self.assertEqual((gone["removed"], [a["id"] for a in gone["accounts"]]), (["whatsapp-main"], ["discord-studio"]))
        self.assertGreaterEqual(hub.chat_removed()["whatsapp-main"], started)

        self.assertEqual(save(id="whatsapp-main", account=account)[0], 200)          # the same fields, a new account
        again = view("whatsapp-main")
        self.assertEqual((again["state"], again["user"], again["name"], again["link"], again["status_at"], again["last_event"]),
                         (None, None, None, None, None, None))
        new = config()
        self.assertEqual(new["removed"], [])
        self.assertEqual({a["id"]: a["removed"] for a in new["accounts"]},
                         {"discord-studio": None, "whatsapp-main": hub.chat_removed()["whatsapp-main"]})
        self.assertNotEqual(hub.chat_version(), version, "the bridge must read the configuration again")
        self.assertEqual(new["version"], hub.chat_version())
        hub.q("INSERT INTO chat_in(account,msg_id,chat,sender,result,request_id,created) VALUES(?,?,?,?,?,NULL,?)",
              ("whatsapp-main", "new-1", "34600111222@s.whatsapp.net", "34600111222@s.whatsapp.net", "ignored", hub.now() + 1))
        self.assertIsNotNone(view("whatsapp-main")["last_event"])
        # Only the owner's own removal forgets an account. A team that only does not name one (a reload of another
        # revision of team.json) ends no phone's link and deletes nothing, and a team that names the same accounts
        # (a rename of an agent keeps the IDs of its accounts) removes nothing.
        marks, team = hub.chat_removed(), json.loads(json.dumps(hub.TEAM))
        self.bridge("/bridge/status", {"accounts": [{"id": "discord-studio", "state": "connected", "user": "4444"}]})
        hub.apply_team(json.loads(json.dumps(team)))
        without = json.loads(json.dumps(team))
        del without["chat_apps"]["discord-studio"]
        hub.apply_team(without)
        self.assertEqual(hub.chat_removed(), marks)
        self.assertIsNotNone(hub.q1("SELECT 1 FROM chat_status WHERE account='discord-studio'"))
        self.assertEqual(self.bridge("/bridge/config")[1]["removed"], [])
        hub.apply_team(team)

    def test_a_removed_bot_leaves_no_token_on_the_hubs_disk(self):
        def sha():
            return self.request("/ui/team?db=test-generation")[1]["sha256"]
        token = os.path.join(hub.CFG["chat_apps_dir"], "discord-studio.json")
        kept = os.path.join(hub.CFG["chat_apps_dir"], "discord-other.json")
        os.makedirs(hub.CFG["chat_apps_dir"], exist_ok=True)
        for path in (token, kept):
            with open(path, "w") as f:
                json.dump({"token": "x" * 60}, f)
        self.bridge("/bridge/status", {"accounts": [{"id": "discord-studio", "state": "connected", "user": "4444",
                                                     "name": "Fleet Studio", "application_id": "5555"}]})
        code, data = self.post("/ui/team/chat-apps", base_sha256=sha(), id="discord-studio", account=None)
        self.assertEqual(code, 200, data)
        self.assertFalse(os.path.exists(token))
        self.assertTrue(os.path.exists(kept), "only the removed account's file goes")
        self.assertIsNone(hub.q1("SELECT 1 FROM chat_status WHERE account='discord-studio'"))
        self.assertIn("removed the bot token file of discord-studio",
                      hub.q1("SELECT what FROM log WHERE what LIKE 'forgot the bridge%' ORDER BY id DESC LIMIT 1")["what"])

    def test_a_new_bot_under_a_removed_bots_id_does_not_catch_up_on_its_chats(self):
        """The catch-up after a restart reads the Discord messages after each chat's last one (`chats`). A chat of the
        bot that left is not the new bot's."""
        def sha():
            return self.request("/ui/team?db=test-generation")[1]["sha256"]
        account = dict(TEAM["chat_apps"]["discord-studio"])
        self.own()
        self.inbound()
        self.assertEqual([c["chat"] for c in self.bridge("/bridge/config")[1]["chats"]], ["dm-1"])
        for new in (None, account):
            self.assertEqual(self.post("/ui/team/chat-apps", base_sha256=sha(), id="discord-studio", account=new)[0], 200)
        config = self.bridge("/bridge/config")[1]
        self.assertEqual(config["chats"], [])
        self.assertIsNotNone(next(a for a in config["accounts"] if a["id"] == "discord-studio")["removed"])

    def test_an_account_of_the_other_app_under_the_same_id_is_a_new_account(self):
        def sha():
            return self.request("/ui/team?db=test-generation")[1]["sha256"]
        os.makedirs(hub.CFG["chat_apps_dir"], exist_ok=True)
        token = os.path.join(hub.CFG["chat_apps_dir"], "discord-studio.json")
        with open(token, "w") as f:
            json.dump({"token": "x" * 60}, f)
        self.bridge("/bridge/status", {"accounts": [{"id": "discord-studio", "state": "connected", "user": "4444",
                                                     "name": "Fleet Studio", "application_id": "5555"}]})
        number = {"app": "whatsapp", "label": "Studio", "agents": ["studio"], "unknown": "ignore"}
        code, data = self.post("/ui/team/chat-apps", base_sha256=sha(), id="discord-studio", account=number)
        self.assertEqual(code, 200, data)
        self.assertFalse(os.path.exists(token))
        self.assertIsNone(hub.q1("SELECT 1 FROM chat_status WHERE account='discord-studio'"),
                          "the bot's report would read as a connected number")
        entry = next(a for a in self.bridge("/bridge/config")[1]["accounts"] if a["id"] == "discord-studio")
        self.assertEqual((entry["app"], entry["removed"]), ("whatsapp", hub.chat_removed()["discord-studio"]))
        # A change that keeps the app (its label) is the same account.
        before = hub.chat_removed()
        code, data = self.post("/ui/team/chat-apps", base_sha256=sha(), id="discord-studio", account=dict(number, label="S"))
        self.assertEqual((code, hub.chat_removed()), (200, before), data)

    def test_owner_views_of_the_accounts_and_the_whatsapp_link(self):
        self.own()
        self.inbound()
        code, data = self.request("/ui/chat-apps?db=test-generation")
        self.assertEqual(code, 200, data)
        self.assertEqual((data["paused"], data["inbound_today"]), (False, 0))     # the owner's are in no count (B9 0d)
        self.assertIsNotNone(data["bridge_seen"])
        discord, wa = data["accounts"]
        self.assertEqual({k: discord[k] for k in ("id", "app", "label", "agents", "default", "unknown", "enabled", "state",
                                                  "invite_url", "link", "sent_today", "ignored_today")},
                         {"id": "discord-studio", "app": "discord", "label": "Studio", "agents": ["studio"],
                          "default": "studio", "unknown": "ignore", "enabled": True, "state": None, "invite_url": None,
                          "link": None, "sent_today": 0, "ignored_today": 0})
        self.assertIsNotNone(discord["last_event"])
        self.assertEqual((wa["default"], wa["last_event"]), ("manager", None))
        self.assertEqual(set(discord), {"id", "app", "label", "agents", "default", "unknown", "enabled", "state", "user",
                                        "name", "error", "application_id", "invite_url", "status_at", "last_event",
                                        "sent_today", "ignored_today", "link", "owner_wrote"})
        # a message of the owner's came in through the Discord account only (CHAT-APPS.md 19.4)
        self.assertEqual((discord["owner_wrote"], wa["owner_wrote"]), (True, False))
        # No console line in the API: the token is pasted into the app and POST /ui/chat-apps/<id>/token writes the
        # file. An API that carries a shell command invites an app to draw one.
        self.assertNotIn("setup", discord)
        self.assertNotIn("mkdir", json.dumps(data))
        # the bridge reports its state
        code, data = self.bridge("/bridge/status", {"accounts": [
            {"id": "discord-studio", "state": "connected", "user": "4444", "name": "Fleet Studio",
             "application_id": "5555", "error": None},
            {"id": "whatsapp-main", "state": "logged_out", "user": None, "name": None, "application_id": None,
             "error": "logged out on the phone"},
            {"id": "gone", "state": "connected"}]})
        self.assertEqual((code, data), (200, {"db": "test-generation", "ok": True}))
        self.assertEqual(self.bridge("/bridge/status", {"accounts": [{"id": "x", "state": "fine"}]})[0], 400)
        self.assertIsNone(hub.kv_get("bridge_code"), "a bridge from before its own code check sends none")
        self.assertEqual(self.bridge("/bridge/status", {"accounts": [], "code": "c0de" * 16})[0], 200)
        self.assertEqual(hub.kv_get("bridge_code"), "c0de" * 16)
        self.assertEqual(self.bridge("/bridge/status", {"accounts": [], "code": "old"})[0], 400)
        self.assertEqual(self.bridge("/bridge/status", {"accounts": [{"id": "discord-studio", "state": "connected",
                                                                      "application_id": "1&x=2"}]})[0], 400)
        discord, wa = self.request("/ui/chat-apps?db=test-generation")[1]["accounts"]
        self.assertEqual((discord["state"], discord["name"], discord["invite_url"]),
                         ("connected", "Fleet Studio",
                          "https://discord.com/oauth2/authorize?client_id=5555&scope=bot&permissions=0"))
        self.assertEqual((wa["state"], wa["error"]), ("logged_out", "logged out on the phone"))
        self.assertEqual(self.request()[1]["chat_apps"], {"paused": False, "problems": 1})
        # the WhatsApp link: one link item, the QR text only on its own route
        code, data = self.post("/ui/chat-apps/whatsapp-main/link")
        self.assertEqual(code, 200, data)
        self.assertEqual(self.out(), [{"id": data["outbound"], "kind": "link", "account": "whatsapp-main"}])
        self.assertEqual(self.post("/ui/chat-apps/discord-studio/link")[0], 409)
        self.assertEqual(self.post("/ui/chat-apps/nope/link")[0], 404)
        code, data = self.bridge("/bridge/link", {"account": "whatsapp-main", "state": "waiting", "qr": "2@QRTEXT",
                                                  "expires": hub.now() + 20, "error": None})
        self.assertEqual(code, 200, data)
        self.assertEqual(self.bridge("/bridge/link", {"account": "discord-studio", "state": "waiting"})[0], 409)
        self.assertEqual(self.bridge("/bridge/link", {"account": "whatsapp-main", "state": "done"})[0], 400)
        code, link = self.request("/ui/chat-apps/whatsapp-main/link?db=test-generation")
        self.assertEqual((code, link["state"], link["qr"]), (200, "waiting", "2@QRTEXT"))
        self.assertEqual(self.request("/ui/chat-apps?db=test-generation")[1]["accounts"][1]["link"]["state"], "waiting")
        self.assertNotIn("QRTEXT", json.dumps(self.request()[1]))
        self.assertNotIn("QRTEXT", json.dumps(self.request("/ui/chat-apps?db=test-generation")[1]))
        self.bridge("/bridge/link", {"account": "whatsapp-main", "state": "linked", "qr": None, "expires": None})
        self.assertIsNone(self.request("/ui/chat-apps/whatsapp-main/link?db=test-generation")[1]["qr"])
        # a new request: the earlier report is not its answer, so the app waits for the bridge's next one
        self.bridge("/bridge/link", {"account": "whatsapp-main", "state": "error", "qr": None, "expires": None,
                                     "error": "wa-link is not running."})
        self.assertEqual(self.post("/ui/chat-apps/whatsapp-main/link")[0], 200)
        self.assertEqual([i["kind"] for i in self.out()], ["link"])
        self.assertEqual(self.request("/ui/chat-apps/whatsapp-main/link?db=test-generation")[1],
                         {"db": "test-generation", "state": None, "qr": None, "expires": None, "error": None})
        self.assertIsNone(self.request("/ui/chat-apps?db=test-generation")[1]["accounts"][1]["link"])
        code, data = self.post("/ui/chat-apps/whatsapp-main/unlink")
        self.assertEqual(self.out(), [{"id": data["outbound"], "kind": "unlink", "account": "whatsapp-main"}])
        self.assertEqual(self.request("/ui/chat-apps?db=old")[0], 409)
        self.assertEqual(self.request("/ui/chat-apps?db=test-generation", headers={"Origin": "https://x"})[0], 403)

    def test_state_features_and_the_bridge_config(self):
        state = self.request()[1]
        self.assertIn("chat_apps", state["ui_features"])
        self.assertIn("people", state["ui_features"])
        self.assertEqual(state["chat_apps"], {"paused": False, "problems": 2})
        self.own()
        self.inbound()
        self.inbound("hi", sender="555")
        self.own("whatsapp", OWNER_WA)
        self.inbound("hi", account="whatsapp-main", sender=OWNER_WA)
        hub.q("INSERT INTO chat_in(account,msg_id,chat,sender,result,created) VALUES('discord-studio','old','dm-old',"
              "'x','stored',?)", (hub.now() - 8 * 86400,))
        config = self.bridge("/bridge/config")[1]
        self.assertEqual(config["accounts"], [{"id": "discord-studio", "app": "discord", "label": "Studio", "enabled": True,
                                               "removed": None},
                                              {"id": "whatsapp-main", "app": "whatsapp", "label": "Fleet", "enabled": True,
                                               "removed": None}])
        self.assertEqual(config["removed"], [])         # no account ever left this fleet (CHAT-APPS.md 18.4)
        self.assertEqual(config["chats"], [{"account": "discord-studio", "chat": "dm-1", "last": "m2"}])
        self.assertEqual((config["db"], config["paused"]), ("test-generation", False))


# ---------------------------------------------------------------- an agent's files in chats (CHAT-APPS.md 20)

CANARY, CANARY_SALT = "SPARROW-CANARY-9931", "canary-salt"


def pdf(*streams, extra=b""):
    """A small PDF: a catalog, `extra` in its syntax, and one object for each (dictionary, plain bytes) stream, packed
    with FlateDecode."""
    out = [b"%PDF-1.7\n", b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n", extra]
    for i, (dictionary, plain) in enumerate(streams, 3):
        body = zlib.compress(plain)
        out.append(b"%d 0 obj << %s /Filter /FlateDecode /Length %d >>\nstream\n" % (i, dictionary, len(body)) + body +
                   b"\nendstream\nendobj\n")
    out.append(b"trailer << /Root 1 0 R >>\n%%EOF\n")
    return b"".join(out)


def office(parts=None, main="xl/workbook.xml"):
    """An Office file: its content types, its main part, and the other parts, {name: text}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as package:
        if "[Content_Types].xml" not in (parts or {}):
            package.writestr("[Content_Types].xml", "<Types/>")
        if main:
            package.writestr(main, "<workbook/>")
        for name, text in (parts or {}).items():
            package.writestr(name, text)
    return buf.getvalue()


ZSTANDARD = 93      # Python 3.14's zipfile unpacks it whole too; an older one cannot write it


def office_packed(method):
    """A spreadsheet whose main part is packed with `method` (bzip2, LZMA, or Zstandard, whose number is written into
    the headers of a stored part, so that each Python makes it), of 2 MiB of zeros: small to keep, so a test never
    unpacks hundreds of MiB."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as package:
        package.writestr("[Content_Types].xml", "<Types/>")
        package.writestr("xl/workbook.xml", "<workbook/>" + "\0" * (2 << 20),
                         compress_type=zipfile.ZIP_STORED if method == ZSTANDARD else method)
    data = buf.getvalue()
    if method == ZSTANDARD:
        return entry_says(data, "xl/workbook.xml", method=ZSTANDARD)
    return data


def central_entry(data, name):
    """Where the central directory of the ZIP `data` holds its entry `name`."""
    at = data.find(b"PK\x01\x02")
    while data[at + 46:at + 46 + int.from_bytes(data[at + 28:at + 30], "little")] != name.encode():
        assert at >= 0, name
        at = data.find(b"PK\x01\x02", at + 4)
    return at


def entry_says(data, name, **fields):
    """The ZIP `data` with fields of its entry `name` (flags, method, crc, csize, usize) changed in its local header and
    in the central directory, which zipfile reads."""
    out, at = bytearray(data), central_entry(data, name)
    local = int.from_bytes(out[at + 42:at + 46], "little")
    for field, value in fields.items():
        offset, size = {"flags": (6, 2), "method": (8, 2), "crc": (14, 4), "csize": (18, 4), "usize": (22, 4)}[field]
        for head in (local + offset, at + 2 + offset):      # each field is 2 bytes further in the central directory
            out[head:head + size] = value.to_bytes(size, "little")
    return bytes(out)


def entry_again(data, name, times=1):
    """The ZIP `data` whose central directory names the packed bytes of its entry `name` `times` times more."""
    out, at = bytearray(data), central_entry(data, name)
    entry = bytes(out[at:at + 46 + sum(struct.unpack_from("<HHH", out, at + 28))])
    end = out.rfind(b"PK\x05\x06")
    count, size = struct.unpack_from("<HI", out, end + 10)
    struct.pack_into("<HHI", out, end + 8, count + times, count + times, size + len(entry) * times)
    return bytes(out[:at] + entry * times + out[at:])


def png(*chunks):
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", bytes(13)) + b"".join(chunk(k, b) for k, b in chunks) + \
        chunk(b"IEND", b"")


def jpeg(comment):
    return b"\xff\xd8\xff\xfe" + struct.pack(">H", len(comment) + 2) + comment + b"\xff\xda\x00\x02\x00\xff\xd9"


PDF_FILE = pdf((b"", b"BT /F1 12 Tf 72 712 Td (Invoice for October) Tj ET"))
# PDFs whose pages draw their words in a font's codes (CHAT-APPS.md 20.2), as Chrome writes them: a Type0 font with
# Identity-H, whose ToUnicode map gives the letters of glyph numbers of two bytes, A at <0024> (glyphs), in each of a
# map's three forms (bfchar, bfrange, and bfrange with an array), and "fi" in one glyph, <00C0>, as Chrome draws it.
CHROME_MAP = (b"/CIDInit /ProcSet findresource begin 12 dict begin begincmap\n1 begincodespacerange\n<0000> <FFFF>\n"
              b"endcodespacerange\n2 beginbfchar\n<0003> <0020>\n<00C0> <FB01>\nendbfchar\n3 beginbfrange\n"
              b"<0010> <001D> <002D>\n<0024> <003D> [" + b" ".join(b"<%04X>" % c for c in range(0x41, 0x5B)) +
              b"]\n<0044> <005D> <0061>\nendbfrange\nendcmap CMapName currentdict /CMap defineresource pop end end\n")
CHROME_FONT = (b"<< /Type /Font /Subtype /Type0 /BaseFont /AAAAAA+Helvetica /Encoding /Identity-H "
               b"/DescendantFonts [4 0 R] /ToUnicode 6 0 R >>")
CHROME_CID = (b"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /AAAAAA+Helvetica /CIDToGIDMap /Identity "
              b"/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> >>")
ROBIN, ROBIN_SALT = "ROBIN-fiord-7720", "robin-salt"        # a made-up key with "fi" in it


def pdf_of(objects, root=1):
    """A PDF of numbered objects, {number: dictionary} or {number: (dictionary, stream bytes)}: a stream is packed with
    FlateDecode."""
    out = [b"%PDF-1.7\n"]
    for num, value in sorted(objects.items()):
        if isinstance(value, tuple):
            body = zlib.compress(value[1])
            out.append(b"%d 0 obj\n<< %s /Filter /FlateDecode /Length %d >>\nstream\n" % (num, value[0], len(body)) +
                       body + b"\nendstream\nendobj\n")
        else:
            out.append(b"%d 0 obj\n%s\nendobj\n" % (num, value))
    out.append(b"trailer << /Root %d 0 R >>\n%%%%EOF\n" % root)
    return b"".join(out)


def glyphs(text):
    """Text in the glyph numbers of CHROME_MAP, as a hex string: A is <0024>, and fi is one glyph."""
    return b"<" + "".join("00C0" if part == "fi" else "%04X" % (ord(part) - 29)
                          for part in re.findall("fi|.", text, re.S)).encode() + b">"


def chrome_pdf(content, fonts=b"/F1 3 0 R", more=None):
    """A PDF of one page that draws `content`, with the fonts `fonts` in its resources: /F1 is CHROME_FONT. `more`
    adds objects, or puts others in their place."""
    objects = {1: b"<< /Type /Catalog /Pages 2 0 R >>", 2: b"<< /Type /Pages /Count 1 /Kids [5 0 R] >>",
               3: CHROME_FONT, 4: CHROME_CID, 6: (b"", CHROME_MAP), 7: (b"", content),
               5: b"<< /Type /Page /Parent 2 0 R /Resources << /Font << %s >> >> /Contents 7 0 R >>" % fonts}
    objects.update(more or {})
    return pdf_of(objects)


class AgentFiles(ChatApps):
    """An agent's file with its words: the upload line, the check of the bytes, the four tools that carry it, the
    bridge's read of the bytes, Send again, the daily limit of a WhatsApp number, the sweep and the sending window."""
    def setUp(self):
        super().setUp()
        self.files = tempfile.TemporaryDirectory(prefix="fleet-agent-files-")
        self.addCleanup(self.files.cleanup)
        hub.CFG["attachment_dir"] = self.files.name
        self.addCleanup(hub.CFG.pop, "attachment_dir", None)
        self.addCleanup(hub.CHAT_FILE_UPLOADS.clear)

    # ---- helpers
    def raw(self, method, path, data=None, headers=None, source="127.0.0.3"):
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers=dict({"X-Test-Source": source}, **(headers or {})))
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with op.open(req, timeout=30) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as r:
            with r:
                return r.code, r.read(), dict(r.headers)

    def line(self, agent="manager", name="Invoice October.pdf", context=None):
        text, error = hub.call_tool(agent, "attach_file", {"name": name}, context)
        self.assertFalse(error, text)
        return re.search(r'/attachment/file/([A-Za-z0-9_-]+)"', text).group(1), text

    def put(self, token, data):
        code, body, _ = self.raw("POST", f"/attachment/file/{token}", data,
                                 {"Content-Type": "application/octet-stream"})
        return code, body.decode()

    def attach(self, data=PDF_FILE, agent="manager", name="Invoice October.pdf", context=None):
        code, text = self.put(self.line(agent, name, context)[0], data)
        self.assertEqual(code, 200, text)
        return int(re.match(r"A-(\d+) ", text).group(1))

    def canary(self):
        hub.ins("INSERT INTO secrets(label,salt,hash,len) VALUES(?,?,?,?)",
                ("canary", CANARY_SALT, hashlib.sha256((CANARY_SALT + CANARY).encode()).hexdigest(), len(CANARY)))

    def bridge_file(self, aid, item):
        return self.raw("GET", f"/bridge/files/{aid}?item={item}", headers={"Authorization": f"Bearer {self.key}"},
                        source=BRIDGE)

    def messages(self):
        return [i for i in self.out() if i["kind"] == "message"]

    def task_context(self, owner="studio"):
        with hub.LOCK, hub.transaction():
            tid = hub.admit_task("manager", {"owner": owner, "title": "Make the invoice", "details": "",
                                             "done_when": "sent", "needs": "none", "goal": None, "goal_id": None,
                                             "parent": None, "follows": None, "case_id": None})
        hub.q("UPDATE tasks SET state='working', started=? WHERE id=?", (hub.now(), tid))
        return ("test-generation", hub.tref(tid), "1")

    def owner_message(self, files, request_id=None, text="Here is the October invoice."):
        return hub.call_tool("manager", "message_owner", {"request_id": request_id or str(uuid.uuid4()), "text": text,
                                                          "files": files}, None)

    # ---- the upload
    def test_attach_file_gives_one_line_and_its_upload_names_the_file(self):
        token, text = self.line(name="../Invoice: October?.pdf")
        self.assertIn("curl -sS --fail-with-body --data-binary @'<path>'", text)
        self.assertIn("The person sees it as __Invoice_ October_.pdf.", text)
        self.assertEqual(self.count("attachments"), 0)              # nothing is on the hub before the upload
        code, said = self.put(token, PDF_FILE)
        self.assertEqual(code, 200, said)
        aid = int(re.match(r"A-(\d+) ", said).group(1))
        self.assertEqual(said, f"A-{aid} __Invoice_ October_.pdf (PDF, 1 KB) is on the hub for one hour. Give A-{aid} "
                               f"in files of the message that sends it.\n")
        row = hub.q1("SELECT * FROM attachments WHERE id=?", (aid,))
        self.assertEqual((row["agent"], row["mime"], row["size"], row["sha256"], row["message"], row["report"],
                          row["cm"], row["carried"]),
                         ("manager", "application/pdf", len(PDF_FILE), hashlib.sha256(PDF_FILE).hexdigest(), None, None,
                          None, None))
        self.assertEqual(hub.attachment_bytes(row), PDF_FILE)
        self.assertEqual(self.put(token, PDF_FILE)[0], 404)          # one use
        logs = json.dumps([dict(r) for r in hub.q("SELECT * FROM log")])
        self.assertNotIn(token, logs)
        # an ended line takes nothing
        token, _ = self.line()
        hub.CHAT_FILE_UPLOADS[token]["ends"] = hub.now() - 1
        self.assertEqual(self.put(token, PDF_FILE), (404, "This upload line is not valid: it was used, or it ended. "
                                                          "Call attach_file for a new one.\n"))
        # a name of any other extension, or of none, is a text file (owner API 1.361), kept as "<name>.txt" unless its
        # ending is a plain text one, and only text goes up under it: a ZIP or a workbook with macros named so is
        # refused
        for name, data, seen, said in (
                ("run.sh", b"echo hello\n", "run.sh.txt (the hub added .txt",
                 "run.sh.txt (text file, 1 KB) is on the hub"),
                ("deploy.yaml", b"on: push\n", "deploy.yaml.", "deploy.yaml (text file, 1 KB) is on the hub"),
                ("Makefile", b"all:\n", "Makefile.", "Makefile (text file, 1 KB) is on the hub"),
                ("report.zip", b"PK\x03\x04\xff\x00", "report.zip.txt", "Not taken: a text file must be UTF-8 text."),
                ("macro.xlsm", b"PK\x03\x04\x00", "macro.xlsm.txt", "Not taken: a text file must hold no NUL byte.")):
            token, text = self.line(name=name)
            self.assertIn(f"The person sees it as {seen}", text)
            self.assertIn("It goes as a text file", text)
            code, answer = self.put(token, data)
            self.assertIn(said, answer, name)
            self.assertEqual(code, 415 if answer.startswith("Not taken") else 200, answer)
        self.assertEqual(hub.q1("SELECT mime FROM attachments WHERE name='run.sh.txt'")["mime"], "text/plain")
        text, error = hub.call_tool("manager", "attach_file", {"name": "  "}, None)
        self.assertTrue(error, text)

    def test_a_chat_app_s_file_is_kept_under_a_name_that_runs_nothing(self):
        """Owner API 1.361: a file that a person or the owner sent through a chat app is kept as an agent's file is,
        under a name that runs nothing on the owner's computer, because his apps save and open a file under its name
        and a hub release reaches them before any app update: a text file named invoice.bat or invoice.html, and a
        program of a type that the hub does not check, and a Word file that would fetch its template, get ".txt"; a
        voice note, a plain Word file and a name with no ending keep theirs. The owner's route serves a sound as its
        own type and any other type that the hub does not check as bytes."""
        self.own()
        template = office_file("Budget", [("word/_rels/settings.xml.rels",
                                           '<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.'
                                           'org/officeDocument/2006/relationships/attachedTemplate" '
                                           'Target="http://x.example/t.dotm" TargetMode="External"/></Relationships>')])
        cases = (("invoice.bat", "text/plain", b"@echo off\n", "invoice.bat.txt"),
                 # the apps cut a name at 80 and add its ending: the cut takes the stem, and the safe name comes after
                 ("b" * 90 + ".bat", "text/plain", b"@echo off\n", "b" * 76 + ".bat.txt"),
                 ("c" * 90 + ".md", "text/plain", b"# Notes\n", "c" * 77 + ".md"),
                 # Word would fetch its template from another computer: kept as data, under a name Word does not open
                 ("Budget.docx", hub.DOCX, template, "Budget.docx.txt"),
                 ("Plain.docx", hub.DOCX, office_file("Budget"), "Plain.docx"),
                 ("invoice.html", "application/octet-stream", b"<script>fetch('/')</script>\n", "invoice.html.txt"),
                 ("notes", "text/plain", b"Notes\n", "notes"),
                 ("voice.ogg", "audio/ogg", b"OggS\x00\x02" + bytes(64), "voice.ogg"),
                 ("setup.exe", "application/x-msdownload", b"MZ\x90\x00" + bytes(64), "setup.exe.txt"))
        ids = {}
        for n, (name, mime, data, kept) in enumerate(cases, 1):
            code, up = self.bridge_upload(data, f"m-name-{n}", mime=mime, name=name)
            self.assertEqual(code, 200, (name, up))
            ids[name] = up["id"]
            self.assertEqual(hub.q1("SELECT name FROM attachments WHERE id=?", (up["id"],))["name"], kept)
        # a sound goes as its own type, which no browser runs; a program of a type that the hub does not check as bytes
        for name, served in (("voice.ogg", "audio/ogg"), ("setup.exe", "application/octet-stream")):
            code, _, headers = self.raw("GET", f"/ui/attachments/{ids[name]}?db=test-generation", source="127.0.0.1")
            self.assertEqual((code, headers["Content-Type"], headers["X-Content-Type-Options"]),
                             (200, served, "nosniff"), name)

    def test_an_office_part_is_read_no_further_than_its_stated_size(self):
        """zipfile unpacks up to the size that a read asks and cuts the result to the part's stated size, so a part that
        states 0 bytes and holds MiB of zeros made the hub unpack up to all of CHAT_FILE_UNPACK for nothing, at each
        part (a review of 22 November 2026: 1.4 MiB with 24 such parts, 1,440 MiB unpacked), and its text was never
        searched. The budget counts the stated sizes, a part is unpacked no further than its stated size and one byte,
        and a part that states less than it holds is refused: a person's login after the stated size was in no text."""
        name, long = "xl/sharedStrings.xml", "<sst>" + "x " * (2 << 20) + "</sst>"
        file = office({name: long})
        self.assertIn("x x x", " ".join(hub.ooxml_texts(file, hub.XLSX, "spreadsheet")))
        body = ("<sst>" + "<si><t>ordinary words</t></si>\n" * 4000 + "<si><t>KEY=at-the-end</t></si></sst>").encode()
        honest = office({name: body.decode()})
        info = zipfile.ZipFile(io.BytesIO(honest)).getinfo(name)
        packed, start = info.compress_size, info.header_offset + 30 + len(name)    # zipfile writes no extra field here
        cut = packed // 2                                       # the stream goes on after its stated packed bytes
        begun = zlib.decompressobj(-15).decompress(honest[start:start + cut])
        lies = {"states 0 bytes": entry_says(file, name, usize=0),
                "stored, states 0 bytes": entry_says(office_file("x" * 99, stored=True), "word/document.xml", usize=0),
                "states one byte less": entry_says(honest, name, usize=len(body) - 1, crc=zlib.crc32(body[:-1])),
                "states 1,000 bytes past its packed size": entry_says(honest, name, usize=packed + 1000,
                                                                      crc=zlib.crc32(body[:packed + 1000])),
                "packs less than its stream": entry_says(honest, name, csize=cut, usize=len(begun),
                                                         crc=zlib.crc32(begun)),
                # 5,000 entries that name the same packed bytes would make the hub read them 5,000 times
                "names its packed bytes twice": entry_again(office({name: "".join(
                    hashlib.sha256(b"%d" % n).hexdigest() for n in range(1000))}), name),
                # zipfile's constructor holds some 500 bytes for each entry, and an agent's file had no count before it
                "has 50,000 entries": entry_again(office({name: "<sst/>"}), "[Content_Types].xml", 50_000),
                # zipfile's open refuses these flags, and ooxml_part does not call it: an encrypted part (ZipCrypto) was
                # read as plain deflate, and its bytes can be a stream of their own
                **{f"flags {bit:#x}": entry_says(honest, name, flags=bit) for bit in (0x01, 0x20, 0x40)}}
        for lie, data in lies.items():
            mime, kind = (hub.DOCX, "Word document") if lie.startswith("stored") else (hub.XLSX, "spreadsheet")
            for inbound in (False, True):
                tracemalloc.start()
                try:
                    with self.assertRaises(hub.Refusal, msg=(lie, inbound)) as refused:
                        list(hub.ooxml_texts(data, mime, kind, inbound=inbound))
                    peak = tracemalloc.get_traced_memory()[1]
                finally:
                    tracemalloc.stop()
                self.assertEqual((refused.exception.status, str(refused.exception)),
                                 (415, f"these bytes are not a {kind}"), (lie, inbound))
                self.assertLess(peak, 1 << 20, (lie, inbound))        # 4 MiB unpacked would be the budget's read
        with patch.object(hub, "CHAT_FILE_UNPACK", 1000):           # a part that states more than is left
            with self.assertRaises(hub.Refusal) as refused:
                list(hub.ooxml_texts(file, hub.XLSX, "spreadsheet", inbound=True))
        self.assertEqual(refused.exception.status, 413)

    def test_an_office_part_that_packs_larger_than_it_states_is_read(self):
        """Writers pack in their own ways: .NET's old deflater starts each stream with a tree of 98 bytes (a part of 139
        bytes of an Office theme that Office ships packs to 229), and a writer that flushes at each write adds an empty
        block of 5 bytes each time. A limit on the packed size (the second round of 22 November 2026) refused 120 of
        the 32,323 XML parts of 365 Office files that programs ship; the test of the stream itself reads
        each of them. And a writer may pack a part of 0 bytes as deflate of 0 bytes, which zipfile reads as empty."""
        xml = (b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n<a:themeManager xmlns:a="http://schemas.'
               b'openxmlformats.org/drawingml/2006/main"/>')
        pack = zlib.compressobj(9, zlib.DEFLATED, -15)
        packed = b"\x00\x00\x00\xff\xff" * 20 + pack.compress(xml) + pack.flush()     # 20 empty stored blocks first
        self.assertGreater(len(packed), len(xml) + 5 * 1 + 16)                      # past the second round's limit
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as package:     # written stored, and then its headers say deflate
            package.writestr("[Content_Types].xml", "<Types/>")
            package.writestr("xl/workbook.xml", "<workbook/>")
            package.writestr("xl/theme/themeManager.xml", packed)
            package.writestr("xl/empty.xml", b"")    # and a part of 0 bytes, packed as deflate of no bytes
        file = entry_says(buf.getvalue(), "xl/theme/themeManager.xml", method=zipfile.ZIP_DEFLATED, usize=len(xml),
                          crc=zlib.crc32(xml))
        file = entry_says(file, "xl/empty.xml", method=zipfile.ZIP_DEFLATED)
        self.assertEqual(zipfile.ZipFile(io.BytesIO(file)).read("xl/theme/themeManager.xml"), xml)
        self.assertEqual(zipfile.ZipFile(io.BytesIO(file)).read("xl/empty.xml"), b"")
        for inbound in (False, True):
            self.assertIn("a:themeManager", " ".join(hub.ooxml_texts(file, hub.XLSX, "spreadsheet", inbound=inbound)))

    def test_the_upload_checks_the_bytes_before_the_hub_keeps_them(self):
        self.canary()
        secret = CANARY.encode()
        refused = [
            ("a.pdf", b"not a pdf", 415, "these bytes are not a PDF"),
            ("a.pdf", pdf(extra=b"2 0 obj << /S /JavaScript /JS (app.alert(1)) >> endobj\n"), 415,
             "a PDF that runs a script, carries a file or launches a program cannot go to a chat"),
            ("a.pdf", pdf(extra=b"2 0 obj << /S /J#61vaScript >> endobj\n"), 415, "a PDF that runs a script"),
            ("a.pdf", pdf((b"/Type /ObjStm /N 1 /First 4", b"5 0 << /Type /Filespec /EF << /F 6 0 R >> /EmbeddedFile 7 "
                                                         b"0 R >>")), 415, "carries a file"),
            ("a.pdf", pdf(extra=b"trailer << /Encrypt 9 0 R >>\n"), 415, "the hub cannot read an encrypted PDF"),
            ("a.pdf", pdf((b"", b"BT (key " + secret + b") Tj ET")), 422, "the file holds a registered secret"),
            ("a.pdf", pdf(extra=b"2 0 obj << /Author (" + secret + b") >> endobj\n"), 422, "registered secret"),
            ("a.xlsx", b"PK\x03\x04 nothing", 415, "these bytes are not a spreadsheet"),
            ("a.xlsx", office(main=None), 415, "these bytes are not a spreadsheet"),
            ("a.xlsx", office(main="word/document.xml"), 415, "these bytes are not a spreadsheet"),
            # a part of bzip2 or LZMA is unpacked whole at its first read, whatever the limit (no Office app writes one)
            ("a.xlsx", office_packed(zipfile.ZIP_BZIP2), 415, "these bytes are not a spreadsheet"),
            ("a.xlsx", office_packed(zipfile.ZIP_LZMA), 415, "these bytes are not a spreadsheet"),
            ("a.xlsx", office_packed(ZSTANDARD), 415, "these bytes are not a spreadsheet"),     # an allow-list
            ("a.docx", entry_says(office({"word/document.xml": "<w:t>x</w:t>"}, main=None), "word/document.xml", crc=0),
             415, "these bytes are not a Word document"),                       # a part with a wrong CRC-32
            ("a.xlsx", office({"xl/vbaProject.bin": "x"}), 415, "a spreadsheet with a macro, an ActiveX control"),
            ("a.docx", office({"word/document.xml": "<w:t>x</w:t>", "word/embeddings/oleObject1.bin": "x",
                               "word/_rels/document.xml.rels": '<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="embeddings/oleObject1.bin"/></Relationships>'}, main=None), 415,
             "a Word document with a macro, an ActiveX control, an OLE object"),
            ("a.xlsx", office({"xl/sharedStrings.xml": f"<sst><si><t>{CANARY}</t></si></sst>"}), 422,
             "registered secret"),
            ("a.xlsx", office({"xl/_rels/workbook.xml.rels": f'<Relationship Target="https://x.example/?k={CANARY}"/>'}),
             422, "registered secret"),
            # a stream that calls itself a picture is read when its bytes are text
            ("a.pdf", pdf((b"/Type /XObject /Subtype /Image /Width 1", b"(" + secret + b")")), 422, "registered secret"),
            ("a.csv", f"name,key\nmain,{CANARY},x\n".encode(), 422, "registered secret"),
            ("a.csv", b"\xff\xfe not utf-8", 415, "a CSV file must be UTF-8 text"),
            ("a.txt", b"one\0two", 415, "a text file must hold no NUL byte"),
            ("a.png", b"GIF89a", 415, "these bytes are not a PNG picture"),
            ("a.png", png((b"tEXt", b"Comment\0" + secret)), 422, "registered secret"),
            ("a.png", png((b"zTXt", b"Comment\0\0" + zlib.compress(secret))), 422, "registered secret"),
            ("a.png", png((b"iTXt", b"Comment\0\x01\0en\0\0" + zlib.compress(secret))), 422, "registered secret"),
            ("a.jpg", jpeg(b"key " + secret), 422, "registered secret"),
            ("a.pdf", b"", 400, "the file is empty"),
            # the first review, 15 November 2026: a stream with no filter, a dictionary that holds <<, an object stream
            # whose first object is binary, an embedded file with no /Type, and a key written the way a CSV, an XML
            # part or a hidden character writes it
            ("a.pdf", b"%PDF-1.4\n3 0 obj << /Length 40 >>\nstream\nBT (key " + secret + b") Tj ET\nendstream\nendobj\n",
             422, "registered secret"),
            ("a.pdf", pdf((b"/X (<<)", b"BT (key " + secret + b") Tj ET")), 422, "registered secret"),
            ("a.pdf", pdf((b"/Type /ObjStm /N 2 /First 9", b"5 0 6 4096 (" + bytes(range(256)) * 16 + b") "
                                                           b"<< /S /JavaScript /JS (app.alert(1)) >>")), 415,
             "a PDF that runs a script"),
            ("a.pdf", b"%PDF-1.4\n3 0 obj << /Type /ObjStm /N 1 /First 4 /Length 30 >>\nstream\n5 0 << /S /Launch >>\n"
                      b"endstream\nendobj\n", 415, "launches a program"),
            ("a.pdf", pdf(extra=b"4 0 obj << /Type /Filespec /F (a.exe) /EF << /F 6 0 R >> >> endobj\n"), 415,
             "carries a file"),
            ("a.pdf", pdf(extra=b"2 0 obj << /S /Lau#6Ech >> endobj\n"), 415, "launches a program"),
            # the second review: reportlab writes [/ASCII85Decode /FlateDecode], and its page text is read through it
            ("a.pdf", b"%PDF-1.4\n3 0 obj << /Filter [/ASCII85Decode /FlateDecode] >>\nstream\n" +
             base64.a85encode(zlib.compress(b"BT (key " + secret + b") Tj ET"), wrapcol=72) + b"~>\nendstream\nendobj\n",
             422, "registered secret"),
            ("a.pdf", b"%PDF-1.4\n3 0 obj << /Type /ObjStm /N 1 /First 4 /Filter [/ASCII85Decode /FlateDecode] >>\n"
                      b"stream\n" + base64.a85encode(zlib.compress(b"5 0 << /S /JavaScript >>")) + b"~>\nendstream\n",
             415, "a PDF that runs a script"),
            ("a.csv", b"name;key\nbank;" + secret + b",x\n", 422, "registered secret"),
            ("a.txt", ("key " + CANARY[:5] + "\u200b" + CANARY[5:] + "\n").encode(), 422, "registered secret"),
            ("a.docx", office({"word/document.xml": "<w:t>" + CANARY.replace("-", "&#45;") + "</w:t>"},
                              main=None), 422, "registered secret"),
            ("a.docx", office({"word/document.xml": "<w:t>x</w:t>", "[Content_Types].xml":
                               '<Types><Default Extension="bin" ContentType="application/vnd.openxmlformats-'
                               'officedocument.oleObject"/></Types>'}, main=None), 415, "a Word document with a macro"),
            ("a.docx", office({"word/document.xml": "<w:t>x</w:t>", "word/_rels/settings.xml.rels":
                               '<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/'
                               'officeDocument/2006/relationships/attachedTemplate" Target="http://x.example/t.dotm" '
                               'TargetMode="External"/></Relationships>'}, main=None), 415,
             "a template from another computer"),
            ("a.docx", office({"word/document.xml": "<w:r><w:instrText>DD</w:instrText></w:r><w:r><w:instrText>"
                               "EAUTO c:\\x\\cmd.exe</w:instrText></w:r>"}, main=None), 415, "a Word document with a macro"),
            ("a.xlsx", office({"xl/externalLinks/externalLink1.xml": "<externalLink><ddeLink ddeService=\"cmd\"/>"
                               "</externalLink>"}), 415, "a spreadsheet with a macro"),
        ]
        for name, data, status, words in refused:
            with self.subTest(name=name, words=words, data=data[:40]):
                code, said = self.put(self.line(name=name)[0], data)
                self.assertEqual(code, status, said)
                self.assertTrue(said.startswith("Not taken: "), said)
                self.assertIn(words, said)
                self.assertTrue(said.endswith("Nothing is on the hub. Call attach_file for a new line.\n"), said)
        self.assertEqual(self.count("attachments"), 0)
        self.assertNotIn(CANARY, json.dumps([dict(r) for r in hub.q("SELECT * FROM log")]))
        # what passes: a picture's pixels in a PDF, and files with no registered login
        for name, data in (("a.pdf", pdf((b"/Type /XObject /Subtype /Image /Width 16", bytes(range(256)) * 64))),
                           ("a.pdf", PDF_FILE), ("a.xlsx", office({"xl/sharedStrings.xml": "<sst><si><t>Total</t></si></sst>"})),
                           ("a.png", png((b"tEXt", b"Comment\0a chart"))), ("a.jpg", jpeg(b"a photo")),
                           ("a.csv", b"a,b\n1,2\n"), ("a.txt", "Grüße\n".encode()),
                           # a hyperlink to a page outside is a link that a person clicks, not one that a file opens
                           ("a.docx", office({"word/document.xml": "<w:t>x</w:t>", "word/_rels/document.xml.rels":
                                              '<Relationships><Relationship Id="r3" Type="http://schemas.openxmlformats.'
                                              'org/officeDocument/2006/relationships/hyperlink" Target="https://x.'
                                              'example/" TargetMode="External"/></Relationships>'}, main=None)),
                           # a short iTXt chunk does not parse, and is read as it stands: no fault of the hub
                           ("a.png", png((b"iTXt", b"k\0\0\0en"))),
                           # the second review: ordinary files that the first rules refused
                           ("a.pdf", b"%PDF-1.4\n3 0 obj << /Filter [/ASCII85Decode /DCTDecode] >>\nstream\n" +
                            base64.a85encode(b"\xff\xd8\xff" + bytes(range(256)) * 64) + b"~>\nendstream\nendobj\n"),
                           ("a.pdf", b"%PDF-1.4\n3 0 obj << /Filter [/ASCII85Decode /FlateDecode] >>\nstream\n" +
                            base64.a85encode(zlib.compress(b"BT /F1 9 Tf (a /JS $ b) Tj ET")) + b"~>\nendstream\n"),
                           ("a.docx", office({"word/document.xml": "<w:t>x</w:t>", "word/_rels/settings.xml.rels":
                                              '<Relationships><Relationship Id="r4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="Normal" TargetMode="External"/></Relationships>'}, main=None)),
                           ("a.docx", office({"word/document.xml": "<w:t>x</w:t>", "word/_rels/document.xml.rels":
                                              '<Relationships><Relationship Id="r5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="http://x.example/a.png" TargetMode="External"/></Relationships>'}, main=None)),
                           ("a.pptx", office({"ppt/embeddings/Microsoft_Excel_Worksheet.xlsx": "chart data",
                                              "ppt/charts/_rels/chart1.xml.rels": '<Relationships><Relationship Id="r6" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/package" Target="../embeddings/Microsoft_Excel_Worksheet.xlsx"/></Relationships>'},
                                             main="ppt/presentation.xml")),
                           ("a.docx", office({"word/document.xml": '<w:r><w:instrText> INCLUDEPICTURE "http://x.'
                                                                   'example/a.png" \\* MERGEFORMATINET </w:instrText>'
                                                                   '</w:r>'}, main=None)),
                           ("a.xlsx", office({"xl/worksheets/sheet1.xml": "<c r=\"A1\"><v>1</v></c>" * 400000})),
                           ("a.csv", "".join(f"{i},{'v' * 40},{'w' * 40},x\n" for i in range(20000)).encode())):
            with self.subTest(name=name, data=data[:40]):
                code, said = self.put(self.line(name=name)[0], data)
                self.assertEqual(code, 200, said)

    def test_the_check_has_limits_of_its_own(self):
        self.canary()
        with patch.object(hub, "CHAT_FILE_UNPACK", 2000):
            code, said = self.put(self.line(name="a.xlsx")[0], office({"xl/sharedStrings.xml": "<t>" + "x " * 3000 + "</t>"}))
            self.assertEqual((code, "the spreadsheet packs more than" in said), (413, True), said)
            code, said = self.put(self.line(name="a.pdf")[0], pdf((b"", b"x " * 3000)))
            self.assertEqual((code, "the PDF packs more than" in said), (413, True), said)
        with patch.object(hub, "CHAT_FILE_HASHES", 1000):
            code, said = self.put(self.line(name="a.txt")[0], ("y" * 5000 + "\n").encode())
            self.assertEqual(code, 413, said)
            self.assertIn("too much text without spaces for the hub's check for saved keys", said)
        with patch.object(hub, "CHAT_FILE_MAX", 1000):
            code, said = self.put(self.line()[0], PDF_FILE + b" " * 1000)
            self.assertEqual((code, said), (413, "Not taken: a file is at most 0 MB.\n"))
        self.assertEqual(self.count("attachments"), 0)

    def test_a_packed_stream_of_more_than_one_piece_is_read_to_its_end(self):
        """inflate_pieces: a FlateDecode stream that inflates to more than one piece, with the line break before its
        endstream as PDFs write it. zlib gives that byte back after the end of its data at every call, and the loop
        must end there: until 16 November 2026 it ran on, and held the check of every later file. The read runs in a
        process of its own, which the timeout stops if it runs on: no loop is left in the tests' own process."""
        read = ("import sys, zlib, hub\nplain = b'0 0 m 1 1 l S\\n' * 2000\n"
                "sys.exit(b''.join(hub.inflate_pieces(zlib.compress(plain) + b'\\n', 1000)) != plain)\n")
        try:
            done = subprocess.run([sys.executable, "-B", "-c", read], cwd=os.path.dirname(os.path.abspath(hub.__file__)),
                                  capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            self.fail("inflate_pieces did not end")
        self.assertEqual(done.returncode, 0, done.stderr)

    # ---- the text that a PDF's pages draw (CHAT-APPS.md 20.2)
    def test_a_pdf_that_draws_a_login_in_a_fonts_codes_is_refused(self):
        """The owner, 15 November 2026, to reading PDF font maps: "Yes, add it". A PDF that Chrome prints draws each word
        in a font's glyph numbers, and the hub reads them in the letters of the font's ToUnicode map: a login in them
        is refused, as it is in a DOCX."""
        self.canary()
        hub.ins("INSERT INTO secrets(label,salt,hash,len) VALUES(?,?,?,?)",
                ("robin", ROBIN_SALT, hashlib.sha256((ROBIN_SALT + ROBIN).encode()).hexdigest(), len(ROBIN)))
        letters, names = "SPAROW-CNY931", {"-": "hyphen", "9": "nine", "3": "three", "1": "one"}   # CANARY's letters
        differences = b"[1 " + " ".join("/" + names.get(c, c) for c in letters).encode() + b"]"
        one_byte = (b"1 begincodespacerange\n<00> <FF>\nendcodespacerange\n2 beginbfrange\n<01> <1A> <0041>\n"
                    b"<1B> <1B> <002D>\nendbfrange\n")
        head = b"3 0 5 %d\n" % (len(CHROME_FONT) + 1)
        old_page = chrome_pdf(b"BT /F1 12 Tf 72 712 Td " + glyphs("old words") + b" Tj ET", more={
            8: (b"", b"BT /F1 12 Tf 72 712 Td " + glyphs(CANARY) + b" Tj ET")})
        later = zlib.compress(b"BT /F1 12 Tf 72 712 Td " + glyphs(CANARY) + b" Tj ET")
        packed = b"5 0 " + b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 3 0 R >> >> /Contents 8 0 R >>"
        drawn = b"BT /F1 12 Tf 72 712 Td " + glyphs(CANARY) + b" Tj " + b"".join(       # 13 KB packed after the key
            b"0 -14 Td " + glyphs(hashlib.sha256(b"%d" % i).hexdigest()[:9]) + b" Tj " for i in range(1500)) + b"ET"
        wrong = zlib.compress(drawn)
        wrong = wrong[:-1] + bytes([wrong[-1] ^ 0xFF])                  # the last byte of the checksum
        pack = zlib.compressobj()
        broken = pack.compress(drawn) + pack.flush(zlib.Z_SYNC_FLUSH) + b"\x07" + bytes(20)     # a block of no type
        cases = {
            # an update that the file appended: the later object 7 is the page's content
            "an appended object": old_page + b"7 0 obj\n<< /Filter /FlateDecode /Length %d >>\nstream\n" % len(later) +
                                  later + b"\nendstream\nendobj\ntrailer << /Root 1 0 R >>\n",
            # an object stream that the file appended: its page 5 draws stream 8, and the earlier page 5 stream 7
            "an appended object stream": old_page + b"20 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode "
                                                     b"/Length %d >>\nstream\n" % len(zlib.compress(packed)) +
                                         zlib.compress(packed) + b"\nendstream\nendobj\ntrailer << /Root 1 0 R >>\n",
            # an object that the file appended after an object stream with the same number
            "an object after an object stream": chrome_pdf(b"BT /F1 12 Tf 72 712 Td " + glyphs("old words") + b" Tj ET",
                                                           more={5: b"<< >>", 8: (b"", b"BT /F1 12 Tf 72 712 Td " +
                                                                                   glyphs(CANARY) + b" Tj ET"),
                                                                 20: (b"/Type /ObjStm /N 1 /First 4",
                                                                      b"5 0 << /Type /Page /Parent 2 0 R /Resources << "
                                                                      b"/Font << /F1 3 0 R >> >> /Contents 7 0 R >>")})
            + b"5 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 3 0 R >> >> /Contents 8 0 R >>\n"
              b"endobj\ntrailer << /Root 1 0 R >>\n",
            # an object stream whose header lists its objects out of the order of their offsets
            "offsets out of order": pdf_of({1: b"<< /Type /Catalog /Pages 2 0 R >>", 2: b"<< /Type /Pages /Count 1 /Kids "
                                                                                     b"[5 0 R] >>",
                                            4: CHROME_CID, 6: (b"", CHROME_MAP), 7: (b"", b"BT /F1 12 Tf " +
                                                                                       glyphs(CANARY) + b" Tj ET"),
                                            10: (b"/Type /ObjStm /N 2 /First %d" % len(b"5 %d 3 0\n" % (len(CHROME_FONT)
                                                                                                        + 1)),
                                                 b"5 %d 3 0\n" % (len(CHROME_FONT) + 1) + CHROME_FONT + b"\n<< /Type "
                                                 b"/Page /Parent 2 0 R /Resources << /Font << /F1 3 0 R >> >> /Contents "
                                                 b"7 0 R >>")}),
            # a page whose /Contents is an array, with the key in its second stream
            "a second content stream": chrome_pdf(b"BT /F1 12 Tf 72 712 Td " + glyphs("first part") + b" Tj ET", more={
                5: b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 3 0 R >> >> /Contents [7 0 R 8 0 R] >>",
                8: (b"", b"BT /F1 12 Tf 72 700 Td " + glyphs(CANARY) + b" Tj ET")}),
            # a page whose fonts are in the page tree above it
            "fonts of the page tree": chrome_pdf(b"BT /F1 12 Tf 72 712 Td " + glyphs(CANARY) + b" Tj ET", more={
                2: b"<< /Type /Pages /Count 1 /Kids [5 0 R] /Resources << /Font << /F1 3 0 R >> >> >>",
                5: b"<< /Type /Page /Parent 2 0 R /Contents 7 0 R >>"}),
            # a form that no page draws: the look of an annotation, with fonts of its own
            "a form that no page draws": chrome_pdf(b"BT /F1 12 Tf 72 712 Td " + glyphs("nothing") + b" Tj ET", more={
                8: (b"/Type /XObject /Subtype /Form /BBox [0 0 100 20] /Resources << /Font << /F1 3 0 R >> >>",
                    b"BT /F1 12 Tf 2 2 Td " + glyphs(CANARY) + b" Tj ET")}),
            # a key that wraps at its hyphen after a paragraph of more than 1,024 letters with spaces
            "a key that wraps after a paragraph": chrome_pdf(b"BT /F1 14 Tf 1 0 0 -1 8 235 Tm " +
                                                             glyphs("lorem ipsum dolor sit amet " * 60 + "SPARROW-") +
                                                             b" Tj ET\nBT /F1 14 Tf 1 0 0 -1 8 251 Tm " +
                                                             glyphs("CANARY-9931 and more") + b" Tj ET"),
            # a Tm that stays on the line after a run of 1,100 letters: no line break inside the key
            "a Tm on the line after a long run": chrome_pdf(b"BT /F1 9 Tf 1 0 0 -1 8 45 Tm " +
                                                            glyphs("x" * 1100 + "SPARROW-CAN") +
                                                            b" Tj 1 0 0 -1 99 45 Tm " + glyphs("ARY-9931") + b" Tj ET"),
            # Chrome: one line in BT and ET, and the key in two strings with a kerning step between them
            "a kerning step": chrome_pdf(b"BT\n/F1 14 Tf\n1 0 0 -1 8 113 Tm\n" + glyphs("Key SPARROW-CAN") +
                                         b" Tj\n59.137695 0 Td " + glyphs("ARY-9931 end.") + b" Tj\nET"),
            # the same after a run of 1,100 letters with no space: a step on the line is no new line
            "a kerning step after a long run": chrome_pdf(b"BT /F1 9 Tf 1 0 0 -1 8 45 Tm " + glyphs("x" * 1100 +
                                                                                                "SPARROW-CAN") +
                                                          b" Tj 59.1 0 Td " + glyphs("ARY-9931") + b" Tj ET"),
            # the numbers of a TJ array fall inside the key
            "TJ kerning": chrome_pdf(b"BT /F1 12 Tf 72 712 Td [" + glyphs("SPARR") + b" -12 " + glyphs("OW-CANA") +
                                     b" 30.5 " + glyphs("RY-9931") + b"] TJ ET"),
            # the key wraps at its hyphen onto the next line, and each line is in its own BT and ET
            "a key that wraps": chrome_pdf(b"BT /F1 14 Tf 1 0 0 -1 8 235 Tm " + glyphs("words SPARROW-") + b" Tj ET\n"
                                           b"BT /F1 14 Tf 1 0 0 -1 8 251 Tm " + glyphs("CANARY-9931 and more") +
                                           b" Tj ET"),
            # a simple font with a map of one-byte codes, literal strings with escapes, and ' and " too
            "a one-byte map": chrome_pdf(b"BT /F2 12 Tf 72 712 Td (\\023\\020\\001\\022\\022\\017\\027\\033) Tj "
                                         b"(\\003\\001\\016\\001\\022\\031\\033) ' 0 0 (9931) \" ET", fonts=b"/F2 8 0 R",
                                         more={8: b"<< /Type /Font /Subtype /TrueType /BaseFont /AAAAAB+Arial "
                                                  b"/ToUnicode 9 0 R >>", 9: (b"", one_byte)}),
            # a standard font with no map, whose codes are its letters: here in a hex string, as pdf-lib writes them
            "a standard font": chrome_pdf(b"BT /F3 12 Tf 72 712 Td <" + CANARY.encode().hex().encode() + b"> Tj ET",
                                          fonts=b"/F3 8 0 R", more={8: b"<< /Type /Font /Subtype /Type1 /BaseFont "
                                                                       b"/Helvetica /Encoding /WinAnsiEncoding >>"}),
            # a font whose /Differences names the glyphs of its codes
            "glyph names": chrome_pdf(b"BT /F4 12 Tf 72 712 Td <" + "".join("%02X" % (letters.index(c) + 1)
                                                                             for c in CANARY).encode() + b"> Tj ET",
                                      fonts=b"/F4 8 0 R", more={8: b"<< /Type /Font /Subtype /Type1 /BaseFont "
                                                                   b"/AAAAAC+CMR10 /Encoding << /Differences %s >> >>"
                                                                   % differences}),
            # a font of Adobe's Korean collection with no map: its codes 1 to 95 are the ASCII letters (the Mac's print
            # system writes such a font)
            "a CJK font with no map": chrome_pdf(
                b"BT /F5 12 Tf 72 712 Td <" + "".join("%04X" % (ord(c) - 31) for c in CANARY).encode() + b"> Tj ET",
                fonts=b"/F5 8 0 R", more={8: b"<< /Type /Font /Subtype /Type0 /BaseFont /AAAAAB+AppleSDGothicNeo "
                                             b"/Encoding /Identity-H /DescendantFonts [9 0 R] >>",
                                          9: b"<< /Type /Font /Subtype /CIDFontType0 /BaseFont /AAAAAB+AppleSDGothicNeo "
                                             b"/CIDSystemInfo << /Registry (Adobe) /Ordering (Korea1) /Supplement 0 >> "
                                             b">>"}),
            # a form that the page draws (Do), with resources of its own, and the page and the font in an object stream
            "a form": pdf_of({1: b"<< /Type /Catalog /Pages 2 0 R >>", 2: b"<< /Type /Pages /Count 1 /Kids [5 0 R] >>",
                              4: CHROME_CID, 6: (b"", CHROME_MAP), 7: (b"", b"q /X1 Do Q"),
                              8: (b"/Type /XObject /Subtype /Form /BBox [0 0 612 792] /Resources << /Font << /F1 3 0 R "
                                  b">> >>", b"BT /F1 12 Tf 72 712 Td " + glyphs(CANARY) + b" Tj ET"),
                              10: (b"/Type /ObjStm /N 2 /First %d" % len(head),
                                   head + CHROME_FONT + b"\n<< /Type /Page /Parent 2 0 R /Resources << /XObject << /X1 8 "
                                                        b"0 R >> >> /Contents 7 0 R >>")}),
            # a form with no resources of its own draws in the fonts of the page that draws it
            "a form in the page's fonts": chrome_pdf(b"q /X1 Do Q", fonts=b"/F1 3 0 R >> /XObject << /X1 8 0 R", more={
                8: (b"/Type /XObject /Subtype /Form /BBox [0 0 612 792]",
                    b"BT /F1 12 Tf 72 712 Td " + glyphs(CANARY) + b" Tj ET")}),
            # Chrome draws "fi" in one glyph, which its map gives as U+FB01
            "a ligature": chrome_pdf(b"BT /F1 12 Tf 72 712 Td " + glyphs("key " + ROBIN) + b" Tj ET"),
            # a page's stream in ASCII85 over FlateDecode, as reportlab writes it
            "a stream in ASCII85": chrome_pdf(b"", more={7: b"<< /Filter [/ASCII85Decode /FlateDecode] >>\nstream\n" +
                                                           base64.a85encode(zlib.compress(b"BT /F1 12 Tf " +
                                                                                          glyphs(CANARY) + b" Tj ET"))
                                                           + b"~>\nendstream"}),
            # a page's stream whose zlib checksum is wrong, which readers of PDFs show: read as raw deflate data
            "a wrong checksum": chrome_pdf(b"", more={7: b"<< /Filter /FlateDecode /Length %d >>\nstream\n" %
                                                        len(wrong) + wrong + b"\nendstream"}),
            # a page's stream with a break near its end, long after the key: read up to the break, a KB at a time
            "a break after the key": chrome_pdf(b"", more={7: b"<< /Filter /FlateDecode /Length %d >>\nstream\n" %
                                                             len(broken) + broken + b"\nendstream"}),
            # a tagged page: 70,000 sequences of marked content, each with a dictionary that closes, before the key
            "a tagged page": chrome_pdf(b"/P <</MCID 0>> BDC EMC " * 70000 + b"BT /F1 12 Tf 72 712 Td " +
                                        glyphs(CANARY) + b" Tj ET"),
        }
        for name, data in cases.items():
            with self.subTest(name):
                self.assertEqual(self.put(self.line(name="a.pdf")[0], data),
                                 (422, "Not taken: the file holds a registered secret. Nothing is on the hub. Call "
                                       "attach_file for a new line.\n"))
        self.assertEqual(self.count("attachments"), 0)

    def test_the_text_that_a_pdf_draws_and_where_its_spaces_go(self):
        """What the hub reads of a PDF's pages (pdf_drawn_texts): the words as the page draws them, with a space only
        where a glyph or the gap of a word puts one, and runs that stay short for the search, also in a file whose
        strings hold no space."""
        drawn = lambda data: "".join(hub.pdf_drawn_texts(data))
        invoice = chrome_pdf(b"BT\n/F1 28 Tf\n1 0 0 -1 8 45 Tm\n" + glyphs("Invoice for Oct") + b" Tj\n90.5 0 Td " +
                             glyphs("ober") + b" Tj\nET")
        self.assertEqual(drawn(invoice), "Invoice for October")
        # pdfTeX draws no space glyph: a TJ number of -250 or less (a quarter of the font's size) is a space, a kerning
        # number is none; and a line goes on in the next, since a line can end inside a login
        tex = chrome_pdf(b"BT /F3 10 Tf 72 720 Td " + b"[(W)83(ord)-333(another)-250(one)-249(two)]TJ 0 -12 Td " * 3 +
                         b"ET", fonts=b"/F3 8 0 R", more={8: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"})
        self.assertEqual(drawn(tex), "Word another onetwo" * 3)
        # a file whose strings hold no space: a line break at the first new line after CHAT_FILE_WRAP letters
        dense = chrome_pdf(b"BT /F1 9 Tf 72 720 Td " + (glyphs("x" * 64) + b" Tj 0 -10 Td ") * 3000 + b"ET")
        text = drawn(dense)
        self.assertEqual(text.replace("\n", ""), "x" * 192000)
        self.assertEqual(set(map(len, text.split()[:-1])), {1024})   # a break after 16 lines of 64: 1,024 letters
        # the same break after a long run at each kind of new line: a Tm that leaves the line, BT, T*, ', " and a form
        x, y = glyphs("x" * 1100), glyphs("y")
        for name, content in (("Tm", b"BT /F1 9 Tf " + x + b" Tj 1 0 0 1 9 30 Tm " + y + b" Tj ET"),
                              ("BT", b"BT /F1 9 Tf " + x + b" Tj ET BT /F1 9 Tf " + y + b" Tj ET"),
                              ("T*", b"BT /F1 9 Tf " + x + b" Tj T* " + y + b" Tj ET"),
                              ("'", b"BT /F1 9 Tf " + x + b" Tj " + y + b" ' ET"),
                              ('"', b"BT /F1 9 Tf " + x + b" Tj 0 0 " + y + b' " ET'),
                              ("a form", b"BT /F1 9 Tf " + x + b" Tj ET /X1 Do")):
            with self.subTest(new_line=name):
                form = {8: (b"/Type /XObject /Subtype /Form /BBox [0 0 9 9]", b"/F1 9 Tf " + y + b" Tj")}  # no BT
                page = chrome_pdf(content, fonts=b"/F1 3 0 R >> /XObject << /X1 8 0 R", more=form if
                                  name == "a form" else None)
                self.assertEqual(drawn(page), "x" * 1100 + "\ny")
        # fonts written in each page's own dictionary, with two maps that change every two pages (the second has each
        # letter 256 codes later), after one small dictionary: a page's dictionary is not kept, and with a cache by id
        # alone this Mac's Python gave a later page the font of an earlier one in 133 of 400 pages
        later = CHROME_MAP.replace(b"<0003> <0020>", b"<0103> <0020>").replace(b"<0010> <001D>", b"<0110> <011D>")
        objects, kids = {1: b"<< /Type /Catalog /Pages 2 0 R >>", 6: (b"", CHROME_MAP), 9: (b"", later.replace(
            b"<0024> <003D>", b"<0124> <013D>").replace(b"<0044> <005D>", b"<0144> <015D>"))}, []
        for i in range(400):
            shift = 0x100 * ((i // 2) % 2)
            objects[1000 + 2 * i] = (b"<< /Type /Page /Parent 2 0 R /Group << /S /Transparency >> /Resources << /Font << "
                                     b"/F1 << /Type /Font /Subtype /Type0 /Encoding /Identity-H /ToUnicode %d 0 R >> >> >> "
                                     b"/Contents %d 0 R >>" % (9 if shift else 6, 1001 + 2 * i))
            objects[1001 + 2 * i] = (b"", b"BT /F1 12 Tf <" + b"".join(b"%04X" % (ord(c) - 29 + shift) for c in CANARY)
                                     + b"> Tj ET")
            kids.append(b"%d 0 R" % (1000 + 2 * i))
        objects[2] = b"<< /Type /Pages /Count 400 /Kids [%s] >>" % b" ".join(kids)
        self.assertEqual(drawn(pdf_of(objects)).count(CANARY), 400)
        # a form that a page draws twice, and a content stream that two pages share, are read once
        twice = chrome_pdf(b"q /X1 Do Q q /X1 Do Q", fonts=b"/F1 3 0 R >> /XObject << /X1 8 0 R", more={
            8: (b"/Type /XObject /Subtype /Form /BBox [0 0 612 792]", b"BT /F1 12 Tf " + glyphs("once") + b" Tj ET")})
        self.assertEqual(drawn(twice), "once")
        shared = chrome_pdf(b"BT /F1 12 Tf " + glyphs("once") + b" Tj ET", more={
            2: b"<< /Type /Pages /Count 2 /Kids [5 0 R 9 0 R] >>",
            9: b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 3 0 R >> >> /Contents 7 0 R >>"})
        self.assertEqual(drawn(shared), "once")
        repeated = chrome_pdf(b"BT /F1 12 Tf " + glyphs("once") + b" Tj ET", more={
            5: b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 3 0 R >> >> /Contents [%s] >>"
               % b" ".join([b"7 0 R"] * 1000)})
        self.assertEqual(drawn(repeated), "once")
        # a form begins with the font of the stream that draws it
        inherits = chrome_pdf(b"BT /F1 12 Tf ET /X1 Do", fonts=b"/F1 3 0 R >> /XObject << /X1 8 0 R", more={
            8: (b"/Type /XObject /Subtype /Form /BBox [0 0 612 792]", b"BT " + glyphs("KEY 42") + b" Tj ET")})
        self.assertEqual(drawn(inherits), "KEY 42")
        # the details of PDF syntax and of fonts that the text depends on
        simple = b"/F3 8 0 R"
        helvetica = {8: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"}
        cjk = lambda ordering, encoding=b"Identity-H", tounicode=b"": chrome_pdf(
            b"BT /F5 12 Tf <" + "".join("%04X" % (ord(c) - 31) for c in "KEY 42").encode() + b"> Tj ET",
            fonts=b"/F5 8 0 R", more={8: b"<< /Type /Font /Subtype /Type0 /Encoding /%s %s/DescendantFonts [9 0 R] >>"
                                         % (encoding, tounicode),
                                      9: b"<< /Type /Font /Subtype /CIDFontType0 /CIDSystemInfo << /Registry (Adobe) "
                                         b"/Ordering (%s) /Supplement 0 >> >>" % ordering})
        for name, data, letters in (
                ("an inline picture", chrome_pdf(b"BI /W 2 /H 2 /CS /G /BPC 8 ID \x00(KEY)Tj BT\x01 EI BT /F3 9 Tf (ok) Tj ET",
                                                 fonts=simple, more=helvetica), "ok"),
                ("ASCIIHex", chrome_pdf(b"", fonts=simple, more={**helvetica, 7: b"<< /Filter /ASCIIHexDecode >>\n"
                                        b"stream\n" + b"BT /F3 9 Tf (hex 42) Tj ET".hex().encode() + b">\nendstream"}),
                 "hex 42"),
                ("a line that a literal string continues", chrome_pdf(b"BT /F3 9 Tf (SPAR\\\nROW) Tj ET", fonts=simple,
                                                                      more=helvetica), "SPARROW"),
                ("nested parentheses", chrome_pdf(b"BT /F3 9 Tf (a (b) \\(c) Tj ET", fonts=simple, more=helvetica),
                 "a (b) (c"),
                ("an odd hex string", chrome_pdf(b"BT /F3 9 Tf <41424> Tj ET", fonts=simple, more=helvetica), "AB@"),
                ("hex strings in a TJ", chrome_pdf(b"BT /F3 9 Tf [<41424> <4 1>] TJ ET", fonts=simple, more=helvetica),
                 "AB@A"),
                ("WinAnsi", chrome_pdf(b"BT /F3 9 Tf <80> Tj ET", fonts=simple, more=helvetica), "\u20ac"),
                ("Identity-V", chrome_pdf(b"BT /F1 9 Tf " + glyphs("KEY 42") + b" Tj ET", more={
                    3: CHROME_FONT.replace(b"Identity-H", b"Identity-V")}), "KEY 42"),
                ("Japan1", cjk(b"Japan1"), "KEY 42"), ("GB1", cjk(b"GB1"), "KEY 42"), ("CNS1", cjk(b"CNS1"), "KEY 42"),
                ("a CJK font of Identity-V", cjk(b"Korea1", encoding=b"Identity-V"), "KEY 42"),
                ("a CJK font with a map", cjk(b"Korea1", tounicode=b"/ToUnicode 6 0 R "), "ICW 20"),   # the map's
                ("a CJK font with another encoding", cjk(b"Korea1", encoding=b"UniKS-UCS2-H"), "      "),
                ("glyph names", chrome_pdf(b"BT /F4 9 Tf <0102030405> Tj ET", fonts=b"/F4 8 0 R", more={
                    8: b"<< /Type /Font /Subtype /Type1 /Encoding << /Differences [1 /uni004B /E.sc /f_i /u1F600 /zz] >> "
                       b">>"}), "KEfi\U0001f600 "),
                ("a letter of one byte in a map", chrome_pdf(b"BT /F2 9 Tf <01> Tj ET", fonts=b"/F2 8 0 R", more={
                    8: b"<< /Type /Font /Subtype /TrueType /ToUnicode 9 0 R >>",
                    9: (b"", b"1 beginbfchar <01> <42> endbfchar")}), "B")):
            with self.subTest(detail=name):
                self.assertEqual(drawn(data), letters)
        # a font whose codes have one byte or two, as its encoding's code ranges give them (Shift-JIS has such codes)
        encoding = (b"3 begincodespacerange <00> <7F> <8140> <9FFC> <20> <30> endcodespacerange")
        letters = (b"1 beginbfrange <41> <5A> <0041> endbfrange 1 beginbfchar <8140> <0020> endbfchar 1 beginbfrange "
                   b"<8141> <815A> <0061> endbfrange")
        mixed = chrome_pdf(b"BT /F6 12 Tf <4B4559814181428143> Tj ET", fonts=b"/F6 8 0 R", more={
            8: b"<< /Type /Font /Subtype /Type0 /Encoding 9 0 R /ToUnicode 10 0 R /DescendantFonts [4 0 R] >>",
            9: (b"/Type /CMap", encoding), 10: (b"", letters)})
        self.assertEqual(drawn(mixed), "KEYabc")
        with patch.object(hub, "PDF_LETTERS_KEPT", 2):                  # past the letters kept, each code in place
            self.assertEqual(drawn(mixed), "KEYabc")
        # pieces of about CHAT_FILE_CHUNK, each up to its last space, also where no string ends with a space
        prose = chrome_pdf(b"".join(b"BT /F3 10 Tf 72 %d Td (the quick brown fox jumps over the lazy dog) Tj ET\n"
                                    % (700 - 10 * (i % 60)) for i in range(300)),
                           fonts=b"/F3 8 0 R", more={8: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"})
        with patch.object(hub, "CHAT_FILE_CHUNK", 1000):
            pieces = list(hub.pdf_drawn_texts(prose))
        self.assertEqual("".join(pieces), "the quick brown fox jumps over the lazy dog" * 300)
        self.assertGreater(len(pieces), 10)
        self.assertTrue(all(piece[-1].isspace() and len(piece) < 1100 for piece in pieces[:-1]), pieces[:2])
        # what the check cannot read: the glyph numbers of a font with no map
        bare = chrome_pdf(b"BT /F1 12 Tf 72 712 Td " + glyphs(CANARY) + b" Tj ET",
                          more={3: CHROME_FONT.replace(b" /ToUnicode 6 0 R", b"")})
        self.assertEqual(drawn(bare).strip(), "")
        self.canary()
        for data in (invoice, tex, dense, bare):
            self.assertEqual(self.put(self.line(name="a.pdf")[0], data)[0], 200)

    def test_the_reader_of_a_pdfs_fonts_has_limits_and_odd_bytes_are_no_fault(self):
        """The reader of the pages keeps at most CHAT_FILE_GLYPHS entries of fonts' maps and CHAT_FILE_OBJECTS objects,
        takes at most CHAT_FILE_WORK steps, and what it unpacks and writes counts against a CHAT_FILE_UNPACK of its own:
        a file past one of them is refused, never read in part. Bytes that do not parse are the file's, never a fault
        of the hub."""
        self.canary()
        page = chrome_pdf(b"BT /F1 12 Tf 72 712 Td " + glyphs("Invoice") + b" Tj ET")
        with patch.object(hub, "CHAT_FILE_GLYPHS", 20):              # CHROME_MAP holds 31 entries
            code, said = self.put(self.line(name="a.pdf")[0], page)
            self.assertEqual((code, "the fonts of the PDF map more codes than the hub's check reads" in said),
                             (413, True), said)
        with patch.object(hub, "CHAT_FILE_OBJECTS", 5):              # the page has 7 objects
            code, said = self.put(self.line(name="a.pdf")[0], page)
            self.assertEqual((code, "the PDF holds more objects than the hub's check reads" in said), (413, True), said)
        # each kind of a map's entry counts against CHAT_FILE_GLYPHS: 40 code ranges, 40 codes, 40 ranges of codes
        for entries in (b"40 begincodespacerange " + b" ".join(b"<%02X> <%02X>" % (i, i) for i in range(40)) +
                        b" endcodespacerange",
                        b"40 beginbfchar " + b" ".join(b"<%02X> <0041>" % i for i in range(40)) + b" endbfchar",
                        b"40 beginbfrange " + b" ".join(b"<%02X> <%02X> <0041>" % (i, i) for i in range(40)) +
                        b" endbfrange"):
            with self.subTest(entries=entries[:20]), patch.object(hub, "CHAT_FILE_GLYPHS", 30):
                code, said = self.put(self.line(name="a.pdf")[0], chrome_pdf(b"BT /F1 9 Tf <0024> Tj ET", more={
                    6: (b"", entries)}))
                self.assertEqual((code, "the fonts of the PDF map more codes than the hub's check reads" in said),
                                 (413, True), said)
        # the objects of an object stream count against CHAT_FILE_OBJECTS
        head = b" ".join(b"%d %d" % (100 + i, 2 * i) for i in range(10)) + b" "
        packed = pdf_of({1: b"<< /Type /Catalog >>", 2: (b"/Type /ObjStm /N 10 /First %d" % len(head),
                                                       head + b"1 " * 10)})
        with patch.object(hub, "CHAT_FILE_OBJECTS", 8), self.assertRaisesRegex(hub.Refusal, "more objects than"):
            list(hub.pdf_drawn_texts(packed))
        self.assertEqual(list(hub.pdf_drawn_texts(packed)), [])
        # bytes whose first two are no zlib header give nothing, as in readers of PDFs, though raw deflate data with
        # words follows them: a header whose check fails, and one that names a preset dictionary
        for head in (b"\x78\x00", b"\x78\xbb"):
            deflate = zlib.compressobj(wbits=-15)
            headless = head + deflate.compress(b"BT /F1 12 Tf " + glyphs("words") + b" Tj ET") + deflate.flush()
            with self.subTest(header=head):
                self.assertEqual("".join(hub.pdf_drawn_texts(chrome_pdf(b"", more={
                    7: b"<< /Filter /FlateDecode /Length %d >>\nstream\n" % len(headless) + headless +
                       b"\nendstream"}))), "")
        # what FlateDecode inflates counts against the reader's CHAT_FILE_UNPACK
        with patch.object(hub, "CHAT_FILE_UNPACK", 1 << 20), self.assertRaisesRegex(hub.Refusal, "packs more than"):
            list(hub.pdf_drawn_texts(chrome_pdf(b"q Q " * (1 << 19))))
        # a chain of 600 forms, each with a letter: a form inside 16 others is read from the top, and the reader's
        # depth stays small
        chain = {8 + i: (b"/Type /XObject /Subtype /Form /Resources << /Font << /F1 3 0 R >> /XObject << /X 0 R >> >>"
                         .replace(b"/X 0 R", b"/X %d 0 R" % (9 + i)), b"BT /F1 9 Tf " + glyphs("a") + b" Tj ET /X Do")
                 for i in range(600)}
        text = "".join(hub.pdf_drawn_texts(chrome_pdf(b"/X Do", fonts=b"/F1 3 0 R >> /XObject << /X 8 0 R",
                                                      more=chain)))
        self.assertEqual(text.replace("\n", ""), "a" * 600)
        # each loop of the reader takes its steps: 20,000 parts of a string, tokens of syntax, numbers of syntax,
        # tokens of a map, bytes in codes of more than one length, new codes of two bytes, simple fonts' letters,
        # objects, and the pairs of an object stream
        for name, data in (
                ("parts of a string", chrome_pdf(b"BT /F1 9 Tf (" + b"\\001" * 20000 + b") Tj ET")),
                ("tokens of syntax", chrome_pdf(b"", more={5: b"<< /Type /Page /Parent 2 0 R /X [" + b"/a " * 20000 +
                                                             b"] /Contents 7 0 R >>"})),
                ("numbers of syntax", chrome_pdf(b"", more={5: b"<< /Type /Page /Parent 2 0 R /X [" + b"1 " * 20000 +
                                                              b"] /Contents 7 0 R >>"})),
                ("numbers of syntax before a word", chrome_pdf(b"", more={
                    5: b"<< /Type /Page /Parent 2 0 R /X [" + b"1 2 3 4 5 6 x " * 3000 + b"] /Contents 7 0 R >>"})),
                ("tokens of a map", chrome_pdf(b"BT /F1 9 Tf <0024> Tj ET", more={6: (b"", b"x " * 20000)})),
                ("glyph names of a map", chrome_pdf(b"BT /F1 9 Tf <0001> Tj ET", more={6: (b"", b"1000 beginbfchar " +
                    b" ".join(b"<%04X> /uni%s" % (i, b"0041" * 29) for i in range(1000)) + b" endbfchar")})),
                ("codes of more than one length", chrome_pdf(b"BT /F6 9 Tf <" + b"41" * 20000 + b"> Tj ET",
                                                             fonts=b"/F6 8 0 R", more={
                    8: b"<< /Type /Font /Subtype /Type0 /Encoding 9 0 R /DescendantFonts [4 0 R] >>",
                    9: (b"/Type /CMap", b"1 begincodespacerange <00> <FF> endcodespacerange")})),
                ("new codes of two bytes", chrome_pdf(b"BT /F1 9 Tf <" + b"".join(b"%04X" % c for c in range(20000)) +
                                                      b"> Tj ET")),
                ("simple fonts", chrome_pdf(b"BT " + b"".join(b"/F%d 9 Tf (a) Tj " % i for i in range(100)) + b"ET",
                                            fonts=b" ".join(b"/F%d %d 0 R" % (i, 100 + i) for i in range(100)),
                                            more={100 + i: b"<< /Type /Font /Subtype /Type1 >>" for i in range(100)})),
                ("objects", b"%PDF-1.7\n" + b"".join(b"%d 0 obj null endobj\n" % i for i in range(1, 20001))),
                ("pairs of an object stream", pdf_of({1: b"<< /Type /Catalog >>", 2: (
                    b"/Type /ObjStm /N 20000 /First 200000", b"".join(b"%d 0 " % (100 + i) for i in range(20000))
                    .ljust(200000))}))):
            with self.subTest(steps=name), patch.object(hub, "CHAT_FILE_WORK", 10_000):
                self.assertRaisesRegex(hub.Refusal, "draws more than", list, hub.pdf_drawn_texts(data))
        # the reader's steps: 20,000 strings and 20,000 operators, in a stream of a few KB, are refused, not read in
        # part; and so are 20,000 operators that draw nothing
        for tiny in (chrome_pdf(b"BT /F1 9 Tf " + b"(a)' " * 20000 + b"ET"), chrome_pdf(b"0 0 m " * 20000)):
            with patch.object(hub, "CHAT_FILE_WORK", 10_000):
                code, said = self.put(self.line(name="a.pdf")[0], tiny)
                self.assertEqual((code, "the PDF draws more than the hub's check reads" in said), (413, True), said)
            self.assertEqual(self.put(self.line(name="a.pdf")[0], tiny)[0], 200)
        # numbers that no operator follows: a step for each
        with patch.object(hub, "CHAT_FILE_WORK", 10_000):
            code, said = self.put(self.line(name="a.pdf")[0], chrome_pdf(b"1 " * 20000))
            self.assertEqual((code, "the PDF draws more than the hub's check reads" in said), (413, True), said)
        # the letters of codes that fonts keep: PDF_LETTERS_KEPT in all fonts, and a code past it is read where it
        # stands, with the same letters (three fonts of 4,000 codes each)
        many = chrome_pdf(b"".join(b"BT /F%d 9 Tf <" % i + b"".join(b"%04X" % c for c in range(4000)) + b"> Tj ET "
                                   for i in (1, 2, 3)), fonts=b"/F1 3 0 R /F2 8 0 R /F3 9 0 R", more={
            8: CHROME_FONT, 9: CHROME_FONT})
        whole = "".join(hub.pdf_drawn_texts(many))
        with patch.object(hub, "PDF_LETTERS_KEPT", 100):
            self.assertEqual("".join(hub.pdf_drawn_texts(many)), whole)
        self.assertEqual(self.put(self.line(name="a.pdf")[0], many)[0], 200)
        # 1,100 simple fonts on one page, as a PDF that merges many files has them: their letters take steps only
        fonts = b" ".join(b"/F%d %d 0 R" % (i, 100 + i) for i in range(1100))
        merged = chrome_pdf(b"BT " + b"".join(b"/F%d 9 Tf (%s) Tj " % (i, b"ab"[i % 2:i % 2 + 1]) for i in range(1100))
                            + b"ET", fonts=fonts, more={100 + i: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
                                                                 b"/Encoding /WinAnsiEncoding >>" for i in range(1100)})
        self.assertEqual("".join(hub.pdf_drawn_texts(merged)), "ab" * 550)
        self.assertEqual(self.put(self.line(name="a.pdf")[0], merged)[0], 200)
        # the tables of simple fonts: fonts with the same /Encoding and /ToUnicode share one, made once (300 fonts and
        # 2,000 glyph names of 119 letters); fonts with maps of their own make their own, each a step for each item of
        # /Differences and one more for each 8 letters of a name (3 fonts); and equal letters are one string in all
        long = b"[0 " + b" ".join([b"/uni" + b"0041" * 29] * 2000) + b"]"
        shared = chrome_pdf(b"BT " + b"".join(b"/F%d 9 Tf (A) Tj " % i for i in range(300)) + b"ET",
                            fonts=b" ".join(b"/F%d %d 0 R" % (i, 100 + i) for i in range(300)), more={
            8: b"<< /Differences %s >>" % long,
            **{100 + i: b"<< /Type /Font /Subtype /Type1 /Encoding 8 0 R >>" for i in range(300)}})
        with patch.object(hub, "CHAT_FILE_WORK", 300_000):
            self.assertEqual("".join(hub.pdf_drawn_texts(shared)), "A" * 29 * 300)
        own = chrome_pdf(b"BT /F1 9 Tf (A) Tj /F2 9 Tf (A) Tj /F3 9 Tf (A) Tj ET",
                         fonts=b"/F1 10 0 R /F2 11 0 R /F3 12 0 R", more={
            8: b"<< /Differences %s >>" % long,
            **{10 + i: b"<< /Type /Font /Subtype /Type1 /Encoding 8 0 R /ToUnicode %d 0 R >>" % (20 + i)
               for i in range(3)},
            **{20 + i: (b"", b"1 beginbfchar <42> <FB00> endbfchar") for i in range(3)}})
        self.assertEqual("".join(hub.pdf_drawn_texts(own)), "A" * 29 * 3)
        with patch.object(hub, "CHAT_FILE_WORK", 60_000):
            self.assertRaisesRegex(hub.Refusal, "draws more than", list, hub.pdf_drawn_texts(own))
        pdf = hub.PdfFile(own, [hub.CHAT_FILE_UNPACK], [hub.CHAT_FILE_GLYPHS], [hub.CHAT_FILE_WORK])
        first, second = (pdf.font(hub.PdfRef(num)).table for num in (10, 11))
        self.assertIsNot(first, second)
        self.assertEqual((first[0x42], first[0x41]), ("ff", "A" * 29))
        self.assertIs(first[0x42], second[0x42])
        self.assertIs(first[0x41], second[0x41])
        # a table of letters that the reader makes is a step more for each 8 of its letters: 50 fonts, each with a map
        # of its own that gives each of its 256 codes 32 letters, are about 66,000 steps
        tables = chrome_pdf(b"BT " + b"".join(b"/F%d 9 Tf (A) Tj " % i for i in range(50)) + b"ET",
                            fonts=b" ".join(b"/F%d %d 0 R" % (i, 100 + i) for i in range(50)), more={
            **{100 + i: b"<< /Type /Font /Subtype /Type1 /ToUnicode %d 0 R >>" % (200 + i) for i in range(50)},
            **{200 + i: (b"", b"1 beginbfrange <00> <FF> <" + b"0051" * 31 + b"%04X> endbfrange" % (0x41 + i))
               for i in range(50)}})
        self.assertEqual(len("".join(hub.pdf_drawn_texts(tables))), 50 * 32)
        with patch.object(hub, "CHAT_FILE_WORK", 50_000):           # a step for each 16 letters: about 40,000
            self.assertRaisesRegex(hub.Refusal, "draws more than", list, hub.pdf_drawn_texts(tables))
        # an encoding written in a font's own dictionary is that font's alone, and two named encodings are two
        for fonts, letters in ((b"<< /Differences [128 /a] >>", b"<< /Differences [128 /b] >>"), "ab"), \
                              ((b"/WinAnsiEncoding", b"/MacRomanEncoding"), "\u20ac\xc4"):
            with self.subTest(encodings=fonts):
                self.assertEqual("".join(hub.pdf_drawn_texts(chrome_pdf(
                    b"BT /F1 9 Tf (\x80) Tj /F2 9 Tf (\x80) Tj ET", fonts=b"/F1 10 0 R /F2 11 0 R", more={
                        10 + i: b"<< /Type /Font /Subtype /Type1 /Encoding %s >>" % encoding
                        for i, encoding in enumerate(fonts)}))), letters)
        # an array of a page's content has at most PDF_ARRAY_MOST items
        with patch.object(hub, "PDF_ARRAY_MOST", 100), self.assertRaisesRegex(hub.Refusal, "draws more than"):
            list(hub.pdf_drawn_texts(chrome_pdf(b"BT /F1 9 Tf [" + b"<0024> -12 " * 150 + b"] TJ ET")))
        # a map whose literal string has no end, made of escaped parentheses: read in one pass, not one for each (
        endless = chrome_pdf(b"BT /F1 9 Tf <0024> Tj ET", more={6: (b"", b"(" + b"\\(" * 40000)})
        started = time.monotonic()                                  # 5 ms; 20 s when each ( scans to the end
        self.assertEqual("".join(hub.pdf_drawn_texts(endless)), " ")
        self.assertLess(time.monotonic() - started, 3)
        # what the reader unpacks counts against its CHAT_FILE_UNPACK: 2 MB of a page's content that no filter packs
        unpacked = chrome_pdf(b"", more={7: b"<< /Length 2097152 >>\nstream\n" + b"q Q " * (1 << 19) + b"\nendstream"})
        with patch.object(hub, "CHAT_FILE_UNPACK", 1 << 20), self.assertRaisesRegex(hub.Refusal, "packs more than"):
            list(hub.pdf_drawn_texts(unpacked))
        # Python decodes ASCII85 itself: its bytes are steps before it runs, also when the text holds one comment
        comment = chrome_pdf(b"", more={7: b"<< /Filter [/FlateDecode /ASCII85Decode] >>\nstream\n" +
                                           zlib.compress(base64.a85encode(b"% " + b"x" * 60000) + b"~>") +
                                           b"\nendstream"})
        with patch.object(hub, "CHAT_FILE_WORK", 10_000):
            code, said = self.put(self.line(name="a.pdf")[0], comment)
            self.assertEqual((code, "the PDF draws more than the hub's check reads" in said), (413, True), said)
        # one code that the map gives as 200 letters, of which the reader keeps 32, drawn 10,000 times: 320,000
        # letters from a small stream
        wide = chrome_pdf(b"BT /F1 12 Tf <" + b"0001" * 10000 + b"> Tj ET",
                          more={6: (b"", b"1 beginbfchar\n<0001> <" + b"0041" * 200 + b">\nendbfchar\n")})
        with patch.object(hub, "CHAT_FILE_UNPACK", 300_000):
            code, said = self.put(self.line(name="a.pdf")[0], wide)
            self.assertEqual((code, "the PDF packs more than" in said), (413, True), said)
        self.assertEqual(self.put(self.line(name="a.pdf")[0], wide)[0], 200)
        # one code gives 32 letters at most: the letters of a map's entry and of a glyph's name are cut to 32 before a
        # range counts its last letter up, and a code's letters again after its ligatures become their letters; a
        # glyph's name longer than a name of PDF can be (127 bytes) gives none, since many fonts can share one
        # encoding's names
        mapped = lambda entries, code: chrome_pdf(b"BT /F1 9 Tf <%s> Tj ET" % code, more={6: (b"", entries)})
        named = lambda name: chrome_pdf(b"BT /F4 9 Tf (A) Tj ET", fonts=b"/F4 8 0 R", more={
            8: b"<< /Type /Font /Subtype /Type1 /Encoding << /Differences [65 /%s] >> >>" % name})
        for kind, data, letters in (
                ("a range of a map", mapped(b"1 beginbfrange <0001> <0002> <" + b"0051" * 40 + b"> endbfrange", b"0002"),
                 "Q" * 31 + "R"),
                ("a glyph's name in a range", mapped(b"1 beginbfrange <0001> <0002> /" + b"_".join([b"f"] * 40) +
                                                     b" endbfrange", b"0002"), "f" * 31 + "g"),
                ("ligatures of a map", mapped(b"1 beginbfchar <0001> <" + b"FB03" * 20 + b"> endbfchar", b"0001"),
                 ("ffi" * 20)[:32]),
                ("ligatures of a simple font", named(b"uni" + b"FB03" * 20), ("ffi" * 20)[:32]),
                ("a name of 127 bytes", named(b"uni" + b"0041" * 31), "A" * 31),
                ("a name of 131 bytes", named(b"uni" + b"0041" * 32), " ")):
            with self.subTest(letters=kind):
                self.assertEqual("".join(hub.pdf_drawn_texts(data)), letters)
        # the letters of a string are made a few codes at a time, and refused before the rest of them is made, and
        # the strings of one TJ are counted one by one: 400,000 codes of 64 bytes each (16 letters U+1F600, the 32
        # UTF-16 units of a map's entry) would be 25 MB. Measured on 16 November 2026: 4 to 7 MB at most; 30 to 43 MB
        # when a string or a TJ was made whole before it was counted
        laughs = b"<" + b"D83DDE00" * 16 + b">"
        for kind, data in (
                ("codes of two bytes", chrome_pdf(b"BT /F1 9 Tf <" + b"0001" * 400000 + b"> Tj ET", more={
                    6: (b"", b"1 beginbfchar <0001> " + laughs + b" endbfchar")})),
                ("a simple font", chrome_pdf(b"BT /F7 9 Tf (" + b"A" * 400000 + b") Tj ET", fonts=b"/F7 8 0 R", more={
                    8: b"<< /Type /Font /Subtype /Type1 /ToUnicode 6 0 R >>",
                    6: (b"", b"1 beginbfchar <41> " + laughs + b" endbfchar")})),
                ("codes of more than one length", chrome_pdf(b"BT /F6 9 Tf (" + b"A" * 400000 + b") Tj ET",
                                                             fonts=b"/F6 8 0 R", more={
                    8: b"<< /Type /Font /Subtype /Type0 /Encoding 9 0 R /DescendantFonts [4 0 R] /ToUnicode 6 0 R >>",
                    9: (b"/Type /CMap", b"1 begincodespacerange <00> <FF> endcodespacerange"),
                    6: (b"", b"1 beginbfchar <41> " + laughs + b" endbfchar")})),
                ("the strings of one TJ", chrome_pdf(b"BT /F1 9 Tf [" + (b"<" + b"0001" * 16000 + b"> -1 ") * 20 +
                                                     b"] TJ ET", more={
                    6: (b"", b"1 beginbfchar <0001> " + laughs + b" endbfchar")}))):
            with self.subTest(made=kind), patch.object(hub, "CHAT_FILE_UNPACK", 3 << 20):
                tracemalloc.start()
                try:
                    self.assertRaisesRegex(hub.Refusal, "packs more than", list, hub.pdf_drawn_texts(data))
                    peak = tracemalloc.get_traced_memory()[1]
                finally:
                    tracemalloc.stop()
                self.assertLess(peak, 16 << 20)
        # pdf_joined counts the bytes of the letters that it has made, all as wide as the widest: "a" and 100 letters
        # U+1F600 are 404 bytes, and so are 100 letters U+1F600 and "€"
        for blocks in (["a", "\U0001F600" * 100], ["\U0001F600" * 100, "€"]):
            self.assertRaisesRegex(hub.Refusal, "packs more than", hub.pdf_joined, iter(blocks), [403])
            self.assertEqual(hub.pdf_joined(iter(blocks), [404]), "".join(blocks))
        # the letters count the bytes in which they are kept, here against a budget of 1,000,000: after a stream of
        # 400,000 bytes, 400,000 letters € (2 bytes each) are too many, and 400,000 A or é (one byte each) are not; nor
        # are 250,000 € after their stream of 250,000 bytes. And a letter wider than those before it in its piece
        # counts them again for the bytes that they gain, and the letters after it count as wide: 100,000 of A and
        # one letter beyond the first plane, in either order, are too many for a budget of 400,000
        euro = lambda letter, count=400000: chrome_pdf(b"BT /F5 9 Tf (" + letter * count + b") Tj ET",
                                                       fonts=b"/F5 8 0 R", more={
            8: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"})
        wider = lambda first, last: chrome_pdf(b"BT /F8 9 Tf (" + first + b") Tj (" + last + b") Tj ET",
                                               fonts=b"/F8 8 0 R", more={
            8: b"<< /Type /Font /Subtype /Type1 /ToUnicode 9 0 R >>", 9: (b"", b"1 beginbfchar <80> <D83DDE00> endbfchar")})
        with patch.object(hub, "CHAT_FILE_UNPACK", 1_000_000):
            self.assertRaisesRegex(hub.Refusal, "packs more than", list, hub.pdf_drawn_texts(euro(b"\x80")))
            self.assertEqual("".join(hub.pdf_drawn_texts(euro(b"\x80", 250000))), "\u20ac" * 250000)
            self.assertEqual("".join(hub.pdf_drawn_texts(euro(b"A"))), "A" * 400000)
            self.assertEqual("".join(hub.pdf_drawn_texts(euro(b"\xe9"))), "\xe9" * 400000)
        with patch.object(hub, "CHAT_FILE_UNPACK", 400_000):
            for first, last in ((b"A" * 100000, b"\x80"), (b"\x80", b"A" * 100000)):    # and the wide letter first
                self.assertRaisesRegex(hub.Refusal, "packs more than", list, hub.pdf_drawn_texts(wider(first, last)))
            self.assertEqual("".join(hub.pdf_drawn_texts(wider(b"A" * 100000, b"A"))), "A" * 100001)
        # a string, a name and a text operator are 3 steps: 8,000 strings that Tj shows, in a few KB
        with patch.object(hub, "CHAT_FILE_WORK", 16_000), self.assertRaisesRegex(hub.Refusal, "draws more than"):
            list(hub.pdf_drawn_texts(chrome_pdf(b"BT " + b"(a) Tj " * 8000 + b"ET")))
        # codes of two bytes past PDF_LETTERS_KEPT are read where they stand, with a step for each: ten strings of
        # the same 150 codes 20 times; kept, they take a step for each new code only
        same = chrome_pdf(b"BT /F1 9 Tf " + (b"<" + b"".join(b"%04X" % c for c in range(1, 151)) * 20 + b"> Tj ") * 10 +
                          b"ET")
        letters = "".join(hub.pdf_drawn_texts(same))
        with patch.object(hub, "PDF_LETTERS_KEPT", 100):
            self.assertEqual("".join(hub.pdf_drawn_texts(same)), letters)
            with patch.object(hub, "CHAT_FILE_WORK", 20_000):
                self.assertRaisesRegex(hub.Refusal, "draws more than", list, hub.pdf_drawn_texts(same))
        with patch.object(hub, "CHAT_FILE_WORK", 20_000):
            self.assertEqual("".join(hub.pdf_drawn_texts(same)), letters)
        # the open arrays of a page's content hold PDF_ARRAY_MOST operands at most in all; an array is kept only while
        # it is open, or as the last operand outside arrays: 20 arrays of 20,000 numbers, inside an array or outside,
        # take about 1 MB at a time, not 17 MB
        with patch.object(hub, "PDF_ARRAY_MOST", 1000), self.assertRaisesRegex(hub.Refusal, "draws more than"):
            list(hub.pdf_drawn_texts(chrome_pdf(b"BT /F1 9 Tf [" + b"-1 " * 600 + b"[" + b"-1 " * 600 + b"] ] TJ ET")))
        numbers = b"[" + b"12 " * 20000 + b"] "
        for kind, data in (("inside an array", chrome_pdf(b"BT [" + numbers * 20 + b"] TJ ET")),
                           ("outside arrays", chrome_pdf(b"BT " + numbers * 20 + b"TJ ET"))):
            with self.subTest(arrays=kind):
                tracemalloc.start()
                try:
                    self.assertEqual("".join(hub.pdf_drawn_texts(data)), "")
                    peak = tracemalloc.get_traced_memory()[1]
                finally:
                    tracemalloc.stop()
                self.assertLess(peak, 8 << 20)
        odd = {
            "a string with no end": chrome_pdf(b"BT /F1 12 Tf (no end <0024> Tj"),
            "hex strings of odd digits": chrome_pdf(b"BT /F1 12 Tf <0024002> Tj <00 24 0> Tj ET"),
            "deep arrays": chrome_pdf(b"[" * 100000 + b"(x) Tj ] TJ"),
            "a page that is its own content": chrome_pdf(b"", more={5: b"<< /Type /Page /Parent 2 0 R /Contents 5 0 R "
                                                                       b"/Resources 5 0 R >>"}),
            "a form that draws itself": chrome_pdf(b"/X1 Do", more={
                5: b"<< /Type /Page /Parent 2 0 R /Resources << /XObject << /X1 8 0 R >> >> /Contents 7 0 R >>",
                8: (b"/Type /XObject /Subtype /Form /Resources << /XObject << /X1 8 0 R >> /Font << /F1 3 0 R >> >>",
                    b"/X1 Do BT /F1 9 Tf <0024> Tj ET")}),
            "a broken map": chrome_pdf(b"BT /F1 12 Tf <002400250026> Tj ET", more={6: (b"", (
                b"beginbfchar <0024 <0041> endbfchar beginbfrange <0030> <0010> <0041> <0102030405> <0102030406> "
                b"<0041> <01> <02> [<0041> endbfrange begincodespacerange <00> endcodespacerange 2 beginbfchar "
                b"<0025> /nonesuch <0026> <D800> endbfchar"))}),
            "odd operands": chrome_pdf(b"BT /F1 Tf 1 2 3 Tm (x) 5 Td [<0024> [1 2] /N null] TJ /F9 12 Tf <0024> Tj "
                                       b"\" ' T* ET ET BT 1\x00 0 Td"),
            "an inline picture": chrome_pdf(b"BI /W 2 /H 2 /CS /G /BPC 8 ID \x00BT(\xff)Tj\x01 EI BT /F1 9 Tf <0024> Tj "
                                            b"ET"),
            "an object stream that does not parse": pdf_of({1: b"<< /Type /Catalog /Pages 2 0 R >>",
                                                            10: (b"/Type /ObjStm /N 3 /First 99", b"1 x 5")}),
            "resources that are a number": chrome_pdf(b"BT /F1 12 Tf <0024> Tj ET", more={
                5: b"<< /Type /Page /Parent 2 0 R /Resources 42 /Contents 7 0 R >>"}),
            "odd differences": chrome_pdf(b"BT /F4 12 Tf <0102FF> Tj ET", fonts=b"/F4 8 0 R", more={
                8: b"<< /Type /Font /Subtype /Type1 /Encoding << /BaseEncoding [1] /Differences [300 /a -5 /b /c (x) "
                   b"2] >> >>"}),
            "an escape that is no octal": chrome_pdf(b"BT /F1 12 Tf (\\8\\9) Tj ET"),
            "a number of 5,000 digits": pdf_of({1: b"<< /Type /Catalog /Pages 2 0 R >>",
                                                3: (b"/Type /ObjStm /N 1 /First 5003", b"9" * 5000 + b" 0 << /A 1 >>")}),
        }
        for name, data in odd.items():
            with self.subTest(name):
                code, said = self.put(self.line(name="a.pdf")[0], data)
                self.assertEqual(code, 200, said)

    def test_only_a_session_with_a_shell_gets_attach_file(self):
        names = lambda agent, context: {t["name"] for t in hub.tools_for(agent, context)}
        self.assertIn("attach_file", names("manager", None))
        self.assertIn("attach_file", names("studio", self.task_context()))
        self.assertNotIn("attach_file", names("studio", CHAT))           # an owner chat has no shell
        self.assertNotIn("attach_file", hub.CHAT_TOOLS)
        self.assertNotIn("attach_file", hub.SHELL_OFF_TOOLS + hub.SHELL_OFF_CHAT)

    # ---- the four tools and the outbound queue
    def test_the_managers_file_goes_to_whatsapp_and_the_bridge_reads_it_while_it_sends(self):
        self.own("whatsapp", OWNER_WA)
        aid = self.attach()
        rid = str(uuid.uuid4())
        text, error = self.owner_message([f"A-{aid}"], rid)
        self.assertFalse(error, text)
        answer = json.loads(text)
        self.assertEqual((answer["via"], answer["files"]), ({"app": "whatsapp", "account": "whatsapp-main"},
                                                            [f"A-{aid}"]))
        self.assertEqual(self.owner_message([f"A-{aid}"], rid)[0], text)              # the same call: its answer
        row = hub.q1("SELECT * FROM attachments WHERE id=?", (aid,))
        self.assertEqual((row["report"], row["cm"]), (answer["report"], None))
        self.assertIsNotNone(row["carried"])
        report = self.request()[1]["reports"][-1]
        self.assertEqual(([f["id"] for f in report["attachments"]], report["attachments"][0]["name"]),
                         ([aid], "Invoice October.pdf"))
        items = self.messages()
        self.assertEqual(items[0]["files"], [{"id": aid, "name": "Invoice October.pdf", "mime": "application/pdf",
                                              "size": len(PDF_FILE), "sha256": hashlib.sha256(PDF_FILE).hexdigest()}])
        code, data, headers = self.bridge_file(aid, items[0]["id"])
        self.assertEqual((code, data, headers["X-Fleet-SHA256"]), (200, PDF_FILE, row["sha256"]))
        other = self.attach()
        self.assertEqual(self.bridge_file(other, items[0]["id"])[0], 404)         # a file that the item does not name
        self.assertEqual(self.bridge_file(aid, items[0]["id"] + 1)[0], 404)       # an item that does not exist
        self.assertEqual(self.raw("GET", f"/bridge/files/{aid}?item={items[0]['id']}", source="127.0.0.3")[0], 403)
        self.report(items[0]["id"], parts=2, platform_ids=["p1", "p2"])
        self.assertEqual(self.bridge_file(aid, items[0]["id"])[0], 404)           # sent: the bridge reads it no more
        # one file goes with one message, and a message carries what this agent sent up only
        text, error = self.owner_message([f"A-{aid}"])
        self.assertTrue(error)
        self.assertIn(f"A-{aid} went with another message already", text)
        hub.q("UPDATE attachments SET agent=NULL WHERE id=?", (other,))          # the owner's own file
        for files, words in (([f"A-{other}"], "is not a file that you sent up with attach_file"),
                             ([f"A-{other + 1}"], "is not a file that you sent up with attach_file"),
                             (["A-1", "A-1"], "files names each file one time"),
                             (["A-1", "A-2", "A-3", "A-4", "A-5"], "files is a list of at most 4 files"),
                             (["invoice.pdf"], "files names each file as attach_file's upload named it"),
                             ("A-1", "files is a list of at most 4 files")):
            with self.subTest(files=files):
                text, error = self.owner_message(files)
                self.assertTrue(error, text)
                self.assertIn(words, text)
        self.assertEqual(self.count("owner_reports"), 1)
        # a file that no message took goes after an hour
        late = self.attach(agent="manager")
        hub.q("UPDATE attachments SET created=? WHERE id=?", (hub.now() - hub.ATTACH_WAIT - 1, late))
        text, error = self.owner_message([f"A-{late}"])
        self.assertTrue(error)
        self.assertIn("is no longer on the hub: a file that no message takes goes after one hour", text)

    def test_a_reply_to_discord_takes_a_file_of_at_most_10_mb_and_a_repeat_sends_nothing(self):
        self.own()
        self.inbound("Send me the invoice")
        self.read()
        req = self.last_request()
        here = self.task_context()
        big = self.attach(b"%PDF-1.4\n" + b"0" * (10 * 1024 * 1024), agent="studio", context=here)
        text, error = hub.call_tool("studio", "tell_owner", {"text": "The file.", "about": "invoice",
                                                             "in_reply_to": req["request_id"], "files": [f"A-{big}"]},
                                    CHAT)
        self.assertTrue(error)
        self.assertIn(f"A-{big} has 10.0 MB, and Discord takes at most 10 MB of files in one message", text)
        self.assertEqual(self.count("owner_reports"), 0)
        aid = self.attach(agent="studio", context=here)
        said = self.tell(in_reply_to=req["request_id"], files=[f"A-{aid}"])
        self.assertIn(f"queued for Studio. With A-{aid} Invoice October.pdf.", said)
        self.assertIn("No duplicate was sent", self.tell(in_reply_to=req["request_id"], files=[f"A-{aid}"]))
        text, error = hub.call_tool("studio", "tell_owner", {"text": "On it. T-9 is 80% done.", "about": "scrape",
                                                             "in_reply_to": req["request_id"]}, CHAT)
        self.assertTrue(error)
        self.assertIn("already has a different reply", text)        # the same words without the file are another
        item = self.messages()[-1]
        self.assertEqual((item["account"], item["reply_to"], [f["id"] for f in item["files"]]),
                         ("discord-studio", "m1", [aid]))

    def test_a_number_sends_at_most_20_files_a_day(self):
        self.own("whatsapp", OWNER_WA)
        with hub.transaction():
            hub.chat_count("whatsapp-main", "files", hub.now(), 19)
        two = [f"A-{self.attach()}", f"A-{self.attach()}"]
        text, error = self.owner_message(two)
        self.assertFalse(error, text)
        r = hub.q1("SELECT state, error FROM chat_out ORDER BY id DESC LIMIT 1")
        self.assertEqual((r["state"], r["error"]), ("failed", "daily limit of 20 WhatsApp files"))
        text, error = self.owner_message([f"A-{self.attach()}"])
        self.assertFalse(error, text)
        self.assertEqual(hub.q1("SELECT state FROM chat_out ORDER BY id DESC LIMIT 1")["state"], "queued")
        self.assertEqual(hub.chat_count("whatsapp-main", "files", hub.now()), 20)
        self.assertEqual(self.request()[1]["reports"][0]["delivery"]["error"], "daily limit of 20 WhatsApp files")

    def test_send_again_sends_the_words_and_their_files(self):
        self.own("whatsapp", OWNER_WA)
        aid = self.attach()
        self.assertFalse(self.owner_message([f"A-{aid}"])[1])
        first = self.messages()[0]
        self.report(first["id"], state="unknown", parts=0, platform_ids=[], error="unknown: connection lost")
        code, data = self.post(f"/ui/outbound/{first['id']}/again")
        self.assertEqual(code, 200, data)
        again = self.messages()[0]
        self.assertEqual((again["id"], again["files"]), (data["outbound"]["id"], first["files"]))
        self.assertEqual(self.bridge_file(aid, again["id"])[:2], (200, PDF_FILE))

    def test_an_item_whose_file_is_gone_fails_and_the_window_grows_with_its_files(self):
        self.own("whatsapp", OWNER_WA)
        aid = self.attach()
        self.assertFalse(self.owner_message([f"A-{aid}"])[1])
        row = hub.q1("SELECT * FROM attachments WHERE id=?", (aid,))
        os.remove(os.path.join(self.files.name, hub.attachment_disk_name(row["sha256"], row["mime"])))
        self.assertEqual(self.out(), [])
        r = hub.q1("SELECT state, error FROM chat_out ORDER BY id DESC LIMIT 1")
        self.assertEqual((r["state"], r["error"]), ("failed", "a file of this message is no longer on the hub"))
        # the sending window: 120 seconds and 150 more for each file
        one = self.attach()
        self.assertFalse(self.owner_message([f"A-{one}"])[1])
        item = self.messages()[0]["id"]
        given = hub.q1("SELECT given FROM chat_out WHERE id=?", (item,))["given"]
        hub.chat_sweep(given + hub.CHAT_SENDING + 1)
        self.assertEqual(hub.q1("SELECT state FROM chat_out WHERE id=?", (item,))["state"], "sending")
        hub.chat_sweep(given + hub.CHAT_SENDING + hub.CHAT_FILE_SENDING)
        r = hub.q1("SELECT state, error FROM chat_out WHERE id=?", (item,))
        self.assertEqual((r["state"], r["error"]), ("unknown", "no report from the bridge in the time of its files"))

    def test_an_older_bridge_gets_no_item_with_files(self):
        """The first review, 15 November 2026: a bridge from before files would send the words alone and report them
        sent. Only a poll with files=1 gets an item with files; a text item goes to every poll as before."""
        self.own("whatsapp", OWNER_WA)
        self.assertFalse(self.owner_message([f"A-{self.attach()}"])[1])
        self.assertFalse(hub.call_tool("manager", "message_owner", {"request_id": str(uuid.uuid4()), "text": "No file."},
                                       None)[1])
        old = self.out(files=False)
        self.assertEqual([(i["text"], "files" in i) for i in old], [("No file.", False)])
        self.assertEqual(hub.q1("SELECT state FROM chat_out WHERE files IS NOT NULL")["state"], "queued")
        new = self.out()
        self.assertEqual([i["text"] for i in new], ["Here is the October invoice."])

    def test_the_count_of_the_search_is_no_less_than_its_hashes(self):
        """secret_cost counts what find_secret_spans hashes, so the budget holds the time of a check: windows, the ends
        of a run with JSON line breaks in it, and a login with no length."""
        key = (("s1", "0" * 64, 24), ("s2", "1" * 64, 9), ("s3", "2" * 64, 0))
        texts = ["plain words and a token-of-thirty-two-characters-xyz", "\\n".join(["abc.:)"] * 30) + " tail",
                 "x" * 3000 + " " + ",".join(["v" * 40] * 50), "short"]
        made = [0]

        class Counting:
            def __init__(self, h):
                self.h = h

            def copy(self):
                made[0] += 1
                return Counting(self.h.copy())

            def update(self, data):
                self.h.update(data)

            def hexdigest(self):
                return self.h.hexdigest()

        counting = type("hashlib", (), {"sha256": staticmethod(lambda data=b"": Counting(hashlib.sha256(data)))})
        for text in texts:
            with self.subTest(text=text[:30]):
                made[0] = 0
                with patch.object(hub, "hashlib", counting):
                    hub.find_secret_spans(text, key)
                cost = hub.secret_cost(text, key, 10 ** 9)
                self.assertGreaterEqual(cost, made[0])
                self.assertLessEqual(cost, 2 * made[0] + 64)            # an upper bound, and not a wild one
        self.assertEqual(hub.secret_cost("y" * 5000, key, 100), 101)     # it stops past its most

    def test_an_agent_holds_at_most_four_open_lines_and_a_line_that_is_not_open_reads_no_body(self):
        tokens = [self.line()[0] for _ in range(hub.CHAT_FILE_LINES)]
        text, error = hub.call_tool("manager", "attach_file", {"name": "e.pdf"}, None)
        self.assertTrue(error)
        self.assertIn(f"You have {hub.CHAT_FILE_LINES} upload lines open", text)
        self.assertEqual(self.put(tokens[0], PDF_FILE)[0], 200)          # a used line frees its place
        self.line()
        self.assertEqual(self.put("no-such-line", b"x" * 1000), (404, "This upload line is not valid: it was used, or "
                                                                     "it ended. Call attach_file for a new one.\n"))

    def test_a_text_behind_a_file_of_its_account_waits_with_it(self):
        """The reviews of 15 November 2026: the bridge sends the items of one account one after the other, and says when
        it begins each one. An item that it has not begun waits while an item before it is sent; a begun item counts
        from its begin; a receipt of another item moves nothing; and the items that a stopped bridge lost all become
        unknown when the first of them does, never one after another."""
        self.own("whatsapp", OWNER_WA)
        self.assertFalse(self.owner_message([f"A-{self.attach()}"])[1])
        self.assertFalse(hub.call_tool("manager", "message_owner", {"request_id": str(uuid.uuid4()), "text": "Behind."},
                                       None)[1])
        first, second = [i["id"] for i in self.messages()]
        given = hub.q1("SELECT given FROM chat_out WHERE id=?", (second,))["given"]
        state = lambda item: hub.q1("SELECT state FROM chat_out WHERE id=?", (item,))["state"]
        self.assertEqual(self.bridge(f"/bridge/out/{first}", {"state": "sending"}), (200, {"db": "test-generation", "ok": True}))
        hub.chat_sweep(given + hub.CHAT_SENDING + 1)
        self.assertEqual((state(first), state(second)), ("sending", "sending"))      # the second waits behind the first
        self.report(first, parts=1, platform_ids=["pf"])
        later = given + 200
        with patch.object(hub, "now", lambda: later):
            self.assertEqual(self.bridge(f"/bridge/out/{second}", {"state": "sending"})[0], 200)
        hub.q("UPDATE chat_out SET updated=? WHERE id=?", (later + 100, first))       # a receipt of the first one
        hub.chat_sweep(later + hub.CHAT_SENDING - 1)
        self.assertEqual(state(second), "sending")
        hub.chat_sweep(later + hub.CHAT_SENDING)
        r = hub.q1("SELECT state, error FROM chat_out WHERE id=?", (second,))
        self.assertEqual((r["state"], r["error"]), ("unknown", "no report from the bridge in 120 seconds"))
        # a begin report after the sweep: the bridge sends it after all
        self.assertEqual(self.bridge(f"/bridge/out/{second}", {"state": "sending"})[0], 200)
        self.assertEqual((state(second), hub.q1("SELECT error FROM chat_out WHERE id=?", (second,))["error"]),
                         ("sending", None))
        self.report(second, parts=1, platform_ids=["ps"])
        # three texts that a stopped bridge lost: all unknown in one sweep
        for n in range(3):
            self.assertFalse(hub.call_tool("manager", "message_owner", {"request_id": str(uuid.uuid4()),
                                                                        "text": f"Lost {n}."}, None)[1])
        lost = [i["id"] for i in self.messages()]
        given = max(hub.q1("SELECT given FROM chat_out WHERE id=?", (i,))["given"] for i in lost)
        hub.chat_sweep(given + hub.CHAT_SENDING)
        self.assertEqual([state(i) for i in lost], ["unknown"] * 3)
        # a begin report for an item that is sent already is refused, and changes nothing
        self.assertEqual(self.bridge(f"/bridge/out/{first}", {"state": "sending"})[0], 409)

    def test_an_older_bridge_is_never_starved_by_items_with_files(self):
        """The second review: the filter is in the read, so that 50 items with files ahead of a text do not keep the
        text from a bridge that does not take files. The items of the built-in account (Teams design 4, S5) are left
        out in the read too: no bridge ever gets one, and a check after the read would let them fill the limit, so
        that each chat app's replies stop."""
        self.own("whatsapp", OWNER_WA)
        for _ in range(2):
            self.assertFalse(self.owner_message([f"A-{self.attach()}"])[1])
        with hub.LOCK, hub.transaction():
            built_in = [hub.chat_queue("message", hub.BUILT_IN_ACCOUNT, hub.now(), chat="link-1/manager",
                                       text="For the app."),
                        hub.chat_queue("typing", hub.BUILT_IN_ACCOUNT, hub.now(), chat="link-1/manager", seconds=8)]
        self.assertFalse(hub.call_tool("manager", "message_owner", {"request_id": str(uuid.uuid4()), "text": "Text."},
                                       None)[1])
        given = hub.chat_give(hub.now(), limit=2, files=False)
        self.assertEqual([i["text"] for i in given], ["Text."])
        self.assertNotIn(hub.BUILT_IN_ACCOUNT, [i["account"] for i in hub.chat_give(hub.now(), files=True)])
        self.assertEqual([hub.q1("SELECT state FROM chat_out WHERE id=?", (i,))["state"] for i in built_in],
                         ["queued", "queued"])       # left for their own sender, neither given nor expired

    def test_a_csv_value_in_quotes_is_read_whole(self):
        """The second review: a CSV is read by its own rules, so a value with the separator in it is one value."""
        value, salt = "Tr0ub,4dor;Horse", "csv-salt"
        hub.ins("INSERT INTO secrets(label,salt,hash,len) VALUES(?,?,?,?)",
                ("csv", salt, hashlib.sha256((salt + value).encode()).hexdigest(), len(value)))
        for data in (f'name,key\nbank,"{value}"\n'.encode(), f'name;key\nbank;"{value}"\n'.encode()):
            with self.subTest(data=data):
                code, said = self.put(self.line(name="a.csv")[0], data)
                self.assertEqual(code, 422, said)

    def test_discord_takes_at_most_10_mb_of_files_in_one_message(self):
        self.own()
        self.inbound("Send me both")
        self.read()
        req = self.last_request()
        here = self.task_context()
        two = [f"A-{self.attach(PDF_FILE + bytes(600), agent='studio', context=here)}" for _ in range(2)]
        with patch.dict(hub.CHAT_FILE_APP_MAX, {"discord": 1000}):
            text, error = hub.call_tool("studio", "tell_owner", {"text": "Both.", "about": "x",
                                                                 "in_reply_to": req["request_id"], "files": two}, CHAT)
        self.assertTrue(error)
        self.assertIn("These files have 1 KB, and Discord takes at most 0 MB of files in one message.", text)

    def test_a_session_that_sends_no_file_up_names_none_and_sees_no_files_field(self):
        """The third review, 15 November 2026: a Shell-off agent and a narrowed conversation name no file, and their
        message tools show no `files`; an owner chat with a shell shows it, since its task may send a file up."""
        here = self.task_context()
        aid = self.attach(agent="studio", context=here)
        self.own()
        self.inbound("Send it")
        self.read()
        req = self.last_request()
        schema = lambda agent, context, tool: next(t for t in hub.tools_for(agent, context)
                                                   if t["name"] == tool)["inputSchema"]["properties"]
        self.assertIn("files", schema("studio", CHAT, "tell_owner"))
        with patch.object(hub, "session_scope", lambda agent, context=None: {"person": 1, "grants": {}}):
            with self.assertRaises(hub.ToolError) as refused:     # call_tool offers a narrowed session no such tool
                hub.chat_files_check_session("studio", (aid,))
        self.assertEqual(str(refused.exception), "Refused: a narrowed conversation sends no file. Nothing was sent.")
        hub.TEAM["agents"]["studio"]["can"] = []                    # its Shell box goes off
        self.addCleanup(hub.TEAM["agents"]["studio"].__setitem__, "can", ["shell"])
        text, error = hub.call_tool("studio", "tell_owner", {"text": "Here.", "about": "x", "files": [f"A-{aid}"],
                                                             "in_reply_to": req["request_id"]}, CHAT)
        self.assertEqual((error, text), (True, "Refused: an agent whose Shell box is off sends no file. Nothing was "
                                               "sent."))
        self.assertNotIn("files", schema("studio", CHAT, "tell_owner"))
        self.assertEqual(self.count("owner_reports"), 0)

    def test_an_app_that_takes_no_file_is_refused_and_a_failed_item_is_told(self):
        """The third review: a chat app whose adapter sends no file yet gets none (never the words alone), and an item
        that fails at once, the 21st file of a WhatsApp number's day, is told to the agent, not only queued."""
        self.own("whatsapp", OWNER_WA)
        aid = self.attach()
        with patch.object(hub, "CHAT_FILE_APPS", ("discord",)):
            text, error = self.owner_message([f"A-{aid}"])
        self.assertTrue(error)
        self.assertIn("WhatsApp takes no file from the fleet yet", text)
        with hub.transaction():
            hub.chat_count("whatsapp-main", "files", hub.now(), hub.WHATSAPP_FILES_DAY)
        text, error = self.owner_message([f"A-{aid}"])
        self.assertFalse(error, text)
        self.assertEqual(json.loads(text)["not_sent"], "daily limit of 20 WhatsApp files")
        # tell_owner, to his message on studio's own WhatsApp number once it sent its parts of the day
        hub.TEAM["chat_apps"]["whatsapp-studio"] = WHATSAPP_STUDIO
        self.inbound("Status?", account="whatsapp-studio", sender=OWNER_WA)
        req = self.last_request()
        self.read()
        with hub.transaction():
            hub.chat_count("whatsapp-studio", "parts", hub.now(), hub.WHATSAPP_PARTS_DAY)
        said = self.tell(in_reply_to=req["request_id"])
        self.assertIn("added to the owner's studio chat, but not sent to Studio WA: daily WhatsApp limit.", said)
        self.assertEqual(hub.q1("SELECT state FROM chat_out WHERE kind='message' ORDER BY id DESC LIMIT 1")["state"],
                         "failed")

    def test_an_agent_sends_up_at_most_20_loose_files_an_hour_and_a_gone_file_is_gone_for_the_bridge(self):
        with patch.object(hub, "CHAT_FILE_LOOSE", 2):
            self.attach()
            self.attach()
            text, error = hub.call_tool("manager", "attach_file", {"name": "c.pdf"}, None)
        self.assertTrue(error)
        self.assertIn("You sent up 2 files in the last hour that no message took", text)
        # the bridge reads a file that is gone from the disk as gone (410), not as a fault
        self.own("whatsapp", OWNER_WA)
        aid = self.attach()
        self.assertFalse(self.owner_message([f"A-{aid}"])[1])
        item = self.messages()[0]["id"]
        row = hub.q1("SELECT * FROM attachments WHERE id=?", (aid,))
        os.remove(os.path.join(self.files.name, hub.attachment_disk_name(row["sha256"], row["mime"])))
        self.assertEqual(self.bridge_file(aid, item)[0], 410)

    def test_two_messages_cannot_take_one_file(self):
        """The race of chat_files_carry: the write that takes a file asks that no message took it, so the second of
        two messages that checked the same free file writes nothing."""
        row = hub.q1("SELECT * FROM attachments WHERE id=?", (self.attach(),))
        with hub.transaction():
            hub.chat_files_carry([row], hub.now(), report=1)
        with self.assertRaises(hub.ToolError):
            with hub.transaction():
                hub.chat_files_carry([row], hub.now(), report=2)
        self.assertEqual(hub.q1("SELECT report FROM attachments WHERE id=?", (row["id"],))["report"], 1)

    def test_the_sweep_keeps_a_carried_file_as_a_file_of_the_owners_message(self):
        carried, alone = self.attach(), self.attach(b"%PDF-1.4\nanother")
        self.assertFalse(self.owner_message([f"A-{carried}"])[1])           # no chat app route: the app only
        t0 = hub.now() + hub.ATTACH_WAIT + 60
        hub.kv_set("attachment_sweep_at", 0)
        hub.attachment_sweep(t0)
        self.assertEqual([r["id"] for r in hub.q("SELECT id FROM attachments ORDER BY id")], [carried])
        hub.kv_set("attachment_sweep_at", 0)
        hub.attachment_sweep(hub.now() + hub.attachment_keep() + 60)
        self.assertEqual(self.count("attachments"), 0)
        self.assertEqual(alone, carried + 1)


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(cls(name) for cls in (ChatApps, AgentFiles) for name in cls.__dict__
                              if name.startswith("test_"))


if __name__ == "__main__":
    unittest.main()
