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
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.error
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
        self.assertEqual(say("a photo", kind="image"), ["I can read text only for now."])
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

    def test_a_registered_secret_in_an_inbound_message_is_not_stored(self):
        self.own()
        value, salt = "SYNTHETICCHATSECRET123", "test-salt"
        hub.ins("INSERT INTO secrets(label,salt,hash,len) VALUES(?,?,?,?)",
                ("Synthetic", salt, hashlib.sha256((salt + value).encode()).hexdigest(), len(value)))
        self.assertEqual(self.inbound(f"the key is {value}")[0], "stored")
        self.assertEqual((self.count("events"), self.count("ui_requests")), (0, 0))
        self.assertEqual(self.texts(), ["That message held a saved secret. It was not stored."])
        self.assertEqual(hub.leak_scan(), [])

    def test_more_than_500_inbound_messages_a_day_are_ignored(self):
        self.own()
        with hub.LOCK, hub.transaction():
            hub.chat_count("*", "inbound", hub.now(), 499)
        self.assertEqual(self.inbound()[0], "stored")
        self.assertEqual(self.inbound()[0], "ignored")
        self.assertEqual(self.inbound("/whoami")[0], "stored")         # a command is no inbound message to an agent
        self.assertEqual(self.request("/ui/chat-apps?db=test-generation")[1]["inbound_today"], 500)
        self.assertEqual(self.count("events"), 1)

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
        for fields, words in (({"purpose": "invite", "app": "discord"}, "purpose"), ({"purpose": "owner", "app": "sms"},
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
        reports = self.request()[1]["reports"]                          # what the apps read: the links, and no turn
        self.assertEqual([r["in_reply_to"] for r in reports],
                         [None, first["request_id"], None, second["request_id"], None])
        self.assertEqual([key for r in reports for key in r if key == "turn"], [])
        code, chat = self.request("/ui/mobile/chat/manager?db=test-generation")
        self.assertEqual(code, 200, chat)
        self.assertNotIn(sent["request_id"], json.dumps([i for i in chat["items"] if i["kind"] == "report"]))

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
        self.assertIn("removed the Discord token file of discord-studio",
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
        self.assertEqual((data["paused"], data["inbound_today"]), (False, 1))
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
                                        "sent_today", "ignored_today", "link"})
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


def png(*chunks):
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", bytes(13)) + b"".join(chunk(k, b) for k, b in chunks) + \
        chunk(b"IEND", b"")


def jpeg(comment):
    return b"\xff\xd8\xff\xfe" + struct.pack(">H", len(comment) + 2) + comment + b"\xff\xda\x00\x02\x00\xff\xd9"


PDF_FILE = pdf((b"", b"BT /F1 12 Tf 72 712 Td (Invoice for October) Tj ET"))
XLSX_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


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
        # a name of another kind of file gets no line at all
        for name in ("report.zip", "run.sh", "notes", ".pdf", "macro.xlsm"):
            text, error = hub.call_tool("manager", "attach_file", {"name": name}, None)
            self.assertTrue(error, name)
            self.assertIn("with one of these extensions: .pdf, .png, .jpg, .xlsx, .docx, .pptx, .csv or .txt", text)

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
        text from a bridge that does not take files."""
        self.own("whatsapp", OWNER_WA)
        for _ in range(2):
            self.assertFalse(self.owner_message([f"A-{self.attach()}"])[1])
        self.assertFalse(hub.call_tool("manager", "message_owner", {"request_id": str(uuid.uuid4()), "text": "Text."},
                                       None)[1])
        given = hub.chat_give(hub.now(), limit=2, files=False)
        self.assertEqual([i["text"] for i in given], ["Text."])

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
