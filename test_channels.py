"""Deterministic checks of the chat apps bridge (channels.py) against local stand-ins of section 15 of CHAT-APPS.md:
a Gateway WebSocket server, Discord's REST API, the hub's /bridge routes and wa-link. No network, no ~/.fleet."""
import base64
import hashlib
import http.server
import io
import json
import os
import re
import shlex
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import uuid
from unittest.mock import patch

import channels
import hub as fleet_hub
import test_ui_api

TOKEN = "TEST-BOT-TOKEN-not-real-7Hq"
KEY = "test-bridge-key"
BOT, APP, OWNER = "900", "800", "555"
DISCORD = {"id": "discord-studio", "app": "discord", "label": "Studio", "enabled": True}
WHATSAPP = {"id": "whatsapp-main", "app": "whatsapp", "label": "Fleet", "enabled": True}
WA_JID = "34600000001:7@s.whatsapp.net"
WA_CHAT = "34600000002@s.whatsapp.net"
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


# ---------------------------------------------------------------- stand-in: the Discord Gateway

class Peer:
    """One Gateway connection, on the server's side."""
    def __init__(self, gw, sock, path):
        self.gw, self.sock, self.path = gw, sock, path
        self.buf, self.wlock = b"", threading.Lock()
        self.pongs, self.close_code = [], None

    def read(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError
            self.buf += chunk
        data, self.buf = self.buf[:n], self.buf[n:]
        return data

    def frame(self):
        b1, b2 = self.read(2)
        n = b2 & 0x7F
        if n == 126:
            n = struct.unpack("!H", self.read(2))[0]
        elif n == 127:
            n = struct.unpack("!Q", self.read(8))[0]
        if not b2 & 0x80:
            raise AssertionError("the client sent an unmasked frame")
        key = self.read(4)
        data = bytes(b ^ key[i % 4] for i, b in enumerate(self.read(n)))
        return bool(b1 & 0x80), b1 & 0x0F, data

    def send_frame(self, op, data, fin=True):
        n = len(data)
        if n < 126:
            head = struct.pack("!BB", (0x80 if fin else 0) | op, n)
        elif n < 65536:
            head = struct.pack("!BBH", (0x80 if fin else 0) | op, 126, n)
        else:
            head = struct.pack("!BBQ", (0x80 if fin else 0) | op, 127, n)
        with self.wlock:
            self.sock.sendall(head + data)

    def send(self, obj):
        self.send_frame(1, json.dumps(obj).encode())

    def dispatch(self, kind, d, fragmented=False):
        with self.gw.lock:
            self.gw.seq += 1
            msg = {"op": 0, "t": kind, "s": self.gw.seq, "d": d}
        if not fragmented:
            return self.send(msg)
        data = json.dumps(msg).encode()
        self.send_frame(1, data[:20], fin=False)
        self.send_frame(9, b"hi")                       # a ping between the fragments
        self.send_frame(0, data[20:40], fin=False)
        self.send_frame(0, data[40:], fin=True)

    def drop(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()

    def close(self, code):
        self.send_frame(8, struct.pack("!H", code))
        self.drop()


class GatewayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        gw, sock = self.server.gw, self.request
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                return
            data += chunk
        head = data.split(b"\r\n\r\n")[0].decode()
        path = head.split("\r\n")[0].split(" ")[1]
        key = re.search(r"(?im)^sec-websocket-key:\s*(\S+)", head).group(1)
        accept = base64.b64encode(hashlib.sha1(key.encode() + GUID).digest())
        sock.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n")
        peer = Peer(gw, sock, path)
        with gw.lock:
            gw.peers.append(peer)
        peer.send({"op": 10, "d": {"heartbeat_interval": gw.interval}})
        try:
            while True:
                fin, op, payload = peer.frame()
                if op == 8:
                    peer.close_code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else None
                    return
                if op == 10:
                    peer.pongs.append(payload)
                elif op == 1:
                    gw.on_message(peer, json.loads(payload))
        except (OSError, EOFError):
            pass


class Gateway:
    def __init__(self):
        self.lock = threading.Lock()
        self.peers, self.received = [], []
        self.interval, self.ack, self.resume_ok, self.on_identify = 100, True, True, None
        self.seq = self.sessions = 0
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), GatewayHandler)
        self.server.daemon_threads, self.server.block_on_close = True, False
        self.server.gw = self
        threading.Thread(target=self.server.serve_forever, args=(0.02,), daemon=True).start()
        self.url = "ws://127.0.0.1:%d" % self.server.server_address[1]

    def on_message(self, peer, msg):
        with self.lock:
            self.received.append((peer, msg))
        op = msg.get("op")
        if op == 1 and self.ack:
            peer.send({"op": 11})
        elif op == 2:
            if self.on_identify:
                return peer.close(self.on_identify)
            with self.lock:
                self.sessions += 1
                self.seq = 1
            peer.send({"op": 0, "t": "READY", "s": 1,
                       "d": {"v": 10, "session_id": f"s{self.sessions}", "resume_gateway_url": self.url,
                             "user": {"id": BOT, "username": "studio-bot", "bot": True}, "application": {"id": APP}}})
        elif op == 6:
            if not self.resume_ok:
                return peer.send({"op": 9, "d": False})
            with self.lock:
                self.seq += 1
                seq = self.seq
            peer.send({"op": 0, "t": "RESUMED", "s": seq, "d": {}})

    def ops(self, op, peer=None):
        with self.lock:
            return [m for p, m in self.received if m.get("op") == op and (peer is None or p is peer)]

    def latest(self):
        with self.lock:
            return self.peers[-1]

    def shutdown(self):
        self.server.shutdown()
        self.server.server_close()
        for peer in list(self.peers):
            peer.drop()


# ---------------------------------------------------------------- stand-ins: Discord REST and the hub

class JSONHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def answer(self, code, body, headers=None):
        data = b"" if body is None else json.dumps(body).encode()
        self.send_response(code)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        if body is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n)) if n else None

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")


def read(path):
    with open(path) as f:
        return f.read()


def serve(handler, owner, port=0):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    server.owner, server.block_on_close = owner, False
    threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True).start()
    return server


class RestHandler(JSONHandler):
    def route(self, method):
        rest = self.server.owner
        if self.headers.get("Authorization") != "Bot " + TOKEN:
            return self.answer(401, {"message": "401: Unauthorized", "code": 0})
        path, _, query = self.path.partition("?")
        m = re.match(r"^/api/v10/channels/(\d+)/(messages|typing)$", path)
        body = self.body()
        with rest.lock:
            rest.requests.append((method, path, query, body, time.monotonic()))
        if (method, path) == ("POST", "/api/v10/users/@me/channels"):
            with rest.lock:
                step = rest.dm_script.pop(0) if rest.dm_script else None
                rest.dm_opens.append(body)
            if step == "drop":
                self.close_connection = True
                return
            if step:
                return self.answer(*step)
            user = body["recipient_id"]
            return self.answer(200, {"id": "9" + user, "type": 1, "recipients": [{"id": user}]})
        if not m:
            return self.answer(404, {"message": "Unknown route", "code": 0})
        chat, what = m.groups()
        if what == "typing":
            with rest.lock:
                rest.typing.append((chat, time.monotonic()))
            return self.answer(204, None)
        if method == "GET":
            after = int(urllib.parse.parse_qs(query)["after"][0])
            page = sorted((x for x in rest.history.get(chat, []) if int(x["id"]) > after),
                          key=lambda x: -int(x["id"]))
            return self.answer(200, page)
        with rest.lock:
            step = rest.script.pop(0) if rest.script else None
            headers = rest.headers.pop(0) if rest.headers else {}
            known = rest.nonces.get(body["nonce"]) if body.get("enforce_nonce") else None
            if step == "drop":
                created = None
            elif known:
                created = known
            elif step is None or step == "create-then-drop":
                rest.next_id += 1
                created = {"id": str(rest.next_id), "channel_id": chat, "content": body["content"]}
                rest.nonces[body["nonce"]] = created
                rest.created.append((chat, body, created["id"]))
        if step in ("drop", "create-then-drop"):
            self.close_connection = True                # no answer: the client cannot know the outcome
            return
        if isinstance(step, tuple):
            return self.answer(*step)
        return self.answer(200, created, headers)


class Rest:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests, self.typing, self.created, self.script, self.headers = [], [], [], [], []
        self.history, self.nonces, self.next_id = {}, {}, 5000
        self.dm_script, self.dm_opens = [], []
        self.server = serve(RestHandler, self)
        self.url = "http://127.0.0.1:%d/api/v10" % self.server.server_address[1]

    def posts(self):
        with self.lock:
            return [r for r in self.requests if r[0] == "POST" and r[1].endswith("/messages")]

    def shutdown(self):
        self.server.shutdown()
        self.server.server_close()


class HubHandler(JSONHandler):
    def route(self, method):
        hub = self.server.owner
        if self.headers.get("Authorization") != "Bearer " + KEY:
            return self.answer(403, {"db": "testdb", "error": "forbidden"})
        path, _, query = self.path.partition("?")
        code, answer = hub.handle(method, path, query, self.body())
        answer.setdefault("db", "testdb")
        self.answer(code, answer)


class FakeHub:
    """The /bridge routes of CHAT-APPS.md 15.4, with a store that the tests read."""
    def __init__(self, journal):
        self.journal = journal
        self.lock = threading.Condition()
        self.config = {"db": "testdb", "paused": False, "version": "v1", "accounts": [], "chats": []}
        self.calls, self.inbound, self.posted, self.journaled, self.forced = [], [], [], [], []
        self.seen, self.items, self.results = set(), [], {}
        self.receipts, self.statuses, self.links = [], [], []
        self.server = serve(HubHandler, self)
        self.port = self.server.server_address[1]
        self.url = "http://127.0.0.1:%d" % self.port

    def handle(self, method, path, query, body):
        with self.lock:
            self.calls.append((method, path))
        if (method, path) == ("GET", "/bridge/config"):
            with self.lock:
                return 200, json.loads(json.dumps(self.config))
        if (method, path) == ("POST", "/bridge/inbound"):
            on_disk = any(body["id"] in read(os.path.join(self.journal, n))
                          for n in os.listdir(self.journal) if n.endswith(".json"))
            with self.lock:
                self.posted.append(body)
                self.journaled.append(on_disk)
                if self.forced:
                    return self.forced.pop(0)
                key = (body["account"], body["id"])
                if key in self.seen:
                    return 200, {"result": "duplicate"}
                self.seen.add(key)
                self.inbound.append(body)
            return 200, {"result": "stored"}
        if (method, path) == ("GET", "/bridge/out"):
            wait = float(urllib.parse.parse_qs(query)["wait"][0])
            with self.lock:
                self.lock.wait_for(lambda: self.items, timeout=min(wait, 1.0))
                items, self.items = self.items, []
                return 200, {"version": self.config["version"], "items": items}
        m = re.match(r"^/bridge/out/(\d+)$", path)
        with self.lock:
            if m and method == "POST":
                self.results[int(m.group(1))] = body
            elif path == "/bridge/receipt":
                self.receipts.append(body)
            elif path == "/bridge/status":
                self.statuses.append(body["accounts"])
            elif path == "/bridge/link":
                self.links.append(body)
            else:
                return 404, {"error": "no such route"}
        return 200, {"ok": True}

    def queue(self, *items):
        with self.lock:
            self.items.extend(items)
            self.lock.notify_all()

    def down(self):
        self.server.shutdown()
        self.server.server_close()

    def up(self):
        self.server = serve(HubHandler, self, self.port)

    def shutdown(self):
        self.down()


# ---------------------------------------------------------------- stand-in: wa-link

STUB = r'''
import json, os, sys, threading, time
args = sys.argv[1:]
db = args[args.index("--db") + 1]
ctl = os.environ["WA_STUB_DIR"]
journal = os.environ.get("WA_STUB_JOURNAL", "")
JID = "34600000001:7@s.whatsapp.net"
lock = threading.Lock()

def emit(obj):
    with lock:
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

def record(obj):
    obj["pid"] = os.getpid()
    with open(os.path.join(ctl, "commands.log"), "a") as f:
        f.write(json.dumps(obj) + "\n")

record({"op": "start", "db": db})
emit({"ev": "state", "state": "connecting", "jid": None, "error": None})
if os.path.exists(db):
    emit({"ev": "state", "state": "linked", "jid": JID, "error": None})
else:
    emit({"ev": "state", "state": "logged_out", "jid": None, "error": None})

def inject():
    folder = os.path.join(ctl, "inject")
    while True:
        for name in sorted(os.listdir(folder)):
            if not name.endswith(".json"):
                continue
            path = os.path.join(folder, name)
            with open(path) as f:
                obj = json.load(f)
            os.unlink(path)
            if obj.get("crash"):
                os._exit(3)
            emit(obj)
        time.sleep(0.01)

threading.Thread(target=inject, daemon=True).start()
for line in sys.stdin:
    cmd = json.loads(line)
    op = cmd.get("op")
    if op == "ack" and journal:
        cmd["journaled"] = any(cmd["id"] in open(os.path.join(journal, n)).read()
                               for n in os.listdir(journal) if n.endswith(".json"))
    record(cmd)
    if op == "pair":
        if not os.path.exists(db):
            emit({"ev": "qr", "code": "QR-CODE-1", "timeout": 20})
            open(db, "w").close()
        emit({"ev": "state", "state": "linked", "jid": JID, "error": None})
    elif op == "send":
        if "NOREPLY" in cmd["text"]:
            continue
        ok = "REFUSE" not in cmd["text"] and "LOST" not in cmd["text"]
        error = None if ok else "refused by the stand-in" if "REFUSE" in cmd["text"] else "unknown: connection lost"
        emit({"ev": "sent", "id": cmd["id"], "ok": ok, "error": error})
    elif op == "logout":
        os.unlink(db)
        emit({"ev": "state", "state": "logged_out", "jid": None, "error": None})
'''


def make_wa_link(folder, journal):
    """The wa-link stand-in in folder, and the environment that makes the bridge start it."""
    os.makedirs(os.path.join(folder, "inject"))
    script = os.path.join(folder, "stub.py")
    with open(script, "w") as f:
        f.write(STUB)
    binary = os.path.join(folder, "wa-link")
    with open(binary, "w") as f:
        f.write(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(script)} \"$@\"\n")
    os.chmod(binary, 0o755)
    return {"FLEET_WA_LINK": binary, "WA_STUB_DIR": folder, "WA_STUB_JOURNAL": journal}


class WaLinkControl:
    """Events into the wa-link stand-in, and the commands that it got."""
    def __init__(self, folder):
        self.folder, self.injected = folder, 0

    def inject(self, obj):
        self.injected += 1
        path = os.path.join(self.folder, "inject", "%04d.json" % self.injected)
        with open(path + ".tmp", "w") as f:
            json.dump(obj, f)
        os.rename(path + ".tmp", path)

    def commands(self, op=None):
        try:
            with open(os.path.join(self.folder, "commands.log")) as f:
                rows = [json.loads(line) for line in f if line.strip()]
        except FileNotFoundError:
            return []
        return [r for r in rows if op is None or r["op"] == op]


def wait_for(test, check, what, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = check()
        if value:
            return value
        time.sleep(0.01)
    test.fail("timed out waiting for " + what)


TIMINGS = dict(OUT_WAIT=1, STATUS_EVERY=0.5, TYPING_EVERY=0.1, BACKOFF_FIRST=0.02, BACKOFF_MAX=0.1, TOKEN_POLL=0.05,
               INVALID_WAIT=(0.01, 0.02), WA_SEND_TIMEOUT=1.0)


# ---------------------------------------------------------------- the test base

def dm(mid, text, author=OWNER, **extra):
    msg = {"id": str(mid), "channel_id": "700", "type": 0, "content": text, "attachments": [],
           "author": {"id": author, "username": "miguel" if author == OWNER else "someone"}}
    msg.update(extra)
    return msg


class Base(unittest.TestCase):
    accounts = []

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.folder = os.path.join(self.tmp.name, "chat-apps")
        os.makedirs(self.folder)
        with open(os.path.join(self.folder, "bridge.key"), "w") as f:
            f.write(KEY + "\n")
        self.journal = os.path.join(self.folder, "journal")
        os.makedirs(self.journal)
        self.log = io.StringIO()
        timings = patch.multiple(channels, LOG=self.log, **TIMINGS)
        timings.start()
        self.addCleanup(timings.stop)
        self.hub, self.gw, self.rest = FakeHub(self.journal), Gateway(), Rest()
        self.hub.config["accounts"] = [dict(a) for a in self.accounts]
        self.bridge = None
        self.private = [TOKEN]

    def tearDown(self):
        if self.bridge:
            self.bridge.stop()
        self.hub.shutdown()
        self.gw.shutdown()
        self.rest.shutdown()
        logs = self.log.getvalue()
        for text in self.private:
            self.assertNotIn(text, logs, "the log holds message text or a token")
        self.tmp.cleanup()

    def start(self):
        self.bridge = channels.Bridge(self.folder, self.hub.url, gateway=self.gw.url, api=self.rest.url)
        self.bridge.start()

    def wait_for(self, check, what, timeout=5.0):
        return wait_for(self, check, what, timeout)

    def write_token(self, token=TOKEN):
        with open(os.path.join(self.folder, "discord-studio.json"), "w") as f:
            json.dump({"token": token}, f)

    def states(self, aid):
        with self.hub.lock:
            return [s for batch in self.hub.statuses for s in batch if s["id"] == aid]

    def has_state(self, aid, state):
        return [s for s in self.states(aid) if s["state"] == state]

    def journal_files(self):
        return [n for n in os.listdir(self.journal) if n.endswith(".json")]

    def config_reads(self):
        with self.hub.lock:
            return self.hub.calls.count(("GET", "/bridge/config"))

    def result(self, item_id):
        return self.wait_for(lambda: self.hub.results.get(item_id), f"the result of item {item_id}")


# ---------------------------------------------------------------- Discord

class DiscordTests(Base):
    accounts = [DISCORD]

    def setUp(self):
        super().setUp()
        self.write_token()

    def ready(self):
        self.start()
        self.wait_for(lambda: self.has_state("discord-studio", "connected"), "the connected state")

    def test_identify_ready_and_status(self):
        self.ready()
        identify = self.gw.ops(2)[0]["d"]
        self.assertEqual(identify["token"], TOKEN)
        self.assertEqual(identify["intents"], 1 << 12)
        self.assertIn("v=10", self.gw.peers[0].path)
        self.assertIn("encoding=json", self.gw.peers[0].path)
        state = self.has_state("discord-studio", "connected")[-1]
        self.assertEqual(state, {"id": "discord-studio", "state": "connected", "user": BOT, "name": "studio-bot",
                                 "application_id": APP, "error": None})
        self.assertIn({"id": "discord-studio", "state": "connecting", "user": None, "name": None,
                       "application_id": None, "error": None}, self.states("discord-studio"))
        posts = len(self.hub.statuses)
        self.wait_for(lambda: len(self.hub.statuses) >= posts + 2, "the status again without a change")

    def test_heartbeat_with_ack_check_then_resume(self):
        self.ready()
        first = self.gw.peers[0]
        beats = self.wait_for(lambda: len(self.gw.ops(1, first)) >= 3 and self.gw.ops(1, first), "three heartbeats")
        self.assertEqual(beats[0]["d"], 1)          # the last sequence number (READY)
        reads = self.config_reads()
        self.gw.ack = False                          # a zombie connection: the client must drop it and resume
        resume = self.wait_for(lambda: self.gw.ops(6), "RESUME")[0]["d"]
        self.gw.ack = True
        self.assertEqual(resume, {"token": TOKEN, "session_id": "s1", "seq": 1})
        self.wait_for(lambda: len(self.has_state("discord-studio", "connected")) >= 2, "connected again")
        self.assertEqual(len(self.gw.ops(2)), 1, "a resume does not identify again")
        time.sleep(0.2)
        self.assertEqual(self.config_reads(), reads, "a resume does not catch up")

    def test_resume_after_a_dropped_socket(self):
        self.ready()
        self.private.append("before the drop zx81")
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(1100, "before the drop zx81"))
        self.wait_for(lambda: self.hub.inbound, "the message")
        self.gw.latest().drop()
        resume = self.wait_for(lambda: self.gw.ops(6), "RESUME")[0]["d"]
        self.assertEqual((resume["session_id"], resume["seq"]), ("s1", 2))
        self.wait_for(lambda: len(self.has_state("discord-studio", "connected")) >= 2, "connected again")
        self.assertEqual(len(self.gw.peers), 2)
        self.assertEqual(len(self.gw.ops(2)), 1)

    def test_invalid_session_identifies_again_and_catches_up(self):
        self.ready()
        reads = self.config_reads()
        self.gw.resume_ok = False
        self.gw.latest().drop()
        self.wait_for(lambda: len(self.gw.ops(2)) == 2, "a second IDENTIFY")
        self.wait_for(lambda: self.config_reads() > reads, "the catch-up of the new session")

    def test_new_session_catches_up_after_the_last_message(self):
        self.private += ["catch me up one", "catch me up two", "my own reply"]
        self.hub.config["chats"] = [{"account": "discord-studio", "chat": "700", "last": "1000"},
                                    {"account": "whatsapp-main", "chat": WA_CHAT, "last": "X"}]
        self.rest.history["700"] = [dm(999, "old"), dm(1001, "catch me up one"), dm(1002, "catch me up two"),
                                    dm(1003, "my own reply", author=BOT)]
        self.ready()
        self.wait_for(lambda: len(self.hub.inbound) == 2, "two caught-up messages")
        self.assertEqual([e["id"] for e in self.hub.inbound], ["1001", "1002"])
        gets = [r for r in self.rest.requests if r[0] == "GET"]
        self.assertEqual(len(gets), 1)
        self.assertEqual(urllib.parse.parse_qs(gets[0][2]), {"after": ["1000"], "limit": ["100"]})
        self.gw.latest().close(4009)                 # session timed out: a new session, so a new catch-up
        self.wait_for(lambda: len(self.gw.ops(2)) == 2, "a second IDENTIFY")
        self.wait_for(lambda: len(self.hub.posted) == 4, "the second catch-up")
        self.assertEqual(len(self.hub.inbound), 2, "the hub answered duplicate")
        self.wait_for(lambda: not self.journal_files(), "an empty journal")

    def test_a_direct_message_goes_to_the_journal_then_the_hub(self):
        self.ready()
        text = "How is the scrape going? q7w"
        self.private.append(text)
        self.private += ["server text p1", "bot text p2", "own text p3"]
        peer = self.gw.latest()
        peer.dispatch("MESSAGE_CREATE", dm(1101, "server text p1", guild_id="42"))
        peer.dispatch("MESSAGE_CREATE", dict(dm(1102, "bot text p2"), author={"id": "777", "bot": True}))
        peer.dispatch("MESSAGE_CREATE", dm(1103, "own text p3", author=BOT))
        peer.dispatch("MESSAGE_CREATE", dm(1104, text))
        event = self.wait_for(lambda: self.hub.inbound, "the message")[0]
        self.assertEqual(event, {"account": "discord-studio", "id": "1104", "chat": "700", "group": False,
                                 "sender": OWNER, "sender_alt": None, "sender_name": "miguel", "bot": False,
                                 "from_me": False, "kind": "text", "text": text,
                                 "ts": channels.snowflake_time("1104")})
        self.assertEqual(self.hub.journaled, [True], "the event was on disk before the hub got it")
        self.wait_for(lambda: not self.journal_files(), "an empty journal")
        time.sleep(0.1)
        self.assertEqual(len(self.hub.posted), 1)
        self.assertIn("inbound discord-studio 1104: stored", self.log.getvalue())

    def test_attachments_have_their_kind(self):
        self.ready()
        peer = self.gw.latest()
        peer.dispatch("MESSAGE_CREATE", dm(1201, "", attachments=[{"content_type": "image/png"}]))
        peer.dispatch("MESSAGE_CREATE", dm(1202, "", attachments=[{"content_type": "audio/ogg"}]))
        peer.dispatch("MESSAGE_CREATE", dm(1203, "", sticker_items=[{"id": "1"}]))
        self.wait_for(lambda: len(self.hub.inbound) == 3, "three messages")
        self.assertEqual([e["kind"] for e in self.hub.inbound], ["image", "audio", "other"])

    def test_fragmented_frames_and_a_ping_between_them(self):
        self.ready()
        self.private.append("in three fragments k2")
        peer = self.gw.latest()
        peer.dispatch("MESSAGE_CREATE", dm(1105, "in three fragments k2"), fragmented=True)
        self.wait_for(lambda: self.hub.inbound, "the message")
        self.assertEqual(self.hub.inbound[0]["text"], "in three fragments k2")
        self.wait_for(lambda: peer.pongs == [b"hi"], "the pong")

    def test_hub_down_then_up_loses_nothing(self):
        self.ready()
        self.private += ["while the hub is down 1", "while the hub is down 2"]
        self.hub.down()
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(1301, "while the hub is down 1"))
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(1302, "while the hub is down 2"))
        self.wait_for(lambda: len(self.journal_files()) == 2, "two events in the journal")
        for name in self.journal_files():
            self.assertEqual(os.stat(os.path.join(self.journal, name)).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.journal).st_mode & 0o777, 0o700)
        time.sleep(0.3)
        self.hub.up()
        self.wait_for(lambda: len(self.hub.inbound) == 2, "both events at the hub")
        self.assertEqual([e["id"] for e in self.hub.inbound], ["1301", "1302"])
        self.wait_for(lambda: not self.journal_files(), "an empty journal")

    def test_the_journal_replays_at_start_and_a_duplicate_is_removed(self):
        journal = channels.Journal(self.journal)
        old = {"account": "discord-studio", "id": "1401", "chat": "700", "text": "left by a crash r4", "kind": "text"}
        dup = {"account": "discord-studio", "id": "1402", "chat": "700", "text": "stored before r5", "kind": "text"}
        self.private += [old["text"], dup["text"]]
        journal.write(old)
        journal.write(dup)
        journal.write(dup)                               # the same message once only
        self.assertEqual(len(self.journal_files()), 2)
        self.hub.seen.add(("discord-studio", "1402"))
        self.ready()
        self.wait_for(lambda: not self.journal_files(), "an empty journal")
        self.assertEqual([e["id"] for e in self.hub.inbound], ["1401"])
        self.assertEqual([e["id"] for e in self.hub.posted], ["1401", "1402"])
        self.assertIn("inbound discord-studio 1402: duplicate", self.log.getvalue())

    def test_409_keeps_the_event_and_400_removes_it(self):
        self.ready()
        self.private += ["kept on 409 m1", "removed on 400 m2"]
        self.hub.forced = [(409, {"error": "unknown account"})]
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(1501, "kept on 409 m1"))
        self.wait_for(lambda: self.hub.inbound, "the event after the retry")
        self.assertEqual(len(self.hub.posted), 2)
        self.hub.forced = [(400, {"error": "bad body"})]
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(1502, "removed on 400 m2"))
        self.wait_for(lambda: len(self.hub.posted) == 3 and not self.journal_files(), "the event removed")
        time.sleep(0.2)
        self.assertEqual(len(self.hub.posted), 3)
        self.assertIn("inbound discord-studio 1502: the hub refused the event (400); removed", self.log.getvalue())

    def test_an_event_of_an_account_that_the_hub_does_not_have_leaves_the_journal(self):
        """The hub's 409 for an unknown or removed account (hub.py bridge_inbound): kept, it went again at every pass."""
        self.ready()
        self.private.append("of a removed account m3")
        self.hub.forced = [(409, {"error": "unknown chat app account"})]
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(1503, "of a removed account m3"))
        self.wait_for(lambda: len(self.hub.posted) == 1 and not self.journal_files(), "the event removed")
        time.sleep(0.2)
        self.assertEqual((len(self.hub.posted), self.hub.inbound), (1, []), "it is never sent again")
        self.assertIn("inbound discord-studio 1503: the hub refused the event (409); removed", self.log.getvalue())

    def test_message_parts_nonces_reply_and_prefix(self):
        self.ready()
        text = "A" * 1500 + "\n\n" + "B" * 1500 + "\n" + "C" * 1000
        self.hub.queue({"id": 41, "kind": "message", "account": "discord-studio", "chat": "700", "text": text,
                        "reply_to": "1104", "prefix": "Studio"})
        result = self.result(41)
        bodies = [body for _, body, _ in self.rest.created]
        self.assertEqual([b["nonce"] for b in bodies], ["f41p1", "f41p2", "f41p3"])
        self.assertTrue(all(b["enforce_nonce"] is True for b in bodies))
        self.assertEqual(bodies[0]["message_reference"], {"message_id": "1104", "fail_if_not_exists": False})
        self.assertNotIn("message_reference", bodies[1])
        self.assertNotIn("message_reference", bodies[2])
        self.assertEqual([b["content"] for b in bodies], ["**Studio:** " + "A" * 1500, "B" * 1500, "C" * 1000])
        self.assertEqual(result, {"state": "sent", "parts": 3, "platform_ids": [i for _, _, i in self.rest.created],
                                  "error": None})

    def test_a_retry_after_429_and_a_lost_answer_makes_one_message(self):
        self.ready()
        self.private.append("send me once w0")
        self.rest.script = [(429, {"retry_after": 0.05, "global": False, "message": "rate limited"}),
                            "create-then-drop"]
        self.hub.queue({"id": 42, "kind": "message", "account": "discord-studio", "chat": "700",
                        "text": "send me once w0", "reply_to": None, "prefix": None})
        result = self.result(42)
        self.assertEqual([r[3]["nonce"] for r in self.rest.posts()], ["f42p1"] * 3)
        self.assertEqual(len(self.rest.created), 1)
        self.assertEqual(result, {"state": "sent", "parts": 1, "platform_ids": [self.rest.created[0][2]],
                                  "error": None})

    def test_no_answer_three_times_is_unknown_and_a_refusal_is_failed(self):
        self.ready()
        self.rest.script = ["drop", "drop", "drop"]
        self.hub.queue({"id": 43, "kind": "message", "account": "discord-studio", "chat": "700", "text": "x",
                        "reply_to": None, "prefix": None})
        self.assertEqual(self.result(43)["state"], "unknown")
        self.rest.script = [(403, {"message": "Cannot send messages to this user", "code": 50007})]
        self.hub.queue({"id": 44, "kind": "message", "account": "discord-studio", "chat": "700", "text": "x",
                        "reply_to": None, "prefix": None})
        result = self.result(44)
        self.assertEqual(result["state"], "failed")
        self.assertIn("50007", result["error"])

    def test_rate_limit_headers_hold_the_next_request(self):
        self.ready()
        self.rest.headers = [{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset-After": "0.3"}]
        for item in (45, 46):
            self.hub.queue({"id": item, "kind": "message", "account": "discord-studio", "chat": "700", "text": "x",
                            "reply_to": None, "prefix": None})
        self.result(45)
        self.result(46)
        times = [r[4] for r in self.rest.posts()]
        self.assertGreaterEqual(times[1] - times[0], 0.28)

    def test_typing_repeats_until_a_message_or_its_time(self):
        self.ready()
        self.hub.queue({"id": 50, "kind": "typing", "account": "discord-studio", "chat": "700", "seconds": 30})
        self.wait_for(lambda: len(self.rest.typing) >= 3, "three typing signals")
        self.hub.queue({"id": 51, "kind": "message", "account": "discord-studio", "chat": "700", "text": "done",
                        "reply_to": None, "prefix": None})
        self.result(51)
        count = len(self.rest.typing)
        time.sleep(0.35)
        self.assertEqual(len(self.rest.typing), count, "the message ended the typing")
        self.hub.queue({"id": 52, "kind": "typing", "account": "discord-studio", "chat": "701", "seconds": 0.25})
        self.wait_for(lambda: any(c == "701" for c, _ in self.rest.typing), "typing in chat 701")
        time.sleep(0.5)
        signals = [t for c, t in self.rest.typing if c == "701"]
        self.assertLessEqual(len(signals), 3)
        self.assertLess(signals[-1] - signals[0], 0.3, "the typing ended after its seconds")

    def test_a_message_with_a_recipient_opens_the_dm_channel_once(self):
        self.ready()
        self.private += ["Written first q1", "Written first q2"]
        self.rest.dm_script = ["drop"]                   # no answer: opening the channel again is harmless
        for item in (60, 61):
            self.hub.queue({"id": item, "kind": "message", "account": "discord-studio", "chat": None,
                            "recipient": OWNER, "text": f"Written first q{item - 59}", "reply_to": None,
                            "prefix": None})
            self.result(item)
        self.assertEqual(self.rest.dm_opens, [{"recipient_id": OWNER}] * 2, "one channel open after the lost answer")
        self.assertEqual([(chat, body["content"], body["nonce"]) for chat, body, _ in self.rest.created],
                         [("9" + OWNER, "Written first q1", "f60p1"), ("9" + OWNER, "Written first q2", "f61p1")])
        self.assertEqual(self.hub.results[60], {"state": "sent", "parts": 1, "platform_ids": [self.rest.created[0][2]],
                                                "error": None})
        self.assertEqual(self.hub.results[61]["state"], "sent")
        self.assertIn(f"DM channel 9{OWNER} with user {OWNER}", self.log.getvalue())

    def test_a_refused_dm_channel_or_a_bad_recipient_fails(self):
        self.ready()
        self.rest.dm_script = [(400, {"message": "Cannot send messages to this user", "code": 50007})]
        self.hub.queue({"id": 62, "kind": "message", "account": "discord-studio", "chat": None, "recipient": "556",
                        "text": "x", "reply_to": None, "prefix": "Studio"})
        self.assertEqual(self.result(62), {"state": "failed", "parts": 0, "platform_ids": [], "error":
                                           "Discord refused the DM channel: HTTP 400, code 50007: "
                                           "Cannot send messages to this user"})
        self.hub.queue({"id": 63, "kind": "message", "account": "discord-studio", "chat": None, "recipient": "x1",
                        "text": "x", "reply_to": None, "prefix": None})
        self.assertEqual(self.result(63)["error"], "The recipient is not a Discord user ID.")
        self.assertEqual(len(self.rest.dm_opens), 1)
        self.assertEqual(self.rest.posts(), [])

    def test_a_changed_token_file_reconnects_with_the_new_token(self):
        self.ready()
        self.private.append(TOKEN + "-2")
        self.write_token(TOKEN + "-2")
        self.wait_for(lambda: len(self.gw.ops(2)) == 2, "a new IDENTIFY with the new token")
        self.assertEqual(self.gw.ops(2)[-1]["d"]["token"], TOKEN + "-2")
        self.assertEqual(self.gw.ops(6), [], "a new token gets a new session, not a resume")
        self.wait_for(lambda: len(self.has_state("discord-studio", "connected")) >= 2, "connected again")
        self.assertIn("the token file changed", self.log.getvalue())
        os.unlink(os.path.join(self.folder, "discord-studio.json"))     # 16.5 delete: the bot goes offline
        self.wait_for(lambda: self.has_state("discord-studio", "missing_token"), "missing_token")
        peers = len(self.gw.peers)
        time.sleep(0.2)
        self.assertEqual(len(self.gw.peers), peers, "no connection without a token")
        self.write_token()
        self.wait_for(lambda: len(self.gw.ops(2)) == 3, "IDENTIFY after the token came back")

    def test_close_code_4014_stops_the_account_until_a_new_token(self):
        self.gw.on_identify = 4014
        self.start()
        state = self.wait_for(lambda: self.has_state("discord-studio", "error"), "the error state")[-1]
        self.assertIn("4014", state["error"])
        time.sleep(0.3)
        self.assertEqual(len(self.gw.peers), 1, "no reconnect after 4014")
        self.gw.on_identify = None
        self.write_token(TOKEN)                          # the same token: still stopped
        time.sleep(0.2)
        self.assertEqual(len(self.gw.peers), 1)
        self.write_token(TOKEN + "-new")
        self.private.append(TOKEN + "-new")
        self.wait_for(lambda: len(self.gw.ops(2)) == 2, "a new IDENTIFY with the new token")
        self.assertEqual(self.gw.ops(2)[-1]["d"]["token"], TOKEN + "-new")
        self.assertEqual(len(self.gw.peers), 2)

    def test_missing_token_then_a_token(self):
        os.unlink(os.path.join(self.folder, "discord-studio.json"))
        self.start()
        self.wait_for(lambda: self.has_state("discord-studio", "missing_token"), "missing_token")
        self.hub.queue({"id": 53, "kind": "message", "account": "discord-studio", "chat": "700", "text": "x",
                        "reply_to": None, "prefix": None})
        self.assertEqual(self.result(53)["state"], "failed")
        self.assertEqual(self.gw.peers, [])
        self.write_token()
        self.wait_for(lambda: self.has_state("discord-studio", "connected"), "connected")

    def test_a_new_config_version_starts_and_stops_accounts(self):
        self.hub.config["accounts"] = []
        self.start()
        self.wait_for(lambda: ("GET", "/bridge/out") in self.hub.calls, "the first poll")
        self.assertEqual(self.gw.peers, [])
        self.hub.config.update(accounts=[DISCORD], version="v2")
        self.wait_for(lambda: self.has_state("discord-studio", "connected"), "the new account connected")
        self.hub.config.update(accounts=[dict(DISCORD, enabled=False)], version="v3")
        peer = self.gw.latest()
        self.wait_for(lambda: self.hub.statuses and self.hub.statuses[-1] == [], "a status without the account")
        self.assertIn("account discord-studio: stopped", self.log.getvalue())
        self.hub.queue({"id": 54, "kind": "message", "account": "discord-studio", "chat": "700", "text": "x",
                        "reply_to": None, "prefix": None})
        self.assertEqual(self.result(54)["error"], "The bridge does not run this account.")
        self.assertEqual(len(self.gw.peers), 1)
        self.assertIsNotNone(peer)


# ---------------------------------------------------------------- WhatsApp

class WhatsAppTests(Base):
    accounts = [WHATSAPP]

    def setUp(self):
        super().setUp()
        self.ctl = os.path.join(self.tmp.name, "stub")
        env = patch.dict(os.environ, make_wa_link(self.ctl, self.journal))
        env.start()
        self.addCleanup(env.stop)
        self.wa = WaLinkControl(self.ctl)
        self.inject, self.commands = self.wa.inject, self.wa.commands

    def link_db(self):
        open(os.path.join(self.folder, "whatsapp-main.db"), "w").close()

    def linked(self):
        self.link_db()
        self.start()
        self.wait_for(lambda: self.has_state("whatsapp-main", "connected"), "the linked state")

    def test_link_message_ack_after_journal_and_receipt(self):
        self.start()
        self.wait_for(lambda: self.has_state("whatsapp-main", "logged_out"), "logged_out")
        self.assertEqual(self.wait_for(lambda: self.hub.links, "the first link report")[0]["state"], "logged_out")
        self.hub.queue({"id": 70, "kind": "link", "account": "whatsapp-main"})
        self.wait_for(lambda: len(self.hub.links) >= 3, "two more link reports")
        waiting, linked = self.hub.links[1], self.hub.links[2]
        self.assertEqual((waiting["state"], waiting["qr"], waiting["error"]), ("waiting", "QR-CODE-1", None))
        self.assertAlmostEqual(waiting["expires"], time.time() + 20, delta=3)
        self.assertEqual((linked["state"], linked["qr"]), ("linked", None))
        state = self.wait_for(lambda: self.has_state("whatsapp-main", "connected"), "connected")[-1]
        self.assertEqual((state["user"], state["name"]), (WA_JID, "34600000001"))
        self.assertNotIn("QR-CODE-1", self.log.getvalue())
        self.hub.queue({"id": 71, "kind": "link", "account": "whatsapp-main"})     # pair on a linked number
        self.wait_for(lambda: len(self.hub.links) == 4, "the link report of the second request")
        self.assertEqual(self.hub.links[3]["state"], "linked")

        text = "Hola, how is the scrape? wa1"
        self.private.append(text)
        self.hub.down()                                  # the journal keeps the event; the ack still goes
        self.inject({"ev": "message", "id": "WAMSG1", "chat": WA_CHAT, "sender": WA_CHAT, "sender_alt": "123@lid",
                     "push_name": "Alex", "group": False, "from_me": False, "kind": "text", "text": text,
                     "ts": 1792134000.5})
        ack = self.wait_for(lambda: self.commands("ack"), "the ack")[0]
        self.assertEqual((ack["id"], ack["journaled"]), ("WAMSG1", True))
        self.hub.up()
        event = self.wait_for(lambda: self.hub.inbound, "the message at the hub")[0]
        self.assertEqual(event, {"account": "whatsapp-main", "id": "WAMSG1", "chat": WA_CHAT, "group": False,
                                 "sender": WA_CHAT, "sender_alt": "123@lid", "sender_name": "Alex", "bot": False,
                                 "from_me": False, "kind": "text", "text": text, "ts": 1792134000.5})
        self.wait_for(lambda: not self.journal_files(), "an empty journal")

        self.inject({"ev": "receipt", "ids": ["3EB0AAAA"], "type": "read"})
        receipt = self.wait_for(lambda: self.hub.receipts, "the receipt")[0]
        self.assertEqual(receipt, {"account": "whatsapp-main", "ids": ["3EB0AAAA"], "type": "read"})

    def test_a_message_item_goes_to_wa_link_with_deterministic_ids(self):
        self.linked()
        body = ("# Title\n**bold** and [site](https://x.y)\n| a | b |\n|---|---|\n| 1 | 2 |\n\n" + "z" * 3990)
        self.hub.queue({"id": 41, "kind": "message", "account": "whatsapp-main", "chat": WA_CHAT, "text": body,
                        "reply_to": "WAMSG1", "prefix": "Studio"})
        result = self.result(41)
        sends = self.commands("send")
        ids = ["3EB0" + hashlib.sha256(f"testdb:41:{n}".encode()).hexdigest()[:16].upper() for n in (1, 2)]
        self.assertEqual([s["id"] for s in sends], ids)
        self.assertEqual([s["to"] for s in sends], [WA_CHAT, WA_CHAT])
        self.assertEqual([s["reply_to"] for s in sends], ["WAMSG1", None])
        self.assertEqual(sends[0]["text"], "*Studio:* *Title*\n*bold* and site (https://x.y)\na · b\n1 · 2")
        self.assertEqual(sends[1]["text"], "z" * 3990)
        self.assertEqual(result, {"state": "sent", "parts": 2, "platform_ids": ids, "error": None})

        self.hub.queue({"id": 42, "kind": "message", "account": "whatsapp-main", "chat": WA_CHAT, "text": "REFUSE",
                        "reply_to": None, "prefix": None})
        self.assertEqual(self.result(42), {"state": "failed", "parts": 0, "platform_ids": [],
                                           "error": "refused by the stand-in"})
        self.hub.queue({"id": 43, "kind": "message", "account": "whatsapp-main", "chat": WA_CHAT, "text": "NOREPLY",
                        "reply_to": None, "prefix": None})
        self.assertEqual(self.result(43)["state"], "unknown")
        self.hub.queue({"id": 44, "kind": "message", "account": "whatsapp-main", "chat": WA_CHAT, "text": "LOST",
                        "reply_to": None, "prefix": None})
        self.assertEqual(self.result(44), {"state": "unknown", "parts": 0, "platform_ids": [],
                                           "error": "unknown: connection lost"})

    def test_read_typing_and_unlink_items(self):
        self.linked()
        self.hub.queue({"id": 80, "kind": "read", "account": "whatsapp-main", "chat": WA_CHAT, "sender": WA_CHAT,
                        "ids": ["WAMSG1"]})
        read = self.wait_for(lambda: self.commands("read"), "the read command")[0]
        self.assertEqual((read["chat"], read["sender"], read["ids"]), (WA_CHAT, WA_CHAT, ["WAMSG1"]))
        self.hub.queue({"id": 81, "kind": "typing", "account": "whatsapp-main", "chat": WA_CHAT, "seconds": 30})
        self.wait_for(lambda: len(self.commands("typing")) >= 2, "typing on twice")
        self.hub.queue({"id": 82, "kind": "message", "account": "whatsapp-main", "chat": WA_CHAT, "text": "ok",
                        "reply_to": None, "prefix": None})
        self.result(82)
        rows = self.wait_for(lambda: [r for r in self.commands() if r["op"] in ("typing", "send")][-1]["op"] == "typing"
                             and [r for r in self.commands() if r["op"] in ("typing", "send")], "typing off")
        self.assertTrue(all(r["on"] for r in rows[:-2]))
        self.assertEqual(rows[-2]["op"], "send")
        self.assertEqual((rows[-1]["op"], rows[-1]["on"]), ("typing", False), "typing off after the reply")
        self.hub.queue({"id": 83, "kind": "unlink", "account": "whatsapp-main"})
        self.wait_for(lambda: self.has_state("whatsapp-main", "logged_out"), "logged_out")
        self.wait_for(lambda: self.hub.links and self.hub.links[-1]["state"] == "logged_out", "the link report")
        self.assertEqual(self.has_state("whatsapp-main", "logged_out")[-1]["user"], None)

    def test_wa_link_restarts_after_a_crash(self):
        self.linked()
        first = self.commands("start")[0]["pid"]
        self.inject({"crash": True})
        self.wait_for(lambda: len(self.commands("start")) == 2, "a second wa-link")
        self.assertNotEqual(self.commands("start")[1]["pid"], first)
        error = self.has_state("whatsapp-main", "error")[-1]
        self.assertEqual(error["error"], "wa-link stopped (exit 3).")
        self.wait_for(lambda: self.states("whatsapp-main")[-1]["state"] == "connected", "connected again")
        self.hub.queue({"id": 90, "kind": "message", "account": "whatsapp-main", "chat": WA_CHAT, "text": "after",
                        "reply_to": None, "prefix": None})
        self.assertEqual(self.result(90)["state"], "sent")
        self.assertEqual(self.commands("send")[0]["pid"], self.commands("start")[1]["pid"])

    def test_no_wa_link_binary_is_an_error_state(self):
        with patch.dict(os.environ, {"FLEET_WA_LINK": os.path.join(self.ctl, "missing")}):
            self.start()
            state = self.wait_for(lambda: self.has_state("whatsapp-main", "error"), "the error state")[-1]
        self.assertEqual(state["error"], "wa-link is not installed on the hub machine.")
        self.hub.queue({"id": 91, "kind": "message", "account": "whatsapp-main", "chat": WA_CHAT, "text": "x",
                        "reply_to": None, "prefix": None})
        self.assertEqual(self.result(91)["error"], "WhatsApp is not linked.")


# ---------------------------------------------------------------- the real hub

OWNER_IP = "127.0.0.9"
REAL_TEAM = {"hub": {"machine": "hub", "port": 8765},
             "addresses": {"owner": OWNER_IP, "hub": "127.0.0.1", "studio-host": "127.0.0.3"},
             "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                        "studio": {"role": "worker", "runtime": "claude", "machine": "studio-host", "can": ["shell"]}},
             "chat_apps": {"discord-studio": {"app": "discord", "label": "Studio", "agents": ["studio"],
                                              "unknown": "ignore"},
                           "whatsapp-main": {"app": "whatsapp", "label": "Fleet", "agents": ["manager"],
                                             "unknown": "ignore"}}}
CHAT_CONTEXT = ("test-generation", "owner-chat", "1")


def git(*args, cwd=None):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


@unittest.skipUnless(hasattr(fleet_hub, "ensure_bridge_key"), "hub.py has no /bridge routes yet")
class RealHub(test_ui_api.OwnerAPI):
    """channels.py against the real hub.Handler in this process: a temporary database, git repository and chat-apps
    folder; the bridge calls from 127.0.0.1, the hub machine's address here."""
    def setUp(self):
        super().setUp()
        root = tempfile.mkdtemp(prefix="fleet-channels-hub-")
        self.addCleanup(shutil.rmtree, root, True)
        seed = os.path.join(root, "seed")
        os.makedirs(seed)
        with open(os.path.join(seed, "team.json"), "w") as f:
            json.dump(REAL_TEAM, f, indent=2)
        git("init", "-q", seed)
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "seed", cwd=seed)
        git("clone", "-q", "--bare", seed, os.path.join(root, "origin.git"))
        git("clone", "-q", os.path.join(root, "origin.git"), os.path.join(root, "kit"))
        fleet_hub._revision_cache.update(at=0.0, value=None)
        fleet_hub.TEAM = json.loads(json.dumps(REAL_TEAM))
        self.folder = os.path.join(root, "home", ".fleet", "chat-apps")
        for key, value in (("team_path", os.path.join(root, "kit", "team.json")), ("chat_apps_dir", self.folder)):
            fleet_hub.CFG[key] = value
            self.addCleanup(fleet_hub.CFG.pop, key, None)
        fleet_hub.ensure_bridge_key()
        self.log = io.StringIO()
        timings = patch.multiple(channels, LOG=self.log, **TIMINGS)
        timings.start()
        self.addCleanup(timings.stop)
        self.gw, self.rest = Gateway(), Rest()
        with open(os.path.join(self.folder, "discord-studio.json"), "w") as f:
            json.dump({"token": TOKEN}, f)
        open(os.path.join(self.folder, "whatsapp-main.db"), "w").close()
        ctl = os.path.join(root, "stub")
        env = patch.dict(os.environ, make_wa_link(ctl, os.path.join(self.folder, "journal")))
        env.start()
        self.addCleanup(env.stop)
        self.wa = WaLinkControl(ctl)
        self.bridge = channels.Bridge(self.folder, self.base, gateway=self.gw.url, api=self.rest.url)
        self.bridge.start()

    def tearDown(self):
        self.bridge.stop()
        self.gw.shutdown()
        self.rest.shutdown()
        super().tearDown()
        logs = self.log.getvalue()
        for text in (TOKEN, "How is the scrape going? rh1", "On it, rh2", "LINK-CODE"):
            self.assertNotIn(text, logs)
        self.assertNotIn(read(os.path.join(self.folder, "bridge.key")).strip(), logs)

    def owner(self, path):
        return self.request(path, source=OWNER_IP)

    def owner_post(self, path, **fields):
        return self.request(path, dict(request_id=str(uuid.uuid4()), db="test-generation", **fields), source=OWNER_IP)

    def accounts(self):
        return {a["id"]: a for a in self.owner("/ui/chat-apps?db=test-generation")[1]["accounts"]}

    def test_the_owner_round_trip_through_the_real_hub(self):
        accounts = wait_for(self, lambda: all(a["state"] == "connected" for a in self.accounts().values())
                            and self.accounts(), "both accounts connected at the hub")
        self.assertEqual((accounts["discord-studio"]["user"], accounts["discord-studio"]["application_id"]), (BOT, APP))
        self.assertEqual(accounts["whatsapp-main"]["name"], "34600000001")

        # Discord: the owner links the ID with a code; the fixed reply goes back as a reply to the code message
        code, data = self.owner_post("/ui/people/codes", purpose="owner", app="discord")
        self.assertEqual(code, 200, data)
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(2001, f"link {data['code']}"))
        wait_for(self, lambda: self.rest.created, "the link reply")
        _, body, _ = self.rest.created[0]
        self.assertEqual(body["content"], "Linked. You are the owner in Founderizer.")

        # a message to Studio: the agent reads it (typing) and replies (the reply goes back with its delivery)
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(2002, "How is the scrape going? rh1"))
        req = wait_for(self, lambda: fleet_hub.q1("SELECT * FROM ui_requests WHERE client=?",
                                                  ("fleet-channels/1/discord-studio",)), "the owner message at the hub")
        self.assertEqual(json.loads(req["origin"])["id"], "2002")
        text, error = fleet_hub.call_tool("studio", "read_messages", {}, CHAT_CONTEXT)
        self.assertFalse(error, text)
        self.assertIn("How is the scrape going? rh1", text)
        wait_for(self, lambda: [c for c, _ in self.rest.typing if c == "700"], "typing in the chat")
        text, error = fleet_hub.call_tool("studio", "tell_owner", {"text": "On it, rh2", "about": "scrape",
                                                                   "in_reply_to": req["request_id"]}, CHAT_CONTEXT)
        self.assertFalse(error, text)
        wait_for(self, lambda: len(self.rest.created) == 2, "the reply")
        _, body, platform_id = self.rest.created[1]
        self.assertEqual((body["content"], body["message_reference"]["message_id"]), ("On it, rh2", "2002"))
        self.assertRegex(body["nonce"], r"^f\d+p1$")
        delivery = wait_for(self, lambda: (self.owner("/ui/state")[1]["reports"][0]["delivery"] or {}).get("state")
                            == "sent" and self.owner("/ui/state")[1]["reports"][0]["delivery"], "the sent delivery")
        self.assertEqual(body["nonce"], f"f{delivery['outbound']}p1")
        self.assertEqual(self.accounts()["discord-studio"]["sent_today"], 2)      # the link reply and this one
        receipt = self.bridge.hub.call("POST", "/bridge/receipt", {"account": "discord-studio", "ids": [platform_id],
                                                                   "type": "read"})
        self.assertEqual(receipt, (200, {"db": "test-generation", "ok": True}))

        # WhatsApp: link the number, then /whoami; parts have the deterministic IDs of the hub's generation
        code, data = self.owner_post("/ui/people/codes", purpose="owner", app="whatsapp")
        self.assertEqual(code, 200, data)
        self.wa.inject({"ev": "message", "id": "WALINK1", "chat": WA_CHAT, "sender": WA_CHAT, "sender_alt": None,
                        "push_name": "Alex", "group": False, "from_me": False, "kind": "text",
                        "text": f"link {data['code']}", "ts": time.time()})
        send = wait_for(self, lambda: self.wa.commands("send"), "the WhatsApp link reply")[0]
        self.assertEqual(send["text"], "Linked. You are the owner in Founderizer.")
        item = fleet_hub.q1("SELECT id FROM chat_out WHERE kind='message' ORDER BY id DESC LIMIT 1")["id"]
        self.assertEqual(send["id"], channels.wa_message_id("test-generation", item, 1))
        self.assertTrue(self.wa.commands("ack")[0]["journaled"])
        self.wa.inject({"ev": "message", "id": "WAWHOAMI", "chat": WA_CHAT, "sender": WA_CHAT, "sender_alt": None,
                        "push_name": "Alex", "group": False, "from_me": False, "kind": "text", "text": "/whoami",
                        "ts": time.time()})
        wait_for(self, lambda: len(self.wa.commands("send")) == 2, "the /whoami reply")
        self.assertEqual(self.wa.commands("send")[1]["text"], "You are the owner.")

        # the owner asks for a new link: pair on a linked number gives linked again
        code, data = self.owner_post("/ui/chat-apps/whatsapp-main/link")
        self.assertEqual(code, 200, data)
        wait_for(self, lambda: self.wa.commands("pair"), "pair")
        link = wait_for(self, lambda: self.owner("/ui/chat-apps/whatsapp-main/link?db=test-generation")[1]
                        .get("state") == "linked", "the link state")
        self.assertTrue(link)
        wait_for(self, lambda: not [n for n in os.listdir(os.path.join(self.folder, "journal"))
                                    if n.endswith(".json")], "an empty journal")
        self.assertNotIn("the hub refused", self.log.getvalue())


# ---------------------------------------------------------------- functions

class Functions(unittest.TestCase):
    def test_split_parts(self):
        self.assertEqual(channels.split_parts("short", 2000), ["short"])
        text = "\n\n".join(f"P{i} " + "x" * 1900 for i in range(6))
        parts = channels.split_parts(text, 2000)
        self.assertEqual(len(parts), 4)
        self.assertTrue(all(len(p) <= 2000 for p in parts))
        self.assertTrue(parts[3].startswith("P3 ") and parts[3].endswith("\n\nThe rest is in Founderizer."))
        exact = "\n\n".join("y" * 1990 for _ in range(4))
        self.assertEqual(channels.split_parts(exact, 2000), ["y" * 1990] * 4, "four parts that fit get no note")
        full = channels.split_parts("w" * 9000, 2000)
        self.assertEqual([len(p) for p in full], [2000, 2000, 2000, 2000])
        self.assertTrue(full[3].endswith("The rest is in Founderizer."))
        words = channels.split_parts("word " * 500, 2000)
        self.assertTrue(all(not p.startswith(" ") and len(p) <= 2000 for p in words))

    def test_wa_format(self):
        self.assertEqual(channels.wa_format("## A **b** [c](https://d.e)\n**x** y"), "*A b c (https://d.e)*\n*x* y")
        self.assertEqual(channels.wa_format("| h1 | h2 |\n| :-- | --: |\n| v1 |  |"), "h1 · h2\nv1")
        self.assertEqual(channels.wa_format("```\n**kept** # not a heading\n```"), "```\n**kept** # not a heading\n```")

    def test_wa_message_id(self):
        self.assertEqual(channels.wa_message_id("20e1f17068fc", 41, 1),
                         "3EB0" + hashlib.sha256(b"20e1f17068fc:41:1").hexdigest()[:16].upper())
        self.assertEqual(len(channels.wa_message_id("db", 1, 1)), 20)

    def test_unit(self):
        out = io.StringIO()
        with patch("sys.stdout", out):
            self.assertEqual(channels.main(["unit"]), 0)
        unit = out.getvalue()
        self.assertIn("ExecStart=" + json.dumps(sys.executable) + " " +
                      json.dumps(os.path.join(channels.KIT, "channels.py")) + " run", unit)
        self.assertIn("Restart=always", unit)
        self.assertIn("WantedBy=default.target", unit)

    def test_a_new_token_file_counts_within_15_seconds(self):
        self.assertLessEqual(channels.TOKEN_POLL, 5, "16.4: the poll plus the connection stay under 15 seconds")

    def test_hub_address_from_team_json(self):
        team = {"hub": {"machine": "hub", "port": 8765}, "addresses": {"hub": "100.1.2.3"}}
        self.assertEqual(channels.hub_url(team), "http://100.1.2.3:8765")
        self.assertEqual(channels.hub_url({"hub": "http://CHANGE-ME:8765"}), "")


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for case in (DiscordTests, WhatsAppTests, Functions):
        suite.addTests(loader.loadTestsFromTestCase(case))
    if hasattr(fleet_hub, "ensure_bridge_key"):     # only RealHub's own tests, not those of OwnerAPI
        suite.addTests(RealHub(name) for name in RealHub.__dict__ if name.startswith("test_"))
    return suite


if __name__ == "__main__":
    unittest.main()
