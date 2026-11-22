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
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request
import uuid
import warnings
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
        raw = self.rfile.read(n) if n else b""
        kind = self.headers.get("Content-Type") or ""
        if kind.startswith("multipart/form-data"):      # a Discord message with files: payload_json and files[n]
            boundary = kind.split("boundary=", 1)[1].encode()
            payload, files = None, []
            for part in raw.split(b"--" + boundary)[1:-1]:
                head, _, data = part.partition(b"\r\n\r\n")
                named = re.search(rb'name="([^"]+)"(?:; filename="([^"]*)")?', head)
                typed = re.search(rb"Content-Type: (\S+)", head)
                if named.group(1) == b"payload_json":
                    payload = json.loads(data[:-2])
                else:
                    files.append((named.group(1).decode(), named.group(2).decode(), typed.group(1).decode(), data[:-2]))
            return dict(payload, _files=files)
        return json.loads(raw) if raw else None

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
        m = re.match(r"^/bridge/files/(\d+)$", path)
        if m and method == "GET":                       # CHAT-APPS.md 20: the bytes of a file of a message item
            with hub.lock:
                hub.calls.append((method, path))
                data = hub.files.get((int(m.group(1)), urllib.parse.parse_qs(query).get("item", [""])[0]))
            if data is None:
                return self.answer(404, {"db": "testdb", "error": "no such file"})
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            return self.wfile.write(data)
        if (method, path) == ("POST", "/bridge/files"):     # the bytes of one file of an inbound message
            n = int(self.headers.get("Content-Length") or 0)
            code, answer = hub.upload(urllib.parse.parse_qs(query, keep_blank_values=True),
                                      self.rfile.read(n) if n else b"", self.headers.get("Content-Type") or "")
            answer.setdefault("db", "testdb")
            return self.answer(code, answer)
        code, answer = hub.handle(method, path, query, self.body())
        answer.setdefault("db", "testdb")
        self.answer(code, answer)


UPLOAD_FIELDS = ("account", "message", "n", "name", "mime", "sender")      # and sender_alt, when the event has one
MIME = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*")     # a type/subtype, any type


class FakeHub:
    """The /bridge routes of CHAT-APPS.md 15.4, with a store that the tests read."""
    def __init__(self, journal):
        self.journal = journal
        self.lock = threading.Condition()
        self.config = {"db": "testdb", "paused": False, "version": "v1", "accounts": [], "chats": []}
        self.calls, self.inbound, self.posted, self.journaled, self.forced = [], [], [], [], []
        self.seen, self.items, self.results = set(), [], {}
        self.receipts, self.statuses, self.links = [], [], []
        self.files = {}                 # (file id, item id as text) -> the bytes that GET /bridge/files serves
        self.uploads = []               # POST /bridge/files, in order: (its query's fields, bytes and Content-Type)
        self.upload_answers = []        # what the next uploads get, in order (None: the default 200): a test's script
        self.checks, self.check_answers = [], []    # the same for its question, check=1 with no body
        self.file_ids = {}              # (account, message, n) -> the id of its row: the same upload again gets it
        self.config_fails = 0           # how many readings of /bridge/config fail first
        self.out_queries, self.begun = [], []
        self.bridge_code = None
        self.server = serve(HubHandler, self)
        self.port = self.server.server_address[1]
        self.url = "http://127.0.0.1:%d" % self.port

    def handle(self, method, path, query, body):
        with self.lock:
            self.calls.append((method, path))
        if (method, path) == ("GET", "/bridge/config"):
            with self.lock:
                if self.config_fails:
                    self.config_fails -= 1
                    return 503, {"error": "hub error"}
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
            with self.lock:
                self.out_queries.append(query)
            wait = float(urllib.parse.parse_qs(query)["wait"][0])
            with self.lock:
                self.lock.wait_for(lambda: self.items, timeout=min(wait, 1.0))
                items, self.items = self.items, []
                return 200, {"version": self.config["version"], "items": items}
        m = re.match(r"^/bridge/out/(\d+)$", path)
        with self.lock:
            if m and method == "POST" and body.get("state") == "sending":
                self.begun.append(int(m.group(1)))     # CHAT-APPS.md 20: the bridge begins this item now
            elif m and method == "POST":
                self.results[int(m.group(1))] = body
            elif path == "/bridge/receipt":
                self.receipts.append(body)
            elif path == "/bridge/status":
                self.statuses.append(body["accounts"])
                self.bridge_code = body.get("code")
            elif path == "/bridge/link":
                self.links.append(body)
            else:
                return 404, {"error": "no such route"}
        return 200, {"ok": True}

    def upload(self, query, data, kind):
        """POST /bridge/files as the interface of the design's version 2 says (20 November 2026), with any type and n
        from 1 to 10: 400 for a bad field; else the next answer that the test asked for; else 200 with the id of the row
        of this account, message and number, which the same upload again gets. With check=1 and no body, the hub's
        question whether it takes this sender's files: 200 welcome, or the answer that the test asked for."""
        fields = {k: v[-1] for k, v in query.items()}
        check = fields.pop("check", None)
        with self.lock:
            self.calls.append(("POST", "/bridge/files?check" if check else "/bridge/files"))
            (self.checks if check else self.uploads).append((fields, data, kind))
            if kind != "application/octet-stream" or not all(fields.get(k) for k in UPLOAD_FIELDS) or \
                    set(fields) - set(UPLOAD_FIELDS) - {"sender_alt"} or \
                    fields["n"] not in [str(n) for n in range(1, 11)] or not MIME.fullmatch(fields["mime"]) or \
                    len(data) > 25 << 20 or check not in (None, "1") or (check and data):
                return 400, {"error": "a bad field"}
            script = self.check_answers if check else self.upload_answers
            answer = script.pop(0) if script else None
            if answer:
                return answer[0], dict(answer[1])
            if check:
                return 200, {"welcome": True}
            return 200, {"id": self.file_ids.setdefault((fields["account"], fields["message"], fields["n"]),
                                                        7000 + len(self.file_ids))}

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


class CDNHandler(JSONHandler):
    def route(self, method):
        cdn, path = self.server.owner, self.path.partition("?")[0]
        with cdn.lock:
            cdn.requests.append((self.path, self.headers.get("Authorization"), self.headers.get("User-Agent")))
            data, how = cdn.files.get(path, (None, None))
        if data is None:
            return self.answer(404, {"message": "404: Not Found", "code": 0})
        if how == "slow-head":          # a head of 200 lines, one each 50 ms (http.client stops at line 101, ~5 s)
            try:
                self.wfile.write(b"HTTP/1.0 200 OK\r\n")
                for i in range(200):
                    self.wfile.write(b"X-Wait: %d\r\n" % i)
                    time.sleep(0.05)
                self.wfile.write(b"Content-Length: 100000000000\r\n\r\n")
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        if how not in ("no-length", "stream"):      # with no length, the answer ends with its connection (HTTP/1.0)
            self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if how == "once":               # an address that ends after its first fetch, as a signed one does in time
            with cdn.lock:
                cdn.files.pop(path, None)
        try:
            if how == "slow":           # a byte every 50 ms: each read is quick, the whole is not
                for i in range(len(data)):
                    self.wfile.write(data[i:i + 1])
                    time.sleep(0.05)
            elif how == "stream":       # data 96 times, as long as the reader reads: cdn.sent counts the times
                for _ in range(96):
                    self.wfile.write(data)
                    with cdn.lock:
                        cdn.sent[path] = cdn.sent.get(path, 0) + 1
            else:
                self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass


class CDN:
    """Discord's CDN, where the files of a message are: the bytes at each path, and the requests that it got."""
    def __init__(self):
        self.lock = threading.Lock()
        self.files, self.requests, self.sent = {}, [], {}
        self.server = serve(CDNHandler, self)
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]

    def add(self, path, data, how=None):
        """The address of a file at path, signed as Discord signs one. No data: a file that is not there (404)."""
        if data is not None:
            with self.lock:
                self.files[path] = (data, how)
        return self.url + path + "?ex=6740b2c1&is=673f6141&hm=signed0f3e9a"

    def fetched(self):
        with self.lock:
            return [path.partition("?")[0] for path, _, _ in self.requests]

    def shutdown(self):
        self.server.shutdown()
        self.server.server_close()


# ---------------------------------------------------------------- stand-in: wa-link

STUB = r'''
import hashlib, json, os, sys, threading, time
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
if not os.environ.get("WA_STUB_OLD"):           # a wa-link of today says what it can do first; an older one says nothing
    emit({"ev": "hello", "features": ["file"] if os.environ.get("WA_STUB_NO_DOWNLOAD") else ["file", "download"]})
emit({"ev": "state", "state": "connecting", "jid": None, "error": None})
linked = threading.Event()      # a download needs WhatsApp's media servers: before the link it fails, as whatsmeow's

def link(delay):
    time.sleep(delay)
    linked.set()
    emit({"ev": "state", "state": "linked", "jid": JID, "error": None})

if os.path.exists(db):
    delay = float(os.environ.get("WA_STUB_LINK_DELAY") or 0)        # a number that takes a while to link, while the
    if delay:                                                       # commands come
        threading.Thread(target=link, args=(delay,), daemon=True).start()
    else:
        link(0)
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

def download(cmd):
    """A download into the inbox beside the database, of the bytes of media/<the direct path's last part>; some
    parts act: fail, large, silent (no answer), slow (an answer after 1.5 s), crash-once (wa-link stops, once)."""
    spec = cmd.get("media") or {}
    name = str(spec.get("direct_path") or "").split("?")[0].rsplit("/", 1)[-1]
    if not linked.is_set():
        return emit({"ev": "downloaded", "id": cmd["id"], "ok": False, "size": None, "too_large": False,
                     "error": "wa-link is not connected to WhatsApp"})
    if name == "silent":
        return
    if name == "crash-once":
        mark = os.path.join(ctl, "crashed")
        if not os.path.exists(mark):
            open(mark, "w").close()
            os._exit(4)
    if name in ("slow", "slow-crash"):
        time.sleep(1.5)
    if name in ("fail", "large"):
        return emit({"ev": "downloaded", "id": cmd["id"], "ok": False, "size": None, "too_large": name == "large",
                     "error": "STUB-WORDS of https://mmg.whatsapp.net/v/t62/x?hash=STUB"})
    with open(os.path.join(ctl, "media", name), "rb") as f:
        data = f.read()
    target = os.path.join(os.path.dirname(db), "inbox", cmd["id"])
    with os.fdopen(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as out:
        out.write(data)
    record({"op": "wrote", "id": cmd["id"]})
    if name == "slow-crash":    # it stops before its answer
        os._exit(5)
    emit({"ev": "downloaded", "id": cmd["id"], "ok": True, "size": len(data), "too_large": False, "error": None})

for line in sys.stdin:
    cmd = json.loads(line)
    op = cmd.get("op")
    if op == "ack" and journal:
        cmd["journaled"] = any(cmd["id"] in open(os.path.join(journal, n)).read()
                               for n in os.listdir(journal) if n.endswith(".json"))
    if op == "send" and cmd.get("file"):        # the bytes that it found at the path, and that folder's mode
        with open(cmd["file"]["path"], "rb") as f:
            cmd["file_sha256"] = hashlib.sha256(f.read()).hexdigest()
        cmd["file_mode"] = oct(os.stat(cmd["file"]["path"]).st_mode & 0o777)
        cmd["outbox"] = os.path.dirname(cmd["file"]["path"]) == os.path.join(os.path.dirname(db), "outbox")
    record(cmd)
    if op == "pair":
        if not os.path.exists(db):
            emit({"ev": "qr", "code": "QR-CODE-1", "timeout": 20})
            open(db, "w").close()
        linked.set()
        emit({"ev": "state", "state": "linked", "jid": JID, "error": None})
    elif op == "send":
        if "NOREPLY" in cmd["text"]:
            continue
        refuse = "REFUSE" in cmd["text"] or "REFUSE" in (cmd.get("file") or {}).get("name", "")
        ok = not refuse and "LOST" not in cmd["text"] and "URLERR" not in cmd["text"]
        error = None if ok else "refused by the stand-in" if refuse else "unknown: connection lost" \
            if "LOST" in cmd["text"] else 'not sent: Post "https://mmg.whatsapp.net/mms/document/x?auth=AUTH-VALUE": EOF'
        emit({"ev": "sent", "id": cmd["id"], "ok": ok, "error": error})
    elif op == "logout":
        os.unlink(db)
        emit({"ev": "state", "state": "logged_out", "jid": None, "error": None})
    elif op == "download":
        threading.Thread(target=download, args=(cmd,), daemon=True).start()
'''


def make_wa_link(folder, journal):
    """The wa-link stand-in in folder, and the environment that makes the bridge start it."""
    os.makedirs(os.path.join(folder, "inject"))
    os.makedirs(os.path.join(folder, "media"))
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

    def media(self, part, data):
        """The bytes that the stand-in downloads for a direct path whose last part is `part`."""
        with open(os.path.join(self.folder, "media", part), "wb") as f:
            f.write(data)

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
               INVALID_WAIT=(0.01, 0.02), WA_SEND_TIMEOUT=1.0, WA_LOGOUT_WAIT=1.0)


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
        self.cdn = CDN()
        self.addCleanup(self.cdn.shutdown)
        cdn = patch.object(channels, "DISCORD_FILES", (self.cdn.url + "/",))
        cdn.start()
        self.addCleanup(cdn.stop)

    def ready(self):
        self.start()
        self.wait_for(lambda: self.has_state("discord-studio", "connected"), "the connected state")

    def attachment(self, aid, name, data, mime="image/png", size=None, how=None):
        """A file of a Discord message, on the CDN stand-in (no data: not there). Its name and its address are what
        the log never holds."""
        path = f"/attachments/700/{aid}/{name}"
        self.private += [name, path, "hm=signed"]
        a = {"id": aid, "filename": name, "size": len(data or b"") if size is None else size,
             "url": self.cdn.add(path, data, how)}
        if mime:
            a["content_type"] = mime
        return a

    def order(self):
        """The hub's questions (check=1), the uploads and the inbound posts, in the order that the hub got them."""
        with self.hub.lock:
            return [path for _, path in self.hub.calls if path in ("/bridge/files?check", "/bridge/files",
                                                                    "/bridge/inbound")]

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
        """Each message's kind, with its words: a picture's words go with it (CHAT-APPS.md 8.1), and a forwarded
        message's words and files are those of its snapshot, which would otherwise be lost in silence."""
        self.ready()
        peer = self.gw.latest()
        peer.dispatch("MESSAGE_CREATE", dm(1201, "The error that I get", attachments=[{"content_type": "image/png"}]))
        peer.dispatch("MESSAGE_CREATE", dm(1202, "", attachments=[{"content_type": "audio/ogg"}]))
        peer.dispatch("MESSAGE_CREATE", dm(1203, "", sticker_items=[{"id": "1"}]))
        peer.dispatch("MESSAGE_CREATE", dm(1204, "", message_reference={"type": 1}, message_snapshots=[
            {"message": {"content": "See the invoice", "attachments": [{"content_type": "application/pdf"}]}}]))
        self.wait_for(lambda: len(self.hub.inbound) == 4, "four messages")
        self.assertEqual([(e["kind"], e["text"]) for e in self.hub.inbound],
                         [("image", "The error that I get"), ("audio", ""), ("other", ""), ("file", "See the invoice")])

    def test_a_picture_with_words_and_a_forwarded_file_go_up_before_their_messages(self):
        """The design of 20 November 2026 (version 2): the hub says first whether it takes the sender's files (check=1,
        no body), then each file of a person's message goes to POST /bridge/files with its query fields and its bytes,
        fetched from Discord's CDN with no bot token, before the message, which then carries no `media`; a forwarded
        message's file is its first snapshot's. Before, the agent read the words and never the screenshot that they
        spoke of."""
        self.ready()
        png, pdf = b"\x89PNG\r\n\x1a\n a screenshot", b"%PDF-1.4 an invoice"
        self.private += ["The error that I get", "See the invoice"]
        peer = self.gw.latest()
        peer.dispatch("MESSAGE_CREATE", dm(1601, "The error that I get",
                                           attachments=[self.attachment("11", "screenshot.png", png)]))
        peer.dispatch("MESSAGE_CREATE", dm(1602, "", message_reference={"type": 1}, message_snapshots=[
            {"message": {"content": "See the invoice",
                         "attachments": [self.attachment("12", "Invoice_October.pdf", pdf, "application/pdf")]}}]))
        self.wait_for(lambda: len(self.hub.inbound) == 2, "both messages")
        fields = {"account": "discord-studio", "n": "1", "sender": OWNER}
        first = dict(fields, message="1601", name="screenshot.png", mime="image/png")
        second = dict(fields, message="1602", name="Invoice_October.pdf", mime="application/pdf")
        octets = "application/octet-stream"
        self.assertEqual(self.hub.uploads, [(first, png, octets), (second, pdf, octets)])
        self.assertEqual(self.hub.checks, [(first, b"", octets), (second, b"", octets)])
        self.assertEqual([(e["kind"], e["text"]) for e in self.hub.inbound],
                         [("image", "The error that I get"), ("file", "See the invoice")])
        self.assertEqual([sorted(set(e) & {"media", "media_more", "missed"}) for e in self.hub.posted], [[], []])
        self.assertEqual(self.order(), ["/bridge/files?check", "/bridge/files", "/bridge/inbound"] * 2,
                         "the hub's yes, then each file, then its message")
        self.assertEqual([(token, agent) for _, token, agent in self.cdn.requests], [(None, channels.USER_AGENT)] * 2,
                         "no bot token goes to the CDN")
        self.wait_for(lambda: not self.journal_files(), "an empty journal")
        self.assertEqual((self.bridge.files_seen, self.bridge.file_held), ({}, None),
                         "the bridge keeps nothing of a message that left the journal")

    def test_every_file_goes_up_with_the_type_that_the_rule_gives(self):
        """The owner, 20 November 2026: "does it accept multiple files, images etc? it should". Each file of a message
        goes up, of any type: Discord's own type without its parameters and in lower case, when it is a valid
        type/subtype; else its name's extension's (the hub's own first, then Python's); else application/octet-stream.
        Only a size above 25 MiB that Discord gives is missed before a fetch; the 11th file and later are `many`, and
        `missed` keeps each code, up to the hub's 20."""
        self.ready()
        big, png = channels.FILE_MOST + 1, b"\x89PNG\r\n\x1a\n"
        files = [self.attachment("21", "clip.mp4", b"\x00\x00\x00\x18ftypmp42", "video/mp4"),
                 self.attachment("22", "big-1.zip", b"PK\x03\x04", "application/zip", size=big),
                 self.attachment("23", "notes.txt", b"Notes", "text/plain; charset=utf-8"),
                 self.attachment("24", "notes.md", b"# Notes", None),
                 self.attachment("25", "big-2.pdf", b"%PDF-", "application/pdf", size=big),
                 self.attachment("26", "report.zip", b"PK\x03\x04", "application/x-zip-compressed"),
                 self.attachment("27", "big-3.png", png, size=big),
                 self.attachment("28", "drawing.svg", b"<svg/>", "image svg"),
                 self.attachment("29", "README", b"Read me", None),
                 self.attachment("30", "Voice.OGG", b"OggS", "AUDIO/OGG")]
        files += [self.attachment(str(31 + i), f"more-{i}.png", png) for i in range(2)]
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(1611, "", attachments=files))
        event = self.wait_for(lambda: self.hub.posted, "the message")[0]
        self.assertEqual(event["missed"], ["size", "size", "size", "many", "many"])
        self.assertEqual([(f["n"], f["name"], f["mime"]) for f, _, _ in self.hub.uploads],
                         [("1", "clip.mp4", "video/mp4"), ("3", "notes.txt", "text/plain"),
                          ("4", "notes.md", "text/markdown"), ("6", "report.zip", "application/x-zip-compressed"),
                          ("8", "drawing.svg", "image/svg+xml"), ("9", "README", "application/octet-stream"),
                          ("10", "Voice.OGG", "audio/ogg")])
        self.assertEqual(len(self.cdn.requests), 7, "no fetch of a file that is too large")

    def test_a_file_that_cannot_be_fetched_or_not_in_time_is_missed(self):
        """A fetch that fails, an address off Discord's CDN, and a fetch that takes longer than its limit in all
        (FILE_FETCH_TIMEOUT, also when each read is quick: one slow file holds every account's messages) are
        `download`, and each message goes on without its file."""
        limit = patch.object(channels, "FILE_FETCH_TIMEOUT", 0.5)
        limit.start()
        self.addCleanup(limit.stop)
        self.ready()
        gone = self.attachment("61", "gone.png", None)
        off = self.attachment("62", "off.png", b"\x89PNG\r\n\x1a\n")
        off["url"] = off["url"].replace("127.0.0.1", "localhost")      # the stand-in, by a name that is not the CDN's
        slow = self.attachment("63", "slow.png", b"\x89PNG\r\n\x1a\n" + b"s" * 192, how="slow")    # 10 s in all
        peer = self.gw.latest()
        for mid, a in ((1661, gone), (1662, off), (1663, slow)):
            peer.dispatch("MESSAGE_CREATE", dm(mid, "", attachments=[a]))
        self.wait_for(lambda: len(self.hub.inbound) == 3, "three messages, the slow file's after its limit, not after "
                                                           "its 10 seconds", timeout=8)
        self.assertEqual([e.get("missed") for e in self.hub.inbound], [["download"]] * 3)
        self.assertEqual((self.hub.uploads, self.cdn.fetched()),
                         ([], ["/attachments/700/61/gone.png", "/attachments/700/63/slow.png"]))

    def test_the_limit_of_a_fetch_holds_before_its_body_too(self):
        """FILE_FETCH_TIMEOUT is the fetch's time in all, before the body too: a name lookup that takes longer (the
        system's has no limit of its own) is `download` in about that time, and so is an answer whose head comes after
        it, whatever length the head gives, also when each line of the head comes quickly: a read's timeout is for
        that read, so a head that came a line at a time held the fetch until http.client's limit of 100 lines (about
        5 s here)."""
        limit = patch.object(channels, "FILE_FETCH_TIMEOUT", 0.5)
        limit.start()
        self.addCleanup(limit.stop)
        real = socket.getaddrinfo

        def lookup(host, *args, **kwargs):          # the CDN stand-in, by a name whose lookup takes 3 s
            if host == "slow-name.test":
                time.sleep(3)
                host = "127.0.0.1"
            return real(host, *args, **kwargs)
        prefix = "http://slow-name.test:%d/" % self.cdn.server.server_address[1]
        for change in (patch.object(socket, "getaddrinfo", lookup),
                       patch.object(channels, "DISCORD_FILES", (self.cdn.url + "/", prefix))):
            change.start()
            self.addCleanup(change.stop)
        self.ready()
        named = self.attachment("81", "named.png", b"\x89PNG\r\n\x1a\n")
        named["url"] = named["url"].replace(self.cdn.url + "/", prefix)
        head = self.attachment("82", "head.png", b"\x89PNG\r\n\x1a\n", how="slow-head")
        peer, at = self.gw.latest(), time.monotonic()
        peer.dispatch("MESSAGE_CREATE", dm(1681, "", attachments=[named]))
        self.wait_for(lambda: self.hub.inbound, "the message whose file's name was not found in time", timeout=8)
        self.assertLess(time.monotonic() - at, 2, "the lookup's 3 seconds held the message")
        at = time.monotonic()
        peer.dispatch("MESSAGE_CREATE", dm(1682, "", attachments=[head]))
        self.wait_for(lambda: len(self.hub.inbound) == 2, "the message whose answer's head came late", timeout=8)
        self.assertLess(time.monotonic() - at, 2, "the head's slow lines held the message")
        self.assertEqual([e.get("missed") for e in self.hub.inbound], [["download"], ["download"]])
        self.assertEqual(self.hub.uploads, [])

    def test_a_file_whose_bytes_pass_25_mib_is_size(self):
        """The bridge reads at most 25 MiB and one byte of a file, also from an answer that gives no length, so that a
        file larger than Discord said is `size` and never fills the hub machine's memory; a file of 25 MiB exactly
        goes up."""
        self.ready()
        whole = b"%PDF-" + b"w" * (channels.FILE_MOST - 5)
        peer = self.gw.latest()
        peer.dispatch("MESSAGE_CREATE", dm(1671, "", attachments=[       # 96 MiB, with no length in the answer
            self.attachment("71", "big.pdf", b"%PDF-" + b"b" * ((1 << 20) - 5), "application/pdf", size=1000,
                            how="stream")]))
        peer.dispatch("MESSAGE_CREATE", dm(1672, "", attachments=[
            self.attachment("72", "whole.pdf", whole, "application/pdf", how="no-length")]))
        self.wait_for(lambda: len(self.hub.inbound) == 2, "both messages", timeout=20)
        self.assertEqual([e.get("missed") for e in self.hub.inbound], [["size"], None])
        self.assertEqual([(f["message"], data == whole) for f, data, _ in self.hub.uploads], [("1672", True)])
        with self.cdn.lock:
            self.assertLess(self.cdn.sent["/attachments/700/71/big.pdf"], 64, "the bridge read the file to its end")

    def test_the_hubs_refusals_give_their_codes_and_cost_no_fetch(self):
        """The hub's answers (the interface of version 2): to its question, a 409 (no such account), a 403 (a sender
        whose files it does not take, as a stranger's) or any other answer but its 200 (a 404 of a hub of an older
        release) makes each file of the message `refused` with no fetch, and the message's own post settles the rest;
        to an upload, 413 is `size`, and 415 (bytes that are not of their type, now that any type goes up), 403, 422
        and 400 are `refused`, and a 403 is the answer for the message's other files too, with no fetch. No refusal of
        a file holds its message back."""
        self.ready()
        png = b"\x89PNG\r\n\x1a\n"
        self.hub.forced = [(409, {"error": "unknown chat app account"})]
        self.hub.check_answers = [(409, {"error": "unknown chat app account"}),
                                  (403, {"code": "not_welcome", "error": "not taken"})] + [None] * 5 + \
            [(404, {"error": "no such route"})]
        self.hub.upload_answers = [(415, {"error": "the bytes are not of the type that the request names"}),
                                   (422, {"error": "a registered login", "code": "login_as_file"}),
                                   (403, {"code": "not_welcome"}), (413, {"error": "an attachment is at most 25 MiB"}),
                                   (400, {"error": "a bad field"})]
        peer = self.gw.latest()
        peer.dispatch("MESSAGE_CREATE", dm(1631, "", attachments=[self.attachment("31", "a.png", png),
                                                                  self.attachment("32", "b.png", png)]))
        peer.dispatch("MESSAGE_CREATE", dm(1632, "", author="999000111",
                                           attachments=[self.attachment("33", "c.png", png)]))
        for mid in range(1633, 1638):
            second = [self.attachment(f"{mid}b", "e.png", png)] if mid == 1635 else []     # after the upload's 403
            peer.dispatch("MESSAGE_CREATE", dm(mid, "", attachments=[self.attachment(str(mid), "d.png", png)] + second))
        peer.dispatch("MESSAGE_CREATE", dm(1638, "", attachments=[self.attachment("1638", "f.png", png)]))
        self.wait_for(lambda: len(self.hub.posted) == 8 and not self.journal_files(), "eight messages", timeout=10)
        self.assertEqual([e.get("missed") for e in self.hub.posted], [["refused", "refused"], ["refused"], ["refused"],
                                                                      ["refused"], ["refused", "refused"], ["size"],
                                                                      ["refused"], ["refused"]])
        self.assertEqual(len(self.hub.uploads), 5)
        self.assertEqual(self.cdn.fetched(), [f"/attachments/700/{mid}/d.png" for mid in range(1633, 1638)],
                         "no fetch of a file that the hub does not take")
        self.assertEqual([e["id"] for e in self.hub.inbound], [str(mid) for mid in range(1632, 1639)])

    def test_an_attempt_after_no_answer_sends_only_what_did_not_come_up(self):
        """No change of the journal (the interface of version 2), and no download for nothing: a 503 to the hub's
        question keeps the message; a file that the hub took does not go again, though its address ended meanwhile;
        the bytes of a file whose upload got no answer go again with no new fetch, after the hub's yes to that
        attempt's question (files_up): no bytes go to a hub that is away; the message goes after its files, and
        nothing of it stays in the bridge's memory once it left the journal."""
        self.ready()
        first, second = b"\x89PNG\r\n\x1a\n first", b"\x89PNG\r\n\x1a\n second"
        self.hub.check_answers = [(503, {"error": "hub error"})]
        self.hub.upload_answers = [None, (503, {"error": "hub error"})]
        self.hub.forced = [(503, {"error": "hub error"})]
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(1641, "", attachments=[
            self.attachment("41", "first.png", first, how="once"),
            self.attachment("42", "second.png", second, how="once")]))
        self.wait_for(lambda: self.hub.inbound and not self.journal_files(), "the message after four attempts")
        self.assertEqual([(f["n"], data) for f, data, _ in self.hub.uploads],
                         [("1", first), ("2", second), ("2", second)])
        self.assertEqual(self.cdn.fetched(), ["/attachments/700/41/first.png", "/attachments/700/42/second.png"])
        self.assertEqual(self.order(), ["/bridge/files?check"] * 2 + ["/bridge/files"] * 2 +
                         ["/bridge/files?check", "/bridge/files"] + ["/bridge/inbound"] * 2)
        self.assertEqual([e.get("missed") for e in self.hub.posted], [None, None])
        self.assertEqual((self.bridge.files_seen, self.bridge.file_held), ({}, None))
        self.assertIn("inbound discord-studio 1641: the hub did not take file 2 (503); kept", self.log.getvalue())

    def test_a_file_that_the_hub_does_not_take_holds_its_message_three_attempts_at_most(self):
        """No message's files hold the journal for ever: uploads that the hub answers with a 5xx keep their message for
        FILE_TRIES attempts in all, whatever its number of files, the first file's bytes fetched once; then the files
        that are left are `refused` with no fetch and no upload, and the message goes on. A count for each file kept a
        message of ten files for about seven times as many attempts, with a download of each file at each."""
        self.ready()
        pngs = [b"\x89PNG\r\n\x1a\n never taken " + bytes([n]) for n in range(3)]
        self.hub.upload_answers = [(503, {"error": "hub error"})] * channels.FILE_TRIES
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(1643, "", attachments=[
            self.attachment(f"4{n}", f"never{n}.png", png) for n, png in enumerate(pngs)]))
        self.wait_for(lambda: self.hub.inbound and not self.journal_files(), "the message after its third attempt")
        self.assertEqual((self.hub.inbound[0].get("missed"), len(self.hub.posted)), (["refused"] * 3, 1))
        self.assertEqual([data for _, data, _ in self.hub.uploads], [pngs[0]] * 3)
        self.assertEqual(len(self.cdn.requests), 1)
        # the same when the hub, up, gives its question no answer (a stuck files route): each attempt asks once more,
        # and counts; a wait with no count, as for a hub that is away, held the journal of every account for ever. An
        # upload that timed out is not sent again: its bytes would only wait as long again
        asked, real = [], self.bridge.hub.upload

        def upload(path, data, timeout=None):
            if "check=1" in path and "message=1644" in path:
                asked.append(path)
                return 0, {"error": "ConnectionResetError"}
            if "check=1" not in path and "message=1647" in path:
                asked.append(path)                      # a stuck upload route: each upload times out
                return 0, {"error": "TimeoutError"}
            return real(path, data, timeout)
        patched = patch.object(self.bridge.hub, "upload", upload)
        patched.start()
        self.addCleanup(patched.stop)
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(1644, "", attachments=[
            self.attachment("44", "stuck.png", b"\x89PNG\r\n\x1a\n stuck")]))
        self.wait_for(lambda: len(self.hub.inbound) == 2 and not self.journal_files(), "the second message")
        self.assertEqual((self.hub.inbound[1].get("missed"), len(asked), len(self.cdn.requests)),
                         (["refused"], 2 * channels.FILE_TRIES, 1))
        self.assertEqual(self.log.getvalue().count("inbound discord-studio 1644: the hub did not say whether it takes "
                                                   "the files (ConnectionResetError); kept"), channels.FILE_TRIES - 1)
        self.assertNotIn("1644: the hub answers nothing", self.log.getvalue())
        # a question that times out while the hub answers nothing at all (it holds its socket, as a restart in place
        # or a hung process does) counts no try either: the read after it finds the hub away, and its files go once
        # it answers again
        frozen, real_call = {"left": 2 * channels.FILE_TRIES + 1}, self.bridge.hub.call

        def upload_frozen(path, data, timeout=None):
            if "check=1" in path and "message=1648" in path and frozen["left"]:
                return 0, {"error": "TimeoutError"}
            return upload(path, data, timeout)

        def call(method, path, data=None, timeout=30):
            if (method, path) == ("GET", "/bridge/config") and frozen["left"]:
                frozen["left"] -= 1
                if frozen["left"]:
                    return 0, {"error": "TimeoutError"}
                # the hub comes back while this read waits: it answers, and the question goes once more
            return real_call(method, path, data, timeout)
        for name, stand_in in (("upload", upload_frozen), ("call", call)):
            patched = patch.object(self.bridge.hub, name, stand_in)
            patched.start()
            self.addCleanup(patched.stop)
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(1648, "", attachments=[
            self.attachment("48", "frozen.png", b"\x89PNG\r\n\x1a\n frozen")]))
        self.wait_for(lambda: len(self.hub.inbound) == 3 and not self.journal_files(), "the message after the freeze")
        self.assertEqual(self.hub.inbound[2].get("missed"), None)
        self.assertNotIn("1648: the hub did not say whether", self.log.getvalue())
        asked.clear()
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(1647, "", attachments=[
            self.attachment("47", "slow.png", b"\x89PNG\r\n\x1a\n slow")]))
        self.wait_for(lambda: len(self.hub.inbound) == 4 and not self.journal_files(), "the fourth message")
        self.assertEqual((self.hub.inbound[3].get("missed"), len(asked)), (["refused"], channels.FILE_TRIES))

    def test_a_file_whose_upload_takes_the_hub_away_each_time_is_given_up(self):
        """No message's files hold the journal, whose later entries wait behind it, for ever: an upload that the hub had
        just said yes to, after which it answers nothing at all, counts, for the whole entry, and after FILE_DOWN_MOST
        of them that file and the ones after it are `refused` and their bytes never go again, so that the message goes
        on and its files stop the hub that many times at most. An upload that never reached the hub (a refused
        connection, an unreachable network) counts nothing. Before, the held bytes went at each attempt and could stop
        the hub each time."""
        self.ready()
        uploads, real_call = [], self.bridge.hub.call

        def upload(path, data, timeout=None):
            if "check=1" in path:
                return 200, {"welcome": True}
            uploads.append(data)
            if len(uploads) <= 2:                       # the upload never reached the hub
                return 0, {"error": "URLError", "cause": "ConnectionRefusedError" if len(uploads) == 1 else "OSError"}
            return 0, {"error": "RemoteDisconnected"}   # it went down during the upload

        def call(method, path, data=None, timeout=30):
            if (method, path) == ("GET", "/bridge/config"):
                return 0, {"error": "URLError"}         # and answers nothing just after it
            return real_call(method, path, data, timeout)
        for name, stand_in in (("upload", upload), ("call", call)):
            patched = patch.object(self.bridge.hub, name, stand_in)
            patched.start()
            self.addCleanup(patched.stop)
        pngs = [b"\x89PNG\r\n\x1a\n down at each upload " + bytes([n]) for n in range(2)]
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(1646, "", attachments=[
            self.attachment(f"6{n}", f"down{n}.png", png) for n, png in enumerate(pngs)]))
        self.wait_for(lambda: self.hub.inbound and not self.journal_files(), "the message without its files")
        self.assertEqual((self.hub.inbound[0].get("missed"), len(self.cdn.requests)), (["refused"] * 2, 1))
        self.assertEqual(uploads, [pngs[0]] * (2 + channels.FILE_DOWN_MOST))
        self.assertIn(f"1646: file 1 refused (the hub went away at {channels.FILE_DOWN_MOST} uploads of the message's "
                      f"files)", self.log.getvalue())

    def test_a_file_that_went_up_goes_again_after_half_the_hubs_hour(self):
        """The hub keeps a file that no message took for an hour (hub.ATTACH_WAIT): a message that still waits
        FILE_UP_FOR after its file went up sends it again, which renews that hour, so that the file is there when the
        message comes."""
        bound = patch.object(channels, "FILE_UP_FOR", 0)
        bound.start()
        self.addCleanup(bound.stop)
        self.ready()
        png = b"\x89PNG\r\n\x1a\n kept"
        self.hub.forced = [(503, {"error": "hub error"})]
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(1645, "", attachments=[self.attachment("45", "kept.png", png)]))
        self.wait_for(lambda: self.hub.inbound and not self.journal_files(), "the message after its second attempt")
        self.assertEqual([data for _, data, _ in self.hub.uploads], [png, png])
        self.assertEqual(len(self.cdn.requests), 2)

    def test_a_name_or_an_id_that_no_query_can_hold_stops_no_message(self):
        """A lone half of a surrogate pair, which Discord's JSON can hold: in a file's name it goes out of the name, and
        in another value of the query the file is `refused`. Before, it raised out of the journal's loop, which then
        stopped for every account, again at each start."""
        self.ready()
        png, half = b"\x89PNG\r\n\x1a\n", chr(0xD83D)
        self.private.append("and the next message")
        a = self.attachment("91", "a.png", png)
        a["filename"] = "a" + half + ".png"
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(1691, "", attachments=[a]))
        self.wait_for(lambda: self.hub.inbound, "the message whose file's name holds half a pair")
        b = self.attachment("92", "b.png", png)
        channels.Journal(self.journal).write({
            "account": "discord-studio", "id": "1692", "chat": "700", "group": False, "sender": OWNER + half,
            "sender_alt": None, "sender_name": "miguel", "bot": False, "from_me": False, "kind": "image", "text": "",
            "ts": 1.0, "media": [{"url": b["url"], "name": "b.png", "mime": "image/png", "size": len(png)}]})
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(1693, "and the next message"))
        self.wait_for(lambda: len(self.hub.inbound) == 3, "the other two messages")
        self.assertEqual([(e["id"], e.get("missed")) for e in self.hub.inbound],
                         [("1691", None), ("1692", ["refused"]), ("1693", None)])
        self.assertEqual([f["name"] for f, _, _ in self.hub.uploads], ["a.png"])

    def test_a_file_that_a_restart_left_waits_for_its_account(self):
        """At a start the journal replays before the bridge has read its accounts: a file of such a message waits for
        its account, and is not missed."""
        png = b"\x89PNG\r\n\x1a\n left by a restart"
        a = self.attachment("51", "left.png", png)
        channels.Journal(self.journal).write({
            "account": "discord-studio", "id": "1651", "chat": "700", "group": False, "sender": OWNER,
            "sender_alt": None, "sender_name": "miguel", "bot": False, "from_me": False, "kind": "image", "text": "",
            "ts": 1.0, "media": [{"url": a["url"], "name": "left.png", "mime": "image/png", "size": len(png)}]})
        self.hub.config_fails = 3
        self.ready()
        event = self.wait_for(lambda: self.hub.inbound, "the message")[0]
        self.assertEqual((event["id"], event.get("missed")), ("1651", None))
        self.assertEqual([data for _, data, _ in self.hub.uploads], [png])
        self.assertIn("inbound discord-studio 1651: the bridge does not run its account yet; kept", self.log.getvalue())

    def test_fragmented_frames_and_a_ping_between_them(self):
        self.ready()
        self.private.append("in three fragments k2")
        peer = self.gw.latest()
        peer.dispatch("MESSAGE_CREATE", dm(1105, "in three fragments k2"), fragmented=True)
        self.wait_for(lambda: self.hub.inbound, "the message")
        self.assertEqual(self.hub.inbound[0]["text"], "in three fragments k2")
        self.wait_for(lambda: peer.pongs == [b"hi"], "the pong")

    def test_hub_down_then_up_loses_nothing(self):
        """Neither a message nor its file (a release restarts the hub): while the hub answers nothing, its attempts
        count no try (files_up's away), and the hub that comes back gets both messages and the file, fetched once."""
        self.ready()
        self.private += ["while the hub is down 1", "while the hub is down 2"]
        png = b"\x89PNG\r\n\x1a\n while the hub is down"
        self.hub.down()
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(1301, "while the hub is down 1",
                                                       attachments=[self.attachment("13", "down.png", png)]))
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(1302, "while the hub is down 2"))
        self.wait_for(lambda: len(self.journal_files()) == 2, "two events in the journal")
        for name in self.journal_files():
            self.assertEqual(os.stat(os.path.join(self.journal, name)).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.journal).st_mode & 0o777, 0o700)
        time.sleep(0.6)                 # twice FILE_TRIES attempts and more, with the tests' backoff
        self.hub.up()
        self.wait_for(lambda: len(self.hub.inbound) == 2, "both events at the hub")
        self.assertEqual([(e["id"], e.get("missed")) for e in self.hub.inbound], [("1301", None), ("1302", None)])
        self.assertEqual(([data for _, data, _ in self.hub.uploads], len(self.cdn.requests)), ([png], 1))
        self.wait_for(lambda: not self.journal_files(), "an empty journal")

    def test_a_hub_that_is_down_costs_no_download(self):
        """The bridge asks the hub at each attempt before it fetches a file (check=1): while the hub is down, no file of
        the chat app is fetched, also past FILE_TRIES, and a hub that comes back gets each file, fetched once. Before,
        each attempt past the question's tries fetched the message's files again (up to 250 MB a minute for ten).

        Here the hub comes back right after a question that got no answer, before the message's post, five times
        FILE_TRIES attempts on: an attempt in which the hub answers nothing at all counts for no try, however many there
        are (a question has no body, so no question takes the hub away), and the attempt in which it comes back asks
        once more and counts none either. Counted, a whole-module run under load once had the hub take the message
        without them."""
        self.ready()
        pngs = [b"\x89PNG\r\n\x1a\n down " + bytes([n]) for n in range(2)]
        asked, back, real = [], [], self.bridge.hub.upload

        def upload(path, data, timeout=None):
            if "check=1" in path and not back:          # the hub is down: no answer
                asked.append(len(self.cdn.requests))
                if len(asked) == 5 * channels.FILE_TRIES:
                    self.hub.up()                       # back, right after this question
                    back.append(True)
                return 0, {"error": "URLError"}
            return real(path, data, timeout)
        patched = patch.object(self.bridge.hub, "upload", upload)
        patched.start()
        self.addCleanup(patched.stop)
        self.hub.down()
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(1303, "", attachments=[
            self.attachment(f"3{n}", f"down{n}.png", png) for n, png in enumerate(pngs)]))
        self.wait_for(lambda: self.hub.inbound and not self.journal_files(), "the message once the hub is back")
        self.assertEqual(set(asked), {0})               # no download while the hub was down
        self.assertEqual((self.hub.inbound[0].get("missed"), len(self.cdn.requests)), (None, 2))
        self.assertNotIn("1303: the hub did not say whether", self.log.getvalue())         # no try counted
        self.assertIn("1303: the hub answers nothing", self.log.getvalue())
        # and right after a read of /bridge/config that got no answer, before the message's post: the attempt in which
        # the hub is away waits, however many there were, so no post goes without the files
        probes, real_call = {"after": False, "n": 0}, self.bridge.hub.call

        def upload_after(path, data, timeout=None):
            code, answer = real(path, data, timeout)
            if "check=1" in path and "message=1305" in path and code == 0:
                probes["after"] = True                  # the next read of /bridge/config is files_up's
            return code, answer

        def call(method, path, data=None, timeout=30):
            if (method, path) == ("GET", "/bridge/config") and probes["after"]:
                probes["after"] = False
                probes["n"] += 1
                if probes["n"] == 5 * channels.FILE_TRIES:
                    self.hub.up()                       # back, right after this read
                return 0, {"error": "URLError"}
            return real_call(method, path, data, timeout)
        for name, stand_in in (("upload", upload_after), ("call", call)):
            patched = patch.object(self.bridge.hub, name, stand_in)
            patched.start()
            self.addCleanup(patched.stop)
        self.hub.down()
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(1305, "", attachments=[
            self.attachment("35", "down-again.png", b"\x89PNG\r\n\x1a\n down again")]))
        self.wait_for(lambda: len(self.hub.inbound) == 2 and not self.journal_files(), "the second message")
        self.assertEqual((self.hub.inbound[1].get("missed"), probes["n"]), (None, 5 * channels.FILE_TRIES))
        self.assertNotIn("1305: the hub did not say whether", self.log.getvalue())

    def test_an_upload_that_a_restart_cuts_goes_again_when_the_hub_is_back(self):
        """The hub says yes to the question and goes down during the upload (a restart): the file waits with its bytes,
        and each later attempt asks the question first, so that the hub's being away costs no try and its bytes go
        only to a hub that said yes again. The hub comes back right after a question that got no answer; the file goes
        up, fetched once, and the message is not posted without it."""
        self.ready()
        png = b"\x89PNG\r\n\x1a\n cut by a restart"
        state, real = {"cut": False, "asked": 0, "back": False}, self.bridge.hub.upload

        def upload(path, data, timeout=None):
            if "check=1" not in path and not state["cut"]:      # its first upload: the hub goes down during it
                state["cut"] = True
                self.hub.down()
                return 0, {"error": "RemoteDisconnected"}
            if "check=1" in path and state["cut"] and not state["back"]:
                state["asked"] += 1
                if state["asked"] == 2 * channels.FILE_TRIES + 1:
                    self.hub.up()                       # back, right after this question
                    state["back"] = True
                    return 0, {"error": "URLError"}
            return real(path, data, timeout)
        patched = patch.object(self.bridge.hub, "upload", upload)
        patched.start()
        self.addCleanup(patched.stop)
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(1304, "", attachments=[
            self.attachment("34", "cut.png", png)]))
        self.wait_for(lambda: self.hub.inbound and not self.journal_files(), "the message once the hub is back")
        self.assertEqual((self.hub.inbound[0].get("missed"), len(self.cdn.requests)), (None, 1))
        self.assertEqual([data for _, data, _ in self.hub.uploads], [png])
        log = self.log.getvalue()
        self.assertEqual(log.count("1304: the hub answers nothing after file 1 (RemoteDisconnected); kept"), 1)
        self.assertNotIn("1304: the hub did not", log)                       # no try counted

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

    def test_the_files_of_a_message_go_with_its_last_part_in_one_multipart_request(self):
        """CHAT-APPS.md 20: Discord takes a message's files in the request of its last part, with the same nonce rule:
        a retry of that request makes no second message."""
        self.ready()
        pdf, png = b"%PDF-1.4 invoice", b"\x89PNG\r\n\x1a\n chart"
        files = []
        for n, (name, mime, data) in enumerate((("Invoice-October.pdf", "application/pdf", pdf),
                                               ("chart.png", "image/png", png)), 1):
            self.hub.files[(450 + n, "45")] = data
            files.append({"id": 450 + n, "name": name, "mime": mime, "size": len(data),
                          "sha256": hashlib.sha256(data).hexdigest()})
        self.rest.script = [None, "create-then-drop"]       # the second part's answer is lost once
        waits, real = [], channels.DiscordREST.call         # how long each message request may take

        def call(rest, method, path, body=None, timeout=20, files=None):
            if method == "POST" and path.endswith("/messages"):
                waits.append((bool(files), timeout))
            return real(rest, method, path, body, timeout=timeout, files=files)
        spy = patch.object(channels.DiscordREST, "call", call)
        spy.start()
        self.addCleanup(spy.stop)
        self.hub.queue({"id": 45, "kind": "message", "account": "discord-studio", "chat": "700",
                        "text": "A" * 1500 + "\n\n" + "B" * 600, "reply_to": "1104", "prefix": None, "files": files})
        result = self.result(45)
        self.assertEqual(waits, [(False, 20), (True, 120), (True, 120)])    # the request with files: 120 s
        bodies = [body for _, body, _ in self.rest.created]
        self.assertEqual([b["nonce"] for b in bodies], ["f45p1", "f45p2"])
        self.assertNotIn("_files", bodies[0])
        self.assertEqual(bodies[1]["attachments"], [{"id": 0, "filename": "Invoice-October.pdf"},
                                                    {"id": 1, "filename": "chart.png"}])
        self.assertEqual(bodies[1]["_files"], [("files[0]", "Invoice-October.pdf", "application/pdf", pdf),
                                               ("files[1]", "chart.png", "image/png", png)])
        self.assertEqual([r[3]["nonce"] for r in self.rest.posts()], ["f45p1", "f45p2", "f45p2"])
        self.assertEqual(result, {"state": "sent", "parts": 2, "platform_ids": [i for _, _, i in self.rest.created],
                                  "error": None})
        self.assertEqual(os.listdir(os.path.join(self.folder, "outbox")), [])

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

    def file_item(self, item_id, text, *files):
        """A message item with files, and the bytes that the fake hub serves for each one."""
        described = []
        for n, (name, mime, data) in enumerate(files, 1):
            fid = item_id * 10 + n
            self.hub.files[(fid, str(item_id))] = data
            described.append({"id": fid, "name": name, "mime": mime, "size": len(data),
                              "sha256": hashlib.sha256(data).hexdigest()})
        return {"id": item_id, "kind": "message", "account": "whatsapp-main", "chat": WA_CHAT, "text": text,
                "reply_to": "WAMSG1", "prefix": None, "files": described}

    def test_a_message_with_files_goes_as_one_bubble_or_as_its_parts_and_then_its_files(self):
        """CHAT-APPS.md 20: the bridge reads each file from the hub, held to the item's size and hash, writes it into
        the outbox beside the sessions, and gives wa-link its path; the file is gone when the send ends."""
        self.linked()
        pdf, sheet = b"%PDF-1.4 invoice", b"PK\x03\x04 a sheet"
        self.private.append("Invoice-October.pdf")
        self.hub.queue(self.file_item(51, "Here is the invoice.", ("Invoice-October.pdf", "application/pdf", pdf)))
        result = self.result(51)
        sends = self.commands("send")
        ids = ["3EB0" + hashlib.sha256(f"testdb:51:{n}".encode()).hexdigest()[:16].upper() for n in (1,)]
        self.assertEqual(len(sends), 1)
        self.assertEqual((sends[0]["id"], sends[0]["text"], sends[0]["reply_to"], sends[0]["file"]["name"],
                          sends[0]["file"]["mime"], sends[0]["file_sha256"], sends[0]["file_mode"], sends[0]["outbox"]),
                         (ids[0], "Here is the invoice.", "WAMSG1", "Invoice-October.pdf", "application/pdf",
                          hashlib.sha256(pdf).hexdigest(), "0o600", True))
        self.assertEqual(result, {"state": "sent", "parts": 1, "platform_ids": ids, "error": None})
        self.assertIn(51, self.hub.begun)           # the bridge said when it began the item, before its result
        outbox = os.path.join(self.folder, "outbox")
        self.assertEqual((stat.S_IMODE(os.stat(outbox).st_mode), os.listdir(outbox)), (0o700, []))
        # a longer text goes in its own parts first, and each file follows with no caption
        self.hub.queue(self.file_item(52, "y" * 1500, ("a.pdf", "application/pdf", pdf),
                                      ("b.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                       sheet)))
        result = self.result(52)
        sends = self.commands("send")[1:]
        self.assertEqual([(s["text"][:3], (s.get("file") or {}).get("name")) for s in sends],
                         [("yyy", None), ("", "a.pdf"), ("", "b.xlsx")])
        self.assertEqual([s["reply_to"] for s in sends], ["WAMSG1", None, None])
        self.assertEqual(result["parts"], 3)
        # a file that wa-link does not take stops the message there; the parts before it are sent
        self.hub.queue(self.file_item(53, "z" * 1500, ("REFUSE.pdf", "application/pdf", pdf)))
        self.assertEqual(self.result(53), {"state": "failed", "parts": 1,
                                           "platform_ids": ["3EB0" + hashlib.sha256(b"testdb:53:1").hexdigest()[:16].upper()],
                                           "error": "refused by the stand-in"})
        # bytes that are not the item's file: nothing goes to wa-link
        item = self.file_item(54, "x", ("c.pdf", "application/pdf", pdf))
        self.hub.files[(541, "54")] = b"other bytes"
        self.hub.queue(item)
        self.assertEqual(self.result(54), {"state": "failed", "parts": 0, "platform_ids": [],
                                           "error": "The bridge could not read file 1 of this message from the hub (200)."})
        item = self.file_item(55, "x", ("d.pdf", "application/pdf", pdf))
        del self.hub.files[(551, "55")]
        self.hub.queue(item)
        self.assertEqual(self.result(55)["error"], "The bridge could not read file 1 of this message from the hub (404).")
        self.assertEqual(len(self.commands("send")), 6)     # 1 + 3 + 2: no send for items 54 and 55
        self.assertEqual(os.listdir(outbox), [])

    def test_an_older_wa_link_gets_no_file_and_the_bridge_asks_the_hub_for_files(self):
        """The first review, 15 November 2026: a wa-link of an older source (its build failed, or FLEET_WA_LINK names
        one) ignores a send's file and sends the caption alone. Only a wa-link that says "file" in its hello gets one;
        and the bridge asks the hub for items with files (files=1), which the hub keeps back from an older bridge."""
        with patch.dict(os.environ, {"WA_STUB_OLD": "1"}):
            self.linked()
            self.hub.queue(self.file_item(56, "Here.", ("a.pdf", "application/pdf", b"%PDF-1.4 x")))
            self.assertEqual(self.result(56), {"state": "failed", "parts": 0, "platform_ids": [],
                                               "error": "The wa-link on the hub machine is too old to send files."})
        self.assertEqual(self.commands("send"), [])
        self.assertTrue(all("files=1" in q for q in self.hub.out_queries), self.hub.out_queries)

    def test_an_adapter_that_sends_no_file_fails_a_message_with_files(self):
        """The third review: an adapter that does not say it sends files (a third app's, until it does) fails such a
        message, and never sends its words alone with the report "sent"."""
        with patch.object(channels.WhatsApp, "sends_files", False):
            self.linked()
            self.hub.queue(self.file_item(57, "Here.", ("a.pdf", "application/pdf", b"%PDF-1.4 x")))
            self.assertEqual(self.result(57), {"state": "failed", "parts": 0, "platform_ids": [],
                                               "error": "The bridge sends no file to WhatsApp yet."})
        self.assertEqual(self.commands("send"), [])

    def test_the_bridge_empties_the_outbox_and_the_inbox_that_a_stop_left(self):
        """A file stays in either folder only while its message is on its way: what a stop left goes at the start."""
        outbox, inbox = os.path.join(self.folder, "outbox"), os.path.join(self.folder, "inbox")
        for folder in (outbox, inbox):
            os.makedirs(folder)
            with open(os.path.join(folder, "9-1"), "wb") as f:
                f.write(b"left from a stop")
        self.start()
        self.assertEqual((os.listdir(outbox), os.listdir(inbox)), ([], []))
        self.assertEqual(stat.S_IMODE(os.stat(inbox).st_mode), 0o700)

    # the media of a person's or the owner's message (CHAT-APPS.md 8.1)

    def wa_media(self, part, kind, mime, size, name=""):
        """A media description as wa-link's message event gives it; the stand-in downloads media/<part>. Its direct
        path and its key are what no log line may hold."""
        key = base64.b64encode(bytes([1]) * 32).decode()
        path = f"/v/t62.7118-24/{part}?ccb=11-4&oh=01_Q5AaIX&oe=6812ABCD"
        self.private += [path, key]
        return {"kind": kind, "mime": mime, "size": size, "name": name, "direct_path": path, "media_key": key,
                "file_sha256": base64.b64encode(bytes([2]) * 32).decode(),
                "file_enc_sha256": base64.b64encode(bytes([3]) * 32).decode()}

    def message(self, mid, kind, text="", spec=None, **extra):
        """A message event of wa-link from WA_CHAT, with its media."""
        event = {"ev": "message", "id": mid, "chat": WA_CHAT, "sender": WA_CHAT, "sender_alt": "123@lid",
                 "push_name": "Alex", "group": False, "from_me": False, "kind": kind, "text": text,
                 "ts": 1792134000.5}
        if spec:
            event["media"] = spec
        event.update(extra)
        return event

    def calls_in_order(self):
        with self.hub.lock:
            return [path for _, path in self.hub.calls if path in ("/bridge/files?check", "/bridge/files",
                                                                    "/bridge/inbound")]

    def test_a_picture_with_words_a_voice_note_a_document_and_a_video_go_up_before_their_messages(self):
        """The owner, 20 November 2026: "pictures and files sohuld be allowed!". A WhatsApp message brings one file:
        the bridge asks the hub first (check=1), and only after its yes asks wa-link to download the media into the
        inbox beside the sessions (its own description back, with the time that is left), uploads the bytes with the
        name and type that the rules give, and then posts the message with no `media`. The direct path and the keys
        stay on the hub machine, and no log line names the file or holds its words."""
        self.linked()
        jpeg, ogg = b"\xff\xd8\xff\xe0 a screenshot", b"OggS\x00\x02 a voice note"
        pdf, mp4 = b"%PDF-1.4 an invoice", b"\x00\x00\x00\x18ftypmp42 a video"
        for part, data in (("pic.enc", jpeg), ("voice.enc", ogg), ("doc.enc", pdf), ("clip.enc", mp4)):
            self.wa.media(part, data)
        specs = [self.wa_media("pic.enc", "image", "image/jpeg", len(jpeg)),
                 self.wa_media("voice.enc", "voice", "audio/ogg; codecs=opus", len(ogg)),
                 self.wa_media("doc.enc", "document", "application/pdf", len(pdf), "Invoice-October.pdf"),
                 self.wa_media("clip.enc", "video", "video/mp4", len(mp4))]
        kinds = ("image", "audio", "file", "other")
        words = ("What does this error say? wa21", "", "Here is the invoice wa23", "Look at this wa24")
        self.private += [w for w in words if w] + ["Invoice-October.pdf"]
        for n, (kind, text, spec) in enumerate(zip(kinds, words, specs), 1):
            self.inject(self.message(f"WAPIC{n}", kind, text, spec))
        self.wait_for(lambda: len(self.hub.inbound) == 4 and not self.journal_files(), "the four messages")
        fields = {"account": "whatsapp-main", "n": "1", "sender": WA_CHAT, "sender_alt": "123@lid"}
        want = [(dict(fields, message="WAPIC1", name="photo.jpg", mime="image/jpeg"), jpeg),
                (dict(fields, message="WAPIC2", name="voice.ogg", mime="audio/ogg"), ogg),
                (dict(fields, message="WAPIC3", name="Invoice-October.pdf", mime="application/pdf"), pdf),
                (dict(fields, message="WAPIC4", name="video.mp4", mime="video/mp4"), mp4)]
        self.assertEqual([(f, data) for f, data, _ in self.hub.uploads], want)
        self.assertEqual([f for f, _, _ in self.hub.checks], [f for f, _ in want])
        self.assertEqual(self.calls_in_order(), ["/bridge/files?check", "/bridge/files", "/bridge/inbound"] * 4)
        self.assertEqual([(e["id"], e["kind"], e["text"]) for e in self.hub.inbound],
                         [(f"WAPIC{n}", k, t) for n, (k, t) in enumerate(zip(kinds, words), 1)])
        self.assertEqual([sorted(set(e) & {"media", "media_more", "missed"}) for e in self.hub.posted], [[]] * 4)
        downloads = self.commands("download")
        self.assertEqual([d["media"] for d in downloads], specs, "wa-link gets its own description back")
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{32}", d["id"]) and 0 < d["seconds"] <= 60 for d in downloads))
        self.assertEqual(os.listdir(os.path.join(self.folder, "inbox")), [])
        self.assertEqual((self.bridge.files_seen, self.bridge.file_held), ({}, None))

    def test_a_groups_an_own_and_a_strangers_media_is_never_downloaded(self):
        """The rule of the design: no byte of a sender whose message the hub would not store is fetched. A group's
        message and the number's own bring no `media` into the journal, so the hub is not even asked, and a stranger's
        gets the hub's 403 to its question: wa-link downloads nothing. Each message still goes on."""
        self.linked()
        self.wa.media("pic.enc", b"\xff\xd8\xff")
        spec = self.wa_media("pic.enc", "image", "image/jpeg", 3)
        self.hub.check_answers = [(403, {"code": "not_welcome", "error": "not taken"})]
        stranger = "34600000777@s.whatsapp.net"
        self.inject(self.message("WAGRP1", "image", "", spec, group=True, chat="120363000000000000@g.us"))
        self.inject(self.message("WAMINE1", "image", "", spec, from_me=True))
        self.inject(self.message("WASTR1", "image", "", spec, chat=stranger, sender=stranger, sender_alt=None))
        self.wait_for(lambda: len(self.hub.posted) == 3 and not self.journal_files(), "the three messages")
        self.assertEqual([(e["id"], e.get("missed")) for e in self.hub.posted],
                         [("WAGRP1", None), ("WAMINE1", None), ("WASTR1", ["refused"])])
        self.assertEqual([f["message"] for f, _, _ in self.hub.checks], ["WASTR1"])
        self.assertEqual((self.commands("download"), self.hub.uploads), ([], []))

    def an_older_wa_link_misses(self, env):
        """A message with a picture to a wa-link of an older source, which ignores the download command."""
        with patch.dict(os.environ, env):
            self.linked()
            self.wa.media("pic.enc", b"\xff\xd8\xff")
            at = time.monotonic()
            self.inject(self.message("WAOLD1", "image", "", self.wa_media("pic.enc", "image", "image/jpeg", 3)))
            event = self.wait_for(lambda: self.hub.inbound, "the message")[0]
        self.assertEqual(event.get("missed"), ["download"])
        self.assertLess(time.monotonic() - at, 3, "a wa-link that cannot download held the message")
        self.assertEqual((self.commands("download"), self.hub.uploads), ([], []))

    def test_a_wa_link_whose_hello_lacks_download_gets_no_command(self):
        """A wa-link of an older source runs when a build of this one fails: its hello says "file" and not
        "download", so each file of its messages is `download` at once, with no command and no wait."""
        self.an_older_wa_link_misses({"WA_STUB_NO_DOWNLOAD": "1"})

    def test_a_wa_link_that_says_no_hello_gets_no_command(self):
        """A wa-link from before hello: its first line is a state, and it gets no download command either."""
        self.an_older_wa_link_misses({"WA_STUB_OLD": "1"})

    def test_a_download_that_fails_is_too_large_or_late_is_missed_and_leaves_no_file(self):
        """wa-link's answers: a failure is `download`, a file above 25 MiB `size`; a size above 25 MiB that the
        message gives is `size` with no question and no download; no answer in the file's time is `download`, and a
        file that wa-link wrote after it goes. The bridge logs none of wa-link's words, which can hold an address."""
        limits = patch.multiple(channels, FILE_FETCH_TIMEOUT=0.5, WA_ANSWER_SLACK=0.2)
        limits.start()
        self.addCleanup(limits.stop)
        self.linked()
        self.wa.media("slow", b"\xff\xd8\xff late")
        self.private += ["STUB-WORDS", "mmg.whatsapp.net"]
        for mid, part, size in (("WAF1", "fail", 10), ("WAF2", "large", 10), ("WAF3", "big", channels.FILE_MOST + 1),
                                ("WAF4", "silent", 10), ("WAF5", "slow", 10)):
            self.inject(self.message(mid, "image", "", self.wa_media(part, "image", "image/jpeg", size)))
        self.wait_for(lambda: len(self.hub.inbound) == 5, "five messages", timeout=10)
        self.assertEqual([e.get("missed") for e in self.hub.inbound],
                         [["download"], ["size"], ["size"], ["download"], ["download"]])
        self.assertEqual([f["message"] for f, _, _ in self.hub.checks], ["WAF1", "WAF2", "WAF4", "WAF5"])
        self.assertEqual((len(self.commands("download")), self.hub.uploads), (4, []))
        late = self.commands("download")[-1]["id"]
        self.wait_for(lambda: [c for c in self.commands("wrote") if c["id"] == late], "the late file", timeout=5)
        inbox = os.path.join(self.folder, "inbox")
        self.wait_for(lambda: not os.listdir(inbox), "an inbox without the late file")

    def test_a_file_that_a_restart_left_waits_for_wa_link_to_link(self):
        """At a start the journal replays before wa-link said its first line and before the number is linked: the
        file waits for both, in its time, and is not missed."""
        jpeg = b"\xff\xd8\xff\xe0 left by a restart"
        self.wa.media("left.enc", jpeg)
        spec = self.wa_media("left.enc", "image", "image/jpeg", len(jpeg))
        event = self.message("WALEFT1", "image", "", spec)
        del event["ev"], event["push_name"], event["media"]
        channels.Journal(self.journal).write(dict(event, account="whatsapp-main", sender_name="Alex", bot=False,
                                                  media=[{"wa": spec, "name": "photo.jpg", "mime": "image/jpeg",
                                                          "size": len(jpeg)}]))
        with patch.dict(os.environ, {"WA_STUB_LINK_DELAY": "0.5"}):
            self.link_db()
            self.start()
            got = self.wait_for(lambda: self.hub.inbound, "the message")[0]
        self.assertEqual((got["id"], got.get("missed")), ("WALEFT1", None))
        self.assertEqual([data for _, data, _ in self.hub.uploads], [jpeg])

    def test_a_wa_link_that_stops_during_a_download_gets_one_more_try(self):
        """A wa-link that stops in the middle of a download starts again: the file gets one more try in its time."""
        self.linked()
        jpeg = b"\xff\xd8\xff\xe0 after a crash"
        self.wa.media("crash-once", jpeg)
        self.inject(self.message("WACRASH1", "image", "", self.wa_media("crash-once", "image", "image/jpeg", 9)))
        got = self.wait_for(lambda: self.hub.inbound, "the message", timeout=10)[0]
        self.assertEqual((got.get("missed"), [data for _, data, _ in self.hub.uploads]), (None, [jpeg]))
        self.assertEqual(len(self.commands("download")), 2)

    def test_a_wa_link_that_does_not_link_holds_the_journal_once_and_not_for_each_file(self):
        """A number that does not link (WhatsApp is down for it, or its wa-link is still being built): the first file
        waits WA_READY_GRACE since the number was last linked, and each file after it is `download` at once, so the
        messages behind them wait once and not a minute for each file."""
        grace = patch.object(channels, "WA_READY_GRACE", 0.5)
        grace.start()
        self.addCleanup(grace.stop)
        with patch.dict(os.environ, {"WA_STUB_LINK_DELAY": "30"}):
            self.link_db()
            self.start()
            self.wait_for(lambda: self.commands("start"), "wa-link")
            self.wa.media("pic.enc", b"\xff\xd8\xff")
            at = time.monotonic()
            for mid in ("WAWAIT1", "WAWAIT2", "WAWAIT3"):
                self.inject(self.message(mid, "image", "", self.wa_media("pic.enc", "image", "image/jpeg", 3)))
            self.wait_for(lambda: len(self.hub.inbound) == 3, "the three messages", timeout=10)
        self.assertLess(time.monotonic() - at, 4, "each file waited for the link")
        self.assertEqual([e.get("missed") for e in self.hub.inbound], [["download"]] * 3)
        self.assertEqual(self.commands("download"), [])

    def test_a_file_that_wa_link_writes_after_the_bridge_stopped_waiting_goes_when_it_stops(self):
        """A download that ends after the bridge stopped waiting for it, by a wa-link that then stops before it
        answers: its file goes when wa-link stops, and does not wait in the inbox for the bridge's next start."""
        limits = patch.multiple(channels, FILE_FETCH_TIMEOUT=0.5, WA_ANSWER_SLACK=0.2)
        limits.start()
        self.addCleanup(limits.stop)
        self.linked()
        self.wa.media("slow-crash", b"\xff\xd8\xff written late")
        self.inject(self.message("WALATE1", "image", "", self.wa_media("slow-crash", "image", "image/jpeg", 20)))
        got = self.wait_for(lambda: self.hub.inbound, "the message")[0]
        self.assertEqual(got.get("missed"), ["download"])
        rid = self.commands("download")[0]["id"]
        self.wait_for(lambda: [c for c in self.commands("wrote") if c["id"] == rid], "the late file", timeout=5)
        inbox = os.path.join(self.folder, "inbox")
        self.wait_for(lambda: not os.listdir(inbox), "an inbox without the late file")

    def test_wa_links_words_reach_the_hub_with_no_address(self):
        """A wa-link of an older source (it runs when a build fails) put the URL of a media request into an upload's
        error, with the media connection's auth: the bridge passes no web address of wa-link's words to the hub, which
        shows them in the owner's apps, neither a send's error nor a state's."""
        self.linked()
        self.private.append("AUTH-VALUE")
        self.hub.queue({"id": 45, "kind": "message", "account": "whatsapp-main", "chat": WA_CHAT, "text": "URLERR",
                        "reply_to": None, "prefix": None})
        self.assertEqual(self.result(45), {"state": "failed", "parts": 0, "platform_ids": [],
                                           "error": 'not sent: Post "<address> EOF'})
        self.inject({"ev": "state", "state": "error", "jid": WA_JID,
                     "error": "connect failure 403 https://www.whatsapp.com/x?token=AUTH-VALUE"})
        state = self.wait_for(lambda: [s for s in self.states("whatsapp-main") if s["state"] == "error"], "the error")
        link = self.wait_for(lambda: [k for k in self.hub.links if k["state"] == "error"], "the link's error")
        self.assertEqual((state[-1]["error"], link[-1]["error"]), ("connect failure 403 <address>",) * 2)

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

    # CHAT-APPS.md 18.4: a number that left the fleet takes its phone's link and its session with it.

    def session(self, aid="whatsapp-main"):
        return os.path.join(self.folder, aid + ".db")

    def stops(self):
        return self.log.getvalue().count("account whatsapp-main: stopped")

    def test_a_number_that_left_the_fleet_is_logged_out_and_its_session_goes(self):
        self.linked()
        self.hub.config.update(accounts=[], removed=["whatsapp-main"], version="v2")
        self.wait_for(lambda: self.commands("logout"), "wa-link's logout")
        self.wait_for(self.stops, "the stop")
        self.wait_for(lambda: not os.path.exists(self.session()), "the session file gone")
        self.assertIn("whatsapp whatsapp-main: the phone's link ended", self.log.getvalue())
        self.assertEqual(len(self.commands("start")), 1, "nothing starts it again")

    def test_a_number_that_is_turned_off_or_that_a_configuration_only_does_not_name_keeps_its_session(self):
        self.linked()
        self.hub.config.update(accounts=[dict(WHATSAPP, enabled=False)], version="v2")
        self.wait_for(self.stops, "the stop of a number that is turned off")
        self.assertTrue(os.path.exists(self.session()))
        self.hub.config.update(accounts=[WHATSAPP], version="v3")
        self.wait_for(lambda: len(self.commands("start")) == 2, "wa-link of the number that is on again")
        # No word of the hub that it left the fleet (an older hub, or a fault): the bridge only stops it.
        self.hub.config.update(accounts=[], version="v4")
        self.wait_for(lambda: self.stops() == 2, "the second stop")
        self.assertTrue(os.path.exists(self.session()))
        self.assertEqual(self.commands("logout"), [])

    def test_a_number_removed_and_added_again_between_two_readings_starts_with_no_session(self):
        self.linked()
        self.hub.config.update(accounts=[dict(WHATSAPP, removed=1700000000.5)], version="v2")
        self.wait_for(lambda: self.commands("logout"), "the logout of the number that was removed")
        self.wait_for(lambda: len(self.commands("start")) == 2, "wa-link of the new account")
        self.wait_for(lambda: self.has_state("whatsapp-main", "logged_out"), "the new account has no phone")
        self.assertFalse(os.path.exists(self.session()))
        # The same time at the next reading is the same account: it runs on.
        reads = self.config_reads()
        self.hub.config.update(version="v3")
        self.wait_for(lambda: self.config_reads() > reads, "one more reading of the configuration")
        self.assertEqual((len(self.commands("start")), len(self.commands("logout")), self.stops()), (2, 1, 1))

    def test_a_session_of_a_number_that_left_while_no_bridge_ran_goes_at_the_first_reading(self):
        for name in ("whatsapp-old.db", "whatsapp-old.db-wal", "whatsapp-kept.db"):
            open(os.path.join(self.folder, name), "w").close()
        outside = os.path.join(self.tmp.name, "outside.db")
        open(outside, "w").close()
        self.hub.config["removed"] = ["whatsapp-old", "../outside", 7, "whatsapp-main"]
        self.linked()               # it is in the accounts, so the hub's list cannot remove it
        self.wait_for(lambda: not os.path.exists(self.session("whatsapp-old")), "the old session gone")
        self.assertFalse(os.path.exists(self.session("whatsapp-old") + "-wal"))
        self.assertTrue(os.path.exists(self.session("whatsapp-kept")), "the hub said nothing of this one")
        self.assertTrue(os.path.exists(outside), "an ID is never a path")
        self.assertTrue(os.path.exists(self.session()))
        self.assertEqual(self.commands("logout"), [])

    def mark(self, text=None):
        """The mark beside the number's session: written with `text`, or read."""
        path = self.session() + channels.STORE_MARK
        if text is None:
            with open(path) as f:
                return f.read().strip()
        with open(path, "w") as f:
            f.write(text + "\n")

    def test_a_number_removed_and_added_again_while_no_bridge_ran_starts_with_no_session(self):
        self.link_db()
        self.mark("null")                       # the session was made before any account of this ID left
        self.hub.config["accounts"] = [dict(WHATSAPP, removed=1700000000.5)]
        self.start()
        self.wait_for(lambda: self.has_state("whatsapp-main", "logged_out"), "the new number has no phone")
        self.assertFalse(os.path.exists(self.session()))
        self.assertEqual((self.mark(), self.commands("logout")), ("1700000000.5", []))
        self.assertIn("the session of the number that left the fleet is removed", self.log.getvalue())

    def test_a_session_whose_mark_agrees_or_that_has_none_stays(self):
        self.link_db()                          # a session from before the marks: it is this account's
        self.hub.config["accounts"] = [dict(WHATSAPP, removed=1700000000.5)]
        self.start()
        self.wait_for(lambda: self.has_state("whatsapp-main", "connected"), "the linked state")
        self.assertTrue(os.path.exists(self.session()))
        self.assertEqual(self.mark(), "1700000000.5")
        # Turned off and on again: the mark agrees now, and the session stays.
        self.hub.config.update(accounts=[dict(WHATSAPP, removed=1700000000.5, enabled=False)], version="v2")
        self.wait_for(self.stops, "the stop")
        self.hub.config.update(accounts=[dict(WHATSAPP, removed=1700000000.5)], version="v3")
        self.wait_for(lambda: len(self.commands("start")) == 2, "wa-link started again")
        self.assertTrue(os.path.exists(self.session()))
        self.assertEqual(self.commands("logout"), [])

    def keeps(self, told):
        """A session of the time 1700000000.5 with what the hub tells now: it stays. Then a later time is the hub's
        word, and the account counted from its session's time."""
        self.link_db()
        self.mark("1700000000.5")
        self.hub.config["accounts"] = [dict(WHATSAPP) if told is None else dict(WHATSAPP, removed=told)]
        self.start()
        self.wait_for(lambda: self.has_state("whatsapp-main", "connected"), "the linked state")
        self.assertTrue(os.path.exists(self.session()))
        self.assertEqual((self.mark(), self.commands("logout")), ("1700000000.5", []))
        self.hub.config.update(accounts=[dict(WHATSAPP, removed=1800000000.25)], version="v2")
        self.wait_for(lambda: self.commands("logout"), "the logout at a later time")
        self.wait_for(lambda: len(self.commands("start")) == 2, "wa-link of the new account")
        self.wait_for(lambda: self.has_state("whatsapp-main", "logged_out"), "the new account has no phone")
        self.assertEqual(self.mark(), "1800000000.25")

    def test_no_time_from_the_hub_deletes_no_session(self):
        """A hub of the release before this rule names no time."""
        self.keeps(None)

    def test_an_earlier_time_from_the_hub_deletes_no_session(self):
        """A hub from a backup can name an earlier time than the session's."""
        self.keeps(1600000000.0)

    def test_a_mark_that_is_no_time_keeps_the_session_and_is_written_again(self):
        self.link_db()
        self.mark("not a time")
        self.hub.config["accounts"] = [dict(WHATSAPP, removed=1700000000.5)]
        self.start()
        self.wait_for(lambda: self.has_state("whatsapp-main", "connected"), "the linked state")
        self.assertTrue(os.path.exists(self.session()))
        self.assertEqual((self.mark(), self.commands("logout")), ("1700000000.5", []))

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
        self.assertEqual(self.hub.bridge_code, channels.own_code(), "each status report carries the bridge's code")
        self.hub.queue({"id": 91, "kind": "message", "account": "whatsapp-main", "chat": WA_CHAT, "text": "x",
                        "reply_to": None, "prefix": None})
        self.assertEqual(self.result(91)["error"], "WhatsApp is not linked.")

    def building(self, build):
        """The bridge builds wa-link into this test's folder with build in place of build_wa_link."""
        program = os.path.join(self.tmp.name, "bin", "wa-link")
        for change in (patch.object(channels, "build_wa_link", build), patch.object(channels, "WA_PROGRAM", program),
                       patch.dict(channels._wa_build, failed=None), patch.dict(os.environ)):
            change.start()
            self.addCleanup(change.stop)
        return os.environ.pop("FLEET_WA_LINK")

    def test_a_link_request_waits_for_the_build_and_gets_its_qr_code(self):
        release, calls = threading.Event(), []

        def build(source, program, want, fetch=None, run=None):
            calls.append(want)
            release.wait(5)
            os.makedirs(os.path.dirname(program), exist_ok=True)
            shutil.copy(stub, program)
            with open(program + ".source", "w") as f:
                f.write(want + "\n")
        stub = self.building(build)
        self.start()
        self.wait_for(lambda: calls, "the build")
        self.wait_for(lambda: self.has_state("whatsapp-main", "connecting"), "connecting while it builds")
        self.hub.queue({"id": 72, "kind": "link", "account": "whatsapp-main"})
        self.wait_for(lambda: "out 72: link for whatsapp-main" in self.log.getvalue(), "the link item at the bridge")
        release.set()
        self.wait_for(lambda: len(self.hub.links) >= 2, "two link reports")
        waiting, linked = self.hub.links[:2]
        self.assertEqual((waiting["state"], waiting["qr"]), ("waiting", "QR-CODE-1"),
                         "the logged_out of wa-link's start is not the answer to the request")
        self.assertEqual(linked["state"], "linked")
        self.assertEqual(calls, [channels.wa_link_source()])
        self.assertEqual(len(self.commands("pair")), 1)

    def test_a_build_that_fails_answers_the_link_request(self):
        calls = []

        def build(source, program, want, fetch=None, run=None):
            calls.append(want)
            raise channels.BuildFailed("the download of Go 1.27.3 failed (URLError)")
        self.building(build)
        reason = "wa-link could not be built on the hub machine: the download of Go 1.27.3 failed (URLError)."
        self.start()
        self.assertEqual(self.wait_for(lambda: self.has_state("whatsapp-main", "error"), "the error")[-1]["error"], reason)
        time.sleep(0.3)         # several tries to start wa-link, at the test's short backoff
        self.assertEqual(len(calls), 1, "a failed build is not tried again at once by itself")
        self.hub.queue({"id": 73, "kind": "link", "account": "whatsapp-main"})
        link = self.wait_for(lambda: self.hub.links, "the link report")[0]
        self.assertEqual((link["state"], link["error"]), ("error", reason))
        self.assertEqual(len(calls), 2, "a link request tries the build again at once")


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
        for text in (TOKEN, "How is the scrape going? rh1", "On it, rh2", "LINK-CODE", "What does this error say? rh3",
                     "screenshot.png", "/attachments/700/", "What does this error say? rh5", "/v/t62.7118-24/"):
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

    def test_the_owners_picture_reaches_the_agent_through_the_real_hub(self):
        """The design of 20 November 2026 (version 2), end to end: the owner sends a PNG in a Discord DM; the bridge
        asks the real hub, fetches the file from the CDN stand-in and uploads it, and the agent's event names A-<id>,
        whose bytes on the hub are the PNG's. So the two sides agree on the route, its fields and its answers."""
        wait_for(self, lambda: self.accounts()["discord-studio"]["state"] == "connected", "Discord connected")
        code, data = self.owner_post("/ui/people/codes", purpose="owner", app="discord")
        self.assertEqual(code, 200, data)
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(2101, f"link {data['code']}"))
        wait_for(self, lambda: self.rest.created, "the link reply")
        cdn = CDN()
        self.addCleanup(cdn.shutdown)
        files = patch.object(channels, "DISCORD_FILES", (cdn.url + "/",))
        files.start()
        self.addCleanup(files.stop)
        png = b"\x89PNG\r\n\x1a\n" + bytes(range(64))
        url = cdn.add("/attachments/700/21/screenshot.png", png)
        self.gw.latest().dispatch("MESSAGE_CREATE", dm(2102, "What does this error say? rh3", attachments=[
            {"id": "21", "filename": "screenshot.png", "content_type": "image/png", "size": len(png), "url": url}]))
        req = wait_for(self, lambda: fleet_hub.q1("SELECT * FROM ui_requests WHERE client=? AND origin LIKE ?",
                                                  ("fleet-channels/1/discord-studio", '%"2102"%')),
                       "the owner's message at the hub")
        text, error = fleet_hub.call_tool("studio", "read_messages", {}, CHAT_CONTEXT)
        self.assertFalse(error, text)
        self.assertIn("What does this error say? rh3", text)
        aid = int(re.search(r"A-(\d+) screenshot\.png \(image/png", text).group(1))
        row = fleet_hub.q1("SELECT * FROM attachments WHERE id=?", (aid,))
        self.assertEqual((fleet_hub.attachment_bytes(row), row["message"]), (png, req["request_id"]))
        self.assertEqual([path.partition("?")[0] for path, _, _ in cdn.requests],
                         ["/attachments/700/21/screenshot.png"])

    def test_a_whatsapp_picture_reaches_the_agent_and_a_strangers_is_never_fetched(self):
        """CHAT-APPS.md 8.1 against the real hub: the owner's WhatsApp picture with words goes up after the hub's yes
        to the bridge's question, and the agent's event names it as A-<id>, whose bytes on the hub are the picture's;
        a stranger's picture gets the hub's no, and wa-link downloads nothing of it."""
        wait_for(self, lambda: self.accounts()["whatsapp-main"]["state"] == "connected", "WhatsApp connected")
        fleet_hub.q("INSERT INTO owner_handles(app,id,alias,name,linked) VALUES('whatsapp',?,NULL,'owner',?)",
                    (WA_CHAT, fleet_hub.now()))
        jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + bytes(range(64))
        with open(os.path.join(self.wa.folder, "media", "rh.enc"), "wb") as f:
            f.write(jpeg)
        spec = {"kind": "image", "mime": "image/jpeg", "size": len(jpeg), "name": "",
                "direct_path": "/v/t62.7118-24/rh.enc?ccb=11-4", "media_key": base64.b64encode(bytes(32)).decode(),
                "file_sha256": base64.b64encode(bytes(32)).decode(),
                "file_enc_sha256": base64.b64encode(bytes(32)).decode()}
        # WhatsApp's own shape: the sender by its hidden ID, the owner's handle by the phone number, its other ID
        for mid, sender, alt in (("WARH1", "123456789012345@lid", WA_CHAT),
                                 ("WARH2", "987654321098765@lid", "34600000777@s.whatsapp.net")):
            self.wa.inject({"ev": "message", "id": mid, "chat": sender, "sender": sender, "sender_alt": alt,
                            "push_name": "Alex", "group": False, "from_me": False, "kind": "image",
                            "text": "What does this error say? rh5", "ts": time.time(), "media": spec})
        req = wait_for(self, lambda: fleet_hub.q1("SELECT * FROM ui_requests WHERE client=? AND origin LIKE ?",
                                                  ("fleet-channels/1/whatsapp-main", '%"WARH1"%')),
                       "the owner's message at the hub")
        wait_for(self, lambda: fleet_hub.q1("SELECT 1 FROM chat_in WHERE account='whatsapp-main' AND msg_id='WARH2'"),
                 "the stranger's message at the hub")
        text, error = fleet_hub.call_tool("manager", "read_messages", {}, CHAT_CONTEXT)
        self.assertFalse(error, text)
        self.assertIn("What does this error say? rh5", text)
        aid = int(re.search(r"A-(\d+) photo\.jpg \(image/jpeg", text).group(1))
        row = fleet_hub.q1("SELECT * FROM attachments WHERE id=?", (aid,))
        self.assertEqual((fleet_hub.attachment_bytes(row), row["message"]), (jpeg, req["request_id"]))
        self.assertEqual(len(self.wa.commands("download")), 1, "a download of the stranger's picture")
        self.assertEqual(fleet_hub.q1("SELECT COUNT(*) AS n FROM attachments WHERE client=?",
                                      ("fleet-channels/1/whatsapp-main",))["n"], 1)

    def test_an_agents_file_goes_through_the_hubs_queue_and_the_bridge(self):
        """CHAT-APPS.md 20, the done-when of the owner's yes of 15 November 2026: the manager sends a PDF up with
        attach_file's line, names it in message_owner, and the bridge reads its bytes from the real hub and gives them
        to the wa-link stand-in with the words as its caption; the hub records the delivery and the owner's apps read
        the file under the report."""
        wait_for(self, lambda: self.accounts()["whatsapp-main"]["state"] == "connected", "WhatsApp connected")
        fleet_hub.q("INSERT INTO owner_handles(app,id,alias,name,linked) VALUES('whatsapp',?,NULL,'owner',?)",
                    (WA_CHAT, fleet_hub.now()))
        text, error = fleet_hub.call_tool("manager", "attach_file", {"name": "Invoice-October.pdf"}, None)
        self.assertFalse(error, text)
        token = re.search(r'/attachment/file/([A-Za-z0-9_-]+)"', text).group(1)
        pdf = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n%%EOF\n"
        req = urllib.request.Request(self.base + f"/attachment/file/{token}", data=pdf, method="POST",
                                     headers={"X-Test-Source": "127.0.0.1"})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=10) as r:
            aid = int(re.match(r"A-(\d+) ", r.read().decode()).group(1))
        text, error = fleet_hub.call_tool("manager", "message_owner", {"request_id": str(uuid.uuid4()),
                                                                       "text": "Here is the invoice.",
                                                                       "files": [f"A-{aid}"]}, None)
        self.assertFalse(error, text)
        send = wait_for(self, lambda: [c for c in self.wa.commands("send") if c.get("file")], "the file at wa-link")[0]
        item = fleet_hub.q1("SELECT * FROM chat_out WHERE kind='message' ORDER BY id DESC LIMIT 1")
        self.assertEqual((send["id"], send["to"], send["text"], send["file"]["name"], send["file"]["mime"],
                          send["file_sha256"], send["outbox"]),
                         (channels.wa_message_id("test-generation", item["id"], 1), WA_CHAT, "Here is the invoice.",
                          "Invoice-October.pdf", "application/pdf", hashlib.sha256(pdf).hexdigest(), True))
        report = wait_for(self, lambda: (self.owner("/ui/state")[1]["reports"][-1]["delivery"] or {}).get("state")
                          == "sent" and self.owner("/ui/state")[1]["reports"][-1], "the sent delivery")
        self.assertEqual([f["id"] for f in report["attachments"]], [aid])
        self.assertEqual(fleet_hub.q1("SELECT parts FROM chat_out WHERE id=?", (item["id"],))["parts"], 1)
        self.assertEqual(os.listdir(os.path.join(self.folder, "outbox")), [])


# ---------------------------------------------------------------- functions

class Functions(unittest.TestCase):
    def test_a_files_type_is_the_apps_own_or_its_names(self):
        """CHAT-APPS.md 8.1: a file's type is its chat app's own, unless that is none, no type token, or the generic
        application/octet-stream: then its name's extension's, from the hub's table, then the bridge's own table of
        media, which is the same on every Python (3.12 names no type for .ogg), then Python's; else
        application/octet-stream. A wrong type keeps the hub from checking a PDF or a Markdown file as one."""
        for mime, name, want in (("Image/PNG; q=1", "x", "image/png"), ("application/octet-stream", "notes.md",
                                 "text/markdown"), ("application/octet-stream", "report.pdf", "application/pdf"),
                                 (None, "voice.ogg", "audio/ogg"), (None, "sticker.tgs", "application/x-tgsticker"),
                                 ("not a type", "blob", "application/octet-stream")):
            self.assertEqual(channels.file_type(mime, name), want, (mime, name))

    def test_a_family_that_the_kernel_refuses_is_one_address_that_fails(self):
        """A file's fetch tries each address of the host: when the lookup gives an IPv6 address first on a server
        whose kernel has IPv6 off, socket.socket raises, and the IPv4 address after it still connects, as
        socket.create_connection did. A socket made outside the try ended the loop at the first address."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        addresses = [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("2001:db8::1", port, 0, 0)),
                     (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", port))]
        real = socket.socket

        def make(family=socket.AF_INET, *args, **kwargs):
            if family == socket.AF_INET6:
                raise OSError(97, "Address family not supported by protocol")
            return real(family, *args, **kwargs)
        with patch.object(channels, "lookup", lambda host, port, end: addresses), \
                patch.object(channels.socket, "socket", make):
            sock = channels.connect_by(time.monotonic() + 5)(("files.example", port))
        self.addCleanup(sock.close)
        self.assertEqual(sock.getpeername(), ("127.0.0.1", port))
        with patch.object(channels, "lookup", lambda host, port, end: addresses[:1]), \
                patch.object(channels.socket, "socket", make):
            with self.assertRaises(channels.Missed) as missed:
                channels.connect_by(time.monotonic() + 5)(("files.example", port))
        self.assertEqual((missed.exception.code, missed.exception.why), ("download", "OSError"))

    def test_the_tls_handshake_gets_only_the_time_that_is_left(self):
        """download()'s limit is its time in all: a connect that is slow but succeeds leaves the TLS handshake only the
        rest of that time. With each address's socket kept at the time that was left before its connect, a slow
        connect and a peer that never answers TLS took almost two times the limit (3.5 s for 2 s)."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        # a TCP peer that never speaks TLS
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        port = listener.getsockname()[1]
        real = socket.socket

        class Slow(real):                   # a connect that takes 1.5 s, as a far server's SYN-ACK can
            def connect(self, where):
                time.sleep(1.5)
                return super().connect(where)
        at = time.monotonic()
        with patch.object(channels.socket, "socket", Slow), self.assertRaises(channels.Missed) as missed:
            channels.download(f"https://127.0.0.1:{port}/f", 2)
        took = time.monotonic() - at
        self.assertEqual(missed.exception.code, "download")
        self.assertLess(took, 2.75, f"the fetch took {took:.2f} s for a limit of 2 s")

    def test_a_body_with_no_length_that_the_watch_ends_is_no_whole_file(self):
        """With no length, the end of the connection ends the answer, and the watch's shutdown at the fetch's limit
        looks the same to http.client: the bytes that came until then are `download`, never a whole file. Each read's
        own timeout is made longer here, so that the watch, and not the read, ends this fetch."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        done = threading.Event()
        self.addCleanup(done.set)

        def serve():                        # a part of a file, then nothing more and no end, for 10 s
            peer, _ = listener.accept()
            with peer:
                peer.recv(65536)
                peer.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: image/png\r\n\r\n\x89PNG part")
                done.wait(10)
        threading.Thread(target=serve, daemon=True).start()
        real = socket.socket.settimeout

        def later(sock, seconds):
            return real(sock, None if seconds is None else seconds + 3)
        at = time.monotonic()
        with patch.object(socket.socket, "settimeout", later), self.assertRaises(channels.Missed) as missed:
            channels.download(f"http://127.0.0.1:{port}/f", 1)
        self.assertEqual((missed.exception.code, missed.exception.why), ("download", "not done in 1 s"))
        self.assertLess(time.monotonic() - at, 2.5, "the watch came late")    # each read's own end is at 4 s

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

    def test_a_file_with_no_type_takes_the_hubs_own_type_of_its_extension(self):
        """A file whose chat app gives no valid type is of its name's extension, the hub's own types first: the bridge's
        table is the hub's (ATTACH_TYPES and ATTACH_OFFICE), so that the hub checks and reads a Markdown or an Office
        file as one and not as data; and the bridge's limit of a file is the hub's, so that no file is fetched for a
        413 or missed as `size` though the hub takes it."""
        self.assertEqual(channels.FILE_TYPES, {mime: ext for mime, (ext, _) in fleet_hub.ATTACH_TYPES.items()}
                         | fleet_hub.ATTACH_OFFICE)
        self.assertEqual(channels.FILE_MOST, fleet_hub.ATTACH_MAX)

    def test_hub_address_from_team_json(self):
        team = {"hub": {"machine": "hub", "port": 8765}, "addresses": {"hub": "100.1.2.3"}}
        self.assertEqual(channels.hub_url(team), "http://100.1.2.3:8765")
        self.assertEqual(channels.hub_url({"hub": "http://CHANGE-ME:8765"}), "")

    def test_a_change_of_wa_link_source_changes_the_bridge_code(self):
        with tempfile.TemporaryDirectory() as source, patch.object(channels, "WA_SOURCE", source):
            write_files(source, {"go.mod": "module x\n", "main.go": "package main\n"})
            first = channels.own_code()
            write_files(source, {"main_test.go": "package main\n"})
            self.assertEqual(channels.own_code(), first, "a test file is not built")
            write_files(source, {"main.go": "package main\n\nfunc f() {}\n"})
            self.assertNotEqual(channels.own_code(), first)


def write_files(folder, files):
    for name, text in files.items():
        with open(os.path.join(folder, name), "w") as f:
            f.write(text)


# go in the stand-in archive: it writes what it was given to GO_LOG, and a program that exits with EXIT
FAKE_GO = r'''#!/bin/sh
echo "mod=$(head -1 go.mod) GOFLAGS=$GOFLAGS GOPROXY=$GOPROXY CGO_ENABLED=$CGO_ENABLED GOTOOLCHAIN=$GOTOOLCHAIN args=$*" >> GO_LOG
mkdir -p "$GOMODCACHE/m/x" && touch "$GOMODCACHE/m/x/f" && chmod 555 "$GOMODCACHE/m/x" "$GOMODCACHE/m"
FAIL
while [ "$1" != "-o" ]; do shift; done
printf '#!/bin/sh\nexit EXIT\n' > "$2"
chmod 755 "$2"
'''


class WaLinkBuild(unittest.TestCase):
    """wa_link_program builds wa-link with Go's pinned archive: here a stand-in archive whose go writes a program."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.source, self.program = os.path.join(tmp.name, "src"), os.path.join(tmp.name, "bin", "wa-link")
        os.makedirs(self.source)
        write_files(self.source, {"go.mod": "module founderizer/wa-link\n", "go.sum": "", "main.go": "package main\n",
                                  "main_test.go": "package main\n"})
        self.go_log, self.urls, self.log = os.path.join(tmp.name, "go.log"), [], io.StringIO()
        for change in (patch.object(channels, "LOG", self.log), patch.dict(channels._wa_build, failed=None),
                       patch.object(channels, "WA_ROOM", 0), patch.dict(channels.GO_ARCHIVES), patch.dict(os.environ)):
            change.start()
            self.addCleanup(change.stop)
        os.environ.pop("FLEET_WA_LINK", None)
        self.serve()

    def serve(self, fail="", exit_code=1, members=None):
        """The archive that the download gives, with its SHA-256 as the pinned one."""
        script = FAKE_GO.replace("GO_LOG", shlex.quote(self.go_log)).replace("FAIL", fail).replace("EXIT", str(exit_code))
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            for name, data in (members or {"go/bin/go": script.encode()}).items():
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(data), 0o755
                tar.addfile(info, io.BytesIO(data))
        self.archive = buffer.getvalue()
        channels.GO_ARCHIVES[channels.go_platform()] = hashlib.sha256(self.archive).hexdigest()

    def fetch(self, request, timeout):
        self.urls.append(request.full_url)
        return io.BytesIO(self.archive)

    def program_for(self, **options):
        return channels.wa_link_program(fetch=self.fetch, program=self.program, source=self.source, **options)

    def test_it_builds_once_for_each_source(self):
        seen = []
        self.assertEqual(self.program_for(building=lambda: seen.append("building")), self.program)
        self.assertEqual(seen, ["building"])
        self.assertEqual(self.urls, [f"https://go.dev/dl/go{channels.GO_VERSION}.{channels.go_platform()}.tar.gz"])
        self.assertEqual(subprocess.run([self.program]).returncode, 1)
        with open(self.program + ".source") as f:
            self.assertEqual(f.read().strip(), channels.wa_link_source(self.source))
        self.assertEqual(sorted(os.listdir(os.path.dirname(self.program))), ["wa-link", "wa-link.source"],
                         "the toolchain, its read-only module folders and the build cache are gone")
        with open(self.go_log) as f:
            self.assertRegex(f.read(), "^mod=module founderizer/wa-link GOFLAGS=-mod=readonly "
                                       "GOPROXY=https://proxy.golang.org CGO_ENABLED=0 GOTOOLCHAIN=local "
                                       "args=build -p 1 -trimpath -buildvcs=false -o "
                                       + re.escape(os.path.dirname(self.program)) + r"/\.wa-link-build-[^/]+/wa-link \.\n$")
        self.program_for()
        write_files(self.source, {"main_test.go": "package main\n\nfunc g() {}\n"})
        self.program_for()
        self.assertEqual(len(self.urls), 1, "the same source, and a changed test file, build nothing")
        write_files(self.source, {"main.go": "package main\n\nfunc f() {}\n"})
        self.program_for()
        self.assertEqual(len(self.urls), 2, "changed Go code builds again")

    def test_a_failed_build(self):
        right = channels.GO_ARCHIVES[channels.go_platform()]
        channels.GO_ARCHIVES[channels.go_platform()] = "0" * 64
        for force in (False, False, True):
            with self.assertRaisesRegex(channels.BuildFailed, "does not match the SHA-256 that go.dev publishes"):
                self.program_for(force=force)
        self.assertEqual(len(self.urls), 2, "the second try waits for WA_BUILD_RETRY; a forced one does not")
        self.assertFalse(os.path.exists(self.program))
        channels.GO_ARCHIVES[channels.go_platform()] = right
        self.assertEqual(self.program_for(force=True), self.program)

        write_files(self.source, {"main.go": "package main\n\nfunc f() {}\n"})
        self.serve(fail='echo "./main.go:3:1: undefined: x" >&2; exit 2')
        self.assertEqual(self.program_for(force=True), self.program, "the program of the older source runs")
        self.assertIn("go build failed: ./main.go:3:1: undefined: x", self.log.getvalue())
        self.assertNotEqual(open(self.program + ".source").read().strip(), channels.wa_link_source(self.source))
        os.remove(self.program)
        with self.assertRaisesRegex(channels.BuildFailed, "^go build failed: ./main.go:3:1: undefined: x$"):
            self.program_for(force=True)
        self.serve(exit_code=0)
        with self.assertRaisesRegex(channels.BuildFailed, r"the new wa-link does not run \(exit 0\)"):
            self.program_for(force=True)
        self.serve(members={"go/bin/go": b"#!/bin/sh\n", "../outside": b"x"})
        with self.assertRaisesRegex(channels.BuildFailed, "cannot be unpacked"):
            self.program_for(force=True)
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(os.path.dirname(self.program)), "outside")))
        self.assertEqual(os.listdir(os.path.dirname(self.program)), ["wa-link.source"],
                         "no build folder is left, and no program of a failed build")


class WaLinkBuildWithoutFilter(WaLinkBuild):
    """The same build where tarfile has no data filter, as on Debian 12 (Python 3.11.2): go_members holds Go's archive
    to the filter's rules."""

    def setUp(self):
        super().setUp()
        unpack = tarfile.TarFile.extractall

        def without_filter(tar, path=".", members=None, *, numeric_owner=False, **more):
            if more:        # what Python 3.11.2 answers, so that a call with the filter fails here as there
                raise TypeError(f"TarFile.extractall() got an unexpected keyword argument {next(iter(more))!r}")
            return unpack(tar, path, members, numeric_owner=numeric_owner)
        for change in (patch.object(channels, "TAR_FILTER", False), warnings.catch_warnings(),
                       patch.object(tarfile.TarFile, "extractall", without_filter)):
            change.__enter__()
            self.addCleanup(change.__exit__, None, None, None)
        warnings.simplefilter("ignore", DeprecationWarning)     # Python 3.12 and 3.13 ask for a filter

    def test_the_rules_of_the_filter(self):
        def archive(*members):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as tar:
                for name, kind, mode in members:
                    info = tarfile.TarInfo(name)
                    info.type, info.mode = kind, mode
                    if kind == tarfile.SYMTYPE:
                        info.linkname = "/etc"
                    tar.addfile(info, io.BytesIO(b"") if kind == tarfile.REGTYPE else None)
            buffer.seek(0)
            return tarfile.open(fileobj=buffer)

        with archive(("go", tarfile.DIRTYPE, 0o1777), ("go/bin/go", tarfile.REGTYPE, 0o6777)) as tar:
            self.assertEqual([(m.name, m.mode) for m in channels.go_members(tar)],
                             [("go", 0o755), ("go/bin/go", 0o755)])
        for name, kind, why in (("go/lib", tarfile.SYMTYPE, "not a file or a folder"),
                                ("go/lib", tarfile.LNKTYPE, "not a file or a folder"),
                                ("go/null", tarfile.CHRTYPE, "not a file or a folder"),
                                ("go/fifo", tarfile.FIFOTYPE, "not a file or a folder"),
                                ("/go/bin/go", tarfile.REGTYPE, "outside its folder"),
                                ("go/../../go", tarfile.REGTYPE, "outside its folder")):
            with archive(("go", tarfile.DIRTYPE, 0o755), (name, kind, 0o644)) as tar:
                with self.assertRaisesRegex(channels.BuildFailed, f"cannot be unpacked: it holds '{re.escape(name)}', "
                                                                  f"which is {why}$"):
                    channels.go_members(tar)


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for case in (DiscordTests, WhatsAppTests, Functions, WaLinkBuild, WaLinkBuildWithoutFilter):
        suite.addTests(loader.loadTestsFromTestCase(case))
    if hasattr(fleet_hub, "ensure_bridge_key"):     # only RealHub's own tests, not those of OwnerAPI
        suite.addTests(RealHub(name) for name in RealHub.__dict__ if name.startswith("test_"))
    return suite


if __name__ == "__main__":
    unittest.main()
