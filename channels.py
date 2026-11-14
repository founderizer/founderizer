#!/usr/bin/env python3
"""Founderizer chat apps bridge (CHAT-APPS.md 15.11). Python standard library only.

  channels.py run     keep the Discord and WhatsApp connections and carry text between them and the hub
  channels.py unit    print the systemd user unit fleet-channels.service

It runs on the hub machine. It keeps the Discord bot tokens, the inbound journal and one wa-link child process for
each WhatsApp account, and it builds wa-link from the release's own source when it has none for it (wa_link_program).
It decides nothing: the hub keeps every rule. It never logs message text or tokens.
"""
import argparse
import base64
import contextlib
import hashlib
import http.client
import json
import os
import queue
import random
import re
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

KIT = os.path.dirname(os.path.abspath(__file__))
CHAT_DIR = os.path.expanduser("~/.fleet/chat-apps")
GATEWAY = "wss://gateway.discord.gg"
DISCORD_API = "https://discord.com/api/v10"
USER_AGENT = "DiscordBot (https://github.com/founderizer/founderizer, 1)"   # the form that Discord asks for
ACCOUNT_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
SNOWFLAKE = re.compile(r"^[0-9]{1,25}$")
INTENTS = 1 << 12                                   # DIRECT_MESSAGES only
FATAL_CLOSE = {4004, 4010, 4011, 4012, 4013, 4014}  # the account stops with state error
NEW_SESSION_CLOSE = {4007, 4009}                    # the session cannot resume
DISCORD_LIMIT, WHATSAPP_LIMIT, MOST_PARTS = 2000, 4000, 4
REST_NOTE = "The rest is in Founderizer."

# Timings in seconds. The tests make them short.
OUT_WAIT = 25               # the /bridge/out long poll
STATUS_EVERY = 60
TYPING_EVERY = 8
BACKOFF_FIRST, BACKOFF_MAX = 1.0, 60.0
TOKEN_POLL = 5              # how often a Discord account looks for a new token file (16.4: it starts within 15 s)
INVALID_WAIT = (1.0, 5.0)   # Discord: wait this long after INVALID_SESSION
SEND_TRIES = 3              # Discord: tries of one part with the same nonce when no answer comes
WA_SEND_TIMEOUT = 25        # WhatsApp: wait this long for wa-link's "sent" event (4 parts stay under the hub's 120)
WA_STABLE = 60              # a wa-link that ran this long starts its backoff again
WA_LOGOUT_WAIT = 5          # WhatsApp: wait this long for wa-link to end the phone's link of a number that left the fleet
CODE_CHECK = 60             # how often the bridge looks whether a release changed its own code

# wa-link on the hub machine. The bridge builds it itself, so that no hub needs a step by hand: the first time a
# WhatsApp account runs, and again when a release changes wa-link's source or this Go pin. The build takes Go's own
# archive for this system, at a version at least seven days old (the owner's rule for packages) and held to the
# SHA-256 that go.dev publishes, and the modules that go.sum pins, from proxy.golang.org only. It runs at a low
# priority, and it is the first process that the kernel ends when memory runs out, so the hub keeps running. The
# toolchain, the modules and the build cache go after the build: only the program stays, and beside it the SHA-256 of
# what it was built from.
GO_VERSION = "1.27.3"       # Go's release of 19 October 2026
GO_DOWNLOADS = "https://go.dev/dl"
GO_SYSTEMS = {"Linux": "linux", "Darwin": "darwin"}
GO_ARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
GO_ARCHIVES = {             # Go's name for a system: the SHA-256 of go<GO_VERSION>.<name>.tar.gz
    "linux-amd64": "65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40",
    "linux-arm64": "a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49",
    "darwin-amd64": "b6f8e931e4ab497fcde6da8ae4499a58f9d258e55c8a80824a516eae5950a750",
    "darwin-arm64": "dd3908cf20959d798c1e06ebe5b72213f0505ce01373b40ce3110975a6cd99c2",
}
GO_MOST = 128 << 20         # bytes of Go's archive: they are about 70 MB
WA_ROOM = 2 << 30           # bytes free before a build: the toolchain, the modules and the build cache
WA_BUILD_TIMEOUT = 1800     # seconds for the build
WA_BUILD_RETRY = 600        # seconds after a failed build before the next try by itself; a link request tries at once
WA_SOURCE = os.path.join(KIT, "wa-link")
WA_PROGRAM = os.path.expanduser("~/.fleet/bin/wa-link")
# The build's own commands: the kernel's out-of-memory killer takes it first (Linux), and it runs at a low priority.
WA_LOW = '{ [ -w /proc/self/oom_score_adj ] && echo 1000 > /proc/self/oom_score_adj; } 2>/dev/null; exec nice -n 10 "$@"'

LOG = sys.stderr
_log_lock = threading.Lock()


def log(msg):
    """One line to the service log. Callers pass IDs, states and codes only: never message text or a token."""
    with _log_lock:
        print(time.strftime("%Y-%m-%d %H:%M:%S ") + msg, file=LOG, flush=True)


class Backoff:
    def __init__(self):
        self.reset()

    def reset(self):
        self.delay = BACKOFF_FIRST

    def next(self):
        delay = self.delay * random.uniform(0.5, 1.0)
        self.delay = min(self.delay * 2, BACKOFF_MAX)
        return delay


def number(*values, default=1.0):
    """The first value that is a non-negative number."""
    for value in values:
        try:
            n = float(value)
        except (TypeError, ValueError):
            continue
        if n >= 0:
            return n
    return default


def outcome(state, ids, error=None):
    """The body of POST /bridge/out/<id>. `parts` counts the parts that went out."""
    return {"state": state, "parts": len(ids), "platform_ids": list(ids), "error": error[:300] if error else None}


# ---------------------------------------------------------------- formats

def break_at(text, limit):
    """Where a part of at most `limit` characters ends, and where the rest starts: at a paragraph, else at a line,
    else at a space."""
    for sep in ("\n\n", "\n", " "):
        i = text.rfind(sep, 0, limit + 1)
        if i > 0:
            return i, i + len(sep)
    return limit, limit


def split_parts(text, limit, most=MOST_PARTS):
    """At most `most` parts of at most `limit` characters (CHAT-APPS.md 8.4). When the text needs more, the last part
    ends with "The rest is in Founderizer."."""
    parts, rest = [], text
    while len(rest) > limit and len(parts) < most:
        end, start = break_at(rest, limit)
        parts.append(rest[:end].rstrip())
        rest = rest[start:].lstrip("\n")
    if not rest.strip():
        return parts or [text]
    if len(parts) < most:
        return parts + [rest]
    note = "\n\n" + REST_NOTE
    last = parts[-1]
    if len(last) + len(note) > limit:
        last = last[:break_at(last, limit - len(note))[0]].rstrip()
    parts[-1] = last + note
    return parts


def _wa_inline(line):
    line = re.sub(r"\*\*(.+?)\*\*", r"*\1*", line)
    return re.sub(r"\[([^\]\n]+)\]\(([^)\s]+)\)", r"\1 (\2)", line)


def wa_format(text):
    """Markdown to WhatsApp (15.11): **b** to *b*, a heading to a bold line, a table to one line for each row,
    [t](u) to t (u). Code blocks stay as they are."""
    out, code = [], False
    for line in text.split("\n"):
        if line.lstrip().startswith("```"):
            code = not code
            out.append(line)
            continue
        if code:
            out.append(line)
            continue
        heading = re.match(r"^\s{0,3}#{1,6}\s+(.*?)[\s#]*$", line)
        if heading:
            title = _wa_inline(heading.group(1).replace("**", "")).strip()
            out.append(f"*{title}*" if title else "")
            continue
        if re.match(r"^\s*\|.*\|\s*$", line):
            if re.match(r"^\s*\|[\s:|-]*-[\s:|-]*\|\s*$", line):
                continue                                    # the line under the header row
            line = " · ".join(c.strip() for c in line.strip().strip("|").split("|") if c.strip())
        out.append(_wa_inline(line))
    return "\n".join(out)


def wa_message_id(db, item_id, n):
    """The WhatsApp message ID of part n of an outbound item: the same for each try (15.11)."""
    return "3EB0" + hashlib.sha256(f"{db}:{item_id}:{n}".encode()).hexdigest()[:16].upper()


def snowflake_time(message_id):
    try:
        return ((int(message_id) >> 22) + 1420070400000) / 1000
    except (TypeError, ValueError):
        return time.time()


# ---------------------------------------------------------------- HTTP

class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an answer, never a second request: the bridge key and the bot tokens must not go to another place."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)


def request(url, method="GET", data=None, headers=None, timeout=30):
    """(status, headers, parsed JSON or None). Status 0: no answer (refused, reset or timed out)."""
    body = None if data is None else json.dumps(data).encode()
    sent = {"Accept": "application/json", **(headers or {})}
    if body is not None:
        sent["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, method=method, headers=sent)
    try:
        try:
            with OPENER.open(req, timeout=timeout) as r:
                status, got, raw = r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            status, got, raw = e.code, e.headers, e.read()
    except (OSError, http.client.HTTPException, ValueError) as e:
        return 0, {}, {"error": type(e).__name__}
    try:
        return status, got, json.loads(raw) if raw else None
    except ValueError:
        return status, got, None


class Hub:
    """The hub's /bridge/* routes, with the key from bridge.key (read for each request, so a new key counts at once)."""
    def __init__(self, url, key_path):
        self.url, self.key_path = url.rstrip("/"), key_path

    def call(self, method, path, data=None, timeout=30):
        try:
            with open(self.key_path, encoding="utf-8") as f:
                key = f.read().strip()
        except OSError:
            key = ""
        if not key:
            return 0, {"error": "no bridge key"}
        status, _, body = request(self.url + path, method, data, {"Authorization": "Bearer " + key}, timeout)
        return status, body if isinstance(body, dict) else {}


def hub_url(team):
    """The same rule as fleet.py's hub_url."""
    hub = team.get("hub")
    if isinstance(hub, dict):
        ip = (team.get("addresses") or {}).get(hub.get("machine", "")) or ""
        return f"http://{ip}:{int(hub.get('port') or 8765)}" if ip else ""
    hub = str(hub or "")
    return "" if "CHANGE-ME" in hub else hub


def default_hub():
    try:
        with open(os.path.join(KIT, "team.json"), encoding="utf-8") as f:
            team = json.load(f)
    except (OSError, ValueError):
        team = {}
    return (os.environ.get("FLEET_HUB") or hub_url(team)).rstrip("/")


# ---------------------------------------------------------------- journal

class Journal:
    """One mode-600 file for each inbound event. It is on disk before the platform gets its confirmation, and it stays
    until the hub answers (CHAT-APPS.md 6.1)."""
    def __init__(self, folder):
        self.folder = folder
        os.makedirs(folder, mode=0o700, exist_ok=True)
        os.chmod(folder, 0o700)
        self.lock = threading.Lock()
        for name in os.listdir(folder):
            if name.endswith(".tmp"):       # a write that a crash cut off: its platform got no confirmation
                os.unlink(os.path.join(folder, name))

    def write(self, event):
        name = event["account"] + "-" + hashlib.sha256(str(event["id"]).encode()).hexdigest()[:32] + ".json"
        path = os.path.join(self.folder, name)
        with self.lock:
            if os.path.exists(path):        # the same message waits already (a live event and a catch-up)
                return path
            tmp = path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"at": time.time(), "event": event}, f)
                f.flush()
                os.fsync(f.fileno())
            os.rename(tmp, path)
            folder = os.open(self.folder, os.O_RDONLY)
            try:
                os.fsync(folder)
            finally:
                os.close(folder)
        return path

    def pending(self):
        """[(path, event)], oldest first."""
        entries = []
        for name in os.listdir(self.folder):
            if not name.endswith(".json"):
                continue
            path = os.path.join(self.folder, name)
            try:
                with open(path, encoding="utf-8") as f:
                    entry = json.load(f)
                entries.append((float(entry.get("at") or 0), path, dict(entry["event"])))
            except FileNotFoundError:
                continue
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                log(f"journal: {name} cannot be read; renamed to .bad")
                try:
                    os.replace(path, path[:-5] + ".bad")
                except OSError:
                    pass
        entries.sort(key=lambda e: e[0])
        return [(path, event) for _, path, event in entries]

    @staticmethod
    def remove(path):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


# ---------------------------------------------------------------- WebSocket (RFC 6455)

class WSError(Exception):
    """A WebSocket protocol fault."""


class WSClosed(Exception):
    """The connection ended. `code` is the peer's close code, or None when the socket dropped."""
    def __init__(self, code=None):
        super().__init__(code)
        self.code = code


def _mask(data, key):
    n = len(data)
    return (int.from_bytes(data, "big") ^ int.from_bytes((key * (n // 4 + 1))[:n], "big")).to_bytes(n, "big")


class WebSocket:
    """A small client: masked frames, ping and pong, close codes and fragmented messages. recv() runs in one thread;
    send() can run in any thread; abort() from another thread ends a recv() that waits."""
    GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    MAX_MESSAGE = 16 << 20

    def __init__(self, url, timeout=20):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("ws", "wss") or not u.hostname:
            raise WSError("not a WebSocket address")
        secure = u.scheme == "wss"
        port = u.port or (443 if secure else 80)
        sock = socket.create_connection((u.hostname, port), timeout=timeout)
        try:
            if secure:
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=u.hostname)
            self.sock, self.buf, self.closed = sock, b"", False
            self.wlock = threading.Lock()
            key = base64.b64encode(os.urandom(16)).decode()
            host = u.hostname if u.port in (None, 443 if secure else 80) else f"{u.hostname}:{port}"
            target = (u.path or "/") + (f"?{u.query}" if u.query else "")
            sock.sendall((f"GET {target} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                          f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nUser-Agent: fleet-channels\r\n\r\n")
                         .encode())
            while b"\r\n\r\n" not in self.buf:
                if len(self.buf) > 16384:
                    raise WSError("the handshake answer is too long")
                chunk = sock.recv(4096)
                if not chunk:
                    raise WSClosed(None)
                self.buf += chunk
            head, _, self.buf = self.buf.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            status = lines[0].split(" ")
            if len(status) < 2 or status[1] != "101":
                raise WSError("the server did not switch to WebSocket")
            headers = {}
            for line in lines[1:]:
                name, _, value = line.partition(":")
                headers[name.strip().lower()] = value.strip()
            accept = base64.b64encode(hashlib.sha1(key.encode() + self.GUID).digest()).decode()
            if headers.get("upgrade", "").lower() != "websocket" or headers.get("sec-websocket-accept") != accept:
                raise WSError("bad handshake answer")
            sock.settimeout(None)
        except BaseException:
            sock.close()
            raise

    def _read(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(max(65536, n - len(self.buf)))
            if not chunk:
                raise WSClosed(None)
            self.buf += chunk
        data, self.buf = self.buf[:n], self.buf[n:]
        return data

    def _fail(self, code, why):
        self.close(code)
        raise WSError(why)

    def _frame(self):
        b1, b2 = self._read(2)
        if b1 & 0x70:
            self._fail(1002, "reserved bits are set")
        if b2 & 0x80:
            self._fail(1002, "the server masked a frame")
        n = b2 & 0x7F
        if n == 126:
            n = struct.unpack("!H", self._read(2))[0]
        elif n == 127:
            n = struct.unpack("!Q", self._read(8))[0]
        if n > self.MAX_MESSAGE:
            self._fail(1009, "the frame is too large")
        return bool(b1 & 0x80), b1 & 0x0F, self._read(n)

    def recv(self):
        """The next whole message: (opcode, bytes). It answers pings. A close frame raises WSClosed(code)."""
        op, parts, size = None, [], 0
        while True:
            fin, fop, data = self._frame()
            if fop >= 8:
                if not fin or len(data) > 125:
                    self._fail(1002, "bad control frame")
                if fop == 8:
                    code = struct.unpack("!H", data[:2])[0] if len(data) >= 2 else None
                    self.close(code)
                    raise WSClosed(code)
                if fop == 9:
                    self.send(10, data)
                elif fop != 10:
                    self._fail(1002, "unknown control frame")
                continue
            if fop == 0:
                if op is None:
                    self._fail(1002, "continuation without a first frame")
            elif fop in (1, 2):
                if op is not None:
                    self._fail(1002, "a new message inside a fragmented one")
                op = fop
            else:
                self._fail(1002, "unknown opcode")
            parts.append(data)
            size += len(data)
            if size > self.MAX_MESSAGE:
                self._fail(1009, "the message is too large")
            if fin:
                return op, b"".join(parts)

    def send(self, op, payload=b""):
        n = len(payload)
        if n < 126:
            head = struct.pack("!BB", 0x80 | op, 0x80 | n)
        elif n < 65536:
            head = struct.pack("!BBH", 0x80 | op, 0x80 | 126, n)
        else:
            head = struct.pack("!BBQ", 0x80 | op, 0x80 | 127, n)
        key = os.urandom(4)
        with self.wlock:
            if self.closed:
                raise WSClosed(None)
            self.sock.sendall(head + key + _mask(payload, key))

    def send_json(self, obj):
        self.send(1, json.dumps(obj).encode())

    def close(self, code=1000):
        try:
            self.send(8, struct.pack("!H", code) if code else b"")
        except (OSError, WSClosed):
            pass
        self.abort()

    def abort(self):
        """Drop the connection without a close frame (Discord can then resume the session)."""
        self.closed = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except (OSError, AttributeError):
            pass
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------- accounts

class Typing:
    """Repeat a typing signal for each chat until its time ends or a message for that chat goes out."""
    def __init__(self, ping, off=None):
        self.ping, self.off = ping, off
        self.chats = {}                     # chat -> [end, next signal] (monotonic)
        self.cond = threading.Condition()
        self.busy = threading.Lock()        # held while signals go out, so that end() waits for them
        self.stopped = False
        threading.Thread(target=self.loop, daemon=True).start()

    def start(self, chat, seconds):
        with self.cond:
            self.chats[chat] = [time.monotonic() + min(number(seconds, default=120), 600), 0]
            self.cond.notify()

    def end(self, chat):
        """Stop the signals for a chat. True when they ran: the caller then ends them after its reply."""
        with self.busy:
            with self.cond:
                return self.chats.pop(chat, None) is not None

    def stop(self):
        with self.cond:
            self.stopped = True
            self.chats.clear()
            self.cond.notify()

    def loop(self):
        while True:
            with self.cond:
                if self.stopped:
                    return
                now, pings, offs = time.monotonic(), [], []
                for chat, times in list(self.chats.items()):
                    if now >= times[0]:
                        del self.chats[chat]
                        offs.append(chat)
                    elif now >= times[1]:
                        times[1] = now + TYPING_EVERY
                        pings.append(chat)
                if not pings and not offs:
                    wake = min((min(t) for t in self.chats.values()), default=None)
                    self.cond.wait(None if wake is None else max(0.0, wake - now))
                    continue
            with self.busy:
                for chat in pings:
                    with self.cond:
                        if chat not in self.chats:
                            continue
                    self.ping(chat)
            for chat in offs:
                if self.off:
                    self.off(chat)


class Account:
    """One chat app account: its connection, its send queue and its typing signals."""
    app = None

    def __init__(self, bridge, conf):
        self.bridge, self.id = bridge, conf["id"]
        # When an account of this ID last left the fleet, as the hub gave it when this one started: another time later
        # means that this account was removed and one was added again under its ID (Bridge.refresh).
        self.removed = conf.get("removed")
        self.stopping = threading.Event()
        self.outbox = queue.Queue()
        self.user = self.name = self.application_id = None
        self.typing = Typing(self.typing_on, self.typing_off)

    def start(self):
        threading.Thread(target=self.run, daemon=True).start()
        threading.Thread(target=self.send_loop, daemon=True).start()

    def stop(self):
        self.stopping.set()
        self.outbox.put(None)
        self.typing.stop()
        self.halt()

    def leave(self):
        """The account left the fleet: what it does about that while it still runs, before its stop."""

    def claim(self):
        """Before its start: what an account of this ID left on the disk is not this account's."""

    def set_state(self, state, error=None):
        self.bridge.set_state(self, {"id": self.id, "state": state, "user": self.user, "name": self.name,
                                     "application_id": self.application_id, "error": error[:300] if error else None})

    def handle(self, item, db):
        kind, chat = item.get("kind"), str(item.get("chat") or "")
        if kind == "message":
            typing = self.typing.end(chat)      # a message item for the same chat ends the typing
            self.outbox.put((item, db, typing))
        elif kind == "typing":
            self.typing.start(chat, item.get("seconds"))
        else:
            self.command_item(item)

    def send_loop(self):
        while True:
            job = self.outbox.get()
            if job is None:
                return
            item, db, typing = job
            try:
                result = self.send(item, db)
            except Exception as e:      # a fault here must not stop the queue; the outcome is then not known
                log(f"{self.app} {self.id}: out {item['id']} raised {type(e).__name__}")
                result = outcome("unknown", [], "The bridge failed while it sent this message.")
            if typing:
                self.typing_off(str(item.get("chat") or ""))
            log(f"{self.app} {self.id}: out {item['id']} {result['state']}, {result['parts']} part(s)")
            self.bridge.report_item(item["id"], result)

    def run(self):
        raise NotImplementedError

    def halt(self):
        pass

    def send(self, item, db):
        raise NotImplementedError

    def command_item(self, item):
        log(f"{self.app} {self.id}: out {item['id']} {item.get('kind')} does not apply; skipped")

    def typing_on(self, chat):
        pass

    def typing_off(self, chat):
        pass


class DiscordREST:
    """Discord's REST API for one bot. It obeys the rate-limit headers and `retry_after`."""
    def __init__(self, base, token):
        self.base, self.token = base.rstrip("/"), token     # token: a function, so a new token file counts at once
        self.lock = threading.Lock()
        self.blocked = {}           # route -> monotonic time when its bucket has room again
        self.global_until = 0.0

    def call(self, method, path, body=None, timeout=20):
        token = self.token()
        if not token:
            return 0, {}, {"message": "no bot token"}
        route = method + " " + path.split("?", 1)[0]
        for _ in range(5):
            with self.lock:
                delay = max(self.global_until, self.blocked.get(route, 0.0)) - time.monotonic()
            if delay > 0:
                time.sleep(min(delay, 60))
            status, headers, answer = request(self.base + path, method, body,
                                              {"Authorization": "Bot " + token, "User-Agent": USER_AGENT}, timeout)
            now = time.monotonic()
            with self.lock:
                if headers.get("X-RateLimit-Remaining") == "0":
                    self.blocked[route] = now + number(headers.get("X-RateLimit-Reset-After"))
                if status != 429:
                    return status, headers, answer
                info = answer if isinstance(answer, dict) else {}
                wait = number(info.get("retry_after"), headers.get("Retry-After"))
                if info.get("global") or headers.get("X-RateLimit-Global"):
                    self.global_until = now + wait
                else:
                    self.blocked[route] = now + wait
            log(f"discord: rate limited on {route.split(' ')[0]} for {wait:.2f} s")
        return status, headers, answer


class _Connection:
    def __init__(self):
        self.done = threading.Event()
        self.acked = True
        self.new_token = False


class _Reconnect(Exception):
    pass


class Discord(Account):
    """One bot: one Gateway connection (DIRECT_MESSAGES only) and the REST calls."""
    app = "discord"

    def __init__(self, bridge, conf):
        super().__init__(bridge, conf)
        self.token_path = os.path.join(bridge.folder, self.id + ".json")
        self.rest = DiscordREST(bridge.api, self.token)
        self.session_id = self.resume_url = self.seq = None
        self.ws = None
        self.backoff = Backoff()
        self.dms = {}               # (token digest, user ID) -> DM channel ID; a new token can be another bot

    def token(self):
        try:
            with open(self.token_path, encoding="utf-8") as f:
                token = json.load(f).get("token")
        except (OSError, ValueError, AttributeError):
            return None
        return token.strip() if isinstance(token, str) and token.strip() else None

    def halt(self):
        ws = self.ws
        if ws:
            ws.abort()

    def run(self):
        while not self.stopping.is_set():
            token = self.token()
            if not token:
                self.set_state("missing_token")
                self.stopping.wait(TOKEN_POLL)
                continue
            result = self.connect(token)
            if result == "fatal":
                # Stopped with state error. A new token starts it again; no token (also a file that is half written)
                # gives missing_token until the file is whole.
                while not self.stopping.wait(TOKEN_POLL) and self.token() == token:
                    pass
            if result in ("fatal", "token"):
                self.session_id = None      # a new token gets a new session
                continue
            self.stopping.wait(self.backoff.next())

    def connect(self, token):
        resuming = bool(self.session_id and self.resume_url)
        base = self.resume_url if resuming else self.bridge.gateway
        self.set_state("connecting")
        try:
            ws = WebSocket(base.rstrip("/") + "/?v=10&encoding=json")
        except (OSError, WSError, WSClosed) as e:
            log(f"discord {self.id}: cannot open the Gateway ({type(e).__name__})")
            return None
        self.ws, conn = ws, _Connection()
        threading.Thread(target=self.watch_token, args=(ws, conn, token), daemon=True).start()
        try:
            if self.stopping.is_set():
                return None
            ws.sock.settimeout(20)                  # HELLO comes at once; after it, the heartbeat finds a dead link
            hello = self.receive(ws)
            if hello.get("op") != 10:
                raise WSError("the first message was not HELLO")
            ws.sock.settimeout(None)
            interval = number((hello.get("d") or {}).get("heartbeat_interval"), default=41250) / 1000
            threading.Thread(target=self.heartbeat, args=(ws, conn, interval), daemon=True).start()
            if resuming:
                ws.send_json({"op": 6, "d": {"token": token, "session_id": self.session_id, "seq": self.seq}})
            else:
                ws.send_json({"op": 2, "d": {"token": token, "intents": INTENTS,
                                             "properties": {"os": sys.platform, "browser": "fleet-channels",
                                                            "device": "fleet-channels"}}})
            while True:
                self.dispatch(ws, conn, self.receive(ws))
        except WSClosed as e:
            if e.code in FATAL_CLOSE:
                log(f"discord {self.id}: Discord closed the connection with code {e.code}; the account stops")
                self.session_id = None
                self.set_state("error", f"Discord closed the connection with code {e.code}.")
                return "fatal"
            if e.code in NEW_SESSION_CLOSE:
                self.session_id = None
            log(f"discord {self.id}: connection closed ({e.code})")
        except _Reconnect as e:
            log(f"discord {self.id}: {e}")
        except (OSError, WSError, ValueError, KeyError, TypeError, AttributeError) as e:
            log(f"discord {self.id}: connection failed ({type(e).__name__})")
        finally:
            conn.done.set()
            ws.abort()
            self.ws = None
        return "token" if conn.new_token else None

    def watch_token(self, ws, conn, token):
        """A token file that changes while the account is connected (a new token, or none) ends the connection, and
        run() starts again with the file."""
        while not conn.done.wait(TOKEN_POLL):
            if self.token() != token:
                log(f"discord {self.id}: the token file changed; connecting again")
                conn.new_token = True
                ws.abort()
                return

    @staticmethod
    def receive(ws):
        while True:
            op, data = ws.recv()
            if op == 1:
                msg = json.loads(data.decode("utf-8"))
                if isinstance(msg, dict):
                    return msg

    def heartbeat(self, ws, conn, interval):
        if conn.done.wait(interval * random.random()):     # the first beat has jitter
            return
        while True:
            if not conn.acked:
                log(f"discord {self.id}: no heartbeat ACK; reconnecting")
                ws.abort()
                return
            conn.acked = False
            try:
                ws.send_json({"op": 1, "d": self.seq})
            except (OSError, WSClosed):
                return
            if conn.done.wait(interval):
                return

    def dispatch(self, ws, conn, msg):
        op = msg.get("op")
        if msg.get("s") is not None:
            self.seq = msg["s"]
        if op == 0:
            kind, d = msg.get("t"), msg.get("d") or {}
            if kind == "READY":
                self.session_id = d.get("session_id")
                self.resume_url = d.get("resume_gateway_url") or None
                user = d.get("user") or {}
                self.user = str(user.get("id") or "") or None
                self.name = user.get("username") or None
                self.application_id = str((d.get("application") or {}).get("id") or "") or None
                self.backoff.reset()
                self.set_state("connected")
                log(f"discord {self.id}: new session")
                threading.Thread(target=self.catch_up, args=(self.session_id,), daemon=True).start()
            elif kind == "RESUMED":
                self.backoff.reset()
                self.set_state("connected")
                log(f"discord {self.id}: session resumed")
            elif kind == "MESSAGE_CREATE":
                self.on_message(d)
        elif op == 1:
            ws.send_json({"op": 1, "d": self.seq})
        elif op == 7:
            raise _Reconnect("Discord asked for a reconnect")
        elif op == 9:
            if not msg.get("d"):
                self.session_id = None
            self.stopping.wait(random.uniform(*INVALID_WAIT))
            raise _Reconnect("invalid session")
        elif op == 11:
            conn.acked = True

    def on_message(self, d):
        """A direct message from a person goes to the journal. Bots, the bot itself, servers and system messages
        do not."""
        author = d.get("author") or {}
        if d.get("guild_id") or d.get("type", 0) not in (0, 19) or author.get("bot") or author.get("system"):
            return
        sender, mid, chat = str(author.get("id") or ""), str(d.get("id") or ""), str(d.get("channel_id") or "")
        if not sender or not mid or not chat or sender == self.user:
            return
        attachments = d.get("attachments") or []
        if attachments:
            ctype = str((attachments[0] or {}).get("content_type") or "")
            kind = "image" if ctype.startswith("image/") else "audio" if ctype.startswith("audio/") else "file"
        elif d.get("content") and not d.get("sticker_items"):
            kind = "text"
        else:
            kind = "other"
        self.bridge.inbound({"account": self.id, "id": mid, "chat": chat, "group": False, "sender": sender,
                             "sender_alt": None, "sender_name": author.get("username"), "bot": False,
                             "from_me": False, "kind": kind, "text": str(d.get("content") or ""),
                             "ts": snowflake_time(mid)})

    def catch_up(self, session):
        """After a new session (not a resume): read each known chat after its last stored message."""
        backoff = Backoff()
        while True:
            if self.stopping.is_set() or self.session_id != session:
                return
            code, config = self.bridge.hub.call("GET", "/bridge/config")
            if code == 200:
                break
            self.stopping.wait(backoff.next())
        chats = [c for c in config.get("chats") or [] if isinstance(c, dict) and c.get("account") == self.id]
        count = 0
        for c in chats:
            chat, after = str(c.get("chat") or ""), str(c.get("last") or "")
            if not SNOWFLAKE.match(chat) or not SNOWFLAKE.match(after):
                continue
            while not self.stopping.is_set() and self.session_id == session:
                code, _, page = self.rest.call("GET", f"/channels/{chat}/messages?after={after}&limit=100")
                if code != 200 or not isinstance(page, list):
                    log(f"discord {self.id}: catch-up of chat {chat} failed ({code})")
                    break
                page = sorted((m for m in page if isinstance(m, dict) and SNOWFLAKE.match(str(m.get("id") or ""))),
                              key=lambda m: int(m["id"]))
                for m in page:
                    m.setdefault("channel_id", chat)
                    self.on_message(m)
                count += len(page)
                if len(page) < 100:
                    break
                after = page[-1]["id"]
        log(f"discord {self.id}: catch-up read {count} message(s) in {len(chats)} chat(s)")

    def dm_channel(self, user):
        """(the DM channel with a user, None), or (None, error). Discord gives the same channel each time
        (POST /users/@me/channels), so the bridge asks once and keeps it for each (account, user)."""
        if not SNOWFLAKE.match(user):
            return None, "The recipient is not a Discord user ID."
        key = (hashlib.sha256((self.token() or "").encode()).hexdigest(), user)
        if key in self.dms:
            return self.dms[key], None
        backoff = Backoff()
        for attempt in range(SEND_TRIES):
            code, _, answer = self.rest.call("POST", "/users/@me/channels", {"recipient_id": user})
            answer = answer if isinstance(answer, dict) else {}
            chat = str(answer.get("id") or "")
            if code == 200 and SNOWFLAKE.match(chat):
                self.dms[key] = chat
                log(f"discord {self.id}: DM channel {chat} with user {user}")
                return chat, None
            if 400 <= code < 500:
                return None, (f"Discord refused the DM channel: HTTP {code}, code {answer.get('code')}: "
                              f"{answer.get('message') or ''}").strip()
            if attempt + 1 < SEND_TRIES:    # no answer, or a server fault: opening the channel again is harmless
                time.sleep(backoff.next())
        return None, "Discord did not open the DM channel."

    def send(self, item, db):
        if not self.token():
            return outcome("failed", [], "The bot has no token on the hub machine.")
        chat = str(item.get("chat") or "")
        if not chat and item.get("recipient"):     # a message that the agent writes first (16.1): chat is null
            chat, error = self.dm_channel(str(item["recipient"]))
            if error:
                return outcome("failed", [], error)
            self.typing.end(chat)
        if not SNOWFLAKE.match(chat):
            return outcome("failed", [], "The chat is not a Discord channel ID.")
        text = str(item.get("text") or "")
        if item.get("prefix"):
            text = f"**{item['prefix']}:** " + text
        reply_to = str(item.get("reply_to") or "")
        ids = []
        for n, part in enumerate(split_parts(text, DISCORD_LIMIT), 1):
            body = {"content": part, "nonce": f"f{item['id']}p{n}", "enforce_nonce": True}
            if n == 1 and SNOWFLAKE.match(reply_to):
                body["message_reference"] = {"message_id": reply_to, "fail_if_not_exists": False}
            backoff = Backoff()
            for attempt in range(SEND_TRIES):
                code, _, answer = self.rest.call("POST", f"/channels/{chat}/messages", body)
                answer = answer if isinstance(answer, dict) else {}
                if code == 200 and answer.get("id"):
                    ids.append(str(answer["id"]))
                    break
                if 400 <= code < 500:
                    return outcome("failed", ids, f"Discord refused part {n}: HTTP {code}, code {answer.get('code')}: "
                                                  f"{answer.get('message') or ''}".strip())
                if attempt + 1 < SEND_TRIES:    # no answer, or a server fault: the same nonce cannot make a second message
                    time.sleep(backoff.next())
            else:
                return outcome("unknown", ids, f"Discord did not confirm part {n}.")
        return outcome("sent", ids)

    def typing_on(self, chat):
        if SNOWFLAKE.match(chat):
            code, _, _ = self.rest.call("POST", f"/channels/{chat}/typing")
            if code not in (200, 204):
                log(f"discord {self.id}: typing signal failed ({code})")


class BuildFailed(Exception):
    """No wa-link for this release can be had on this machine. The text says why, in a few words."""


def runnable(path):
    return os.path.isfile(path) and os.access(path, os.X_OK)


def wa_link_source(folder=None):
    """The SHA-256 of what wa-link is built from: the Go pin, and the go.mod, go.sum and Go files (not the tests) of
    the release. None when the release has no wa-link source."""
    folder = folder or WA_SOURCE
    try:
        names = sorted(n for n in os.listdir(folder)
                       if n in ("go.mod", "go.sum") or (n.endswith(".go") and not n.endswith("_test.go")))
        if "go.mod" not in names:
            return None
        digest = hashlib.sha256(f"go{GO_VERSION}\n".encode())
        for name in names:
            with open(os.path.join(folder, name), "rb") as f:
                data = f.read()
            digest.update(f"{name} {len(data)}\n".encode() + data)
    except OSError:
        return None
    return digest.hexdigest()


def go_platform():
    """Go's name for this system and processor (linux-amd64), or None where Go publishes no archive."""
    name = f"{GO_SYSTEMS.get(os.uname().sysname)}-{GO_ARCH.get(os.uname().machine)}"
    return name if name in GO_ARCHIVES else None


def remove_tree(path):
    """shutil.rmtree, also of Go's module cache, whose folders are read-only."""
    for root, dirs, _ in os.walk(path):
        for name in dirs:
            inner = os.path.join(root, name)
            if not os.path.islink(inner):
                with contextlib.suppress(OSError):
                    os.chmod(inner, 0o700)
    shutil.rmtree(path, ignore_errors=True)


_wa_build = {"lock": threading.Lock(), "failed": None}     # failed: (monotonic time, source, reason)


def wa_link_program(building=None, force=False, fetch=None, run=subprocess.run, program=None, source=None):
    """The wa-link to start. FLEET_WA_LINK when it is set (None when that is no program); else the program that the
    bridge built from this release's source, built now when it is missing or was built from another source.
    building() is called just before a build. A failed build is tried again after WA_BUILD_RETRY seconds, or at once
    with force. When it fails and a wa-link built from an older source is there, that one runs, because a WhatsApp
    that keeps its link is better than none; else BuildFailed."""
    if os.environ.get("FLEET_WA_LINK"):
        path = os.environ["FLEET_WA_LINK"]
        return path if runnable(path) else None
    program, source = program or WA_PROGRAM, source or WA_SOURCE
    want = wa_link_source(source)
    if want is None:                    # no source in this release: only a program that was put there
        return program if runnable(program) else None

    def current():
        try:
            with open(program + ".source") as f:
                return runnable(program) and f.read().strip() == want
        except OSError:
            return False

    with _wa_build["lock"]:
        if current():
            return program
        failed = _wa_build["failed"]
        if not force and failed and failed[1] == want and time.monotonic() - failed[0] < WA_BUILD_RETRY:
            if runnable(program):
                return program
            raise BuildFailed(failed[2])
        if building:
            building()
        started = time.monotonic()
        log(f"wa-link: building it from this release's source with Go {GO_VERSION}")
        try:
            build_wa_link(source, program, want, fetch, run)
        except BuildFailed as e:
            _wa_build["failed"] = (time.monotonic(), want, str(e))
            log(f"wa-link: the build failed: {e}")
            if runnable(program):
                log("wa-link: the program of an older source runs until a build succeeds")
                return program
            raise
        _wa_build["failed"] = None
        log(f"wa-link: built in {time.monotonic() - started:.0f} s")
        return program


def build_wa_link(source, program, want, fetch=None, run=subprocess.run):
    """Builds wa-link from the folder source into program, with Go's pinned archive, in a folder beside program that
    goes after the build. The program appears whole or not at all, and program.source says what it was built from."""
    name = go_platform()
    if name is None:
        raise BuildFailed(f"Go publishes no build for {os.uname().sysname} {os.uname().machine}")
    folder = os.path.dirname(program)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    for left in os.listdir(folder):     # what a bridge that ended in the middle of a build left; one bridge builds
        if left.startswith(".wa-link-build-"):
            remove_tree(os.path.join(folder, left))
    if shutil.disk_usage(folder).free < WA_ROOM:
        raise BuildFailed(f"the disk of the hub machine has less than {WA_ROOM >> 30} GB free")
    work = tempfile.mkdtemp(prefix=".wa-link-build-", dir=folder)
    try:
        archive = os.path.join(work, "go.tar.gz")
        digest, size = hashlib.sha256(), 0
        try:
            with (fetch or urllib.request.urlopen)(urllib.request.Request(
                    f"{GO_DOWNLOADS}/go{GO_VERSION}.{name}.tar.gz", headers={"User-Agent": "founderizer-channels"}),
                    timeout=60) as r, open(archive, "wb") as f:
                for block in iter(lambda: r.read(1 << 20), b""):
                    size += len(block)
                    if size > GO_MOST:
                        raise BuildFailed(f"the download of Go {GO_VERSION} is larger than {GO_MOST >> 20} MB")
                    digest.update(block)
                    f.write(block)
        except (OSError, http.client.HTTPException, ValueError) as e:      # URLError is an OSError
            raise BuildFailed(f"the download of Go {GO_VERSION} failed ({type(e).__name__})") from None
        if digest.hexdigest() != GO_ARCHIVES[name]:
            raise BuildFailed(f"the download of Go {GO_VERSION} does not match the SHA-256 that go.dev publishes")
        try:
            with tarfile.open(archive, "r:gz") as tar:
                tar.extractall(work, filter="data")     # nothing outside work, no device and no set-user-ID file
        except (tarfile.TarError, OSError, EOFError, TypeError) as e:
            raise BuildFailed(f"the archive of Go {GO_VERSION} cannot be unpacked ({type(e).__name__})") from None
        os.remove(archive)
        go = os.path.join(work, "go", "bin", "go")
        for inner in ("home", "tmp"):
            os.mkdir(os.path.join(work, inner))
        home = os.path.join(work, "home")
        env = {"PATH": os.pathsep.join([os.path.dirname(go), "/usr/local/bin", "/usr/bin", "/bin"]), "HOME": home,
               "XDG_CONFIG_HOME": os.path.join(home, ".config"), "TMPDIR": os.path.join(work, "tmp"),
               "GOPATH": os.path.join(work, "path"), "GOMODCACHE": os.path.join(work, "mod"),
               "GOCACHE": os.path.join(work, "cache"), "GOENV": "off", "GOTOOLCHAIN": "local",
               "GOFLAGS": "-mod=readonly", "GOPROXY": "https://proxy.golang.org", "GOSUMDB": "sum.golang.org",
               "GONOSUMDB": "", "GONOPROXY": "", "GOPRIVATE": "", "CGO_ENABLED": "0"}
        out = os.path.join(work, "wa-link")
        try:    # -p 1: one package at a time, so that a hub with little memory builds it too
            done = run(["sh", "-c", WA_LOW, "sh", go, "build", "-p", "1", "-trimpath", "-buildvcs=false", "-o", out,
                        "."], cwd=source, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                       timeout=WA_BUILD_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise BuildFailed(f"the build took longer than {WA_BUILD_TIMEOUT // 60} minutes") from None
        except OSError as e:
            raise BuildFailed(f"Go cannot start ({type(e).__name__})") from None
        if done.returncode != 0:
            last = [line.strip() for line in (done.stderr or "").splitlines() if line.strip()][-1:]
            raise BuildFailed("go build failed: " + (last[0][:200] if last else f"exit {done.returncode}"))
        try:    # the program runs: it starts and cannot open a database in a folder that is not there
            check = run([out, "--db", "/dev/null/x"], stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise BuildFailed(f"the new wa-link does not run ({type(e).__name__})") from None
        if check.returncode != 1:
            raise BuildFailed(f"the new wa-link does not run (exit {check.returncode})")
        os.chmod(out, 0o755)
        os.replace(out, program)
        with open(os.path.join(work, "source"), "w") as f:
            f.write(want + "\n")
        os.replace(os.path.join(work, "source"), program + ".source")
    finally:
        remove_tree(work)


def own_code():
    """The SHA-256 of this file and of wa-link's source. When a release changes either, the bridge stops, and its
    service starts the new code (a release restarts the hub, not the bridge)."""
    digest = hashlib.sha256()
    with contextlib.suppress(OSError):
        with open(os.path.abspath(__file__), "rb") as f:
            digest.update(f.read())
    digest.update((wa_link_source() or "").encode())
    return digest.hexdigest()


STORE_MARK = ".account"     # beside a session <ID>.db: the removal time of its ID that the session was made under


def removed_later(new, old):
    """Whether the hub's time of an ID's last removal is later than the one that a session or an account was made
    under. The hub's times only grow. An earlier time or none (a hub of an older release, a hub from a backup) is no
    word that the account left, so nothing is deleted on it."""
    return isinstance(new, (int, float)) and not isinstance(new, bool) and (old is None or new > old)


def forget_store(folder, aid):
    """Deletes the WhatsApp session of an account that left the fleet: wa-link's database <ID>.db, SQLite's files
    beside it and the session's mark. True when a session file went."""
    went = False
    for suffix in ("", "-wal", "-shm", "-journal", STORE_MARK, STORE_MARK + ".tmp"):
        try:
            os.remove(os.path.join(folder, aid + ".db" + suffix))
            went = went or not suffix.startswith(STORE_MARK)
        except FileNotFoundError:
            pass
        except OSError as e:
            log(f"account {aid}: its session file could not be removed ({type(e).__name__})")
    return went


class WhatsApp(Account):
    """One linked number: a wa-link child process that speaks JSON lines (CHAT-APPS.md 15.12)."""
    app = "whatsapp"

    def __init__(self, bridge, conf):
        super().__init__(bridge, conf)
        self.db_path = os.path.join(bridge.folder, self.id + ".db")
        self.proc = None
        self.plock = threading.Lock()
        self.waiting = {}           # message ID -> [Event, the "sent" event or None]
        self.wa_state = None
        self.link_state = None
        # A link request while no wa-link runs (it is built, or it starts again): the pair goes at wa-link's first
        # state, and the next try to start it does not wait. Both under plock.
        self.pair_wanted = False
        self.force_build = False
        self.wake = threading.Event()

    def stop(self):
        super().stop()
        self.wake.set()

    def leave(self):
        """The number left the fleet: wa-link ends the phone's link (its logout also deletes its session). The bridge
        deletes the session file after the stop in any case (forget_store), so a number that is added again under this
        ID is linked by a new scan and never comes back by itself."""
        if self.wa_state == "logged_out" or not self.command({"op": "logout"}):
            return                  # no phone holds it, or no wa-link runs: there is no link to end
        end = time.monotonic() + WA_LOGOUT_WAIT
        while self.wa_state != "logged_out" and time.monotonic() < end:
            time.sleep(0.05)
        log(f"whatsapp {self.id}: " + ("the phone's link ended" if self.wa_state == "logged_out"
                                       else "wa-link did not confirm the end of the phone's link"))

    def claim(self):
        """Before its start. A session file is of the account that made it: a file beside it keeps the hub's time of
        the last removal of this ID as it was then (`removed`, null for none). A later time now means that the number
        was removed and one was added again under its ID while no account of it ran here (the bridge was down, or the
        number was off), so the session goes and the new number is linked by a new scan. Only a later time is the
        hub's word (removed_later): on an earlier one, or on none, the session and its mark stay, and the account
        counts from the mark's time. A session with no mark, or with a mark that is no time, is kept and marked."""
        mark = self.db_path + STORE_MARK
        try:
            with open(mark, encoding="utf-8") as f:
                text = f.read().strip()
        except FileNotFoundError:
            text = None
        except OSError as e:
            log(f"whatsapp {self.id}: its session's mark could not be read ({type(e).__name__})")
            return
        have, timed = None, False               # timed: the mark holds a time, or null for "no removal yet"
        if text is not None:
            try:
                have = json.loads(text)
                timed = have is None or (isinstance(have, (int, float)) and not isinstance(have, bool))
            except ValueError:
                pass
        if timed:
            if not removed_later(self.removed, have):
                if have is not None:
                    self.removed = have         # the session is of this time
                return
            if forget_store(self.bridge.folder, self.id):
                log(f"whatsapp {self.id}: the session of the number that left the fleet is removed")
        try:
            with open(mark + ".tmp", "w", encoding="utf-8") as f:
                f.write(json.dumps(self.removed) + "\n")
            os.replace(mark + ".tmp", mark)
        except OSError as e:
            log(f"whatsapp {self.id}: its session's mark could not be written ({type(e).__name__})")

    def pause(self, seconds):
        """The wait between two tries to start wa-link. A link request or the stop ends it."""
        self.wake.wait(seconds)
        self.wake.clear()

    def cannot_start(self, reason):
        """No wa-link runs: the account's error, and the link request's too, when one waits."""
        self.set_state("error", reason)
        with self.plock:
            wanted, self.pair_wanted = self.pair_wanted, False
        if wanted:
            self.post_link("error", error=reason)

    def building(self):
        self.set_state("connecting")

    def run(self):
        backoff = Backoff()
        while not self.stopping.is_set():
            with self.plock:
                force, self.force_build = self.force_build, False
            try:
                binary = wa_link_program(self.building, force=force)
            except BuildFailed as e:
                binary, reason = None, f"wa-link could not be built on the hub machine: {e}."
            except Exception as e:      # a fault of the build must not end this account's thread
                binary, reason = None, f"wa-link could not be built on the hub machine ({type(e).__name__})."
            else:
                reason = "wa-link is not installed on the hub machine."
            if self.stopping.is_set():
                return
            if not binary:
                self.cannot_start(reason)
                self.pause(backoff.next())
                continue
            started = time.monotonic()
            try:
                proc = subprocess.Popen([binary, "--db", self.db_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        text=True, encoding="utf-8", errors="replace", bufsize=1)
            except OSError as e:
                self.cannot_start(f"wa-link cannot start ({type(e).__name__}).")
                self.pause(backoff.next())
                continue
            with self.plock:
                self.proc = proc
            if self.stopping.is_set():
                self.halt()
            log(f"whatsapp {self.id}: wa-link started (pid {proc.pid})")
            self.set_state("connecting")
            for line in proc.stdout:
                try:
                    event = json.loads(line)
                except ValueError:
                    log(f"whatsapp {self.id}: wa-link wrote a line that is not JSON")
                    continue
                if isinstance(event, dict):
                    try:
                        self.on_event(event)
                    except Exception as e:
                        log(f"whatsapp {self.id}: a wa-link event failed ({type(e).__name__})")
            code = proc.wait()
            with self.plock:
                self.proc = None
            for pipe in (proc.stdin, proc.stdout):
                try:
                    pipe.close()
                except OSError:
                    pass
            self.wa_state = None
            for waiter in list(self.waiting.values()):      # its sends have no confirmation now
                waiter[0].set()
            if self.stopping.is_set():
                return
            log(f"whatsapp {self.id}: wa-link stopped (exit {code})")
            self.set_state("error", f"wa-link stopped (exit {code}).")
            if time.monotonic() - started >= WA_STABLE:
                backoff.reset()
            self.pause(backoff.next())

    def halt(self):
        with self.plock:
            proc = self.proc
        if not proc or proc.poll() is not None:
            return
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()

    def command(self, obj):
        line = json.dumps(obj) + "\n"
        with self.plock:
            proc = self.proc
            if not proc or proc.poll() is not None:
                return False
            try:
                proc.stdin.write(line)
                proc.stdin.flush()
                return True
            except (OSError, ValueError):
                return False

    def on_event(self, event):
        kind = event.get("ev")
        if kind == "message":
            self.on_message(event)
        elif kind == "sent":
            waiter = self.waiting.get(str(event.get("id") or ""))
            if waiter:
                waiter[1] = event
                waiter[0].set()
        elif kind == "state":
            self.on_state(event)
        elif kind == "qr":
            self.post_link("waiting", qr=str(event.get("code") or ""),
                           expires=time.time() + number(event.get("timeout"), default=20))
        elif kind == "receipt":
            ids = [str(i) for i in event.get("ids") or []]
            if ids and event.get("type") in ("delivered", "read"):
                self.bridge.report("/bridge/receipt", {"account": self.id, "ids": ids, "type": event["type"]})
        else:
            log(f"whatsapp {self.id}: unknown wa-link event")

    def on_state(self, event):
        state, jid, error = event.get("state"), event.get("jid") or None, event.get("error") or None
        self.wa_state = state
        if jid:
            self.user = str(jid)
            self.name = re.split(r"[:@.]", self.user)[0] or None
        elif state == "logged_out":
            self.user = self.name = None
        mapped = {"linked": "connected", "connecting": "connecting", "logged_out": "logged_out"}.get(state, "error")
        self.set_state(mapped, str(error) if error else "wa-link reported an error." if mapped == "error" else None)
        if state in ("linked", "logged_out", "error"):
            with self.plock:
                wanted, self.pair_wanted = self.pair_wanted, False
            if wanted and state == "logged_out" and self.command({"op": "pair"}):
                return      # the start of a wa-link with no device, not the end of a link: its QR code follows
        if state in ("linked", "logged_out", "error") and state != self.link_state:
            self.post_link(state, error=str(error) if error else None)

    def post_link(self, state, qr=None, expires=None, error=None):
        self.link_state = state
        self.bridge.report("/bridge/link", {"account": self.id, "state": state, "qr": qr, "expires": expires,
                                            "error": error[:300] if error else None})

    def on_message(self, event):
        mid = str(event.get("id") or "")
        if not mid:
            return
        ok = self.bridge.inbound({"account": self.id, "id": mid, "chat": str(event.get("chat") or ""),
                                  "group": bool(event.get("group")), "sender": str(event.get("sender") or ""),
                                  "sender_alt": event.get("sender_alt") or None,
                                  "sender_name": event.get("push_name") or None, "bot": False,
                                  "from_me": bool(event.get("from_me")), "kind": event.get("kind") or "other",
                                  "text": str(event.get("text") or ""), "ts": number(event.get("ts"),
                                                                                       default=time.time())})
        if ok:      # the ack goes only after the journal write: then whatsmeow confirms the message to WhatsApp
            self.command({"op": "ack", "id": mid})

    def send(self, item, db):
        if self.wa_state != "linked":
            return outcome("failed", [], "WhatsApp is not linked.")
        text = wa_format(str(item.get("text") or ""))
        if item.get("prefix"):
            text = f"*{item['prefix']}:* " + text
        ids = []
        for n, part in enumerate(split_parts(text, WHATSAPP_LIMIT), 1):
            mid = wa_message_id(db, item["id"], n)
            waiter = self.waiting[mid] = [threading.Event(), None]
            try:
                if not self.command({"op": "send", "id": mid, "to": str(item.get("chat") or ""), "text": part,
                                     "reply_to": (item.get("reply_to") or None) if n == 1 else None}):
                    return outcome("failed", ids, "wa-link is not running.")
                if not waiter[0].wait(WA_SEND_TIMEOUT) or waiter[1] is None:
                    return outcome("unknown", ids, f"wa-link did not confirm part {n}.")
                if not waiter[1].get("ok"):
                    error = str(waiter[1].get("error") or "WhatsApp refused the message.")
                    # wa-link: an error that starts with "unknown: " means that the message can have arrived.
                    return outcome("unknown" if error.startswith("unknown: ") else "failed", ids, error)
                ids.append(mid)
            finally:
                self.waiting.pop(mid, None)
        return outcome("sent", ids)

    def command_item(self, item):
        kind = item.get("kind")
        if kind == "read":
            self.command({"op": "read", "chat": item.get("chat"), "sender": item.get("sender"),
                          "ids": [str(i) for i in item.get("ids") or []]})
        elif kind in ("link", "unlink"):
            self.link_state = None              # the hub gets the next state, also when it did not change
            if kind == "link":
                with self.plock:
                    running = self.proc is not None and self.proc.poll() is None
                    if not running:             # wa-link is built or starts again: the pair waits for it
                        self.pair_wanted = self.force_build = True
                if not running:
                    self.wake.set()
                    return
            if not self.command({"op": "pair" if kind == "link" else "logout"}):
                self.post_link("error", error="wa-link is not running.")
        else:
            super().command_item(item)

    def typing_on(self, chat):
        self.command({"op": "typing", "chat": chat, "on": True})

    def typing_off(self, chat):
        self.command({"op": "typing", "chat": chat, "on": False})


APPS = {"discord": Discord, "whatsapp": WhatsApp}


# ---------------------------------------------------------------- the bridge

class Bridge:
    def __init__(self, folder, hub, gateway=GATEWAY, api=DISCORD_API):
        self.folder, self.gateway, self.api = folder, gateway, api
        os.makedirs(folder, mode=0o700, exist_ok=True)
        os.chmod(folder, 0o700)
        self.hub = Hub(hub, os.path.join(folder, "bridge.key"))
        self.journal = Journal(os.path.join(folder, "journal"))
        self.stopping = threading.Event()
        self.lock = threading.Lock()
        self.accounts = {}
        self.states = {}
        self.configured, self.version = False, None
        self.inbound_due = threading.Event()
        self.status_due = threading.Event()
        self.reports = queue.Queue()
        self.code = own_code()      # the code this bridge runs; each status report carries it

    def start(self):
        for target in (self.inbound_loop, self.out_loop, self.status_loop, self.report_loop):
            threading.Thread(target=target, daemon=True).start()

    def stop(self):
        self.stopping.set()
        self.inbound_due.set()
        self.status_due.set()
        self.reports.put(None)
        with self.lock:
            accounts = list(self.accounts.values())
            self.accounts.clear()
        for account in accounts:
            account.stop()

    # inbound

    def inbound(self, event):
        """Journal first. True when the event is on disk."""
        try:
            self.journal.write(event)
        except OSError as e:
            log(f"journal: cannot write an event of {event.get('account')} ({type(e).__name__})")
            return False
        self.inbound_due.set()
        return True

    def inbound_loop(self):
        """Post the journal to the hub, oldest first, until the hub answers. Replays what a restart left."""
        backoff = Backoff()
        while not self.stopping.is_set():
            self.inbound_due.clear()
            retry = False
            for path, event in self.journal.pending():
                if self.stopping.is_set():
                    return
                code, answer = self.hub.call("POST", "/bridge/inbound", event)
                where = f"{event.get('account')} {event.get('id')}"
                if code == 200:
                    self.journal.remove(path)
                    log(f"inbound {where}: {answer.get('result')}")
                elif code in (400, 413) or (code == 409 and answer.get("error") == "unknown chat app account"):
                    # a bad event, or one of an account that the hub does not have (any more): it never gets in
                    self.journal.remove(path)
                    log(f"inbound {where}: the hub refused the event ({code}); removed")
                elif code == 409:
                    retry = True
                    log(f"inbound {where}: the hub does not know the account yet; kept")
                else:
                    retry = True
                    log(f"inbound: the hub did not take the event ({code or 'no answer'}); kept")
                    break
            if retry:
                self.inbound_due.wait(backoff.next())
            else:
                backoff.reset()
                self.inbound_due.wait(30)

    # configuration and the outbound queue

    def refresh(self):
        code, config = self.hub.call("GET", "/bridge/config")
        if code != 200 or not isinstance(config.get("accounts"), list):
            log(f"cannot read /bridge/config ({code or config.get('error') or 'no answer'})")
            return False
        want = {}
        for conf in config["accounts"]:
            aid = str((conf or {}).get("id") or "") if isinstance(conf, dict) else ""
            if not ACCOUNT_ID.match(aid) or conf.get("app") not in APPS:
                log("config: an account with a bad ID or app is skipped")
                continue
            if conf.get("enabled", True) is not False:
                want[aid] = conf
        # The accounts that the hub saw leave the fleet (CHAT-APPS.md 18.4). Only its word ends a phone's link and
        # deletes a session: an account that is turned off, or that a configuration only does not name, keeps both.
        known = {str(conf.get("id") or "") for conf in config["accounts"] if isinstance(conf, dict)}
        left = {aid for aid in config.get("removed") or [] if isinstance(aid, str) and ACCOUNT_ID.match(aid)} - known
        with self.lock:
                # Removed and added again between two readings (also as an account of the other app): the hub's time of
            # the removal is a later one now.
            again = {aid for aid, a in self.accounts.items()
                     if aid in want and removed_later(want[aid].get("removed"), a.removed)}
            stopped = [a for aid, a in self.accounts.items()
                       if aid not in want or a.app != want[aid]["app"] or aid in again]
            for account in stopped:
                del self.accounts[account.id]
                self.states.pop(account.id, None)
            started = [APPS[conf["app"]](self, conf) for aid, conf in want.items() if aid not in self.accounts]
            for account in started:
                self.accounts[account.id] = account
            self.configured, self.version = True, config.get("version")
        for account in stopped:
            leaves = account.id in left or account.id in again
            if leaves:
                account.leave()
            account.stop()
            log(f"account {account.id}: stopped")
            if leaves and forget_store(self.folder, account.id):
                log(f"account {account.id}: its session file is removed")
        # A session of an account that left while no account of it ran here (the bridge was down, or it was off).
        for aid in sorted(left):
            if forget_store(self.folder, aid):
                log(f"account {aid}: its session file is removed")
        for account in started:
            account.claim()
            account.start()
            log(f"account {account.id}: started ({account.app})")
        if stopped:
            self.status_due.set()
        return True

    def out_loop(self):
        backoff = Backoff()
        while not self.stopping.is_set():
            if not self.configured and not self.refresh():
                self.stopping.wait(backoff.next())
                continue
            code, answer = self.hub.call("GET", f"/bridge/out?wait={OUT_WAIT}", timeout=OUT_WAIT + 15)
            if self.stopping.is_set():
                return
            if code != 200:
                log(f"cannot read /bridge/out ({code or answer.get('error') or 'no answer'})")
                self.stopping.wait(backoff.next())
                continue
            backoff.reset()
            if answer.get("version") != self.version:
                self.refresh()
            db = str(answer.get("db") or "")
            for item in answer.get("items") or []:
                if isinstance(item, dict):
                    self.route(item, db)

    def route(self, item, db):
        if not isinstance(item.get("id"), int):
            log("out: an item without a number ID is skipped")
            return
        aid, kind = str(item.get("account") or ""), item.get("kind")
        log(f"out {item['id']}: {kind} for {aid}")
        with self.lock:
            account = self.accounts.get(aid)
        if account:
            account.handle(item, db)
        elif kind == "message":
            self.report_item(item["id"], outcome("failed", [], "The bridge does not run this account."))
        elif kind in ("link", "unlink"):
            self.report("/bridge/link", {"account": aid, "state": "error", "qr": None, "expires": None,
                                         "error": "The bridge does not run this account."})

    # reports to the hub

    def report(self, path, body):
        self.reports.put((path, body))

    def report_item(self, item_id, result):
        self.report(f"/bridge/out/{int(item_id)}", result)

    def report_loop(self):
        """Results, receipts and link states, in order. Each is tried until the hub answers."""
        while True:
            job = self.reports.get()
            if job is None:
                return
            path, body = job
            backoff = Backoff()
            while not self.stopping.is_set():
                code, _ = self.hub.call("POST", path, body)
                if code == 200:
                    break
                if 400 <= code < 500 and code not in (403, 408, 429):
                    log(f"{path}: the hub refused the report ({code}); dropped")
                    break
                self.stopping.wait(backoff.next())

    def set_state(self, account, entry):
        with self.lock:
            if self.accounts.get(account.id) is not account or self.states.get(account.id) == entry:
                return
            self.states[account.id] = entry
        log(f"account {account.id}: {entry['state']}")
        self.status_due.set()

    def status_loop(self):
        """POST /bridge/status at each change and every STATUS_EVERY seconds."""
        backoff = Backoff()
        while not self.stopping.is_set():
            self.status_due.wait(STATUS_EVERY)
            self.status_due.clear()
            if self.stopping.is_set():
                return
            with self.lock:
                accounts = [dict(s) for s in self.states.values()]
            code, _ = self.hub.call("POST", "/bridge/status", {"accounts": accounts, "code": self.code})
            if code == 200:
                backoff.reset()
            else:
                self.stopping.wait(min(backoff.next(), STATUS_EVERY))
                self.status_due.set()


# ---------------------------------------------------------------- commands

def unit_text():
    def quote(x):
        return json.dumps(x.replace("%", "%%"))
    return ("[Unit]\nDescription=Founderizer chat apps bridge (Discord and WhatsApp)\n"
            "After=network-online.target fleet-hub.service\nWants=network-online.target\n\n"
            "[Service]\nType=simple\nWorkingDirectory=" + KIT.replace("%", "%%").replace(" ", r"\x20") + "\n"
            "ExecStart=" + quote(sys.executable) + " " + quote(os.path.join(KIT, "channels.py")) + " run\n"
            "Restart=always\nRestartSec=5\nUMask=0077\nTimeoutStopSec=20\n\n"
            "[Install]\nWantedBy=default.target\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run", help="run the bridge")
    sub.add_parser("unit", help="print the systemd user unit fleet-channels.service")
    args = parser.parse_args(argv)
    if args.cmd == "unit":
        sys.stdout.write(unit_text())
        return 0
    hub = default_hub()
    if not hub:
        log("no hub address in team.json")
        return 1
    bridge = Bridge(CHAT_DIR, hub)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: bridge.stopping.set())
    log(f"bridge started; hub {hub}; journal holds {len(bridge.journal.pending())} event(s)")
    bridge.start()
    code, looked = bridge.code, time.monotonic()
    while not bridge.stopping.wait(1):
        if time.monotonic() - looked >= CODE_CHECK:
            looked = time.monotonic()
            if own_code() != code:
                log("the bridge's code changed: it stops, and its service starts the new code")
                break
    bridge.stop()
    log("bridge stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
