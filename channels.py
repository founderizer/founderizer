#!/usr/bin/env python3
"""Founderizer chat apps bridge (CHAT-APPS.md 15.11). Python standard library only.

  channels.py run     keep the Discord, Telegram and WhatsApp connections and carry text between them and the hub
  channels.py unit    print the systemd user unit fleet-channels.service

It runs on the hub machine. It keeps the Discord and Telegram bot tokens, the inbound journal and one wa-link child
process for
each WhatsApp account, and it builds wa-link from the release's own source when it has none for it (wa_link_program).
It decides nothing: the hub keeps every rule. It never logs message text or tokens.
"""
import argparse
import base64
import contextlib
import hashlib
import http.client
import json
import mimetypes
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
WA_CAPTION = 1024           # WhatsApp: a text this short is the caption of a message's first file (CHAT-APPS.md 20)
FILE_MOST = 25 << 20        # bytes of one file of a message: the hub's own limit (hub.CHAT_FILE_MAX)
OUTBOX = "outbox"           # beside the sessions: the files of the messages that are being sent, mode 600
# The files that a person's or the owner's message brings (the design "Files from chat apps to agents", version 2, of
# 20 November 2026, and the owner's words of that day: "does it accept multiple files, images etc? it should"): the
# bridge uploads each file of a message, of any type, to POST /bridge/files before the message's own POST
# /bridge/inbound. A file that does not come up is one code of the message's `missed`: size (more than FILE_MOST, or
# than Telegram gives a bot), download, refused (by the hub, also for bytes that are not of their type, and after
# FILE_TRIES attempts that it did not answer) or many (past FILES_IN).
FILES_IN = 10               # Discord's own most for one message
MISSED_MOST = 20            # codes of one message's `missed` that the hub takes
FILE_TRIES = 3              # attempts that a message's files keep it, in all, after no answer or a 5xx: then `refused`
# The types whose bytes the hub checks (hub.ATTACH_TYPES and hub.ATTACH_OFFICE), with their extensions. A file whose
# chat app gives no valid type is of its name's extension: these first, so that the hub reads a Markdown or an Office
# file as one, then Python's own table (never the system's, so that each machine says the same), else
# application/octet-stream. Any type goes up: the hub keeps one that it does not check as data.
FILE_TYPES = {"image/png": ".png", "image/jpeg": ".jpg", "image/gif": ".gif", "image/webp": ".webp",
              "application/pdf": ".pdf", "application/zip": ".zip", "text/plain": ".txt", "text/markdown": ".md",
              "text/csv": ".csv", "application/json": ".json",
              "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
              "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
              "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx"}
FILE_EXTENSIONS = {**{ext: mime for mime, ext in FILE_TYPES.items()}, ".jpeg": "image/jpeg"}
PYTHON_TYPES = mimetypes.MimeTypes()
MIME_TOKEN = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}")     # RFC 6838
DISCORD_FILES = ("https://cdn.discordapp.com/", "https://media.discordapp.net/")   # Discord's CDN: a message's files
REST_NOTE = "The rest is in Founderizer."
# Telegram (CHAT-APPS.md 19.2). Facts read on core.telegram.org on 15 November 2026 (Bot API 10.4): every call is
# <api>/bot<token>/<method>; sendMessage takes 1 to 4,096 characters after the entities; "typing" shows for 5 seconds;
# at most one message a second in one chat; there is no idempotency key, so a lost answer can be a sent message.
TELEGRAM_API = "https://api.telegram.org"
TELEGRAM_LIMIT = 4000
TELEGRAM_TOKEN = re.compile(r"^[0-9]{5,20}:[A-Za-z0-9_-]{30,80}$")
TELEGRAM_CHAT = re.compile(r"^-?[1-9][0-9]{0,19}$")
TELEGRAM_UPDATES = ["message", "my_chat_member"]
TELEGRAM_STATUSES = ("creator", "administrator", "member", "restricted", "left", "kicked")
# The fields of a message that a person sent that is neither words, a picture, a voice note nor a file: the hub passes
# it on as kind "other" (CHAT-APPS.md 8.1). A message with none of them is Telegram's own (a pin, the auto-delete
# timer), which no person wrote, and the bridge drops it.
TELEGRAM_OTHER = ("video", "video_note", "animation", "sticker", "location", "venue", "contact", "poll", "dice", "story",
                  "checklist", "game", "paid_media")
TELEGRAM_FILE_MOST = 20 << 20   # bytes of a file that getFile gives a bot: Telegram's own 20 MB
# The fields of a message that hold a file, besides its photo, with the name of a file that comes with none. A message
# with an animation has its document too, so the animation comes first.
TELEGRAM_FILES = (("animation", "animation.mp4"), ("video", "video.mp4"), ("video_note", "video.mp4"),
                  ("voice", "voice.ogg"), ("audio", "audio.mp3"), ("sticker", "sticker.webp"), ("document", ""))

# The types of the media that a chat app sends with no type of its own, the same on every machine: Python's table
# changes with its version (3.12 names no type for .ogg).
MEDIA_EXTENSIONS = {".ogg": "audio/ogg", ".oga": "audio/ogg", ".opus": "audio/ogg", ".mp3": "audio/mpeg",
                    ".m4a": "audio/mp4", ".mp4": "video/mp4", ".mov": "video/quicktime", ".webm": "video/webm",
                    ".tgs": "application/x-tgsticker", ".heic": "image/heic"}

# Timings in seconds. The tests make them short.
OUT_WAIT = 25               # the /bridge/out long poll
STATUS_EVERY = 60
TYPING_EVERY = 8
TELEGRAM_POLL = 25          # Telegram: seconds of one getUpdates long poll
TELEGRAM_TYPING_EVERY = 4   # Telegram: "typing" lasts 5 seconds
TELEGRAM_PART_GAP = 1.0     # Telegram: seconds between two parts to one chat
TELEGRAM_TRIES = 3          # Telegram: tries of a request that did not reach it (nothing was sent)
TELEGRAM_WAITS = 5          # Telegram: waits of retry_after for one part before it fails
BACKOFF_FIRST, BACKOFF_MAX = 1.0, 60.0
TOKEN_POLL = 5              # how often a Discord account looks for a new token file (16.4: it starts within 15 s)
INVALID_WAIT = (1.0, 5.0)   # Discord: wait this long after INVALID_SESSION
SEND_TRIES = 3              # Discord: tries of one part with the same nonce when no answer comes
WA_SEND_TIMEOUT = 25        # WhatsApp: wait this long for wa-link's "sent" event (4 parts stay under the hub's 120)
WA_STABLE = 60              # a wa-link that ran this long starts its backoff again
WA_LOGOUT_WAIT = 5          # WhatsApp: wait this long for wa-link to end the phone's link of a number that left the fleet
WA_FILE_TIMEOUT = 120       # WhatsApp: wait this long for wa-link's "sent" of a file part (its upload and its send)
CODE_CHECK = 60             # how often the bridge looks whether a release changed its own code
FILE_FETCH_TIMEOUT = 60     # seconds of one file's download from its chat app, in all: no account waits long behind it
FILE_UPLOAD_TIMEOUT = 120   # seconds of one file's upload to the hub, which checks its bytes before it answers
FILE_UP_FOR = 1800          # seconds that an upload's 200 counts: half the hour that the hub keeps a file that no
                            # message took (hub.ATTACH_WAIT); after it, the file goes up again, which renews that hour

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
# Whether this Python's tarfile has the data filter: Python 3.12, and 3.10.12 and 3.11.4 of their own lines. Debian 12
# has Python 3.11.2, which the installers take: there go_members holds Go's archive to the filter's rules.
TAR_FILTER = hasattr(tarfile, "data_filter")
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


def _tg_escape(text):
    """Text as Telegram's HTML takes it: &, < and > as entities (CHAT-APPS.md 19.2)."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


TG_INLINE = re.compile(r"`([^`\n]+)`|\*\*(.+?)\*\*|\[([^\]\n]+)\]\(((?:https?|tg)://[^)\s]+)\)")


def _tg_inline(line):
    """One line of Markdown outside a code block as Telegram's HTML: `c` to <code>, **b** to <b>, [t](u) to a link of
    http, https or tg. Everything between is escaped, so no text of the agent becomes a tag."""
    out, at = [], 0
    for m in TG_INLINE.finditer(line):
        out.append(_tg_escape(line[at:m.start()]))
        if m.group(1) is not None:
            out.append("<code>" + _tg_escape(m.group(1)) + "</code>")
        elif m.group(2) is not None:
            out.append("<b>" + _tg_escape(m.group(2)) + "</b>")
        else:
            out.append('<a href="' + _tg_escape(m.group(4)).replace('"', "&quot;") + '">' + _tg_escape(m.group(3)) +
                       "</a>")
        at = m.end()
    out.append(_tg_escape(line[at:]))
    return "".join(out)


def _tg_lines(text, inline, block):
    """The lines of a Markdown text with a heading as a bold line and a table as one line for each row, as for
    WhatsApp; inline(line) makes each line, block(lines) each code block, and a block that a part's end cut off is
    closed."""
    out, code = [], None
    for line in text.split("\n"):
        if line.lstrip().startswith("```"):
            if code is None:
                code = []
            else:
                if code:
                    out.append(block(code))
                code = None
            continue
        if code is not None:
            code.append(line)
            continue
        heading = re.match(r"^\s{0,3}#{1,6}\s+(.*?)[\s#]*$", line)
        if heading:
            title = heading.group(1).replace("**", "").strip()
            out.append(inline(f"**{title}**") if title else "")
            continue
        if re.match(r"^\s*\|.*\|\s*$", line):
            if re.match(r"^\s*\|[\s:|-]*-[\s:|-]*\|\s*$", line):
                continue                                    # the line under the header row
            line = " · ".join(c.strip() for c in line.strip().strip("|").split("|") if c.strip())
        out.append(inline(line))
    if code:
        out.append(block(code))
    return "\n".join(out)


def tg_format(text):
    """Markdown to Telegram's HTML (parse_mode HTML, CHAT-APPS.md 19.2): bold, inline code, code blocks as <pre>,
    links, a heading as a bold line, a table as one line for each row. One * or _ stays as it is, as for WhatsApp:
    an agent's list marks are stars too."""
    return _tg_lines(text, _tg_inline, lambda lines: "<pre>" + _tg_escape("\n".join(lines)) + "</pre>")


def tg_plain(text):
    """The same text with no markup, for a part whose HTML Telegram refused: **b** to b, [t](u) to t (u)."""
    def inline(line):
        line = re.sub(r"\*\*(.+?)\*\*", r"\1", line)
        return re.sub(r"\[([^\]\n]+)\]\(([^)\s]+)\)", r"\1 (\2)", line)
    return _tg_lines(text, inline, "\n".join)


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


def request(url, method="GET", data=None, headers=None, timeout=30, raw=None):
    """(status, headers, parsed JSON or None). Status 0: no answer (refused, reset or timed out). raw: (bytes, content
    type) of a body that is not JSON, such as a Discord message with files."""
    body = None if data is None else json.dumps(data).encode()
    sent = {"Accept": "application/json", **(headers or {})}
    if raw is not None:
        body, sent["Content-Type"] = raw
    elif body is not None:
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


class Missed(Exception):
    """A file of an inbound message that does not come up: its code, which the message's POST /bridge/inbound carries
    in `missed`, and for the log a few words of why, which hold no name, address, caption, file id or token."""
    def __init__(self, code, why=None):
        super().__init__(code)
        self.code, self.why = code, why


def lookup(host, port, end):
    """The addresses of host, found before the monotonic time `end`: the system's lookup has no time limit of its own,
    so it runs beside, and nothing waits for it past that time."""
    found = {}

    def run():
        try:
            found["addresses"] = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        except (OSError, UnicodeError) as e:
            found["error"] = e
    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(max(0.0, end - time.monotonic()))
    if worker.is_alive():
        raise Missed("download", "its name was not found in its time")
    if "error" in found:
        raise Missed("download", type(found["error"]).__name__)
    return found["addresses"]


def connect_by(end):
    """http.client's connection for download(): each address of the host with the time that is left before `end`, not
    each with the whole time, as socket.create_connection gives it."""
    def connect(address, timeout=None, source=None):
        error = None
        for family, kind, proto, _, where in lookup(address[0], address[1], end):
            rest = end - time.monotonic()
            if rest <= 0:
                break
            sock = socket.socket(family, kind, proto)
            try:
                sock.settimeout(rest)
                sock.connect(where)
                return sock
            except OSError as e:
                error = e
                sock.close()
        raise Missed("download", type(error).__name__ if error else "not connected in its time")
    return connect


def download(url, timeout, headers=None):
    """The bytes of a GET of a file that a message brings, in `timeout` seconds in all, not only for each read: a slow
    chat app holds the other accounts' messages no longer. The name lookup and each address of the host get the time
    that is left, and so does each read; the head of the answer must come in that time too. It reads at most
    FILE_MOST + 1 bytes, so that a larger file is `size`, also one whose answer gives no length; anything else that
    fails is `download`, a redirect too (NoRedirect's rule). No reason holds the address: a Telegram file's address
    holds the bot's token."""
    end = time.monotonic() + timeout
    try:
        parts = urllib.parse.urlsplit(url)
        host, port = parts.hostname, parts.port
    except ValueError:
        raise Missed("download", "not a web address") from None
    if parts.scheme not in ("http", "https") or not host:
        raise Missed("download", "not a web address")
    if timeout <= 0:
        raise Missed("download", "no time left")

    def left():
        rest = end - time.monotonic()
        if rest <= 0:
            raise Missed("download", f"not done in {timeout:g} s")
        return rest
    cls = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
    conn, r = cls(host, port, timeout=timeout), None
    conn._create_connection = connect_by(end)
    try:
        conn.connect()
        sock = conn.sock        # the response may take the connection's socket: each step gets the time that is left
        sock.settimeout(left())
        conn.request("GET", (parts.path or "/") + ("?" + parts.query if parts.query else ""),
                     headers={"Accept": "*/*", **(headers or {})})
        sock.settimeout(left())
        r = conn.getresponse()
        left()                  # each read of the head had the time that was left, but not the head in all
        if r.status != 200:
            raise Missed("download", f"HTTP {r.status}")
        if r.length is not None and r.length > FILE_MOST:
            raise Missed("size")
        data = bytearray()
        while len(data) <= FILE_MOST and not r.isclosed():     # a whole answer of its length closes its socket
            sock.settimeout(left())
            chunk = r.read1(min(1 << 16, FILE_MOST + 1 - len(data)))     # one read of the socket at most
            if not chunk:
                break
            data += chunk
        if r.length:            # the answer ended before the length that it gave
            raise Missed("download", "cut off")
    except (OSError, http.client.HTTPException, ValueError) as e:
        raise Missed("download", type(e).__name__) from None
    finally:
        if r is not None:       # an answer that ends the connection holds its socket itself
            r.close()
        conn.close()
    if len(data) > FILE_MOST:
        raise Missed("size")
    return bytes(data)


def file_type(mime, name):
    """The type that POST /bridge/files names, of any file: its chat app's own without its parameters, in lower case,
    when that is a valid type/subtype; else its name's extension's (FILE_TYPES, then Python's own table); else
    application/octet-stream. The hub checks the bytes of a type that it knows and keeps any other as data."""
    mime = str(mime or "").split(";", 1)[0].strip().lower()
    if MIME_TOKEN.fullmatch(mime) and mime != "application/octet-stream":   # the generic type yields to the name's
        return mime
    ext = os.path.splitext(str(name or ""))[1].lower()
    guess = FILE_EXTENSIONS.get(ext) or MEDIA_EXTENSIONS.get(ext) or PYTHON_TYPES.guess_type("file" + ext)[0] or ""
    return guess if MIME_TOKEN.fullmatch(guess) else "application/octet-stream"


def file_name(name, mime):
    """A file's name for POST /bridge/files: no control character and no lone half of a surrogate pair (JSON can hold
    one, and no query can: urlencode raises), at most 200 characters, and never empty (the hub makes its own safe
    name of it)."""
    name = re.sub(r"[\x00-\x1f\x7f-\x9f\ud800-\udfff]", "", str(name or "")).strip()[:200]
    return name or "file" + FILE_TYPES.get(mime, "")


def upload_path(event, n, f, mime, check=False):
    """POST /bridge/files's path and query for file n of an inbound event, each value URL-encoded (%20, never +, for a
    space). check: the hub's question, with no body, whether it takes a file of this sender now."""
    fields = {"account": event.get("account"), "message": event.get("id"), "n": n,
              "name": file_name(f.get("name"), mime), "mime": mime, "sender": event.get("sender")}
    if event.get("sender_alt"):
        fields["sender_alt"] = event["sender_alt"]
    if check:
        fields["check"] = 1
    return "/bridge/files?" + urllib.parse.urlencode(fields, quote_via=urllib.parse.quote)


def media(name, mime, size, **where):
    """One file that a message brings, as its journal event describes it, never with its bytes: its name, its type
    without parameters in lower case (None: its chat app gave none), its size as its chat app gave it (None: none), and
    where its account fetches it (Discord: url; Telegram: file_id)."""
    mime = str(mime or "").split(";", 1)[0].strip().lower() or None
    size = size if isinstance(size, int) and not isinstance(size, bool) and size >= 0 else None
    return dict(where, name=str(name or ""), mime=mime, size=size)


def with_media(event, files):
    """The inbound event with its message's files: `media`, the first FILES_IN, and `media_more`, how many came after
    them, which go up as `many`."""
    if files:
        event["media"] = files[:FILES_IN]
        if len(files) > FILES_IN:
            event["media_more"] = len(files) - FILES_IN
    return event


class Hub:
    """The hub's /bridge/* routes, with the key from bridge.key (read for each request, so a new key counts at once)."""
    def __init__(self, url, key_path):
        self.url, self.key_path = url.rstrip("/"), key_path

    def key(self):
        try:
            with open(self.key_path, encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            return ""

    def call(self, method, path, data=None, timeout=30):
        key = self.key()
        if not key:
            return 0, {"error": "no bridge key"}
        status, _, body = request(self.url + path, method, data, {"Authorization": "Bearer " + key}, timeout)
        return status, body if isinstance(body, dict) else {}

    def upload(self, path, data, timeout=None):
        """(status, answer) of a POST whose body is the bytes of one file (POST /bridge/files): the hub's 1 MiB rule of
        a bridge body does not hold for it. Status 0: no answer, also none in its time (FILE_UPLOAD_TIMEOUT)."""
        key = self.key()
        if not key:
            return 0, {"error": "no bridge key"}
        status, _, body = request(self.url + path, "POST", None, {"Authorization": "Bearer " + key},
                                  FILE_UPLOAD_TIMEOUT if timeout is None else timeout,
                                  raw=(data, "application/octet-stream"))
        return status, body if isinstance(body, dict) else {}

    def fetch(self, path, timeout=60, most=FILE_MOST):
        """(status, bytes) of a GET whose answer is not JSON: the bytes of a file of a message (CHAT-APPS.md 20). b""
        with any other status, or with more than `most` bytes."""
        key = self.key()
        if not key:
            return 0, b""
        req = urllib.request.Request(self.url + path, headers={"Authorization": "Bearer " + key})
        try:
            with OPENER.open(req, timeout=timeout) as r:
                data = r.read(most + 1)
                return r.status, data if len(data) <= most else b""
        except urllib.error.HTTPError as e:
            e.close()
            return e.code, b""
        except (OSError, http.client.HTTPException, ValueError):
            return 0, b""


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
    """Repeat a typing signal for each chat until its time ends or a message for that chat goes out. every: the
    seconds between two signals, read at each signal (None: TYPING_EVERY)."""
    def __init__(self, ping, off=None, every=None):
        self.ping, self.off, self.every = ping, off, every
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
                        times[1] = now + (self.every() if self.every else TYPING_EVERY)
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
    # CHAT-APPS.md 20: an adapter that sends a message's files says so; any other one fails such a message, and never
    # sends its words alone with the report "sent" (a third app's adapter sets it once it sends files).
    sends_files = False
    typing_every = None         # the seconds between two typing signals (Typing), when the app's own differ

    def __init__(self, bridge, conf):
        self.bridge, self.id = bridge, conf["id"]
        # When an account of this ID last left the fleet, as the hub gave it when this one started: another time later
        # means that this account was removed and one was added again under its ID (Bridge.refresh).
        self.removed = conf.get("removed")
        self.stopping = threading.Event()
        self.outbox = queue.Queue()
        self.user = self.name = self.application_id = None
        self.typing = Typing(self.typing_on, self.typing_off, self.typing_every)

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
            # The hub counts this item's time from now (CHAT-APPS.md 20): the items of one account go one after the
            # other, so a text behind a message with files waits for its uploads without being lost.
            self.bridge.report_item(item["id"], {"state": "sending", "parts": 0, "platform_ids": [], "error": None})
            try:
                if item.get("files") and not self.sends_files:
                    app = {"whatsapp": "WhatsApp"}.get(self.app, str(self.app).capitalize())
                    result = outcome("failed", [], f"The bridge sends no file to {app} yet.")
                else:
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

    def fetch_files(self, item):
        """The files of a message item (CHAT-APPS.md 20), read from the hub and written into the outbox folder, each
        held to the size and the SHA-256 that the item gave: (paths, None), or (the paths written so far, why not). The
        caller gives the paths to drop_files when the send ends, whatever its outcome."""
        paths = []
        for n, f in enumerate(item.get("files") or [], 1):
            fid, size = f.get("id") if isinstance(f, dict) else None, f.get("size") if isinstance(f, dict) else None
            if not isinstance(fid, int) or isinstance(fid, bool) or not isinstance(size, int) or \
                    not 0 < size <= FILE_MOST or not re.fullmatch(r"[0-9a-f]{64}", str(f.get("sha256") or "")):
                return paths, "The hub described a file of this message in a way that the bridge does not take."
            status, data = self.bridge.hub.fetch(f"/bridge/files/{fid}?item={int(item['id'])}")
            if status != 200 or len(data) != size or hashlib.sha256(data).hexdigest() != f["sha256"]:
                return paths, f"The bridge could not read file {n} of this message from the hub ({status or 'no answer'})."
            path = os.path.join(self.bridge.outbox_dir, f"{int(item['id'])}-{n}")
            try:
                with contextlib.suppress(FileNotFoundError):
                    os.remove(path)
                with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as out:
                    out.write(data)
            except OSError as e:
                return paths, f"The bridge could not write file {n} of this message ({type(e).__name__})."
            paths.append(path)
        return paths, None

    @staticmethod
    def drop_files(paths):
        for path in paths:
            with contextlib.suppress(OSError):
                os.remove(path)

    def fetch_media(self, f, timeout):
        """The bytes of one file that a message of this account brought (its description in the journal event's
        `media`), fetched from the chat app in `timeout` seconds in all; raises Missed. An app whose messages bring no
        `media` fetches nothing."""
        raise Missed("download", f"{self.app} fetches no file")

    def command_item(self, item):
        log(f"{self.app} {self.id}: out {item['id']} {item.get('kind')} does not apply; skipped")

    def typing_on(self, chat):
        pass

    def typing_off(self, chat):
        pass


def multipart(payload, files):
    """(body, content type) of a Discord message with files: payload_json and files[n], Discord's own form. files:
    (name, type, bytes) each; the hub gives names of letters, digits, . _ - and spaces only."""
    boundary = "founderizer-" + os.urandom(12).hex()

    def head(name, filename=None, kind="application/json"):
        named = f'; filename="{filename}"' if filename else ""
        return (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"{named}\r\n"
                f"Content-Type: {kind}\r\n\r\n").encode()
    body = head("payload_json") + json.dumps(payload).encode() + b"\r\n"
    for n, (name, kind, data) in enumerate(files):
        body += head(f"files[{n}]", name, kind) + data + b"\r\n"
    return body + f"--{boundary}--\r\n".encode(), f"multipart/form-data; boundary={boundary}"


class DiscordREST:
    """Discord's REST API for one bot. It obeys the rate-limit headers and `retry_after`."""
    def __init__(self, base, token):
        self.base, self.token = base.rstrip("/"), token     # token: a function, so a new token file counts at once
        self.lock = threading.Lock()
        self.blocked = {}           # route -> monotonic time when its bucket has room again
        self.global_until = 0.0

    def call(self, method, path, body=None, timeout=20, files=None):
        """files: (name, type, bytes) of a message's files, which go with the body in one multipart request."""
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
                                              {"Authorization": "Bot " + token, "User-Agent": USER_AGENT}, timeout,
                                              raw=multipart(body, files) if files else None)
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
    sends_files = True          # with the last part of a message (CHAT-APPS.md 20)

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
        do not. Its files, or a forward's (those of its first snapshot), go as `media`: each one's CDN address, name,
        type and size, which the bridge fetches and uploads before the message (Bridge.files_up)."""
        author = d.get("author") or {}
        if d.get("guild_id") or d.get("type", 0) not in (0, 19) or author.get("bot") or author.get("system"):
            return
        sender, mid, chat = str(author.get("id") or ""), str(d.get("id") or ""), str(d.get("channel_id") or "")
        if not sender or not mid or not chat or sender == self.user:
            return
        attachments, words = d.get("attachments") or [], d.get("content") or ""
        snapshots = d.get("message_snapshots")
        if not attachments and not words and isinstance(snapshots, list) and snapshots and \
                isinstance(snapshots[0], dict) and isinstance(snapshots[0].get("message"), dict):
            forwarded = snapshots[0]["message"]     # a forwarded message: its words and its files are in its snapshot
            attachments, words = forwarded.get("attachments") or [], forwarded.get("content") or ""
        if attachments:
            ctype = str((attachments[0] or {}).get("content_type") or "")
            kind = "image" if ctype.startswith("image/") else "audio" if ctype.startswith("audio/") else "file"
        elif words and not d.get("sticker_items"):
            kind = "text"
        else:
            kind = "other"
        files = [media(a.get("filename"), a.get("content_type"), a.get("size"), url=str(a.get("url") or ""))
                 for a in (attachments if isinstance(attachments, list) else []) if isinstance(a, dict)]
        self.bridge.inbound(with_media({"account": self.id, "id": mid, "chat": chat, "group": False, "sender": sender,
                                        "sender_alt": None, "sender_name": author.get("username"), "bot": False,
                                        "from_me": False, "kind": kind, "text": str(words),
                                        "ts": snowflake_time(mid)}, files))

    def fetch_media(self, f, timeout):
        """An HTTPS GET of the file's address on Discord's CDN, which Discord signed itself: no token goes with it."""
        url = str(f.get("url") or "")
        if not url.startswith(DISCORD_FILES):
            raise Missed("download", "not an address of Discord's CDN")
        return download(url, timeout, {"User-Agent": USER_AGENT})

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
        files, paths = item.get("files") or [], []
        try:
            if files:
                paths, error = self.fetch_files(item)
                if error:
                    return outcome("failed", [], error)
            return self.send_parts(item, chat, split_parts(text, DISCORD_LIMIT), files, paths)
        finally:
            self.drop_files(paths)

    def send_parts(self, item, chat, parts, files, paths):
        """The parts of one message, each with its own nonce; the last one carries the files (CHAT-APPS.md 20)."""
        reply_to = str(item.get("reply_to") or "")
        ids = []
        for n, part in enumerate(parts, 1):
            body = {"content": part, "nonce": f"f{item['id']}p{n}", "enforce_nonce": True}
            if n == 1 and SNOWFLAKE.match(reply_to):
                body["message_reference"] = {"message_id": reply_to, "fail_if_not_exists": False}
            attached = None
            if n == len(parts) and paths:
                body["attachments"] = [{"id": i, "filename": f["name"]} for i, f in enumerate(files)]
                attached = []
                for f, path in zip(files, paths):
                    with open(path, "rb") as fh:
                        attached.append((f["name"], f["mime"], fh.read()))
            backoff = Backoff()
            for attempt in range(SEND_TRIES):
                # a request with up to 10 MB of files: as long as a file part waits for wa-link (WA_FILE_TIMEOUT)
                code, _, answer = self.rest.call("POST", f"/channels/{chat}/messages", body, files=attached,
                                                 timeout=WA_FILE_TIMEOUT if attached else 20)
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


def go_members(tar):
    """The members of Go's archive for a Python with no data filter (TAR_FILTER), held to its rules: each one a folder
    or a regular file whose name stays inside the folder that it goes into, with no set-user-ID, set-group-ID or sticky
    bit and no write for others. It refuses a link, which the filter takes when it stays inside: Homebrew's Go 1.27.2,
    built from go.dev's source archive, has no link in its whole tree. The bytes are the ones whose SHA-256 go.dev
    publishes, so this is the filter's rule again, not a defence of its own. Anything else raises BuildFailed with its
    name."""
    members = tar.getmembers()
    for member in members:
        if not (member.isfile() or member.isdir()):
            why = "which is not a file or a folder"
        elif member.name.startswith("/") or ".." in member.name.split("/"):
            why = "which is outside its folder"
        else:
            member.mode &= 0o755
            continue
        raise BuildFailed(f"the archive of Go {GO_VERSION} cannot be unpacked: it holds {member.name!r}, {why}")
    return members


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
                if TAR_FILTER:
                    tar.extractall(work, filter="data")     # nothing outside work, no device and no set-user-ID file
                else:
                    tar.extractall(work, members=go_members(tar))
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
    sends_files = True          # each file as one more message, through wa-link (CHAT-APPS.md 20)

    def __init__(self, bridge, conf):
        super().__init__(bridge, conf)
        self.db_path = os.path.join(bridge.folder, self.id + ".db")
        self.proc = None
        self.plock = threading.Lock()
        self.waiting = {}           # message ID -> [Event, the "sent" event or None]
        self.wa_state = None
        self.link_state = None
        self.features = set()       # what the running wa-link said it can do (its hello): "file" for a file
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
                self.features = set()           # until its hello: a wa-link of an older source says none
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
        if kind == "hello":
            self.features = {str(f) for f in event.get("features") or [] if isinstance(f, str)}
        elif kind == "message":
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
        files, paths = item.get("files") or [], []
        if files and "file" not in self.features:
            # a wa-link of an older source (its build failed, or FLEET_WA_LINK names one) would send the words alone
            return outcome("failed", [], "The wa-link on the hub machine is too old to send files.")
        try:
            if files:
                paths, error = self.fetch_files(item)
                if error:
                    return outcome("failed", [], error)
            # CHAT-APPS.md 20: a short text is the caption of the first file, so the words and the file are one bubble;
            # a longer one goes in its own parts first. Each file is one message more, with the ID of its part.
            caption = text if files and len(text) <= WA_CAPTION else None
            sends = [{"text": part} for part in ([] if caption is not None else split_parts(text, WHATSAPP_LIMIT))]
            sends += [{"text": caption if n == 0 and caption is not None else "",
                       "file": {"path": path, "name": f["name"], "mime": f["mime"]}}
                      for n, (f, path) in enumerate(zip(files, paths))]
            return self.send_parts(item, db, sends)
        finally:
            self.drop_files(paths)

    def send_parts(self, item, db, sends):
        ids = []
        for n, part in enumerate(sends, 1):
            mid = wa_message_id(db, item["id"], n)
            waiter = self.waiting[mid] = [threading.Event(), None]
            try:
                if not self.command({"op": "send", "id": mid, "to": str(item.get("chat") or ""), "text": part["text"],
                                     "reply_to": (item.get("reply_to") or None) if n == 1 else None,
                                     **({"file": part["file"]} if "file" in part else {})}):
                    return outcome("failed", ids, "wa-link is not running.")
                if not waiter[0].wait(WA_FILE_TIMEOUT if "file" in part else WA_SEND_TIMEOUT) or waiter[1] is None:
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


class TelegramPoll:
    """The one getUpdates request that a Telegram account has open, so that its stop ends the long poll at once."""
    def __init__(self):
        self.lock = threading.Lock()
        self.conn = None

    def set(self, conn):
        with self.lock:
            self.conn = conn

    def close(self):
        with self.lock:
            conn = self.conn
        sock = getattr(conn, "sock", None)
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)


def telegram_call(base, token, method, body=None, timeout=20, poll=None):
    """(status, answer, reached) of one Bot API call: <base>/bot<token>/<method>, a JSON body. status 0: no answer.
    reached is False only when no connection was made, so that nothing can have reached Telegram: a send may then go
    again. The token is in the path, so nothing here ever logs the address or an error's own words."""
    url = urllib.parse.urlsplit(f"{base.rstrip('/')}/bot{token}/{method}")
    cls = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
    conn = cls(url.hostname, url.port, timeout=timeout)
    if poll:
        poll.set(conn)
    try:
        try:
            conn.connect()
        except (OSError, http.client.HTTPException, ValueError):
            return 0, {}, False
        data = json.dumps(body or {}).encode()
        try:
            conn.request("POST", url.path, data, {"Content-Type": "application/json", "Accept": "application/json",
                                                  "User-Agent": "Founderizer-channels"})
            r = conn.getresponse()
            status, raw = r.status, r.read()
        except (OSError, http.client.HTTPException, ValueError):
            return 0, {}, True
    finally:
        if poll:
            poll.set(None)
        conn.close()
    try:
        answer = json.loads(raw) if raw else {}
    except ValueError:
        answer = {}
    return status, answer if isinstance(answer, dict) else {}, True


class Telegram(Account):
    """One bot (CHAT-APPS.md 19.2): a getUpdates long poll, and the Bot API's sends. Telegram keeps an update until a
    later getUpdates confirms it with a higher offset, so each message is in the journal before the bridge asks for the
    next ones: a stop or a crash in between gets the same update again, and the journal and the hub drop the copy."""
    app = "telegram"
    typing_every = staticmethod(lambda: TELEGRAM_TYPING_EVERY)

    def __init__(self, bridge, conf):
        super().__init__(bridge, conf)
        self.token_path = os.path.join(bridge.folder, self.id + ".json")
        self.api = bridge.telegram_api
        self.offset = None          # the next update to ask for; None: the first one that Telegram keeps
        self.bot = None             # the bot's number, from getMe: the first part of each message key
        self.backoff = Backoff()
        self.poll = TelegramPoll()

    def token(self):
        try:
            with open(self.token_path, encoding="utf-8") as f:
                token = json.load(f).get("token")
        except (OSError, ValueError, AttributeError):
            return None
        token = token.strip() if isinstance(token, str) else ""
        return token if TELEGRAM_TOKEN.match(token) else None

    def halt(self):
        self.poll.close()

    def call(self, token, method, body=None, timeout=20, poll=False):
        return telegram_call(self.api, token, method, body, timeout, self.poll if poll else None)

    def run(self):
        while not self.stopping.is_set():
            token = self.token()
            if not token:
                self.set_state("missing_token")
                self.stopping.wait(TOKEN_POLL)
                continue
            result = self.session(token)
            if result == "fatal":       # a token that Telegram does not take: a new token file starts it again
                while not self.stopping.wait(TOKEN_POLL) and self.token() == token:
                    pass
                continue
            if result == "token":
                continue
            self.stopping.wait(self.backoff.next())

    def session(self, token):
        """getMe, then the long poll until a fault, a stop or a new token file."""
        self.set_state("connecting")
        status, me, _ = self.call(token, "getMe")
        if status in (401, 404):
            self.set_state("error", "Telegram does not take this token.")
            return "fatal"
        user = me.get("result") if me.get("ok") else None
        if status != 200 or not isinstance(user, dict) or not isinstance(user.get("id"), int):
            log(f"telegram {self.id}: getMe failed ({status or 'no answer'})")
            return None
        self.meet(str(user["id"]))
        self.name = str(user.get("username") or "") or None
        first = True
        while not self.stopping.is_set():
            if self.token() != token:
                log(f"telegram {self.id}: the token file changed; connecting again")
                return "token"
            body = {"timeout": 0 if first else TELEGRAM_POLL, "allowed_updates": TELEGRAM_UPDATES}
            if self.offset is not None:
                body["offset"] = self.offset
            status, answer, _ = self.call(token, "getUpdates", body, timeout=TELEGRAM_POLL + 15, poll=True)
            if self.stopping.is_set():
                return None
            if status in (401, 404):
                self.set_state("error", "Telegram does not take this token.")
                return "fatal"
            if status == 409:
                self.set_state("error", "Another program reads this bot's updates (a webhook, or a second bridge).")
                return None
            if status == 429:
                self.stopping.wait(min(number((answer.get("parameters") or {}).get("retry_after"), default=1), 60))
                continue
            updates = answer.get("result") if answer.get("ok") else None
            if status != 200 or not isinstance(updates, list):
                log(f"telegram {self.id}: getUpdates failed ({status or 'no answer'})")
                return None
            if first:
                first = False
                self.backoff.reset()
                self.set_state("connected")
            for update in updates:
                uid = update.get("update_id") if isinstance(update, dict) else None
                if not isinstance(uid, int) or isinstance(uid, bool):
                    continue
                if not self.on_update(update):
                    return None         # not kept: the next getUpdates asks for it again
                self.offset = uid + 1
        return None

    def meet(self, bot):
        """The bot that this token is. Another bot than the last one starts from its own updates: an offset of the
        bot before would confirm, and so lose, every update of the new one whose number is lower."""
        if bot != self.bot:
            self.offset = None
        self.bot = self.user = bot

    def on_update(self, update):
        """True when the update is kept (or is one the bridge drops), so that the next getUpdates may confirm it."""
        if isinstance(update.get("message"), dict):
            return self.on_message(update["message"])
        if isinstance(update.get("my_chat_member"), dict):
            return self.on_member(update["my_chat_member"])
        return True

    def on_message(self, msg):
        """A person's message in a private chat goes to the journal. A bot's, a group's and a channel's do not: in a
        group, the bot only posts (19.5). A group that became a supergroup tells the hub its new number. The words of
        a picture, a file or a voice note are its caption, which goes as its text, as Discord's and WhatsApp's words
        do (CHAT-APPS.md 8.1). Its file goes as `media`, of any kind (a photo, its largest size, or the file of
        TELEGRAM_FILES): its file id, name, type and size, which the bridge fetches with getFile and uploads before
        the message (Bridge.files_up)."""
        chat, sender = msg.get("chat") or {}, msg.get("from") or {}
        kind, cid, mid, uid = chat.get("type"), chat.get("id"), msg.get("message_id"), sender.get("id")
        if not isinstance(cid, int):
            return True
        if kind in ("group", "supergroup"):
            moved = msg.get("migrate_to_chat_id")
            if isinstance(moved, int) and moved != cid:
                return self.place({"account": self.id, "chat": str(cid), "moved_to": str(moved)})
            return True
        if kind != "private" or sender.get("is_bot") or not isinstance(uid, int) or not isinstance(mid, int):
            return True
        if msg.get("text"):
            what = "text"
        elif msg.get("photo"):
            what = "image"
        elif msg.get("voice") or msg.get("audio"):
            what = "audio"
        elif msg.get("document"):
            what = "file"
        elif any(msg.get(k) for k in TELEGRAM_OTHER):
            what = "other"
        else:
            return True         # Telegram's own message in the chat (a pin, the auto-delete timer): nobody wrote it
        name = " ".join(str(x) for x in (sender.get("first_name"), sender.get("last_name")) if x) or \
            str(sender.get("username") or "") or None
        files, photo = [], msg.get("photo")
        sizes = [p for p in photo if isinstance(p, dict) and isinstance(p.get("file_id"), str) and p["file_id"]] \
            if isinstance(photo, list) else []
        if sizes:           # Telegram gives a photo in several sizes, the largest last: the largest one goes up
            big = max(sizes, key=lambda p: (number(p.get("width"), default=0) * number(p.get("height"), default=0),
                                            number(p.get("file_size"), default=0)))
            files = [media("photo.jpg", "image/jpeg", big.get("file_size"), file_id=big["file_id"])]
        for field, default in TELEGRAM_FILES:      # the name of a file that comes with none
            item = msg.get(field)
            if files or not isinstance(item, dict) or not isinstance(item.get("file_id"), str) or not item["file_id"]:
                continue
            if field == "sticker":      # a sticker has no type of its own: its kind gives one
                default = "sticker.tgs" if item.get("is_animated") else "sticker.webm" if item.get("is_video") else \
                    default
            files = [media(item.get("file_name") or default, item.get("mime_type"), item.get("file_size"),
                           file_id=item["file_id"])]
        return self.bridge.inbound(with_media({"account": self.id, "id": f"{self.bot}:{cid}:{mid}", "chat": str(cid),
                                               "group": False, "sender": str(uid), "sender_alt": None,
                                               "sender_name": name, "bot": False, "from_me": False, "kind": what,
                                               "text": str(msg.get("text" if what == "text" else "caption") or ""),
                                               "ts": number(msg.get("date"), default=time.time())}, files))

    def fetch_media(self, f, timeout):
        """getFile, then the file's own address, <api>/file/bot<token>/<file_path>, which holds the bot's token: nothing
        here puts the address into a reason. Telegram gives a bot a file of at most 20 MB so: a larger one is `size`,
        with no getFile, which would refuse it."""
        end, token, fid, size = time.monotonic() + timeout, self.token(), f.get("file_id"), f.get("size")
        if isinstance(size, int) and not isinstance(size, bool) and size > TELEGRAM_FILE_MOST:
            raise Missed("size", "more than Telegram gives a bot")
        if not token:
            raise Missed("download", "no bot token")
        if not isinstance(fid, str) or not fid:
            raise Missed("download", "no file id")
        status, answer, _ = self.call(token, "getFile", {"file_id": fid},
                                      timeout=max(0.1, min(20.0, end - time.monotonic())))
        result = answer.get("result") if answer.get("ok") else None
        path = result.get("file_path") if isinstance(result, dict) else None
        if status != 200 or not isinstance(path, str) or not path or path.startswith("/") or \
                ".." in path.split("/") or re.search(r"[\x00-\x20\x7f]", path):
            raise Missed("download", f"getFile answered {status or 'nothing'}")
        return download(f"{self.api.rstrip('/')}/file/bot{token}/{urllib.parse.quote(path)}", end - time.monotonic())

    def on_member(self, change):
        """The bot's own status changed in a chat: in a group or a channel, the hub gets it, with who changed it
        (19.5). A private chat's (a person stopped or started the bot) is dropped."""
        chat, new = change.get("chat") or {}, change.get("new_chat_member") or {}
        kind, cid, status = chat.get("type"), chat.get("id"), new.get("status")
        if kind not in ("group", "supergroup", "channel") or not isinstance(cid, int) or status not in TELEGRAM_STATUSES:
            return True
        if kind == "channel":
            can_post = status == "creator" or (status == "administrator" and new.get("can_post_messages") is True)
        else:
            can_post = status in ("creator", "administrator", "member") or \
                (status == "restricted" and new.get("can_send_messages") is True)
        by = (change.get("from") or {}).get("id")
        title, username = chat.get("title"), chat.get("username")
        return self.place({"account": self.id, "chat": str(cid), "kind": kind, "status": status, "can_post": can_post,
                           "title": str(title)[:255] if title else None,
                           "username": str(username) if username else None,
                           "by": str(by) if isinstance(by, int) and by > 0 else None})

    def place(self, body):
        """POST /bridge/places until the hub answers. False when the bridge stops first: the update is asked for
        again. A body that the hub refuses, or a hub with no such route, lets the update go."""
        backoff = Backoff()
        while not self.stopping.is_set():
            code, _ = self.bridge.hub.call("POST", "/bridge/places", body)
            if code == 200:
                log(f"telegram {self.id}: a group or channel change went to the hub")
                return True
            if code in (400, 404, 409):
                log(f"telegram {self.id}: the hub refused a group or channel change ({code}); let go")
                return True
            self.stopping.wait(backoff.next())
        return False

    def reply_id(self, reply_to, chat):
        """Telegram's own number of the message that a reply answers, when it is in this chat of this bot."""
        parts = str(reply_to or "").split(":")
        if len(parts) == 3 and parts[0] == self.bot and parts[1] == chat and parts[2].isdigit():
            return int(parts[2])
        return None

    def send(self, item, db):
        token = self.token()
        if not token:
            return outcome("failed", [], "The bot has no token on the hub machine.")
        chat = str(item.get("chat") or item.get("recipient") or "")
        if not TELEGRAM_CHAT.match(chat):
            return outcome("failed", [], "The chat is not a Telegram chat number.")
        text = str(item.get("text") or "")
        if item.get("prefix"):
            text = f"**{item['prefix']}:** " + text
        reply = self.reply_id(item.get("reply_to"), chat)
        ids = []
        for n, part in enumerate(split_parts(text, TELEGRAM_LIMIT), 1):
            if n > 1:
                time.sleep(TELEGRAM_PART_GAP)
            body = {"chat_id": chat, "text": tg_format(part), "parse_mode": "HTML"}
            if n == 1 and reply is not None:
                body["reply_parameters"] = {"message_id": reply, "allow_sending_without_reply": True}
            state, said = self.send_part(token, body, part, n, lambda: self.bridge.report_item(
                item["id"], {"state": "sending", "parts": 0, "platform_ids": [], "error": None}))
            if state != "sent":
                return outcome(state, ids, said)
            ids.append(said)
        return outcome("sent", ids)

    def send_part(self, token, body, part, n, begin=lambda: None):
        """("sent", the part's message key) or (state, error). A request that reached no Telegram server, a 429 and a
        refused HTML sent nothing, so they go again: the HTML as plain text. A lost answer is unknown, never a second
        try: Telegram has no idempotency key, so a second try could be a second message (19.2). Before each wait of a
        429, begin() tells the hub that the item begins again (CHAT-APPS.md 20): a wait can be longer than the hub's
        window of a sending item, and an item that the hub made unknown meanwhile could be sent twice by Send again."""
        tries = waits = 0
        backoff = Backoff()
        while True:
            status, answer, reached = self.call(token, "sendMessage", body)
            if status == 200 and answer.get("ok"):
                mid = (answer.get("result") or {}).get("message_id")
                return "sent", f"{self.bot}:{body['chat_id']}:{mid}"
            if status == 0:
                if reached:
                    return "unknown", f"Telegram did not confirm part {n}."
                tries += 1
                if tries >= TELEGRAM_TRIES:
                    return "failed", "The bridge could not reach Telegram."
                time.sleep(backoff.next())
                continue
            params = answer.get("parameters") if isinstance(answer.get("parameters"), dict) else {}
            said = str(answer.get("description") or "")[:200]
            if status == 429 and waits < TELEGRAM_WAITS:
                waits += 1
                wait = number(params.get("retry_after"), default=1.0)
                if wait > 60:
                    return "failed", f"Telegram asks the bot to wait {int(wait)} seconds before it sends again."
                begin()
                time.sleep(wait)
                continue
            if status == 400 and "parse_mode" in body and "entit" in said.lower():
                body = {k: v for k, v in body.items() if k != "parse_mode"}
                body["text"] = tg_plain(part)
                continue
            moved = params.get("migrate_to_chat_id")
            if isinstance(moved, int) and str(moved) != body["chat_id"]:
                self.place({"account": self.id, "chat": body["chat_id"], "moved_to": str(moved)})
                body = dict(body, chat_id=str(moved))
                continue
            if status >= 500:
                return "unknown", f"Telegram answered HTTP {status} for part {n}."
            return "failed", f"Telegram refused part {n}: HTTP {status}: {said}".strip()

    def typing_on(self, chat):
        token = self.token()
        if token and TELEGRAM_CHAT.match(chat):
            status, _, _ = self.call(token, "sendChatAction", {"chat_id": chat, "action": "typing"})
            if status != 200:
                log(f"telegram {self.id}: typing signal failed ({status or 'no answer'})")


APPS = {"discord": Discord, "whatsapp": WhatsApp, "telegram": Telegram}


# ---------------------------------------------------------------- the bridge

class Bridge:
    def __init__(self, folder, hub, gateway=GATEWAY, api=DISCORD_API, telegram_api=TELEGRAM_API):
        self.folder, self.gateway, self.api, self.telegram_api = folder, gateway, api, telegram_api
        os.makedirs(folder, mode=0o700, exist_ok=True)
        os.chmod(folder, 0o700)
        self.hub = Hub(hub, os.path.join(folder, "bridge.key"))
        self.journal = Journal(os.path.join(folder, "journal"))
        # CHAT-APPS.md 20: the files of the messages on their way, which wa-link reads beside its database. A file
        # stays only while its message is sent, so what a stop left goes now.
        self.outbox_dir = os.path.abspath(os.path.join(folder, OUTBOX))    # wa-link takes the clean, absolute path only
        os.makedirs(self.outbox_dir, mode=0o700, exist_ok=True)
        os.chmod(self.outbox_dir, 0o700)
        for name in os.listdir(self.outbox_dir):
            with contextlib.suppress(OSError):
                os.remove(os.path.join(self.outbox_dir, name))
        self.stopping = threading.Event()
        self.lock = threading.Lock()
        self.accounts = {}
        self.states = {}
        self.configured, self.version = False, None
        self.inbound_due = threading.Event()
        # files_up's memory, in this process only (the journal does not change): for each journal path, when the hub
        # took each file ("up", by its number) and the attempts that it kept each one ("tries"; 0 is the hub's
        # question); and (path, number, bytes) of the one file whose upload got no answer, which goes again as it is
        self.files_seen, self.file_held = {}, None
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
        """Post the journal to the hub, oldest first, until the hub answers. Replays what a restart left. The files of
        a message go up first, at each attempt (files_up), and the message goes with the codes of those that did not
        and without its `media`."""
        backoff = Backoff()
        while not self.stopping.is_set():
            self.inbound_due.clear()
            retry = False
            for path, event in self.journal.pending():
                if self.stopping.is_set():
                    return
                where = f"{event.get('account')} {event.get('id')}"
                missed = self.files_up(path, event, where)
                if missed is None:
                    retry = True
                    break
                body = {k: v for k, v in event.items() if k not in ("media", "media_more")}
                if missed:
                    body["missed"] = missed
                code, answer = self.hub.call("POST", "/bridge/inbound", body)
                if code == 200:
                    self.journal.remove(path)
                    self.forget_files(path)
                    log(f"inbound {where}: {answer.get('result')}")
                elif code in (400, 413) or (code == 409 and answer.get("error") == "unknown chat app account"):
                    # a bad event, or one of an account that the hub does not have (any more): it never gets in
                    self.journal.remove(path)
                    self.forget_files(path)
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

    def files_up(self, path, event, where):
        """The files of an inbound event (its `media`), in their order and numbered 1 to FILES_IN, each held to its chat
        app's size, fetched by its account and uploaded to POST /bridge/files. Before the first fetch of an attempt the
        hub says whether it takes this sender's files now (check=1), so that a stranger's file costs no download and
        the other messages no wait. A file that the hub took is not sent again for FILE_UP_FOR, and the bytes of the
        one file whose upload got no answer go again with no new fetch: an address of the chat app can end meanwhile.
        The codes of the files that did not come up (at most MISSED_MOST), or None when the event waits for the next
        attempt: the hub gave no answer to its question or to an upload, or a 5xx, or an answer that the interface
        does not name (for FILE_TRIES attempts of the entry in all, whatever its number of files: then its files that
        are left are `refused` with no fetch and the message goes on; if the hub takes no message either, the next
        attempt asks again, and a hub that comes back gets the files), or the bridge has not read its accounts yet (at
        a start, the journal replays first)."""
        files, more = event.get("media"), event.get("media_more")
        files = [f if isinstance(f, dict) else {} for f in files] if isinstance(files, list) else []
        more = more if isinstance(more, int) and not isinstance(more, bool) and more > 0 else 0
        if not files and not more:
            return []
        with self.lock:
            account, configured = self.accounts.get(str(event.get("account") or "")), self.configured
        if account is None and not configured:
            log(f"inbound {where}: the bridge does not run its account yet; kept")
            return None
        seen = self.files_seen.setdefault(path, {"up": {}, "kept": 0})
        done = seen["up"]

        def kept():
            """Whether the entry waits for the next attempt after one more that got no answer, of the hub's question or
            of an upload: FILE_TRIES of them for the whole entry, whatever its number of files. Past them, the files
            that are left are `refused` with no fetch, and the message goes on."""
            seen["kept"] += 1
            return seen["kept"] < FILE_TRIES

        missed, up, asked, refused_all = [], 0, False, False
        for n, f in enumerate(files[:FILES_IN], 1):
            if self.stopping.is_set():
                return None
            if n in done and time.monotonic() - done[n] < FILE_UP_FOR:      # the hub keeps it for its message
                up += 1
                continue
            data, held = None, self.file_held
            if held and held[:2] == (path, n):
                data, self.file_held = held[2], None
            try:
                mime, size = file_type(f.get("mime"), f.get("name")), f.get("size")
                if data is None:
                    if isinstance(size, int) and not isinstance(size, bool) and size > FILE_MOST:
                        raise Missed("size")
                    if refused_all:     # the hub refused this message's sender or account: it refuses each file
                        raise Missed("refused")
                    if account is None:
                        raise Missed("download", "the bridge does not run its account")
                    if not asked:       # at each attempt: a hub that is down costs no download
                        asked = refused_all = True      # until the hub says yes: a fault here refuses them all
                        code, _ = self.hub.upload(upload_path(event, n, f, mime, check=True), b"")
                        if code == 0 or code >= 500:
                            if kept():
                                log(f"inbound {where}: the hub did not say whether it takes the files "
                                    f"({code or 'no answer'}); kept")
                                return None
                            raise Missed("refused", f"no answer of the hub in {FILE_TRIES} attempts")
                        if code in (400, 403, 409):
                            raise Missed("refused", f"the hub answered {code}")
                        refused_all = False     # a yes, or an answer that only the upload's own answer settles
                    try:
                        data = account.fetch_media(f, FILE_FETCH_TIMEOUT)
                    except Missed:
                        raise
                    except Exception as e:      # a fault of one fetch must not stop the journal
                        raise Missed("download", type(e).__name__) from None
                code, _ = self.hub.upload(upload_path(event, n, f, mime), data)
                if code == 200:
                    done[n] = time.monotonic()
                    up += 1
                    continue
                if code == 413:
                    raise Missed("size", "the hub answered 413")
                if code in (400, 403, 409, 415, 422):
                    # 403 and 409 are of the message's sender or account (409: the hub has no such account, and the
                    # message's own post lets it go), so they are the answer for its other files too. A 415 is bytes
                    # that are not of their type, an empty file or a text that is not UTF-8; a 400 comes again at
                    # each attempt: kept, the message would wait for ever.
                    refused_all = refused_all or code in (403, 409)
                    raise Missed("refused", f"the hub answered {code}")
                # these bytes go again at the next attempt, with no new fetch; past FILE_TRIES too, when the hub then
                # takes no message either (it is down): a hub that comes back gets the file
                self.file_held = (path, n, data)
                if not kept():
                    refused_all = True          # the files after it go with this one: no fetch, no upload
                    raise Missed("refused", f"no answer of the hub in {FILE_TRIES} attempts ({code or 'none'})")
                log(f"inbound {where}: the hub did not take file {n} ({code or 'no answer'}); kept")
                return None
            except Missed as e:
                missed.append(e.code)
                if e.why:
                    log(f"inbound {where}: file {n} {e.code} ({e.why})")
            except Exception as e:      # a name or an id that no query can hold, or another fault after the fetch
                missed.append("refused")
                log(f"inbound {where}: file {n} refused ({type(e).__name__})")
        missed = (missed + ["many"] * min(more, MISSED_MOST))[:MISSED_MOST]
        log(f"inbound {where}: {up} of {len(files) + more} file(s) came up" +
            (f"; missed {', '.join(missed)}" if missed else ""))
        return missed

    def forget_files(self, path):
        """files_up's memory of an entry that left the journal."""
        self.files_seen.pop(path, None)
        if self.file_held and self.file_held[0] == path:
            self.file_held = None

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
            # files=1: this bridge sends the files of a message (CHAT-APPS.md 20); the hub keeps an item with files
            # back from a bridge that does not say so, which would send its words alone and report it sent
            code, answer = self.hub.call("GET", f"/bridge/out?wait={OUT_WAIT}&files=1", timeout=OUT_WAIT + 15)
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
    return ("[Unit]\nDescription=Founderizer chat apps bridge (Discord, Telegram and WhatsApp)\n"
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
