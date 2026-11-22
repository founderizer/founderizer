"""The package of the Teams code and its lock (Founderizer for Teams, design 2, section 3.3).

The Teams code is never published. A release names it by a hash: `publish.py` builds the package of the Teams files
of the same source and writes its lock, the file `teams.lock`, into the published tree. The release's signature names
the revision, the revision fixes the tree, and the tree holds the lock, so a copy of the channel that is taken over can
keep a package back and cannot give a hub other code. This module holds the format, for the hub and the tests. It is
standard library only, in the syntax of Python 3.10, and it imports no module of the hub: a hub with no licence never
calls it. `publish.py` writes the rule of `pack` and of the lock again (its own reason is there), and test_publish
holds the two copies equal.

- **The package** is one text of JSON, `{"files": {"<name>": "<text>", ...}, "format": 1}`, with sorted keys, no
  spaces, ASCII only and one line end, so the same files give the same bytes on each machine and each Python. Each
  name is `teams_<name>.py`, `teams_<name>.json` or `TEAMS-LICENSE.md` (NAME): no folder, so no file is written
  outside its folder. Each file is UTF-8 text. At most MOST_FILES files and MOST_BYTES bytes.
- **The lock** is one line of JSON: `{"files": 3, "format": 1, "sha256": "<64 hex>", "size": 51234}`. `files` counts
  the Python files, so the lock of a package that holds only the licence names no part.
- **A package on a hub** is the folder `<root>/<sha256>/`, mode 700, with each file at mode 600. `have` takes it only
  while the package of its files has the lock's hash, so a changed, added or removed file is found.
"""
import hashlib
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import tempfile
import threading
import time
import urllib.parse

FORMAT = 1
NAME = re.compile(r"teams_[a-z0-9_]{1,40}\.(?:py|json)|TEAMS-LICENSE\.md")
MOST_FILES = 64
MOST_BYTES = 4 * 1024 * 1024
LOCK_KEYS = ("files", "format", "sha256", "size")
SHA256 = re.compile(r"[0-9a-f]{64}")
FETCH_WAIT = 30         # seconds for the one GET of a package, all of it
FETCH_PIECE = 65536     # bytes of one read of the body of an answer (fetch)
PYCACHE = "__pycache__"  # what Python writes into a folder that it imports from, and no file of a package
PART = ".part-"         # how a folder begins that `place` writes before its one rename, or moves aside


def pack(files):
    """The package of `files`, {name: text}, as bytes. ValueError for a name that no package holds, a file that is no
    text (no str, a NUL, or a character that UTF-8 cannot hold) and a package above the limits."""
    if not isinstance(files, dict):
        raise ValueError("the files of a package are {name: text}")
    if len(files) > MOST_FILES:
        raise ValueError(f"{len(files)} files, and a package holds at most {MOST_FILES}")
    for name, text in files.items():
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise ValueError(f"{name!r} is no name of a file of a package")
        if not isinstance(text, str) or "\0" in text:
            raise ValueError(f"{name} is no text")
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError(f"{name} is no UTF-8 text") from None
    data = (json.dumps({"files": files, "format": FORMAT}, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("ascii")
    if len(data) > MOST_BYTES:
        raise ValueError(f"{len(data)} bytes, and a package holds at most {MOST_BYTES}")
    return data


def unpacked(data):
    """{name: text} of the package `data`, or ValueError: bytes above the limit, bytes that are no package of this
    format, a name or a file that `pack` refuses, and a package that is not in its one form (pack of its files gives
    other bytes), so that the hash of a lock names one set of files and nothing else."""
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("a package is bytes")
    if len(data) > MOST_BYTES:
        raise ValueError(f"{len(data)} bytes, and a package holds at most {MOST_BYTES}")
    try:
        whole = json.loads(bytes(data).decode("ascii"))
    except (ValueError, RecursionError) as e:       # UnicodeDecodeError is one too; RecursionError: JSON too deep
        raise ValueError(f"no package: {e}") from None
    if not isinstance(whole, dict) or set(whole) != {"files", "format"} or not isinstance(whole["files"], dict):
        raise ValueError("no package: not the two fields files and format")
    if whole["format"] != FORMAT:
        raise ValueError(f"a package of format {whole['format']!r}, and this code reads format {FORMAT}")
    if pack(whole["files"]) != bytes(data):
        raise ValueError("a package that is not in its one form")
    return whole["files"]


def lock_of(data):
    """The lock of the package `data` (ValueError as `unpacked`)."""
    files = unpacked(data)
    return {"files": sum(1 for name in files if name.endswith(".py")), "format": FORMAT,
            "sha256": hashlib.sha256(bytes(data)).hexdigest(), "size": len(data)}


def lock_text(lock):
    """The text of the file teams.lock for `lock`: one line of JSON with sorted keys."""
    return json.dumps({key: lock[key] for key in LOCK_KEYS}, sort_keys=True) + "\n"


def read_lock(text):
    """The lock that `text` holds, checked field by field, or None for a text that is no lock: no JSON object, a key
    more or less, a count that is no whole number from 0 to MOST_FILES, another format, a SHA-256 that is not 64
    lower-case hex characters, or a size that is no whole number from 1 to MOST_BYTES. JSON nested too deep for the
    parser (RecursionError) is no lock either."""
    try:
        lock = json.loads(text)
    except (TypeError, ValueError, RecursionError):
        return None
    if not isinstance(lock, dict) or set(lock) != set(LOCK_KEYS):
        return None
    files, form, sha256, size = (lock[key] for key in LOCK_KEYS)
    if not (type(files) is int and 0 <= files <= MOST_FILES and type(form) is int and form == FORMAT
            and isinstance(sha256, str) and SHA256.fullmatch(sha256)
            and type(size) is int and 0 < size <= MOST_BYTES):
        return None
    return {key: lock[key] for key in LOCK_KEYS}


def checked(lock):
    """`lock` as read_lock reads it, or ValueError."""
    try:
        found = read_lock(json.dumps(lock))
    except (TypeError, ValueError, RecursionError):
        found = None
    if found is None:
        raise ValueError("no lock")
    return found


def folder_pack(folder):
    """The package of the files of `folder`, read as bytes and as UTF-8, every byte kept. Python's own `__pycache__`
    is left out. ValueError for anything else that is no file of a package (a link, a folder, a name that `pack`
    refuses) and for a file that is no UTF-8 text; OSError when the folder cannot be read."""
    files = {}
    for name in sorted(os.listdir(folder)):
        path = os.path.join(folder, name)
        if name == PYCACHE and os.path.isdir(path) and not os.path.islink(path):
            continue
        if os.path.islink(path) or not os.path.isfile(path):
            raise ValueError(f"{name} is no file of a package")
        with open(path, "rb") as f:
            raw = f.read(MOST_BYTES + 1)
        try:
            files[name] = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError(f"{name} is no UTF-8 text") from None
    return pack(files)


def have(lock, root):
    """The folder of the package that `lock` names, `<root>/<sha256>`, when the package of its files has the lock's
    hash; else None (no such folder, a file changed, added or taken away, a lock that is no lock)."""
    try:
        sha256 = checked(lock)["sha256"]
        folder = os.path.join(root, sha256)
        if not os.path.islink(folder) and os.path.isdir(folder) \
                and hashlib.sha256(folder_pack(folder)).hexdigest() == sha256:
            return folder
    except (OSError, ValueError):
        pass
    return None


def place(data, lock, root):
    """The package `data` in `<root>/<sha256>/`, and that folder. It checks the size and the SHA-256 against `lock`
    first, and raises ValueError with nothing written for bytes that the lock does not name, and for a package that
    `unpacked` refuses. It writes a temporary folder of `root` and moves it into its place with one rename, so a
    half-written package is never at that name; a folder at that name that is not the package goes. `root` and the
    folder are mode 700, and each file mode 600."""
    want = checked(lock)
    if len(data) != want["size"] or hashlib.sha256(bytes(data)).hexdigest() != want["sha256"]:
        raise ValueError("bytes whose size or SHA-256 is not the lock's")
    files = unpacked(data)
    if lock_of(data) != want:
        raise ValueError("a lock whose count of Python files is not the package's")
    final = os.path.join(root, want["sha256"])
    if have(want, root):
        return final
    os.makedirs(root, mode=0o700, exist_ok=True)
    work = tempfile.mkdtemp(prefix=PART, dir=root)
    try:
        for name, text in files.items():
            path = os.path.join(work, name)
            with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
                f.write(text.encode("utf-8"))
            os.chmod(path, 0o600)
        os.chmod(work, 0o700)
        if os.path.lexists(final):
            gone = tempfile.mkdtemp(prefix=PART, dir=root)
            os.rename(final, os.path.join(gone, "gone"))
            shutil.rmtree(gone, ignore_errors=True)
        os.rename(work, final)
    finally:
        if os.path.isdir(work):
            shutil.rmtree(work, ignore_errors=True)
    return final


def prune(root, keep):
    """Remove each package of `root` whose SHA-256 is not in `keep`, and each folder that `place` left behind. Nothing
    else of `root` is touched. The names it removed."""
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return []
    removed = []
    for name in names:
        path = os.path.join(root, name)
        if (SHA256.fullmatch(name) and name not in keep or name.startswith(PART)) \
                and os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path, ignore_errors=True)
            removed.append(name)
    return removed


def loopback(host):
    """True for a literal address of this machine's loopback (127.0.0.0/8, ::1), the one host that fetch asks over
    http: a test's stand-in of the channel. A name is no such address: what it resolves to is not this code's to say."""
    try:
        return ipaddress.ip_address(host).is_loopback
    except (TypeError, ValueError):
        return False


NO_REQUEST = "no request could be made of that address and token"
ONLY_HTTPS = "a package is asked for only over https, and over http only of this machine's loopback address"


def fetch(address, lock, token, wait=FETCH_WAIT):
    """One GET of the package that `lock` names at `address`, with `token` as the bearer of its Authorization header
    and nowhere else. (200, the bytes) for an answer 200 of at most the lock's size; else (the status, or 0 when
    nothing answered, and the reason in words that never quote the token). It checks no hash: `place` does.

    - **https only**, with the certificate and the name checked; http only to a literal loopback address (a test's
      stand-in). Any other scheme (file:, ftp:, data:) and http to any other host is refused before a connection,
      because the bearer would go in clear or to no channel at all.
    - **No proxy and no redirect.** http.client reads no proxy that the environment names and follows nothing, so the
      token reaches only the host of `address`. A redirect is an answer: its status.
    - **`wait` seconds for the whole GET**: the connection, the TLS handshake, the request, the head and the body
      together, and not only each read of the socket (its own timeout): at the limit a timer shuts the socket down,
      so a channel that sends one byte at a time holds the one release thread no longer than that. This code makes
      the connection and the TLS socket itself, before its handshake, so that the timer reaches the socket of each
      step (http.client's own connect wraps a socket that the timer still names, and that socket is detached then).
      Only the lookup of the host's name before the connection is the system's own, with the system's limits.
    - A certificate that does not verify is said in its own words (ssl.SSLCertVerificationError is a ValueError
      too, and is no request that could not be made).
    - At most the lock's size and one byte of the body are read, in pieces.
    - An address that is no text, whose port is no number, or whose host http.client refuses, and a token that is no
      text or that no header can carry, make no request (the words of such a refusal can quote the token)."""
    try:
        want = checked(lock)
    except ValueError:
        return 0, "no lock"
    try:
        if not isinstance(address, str) or not isinstance(token, str):
            raise TypeError("an address and a token are text")
        parts = urllib.parse.urlsplit(address)
        if not (parts.scheme == "https" or parts.scheme == "http" and loopback(parts.hostname)):
            return 0, ONLY_HTTPS
        host, port = parts.hostname, parts.port         # .port: ValueError for a port that is no number
        if not host:
            raise ValueError("no host")
        if parts.scheme == "https":
            context = ssl.create_default_context()
            conn = http.client.HTTPSConnection(host, port or 443, timeout=wait, context=context)
        else:
            context, conn = None, http.client.HTTPConnection(host, port or 80, timeout=wait)
        target = (parts.path or "/") + ("?" + parts.query if parts.query else "")
        headers = {"Accept": "application/octet-stream", "User-Agent": "founderizer-hub",
                   "Authorization": "Bearer " + token}
    except (TypeError, ValueError, http.client.InvalidURL):
        return 0, NO_REQUEST
    except OSError as e:            # this machine's certificates for TLS (ssl.SSLError), which hold no token
        return 0, "no request could be made: " + str(e)[:300]
    ended = threading.Event()

    def cut():
        """The limit of the whole GET: a read or a write that waits on the socket ends at once."""
        ended.set()
        sock = conn.sock
        if sock is not None:
            try:
                socket.socket.shutdown(sock, socket.SHUT_RDWR)
            except OSError:
                pass
    deadline = time.monotonic() + wait
    timer = threading.Timer(wait, cut)
    timer.daemon = True
    timer.start()
    try:
        conn.sock = socket.create_connection((conn.host, conn.port), timeout=wait)
        if ended.is_set():          # the timer came during the connection, when no socket was there to shut
            raise TimeoutError()
        if context is not None:
            conn.sock = context.wrap_socket(conn.sock, server_hostname=host, do_handshake_on_connect=False)
            if ended.is_set():      # the timer came while the socket changed hands: the handshake has no limit
                raise TimeoutError()
            conn.sock.do_handshake()
        conn.request("GET", target, headers=headers)
        answer = conn.getresponse()
        status, body = answer.status, b""
        while status == 200 and len(body) <= want["size"] and time.monotonic() < deadline:
            piece = answer.read1(min(FETCH_PIECE, want["size"] + 1 - len(body)))
            if not piece:
                break
            body += piece
    except ssl.SSLCertVerificationError as e:
        return 0, "the channel's certificate did not verify: " + str(getattr(e, "verify_message", None) or e)[:300]
    except (ValueError, http.client.InvalidURL):    # a header or a path that http.client refuses, in words of its own
        return 0, NO_REQUEST
    except (OSError, http.client.HTTPException) as e:
        if ended.is_set() or time.monotonic() >= deadline:      # the timer's cut, or a socket's own end at the limit
            return 0, f"the channel did not answer whole in {wait} seconds"
        return 0, "the channel did not answer: " + str(e)[:300]
    finally:
        timer.cancel()
        conn.close()
    if status != 200:
        return status, f"the channel answered {status}"
    if len(body) > want["size"]:
        return status, f"an answer of more than the lock's {want['size']} bytes"
    if len(body) < want["size"] and (ended.is_set() or time.monotonic() >= deadline):
        return 0, f"the channel did not answer whole in {wait} seconds"
    return status, body
