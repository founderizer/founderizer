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
import json
import os
import re
import shutil
import tempfile
import urllib.error
import urllib.request

FORMAT = 1
NAME = re.compile(r"teams_[a-z0-9_]{1,40}\.(?:py|json)|TEAMS-LICENSE\.md")
MOST_FILES = 64
MOST_BYTES = 4 * 1024 * 1024
LOCK_KEYS = ("files", "format", "sha256", "size")
SHA256 = re.compile(r"[0-9a-f]{64}")
FETCH_WAIT = 30         # seconds for the one GET of a package
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
    except ValueError as e:         # UnicodeDecodeError is one too
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
    lower-case hex characters, or a size that is no whole number from 1 to MOST_BYTES."""
    try:
        lock = json.loads(text)
    except (TypeError, ValueError):
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
    except (TypeError, ValueError):
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


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an answer, not a way: urllib sends the request's headers on to the address of a redirect, and
    the token must reach no other address."""

    def redirect_request(self, *args, **kwargs):
        return None


def fetch(address, lock, token, wait=FETCH_WAIT):
    """One GET of the package that `lock` names at `address`, with `token` as the bearer of its Authorization header
    and nowhere else: no proxy that the environment names, no redirect, `wait` seconds, and at most the lock's size
    and one byte read. (200, the bytes) for an answer 200 of at most the lock's size; else (the status, or 0 when
    nothing answered, and the reason in words). It checks no hash: `place` does."""
    try:
        want = checked(lock)
    except ValueError:
        return 0, "no lock"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(address, method="GET", headers={
        "Accept": "application/octet-stream", "User-Agent": "founderizer-hub", "Authorization": "Bearer " + token})
    try:
        with opener.open(request, timeout=wait) as answer:
            status, body = answer.status, answer.read(want["size"] + 1)
    except urllib.error.HTTPError as answer:
        with answer:
            return answer.code, f"the channel answered {answer.code}"
    except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
        return 0, "the channel did not answer: " + str(getattr(e, "reason", e))[:300]
    except ValueError:      # an address or a header that urllib or http.client refuses, whose words can quote the token
        return 0, "no request could be made of that address and token"
    if status != 200:
        return status, f"the channel answered {status}"
    if len(body) > want["size"]:
        return status, f"an answer of more than the lock's {want['size']} bytes"
    return status, body
