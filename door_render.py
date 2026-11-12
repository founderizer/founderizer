#!/usr/bin/env python3
"""The door's render helper: what a GitOps commit makes a cluster apply. Standard library only.

    python3 door_render.py box      one request on standard input, one JSON answer on standard output. systemd starts
                                    it for each connection to the door's render socket (door.py, ensure_render), in a
                                    box with no network and no key of the door.

A GitOps repository holds charts and Kustomize folders, and a cluster applies what they render, not their files. So a
line reader of a file cannot say what a commit does: a value and the template that uses it are two files, a template
builds a key from parts, and a patch changes an object of another file. The helper renders each chart and each
Kustomize folder that a commit touches, at HEAD and after the commit, with the two programs that ArgoCD runs, and
gives back the objects that differ. door_targets decides on them, outside the box.

It reads YAML with Helm's own parser (a chart of its own, READER, with fromYaml and toJson), which is the parser of
kubectl and ArgoCD. So no spelling of a manifest reads one way here and another way in the cluster.

The programs are pinned (PINS). The door's update puts them in TOOLS_DIR as root's files. The helper renders nothing
outside the box (boxed), and a caller that gets no render keeps the rules that need none.
"""
import base64
import collections
import hashlib
import io
import json
import os
import posixpath
import re
import resource
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))     # python3 -I leaves the code's own folder out

TOOLS_DIR = "/opt/fleet-door/tools"
# The versions of ArgoCD's stable branch on 12 November 2026 (hack/tool-versions.sh), each more than 7 days old. The
# SHA-256 of each archive is the publisher's own, and the program's is of the one member that the door takes.
PINS = {
    "helm": {
        "version": "v4.3.1", "url": "https://get.helm.sh/helm-v4.3.1-linux-{arch}.tar.gz",
        "member": "linux-{arch}/helm",
        "amd64": {"archive": "0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b",
                  "program": "b66cb19f2b31f9d427632ea6c4b4a1ff89b74ecaeaee323cd166da41a7af53bd"},
        "arm64": {"archive": "8cf8f66ecbc252ac8f7f06cca68aba88508ddfde3a6a34feb1678ad1694b4f88",
                  "program": "d459cbff1331af4326a6f97ea83c547742b4056dac7404f20fc436c084178c43"}},
    "kustomize": {
        "version": "v5.8.3", "url": "https://github.com/kubernetes-sigs/kustomize/releases/download/"
                                    "kustomize%2Fv5.8.3/kustomize_v5.8.3_linux_{arch}.tar.gz",
        "member": "kustomize",
        "amd64": {"archive": "cb9e31198d3f63b44848bd0afc4c8efc56e6cfef9c93a4a39a211940e6decd61",
                  "program": "a5e53d28755098b003ae2b6bff7b1650a411a366a0c800c1ea1b677e0cfff747"},
        "arm64": {"archive": "9867b76482cfc6d25b546abc1d2b5a32bd137505aba640649b4b378f64f6d68f",
                  "program": "dd14c7e37e65cd2ec6dd07dfaf0bf02355113d9b925dfa47c1354134a6f8051b"}},
}
# What the box must not reach: the door's two folders and its Teleport bot's token (door.py ETC, STATE, AWS_TOKEN_FILE)
KEY_PATHS = ("/etc/fleet-door", "/var/lib/fleet-door", "/opt/machine-id")
RUN_SECONDS = 30                    # one run of a program
RUN_BYTES = 32 * 1024 * 1024        # and the most that it writes
TOTAL_SECONDS = 110                 # one request
TAR_MAX = 64 * 1024 * 1024          # the repository's tarball
TREE_FILES = 100000
TREE_BYTES = 1024 * 1024 * 1024
HEAD_MAX = 8 * 1024 * 1024          # one file at HEAD that the answer carries
READ_MAX = 1024 * 1024              # one file that the helper reads as it is: an Application, a kustomization
ANSWER_MAX = 24 * 1024 * 1024
UNITS_MOST = 16                     # charts and Kustomize folders that one commit touches
SETS_MOST = 12                      # value sets of one chart
KUSTOMIZATIONS = ("kustomization.yaml", "kustomization.yml", "Kustomization")
READER = {
    "Chart.yaml": "apiVersion: v2\nname: reader\nversion: 0.0.0\n",
    # each file of in/ is one YAML document: its name, and the object that the parser reads in it
    "templates/out.yaml": '{{- $out := dict }}{{- range $path, $_ := .Files.Glob "in/*" }}'
                          '{{- $_ := set $out (base $path) ($.Files.Get $path | fromYaml) }}{{- end }}'
                          '{{ dict "docs" $out | toJson }}\n',
}
# What a program's error may say to the agent: only these words of it, and a file with its line. A program quotes the
# text that it could not read, and that text can be a file that the agent may not read (a secret path).
HINTS = ("nil pointer evaluating", "map has no entry for key", "wrong type for value", "not defined",
         "missing in charts/ directory", "must specify --enable-helm", "no such file or directory",
         "is not in or below", "accumulating resources", "YAML parse error", "error converting YAML to JSON",
         "values don't meet the specifications of the schema", "Chart.yaml file is missing", "parse error",
         "missing value for", "unexpected", "unclosed action", "unable to find", "no matches for",
         "already registered id", "cycle detected", "dial tcp", "no such host", "unsupported protocol scheme")
# The file that helm itself names at the start of its error, before any text of a template
HINT_FILE = re.compile(r"Error: (?:template: |execution error at \(|parse error at \(|YAML parse error on )"
                       r"([\w./@+-]{1,200}\.(?:ya?ml|tpl|txt|json))")
SOURCE = re.compile(r"# Source: ([\w./@+-]{1,200})\n")
MARK = re.compile(r"---[ \t]*\r?")
def hidden_path(path, exposure):
    """True for a path that the door gives no agent: door_targets.gitops_path_refused, with the access file's
    exposure register, which the door sends with a request."""
    import door_targets
    return door_targets.gitops_path_refused(path, {"exposure": list(exposure)}) is not None


class Failed(Exception):
    "One render or one reading that could not be made: its words go to the report."


class Late(Exception):
    "The whole request is over its time."


class Skip(Exception):
    "No render can be made here at all: the caller keeps the rules that need none."


def tool_path(name):
    return f"{TOOLS_DIR}/{name}-{PINS[name]['version']}/{name}"


def installed_tools():
    "The pinned programs as the door's update placed them, or None when one is not there."
    tools = {name: [tool_path(name)] for name in PINS}
    return tools if all(os.access(argv[0], os.X_OK) for argv in tools.values()) else None


# ---------------------------------------------------------------- the box

def probe():
    """What this process can reach: the families of socket that it can make, the network interfaces that are up
    beside the loopback, the key paths that it can read, and its user. boxed is true when it can reach none of them
    and is not root. A kernel gives each new network namespace its tunnel devices (sit0, tunl0), which are down."""
    families = []
    for name in ("AF_INET", "AF_INET6", "AF_UNIX", "AF_NETLINK", "AF_PACKET"):
        family = getattr(socket, name, None)
        if family is None:
            continue
        try:
            socket.socket(family, socket.SOCK_DGRAM if name != "AF_PACKET" else socket.SOCK_RAW).close()
            families.append(name)
        except OSError:
            pass
    interfaces = []
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            try:
                with open(f"/sys/class/net/{name}/flags") as f:
                    if name != "lo" and int(f.read().strip(), 16) & 1:      # IFF_UP
                        interfaces.append(name)
            except (OSError, ValueError):
                pass
    except OSError:
        interfaces = None           # no /sys here (a Mac): the sockets say it
    keys = []
    for path in KEY_PATHS:
        try:
            os.listdir(path)
            keys.append(path)
        except NotADirectoryError:
            keys.append(path)
        except OSError:
            pass
    facts = {"sockets": families, "interfaces": interfaces, "keys": keys, "user": os.geteuid(),
             "tools": {name: os.access(tool_path(name), os.X_OK) for name in PINS}}
    facts["boxed"] = not families and not interfaces and not keys and os.geteuid() != 0
    return facts


# ---------------------------------------------------------------- programs

class Runner:
    """The programs, a scratch folder and the request's time. Each run has an empty environment, no input, a time and
    a cap on what it writes."""

    def __init__(self, tools, scratch, seconds=TOTAL_SECONDS, log=False):
        self.tools, self.scratch, self.until, self.n = tools, scratch, time.monotonic() + seconds, 0
        self.log = log              # in the box: a program's own error goes to the unit's journal, which root reads
        self.quiet = False          # for a unit that can read what no agent may read: no word of a program's error
        self.read = {}              # a YAML document's text -> the object that the parser read in it, or None
        self.home = os.path.join(scratch, "home")
        os.makedirs(self.home, exist_ok=True)

    def on_time(self):
        "Late when the request is over its time: the work between two runs of a program counts too."
        if self.until - time.monotonic() <= 1:
            raise Late()

    def folder(self, prefix):
        self.n += 1
        path = os.path.join(self.scratch, f"{prefix}-{self.n}")
        os.makedirs(path)
        return path

    def run(self, tool, args, cwd):
        """The standard output of one run, or Failed with the words of its error that an agent may read."""
        self.on_time()
        left = self.until - time.monotonic()
        argv = self.tools[tool] + args
        work = self.folder("run")
        env = {"PATH": "/usr/bin:/bin", "HOME": self.home, "LANG": "C.UTF-8", "HELM_NO_PLUGINS": "1",
               "HELM_PLUGINS": os.path.join(self.home, "no-plugins"), "TMPDIR": work}
        try:
            with open(os.path.join(work, "out"), "wb") as out, open(os.path.join(work, "err"), "wb") as err:
                done = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err, cwd=cwd, env=env,
                                      timeout=min(RUN_SECONDS, left),
                                      preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE,
                                                                            (RUN_BYTES, RUN_BYTES)))
            with open(os.path.join(work, "out"), "rb") as f:
                said = f.read(RUN_BYTES + 1)
            with open(os.path.join(work, "err"), "rb") as f:
                error = f.read(65536).decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            if self.until - time.monotonic() <= 1:
                raise Late() from None
            raise Failed(f"{tool} took longer than {RUN_SECONDS} seconds") from None
        except OSError as e:
            raise Failed(f"{tool} did not start ({e.__class__.__name__})") from None
        finally:
            shutil.rmtree(work, ignore_errors=True)
        if done.returncode != 0 or len(said) >= RUN_BYTES:
            if self.log:
                print(f"{' '.join(argv)[:300]}: {done.returncode}: {error[-2000:]}", file=sys.stderr)
            if done.returncode < 0 or len(said) >= RUN_BYTES:
                raise Failed(f"{tool} wrote more than {RUN_BYTES // 2 ** 20} MiB, or was stopped")
            raise Failed(f"{tool} failed{'' if self.quiet else hint(error)}")
        try:
            return said.decode("utf-8")
        except UnicodeDecodeError:
            raise Failed(f"{tool} wrote bytes that are not UTF-8") from None


def hint(error):
    """The words of a program's error that an agent may read. Where helm names a template at the start of its error,
    only that file: a template chooses the line where it fails, the kind of its error and the text of it (`fail`),
    and can choose them by what it read. For every other error, the first phrase of HINTS that it holds. Never the
    error itself."""
    found = HINT_FILE.match(error.lstrip())
    if found:
        return f": in {found.group(1)}"
    said = [h for h in HINTS if h in error][:1]
    return ": " + said[0] if said else ""


# ---------------------------------------------------------------- the two trees

def safe(path):
    "A path of the repository as its parts, or None: relative, with no empty part, dot or dot-dot."
    parts = path.split("/") if isinstance(path, str) else []
    return parts if parts and not any(p in ("", ".", "..") or "\0" in p or "\\" in p for p in parts) else None


def unpack(raw, into):
    """The repository's tarball, as GitHub packs it (one top folder), into a folder: files, folders, and the links
    that stay in the tree. Returns [(the path of a link, the path that it names)] for the links that it kept."""
    count = size = 0
    links = []
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tar:
            for member in tar:
                parts = safe(member.name.split("/", 1)[1]) if "/" in member.name else None
                if parts is None:
                    continue
                dest = os.path.join(into, *parts)
                count, size = count + 1, size + (member.size if member.isreg() else 0)
                if count > TREE_FILES or size > TREE_BYTES:
                    raise Skip(f"the repository has more than {TREE_FILES} files or {TREE_BYTES // 2 ** 30} GiB")
                if member.isdir():
                    os.makedirs(dest, exist_ok=True)
                elif member.isreg():
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with open(dest, "wb") as f:
                        shutil.copyfileobj(tar.extractfile(member), f)
                    os.chmod(dest, 0o755 if member.mode & 0o100 else 0o644)
                elif member.issym():
                    links.append((parts, member.linkname))
    except (tarfile.TarError, OSError, EOFError) as e:
        raise Skip(f"the repository's tarball cannot be read ({e.__class__.__name__})") from None
    root, kept = os.path.realpath(into), []
    try:
        for parts, target in links:     # after every file, so that no file is written through a link
            names = posixpath.normpath(posixpath.join("/".join(parts[:-1]), target))
            dest = os.path.join(into, *parts)
            if target.startswith("/") or names == ".." or names.startswith("../") or os.path.lexists(dest):
                continue                # a link that leaves the repository: ArgoCD refuses such a repository whole
            at = into
            for part in parts[:-1]:     # its folders, one by one: none of them is a link, and none is made under one
                at = os.path.join(at, part)
                if os.path.islink(at) or (os.path.lexists(at) and not os.path.isdir(at)):
                    break
                if not os.path.lexists(at):
                    os.mkdir(at)
            else:
                os.symlink(target, dest)
                kept.append(("/".join(parts), "" if names == "." else names))
        # A link can name a path through another link, so the text of its target does not say where it ends. Each
        # link that ends outside the tree, or at a folder above itself, goes; and again, until none is left.
        while True:
            bad = {link for link, _names in kept if stray(root, os.path.join(into, *link.split("/")))}
            if not bad:
                break
            for link in bad:
                os.unlink(os.path.join(into, *link.split("/")))
            kept = [(link, names) for link, names in kept if link not in bad]
    except (OSError, RecursionError) as e:       # a chain of a thousand links ends Python's own reading of a path
        raise Skip(f"the repository's links cannot be made ({e.__class__.__name__})") from None
    return kept


def stray(root, link):
    "True for a link that ends outside the tree whose real path is `root`, or at a folder above itself."
    real, above = os.path.realpath(link), os.path.realpath(os.path.dirname(link))
    return not real.startswith(root + os.sep) or above == real or above.startswith(real + os.sep)


def stray_links(tree):
    "The paths of the links of a tree that end outside it or above themselves."
    root, found = os.path.realpath(tree), []
    for folder, dirs, names in os.walk(tree):
        for name in dirs + names:
            full = os.path.join(folder, name)
            if os.path.islink(full) and stray(root, full):
                found.append(os.path.relpath(full, tree).replace(os.sep, "/"))
    return found


def also_at(links, path):
    """The other paths at which a tree shows one file: under each link that names the file or a folder above it. A
    chart reads a file of another folder through such a link, so a change of the file is a change of the chart."""
    found, left = [], [(path, 0)]
    while left:
        at, depth = left.pop()
        for link, names in links:
            if depth < 4 and (at == names or names == "" or at.startswith(names + "/")):
                other = link + at[len(names):] if names else link + "/" + at
                if other != path and other not in found:
                    found.append(other)
                    left.append((other, depth + 1))
    return found


def copy_tree(src, dst):
    "A second tree of hard links, so that a tree of 1,000 files costs no second copy of them."
    for folder, _dirs, names in os.walk(src):
        rel = os.path.relpath(folder, src)
        os.makedirs(os.path.join(dst, rel), exist_ok=True)
        for name in names + [d for d in _dirs if os.path.islink(os.path.join(folder, d))]:
            a, b = os.path.join(folder, name), os.path.join(dst, rel, name)
            if os.path.islink(a):
                os.symlink(os.readlink(a), b)
            else:
                os.link(a, b)


def put(tree, path, data, mode):
    "One file of the commit on the second tree: written new, never through a link and never into the first tree's file."
    parts = safe(path)
    if parts is None:
        raise Failed(f"{path} is no path of a repository")
    at = tree
    for part in parts[:-1]:
        at = os.path.join(at, part)
        if os.path.islink(at) or (os.path.lexists(at) and not os.path.isdir(at)):
            raise Failed(f"{path} goes through a link or a file")
    dest = os.path.join(tree, *parts)
    if os.path.isdir(dest) and not os.path.islink(dest):
        raise Failed(f"{path} is a folder at HEAD")
    if os.path.lexists(dest):
        os.unlink(dest)
    if data is None:
        return
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "wb") as f:
        f.write(data)
    os.chmod(dest, 0o755 if mode == "100755" else 0o644)


def read(tree, path, most=READ_MAX):
    "The bytes of one file of a tree, or None: no file, a link that leaves the tree, or more than `most` bytes."
    if path != "" and safe(path) is None:
        return None
    full = os.path.join(tree, *path.split("/")) if path else tree
    real, root = os.path.realpath(full), os.path.realpath(tree)
    if not (real == root or real.startswith(root + os.sep)) or not os.path.isfile(real) or \
            os.path.getsize(real) > most:
        return None
    with open(real, "rb") as f:
        return f.read()


def is_dir(tree, path):
    full = os.path.realpath(os.path.join(tree, *path.split("/")) if path else tree)
    root = os.path.realpath(tree)
    return (full == root or full.startswith(root + os.sep)) and os.path.isdir(full)


def is_file(tree, path):
    if path == "" or safe(path) is None:
        return False
    full, root = os.path.realpath(os.path.join(tree, *path.split("/"))), os.path.realpath(tree)
    return full.startswith(root + os.sep) and os.path.isfile(full)


def inside(base, name):
    "A path that a file of the folder `base` names, as a path of the repository, or None when it leaves it."
    if not isinstance(name, str) or "\0" in name or "://" in name or len(name) > 1000 or "\n" in name:
        return None
    path = posixpath.normpath(posixpath.join(base, name) if not name.startswith("/") else name.lstrip("/"))
    return None if path == ".." or path.startswith("../") else "" if path == "." else path


# ---------------------------------------------------------------- reading YAML

def split_docs(text):
    """The documents of a YAML stream, as every reader of a cluster splits them. A line that starts with a document
    mark and holds more than the mark, and a line that ends a document (...), are Failed: one reader of a cluster
    takes the rest of such a line and another drops it, so the door reads no stream that has one."""
    docs, lines = [], []
    for line in text.split("\n"):
        if line.startswith("---"):
            if not MARK.fullmatch(line):
                raise Failed("content on the line of a document mark")
            docs.append(lines)
            lines = []
        elif line.startswith("..."):
            raise Failed("a line that ends a document (...)")
        else:
            lines.append(line)
    docs.append(lines)
    return ["\n".join(doc).rstrip("\r\n") + "\n" for doc in docs
            if any(x.strip() and not x.lstrip().startswith("#") for x in doc)]


def read_yaml(runner, texts):
    """Each text, one YAML document, as the object that Helm's parser reads in it, or None: a document that it cannot
    read, or that is no object. One run of helm reads all the texts that no run read before."""
    new = [text for text in dict.fromkeys(texts) if text not in runner.read]
    if new:
        runner.read.update(zip(new, parse(runner, new)))
    return [runner.read[text] for text in texts]


def parse(runner, texts):
    chart = runner.folder("reader")
    for name, text in READER.items():
        os.makedirs(os.path.dirname(os.path.join(chart, name)), exist_ok=True)
        with open(os.path.join(chart, name), "w", encoding="utf-8") as f:
            f.write(text)
    os.makedirs(os.path.join(chart, "in"))
    for n, text in enumerate(texts):
        with open(os.path.join(chart, "in", f"{n:07d}"), "w", encoding="utf-8", newline="") as f:
            f.write(text)
    try:
        said = runner.run("helm", ["template", "reader", chart], chart)
    finally:
        shutil.rmtree(chart, ignore_errors=True)
    line = next((x for x in said.split("\n") if x.startswith('{"docs":')), None)
    try:
        docs = json.loads(line)["docs"]
    except (TypeError, ValueError, KeyError, RecursionError):
        raise Failed("the reader of YAML gave no answer") from None
    out = []
    for n in range(len(texts)):
        doc = docs.get(f"{n:07d}") if isinstance(docs, dict) else None
        # fromYaml gives exactly {"Error": "<text>"} for a text that it cannot read. A document with other keys
        # beside it is an object, and is read as one.
        unread = not isinstance(doc, dict) or (set(doc) == {"Error"} and isinstance(doc["Error"], str))
        out.append(None if unread else doc)
    return out


def file_docs(data):
    "The texts of the documents of one YAML file, or None: no file, too big, no UTF-8, or a stream that no reader splits."
    if data is None or len(data) > READ_MAX:
        return None
    try:
        return split_docs(data.decode("utf-8"))
    except (UnicodeDecodeError, Failed):
        return None


def read_file(runner, data):
    """The documents of one YAML file, each as its object or None (a template, or no object), or None for a file whose
    stream no reader splits."""
    texts = file_docs(data)
    return None if texts is None else read_yaml(runner, texts)


def objects(doc):
    "The objects of one document: itself, or the items of a List, at any depth."
    kind, items = doc.get("kind"), doc.get("items")
    if isinstance(kind, str) and kind.endswith("List") and isinstance(items, list):
        return [o for item in items if isinstance(item, dict) for o in objects(item)]
    return [doc]


def word(value):
    "A name out of a manifest as a refusal may print it: its letters, digits and a few marks, and 80 of them at most."
    return re.sub(r"[^\w.:/-]", "?", value)[:80] if isinstance(value, str) else ""


def label(doc):
    "One object's kind, namespace and name: the key of its group in a report, and never a word of one."
    meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    name = "/".join(x for x in (word(meta.get("namespace")), word(meta.get("name"))) if x)
    return (word(doc.get("kind")) or "an object with no kind") + (f" {name}" if name else "")


def strings(value, depth=0):
    "Every text in a value, at any depth: what a kustomization may name as a path."
    if isinstance(value, str):
        yield value
    elif depth < 40 and isinstance(value, (dict, list)):
        for item in value.values() if isinstance(value, dict) else value:
            yield from strings(item, depth + 1)


def braces(value):
    return any("{{" in text for text in strings(value))


# ---------------------------------------------------------------- units

def chart_roots(trees, path):
    "The folders above a path that hold Chart.yaml, in either tree."
    parts, found = path.split("/")[:-1], []
    for n in range(len(parts), -1, -1):
        root = "/".join(parts[:n])
        if any(is_file(tree, posixpath.join(root, "Chart.yaml")) for tree in trees):
            found.append(root)
    return found


def kustomizations(tree):
    "{folder: the path of its kustomization file} for every folder of a tree that has one."
    found = {}
    for folder, dirs, names in os.walk(tree):
        dirs[:] = [d for d in dirs if d != ".git" and not os.path.islink(os.path.join(folder, d))]
        rel = os.path.relpath(folder, tree).replace(os.sep, "/")
        rel = "" if rel == "." else rel
        name = next((n for n in KUSTOMIZATIONS if n in names), None)
        if name:
            found[rel] = posixpath.join(rel, name)
    return found


class Kustomize:
    """The Kustomize folders of one tree, and what each one can read. A kustomization names files and folders in many
    keys, and a key that the helper does not know must not hide one. So every text of a kustomization is taken as a
    path: a folder that it names is read whole, and the kustomization of that folder in turn."""

    def __init__(self, runner, tree):
        self.tree, self.files = tree, kustomizations(tree)
        folders = sorted(self.files)
        self.texts = [(read(tree, self.files[f]) or b"").decode("utf-8", "replace") for f in folders]
        self.runner, self.folders, self.read, self.reached = runner, folders, None, {}

    @property
    def docs(self):
        if self.read is None:
            self.read = dict(zip(self.folders, read_yaml(self.runner, self.texts)))
        return self.read

    def unit(self, folder):
        "True for a folder that Kustomize builds by itself: a Component is built only through the folder that names it."
        doc = self.docs.get(folder)
        return folder in self.files and not (isinstance(doc, dict) and doc.get("kind") == "Component")

    def reach(self, folder):
        "(folders, files) that a build of this folder can read."
        if folder in self.reached:
            return self.reached[folder]
        self.runner.on_time()
        folders, files, left = set(), set(), [folder]
        while left:
            at = left.pop()
            if at in folders:
                continue
            folders.add(at)
            for text in strings(self.docs.get(at)):
                path = inside(at, text)
                if path is None:
                    continue
                if is_dir(self.tree, path):
                    left.append(path)
                elif is_file(self.tree, path):
                    files.add(path)
        self.reached[folder] = (folders, files)
        return folders, files

    def reads(self, folder, path):
        folders, files = self.reach(folder)
        return path in files or any(f == "" or path == f or path.startswith(f + "/") for f in folders)


# ---------------------------------------------------------------- Applications

APP_FILES = (".yaml", ".yml", ".json")
APP_KIND = re.compile(r"(?i)kind[\"']?\s*:\s*[\"']?application(?:set)?\b")
HELM_KEYS = {"valueFiles", "values", "valuesObject", "parameters", "fileParameters", "releaseName", "namespace",
             "kubeVersion", "apiVersions", "skipCrds", "skipTests", "skipSchemaValidation",
             "ignoreMissingValueFiles", "passCredentials", "version"}


def application_texts(tree):
    """([the text of each document of a tree that may hold an Application], [its file], the first file that may hold
    one and that no reader splits or None)."""
    texts, where = [], []
    for folder, dirs, names in os.walk(tree):
        dirs[:] = [d for d in dirs if d != ".git" and not os.path.islink(os.path.join(folder, d))]
        for name in names:
            if not name.lower().endswith(APP_FILES):
                continue
            rel = os.path.relpath(os.path.join(folder, name), tree).replace(os.sep, "/")
            data = read(tree, rel, most=HEAD_MAX)
            if data is None or b"argoproj.io" not in data:
                continue
            try:
                docs = split_docs(data.decode("utf-8"))
            except (UnicodeDecodeError, Failed):
                if APP_KIND.search(data.decode("utf-8", "replace")):
                    return [], [], rel
                continue
            docs = [d for d in docs if "argoproj.io" in d]
            texts.extend(docs)
            where.extend([rel] * len(docs))
    return texts, where, None


def applications(runner, found_texts):
    """([(an Application or an ApplicationSet that a file of a tree holds, that file)], the first file with one that
    the parser cannot read or None). They say with which values a cluster renders a chart, so one that is not read
    leaves every unit unknown."""
    texts, where, bad = found_texts
    if bad:
        return [], bad
    found = []
    for doc, text, rel in zip(read_yaml(runner, texts), texts, where):
        if doc is None:
            if APP_KIND.search(text):
                return [], rel
            continue
        found.extend((o, rel) for o in objects(doc) if o.get("kind") in ("Application", "ApplicationSet"))
    return found, None


def sources(app):
    """[(the Application's name, its namespace of destination, one source, all its sources, whether the Application
    is the template of an ApplicationSet whose words the door cannot follow)]."""
    spec, meta = app.get("spec"), app.get("metadata")
    patched = False
    if app.get("kind") == "ApplicationSet":
        patched = isinstance(spec, dict) and bool(spec.get("templatePatch"))
        template = spec.get("template") if isinstance(spec, dict) else None
        spec, meta = (template.get("spec"), template.get("metadata")) if isinstance(template, dict) else (None, None)
    if not isinstance(spec, dict):
        return []
    every = [s for s in [spec.get("source")] + (spec.get("sources") if isinstance(spec.get("sources"), list) else [])
             if isinstance(s, dict)]
    name = meta.get("name") if isinstance(meta, dict) else None
    dest = spec.get("destination") if isinstance(spec.get("destination"), dict) else {}
    return [(name, dest.get("namespace"), s, every, patched) for s in every]


def names_root(source, root):
    "True when a source of an Application names this folder of the repository, or a folder that only a cluster knows."
    path = source.get("path")
    if not isinstance(path, str) or "chart" in source:
        return False
    return "{{" in path or inside("", path) == root


class Unknown(Exception):
    "An Application gives a unit an input that the door cannot give it."


def value_set(name, namespace, source, every, patched, root):
    """What one source of an Application gives a chart: {release, namespace, steps, flags}, where steps are ("file",
    a path of the repository, may be missing), ("text", YAML), ("json", an object) and ("arg", flag, value), in
    ArgoCD's order. Unknown when the door cannot give the chart the same."""
    if "plugin" in source or patched:
        raise Unknown("a plugin or a patch of an ApplicationSet")
    helm = source.get("helm") if "helm" in source else {}
    if not isinstance(helm, dict):
        raise Unknown("helm settings that are no object")
    if braces(helm):
        raise Unknown("values that an ApplicationSet fills in")
    odd = sorted(set(helm) - HELM_KEYS)
    if odd:
        raise Unknown(f"the helm setting {word(odd[0])[:40]}")

    def text(value, fallback):
        return value if isinstance(value, str) and value and "{{" not in value else fallback

    def tree_path(value):
        if not isinstance(value, str):
            raise Unknown("a values file that is no text")
        if value.startswith("$"):           # $<ref>/<path>: a file of another source of the same Application
            ref, _, rest = value[1:].partition("/")
            other = next((s for s in every if s.get("ref") == ref), None)
            if other is None or "chart" in other or other.get("repoURL") != source.get("repoURL") or \
                    other.get("targetRevision") != source.get("targetRevision"):
                raise Unknown("a values file of another repository or revision")
            path = inside("", rest)
        else:
            path = inside(root, value)
        if path is None:
            raise Unknown("a values file at a URL or outside the repository")
        return path
    steps, flags = [], []
    files = helm.get("valueFiles") or []
    if not isinstance(files, list):
        raise Unknown("valueFiles that are no list")
    for value in files:
        steps.append(("file", tree_path(value), helm.get("ignoreMissingValueFiles") is True))
    if isinstance(helm.get("valuesObject"), dict):
        steps.append(("json", helm["valuesObject"]))
    elif isinstance(helm.get("values"), str) and helm["values"].strip():
        steps.append(("text", helm["values"]))
    elif helm.get("values") or helm.get("valuesObject"):
        raise Unknown("values that are no text and no object")
    for key, flag in (("parameters", "--set"), ("fileParameters", "--set-file")):
        entries = helm.get(key) or []
        if not isinstance(entries, list):
            raise Unknown(f"{key} that are no list")
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                raise Unknown(f"one of the {key} has no name")
            if key == "fileParameters":
                steps.append(("setfile", entry["name"], tree_path(entry.get("path"))))
                continue
            value = entry.get("value", "")
            value = json.dumps(value) if isinstance(value, bool) else str(value)
            # ArgoCD's own escape: a comma that has no backslash before it gets one
            value = re.sub(r"(?<!\\),", r"\\,", value)
            steps.append(("arg", "--set-string" if entry.get("forceString") is True else flag,
                          f"{entry['name']}={value}"))
    if isinstance(helm.get("kubeVersion"), str):
        flags += ["--kube-version", helm["kubeVersion"]]
    versions = helm.get("apiVersions") or []
    if not isinstance(versions, list) or not all(isinstance(v, str) for v in versions):
        raise Unknown("apiVersions that are no list of texts")
    for version in versions:
        flags += ["--api-versions", version]
    if helm.get("skipCrds") is not True:
        flags.append("--include-crds")
    if helm.get("skipTests") is True:
        flags.append("--skip-tests")
    if helm.get("skipSchemaValidation") is True:
        flags.append("--skip-schema-validation")
    return {"release": text(helm.get("releaseName"), None) or text(name, None),
            "namespace": text(helm.get("namespace"), None) or text(namespace, None), "steps": steps, "flags": flags,
            "name": f"the values of the Application {word(name) or 'with no name'}"}


def release_name(root):
    name = re.sub(r"[^a-z0-9-]+", "-", posixpath.basename(root).lower()).strip("-")[:40]
    return name or "release"


OWN = {"release": None, "namespace": None, "steps": [], "flags": ["--include-crds"], "name": "its own values"}


def value_sets(found, kind, root, exposure=()):
    """The value sets of one unit in one tree, {key: set}: its own under the key None, and one for each source of an
    Application that names its folder, under the Application's file, kind, name and namespace and the source's place.
    The key says which set of HEAD a set after the commit takes the place of. `found` is applications()'s list.
    Raises Unknown for an input that the door cannot give. An Application in a path that the door gives no agent
    is named by no word of its own (`mute`), and a set with its values is `closed` too."""
    sets, seen = {None: OWN}, collections.Counter()
    for app, file in found:
        for name, namespace, source, every, patched in sources(app):
            if not names_root(source, root):
                continue
            forced = next((k for k in ("helm", "kustomize", "directory", "plugin") if k in source), None)
            if forced == "directory" or (forced in ("helm", "kustomize") and forced != kind):
                continue                # this Application applies the folder's files as they are, or another way
            if kind == "kustomize":
                if forced == "plugin" or patched or source.get("kustomize"):
                    raise Unknown("Kustomize options, a plugin or a patch of an ApplicationSet")
                continue
            meta = app.get("metadata") if isinstance(app.get("metadata"), dict) else {}
            key = json.dumps([file, app.get("kind"), word(meta.get("name")), word(meta.get("namespace"))])
            seen[key] += 1
            secret = hidden_path(file, exposure)
            try:
                one = value_set(name, namespace, source, every, patched, root)
            except Unknown as e:
                raise Unknown("an input that the door cannot give it" if secret else str(e)) from None
            if secret:
                # Its release name and namespace go into the render, as a cluster gives them, and into no word of the
                # report (mute). Its values make the unit closed.
                one.update(name="the values of an Application", mute=True,
                           closed=bool(one["steps"]) or one["flags"] != OWN["flags"])
            sets[f"{key}#{seen[key]}"] = one
            if len(sets) > SETS_MOST:
                raise Unknown(f"more than {SETS_MOST} value sets")
    return sets


def set_paths(one):
    "The files of the repository that a value set names."
    return {step[1] if step[0] == "file" else step[2] for step in one["steps"] if step[0] in ("file", "setfile")}


# ---------------------------------------------------------------- rendering

def render(runner, tree, kind, root, one):
    """The stream that a cluster's tool gives for one unit of one tree, or "" when the tree has no such folder."""
    folder = os.path.join(tree, *root.split("/")) if root else tree
    if not is_dir(tree, root):
        return ""
    if kind == "kustomize":
        return runner.run("kustomize", ["build", folder], folder)
    if not is_file(tree, posixpath.join(root, "Chart.yaml")):
        return ""
    args = ["template", one["release"] or release_name(root), folder, "--namespace", one["namespace"] or "default"]
    extra = None
    for step in one["steps"]:
        if step[0] == "file":
            if not is_file(tree, step[1]):
                if step[2]:
                    continue
                raise Failed("a values file that an Application names is not there")
            args += ["--values", os.path.join(tree, *step[1].split("/"))]
        elif step[0] == "setfile":
            if not is_file(tree, step[2]):
                raise Failed("a file parameter that an Application names is not there")
            args += ["--set-file", f"{step[1]}={os.path.join(tree, *step[2].split('/'))}"]
        elif step[0] in ("text", "json"):
            extra = extra or runner.folder("values")
            path = os.path.join(extra, f"{len(os.listdir(extra))}.yaml")
            with open(path, "w", encoding="utf-8") as f:
                f.write(step[1] if step[0] == "text" else json.dumps(step[1]))
            args += ["--values", path]
        else:
            args += [step[1], step[2]]
    return runner.run("helm", args + one["flags"], folder)


def documents(runner, tree, kind, root, one):
    "The documents of one render of one unit, as texts."
    return split_docs(render(runner, tree, kind, root, one))


def head_fault(runner, tree, kind, root, pairs, shut=False):
    """Why the door cannot read what a cluster applies of a unit at HEAD, or None: the unit is not there, or it
    renders with each value set of HEAD, twice the same."""
    loud = runner.quiet
    try:
        for head, _new in pairs:
            runner.quiet = shut or bool(head and head.get("mute"))
            if head and collections.Counter(documents(runner, tree, kind, root, head)) != \
                    collections.Counter(documents(runner, tree, kind, root, head)):
                return "two renders of the same tree differ: a template uses a random or a time function"
    except Failed as e:
        return str(e)
    finally:
        runner.quiet = loud
    return None


def unit_report(runner, trees, kind, root, pairs, shut=False):
    """One unit, rendered at HEAD and after the commit. pairs: [(a value set of HEAD or None, the value set that a
    cluster uses in its place after the commit)]: the unit's own values with themselves, an Application's values at
    HEAD with the same Application's after the commit, and None with the values of an Application that is new. ok:
    the door read what a cluster applies after the commit, and changed holds the objects that differ. broke: the door
    cannot read it after the commit, and it can at HEAD (or the unit is new): that is the commit's doing, and the
    commit is refused, so that no commit takes a unit out of the render. Neither: the door cannot read it at HEAD
    either, as its own people left it, and its files keep the rules that need no render. shut: the unit can read what
    the door gives no agent, so the report names no object and carries no word of a program's error."""
    before_tree, after_tree = trees
    report = {"kind": kind, "root": root or ".", "ok": True, "broke": False, "why": "", "changed": [],
              "closed": shut}
    try:
        for head, one in pairs:
            runner.quiet = shut or bool(one.get("mute"))
            new = documents(runner, after_tree, kind, root, one)
            try:
                old = documents(runner, before_tree, kind, root, head) if head else []
            except Failed:
                old = []            # nothing that the door reads at HEAD: every object after the commit is new
            gone = collections.Counter(old) - collections.Counter(new)
            came = collections.Counter(new) - collections.Counter(old)
            if not gone and not came:
                continue
            if collections.Counter(documents(runner, after_tree, kind, root, one)) != collections.Counter(new):
                raise Failed("two renders of the same tree differ: a template uses a random or a time function")
            texts = list(gone.elements()) + list(came.elements())
            groups, shown = {}, {}
            for n, doc in enumerate(read_yaml(runner, texts)):
                side = "before" if n < sum(gone.values()) else "after"
                if doc is None and side == "after":
                    raise Failed("the render gives a document that is no object, or that the parser cannot read")
                # The words for an object are the template that helm says it came from, in helm's own first line of
                # the document. Never its kind or its name: a template writes those, and can write there what it read.
                source = SOURCE.match(texts[n]) if kind == "helm" and not runner.quiet else None
                for obj in objects(doc) if doc is not None else []:
                    groups.setdefault(label(obj), {"before": [], "after": []})[side].append(obj)
                    if side == "after":
                        shown.setdefault(label(obj), f"an object of {source.group(1)}" if source else "an object")
            for name, group in sorted(groups.items()):
                report["changed"].append({"object": shown.get(name, "an object"), "set": one["name"], **group})
    except Failed as e:
        head = head_fault(runner, before_tree, kind, root, pairs, shut)
        report.update(ok=False, changed=[], broke=head is None,
                      why=str(e) if head is None else f"its render fails at HEAD too: {head}")
    finally:
        runner.quiet = False
    return report


def tree_files(tree, folder, seen=None):
    """Each file under a folder of a tree as (its path, the path of the file that it is or is a link to, or None for
    a link that ends outside the tree), with the files of each folder that a link names."""
    seen = set() if seen is None else seen
    top = os.path.join(tree, *folder.split("/")) if folder else tree
    root = os.path.realpath(tree)
    for at, dirs, names in os.walk(top):
        for name in names + [d for d in dirs if os.path.islink(os.path.join(at, d))]:
            full = os.path.join(at, name)
            path, real = os.path.relpath(full, tree).replace(os.sep, "/"), os.path.realpath(full)
            if not real.startswith(root + os.sep):
                yield path, None
            elif os.path.isdir(real):
                inner = os.path.relpath(real, root).replace(os.sep, "/")
                yield path, inner       # the link itself, by its own path, also when its folder was walked before
                if inner not in seen:
                    seen.add(inner)
                    for below, its in tree_files(tree, inner, seen):
                        yield path + below[len(inner):], its
            elif os.path.isfile(real):
                yield path, os.path.relpath(real, root).replace(os.sep, "/")


def closed(runner, trees, kind, root, kustomize, pairs, exposure):
    """True when a unit can read a path that the door gives no agent (hidden_path: a secret path of the repository,
    or one of the exposure register): a file under a chart's folder or in a Kustomize folder's reach, also through a
    link; a values file or a file parameter that an Application names, also through a link; a link that ends outside
    the tree; or the values of an Application that is itself in such a path. The door renders a closed unit and
    decides on it, its refusal says only "an object" and the form, and its files keep the rules that need no render:
    the door widens nothing there. It is a rule of paths, not of what a file holds: a chart's templates read the
    chart's other templates, files and values whatever the door does (UI-API.md, version 1.126, "What a template can read")."""
    sets = [one for pair in pairs for one in pair if one]
    if any(one.get("closed") for one in sets):
        return True
    root_of = [os.path.realpath(tree) for tree in trees]
    for n, tree in enumerate(trees):
        if kind == "helm":
            folders, files = {root}, set()
        elif root in kustomize[n].files:
            folders, files = kustomize[n].reach(root)
        else:
            folders, files = set(), set()
        named = []
        for path in sorted(files | {p for one in sets for p in set_paths(one)}):
            real = os.path.realpath(os.path.join(tree, *path.split("/")))
            inside = real.startswith(root_of[n] + os.sep)
            named.append((path, os.path.relpath(real, root_of[n]).replace(os.sep, "/") if inside else None))
        seen = set()
        for path, real in named + [x for f in sorted(folders) for x in tree_files(tree, f)]:
            runner.on_time()
            if path in seen:
                continue
            seen.add(path)
            if real is None or hidden_path(path, exposure) or hidden_path(real, exposure):
                return True
    return False


def answer(header, tar, blobs, tools, scratch, log=False):
    """The report of one commit: {ok, files: {path: {head, units, before, after}}, units: {id: unit_report}}. files:
    the bytes at HEAD of each path of the commit (base64, or None), the units that read it, and its documents at HEAD
    and after the commit as the parser reads them (read_file). Or {ok: False, skip} when no render can
    be made of this repository here, whatever the commit, and {ok: False, why} when the render of this commit
    failed: the first keeps the rules that need no render, and the second refuses the commit."""
    if tools is None:
        return {"v": 1, "ok": False, "skip": "the pinned helm and kustomize are not on the door yet"}
    if len(tar) > TAR_MAX:
        return {"v": 1, "ok": False, "skip": f"the repository's tarball is over {TAR_MAX // 2 ** 20} MiB"}
    runner = Runner(tools, scratch, log=log)
    exposure = [p for p in header.get("exposure") or [] if isinstance(p, str)] \
        if isinstance(header.get("exposure"), list) else []
    before, after = os.path.join(scratch, "before"), os.path.join(scratch, "after")
    os.makedirs(before)
    try:
        links = unpack(tar, before)
        copy_tree(before, after)
        commit = []
        for entry, data in zip(header.get("files") or [], blobs):
            path = entry.get("path")
            if safe(path) is None:
                raise Failed("a path of the commit is no path of a repository")
            put(after, path, data, entry.get("mode"))
            commit.append(path)
        # A file of the commit in the place of a link, or of a folder that a link named, can turn another link of
        # HEAD to a place outside the tree.
        if stray_links(after):
            raise Failed("after this commit a link of the repository ends outside it")
        trees = (before, after)
        heads = {}
        for path in commit:
            heads[path] = read(before, path, most=HEAD_MAX)
            if heads[path] is None and os.path.lexists(os.path.join(before, *path.split("/"))):
                # the commit's own choice of path, so a refusal and no reason to render nothing
                raise Failed(f"{path} at HEAD is a link, a folder or more than {HEAD_MAX // 2 ** 20} MiB")
        yaml_names = [path for path in commit if path.lower().endswith((".yaml", ".yml"))]
        kustomize = [Kustomize(runner, tree) for tree in trees]
        app_texts = [application_texts(tree) for tree in trees]
        # one run of helm reads every text that needs no render: the commit's files, the kustomizations and the
        # Applications of both trees. The readers below find them read.
        read_yaml(runner, [text for path in yaml_names for data in (heads[path], read(after, path))
                           for text in file_docs(data) or []]
                  + [text for k in kustomize for text in k.texts] + [text for found in app_texts for text in found[0]])
        files = {}
        for path in commit:
            files[path] = {"head": None if heads[path] is None else base64.b64encode(heads[path]).decode(),
                           "units": [],
                           "before": read_file(runner, heads[path]) if path in yaml_names else None,
                           "after": read_file(runner, read(after, path)) if path in yaml_names else None}
        apps = [applications(runner, found_texts) for found_texts in app_texts]

        def inputs(n, kind, root):
            """(the value sets that tree n gives a unit, None), or (None, why the door cannot give the unit what a
            cluster gives it in that tree)."""
            found, unread = apps[n]
            if unread:
                return None, f"{unread} holds an Application that the parser cannot read"
            if kind == "kustomize" and root in kustomize[n].files and kustomize[n].docs.get(root) is None:
                return None, "its kustomization is not read"
            try:
                return value_sets(found, kind, root, exposure), None
            except Unknown as e:
                return None, f"an Application gives it {e}"
        wanted = {}                     # (kind, root) -> the paths of the commit that it reads
        for path in commit:
            for at in [path] + also_at(links, path):
                for root in chart_roots(trees, at):
                    wanted.setdefault(("helm", root), set()).add(path)
                for k in kustomize:
                    for root in k.files:
                        if k.unit(root) and k.reads(root, at):
                            wanted.setdefault(("kustomize", root), set()).add(path)
        charts = sorted({posixpath.dirname(p) for tree in trees for p in find(tree, "Chart.yaml")})
        # a file of the commit that holds an Application: the units that the Application names, at HEAD or after the
        # commit, get their values from it
        for found, _unread in apps:
            for app, file in found:
                if file in commit:
                    for _name, _namespace, source, _every, _patched in sources(app):
                        for kind, root in [("helm", r) for r in charts] + \
                                [("kustomize", r) for k in kustomize for r in k.files if k.unit(r)]:
                            if names_root(source, root):
                                wanted.setdefault((kind, root), set()).add(file)
        # a chart elsewhere that takes a file of the commit as its values, by an Application's word
        for root in charts:
            named = set()
            for n in (0, 1):
                for one in (inputs(n, "helm", root)[0] or {}).values():
                    named |= set_paths(one)
            for path in commit:
                if named & set([path] + also_at(links, path)):
                    wanted.setdefault(("helm", root), set()).add(path)
        if len(wanted) > UNITS_MOST:
            raise Failed(f"the commit touches more than {UNITS_MOST} charts and Kustomize folders: commit fewer at "
                         f"a time")
        units = {}
        for kind, root in sorted(wanted):
            runner.on_time()
            uid = f"{kind}:{root or '.'}"
            for path in wanted[kind, root]:
                files[path]["units"].append(uid)
            base = {"kind": kind, "root": root or ".", "ok": False, "broke": False, "changed": []}
            (head_sets, head_why), (new_sets, new_why) = inputs(0, kind, root), inputs(1, kind, root)
            if head_why:                # as the repository's own people left it: the rules that need no render
                units[uid] = dict(base, why=head_why)
            elif new_why:               # the commit's doing: refused, so that no commit takes a unit out of the render
                units[uid] = dict(base, broke=True, why=f"after this commit, {new_why}")
            else:
                # An Application of HEAD that the tree no longer holds can still be in the cluster: its values stay.
                pairs, seen = [], set()
                for key in list(head_sets) + [k for k in new_sets if k not in head_sets]:
                    pair = (head_sets.get(key), new_sets.get(key) or head_sets[key])
                    same = json.dumps(pair, sort_keys=True)
                    if same not in seen:
                        seen.add(same)
                        pairs.append(pair)
                units[uid] = unit_report(runner, trees, kind, root, pairs,
                                         shut=closed(runner, trees, kind, root, kustomize, pairs, exposure))
        report = {"v": 1, "ok": True, "files": files, "units": units}
    except Skip as e:
        return {"v": 1, "ok": False, "skip": str(e)}
    except Late:
        return {"v": 1, "ok": False, "why": f"the render took longer than {TOTAL_SECONDS} seconds: commit fewer "
                                            f"charts at a time"}
    except Failed as e:
        return {"v": 1, "ok": False, "why": str(e)}
    if len(json.dumps(report)) > ANSWER_MAX:
        return {"v": 1, "ok": False, "why": "the commit changes more rendered objects than the door reads at a time: "
                                            "commit fewer charts at a time"}
    return report


def find(tree, name):
    "The paths of every file of that name in a tree."
    found = []
    for folder, dirs, names in os.walk(tree):
        dirs[:] = [d for d in dirs if d != ".git" and not os.path.islink(os.path.join(folder, d))]
        if name in names:
            found.append(os.path.relpath(os.path.join(folder, name), tree).replace(os.sep, "/"))
    return found


# ---------------------------------------------------------------- one request

def take(stream):
    "(header, the tarball, the bytes of each file of the commit or None for a delete) of one request."
    line = stream.readline(1024 * 1024 + 1)
    header = json.loads(line)
    if not isinstance(header, dict) or header.get("v") != 1:
        raise ValueError("no request of version 1")

    def exactly(size):
        data = stream.read(size)
        if len(data) != size:
            raise ValueError("the request ended early")
        return data
    if header.get("op") != "render":
        return header, b"", []
    size = header.get("tar")
    if not isinstance(size, int) or not 0 <= size <= TAR_MAX + 1 or not isinstance(header.get("files"), list):
        raise ValueError("a render names its tarball and its files")
    tar, blobs = exactly(size), []
    for entry in header["files"]:
        size = entry.get("size") if isinstance(entry, dict) else None
        if size is not None and (not isinstance(size, int) or not 0 <= size <= TAR_MAX):
            raise ValueError("a file's size")
        blobs.append(None if size is None else exactly(size))
    return header, tar, blobs


def serve(stream, out, tools, check=True):
    """One request of the door's, answered. With check, which only a test turns off, the helper renders nothing where
    it can reach a network or a key of the door: the box is the unit's, and a helper that was started another way has
    none."""
    try:
        header, tar, blobs = take(stream)
        facts = probe()
        if header.get("op") == "probe":
            said = dict(facts, v=1, ok=True)
        elif check and not facts["boxed"]:
            said = {"v": 1, "ok": False, "skip": "the render helper is not in its box"}
        else:
            # the box's private /var/tmp is on the disk; /tmp can be memory
            base = "/var/tmp" if check and os.path.isdir("/var/tmp") else None
            scratch = tempfile.mkdtemp(prefix="door-render-", dir=base)
            try:
                said = answer(header, tar, blobs, tools, scratch, log=check)
            finally:
                shutil.rmtree(scratch, ignore_errors=True)
    except (ValueError, OSError, RecursionError) as e:
        said = {"v": 1, "ok": False, "why": f"the render helper could not read its request ({e.__class__.__name__})"}
    out.write(json.dumps(said).encode())
    out.flush()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv != ["box"]:
        sys.exit("door_render.py box: one request on standard input (door.py sends it)")
    serve(sys.stdin.buffer, sys.stdout.buffer, installed_tools())


if __name__ == "__main__":
    main()
