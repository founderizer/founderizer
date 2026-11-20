#!/usr/bin/env python3
"""The home reading (the session wall, version 2, slice 0): what stays in one agent's home, as that agent's own OS
user sees it. Standard library only. It changes nothing and prints no content of any file.

The server service runs this file as each agent's own user (server.Service.homes_round: sudo's one line, then
`/usr/bin/timeout ... /usr/bin/python3 -I <a file of the service's own>`), with no word of the hub or of an agent on
its command line, and posts what it prints to the hub. The hub keeps one row for each agent and item (POST
/server/<name>/homes, GET /ui/homes).

Today a session of an agent can write the agent's whole home: the helper's code, its unit, the agent's key, the
programs that each session starts and each runtime's settings (VAULT.md, "What a session writes on its own machine").
Nothing stops such a change, and until this reading nothing recorded it. This reading stops nothing either: it turns
the silence into a record. A program of the same user can change what this reading prints, so the hub takes it as
untrusted input, and the record is one of what that user's files looked like, not a proof. The fixed set that it
lists (the session wall, version 2, section 6), each kind with a bound of its own, the kit last:

- dot: the shell, git, npm, SSH, tmux and uv files of the home;
- runtime: each runtime's settings files, and its skills, agents, commands, plugins and prompts;
- unit: the user's own systemd units; bin: ~/.local/bin; program: the helper's pinned uv and Node, and each MCP
  package's ready.json (~/.fleet/programs);
- site: the Python user site, which a Python with no -I reads;
- cron: the user's crontab;
- process: each process of the user, with the task that its environment names (FLEET_TASK), or none;
- listener: each TCP port and each abstract socket that a process of the user listens on;
- kit: the files of each checkout of the home (~/fleet-<agent>): its top files and KIT_FOLDERS, with the commit that
  its HEAD names (kit_head), and its git settings and hooks (kit_git), which run when the helper's git works there.

For a file: its name, its size and its SHA-256 (up to FILE_MOST bytes; a larger file gives its size alone). Each file
is opened with no link followed and not blocking, and read only when it is a regular file, so a link, a FIFO or a
device in the home cannot make the reading read another place or wait. A name is data: each byte that is no plain
character comes as \\xHH, so a name with a line end is one escaped row."""
import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
import time

FILE_MOST = 4 * 1024 * 1024     # bytes of one file that the reading hashes; a larger one gives its size alone
KIT_FILE_MOST = 32 * 1024 * 1024    # the same for a kit file: hub.py is larger than FILE_MOST
NAME_MOST = 400                 # characters of one escaped name; a longer one is cut and ends with a digest
KIND_MOST = {"dot": 200, "runtime": 400, "unit": 200, "bin": 300, "program": 200, "site": 200, "cron": 1,
             "process": 300, "listener": 100, "kit": 800, "kit_head": 20, "kit_git": 100}  # items of each kind
TIME_MOST = 60                  # seconds that a reading may take: then it ends, and its service records the failure
MEMORY_MOST = 512 * 1024 * 1024     # bytes of memory that a reading may take
DOT_FILES = (".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zshenv", ".zprofile",
             ".zlogin", ".inputrc", ".pam_environment", ".gitconfig", ".config/git/config", ".config/git/attributes",
             ".config/git/ignore", ".npmrc", ".yarnrc", ".yarnrc.yml", ".config/pip/pip.conf", ".pip/pip.conf",
             ".ssh/config", ".ssh/authorized_keys", ".ssh/rc", ".ssh/environment", ".tmux.conf",
             ".config/tmux/tmux.conf", ".config/systemd/user.conf", ".config/uv/uv.toml", ".bash_aliases",
             ".fleet/release-floor")
DOT_FOLDERS = (".config/environment.d",)
RUNTIME_FILES = (".codex/config.toml", ".codex/AGENTS.md", ".codex/AGENTS.override.md", ".codex/hooks.json",
                 ".claude.json", ".claude/settings.json", ".claude/settings.local.json", ".claude/CLAUDE.md",
                 "CLAUDE.md", ".config/opencode/opencode.json", ".config/opencode/AGENTS.md")
RUNTIME_FOLDERS = (".claude/skills", ".claude/agents", ".claude/commands", ".claude/rules", ".claude/plugins",
                   ".codex/skills", ".codex/prompts", ".codex/rules", ".agents/skills")
FOLDERS = (("unit", ".config/systemd/user", 2), ("unit", ".local/share/systemd/user", 2), ("bin", ".local/bin", 1))
# The helper's pinned programs (fleet.py, "pinned programs"): the uv and Node binaries under tools/, and each package's
# ready.json, which say what each MCP program that the helper installs and starts runs. Found by name down to
# PROGRAM_DEPTH levels, with no other file of those trees read and no folder of PROGRAM_SKIP entered.
PROGRAMS = ".fleet/programs"
PROGRAM_NAMES = ("uv", "uvx", "node", "npm", "npx", "ready.json")      # and each python3* that uv put under tools/
PROGRAM_SKIP = ("node_modules", "lib", "include", "share", "site-packages", "__pycache__")
PROGRAM_SKIP_TOP = ("cache", "run")     # the helper's caches and runs, skipped only right under ~/.fleet/programs
PROGRAM_DEPTH = 6
PROGRAM_FOLDERS_MOST = 3000     # folders of that tree that the reading enters, at most
# The parts of a checkout that run or steer (fleet.PROTECTED and section 6, row 1): its top files, and these folders
# down to KIT_DEPTH levels. Its git settings and hooks (kit_git) run when the helper's git works in it.
KIT_FOLDERS = ("rules", "profiles", "skills", "prices", "checks")
KIT_DEPTH = 3
CRONTAB = "/usr/bin/crontab"


def esc(raw):
    """A name as one line of plain characters: each byte that is no printable ASCII, and the backslash, as \\xHH. A
    name longer than NAME_MOST is cut and ends with the start of its digest, so two long names stay two rows."""
    data = raw if isinstance(raw, bytes) else os.fsencode(raw)
    text = "".join(chr(b) if 0x20 <= b < 0x7f and b != 0x5c else f"\\x{b:02x}" for b in data)
    if len(text) <= NAME_MOST:
        return text
    return text[:NAME_MOST - 16] + "..." + hashlib.sha256(data).hexdigest()[:13]


def read_file(path, most):
    """The first `most` bytes of a regular file, or None: opened with no link followed and not blocking, and read only
    when it is a regular file, so a FIFO, a device or a link there cannot make the reading wait or read elsewhere."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) |
                     getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        chunks, left = [], most
        while left > 0:
            block = os.read(fd, min(left, 1 << 16))
            if not block:
                break
            chunks.append(block)
            left -= len(block)
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(fd)


def digest(path, most=FILE_MOST):
    """(size, sha256 or None) of a regular file or a link, or None for anything else. A link is read as a link (the
    digest of its target's name), and a regular file through read_file's checks, up to `most` bytes."""
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if stat.S_ISLNK(st.st_mode):
        try:
            target = os.readlink(path)
        except OSError:
            return None
        return len(target), hashlib.sha256(b"link:" + os.fsencode(target)).hexdigest()
    if not stat.S_ISREG(st.st_mode):
        return None
    if st.st_size > most:
        return st.st_size, None
    data = read_file(path, most + 1)
    if data is None:
        return st.st_size, None
    return len(data), hashlib.sha256(data).hexdigest() if len(data) <= most else None


class Reading:
    def __init__(self, home, uid=None, proc="/proc", clock=time.time):
        self.home, self.uid, self.proc, self.clock = home, os.getuid() if uid is None else uid, proc, clock
        self.items, self.more, self.counts, self.cut = [], 0, {}, set()

    def add(self, kind, name, size=None, sha256=None, task=None):
        if self.counts.get(kind, 0) >= KIND_MOST.get(kind, 100):
            self.more += 1
            self.cut.add(kind)          # the hub marks nothing of this kind gone: what was left out may be there
            return
        self.counts[kind] = self.counts.get(kind, 0) + 1
        item = {"kind": kind, "name": name, "size": size, "sha256": sha256}
        if task:
            item["task"] = task
        self.items.append(item)

    def file(self, kind, rel, most=FILE_MOST):
        found = digest(os.path.join(self.home, rel), most)
        if found:
            self.add(kind, esc(rel), *found)

    def folder(self, kind, rel, depth, most=FILE_MOST):
        """Each file and link of a folder of the home, down to `depth` levels, in name order, with no link to a
        folder followed. It stops at the kind's bound, and each entry past it counts in `more`."""
        root = os.path.join(self.home, rel)
        if os.path.islink(root) or not os.path.isdir(root):
            return
        level = [root]
        for _ in range(depth):
            below = []
            for here in level:
                try:
                    with os.scandir(here) as it:
                        entries = sorted(it, key=lambda e: e.name)
                except OSError:
                    continue
                for entry in entries:
                    if self.counts.get(kind, 0) >= KIND_MOST.get(kind, 100):
                        self.more += 1
                        self.cut.add(kind)
                        continue
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            below.append(entry.path)
                            continue
                    except OSError:
                        continue
                    self.file(kind, os.path.relpath(entry.path, self.home), most)
            level = below

    def kit(self):
        """Each checkout of the home (fleet-<name> with a .git): the commit that its HEAD names, read from git's own
        files with no git command (a git command would run the checkout's own hooks and settings); its top files and
        the files of KIT_FOLDERS; and its git settings and hooks (kit_git), which run when the helper's git works
        there. HEAD is read again after the files, so a reading in the middle of an update says so (None)."""
        try:
            entries = sorted(os.listdir(self.home))
        except OSError:
            return
        for top in entries:
            checkout = os.path.join(self.home, top)
            git_dir = os.path.join(checkout, ".git")
            if not top.startswith("fleet-") or os.path.islink(checkout) or os.path.islink(git_dir) or \
                    not os.path.isdir(git_dir):
                continue
            head = head_commit(git_dir)
            try:
                with os.scandir(checkout) as it:
                    tops = sorted(it, key=lambda e: e.name)
            except OSError:
                tops = []
            for entry in tops:
                try:
                    if entry.name == ".git" or entry.is_dir(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                self.file("kit", os.path.relpath(entry.path, self.home), KIT_FILE_MOST)
            for sub in KIT_FOLDERS:
                self.folder("kit", os.path.join(top, sub), KIT_DEPTH, KIT_FILE_MOST)
            self.file("kit_git", os.path.join(top, ".git", "config"))
            self.folder("kit_git", os.path.join(top, ".git", "hooks"), 1)
            self.add("kit_head", esc(top), None, head if head_commit(git_dir) == head else None)

    def programs(self):
        """The pinned programs: each file named in PROGRAM_NAMES under ~/.fleet/programs, with no link to a folder
        followed and no folder of PROGRAM_SKIP entered."""
        root = os.path.join(self.home, PROGRAMS)
        if os.path.islink(root) or not os.path.isdir(root):
            return
        level, entered = [root], 0
        for depth in range(PROGRAM_DEPTH):
            below = []
            for here in level:
                if entered >= PROGRAM_FOLDERS_MOST:
                    self.more += 1
                    self.cut.add("program")
                    return
                entered += 1
                try:
                    with os.scandir(here) as it:
                        entries = sorted(it, key=lambda e: e.name)
                except OSError:
                    continue
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name not in PROGRAM_SKIP and (depth or entry.name not in PROGRAM_SKIP_TOP):
                                below.append(entry.path)
                            continue
                    except OSError:
                        continue
                    if entry.name in PROGRAM_NAMES or entry.name.startswith("python3"):
                        self.file("program", os.path.relpath(entry.path, self.home))
            level = below

    def site(self):
        """The Python user site: each entry's name, and a digest of each file there (a .pth file runs at each start
        of a Python with no -I)."""
        import site
        try:
            folder = site.getusersitepackages()
        except Exception:       # noqa: BLE001 -- a Python with no user site: nothing to list
            return
        if not isinstance(folder, str) or not folder.startswith(self.home + os.sep):
            return
        self.folder("site", os.path.relpath(folder, self.home), 1)

    def cron(self):
        if not os.path.exists(CRONTAB):
            return
        try:
            done = subprocess.run([CRONTAB, "-l"], capture_output=True, timeout=20, stdin=subprocess.DEVNULL,
                                  env={"PATH": "/usr/bin:/bin", "LANG": "C"}, cwd="/")
        except (OSError, subprocess.SubprocessError):
            return
        if done.returncode == 0 and done.stdout:
            self.add("cron", "crontab", len(done.stdout), hashlib.sha256(done.stdout).hexdigest())

    def processes(self):
        """Each process of this user: its command's name and the task that its environment names, one item for each
        name and task (so a process with no task never hides under one that has a task), its count as `size`; and
        the inodes of the sockets that its processes hold."""
        counts, sockets = {}, set()
        try:
            pids = [p for p in os.listdir(self.proc) if p.isdigit()]
        except OSError:
            return sockets
        parents = {pid: parent_of(os.path.join(self.proc, pid)) for pid in pids}
        own = self.pipeline(parents)
        for pid in pids:
            base = os.path.join(self.proc, pid)
            try:
                if os.stat(base).st_uid != self.uid:
                    continue
            except OSError:
                continue
            if pid in own or parents.get(pid) in own:
                continue                # the reading's own pipeline (timeout, this Python) and its children
            comm = read_file(os.path.join(base, "comm"), 64)
            if comm is None:
                continue
            task = None
            for part in (read_file(os.path.join(base, "environ"), 1 << 20) or b"").split(b"\0"):
                if part.startswith(b"FLEET_TASK=T-") and part[13:].isdigit() and len(part) <= 33:
                    task = part[11:].decode("ascii")
            key = (esc(comm.rstrip(b"\n")), task)
            counts[key] = counts.get(key, 0) + 1
            try:
                for fd in os.listdir(os.path.join(base, "fd"))[:4096]:
                    target = os.readlink(os.path.join(base, "fd", fd))
                    if target.startswith("socket:[") and target.endswith("]"):
                        sockets.add(target[8:-1])
            except OSError:
                pass
        for (comm, task), n in sorted(counts.items(), key=lambda kv: (kv[0][0], kv[0][1] or "")):
            self.add("process", f"{comm} {task or '(no task)'}", n, None, task)
        return sockets

    def pipeline(self, parents):
        """The reading's own process, and its parent when that is the timeout that runs it (of this user), and no
        other process: a process that the agent's user left behind stays in the reading, whatever its session, also
        a child of that user's own systemd or of the service where the agent runs as the service's user."""
        me = str(os.getpid())
        own, parent = {me}, parents.get(me)
        if parent:
            try:
                mine = os.stat(os.path.join(self.proc, parent)).st_uid == self.uid
            except OSError:
                mine = False
            if mine and (read_file(os.path.join(self.proc, parent, "comm"), 64) or b"").rstrip(b"\n") == b"timeout":
                own.add(parent)
        return own

    def listeners(self, sockets):
        """Each TCP port that a socket of this user listens on, and each abstract socket of its processes that
        listens (a program with no session can wait there). The kernel's tables are read as bytes: an abstract
        socket's name is raw bytes that any user of the machine chooses."""
        for table in ("tcp", "tcp6"):
            data = read_file(os.path.join(self.proc, "net", table), 8 * 1024 * 1024) or b""
            for line in data.split(b"\n")[1:]:
                parts = line.split()
                if len(parts) < 8 or parts[3] != b"0A" or not parts[7].isdigit() or int(parts[7]) != self.uid:
                    continue
                address, _, port = parts[1].partition(b":")
                try:
                    self.add("listener", f"{table} {address_text(address.decode('ascii'))}:{int(port, 16)}")
                except ValueError:
                    continue
        data = read_file(os.path.join(self.proc, "net", "unix"), 16 * 1024 * 1024) or b""
        for line in data.split(b"\n")[1:]:
            parts = line.split(None, 7)
            # Num RefCount Protocol Flags Type St Inode Path; Flags 00010000 is a listening socket
            try:
                listening = int(parts[3], 16) & 0x10000 if len(parts) == 8 else 0
            except ValueError:
                continue
            if listening and parts[7].startswith(b"@") and parts[6].decode("ascii", "replace") in sockets:
                self.add("listener", "unix " + esc(parts[7]))

    def read(self):
        for rel in DOT_FILES:
            self.file("dot", rel)
        for rel in DOT_FOLDERS:
            self.folder("dot", rel, 1)
        for rel in RUNTIME_FILES:
            self.file("runtime", rel)
        for rel in RUNTIME_FOLDERS:
            self.folder("runtime", rel, 2)
        for kind, rel, depth in FOLDERS:
            self.folder(kind, rel, depth)
        self.programs()
        self.site()
        self.cron()
        self.listeners(self.processes())
        self.kit()                      # last: many checkouts can fill only their own kinds
        return {"version": 1, "read": self.clock(), "items": self.items, "more": self.more, "cut": sorted(self.cut)}


def parent_of(base):
    """The parent's id of a process from its /proc stat line (the second field after the command's name), or None."""
    data = read_file(os.path.join(base, "stat"), 4096) or b""
    fields = data.rpartition(b")")[2].split()
    return fields[1].decode("ascii") if len(fields) > 1 and fields[1].isdigit() else None


def head_commit(git_dir):
    """The commit that a checkout's HEAD names, from git's own files (HEAD, then the ref's file or packed-refs), each
    read through read_file with a bound, or None. 40 hex characters only."""
    def plain(raw):
        text = (raw or b"").strip().decode("ascii", "replace")
        return text if len(text) == 40 and all(c in "0123456789abcdef" for c in text) else None
    head = (read_file(os.path.join(git_dir, "HEAD"), 256) or b"").strip()
    if not head.startswith(b"ref: "):
        return plain(head)
    ref = head[5:].strip().decode("ascii", "replace")
    if not ref.startswith("refs/") or ".." in ref or "\\" in ref:
        return None
    found = read_file(os.path.join(git_dir, ref), 128)
    if found is not None:
        return plain(found)
    for line in (read_file(os.path.join(git_dir, "packed-refs"), 1 << 20) or b"").split(b"\n"):
        sha, _, name = line.strip().partition(b" ")
        if name.decode("ascii", "replace") == ref:
            return plain(sha)
    return None


def address_text(hexed):
    """A /proc/net/tcp address in its usual form."""
    try:
        raw = bytes.fromhex(hexed)
        if len(raw) == 4:
            return socket.inet_ntop(socket.AF_INET, raw[::-1])
        if len(raw) == 16:
            return "[" + socket.inet_ntop(socket.AF_INET6, b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))) + "]"
    except (ValueError, OSError):
        pass
    return esc(hexed)


def limits():
    """A reading ends after TIME_MOST seconds and takes at most MEMORY_MOST bytes: limits of this process, which no
    other process of the user can lift. On a system without them (a Mac in a test) nothing is set."""
    try:
        import resource
        import signal
        signal.alarm(TIME_MOST)
        resource.setrlimit(resource.RLIMIT_AS, (MEMORY_MOST, MEMORY_MOST))
    except (ImportError, OSError, ValueError, AttributeError):
        pass


if __name__ == "__main__":
    limits()
    json.dump(Reading(os.path.expanduser("~")).read(), sys.stdout, separators=(",", ":"))
