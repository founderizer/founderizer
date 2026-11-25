#!/usr/bin/env python3
"""The hub's ports answer only as their own users (VAULT.md limit 29; MUST 1 of the read "F1 P8" of the area "Vault,
keys and access", 23 November 2026). Root's program on the hub's Linux server. Standard library only.

    python3 -I ports.py install --hub-user fleet [--gate-user founderizer-connect] [--check]
                    root's step: hub.sh runs it in its firewall step, and `hubsetup.py one-server` before it clones
                    anything (hubsetup.py ports_install). It installs this program, the kernel rule and its units, the
                    one root command below and its sudoers file, loads the rule, and starts or stops no service of the
                    hub. Safe to run again. --check changes nothing: it says whether the rule's unit is active, whether
                    the kernel's sets are the UIDs of the users of now, and whether another user listens on the ports
    python3 -I /usr/local/lib/founderizer-ports/ports.py rules
                    the units' step: the kernel rule with the UIDs of now, then the holder's round
    /usr/local/lib/founderizer-ports/holder
                    the one fixed root command: no argument and no input. The users of the three ports run it with
                    `sudo -n`. It ends each listener on the three ports whose user is neither root nor the port's own,
                    and prints one line for each port (holder_round says its words)

Why. The hub listens on 8765 and its git service on 9418, both as the hub's user, and the connect gate on 127.0.0.1:8767
as its own user. Each port is above 1024, so each user of the server can listen there while the program does not run:
after a crash, a restart, a new unit text, a start of the server, a second owner claim. On a server that also runs
agents, an agent's user could then answer as the hub, and the server's broker would give it keys.

The kernel rule. One nftables table, `inet founderizer_ports`, in the output hook, for IPv4 and IPv6: a packet from TCP
port 8765 or 9418 whose socket's user is not the hub's user or root is dropped, and so is a packet from 127.0.0.1 or ::1
port 8767 whose socket's user is not the gate's user or root. The kernel reads the user of the socket (meta skuid), so
the rule holds for each program of a user. A client of a foreign listener gets no handshake: the kernel sends the
SYN-ACK of a listener as a packet of the listener's socket. Root stays in each set, for the owner claim and for a
program of root's. A packet that no socket of a user sends (the kernel's own reset) does not match, and goes out. The
sets are the UIDs of the users at the time of the load: the boot unit loads them before the users' services, and the
path unit of /etc/passwd loads them again when a user comes or goes (the gate's user comes with `connect on`).

The held port. The rule keeps a foreign listener from answering, but the port stays taken, and the program of the port
cannot bind. So the holder ends it. It reads each listener of the three ports from the kernel's own tables
(/proc/net/tcp and tcp6, whose uid column is the socket's user, never a word of a process), and ends each process that
holds a listener whose user is neither root nor the port's own: it stops each such process (SIGSTOP), and each one
that a fork gave the socket in the meantime, then ends them all (SIGKILL). It judges a process by its real UID only, and
ends no process whose real UID is root's or the port's own user's, also when such a process holds a foreign socket:
then it ends nothing on that port and says why. The units' step runs it after each load, the gate's unit runs that
step before each start, the hub's and the git service's units run the holder before each start
(lifecycle.service_unit), and the hub may call it once when its bind meets a taken port. A program of a user that is not root can run it too (no sudo): then it ends nothing and only says who holds what.

The owner claim's pause. While root's side of a second claim (hub.sh, its claim step) holds the lock of PAUSE, a file
of root's alone in /run, the claim has stopped the hub and listens on its port itself. The holder then says so in the
line of a listener of root's or of the hub's own user (it never ends either), so that a start of the hub in that time
can end quietly. A lock that nobody holds is no pause: a claim that ended, also by a kill, leaves none.

The units. founderizer-ports.service loads the rule at boot (DefaultDependencies=no, before the network and the users'
services). Each user's manager (a drop-in of user@.service: the hub's user runs the hub and its git service there,
and an agent's user its own services), the gate's unit, this server's vault broker, and cron and at require it, so none
of them starts when the rule does not load (the coordinator's validator and the Door area, 24 November 2026): not the
hub, not an agent's own service or job, and not the broker, which would send an agent's key to the hub's address. Its
own line in the journal says why. And no agent user logs in by SSH (a file of sshd's, DenyGroups of the agents'
group): an agent owns its home and could put a key of its own there. What still runs then is root's and the hub's
user's login by SSH, which pam_systemd lets go on with no user manager, for a repair. **Never restart that unit**: a restart of a unit restarts each unit that requires it. founderizer-ports-reload.service
runs the same step again, from the path unit; and a drop-in of nftables.service runs it after that unit flushes the
kernel's rules (its start, reload and stop). A flush by hand (`nft flush ruleset`) takes the rule away until the next
change of /etc/passwd, the next start of the gate or the next boot, as it does with each table of root's."""
import argparse
import contextlib
import fcntl
import glob
import ipaddress
import json
import os
import platform
import pwd
import re
import signal
import stat
import subprocess
import sys
import time

HUB_PORT, GIT_PORT, GATE_PORT = 8765, 9418, 8767    # HUB_PORT: the hub's port when hub.sh had no --port
SETS = {HUB_PORT: "hub", GIT_PORT: "git", GATE_PORT: "gate"}    # each port and its set of users, in this order
GATE_USER = "founderizer-connect"       # hubsetup.CONNECT_USER: the connect gate's own user
TABLE = 2                               # the version of the table's text, in its comment
LIB = "/usr/local/lib/founderizer-ports"
PROGRAM = LIB + "/ports.py"             # this program as root's step installed it: what each unit and the holder run
HOLDER = LIB + "/holder"                # the one root command, and the only one in the sudoers file
CONF_DIR = "/etc/founderizer-ports"
CONF = CONF_DIR + "/ports.json"         # root's, mode 644: the user of each port, by name
LOCK = "/run/founderizer-ports.lock"    # one load at a time: boot, the path unit, nftables.service, the gate, a step
PAUSE = "/run/founderizer-hub-pause"    # hub.sh PAUSE_MARK: root holds its lock for the time of a second owner claim
UNITS = "/etc/systemd/system"
SERVICE = "founderizer-ports"           # the boot unit
RELOAD = "founderizer-ports-reload"     # the same step again, from the path unit
GATE_SERVICE = "founderizer-connect"    # hubsetup.CONNECT_SERVICE
BROKER_SERVICE = "fleet-vault"           # hubsetup.VAULT_UNIT: this server's vault broker, which sends keys to the hub
NFT_SERVICE = "nftables"
SUDOERS = "/etc/sudoers.d/founderizer-ports"
AGENT_GROUP = "fleet-agents"            # hubsetup.AGENT_GROUP: every agent user of this server, and nobody else
SSHD_DIR = "/etc/ssh/sshd_config.d"     # hubsetup.SSHD_DIR: sshd's own folder of files
SSHD_AGENTS = SSHD_DIR + "/10-founderizer-agents.conf"
SSHD_AGENTS_TEXT = ("# Founderizer: no agent user logs in by SSH on the hub's server (ports.py). An agent's user owns its\n"
                    "# home, so a key of its own in ~/.ssh would else let it log in, also when the rule of the hub's\n"
                    "# ports did not load and the port has no rule. Root's: `ports.py install` writes it.\n"
                    f"DenyGroups {AGENT_GROUP}\n")
JOB_SERVICES = ("cron", "atd")         # the system units that run an agent's own jobs: cron and at
NFT = "/usr/sbin/nft"
PYTHON = "/usr/bin/python3"
APT_LOCK_WAIT = 1200                    # hubsetup.APT_LOCK_WAIT: the first updates of a new server hold apt's lock
TCP_TABLES = (("/proc/net/tcp", False), ("/proc/net/tcp6", True))
LISTEN = "0A"                           # the state of a listening socket in those tables
# The holder's rounds: in each one it stops (SIGSTOP) each process that holds a foreign listener, looks again until
# no new holder comes (a stopped process forks no more, so a child that a fork gave the socket is found and stopped
# too), then ends them all (SIGKILL, which no handler catches) and waits for the port. At most about 7 seconds in all,
# so that the wait of the program that called it stays short.
ROUNDS = 3
FREEZE = 50                             # looks for new holders in one round, at most
KILL_WAIT = 2.0                         # seconds that a round waits for the port after its SIGKILL
OWNER = 0                               # the owner of each file of root's (a test's own user in a test)
NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}")    # a user name, as useradd makes one
PAUSED = ", paused for the owner claim"    # the words of a line of the holder: see holder_round


class Refused(Exception):
    """A step that cannot be done. Its words say why, and nothing changed after them."""


class SSHRefused(Refused):
    """The SSH part of root's step cannot be done, after the rule and its units hold: its words say why. Its answer
    names the part ("part": "ssh"), so that the caller does not say that the hub's ports are open to each user."""


def run_argv(argv, input=None, timeout=120):
    """(exit code, standard output, standard error) of one command. A command that cannot start is code 1."""
    try:
        if input is None:
            done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        else:
            done = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return 1, "", str(e)
    return done.returncode, done.stdout or "", done.stderr or ""


def uid_of(name):
    try:
        return pwd.getpwnam(name).pw_uid
    except KeyError:
        return None


def name_of(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


# ---------------------------------------------------------------- the users of the ports

def conf_text(hub_user, gate_user=GATE_USER, hub_port=HUB_PORT):
    """The configuration: the user of each port, by name, and the hub's port (hub.sh --port, team.json's
    hub.port). The git service runs as the hub's user."""
    return json.dumps({"ports": 1, "hub": hub_user, "git": hub_user, "gate": gate_user, "hub_port": hub_port},
                      indent=2) + "\n"


def hub_port_of(value):
    """The hub's port as a number, or Refused: above 1024 (the hub runs as a user), and none of the other two."""
    if isinstance(value, bool) or not isinstance(value, int) or not 1024 < value < 65536 or \
            value in (GIT_PORT, GATE_PORT):
        raise Refused(f"{value!r} is not a port that the hub can have: a number above 1024, and not {GIT_PORT} or "
                      f"{GATE_PORT}")
    return value


def ports_of(conf):
    """{port: set} of this server, in the order of SETS: the hub's own port (a hub that hub.sh started with --port has
    another one than 8765, the coordinator's validator, 24 November 2026), the git service's and the gate's."""
    return {conf.get("hub_port", HUB_PORT): "hub", GIT_PORT: "git", GATE_PORT: "gate"}


def config(path=None):
    """The user of each set, checked: {"hub", "git", "gate"}. Only a file of root's, which no other user can change,
    counts. Raises Refused with the reason."""
    path = path or CONF
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as e:
        raise Refused(f"{path} is not there ({e.strerror}): run root's step `ports.py install` again") from None
    with os.fdopen(fd, encoding="utf-8") as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != OWNER or info.st_mode & 0o022:
            raise Refused(f"{path} is not a file of root's that only root can change")
        try:
            conf = json.loads(f.read(4096))
        except ValueError:
            raise Refused(f"{path} is no JSON") from None
    if not isinstance(conf, dict) or conf.get("ports") != 1:
        raise Refused(f"{path} is not of format 1")
    for key in SETS.values():
        if not isinstance(conf.get(key), str) or not NAME.fullmatch(conf[key]):
            raise Refused(f"{path} names no valid user for {key}")
    conf["hub_port"] = hub_port_of(conf.get("hub_port", HUB_PORT))
    return conf


def wanted(conf, uid=uid_of):
    """{set: sorted UIDs}: root, and the port's own user when this server has that user (the gate's user comes with
    `connect on`; until then only root answers on 8767)."""
    out = {}
    for name in SETS.values():
        own = uid(conf[name])
        out[name] = sorted({0} | ({own} if own is not None else set()))
    return out


# ---------------------------------------------------------------- the kernel rule

def table_text(hub_port=HUB_PORT):
    """The table with no elements. The first two lines make the whole table new in the same transaction, so that a
    load replaces it and no packet sees half of one (as vault.egress_table).

    For each port, three lines in this order: a packet of a socket of the port's own user or root goes; a SYN-ACK
    that no such socket sends is dropped; a packet of another user's socket is dropped. The second line is for a SYN
    cookie: the kernel sends a cookie's SYN-ACK with no socket (tcp_make_synack, TCP_SYNACK_COOKIE), so `meta skuid`
    matches nothing in it, and an agent's listener whose queue it filled itself (its own SYN-ACKs are dropped) would
    else complete a client's handshake by cookie and read the client's first data (the Door area's read of 24
    November 2026). Under a SYN flood the port's own program then answers no new client by cookie either: a denial
    only, which VAULT.md limit 29 says. Other packets with no socket (a reset of the kernel) still go."""
    return f"""table inet founderizer_ports
delete table inet founderizer_ports
table inet founderizer_ports {{
  comment "founderizer-ports {TABLE}"
  set hub {{ type uid; }}
  set git {{ type uid; }}
  set gate {{ type uid; }}
  chain out {{
    type filter hook output priority 0; policy accept;
    tcp sport {hub_port} meta skuid @hub accept
    tcp sport {hub_port} tcp flags & (syn | ack) == syn | ack drop
    tcp sport {hub_port} meta skuid != @hub drop
    tcp sport {GIT_PORT} meta skuid @git accept
    tcp sport {GIT_PORT} tcp flags & (syn | ack) == syn | ack drop
    tcp sport {GIT_PORT} meta skuid != @git drop
    ip saddr 127.0.0.1 tcp sport {GATE_PORT} meta skuid @gate accept
    ip saddr 127.0.0.1 tcp sport {GATE_PORT} tcp flags & (syn | ack) == syn | ack drop
    ip saddr 127.0.0.1 tcp sport {GATE_PORT} meta skuid != @gate drop
    ip6 saddr ::1 tcp sport {GATE_PORT} meta skuid @gate accept
    ip6 saddr ::1 tcp sport {GATE_PORT} tcp flags & (syn | ack) == syn | ack drop
    ip6 saddr ::1 tcp sport {GATE_PORT} meta skuid != @gate drop
  }}
}}
"""


def load_text(sets, hub_port=HUB_PORT):
    """One nft transaction: the whole table, then the elements of its sets."""
    return table_text(hub_port) + "".join(f"add element inet founderizer_ports {name} {{ {', '.join(map(str, uids))} }}\n"
                                  for name, uids in sets.items())


@contextlib.contextmanager
def locked(path=None):
    fd = os.open(path or LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def load(conf, run=run_argv, uid=uid_of):
    """The table with the sets of now, in one nft transaction, under LOCK. (ok, the sets, what nft said). nft takes a
    file whole or not at all, so a load that fails leaves the table of before, or none."""
    sets = wanted(conf, uid)
    with locked():
        code, out, err = run([NFT, "-f", "-"], input=load_text(sets, conf.get("hub_port", HUB_PORT)))
    return code == 0, sets, " ".join((err or out).split())[-300:]


def kernel(run=run_argv, uid=uid_of):
    """(version, {set: sorted UIDs}) of the table in the kernel now, or (None, {}) when it has none."""
    code, out, _ = run([NFT, "-j", "list", "table", "inet", "founderizer_ports"])
    if code != 0:
        return None, {}
    try:
        items = json.loads(out).get("nftables", [])
    except (ValueError, AttributeError):
        return None, {}
    version, sets = None, {}
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        table = item.get("table")
        if isinstance(table, dict) and isinstance(table.get("comment"), str):
            found = re.fullmatch(r"founderizer-ports ([0-9]{1,6})", table["comment"])
            version = int(found.group(1)) if found else None
        one = item.get("set")
        if isinstance(one, dict) and one.get("name") in SETS.values():
            elems = one.get("elem", [])
            got = set()
            for elem in elems if isinstance(elems, list) else [elems]:
                if isinstance(elem, int) and not isinstance(elem, bool):
                    got.add(elem)
                elif isinstance(elem, str):     # a version of nft that prints the user's name
                    got.add(int(elem) if elem.isdigit() else uid(elem))
            sets[one["name"]] = sorted(u for u in got if u is not None)
    return version, sets


# ---------------------------------------------------------------- the held port

def address_of(word):
    """An address as /proc/net/tcp and tcp6 write it: each 32-bit word in the machine's own byte order."""
    raw = bytes.fromhex(word)
    if sys.byteorder == "little":
        raw = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
    return ipaddress.ip_address(raw)


def listeners(tables=None, ports=None):
    """[(port, address, uid, inode)] of each TCP socket that listens on one of the three ports, from the kernel's own
    tables. The uid is the socket's own, which the kernel keeps: never a word of a process."""
    found = []
    for path, six in tables or TCP_TABLES:
        try:
            with open(path, encoding="ascii", errors="replace") as f:
                rows = f.read().splitlines()[1:]
        except FileNotFoundError:
            if six:
                continue            # a kernel with no IPv6
            raise
        for row in rows:
            cols = row.split()
            if len(cols) < 10 or cols[3] != LISTEN:
                continue
            host, _, port = cols[1].partition(":")
            try:
                port = int(port, 16)
                if port in (ports or SETS):
                    found.append((port, address_of(host), int(cols[7]), int(cols[9])))
            except ValueError:
                continue
    return found


def takes(port, address):
    """True when a listener at this address takes the port's place. Each address of 8765 and 9418. For the gate's
    127.0.0.1:8767, the addresses whose listener a client of 127.0.0.1 or ::1 reaches, or that keep the gate from its
    bind: 0.0.0.0, ::, 127.0.0.1, ::1 and ::ffff:127.0.0.1. An agent's listener on another address of 8767 takes
    nothing of the gate's."""
    if port != GATE_PORT:
        return True
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_unspecified or str(address) in ("127.0.0.1", "::1")


def holders(inode, proc="/proc"):
    """The PIDs of the processes that hold the socket `inode`: each process with a descriptor of it."""
    target, out = f"socket:[{inode}]", []
    for name in os.listdir(proc):
        if not name.isdigit():
            continue
        if holds(int(name), inode, proc, target):
            out.append(int(name))
    return out


def holds(pid, inode, proc="/proc", target=None):
    target = target or f"socket:[{inode}]"
    folder = os.path.join(proc, str(pid), "fd")
    try:
        fds = os.listdir(folder)
    except OSError:
        return False
    for fd in fds:
        try:
            if os.readlink(os.path.join(folder, fd)) == target:
                return True
        except OSError:
            continue
    return False


def real_uid(pid, proc="/proc"):
    """The real UID of a process, or None when it is gone. Only the real UID says whose a process is: a program with
    the setuid bit that an agent's user started (passwd, su) has the effective UID 0, and an open descriptor of the
    agent's socket that it holds must not make the socket root's (the Door area's read of 24 November 2026)."""
    try:
        with open(os.path.join(proc, str(pid), "status"), encoding="ascii", errors="replace") as f:
            for line in f:
                if line.startswith("Uid:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def program_of(pid, proc="/proc"):
    """The name of a process's program, for the words only: its own text, so only plain characters of it."""
    try:
        with open(os.path.join(proc, str(pid), "comm"), encoding="utf-8", errors="replace") as f:
            word = re.sub(r"[^A-Za-z0-9._+-]", "?", f.read().strip())[:15]
    except OSError:
        word = ""
    return word or "unknown"


def send(pid, inode, never, sig, proc="/proc", keep=False):
    """`sig` to the process `pid`, when it still holds the socket `inode` and its real UID is not in `never`. Through
    a pidfd, so that a new process that took the number in between gets nothing: the check comes after the pidfd is
    open. True when the signal went; with `keep`, the pidfd itself then (True on a system with none), open, for the
    signals after a stop (resend), which the caller closes (close)."""
    pidfd = None
    try:
        if hasattr(os, "pidfd_open"):
            pidfd = os.pidfd_open(pid)
        owner = real_uid(pid, proc)
        if owner is None or owner in never or not holds(pid, inode, proc):
            return False
        if pidfd is not None and hasattr(signal, "pidfd_send_signal"):
            signal.pidfd_send_signal(pidfd, sig)
        else:
            os.kill(pid, sig)
        if keep:
            kept, pidfd = (pidfd if pidfd is not None else True), None
            return kept
        return True
    except OSError:
        return False
    finally:
        if pidfd is not None:
            os.close(pidfd)


def close(handle):
    """A pidfd that send(keep=True) gave, closed; nothing for True."""
    if handle is not True and isinstance(handle, int):
        with contextlib.suppress(OSError):
            os.close(handle)


def resend(pid, handle, never, sig, proc="/proc"):
    """`sig` to a process that the holder stopped, with no look at its descriptors: a sibling that shares its
    descriptor table (CLONE_FILES) may have closed the socket in the meantime, and a stopped process must still get
    its SIGKILL or SIGCONT, never stay stopped (the Door area's read of 24 November 2026). Through the pidfd of its stop
    (`handle`), so that a process that took its number after another one ended it gets nothing (the reads of Vault and
    Door, 24 November 2026); on a system with no pidfd, by its number, when its real UID is not in `never`. True when
    the signal went."""
    try:
        if handle is not True and isinstance(handle, int) and hasattr(signal, "pidfd_send_signal"):
            signal.pidfd_send_signal(handle, sig)
            return True
        owner = real_uid(pid, proc)
        if owner is None or owner in never:
            return False
        os.kill(pid, sig)
        return True
    except OSError:
        return False


def end_listener(inode, never, proc="/proc", tables=None, sleep=time.sleep, clock=time.monotonic, ports=None):
    """End each process that holds the listening socket `inode` (ROUNDS). Returns "" when the socket is gone, and else
    why it stays. It ends nothing when a process whose real UID is in `never` holds the socket too: then the socket
    stays in any case, and ending the others would only end programs. A process that it stopped in a round that then
    meets such a process goes on again (SIGCONT)."""
    def gone():
        return all(found != inode for _port, _address, _uid, found in listeners(tables, ports))

    def ours(pids):
        return any(real_uid(pid, proc) in never for pid in pids)

    for _round in range(ROUNDS):
        pids = holders(inode, proc)
        if not pids:
            return "" if gone() else "no process of this server holds it"
        if ours(pids):
            return "a process of root or of the port's own user holds it too"
        stopped, seen = [], set()           # (pid, the pidfd of its stop)
        try:
            for _look in range(FREEZE):
                new = [pid for pid in holders(inode, proc) if pid not in seen]
                if not new:
                    break
                if ours(new):
                    for pid, handle in stopped:
                        resend(pid, handle, never, signal.SIGCONT, proc)
                    return "a process of root or of the port's own user holds it too"
                seen.update(new)
                for pid in new:
                    handle = send(pid, inode, never, signal.SIGSTOP, proc, keep=True)
                    if handle is not False:
                        stopped.append((pid, handle))
            if not stopped:
                return "" if gone() else "no signal reached its process"
            for pid, handle in stopped:
                resend(pid, handle, never, signal.SIGKILL, proc)
        finally:
            for _pid, handle in stopped:
                close(handle)
        end = clock() + KILL_WAIT
        while clock() < end:
            if gone():
                return ""
            sleep(0.05)
    return "it still listens after SIGKILL"


def paused(path=None):
    """True while root's side of a second owner claim holds the lock of PAUSE. The file is root's alone (mode 600), so
    no other user can open it and hold a lock of its own; a file whose lock nobody holds is a claim that ended."""
    try:
        fd = os.open(path or PAUSE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != OWNER or info.st_mode & 0o077:
            return False
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        except OSError:
            return False
        return False
    finally:
        os.close(fd)


def holder_round(conf, end=True, uid=uid_of, proc="/proc", tables=None, pause=None, sleep=time.sleep, name=name_of):
    """The holder: (one line for each port, in the order of SETS, and True when a port stays held against its own
    user). With end=False (a run that is not root's) it ends nothing and says who holds what.

    The words of a line, `port <port>: <parts>`, parts in this order and joined with "; ":
      free                                  no listener that takes the port's place
      held by <user>, not ended (<why>)     a listener of another user that stays: the port is not free
      root's program <name>                 a listener of root's, which the holder never ends
      ended <user>                          a listener of another user, ended: the port is free for its own user
      own (<user>)                          a listener of the port's own user, which the holder never ends
    and ", paused for the owner claim" after a root's or an own part while a second claim holds PAUSE.
    A port is held when a part `held by` is in its line, or `root's program` with no pause."""
    is_paused = paused() if pause is None else pause
    chosen = ports_of(conf)
    rows = listeners(tables, chosen)
    lines, held = [], False
    for port, role in chosen.items():
        own = uid(conf[role])
        never = {0} | ({own} if own is not None else set())
        stays, roots, ended, owns = [], [], [], []
        for row_port, address, owner, inode in rows:
            if row_port != port or not takes(port, address):
                continue
            user = name(owner)
            if owner == 0:
                names = sorted({program_of(pid, proc) for pid in holders(inode, proc)}) or ["unknown"]
                roots += [n for n in names if n not in roots]
            elif owner == own:
                owns += [user] if user not in owns else []
            elif not end:
                stays += [f"{user}, not ended (only root ends it)"]
            else:
                why = end_listener(inode, never, proc, tables, sleep=sleep, ports=chosen)
                if why:
                    stays.append(f"{user}, not ended ({why})")
                elif user not in ended:
                    ended.append(user)
        pause_words = PAUSED if is_paused else ""
        parts = ([f"held by {one}" for one in dict.fromkeys(stays)]
                 + [f"root's program {', '.join(roots)}{pause_words}"] * bool(roots)
                 + [f"ended {', '.join(ended)}"] * bool(ended)
                 + [f"own ({', '.join(owns)}){pause_words}"] * bool(owns))
        held = held or bool(stays) or (bool(roots) and not is_paused)
        lines.append(f"port {port}: {'; '.join(parts) or 'free'}")
    return lines, held


# ---------------------------------------------------------------- root's files and units

HOLDER_TEXT = """#!/bin/sh
# Founderizer: the one root command of the hub's ports (ports.py, the holder). Root's: `ports.py install` writes it.
# It takes no argument and no input. The users of the three ports run it with sudo -n.
[ "$#" -eq 0 ] || {{ echo "founderizer-ports: this command takes no argument" >&2; exit 2; }}
exec {python} -I {program} holder </dev/null
"""

BOOT_UNIT = """# Founderizer: the hub's ports answer only as their own users (ports.py). Root's: `ports.py install`
# writes it. Never restart this unit: the hub user's manager and the connect gate require it, and a restart of a
# unit restarts each unit that requires it. To load the rule again: systemctl start {reload}.service
[Unit]
Description=Founderizer: the kernel rule of the hub's ports, before the users' services
DefaultDependencies=no
Wants=network-pre.target
After=local-fs.target
Before=network-pre.target systemd-user-sessions.service user@{uid}.service {gate}.service shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={python} -I {program} rules

[Install]
WantedBy=sysinit.target
"""

RELOAD_UNIT = """# Founderizer: the hub's ports (ports.py). Root's: `ports.py install` writes it. The path unit
# starts it.
[Unit]
Description=Founderizer: the kernel rule of the hub's ports again, with the users of now
StartLimitIntervalSec=0
After={service}.service

[Service]
Type=oneshot
ExecStart={python} -I {program} rules
"""

# One path unit for one file, as vault.EGRESS_PATH_UNIT: a path unit with more watches lost events under systemd 255.
PATH_UNIT = """# Founderizer: the hub's ports (ports.py). Root's: `ports.py install` writes it.
[Unit]
Description=Founderizer: the kernel rule of the hub's ports again at each change of /etc/passwd

[Path]
PathChanged=/etc/passwd
Unit={reload}.service

[Install]
WantedBy=paths.target
"""

USER_DROPIN = """# Founderizer: each user's services (the hub's user runs the hub and its git service, an agent's
# user its own) start only after the kernel rule of the hub's ports loaded, and not when it did not load, so that no
# program can take a port of the hub's that has no rule (ports.py). Root's: `ports.py install` writes it.
[Unit]
Requires={service}.service
After={service}.service
"""

JOBS_DROPIN = """# Founderizer: the jobs of this server's users (cron, at) run only after the kernel rule of the hub's
# ports loaded: an agent's job could else take the hub's free port with no rule after a start of the server whose
# load failed, and the other servers' helpers and brokers would speak to it (ports.py). Root's jobs wait for it too.
# Root's: `ports.py install` writes it.
[Unit]
Requires={service}.service
After={service}.service
"""

BROKER_DROPIN = """# Founderizer: this server's vault broker starts only after the kernel rule of the hub's ports loaded:
# it sends an agent's key to the hub's address, so with no rule a program of an agent's user that took the hub's port
# would get it (ports.py). Root's: `ports.py install` writes it.
[Unit]
Requires={service}.service
After={service}.service
"""

GATE_DROPIN = """# Founderizer: the connect gate starts only after the kernel rule of the hub's ports loaded.
# Before each start, root loads it again with the users of now and ends another user's listener on the gate's port
# (ports.py). Root's: `ports.py install` writes it.
[Unit]
Requires={service}.service
After={service}.service

[Service]
ExecStartPre=+{python} -I {program} rules
"""

NFT_DROPIN = """# Founderizer: the kernel rule of the hub's ports again after this unit loads or flushes the
# kernel's rules (ports.py). Root's: `ports.py install` writes it.
[Service]
ExecStartPost=-+{python} -I {program} rules
ExecReload=-+{python} -I {program} rules
ExecStopPost=-+{python} -I {program} rules
"""


def users_of(hub_user, gate_user=GATE_USER):
    """The users that may run the holder with sudo: the hub's (also the git service's) and the gate's."""
    return list(dict.fromkeys([hub_user, gate_user]))


def sudoers_text(users):
    return ("# Founderizer: ports.py writes this file. The users of the hub's ports may run its one root command as\n"
            "# root, which ends another user's listener on those ports and nothing else. It takes no argument and\n"
            "# no input: the empty argument list is sudoers saying \"with no arguments at all\".\n"
            + "".join(f'{user} ALL=(root) NOPASSWD: {HOLDER} ""\n' for user in users))


def files(hub_user, hub_uid, program, gate_user=GATE_USER, hub_port=HUB_PORT):
    """{path: (bytes, mode)} of each file of root's step. `program`: this program's own bytes."""
    words = {"python": PYTHON, "program": PROGRAM, "service": SERVICE, "reload": RELOAD, "gate": GATE_SERVICE,
             "uid": hub_uid, "user": hub_user}
    templates = {
        HOLDER: (HOLDER_TEXT, 0o755),
        f"{UNITS}/{SERVICE}.service": (BOOT_UNIT, 0o644),
        f"{UNITS}/{RELOAD}.service": (RELOAD_UNIT, 0o644),
        f"{UNITS}/{SERVICE}.path": (PATH_UNIT, 0o644),
        f"{UNITS}/user@.service.d/{SERVICE}.conf": (USER_DROPIN, 0o644),
        f"{UNITS}/{GATE_SERVICE}.service.d/{SERVICE}.conf": (GATE_DROPIN, 0o644),
        f"{UNITS}/{BROKER_SERVICE}.service.d/{SERVICE}.conf": (BROKER_DROPIN, 0o644),
        **{f"{UNITS}/{job}.service.d/{SERVICE}.conf": (JOBS_DROPIN, 0o644) for job in JOB_SERVICES},
        f"{UNITS}/{NFT_SERVICE}.service.d/{SERVICE}.conf": (NFT_DROPIN, 0o644),
    }
    out = {PROGRAM: (program, 0o644), CONF: (conf_text(hub_user, gate_user, hub_port).encode(), 0o644),
           SUDOERS: (sudoers_text(users_of(hub_user, gate_user)).encode(), 0o440)}
    out.update({path: (text.format(**words).encode(), mode) for path, (text, mode) in templates.items()})
    return out


def same(path, data, mode):
    """True when `path` is a file of root's with these bytes and this mode, and no link."""
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != OWNER or stat.S_IMODE(info.st_mode) != mode:
            return False
        with open(path, "rb") as f:
            return f.read() == data
    except OSError:
        return False


def folder_of_root(path):
    """Make each missing folder of `path` as root's, mode 755, and refuse a folder that another user can change."""
    folder = os.path.dirname(path)
    if not os.path.lexists(folder):
        os.makedirs(folder, exist_ok=True)
        os.chmod(folder, 0o755)
    info = os.lstat(folder)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != OWNER or info.st_mode & 0o022:
        raise Refused(f"{folder} is not a folder of root's that only root can change, so {path} is not written there")


def put(path, data, mode):
    """Write a file of root's whole: a new file beside it, then a rename. A stop in the middle leaves the old file."""
    folder_of_root(path)
    temp = f"{path}.new-{os.getpid()}"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            if os.geteuid() == 0:
                os.fchown(f.fileno(), OWNER, OWNER)
            os.fchmod(f.fileno(), mode)
            os.fsync(f.fileno())
        os.replace(temp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp)
        raise


def nft_package(run):
    """The package nftables, where this server has no nft (a server whose image left it out). apt's lists of a server
    that ran hub.sh are there; when the install fails, the lists once more, then the install."""
    install = (f"DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout={APT_LOCK_WAIT} install -y -q "
               f"--no-install-recommends nftables </dev/null >/dev/null 2>&1")
    return run(["sh", "-c", f"{install} || {{ apt-get -o DPkg::Lock::Timeout={APT_LOCK_WAIT} update -q </dev/null "
                            f">/dev/null 2>&1 && {install}; }}"], timeout=2 * APT_LOCK_WAIT + 600)


def systemctl(run, *words):
    code, out, err = run(["systemctl", *words])
    return code, " ".join((out + " " + err).split())


def state(run):
    """{unit: what systemctl is-active says} of the boot unit and the path unit."""
    out = {}
    for unit in (f"{SERVICE}.service", f"{SERVICE}.path"):
        out[unit] = systemctl(run, "is-active", unit)[1] or "not there"
    return out


def install(hub_user, gate_user=GATE_USER, check=False, run=run_argv, root="", source=None, uid=uid_of,
            rounds=None, hub_port=HUB_PORT):
    """Root's step. Returns the answer: {"ok", "state": "made" | "there" | "would make", "said": [sentences],
    "lines": [the holder's lines], "sets"}; with check, also "problems". Raises Refused with the reason.

    The order: the program, its command and the configuration; then the rule, loaded by this program now; and only
    when it loaded, the units, the drop-ins and the sudoers file, and the units enabled and started. So a rule that
    does not load leaves no unit that would keep the hub's services from their next start. A unit that is active
    stays as it is (never a restart: see the top of this file). rounds: the holder's round (a test's own)."""
    rounds = rounds or holder_round
    for who, name in (("the hub's", hub_user), ("the connect gate's", gate_user)):
        if not NAME.fullmatch(name or ""):
            raise Refused(f"{name!r} is not a user name, so it cannot be {who} user")
    hub_uid = uid(hub_user)
    if hub_uid is None:
        raise Refused(f"this server has no user {hub_user}: name the user the hub runs as with --hub-user")
    if hub_uid == 0:
        raise Refused("the hub never runs as root, so root cannot be the hub's user here")
    if hub_user == gate_user:
        raise Refused("the connect gate runs as a user of its own, never as the hub's user")
    hub_port = hub_port_of(hub_port)
    with open(source or os.path.realpath(__file__), "rb") as f:
        program = f.read()
    want = files(hub_user, hub_uid, program, gate_user, hub_port)
    differ = [path for path, (data, mode) in want.items() if not same(root + path, data, mode)]
    stale = [path for path in glob.glob(f"{root}{UNITS}/user@*.service.d/{SERVICE}.conf")     # one user's of before
             if path != f"{root}{UNITS}/user@.service.d/{SERVICE}.conf"]
    conf = json.loads(want[CONF][0])
    if check:
        return check_state(conf, differ + [path[len(root):] for path in stale], run, uid, rounds, root)
    said = []
    if not os.access(root + NFT, os.X_OK):
        code, _out, err = nft_package(run)
        if not os.access(root + NFT, os.X_OK):
            raise Refused(f"this server has no {NFT}, and the package nftables did not install "
                          f"({' '.join(err.split())[-200:] or code}), so the hub's ports have no kernel rule. Nothing "
                          f"else changed")
        said.append("installed the package nftables, for the kernel rule of the hub's ports")
    before = state(run)
    for path in (PROGRAM, CONF):
        if path in differ:
            put(root + path, *want[path])
    ok, sets, nft_said = load(conf, run, uid)
    if not ok:
        raise Refused(f"the kernel rule of the hub's ports did not load ({nft_said or 'nft said nothing'}). No unit of "
                      f"it was written, so the hub's services start as before")
    said.append(f"the kernel rule holds: only {hub_user} and root answer on {hub_port} and {GIT_PORT}, and only "
                f"{gate_user} and root on 127.0.0.1:{GATE_PORT} (IPv4 and IPv6)")
    if SUDOERS in differ:
        temp = f"{root}{SUDOERS}.check-{os.getpid()}"
        put(temp, *want[SUDOERS])
        try:
            code, out, err = run(["visudo", "-cqf", temp])
            if code != 0:
                why = " ".join((err or out).split())[-200:]
                raise Refused(f"visudo refused the sudoers file of the hub's ports ({why}), so the root command has no "
                              f"sudoers line. The rule holds")
            os.replace(temp, root + SUDOERS)
        finally:
            with contextlib.suppress(OSError):
                os.unlink(temp)
    # The holder after its sudoers line: the units run it where it is (`test -x`, lifecycle.PORT_HOLD), so it comes
    # only with the line that lets their users run it, and a step that stopped before leaves no sudo refusal at each
    # start (the coordinator's validator, 24 November 2026).
    if HOLDER in differ:
        put(root + HOLDER, *want[HOLDER])
    for path in differ:
        if path not in (PROGRAM, HOLDER, CONF, SUDOERS):
            put(root + path, *want[path])
    for path in stale:              # the drop-in of a user that is no longer the hub's
        with contextlib.suppress(OSError):
            os.unlink(path)
    for words in (("daemon-reload",), ("enable", f"{SERVICE}.service", f"{SERVICE}.path"),
                  ("start", f"{SERVICE}.service", f"{SERVICE}.path")):
        code, why = systemctl(run, *words)
        if code != 0:
            raise Refused(f"systemctl {' '.join(words)} failed ({why[-200:] or code}). The rule holds now; run the "
                          f"step again so that it holds after the next start of the server")
    after = state(run)
    if after.get(f"{SERVICE}.service") != "active":
        raise Refused(f"the unit {SERVICE} is {after.get(f'{SERVICE}.service')} after its start: look at journalctl -u "
                      f"{SERVICE}. The rule holds now; run the step again")
    ssh_changed, ssh_words = sshd_agents(run, root)
    said.append(f"the unit {SERVICE} loads it at each start of the server, before the users' services; no user's "
                f"services, no connect gate and no vault broker of this server start without it, and it loads again at "
                f"each change of /etc/passwd")
    said.append(f"{HOLDER} ends another user's listener on those ports: {' and '.join(users_of(hub_user, gate_user))} "
                f"may run it as root with sudo, with no argument")
    lines, _held = rounds(conf, uid=uid)
    said.append(ssh_words)
    made = bool(differ or stale) or ssh_changed or any(value != "active" for value in before.values())
    return {"ok": True, "state": "made" if made else "there", "said": said, "lines": lines, "sets": sets}


def sshd_words(code, out, err):
    """The last words of a refusal of sshd's, on one line: its standard error, else its output, else its exit code."""
    return " ".join((err or out or "").split())[-200:] or f"exit {code}"


def sshd_denies(run):
    """(True, "") when sshd's own reading of its settings (`sshd -T`) denies the agents' group, (False, "") when it
    does not, and (None, sshd's words) when it cannot say."""
    code, out, err = run(["sshd", "-T"])
    if code != 0:
        return None, sshd_words(code, out, err)
    for line in (out or "").lower().splitlines():
        if line.startswith("denygroups "):
            return AGENT_GROUP in line.split()[1:], ""
    return False, ""


def sshd_agents(run, root="", check=False):
    """No agent user logs in by SSH on this server (SSHD_AGENTS, `DenyGroups` of the agents' group): an agent's user
    owns its home and could put a key of its own there, and a login of it would run also when the rule did not load at
    a start of the server (the Door area's read of 24 November 2026). Only where OpenSSH has a folder of its own files.
    sshd checks the file (`sshd -t`, which needs its privilege separation folder) before it reloads, and a file that it
    refuses is taken back. Each run that is not a check reloads sshd, after its check, so that the running sshd reads
    what `sshd -T` reads. Then sshd's own reading of its settings (`sshd -T`) must deny the group, which a file of
    the folder does only where sshd_config reads the folder (the Door area: a test of the file's text alone said so
    for nothing). Before it writes the file or reloads, sshd checks the settings of this server as they are: a fault
    there is not the file's, and the words say so; only a file of ours with other text, which this step's text may
    mend, is written over then, and put back when sshd still refuses. Returns (changed, its words); with check, (would change, or does not hold,
    its words). Raises SSHRefused when sshd refuses the settings as they are or the file, when the file cannot be
    written, when the reload fails, when sshd cannot say what it reads (`sshd -T` fails), and when it does not deny the
    group; each with its own words."""
    if not os.path.isdir(root + SSHD_DIR) or not os.path.exists(root + "/usr/sbin/sshd"):
        return False, "this server has no OpenSSH with a folder of its own files, so no agent user logs in by SSH"
    path = root + SSHD_AGENTS
    try:
        with open(path, "rb") as f:            # bytes: a damaged file need not be UTF-8
            before = f.read()
    except OSError:
        before = None
    held_words = f"sshd lets no member of {AGENT_GROUP} log in; root and the hub's user still can"
    unread = (f"{SSHD_AGENTS} is there, but sshd's own reading of its settings (sshd -T) does not deny "
              f"{AGENT_GROUP}: this server's sshd_config reads no file of {SSHD_DIR}, so an agent user can still log in "
              f"by SSH")
    if check:
        if before != SSHD_AGENTS_TEXT.encode():
            return True, f"would write {SSHD_AGENTS}: sshd lets no member of {AGENT_GROUP} log in"
        held, why = sshd_denies(run)
        return (False, held_words) if held else (True, unread if held is False else
                                                  f"sshd cannot say whether it denies {AGENT_GROUP}: sshd -T failed "
                                                  f"({why})")
    with contextlib.suppress(OSError):
        os.makedirs(root + "/run/sshd", 0o755, exist_ok=True)       # sshd -t and -T need it
    changed = before != SSHD_AGENTS_TEXT.encode()
    code, out, err = run(["sshd", "-t"])                    # the settings as they are, before any change or reload
    first = sshd_words(code, out, err) if code != 0 else None
    if first is not None and (not changed or before is None):
        raise SSHRefused(f"sshd refuses this server's own settings before any change ({first}), so "
                         f"{'sshd was not reloaded' if not changed else f'{SSHD_AGENTS} was not written'}. The rule "
                         f"holds; an agent user may still log in by SSH. Correct what `sshd -t` says, and run the step "
                         f"again")
    try:
        if changed:             # also a file of ours with other text that sshd refused: this step's text may mend it
            put(path, SSHD_AGENTS_TEXT.encode(), 0o644)
            code, out, err = run(["sshd", "-t"])
            if code != 0:
                if before is None:
                    os.unlink(path)
                else:
                    put(path, before, 0o644)
                if first is not None:
                    raise SSHRefused(f"sshd refuses this server's own settings ({sshd_words(code, out, err)}), also "
                                     f"with {SSHD_AGENTS} as this step writes it, so the file of before was put back. "
                                     f"The rule holds; an agent user may still log in by SSH. Correct what `sshd -t` "
                                     f"says, and run the step again")
                raise SSHRefused(f"sshd refused {SSHD_AGENTS} ({sshd_words(code, out, err)}), so it was taken back. "
                                 f"The rule holds; an agent user can still log in by SSH. Run the step again")
    except SSHRefused:
        raise
    except (OSError, Refused) as e:            # put's own refusal of a folder too: still the SSH part's
        raise SSHRefused(f"{SSHD_AGENTS} could not be written or taken back ({e}). The rule holds; an agent user may "
                         f"still log in by SSH. Run the step again") from e
    # At each run, not only when the file changed: sshd -T reads the files, not the running sshd, which a reload that
    # failed or a run that ended before it leaves with the settings of before. A session that is open keeps going.
    code, out, err = run(["systemctl", "try-reload-or-restart", "ssh.service"])
    if code != 0:
        raise SSHRefused(f"sshd did not take its settings again (systemctl try-reload-or-restart ssh.service: "
                         f"{sshd_words(code, out, err)}). The rule holds; the running sshd may still let an agent user "
                         f"log in until it starts again. Run the step again")
    held, why = sshd_denies(run)
    if held is None:
        raise SSHRefused(f"sshd cannot say whether it denies {AGENT_GROUP}: sshd -T failed ({why}). The rule holds; an "
                         f"agent user may still log in by SSH. Correct what `sshd -T` says, and run the step again")
    if not held:
        raise SSHRefused(f"{unread}. The rule holds. Add `Include {SSHD_DIR}/*.conf` at the top of "
                         f"/etc/ssh/sshd_config, or `DenyGroups {AGENT_GROUP}` there, and run the step again")
    return changed, held_words


def check_state(conf, differ, run=run_argv, uid=uid_of, rounds=None, root=""):
    """--check: what root's step would write, whether its units are active, whether the kernel's sets are the UIDs of
    the users of now, and whether another user listens on the ports. It changes nothing and ends nothing."""
    problems, said = [], []
    problems += [f"would write {path}" for path in differ]
    for unit, active in state(run).items():
        if active != "active":
            problems.append(f"the unit {unit} is {active}")
    if not [p for p in problems if p.startswith("the unit")]:
        said.append(f"the units {SERVICE}.service and {SERVICE}.path are active")
    version, sets = kernel(run, uid)
    want = wanted(conf, uid)
    if version is not None and version != TABLE:        # the rules of another release, whatever its sets
        problems.append(f"the kernel's table is of version {version}, not {TABLE}, so root's step is owed")
    elif version != TABLE or sets != want:
        now = json.dumps(sets, sort_keys=True) if version else "not there"
        problems.append(f"the kernel's sets are {now}, and not the UIDs of the users of now "
                        f"({json.dumps(want, sort_keys=True)})")
    else:
        said.append(f"the kernel's sets match the users of now: {json.dumps(want, sort_keys=True)}")
    lines, _held = (rounds or holder_round)(conf, end=False, uid=uid)
    foreign = [line for line in lines if "held by " in line or "root's program" in line]
    problems += foreign
    would, words = sshd_agents(run, root, check=True)
    (problems if would else said).append(words)
    if not foreign:
        said.append(f"no other user's process listens on {conf.get('hub_port', HUB_PORT)}, {GIT_PORT} or "
                    f"127.0.0.1:{GATE_PORT}")
    return {"ok": not problems, "state": "there" if not problems else "would make", "said": said,
            "problems": problems, "lines": lines, "sets": sets}


# ---------------------------------------------------------------- the commands

def cmd_rules():
    """The units' step: the rule with the UIDs of now, then the holder. Its exit status is the load's alone: a port
    that root's program holds is said, and it keeps no unit from its start."""
    try:
        conf = config()
        ok, sets, said = load(conf)
    except (Refused, OSError) as e:
        ok, sets, said = False, {}, str(e)
    if not ok:
        print(f"founderizer-ports: the kernel rule of the hub's ports did not load ({said or 'nft said nothing'}), so "
              f"the hub, its git service and the connect gate do not start: an agent's user could answer on their "
              f"ports", file=sys.stderr, flush=True)
        return 1
    print(f"the kernel rule of the hub's ports holds: {json.dumps(sets, sort_keys=True)}", flush=True)
    try:
        lines, _held = holder_round(conf)
    except OSError as e:
        lines = [f"the holder could not read the listeners ({e})"]
    for line in lines:
        print(line, flush=True)
    return 0


def cmd_holder():
    """The fixed root command. Exit 0 when no port is held against its own user, 1 when one is (its line says by
    whom), 2 when it cannot read what it needs: then it ends nothing."""
    try:
        conf = config()
        lines, held = holder_round(conf, end=os.geteuid() == 0)
    except (Refused, OSError) as e:
        print(f"founderizer-ports: the holder ended nothing: {e}", flush=True)
        return 2
    for line in lines:
        print(line, flush=True)
    return 1 if held else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="The hub's ports answer only as their own users")
    sub = ap.add_subparsers(dest="what", required=True)
    ins = sub.add_parser("install", help="root's step: the rule, its units, the holder and its sudoers file")
    ins.add_argument("--hub-user", default="fleet", help="the user the hub and its git service run as")
    ins.add_argument("--gate-user", default=GATE_USER, help="the connect gate's own user")
    ins.add_argument("--hub-port", type=int, default=HUB_PORT, help="the hub's port (hub.sh --port)")
    ins.add_argument("--check", action="store_true", help="change nothing; say whether the rule holds")
    sub.add_parser("rules", help="the units' step: the rule with the UIDs of now, then the holder")
    sub.add_parser("holder", help="the fixed root command: end another user's listener on the three ports")
    args = ap.parse_args(argv)
    if args.what == "rules":
        return cmd_rules()
    if args.what == "holder":
        return cmd_holder()
    try:
        if platform.system() != "Linux":
            raise Refused("the hub's ports have a kernel rule on a Linux server, and this machine is not one")
        if os.geteuid() != 0:
            raise Refused(f"run it as root on the hub's server: python3 -I {os.path.realpath(__file__)} install")
        answer = install(args.hub_user, args.gate_user, check=args.check, hub_port=args.hub_port)
    except (Refused, OSError) as e:
        print(json.dumps({"ok": False, "reason": str(e), **({"part": "ssh"} if isinstance(e, SSHRefused) else {})}),
              flush=True)
        return 1
    for line in answer["said"] + answer["lines"] + answer.get("problems", []):
        print(line, flush=True)
    print(json.dumps(answer), flush=True)
    return 0 if answer["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
