"""The hub's ports answer only as their own users (ports.py; VAULT.md limit 29): the kernel rule's text and sets,
the holder that ends another user's listener, the pause of a second claim, and root's step with its units. The parts
that need no root and no Linux kernel: the kernel's part runs in test_port_owners_systemd.py, in a container of its own
and only when its variable asks for it.

    python3 -m unittest test_ports

The holder runs against a /proc and the kernel's two socket tables in a folder of the test. Each process that holds a
listener is a real child of the test (sleep), so a signal really ends it, and the folder loses that process and its
listener when it is gone, as the kernel does. Every name, UID and address is made up."""
import fcntl
import ipaddress
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import gate
import hubsetup
import lifecycle
import ports
from leftovers import ROOT

UIDS = {"fleet": 1100, "founderizer-connect": 999}         # the hub's user and the gate's user of these tests
NAMES = {0: "root", 1100: "fleet", 999: "founderizer-connect", 2001: "fleet-alpha", 2002: "fleet-beta"}
AGENT = 2001
CONF = {"ports": 1, "hub": "fleet", "git": "fleet", "gate": "founderizer-connect"}


def uid(name):
    return UIDS.get(name)


def name(number):
    return NAMES.get(number, str(number))


def row(address, port, owner, inode, state="0A"):
    """One row of /proc/net/tcp or tcp6 as the kernel writes it: each 32-bit word of the address in this machine's
    own byte order, the port in hex, the state, and the socket's uid and inode in their columns."""
    raw = ipaddress.ip_address(address).packed
    if sys.byteorder == "little":
        raw = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
    return (f"   0: {raw.hex().upper()}:{port:04X} {'0' * 2 * len(raw)}:0000 {state} 00000000:00000000 00:00000000 "
            f"00000000 {owner:>5}        0 {inode} 1 0000000000000000 100 0 0 10 0")


class Server:
    """A /proc and the kernel's two socket tables, in a folder. A listener is a row; each process that holds it is a
    real child of the test (sleep), with a folder of its own: its UIDs, its program's name and a descriptor of the
    socket. sleep() does the kernel's part between two looks of the holder: a child that a signal ended loses its
    folder, and a socket that no process holds any more loses its row."""

    HEAD = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

    def __init__(self, folder):
        self.proc, self.tcp, self.tcp6 = folder / "proc", folder / "tcp", folder / "tcp6"
        self.proc.mkdir()
        self.rows, self.children, self.inode = {}, {}, 4000
        self.write()

    def tables(self):
        return ((str(self.tcp), False), (str(self.tcp6), True))

    def child(self, owner, program="python3", inode=None, effective=None):
        """A real process, as the process of the (real) UID `owner` that holds the socket `inode`; with `effective`, a
        program with the setuid bit whose other three UIDs are that one."""
        child = subprocess.Popen(["sleep", "60"], stdin=subprocess.DEVNULL)
        self.children[child.pid] = child
        folder = self.proc / str(child.pid)
        (folder / "fd").mkdir(parents=True)
        other = owner if effective is None else effective
        (folder / "status").write_text(f"Name:\t{program}\nUid:\t{owner}\t{other}\t{other}\t{other}\n")
        (folder / "comm").write_text(program + "\n")
        os.symlink("/dev/null", folder / "fd" / "0")
        if inode is not None:
            os.symlink(f"socket:[{inode}]", folder / "fd" / "3")
        return child

    def listen(self, address, port, owner, program="python3", also=()):
        """A listener of the UID `owner`, held by a child of that UID and by one more child for each UID of `also`.
        Returns (its inode, its children)."""
        self.inode += 1
        held = [self.child(owner, program, self.inode)] + [self.child(more, "other", self.inode) for more in also]
        self.rows[self.inode] = (address, port, owner, [one.pid for one in held])
        self.write()
        return self.inode, held

    def write(self):
        for path, version in ((self.tcp, 4), (self.tcp6, 6)):
            rows = [row(*listener[:3], inode) for inode, listener in self.rows.items()
                    if ipaddress.ip_address(listener[0]).version == version]
            path.write_text(self.HEAD + "".join(line + "\n" for line in rows))

    def sleep(self, seconds):
        time.sleep(min(seconds, 0.05))
        for pid, child in list(self.children.items()):
            if child.poll() is not None:
                shutil.rmtree(self.proc / str(pid), ignore_errors=True)
        for inode, (_address, _port, _owner, pids) in list(self.rows.items()):
            if not any((self.proc / str(pid)).exists() for pid in pids):
                del self.rows[inode]
        self.write()

    def stop(self):
        for child in self.children.values():
            if child.poll() is None:
                child.kill()
            child.wait()

    def round(self, end=True, pause=False):
        return ports.holder_round(CONF, end=end, uid=uid, proc=str(self.proc), tables=self.tables(), pause=pause,
                                  sleep=self.sleep, name=name)


def alive(child):
    return child.poll() is None


class Rule(unittest.TestCase):
    """The kernel rule: its text, its sets, and one load of the whole table."""

    def test_another_users_answer_from_each_port_is_dropped_in_both_families(self):
        """The output hook of one inet table drops each packet from 8765 and 9418 whose socket is not of a user of the
        port's set, and from 127.0.0.1 and ::1 port 8767 likewise. A packet of the port's own user or root goes first,
        and then each SYN-ACK from the port that no such socket sends is dropped: a SYN cookie's SYN-ACK has no socket,
        so the rule of the user alone lets it out. Bugs it catches: a table of the family ip (an agent's listener on ::
        answers over IPv6), a rule of the gate's port with no ::1 line, a gate rule with no address part, which would
        take 8767 on every address from an agent's own program, and a rule with no line for a cookie (an agent's
        listener that fills its own queue completes a client's handshake by cookie and reads its first data)."""
        text = ports.table_text()
        lines = [line.strip() for line in text.splitlines()]
        self.assertEqual(lines[:3], ["table inet founderizer_ports", "delete table inet founderizer_ports",
                                     "table inet founderizer_ports {"])
        self.assertIn(f'comment "founderizer-ports {ports.TABLE}"', lines)
        self.assertEqual([line for line in lines if line.startswith(("set ", "type ", "tcp ", "ip ", "ip6 "))],
                         ["set hub { type uid; }", "set git { type uid; }", "set gate { type uid; }",
                          "type filter hook output priority 0; policy accept;",
                          "tcp sport 8765 meta skuid @hub accept",
                          "tcp sport 8765 tcp flags & (syn | ack) == syn | ack drop",
                          "tcp sport 8765 meta skuid != @hub drop",
                          "tcp sport 9418 meta skuid @git accept",
                          "tcp sport 9418 tcp flags & (syn | ack) == syn | ack drop",
                          "tcp sport 9418 meta skuid != @git drop",
                          "ip saddr 127.0.0.1 tcp sport 8767 meta skuid @gate accept",
                          "ip saddr 127.0.0.1 tcp sport 8767 tcp flags & (syn | ack) == syn | ack drop",
                          "ip saddr 127.0.0.1 tcp sport 8767 meta skuid != @gate drop",
                          "ip6 saddr ::1 tcp sport 8767 meta skuid @gate accept",
                          "ip6 saddr ::1 tcp sport 8767 tcp flags & (syn | ack) == syn | ack drop",
                          "ip6 saddr ::1 tcp sport 8767 meta skuid != @gate drop"])
        self.assertEqual((ports.HUB_PORT, ports.GIT_PORT, ports.GATE_PORT), (8765, 9418, gate.PORT))

    def test_each_set_is_root_and_the_ports_own_user_and_a_load_is_one_transaction(self):
        """Root stays in each set: the owner claim and its second claim listen as root or as the hub's user. The git
        service runs as the hub's user. A gate's user that this server does not have yet (no `connect on`) leaves
        root alone on 8767. The load is the whole table with its elements in one nft input, and a load that nft
        refuses says nft's words and keeps the table of before (nft takes a file whole or not at all). Bugs it
        catches: a set without root (the claim gets no answer through), the hub's user in the gate's set, and a set
        that is filled in a second command after the table (a moment with empty sets, which drop every answer)."""
        self.assertEqual(ports.wanted(CONF, uid), {"hub": [0, 1100], "git": [0, 1100], "gate": [0, 999]})
        self.assertEqual(ports.wanted(CONF, lambda user: {"fleet": 1100}.get(user)),
                         {"hub": [0, 1100], "git": [0, 1100], "gate": [0]})
        calls = []
        folder = Path(tempfile.mkdtemp(prefix="fleet-ports-load-"))
        self.addCleanup(shutil.rmtree, str(folder), True)

        def run(argv, input=None, timeout=120):
            calls.append((argv, input))
            return (0, "", "") if len(calls) == 1 else (1, "", "Error: Could not process rule: No such file\n")
        with patch.object(ports, "LOCK", str(folder / "lock")):
            self.assertEqual(ports.load(CONF, run, uid), (True, {"hub": [0, 1100], "git": [0, 1100], "gate": [0, 999]},
                                                          ""))
            self.assertEqual(ports.load(CONF, run, uid)[::2], (False, "Error: Could not process rule: No such file"))
        self.assertEqual(calls[0][0], [ports.NFT, "-f", "-"])
        self.assertEqual(calls[0][1], ports.table_text() + "add element inet founderizer_ports hub { 0, 1100 }\n"
                         "add element inet founderizer_ports git { 0, 1100 }\n"
                         "add element inet founderizer_ports gate { 0, 999 }\n")

    def test_the_kernels_sets_are_read_back_as_uids(self):
        """--check compares the kernel's sets with the users of now: a version of nft may print a user's name in
        place of its UID. A table with another comment is no table of this version."""
        listing = {"nftables": [{"metainfo": {"version": "1.0.9"}},
                                {"table": {"family": "inet", "name": "founderizer_ports", "handle": 7,
                                           "comment": "founderizer-ports 1"}},
                                {"set": {"name": "hub", "type": "uid", "elem": [0, 1100]}},
                                {"set": {"name": "git", "type": "uid", "elem": ["root", "fleet"]}},
                                {"set": {"name": "gate", "type": "uid", "elem": 0}}]}
        run = lambda argv, input=None, timeout=120: (0, json.dumps(listing), "")
        self.assertEqual(ports.kernel(run, lambda user: {"root": 0, "fleet": 1100}.get(user)),
                         (1, {"hub": [0, 1100], "git": [0, 1100], "gate": [0]}))
        self.assertEqual(ports.kernel(lambda argv, input=None, timeout=120: (1, "", "No such file"), uid), (None, {}))


class Holder(unittest.TestCase):
    """The fixed root command: it ends another user's listener on the three ports, and never one of root's or of the
    port's own user."""

    def setUp(self):
        folder = Path(tempfile.mkdtemp(prefix="fleet-ports-holder-"))
        self.addCleanup(shutil.rmtree, str(folder), True)
        self.server = Server(folder)
        self.addCleanup(self.server.stop)

    def test_the_listeners_are_the_kernels_rows_with_the_sockets_own_uid(self):
        """The holder reads who listens from the kernel's own tables, whose uid column is the socket's user: never
        the text of a process, which that process writes. Only listening sockets of the three ports count, and for
        8767 only an address whose listener a client of 127.0.0.1 or ::1 reaches, or that keeps the gate from its
        bind. Bugs it catches: the timeout column read as the uid, the IPv6 words read in the wrong byte order, a
        connection (not a listener) ended, and an agent's own program on another address of 8767 ended."""
        tcp, tcp6 = self.server.tcp, self.server.tcp6
        tcp.write_text(Server.HEAD + row("127.0.0.1", 8765, 2001, 11) + "\n" + row("100.64.0.1", 8765, 1100, 12, "01")
                       + "\n" + row("0.0.0.0", 22, 0, 13) + "\n" + row("0.0.0.0", 8767, 2002, 14) + "\n")
        tcp6.write_text(Server.HEAD + row("::", 9418, 1100, 21) + "\n" + row("::ffff:127.0.0.1", 8767, 2001, 22) + "\n"
                        + row("fd7a:115c:a1e0::5", 8765, 2001, 23) + "\n")
        got = ports.listeners(self.server.tables())
        self.assertEqual([(port, str(address), owner, inode) for port, address, owner, inode in got],
                         [(8765, "127.0.0.1", 2001, 11), (8767, "0.0.0.0", 2002, 14), (9418, "::", 1100, 21),
                          (8767, str(ipaddress.ip_address("::ffff:127.0.0.1")), 2001, 22),
                          (8765, "fd7a:115c:a1e0::5", 2001, 23)])
        takes = {address: ports.takes(8767, ipaddress.ip_address(address))
                 for address in ("127.0.0.1", "0.0.0.0", "::", "::1", "::ffff:127.0.0.1", "100.64.0.5", "127.0.0.2",
                                 "fd7a:115c:a1e0::5")}
        self.assertEqual(takes, {"127.0.0.1": True, "0.0.0.0": True, "::": True, "::1": True, "::ffff:127.0.0.1": True,
                                 "100.64.0.5": False, "127.0.0.2": False, "fd7a:115c:a1e0::5": False})
        self.assertTrue(ports.takes(8765, ipaddress.ip_address("100.64.0.5")))

    def test_another_users_listener_is_ended_and_roots_and_the_own_users_are_not(self):
        """An agent's user on each port, IPv4 and IPv6, ended, so that the port's own program binds after it. A
        listener of root's (the owner claim, a program of root's) and one of the port's own user (the hub, its git
        service, the gate) are never ended: root's is named, and it holds the port. An agent's own program on another
        address of 8767 is not ended. Bugs it catches: a holder that ends the claim or the hub itself (which a broken
        hub could then ask for), one that ends only IPv4 listeners, and one that ends every listener of 8767."""
        server = self.server
        _, (on_hub,) = server.listen("127.0.0.1", 8765, AGENT)
        _, (claim,) = server.listen("100.64.0.1", 8765, 0, program="python3")
        _, (git_daemon,) = server.listen("100.64.0.1", 9418, 1100, program="git")
        _, (on_git,) = server.listen("::1", 9418, AGENT)
        _, (on_gate,) = server.listen("0.0.0.0", 8767, 2002)
        _, (elsewhere,) = server.listen("100.64.0.5", 8767, AGENT)
        lines, held = server.round()
        self.assertEqual(lines, ["port 8765: root's program python3; ended fleet-alpha",
                                 "port 9418: ended fleet-alpha; own (fleet)",
                                 "port 8767: ended fleet-beta"])
        self.assertTrue(held)                   # root's program holds 8765, and the hub's start stops with its line
        self.assertEqual([alive(one) for one in (on_hub, on_git, on_gate)], [False, False, False])
        self.assertEqual([alive(one) for one in (claim, git_daemon, elsewhere)], [True, True, True])
        self.assertEqual(server.round()[0], ["port 8765: root's program python3", "port 9418: own (fleet)",
                                             "port 8767: free"])

    def test_a_setuid_program_of_the_agent_and_a_child_that_a_fork_gave_the_socket_are_ended_too(self):
        """Only the real UID says whose a process is: an agent's user that leaves its socket open in a waiting program
        with the setuid bit (passwd, whose effective UID is root's) still loses its listener. And a process that forks
        while the holder ends it gives the socket to a child: the holder stops each holder, finds the child and stops
        it, then ends them all. Bugs they catch (the Door area's read of 24 November 2026): a holder that takes any
        UID of a process for its owner, so that a setuid program keeps the agent's listener for ever, and one that
        ends the processes that it found first, so that a program that forks faster than its rounds keeps the port;
        and one that signals a stopped process by its number, which another process may have taken since."""
        server = self.server
        inode, (agent,) = server.listen("::", 8765, AGENT)
        setuid = server.child(AGENT, "passwd", inode, effective=0)
        server.rows[inode][3].append(setuid.pid)
        forked, chain = [], {agent.pid}
        send = ports.send

        def forking(pid, socket_inode, never, sig, proc="/proc", keep=False):
            """Each process of the chain forked once just before its stop, five times in a row: more children than
            the holder has rounds, so only a holder that looks again after each stop finds the last one."""
            done = send(pid, socket_inode, never, sig, proc, keep=keep)
            if sig == signal.SIGSTOP and pid in chain and len(forked) < 5:
                forked.append(server.child(AGENT, "python3", socket_inode))
                server.rows[socket_inode][3].append(forked[-1].pid)
                chain.add(forked[-1].pid)
            return done

        # A stand-in pidfd for each process (this Mac has none): a descriptor of /dev/null that names its process, and
        # each signal through it recorded, so that a later signal by the process's number shows.
        by_fd, through, by_number = {}, [], []

        def pidfd_open(pid, flags=0):
            fd = os.open(os.devnull, os.O_RDONLY)
            by_fd[fd] = pid
            return fd

        kill = os.kill

        def pidfd_send_signal(fd, sig, siginfo=None, flags=0):
            through.append((by_fd[fd], sig))
            kill(by_fd[fd], sig)

        def number(pid, sig):
            by_number.append((pid, sig))
            kill(pid, sig)

        with patch.object(ports, "send", forking), patch.object(os, "pidfd_open", pidfd_open, create=True), \
                patch.object(signal, "pidfd_send_signal", pidfd_send_signal, create=True), \
                patch.object(ports.os, "kill", number):
            lines, held = server.round()
        self.assertEqual(lines[0], "port 8765: ended fleet-alpha")
        self.assertFalse(held)
        self.assertEqual(len(forked), 5)
        self.assertEqual([alive(one) for one in (agent, setuid, *forked)], [False] * 7)
        killed = {pid for pid, sig in through if sig == signal.SIGKILL}
        self.assertEqual(killed, {one.pid for one in (agent, setuid, *forked)}, "each SIGKILL through its stop's pidfd")
        self.assertEqual([pid for pid, sig in by_number if sig in (signal.SIGKILL, signal.SIGCONT)], [],
                         "no signal after a stop by the process's number (its number may be another process's now)")

    def test_a_hub_on_another_port_keeps_that_port_and_8765_is_none_of_its_own(self):
        """hub.sh --port 8800 (team.json's hub.port): the configuration names the hub's port, the rule's lines and its
        load name that port, and the holder ends another user's listener there and none on 8765, which is no port of
        this hub's. A configuration whose port is another service's, or no port above 1024, is refused. Bugs it
        catches (the coordinator's validator, 24 November 2026): a hub on another port whose own port keeps no rule,
        and a holder that ends other users' programs on 8765 where the hub is not."""
        server = self.server
        moved = dict(CONF, hub_port=8800)
        _, (on_hub,) = server.listen("0.0.0.0", 8800, AGENT)
        _, (elsewhere,) = server.listen("0.0.0.0", 8765, AGENT)
        lines, held = ports.holder_round(moved, uid=uid, proc=str(server.proc), tables=server.tables(), pause=False,
                                         sleep=server.sleep, name=name)
        self.assertEqual((lines[0], held), ("port 8800: ended fleet-alpha", False))
        self.assertEqual([alive(on_hub), alive(elsewhere)], [False, True])
        folder = Path(tempfile.mkdtemp(prefix="fleet-ports-moved-"))
        self.addCleanup(shutil.rmtree, str(folder), True)
        given = []
        with patch.object(ports, "LOCK", str(folder / "lock")):
            ports.load(moved, run=lambda argv, input=None, timeout=120: (given.append(input), (0, "", ""))[1], uid=uid)
        self.assertIn("tcp sport 8800 meta skuid @hub accept", given[0])
        self.assertNotIn("8765", given[0])
        with patch.object(ports, "OWNER", os.getuid()):
            for port, ok in ((8800, True), (9418, False), (8767, False), (80, False)):
                path = folder / f"ports-{port}.json"
                path.write_text(ports.conf_text("fleet", hub_port=port))
                path.chmod(0o644)
                if ok:
                    self.assertEqual(ports.config(str(path))["hub_port"], port)
                else:
                    with self.assertRaisesRegex(ports.Refused, "not a port that the hub can have"):
                        ports.config(str(path))

    def test_a_socket_that_root_or_the_own_user_holds_too_is_not_ended_and_a_run_of_another_user_ends_nothing(self):
        """An agent's listening socket that a process of the hub's user holds too (passed to it) stays whatever the
        holder ends, so it ends nothing and says why: it never signals a process of root or of the port's own user.
        A run that is not root's (no sudo) ends nothing and says who holds the port. Bugs it catches: a holder that
        ends the hub's own process, and one that ends the agent's process for nothing while the port stays held."""
        server = self.server
        _, (agent, hubs) = server.listen("::", 8765, AGENT, also=(1100,))
        lines, held = server.round()
        self.assertEqual(lines[0], "port 8765: held by fleet-alpha, not ended (a process of root or of the port's own "
                                   "user holds it too)")
        self.assertTrue(held)
        self.assertEqual([alive(agent), alive(hubs)], [True, True])
        _, (other,) = server.listen("127.0.0.1", 9418, 2002)
        lines, held = server.round(end=False)
        self.assertEqual(lines[1], "port 9418: held by fleet-beta, not ended (only root ends it)")
        self.assertTrue(held)
        self.assertTrue(alive(other))

    def test_the_pause_of_a_second_claim_is_a_lock_that_root_holds_on_its_own_file(self):
        """While root's side of a second claim holds the lock of PAUSE, the line of the claim's listener (the hub's
        user's, or root's) says so, and the port counts as not held: a start of the hub in that time ends quietly.
        Only a lock on a file of root's alone counts: a file of mode 644 (any user could open it and hold a lock), a
        link, and a file whose lock nobody holds (a claim that ended, also by a kill) are no pause. Bugs it catches: a
        pause that an agent's user can make, and one that stays for ever after a claim that was killed."""
        folder = Path(tempfile.mkdtemp(prefix="fleet-ports-pause-"))
        self.addCleanup(shutil.rmtree, str(folder), True)
        mark = folder / "pause"
        with patch.object(ports, "OWNER", os.getuid()):
            self.assertFalse(ports.paused(str(mark)))
            mark.write_text("")
            mark.chmod(0o600)
            self.assertFalse(ports.paused(str(mark)))               # no lock: the claim ended
            holder = os.open(mark, os.O_RDWR)
            self.addCleanup(os.close, holder)
            fcntl.flock(holder, fcntl.LOCK_EX)
            self.assertTrue(ports.paused(str(mark)))
            (folder / "link").symlink_to(mark)
            self.assertFalse(ports.paused(str(folder / "link")))
            mark.chmod(0o644)
            self.assertFalse(ports.paused(str(mark)))
            mark.chmod(0o600)
            fcntl.flock(holder, fcntl.LOCK_UN)
            self.assertFalse(ports.paused(str(mark)))
        _, (claim,) = self.server.listen("100.64.0.1", 8765, 1100)
        _, (root_claim,) = self.server.listen("100.64.0.1", 9418, 0)
        lines, held = self.server.round(pause=True)
        self.assertEqual(lines[:2], ["port 8765: own (fleet), paused for the owner claim",
                                     "port 9418: root's program python3, paused for the owner claim"])
        self.assertFalse(held)
        self.assertEqual(self.server.round(pause=False)[1], True)
        self.assertTrue(alive(claim) and alive(root_claim))


class Install(unittest.TestCase):
    """Root's step, in a folder that stands in for /, with a stand-in for each command."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="fleet-ports-root-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        (self.root / "usr/sbin").mkdir(parents=True)
        (self.root / "usr/sbin/nft").write_text("#!/bin/sh\n")
        (self.root / "usr/sbin/nft").chmod(0o755)
        for name, value in (("OWNER", os.getuid()), ("LOCK", str(self.root / "lock"))):
            patcher = patch.object(ports, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.calls, self.active, self.nft, self.sshd = [], "inactive", (0, "", ""), (0, "", "")
        self.sshd_settings = "port 22\ndenygroups fleet-agents\n"        # what sshd -T says
        self.units_at_load = None

    def run_(self, argv, input=None, timeout=120):
        self.calls.append(argv)
        if argv[:2] == [ports.NFT, "-f"]:
            self.units_at_load = sorted(p.name for p in (self.root / "etc/systemd/system").rglob("*")) \
                if (self.root / "etc/systemd/system").exists() else []
            return self.nft
        if argv[:2] == ["systemctl", "is-active"]:
            return (0 if self.active == "active" else 3), self.active + "\n", ""
        if argv[:2] == ["systemctl", "start"]:
            self.active = "active"
        if argv == ["sshd", "-t"]:
            return self.sshd
        if argv == ["sshd", "-T"]:
            return 0, self.sshd_settings, ""
        return 0, "", ""

    def install(self, **more):
        return ports.install("fleet", run=self.run_, root=str(self.root), source=str(Path(ROOT) / "ports.py"),
                             uid=uid, rounds=lambda conf, end=True, uid=None: (["port 8765: free"], False), **more)

    def text(self, path):
        return (self.root / path.lstrip("/")).read_text()

    def test_roots_step_loads_the_rule_first_then_its_units_which_come_before_the_hubs_services(self):
        """The rule loads before any unit is written, so a rule that does not load leaves no unit that keeps the
        hub's services from their start. The boot unit loads it at each start of the server with no default
        dependencies, before the network, the users' sessions, the hub user's manager (which runs the hub and its git
        service) and the gate; every user's manager (one drop-in of user@.service), the gate and this server's vault
        broker require it, so none starts without it. The step starts the units and never restarts one: a restart of
        a required unit restarts the hub. A second run writes nothing, and a drop-in of one user's manager (an earlier
        form) goes. Bugs it catches: a boot unit that the users' services can overtake, a unit whose failure lets the
        hub start anyway, one whose failure lets an agent's services start with no rule (so its program takes the hub's
        free port), a broker that starts with no rule and sends an agent's key to such a program (the Door area, 24
        November 2026), and a step that restarts the hub."""
        answer = self.install()
        self.assertEqual((answer["ok"], answer["state"], answer["lines"]), (True, "made", ["port 8765: free"]))
        self.assertEqual(self.units_at_load, [])
        steps = [argv for argv in self.calls
                 if argv[0] in ("systemctl", "visudo", ports.NFT) and "is-active" not in argv]
        self.assertEqual([argv[:2] for argv in steps],
                         [[ports.NFT, "-f"], ["visudo", "-cqf"], ["systemctl", "daemon-reload"],
                          ["systemctl", "enable"], ["systemctl", "start"]])
        self.assertEqual(steps[-1], ["systemctl", "start", "founderizer-ports.service", "founderizer-ports.path"])
        self.assertFalse([argv for argv in self.calls if "restart" in argv or "stop" in argv])
        rules = "/usr/bin/python3 -I /usr/local/lib/founderizer-ports/ports.py rules"
        boot = self.text("/etc/systemd/system/founderizer-ports.service").splitlines()
        for line in ("DefaultDependencies=no", "After=local-fs.target", "Type=oneshot", "RemainAfterExit=yes",
                     "Before=network-pre.target systemd-user-sessions.service user@1100.service "
                     "founderizer-connect.service shutdown.target", f"ExecStart={rules}", "WantedBy=sysinit.target"):
            self.assertIn(line, boot)
        for path in ("/etc/systemd/system/user@.service.d/founderizer-ports.conf",
                     "/etc/systemd/system/founderizer-connect.service.d/founderizer-ports.conf",
                     "/etc/systemd/system/fleet-vault.service.d/founderizer-ports.conf",
                     "/etc/systemd/system/cron.service.d/founderizer-ports.conf",
                     "/etc/systemd/system/atd.service.d/founderizer-ports.conf"):
            lines = self.text(path).splitlines()
            self.assertIn("Requires=founderizer-ports.service", lines, path)
            self.assertIn("After=founderizer-ports.service", lines, path)
        self.assertIn(f"ExecStartPre=+{rules}",
                      self.text("/etc/systemd/system/founderizer-connect.service.d/founderizer-ports.conf"))
        self.assertEqual([line for line in self.text("/etc/systemd/system/nftables.service.d/founderizer-ports.conf")
                          .splitlines() if line.startswith("Exec")],
                         [f"ExecStartPost=-+{rules}", f"ExecReload=-+{rules}", f"ExecStopPost=-+{rules}"])
        path_unit = self.text("/etc/systemd/system/founderizer-ports.path")
        self.assertIn("PathChanged=/etc/passwd\nUnit=founderizer-ports-reload.service\n", path_unit)
        self.assertIn(f"ExecStart={rules}", self.text("/etc/systemd/system/founderizer-ports-reload.service"))
        self.assertEqual([line for line in self.text(ports.SUDOERS).splitlines() if not line.startswith("#")],
                         ['fleet ALL=(root) NOPASSWD: /usr/local/lib/founderizer-ports/holder ""',
                          'founderizer-connect ALL=(root) NOPASSWD: /usr/local/lib/founderizer-ports/holder ""'])
        self.assertEqual(json.loads(self.text(ports.CONF)), dict(CONF, hub_port=8765))
        self.assertEqual((self.root / ports.PROGRAM.lstrip("/")).read_bytes(), (Path(ROOT) / "ports.py").read_bytes())
        modes = {path: stat.S_IMODE(os.stat(self.root / path.lstrip("/")).st_mode)
                 for path in (ports.PROGRAM, ports.HOLDER, ports.CONF, ports.SUDOERS)}
        self.assertEqual(modes, {ports.PROGRAM: 0o644, ports.HOLDER: 0o755, ports.CONF: 0o644, ports.SUDOERS: 0o440})
        # a second run on a server whose units are active: nothing written, and a drop-in of one user's manager goes
        stale = self.root / "etc/systemd/system/user@1100.service.d/founderizer-ports.conf"
        stale.parent.mkdir()
        stale.write_text("[Unit]\nRequires=founderizer-ports.service\n")
        written = {p: p.stat().st_mtime_ns for p in self.root.rglob("*") if p.is_file() and p != stale}
        self.calls.clear()
        self.assertEqual(self.install()["state"], "made")         # the stale drop-in was a change
        self.assertFalse(stale.exists())
        self.assertEqual({p: p.stat().st_mtime_ns for p in written if p.exists()}, written)
        self.assertNotIn(["visudo", "-cqf"], [argv[:2] for argv in self.calls])
        self.assertEqual(self.install()["state"], "there")

    def test_no_agent_user_logs_in_by_ssh_and_a_file_that_sshd_refuses_is_taken_back(self):
        """Where OpenSSH has a folder of its own files, the step writes one with `DenyGroups fleet-agents`, checks it
        with `sshd -t` and reloads SSH; a second run writes nothing; a file that sshd refuses is taken back and the step
        stops with sshd's words. A server with no OpenSSH gets no file. Bugs it catches (the Door area's read of 24
        November 2026): an agent's user that puts a key of its own in its home and logs in by SSH after a start of the
        server whose rule did not load, so that its program takes the hub's free port, and a file that sshd refuses
        left in place, which keeps SSH from its next start; and a step or a check that says that sshd denies the group
        where sshd_config reads no file of the folder, so the file does nothing."""
        self.assertIn("this server has no OpenSSH", " ".join(self.install()["said"]))
        self.assertFalse((self.root / ports.SSHD_AGENTS.lstrip("/")).exists())
        (self.root / "etc/ssh/sshd_config.d").mkdir(parents=True)
        (self.root / "usr/sbin/sshd").write_text("#!/bin/sh\n")
        self.calls.clear()
        self.assertEqual(self.install()["state"], "made")
        self.assertEqual(self.text(ports.SSHD_AGENTS).splitlines()[-1], "DenyGroups fleet-agents")
        self.assertLess(self.calls.index(["sshd", "-t"]),
                        self.calls.index(["systemctl", "try-reload-or-restart", "ssh.service"]))
        self.calls.clear()
        self.assertEqual(self.install()["state"], "there")
        self.assertNotIn(["sshd", "-t"], self.calls)
        (self.root / ports.SSHD_AGENTS.lstrip("/")).unlink()
        self.sshd = (255, "", "/etc/ssh/sshd_config.d/10-founderizer-agents.conf line 4: Bad configuration option\n")
        with self.assertRaisesRegex(ports.Refused, "sshd refused .* Bad configuration option.*so it was taken back"):
            self.install()
        self.assertFalse((self.root / ports.SSHD_AGENTS.lstrip("/")).exists())
        # an sshd_config that reads no file of the folder: the file is there, and sshd's own reading must say so
        self.sshd = (0, "", "")
        self.sshd_settings = "port 22\n"
        with self.assertRaisesRegex(ports.Refused, "sshd -T. does not deny fleet-agents"):
            self.install()
        check = self.install(check=True)
        self.assertIn("does not deny fleet-agents", " ".join(check["problems"]))
        self.sshd_settings = "port 22\ndenygroups fleet-agents\n"
        self.assertNotIn("fleet-agents", " ".join(self.install(check=True)["problems"]))

    def test_a_rule_that_does_not_load_writes_no_unit_and_says_nfts_words(self):
        """nft refuses the table (an old nft, a kernel with no nf_tables): the step stops with nft's words, and
        writes no unit, no drop-in, no sudoers file and no holder. Bugs it catches: a boot unit that fails at each start
        of the server and so keeps the hub's services down, put there by a step that never saw the rule load, and a
        holder with no sudoers line, which the hub's and the git service's units then run in vain at each start."""
        self.nft = (1, "", "Error: Could not process rule: No such file or directory\n")
        with self.assertRaisesRegex(ports.Refused, "did not load \\(Error: Could not process rule: No such file or "
                                                   "directory\\). No unit of it was written"):
            self.install()
        self.assertFalse((self.root / "etc/systemd").exists())
        self.assertFalse((self.root / ports.SUDOERS.lstrip("/")).exists())
        # nor the holder, which the units run where it is: with no sudoers line each start would log sudo's refusal
        self.assertFalse((self.root / ports.HOLDER.lstrip("/")).exists())
        self.assertFalse([argv for argv in self.calls
                          if argv[0] in ("systemctl", "visudo") and "is-active" not in argv])

    def test_check_changes_nothing_and_says_what_does_not_hold(self):
        """--check: each file that the step would write, a unit that is not active, kernel sets that are not the UIDs
        of the users of now, and a listener of another user. It writes nothing and ends nothing. Bug it catches: a
        check that says that the rule holds while the kernel has the sets of before (a user that came later)."""
        answer = self.install(check=True)
        self.assertFalse(answer["ok"])
        self.assertIn(f"would write {ports.PROGRAM}", answer["problems"])
        self.assertIn("the unit founderizer-ports.service is inactive", answer["problems"])
        self.assertEqual(sorted(p.name for p in self.root.rglob("*")), ["nft", "sbin", "usr"])
        self.install()
        sets = {"hub": [0, 1100], "git": [0, 1100], "gate": [0]}         # loaded before the gate's user came
        listing = {"nftables": [{"table": {"comment": f"founderizer-ports {ports.TABLE}"}}]
                   + [{"set": {"name": key, "elem": value}} for key, value in sets.items()]}
        kernel = lambda argv, input=None, timeout=120: (0, json.dumps(listing), "") if argv[:2] == [ports.NFT, "-j"] \
            else self.run_(argv, input, timeout)
        foreign = "port 8765: held by fleet-alpha, not ended (only root ends it)"
        held = lambda conf, end=True, uid=None: ([foreign], True)
        answer = ports.install("fleet", check=True, run=kernel, root=str(self.root), uid=uid, rounds=held,
                               source=str(Path(ROOT) / "ports.py"))
        self.assertFalse(answer["ok"])
        self.assertEqual(len(answer["problems"]), 2, answer)
        self.assertIn("the kernel's sets are", answer["problems"][0])
        self.assertEqual(answer["problems"][1], foreign)
        listing["nftables"][-1]["set"]["elem"] = [0, 999]
        answer = ports.install("fleet", check=True, run=kernel, root=str(self.root), uid=uid,
                               rounds=lambda conf, end=True, uid=None: (["port 8765: own (fleet)"], False),
                               source=str(Path(ROOT) / "ports.py"))
        self.assertEqual((answer["ok"], answer["problems"]), (True, []), answer)
        # the same sets in the table of a release before: its rules are not this release's, so the step is owed
        listing["nftables"][0]["table"]["comment"] = f"founderizer-ports {ports.TABLE - 1}"
        answer = ports.install("fleet", check=True, run=kernel, root=str(self.root), uid=uid,
                               rounds=lambda conf, end=True, uid=None: (["port 8765: own (fleet)"], False),
                               source=str(Path(ROOT) / "ports.py"))
        self.assertFalse(answer["ok"], answer)
        self.assertEqual(len(answer["problems"]), 1, answer)


class Callers(unittest.TestCase):
    """What the other files of the fleet hold of the port piece."""

    def test_the_root_command_takes_no_argument_and_its_sudo_line_says_so(self):
        """sudo runs a command written with no argument list with any arguments, so each line ends with "", and the
        command refuses an argument itself as well. Bug it catches: a root command that a broken hub could give a
        word to."""
        text = ports.HOLDER_TEXT.format(python=sys.executable, program="/nonexistent/ports.py")
        done = subprocess.run(["sh", "-c", text, "holder", "--any"], capture_output=True, text=True, timeout=30)
        self.assertEqual((done.returncode, done.stderr.strip()), (2, "founderizer-ports: this command takes no "
                                                                     "argument"))
        for line in ports.sudoers_text(ports.users_of("fleet")).splitlines():
            self.assertTrue(line.startswith("#") or line.endswith(f'NOPASSWD: {ports.HOLDER} ""'), line)

    def test_the_hub_and_its_git_service_run_the_root_command_before_each_start_and_no_other_service_does(self):
        """The hub and git daemon stop when their port is taken, and their units start them again 5 seconds later: the
        command before that start ends another user's listener there, also after a crash, a restart and a start of
        the server. Only where root's step installed the command: a server from before it runs nothing, and sudo logs
        no refusal at each start; a fault goes on ("-"). The line tests the command itself, which the hub's user can
        see: /etc/sudoers.d is root's 0750 on Debian and Ubuntu. Bugs it catches (the Door area's reads of 24
        November 2026): a hub that loops on a taken 8765 after a restart while an agent's program holds it, a git
        service that does the same on 9418, and a line whose test the hub's user can never pass, so that it runs
        nothing at all."""
        path = lifecycle.service_path("/home/fleet")
        line = ('ExecStartPre=-/bin/sh -c "test -x /usr/local/lib/founderizer-ports/holder && exec /usr/bin/sudo -n '
                '/usr/local/lib/founderizer-ports/holder; exit 0"')
        for one, argv in (("hub", lifecycle.hub_start("/usr/bin/python3")), ("git", ["/usr/bin/git", "daemon"])):
            self.assertIn(line + "\n", lifecycle.service_unit(one, argv, "/home/fleet/k", path), one)
        self.assertIn(line + "\n", lifecycle.hub_unit("/home/fleet/k", "/usr/bin/python3", "/home/fleet"))
        for one in ("channels", "dev-lead"):
            self.assertNotIn("ExecStartPre", lifecycle.service_unit(one, ["/usr/bin/python3"], "/home/fleet/k", path))
        # The line's own shell, with a stand-in for the command (and no sudo): it runs the command where the command is
        # there and can run, and nothing where it is not.
        folder = Path(tempfile.mkdtemp(prefix="fleet-ports-pre-"))
        self.addCleanup(shutil.rmtree, str(folder), True)
        holder = folder / "holder"
        shell = line.split(" -c ", 1)[1].strip('"').replace("/usr/bin/sudo -n ", "").replace(ports.HOLDER, str(holder))
        done = subprocess.run(["sh", "-c", shell], capture_output=True, text=True, timeout=30)
        self.assertEqual((done.returncode, done.stdout + done.stderr), (0, ""), "no command: nothing runs")
        holder.write_text("#!/bin/sh\necho port 8765: ended fleet-alpha\n")
        holder.chmod(0o755)
        done = subprocess.run(["sh", "-c", shell], capture_output=True, text=True, timeout=30)
        self.assertEqual(done.stdout, "port 8765: ended fleet-alpha\n", "the command is there: it runs")

    def test_each_copy_of_a_name_is_the_port_pieces_own(self):
        """The root command in the git unit, the gate's user, unit and address in hubsetup.py, and apt's wait: one
        value each (hub.sh's copy of the pause's file: test_hub_install.PortStep). Bug it catches: a git unit that
        runs a command that is not there, so a held 9418 stays held."""
        self.assertEqual((lifecycle.PORT_HOLDER, lifecycle.PORT_SUDOERS, hubsetup.CONNECT_USER,
                          hubsetup.CONNECT_SERVICE, hubsetup.APT_LOCK_WAIT, os.path.basename(hubsetup.VAULT_UNIT)),
                         (ports.HOLDER, ports.SUDOERS, ports.GATE_USER, ports.GATE_SERVICE, ports.APT_LOCK_WAIT,
                          ports.BROKER_SERVICE + ".service"))
        self.assertEqual(hubsetup.CONNECT_TARGET, f"http://127.0.0.1:{ports.GATE_PORT}")


if __name__ == "__main__":
    unittest.main()
