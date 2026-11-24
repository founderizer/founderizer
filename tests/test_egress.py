"""The outgoing gate, step 1 (vault.py, "the outgoing gate"; agent-outgoing-connections-proposal.md, section 10): the
parts that need no root and no Linux kernel. The kernel's part runs in test_egress_e2e.py and the units under a real
systemd in test_egress_systemd.py, each in a container of its own and only when its variable asks for it.

    python3 -m unittest test_egress

Every name, address and key here is made up: example names, the documentation ranges and 100.64.0.0/10."""
import contextlib
import hashlib
import io
import json
import os
import shutil
import socket
import ssl
import struct
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import hub
import hubsetup
import server
import test_servers
import vault


def client_hello(name):
    """The first bytes of a real TLS client (Python's own) for this server name, with no network."""
    context = ssl.create_default_context()
    out = ssl.MemoryBIO()
    tls = context.wrap_bio(ssl.MemoryBIO(), out, server_hostname=name)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


def dns_message(name, kind=1, answers=()):
    """A DNS question for a name, and with answers (address, type) a response whose answer names point back at the
    question's name (compression)."""
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    head = struct.pack("!HHHHHH", 0x1234, 0x8180 if answers else 0x0100, 1, len(answers), 0, 0)
    body = labels + struct.pack("!HH", kind, 1)
    for address, kind_of in answers:
        raw = socket.inet_pton(socket.AF_INET6 if kind_of == 28 else socket.AF_INET, address)
        body += b"\xc0\x0c" + struct.pack("!HHIH", kind_of, 1, 60, len(raw)) + raw
    return head + body


class Readers(unittest.TestCase):
    """The first bytes of a connection, and DNS: the gate reads a name, and no byte after it."""

    def test_the_server_name_of_a_real_client_hello_also_in_two_parts(self):
        hello = client_hello("api.example.com")
        self.assertEqual(vault.egress_sni(hello), ("done", "api.example.com"))
        self.assertEqual(vault.egress_sni(hello[:30]), ("more", None))
        self.assertEqual(vault.egress_first(hello), ("done", "api.example.com", "sni"))
        self.assertEqual(vault.egress_first(hello[:7]), ("more", None, None))

    def test_bytes_that_are_no_hello_and_no_request_name_nothing(self):
        for data in (b"SSH-2.0-OpenSSH_9.6\r\n", b"\x16\x03\x01\x00\x05\x02\x00\x00\x01\x00", b"\x00" * 40):
            self.assertEqual(vault.egress_first(data)[0], "done")
            self.assertIsNone(vault.egress_first(data)[1])

    def test_the_host_of_an_http_request_head(self):
        for data, name in ((b"GET / HTTP/1.1\r\nHost: Docs.Example.com:8080\r\n\r\n", "Docs.Example.com"),
                           (b"GET http://files.example.org/a HTTP/1.1\r\nHost: x\r\n\r\n", "files.example.org"),
                           (b"POST /x HTTP/1.0\r\nhost: example.net\r\n\r\n", "example.net"),
                           (b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n", None),
                           (b"GET / HTTP/1.1\r\nHost: 192.0.2.7\r\n\r\n", None)):
            self.assertEqual(vault.egress_http_host(data), ("done", name), data)
        self.assertEqual(vault.egress_http_host(b"GET / HTTP/1.1\r\nHost: exa"), ("more", None))
        self.assertEqual(vault.egress_first(b"GE"), ("more", None, None))

    def test_a_dns_question_and_its_answers_through_compression(self):
        question = dns_message("www.Example.com")
        self.assertEqual(vault.egress_dns_question(question), ("www.Example.com", 1))
        answer = dns_message("www.example.com", 1, [("192.0.2.10", 1), ("2001:db8::10", 28)])
        self.assertEqual(vault.egress_dns_answers(answer), ["192.0.2.10", "2001:db8::10"])
        self.assertIsNone(vault.egress_dns_question(b"\x00" * 5))

    def test_a_name_keeps_its_case_and_its_odd_bytes_come_as_dns_escapes(self):
        labels = b"\x05Ab+/=" + b"\x07Example\x03com\x00"
        msg = struct.pack("!HHHHHH", 1, 0x100, 1, 0, 0, 0) + labels + b"\x00\x01\x00\x01"
        self.assertEqual(vault.egress_dns_question(msg), ("Ab\\043\\047\\061.Example.com", 1))
        self.assertEqual(vault.egress_host("Mixed.Example.COM."), "Mixed.Example.COM")

    def test_a_question_with_no_answer_gets_a_server_failure_with_its_own_id_and_question(self):
        question = dns_message("site.example")
        fail = vault.egress_servfail(question)
        self.assertEqual(fail[:2], question[:2])
        self.assertEqual(struct.unpack("!H", fail[2:4])[0] & 0x800F, 0x8002)
        self.assertEqual(vault.egress_dns_question(fail), ("site.example", 1))
        self.assertIsNone(vault.egress_servfail(b"\x01\x02"))

    def test_the_kinds_of_address_of_the_records(self):
        for address, kind in (("169.254.169.254", "metadata"), ("fd00:ec2::254", "metadata"),
                              ("169.254.3.4", "link-local"), ("fe80::1", "link-local"), ("100.64.0.7", "fleet"),
                              ("10.1.2.3", "private"), ("172.20.0.1", "private"), ("fc00::1", "private"),
                              ("127.0.0.1", "local"), ("::1", "local"), ("::ffff:10.0.0.1", "private"),
                              ("240.0.0.1", "reserved"), ("192.0.2.1", "public"), ("2001:db8::1", "public")):
            self.assertEqual(vault.egress_class(address), kind, address)

    def test_the_readers_check_themselves(self):
        self.assertTrue(vault.egress_selftest())

    def test_the_kernels_table_of_sockets_in_its_own_byte_order(self):
        little = vault.sys.byteorder == "little"
        self.assertEqual(vault.egress_hex("127.0.0.1", 877), ("0100007F" if little else "7F000001") + ":036D")
        self.assertEqual(vault.egress_hex("10.0.0.1", 80, mapped=True)[:24], "0000000000000000" +
                         ("FFFF0000" if little else "0000FFFF"))


class Lookups(unittest.TestCase):
    """How the gate and the swap proxy find the user of a socket: the kernel's own lookup, checked at each start, and
    /proc only where that lookup does not work (the fourth review round)."""

    def setUp(self):
        patcher = patch.dict(vault.EGRESS_LOOKUP, {socket.IPPROTO_TCP: True, socket.IPPROTO_UDP: True})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_start_check_sends_a_lookup_that_finds_nothing_to_proc(self):
        with patch.object(vault, "egress_diag", lambda *a: os.getuid()):
            self.assertEqual(vault.egress_lookup_check(), {"tcp": True, "udp": True})
        with patch.object(vault, "egress_diag", lambda *a: None):       # a kernel with no inet_diag handler
            self.assertEqual(vault.egress_lookup_check(), {"tcp": False, "udp": False})
        self.assertIs(vault.egress_diag(socket.AF_INET, socket.IPPROTO_TCP, ("127.0.0.1", 1), ("127.0.0.1", 2)),
                      False)
        self.assertIs(vault.egress_udp_port(socket.AF_INET, 53), False)

    def test_a_listener_that_does_not_answer_yet_keeps_the_lookup_on(self):
        with socket.socket() as closed:                 # a port that nothing listens on: the gate, starting at boot
            closed.bind(("127.0.0.1", 0))
            port = closed.getsockname()[1]
        with patch.object(vault, "egress_diag", lambda *a: os.getuid()):
            self.assertEqual(vault.egress_lookup_check(("127.0.0.1", port))["tcp"], None)
        self.assertTrue(vault.EGRESS_LOOKUP[socket.IPPROTO_TCP])

    def test_the_relay_port_and_the_swap_proxy_ask_the_kernel_first(self):
        conn = types.SimpleNamespace(getpeername=lambda: ("127.0.0.1", 40000), getsockname=lambda: ("127.0.0.1", 879))
        asked = []

        def diag(family, protocol, local, remote):
            asked.append((protocol, local, remote))
            return 2001
        with patch.object(vault, "egress_diag", diag):
            self.assertEqual(vault.egress_direct_uid(conn), 2001)
            conn.getsockname = lambda: ("127.0.0.1", 876)
            self.assertEqual(vault.swap_peer(conn), 2001)
        self.assertEqual(asked, [(socket.IPPROTO_TCP, ("127.0.0.1", 40000), ("127.0.0.1", 879)),
                                 (socket.IPPROTO_TCP, ("127.0.0.1", 40000), ("127.0.0.1", 876))])
        folder = tempfile.mkdtemp(prefix="fleet-egress-proc-")
        self.addCleanup(shutil.rmtree, folder, True)
        table = os.path.join(folder, "tcp")
        with open(table, "w", encoding="ascii") as f:
            f.write("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                    f"   0: {vault.egress_hex('127.0.0.1', 40000)} {vault.egress_hex('127.0.0.1', 876)} 01 "
                    "00000000:00000000 00:00000000 00000000  2005        0 12345 1\n")
        with patch.object(vault, "SWAP_TABLES", ((table, False),)):
            with patch.object(vault, "egress_diag", lambda *a: None):
                self.assertIsNone(vault.swap_peer(conn))        # the kernel's own answer: no such socket
            with patch.object(vault, "egress_diag", lambda *a: False):
                self.assertEqual(vault.swap_peer(conn), 2005)   # no lookup on this machine: /proc

    def test_a_question_that_the_exact_lookups_miss_is_placed_by_the_sockets_of_its_port(self):
        four, tables = socket.inet_aton, {}
        with patch.object(vault, "egress_udp_port", lambda family, port: tables.get(family, [])):
            tables = {socket.AF_INET: [(four("0.0.0.0"), 2002), (four("10.0.0.5"), 2001)]}
            self.assertEqual(vault.egress_udp_uid(("10.0.0.5", 40000)), 2001)      # the exact address first
            tables = {socket.AF_INET: [(four("0.0.0.0"), 2002)],
                      socket.AF_INET6: [(bytes(10) + b"\xff\xff" + four("10.0.0.5"), 2003)]}
            self.assertEqual(vault.egress_udp_uid(("10.0.0.5", 40000)), 2003)      # one socket for both IP versions
            tables = {socket.AF_INET: [(four("0.0.0.0"), 2002), (four("0.0.0.0"), 2004)]}
            self.assertIsNone(vault.egress_udp_uid(("10.0.0.5", 40000)))           # two users: no one's
            tables = {socket.AF_INET6: [(bytes(16), 2005)]}
            self.assertEqual(vault.egress_udp_uid(("2001:db8::5", 40000)), 2005)
            tables = {}
            self.assertIsNone(vault.egress_udp_uid(("10.0.0.5", 40000)))
        with patch.object(vault, "egress_udp_port", lambda family, port: None):
            self.assertIsNone(vault.egress_udp_uid(("10.0.0.5", 40000)))           # a port with too many sockets
        with patch.object(vault, "egress_udp_port", lambda family, port: False), \
                patch.object(vault, "egress_udp_proc", lambda peer: 2006):
            self.assertEqual(vault.egress_udp_uid(("10.0.0.5", 40000)), 2006)      # no dump on this machine: /proc


class Rows(unittest.TestCase):
    """What the gate counts: rows, a fold past the limit of names, and the merge of a gate that gave way."""

    def test_rows_add_take_and_merge(self):
        counts = vault.EgressCounts(clock=lambda: 100.0)
        key = counts.add(2001, "api.example.com", 443, "pass", "sni", "public", conns=1)
        with counts.lock:
            counts.add_key(key, {"up": 10, "down": 99})
        counts.add(2001, "api.example.com", 53, "pass", "dns", "", dns=2)
        rows = counts.take()
        self.assertEqual(sorted((r["host"], r["port"], r["conns"], r["dns"], r["up"], r["down"]) for r in rows),
                         [("api.example.com", 53, 0, 2, 0, 0), ("api.example.com", 443, 1, 0, 10, 99)])
        self.assertEqual(counts.take(), [])
        counts.merge(rows + [{"uid": "x"}])
        self.assertEqual(len(counts.take()), 2)

    def test_past_the_limit_a_new_name_counts_under_its_last_two_labels(self):
        counts = vault.EgressCounts()
        with patch.object(vault, "EGRESS_NAMES", 2):
            for name in ("a.example.com", "b.example.com", "x.y.example.org"):
                counts.add(1, name, 443, "pass", "sni", "public", conns=1)
            counts.add(1, "a.example.com", 443, "pass", "sni", "public", conns=1)
        self.assertEqual(sorted((r["host"], r["conns"]) for r in counts.take()),
                         [("a.example.com", 2), ("b.example.com", 1), ("example.org", 1)])

    def test_past_the_limit_of_rows_a_new_row_counts_as_more_hosts(self):
        counts = vault.EgressCounts()
        with patch.object(vault, "EGRESS_ROWS", 2):
            for port in (1, 2, 3, 4):
                counts.add(1, "a.example.com", port, "pass", "sni", "public", conns=1)
        self.assertEqual(sorted((r["host"], r["port"], r["conns"]) for r in counts.take()),
                         [("(more hosts)", 0, 2), ("a.example.com", 1, 1), ("a.example.com", 2, 1)])

    def test_made_up_names_and_addresses_stay_under_a_bound(self):
        counts = vault.EgressCounts()
        with patch.object(vault, "EGRESS_NAMES", 20), patch.object(vault, "EGRESS_FOLDED", 20), \
                patch.object(vault, "EGRESS_ROWS", 60):
            for i in range(3000):
                counts.add(7, f"x{i}.n{i}.example.org", 53, "pass", "dns", "", dns=1)
                counts.add(7, f"192.0.{i // 250}.{i % 250}", 443, "pass", "address", "public", conns=1)
        rows = counts.take()
        self.assertLessEqual(len(rows), 60 + 4)
        self.assertEqual(sum(r["dns"] for r in rows) + sum(r["conns"] for r in rows), 6000)     # nothing is lost

    def test_the_names_that_the_resolver_gave_keep_a_count_limit(self):
        names = vault.EgressNames()
        with patch.object(vault, "EGRESS_ADDRESSES", 2):
            names.learn(1, "a.example.com", ["192.0.2.1", "192.0.2.2"])
            names.learn(1, "b.example.com", ["192.0.2.3"])
        self.assertEqual((names.name(1, "192.0.2.1"), names.name(1, "192.0.2.3"), names.name(2, "192.0.2.3")),
                         (None, "b.example.com", None))


class Dial(unittest.TestCase):
    """The gate's own fallback for a program whose fallback cannot run: the kernel gave it the gate's handshake."""

    def connect_with(self, slow=(), fail=()):
        tried = []

        def connect(address):
            tried.append(address)
            if address in fail:
                raise OSError("no route")
            if address in slow:
                time.sleep(2)
                raise OSError("timed out")
            return types.SimpleNamespace(address=address, setsockopt=lambda *a: None, settimeout=lambda t: None,
                                         close=lambda: None)
        return connect, tried

    def test_the_address_that_the_program_chose_first(self):
        connect, tried = self.connect_with()
        sock = vault.egress_dial(443, first="2001:db8::1", name="api.example.com", resolve=lambda n: ["192.0.2.1"],
                                 connect=connect, fallback=0.05)
        self.assertEqual((sock.address, tried), ("2001:db8::1", ["2001:db8::1"]))

    def test_a_first_address_that_does_not_answer_gives_way_to_the_names_other_address(self):
        connect, tried = self.connect_with(slow=("2001:db8::1",))
        t0 = time.monotonic()
        sock = vault.egress_dial(443, first="2001:db8::1", name="api.example.com",
                                 resolve=lambda n: ["2001:db8::1", "192.0.2.1"], connect=connect, fallback=0.05)
        self.assertEqual(sock.address, "192.0.2.1")
        self.assertLess(time.monotonic() - t0, 1.5)

    def test_a_first_address_that_fails_at_once_and_no_name_is_no_connection(self):
        connect, tried = self.connect_with(fail=("192.0.2.9",))
        self.assertIsNone(vault.egress_dial(22, first="192.0.2.9", connect=connect, fallback=0.05))
        self.assertEqual(tried, ["192.0.2.9"])

    def test_a_refusal_is_the_programs_own_answer_with_no_fallback(self):
        tried = []

        def connect(address):
            tried.append(address)
            if address == "2001:db8::1":
                raise ConnectionRefusedError("refused")
            return types.SimpleNamespace(address=address, setsockopt=lambda *a: None, settimeout=lambda t: None,
                                         close=lambda: None)
        self.assertIsNone(vault.egress_dial(443, first="2001:db8::1", name="api.example.com",
                                            resolve=lambda n: ["192.0.2.1"], connect=connect, fallback=0.05))
        self.assertEqual(tried, ["2001:db8::1"])

    def test_the_fallback_tries_the_other_family_first_then_the_same_one(self):
        connect, tried = self.connect_with(slow=("2001:db8::1", "2001:db8::2"))
        sock = vault.egress_dial(443, first="2001:db8::1", name="api.example.com",
                                 resolve=lambda n: ["2001:db8::1", "2001:db8::2", "192.0.2.1"], connect=connect,
                                 fallback=0.05)
        self.assertEqual((sock.address, tried[:2]), ("192.0.2.1", ["2001:db8::1", "192.0.2.1"]))
        connect, tried = self.connect_with(slow=("192.0.2.1",))
        sock = vault.egress_dial(443, first="192.0.2.1", name="api.example.com",
                                 resolve=lambda n: ["192.0.2.1", "192.0.2.2"], connect=connect, fallback=0.05,
                                 stall=0.3)
        self.assertEqual(sock.address, "192.0.2.2")             # a name with two IPv4 addresses, the first silent

    def test_a_first_address_that_answers_in_time_races_no_address_of_its_family(self):
        tried = []

        def connect(address):
            tried.append(address)
            time.sleep(0.4 if address == "192.0.2.1" else 0)       # slower than the fallback, within the stall
            return types.SimpleNamespace(address=address, setsockopt=lambda *a: None, settimeout=lambda t: None,
                                         close=lambda: None)
        sock = vault.egress_dial(443, first="192.0.2.1", name="api.example.com",
                                 resolve=lambda n: ["192.0.2.1", "192.0.2.2"], connect=connect, fallback=0.05,
                                 stall=2)
        self.assertEqual((sock.address, tried), ("192.0.2.1", ["192.0.2.1"]))

    def test_an_ipv4_address_in_its_ipv6_form_is_of_the_ipv4_family(self):
        addresses = ("192.0.2.1", "::ffff:192.0.2.2", "2001:db8::1", "fe80::1%eth0")
        self.assertEqual([vault.egress_six(a) for a in addresses], [False, False, True, True])
        connect, tried = self.connect_with(slow=("192.0.2.1",))
        t0 = time.monotonic()
        sock = vault.egress_dial(443, first="192.0.2.1", name="api.example.com", resolve=lambda n: ["::ffff:192.0.2.2"],
                                 connect=connect, fallback=0.05, stall=0.4)
        self.assertEqual(sock.address, "::ffff:192.0.2.2")
        self.assertGreaterEqual(time.monotonic() - t0, 0.35)    # after the stall, as its own family: not the fallback

    def test_with_no_first_address_the_names_addresses_in_their_order(self):
        connect, tried = self.connect_with(fail=("192.0.2.1",))
        sock = vault.egress_dial(443, name="api.example.com", resolve=lambda n: ["192.0.2.1", "192.0.2.2"],
                                 connect=connect, fallback=0.05)
        self.assertEqual(sock.address, "192.0.2.2")


class Control(unittest.TestCase):
    """The gate's control socket: the service user's word, its counts and its policy; the gate's own merge."""

    def setUp(self):
        self.state = tempfile.mkdtemp(prefix="egress-state-")
        self.addCleanup(shutil.rmtree, self.state, True)
        conf = {"user": "founderizer-egress", "service_user": "fleet", "swap_user": "founderizer-swap",
                "group": "fleet-agents"}
        ids = {"fleet": 1100, "founderizer-swap": 1200}
        patcher = patch.object(vault, "egress_uid_of", lambda name: ids.get(name))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.gate = vault.Egress(conf, socks={}, program="a" * 64, state=self.state)

    def test_the_service_user_reads_the_state_and_takes_the_counts(self):
        self.gate.counts.add(2001, "api.example.com", 443, "pass", "sni", "public", conns=1)
        loaded = os.path.join(self.state, "table")
        with patch.object(vault, "EGRESS_LOADED", loaded):
            status = self.gate.control_answer(1100, {"op": "status"})
            # the table that the kernel has, by root's word, not the rules file: a load that failed, or a flush that
            # nothing loaded again, says so (a review of 17 November 2026)
            Path(loaded).write_text("1\n")
            self.assertEqual(self.gate.control_answer(1100, {"op": "status"})["table"], 1)
            Path(loaded).write_text("one\n")
            self.assertIsNone(self.gate.control_answer(1100, {"op": "status"})["table"])
        self.assertEqual((status["ok"], status["mode"], status["knows_table"], status["policy"], status["table"]),
                         (True, "records", vault.EGRESS_TABLE, None, None))
        self.assertEqual(set(status["lookup"]), {"tcp", "udp"})
        self.assertNotIn("open_families", status)           # only root's step can try a family (egress_rules)
        rows = self.gate.control_answer(1100, {"op": "counts"})["rows"]
        self.assertEqual([(r["uid"], r["host"], r["conns"]) for r in rows], [(2001, "api.example.com", 1)])
        self.assertEqual(self.gate.control_answer(1100, {"op": "counts"})["rows"], [])

    def test_another_user_gets_nothing_and_only_the_gates_own_user_merges(self):
        self.assertEqual(self.gate.control_answer(2001, {"op": "counts"})["ok"], False)
        self.assertEqual(self.gate.control_answer(1100, {"op": "merge", "rows": []})["ok"], False)
        row = {"uid": 2001, "host": "example.org", "port": 80, "verdict": "pass", "how": "host", "cls": "public",
               "dns": 0, "conns": 1, "up": 1, "down": 2, "first": 1.0, "last": 2.0}
        self.assertEqual(self.gate.control_answer(os.getuid(), {"op": "merge", "rows": [row]}), {"ok": True})
        self.assertEqual(len(self.gate.counts.take()), 1)

    def test_one_agent_user_has_its_own_limits_of_connections_and_questions(self):
        with patch.object(vault, "EGRESS_PER_USER", 2):
            flows = [self.gate.begin_flow(2001, []) for _ in range(3)]
            self.assertEqual([f is not None for f in flows], [True, True, False])
            self.assertIsNotNone(self.gate.begin_flow(2002, []))         # another agent user is not held by it
            self.gate.end(flows[0])
            self.assertIsNotNone(self.gate.begin_flow(2001, []))
        question = dns_message("a.example.com")
        with patch.object(vault, "EGRESS_DNS_PER_USER", 2), patch.object(vault, "egress_udp_uid", lambda peer: 2001), \
                patch.object(vault.Egress, "is_agent", lambda self, uid: True):
            took = [self.gate.asked(question, ("127.0.0.1", 5353)) for _ in range(3)]
            self.assertEqual([t is not None for t in took], [True, True, False])
            self.gate.done_asking(2001)
            self.assertIsNotNone(self.gate.asked(question, ("127.0.0.1", 5353)))

    def test_a_gate_that_gives_way_takes_no_merge(self):
        self.gate.ending = True
        self.assertEqual(self.gate.control_answer(os.getuid(), {"op": "merge", "rows": []})["ok"], False)

    def test_a_line_that_does_not_come_whole_in_time_is_none(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        a.sendall(b'{"op": ')                       # and no more, and no end of line
        t0 = time.monotonic()
        self.assertEqual(vault.egress_line(b, 65536, 0.5), "")
        self.assertLess(time.monotonic() - t0, 2)
        a.sendall(b'"status"}\n')
        self.assertEqual(vault.egress_line(b, 65536, 1), '"status"}\n')

    def test_the_policy_of_this_step_and_no_other(self):
        good = {"version": 1, "mode": "records"}
        self.assertEqual(self.gate.control_answer(1100, {"op": "policy", "policy": good}), {"ok": True})
        for bad in ({"version": 2, "mode": "records"}, {"version": 1, "mode": "lists"}, None):
            self.assertFalse(self.gate.control_answer(1100, {"op": "policy", "policy": bad})["ok"])
        self.assertEqual(self.gate.control_answer(1100, {"op": "status"})["policy"], good)
        again = vault.Egress(self.gate.conf, socks={}, state=self.state)
        self.assertEqual(again.policy, good)                # the last policy, kept in the gate's own folder

    def test_the_word_starts_a_new_program_once_and_a_failed_one_waits(self):
        started = []
        self.gate.spawn = lambda program, socks: started.append(program) or "exit 1"
        with patch.object(vault.Egress, "installed_program", lambda self: "b" * 64):
            self.gate.control_answer(1100, {"op": "status"})
            for _ in range(50):
                if not self.gate.trying and started:
                    break
                time.sleep(0.02)
            for _ in range(4):
                self.gate.control_answer(1100, {"op": "status"})
            time.sleep(0.1)
        self.assertEqual(started, ["b" * 64])               # the next try only after 4 words
        self.assertEqual(self.gate.failed[:2], ("b" * 64, 1))
        # a program that took over and then ended three times in the last hour with no stop asked for (the
        # launcher's count, from the unit's ExecStopPost) gets no hand-over then: the safe copy that serves keeps
        # serving, and an hour later the program gets its turn again
        crashes, now = os.path.join(self.state, "crashes"), 50000.0      # seconds since boot
        # c ended three times in the last hour; b three times, two hours ago, which no longer counts
        Path(crashes).write_text("".join(f"{x * 64} {at:.0f}\n" for x, at in (("c", now - 60), ("c", now - 30),
                                                                             ("c", now - 5), ("b", now - 7200),
                                                                             ("b", now - 7100), ("b", now - 7000))))
        self.gate.failed, started[:] = None, []
        with patch.object(vault, "EGRESS_CRASHES", crashes), patch.object(vault, "egress_uptime", lambda: now):
            with patch.object(vault.Egress, "installed_program", lambda self: "c" * 64):
                self.gate.control_answer(1100, {"op": "status"})
            with patch.object(vault.Egress, "installed_program", lambda self: "b" * 64):
                self.gate.control_answer(1100, {"op": "status"})
                for _ in range(50):
                    if not self.gate.trying and started:
                        break
                    time.sleep(0.02)
        self.assertEqual(started, ["b" * 64])


class StoredPolicy(unittest.TestCase):
    """A gate does not serve in the place of a policy that a later program stored: the launcher's fallback to the safe
    copy of an earlier root step would otherwise drop that policy's refusals (a review of 17 November 2026)."""

    def test_a_program_does_not_take_a_later_programs_policy(self):
        state = tempfile.mkdtemp(prefix="egress-policy-")
        self.addCleanup(shutil.rmtree, state, True)
        self.assertTrue(vault.egress_policy_taken(state))                    # none stored yet
        for text, taken in (('{"version": 1, "mode": "records"}', True), ("{not json", True),
                            ('{"version": 2, "mode": "lists"}', False), ('{"version": 1, "mode": "lists"}', False)):
            Path(state, "policy.json").write_text(text)
            self.assertIs(vault.egress_policy_taken(state), taken, text)


class Texts(unittest.TestCase):
    """The root-owned texts: the table, its loads, the units, the launcher, the drop-ins and the D-Bus policy."""
    CONF = {"user": "founderizer-egress", "service_user": "fleet", "swap_user": "founderizer-swap",
            "group": "fleet-agents", "hub": "100.64.0.1", "hub_ports": [8765, 9418]}

    def test_the_table_names_its_version_and_refuses_what_it_does_not_send_to_the_gate(self):
        text = vault.egress_table()
        self.assertEqual(vault.egress_rules_version(text), vault.EGRESS_TABLE)
        for line in ("meta skuid @agents jump agent_nat", "meta skuid @agents jump agent_out",
                     "meta skuid @relays jump relay_out", "meta l4proto { udp, tcp } th dport 53 redirect to :880",
                     "fib daddr type local meta l4proto tcp redirect to :878", "meta l4proto tcp redirect to :877",
                     "ip daddr 127.0.0.1 tcp dport 879 accept", "ct state established accept",
                     "ct state new meta l4proto tcp update @new_rate { meta skuid limit rate over 200/second burst "
                     "2000 packets } reject with tcp reset",
                     "ct status dnat ip daddr 127.0.0.1 udp dport 880 update @dns_rate { meta skuid limit rate over "
                     "200/second burst 2000 packets } drop",
                     "reject with icmpx admin-prohibited", "type nat hook output priority -101; policy accept;",
                     'comment "founderizer-egress 1"',
                     # an agent's own browser keeps the agent's UID, which the browsers' table reads; another agent's
                     # connection to that port goes through the gate, which records it
                     "set browser { type uid . inet_service; }",
                     "ip daddr 127.0.0.1 meta skuid . tcp dport @browser return",
                     "ip6 daddr ::1 meta skuid . tcp dport @browser return",
                     "ip daddr 127.0.0.1 meta skuid . tcp dport @browser accept",
                     "ip6 daddr ::1 meta skuid . tcp dport @browser accept",
                     # a sub-uid of an agent in a user namespace of its own meets a refusal, not no rule at all
                     "set subagents { type uid; flags interval; }", "meta skuid @subagents jump sub_out"):
            self.assertIn(line, text)
        sub = text[text.index("chain sub_out"):text.index("chain relay_out")].split("\n")
        self.assertEqual(sub[1:5], ["    ct state established accept", "    meta l4proto tcp reject with tcp reset",
                                    "    reject with icmpx admin-prohibited", "  }"])
        # the browser's ports go direct before any redirect of a local connection to the gate
        self.assertLess(text.index("tcp dport @browser return"), text.index("redirect to :878"))
        # A packet that no user's socket makes (the kernel's own) meets no rule of a user: no "!=" test of a set,
        # which would not match it and would send it on to a refusal
        self.assertNotIn("!= @", text)
        # A TCP connection to another Tailscale machine goes direct, because Tailscale's own rule drops each answer of
        # the gate from its IPv4 range (19 November 2026: no agent reached the door): after the redirect of DNS, so
        # that each question still reaches the gate's resolver; only by Tailscale's interface, so that this
        # machine's own address keeps the gate's local port and a cloud's own service in that range keeps the gate;
        # never to tailscaled's own address; and the kernel lets it through. Tailscale has no such rule for its IPv6
        # range, which stays with the gate.
        nat = text[text.index("chain agent_nat"):text.index("chain filter_out")]
        out = text[text.index("chain agent_out"):text.index("chain sub_out")]
        direct = 'ip daddr 100.64.0.0/10 ip daddr != 100.100.100.100 oifname "tailscale0" meta l4proto tcp'
        self.assertIn(f"{direct} return", nat)
        self.assertIn(f"{direct} accept", out)
        self.assertEqual((nat.count("100.64.0.0/10"), out.count("100.64.0.0/10")), (1, 1))
        self.assertLess(nat.index("th dport 53 redirect"), nat.index(direct))
        self.assertLess(nat.index(direct), nat.index("redirect to :877"))
        self.assertLess(out.index(direct), out.index("meta l4proto tcp reject with tcp reset"))
        self.assertNotIn("fd7a:115c:a1e0", text)

    def test_a_load_is_the_whole_table_with_the_elements_of_its_sets(self):
        folder = tempfile.mkdtemp(prefix="egress-elements-")
        self.addCleanup(shutil.rmtree, folder, True)
        ports, subuid = os.path.join(folder, "ports"), os.path.join(folder, "subuid")
        # the browsers' ports: each agent user's own DevTools port; a line of another form, or with no new line
        # yet, is left out, and the others stay
        Path(ports).write_text("fleet-ana 9301 5911\nfleet-vault 9302 5912\nfleet-bo 9303 5913 later\n"
                               "fleet-bo 9304 5914\nfleet-cy 9305")
        Path(subuid).write_text("fleet-ana:100000:65536\n2002:165536:65536\nfleet-cy:231072:65536\n"
                                "fleet-ana:300000:10\nfleet-bo:1000:100\nfleet-ana:0:3\nfleet-bo:4294967000:9999\n")
        uids = {"fleet-ana": 2001, "fleet-bo": 2002, "fleet-vault": 999}
        with patch.object(vault, "EGRESS_BROWSER", ports), patch.object(vault, "EGRESS_SUBUID", subuid), \
                patch.object(vault, "egress_uid_of", uids.get), \
                patch.object(vault.pwd, "getpwuid", lambda uid: types.SimpleNamespace(
                    pw_name={2001: "fleet-ana", 2002: "fleet-bo"}[uid])), \
                patch.object(vault.pwd, "getpwall", lambda: [types.SimpleNamespace(pw_uid=u) for u in (0, 1050, 2001,
                                                                                                     2002)]):
            elements = vault.egress_elements(dict(self.CONF), agents=[2001, 2002])
            # by name and by UID; next to each other in one interval; a user's own UID (1050) is cut out of the
            # range that holds it, so that no user's packets are refused, and the rest of the range stays
            # a range that starts at root's UID or ends past the last UID that a socket can have is cut, not left
            # with no rule
            self.assertEqual(elements["subagents"], ["1-2", "1000-1049", "1051-1099", "100000-231071", "300000-300009",
                                                     "4294967000-4294967294"])
            held = []                           # ... and the step names each range that holds a user's UID
            vault.egress_subids([2001, 2002], held=held)
            self.assertEqual(held, ["the sub-uids 1000-1099 of fleet-bo hold the UID of a user of this machine (1050), "
                                    "which a process of that agent can take",
                                    "the sub-uids 0-2 of fleet-ana hold the UID of a user of this machine (0), which a "
                                    "process of that agent can take"])
            self.assertEqual(elements["browser"], ["2001 . 9301", "2002 . 9304"])
            os.unlink(ports)
            self.assertEqual(vault.egress_elements(dict(self.CONF), agents=[2001, 2002])["browser"], [])
        self.assertEqual(elements["agents"], ["2001", "2002"])
        self.assertEqual(elements["direct4"], ["100.64.0.1 . 8765", "100.64.0.1 . 9418"])
        text = vault.egress_load_text("TABLE\n", elements)
        self.assertTrue(text.startswith("TABLE\n"))
        self.assertNotIn("flush set", text)         # the whole table each time: no refresh of an interval set
        self.assertIn("add element inet founderizer_egress agents { 2001, 2002 }\n", text)
        self.assertNotIn(" relays ", text)          # a set with no element gets no line

    def test_the_units_and_the_launcher(self):
        files = vault.egress_files('{"egress": 1}\n')
        unit = files["/etc/systemd/system/fleet-egress.service"][0]
        step = ("+/usr/bin/python3 -I /usr/local/lib/founderizer-egress/vault.py egress-rules --config "
                "/etc/founderizer-egress/egress.json --table")
        for line in ("User=founderizer-egress", "ExecStart=/usr/local/lib/founderizer-egress/launch",
                     "NotifyAccess=all", "AmbientCapabilities=CAP_NET_BIND_SERVICE", "Restart=always",
                     "StartLimitIntervalSec=0", "Before=systemd-user-sessions.service cron.service"):
            self.assertIn(line, unit)
        # the gate's unit never takes the table away: it stays while the gate does not run, as a gap with no table
        # would let an agent open a connection that it keeps after the gate is back (a review of 17 November 2026);
        # each end of the gate goes through the launcher, which counts one that nobody asked for
        self.assertNotIn("egress-rules", unit)
        self.assertIn("\nExecStopPost=/usr/local/lib/founderizer-egress/launch --stopped\n", unit)
        # and the step every 5 minutes, after a flush that no unit saw
        timer = files["/etc/systemd/system/fleet-egress-rules.timer"][0]
        for line in ("OnUnitInactiveSec=5min", "Unit=fleet-egress-rules.service", "WantedBy=timers.target"):
            self.assertIn(line, timer)
        rules = files["/etc/systemd/system/fleet-egress-rules.service"][0]
        self.assertIn("ExecStart=/usr/bin/python3 -I /usr/local/lib/founderizer-egress/vault.py egress-rules", rules)
        self.assertIn("\nStartLimitIntervalSec=0\n", rules)     # four units start it: no limit stops the path units
        # one path unit for each file that the step reads: one unit's event of a file that is not there sets all of
        # its watches up again and loses their waiting events (proved under systemd 255, 17 November 2026)
        for name, watched in (("fleet-egress-rules", "/etc/group"), ("fleet-egress-subuid", "/etc/subuid"),
                              ("fleet-egress-browser", "/etc/fleet-browser/ports")):
            text = files[f"/etc/systemd/system/{name}.path"][0]
            self.assertEqual([x for x in text.splitlines() if x.startswith("PathChanged=")],
                             [f"PathChanged={watched}"], name)
            self.assertIn("\nUnit=fleet-egress-rules.service\n", text)
        # nftables.service flushes every table at its start, its reload and its stop: the gate's comes back after each
        nft = files["/etc/systemd/system/nftables.service.d/founderizer-egress.conf"][0]
        for key in ("ExecStartPost", "ExecReload", "ExecStopPost"):
            self.assertIn(f"\n{key}=-{step}\n", nft)
        launch, mode = files[vault.EGRESS_LAUNCH]
        self.assertEqual(mode, 0o755)
        self.assertLess(launch.index(vault.INSTALLED), launch.index(vault.EGRESS_SAFE))
        # an end that nobody asked for counts against the program that ran; at 3 in the last hour, the safe copy
        self.assertIn('if [ "$SERVICE_RESULT" != "success" ] && [ -f /run/founderizer-egress/running ]', launch)
        self.assertIn('[ "${ended:-0}" -ge 3 ]', launch)
        self.assertIn("since=$(($(cut -d. -f1 /proc/uptime) - 3600))", launch)    # since boot: no clock step moves it
        self.assertIn("'$1 == h && $2 > since'", launch)
        self.assertIn("> /run/founderizer-egress/running", launch)
        dropin = files["/etc/systemd/system/systemd-resolved.service.d/founderizer-egress.conf"][0]
        self.assertIn("ExecStartPre=-+/usr/bin/python3 -I /usr/local/lib/founderizer-egress/vault.py egress-close "
                      "--config /etc/founderizer-egress/egress.json resolved", dropin)
        self.assertIn("[Socket]\nExecStartPost=-/usr/bin/python3",
                      files["/etc/systemd/system/snapd.socket.d/founderizer-egress.conf"][0])

    def test_the_kernels_socket_families_are_kept_from_loading_and_a_loaded_one_is_named(self):
        text = vault.egress_files("{}")[vault.EGRESS_MODPROBE][0]
        for module in ("rxrpc", "smc", "rds", "tipc"):
            self.assertIn(f"install {module} /bin/false\n", text)
        modules = tempfile.NamedTemporaryFile("w", delete=False)
        self.addCleanup(os.unlink, modules.name)
        modules.write("rxrpc 438272 0 - Live 0x0\nnf_tables 1 0 - Live 0x0\n")
        modules.close()
        self.assertEqual(vault.egress_open_families(modules.name), ["rxrpc"])
        dropin = vault.egress_files("{}")["/etc/systemd/system/docker.socket.d/founderizer-egress.conf"][0]
        self.assertIn("egress-close --config /etc/founderizer-egress/egress.json daemons", dropin)

    def test_the_rules_step_tries_each_family_itself_and_names_an_open_one(self):
        rules = tempfile.NamedTemporaryFile("w", delete=False, suffix=".nft")
        self.addCleanup(os.unlink, rules.name)
        rules.write(vault.egress_table(None))
        rules.close()
        ran = []

        def run(command):
            ran.append(command)
            return 0, "", ""
        modprobe = tempfile.NamedTemporaryFile("w", delete=False, suffix=".conf")
        self.addCleanup(os.unlink, modprobe.name)
        modprobe.write(vault.egress_files("{}")[vault.EGRESS_MODPROBE][0])
        modprobe.close()
        tried = []

        def families():
            tried.append(True)
            return ["tipc"]
        folder = tempfile.mkdtemp(prefix="egress-rules-")
        self.addCleanup(shutil.rmtree, folder, True)
        with patch.object(vault, "EGRESS_RULES", rules.name), patch.object(vault, "EGRESS_MODPROBE", modprobe.name), \
                patch.object(vault, "EGRESS_LOCK", os.path.join(folder, "lock")), \
                patch.object(vault, "EGRESS_LOADED", os.path.join(folder, "table")), \
                patch.object(vault, "egress_close", lambda conf: ([], [])), \
                patch.object(vault, "egress_daemons", lambda conf, agents=None: ([], [])), \
                patch.object(vault, "egress_open_families", lambda path="/proc/modules", tries=True:
                             ["tipc"] if tries else ["rxrpc"]):
            answer = vault.egress_rules(self.CONF, run=run, write=lambda *a: False, agents=[])
            self.assertTrue(answer["ok"])
            self.assertIn("the module rxrpc is out", answer["closed"])
            self.assertEqual(answer["unclosed"], ["the socket family tipc is open to the agents (built into this "
                                                  "kernel, or its module is in use)"])
            self.assertTrue(any(c.startswith("modprobe -r rxrpc") for c in ran))
            os.unlink(modprobe.name)                    # no file: no try, which would load the module it looks for
            answer = vault.egress_rules(self.CONF, run=run, write=lambda *a: False, agents=[], families=families)
            open(modprobe.name, "w").close()
        self.assertEqual(tried, [])
        self.assertEqual(len(answer["unclosed"]), 1)
        self.assertIn("is missing or changed", answer["unclosed"][0])

    def test_the_table_is_loaded_whole_whenever_root_s_rules_file_is_there(self):
        """Also while the gate does not run: the table stays, and an agent's DNS and TCP fail at once (the proposal's
        section 5.4; a review of 17 November 2026: a gap with no table lets an agent keep a tunnel open after the
        gate is back). The whole table each time; no rules file is no table. Root's file names the version that the
        kernel has, for the gate's state. A change of what the step reads while it runs makes it run again."""
        folder = tempfile.mkdtemp(prefix="egress-table-")
        self.addCleanup(shutil.rmtree, folder, True)
        rules, loaded = os.path.join(folder, "rules.nft"), os.path.join(folder, "table")
        Path(rules).write_text(vault.egress_table(None))
        kernel = {"table": None, "fail": False}
        loads = []

        def run(command):
            if "list table inet founderizer_egress" in command:
                return 0, json.dumps({"nftables": [{"table": {"comment": f"founderizer-egress {kernel['table']}"}}]}
                                     if kernel["table"] else {}), ""
            if command.startswith("/usr/sbin/nft -f -"):
                loads.append(command)
                if kernel["fail"]:
                    return 1, "", "Error: Could not process rule"
                kernel["table"] = 1
            elif "delete table inet founderizer_egress" in command:
                kernel["table"] = None
            return 0, "", ""

        def step():
            with patch.object(vault, "EGRESS_RULES", rules), patch.object(vault, "EGRESS_LOADED", loaded), \
                    patch.object(vault, "EGRESS_LOCK", os.path.join(folder, "lock")), \
                    patch.object(vault, "egress_uid_of", lambda name: None):
                return vault.egress_rules(self.CONF, run=run, agents=[2001], table_only=True)
        self.assertEqual(step(), {"ok": True, "table": "loaded"})
        self.assertIn("table inet founderizer_egress {", loads[-1])
        self.assertEqual(Path(loaded).read_text(), "1\n")
        self.assertEqual(step(), {"ok": True, "table": "loaded"})      # whole again, with no flush of a set
        self.assertIn("table inet founderizer_egress {", loads[-1])
        kernel["fail"] = True               # a load that fails keeps the table that is there, and root's file
        answer = step()
        self.assertEqual((answer["ok"], kernel["table"], Path(loaded).read_text()), (False, 1, "1\n"))
        self.assertIn("Could not process rule", answer["reason"])
        kernel["table"] = None              # with no table there, root's file goes
        self.assertEqual((step()["ok"], os.path.exists(loaded)), (False, False))
        kernel["fail"] = False
        changes = iter(["a", "b", "b", "b"])      # what the step reads changed while it ran: once more
        loads.clear()
        with patch.object(vault, "egress_inputs", lambda: next(changes)):
            step()
        self.assertEqual(len(loads), 2)
        os.unlink(rules)                    # before the root step's gate serves, and after "off"
        self.assertEqual(step(), {"ok": True, "table": "none"})
        self.assertEqual((kernel["table"], os.path.exists(loaded)), (None, False))

    def test_the_dbus_policy_names_the_group_and_each_agent_user(self):
        with patch.object(vault.pwd, "getpwuid", lambda uid: types.SimpleNamespace(pw_name=f"fleet-a{uid}")):
            text = vault.egress_dbus(self.CONF, [1, 2])
        self.assertIn('<policy group="fleet-agents"><deny send_destination="org.freedesktop.resolve1"/></policy>',
                      text)
        self.assertIn('<policy user="fleet-a2"><deny send_destination="org.freedesktop.resolve1"/></policy>', text)

    def test_the_configuration_takes_the_hubs_address_and_no_name(self):
        text = vault.egress_conf_text({"hub": "http://100.64.0.1:8765", "worker_group": "fleet-agents"})
        conf = json.loads(text)
        self.assertEqual((conf["hub"], conf["hub_ports"], conf["service_user"]), ("100.64.0.1", [8765, 9418], "fleet"))
        with self.assertRaises(vault.ConfigureStop):
            vault.egress_conf_text({"hub": "http://hub.example.com:8765"})
        read = lambda path: text
        self.assertEqual(vault.egress_config("x", read=read)["hub"], "100.64.0.1")
        with self.assertRaises(vault.Refused):
            vault.egress_config("x", read=lambda path: text.replace('"egress": 1', '"egress": 9'))


class Acl(unittest.TestCase):
    """The closures' ACL entries as the kernel keeps them (acl(5)): the named group decides before others."""

    def test_an_entry_keeps_each_other_entrys_effect_through_the_mask(self):
        base = [(vault.ACL_USER_OBJ, 6, vault.ACL_NO_ID), (vault.ACL_GROUP_OBJ, 6, vault.ACL_NO_ID),
                (vault.ACL_OTHER, 6, vault.ACL_NO_ID)]
        out = sorted(vault.acl_with(base, 1000, 4))
        self.assertIn((vault.ACL_GROUP, 4, 1000), out)
        self.assertIn((vault.ACL_MASK, 6, vault.ACL_NO_ID), out)          # rw- of the socket stays for its group
        raw = vault.acl_bytes(out)
        self.assertEqual(struct.unpack_from("<I", raw)[0], 2)
        self.assertEqual(len(raw), 4 + 8 * len(out))
        tags = [struct.unpack_from("<H", raw, i)[0] for i in range(4, len(raw), 8)]
        self.assertEqual(tags, sorted(tags))


class Machine:
    """The machine of the root step's gate part (vault.configure_egress): it answers its readings and carries out
    the effects that the step reads after."""

    def __init__(self, **state):
        self.ran, self.files, self.loaded, self.gate_stays, self.table_stays = [], {}, None, True, False
        self.state = dict({"euser": "no", "elow": "1024", "enft": "yes", "eactive": "inactive", "eenabled": "",
                           "erestarts": "0", "epath": "inactive", "erules": "", "eswap": "inactive", "eswap_at": "",
                           "eprogram_at": "", "elisten": "0", "eports": ""}, **state)

    def run(self, script, timeout=120):
        self.ran.append(script)
        if "echo eactive=" in script:
            lines = [f"{k}={v}" for k, v in self.state.items()] + \
                    [f"hash {h} {p}" for p, h in self.files.items()]
            return 0, "\n".join(lines), ""
        if "-j list table inet founderizer_egress" in script:          # egress_loaded's reading of the kernel
            out = {"nftables": [{"table": {"comment": f"founderizer-egress {self.loaded}"}}]} if self.loaded else {}
            return 0, json.dumps(out), ""
        if "useradd --system" in script:
            self.state["euser"] = "yes"
        for line in script.splitlines():
            if line.startswith("install -o root") and not line.startswith("install -d"):
                local, path = line.split()[-2:]
                self.files[path.strip("'")] = hashlib.sha256(Path(local.strip("'")).read_bytes()).hexdigest()
            if line.startswith("mv -f "):           # root's file in place in one step
                old, new = (x.strip("'") for x in line.split()[-2:])
                self.files[new] = self.files.pop(old)
            if line == f"systemctl restart {vault.EGRESS_SERVICE}":
                self.state.update(eactive="active" if self.gate_stays else "activating",
                                  elisten="1" if self.gate_stays else "0")
            if line.startswith("systemctl enable --now fleet-egress-rules.path"):
                self.state.update(epath="active", erules="enabled")
            if "delete table inet founderizer_egress" in line and not self.table_stays:
                self.loaded = None
        return 0, "", ""


class ConfigureEgress(unittest.TestCase):
    """The root step's gate part (`vault.py configure --egress on|off`), in the order of the proposal's section 8."""
    BROKER = {"hub": "http://100.64.0.1:8765", "worker_group": "fleet-agents"}

    def step(self, machine, egress="on", check=False):
        loads = []

        def rules(conf):
            loads.append(conf)
            machine.loaded = vault.EGRESS_TABLE
            return {"ok": True, "groups_removed": ["fleet-dana:docker"], "closed": ["resolved: ..."]}
        with patch.object(vault, "egress_uid_of", lambda name: 1100 if name == "fleet" else None), \
                patch.object(vault, "egress_config", lambda path=None, read=None: {"group": "fleet-agents"}), \
                patch.object(vault, "INSTALLED", self.program):
            return vault.configure_egress(egress, check, machine.run, self.BROKER, 0, rules=rules), loads

    def setUp(self):
        folder = tempfile.mkdtemp(prefix="egress-configure-")
        self.addCleanup(shutil.rmtree, folder, True)
        self.program = os.path.join(folder, "vault.py")
        Path(self.program).write_text("# the installed program\n")

    def test_on_starts_the_gate_first_a_second_run_changes_nothing_and_a_new_text_loads_with_no_restart(self):
        machine = Machine()
        (changes, answer), loads = self.step(machine)
        self.assertEqual(changes, ["the gate's user", "the gate's files", "the gate", "the kernel rules",
                                   "the rules' unit"])
        self.assertEqual((answer["egress"], answer["egress_table"], answer["groups_removed"]),
                         (True, vault.EGRESS_TABLE, ["fleet-dana:docker"]))
        scripts = "\n".join(machine.ran)
        self.assertLess(scripts.index("systemctl restart fleet-egress"),
                        scripts.index("systemctl enable --now fleet-egress-rules.path"))
        # root's files go in place in one step each: a step never finds the rules file missing while it is written
        self.assertIn(f"mv -f {vault.EGRESS_RULES}.new {vault.EGRESS_RULES}\n", scripts)
        self.assertEqual(len(loads), 1)
        self.assertIn(vault.EGRESS_SAFE, machine.files)
        (changes, answer), loads = self.step(machine)
        self.assertEqual((changes, answer["egress_state"], loads), ([], "there", []))
        # A later program's new table text of the same version (19 November 2026: the Tailscale range), on a machine
        # whose gate and swap proxy run: the step finds it by its file's hash and says so, then writes and loads it,
        # and restarts neither the gate nor the swap proxy, whose restart would cut each open tunnel
        machine.files[vault.EGRESS_RULES] = "0" * 64
        machine.state.update(eswap="active", eswap_at="100", eprogram_at="200")
        (changes, answer), loads = self.step(machine, check=True)
        self.assertEqual((changes, answer["egress_state"], loads),
                         (["the gate's files", "the kernel rules"], "would make", []))
        before = len(machine.ran)
        (changes, answer), loads = self.step(machine)
        self.assertEqual((changes, answer["egress_state"], len(loads)),
                         (["the gate's files", "the kernel rules"], "made", 1))
        later = "\n".join(machine.ran[before:])
        self.assertIn(f"mv -f {vault.EGRESS_RULES}.new {vault.EGRESS_RULES}\n", later)
        self.assertNotIn("systemctl restart", later)

    def test_a_gate_that_does_not_start_leaves_no_table_no_rules_file_and_no_rules_unit(self):
        machine = Machine()
        machine.gate_stays = False
        with self.assertRaises(vault.ConfigureStop) as stop:
            self.step(machine)
        self.assertIn("each agent connects as before", str(stop.exception))
        self.assertIsNone(machine.loaded)
        self.assertNotIn(vault.EGRESS_RULES, machine.files)        # the swap proxy keeps connecting by itself
        self.assertIn("systemctl disable --now fleet-egress-rules.path", "\n".join(machine.ran))

    def test_a_gate_that_does_not_start_again_keeps_the_table_that_was_there(self):
        """A second run that finds a gate that served before and does not start now takes nothing away: the table
        stays while any gate does not run (the proposal's section 5.4), and the server watch tells the manager. Only a
        first install whose gate does not start takes the table back (the test above)."""
        for loaded in (vault.EGRESS_TABLE, None):          # a flush by hand a minute ago leaves the rules file
            machine = Machine(epath="active", erules="enabled")
            machine.files[vault.EGRESS_RULES] = "0" * 64       # the hash of an older text
            machine.loaded, machine.gate_stays = loaded, False
            with self.assertRaises(vault.ConfigureStop) as stop:
                self.step(machine)
            self.assertIn("Its kernel rules stay", str(stop.exception))
            self.assertEqual(machine.loaded, loaded)
            self.assertFalse(any("delete table" in s or "disable --now fleet-egress-rules" in s for s in machine.ran))
            # the new rules file is in place with the new program, so the next step loads the table that it knows
            self.assertNotEqual(machine.files[vault.EGRESS_RULES], "0" * 64)

    def test_the_rules_file_comes_only_after_the_gate_serves(self):
        machine = Machine()
        self.step(machine)
        restart = next(i for i, x in enumerate(machine.ran) if "systemctl restart fleet-egress\n" in x)
        rules = next(i for i, x in enumerate(machine.ran) if "install -o root" in x and vault.EGRESS_RULES in x)
        self.assertLess(restart, rules)

    def test_a_gate_that_runs_is_not_started_again_and_a_taken_port_stops_a_new_one(self):
        machine = Machine(eactive="active", elisten="1")
        self.step(machine)
        self.assertNotIn("systemctl restart fleet-egress\n", "\n".join(machine.ran))
        machine = Machine(eports="878 ")
        with self.assertRaises(vault.ConfigureStop) as stop:
            self.step(machine)
        self.assertIn("Another program listens on the gate's port 878", str(stop.exception))

    def test_it_stops_where_each_user_can_take_a_port_of_the_gate_or_there_is_no_nft(self):
        for state, words in (({"elow": "800"}, "each user can listen on the gate's ports"),
                             ({"enft": "no"}, "has no /usr/sbin/nft")):
            machine = Machine(**state)
            with self.assertRaises(vault.ConfigureStop) as stop:
                self.step(machine)
            self.assertIn(words, str(stop.exception))
            self.assertFalse(any("useradd" in s for s in machine.ran))

    def test_the_swap_proxy_of_an_older_program_starts_again_before_the_table(self):
        machine = Machine(eswap="active", eswap_at="100", eprogram_at="200")
        (changes, _), _ = self.step(machine)
        self.assertIn("the swap proxy", changes)
        scripts = "\n".join(machine.ran)
        self.assertIn("systemctl restart fleet-vault-swap", scripts)

    def test_check_reads_and_changes_nothing_and_off_takes_the_table_first(self):
        machine = Machine()
        (changes, answer), _ = self.step(machine, check=True)
        self.assertEqual((answer["egress_state"], machine.files), ("would make", {}))
        self.step(machine)
        opened, at = [], len(machine.ran)
        with patch.object(vault, "egress_open", opened.append):
            (changes, answer), _ = self.step(machine, egress="off")
        self.assertEqual((changes, answer["egress"]), (["the gate"], False))
        off = "\n".join(machine.ran[at:])
        self.assertLess(off.index("delete table inet founderizer_egress"), off.index("rm -f " + vault.EGRESS_RULES))
        # under the rules' step's lock: no step that read the rules file loads the table after its delete; and root's
        # files go only once the table is gone, so a table that stays keeps the swap proxy and the records as they are
        self.assertLess(off.index(f"flock {vault.EGRESS_LOCK} sh -c "), off.index("delete table"))
        self.assertIn("delete table inet founderizer_egress || exit 1; fi; rm -f", off)
        self.assertLess(off.index("rm -f " + vault.EGRESS_RULES), off.index("disable --now fleet-egress >"))
        # root's off keeps the gate's configuration: the owner's Mac makes a gate on the hub's own server only where
        # that file is not there (KeySwapRemote.gate), so without it the Mac's next keys step there undoes root's off
        self.assertNotIn("rm -f " + vault.EGRESS_CONF, off)
        # a table that does not go stops the step before the gate stops: the agents still have their gate
        machine = Machine()
        self.step(machine)
        machine.table_stays, at = True, len(machine.ran)
        with patch.object(vault, "egress_open", opened.append), self.assertRaises(vault.ConfigureStop) as stop:
            self.step(machine, egress="off")
        self.assertIn("did not go", str(stop.exception))
        self.assertNotIn("disable --now fleet-egress >", "\n".join(machine.ran[at:]))


class Install(unittest.TestCase):
    """The install's step (hubsetup.egress_install): the installed program's own configure, and its answer."""

    def install(self, answer, check=False):
        ran = []
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            state = hubsetup.egress_install(check=check, run=lambda s, timeout=120: ran.append(s) or answer)
        return state, out.getvalue(), ran

    def test_it_runs_the_installed_programs_own_step_and_says_its_answer(self):
        state, words, ran = self.install((0, json.dumps({"ok": True, "state": "made", "egress": True,
                                                         "groups_removed": ["fleet-dana:docker"]}), ""))
        self.assertEqual(state, "made")
        self.assertEqual(ran, ["python3 -I /usr/local/lib/fleet-vault/vault.py configure --config "
                               "/etc/fleet-vault/vault.json --egress on"])
        self.assertIn("this machine's outgoing gate is on", words)
        self.assertIn("fleet-dana:docker", words)
        state, words, _ = self.install((0, json.dumps({"ok": True, "state": "would make", "egress": False,
                                                       "groups_to_leave": ["fleet-dana:docker"]}), ""), check=True)
        self.assertEqual(state, "would make")
        self.assertIn("would take this agent user out of a container group", words)
        with self.assertRaises(hubsetup.Stop):
            self.install((1, json.dumps({"ok": False, "reason": "no nft"}), ""))
        with self.assertRaises(hubsetup.Stop):
            self.install((2, "usage: vault.py", ""))


class Chain(unittest.TestCase):
    """The key swap through the gate (the proposal's section 5.9): with the root-owned rules file, the swap proxy's
    connection goes to the gate's relay port with the agent user's UID, and to no host of its own."""

    def gate(self, answer=b"HTTP/1.1 200 Connection established\r\n\r\n"):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        self.addCleanup(listener.close)
        heads = []

        def serve():
            conn, _ = listener.accept()
            head, _ = vault.swap_head(conn, 4096)
            heads.append(head)
            conn.sendall(answer)
            conn.recv(1)
            conn.close()
        threading.Thread(target=serve, daemon=True).start()
        return listener.getsockname(), heads

    def test_with_the_rules_file_it_asks_the_gate_with_the_agents_uid(self):
        rules = tempfile.NamedTemporaryFile(delete=False)
        self.addCleanup(os.unlink, rules.name)
        address, heads = self.gate()
        sock = vault.swap_reach("api.example.com", 443, 2001, rules=rules.name, gate=address)
        self.assertIsNotNone(sock)
        sock.close()
        self.assertEqual(heads[0], b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n"
                                   b"X-Founderizer-Agent-Uid: 2001")

    def test_a_refusal_of_the_gate_or_no_uid_is_no_connection(self):
        rules = tempfile.NamedTemporaryFile(delete=False)
        self.addCleanup(os.unlink, rules.name)
        address, _ = self.gate(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        self.assertIsNone(vault.swap_reach("api.example.com", 443, 2001, rules=rules.name, gate=address))
        self.assertIsNone(vault.swap_reach("api.example.com", 443, None, rules=rules.name, gate=address))

    def test_without_the_rules_file_it_connects_by_itself_as_before(self):
        site = socket.socket()
        site.bind(("127.0.0.1", 0))
        site.listen(1)
        self.addCleanup(site.close)
        sock = vault.swap_reach("127.0.0.1", site.getsockname()[1], 2001, rules="/nonexistent/egress/rules.nft")
        self.assertIsNotNone(sock)
        sock.close()


class Domains(unittest.TestCase):
    """The hub folds a name into its registrable domain by the Public Suffix List, both of its sections."""

    def test_registrable_domains(self):
        for host, domain in (("api.example.com", "example.com"), ("a.b.example.co.uk", "example.co.uk"),
                             ("alice.github.io", "alice.github.io"), ("x.alice.github.io", "alice.github.io"),
                             ("co.uk", "co.uk"), ("192.0.2.1", "192.0.2.1"), ("2001:db8::1", "2001:db8::1"),
                             ("localhost", "localhost"), ("deep.name.example", "name.example")):
            self.assertEqual(hub.registrable_domain(host), domain, host)


class Records(test_servers.Servers):
    """The hub's records (POST /server/<name>/egress, GET /ui/hosts): from the server's own service only, each row
    under its registrable domain, for an agent of that server."""

    def setUp(self):
        super().setUp()
        self.joined("mini", kind="linux")
        hub.TEAM["agents"]["vps"]["machine"] = "mini"
        patcher = patch.object(hub, "agents", lambda: hub.TEAM["agents"])
        patcher.start()
        self.addCleanup(patcher.stop)

    def post(self, rows, gate=None, key=test_servers.KEY, other=0):
        return self.service("/server/mini/egress", {"gate": gate or {"table": 1, "mode": "records"}, "rows": rows,
                                                    "other_users": other}, key=key)

    def row(self, host, agent="vps", port=443, **more):
        return dict({"agent": agent, "host": host, "port": port, "verdict": "pass", "how": "sni", "cls": "public",
                     "dns": 0, "conns": 1, "up": 10, "down": 20, "first": 1000.0, "last": 1001.0}, **more)

    def hosts(self, query=""):
        status, view = self.request("/ui/hosts?db=test-generation" + query.replace("?", "&"),
                                    source=test_servers.OWNER)
        self.assertEqual(status, 200, view)
        return view

    def test_rows_go_under_their_domain_with_names_and_the_answer_is_the_policy(self):
        status, answer = self.post([self.row("a.example.com"), self.row("b.example.com", up=5),
                                    self.row("a.example.com", port=53, how="dns", dns=3, conns=0, cls=""),
                                    self.row("x" * 60 + ".example.org")])
        self.assertEqual((status, answer["kept"], answer["policy"]), (200, 4, {"version": 1, "mode": "records"}))
        view = self.hosts()
        rows = {(h["domain"], h["port"]): h for h in view["agents"][0]["hosts"]}
        self.assertEqual((rows[("example.com", 443)]["conns"], rows[("example.com", 443)]["up"],
                          rows[("example.com", 443)]["names"]), (2, 15, 2))
        self.assertEqual(rows[("example.com", 53)]["dns"], 3)
        self.assertEqual(rows[("example.org", 443)]["longest"], 60)
        self.assertEqual(view["servers"][0]["server"], "mini")
        one = self.hosts("?agent=vps")
        self.assertEqual(sorted(next(h for h in one["agents"][0]["hosts"] if h["port"] == 443 and
                                     h["domain"] == "example.com")["full_names"]), ["a.example.com", "b.example.com"])

    def test_names_are_counted_for_each_row_and_over_is_a_flag(self):
        self.post([self.row("a.example.com", port=53, how="dns", dns=1, conns=0, cls="")])
        self.post([self.row("b.example.com"), self.row("c.example.com")])        # the 443 row comes after the names
        with patch.object(hub, "EGRESS_NAMES_MOST", 3):
            for _ in range(3):
                self.post([self.row("d.example.com"), self.row("e.example.com")])
        rows = {h["port"]: h for h in self.hosts()["agents"][0]["hosts"]}
        self.assertEqual((rows[53]["names"], rows[443]["names"]), (3, 3))
        self.assertEqual((rows[53]["over"], rows[443]["over"]), (1, 1))

    def test_one_post_of_many_names_keeps_the_bounds(self):
        with patch.object(hub, "EGRESS_NAMES_MOST", 3):
            self.post([self.row(f"n{i}.example.com") for i in range(5)])
        row = self.hosts()["agents"][0]["hosts"][0]
        self.assertEqual((row["domain"], row["names"], row["over"], row["conns"]), ("example.com", 3, 1, 5))
        with patch.object(hub, "EGRESS_AGENT_NAMES", 4):
            self.post([self.row(f"n{i}.example.org") for i in range(3)])
        self.assertEqual(hub.q1("SELECT COUNT(*) AS n FROM egress_names")["n"], 4)

    def test_a_name_with_data_in_its_labels_is_kept_as_it_went_out(self):
        status, answer = self.post([self.row("Ab\\043\\047.Exfil.example.com", how="dns", port=53, dns=1, conns=0,
                                              cls=""), self.row("(more hosts)", port=0)])
        self.assertEqual(answer["kept"], 2)
        names = [r["name"] for r in hub.q("SELECT name FROM egress_names")]
        self.assertEqual(names, ["ab\\043\\047.exfil.example.com"])

    def test_a_login_with_escaped_bytes_in_a_label_is_found(self):
        with patch.object(hub, "secret_hit", lambda *texts: any("sk/ab+cd=" in t for t in texts)):
            self.post([self.row("sk\\047ab\\043cd\\061.attacker.example", how="dns", port=53, dns=1, conns=0, cls="")])
        self.assertEqual([r["domain"] for r in hub.q("SELECT domain FROM egress_hosts")], [hub.EGRESS_HELD])

    def test_an_agents_rows_stay_under_a_bound(self):
        with patch.object(hub, "EGRESS_AGENT_ROWS", 3):
            self.post([self.row(f"h{i}.example{i}.com") for i in range(6)])
        domains = sorted(r["domain"] for r in hub.q("SELECT domain FROM egress_hosts"))
        self.assertEqual(domains, ["(more hosts)", "example0.com", "example1.com", "example2.com"])
        self.assertEqual(hub.q1("SELECT conns FROM egress_hosts WHERE domain='(more hosts)'")["conns"], 3)

    def test_the_check_of_a_logins_value_reads_the_name_as_it_went_out(self):
        seen = []
        with patch.object(hub, "secret_hit", lambda *texts: seen.extend(texts) or "MixedCase" in "".join(texts)):
            self.post([self.row("MixedCaseSecret.example.com")])
        self.assertIn("MixedCaseSecret.example.com", seen)
        self.assertEqual([r["domain"] for r in hub.q("SELECT domain FROM egress_hosts")], [hub.EGRESS_HELD])

    def test_a_row_of_an_agent_of_another_server_is_not_kept(self):
        status, answer = self.post([self.row("a.example.com", agent="studio")])
        self.assertEqual((status, answer["kept"]), (200, 0))
        self.assertEqual(hub.q1("SELECT other_users FROM egress_servers WHERE server='mini'")["other_users"], 1)

    def test_a_name_that_holds_a_logins_value_is_not_kept(self):
        with patch.object(hub, "secret_hit", lambda *texts: any("secretvalue" in t for t in texts)):
            self.post([self.row("secretvalue123.example.com")])
        names = [r["name"] for r in hub.q("SELECT name FROM egress_names")]
        domains = [r["domain"] for r in hub.q("SELECT domain FROM egress_hosts")]
        self.assertNotIn("secretvalue123.example.com", names)
        self.assertEqual(domains, [hub.EGRESS_HELD])

    def test_another_key_and_a_bad_body_are_refused(self):
        self.assertEqual(self.post([self.row("a.example.com")], key="another-key")[0], 403)
        for rows in ("x", [self.row("a.example.com")] * (hub.EGRESS_ROWS_MOST + 1)):
            self.assertEqual(self.post(rows)[0], 400)
        self.assertEqual(self.post([self.row("a.example.com", verdict="maybe")])[1]["kept"], 0)

    def test_a_rename_of_the_agent_takes_its_rows(self):
        self.post([self.row("a.example.com")])
        with hub.transaction():
            hub.rename_rows("vps", "vps2", time.time())
        self.assertEqual(hub.q1("SELECT agent FROM egress_hosts")["agent"], "vps2")
        self.assertEqual(hub.q1("SELECT agent FROM egress_names")["agent"], "vps2")


# Records takes the harness of test_servers.Servers (its hub, a joined server and its key), and none of its tests.
for _name in dir(test_servers.Servers):
    if _name.startswith("test") and _name not in Records.__dict__:
        setattr(Records, _name, None)


class ServiceRound(unittest.TestCase):
    """The service user's part (server.Service.egress_round): the gate's counts to the hub by agent, and the hub's
    policy to the gate."""

    def setUp(self):
        folder = tempfile.mkdtemp(prefix="egress-svc-")
        self.addCleanup(shutil.rmtree, folder, True)
        self.path = os.path.join(folder, "control.sock")
        self.asked, self.policy = [], None
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(self.path)
        listener.listen(8)
        self.addCleanup(listener.close)

        def serve():
            while True:
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                request = json.loads(conn.makefile().readline())
                self.asked.append(request["op"])
                answer = {"status": {"ok": True, "table": 1, "mode": "records", "policy": self.policy},
                          "counts": {"ok": True, "rows": [
                              {"uid": 2001, "user": "fleet-vps", "host": "a.example.com", "port": 443,
                               "verdict": "pass", "how": "sni", "cls": "public", "dns": 0, "conns": 1, "up": 1,
                               "down": 2, "first": 1.0, "last": 2.0},
                              {"uid": 3333, "host": "b.example.com", "port": 443}]},
                          "policy": {"ok": True}}[request["op"]]
                if request["op"] == "policy":
                    self.policy = request["policy"]
                conn.sendall((json.dumps(answer) + "\n").encode())
                conn.close()
        threading.Thread(target=serve, daemon=True).start()
        self.posts, self.hub_status = [], 200

        class Hub:
            def call(inner, method, path, body=None, timeout=30):
                self.posts.append((path, body))
                return self.hub_status, {"ok": True, "policy": {"version": 1, "mode": "records"}}
        self.rules = os.path.join(folder, "rules.nft")
        Path(self.rules).write_text("# founderizer-egress table 1\n")
        self.svc = types.SimpleNamespace(platform="linux", egress=self.path, egress_kept=[], name="mini", hub=Hub(),
                                         egress_lock=threading.Lock(), egress_rules=self.rules, egress_on=True,
                                         agent_users=lambda: {"vps": {"user": "fleet-vps", "uid": 2001}})
        self.svc.egress_once = lambda: server.Service.egress_once(self.svc)
        self.svc.egress_ask = lambda request, timeout=10: server.Service.egress_ask(self.svc, request, timeout)
        self.svc.post_egress = lambda body: server.Service.post_egress(self.svc, body)

    def test_rows_by_agent_to_the_hub_and_the_policy_to_the_gate_once(self):
        server.Service.egress_round(self.svc)
        path, body = self.posts[-1]
        self.assertEqual(path, "/server/mini/egress")
        self.assertEqual([(r["agent"], r["host"]) for r in body["rows"]], [("vps", "a.example.com")])
        self.assertEqual(body["other_users"], 1)
        self.assertEqual(self.asked, ["status", "counts", "policy"])
        server.Service.egress_round(self.svc)
        self.assertEqual(self.asked[3:], ["status", "counts"])             # the gate has that policy now

    def test_rows_that_the_hub_did_not_take_wait_for_the_next_round(self):
        self.hub_status = 503
        server.Service.egress_round(self.svc)
        self.assertEqual(len(self.svc.egress_kept), 1)
        self.hub_status = 200
        server.Service.egress_round(self.svc)
        self.assertEqual(len(self.posts[-1][1]["rows"]), 2)
        self.assertEqual(self.svc.egress_kept, [])

    def test_a_part_that_the_hub_took_is_not_posted_again(self):
        calls, parts = [], []

        class Hub:
            def call(inner, method, path, body=None, timeout=30):
                calls.append(len(body["rows"]))
                parts.append(body["part"])
                return (200, {"ok": True}) if len(calls) == 1 else (503, {})
        self.svc.hub = Hub()
        answer, sent = server.Service.post_egress(self.svc, {"gate": None, "rows": [{}] * 2500, "other_users": 0})
        self.assertEqual((answer, sent, calls), (None, 2000, [2000, 500]))
        self.assertEqual(parts, [0, 1])         # numbered: the hub counts the gate's state once for each report

    def test_a_gate_that_never_made_its_socket_is_posted_as_none(self):
        """After a boot where the gate did not start (its socket was never made), the hub hears that the gate does
        not answer, and its server watch tells the manager (a review of 17 November 2026: it heard nothing)."""
        self.svc.egress = self.path + ".none"
        loaded = os.path.join(os.path.dirname(self.rules), "table")
        Path(loaded).write_text("1\n")
        with patch.object(server, "EGRESS_LOADED", loaded):
            server.Service.egress_round(self.svc)
        # a gate that is there and does not answer, with root's word that the kernel has its table: the agents
        # reach the hub and nothing else
        self.assertEqual([(path, body["gate"], body.get("installed", True), body["table"])
                          for path, body in self.posts], [("/server/mini/egress", None, True, 1)])

    def test_a_machine_with_no_gate_says_so_once_until_the_hub_takes_it(self):
        """With no rules file (`--egress off`, or no root step), the hub forgets the gate's state once, and then the
        service asks the gate nothing."""
        os.unlink(self.rules)
        self.hub_status = 0                     # the hub does not answer: it is said again
        server.Service.egress_round(self.svc)
        self.hub_status = 200
        server.Service.egress_round(self.svc)
        server.Service.egress_round(self.svc)
        self.assertEqual([body.get("installed") for _, body in self.posts], [False, False])
        self.assertEqual(self.asked, [])


if __name__ == "__main__":
    unittest.main()
