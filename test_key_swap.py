"""The key swap (VAULT.md): an API key that an agent reads stays out of its sessions. The session holds a placeholder,
and the vault's swap proxy puts the real key into the Authorization header of an HTTPS request to the key's own site.

Five parts. The proxy's reading of a request head. A real proxy in this process, with a local HTTPS site, real
certificates that the openssl program makes, and stand-ins for the kernel's table of sockets and for the broker. The
broker's part, with the in-process hub of the vault tests: the placeholder, the question at each use, and the end of a
grant. The hub's rule and routes. The helper's variables and the installer's step. The hub's take-back and delivery
of a value on a machine that swaps keys, with the pieces of the central vault's end-to-end test. Made-up keys and
example hosts only; nothing here touches this computer's own vault, and no test leaves a folder or a server.

What no test here proves is in test_key_swap_e2e.py (the two OS users, the kernel's table, real clients) and on the
first server (the units under systemd)."""
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from unittest.mock import patch

import fleet
import hub
import hubsetup
import leftovers
import lifecycle
import owner_mcp
import test_central_e2e
import test_grants
import test_vault
import vault

HOST, OTHER_HOST = "api.example.com", "files.example.com"
KEY = "sk-example-only-key-0123456789abcdef"                # made up: the "real" key of these tests
PLACE = "vaultswap_" + "a1" * 20
OPENSSL = shutil.which("openssl") or "/usr/bin/openssl"


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for case in (Reading, Rule, Proxy, Start, Installer, Helper):
        suite.addTests(loader.loadTestsFromTestCase(case))
    suite.addTests(Configuration(name) for name in Configuration.__dict__ if name.startswith("test_"))
    suite.addTests(BrokerPart(name) for name in BrokerPart.__dict__ if name.startswith("test_"))
    suite.addTests(HubRoutes(name) for name in HubRoutes.__dict__ if name.startswith("test_"))
    suite.addTests(Delivery(name) for name in Delivery.__dict__ if name.startswith("test_"))
    suite.addTests(Fact(name) for name in Fact.__dict__ if name.startswith("test_"))
    return suite


def head(*lines):
    return b"\r\n".join(x.encode() for x in lines)


def basic(text):
    return "Basic " + base64.b64encode(text.encode()).decode()


class Reading(unittest.TestCase):
    """The proxy's reading of one request head, with no socket."""

    def test_a_plain_request_head_is_read_and_written_again_from_its_parts(self):
        got = vault.swap_request(head("POST /v1/items?x=1 HTTP/1.1", "Host: " + HOST, "Authorization: Bearer " + PLACE,
                                      "Content-Type: application/json", "X-Empty:"), HOST, 443)
        self.assertEqual(got, (b"POST", b"/v1/items?x=1", [(b"Host", HOST.encode()),
                                                           (b"Authorization", ("Bearer " + PLACE).encode()),
                                                           (b"Content-Type", b"application/json"), (b"X-Empty", b"")]))
        port = vault.swap_request(head("GET / HTTP/1.1", f"Host: {HOST}:8443"), HOST, 8443)
        self.assertEqual(port[0], b"GET")

    def test_a_head_that_two_readers_can_read_in_two_ways_is_refused(self):
        good = ["GET /a HTTP/1.1", "Host: " + HOST, "Authorization: Bearer " + PLACE]
        for why, lines in (("a bare line feed", [good[0], good[1], "X-A: 1\nAuthorization: Bearer " + PLACE]),
                           ("a folded line", good[:2] + ["X-A: 1", " Authorization: Bearer " + PLACE]),
                           ("a space before the colon", good[:2] + ["Authorization : Bearer " + PLACE]),
                           ("a NUL", good[:2] + ["X-A: a\0b"]),
                           ("a control character in a value", good[:2] + ["X-A: a\x0bb"]),
                           ("no colon", good[:2] + ["Authorization Bearer"]),
                           ("HTTP/1.0", ["GET /a HTTP/1.0"] + good[1:]),
                           ("a full address", ["GET https://" + OTHER_HOST + "/a HTTP/1.1"] + good[1:]),
                           ("a small-letter method", ["get /a HTTP/1.1"] + good[1:]),
                           ("no Host", [good[0], good[2]]),
                           ("two Hosts", good + ["Host: " + OTHER_HOST]),
                           ("another Host", [good[0], "Host: " + OTHER_HOST, good[2]]),
                           ("the Host of another port", [good[0], f"Host: {HOST}:8443", good[2]])):
            with self.subTest(why):
                self.assertIsInstance(vault.swap_request(head(*lines), HOST, 443), str)
        many = [good[0], good[1]] + [f"X-{i}: 1" for i in range(vault.SWAP_HEADERS)]
        self.assertIsInstance(vault.swap_request(head(*many), HOST, 443), str)

    def found(self, *headers, target=b"/"):
        return vault.swap_found(target, [(n.encode(), v.encode()) for n, v in headers])

    def test_a_key_goes_into_the_authorization_header_only_and_as_the_whole_credential(self):
        for value, form in (("Bearer " + PLACE, "bearer"), ("bearer " + PLACE, "bearer"), ("BEARER " + PLACE, "bearer"),
                            ("token " + PLACE, "token"), ("Token " + PLACE, "token"),
                            (basic(PLACE + ":"), "basic-user"), (basic(PLACE + ":x:y"), "basic-user"),
                            (basic("user:" + PLACE), "basic-password"), (basic(":" + PLACE), "basic-password")):
            with self.subTest(value=value):
                self.assertEqual(self.found(("Host", HOST), ("authorization", value)), (PLACE, form, False))
        self.assertEqual(self.found(("Host", HOST), ("Authorization", "Bearer some-other-token")), (None, None, False))
        self.assertEqual(self.found(("Host", HOST)), (None, None, False))

    def test_a_placeholder_in_each_other_place_or_form_is_no_place_for_a_key(self):
        other = "vaultswap_" + "b2" * 20
        for why, headers, target in (
                ("another header", [("X-Api-Key", PLACE)], b"/"),
                ("a header that a site gives back", [("Idempotency-Key", PLACE)], b"/"),
                ("a header name", [(PLACE, "1")], b"/"),
                ("the request line", [("Authorization", "Bearer x")], ("/?key=" + PLACE).encode()),
                ("text after it", [("Authorization", "Bearer " + PLACE + "x")], b"/"),
                ("text before it", [("Authorization", "Bearer x" + PLACE)], b"/"),
                ("two spaces", [("Authorization", "Bearer  " + PLACE)], b"/"),
                ("no scheme word", [("Authorization", PLACE)], b"/"),
                ("another scheme word", [("Authorization", "Splunk " + PLACE)], b"/"),
                ("two of them", [("Authorization", f"Bearer {PLACE} {other}")], b"/"),
                ("Basic with two of them", [("Authorization", basic(f"{PLACE}:{other}"))], b"/"),
                ("Basic with text beside it", [("Authorization", basic(f"user:x{PLACE}"))], b"/"),
                ("Basic with no colon", [("Authorization", basic(PLACE))], b"/"),
                ("Basic with a colon in the user", [("Authorization", basic(f"a:b:{PLACE}"))], b"/"),
                ("a second Authorization header", [("Authorization", "Bearer " + PLACE), ("Authorization", "Bearer x")], b"/"),
                ("two Authorization headers with one each", [("Authorization", "Bearer " + PLACE),
                                                             ("authorization", "token " + other)], b"/")):
            with self.subTest(why):
                name, form, elsewhere = self.found(("Host", HOST), *headers, target=target)
                self.assertTrue(elsewhere)

    def test_the_value_takes_the_place_of_the_placeholder_in_the_form_that_was_found(self):
        put = lambda value: dict(vault.swap_put([(b"Authorization", value.encode()), (b"X-A", b"1")], PLACE, KEY))
        self.assertEqual(put("Bearer " + PLACE), {b"Authorization": ("Bearer " + KEY).encode(), b"X-A": b"1"})
        self.assertEqual(put("token " + PLACE)[b"Authorization"], ("token " + KEY).encode())
        self.assertEqual(put(basic(PLACE + ":"))[b"Authorization"], basic(KEY + ":").encode())
        self.assertEqual(put(basic("user:" + PLACE))[b"Authorization"], basic("user:" + KEY).encode())

    def test_a_site_is_an_https_address_with_a_dns_name(self):
        self.assertEqual(vault.swap_site("https://API.Example.com/v1/x"), (HOST, 443))
        self.assertEqual(vault.swap_site("https://api.example.com.:8443"), (HOST, 8443))
        for bad in ("http://api.example.com", "https://203.0.113.7", "https://[2001:db8::1]", "https://user@api.example.com",
                    "https://bücher.example", "https://" + "a" * 250 + ".example", "api.example.com", "", None, 7):
            with self.subTest(bad=bad):
                self.assertIsNone(vault.swap_site(bad))
        self.assertEqual((vault.swap_origin(HOST, 443), vault.swap_origin(HOST, 8443)), (HOST, HOST + ":8443"))
        # one written form for the hub and the vault: what the hub names is what the vault asks back
        self.assertEqual(lifecycle.key_site("https://API.example.com:443/v1"), "https://" + HOST)
        self.assertEqual(lifecycle.key_site("https://api.example.com:8443"), f"https://{HOST}:8443")
        self.assertEqual(vault.swap_site(lifecycle.key_site("https://api.example.com:8443/x")), (HOST, 8443))
        self.assertEqual(lifecycle.KEY_FORMS, vault.SWAP_FORMS)

    def test_the_user_of_a_connection_is_the_row_with_exactly_its_addresses_and_ports(self):
        """The kernel's table of sockets: only the row of this connection's other end names its user."""
        def four(ip):
            return "%08X" % int.from_bytes(socket.inet_aton(ip), sys.byteorder)

        def row(local, local_port, remote, remote_port, uid, mapped=False):
            lead = "0000000000000000" + ("FFFF0000" if sys.byteorder == "little" else "0000FFFF") if mapped else ""
            return (f"   0: {lead}{four(local)}:{local_port:04X} {lead}{four(remote)}:{remote_port:04X} 01 "
                    f"00000000:00000000 00:00000000 00000000  {uid}        0 12345 1 0000000000000000 20 4 30 10 -1\n")

        class Conn:
            def getpeername(self):
                return ("127.0.0.1", 40000)

            def getsockname(self):
                return ("127.0.0.1", 876)
        folder = Path(tempfile.mkdtemp(prefix="fleet-key-swap-table-"))
        self.addCleanup(shutil.rmtree, folder, True)
        v4, v6 = folder / "tcp", folder / "tcp6"
        top = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        near = (row("127.0.0.1", 40001, "127.0.0.1", 876, 2001) + row("127.0.0.1", 40000, "127.0.0.1", 877, 2002)
                + row("127.0.0.2", 40000, "127.0.0.1", 876, 2003) + row("127.0.0.1", 876, "127.0.0.1", 40000, 990))
        self.assertEqual(vault.SWAP_TABLES, (("/proc/net/tcp", False), ("/proc/net/tcp6", True)))
        with patch.object(vault, "SWAP_TABLES", ((str(v4), False), (str(v6), True))):
            v4.write_text(top + near)
            v6.write_text(top)
            self.assertIsNone(vault.swap_peer(Conn()))          # other ports, another address, and the proxy's own end
            v4.write_text(top + near + row("127.0.0.1", 40000, "127.0.0.1", 876, 2004))
            self.assertEqual(vault.swap_peer(Conn()), 2004)
            v4.write_text(top + near)
            v6.write_text(top + row("127.0.0.1", 40001, "127.0.0.1", 876, 2006, mapped=True)
                          + row("127.0.0.1", 40000, "127.0.0.1", 876, 2005, mapped=True))
            self.assertEqual(vault.swap_peer(Conn()), 2005)     # a program with one socket for both IP versions
            v4.unlink()
            v6.unlink()
            self.assertIsNone(vault.swap_peer(Conn()))          # a machine with no such table

    def test_call_api_is_no_second_road_for_a_key_that_swaps(self):
        """On a machine that swaps keys, the broker sends a key that the hub names with a site only as the proxy
        does: to that site, in the Authorization header, in the key's own form."""
        swaps, plain = {"_swap": {}}, {}
        item = {"url": "https://api.example.com/v1", "password": KEY, "username": "AC123"}
        named = {"site": "https://" + HOST, "form": "bearer"}

        def may(conf, confirmed, auth, login=item):
            return vault.swap_call(conf, confirmed, {"auth": auth}, login)
        self.assertTrue(may(swaps, named, "bearer"))
        self.assertTrue(may(swaps, dict(named, form="basic-password"), "basic"))
        for why, confirmed, auth, login in (
                ("a header of the agent's choice", named, "header:X-Request-Id", item),
                ("basic for a bearer key", named, "basic", item),
                ("bearer for a basic key", dict(named, form="basic-password"), "bearer", item),
                ("a form that only the proxy sends", dict(named, form="token"), "bearer", item),
                ("the key as the user name", dict(named, form="basic-user"), "basic", item),
                ("the saved item's other address", named, "bearer", dict(item, url="https://files.example.com")),
                ("another port", named, "bearer", dict(item, url="https://api.example.com:8443")),
                ("plain HTTP", named, "bearer", dict(item, url="http://api.example.com")),
                ("an item with no address", named, "bearer", {"password": KEY}),
                ("a site that is none", dict(named, site="https://203.0.113.7"), "bearer", item)):
            with self.subTest(why):
                self.assertFalse(may(swaps, confirmed, auth, login))
        self.assertTrue(may(plain, named, "header:X-Request-Id"))          # a machine that does not swap: as before
        self.assertTrue(may(swaps, {}, "header:X-Api-Key"))                # a key with no site: as before

    def test_the_configuration_takes_the_part_swap_in_its_form_and_no_other(self):
        part = {"user": "founderizer-swap", "vault": "fleet-vault", "port": 876, "openssl": "/usr/bin/openssl"}
        self.assertTrue(vault.swap_shape(part))
        for bad in (dict(part, port="876"), dict(part, port=0), dict(part, port=True), dict(part, openssl="openssl"),
                    dict(part, extra=1), {k: v for k, v in part.items() if k != "vault"}, dict(part, user=""), [], None):
            with self.subTest(bad=bad):
                self.assertFalse(vault.swap_shape(bad))

    def test_the_proxys_unit_has_its_own_user_and_a_restart_of_the_broker_does_not_touch_it(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(vault.main(["unit", "--swap", "--config", "/etc/fleet-vault/vault.json"]), 0)
        unit = out.getvalue()
        for line in ("User=founderizer-swap", "Group=founderizer-swap", "After=network-online.target fleet-vault.service",
                     "NotifyAccess=all",        # the process that takes over tells systemd that it is the main one
                     "AmbientCapabilities=CAP_NET_BIND_SERVICE", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
                     "StateDirectoryMode=0700", "RuntimeDirectoryPreserve=yes", "NoNewPrivileges=yes", "Restart=always",
                     " swap --config /etc/fleet-vault/vault.json"):
            self.assertIn(line, unit)
        for absent in ("ProtectProc", "ProcSubset", "RestrictAddressFamilies", "Group=fleet-agents"):
            self.assertNotIn(absent, unit)             # it reads /proc/net/tcp, and it is no agent user
        for absent in ("PartOf=", "BindsTo=", "Type="):
            self.assertNotIn(absent, unit)             # a restart of the broker would cut each open connection
        for bad in (["--user", "fleet-swap"], ["--group", "fleet-agents"], ["--central"]):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                vault.main(["unit", "--swap", "--config", "/etc/fleet-vault/vault.json"] + bad)


class Configuration(test_vault.BrokerConfiguration):
    """The broker's configuration with the part "swap": load_config checks its form, and the machine's facts are read
    at each start, by the broker and by the proxy."""
    PART = {"user": "founderizer-swap", "vault": "fleet-vault", "port": 876, "openssl": "/usr/bin/openssl"}

    def test_a_configuration_with_the_part_loads_and_one_with_a_wrong_part_stops_the_broker(self):
        self.assertEqual(self.load(swap=self.PART)["swap"], self.PART)
        self.assertNotIn("swap", self.load())                               # and without it, as before
        for bad in (dict(self.PART, port="876"), dict(self.PART, more=1), {"user": "founderizer-swap"}, True, None):
            with self.subTest(bad=bad), self.assertRaisesRegex(SystemExit, "swap must be the key swap of this machine"):
                self.load(swap=bad)
        with self.assertRaisesRegex(SystemExit, "needs exactly"):           # each other key that nobody knows, as before
            self.load(swop=self.PART)

    def test_the_central_vault_takes_no_such_part(self):
        central = {"central": True, "hub_uid": os.getuid() + 1, "fleet": "0123456789abcdef", "owner_keys": [],
                   "age": str(self.dir / "age"), "age_key": "/var/lib/c/age.key", "store": "/var/lib/c/store.age",
                   "store_key": "/var/lib/c/store.key", "socket": "/run/c/vault.sock", "state": "/var/lib/c/state.json",
                   "swap": self.PART}
        path = self.dir / "central.json"
        path.write_text(json.dumps(central))
        path.chmod(0o644)
        with self.assertRaisesRegex(SystemExit, "A central vault's configuration needs exactly"):
            vault.load_config(str(path))

    def facts(self, conf, users, groups):
        def user(name):
            if name not in users:
                raise KeyError(name)
            return type("U", (), {"pw_uid": users[name][0], "pw_gid": users[name][1], "pw_name": name})()

        def group(name):
            if name not in groups:
                raise KeyError(name)
            return type("G", (), {"gr_gid": groups[name][0], "gr_mem": groups[name][1]})()
        with patch.object(vault.pwd, "getpwnam", user), patch.object(vault.grp, "getgrnam", group), \
                patch.object(vault, "unchangeable", lambda path, what: None):
            return vault.swap_part(conf)

    def test_the_machines_facts_of_the_part_are_read_at_each_start(self):
        conf = dict(self.conf, worker_group="fleet-agents", swap=self.PART)
        users = {"founderizer-swap": (990, 990), "fleet-vault": (991, 991)}
        groups = {"fleet-agents": (1500, ["fleet-dev-lead"])}
        part = self.facts(conf, users, groups)
        self.assertEqual((part["uid"], part["vault_uid"], part["group"], part["broker"]),
                         (990, 991, "fleet-agents", "/run/fleet-vault/swap.sock"))
        for why, u, g, c in (("no proxy user", {"fleet-vault": (991, 991)}, groups, conf),
                             ("no vault user", {"founderizer-swap": (990, 990)}, groups, conf),
                             ("no group", users, {}, conf),
                             ("no worker_group", users, groups, {k: v for k, v in conf.items() if k != "worker_group"}),
                             ("root", dict(users, **{"founderizer-swap": (0, 0)}), groups, conf),
                             ("the vault's own user", dict(users, **{"founderizer-swap": (991, 991)}), groups, conf),
                             ("a member of the agents' group", users, {"fleet-agents": (1500, ["founderizer-swap"])}, conf),
                             ("the agents' group as its own", dict(users, **{"founderizer-swap": (990, 1500)}), groups, conf)):
            with self.subTest(why), self.assertRaises(vault.Refused):
                self.facts(c, u, g)
        open_to_all = self.dir / "openssl"                                  # an openssl that an agent can change
        open_to_all.write_text("#!/bin/sh\n")
        open_to_all.chmod(0o777)
        for why, program, words in (("a program that others can write", open_to_all, "The openssl program must be owned by root"),
                                    ("no such program", self.dir / "no-such-openssl", "No such file")):
            with self.subTest(why), \
                    patch.object(vault.pwd, "getpwnam", lambda name: type("U", (), {"pw_uid": users[name][0], "pw_gid": users[name][1], "pw_name": name})()), \
                    patch.object(vault.grp, "getgrnam", lambda name: type("G", (), {"gr_gid": 1500, "gr_mem": []})()), \
                    self.assertRaisesRegex(vault.Refused, words):
                vault.swap_part(dict(conf, swap=dict(self.PART, openssl=str(program))))


class Rule(unittest.TestCase):
    """Which key can swap: the hub's rule, from the owner's settings only."""
    REF = "bws://11111111-2222-4333-8444-555555555551"

    def team(self, **changes):
        team = {"agents": {"dev-lead": {"role": "worker", "runtime": "claude", "machine": "app-1", "can": ["shell"],
                                        "secrets": {self.REF: "read"}}},
                "logins": {self.REF: {"title": "SHOP_API_KEY", "kind": "api_key", "env": "SHOP_API_KEY",
                                      "site": "https://api.example.com/v1"}}}
        for path, value in changes.items():
            where, keys = team, path.split("__")
            for key in keys[:-1]:
                where = where.setdefault(self.REF if key == "REF" else key, {})
            where[self.REF if keys[-1] == "REF" else keys[-1]] = value
        return team

    def test_a_read_key_with_a_site_swaps_for_a_proved_program(self):
        self.assertEqual(lifecycle.key_swap(self.team(), "dev-lead", self.REF), ("https://" + HOST, "bearer"))
        self.assertEqual(lifecycle.key_swap(self.team(logins__REF__form="basic-user"), "dev-lead", self.REF),
                         ("https://" + HOST, "basic-user"))
        self.assertEqual(lifecycle.key_swap(self.team(**{"agents__dev-lead__runtime": "codex"}), "dev-lead", self.REF),
                         ("https://" + HOST, "bearer"))

    def test_each_part_of_the_rule_is_needed(self):
        for why, team in (
                ("a use grant", self.team(**{"agents__dev-lead__secrets": {self.REF: "use"}})),
                ("no grant", self.team(**{"agents__dev-lead__secrets": {}})),
                ("no site", self.team(logins__REF={"title": "SHOP_API_KEY", "kind": "api_key", "env": "SHOP_API_KEY"})),
                ("an http site", self.team(logins__REF__site="http://api.example.com")),
                ("a site that is an IP address", self.team(logins__REF__site="https://203.0.113.7")),
                ("a login", self.team(logins__REF__kind="login")),
                ("a form that is none", self.team(logins__REF__form="header")),
                ("a program that nobody proved", self.team(**{"agents__dev-lead__runtime": "grok"})),
                ("a program of the ACP runner", self.team(**{"agents__dev-lead__runtime": "opencode"})),
                ("no program", self.team(**{"agents__dev-lead__runtime": None})),
                ("a site of the program's own provider", self.team(logins__REF__site="https://api.anthropic.com")),
                ("the provider's own name", self.team(logins__REF__site="https://claude.ai")),
                ("the key of a model account", self.team(accounts={"main": {"kind": "key", "provider": "xai",
                                                                            "secret": self.REF}})),
                ("the key of an MCP server", self.team(mcp={"crm": {"title": "CRM", "url": "https://api.example.com/mcp",
                                                                    "auth": "key", "key": "SHOP_API_KEY"}})),
                ("a variable of an MCP program", self.team(mcp={"crm": {"title": "CRM", "command": "crm-mcp",
                                                                        "env": {"CRM_TOKEN": "SHOP_API_KEY"}}}))):
            with self.subTest(why):
                self.assertIsNone(lifecycle.key_swap(team, "dev-lead", self.REF))
        self.assertIsNone(lifecycle.key_swap(self.team(), "another", self.REF))
        self.assertIsNone(lifecycle.key_swap({}, "dev-lead", self.REF))
        self.assertIsNone(lifecycle.key_swap(None, "dev-lead", self.REF))

    def test_a_site_that_only_looks_like_the_providers_host_swaps(self):
        for site in ("https://api.openai.com", "https://notanthropic.com", "https://anthropic.com.example.com"):
            with self.subTest(site=site):
                self.assertEqual(lifecycle.key_swap(self.team(logins__REF__site=site), "dev-lead", self.REF),
                                 (site, "bearer"))          # a Claude Code agent: its own hosts are Anthropic's

    def test_only_a_proved_program_has_its_own_hosts(self):
        self.assertEqual({name: bool(entry["own_hosts"]) for name, entry in lifecycle.RUNTIMES.items()},
                         {"claude": True, "codex": True, "grok": False, "opencode": False})

    def test_the_variables_keep_the_programs_own_calls_out_of_the_proxy(self):
        env = lifecycle.key_swap_env("http://127.0.0.1:876", "/home/a/.fleet/key-swap-ca.pem",
                                     "/home/a/.fleet/key-swap-sites.pem", ("anthropic.com", "claude.ai"), "100.80.1.2")
        self.assertEqual(env["HTTPS_PROXY"], env["https_proxy"])
        self.assertEqual(env["NO_PROXY"], env["no_proxy"])
        self.assertEqual(env["NO_PROXY"].split(","), ["localhost", "127.0.0.1", "::1", ".localhost", "100.80.1.2",
                                                      "anthropic.com", ".anthropic.com", "claude.ai", ".claude.ai"])
        self.assertEqual({env[k] for k in ("SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO")},
                         {"/home/a/.fleet/key-swap-ca.pem"})
        self.assertEqual((env["NODE_EXTRA_CA_CERTS"], env["NODE_USE_ENV_PROXY"]), ("/home/a/.fleet/key-swap-sites.pem", "1"))
        self.assertNotIn("HTTP_PROXY", env)            # plain HTTP, the hub's own, never goes to the proxy
        self.assertFalse([name for name in env if lifecycle.ENV_RESERVED.fullmatch(name)])


class Site(threading.Thread):
    """A local HTTPS site that keeps what it got: each request's first line and its headers. contexts: the TLS context
    for each host name that a client asks for. only: one context for each client, whatever it asks for. hold: an
    Event that a test sets, and the site then answers a request that it got only after it."""
    def __init__(self, contexts, only=None):
        super().__init__(daemon=True)
        self.contexts, self.only, self.got, self.hold = contexts, only, [], None
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]

    def run(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.one, args=(conn,), daemon=True).start()

    def one(self, conn):
        try:
            conn.settimeout(10)
            base = self.only
            if base is None:
                base = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                base.sni_callback = lambda sock, name, _: setattr(sock, "context", self.contexts[name])
            with base.wrap_socket(conn, server_side=True) as tls:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = tls.recv(65536)
                    if not chunk:
                        return
                    data += chunk
                top, _, rest = data.partition(b"\r\n\r\n")
                lines = top.decode("latin-1").split("\r\n")
                headers = dict(line.split(": ", 1) for line in lines[1:])
                length = int(headers.get("Content-Length", 0))
                while len(rest) < length:
                    rest += tls.recv(65536)
                self.got.append({"line": lines[0], "headers": headers, "lines": lines[1:], "body": rest.decode("latin-1")})
                hold = self.hold
                if hold is not None:
                    hold.wait(20)
                body = b"it works\n"
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
        except (OSError, ssl.SSLError, KeyError):
            pass
        finally:
            conn.close()

    def close(self):
        self.sock.close()


class Proxy(unittest.TestCase):
    """A real swap proxy in this process. The site's certificates come from a second SwapAuthority, as the "public"
    CAs of this test; the proxy's own come from its own. The broker is `self.said`, and the kernel's table says that
    each connection is this test's own user."""

    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp(prefix="fleet-key-swap-"))
        leftovers.removed_when_gone(str(cls.dir))                # a test process that is killed removes it too
        for name in ("state", "public", "world", "world-public"):
            (cls.dir / name).mkdir(mode=0o700)
        cls.world = vault.SwapAuthority(str(cls.dir / "world"), str(cls.dir / "world-public"), OPENSSL)
        cls.site = Site({host: cls.world.context(host) for host in (HOST, OTHER_HOST)})
        cls.site.start()
        cls.authority = vault.SwapAuthority(str(cls.dir / "state"), str(cls.dir / "public"), OPENSSL)

    @classmethod
    def tearDownClass(cls):
        cls.site.close()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def setUp(self):
        self.site.got.clear()
        self.asked, self.sites, self.answer = [], {(HOST, 443)}, {"ok": True, "value": KEY}
        upstream = ssl.create_default_context(cafile=str(self.dir / "world-public" / (HOST + ".pem")))
        upstream.load_verify_locations(str(self.dir / "world-public" / (OTHER_HOST + ".pem")))
        upstream.verify_flags |= ssl.VERIFY_X509_STRICT
        patched = patch.object(vault.SwapProxy, "agent_user", lambda proxy, uid: uid == os.getuid())
        patched.start()
        self.addCleanup(patched.stop)
        quiet = patch.object(vault, "log", lambda text: self.logged.append(text))
        self.logged = []
        quiet.start()
        self.addCleanup(quiet.stop)
        self.proxy = vault.SwapProxy({"port": 0, "group": "fleet-agents"}, self.authority, ask=self.ask, site=upstream,
                                     peer=lambda conn: self.uid, reach=self.reach, port=0)
        self.uid = os.getuid()
        threading.Thread(target=self.proxy.serve, daemon=True).start()
        self.addCleanup(self.proxy.close)

    def ask(self, request):
        self.asked.append(request)
        if request["op"] == "site":
            return {"ok": True, "site": (request["host"], request["port"]) in self.sites}
        return self.answer

    def reach(self, host, port):
        """Each example host is this test's own local site."""
        if host not in (HOST, OTHER_HOST):
            return None
        return socket.create_connection(("127.0.0.1", self.site.port), timeout=10)

    def connect(self, host=HOST, port=443):
        s = socket.create_connection(("127.0.0.1", self.proxy.port), timeout=10)
        s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        first = b""
        while b"\r\n\r\n" not in first:
            try:
                chunk = s.recv(4096)
            except OSError:             # the proxy closed the connection with no answer
                break
            if not chunk:
                break
            first += chunk
        return s, first

    def request(self, raw, host=HOST, trust="public"):
        """One request through the proxy as a client that trusts the CA of `host` in the folder `trust`: (the status
        line, the headers, the body)."""
        s, first = self.connect(host)
        self.assertTrue(first.startswith(b"HTTP/1.1 200"), first)
        context = ssl.create_default_context(cafile=str(self.dir / trust / (host + ".pem")))
        context.verify_flags |= ssl.VERIFY_X509_STRICT          # as the default of Python 3.13 and later
        with context.wrap_socket(s, server_hostname=host) as tls:
            tls.sendall(raw)
            data = b""
            while True:
                try:
                    chunk = tls.recv(65536)
                except (ssl.SSLError, OSError):
                    break
                if not chunk:
                    break
                data += chunk
        top, _, body = data.partition(b"\r\n\r\n")
        lines = top.decode("latin-1").split("\r\n")
        return lines[0], dict(line.split(": ", 1) for line in lines[1:] if ": " in line), body.decode("latin-1")

    def get(self, *headers, target="/v1/charges", host=HOST, method="GET", body=""):
        lines = [f"{method} {target} HTTP/1.1", "Host: " + host, *headers]
        if body:
            lines.append(f"Content-Length: {len(body)}")
        return self.request(head(*lines) + b"\r\n\r\n" + body.encode(), host)

    def swaps(self):
        return [r for r in self.asked if r["op"] == "swap"]

    def test_the_key_reaches_its_site_in_the_authorization_header_and_the_client_never_holds_it(self):
        status, headers, body = self.get("Authorization: Bearer " + PLACE, "User-Agent: example/1", method="POST",
                                         body='{"amount": 5}')
        self.assertEqual((status, body), ("HTTP/1.1 200 OK", "it works\n"))
        got = self.site.got[-1]
        self.assertEqual(got["line"], "POST /v1/charges HTTP/1.1")
        self.assertEqual(got["headers"]["Authorization"], "Bearer " + KEY)
        self.assertEqual((got["headers"]["Host"], got["headers"]["User-Agent"], got["body"]), (HOST, "example/1", '{"amount": 5}'))
        self.assertEqual(got["headers"]["Connection"], "close")            # one request for each connection
        self.assertEqual(self.swaps(), [{"op": "swap", "uid": os.getuid(), "host": HOST, "port": 443, "name": PLACE,
                                         "form": "bearer"}])
        self.assertNotIn(KEY, " ".join(self.logged))                       # no value in the proxy's log
        self.assertNotIn(PLACE, " ".join(self.logged))
        self.assertTrue(any("the key of one placeholder" in line for line in self.logged))

    def test_each_form_of_a_key_is_named_to_the_broker_and_put_back_in_that_form(self):
        for value, form, wanted in (("token " + PLACE, "token", "token " + KEY),
                                    (basic(PLACE + ":"), "basic-user", basic(KEY + ":")),
                                    (basic("AC123:" + PLACE), "basic-password", basic("AC123:" + KEY))):
            with self.subTest(form=form):
                self.asked.clear()
                self.assertEqual(self.get("Authorization: " + value)[0], "HTTP/1.1 200 OK")
                self.assertEqual(self.swaps()[0]["form"], form)
                self.assertEqual(self.site.got[-1]["headers"]["Authorization"], wanted)

    def test_without_a_context_of_its_own_the_proxy_checks_the_site_against_the_systems_cas(self):
        """The site of these tests has a certificate that no CA of this machine signed: it gets no key."""
        strict = vault.SwapProxy({"port": 0, "group": "fleet-agents"}, self.authority, ask=self.ask,
                                 peer=lambda conn: os.getuid(), reach=self.reach, port=0)
        self.addCleanup(strict.close)
        self.assertEqual((strict.site.verify_mode, strict.site.check_hostname), (ssl.CERT_REQUIRED, True))
        threading.Thread(target=strict.serve, daemon=True).start()
        self.proxy = strict
        status, headers, body = self.get("Authorization: Bearer " + PLACE)
        self.assertEqual(status, "HTTP/1.1 502 Bad Gateway")
        self.assertIn("a certificate that is the site's own", json.loads(body)["error"])
        self.assertEqual(self.site.got, [])

    def test_no_upgrade_and_no_header_for_a_proxy_reaches_a_keys_site(self):
        status, _, _ = self.get("Authorization: Bearer " + PLACE, "Upgrade: websocket", "Connection: Upgrade, keep-alive",
                                "Keep-Alive: timeout=5", "Proxy-Authorization: Basic eDp5", "Proxy-Connection: keep-alive")
        self.assertEqual(status, "HTTP/1.1 200 OK")
        got = self.site.got[-1]
        self.assertEqual(sorted(got["lines"]), ["Authorization: Bearer " + KEY, "Connection: close", "Host: " + HOST])

    def test_the_proxy_reads_its_own_user_from_a_connection_on_this_machine(self):
        for peer, good in ((lambda conn: os.getuid(), True), (lambda conn: os.getuid() + 1, False), (lambda conn: None, False)):
            with self.subTest(good=good):
                proxy = vault.SwapProxy({"port": 0, "group": "fleet-agents"}, self.authority, ask=self.ask, peer=peer, port=0)
                self.addCleanup(proxy.close)
                self.assertIs(proxy.reads_users(), good)

    def test_a_request_with_no_placeholder_passes_with_no_question_for_a_key(self):
        self.assertEqual(self.get("Authorization: Bearer my-own-token")[0], "HTTP/1.1 200 OK")
        self.assertEqual(self.site.got[-1]["headers"]["Authorization"], "Bearer my-own-token")
        self.assertEqual(self.swaps(), [])

    def test_another_host_is_a_tunnel_that_the_proxy_does_not_read(self):
        """The client sees the site's own certificate, not one of the proxy's, and the site gets the placeholder."""
        status, _, body = self.request(head("GET /x HTTP/1.1", "Host: " + OTHER_HOST, "Authorization: Bearer " + PLACE,
                                            "X-Odd : folded is the site's own affair") + b"\r\n\r\n",
                                       host=OTHER_HOST, trust="world-public")
        self.assertEqual((status, body), ("HTTP/1.1 200 OK", "it works\n"))
        self.assertEqual(self.site.got[-1]["headers"]["Authorization"], "Bearer " + PLACE)
        self.assertEqual(self.swaps(), [])
        self.assertFalse((self.dir / "public" / (OTHER_HOST + ".pem")).exists())      # no CA for a host that is no site
        self.assertEqual(self.logged, [])                                              # and no line about a tunnel

    def test_a_placeholder_where_no_key_goes_is_refused_and_nothing_is_sent(self):
        for why, headers, target in (("another header", ["X-Api-Key: " + PLACE], "/"),
                                     ("text beside it", ["Authorization: Bearer " + PLACE + "-x"], "/"),
                                     ("the address", ["Authorization: Bearer x"], "/?key=" + PLACE),
                                     ("two Authorization headers", ["Authorization: Bearer " + PLACE,
                                                                    "Authorization: Bearer x"], "/")):
            with self.subTest(why):
                status, headers, body = self.get(*headers, target=target)
                self.assertEqual(status, "HTTP/1.1 400 Bad Request")
                self.assertEqual(headers["X-Founderizer-Vault"], "key-swap")
                self.assertIn("Nothing was sent", json.loads(body)["error"])
        self.assertEqual((self.site.got, self.swaps()), ([], []))

    def test_no_key_goes_into_a_request_that_a_server_sends_back(self):
        """A server answers TRACE with the request that it got, the Authorization header too."""
        for method in ("TRACE", "TRACK"):
            with self.subTest(method=method):
                status, headers, body = self.get("Authorization: Bearer " + PLACE, method=method)
                self.assertEqual(status, "HTTP/1.1 400 Bad Request")
                self.assertIn(f"sends a {method} request back", json.loads(body)["error"])
        self.assertEqual((self.site.got, self.swaps()), ([], []))
        self.assertEqual(self.get("Authorization: Bearer my-own-token", method="TRACE")[0], "HTTP/1.1 200 OK")
        self.assertEqual(self.site.got[-1]["line"], "TRACE /v1/charges HTTP/1.1")      # with no placeholder: the client's own

    def test_one_user_has_a_few_questions_for_a_key_open_at_one_time(self):
        with patch.object(vault, "SWAP_ASKS", 0):
            status, headers, body = self.get("Authorization: Bearer " + PLACE)
        self.assertEqual(status, "HTTP/1.1 503 Service Unavailable")
        self.assertIn("too many", json.loads(body)["error"])
        self.assertEqual((self.site.got, self.swaps()), ([], []))
        self.assertEqual(self.get("Authorization: Bearer " + PLACE)[0], "HTTP/1.1 200 OK")
        self.assertEqual(self.proxy.asking, {})                             # each question gave its place back
        self.answer = None                                                  # also one that got no answer
        self.assertEqual(self.get("Authorization: Bearer " + PLACE)[0], "HTTP/1.1 503 Service Unavailable")
        self.assertEqual(self.proxy.asking, {})

    def test_a_head_that_is_not_read_strictly_is_refused_and_nothing_is_sent(self):
        status, headers, body = self.request(head("GET / HTTP/1.1", "Host: " + HOST, "X-A: 1",
                                                  " Authorization: Bearer " + PLACE) + b"\r\n\r\n")
        self.assertEqual(status, "HTTP/1.1 400 Bad Request")
        self.assertIn("a header line is not", json.loads(body)["error"])
        status = self.request(head("GET / HTTP/1.1", "Host: " + OTHER_HOST, "Authorization: Bearer " + PLACE) + b"\r\n\r\n")[0]
        self.assertEqual(status, "HTTP/1.1 400 Bad Request")               # the Host of another site
        self.assertEqual((self.site.got, self.swaps()), ([], []))

    def test_the_brokers_no_is_an_answer_of_the_proxy_and_nothing_is_sent(self):
        for answer, status, words in (({"ok": False, "code": "refused"}, "HTTP/1.1 403 Forbidden", "is not a key that this agent holds"),
                                      ({"ok": False, "code": "hub"}, "HTTP/1.1 503 Service Unavailable", "the hub did not confirm"),
                                      (None, "HTTP/1.1 503 Service Unavailable", "no answer from this machine's vault"),
                                      ({"ok": True, "value": "two\r\nlines"}, "HTTP/1.1 503 Service Unavailable", "no answer"),
                                      ({"ok": True, "value": ""}, "HTTP/1.1 503 Service Unavailable", "no answer"),
                                      ({"ok": True}, "HTTP/1.1 503 Service Unavailable", "no answer")):
            with self.subTest(answer=answer):
                self.answer = answer
                got, headers, body = self.get("Authorization: Bearer " + PLACE)
                self.assertEqual(got, status)
                self.assertIn(words, json.loads(body)["error"])
                self.assertEqual(headers["X-Founderizer-Vault"], "key-swap")
        self.assertEqual(self.site.got, [])

    def test_a_broker_that_gives_no_answer_at_the_connect_makes_a_tunnel(self):
        real = self.proxy.ask
        self.proxy.ask = lambda request: None
        self.addCleanup(setattr, self.proxy, "ask", real)
        status, _, _ = self.request(head("GET / HTTP/1.1", "Host: " + HOST, "Authorization: Bearer " + PLACE) + b"\r\n\r\n",
                                    trust="world-public")
        self.assertEqual(status, "HTTP/1.1 200 OK")
        self.assertEqual(self.site.got[-1]["headers"]["Authorization"], "Bearer " + PLACE)

    def test_only_connect_and_only_an_agent_user_of_this_machine(self):
        with socket.create_connection(("127.0.0.1", self.proxy.port), timeout=10) as s:
            s.sendall(b"GET http://api.example.com/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
            self.assertIn(b"405", s.recv(4096).split(b"\r\n")[0])
        s, first = self.connect("no-such-host.example")
        s.close()
        self.assertTrue(first.startswith(b"HTTP/1.1 502"), first)
        self.asked.clear()
        self.uid = os.getuid() + 1                                          # the kernel names another user
        s, first = self.connect()
        s.close()
        self.assertEqual(first, b"")
        self.uid = None                                                     # the kernel names none
        s, first = self.connect()
        s.close()
        self.assertEqual(first, b"")
        self.assertEqual(self.asked, [])

    def test_a_connect_with_no_tls_after_it_makes_the_sites_ca_and_asks_for_no_key(self):
        """What a session's start does for each of its sites (fleet.swap_variables)."""
        shown = self.dir / "public" / (HOST + ".pem")
        shown.unlink(missing_ok=True)
        self.authority.made.pop(HOST, None)
        s, first = self.connect()
        s.close()
        self.assertTrue(first.startswith(b"HTTP/1.1 200"))
        self.assertIn("-----BEGIN CERTIFICATE-----", shown.read_text())     # in place before the answer
        self.assertEqual(shown.stat().st_mode & 0o777, 0o644)
        self.assertEqual((self.swaps(), self.logged), ([], []))

    def test_each_users_connections_have_a_limit_and_the_next_one_is_told(self):
        with patch.object(vault, "SWAP_PER_USER", 2):
            held = [self.connect(OTHER_HOST) for _ in range(2)]
            s, first = self.connect(OTHER_HOST)
            s.close()
            self.assertTrue(first.startswith(b"HTTP/1.1 503"), first)
            for sock, _ in held:
                sock.close()

    def held_tunnel(self):
        """One tunnel through self.proxy to the other host, open and not used yet: its TLS socket."""
        s, first = self.connect(OTHER_HOST)
        self.assertTrue(first.startswith(b"HTTP/1.1 200"), first)
        context = ssl.create_default_context(cafile=str(self.dir / "world-public" / (OTHER_HOST + ".pem")))
        return context.wrap_socket(s, server_hostname=OTHER_HOST)

    def serving(self, proxy):
        """The thread of this proxy's serve."""
        thread = threading.Thread(target=proxy.serve, daemon=True)
        thread.start()
        return thread

    def second(self, old, **more):
        """A second proxy on the listener of `old`, as the process that takes over: (it, the questions that it asked)."""
        asked = []
        new = vault.SwapProxy({"port": 0, "group": "fleet-agents"}, self.authority,
                              ask=lambda request: asked.append(request) or self.ask(request),
                              site=old.site, peer=lambda conn: self.uid, reach=self.reach,
                              sock=socket.socket(fileno=os.dup(old.sock.fileno())), **more)
        self.addCleanup(new.close)
        self.assertEqual(new.port, old.port)                                # the same listener
        return new, asked

    def fresh(self, **more):
        """A proxy of this test's own, with its serve thread: (the proxy, the thread)."""
        proxy = vault.SwapProxy({"port": 0, "group": "fleet-agents"}, self.authority, ask=self.ask, site=self.proxy.site,
                                peer=lambda conn: self.uid, reach=self.reach, port=0, **more)
        self.addCleanup(proxy.close)
        return proxy, self.serving(proxy)

    def timed(self, grace=0.6, patience=30):
        for name, value in (("SWAP_GRACE", grace), ("SWAP_PATIENCE", patience)):
            patched = patch.object(vault, name, value)
            patched.start()
            self.addCleanup(patched.stop)

    def test_a_process_that_gave_way_takes_no_new_connection_and_ends_with_its_last_one(self):
        """The hand-over to a new program: two proxies on one listener, as the old process and the new one."""
        self.timed()
        old, served = self.fresh()
        self.proxy = old                                                    # the helpers of this class connect to it
        tunnel = self.held_tunnel()                                         # open in the old process
        self.addCleanup(tunnel.close)
        new, asked = self.second(old)
        self.serving(new)
        old.heir, old.ending = True, True                                   # the new process said that it serves
        for _ in range(60):
            if old.sock.fileno() < 0:
                break
            time.sleep(0.1)
        self.assertLess(old.sock.fileno(), 0)                               # the old one closed its copy of the listener
        self.asked.clear()
        self.assertEqual(self.get("Authorization: Bearer " + PLACE)[0], "HTTP/1.1 200 OK")
        self.assertTrue(asked)                                              # the new process served this one
        time.sleep(1.5)                                                     # longer than the grace
        self.assertTrue(served.is_alive())                                  # the old one lives on for its one connection
        tunnel.sendall(head("GET /held HTTP/1.1", "Host: " + OTHER_HOST) + b"\r\n\r\n")
        self.assertIn(b"it works", tunnel.recv(65536) + tunnel.recv(65536))  # the old tunnel still passes bytes
        tunnel.close()
        served.join(10)
        self.assertFalse(served.is_alive())                                 # its last connection ended: it ends
        self.assertEqual(old.conns, {})

    def test_a_process_with_no_connection_ends_after_the_grace_and_not_before(self):
        self.timed(grace=1.5)
        old, served = self.fresh()
        old.heir, old.ending = True, True
        time.sleep(1.2)                                                     # the accept loop saw it, the grace is not over
        self.assertTrue(served.is_alive())
        served.join(5)
        self.assertFalse(served.is_alive())

    def test_a_connection_that_came_in_the_last_second_is_kept_to_its_end(self):
        """The old process still accepts for one second after the word. Such a connection is its own to the end, also
        when an earlier one ended in between."""
        self.timed(grace=0.3)
        old, served = self.fresh()
        self.proxy = old
        first = self.held_tunnel()
        old.heir, old.ending = True, True
        late = self.held_tunnel()                                           # accepted in that last second
        self.addCleanup(late.close)
        first.close()
        time.sleep(2)
        self.assertTrue(served.is_alive())
        self.assertEqual(len(old.conns), 1)
        late.sendall(head("GET /late HTTP/1.1", "Host: " + OTHER_HOST) + b"\r\n\r\n")
        self.assertIn(b"it works", late.recv(65536) + late.recv(65536))
        late.close()
        served.join(10)
        self.assertFalse(served.is_alive())

    def test_the_old_program_does_no_new_work_for_a_connection_that_only_waits(self):
        """After the hand-over, a connection that did not start to pass bytes is closed, and a tunnel lives on."""
        self.timed(grace=0.3, patience=60)         # each connection's own time limit is long: it does not end by itself
        old, served = self.fresh()
        self.proxy = old
        tunnel = self.held_tunnel()
        self.addCleanup(tunnel.close)
        slow = socket.create_connection(("127.0.0.1", old.port), timeout=10)        # it never sends its CONNECT line
        self.addCleanup(slow.close)
        opened, first = self.connect()                                      # a key's site: the proxy waits for the TLS
        self.assertTrue(first.startswith(b"HTTP/1.1 200"))
        self.addCleanup(opened.close)
        raw, first = self.connect()                                         # a key's site: the TLS is made, no request yet
        context = ssl.create_default_context(cafile=str(self.dir / "public" / (HOST + ".pem")))
        secure = context.wrap_socket(raw, server_hostname=HOST)
        self.addCleanup(secure.close)
        for _ in range(50):
            if len(old.conns) == 4 and len(old.tls) == 2:
                break
            time.sleep(0.1)
        self.assertEqual((sorted(old.conns.values()), len(old.tls)), ([False, False, False, True], 2))
        with patch.object(vault, "SWAP_PATIENCE", 1.5):                     # the hand-over's own limit
            old.heir, old.ending = True, True
            for waiting in (slow, opened, secure):
                waiting.settimeout(8)
                try:
                    self.assertEqual(waiting.recv(16), b"")                 # each was closed by the old process
                except ssl.SSLError:
                    pass                                                    # a TLS connection that was cut says so
            self.assertTrue(served.is_alive())
        tunnel.sendall(head("GET /held HTTP/1.1", "Host: " + OTHER_HOST) + b"\r\n\r\n")
        self.assertIn(b"it works", tunnel.recv(65536) + tunnel.recv(65536))
        tunnel.close()
        served.join(10)
        self.assertFalse(served.is_alive())

    def test_a_request_to_a_keys_site_is_kept_across_the_hand_over_or_gets_no_key_at_all(self):
        """Two requests with a placeholder are in the old process at the hand-over. The site has the first one, and
        its answer comes later: the old process keeps that connection to its end. The second one waits for the
        broker's answer: the old process closes it, and when the answer then comes, nothing goes to the site."""
        self.timed(grace=0.3, patience=60)         # each connection's own time limit is long: it does not end by itself
        late, swaps, real = threading.Event(), [], self.ask

        def ask(request):
            said = real(request)
            if request["op"] == "swap":
                swaps.append(request)
                if len(swaps) == 2:
                    late.wait(20)                                           # the broker's answer to the second request
            return said
        self.ask = ask
        self.addCleanup(late.set)
        reached, reach = [], self.reach

        def counted(host, port):
            reached.append(host)
            return reach(host, port)
        self.reach = counted                                                # each connection that the proxy makes to a site
        old, served = self.fresh()
        self.proxy = old
        hold = self.site.hold = threading.Event()                           # the site's answer to the first request
        self.addCleanup(setattr, self.site, "hold", None)
        self.addCleanup(hold.set)
        answers = {}

        def asks(name):
            answers[name] = self.get("Authorization: Bearer " + PLACE, target="/v1/" + name, method="POST", body="{}")

        def until(test):
            for _ in range(100):
                if test():
                    return
                time.sleep(0.1)
            self.fail("it did not come")
        kept = threading.Thread(target=asks, args=("kept",), daemon=True)
        kept.start()
        until(lambda: len(self.site.got) == 1)                              # the site has it, and holds its answer
        cut = threading.Thread(target=asks, args=("cut",), daemon=True)
        cut.start()
        until(lambda: len(swaps) == 2)                                      # it waits for the broker
        self.assertEqual(sorted(old.conns.values()), [False, True])
        with patch.object(vault, "SWAP_PATIENCE", 1.5):                     # the hand-over's own limit
            old.heir, old.ending = True, True
            cut.join(10)
            self.assertFalse(cut.is_alive())
            self.assertEqual(answers["cut"], ("", {}, ""))                  # closed by the old process, with no answer
            time.sleep(1.2)                                                 # two more turns of the old process
            self.assertTrue(kept.is_alive())                                # the first one is not closed
            late.set()                                                      # now the broker gives the key
            until(lambda: len(old.conns) == 1)                              # the second connection's thread ended
            time.sleep(0.5)
            self.assertEqual([got["line"] for got in self.site.got], ["POST /v1/kept HTTP/1.1"])    # no request, no key
            self.assertEqual(reached, [HOST])                               # and no connection to the site for it
            self.assertEqual(sum("the key of one placeholder" in line for line in self.logged), 1)
            hold.set()
            kept.join(10)
        self.assertEqual((answers["kept"][0], answers["kept"][2]), ("HTTP/1.1 200 OK", "it works\n"))
        self.assertEqual(self.site.got[0]["headers"]["Authorization"], "Bearer " + KEY)
        served.join(10)
        self.assertFalse(served.is_alive())                                 # its last connection ended: it ends

    def test_when_the_process_that_took_over_ends_with_a_fault_the_old_one_ends_too(self):
        """The new main process is the old one's child, so systemd does not see its end while the old one lives."""
        self.timed(grace=30)

        class Heir:
            code = None

            def poll(self):
                return self.code
        old, served = self.fresh()
        failed = threading.Event()
        old.fails = failed.set
        old.heir, old.ending = Heir(), True
        time.sleep(2)
        self.assertFalse(failed.is_set())                                   # the new process runs: nothing
        old.heir.code = 0                                                   # it gave way itself later, and ended well
        time.sleep(1.2)
        self.assertFalse(failed.is_set())
        old.heir.code = -9                                                  # it was killed
        self.assertTrue(failed.wait(5))
        self.assertTrue(any("ended with a fault (-9)" in line for line in self.logged))

    def test_at_most_one_old_process_the_one_before_ends_at_the_next_hand_over(self):
        killed = []
        with patch.object(vault.os, "kill", lambda pid, sig: killed.append((pid, sig))), \
                patch.object(vault.os, "getppid", lambda: 4321):
            for parent, wanted in ((4321, [(4321, vault.signal.SIGTERM)]), (999, []), (None, []), (1, [])):
                with self.subTest(parent=parent):
                    killed.clear()
                    proxy = self.giving_way(lambda program, sock: True, parent=parent)
                    self.said = {"ok": True, "site": False, "program": "b" * 64}
                    proxy.ask({"op": "site"})
                    self.settled(proxy)
                    self.assertTrue(proxy.ending)
                    self.assertEqual(killed, wanted)        # only the process that it took over from, while it lives

    def giving_way(self, spawn, program="a" * 64, **more):
        """A proxy that knows its own program and how a candidate starts."""
        proxy = vault.SwapProxy({"port": 0, "group": "fleet-agents"}, self.authority, ask=lambda request: self.said,
                                peer=lambda conn: self.uid, reach=self.reach, port=0, program=program, spawn=spawn, **more)
        self.addCleanup(proxy.close)
        return proxy

    def settled(self, proxy):
        for _ in range(100):
            if not proxy.trying:
                return
            time.sleep(0.05)
        self.fail("the candidate did not end")

    def test_the_brokers_new_program_gets_its_try_and_a_program_that_failed_gets_later_ones(self):
        tries, answer = [], ["exit 1"]
        proxy = self.giving_way(lambda program, sock: tries.append((program, sock)) or answer[0])
        new, newer = "b" * 64, "c" * 64

        def asks(times=1):
            for _ in range(times):
                proxy.ask({"op": "site"})
                self.settled(proxy)
        for self.said in ({"ok": True, "site": False}, {"ok": True, "site": False, "program": "a" * 64},
                          {"ok": True, "site": False, "program": "not a checksum"}, None):
            asks()                                                          # the broker runs this program, or says none
        self.assertEqual(tries, [])
        self.said = {"ok": True, "site": False, "program": new}
        self.assertEqual(proxy.ask({"op": "site"}), self.said)              # the answer itself is as it came
        self.settled(proxy)
        self.assertEqual(tries, [(new, proxy.sock)])
        self.assertEqual((proxy.failed, proxy.ending), ((new, 1, 4), False))        # it did not start: this process goes on
        self.assertTrue(any("did not start (exit 1)" in line and "goes on" in line for line in self.logged))
        asks(4)
        self.assertEqual(len(tries), 1)                                     # not at each connection
        asks()
        self.assertEqual((len(tries), proxy.failed), (2, (new, 2, 16)))     # and not never: a later try
        asks(16)
        self.assertEqual(len(tries), 2)
        asks()
        self.assertEqual((len(tries), proxy.failed), (3, (new, 3, 64)))
        proxy.failed = (new, 9, 0)
        asks()
        self.assertEqual(proxy.failed, (new, 10, 1024))                     # at the most each 1024 answers
        self.said = {"ok": True, "site": False, "program": newer}           # another program has its own count
        answer[0] = None                                                    # not the time (the installed file is another)
        before = len(tries)
        asks(2)
        self.assertEqual((len(tries), proxy.failed, proxy.ending), (before + 2, (new, 10, 1024), False))
        answer[0] = "exit 3"
        asks()
        self.assertEqual(proxy.failed, (newer, 1, 4))
        proxy.failed = None
        heir = object()
        answer[0] = heir                                                    # and then it serves
        asks()
        self.assertEqual((proxy.ending, proxy.heir), (True, heir))
        before = len(tries)
        self.said = {"ok": True, "site": False, "program": "d" * 64}
        asks()
        self.assertEqual(len(tries), before)                                # a process that ends starts no candidate

    def test_one_candidate_at_a_time_and_none_without_a_way_to_start_one(self):
        started, go = [], threading.Event()
        proxy = self.giving_way(lambda program, sock: started.append(program) or go.wait(10) and "exit 2")
        self.said = {"ok": True, "site": False, "program": "b" * 64}
        proxy.ask({"op": "site"})
        proxy.ask({"op": "site"})
        self.said = {"ok": True, "site": False, "program": "c" * 64}
        proxy.ask({"op": "site"})                                           # while the first one runs
        go.set()
        self.settled(proxy)
        self.assertEqual(started, ["b" * 64])
        alone = self.giving_way(None)                                       # the proxy of a test, or of the first version
        alone.ask({"op": "site"})
        self.assertFalse(alone.trying)
        failing = self.giving_way(lambda program, sock: 1 / 0)              # a fault in the try is a failed try, not a crash
        failing.ask({"op": "site"})
        self.settled(failing)
        self.assertEqual(failing.failed, ("c" * 64, 1, 4))

    def test_the_check_of_the_callers_user_does_not_use_the_proxys_own_listener(self):
        """In a hand-over another process accepts on that listener too."""
        class Shared:
            def getsockname(self):
                return ("127.0.0.1", 876)

            def accept(self):
                raise AssertionError("the shared listener was used")
            settimeout = close = accept
        proxy = vault.SwapProxy({"port": 876, "group": "fleet-agents"}, self.authority, ask=self.ask,
                                peer=lambda conn: os.getuid(), sock=Shared())
        self.assertIs(proxy.reads_users(), True)

    def test_one_process_at_a_time_makes_the_files_of_a_site(self):
        """Two processes of the proxy share the state folder in a hand-over: a lock on a file there."""
        import fcntl
        folder = self.dir / "state"
        with open(folder / "making", "a") as other:                         # as a second process reads there
            fcntl.flock(other, fcntl.LOCK_SH)                               # a shared hold: only an exclusive one waits
            made = []
            thread = threading.Thread(target=lambda: made.append(self.authority.context("locked.example.com")), daemon=True)
            thread.start()
            thread.join(1.5)
            self.assertTrue(thread.is_alive())                              # it waits
            self.assertFalse((folder / "locked.example.com.ca.pem").exists())
            fcntl.flock(other, fcntl.LOCK_UN)
            thread.join(30)
        self.assertEqual(len(made), 1)
        with open(folder / "making", "a") as other:                         # and it gave the lock back
            fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_the_proxy_goes_on_when_it_has_no_free_file(self):
        calls, real = [], self.proxy.sock

        class Full:
            def fileno(self):
                return real.fileno()

            def accept(self):
                calls.append(1)
                if len(calls) == 1:
                    raise OSError(24, "Too many open files")
                return real.accept()

            def close(self):
                real.close()

            def settimeout(self, seconds):
                real.settimeout(seconds)
        with patch.object(vault.time, "sleep", lambda seconds: None):
            other = vault.SwapProxy({"port": 0, "group": "fleet-agents"}, self.authority, ask=self.ask, peer=lambda c: None,
                                    port=0)
            self.addCleanup(other.close)
            real, other.sock = other.sock, Full()
            threading.Thread(target=other.serve, daemon=True).start()
            with socket.create_connection(("127.0.0.1", real.getsockname()[1]), timeout=10) as s:
                s.settimeout(10)
                self.assertEqual(s.recv(16), b"")           # served after the failed accept: the user is not known, so no answer
        self.assertGreaterEqual(len(calls), 2)

    def test_a_sites_ca_speaks_for_that_one_host_name_and_for_nothing_else(self):
        """The limit is in the CA itself, so it holds also for a certificate that the proxy would never make."""
        state = self.dir / "state"
        self.authority.context(HOST)
        ca, key = state / (HOST + ".ca.pem"), state / (HOST + ".ca.key")
        text = subprocess.run([OPENSSL, "x509", "-in", str(ca), "-noout", "-text"], capture_output=True, text=True).stdout
        self.assertIn("Name Constraints: critical", text)
        self.assertIn("DNS:" + HOST, text)
        self.assertIn("DNS:." + HOST, text)
        self.assertIn("IP:0.0.0.0/0.0.0.0", text)
        self.assertEqual(key.stat().st_mode & 0o077, 0)
        trust = ssl.create_default_context(cafile=str(self.dir / "public" / (HOST + ".pem")))
        for name, san, good in ((HOST, "DNS:" + HOST, True), ("under." + HOST, "DNS:under." + HOST, False),
                                (OTHER_HOST, "DNS:" + OTHER_HOST, False), ("127.0.0.1", "IP:127.0.0.1", False)):
            with self.subTest(name=name):
                ext, csr, leaf = (state / f"forged-{name}.{end}" for end in ("cnf", "csr", "pem"))
                ext.write_text(f"subjectAltName={san}\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n")
                for args in (["req", "-new", "-key", str(state / "leaf.key"), "-subj", "/CN=x", "-out", str(csr)],
                             ["x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(key), "-set_serial",
                              "0x1" + "0" * 15, "-days", "2", "-sha256", "-extfile", str(ext), "-out", str(leaf)]):
                    subprocess.run([OPENSSL, *args], capture_output=True, check=True)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(str(leaf), str(state / "leaf.key"))
                forged = Site({}, only=context)             # a server with a certificate that this CA signed
                forged.start()
                self.addCleanup(forged.close)
                raw = socket.create_connection(("127.0.0.1", forged.port), timeout=10)
                try:
                    if good:
                        trust.wrap_socket(raw, server_hostname=name).close()
                    else:
                        with self.assertRaises(ssl.SSLCertVerificationError):
                            trust.wrap_socket(raw, server_hostname=name)
                finally:
                    raw.close()


class Start(unittest.TestCase):
    """`vault.py swap`: what the proxy checks before it serves."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="fleet-key-swap-start-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        (self.dir / "state").mkdir(mode=0o700)
        (self.dir / "run").mkdir(mode=0o755)
        self.low = self.dir / "low"
        self.low.write_text("1024\n")
        self.conf = {"swap": {"user": "founderizer-swap", "vault": "fleet-vault", "port": 0, "openssl": OPENSSL}}
        self.part = dict(self.conf["swap"], uid=os.getuid(), vault_uid=os.getuid() + 1, group="fleet-agents",
                         broker=str(self.dir / "swap.sock"))
        self.served, self.reads, self.said, self.proxies = [], True, [], []
        for p in (patch.object(vault, "unchangeable", lambda path, what: None),
                  patch.object(vault, "load_config", lambda path: self.conf),
                  patch.object(vault, "swap_part", lambda conf: dict(self.part)),
                  patch.object(vault, "SWAP_LOW_PORTS", str(self.low)),
                  patch.object(vault.SwapProxy, "serve",
                               lambda proxy: self.served.append(proxy.port) or self.proxies.append(proxy) or proxy.close()),
                  patch.object(vault.SwapProxy, "reads_users", lambda proxy: self.reads or proxy.close() or False),
                  patch.object(vault, "log", self.said.append),
                  patch.dict(os.environ, {"STATE_DIRECTORY": str(self.dir / "state"),
                                          "RUNTIME_DIRECTORY": str(self.dir / "run")})):
            p.start()
            self.addCleanup(p.stop)

    def test_it_serves_when_each_check_passes(self):
        self.assertEqual(vault.swap_main("/etc/fleet-vault/vault.json"), 0)
        self.assertEqual(len(self.served), 1)
        self.assertIn("swap proxy for the agents of this machine", self.said[-1])
        self.low.unlink()                                                   # a machine with no such setting
        self.assertEqual(vault.swap_main("/etc/fleet-vault/vault.json"), 0)

    def notify_socket(self):
        """A stand-in for systemd's notify socket: (its path, the socket)."""
        path = str(self.dir / "notify")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(path)
        sock.settimeout(1.5)
        self.addCleanup(sock.close)
        return path, sock

    def listener(self):
        """The proxy's listener, as the process that serves holds it; the configuration names its port."""
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        self.addCleanup(listener.close)
        self.part["port"] = listener.getsockname()[1]
        self.low.unlink(missing_ok=True)                    # this test's port is no low port
        return listener

    def taking(self, listener, notify_path, pipe=None):
        """swap_main as the candidate: (what it returned or raised, what the old process reads on the pipe)."""
        mine, theirs = pipe or os.pipe()
        if pipe is None:
            self.addCleanup(os.close, mine)
        try:
            with patch.dict(os.environ, {"NOTIFY_SOCKET": notify_path}):
                out = vault.swap_main("/etc/fleet-vault/vault.json", take=(os.dup(listener.fileno()), theirs))
        except SystemExit as e:
            out = str(e)
            try:
                os.close(theirs)
            except OSError:
                pass
        return out, (os.read(mine, 16) if pipe is None else None)

    def test_a_candidate_takes_the_listener_and_says_that_it_is_the_main_process(self):
        path, notify = self.notify_socket()
        listener = self.listener()
        self.assertEqual(self.taking(listener, path), (0, vault.SWAP_SERVES))       # the word comes after systemd knows
        self.assertEqual(self.served, [listener.getsockname()[1]])          # it serves on the listener that it got
        self.assertEqual(notify.recv(4096).decode(), f"MAINPID={os.getpid()}\nREADY=1")
        self.assertIn("in the place of the process that served before", self.said[-1])
        self.assertEqual(self.proxies[-1].parent, os.getppid())             # the process that it took over from
        # each check of a normal start comes before those two words
        self.reads = False
        out, word = self.taking(listener, path)
        self.assertIn("cannot read the user", out)
        self.assertEqual(word, b"")                                         # no word: the old process goes on
        with self.assertRaises(socket.timeout):
            notify.recv(4096)

    def test_a_candidate_stops_when_systemd_does_not_take_its_word(self):
        listener = self.listener()
        out, word = self.taking(listener, str(self.dir / "no-such-socket"))
        self.assertIn("systemd did not take its word", out)
        self.assertEqual((word, self.served), (b"", []))                    # no word for the old process, and it serves not

    def test_a_candidate_takes_only_the_proxys_own_listener(self):
        path, notify = self.notify_socket()
        listener = self.listener()
        other = socket.socket()                                             # a listener on another port
        other.bind(("127.0.0.1", 0))
        other.listen(1)
        plain = socket.socket()                                             # the right port would not help: it does not listen
        self.addCleanup(other.close)
        self.addCleanup(plain.close)
        for sock in (other, plain):
            out, word = self.taking(sock, path)
            self.assertIn("did not get the proxy's listener", out)
            self.assertEqual(word, b"")
        self.assertEqual(self.served, [])
        self.assertEqual(self.taking(listener, path)[0], 0)

    def test_a_candidate_whose_word_the_old_process_does_not_take_ends(self):
        """The old process gave the try up (it closed the pipe) and still lives: two proxies must not serve."""
        path, notify = self.notify_socket()
        listener = self.listener()
        mine, theirs = os.pipe()
        os.close(mine)
        out, _ = self.taking(listener, path, pipe=(mine, theirs))
        self.assertIn("did not take its word", out)
        self.assertEqual(self.served, [])
        # the old process has ended in between (this process has another parent now): the candidate serves alone
        mine, theirs = os.pipe()
        os.close(mine)
        parents = iter([4321] + [1] * 5)
        with patch.object(vault.os, "getppid", lambda: next(parents)):
            out, _ = self.taking(listener, path, pipe=(mine, theirs))
        self.assertEqual((out, len(self.served)), (0, 1))

    def test_a_candidate_needs_the_unit_that_lets_it_take_over(self):
        with patch.dict(os.environ), self.assertRaisesRegex(SystemExit, "cannot take over under this unit"):
            os.environ.pop("NOTIFY_SOCKET", None)
            vault.swap_main("/etc/fleet-vault/vault.json", take=(0, 1))
        self.assertEqual(self.served, [])
        with self.assertRaisesRegex(SystemExit, "--take is for the swap proxy's own hand-over"):
            vault.main(["swap", "--config", "/etc/fleet-vault/vault.json", "--take", "3"])
        with patch.object(vault, "swap_main", lambda config, take=None: (config, take)):
            self.assertEqual(vault.main(["swap", "--config", "/x/vault.json", "--take", "5,6"]), ("/x/vault.json", (5, 6)))
            self.assertEqual(vault.main(["swap", "--config", "/x/vault.json"]), ("/x/vault.json", None))

    def test_a_normal_start_tells_systemd_that_it_is_ready_and_knows_how_to_give_way(self):
        path, notify = self.notify_socket()
        with patch.dict(os.environ, {"NOTIFY_SOCKET": path}):
            self.assertEqual(vault.swap_main("/etc/fleet-vault/vault.json"), 0)
        self.assertEqual(notify.recv(4096), b"READY=1")
        proxy = self.proxies[-1]
        self.assertEqual((proxy.program, proxy.parent), (vault.swap_program(), None))
        with open(vault.__file__, "rb") as f:
            self.assertEqual(proxy.program, hashlib.sha256(f.read()).hexdigest())
        with patch.object(vault, "swap_candidate", lambda config, program, sock: (config, program, sock)):
            self.assertEqual(proxy.spawn("b" * 64, "the listener"), ("/etc/fleet-vault/vault.json", "b" * 64, "the listener"))
        with patch.dict(os.environ, {"NOTIFY_SOCKET": str(self.dir / "none")}):
            self.assertIs(vault.swap_notify("READY=1"), False)              # no socket there: no word, and no fault
            self.assertEqual(vault.swap_main("/etc/fleet-vault/vault.json"), 0)

    def child(self, script, pipe=None):
        """swap_candidate, with a child of this test in the place of the installed program: (what it returns, the
        command that it started, the children)."""
        real = subprocess.Popen
        made, children = [], []

        def popen(argv, **more):
            take = argv[argv.index("--take") + 1]
            made.append(argv)
            children.append(real([sys.executable, "-c", script, take], **more))
            return children[-1]
        listener = socket.socket()
        self.addCleanup(listener.close)
        with patch.object(vault.subprocess, "Popen", popen), \
                patch.object(vault.os, "pipe", pipe or os.pipe):
            return vault.swap_candidate("/etc/fleet-vault/vault.json", vault.swap_program(), listener), made, children

    SAYS = "import os, sys, time; os.write(int(sys.argv[1].split(',')[1]), b'serves\\n'); time.sleep(30)"

    def test_the_old_process_waits_for_the_candidates_word_and_else_ends_it(self):
        path, notify = self.notify_socket()
        with patch.dict(os.environ, {"NOTIFY_SOCKET": path}):
            taken, made, children = self.child(self.SAYS)
            self.addCleanup(children[0].kill)
            self.assertIs(taken, children[0])                               # the process that serves now
            self.assertIsNone(taken.poll())
            self.assertEqual(made[0][1:5], [os.path.realpath(vault.__file__), "swap", "--config", "/etc/fleet-vault/vault.json"])
            with self.assertRaises(socket.timeout):
                notify.recv(4096)                                           # nothing to put right at systemd
            self.assertEqual(self.child("import sys; sys.exit(7)")[0], "exit 7")
            self.assertEqual(notify.recv(4096).decode(), f"MAINPID={os.getpid()}")      # this process is the main one again
            self.assertEqual(self.child("import os, sys; os.write(int(sys.argv[1].split(',')[1]), b'other\\n')")[0], "exit 0")
            with patch.object(vault, "SWAP_CANDIDATE", 0.3):
                taken, made, children = self.child("import time; time.sleep(30)")
            self.assertEqual(taken, "no word in 0.3 seconds, and it was ended")
            self.assertIsNotNone(children[0].poll())                        # no child that could serve later
            taken, made, children = self.child("import os, sys, time; os.write(int(sys.argv[1].split(',')[1]), b'other\\n'); time.sleep(30)")
            self.assertEqual(taken, "it did not say that it serves, and it was ended")
            self.assertIsNotNone(children[0].poll())
            listener = socket.socket()
            self.addCleanup(listener.close)
            self.assertIsNone(vault.swap_candidate("/etc/fleet-vault/vault.json", "e" * 64, listener))    # not the installed file
        with patch.dict(os.environ):
            os.environ.pop("NOTIFY_SOCKET", None)
            taken, made, children = self.child(self.SAYS)
            self.assertEqual(taken, vault.SWAP_NO_UNIT)
            self.assertEqual(made, [])                                      # nothing was started

    def test_a_process_with_more_than_1024_open_files_still_reads_the_candidates_word(self):
        """The unit lets the proxy have 65536 open files, and select.select fails above 1023."""
        import fcntl
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft < 1300:
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (1300 if hard == resource.RLIM_INFINITY else min(1300, hard), hard))
            except (ValueError, OSError):
                self.skipTest("this machine does not let a process have 1300 open files")
            self.addCleanup(resource.setrlimit, resource.RLIMIT_NOFILE, (soft, hard))
        if resource.getrlimit(resource.RLIMIT_NOFILE)[0] < 1300:
            self.skipTest("this machine does not let a process have 1300 open files")

        real = os.pipe

        def high():
            low = real()
            ends = tuple(fcntl.fcntl(fd, fcntl.F_DUPFD, 1100) for fd in low)
            for fd in low:
                os.close(fd)
            return ends
        path, notify = self.notify_socket()
        with patch.dict(os.environ, {"NOTIFY_SOCKET": path}):
            taken, made, children = self.child(self.SAYS, pipe=high)
            self.addCleanup(children[0].kill)
            self.assertIs(taken, children[0])
            taken, made, children = self.child("import time; time.sleep(30)", pipe=lambda: 1 / 0)    # a fault before the child
            self.assertEqual((taken, children), ("the try failed (ZeroDivisionError)", []))
            with self.assertRaises(socket.timeout):
                notify.recv(4096)                                           # no child: nothing to put right at systemd
            with patch.object(vault.select, "poll", side_effect=OSError):   # a fault while the child runs
                taken, made, children = self.child(self.SAYS)
            self.assertEqual(taken, "the try failed (OSError), and it was ended")
            self.assertIsNotNone(children[0].poll())                        # no child that could serve beside this process
            self.assertEqual(notify.recv(4096).decode(), f"MAINPID={os.getpid()}")      # the child can have said its own

    def test_it_does_not_start_where_each_user_can_listen_on_its_port(self):
        self.part["port"] = 876
        for low in ("0", "80", "876"):
            self.low.write_text(low + "\n")
            with self.subTest(low=low), self.assertRaisesRegex(SystemExit, "ip_unprivileged_port_start is " + low):
                vault.swap_main("/etc/fleet-vault/vault.json")
        self.assertEqual(self.served, [])

    def test_it_does_not_start_where_it_cannot_read_the_user_of_a_connection(self):
        self.reads = False
        with self.assertRaisesRegex(SystemExit, "cannot read the user of a connection"):
            vault.swap_main("/etc/fleet-vault/vault.json")
        self.assertEqual(self.served, [])

    def test_it_runs_only_as_its_own_user_with_its_own_state_folder_and_with_the_part(self):
        (self.dir / "state").chmod(0o755)
        with self.assertRaisesRegex(SystemExit, "state folder must belong to its user and have mode 700"):
            vault.swap_main("/etc/fleet-vault/vault.json")
        (self.dir / "state").chmod(0o700)
        self.part["uid"] = os.getuid() + 1
        with self.assertRaisesRegex(SystemExit, "runs as founderizer-swap, and as no other user"):
            vault.swap_main("/etc/fleet-vault/vault.json")
        with patch.object(vault, "swap_part", side_effect=vault.Refused("this machine has no user founderizer-swap")), \
                self.assertRaisesRegex(SystemExit, "does not start: this machine has no user founderizer-swap"):
            vault.swap_main("/etc/fleet-vault/vault.json")
        for conf in ({}, {"central": True, "swap": self.conf["swap"]}):
            self.conf = conf
            with self.subTest(conf=conf), self.assertRaisesRegex(SystemExit, "has no part swap"):
                vault.swap_main("/etc/fleet-vault/vault.json")
        self.assertEqual(self.served, [])


class BrokerPart(test_vault.VaultBroker):
    """The broker's part, with the in-process hub: the fixture's broker of vps, started again with the part "swap" in
    its configuration. The machine's users are stand-ins: the proxy's user and the vault's user are this test's own."""
    VALUE = "sk-example-only-key-20261112-abcdef"
    PART = {"user": "founderizer-swap", "vault": "fleet-vault", "port": 876, "openssl": "/usr/bin/openssl"}

    def setUp(self):
        super().setUp()
        self.item(test_vault.SECRET_ID, {"username": "", "password": self.VALUE}, key="SHOP_API_KEY")
        hub.TEAM["logins"] = {test_vault.REF: {"title": "SHOP_API_KEY", "kind": "api_key", "env": "SHOP_API_KEY",
                                               "site": "https://api.example.com/v1"}}
        self.addCleanup(hub.TEAM.pop, "logins", None)
        hub.TEAM["agents"]["vps"]["secrets"] = {test_vault.REF: "read"}
        self.addCleanup(hub.TEAM["agents"]["vps"].pop, "secrets", None)
        self.swap_sock = str(self.dir / "swap.sock")
        self.programs = []
        self.part = dict(self.PART, uid=os.getuid(), vault_uid=os.getuid(), group="fleet-agents", broker=self.swap_sock)
        # this test's own user stands in for the OS user of the agent vps, as the hub names it (fleet-<name>)
        real = vault.swap_user
        named = patch.object(vault, "swap_user", lambda uid: "fleet-vps" if uid == os.getuid() else real(uid))
        named.start()
        self.addCleanup(named.stop)

    def started(self, part=None, fault=None):
        """The fixture's broker, started again: with the part swap (or a part whose machine facts are a fault)."""
        self.broker.close()

        def facts(conf):
            if fault:
                raise vault.Refused(fault)
            return dict(part or self.part)
        patched = patch.object(vault, "swap_part", facts)
        patched.start()
        self.addCleanup(patched.stop)
        self.conf = dict(self.conf, swap=dict(self.PART))
        self.broker = vault.Broker(self.conf).open()
        threading.Thread(target=self.broker.serve, daemon=True).start()
        self.addCleanup(self.broker.close)
        return self.broker

    def proxy_asks(self, **request):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect(self.swap_sock)
            data = b""
            try:
                s.sendall((json.dumps(request) + "\n").encode())
                while not data.endswith(b"\n"):
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except (ConnectionResetError, BrokenPipeError):     # the broker closed with nothing read: no answer
                return None
        said = json.loads(data) if data else None
        if isinstance(said, dict):
            self.programs.append(said.pop("program", None))     # which program the broker runs: its own test below
        return said

    def swap(self, placeholder, **changes):
        return self.proxy_asks(**dict({"op": "swap", "uid": os.getuid(), "host": HOST, "port": 443, "name": placeholder,
                                       "form": "bearer"}, **changes))

    def test_a_broker_without_the_part_gives_the_key_as_before_and_opens_nothing(self):
        raw = fleet.vault_call({"op": "read"})
        self.assertEqual(raw, {"ok": True, "v": 2, "env": {"SHOP_API_KEY": self.VALUE}, "missing": []})
        self.assertNotIn("swaps", fleet.vault_call({"op": "status"}))
        self.assertFalse(os.path.exists(self.swap_sock))
        self.assertEqual(self.dir.stat().st_mode & 0o777, 0o700)           # its folder keeps its mode
        self.assertFalse((self.dir / "state" / vault.SWAPS).exists())

    def test_a_broker_with_the_part_gives_a_placeholder_and_never_the_key(self):
        self.started()
        raw = fleet.vault_call({"op": "read"})
        name = raw["env"]["SHOP_API_KEY"]
        self.assertRegex(name, r"^vaultswap_[0-9a-f]{40}$")
        self.assertEqual(raw, {"ok": True, "v": 2, "env": {"SHOP_API_KEY": name}, "missing": [],
                               "swap": {"proxy": "http://127.0.0.1:876", "ca": vault.SWAP_RUN,
                                        "names": {"SHOP_API_KEY": HOST}}})
        self.assertNotIn(self.VALUE, json.dumps(raw))
        self.assertTrue(hub.secret_hit("echo " + self.VALUE))              # the real key is still masked in texts
        self.assertFalse(hub.secret_hit("echo " + name))                   # the placeholder is no secret
        self.assertEqual(fleet.vault_call({"op": "read", "for": "check"})["env"], {"SHOP_API_KEY": name})   # the same one
        self.assertIs(fleet.vault_call({"op": "status"})["swaps"], True)
        kept = json.loads((self.dir / "state" / vault.SWAPS).read_text())
        self.assertEqual(set(kept), {name})
        self.assertEqual({k: v for k, v in kept[name].items() if k != "token"},
                         {"uid": os.getuid(), "user": "fleet-vps", "agent": "vps",
                          "login": test_vault.REF, "host": HOST, "port": 443, "form": "bearer"})
        self.assertNotIn(self.VALUE, (self.dir / "state" / vault.SWAPS).read_text())
        self.assertEqual((self.dir / "state" / vault.SWAPS).stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.dir.stat().st_mode & 0o777, 0o751)           # passable for the proxy's user, not listable
        self.assertEqual(os.stat(self.swap_sock).st_mode & 0o777, 0o666)
        # a key with no site is a value as before, beside the placeholder
        other = "sk-example-other-key-20261112"
        self.item(test_vault.THIRD_ID, {"username": "", "password": other}, key="OTHER_KEY")
        third = "bws://" + test_vault.THIRD_ID
        hub.TEAM["logins"][third] = {"title": "OTHER_KEY", "kind": "api_key", "env": "OTHER_KEY"}
        hub.TEAM["agents"]["vps"]["secrets"][third] = "read"
        both = fleet.vault_call({"op": "read"})
        self.assertEqual(both["env"], {"OTHER_KEY": other, "SHOP_API_KEY": name})
        self.assertEqual(both["swap"]["names"], {"SHOP_API_KEY": HOST})

    def test_the_proxy_gets_the_value_for_this_user_this_host_and_this_form_only(self):
        self.started()
        name = fleet.vault_call({"op": "read"})["env"]["SHOP_API_KEY"]
        self.assertEqual(self.proxy_asks(op="site", uid=os.getuid(), host=HOST, port=443), {"ok": True, "site": True})
        for other in (dict(host=OTHER_HOST), dict(port=8443), dict(uid=os.getuid() + 1)):
            with self.subTest(other=other):
                asked = dict(dict(op="site", uid=os.getuid(), host=HOST, port=443), **other)
                self.assertEqual(self.proxy_asks(**asked), {"ok": True, "site": False})
        self.assertEqual(self.swap(name), {"ok": True, "value": self.VALUE})
        for why, changes in (("another user", dict(uid=os.getuid() + 1)), ("another host", dict(host=OTHER_HOST)),
                             ("another port", dict(port=8443)), ("another form", dict(form="basic-user")),
                             ("no form", dict(form=None)), ("another placeholder", dict(name="vaultswap_" + "0" * 40)),
                             ("no placeholder", dict(name="SHOP_API_KEY"))):
            with self.subTest(why):
                self.assertEqual(self.swap(name, **changes), {"ok": False, "code": "refused"})
        # the broker's own check, also when the hub says yes to each question (a hub that is broken into)
        with patch.object(vault, "hub", return_value=(200, {"ok": True, "login": test_vault.REF})):
            self.assertEqual(self.swap(name), {"ok": True, "value": self.VALUE})
            for why, changes in (("another user", dict(uid=os.getuid() + 1)), ("another host", dict(host=OTHER_HOST)),
                                 ("another port", dict(port=8443)), ("another form", dict(form="basic-user"))):
                with self.subTest("a hub that says yes: " + why):
                    self.assertEqual(self.swap(name, **changes), {"ok": False, "code": "refused"})
        for bad in ("two\r\nlines-0123456789", "a-value-with\x00-in-it", "a-value-with\x7f-in-it"):
            with self.subTest(bad=bad), patch.object(vault, "check_value", return_value={"password": bad}):
                self.assertEqual(self.swap(name), {"ok": False, "code": "refused"})    # no header value
        self.assertFalse(self.proxy_asks(op="read")["ok"])                  # no other operation on this socket
        self.assertFalse(self.proxy_asks(op="swap", uid="1", host=HOST, port=443, name=name, form="bearer")["ok"])

    def test_a_value_with_a_login_s_shape_gets_no_placeholder_and_the_proxy_gives_none_of_it(self):
        """C11 on the swap way: a value with a user name gets no placeholder, the read switches off the placeholder
        that an earlier read made, and the proxy's own value path refuses that value too (the second wall)."""
        self.started()
        name = fleet.vault_call({"op": "read"})["env"]["SHOP_API_KEY"]        # a key: its placeholder, which works
        self.assertEqual(self.swap(name), {"ok": True, "value": self.VALUE})
        self.item(test_vault.SECRET_ID, {"username": "pilot-b", "password": self.VALUE}, key="SHOP_API_KEY")
        self.assertEqual(self.swap(name), {"ok": False, "code": "refused"})    # the second wall, before any new read
        raw = fleet.vault_call({"op": "read"})
        self.assertEqual(raw, {"ok": True, "v": 2, "env": {}, "missing": ["SHOP_API_KEY"], "logins": ["SHOP_API_KEY"]})
        self.assertIn(name, self.off())                                         # the earlier placeholder is off

    def off(self):
        """The placeholders of the broker's list that are switched off. The list has one form of off, true, and it is
        a list that a broker reads at its start: a vault.py of the first version takes the same form and no other."""
        path = self.dir / "state" / vault.SWAPS
        entries = json.loads(path.read_text())
        self.assertEqual([e["off"] for e in entries.values() if "off" in e and e["off"] is not True], [])
        self.assertEqual(vault.Swaps(str(path)).entries, entries)
        return {name for name, e in entries.items() if e.get("off")}

    def test_the_hubs_no_switches_off_that_one_placeholder_and_no_other(self):
        """Not each placeholder of that key (another agent of the machine still reads it), and not each one of that
        OS user (it still reads its other keys)."""
        broker = self.started()
        other_value = "sk-example-other-key-20261112"
        third = "bws://" + test_vault.THIRD_ID
        self.item(test_vault.THIRD_ID, {"username": "", "password": other_value}, key="OTHER_KEY")
        hub.TEAM["logins"][third] = {"title": "OTHER_KEY", "kind": "api_key", "env": "OTHER_KEY",
                                     "site": "https://" + OTHER_HOST}
        hub.TEAM["agents"]["vps"]["secrets"][third] = "read"
        env = fleet.vault_call({"op": "read"})["env"]
        name, second = env["SHOP_API_KEY"], env["OTHER_KEY"]
        far = broker.conf["_swaps"].place(0, "another", test_vault.REF, HOST, 443, "bearer", "0" * 64)   # another OS user
        self.assertEqual(len({name, second, far}), 3)
        hub.TEAM["agents"]["vps"]["secrets"] = {third: "read"}              # the owner ends the grant of the one key
        self.assertEqual(self.swap(name), {"ok": False, "code": "refused"})
        self.assertEqual(self.off(), {name})
        self.assertEqual(self.swap(second, host=OTHER_HOST), {"ok": True, "value": other_value})
        self.assertIs(broker.conf["_swaps"].site(0, HOST, 443), True)

    def test_the_hubs_no_to_a_use_stops_the_request_and_switches_the_placeholder_off_with_no_read(self):
        """An agent with no read grant left makes no read of its keys, so the hub's no itself is what switches its
        placeholder off. The agent's next read that names the key with its site switches it on again."""
        self.started()
        read = lambda: fleet.vault_call({"op": "read"})["env"].get("SHOP_API_KEY")
        open_now = dict(op="site", uid=os.getuid(), host=HOST, port=443)
        name = read()
        agent, entry = hub.TEAM["agents"]["vps"], hub.TEAM["logins"][test_vault.REF]
        for why, where, key, changed in (
                ("the owner ends the grant", agent, "secrets", {}),
                ("or makes it a use grant", agent, "secrets", {test_vault.REF: "use"}),
                ("the key loses its site", entry, "site", None),
                ("or gets another one", entry, "site", "https://files.example.com"),
                ("or another form", entry, "form", "basic-user"),
                ("its name is another OS user's agent now", agent, "user", "fleet-renamed")):
            with self.subTest(why):
                self.assertEqual((self.swap(name)["value"], self.off(), self.proxy_asks(**open_now)["site"]),
                                 (self.VALUE, set(), True))
                before = where.get(key)
                if changed is None:
                    del where[key]
                else:
                    where[key] = changed
                try:
                    self.assertEqual(self.swap(name), {"ok": False, "code": "refused"})     # the request that asked
                    self.assertEqual(self.off(), {name})                    # and the placeholder is off, with no read
                    self.assertEqual(self.proxy_asks(**open_now), {"ok": True, "site": False})  # the proxy opens it no more
                finally:
                    if before is None:
                        del where[key]
                    else:
                        where[key] = before
                # what was changed is as before, and no read came: an entry that is off gives nothing, and asks nothing
                with patch.object(vault, "hub", side_effect=AssertionError("the hub was asked")):
                    self.assertEqual(self.swap(name), {"ok": False, "code": "refused"})
                self.assertEqual(read(), name)                              # the agent's next read: the same placeholder
        self.assertEqual((self.swap(name)["value"], self.off()), (self.VALUE, set()))

    def test_a_hub_that_is_silent_or_gives_another_answer_is_a_refusal_and_switches_nothing_off(self):
        self.started()
        name = fleet.vault_call({"op": "read"})["env"]["SHOP_API_KEY"]
        for said, code in ((vault.Refused("the vault broker could not reach the hub"), "hub"), ((500, {}), "hub"),
                           ((200, {"ok": True, "login": "bws://" + test_vault.OTHER_ID}), "hub"),    # not an exact yes
                           ((200, {"ok": False, "login": test_vault.REF}), "hub"),
                           ((403, {"error": "127.0.0.9 is not vps's machine"}), "refused"),     # not a word on the grant
                           # a hub that does not know the route says 404 too: it must not switch each used one off
                           ((404, {"error": "unknown agent"}), "refused"),
                           ((400, {"error": "send {login, site, form, swap}"}), "hub")):
            with self.subTest(said=said):
                how = dict(side_effect=said) if isinstance(said, Exception) else dict(return_value=said)
                with patch.object(vault, "hub", **how):
                    self.assertEqual(self.swap(name), {"ok": False, "code": code})
                self.assertEqual(self.off(), set())
                self.assertEqual(self.swap(name)["value"], self.VALUE)
        # the real hub's 404, for an agent that it does not know: refused, and nothing is switched off
        gone = hub.TEAM["agents"].pop("vps")
        try:
            self.assertEqual(self.swap(name), {"ok": False, "code": "refused"})
        finally:
            hub.TEAM["agents"]["vps"] = gone
        self.assertEqual((self.off(), self.swap(name)["value"]), (set(), self.VALUE))
        # a hub from before it named the agent's OS user: a use is as before
        with patch.object(vault, "hub", return_value=(200, {"ok": True, "login": test_vault.REF})):
            self.assertEqual(self.swap(name), {"ok": True, "value": self.VALUE})
        # the hub's no for another token than the entry has now (a read gave it a new one while the hub was asked)
        # does not switch the entry of now off
        broker = self.broker
        asked = broker.conf["_swaps"].get(name)
        broker.conf["_swaps"].refused(name, dict(asked, token="0" * 64))
        self.assertEqual(self.off(), set())
        # a list that cannot be written: the request is refused as before, and each use still asks the hub
        hub.TEAM["agents"]["vps"]["secrets"] = {}
        with patch.object(vault.Swaps, "keep", side_effect=vault.Refused("the vault could not keep its list")):
            self.assertEqual(self.swap(name), {"ok": False, "code": "refused"})
            self.assertEqual(self.swap(name), {"ok": False, "code": "refused"})
        self.assertEqual(self.off(), set())

    def test_the_question_after_a_delivery_is_marked_as_no_use_and_a_use_is_not(self):
        broker = self.started()
        name = fleet.vault_call({"op": "read"})["env"]["SHOP_API_KEY"]
        entry, asked = broker.conf["_swaps"].get(name), []
        real = vault.hub

        def hub_call(conf, method, path, body=None, **more):
            asked.append((conf.get("agent"), conf.get("agent_key"), method, path, body))
            return real(conf, method, path, body, **more)
        with patch.object(vault, "hub", hub_call):
            self.assertEqual(vault.swap_asks(broker.conf, entry), (200, True))     # the hub named this entry's OS user
            self.assertEqual(vault.swap_asks(broker.conf, entry, use=False), (200, True))
            self.assertEqual(vault.swap_asks(broker.conf, dict(entry, token="0" * 64), use=False), (409, False))
        question = {"login": test_vault.REF, "site": "https://" + HOST, "form": "bearer", "swap": entry["token"]}
        self.assertEqual(asked, [("vps", None, "POST", "/helper/vault/vps/swap", question),
                                 ("vps", None, "POST", "/helper/vault/vps/swap", dict(question, use=False)),
                                 ("vps", None, "POST", "/helper/vault/vps/swap", dict(question, swap="0" * 64, use=False))])
        # A delivery comes with the fields of the agent that carries it. The question is about the placeholder's
        # own agent, on that agent's route, and with no agent key: the carrier's key is not that agent's.
        del asked[:]
        with patch.object(vault, "hub", hub_call):
            self.assertEqual(vault.swap_asks(dict(broker.conf, agent="studio", agent_key="k" * 43), entry, use=False),
                             (200, True))
            # and the site of the question has the entry's port, when that is not 443
            self.assertEqual(vault.swap_asks(broker.conf, dict(entry, port=8443), use=False), (409, False))
        self.assertEqual(asked, [("vps", None, "POST", "/helper/vault/vps/swap", dict(question, use=False)),
                                 ("vps", None, "POST", "/helper/vault/vps/swap",
                                  dict(question, site="https://" + HOST + ":8443", use=False))])
        with patch.object(vault, "hub", side_effect=vault.Refused("no hub")):
            self.assertEqual(vault.swap_asks(broker.conf, entry), (None, False))
        with patch.object(vault, "hub", return_value=(200, {"ok": True, "login": "bws://" + test_vault.OTHER_ID})):
            self.assertEqual(vault.swap_asks(broker.conf, entry), (0, False))
        # the agent's name is one thing and the entry's OS user another: the hub's yes for the name of an agent that
        # is another OS user's now is its no for this entry, and a hub that names no OS user says nothing of it
        for said, wanted in (({"ok": True, "login": test_vault.REF, "user": "fleet-vps"}, (200, True)),
                             ({"ok": True, "login": test_vault.REF}, (200, False)),
                             ({"ok": True, "login": test_vault.REF, "user": None}, (200, False)),
                             ({"ok": True, "login": test_vault.REF, "user": "fleet-other"}, (409, True)),
                             ({"ok": True, "login": test_vault.REF, "user": ""}, (409, True)),
                             ({"ok": True, "login": test_vault.REF, "user": ["fleet-vps"]}, (409, True)),
                             ({"ok": False, "login": test_vault.REF, "user": "fleet-vps"}, (0, False))):
            with self.subTest(said=said), patch.object(vault, "hub", return_value=(200, said)):
                self.assertEqual(vault.swap_asks(broker.conf, entry), wanted)

    def test_a_key_that_the_hub_names_no_more_opens_no_connection_and_keeps_its_placeholder(self):
        """Else the proxy would open that host for this user for ever, with a certificate that its next sessions do
        not trust."""
        self.started()
        open_now = dict(op="site", uid=os.getuid(), host=HOST, port=443)
        name = fleet.vault_call({"op": "read"})["env"]["SHOP_API_KEY"]
        self.assertIs(self.proxy_asks(**open_now)["site"], True)
        # a value that the store cannot give now keeps its placeholder on: a session that runs holds it
        with patch.object(vault, "check_value", side_effect=vault.Refused("the item is not a saved value")):
            self.assertEqual(fleet.vault_call({"op": "read"})["missing"], ["SHOP_API_KEY"])
        self.assertEqual((self.off(), self.proxy_asks(**open_now)["site"]), (set(), True))
        site = hub.TEAM["logins"][test_vault.REF].pop("site")               # the key loses its site
        self.assertEqual(fleet.vault_call({"op": "read"})["env"], {"SHOP_API_KEY": self.VALUE})
        self.assertEqual(self.off(), {name})
        self.assertEqual(self.proxy_asks(**open_now), {"ok": True, "site": False})
        hub.TEAM["logins"][test_vault.REF]["site"] = site                   # it gets its site again, and no read yet:
        with patch.object(vault, "hub", return_value=(200, {"ok": True, "login": test_vault.REF})):
            self.assertEqual(self.swap(name), {"ok": False, "code": "refused"})     # an entry that is off gives nothing
        self.assertEqual(fleet.vault_call({"op": "read"})["env"]["SHOP_API_KEY"], name)     # the same placeholder again
        self.assertEqual((self.off(), self.proxy_asks(**open_now)["site"]), (set(), True))
        self.assertEqual(self.swap(name), {"ok": True, "value": self.VALUE})
        hub.TEAM["agents"]["vps"]["secrets"] = {}                           # and the end of the grant does the same
        self.assertEqual(fleet.vault_call({"op": "read"})["env"], {})
        self.assertEqual((self.off(), self.proxy_asks(**open_now)["site"]), ({name}, False))

    def test_an_entry_is_for_one_os_user_by_number_and_name_and_for_its_one_agent(self):
        broker = self.started()
        name = fleet.vault_call({"op": "read"})["env"]["SHOP_API_KEY"]
        open_now = dict(op="site", uid=os.getuid(), host=HOST, port=443)
        # the number of a user that was removed, with a new user's name: the entry opens nothing for it
        with patch.object(vault, "swap_user", lambda uid: "fleet-new-agent"):
            self.assertEqual(self.proxy_asks(**open_now), {"ok": True, "site": False})
            self.assertEqual(self.swap(name), {"ok": False, "code": "refused"})
        with patch.object(vault, "swap_user", lambda uid: None):            # a number with no user
            self.assertEqual(self.proxy_asks(**open_now), {"ok": True, "site": False})
            self.assertEqual(self.swap(name), {"ok": False, "code": "refused"})
            self.assertEqual(fleet.vault_call({"op": "read"})["missing"], ["SHOP_API_KEY"])    # and gets no placeholder
        self.assertEqual(self.swap(name), {"ok": True, "value": self.VALUE})
        # an entry of this OS user from before its agent got a new name is switched off at the agent's next read,
        # and an entry of another OS user, with another agent, stays as it is
        old = broker.conf["_swaps"].place(os.getuid(), "old-name", "bws://" + test_vault.OTHER_ID, OTHER_HOST, 443,
                                          "bearer", "0" * 64)
        far = broker.conf["_swaps"].place(0, "another", "bws://" + test_vault.OTHER_ID, OTHER_HOST, 443, "bearer", "0" * 64)
        other = dict(open_now, host=OTHER_HOST)
        self.assertIs(self.proxy_asks(**other)["site"], True)
        self.assertEqual(fleet.vault_call({"op": "read"})["env"]["SHOP_API_KEY"], name)
        self.assertEqual((self.off(), self.proxy_asks(**other)["site"], self.proxy_asks(**open_now)["site"]),
                         ({old}, False, True))
        self.assertIs(broker.conf["_swaps"].site(0, OTHER_HOST, 443), True)     # the other user's entry is still on
        self.assertEqual(len({name, old, far}), 3)
        # the agent's new name gets a placeholder of its own for that key, not the one of its old name
        renamed = broker.conf["_swaps"].place(os.getuid(), "new-name", "bws://" + test_vault.OTHER_ID, OTHER_HOST, 443,
                                              "bearer", "0" * 64)
        self.assertNotIn(renamed, {name, old, far})
        # an entry of this user number with the name of a user that is gone is removed at the next read
        with patch.object(vault, "swap_user", lambda uid: "fleet-removed"):
            gone = broker.conf["_swaps"].place(os.getuid(), "removed", "bws://" + test_vault.OTHER_ID, OTHER_HOST, 443,
                                               "bearer", "0" * 64)
        listed = lambda: set(json.loads((self.dir / "state" / vault.SWAPS).read_text()))
        self.assertEqual(listed(), {name, old, far, renamed, gone})
        self.assertEqual(fleet.vault_call({"op": "read"})["env"]["SHOP_API_KEY"], name)
        self.assertEqual((listed(), self.off()), ({name, old, far, renamed}, {old, renamed}))
        # and a list with an entry in another form is not read
        kept = self.dir / "state" / vault.SWAPS
        entries = json.loads(kept.read_text())
        for bad in (dict(entries[name], off=False), {k: v for k, v in entries[name].items() if k != "user"},
                    dict(entries[name], user="")):
            with self.subTest(bad=bad):
                kept.write_text(json.dumps({name: bad}))
                with self.assertRaises(vault.Refused):
                    vault.Swaps(str(kept))

    def test_a_key_with_a_colon_is_not_the_user_name_of_basic(self):
        value = "id-part:secret-part-0123456789"
        self.item(test_vault.SECRET_ID, {"username": "", "password": value}, key="SHOP_API_KEY")
        hub.TEAM["logins"][test_vault.REF]["form"] = "basic-user"
        self.started()
        name = fleet.vault_call({"op": "read"})["env"]["SHOP_API_KEY"]
        self.assertEqual(self.swap(name, form="basic-user"), {"ok": False, "code": "refused"})
        hub.TEAM["logins"][test_vault.REF]["form"] = "basic-password"
        name = fleet.vault_call({"op": "read"})["env"]["SHOP_API_KEY"]
        self.assertEqual(self.swap(name, form="basic-password"), {"ok": True, "value": value})

    def test_the_hub_names_site_and_form_when_it_confirms_a_request_with_such_a_key(self):
        """call_api: a broker that swaps keys then sends the key only as its proxy does (vault.swap_call)."""
        attempt = hub.q1("SELECT attempt FROM tasks WHERE id=?", (self.task,))["attempt"]
        job = hub.ins("INSERT INTO jobs(agent,task,kind,login,target,created,attempt,request_id,method,path,auth,headers) "
                      "VALUES('vps',?,'request',?,'',?,?,?,'GET','/v1/items','bearer','{}')",
                      (self.task, test_vault.REF, hub.now(), attempt, "11111111-2222-4333-8444-555555555559"))
        code, said = self.request("/helper/vault/vps", {"job": job, "kind": "request", "creation": 1},
                                  source=hub.address_of("vps"))
        self.assertEqual((code, said.get("site"), said.get("form")), (200, "https://" + HOST, "bearer"), said)
        del hub.TEAM["logins"][test_vault.REF]["site"]
        job = hub.ins("INSERT INTO jobs(agent,task,kind,login,target,created,attempt,request_id,method,path,auth,headers) "
                      "VALUES('vps',?,'request',?,'',?,?,?,'GET','/v1/items','bearer','{}')",
                      (self.task, test_vault.REF, hub.now(), attempt, "11111111-2222-4333-8444-555555555558"))
        code, said = self.request("/helper/vault/vps", {"job": job, "kind": "request", "creation": 1},
                                  source=hub.address_of("vps"))
        self.assertEqual((code, "site" in said, "form" in said), (200, False, False), said)

    def test_the_brokers_own_request_with_a_key_that_swaps_goes_only_as_the_proxy_sends_it(self):
        """call_api through a broker that swaps keys (vault.swap_call in send): refused before a request starts when
        the saved item's address is not the key's site, or the auth is not the key's form."""
        curl = shutil.which("curl")
        if not curl:
            self.skipTest("no curl program on this machine")
        key = "vps-agent-key-".ljust(43, "k")
        hub.ins("INSERT OR REPLACE INTO agent_keys(agent,sha256,created,source) VALUES('vps',?,?,'owner')",
                (hashlib.sha256(key.encode()).hexdigest(), hub.now()))
        attempt = hub.q1("SELECT attempt FROM tasks WHERE id=?", (self.task,))["attempt"]
        self.conf = dict(self.conf, curl=os.path.realpath(curl))
        self.started()

        def asked(auth, url):
            self.item(test_vault.SECRET_ID, {"username": "", "password": self.VALUE, "url": url}, key="SHOP_API_KEY")
            job = hub.ins("INSERT INTO jobs(agent,task,kind,login,target,created,attempt,request_id,method,path,auth,headers) "
                          "VALUES('vps',?,'request',?,'',?,?,?,'GET','/v1/items',?,'{}')",
                          (self.task, test_vault.REF, hub.now(), attempt, str(uuid.uuid4()), auth))
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(30)
                s.connect(self.conf["socket"])
                s.sendall((json.dumps({"v": 2, "op": "request", "job": job, "agent": "vps", "agent_key": key}) + "\n").encode())
                data = b""
                while not data.endswith(b"\n"):
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            return json.loads(data)
        with patch.object(vault, "Child", side_effect=AssertionError("a request was started")):
            for why, auth, url in (("a header of the agent's choice", "header:X-Request-Id", "https://" + HOST + "/v1"),
                                   ("the saved item's other address", "bearer", "https://" + OTHER_HOST + "/"),
                                   ("basic for a bearer key", "basic", "https://" + HOST + "/v1")):
                with self.subTest(why):
                    reply = asked(auth, url)
                    self.assertEqual((reply["ok"], reply.get("error")), (False, vault.SWAP_CALL), reply)
            reply = asked("bearer", "https://" + HOST + "/v1")              # the key's own site and form pass this check
            self.assertIn("AssertionError", reply.get("error", ""), reply)

    def test_the_brokers_answers_for_the_proxy_go_on_when_no_thread_starts(self):
        with patch.object(vault, "SWAP_ROOM", 1):
            broker = self.started()
        name = fleet.vault_call({"op": "read"})["env"]["SHOP_API_KEY"]
        real, failed = threading.Thread.start, []

        def start(thread):
            if getattr(thread, "_target", None) == broker.swap_served and not failed:
                failed.append(thread)
                raise RuntimeError("can't start new thread")
            return real(thread)
        with patch.object(threading.Thread, "start", start):
            self.assertIsNone(self.swap(name))                              # this question gets no answer
            self.assertEqual(self.swap(name), {"ok": True, "value": self.VALUE})    # and its one place is free again
        self.assertEqual(len(failed), 1)

    def test_the_placeholder_and_the_question_outlive_a_restart_of_the_broker(self):
        self.started()
        name = fleet.vault_call({"op": "read"})["env"]["SHOP_API_KEY"]
        self.started()
        self.assertEqual(self.swap(name), {"ok": True, "value": self.VALUE})
        self.assertEqual(fleet.vault_call({"op": "read"})["env"]["SHOP_API_KEY"], name)

    def test_a_fault_in_the_swap_parts_leaves_the_key_out_and_the_broker_serves(self):
        self.started(fault="the key swap needs the proxy's own OS user")
        raw = fleet.vault_call({"op": "read"})
        self.assertEqual(raw, {"ok": True, "v": 2, "env": {}, "missing": ["SHOP_API_KEY"]})
        self.assertNotIn("swaps", fleet.vault_call({"op": "status"}))
        self.assertFalse(os.path.exists(self.swap_sock))
        # and so does a site or a token that is not in its form: never the key on a machine that swaps
        self.started()
        for bad in (dict(site="https://203.0.113.7"), dict(swap="short"), dict(form="header"), dict(site=None)):
            with self.subTest(bad=bad), patch.object(hub.Handler, "helper_vault_read", self.answering(**bad)):
                self.assertEqual(fleet.vault_call({"op": "read"})["missing"], ["SHOP_API_KEY"])

    def answering(self, **changes):
        """The hub's read route with one field of its answer changed: a hub that names a key in a wrong form."""
        def route(handler, agent):
            salts = {k: hub.fingerprint_salt(hub.fingerprint_label(test_vault.REF, k)) for k in ("password", "totp")}
            item = dict({"login": test_vault.REF, "env": "SHOP_API_KEY", "fingerprint_salts": salts,
                         "site": "https://" + HOST, "form": "bearer", "swap": "0" * 64}, **changes)
            return handler.json(200, {"ok": True, "secrets": [item]})
        return route

    def test_a_list_that_cannot_be_read_or_another_vault_user_leaves_the_key_out(self):
        (self.dir / "state" / vault.SWAPS).write_text("not a list")
        (self.dir / "state" / vault.SWAPS).chmod(0o600)
        self.started()
        self.assertEqual(fleet.vault_call({"op": "read"}), {"ok": True, "v": 2, "env": {}, "missing": ["SHOP_API_KEY"]})
        (self.dir / "state" / vault.SWAPS).unlink()
        self.started(part=dict(self.part, vault_uid=os.getuid() + 1))      # the part names another vault user
        self.assertEqual(fleet.vault_call({"op": "read"})["missing"], ["SHOP_API_KEY"])
        self.assertFalse(os.path.exists(self.swap_sock))

    def test_only_the_proxys_user_is_answered_on_the_second_socket(self):
        self.started(part=dict(self.part, uid=os.getuid() + 1))            # this test is then not the proxy's user
        name = fleet.vault_call({"op": "read"})["env"]["SHOP_API_KEY"]
        self.assertIsNone(self.swap(name))
        self.assertIsNone(self.proxy_asks(op="site", uid=os.getuid(), host=HOST, port=443))

    def test_the_proxys_side_takes_an_answer_from_the_vaults_user_only(self):
        self.started()
        name = fleet.vault_call({"op": "read"})["env"]["SHOP_API_KEY"]
        question = {"op": "swap", "uid": os.getuid(), "host": HOST, "port": 443, "name": name, "form": "bearer"}
        with open(vault.__file__, "rb") as f:
            program = hashlib.sha256(f.read()).hexdigest()
        self.assertEqual(vault.swap_ask(self.part, question), {"ok": True, "value": self.VALUE, "program": program})
        self.swap(self.programs.clear() or "vaultswap_" + "0" * 40)         # each answer names it, a refusal too
        self.proxy_asks(op="site", uid=os.getuid(), host=HOST, port=443)
        self.proxy_asks(op="read")
        self.assertEqual(self.programs, [program] * 3)
        self.assertIsNone(vault.swap_ask(dict(self.part, vault_uid=os.getuid() + 1), question))
        self.assertIsNone(vault.swap_ask(dict(self.part, broker=str(self.dir / "none.sock")), question))

    def test_the_hubs_start_text_says_what_a_placeholder_is(self):
        words = hub.key_words("vps")
        self.assertIn("SHOP_API_KEY is for api.example.com only", words)
        self.assertIn("begins with vaultswap_", words)
        self.assertIn("ask your requester", words)
        self.assertIn("SHOP_API_KEY for api.example.com", hub.key_words("vps", short=True))
        self.assertIn("API keys in this session: SHOP_API_KEY (SHOP_API_KEY is for api.example.com only",
                      "; ".join(hub.holdings_parts("vps")))
        del hub.TEAM["logins"][test_vault.REF]["site"]
        self.assertEqual((hub.key_words("vps"), hub.key_words("vps", short=True)), ("", ""))
        self.assertIn("API keys in this session: SHOP_API_KEY", "; ".join(hub.holdings_parts("vps")))


class HubRoutes(test_grants.Grants):
    """The hub's routes, with the owner API of the grants tests: the key's site and form, the read answer, and the
    question at each use."""
    SITE = "https://api.example.com"

    def label(self, **fields):
        return self.request("/ui/team/logins", dict({"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                     "base_sha256": self.team()["sha256"], "login": test_grants.KEY,
                                                     "title": "OPENAI_API_KEY"}, **fields))

    def asks(self, agent="alpha", source=None, token=None, **body):
        headers = dict({"Content-Type": "application/json"}, **({"Authorization": "Bearer " + token} if token else {}))
        return self.request(f"/helper/vault/{agent}/swap", body, headers=headers, source=source or hub.address_of(agent))

    def test_the_owner_gives_a_key_its_site_and_form_and_takes_them_away(self):
        code, receipt = self.label(site=self.SITE + "/v1", form="basic-user")
        self.assertEqual((code, receipt["changed"], receipt["swap_site"]), (200, True, self.SITE), receipt)
        self.assertEqual(self.committed()["logins"][test_grants.KEY],
                         {"title": "OPENAI_API_KEY", "kind": "api_key", "env": "OPENAI_API_KEY", "site": self.SITE + "/v1",
                          "form": "basic-user"})
        self.assertEqual(self.label()[1]["changed"], False)                 # a title alone keeps both
        self.assertEqual(self.label(form="")[0], 200)                       # an empty one takes it away
        self.assertNotIn("form", self.committed()["logins"][test_grants.KEY])
        self.assertEqual(self.label(site="")[0], 200)
        self.assertEqual(self.committed()["logins"][test_grants.KEY],
                         {"title": "OPENAI_API_KEY", "kind": "api_key", "env": "OPENAI_API_KEY"})
        code, receipt = self.label(site="https://203.0.113.7")              # a site of the catalog that cannot swap
        self.assertEqual((code, receipt["swap_site"]), (200, None), receipt)
        self.assertEqual(self.label(site="")[0], 200)
        for bad in (dict(form="header"), dict(form="Bearer"), dict(site="http://api.example.com"), dict(site="api.example.com")):
            with self.subTest(bad=bad):
                self.assertEqual(self.label(**bad)[0], 400)
        code, answer = self.request("/ui/team/logins", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                            base_sha256=self.team()["sha256"], login=test_grants.LOGIN,
                                                            title="shop.test · admin", form="bearer"))
        self.assertEqual(code, 400, answer)                                 # only an API key has a form

    def test_a_secret_that_is_saved_again_keeps_its_site_and_form(self):
        self.assertEqual(self.label(site=self.SITE, form="token")[0], 200)
        code, receipt = self.add(login=test_grants.KEY, title="OPENAI_API_KEY", kind="api_key", env="OPENAI_API_KEY",
                                 fingerprints=self.prints(test_grants.KEY))
        self.assertEqual(code, 200, receipt)
        self.assertEqual(self.committed()["logins"][test_grants.KEY],
                         {"title": "OPENAI_API_KEY", "kind": "api_key", "env": "OPENAI_API_KEY", "site": self.SITE,
                          "form": "token"})

    def test_the_read_answer_names_site_form_and_token_and_the_question_is_answered_from_the_team_now(self):
        self.assertEqual(self.grant(test_grants.KEY, "alpha", "read")[0], 200)
        code, answer = self.vault_call("alpha", "read", {})
        self.assertEqual(set(answer["secrets"][0]), {"login", "env", "fingerprint_salts"})     # no site: as before
        self.assertEqual(self.label(site=self.SITE + "/v1")[0], 200)
        code, answer = self.vault_call("alpha", "read", {})
        key = answer["secrets"][0]
        self.assertEqual((key["site"], key["form"]), (self.SITE, "bearer"))
        self.assertRegex(key["swap"], r"^[0-9a-f]{64}$")
        self.assertEqual(self.vault_call("alpha", "read", {})[1]["secrets"][0]["swap"], key["swap"])   # the same each time
        asked = dict(login=test_grants.KEY, site=self.SITE, form="bearer", swap=key["swap"])
        self.assertEqual(self.asks(**asked), (200, {"ok": True, "login": test_grants.KEY, "user": "fleet-alpha"}))
        with patch.dict(hub.agents()["alpha"], {"user": "fleet-first-name"}):     # the user that it kept after a rename
            self.assertEqual(self.asks(**asked)[1]["user"], "fleet-first-name")
        for role in ("lead", "manager"):                    # each agent of a server has its OS user by the same rule
            with self.subTest(role=role), patch.dict(hub.agents()["alpha"], {"role": role}):
                self.assertEqual(self.asks(**asked), (200, {"ok": True, "login": test_grants.KEY, "user": "fleet-alpha"}))
        for why, changes in (("another token", dict(swap="0" * 64)), ("another site", dict(site="https://files.example.com")),
                             ("another form", dict(form="token")), ("another key", dict(login=test_grants.NEW))):
            with self.subTest(why):
                self.assertEqual(self.asks(**dict(asked, **changes))[0], 409)
        self.assertEqual(self.asks(**{k: v for k, v in asked.items() if k != "swap"})[0], 400)
        self.assertEqual(self.asks(source="127.0.0.9", **asked)[0], 403)    # not the agent's machine
        self.assertEqual(self.asks(agent="beta", **asked)[0], 409)          # another agent of the same machine: not its token
        self.assertEqual(self.asks(agent="nobody", **asked)[0], 404)
        with patch.dict(hub.agents()["alpha"], {"vault": "none"}):          # an agent with no credential access
            self.assertEqual(self.asks(**asked)[0], 409)
        self.assertEqual(self.grant(test_grants.KEY, "beta", "read")[0], 200)       # beta reads the key too:
        self.assertEqual(self.asks(agent="beta", **asked)[0], 409)          # a token is of one agent
        mine = hub.swap_token("beta", test_grants.KEY)
        self.assertNotEqual(mine, key["swap"])
        self.assertEqual(self.asks(agent="beta", **dict(asked, swap=mine))[0], 200)
        self.assertEqual(self.grant(test_grants.KEY, "beta", None)[0], 200)
        self.assertEqual(self.asks(token="alpha", **asked)[0], 200)        # the route asks for no key; the right one passes
        code, said = self.asks(token="beta", **asked)                       # and a wrong one is refused, never taken as none
        self.assertEqual((code, said.get("auth")), (403, "key_mismatch"))
        before = self.commits()
        self.assertEqual(self.grant(test_grants.KEY, "alpha", None)[0], 200)        # the owner ends the grant
        self.assertEqual(self.asks(**asked)[0], 409)
        self.assertEqual(self.grant(test_grants.KEY, "alpha", "read")[0], 200)
        self.assertEqual(self.asks(**asked)[0], 200)
        self.assertEqual(self.label(site="")[0], 200)                       # or takes the site away
        self.assertEqual(self.asks(**asked)[0], 409)
        self.assertEqual(self.commits(), before + 3)                        # the questions wrote nothing

    def test_a_refused_use_gets_a_line_in_the_hubs_log_and_a_question_after_a_delivery_gets_none(self):
        self.assertEqual(self.grant(test_grants.KEY, "alpha", "read")[0], 200)
        self.assertEqual(self.label(site=self.SITE)[0], 200)
        asked = dict(login=test_grants.KEY, site=self.SITE, form="bearer", swap=hub.swap_token("alpha", test_grants.KEY))
        self.assertEqual(self.asks(use=False, **asked)[0], 200)             # the answer is the same one
        self.assertEqual(self.grant(test_grants.KEY, "alpha", None)[0], 200)
        lines, real = [], hub.log

        def log(who, text, *more, **named):
            lines.append((who, text))
            return real(who, text, *more, **named)
        with patch.object(hub, "log", log):
            self.assertEqual(self.asks(use=False, **asked)[0], 409)
            self.assertEqual([text for _, text in lines if "key swap" in text], [])
            for use in ({}, {"use": True}, {"use": None}, {"use": 0}, {"use": "false"}):    # only false itself
                lines.clear()
                self.assertEqual(self.asks(**dict(asked, **use))[0], 409)
                self.assertEqual([who for who, text in lines if text.startswith("REFUSED a key swap: alpha")], ["alpha"], use)


class Fact(test_grants.Grants):
    """The owner's word that the vault of a server swaps keys: `"key_swap": true` in the server's entry of team.json,
    the owner's route that writes it, and the three readers that say what is so by it. The agent alpha is on the
    Linux server box. It reads two keys, one with a site and one with none, and it has a shell and the web."""
    SITE = "https://" + HOST
    KEY, BARE = test_grants.KEY, test_grants.NEW            # OPENAI_API_KEY with a site, SHOP_API_KEY with none

    def setUp(self):
        team = json.loads(json.dumps(test_grants.TEAM))
        team["servers"] = {"box": {"kind": "linux", "user": "fleet"}, "lone": {"kind": "mac", "user": "fleet"}}
        team["logins"][self.KEY]["site"] = self.SITE
        team["logins"][self.BARE] = {"title": "SHOP_API_KEY", "kind": "api_key", "env": "SHOP_API_KEY"}
        team["agents"]["alpha"].update(can=["shell", "web"], title="Developer",
                                       secrets={self.KEY: "read", self.BARE: "read"})
        with patch.object(test_grants, "TEAM", team):
            super().setUp()

    def says(self, server, on, **more):
        body = dict({"request_id": str(uuid.uuid4()), "db": "test-generation", "base_sha256": self.team()["sha256"],
                     "on": on}, **more)
        return self.request(f"/ui/servers/{server}/key-swap", body)

    def test_the_owner_says_that_the_vault_of_a_server_swaps_keys_and_takes_the_word_back(self):
        before = self.commits()
        code, receipt = self.says("box", True)
        self.assertEqual((code, receipt.get("server"), receipt.get("key_swap"), receipt.get("changed")),
                         (200, "box", True, True), receipt)
        self.assertEqual(self.committed()["servers"]["box"], {"kind": "linux", "user": "fleet", "key_swap": True})
        self.assertEqual((receipt["sha256"], self.commits()), (self.team()["sha256"], before + 1))
        code, receipt = self.says("box", True)                              # the same word again: nothing is written
        self.assertEqual((code, receipt["key_swap"], receipt["changed"], self.commits()), (200, True, False, before + 1))
        code, receipt = self.says("box", False)                             # and it takes the word back
        self.assertEqual((code, receipt["key_swap"], receipt["changed"]), (200, False, True), receipt)
        self.assertEqual(self.committed()["servers"]["box"], {"kind": "linux", "user": "fleet"})
        self.assertEqual((self.says("box", False)[1]["changed"], self.commits()), (False, before + 2))
        # a field in another form, in a team.json that the hub started with: the take-back removes it too
        team = self.committed()
        team["servers"]["box"]["key_swap"] = "yes"
        written = []
        commit = lambda path, data, why: written.append(json.loads(data)) or "c" * 40
        with patch.object(hub, "team_view", lambda rev: (team, "a" * 64, None)), \
                patch.object(hub, "commit_kit_file", commit), patch.object(hub, "apply_team", lambda new: None):
            receipt = hub.server_key_swap("box", {"on": False, "base_sha256": "a" * 64})
        self.assertEqual((receipt["changed"], receipt["key_swap"]), (True, False))
        self.assertEqual(written[0]["servers"]["box"], {"kind": "linux", "user": "fleet"})

    def test_the_word_is_for_a_linux_server_of_the_fleet_and_only_the_owner_gives_it(self):
        before = self.commits()
        code, said = self.says("lone", True)
        self.assertEqual((code, said["error"]), (409, "The key swap is for a Linux server."))
        for server in ("files", "hub", "nowhere", "owner"):                 # machines that are no joined server
            with self.subTest(server):
                self.assertEqual(self.says(server, True)[0], 404)
        for bad in ("yes", 1, 0, None, [True]):
            with self.subTest(on=bad):
                self.assertEqual(self.says("box", bad)[0], 400)
        self.assertEqual(self.says("box", True, base_sha256="0" * 64)[0], 409)      # another team.json than he read
        self.assertEqual(self.says("box", True, base_sha256="short")[0], 400)
        # no report and no request of a machine writes it: the route is the owner's
        body = {"request_id": str(uuid.uuid4()), "db": "test-generation", "base_sha256": self.team()["sha256"], "on": True}
        code, _ = self.request("/ui/servers/box/key-swap", body, source=hub.address_of("alpha"))
        self.assertEqual(code, 403)
        self.assertEqual(self.commits(), before)
        self.assertNotIn("key_swap", self.committed()["servers"]["box"])
        # team.json takes the field only as true, and only for a Linux server
        team = self.committed()
        for server, value in (("box", False), ("box", "yes"), ("box", 1), ("box", None), ("lone", True)):
            with self.subTest(server=server, value=value):
                changed = json.loads(json.dumps(team))
                changed["servers"][server]["key_swap"] = value
                with self.assertRaisesRegex(ValueError, "key_swap"):
                    hub.validate_team(changed)
        team["servers"]["box"]["key_swap"] = True
        hub.validate_team(team)

    def test_a_key_that_swaps_there_is_no_key_in_the_agents_sessions(self):
        """hub.session_keys, the one answer to "do this agent's sessions hold the value of a key"."""
        self.assertEqual(hub.session_keys("alpha"), ["OPENAI_API_KEY", "SHOP_API_KEY"])
        self.assertIsNone(hub.key_swaps("alpha", self.KEY))                 # the rule holds, the owner's word is not there
        self.assertEqual(hub.key_swap("alpha", self.KEY), (self.SITE, "bearer"))
        before = self.vault_call("alpha", "read", {})
        self.assertEqual(self.says("box", True)[0], 200)
        self.assertEqual(hub.key_swaps("alpha", self.KEY), (self.SITE, "bearer"))
        self.assertIsNone(hub.key_swaps("alpha", self.BARE))                # a key with no site is a value there too
        self.assertEqual(hub.session_keys("alpha"), ["SHOP_API_KEY"])
        # the session still gets both variables by name (one holds a placeholder), and what the hub tells a vault
        # is the same with the word and without it: each vault decides by its own configuration
        after = self.vault_call("alpha", "read", {})
        self.assertEqual(after, before)
        self.assertEqual([x["env"] for x in after[1]["secrets"]], ["OPENAI_API_KEY", "SHOP_API_KEY"])
        asked = dict(login=self.KEY, site=self.SITE, form="bearer", swap=hub.swap_token("alpha", self.KEY))
        self.assertEqual(self.request("/helper/vault/alpha/swap", asked, source=hub.address_of("alpha"),
                                      headers={"Content-Type": "application/json"})[0], 200)
        # each part of the rule is still needed: a use grant, another runtime, an agent of another server
        with patch.dict(hub.agents()["alpha"], {"secrets": {self.KEY: "use", self.BARE: "read"}}):
            self.assertEqual((hub.key_swaps("alpha", self.KEY), hub.session_keys("alpha")), (None, ["SHOP_API_KEY"]))
        with patch.dict(hub.agents()["alpha"], {"runtime": "opencode"}):
            self.assertEqual(hub.session_keys("alpha"), ["OPENAI_API_KEY", "SHOP_API_KEY"])
        with patch.dict(hub.agents()["alpha"], {"machine": "files"}):
            self.assertEqual(hub.session_keys("alpha"), ["OPENAI_API_KEY", "SHOP_API_KEY"])
        self.assertIsNone(hub.key_swaps("nobody", self.KEY))
        self.assertEqual(self.says("box", False)[0], 200)
        self.assertEqual(hub.session_keys("alpha"), ["OPENAI_API_KEY", "SHOP_API_KEY"])

    def findings(self):
        return [dict(r) for r in hub.q("SELECT id, text, decided, note FROM reports WHERE from_agent='hub' ORDER BY id")]

    def test_the_settings_check_counts_only_the_keys_that_are_values_and_says_which_are_placeholders(self):
        hub.settings_check()
        (first,) = self.findings()
        self.assertTrue(first["text"].startswith(
            "Developer reads 2 API keys in its sessions (OPENAI_API_KEY, SHOP_API_KEY), and it has a shell and the web "
            "(Tools: Shell, Web). A text from outside, a web page for example, can then make it send a key"), first["text"])
        self.assertNotIn("placeholder", first["text"])
        self.assertEqual(self.says("box", True)[0], 200)                    # the hub checks the settings at each change
        old, new = self.findings()
        self.assertEqual((old["id"], old["note"]), (first["id"], f"The settings changed. UP-{new['id']} replaces this finding."))
        self.assertTrue(new["text"].startswith(
            "Developer reads 1 API key in its sessions (SHOP_API_KEY), and it has a shell and the web (Tools: Shell, "
            "Web). 1 more key is not in its sessions: the vault of its server swaps it, so a session holds a "
            "placeholder (OPENAI_API_KEY). A text from outside, a web page for example, can then make it send a key "
            "to another place."), new["text"])
        self.assertIsNone(new["decided"])
        self.assertEqual(json.loads(hub.kv_get("settings_finding:alpha"))["keys"], ["SHOP_API_KEY"])
        # each key swaps: the three are no longer together, and the open finding ends
        with patch.dict(hub.logins()[self.BARE], {"site": "https://" + OTHER_HOST}):
            self.assertEqual((hub.session_keys("alpha"), hub.settings_junction("alpha")), ([], None))
            hub.settings_check()
            self.assertEqual([f["note"] for f in self.findings()][-1],
                             "The settings changed: what this finding says is no longer there.")
            self.assertIsNone(hub.kv_get("settings_finding:alpha"))

    def test_the_finding_names_two_placeholders_and_counts_the_rest_and_stays_inside_one_report(self):
        self.assertEqual(self.says("box", True)[0], 200)
        catalog, grants = hub.logins(), hub.agents()["alpha"]["secrets"]
        with patch.dict(hub.agents()["alpha"], {"title": "R" * 60}):
            for n in range(40):                                             # the longest names that team.json takes
                ref = f"bws://11111111-2222-4333-8444-5555555555{n:02d}"
                catalog[ref] = {"title": f"K{n:02d}", "kind": "api_key", "env": f"K{n:02d}_" + "A" * 56}
                if n >= 36:
                    catalog[ref]["site"] = f"https://s{n}.example.com"
                grants[ref] = "read"
            keys, boxes = hub.settings_junction("alpha")
            text = hub.settings_words("alpha", keys, boxes)
            self.assertEqual(len(keys), 37)                                 # 36 of these and SHOP_API_KEY are values
            # With the longest role and key names, two names of the placeholders still fit into one report, since
            # the finding gives only the options that fit its keys (13 November 2026). The form with their number
            # alone is for a longer finding: test_settings_check.Finding holds it.
            placed = sorted(f"K{n:02d}_" + "A" * 56 for n in range(36, 40)) + ["OPENAI_API_KEY"]
            self.assertIn(f" 5 more keys are not in its sessions: the vault of its server swaps them, so a session "
                          f"holds a placeholder ({placed[0]}, {placed[1]} and 3 more). A text from outside", text)
            self.assertLessEqual(len(text), hub.REPORT_TEXT_MAX)
            self.assertEqual(text, " ".join(text.split()))
        with patch.dict(hub.agents()["alpha"], {"title": "Developer"}):     # with a shorter role they fit: two names
            keys, boxes = hub.settings_junction("alpha")
            text = hub.settings_words("alpha", keys, boxes)
            placed = sorted(f"K{n:02d}_" + "A" * 56 for n in range(36, 40)) + ["OPENAI_API_KEY"]
            self.assertIn(f" 5 more keys are not in its sessions: the vault of its server swaps them, so a session "
                          f"holds a placeholder ({placed[0]}, {placed[1]} and 3 more). A text from outside", text)
            self.assertLessEqual(len(text), hub.REPORT_TEXT_MAX)

    def test_a_start_text_says_that_the_variable_holds_a_placeholder_on_such_a_server(self):
        words = (hub.key_words("alpha"), hub.key_words("alpha", short=True))
        self.assertEqual(words[0], " (OPENAI_API_KEY is for api.example.com only: when its value begins with "
                                   "vaultswap_, it is a placeholder, and this machine's vault puts the key into the "
                                   "Authorization header of an HTTPS request to that host, and nowhere else; a program "
                                   "that needs the key itself does not work with a placeholder, so ask your requester "
                                   "then, and do not look for the key)")
        self.assertEqual(words[1], " (a placeholder when its value begins with vaultswap_: OPENAI_API_KEY for "
                                   "api.example.com)")
        self.assertEqual(self.says("box", True)[0], 200)
        self.assertEqual(hub.key_words("alpha"),
                         " (OPENAI_API_KEY is for api.example.com only: the variable holds a placeholder, which begins "
                         "with vaultswap_, and not the key, and this machine's vault puts the key into the "
                         "Authorization header of an HTTPS request to that host, and nowhere else; a program that "
                         "needs the key itself does not work with a placeholder, so ask your requester then, and do "
                         "not look for the key)")
        self.assertEqual(hub.key_words("alpha", short=True),
                         " (a placeholder, which begins with vaultswap_, and not the key: OPENAI_API_KEY for "
                         "api.example.com)")
        self.assertIn("API keys in this session: OPENAI_API_KEY, SHOP_API_KEY (OPENAI_API_KEY is for api.example.com "
                      "only: the variable holds a placeholder, which begins with vaultswap_, and not the key,",
                      " ".join(hub.holdings_parts("alpha")))
        with patch.dict(hub.agents()["alpha"], {"secrets": {self.BARE: "read"}}):   # no key of it has a site
            self.assertEqual(hub.key_words("alpha"), "")
        # an agent whose sessions get no variable (no vault access, or its Shell box is off) reads no sentence that
        # says what the variable holds: the words of before, which say "when"
        for changed in ({"vault": "none"}, {"can": ["web"]}):
            with self.subTest(changed=changed), patch.dict(hub.agents()["alpha"], changed):
                self.assertEqual((hub.key_words("alpha"), hub.key_words("alpha", short=True)), words)
        self.assertEqual(self.says("box", False)[0], 200)
        self.assertEqual((hub.key_words("alpha"), hub.key_words("alpha", short=True)), words)

    def test_the_owners_tool_sends_the_word_to_the_route(self):
        found = {t["name"]: t for t in owner_mcp.tools()}["server_key_swap"]
        self.assertEqual((found["inputSchema"]["required"], sorted(found["inputSchema"]["properties"])),
                         (["server", "on"], ["on", "request_id", "server"]))
        self.assertIn("after root ran `hubsetup.py vault --swap`", found["description"])
        sent = []
        with patch.object(owner_mcp, "team", lambda: {"sha256": "a" * 64}), \
                patch.object(owner_mcp, "command", lambda route, body, what, rid=None: sent.append((route, body))):
            found["run"]({"server": "box", "on": True})
            found["run"]({"server": "box", "on": False})                    # false is a word too, not a field left out
        self.assertEqual(sent, [("/ui/servers/box/key-swap", {"on": True, "base_sha256": "a" * 64}),
                                ("/ui/servers/box/key-swap", {"on": False, "base_sha256": "a" * 64})])


def proxy_asks(path, **request):
    """One question of the proxy on a broker's second socket: the answer, without the broker's program."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(30)
        s.connect(path)
        s.sendall((json.dumps(request) + "\n").encode())
        data = b""
        while not data.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    said = json.loads(data)
    said.pop("program", None)
    return said


@unittest.skipUnless(test_central_e2e.AGE and test_central_e2e.KEYGEN, "the real age program is not installed")
class Delivery(test_central_e2e.EndToEnd):
    """The hub's take-back and delivery of a key's value on a machine that swaps keys, with the pieces of the central
    vault's end-to-end test: the hub's reconciler and routes, the real age program and fleet.py's own helper code.
    The broker of vps has the part "swap". No agent reads its keys between the take-back and the delivery."""
    SITE = "https://" + HOST

    def setUp(self):
        def facts(conf):                # the machine's users are stand-ins, as in BrokerPart
            return dict(conf[vault.SWAP_KEY], uid=os.getuid(), vault_uid=os.getuid(), group="fleet-agents",
                        broker=os.path.join(os.path.dirname(conf["socket"]), "vps-" + vault.SWAP_SOCKET))
        # this test's own user stands in for the OS user of the agent vps, as the hub names it; two more users of
        # this computer stand in for the OS user of studio, and for a user that had the name vps before a rename
        users, real = {os.getuid(): "fleet-vps", 0: "fleet-studio", 1: "fleet-first-vps"}, vault.swap_user
        for patched in (patch.object(vault, "swap_part", facts), patch.object(vault, "log", lambda text: None),
                        patch.object(vault, "swap_user", lambda uid: users.get(uid) or real(uid))):
            patched.start()
            self.addCleanup(patched.stop)
        super().setUp()
        self.server.machines = True     # each request comes from the machine that its route names
        self.swaps = self.brokers["vps"].conf["_swaps"]
        self.add_and_give("vps")
        self.give("vps", "read")
        code, said = self.request("/ui/team/logins", self.cmd(base_sha256=self.request("/ui/team?db=test-generation")[1]["sha256"],
                                                             login=test_central_e2e.KEY_REF, title="SHOP_API_KEY",
                                                             site=self.SITE))
        self.assertEqual((code, said.get("swap_site")), (200, self.SITE), said)
        self.pass_once()
        self.assertEqual(self.held("vps"), {test_central_e2e.KEY_REF: test_central_e2e.VALUE})
        self.name = self.read()["env"]["SHOP_API_KEY"]
        self.assertRegex(self.name, r"^vaultswap_[0-9a-f]{40}$")

    def broker(self, machine):
        public = super().broker(machine)
        if machine == "vps":            # the same broker again, with the part "swap"
            conf = dict(self.brokers[machine].conf, swap=dict(BrokerPart.PART))
            self.brokers[machine].close()
            self.brokers[machine] = self.serve(conf)
        return public

    def read(self):
        """The agent's read of its keys, as the helper makes it at the start of a session."""
        with patch.object(fleet, "vault_socket", lambda: self.brokers["vps"].conf["socket"]):
            return fleet.broker_job_request("vps", {"op": "read", "for": "session"})

    def asks(self, **request):
        return proxy_asks(self.brokers["vps"].conf["_swap"]["broker"], **request)

    def opens(self):
        return self.asks(op="site", uid=os.getuid(), host=HOST, port=443)["site"]

    def use(self):
        return self.asks(op="swap", uid=os.getuid(), host=HOST, port=443, name=self.name, form="bearer")

    def off(self):
        """The placeholders that are off. One form of off, and a list that a broker reads at its start (BrokerPart)."""
        entries = self.swaps.entries
        self.assertEqual([e["off"] for e in entries.values() if "off" in e and e["off"] is not True], [])
        self.assertEqual(vault.Swaps(self.swaps.path).entries, entries)
        return {name for name, e in entries.items() if e.get("off")}

    def token(self, token):
        """Give this agent's entry another token, as a read of its keys does."""
        self.swaps.keep(dict(self.swaps.entries, **{self.name: dict(self.swaps.entries[self.name], token=token)}))

    def ended(self, table):
        """How the hub's newest delivery or withdrawal ended: 1 when the broker's step ended well."""
        return hub.q1(f"SELECT ok FROM {table} ORDER BY id DESC LIMIT 1")["ok"]

    def test_a_take_back_switches_each_placeholder_of_the_key_off_and_a_delivery_switches_a_live_one_on(self):
        value = test_central_e2e.VALUE["password"]
        # a placeholder of another OS user and agent for the same key, from a grant that it has no more
        other = self.swaps.place(0, "studio", test_central_e2e.KEY_REF, HOST, 443, "bearer",
                                 hub.swap_token("studio", test_central_e2e.KEY_REF))
        # and a placeholder of another key, which the hub does not take back
        kept = self.swaps.place(os.getuid(), "vps", "bws://" + test_vault.THIRD_ID, OTHER_HOST, 443, "bearer", "3" * 64)
        self.assertEqual((self.opens(), self.use(), self.off()), (True, {"ok": True, "value": value}, set()))
        self.assertIs(self.swaps.site(0, HOST, 443), True)
        self.give("vps", None)                                              # the owner ends the grant
        self.pass_once()                                                    # the hub takes the value back
        self.assertEqual(self.held("vps"), {})
        self.assertEqual(self.off(), {self.name, other})                    # off for each user, with no read and no use
        self.assertEqual((self.opens(), self.swaps.site(0, HOST, 443)), (False, False))
        self.assertIs(self.swaps.site(os.getuid(), OTHER_HOST, 443), True)  # the other key's placeholder is as it was
        self.assertNotIn(kept, self.off())
        with patch.object(vault, "hub", side_effect=AssertionError("the hub was asked")):
            self.assertEqual(self.use(), {"ok": False, "code": "refused"})
        self.give("vps", "read")                                            # the owner gives it again
        lines, real = [], hub.log

        def log(who, text, *more, **named):
            lines.append(text)
            return real(who, text, *more, **named)
        with patch.object(hub, "log", log):
            self.pass_once()                                                # the hub delivers the value
        self.assertEqual(self.held("vps"), {test_central_e2e.KEY_REF: test_central_e2e.VALUE})
        self.assertEqual(self.off(), {other})                               # on again: the hub calls it live. The other
        self.assertEqual((self.opens(), self.swaps.site(0, HOST, 443)), (True, False))     # agent holds no grant
        self.assertEqual(self.use(), {"ok": True, "value": value})          # a session that still runs has its key again
        self.assertEqual([text for text in lines if "REFUSED a key swap" in text], [])     # no line of a refused use
        self.assertEqual(self.read()["env"]["SHOP_API_KEY"], self.name)     # and its next read gives the same one

    def test_a_replaced_value_keeps_its_placeholder_and_the_next_request_carries_the_new_value(self):
        """The owner replaces the value of the key in Add secret (owner feature secret_replace). The list of
        placeholders is not touched: a session that runs keeps its placeholder, and the proxy's next question for it
        gets the new value, because the broker reads its store at each use."""
        old, new = test_central_e2e.VALUE["password"], test_central_e2e.NEW["password"]
        self.assertEqual(self.use(), {"ok": True, "value": old})
        entries = json.dumps(self.swaps.entries, sort_keys=True)
        code, body = self.replace()
        self.assertEqual((code, body["saved"]), (200, "replaced"), body)
        self.assertEqual(hub.logins()[test_central_e2e.KEY_REF]["site"], self.SITE)     # the key's site stays
        self.assertEqual(self.use(), {"ok": True, "value": old})            # until the delivery lands: the old value
        self.pass_once()                                                    # the hub delivers the new value
        self.assertEqual(self.held("vps"), {test_central_e2e.KEY_REF: test_central_e2e.NEW})
        self.assertEqual(self.ended("deposits"), 1)
        self.assertEqual(self.off(), set())                                 # no placeholder went off in between
        self.assertEqual(json.dumps(self.swaps.entries, sort_keys=True), entries)
        self.assertEqual((self.opens(), self.use()), (True, {"ok": True, "value": new}))   # the next request
        self.assertEqual(self.read()["env"]["SHOP_API_KEY"], self.name)     # and the next read: the same placeholder
        self.assertNotIn(old, self.stores())

    def test_a_name_that_changed_hands_opens_nothing_for_the_os_user_that_had_it_before(self):
        """The owner renames an agent, which keeps its OS user, and gives its old name to another agent of the same
        server. The hub's yes is for the name; the list's entry is for an OS user. The first holder's placeholder
        gets no key at a use, and no delivery switches it on."""
        token = hub.swap_token("vps", test_central_e2e.KEY_REF)
        first = self.swaps.place(1, "vps", test_central_e2e.KEY_REF, HOST, 443, "bearer", token)   # from before the rename
        asked = dict(op="swap", uid=1, host=HOST, port=443, name=first, form="bearer")
        self.assertEqual(self.swaps.get(first)["user"], "fleet-first-vps")
        self.assertIs(self.swaps.site(1, HOST, 443), True)                  # still on: its user made no read since
        said = []
        with patch.object(vault, "log", said.append):
            self.assertEqual(self.asks(**asked), {"ok": False, "code": "refused"})  # the hub says yes for the name vps
        self.assertEqual(self.off(), {first})                               # and that is a no for this OS user
        self.assertEqual([line for line in said if "another OS user" in line],     # the broker's log says why
                         ["swap: the hub names another OS user for the agent vps than fleet-first-vps, whose "
                          "placeholder this is: the name is another agent's now"])
        self.assertEqual(self.use(), {"ok": True, "value": test_central_e2e.VALUE["password"]})    # the holder of now
        self.give("vps", None)
        self.pass_once()
        self.give("vps", "read")
        self.pass_once()                                                    # a take-back and a delivery
        self.assertEqual(self.off(), {first})                               # its own entry is on again, this one is not
        self.assertEqual((self.opens(), self.swaps.site(1, HOST, 443)), (True, False))
        self.assertEqual(self.asks(**asked), {"ok": False, "code": "refused"})

    def test_a_delivery_switches_nothing_on_when_the_hub_does_not_call_it_live_or_does_not_answer(self):
        self.give("vps", None)
        self.pass_once()
        self.assertEqual(self.off(), {self.name})
        self.give("vps", "read")
        real = vault.swap_asks
        for said in ((409, False), (409, True), (404, False), (403, False), (500, False), (0, False), (None, False),
                     (200, False)):                     # the last one: a hub from before it named the agent's OS user
            with self.subTest(said=said):
                with patch.object(vault, "swap_asks", lambda conf, entry, use=True: said):
                    vault.swap_given(self.brokers["vps"].conf, test_central_e2e.KEY_REF)
                self.assertEqual(self.off(), {self.name})
        # a hub that does not answer is asked one time, whatever the number of entries: the broker holds its lock
        more = self.swaps.place(0, "studio", test_central_e2e.KEY_REF, HOST, 443, "bearer", "2" * 64)
        self.swaps.taken(test_central_e2e.KEY_REF)
        silent = []
        with patch.object(vault, "swap_asks", lambda conf, entry, use=True: silent.append(entry["agent"]) or (None, False)):
            vault.swap_given(self.brokers["vps"].conf, test_central_e2e.KEY_REF)
        self.assertEqual((len(silent), self.off()), (1, {self.name, more}))
        # a fault of this part is no fault of the delivery
        with patch.object(vault, "swap_asks", side_effect=ZeroDivisionError):
            vault.swap_given(self.brokers["vps"].conf, test_central_e2e.KEY_REF)
        self.assertEqual(self.off(), {self.name, more})
        self.swaps.keep({name: e for name, e in self.swaps.entries.items() if name != more})
        asked = []

        def asks(conf, entry, use=True):
            asked.append((entry["agent"], use))
            return real(conf, entry, use)
        # the entry changed while the hub was asked (the agent's read gave it another token): not switched on here
        def changed(conf, entry, use=True):
            self.token("1" * 64)
            return 200, True
        with patch.object(vault, "swap_asks", changed):
            vault.swap_given(self.brokers["vps"].conf, test_central_e2e.KEY_REF)
        self.assertEqual(self.off(), {self.name})
        self.token(hub.swap_token("vps", test_central_e2e.KEY_REF))
        vault.swap_given(self.brokers["vps"].conf, "bws://" + "0" * 8 + "-0000-4000-8000-" + "0" * 12)     # another key
        self.assertEqual(self.off(), {self.name})
        with patch.object(vault, "swap_asks", asks):
            self.pass_once()                                                # the real delivery
        self.assertEqual((asked, self.off()), ([("vps", False)], set()))    # one question, marked as no use
        with patch.object(vault, "swap_asks", asks):
            vault.swap_given(self.brokers["vps"].conf, test_central_e2e.KEY_REF)
        self.assertEqual(len(asked), 1)                                     # nothing is off: no question

    def test_a_list_that_cannot_be_written_stops_no_take_back_and_no_delivery(self):
        self.give("vps", None)
        with patch.object(vault.Swaps, "keep", side_effect=vault.Refused("the vault could not keep its list")):
            self.pass_once()
        self.assertEqual((self.held("vps"), self.off()), ({}, set()))       # the value left; the entry is as it was
        self.assertEqual(self.ended("withdrawals"), 1)                      # and the hub heard that the step ended well
        self.assertEqual(self.use(), {"ok": False, "code": "refused"})      # and a use gets the hub's no, which
        self.assertEqual(self.off(), {self.name})                           # switches it off
        self.give("vps", "read")
        with patch.object(vault.Swaps, "keep", side_effect=vault.Refused("the vault could not keep its list")):
            self.pass_once()
        self.assertEqual(self.held("vps"), {test_central_e2e.KEY_REF: test_central_e2e.VALUE})
        self.assertEqual(self.ended("deposits"), 1)
        self.assertEqual(self.off(), {self.name})                           # still off: the agent's next read
        self.assertEqual(self.read()["env"]["SHOP_API_KEY"], self.name)
        self.assertEqual((self.off(), self.use().get("value")), (set(), test_central_e2e.VALUE["password"]))


class Machine:
    """The machine that the installer's swap step works on: it answers the step's one reading, records each script,
    and carries out the few effects that the step then reads."""
    UNIT = "[Unit]\nAfter=fleet-vault.service\n[Service]\nUser=founderizer-swap\nExecStart=/usr/bin/python3 x swap\nNotifyAccess=all\n"

    def __init__(self, conf, **state):
        self.conf, self.ran, self.knows, self.proxy_stays, self.broker_stays = conf, [], True, True, True
        self.state = dict({"user": "no", "low": "1024", "unit": "", "broker": "active", "broker_restarts": "0",
                           "active": "inactive", "restarts": "0"}, **state)

    def read(self, path):
        if path != hubsetup.VAULT_CONF or self.conf is None:
            raise OSError(path)
        return json.dumps(self.conf)

    def run(self, script, timeout=120):
        self.ran.append(script)
        if "echo active=" in script:
            return 0, "\n".join(f"{k}={v}" for k, v in self.state.items()), ""
        if "vault.py unit --swap" in script:
            return (0, self.UNIT, "") if self.knows else (2, "", "vault.py: error: unrecognized arguments: --swap")
        if "useradd --system" in script:
            self.state["user"] = "yes"
        for line in script.splitlines():
            if line.startswith("install ") and line.endswith(hubsetup.VAULT_CONF):
                self.conf = json.loads(Path(line.split()[-2]).read_text())
                self.state.update(broker="active" if self.broker_stays or "swap" not in self.conf else "activating",
                                  broker_restarts="0" if self.broker_stays or "swap" not in self.conf else "3")
            if line.startswith("install ") and line.endswith(hubsetup.SWAP_UNIT):
                self.state["unit"] = hashlib.sha256(Path(line.split()[-2]).read_bytes()).hexdigest()
            if line == "systemctl restart " + hubsetup.SWAP_SERVICE:
                self.state.update(active="active" if self.proxy_stays else "activating",
                                  restarts="0" if self.proxy_stays else "4")
        return 0, "", ""

    def changes(self):
        return [s for s in self.ran if "echo active=" not in s and "unit --swap" not in s]


class Installer(unittest.TestCase):
    BROKER = {"hub": "http://100.80.1.2:8765", "store": "/var/lib/fleet-vault/store.age",
              "store_key": "/var/lib/fleet-vault/store.key", "age_key": "/var/lib/fleet-vault/age.key",
              "socket": "/run/fleet-vault/vault.sock", "age": "/usr/bin/age", "curl": "/usr/bin/curl",
              "worker_group": "fleet-agents"}
    PART = {"user": "founderizer-swap", "vault": "fleet-vault", "port": 876, "openssl": "/usr/bin/openssl"}

    def install(self, machine, check=False):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            return hubsetup.swap_install(check=check, run=machine.run, read=machine.read), out.getvalue()

    def test_it_makes_the_user_the_part_and_the_service_in_that_order(self):
        machine = Machine(dict(self.BROKER))
        state, said = self.install(machine)
        self.assertEqual(state, "made")
        self.assertEqual(machine.conf, dict(self.BROKER, swap=self.PART))
        made = machine.changes()
        self.assertIn("useradd --system --user-group", made[0])
        self.assertIn("founderizer-swap", made[0])
        self.assertIn("install -o root -g root -m 644", made[1])
        self.assertIn("systemctl restart fleet-vault\n", made[1])          # the broker reads its configuration again
        self.assertIn("systemctl enable fleet-vault-swap", made[2])
        self.assertIn("systemctl restart fleet-vault-swap", made[2])
        self.assertLess(next(i for i, s in enumerate(machine.ran) if "unit --swap" in s),
                        next(i for i, s in enumerate(machine.ran) if "useradd" in s))     # before anything changes
        self.assertIn("this machine's key swap is on", said)
        for pinned in (hubsetup.HELPER, hubsetup.VAULT_UPDATE, hubsetup.SUDOERS):
            self.assertFalse([s for s in machine.ran if pinned in s])       # the root helpers and the sudoers file stay
        self.assertNotIn("founderizer-swap", hubsetup.RESERVED_USERS)       # a name there changes fleet-agent-user
        self.assertNotIn("founderizer-swap", hubsetup.helper_script())

    def test_a_second_run_changes_nothing(self):
        machine = Machine(dict(self.BROKER))
        self.install(machine)
        machine.ran.clear()
        state, said = self.install(machine)
        self.assertEqual((state, machine.changes()), ("there", []))
        self.assertIn("in place already", said)

    def test_a_second_run_starts_a_proxy_that_is_down_again(self):
        machine = Machine(dict(self.BROKER))
        self.install(machine)
        machine.ran.clear()
        machine.state["active"] = "failed"
        state, said = self.install(machine)
        self.assertEqual(state, "made")
        self.assertTrue([s for s in machine.changes() if "systemctl restart fleet-vault-swap" in s])
        self.assertFalse([s for s in machine.changes() if "systemctl restart fleet-vault\n" in s])    # not the broker
        self.assertEqual((machine.state["active"], machine.conf), ("active", dict(self.BROKER, swap=self.PART)))

    def test_a_second_run_with_another_unit_installs_it_and_starts_only_the_proxy_again(self):
        """A server that got the key swap from the first version: its unit has PartOf, and the program prints another."""
        machine = Machine(dict(self.BROKER))
        self.install(machine)
        first = machine.state["unit"]
        machine.ran.clear()
        machine.UNIT = Machine.UNIT + "LimitCORE=0\n"                       # the installed program prints another unit
        state, said = self.install(machine)
        self.assertEqual(state, "made")
        self.assertNotEqual(machine.state["unit"], first)                   # the new unit is in place
        self.assertTrue([s for s in machine.changes() if "systemctl restart fleet-vault-swap" in s])
        self.assertFalse([s for s in machine.changes() if "systemctl restart fleet-vault\n" in s])    # not the broker
        machine.ran.clear()
        self.assertEqual((self.install(machine)[0], machine.changes()), ("there", []))

    def test_a_check_run_reads_and_changes_nothing(self):
        machine = Machine(dict(self.BROKER))
        state, said = self.install(machine, check=True)
        self.assertEqual((state, machine.changes(), machine.conf), ("would make", [], self.BROKER))
        self.assertIn("would switch this machine's key swap on", said)
        self.assertEqual(self.install(Machine(None), check=True)[0], "would make")

    def test_a_machine_that_lets_each_user_listen_on_the_port_is_not_switched_on(self):
        for low in ("0", "80", "876"):
            with self.subTest(low=low):
                machine = Machine(dict(self.BROKER), low=low)
                with self.assertRaisesRegex(hubsetup.Stop, "ip_unprivileged_port_start"):
                    self.install(machine)
                self.assertEqual((machine.changes(), machine.conf), ([], self.BROKER))
        self.assertEqual(self.install(Machine(dict(self.BROKER), low="877"))[0], "made")

    def test_a_program_that_does_not_know_the_swap_changes_nothing(self):
        machine = Machine(dict(self.BROKER))
        machine.knows = False
        with self.assertRaisesRegex(hubsetup.Stop, "does not know the key swap, so nothing changed"):
            self.install(machine)
        self.assertEqual((machine.changes(), machine.conf), ([], self.BROKER))

    def test_a_machine_with_no_broker_is_told_to_install_it_first(self):
        for conf in (None, {k: v for k, v in self.BROKER.items() if k != "worker_group"}):
            with self.subTest(conf=conf), self.assertRaisesRegex(hubsetup.Stop, "needs this machine's vault broker"):
                self.install(Machine(conf))

    def test_a_broker_that_does_not_stay_up_gets_its_configuration_back(self):
        machine = Machine(dict(self.BROKER))
        machine.broker_stays = False
        with self.assertRaisesRegex(hubsetup.Stop, "the configuration is as it was"):
            self.install(machine)
        self.assertEqual(machine.conf, self.BROKER)
        self.assertEqual(machine.state["broker"], "active")
        self.assertFalse([s for s in machine.changes() if hubsetup.SWAP_UNIT in s])     # the proxy was not installed

    def test_a_proxy_that_does_not_stay_up_is_not_a_finished_step(self):
        machine = Machine(dict(self.BROKER))
        machine.proxy_stays = False
        with self.assertRaisesRegex(hubsetup.Stop, "journalctl -u fleet-vault-swap"):
            self.install(machine)
        self.assertEqual(machine.conf, dict(self.BROKER, swap=self.PART))   # the broker serves, and gives no such key

    def test_the_vault_step_without_the_option_is_as_it_was_and_keeps_the_part(self):
        self.assertEqual(hubsetup.vault_config("http://100.80.1.2:8765", before=dict(self.BROKER, swap=self.PART))["swap"],
                         self.PART)
        with patch.object(hubsetup, "vault_install") as broker, patch.object(hubsetup, "swap_install") as swap, \
                patch.object(hubsetup.platform, "system", return_value="Linux"):
            hubsetup.main(["vault", "--hub", "http://100.80.1.2:8765"])
            self.assertEqual((broker.call_count, swap.call_count), (1, 0))
            hubsetup.main(["vault", "--hub", "http://100.80.1.2:8765", "--swap", "--check"])
            self.assertEqual((broker.call_count, swap.call_count), (2, 1))
            self.assertEqual(swap.call_args.kwargs, {"check": True})
        out = io.StringIO()
        with patch.object(hubsetup, "vault_install"), patch.object(hubsetup, "swap_install") as swap, \
                patch.object(hubsetup.platform, "system", return_value="Darwin"), contextlib.redirect_stdout(out):
            hubsetup.main(["vault", "--hub", "http://100.80.1.2:8765", "--swap"])
        self.assertEqual(swap.call_count, 0)
        self.assertIn("the key swap is for a Linux server", out.getvalue())      # and it says so


class Helper(unittest.TestCase):
    """The helper's step at the start of a session that holds a placeholder (fleet.swap_variables, fleet.read_env)."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="fleet-key-swap-helper-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        (self.dir / "ca").mkdir()
        (self.dir / "ca" / (HOST + ".pem")).write_text("-----BEGIN CERTIFICATE-----\nsite\n-----END CERTIFICATE-----\n")
        (self.dir / "system.pem").write_text("-----BEGIN CERTIFICATE-----\nsystem\n-----END CERTIFICATE-----")
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.addCleanup(self.listener.close)
        self.connects, self.answer = [], b"HTTP/1.1 200 Connection established\r\n\r\n"
        threading.Thread(target=self.serve, daemon=True).start()
        self.swap = {"proxy": f"http://127.0.0.1:{self.listener.getsockname()[1]}", "ca": str(self.dir / "ca"),
                     "names": {"SHOP_API_KEY": HOST}}
        for p in (patch.object(fleet, "HOME", str(self.dir / "home")), patch.object(fleet, "SWAP_CA_LIST", str(self.dir / "system.pem")),
                  patch.object(fleet, "HUB", "http://100.80.1.2:8765")):
            p.start()
            self.addCleanup(p.stop)

    def serve(self):
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            with conn:
                self.connects.append(conn.recv(4096).split(b"\r\n")[0].decode())
                conn.sendall(self.answer)

    def proxy_ends(self):
        """The stand-in proxy goes away. On Linux a close alone does not end an accept that waits, and the port
        would still take a connection: a shutdown ends it. On macOS a shutdown of a listener is an error, and the
        close is enough."""
        try:
            self.listener.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.listener.close()

    def test_the_variables_name_the_proxy_and_the_ca_files_of_this_agents_sites(self):
        env = fleet.swap_variables({"runtime": "claude"}, self.swap, ["SHOP_API_KEY"])
        bundle, sites = (str(self.dir / "home" / name) for name in fleet.SWAP_CA_FILES)
        self.assertEqual((env["HTTPS_PROXY"], env["SSL_CERT_FILE"], env["NODE_EXTRA_CA_CERTS"]), (self.swap["proxy"], bundle, sites))
        self.assertEqual(self.connects, [f"CONNECT {HOST}:443 HTTP/1.1"])   # the proxy makes the site's CA at this
        self.assertEqual(Path(sites).read_text(), "-----BEGIN CERTIFICATE-----\nsite\n-----END CERTIFICATE-----\n")
        self.assertEqual(Path(bundle).read_text(), "-----BEGIN CERTIFICATE-----\nsystem\n-----END CERTIFICATE-----\n"
                                                   "-----BEGIN CERTIFICATE-----\nsite\n-----END CERTIFICATE-----\n")
        for host in ("anthropic.com", ".anthropic.com", "claude.ai", "100.80.1.2", "localhost"):
            self.assertIn(host, env["NO_PROXY"].split(","))
        self.assertNotIn("openai.com", env["NO_PROXY"])
        self.assertEqual(fleet.swap_variables(None, self.swap, ["SHOP_API_KEY"])["HTTPS_PROXY"], self.swap["proxy"])   # a check
        self.assertEqual(sorted(p.name for p in (self.dir / "home").iterdir()), sorted(fleet.SWAP_CA_FILES))     # no file left over

    def test_a_proxy_or_an_answer_that_is_not_ready_is_refused(self):
        held = ["SHOP_API_KEY"]
        here = self.swap["proxy"]
        for why, swap in (("no part", None), ("no proxy", dict(self.swap, proxy="http://203.0.113.7:876")),
                          ("another address with the proxy's port", dict(self.swap, proxy=here.replace("127.0.0.1", "127.0.0.2"))),
                          ("a name for the address", dict(self.swap, proxy=here.replace("127.0.0.1", "localhost"))),
                          ("an https proxy", dict(self.swap, proxy=here.replace("http://", "https://"))),
                          ("a path after the port", dict(self.swap, proxy=here + "/x")),
                          ("another list of names", dict(self.swap, names={"OTHER_KEY": HOST})),
                          ("a host that is no host", dict(self.swap, names={"SHOP_API_KEY": "../etc"})),
                          ("no CA of the site", dict(self.swap, ca=str(self.dir / "empty"))),
                          ("a folder that is no path", dict(self.swap, ca="ca"))):
            with self.subTest(why), self.assertRaises(fleet.Refused):
                fleet.swap_variables({"runtime": "claude"}, swap, held)
        self.answer = b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
        with self.assertRaises(fleet.Refused):
            fleet.swap_variables({"runtime": "claude"}, self.swap, held)
        self.answer = b"HTTP/1.1 200 Connection established\r\n\r\n"         # a good answer again, and then no proxy
        self.assertEqual(fleet.swap_variables({"runtime": "claude"}, self.swap, held)["HTTPS_PROXY"], self.swap["proxy"])
        self.proxy_ends()
        with self.assertRaises(fleet.Refused):
            fleet.swap_variables({"runtime": "claude"}, self.swap, held)

    def read(self, done):
        team = {"agents": {"dev-lead": {"secrets": {"bws://11111111-2222-4333-8444-555555555551": "read"}}}}
        out = io.StringIO()
        with patch.object(fleet, "TEAM", team), patch.object(fleet, "KIT", str(self.dir / "no-kit")), \
                patch.object(fleet, "vault_mode", return_value="broker"), \
                patch.object(fleet, "broker_job_request", return_value=done), contextlib.redirect_stdout(out):
            return fleet.read_env("dev-lead", {"runtime": "codex"}, "task"), out.getvalue()

    def test_an_owner_chat_and_a_check_get_the_placeholder_by_the_same_read(self):
        """Each kind of session (fleet.session_env) and the agent's checks (Helper.check_keys) read the keys by
        read_env, so on a machine that swaps none of them holds the key."""
        done = {"ok": True, "env": {"SHOP_API_KEY": PLACE}, "missing": [], "swap": self.swap}
        team = {"agents": {"dev-lead": {"secrets": {"bws://11111111-2222-4333-8444-555555555551": "read"}}}}
        asked = []

        def broker(agent, request, timeout=60):
            asked.append(request)
            return done
        with patch.object(fleet, "TEAM", team), patch.object(fleet, "KIT", str(self.dir / "no-kit")), \
                patch.object(fleet, "vault_mode", return_value="broker"), patch.object(fleet, "broker_job_request", broker):
            chat = fleet.session_env("dev-lead", {"runtime": "codex"}, "chat")
            manager = fleet.session_env("dev-lead", {"runtime": "claude"}, "manager")
            check = fleet.read_env("dev-lead", None, "check")               # as Helper.check_keys reads them
        for env in (chat, manager, check):
            self.assertEqual((env["SHOP_API_KEY"], env["HTTPS_PROXY"]), (PLACE, self.swap["proxy"]))
        self.assertEqual([r["for"] for r in asked], ["session", "session", "check"])
        self.assertIn("openai.com", chat["NO_PROXY"])
        self.assertNotIn("openai.com", check["NO_PROXY"])                   # a check is not the agent's program

    def test_a_session_gets_the_placeholder_with_the_variables_or_neither(self):
        done = {"ok": True, "env": {"SHOP_API_KEY": PLACE, "OTHER_KEY": "sk-example-plain-value"}, "missing": [],
                "swap": self.swap}
        env, said = self.read(done)
        self.assertEqual((env["SHOP_API_KEY"], env["OTHER_KEY"], env["HTTPS_PROXY"]), (PLACE, "sk-example-plain-value", self.swap["proxy"]))
        self.assertIn("openai.com", env["NO_PROXY"])
        self.assertEqual(said, "")
        self.proxy_ends()                                                   # the proxy does not answer
        env, said = self.read(done)
        self.assertEqual(env, {"OTHER_KEY": "sk-example-plain-value"})      # no placeholder and no proxy variable
        self.assertIn("the vault's proxy is not ready for SHOP_API_KEY", said)
        env, said = self.read({"ok": True, "env": {"SHOP_API_KEY": PLACE}, "missing": []})      # an answer with no part
        self.assertEqual(env, {})
        env, said = self.read({"ok": True, "env": {"OTHER_KEY": "sk-example-plain-value"}, "missing": []})
        self.assertEqual((env, said), ({"OTHER_KEY": "sk-example-plain-value"}, ""))            # as before
