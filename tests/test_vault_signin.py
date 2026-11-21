"""The vault's sign-in in an agent's own browser on a Linux server (build plan 04, S5): the broker fills the form in the
agent's Chrome over DevTools, only where that Chrome is the agent's own, and records what the sign-in left there; the
hub keeps that record with the agent's use of the login and has the agent's helper clear it when that use ends. The
DevTools side is a scripted stand-in here; the live checks on a throwaway server ran the real Chrome."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

import fleet
import hub
import lifecycle
import server
import vault
import leftovers
from leftovers import scratch_home
from pathlib import Path
from test_agent_auth import BOX, KEYS, LOGIN, Routes, sha

ORIGIN = "https://shop.example"
LOGIN_VALUE = {"username": "ana@example.com", "password": "pa'ss\"word\\</script>", "url": ORIGIN + "/login",
               "totp": "JBSWY3DPEHPK3PXP"}
QUICK = dict(step=1.0, tick=0.01, quiet=0.0, first=0.0)


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real ~/.fleet (leftovers.scratch_home)


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (BrokerFill, HelperSide, SigninRecords, MacVaultNumber):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class FakeCdp:
    """A scripted DevTools connection: `answer(expression)` gives what each script returns in the page; each wait gives
    the next list of `waves` (or raises `lost` once they are used up); `cookies` are the answers of Storage.getCookies,
    in order."""
    def __init__(self, answer, waves=(), cookies=([], []), tabs=None, lost=None):
        self.answer, self.waves, self.cookies, self.calls, self.lost = answer, list(waves), list(cookies), [], lost
        self.limit = None
        self.tabs = tabs if tabs is not None else [{"type": "page", "targetId": "T1", "url": ORIGIN + "/login"},
                                                   {"type": "page", "targetId": "T2", "url": "https://other.example/"}]

    def call(self, method, params=None, session=None):
        self.calls.append((method, params or {}, session))
        return {"Storage.getCookies": lambda: {"cookies": self.cookies.pop(0) if self.cookies else []},
                "Target.getTargets": lambda: {"targetInfos": self.tabs},
                "Target.attachToTarget": lambda: {"sessionId": "S1"},
                "Page.getFrameTree": lambda: {"frameTree": {"frame": {"id": "F1"}}},
                "Page.createIsolatedWorld": lambda: {"executionContextId": 7},
                "Runtime.evaluate": lambda: {"result": {"value": self.answer(params["expression"])}},
                }.get(method, dict)()

    def wait(self, end):
        """The next wave's events, and then the rest of the wait, as a connection with nothing more to read waits."""
        if not self.waves and self.lost:
            raise vault.Refused(self.lost)
        yield from self.waves.pop(0) if self.waves else ()
        vault.time.sleep(max(0.0, end - vault.time.monotonic()))

    def scripts(self):
        return [(p["expression"], p.get("contextId")) for m, p, _ in self.calls if m == "Runtime.evaluate"]


def page(fill="filled", checks=("none",), code="filled"):
    """An answer function: the fill script's answer, then each check's in turn (the last one repeats)."""
    left = list(checks)

    def answer(expression):
        if "secret(p," in expression:
            return fill
        if "'emptied'" in expression:
            return "emptied"
        if "'otp':" in expression:
            return left.pop(0) if len(left) > 1 else left[0]
        return code
    return answer


def document(url, frame="F1"):
    return {"method": "Network.requestWillBeSent", "sessionId": "S1",
            "params": {"type": "Document", "frameId": frame, "request": {"url": url}}}


def fill(cdp, code=None, **timing):
    """vault.signin_page with a `keep` that holds what it got: (signed in, with a code, the records)."""
    kept = []
    signed, with_code = vault.signin_page(cdp, LOGIN_VALUE, code, kept.append, **dict(QUICK, **timing))
    return signed, with_code, kept


class BrokerFill(unittest.TestCase):
    """The broker's side: vault.signin_page and the checks before it."""

    def test_a_sign_in_fills_in_the_page_of_its_origin_and_records_what_it_created(self):
        """The fill and each check run in a world of the vault's own; the record names each top-level page of the
        sign-in, its redirects too, and only the cookies that the sign-in created on other sites, by name: a cookie that
        was there before stays out, also with a new value (another session of that site), and a site of a top-level
        page loses all its cookies at the clear anyway. An entry that the hub's rule would refuse stays out alone."""
        wave = [document("https://sso.example/auth?r=1"), document("https://frame.example/", frame="F9"),
                document("https://[::1]:8443/x"),
                {"method": "Page.frameNavigated", "sessionId": "S1", "params": {"frame": {"id": "F1",
                                                                                       "url": ORIGIN + "/home"}}},
                {"method": "Page.loadEventFired", "sessionId": "S1", "params": {}}]
        before = [{"name": "sid", "domain": "shop.example", "path": "/", "value": "0"},
                  {"name": "t", "domain": ".tracker.example", "path": "/", "value": "1"},
                  {"name": "sess", "domain": ".embedded.example", "path": "/", "value": "a"}]
        after = before[1:2] + [{"name": "sid", "domain": "shop.example", "path": "/", "value": "1"},
                               {"name": "sess", "domain": ".embedded.example", "path": "/", "value": "b"},
                               {"name": "s2", "domain": ".sso.example", "path": "/", "value": "x"},
                               {"name": "", "domain": ".ads.example", "path": "/", "value": "z"},
                               {"name": "ad", "domain": ".ads.example", "path": "/", "value": "9",
                                "partitionKey": {"topLevelSite": ORIGIN}}]
        cdp = FakeCdp(page(), [wave], (before, after))
        self.assertEqual(fill(cdp), (True, False, [{"origins": [ORIGIN, "https://sso.example"],
                                                    "cookies": [{"name": "ad", "domain": ".ads.example", "path": "/",
                                                                 "partitionKey": {"topLevelSite": ORIGIN}}]}]))
        record = cdp_record = fill(FakeCdp(page(), [list(wave)], (before, after)))[2][0]
        self.assertEqual(lifecycle.browser_clear_valid(record), cdp_record)    # the hub's rule takes it as it is
        scripts = cdp.scripts()
        self.assertTrue(scripts and all(context == 7 for _, context in scripts), scripts)
        self.assertIn(json.dumps(LOGIN_VALUE["password"]), scripts[0][0])      # the value as one JSON string
        self.assertIn(f"location.origin!=={json.dumps(ORIGIN)}", scripts[0][0])
        self.assertEqual([p for m, p, _ in cdp.calls if m == "Target.attachToTarget"],
                         [{"targetId": "T1", "flatten": True}])     # only the tab of the login's origin

    def test_the_scripts_reach_the_dom_only_through_their_own_worlds_prototypes(self):
        """A page's markup can shadow a member of a form or of the document by a name (<input name="action"> makes
        form.action that element, so the check of the action passes and the submit sends the password elsewhere),
        and the isolated world shares those names; only the prototypes of the vault's own world are out of its reach.
        The live check of 18 November 2026 filled no such page."""
        scripts = [vault.signin_fill(ORIGIN, LOGIN_VALUE), vault.signin_check(ORIGIN),
                   vault.signin_code(ORIGIN, "123456"), vault.SIGNIN_EMPTY]
        for script in scripts:
            self.assertTrue(script.startswith("(()=>{" + vault.SIGNIN_DOM), script[:80])
            body = script[len("(()=>{" + vault.SIGNIN_DOM):]
            self.assertIsNone(re.search(r"\.(querySelector|querySelectorAll|action|form|requestSubmit|submit|"
                                        r"dispatchEvent|value|readyState)\b", body), body)
        self.assertIsNone(re.search(r"\b(document|[a-z])\.(querySelector|querySelectorAll|action|form|requestSubmit|"
                                    r"submit|dispatchEvent|value|readyState)\b", vault.SIGNIN_DOM))    # the Mac's

    APP = Path(leftovers.ROOT) / "app"      # the apps' folder, which the published repository never has
    NO_APP = "the apps' folder app/ is not in this tree (the published repository has none)"

    @unittest.skipUnless(APP.is_dir(), NO_APP)
    def test_the_scripts_dom_is_the_macs_own_byte_for_byte(self):
        """The Linux broker's DOM helpers are the Mac's (VaultBrowser.dom): the Mac's tests run them in a stand-in page
        (a field that form= gives to another form, an `input` inside `<svg>`), so a change of one copy alone fails
        here instead of going out unchecked."""
        swift = (self.APP / "Sources/FleetVaultCore/VaultBrowser.swift").read_text(encoding="utf-8")
        body = re.search(r'static let dom = ((?:"(?:[^"\\\n]|\\.)*"\s*\+?\s*)+)', swift).group(1)
        mac = "".join(json.loads(f'"{part}"') for part in re.findall(r'"((?:[^"\\\n]|\\.)*)"', body))
        self.assertEqual(vault.SIGNIN_DOM, mac)

    @unittest.skipUnless(APP.is_dir(), NO_APP)
    def test_the_fill_the_code_and_the_check_are_the_macs_own(self):
        """The fill, the code and the check are the Mac's scripts (VaultBrowser.fillScript, otpScript, checkScript)
        with the same values in them and no line breaks: the Mac's flow tests run those in a stand-in page (a GET form
        that must go by POST, a field that form= gives to another form, an `input` inside `<svg>`, a form that moves
        while the values are typed, CSS that reads a field), so a change of one copy alone fails here."""
        swift = (self.APP / "Sources/FleetVaultCore/VaultBrowser.swift").read_text(encoding="utf-8")
        otp = json.loads(re.search(r'static let otpSelector = ("(?:[^"\\\n]|\\.)*")', swift).group(1))
        self.assertEqual(otp, vault.SIGNIN_OTP)
        origin, code = "https://login.example", "135790"
        login = {"username": "user@example.test", "password": "pw-EXAMPLE-1"}
        values = {"\\(dom)": vault.SIGNIN_DOM, "\\(origin)": json.dumps(origin),
                  "\\(try jsonString(origin))": json.dumps(origin),
                  "\\(try jsonString(login.username))": json.dumps(login["username"]),
                  "\\(try jsonString(login.password))": json.dumps(login["password"]),
                  "\\(try jsonString(otpSelector))": json.dumps(otp), "\\(try jsonString(code))": json.dumps(code)}

        def mac(name):
            text = re.search(r'static func %s\(.*?"""[ ]*\n(.*?)\n[ ]*"""' % name, swift, re.S).group(1)
            lines = [line.strip() for line in text.split("\n")]
            self.assertTrue(all(line.endswith((";", "})()")) for line in lines), lines)     # no break that JS reads
            text = "".join(lines)
            for key, value in values.items():
                text = text.replace(key, value)
            self.assertNotIn("\\(", text, name)
            return text
        self.assertEqual(vault.signin_fill(origin, login), mac("fillScript"))
        self.assertEqual(vault.signin_code(origin, code), mac("otpScript"))
        self.assertEqual(vault.signin_check(origin), mac("checkScript"))

    @unittest.skipUnless(sys.platform == "darwin", "the script runs in the JavaScript of macOS (osascript)")
    def test_the_clean_up_empties_the_fields_after_one_that_is_no_html_field(self):
        """SIGNIN_EMPTY in JavaScriptCore with a stand-in page whose first password field is an `input` inside `<svg>`,
        which is no HTML field: its value setter throws, as in Chrome. The real field after it is emptied, with the
        events that a page's framework listens to; before, the script stopped at the first one and the password
        stayed in the page."""
        script = """
            var EMPTY = %s;
            class EventTarget {
                addEventListener() {} removeEventListener() {}
                dispatchEvent(e) { (this.events = this.events || []).push(e.type); return true; } }
            class Node extends EventTarget {}
            class Element extends Node { querySelector() { return null; } querySelectorAll() { return []; }
                removeAttribute() {} }
            class Document extends Element {
                constructor(fields) { super(); this.fields = fields; }
                querySelectorAll() { return this.fields; } }
            class HTMLFormElement extends Element {}
            class HTMLInputElement extends Element {
                constructor(type, value) { super(); this.kind = type; this.kept = value; }
                get type() { if (!(this instanceof HTMLInputElement)) throw new TypeError('Illegal invocation');
                             return this.kind; }
                get value() { return this.kept; }
                set value(v) { if (!(this instanceof HTMLInputElement)) throw new TypeError('Illegal invocation');
                               this.kept = v; } }
            class SVGElement extends Element {}
            class Event { constructor(type) { this.type = type; } preventDefault() {} stopImmediatePropagation() {} }
            var real = new HTMLInputElement('password', 'typed-EXAMPLE'), page = new Document([new SVGElement(), real]);
            var said = new Function('Document', 'Element', 'HTMLFormElement', 'HTMLInputElement', 'Node', 'EventTarget',
                                    'Event', 'window', 'document', 'return ' + EMPTY)(
                Document, Element, HTMLFormElement, HTMLInputElement, Node, EventTarget, Event, new EventTarget(),
                page);
            JSON.stringify([said, real.value, real.events || []]);
        """ % json.dumps(vault.SIGNIN_EMPTY)
        answer = subprocess.run(["osascript", "-l", "JavaScript", "-e", script], capture_output=True, text=True,
                                timeout=30)
        self.assertEqual(json.loads(answer.stdout or "null"), ["emptied", "", ["input", "change"]], answer.stderr)

    def test_the_first_look_after_a_submit_waits_as_the_macs_one_look_does(self):
        """Each look at the page wipes a password or a code that is still in it, and a page's own handler may still
        read its field after the submit (a captcha, then its own submit): the first look comes `first` seconds after
        the fill, as the Mac's one look comes 3 s after it, and not at the first tick."""
        cdp = FakeCdp(page(), [], ([], []))
        timed, call = [], cdp.call

        def timing(method, params=None, session=None):
            if method == "Runtime.evaluate":
                timed.append((vault.time.monotonic(), params["expression"]))
            return call(method, params, session)
        cdp.call = timing
        self.assertTrue(fill(cdp, first=0.3)[0])
        filled = next(at for at, script in timed if "secret(p," in script)
        looked = next(at for at, script in timed if "'otp':" in script and at > filled)
        self.assertGreaterEqual(looked - filled, 0.3)
        self.assertEqual(vault.SIGNIN_FIRST_LOOK, 3.0)

    def test_a_state_counts_only_once_the_tab_is_quiet(self):
        """A page that a widget's script changes, a single sign-on page after the landing page, and a page between two
        steps on another site: the broker answers, and reads the cookies for its record, only after the tab had no new
        top-level page, document request or load for `quiet` seconds (plan 04: after its redirects end)."""
        late = [document("https://sso.example/saml")]
        cdp = FakeCdp(page(checks=("none",)), [[], late, [], []], ([], []))
        signed, _, kept = fill(cdp, quiet=0.2, tick=0.05)
        self.assertEqual((signed, kept[0]["origins"]), (True, [ORIGIN, "https://sso.example"]))
        cdp = FakeCdp(page(checks=("wrong-origin", "none")), [], ([], []))      # it passes through another site
        self.assertEqual(fill(cdp, quiet=0.2, tick=0.05)[:2], (True, False))
        # a widget's frame that changes its own history all the time keeps the tab open no longer than the main frame
        widget = [{"method": "Page.navigatedWithinDocument", "sessionId": "S1", "params": {"frameId": "F9"}}]
        start = vault.time.monotonic()
        cdp = FakeCdp(page(checks=("none",)), [widget] * 40, ([], []))
        self.assertEqual((fill(cdp, quiet=0.2, tick=0.05, step=2.0)[0], vault.time.monotonic() - start < 1.0),
                         (True, True))

    def test_a_sign_in_that_is_not_confirmed_or_breaks_empties_its_fields_and_keeps_its_record(self):
        """The plan: a field that stays filled after a failed sign-in is cleared before the broker answers. So after
        any fill: a page that still asks for the login, a fill that stopped after it may have typed, and an error of
        the connection all empty the fields, and the hub still gets the record."""
        cdp = FakeCdp(page(checks=("form",)), [], ([], []))
        signed, _, kept = fill(cdp, step=0.05)
        self.assertEqual((signed, len(kept)), (False, 1))
        self.assertIn("'emptied'", cdp.scripts()[-1][0])
        # a new page that loaded with the form again ends the wait at once (a wrong password); a load of the page from
        # before the submit does not
        late_load = {"method": "Page.loadEventFired", "sessionId": "S1", "params": {}}
        moved = {"method": "Page.frameNavigated", "sessionId": "S1",
                 "params": {"frame": {"id": "F1", "url": ORIGIN + "/"}}}
        for waves, quick in (([[late_load, moved, late_load]], True), ([[late_load]], False)):
            start = vault.time.monotonic()
            signed, _, _ = fill(FakeCdp(page(checks=("form",)), waves, ([], [])), step=0.6)
            self.assertEqual((signed, vault.time.monotonic() - start < 0.3), (False, quick), waves)
        # a fill that stopped after it may have typed (an answer that is none of the refusals before typing)
        for answer in (None, "moved"):          # (a page that signs in after a fill with no answer is taken)
            cdp = FakeCdp(page(fill=answer, checks=("form",)), [], ([], []), tabs=[{"type": "page", "targetId": "T1",
                                                                                     "url": ORIGIN + "/login"}])
            with self.assertRaises(vault.Refused):
                fill(cdp)
            self.assertIn("'emptied'", cdp.scripts()[-1][0], answer)
        # an error of the connection after the fill: the fields are emptied as far as it goes, the record is kept
        cdp = FakeCdp(page(), [], ([], []), lost="the DevTools connection to the agent's browser failed")
        kept = []
        with self.assertRaisesRegex(vault.Refused, "connection"):
            vault.signin_page(cdp, LOGIN_VALUE, None, kept.append, **QUICK)
        self.assertEqual((kept, "'emptied'" in cdp.scripts()[-1][0]), ([{"origins": [ORIGIN], "cookies": []}], True))
        # a form that sends elsewhere, and a page of another origin, get no fill at all and nothing to empty
        for refusal in ("wrong-action", "wrong-origin", "no-form"):
            cdp = FakeCdp(page(fill=refusal), [], ([], []))
            with self.assertRaises(vault.Refused):
                fill(cdp)
            self.assertFalse(any("'emptied'" in s for s, _ in cdp.scripts()), refusal)
        with self.assertRaisesRegex(vault.Refused, "no tab of the agent's browser shows https://shop.example"):
            fill(FakeCdp(page(), [], ([], []), tabs=[]))
        # a form that the vault held (it would send by GET, in the page's address) and a field that takes no secret
        # are emptied and named in the refusal, so that the agent does not look for another form
        for answer, words in (("not-sent", "sent nothing that the vault saw: it sends by GET.*not valid"),
                              ("bad-field", "types no secret into"), (None, "no answer, and.*no other tab")):
            cdp, kept = FakeCdp(page(fill=answer, checks=("form",)), [], ([], [])), []
            with self.assertRaisesRegex(vault.Refused, words):
                vault.signin_page(cdp, LOGIN_VALUE, None, kept.append, **QUICK)
            self.assertIn("'emptied'", cdp.scripts()[-1][0], answer)
            self.assertEqual(len(kept), 0 if answer == "bad-field" else 1, answer)     # where a submit can have gone
        # a listener of the page can hide a submit that went: after `not-sent` or no answer the broker watches that
        # tab, takes a sign-in that went and keeps its record, and no second tab of the origin gets the password;
        # after `bad-field` (nothing typed but the user name) the next tab is tried
        two = [{"type": "page", "targetId": "T1", "url": ORIGIN + "/login"},
               {"type": "page", "targetId": "T2", "url": ORIGIN + "/account"}]
        for answer, fills in (("not-sent", 1), (None, 1), ("bad-field", 2)):
            cdp = FakeCdp(page(fill=answer, checks=("form",)), [], ([], []), tabs=two)
            with self.assertRaises(vault.Refused):
                fill(cdp)
            self.assertEqual(sum("secret(p," in s for s, _ in cdp.scripts()), fills, answer)
        signed, _, kept = fill(FakeCdp(page(fill="not-sent"), [], ([], [])))
        self.assertEqual((signed, len(kept)), (True, 1))         # the hidden submit signed in
        for shown in ("otp", "wrong-origin"):       # it went: a code page (a login with no seed) or another site
            for answer in ("not-sent", None):
                signed, _, kept = fill(FakeCdp(page(fill=answer, checks=(shown,)), [], ([], [])))
                self.assertEqual((signed, len(kept)), (False, 1), (shown, answer))      # signin's own words, no retry
        for answer in ("not-sent", None):           # it went, and the site gave its form back on a new page, also
            for waves in ([[late_load, moved, late_load]], [[moved]]):     # one whose load has not come yet
                signed, _, kept = fill(FakeCdp(page(fill=answer, checks=("form",)), waves, ([], [])), step=0.6)
                self.assertEqual((signed, len(kept)), (False, 1), (answer, waves))  # no "ask again" to a wrong password
        # the code step: a field that takes no code is a refusal at once; a code that can have gone is watched, and
        # its refusal says so where the page does not sign in
        for answer, words in (("bad-field", "types no code into"),
                              ("not-sent", "code form on .* sent nothing.*can have gone"),
                              (None, "code page on .* no answer, and")):
            cdp = FakeCdp(page(checks=("otp",), code=answer), [], ([], []))
            with self.assertRaisesRegex(vault.Refused, words):
                fill(cdp, code=lambda: "135790")
            self.assertIn("'emptied'", cdp.scripts()[-1][0], answer)
        self.assertEqual(fill(FakeCdp(page(checks=("otp", "none"), code="not-sent"), [], ([], [])),
                              code=lambda: "135790")[:2], (True, True))
        self.assertEqual(fill(FakeCdp(page(checks=("otp", "none"), code=None), [], ([], [])),
                              code=lambda: "135790")[:2], (True, False))     # a code with no answer that went

    def test_the_whole_fills_limit_ends_the_wait_and_leaves_the_clean_up_its_own_seconds(self):
        """After the limit nothing more is sent and no wait spins; the fields are emptied all the same, because the
        clean-up has its own few seconds."""
        cdp = FakeCdp(page(checks=("form",)), [], ([], []))
        cdp.limit = vault.time.monotonic() - 1
        start = vault.time.monotonic()
        signed, _, kept = fill(cdp, step=20.0)
        self.assertEqual((signed, vault.time.monotonic() - start < 1, len(kept)), (False, True, 1))
        self.assertIn("'emptied'", cdp.scripts()[-1][0])
        self.assertGreater(cdp.limit, vault.time.monotonic() + vault.SIGNIN_CLEANUP - 2)
        sent = []
        late = vault.SigninCdp.__new__(vault.SigninCdp)
        late.limit, late.last, late.timeout = vault.time.monotonic() - 1, 0, 5
        late.sock = types.SimpleNamespace(sendall=sent.append)
        with self.assertRaisesRegex(vault.Refused, "ran out of its time"):
            late.call("Page.enable")
        self.assertEqual(sent, [])

    def test_a_kept_event_holds_only_what_the_wait_reads(self):
        """An agent's own listener can send large events: the broker keeps only the few fields that its wait reads,
        and no event of another kind."""
        c = vault.SigninCdp.__new__(vault.SigninCdp)
        c.events, c.kept, c.size = [], 0, 100
        c.keep({"method": "Page.loadEventFired", "sessionId": "S1", "params": {"timestamp": 1, "junk": [{}] * 1000}})
        c.keep({"method": "Network.requestWillBeSent", "params": {"type": "Script", "request": {"url": "https://x/"}}})
        c.keep({"method": "Runtime.consoleAPICalled", "params": {}})
        self.assertEqual(c.events, [{"method": "Page.loadEventFired", "sessionId": "S1",
                                     "params": {"type": None, "frameId": None, "request": {"url": None},
                                                "frame": {"id": None, "url": None, "parentId": None}}}])
        c.events, c.kept, c.size = [], 0, 32        # a flood of small events: each counts 1 KiB at least
        for _ in range(vault.SIGNIN_KEPT // vault.SIGNIN_EVENT + 10):
            c.keep({"method": "Page.loadEventFired", "params": {}})
        self.assertEqual(len(c.events), vault.SIGNIN_KEPT // vault.SIGNIN_EVENT)

    def test_an_authenticator_code_goes_in_where_the_site_asks_for_one(self):
        cdp = FakeCdp(page(checks=("otp", "none")), [], ([], []))
        self.assertEqual(fill(cdp, lambda: "123456")[:2], (True, True))
        self.assertTrue(any('"123456"' in s for s, _ in cdp.scripts()))
        # the broker's code is the helper's own rule
        for at in (59, 1111111109, 2000000000):
            self.assertEqual(vault.totp_now(LOGIN_VALUE["totp"], at=at), fleet.totp_code(LOGIN_VALUE["totp"], at=at))

    def test_only_a_browser_of_the_agents_own_uid_gets_a_fill(self):
        """D11: the broker sends no fill to a port where any socket of another user listens, IPv4 or IPv6, nor where
        it cannot read the kernel's lists, and it connects to nothing then; after it connected, the far end of its own
        connection must be of the agent's uid too (a port that another user took between the look and the connect)."""
        head = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        line = ("   0: {addr}:{port:04X} {rem}:{far:04X} {st} 00000000:00000000 00:00000000 00000000  {uid}        "
                "0 1 1\n")
        folder = tempfile.mkdtemp(prefix="signin-tcp-")
        self.addCleanup(shutil.rmtree, folder, True)

        def tables(v4, v6=""):
            for name, text in (("tcp", v4), ("tcp6", v6)):
                with open(os.path.join(folder, name), "w") as f:
                    f.write(head + text)
            return ((os.path.join(folder, "tcp"), False), (os.path.join(folder, "tcp6"), True))
        listen = lambda uid, addr="0100007F": line.format(addr=addr, port=9311, rem="00000000", far=0, st="0A", uid=uid)
        own = listen(1002)
        self.assertEqual(vault.signin_listeners(9311, tables(own)), {1002})
        for v4, v6 in ((listen(1003), ""), (own, listen(1003, "00000000000000000000000000000000")), ("", "")):
            with patch.object(vault.socket, "create_connection", side_effect=AssertionError("it connected")):
                with self.assertRaisesRegex(vault.Refused, "no browser of this agent alone listens"):
                    vault.SigninCdp(9311, 1002, tables=tables(v4, v6))
        far = line.format(addr="0100007F", port=9311, rem="0100007F", far=40000, st="01", uid=1003)
        mapped = line.format(addr="0000000000000000FFFF00000100007F", port=9311,
                             rem="0000000000000000FFFF00000100007F", far=40000, st="01", uid=1002)
        self.assertEqual(vault.signin_peer(9311, 40000, tables(own + far)), {1003})
        self.assertEqual(vault.signin_peer(9311, 40000, tables(own, mapped)), {1002})
        self.assertEqual(vault.signin_listeners(9311, ((os.path.join(folder, "none"), False),)), set())
        closed = os.path.join(folder, "closed")
        with open(closed, "w") as f:
            f.write(head + own)
        os.chmod(closed, 0)
        if os.geteuid() != 0:
            self.assertEqual(vault.signin_listeners(9311, ((closed, False),)), {-1})

    def test_a_connection_whose_far_end_is_another_users_gets_no_fill(self):
        """After the look at the listeners and the connect: a port that another user's process took in between is
        refused by the far end of the broker's own connection (here a stand-in DevTools server on this machine)."""
        import socket
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        self.addCleanup(listener.close)
        port = listener.getsockname()[1]

        body = b'{"webSocketDebuggerUrl": "ws://127.0.0.1/devtools/browser/0123-abcd-4567"}'

        def serve():
            for answer in (b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body),
                           b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"):
                conn, _ = listener.accept()
                conn.recv(4096)
                conn.sendall(answer)
                if answer.startswith(b"HTTP/1.1 200"):
                    conn.close()
        threading.Thread(target=serve, daemon=True).start()
        uid = os.getuid()
        with patch.object(vault, "signin_listeners", lambda p, tables=None: {uid} if p == port else set()), \
                patch.object(vault, "signin_peer", lambda p, local, tables=None: {uid + 1}):
            with self.assertRaisesRegex(vault.Refused, "far end of the connection"):
                vault.SigninCdp(port, uid, timeout=5)

    def test_the_port_comes_from_roots_own_ports_file(self):
        folder = tempfile.mkdtemp(prefix="signin-ports-")
        path = os.path.join(folder, "ports")
        self.addCleanup(shutil.rmtree, folder, True)
        with open(path, "w") as f:
            f.write("fleet-alpha 9311 5911\nfleet-beta 9312 5912\n")
        os.chmod(path, 0o644)
        if os.geteuid() != 0:
            with self.assertRaisesRegex(vault.Refused, "not root's own"):        # this test's own file
                vault.signin_port("fleet-beta", path)
        real = os.fstat
        as_root = lambda fd: types.SimpleNamespace(**{k: getattr(real(fd), k) for k in ("st_mode", "st_size")},
                                                   st_uid=0)
        with patch.object(vault.os, "fstat", as_root):
            self.assertEqual(vault.signin_port("fleet-beta", path), 9312)
            with self.assertRaisesRegex(vault.Refused, "no browser port"):
                vault.signin_port("fleet-gamma", path)
        with self.assertRaisesRegex(vault.Refused, "no ports file"):
            vault.signin_port("fleet-beta", path + ".none")

    def test_the_browser_comes_first_the_lock_is_free_while_it_works_and_the_agent_gets_no_value(self):
        """The connection to the agent's own browser comes before the hub's job is used. The record of the login's
        own origin reaches the hub before anything is typed, then the whole record; a seed that makes no code refuses
        before that. The broker's lock is free while the browser works, so that the other agents' vault calls go on;
        one sign-in of an agent at a time. The answer has the origin, the login's name and the code's use, as the Mac's
        vault helper answers; an unconfirmed sign-in is refused with no value either."""
        said, lock = [], threading.Lock()

        def hub_call(conf, method, path, body=None):
            said.append((path.rsplit("/", 1)[-1], body))
            return 200, {"ok": True, "job": 5}

        class Stand:
            def __init__(self, *_a, **_k):
                said.append(("browser", lock.locked()))

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

        def page_stand(signed):
            def run(cdp, login, code, keep):
                said.append(("fill", lock.locked()))
                keep({"origins": [ORIGIN, "https://sso.example"], "cookies": []})
                return signed, code is not None
            return run
        conf = {"agent": "beta", "_lock": lock}
        login = dict(LOGIN_VALUE)
        for signed in (True, False, None):
            said.clear()
            login["totp"] = LOGIN_VALUE["totp"] if signed is not None else "not base32!"
            with lock, patch.object(vault, "LocalStore", lambda conf: None), \
                    patch.object(vault, "signin_port", lambda user, path: 9312), \
                    patch.object(vault, "confirm_job", lambda conf, job, kind: said.append(("job", None)) or {
                        "login": LOGIN, "job": job}), \
                    patch.object(vault, "open_login", lambda conf, ref, task, store: (dict(login), "Shop", None)), \
                    patch.object(vault, "protect", lambda *a: None), patch.object(vault, "hub", hub_call), \
                    patch.object(vault, "SigninCdp", Stand), patch.object(vault, "signin_page", page_stand(signed)):
                if signed:
                    answer = vault.signin(conf, 5, os.getuid())
                    self.assertEqual(answer, {"ok": True, "v": vault.PROTOCOL, "job": 5, "origin": ORIGIN,
                                              "label": "Shop", "authenticator": True})
                else:
                    with self.assertRaisesRegex(vault.Refused, "could not be confirmed.*never shown to you"
                                                if signed is False else "seed is not base32") as caught:
                        vault.signin(conf, 5, os.getuid())
                    self.assertNotIn(LOGIN_VALUE["password"], str(caught.exception))
            whole = [("signed", {"origins": [ORIGIN, "https://sso.example"], "cookies": [], "job": 5})]
            self.assertEqual(said, [("browser", False), ("job", None)] + (
                [("signed", {"origins": [ORIGIN], "cookies": [], "job": 5}), ("fill", False)] + whole
                if signed is not None else []), signed)
            self.assertEqual(vault.SIGNING, set())
        vault.SIGNING.add(os.getuid())
        self.addCleanup(vault.SIGNING.discard, os.getuid())
        with self.assertRaisesRegex(vault.Refused, "runs already"):
            vault.signin(conf, 6, os.getuid())


class HelperSide(unittest.TestCase):
    """The helper's side: its sign-in on Linux, a move and a rename."""

    def test_the_helper_asks_its_linux_broker_and_runs_the_sign_in_in_a_thread_of_its_own(self):
        """The fill in the agent's own browser takes up to a minute: the helper's loop serves a pause or a stop
        meanwhile, and the same job's event again starts nothing."""
        with patch.object(fleet.sys, "platform", "linux"), patch.object(fleet, "vault_mode", lambda a: "broker"), \
                patch.object(fleet, "broker_job", lambda agent, job: job), \
                patch.object(fleet, "broker_job_request", lambda agent, req: {
                    "origin": ORIGIN, "label": "Shop", "authenticator": True} if req == {"op": "signin", "job": 5}
                    else {}):
            self.assertEqual(fleet.do_signin("bws://x", "beta", "T-1", 5),
                             f'Signed in on {ORIGIN} with the login "Shop", with its authenticator code. The password '
                             f'was never shown to you.')
        h = fleet.Helper.__new__(fleet.Helper)
        h.outside_lock, gate, ran, outside = threading.Lock(), threading.Event(), [], []
        h.begin_outside, h.end_outside = (lambda: outside.append("begin")), (lambda: outside.append("end"))
        h.login_job = lambda kind, task, extra, outside=True: (ran.append((kind, task, extra["job"], outside)),
                                                                gate.wait(5))
        fleet.Helper.signin_job(h, "T-1", {"job": 5})
        fleet.Helper.signin_job(h, "T-1", {"job": 5})             # the same event again, while the first runs
        gate.set()
        for _ in range(100):
            if outside == ["begin", "end"]:
                break
            fleet.time.sleep(0.01)
        self.assertEqual((ran, outside, h.signins), ([("signin", "T-1", 5, False)], ["begin", "end"], set()))

    def test_a_move_takes_the_agents_sign_ins_away_from_the_server_that_it_left(self):
        """The hub sends the clear of a login's end to the agent's new server; the old server's helper deletes the
        browser data there once its units ended, so that a move back finds no old session."""
        h = fleet.Helper.__new__(fleet.Helper)
        h.agent, h.session, gone = "scout", "fleet-scout", []
        h.own_user, h.browser_data_gone = (lambda: True), (lambda team=None: gone.append(1))
        for ended, deleted in ((True, [1]), (False, [])):
            gone.clear()
            with patch.object(fleet.sys, "platform", "linux"), patch.object(fleet, "tmux", lambda *a, **k: None), \
                    patch.object(fleet, "stop_browser_units", lambda run=None: True), \
                    patch.object(fleet, "browser_units_ended", lambda run=None: ended), \
                    patch.object(fleet, "BROWSER_MOVED_WAIT", 0), \
                    patch.object(fleet.subprocess, "run", lambda argv, **kw: fleet.subprocess.CompletedProcess(
                        argv, 0, "", "")):
                h.moved_away()
            self.assertEqual(gone, deleted, ended)

    def test_a_rename_carries_the_browsers_waiting_clears(self):
        """A clear of a login whose use ended waits in the helper's list for the browser's next start; a rename of
        the agent carries the lists to its new name, so that the clear still runs."""
        home = tempfile.mkdtemp(prefix="signin-rename-")
        self.addCleanup(shutil.rmtree, home, True)
        os.makedirs(os.path.join(home, ".fleet"))
        for kind in ("clears", "done"):
            with open(os.path.join(home, ".fleet", f"browser-{kind}-nova.json"), "w") as f:
                f.write("[]")
        s = server.Service.__new__(server.Service)
        s.home_of, s.there, s.as_agent = (lambda user: home), (lambda path, user: os.path.exists(path)), \
            (lambda user, argv: argv)
        s.run = lambda argv: (lambda r: (r.returncode, r.stdout, r.stderr))(
            __import__("subprocess").run(argv, capture_output=True, text=True))
        server.Service.carry_browser(s, "nova", "orion", "fleet-nova")
        self.assertEqual(sorted(os.listdir(os.path.join(home, ".fleet"))),
                         ["browser-clears-orion.json", "browser-done-orion.json"])


class SigninRecords(Routes):
    """The hub's side: the record's route and the clear at the end of a login's use."""

    def setUp(self):
        super().setUp()
        hub.TEAM["agents"]["beta"]["vault"] = "broker"
        hub.SIGNIN_TOLD.clear()
        self.addCleanup(hub.SIGNIN_TOLD.clear)
        hub.ins("INSERT INTO agent_keys(agent,sha256,created,source) VALUES('beta',?,?,'owner')",
                (sha(KEYS["beta"]), hub.now()))
        self.tid = self.task("beta", needs="browser")

    def job(self, agent="beta", kind="signin", released=True, login=LOGIN):
        return hub.ins("INSERT INTO jobs(agent,task,kind,login,target,created,released) VALUES(?,?,?,?,'',?,?)",
                       (agent, self.tid, kind, login, hub.now(), hub.now() if released else None))

    def signed(self, job, origins=(ORIGIN,), cookies=()):
        return self.call("/helper/vault/beta/signed", {"job": job, "origins": list(origins), "cookies": list(cookies)},
                         source=BOX, token=KEYS["beta"])

    def records(self):
        return [(r["agent"], r["login"], json.loads(r["origins"]), json.loads(r["cookies"]))
                for r in hub.q("SELECT * FROM signin_records ORDER BY agent, login")]

    def clears(self):
        return [json.loads(r["extra"])
                for r in hub.q("SELECT extra FROM events WHERE agent='beta' AND kind='browser_clear'")]

    def sweep(self, granted=frozenset(), rev="r1"):
        hub.SIGNIN_CLEAR.update(at=0.0)
        with patch.object(hub, "signin_grants", lambda agent, rev: None if granted is None else set(granted)), \
                patch.object(hub, "kit_revision", lambda fresh=False: rev):
            hub.signin_clear_sweep(hub.now())

    def test_a_sign_in_is_kept_with_its_login_and_two_records_merge_the_newest_first(self):
        """The agent's own processes can post a record of their job too, which the hub cannot tell from the broker's:
        the newest entries come first at the rule's limits, so that the broker's record after the fill keeps its
        place."""
        ad = {"name": "ad", "domain": ".ads.example", "path": "/"}
        job = self.job()
        self.assertEqual(self.signed(job, [ORIGIN + "/home", "https://sso.example/a"], [ad]),
                         (200, {"ok": True, "job": job}))
        self.assertEqual(self.signed(self.job(), [ORIGIN, "https://pay.example"], [ad])[0], 200)
        self.assertEqual(self.records(),
                         [("beta", LOGIN, [ORIGIN, "https://pay.example", "https://sso.example"], [ad])])
        self.signed(self.job(), [f"https://x{i}.example" for i in range(50)])
        self.signed(self.job(), [ORIGIN])
        origins = self.records()[0][2]
        self.assertEqual((origins[0], len(origins)), (ORIGIN, 50))

    def test_only_an_opened_sign_in_job_of_the_agent_keeps_a_record(self):
        for job, code in ((self.job(kind="handover"), 404), (self.job(released=False), 404),
                          (self.job(agent="alpha"), 404), (9999, 404)):
            self.assertEqual(self.signed(job)[0], code, job)
        old = self.job()
        hub.q("UPDATE jobs SET released=? WHERE id=?", (hub.now() - hub.SIGNIN_RECORD_WINDOW - 1, old))
        self.assertEqual(self.signed(old)[0], 409)
        for origins, cookies in (([], []), (["file:///etc/passwd"], []), ([ORIGIN], [{"name": "x"}])):
            self.assertEqual(self.signed(self.job(), origins, cookies)[0], 400, origins)
        self.assertEqual(self.records(), [])

    def test_the_end_of_an_owners_grant_clears_its_sign_ins_at_once(self):
        """login_refusal's rule: the owner's grant keeps the record; its end sends the clear to the agent's helper at
        the next pass, also while the task that signed in still works, and once; and so does the end of the agent's
        broker, also for a handover's copy that its running task still gives, and with no read of its profile. A pass
        whose revision of the owner's files cannot be read clears nothing."""
        self.signed(self.job(), [ORIGIN], [{"name": "ad", "domain": ".ads.example"}])
        self.sweep(granted={LOGIN})
        self.sweep(rev=None)
        self.sweep(granted=None)                    # this agent's profile could not be read in that pass
        self.assertEqual((len(self.records()), self.clears()), (1, []))
        self.sweep()
        self.sweep()
        self.assertEqual(self.clears(), [{"origins": [ORIGIN], "cookies": [{"name": "ad", "domain": ".ads.example"}]}])
        self.assertEqual(self.records(), [])
        self.signed(self.job(login="sealed:7"))
        hub.TEAM["agents"]["beta"]["vault"] = "none"
        self.sweep(granted=None, rev=None)          # an agent with no broker needs no profile and no revision
        self.assertEqual((self.records(), len(self.clears())), ([], 2))

    def test_a_profile_that_cannot_be_read_now_ends_no_use(self):
        """git's answer that the profile is not in the revision gives no logins; a git call that failed or ran out of
        time gives nothing to decide on (None), so that no record clears by mistake."""
        hub.TEAM["agents"]["beta"]["secrets"] = {LOGIN: "use"}
        answers = {"none": (128, b"", b"fatal: path 'profiles/beta.md' does not exist in 'r1'"),
                   "failed": (128, b"", b"fatal: unable to read tree"), "ok": (0, b"", b"")}
        for answer, grants in (("none", {LOGIN}), ("failed", None), ("ok", {LOGIN})):
            code, out, err = answers[answer]
            calls = []
            with patch.object(hub.subprocess, "run", lambda argv, **kw: calls.append(kw) or
                              hub.subprocess.CompletedProcess(argv, code, out, err)):
                self.assertEqual(hub.signin_grants("beta", "r1"), grants, answer)
            self.assertEqual(calls[0]["env"]["LC_ALL"], "C")       # git's own words, never a translation

    def test_the_clears_grants_are_the_hubs_grants(self):
        """The clear reads the owner's grants as the hub's grant check reads them (granted_logins): the profile's
        section "Logins it may use" and the secrets that the owner gave, so that the two never disagree."""
        other = "bws://99999999-2222-4333-8444-55555555555b"
        hub.TEAM["agents"]["beta"]["secrets"] = {other: "use"}
        profile = f"**Role.** A worker.\n\n**Logins it may use.** bws://{LOGIN[6:].upper()} for the shop.\n".encode()
        with patch.object(hub.subprocess, "run", lambda argv, **kw: hub.subprocess.CompletedProcess(
                argv, 0, profile if "show" in argv else b"r1\n", b"")):
            self.assertEqual(hub.signin_grants("beta", "r1"), hub.granted_logins("beta", "r1"))
            self.assertEqual(hub.signin_grants("beta", "r1"), {LOGIN, other})

    def test_a_row_whose_decision_fails_waits_alone(self):
        """An error of the hub's own reads for one record keeps that record for a later pass and is told once; the
        other records still clear."""
        self.signed(self.job(login=LOGIN))
        self.signed(self.job(login="sealed:7"))
        real = hub.signin_ended

        def ended(agent, login, task, granted):
            if login == "sealed:7":
                raise ValueError("an unusual stored address")
            return real(agent, login, task, granted)
        with patch.object(hub, "signin_ended", ended):
            self.sweep()
            self.sweep()
        self.assertEqual(([r[1] for r in self.records()], len(self.clears())), (["sealed:7"], 1))
        said = lambda: hub.q("SELECT what FROM log WHERE what LIKE '%could not be decided%'")
        self.assertEqual(len(said()), 1)
        self.sweep()                                # decided now (its running task still gives it)
        with patch.object(hub, "signin_ended", ended):
            self.sweep()
        self.assertEqual(len(said()), 2)            # so its next failure is told again

    def test_a_login_that_only_its_task_gives_ends_with_that_task(self):
        """A login that the task made in its current attempt (made_here), and a sealed copy of a handover: their use
        is the task's, so their clear waits for its end. An agent that left team.json takes its records with it and
        gets no event: its user and its browser went with it."""
        for login, made in ((LOGIN, True), ("sealed:4", False)):
            hub.q("UPDATE tasks SET state='working' WHERE id=?", (self.tid,))
            self.signed(self.job(login=login))
            with patch.object(hub, "made_here", lambda agent, t, l: {"id": 1} if made else None):
                self.sweep()
                self.assertEqual(len(self.records()), 1, login)
                hub.q("UPDATE tasks SET state='completed' WHERE id=?", (self.tid,))
                self.sweep()
            self.assertEqual(self.records(), [], login)
        self.assertEqual(len(self.clears()), 2)
        self.signed(self.job())
        del hub.TEAM["agents"]["beta"]
        self.sweep()
        self.assertEqual((self.records(), len(self.clears())), ([], 2))


class MacVaultNumber(unittest.TestCase):
    def test_a_mac_vaults_error_number_reaches_the_agent_with_its_words(self):
        """A Mac vault's error that has no words of its own (Chrome's or macOS's number, 20 November 2026) gives its number
        beside "Chrome gave the vault no answer, or an unknown error.". The vault logs nothing that the hub reads, so a
        helper that drops the number leaves a timeout and every other fault the same."""
        import socket
        home = tempfile.mkdtemp(prefix="vn", dir="/tmp")             # a socket's path has at most 104 bytes
        self.addCleanup(shutil.rmtree, home, True)
        path = os.path.join(home, "vault.sock")
        server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server_socket.close)
        server_socket.bind(path)
        server_socket.listen(1)

        def answer():
            connection, _ = server_socket.accept()
            with connection, connection.makefile("rwb") as stream:
                stream.readline()
                stream.write(b'{"ok": false, "v": 2, "error": "Chrome gave the vault no answer, or an unknown error.", '
                             b'"number": -1712}\n')
                stream.flush()

        vault_side = threading.Thread(target=answer)
        vault_side.start()
        with patch.object(fleet, "vault_socket", lambda: path), patch.object(fleet.sys, "platform", "darwin"), \
                self.assertRaises(fleet.Refused) as got:
            fleet.vault_call({"op": "signin", "job": 7}, timeout=5)
        vault_side.join(5)
        self.assertEqual(str(got.exception), "the vault broker refused: Chrome gave the vault no answer, or an unknown "
                                             "error. (Chrome or macOS error -1712)")

    def test_a_tab_that_left_the_site_after_the_login_went_is_no_sign_in_and_no_refusal(self):
        """The Mac vault answers "left": true when the tab left the login's site, or closed, after the login went (a
        single sign-on page, a site's own redirect). The helper says that the login went and that the agent looks at
        the page: "Signed in", which nobody saw, would hide a sign-in that failed, and a refusal would make the agent
        type the login again."""
        answer = {"ok": True, "v": 2, "job": 5, "origin": ORIGIN, "label": "Shop", "authenticator": False, "left": True}
        with patch.object(fleet, "vault_mode", lambda a: "broker"), patch.object(fleet, "broker_job", lambda agent, job: job), \
                patch.object(fleet, "broker_job_request", lambda agent, req: answer if req == {"op": "signin", "job": 5}
                             else {}):
            self.assertEqual(fleet.do_signin("bws://x", "beta", "T-1", 5),
                             f"The login was sent on {ORIGIN}, and the tab then left that site. Look at the page to see "
                             f"if you are signed in.")


if __name__ == "__main__":
    unittest.main()
