"""The practice page /site/mfa: a sign-in with an authenticator step, for a real sign_in without a customer site. The
hub runs in this process. A stand-in does the steps of the helper's sign-in (VaultBrowser.signIn in the app, do_signin
in fleet.py) on the pages as the hub sends them, and it makes each code with the helper's own function. Synthetic data
only: no vault, no Chrome, no real login, and no network other than 127.0.0.1."""
import base64
import hashlib
import html.parser
import http.client
import json
import re
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.server import ThreadingHTTPServer
from unittest.mock import patch

import fleet
import hub

SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"          # the published test key of RFC 6238: the totp of a login for it
USER, WORD = "pilot-mfa", "synthetic-word-for-mfa-0001"         # stand-ins; never a real value
OLD_USER, OLD_WORD = "pilot-a", "synthetic-word-for-old-0002"   # a user of /site/login, as before
LOGIN = {"username": USER, "password": WORD, "totp": SEED}
PHRASE = "amber birch cobalt 123"
AT = 1760000020.0                                   # a fixed time, 10 seconds after the start of a step of 30 seconds


def is_password(a):
    return (a.get("type") or "").lower() == "password"                          # input[type=password]


def is_text(a):
    return "type" not in a or (a["type"] or "").lower() in ("email", "text")    # the helper's user name field


def is_code(a):
    """The helper's selector of a code field (otpSelector in VaultBrowser.swift, OTP_FIELD in fleet.py):
    input[autocomplete=one-time-code],input[name*=otp i],input[id*=otp i],input[name=code],input[id=code]"""
    name, ident = a.get("name") or "", a.get("id") or ""
    return a.get("autocomplete") == "one-time-code" or "otp" in name.lower() or "otp" in ident.lower() \
        or name == "code" or ident == "code"


class Page(html.parser.HTMLParser):
    """What the helper's scripts look at in a page: each input, with the form that it is in."""
    def __init__(self, text):
        super().__init__()
        self.text, self.inputs, self.form = text, [], None
        self.feed(text)
        self.close()

    def handle_starttag(self, tag, attrs):
        if tag == "form":
            self.form = dict(attrs)
        elif tag == "input":
            self.inputs.append((dict(attrs), self.form))

    def handle_endtag(self, tag):
        if tag == "form":
            self.form = None

    def check(self):
        """The helper's check: "form" for a page with a password field, else "otp" for one with a code field, else
        "none", which is the signed-in page."""
        if any(is_password(a) for a, _ in self.inputs):
            return "form"
        return "otp" if any(is_code(a) for a, _ in self.inputs) else "none"


class Tab:
    """One browser tab on the hub. It keeps each cookie for the paths of its Path, and it follows a 303 with a GET."""
    def __init__(self, base):
        self.base, self.cookies, self.seen = base, {}, []
        self.path = self.status = self.page = None

    def send(self, method, path, form=None, data=None):
        """One request, not followed: (the status, the answer, the text). `data` is a JSON body in place of a form."""
        at = urllib.parse.urlsplit(self.base)
        headers = {"Content-Type": "application/json" if data is not None else "application/x-www-form-urlencoded"} \
            if form is not None or data is not None else {}
        mine = "; ".join(f"{name}={value}" for name, (value, where) in self.cookies.items()
                         if path == where or path.startswith(where.rstrip("/") + "/"))
        if mine:
            headers["Cookie"] = mine
        conn = http.client.HTTPConnection(at.hostname, at.port, timeout=5)
        try:
            conn.request(method, path, json.dumps(data) if data is not None else
                         urllib.parse.urlencode(form) if form is not None else None, headers)
            answer = conn.getresponse()
            text = answer.read().decode()
        finally:
            conn.close()
        for line in answer.headers.get_all("Set-Cookie") or []:
            pair, *more = [part.strip() for part in line.split(";")]
            name, _, value = pair.partition("=")
            self.cookies[name] = (value, next((m[5:] for m in more if m.lower().startswith("path=")), "/"))
        self.seen.append((method, path, answer.status, answer.getheader("Location"), answer.getheader("Set-Cookie"),
                          answer.getheader("Cache-Control"), text))
        return answer.status, answer, text

    def go(self, method, path, form=None, data=None):
        """As a browser does it: the request, then a GET of each 303 on this origin. Returns the page that the tab
        then shows."""
        status, answer, text = self.send(method, path, form, data)
        while status == 303:
            path = answer.getheader("Location")
            assert path.startswith("/") and not path.startswith("//"), path     # the same origin
            status, answer, text = self.send("GET", path)
        self.path, self.status, self.page = path, status, Page(text)
        return self.page


class NotConfirmed(Exception):
    """The helper's refusal: Chrome did not confirm the sign-in."""


def helper_sign_in(tab, login, at=None):
    """The helper's sign-in in the page that a tab shows, step for step, without its two waits of 3 seconds. It finds
    the fields as the helper's scripts do and takes their names from the page. It sends only the fields of the form,
    as requestSubmit() does without a button. True: signed in with a code. False: signed in without one."""
    def submit(field, values):
        attrs, form = field
        action = urllib.parse.urljoin(tab.base + tab.path, (form or {}).get("action") or "")
        if form is None or hub.origin(action) != hub.origin(tab.base):
            raise NotConfirmed("no-form" if form is None else "wrong-action")
        fields = {a["name"]: a.get("value") or "" for a, f in tab.page.inputs if f is form and a.get("name")}
        tab.go("POST", urllib.parse.urlsplit(action).path, dict(fields, **values))

    password = next((x for x in tab.page.inputs if is_password(x[0])), None)
    if password is None:
        raise NotConfirmed("no-form")
    user = next((x for x in tab.page.inputs if x[1] is password[1] and is_text(x[0])), None)
    submit(password, {x[0]["name"]: value
                      for x, value in ((user, login["username"]), (password, login["password"])) if x})
    if tab.page.check() == "none":
        return False
    if not login.get("totp") or tab.page.check() != "otp":
        raise NotConfirmed(tab.page.check())
    code = next(x for x in tab.page.inputs if is_code(x[0]))
    submit(code, {code[0]["name"]: fleet.totp_code(login["totp"], at)})         # one code for one sign-in
    if tab.page.check() != "none":
        raise NotConfirmed(tab.page.check())
    return True


class SiteMfa(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="fleet-site-mfa-")
        self.addCleanup(self.tmp.cleanup)
        hub.DB = sqlite3.connect(self.tmp.name + "/test.db", check_same_thread=False)
        hub.DB.row_factory = sqlite3.Row
        hub.DB.executescript(hub.SCHEMA)
        hub.migrate()
        self.addCleanup(hub.DB.close)
        hub.TEAM = {"addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2"}, "hub": {"machine": "hub", "port": 8765},
                    "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []}}}
        hub.kv_set("site_phrase", PHRASE)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), hub.Handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.register("pilot-site-mfa", USER, WORD)
        self.register("pilot-site-a", OLD_USER, OLD_WORD)

    # ---- helpers
    def register(self, label, user, word):
        """The owner's existing route for the fingerprint of a practice login with its user name. No password goes to
        the hub."""
        salt = hashlib.sha256(label.encode()).hexdigest()[:16]
        status, _, text = Tab(self.base).send("POST", "/secrets", {
            "label": label, "salt": salt, "len": len(word), "username": user,
            "hash": hashlib.sha256((salt + word).encode()).hexdigest()})
        self.assertEqual((status, json.loads(text)), (200, {"ok": True}))

    def tab(self, path="/site/mfa"):
        tab = Tab(self.base)
        tab.go("GET", path)
        return tab

    def account(self, tab):
        """What the account page shows: (the user, the sign-in number, the phrase). None for each other page."""
        found = [re.search(rf"<b id='{name}'>([^<]*)</b>", tab.page.text) for name in ("user", "signin", "phrase")]
        return tuple(m.group(1) for m in found) if all(found) else None

    def visit(self):
        return {r["k"]: r["v"] for r in hub.q("SELECT k, v FROM kv WHERE k LIKE 'site_mfa%'")}

    def site_log(self):
        return [r["what"] for r in hub.q("SELECT what FROM log WHERE agent='site' ORDER BY id")]

    # ---- the code
    def test_the_code_is_the_rfc_6238_code_of_the_published_key(self):
        self.assertEqual(base64.b32encode(hub.MFA_SEED).decode(), SEED)         # what a login for the page has in totp
        # RFC 6238, appendix B, SHA-1: the published codes have 8 digits; a code of 6 digits is their last 6
        for at, code in ((59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                         (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")):
            self.assertEqual(hub.mfa_code(at), code[2:])
            self.assertEqual(hub.mfa_code(at), fleet.totp_code(SEED, at))       # what the helper types for this seed

    def test_a_code_of_this_step_or_of_the_step_before_or_after_is_right(self):
        codes = [fleet.totp_code(SEED, AT + shift) for shift in (-60, -30, 0, 30, 60)]
        self.assertEqual(len(set(codes)), 5)
        start, end = AT - 10, AT + 19.999                                       # the first and last moment of a step
        for clock, typed, right in ((AT, AT - 60, False), (AT, AT - 30, True), (AT, AT, True), (AT, AT + 30, True),
                                    (AT, AT + 60, False),
                                    (start, start - 0.001, True),               # typed as a step ended, arrived later
                                    (end, end + 0.002, True),                   # a helper clock that is a little ahead
                                    (start, start - 30.001, False), (end, end + 30.002, False)):
            with self.subTest(clock=clock, typed=typed), patch.object(hub, "now", return_value=clock):
                tab = self.tab()
                if right:
                    self.assertTrue(helper_sign_in(tab, LOGIN, typed))
                    self.assertEqual(self.account(tab)[0], USER)
                else:
                    with self.assertRaises(NotConfirmed):
                        helper_sign_in(tab, LOGIN, typed)
                    self.assertEqual((tab.page.check(), self.visit()["site_mfa_state"]), ("otp", "code"))
        # A synthetic fixture: the site takes a code again. Two sign_in calls in one step type the same code.
        with patch.object(hub, "now", return_value=AT):
            count = int(hub.kv_get("site_mfa_count"))
            for n in (1, 2):
                tab = self.tab()
                self.assertTrue(helper_sign_in(tab, LOGIN, AT))
                self.assertEqual(self.account(tab), (USER, str(count + n), PHRASE))

    # ---- the pages and the steps
    def test_the_helper_signs_in_with_a_code_and_again_after_the_expiry(self):
        tab = self.tab()
        self.assertEqual((tab.status, tab.page.check(), self.account(tab)), (200, "form", None))
        self.assertEqual(tab.page.text, hub.site_page("Pilot site: sign in with an authenticator", hub.MFA_FORM))
        self.assertEqual(hub.MFA_FORM, hub.LOGIN_FORM.replace("action='/site/login'", "action='/site/mfa'"))
        self.assertTrue(helper_sign_in(tab, LOGIN))                             # "with its authenticator code"
        self.assertEqual((tab.path, tab.status, tab.page.check()), ("/site/mfa", 200, "none"))
        self.assertEqual((self.account(tab), tab.page.inputs), ((USER, "1", PHRASE), []))
        token = hub.kv_get("site_mfa_token")
        self.assertRegex(token, "^[0-9a-f]{32}$")
        self.assertEqual(self.visit(), {"site_mfa_token": token, "site_mfa_user": USER, "site_mfa_state": "in",
                                        "site_mfa_count": "1"})
        # Each step is a POST, a 303 and a GET of the same address in the same tab. Only the password step sets the
        # cookie.
        self.assertEqual([step[:6] for step in tab.seen], [
            ("GET", "/site/mfa", 200, None, None, "no-store"),
            ("POST", "/site/mfa", 303, "/site/mfa", f"pilot_mfa={token}; Path=/site/mfa; HttpOnly", None),
            ("GET", "/site/mfa", 200, None, None, "no-store"),
            ("POST", "/site/mfa", 303, "/site/mfa", None, None),
            ("GET", "/site/mfa", 200, None, None, "no-store")])
        code_page = Page(tab.seen[2][6])                                        # the authenticator form, as it was sent
        self.assertEqual(code_page.text, hub.site_page("Pilot site: authenticator code", hub.MFA_CODE_FORM))
        self.assertEqual(code_page.inputs, [
            ({"type": "text", "name": "otp", "id": "otp", "inputmode": "numeric", "autocomplete": "one-time-code"},
             {"method": "post", "action": "/site/mfa"})])
        self.assertEqual(code_page.check(), "otp")                              # no password field in this page

        # The explicit expiry, from another machine and without the cookie. The browser keeps its cookie.
        status, answer, _ = Tab(self.base).send("GET", "/site/mfa/expire")
        self.assertEqual((status, answer.getheader("Location"), answer.getheader("Set-Cookie")),
                         (303, "/site/mfa", None))
        self.assertEqual((self.visit()["site_mfa_state"], tab.cookies),
                         ("expired", {"pilot_mfa": (token, "/site/mfa")}))
        page = tab.go("GET", "/site/mfa")                                       # the tab loads the page again
        self.assertEqual((page.check(), self.account(tab)), ("form", None))
        self.assertEqual(page.text, hub.site_page("Pilot site: sign in with an authenticator",
                                                  "<p>Your session expired. Sign in again.</p>" + hub.MFA_FORM))
        self.assertTrue(helper_sign_in(tab, LOGIN))                             # the same tab, a new sign-in
        self.assertEqual(self.account(tab), (USER, "2", PHRASE))
        self.assertNotEqual(hub.kv_get("site_mfa_token"), token)

        # The link of the account page is the same expiry. A second expiry changes nothing.
        link = re.search(r"<a href='([^']+)'>End this session \(test expiry\)</a>", tab.page.text).group(1)
        page = tab.go("GET", link)
        self.assertEqual((link, tab.path, page.check()), ("/site/mfa/expire", "/site/mfa", "form"))
        self.assertIn("Your session expired. Sign in again.", page.text)
        tab.go("GET", link)
        self.assertEqual(self.site_log(), [
            f"the authenticator practice page took the password of {USER}",
            f"the authenticator practice page signed in {USER} with a code (sign-in 1)",
            f"the authenticator practice page ended the session of {USER} (test expiry)",
            f"the authenticator practice page took the password of {USER}",
            f"the authenticator practice page signed in {USER} with a code (sign-in 2)",
            f"the authenticator practice page ended the session of {USER} (test expiry)"])

    def test_a_wrong_password_or_a_wrong_code_signs_nobody_in(self):
        status, _, _ = Tab(self.base).send("GET", "/site/mfa/expire")           # an expiry without a visit
        self.assertEqual((status, self.visit(), self.site_log()), (303, {}, []))
        tab = self.tab()
        for user, word in ((USER, WORD + "x"), (USER, WORD[:-1]), (USER, ""), ("nobody", WORD), (OLD_USER, WORD),
                           ("", WORD)):
            with self.subTest(user=user, word=len(word)):
                with self.assertRaises(NotConfirmed):
                    helper_sign_in(tab, dict(LOGIN, username=user, password=word))
                self.assertEqual((tab.status, tab.page.check(), "Wrong login." in tab.page.text), (200, "form", True))
        page = tab.go("POST", "/site/mfa", data={"username": 7, "password": [WORD]})    # values that are no text
        self.assertEqual((tab.status, page.check(), "Wrong login." in page.text), (200, "form", True))
        self.assertEqual((self.visit(), tab.cookies), ({}, {}))                 # a refused password starts no visit

        # The right password of a login without a seed: the helper stops at the code form, and the visit waits.
        with self.assertRaises(NotConfirmed):
            helper_sign_in(tab, {"username": USER, "password": WORD})
        self.assertEqual((tab.page.check(), self.visit()["site_mfa_state"], self.account(tab)), ("otp", "code", None))
        near = {hub.mfa_code(time.time() + shift) for shift in range(-90, 91, 30)}
        wrong = next(code for code in (f"{n:06d}" for n in range(10)) if code not in near)
        for code in (wrong, "12345", "1234567", "12345a", "１２３４５６"):
            page = tab.go("POST", "/site/mfa", {"otp": code})
            self.assertEqual((tab.status, page.check(), "Wrong code." in page.text), (200, "otp", True), code)
        page = tab.go("POST", "/site/mfa", data={"otp": 123456})
        self.assertEqual((tab.status, page.check(), "Wrong code." in page.text), (200, "otp", True))
        # A request without the field otp is the password step. The visit continues to wait for the code.
        page = tab.go("POST", "/site/mfa", {"otp": ""})
        self.assertEqual((page.check(), "Wrong login." in page.text, self.visit()["site_mfa_state"]),
                         ("form", True, "code"))
        self.assertEqual(tab.go("GET", "/site/mfa").check(), "otp")
        self.assertEqual(self.visit()["site_mfa_state"], "code")                # no refusal changed the visit
        tab.go("POST", "/site/mfa", {"otp": fleet.totp_code(SEED)})
        self.assertEqual(self.account(tab), (USER, "1", PHRASE))
        log = self.site_log()
        self.assertEqual((log.count("the authenticator practice page REFUSED a password"),
                          log.count(f"the authenticator practice page REFUSED a code for {USER}")), (8, 6))

    def test_the_site_keeps_one_visit_and_a_code_needs_the_cookie_of_the_visit(self):
        first = self.tab()
        self.assertTrue(helper_sign_in(first, LOGIN))
        second = self.tab()                                                     # another browser: the plain form
        self.assertEqual((second.page.check(), "expired" in second.page.text), ("form", False))
        second.go("POST", "/site/mfa", {"username": USER, "password": WORD})
        self.assertEqual((second.page.check(), self.visit()["site_mfa_state"]), ("otp", "code"))
        page = first.go("GET", "/site/mfa")                                     # its cookie is not the visit's any more
        self.assertEqual((page.check(), self.account(first), "expired" in page.text), ("form", None, False))
        for other in (Tab(self.base), first):                                   # a code without the cookie of the visit
            page = other.go("POST", "/site/mfa", {"otp": fleet.totp_code(SEED)})
            self.assertEqual((page.check(), "Wrong login." in page.text, self.visit()["site_mfa_state"]),
                             ("form", True, "code"))
        second.go("POST", "/site/mfa", {"otp": fleet.totp_code(SEED)})
        self.assertEqual(self.account(second), (USER, "2", PHRASE))

    # ---- the logins that the page takes
    def test_the_page_takes_a_practice_login_by_the_fingerprint_with_its_user_name(self):
        ref, word = "bws://51111111-2222-4333-8444-55555555555b", "synthetic-word-for-add-0003"

        def mark(login, kind, value):
            return {"kind": kind, "len": len(value), "hash": hashlib.sha256(
                (hub.fingerprint_salt(hub.fingerprint_label(login, kind)) + value).encode()).hexdigest()}
        # The fingerprints of the app's Add login form have no user name: they sign nobody in.
        self.assertEqual(hub.register_fingerprints(ref, [mark(ref, "password", word), mark(ref, "totp", SEED)]), (2, 0))
        tab = self.tab()
        with self.assertRaises(NotConfirmed):
            helper_sign_in(tab, dict(LOGIN, username="added-user", password=word))
        self.assertIn("Wrong login.", tab.page.text)
        # The owner's fingerprint route gives the user name: the same login then signs in.
        self.register("pilot-site-added", "added-user", word)
        self.assertTrue(helper_sign_in(tab, dict(LOGIN, username="added-user", password=word)))
        self.assertEqual(self.account(tab), ("added-user", "1", PHRASE))
        # A login that a task made for this hub (create_login): as at /site/login, and the log names it.
        made, value = "bws://61111111-2222-4333-8444-55555555555b", "synthetic-word-for-made-0004"
        hub.register_fingerprints(made, [mark(made, "password", value)])
        hub.ins("INSERT INTO jobs(agent,task,kind,login,created,ok,finished,username,url) "
                "VALUES('studio',1,'create',?,?,1,?,?,?)",
                (made, hub.now(), hub.now(), "made-user", "http://127.0.0.2:8765/site/mfa"))
        tab = self.tab()
        self.assertTrue(helper_sign_in(tab, dict(LOGIN, username="made-user", password=value)))
        self.assertEqual(self.account(tab), ("made-user", "2", PHRASE))
        self.assertIn(f"the authenticator practice page took the password of made-user with the made login {made}",
                      self.site_log())

    # ---- what stays as it is
    def test_the_users_and_the_session_of_site_login_stay_as_they_are(self):
        self.assertEqual(Tab(self.base).send("GET", "/site/login")[2],
                         hub.site_page("Pilot site: sign in", hub.LOGIN_FORM))
        self.assertIn("<form method='post' action='/site/login'>", hub.LOGIN_FORM)
        old = self.tab("/site/login")
        self.assertFalse(helper_sign_in(old, {"username": OLD_USER, "password": OLD_WORD}))     # no code is asked there
        self.assertEqual((old.path, f"<b id='user'>{OLD_USER}</b>" in old.page.text), ("/site/account", True))
        kept = {k: hub.kv_get(k) for k in ("site_session", "site_user", "site_phrase")}
        self.assertEqual((old.cookies, kept["site_user"]), ({"pilot": (kept["site_session"], "/")}, OLD_USER))

        tab = self.tab()                                                        # a sign-in, an expiry and a sign-in
        self.assertTrue(helper_sign_in(tab, LOGIN))
        tab.go("GET", "/site/mfa/expire")
        self.assertTrue(helper_sign_in(tab, LOGIN))
        self.assertEqual({k: hub.kv_get(k) for k in kept}, kept)                # no record of /site/login changed
        self.assertIn(f"<b id='user'>{OLD_USER}</b>", old.go("GET", "/site/account").text)

        # Each cookie opens only its own page.
        token = hub.kv_get("site_mfa_token")
        self.assertEqual(tab.cookies, {"pilot_mfa": (token, "/site/mfa")})
        self.assertEqual(tab.go("GET", "/site/account").check(), "form")        # the browser does not send it there
        self.assertEqual((tab.path, tab.seen[-2][2:4]), ("/site/login", (303, "/site/login")))
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        self.addCleanup(conn.close)
        conn.request("GET", "/site/account", headers={"Cookie": f"pilot_mfa={token}; pilot={token}"})
        answer = conn.getresponse()
        self.assertEqual((answer.status, answer.getheader("Location"), answer.read()), (303, "/site/login", b""))
        page = old.go("GET", "/site/mfa")                                       # the cookie of /site/login goes there
        self.assertEqual((old.seen[-1][2], page.check(), self.account(old)), (200, "form", None))

        # The same user at /site/login: the password only, as each practice user. The visit of /site/mfa stays.
        third = self.tab("/site/login")
        self.assertFalse(helper_sign_in(third, LOGIN))
        self.assertEqual((third.path, hub.kv_get("site_user")), ("/site/account", USER))
        third.go("GET", "/site/logout")
        self.assertEqual((hub.kv_get("site_session"), hub.kv_get("site_user")), (None, None))
        tab.go("GET", "/site/mfa")
        self.assertEqual(self.account(tab), (USER, "2", PHRASE))
        self.assertEqual([line for line in self.site_log() if "authenticator" not in line], [
            f"a sign-in to the practice site succeeded as {OLD_USER}",
            f"a sign-in to the practice site succeeded as {USER}"])

    def test_no_password_seed_or_code_is_in_a_record_or_in_a_page(self):
        right, wrong = fleet.totp_code(SEED, AT), fleet.totp_code(SEED, AT + 90)
        self.assertNotEqual(right, wrong)
        tabs = [self.tab(), self.tab()]
        with patch.object(hub, "now", return_value=AT):
            with self.assertRaises(NotConfirmed):
                helper_sign_in(tabs[0], dict(LOGIN, password=WORD + "x"))
            with self.assertRaises(NotConfirmed):
                helper_sign_in(tabs[0], LOGIN, AT + 90)
            self.assertTrue(helper_sign_in(tabs[1], LOGIN, AT))
            tabs[1].go("GET", "/site/mfa/expire")
        token = hub.kv_get("site_mfa_token")
        tables = [r["name"] for r in hub.q("SELECT name FROM sqlite_master WHERE type='table'")]
        # A blob is read as text rather than skipped, so the check still covers it: the search index of an agent's
        # own memory keeps its text in one (memory_fts_data.block), and a secret written into a lesson would be
        # there too. It is not — memory_indexed indexes the row, which guard and mask_secrets have already been
        # through — and this is what says so.
        kept = json.dumps([dict(r) for table in tables for r in hub.q(f"SELECT * FROM {table}")],
                          default=lambda o: o.decode("utf-8", "replace") if isinstance(o, bytes) else repr(o))
        pages = "".join(step[6] for tab in tabs for step in tab.seen)
        self.assertIn(USER, kept)
        self.assertIn("Wrong code.", pages)
        for value in (WORD, SEED, hub.MFA_SEED.decode()):
            self.assertNotIn(value, kept)
            self.assertNotIn(value, pages)
        written = json.dumps([self.site_log(), {k: v for k, v in self.visit().items() if k != "site_mfa_token"}])
        for value in (right, wrong, token):                                     # the token: only its record and cookie
            self.assertNotIn(value, written)
            self.assertNotIn(value, pages)
        self.assertEqual(sorted(self.visit()), ["site_mfa_count", "site_mfa_state", "site_mfa_token", "site_mfa_user"])
        # The page writes to no other table. The search indexes of an agent's own memory and of its history are
        # left out of the comparison and not added to it: FTS5 writes its config and one empty data block when
        # migrate creates the table, so its shadow tables are non-empty from birth rather than from anything this
        # page did. The roles table is left out for the same reason: migrate writes its three default roles
        # (AUTONOMY.md P1).
        self.assertEqual({t for t in tables if not t.startswith(("memory_fts", "history_fts")) and t != "roles"
                          and hub.q(f"SELECT 1 FROM {t} LIMIT 1")},
                         {"kv", "log", "secrets"})


if __name__ == "__main__":
    unittest.main()
