"""The owner signs a machine in from the app (machine_signin): the hub starts the provider's own flow on the machine
the credential belongs to, passes the link along, and hands the code the owner got back to that machine.

What these checks are really about. A platform may host the unmodified Claude Code only while each end user signs in
through the provider's own flow and the operator never collects, stores or intermediates the credential. The whole
feature is that sentence turned into code, so the tests that matter here are the refusals and the absences:

  - no long-lived token path (`claude setup-token` and anything like it),
  - the link, the code the provider shows and the code the owner pastes reach no row, no event and no log line,
  - the code reaches the machine once and is then gone,
  - a machine cannot send the owner to an address that is not the provider's own,
  - Grok has no sign-in path at all, because xAI's terms do not allow one.

In-process hub, no machine, no tmux, no provider and no AI call. The helper side is checked against its own stand-ins:
the exact `claude` invocation and what it prints cannot be checked here, because checking them means signing in with a
real credential. That is the operator's first live step, and `runtime_login_command` keeps it to one line.
"""
import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import fleet
import lifecycle
import hub
from test_release_turns import helper_reports
from test_ui_api import OwnerAPI, SourceHandler

CLAUDE_URL = "https://claude.ai/oauth/authorize?code=1&state=abc"
CODEX_URL = "https://auth.openai.com/activate?user_code=WXYZ-1234"
CODE = "AbCd-1234-EfGh"             # what the provider gives the owner, and the one thing that must leave no trace
KIT = Path(__file__).resolve().parent
REAL_SLEEP = time.sleep             # the test's own waits, while a helper under test sleeps a stand-in


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (Signin, AnotherAccount, NoCredentialKept, HubRestart, HelperSide, NoTokenPath):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class Machines(OwnerAPI):
    """One worker, `solo`, on a machine of its own, with a helper that reports."""

    def setUp(self):
        super().setUp()
        hub.TEAM = {"addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "box": "127.0.0.3"},
                    "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                               "solo": {"role": "worker", "runtime": "claude", "machine": "box", "can": ["shell"]}}}
        hub.LIVE_LOGINS.clear()
        self.addCleanup(hub.LIVE_LOGINS.clear)
        self.reports("solo")

    # ---- helpers
    def reports(self, agent, claude=False, codex=None, seen=0.0):
        """This machine's helper is checking in, and says whether each runtime is signed in."""
        hub.q("INSERT OR REPLACE INTO agents(name,last_seen) VALUES(?,?)", (agent, hub.now() - seen))
        data = {"runtimes": {"claude": {"version": "2.1.287", "signed_in": claude},
                             "codex": {"version": "0.160.0", "signed_in": codex}}}
        hub.q("INSERT OR REPLACE INTO machine_status(agent,data,reported) VALUES(?,?,?)",
              (agent, json.dumps(data), hub.now()))

    def start(self, agent="solo", runtime="claude", **changes):
        return self.request(f"/ui/machines/{agent}/signin",
                            self.command(**dict({"runtime": runtime}, **changes)))

    def send_code(self, agent="solo", code=CODE, **changes):
        return self.request(f"/ui/machines/{agent}/signin/code", self.command(**dict({"code": code}, **changes)))

    def machine_report(self, lid, agent="solo", **fields):
        """As that machine's own helper: from its own address, which is the rule these routes keep."""
        return self.request(f"/helper/login/{agent}/{lid}", fields, source="127.0.0.3")

    def machine_asks(self, lid, agent="solo"):
        return self.request(f"/helper/login/{agent}/{lid}", None, source="127.0.0.3")

    def row(self, lid):
        return hub.q1("SELECT * FROM signin_jobs WHERE id=?", (lid,))

    def view(self, agent="solo"):
        code, state = self.request("/ui/machines?db=test-generation")
        self.assertEqual(code, 200, state)
        return next(m for m in state["machines"] if m["agent"] == agent)["login"]

    def machine_says(self, agent="solo", claude=None, codex=None):
        """That machine's helper checking in through its own route, so the hub reads the report as it really does."""
        return self.request(f"/helper/status/{agent}", {
            "os": {"name": "Debian GNU/Linux 12", "kernel": "6.1.0"}, "update": {"state": None, "detail": None},
            "runtime": {"name": "claude", "version": "2.1.287", "signed_in": claude},
            "runtimes": {"claude": {"version": "2.1.287", "signed_in": claude},
                         "codex": {"version": "0.160.0", "signed_in": codex}}}, source="127.0.0.3")

    def waiting_job(self, runtime="claude", agent="solo", kind="install"):
        """A server job of that agent parked at its sign-in step, as a server service leaves one."""
        t0 = hub.now()
        return hub.ins("INSERT INTO server_jobs(server,kind,agent,runtime,state,step,detail,prompt,created,updated) "
                       "VALUES('box',?,?,?,'needs_owner','sign_in',?,?,?,?)",
                       (kind, agent, runtime, "Sign in to Codex with this code.",
                        json.dumps({"kind": "open_url", "purpose": "codex_login",
                                    "url": CODEX_URL, "code": "WXYZ-1234"}), t0, t0))

    def job(self, jid):
        return hub.q1("SELECT * FROM server_jobs WHERE id=?", (jid,))

    def open_one(self, runtime="claude", url=CLAUDE_URL, wants=True, shown=None):
        """A sign-in that waits for the owner, as the machine would leave it."""
        code, answer = self.start(runtime=runtime)
        self.assertEqual(code, 200, answer)
        lid = answer["login"]["id"]
        code, said = self.machine_report(lid, state="needs_owner", url=url, wants_code=wants, shows_code=shown)
        self.assertEqual(code, 200, said)
        return lid


class Signin(Machines):
    """The flow and its refusals."""

    def test_the_owner_starts_it_and_the_machine_is_asked(self):
        code, answer = self.start()
        self.assertEqual(code, 200, answer)
        self.assertEqual((answer["changed"], answer["login"]["state"], answer["login"]["runtime"]),
                         (True, "starting", "claude"))
        event = hub.q1("SELECT * FROM events WHERE agent='solo' AND kind='login' ORDER BY id DESC")
        self.assertEqual(json.loads(event["extra"]),
                         {"login": answer["login"]["id"], "runtime": "claude", "replace": False})

    def test_a_second_start_gives_back_the_open_one(self):
        first = self.start()[1]["login"]["id"]
        code, answer = self.start()
        self.assertEqual((code, answer["changed"], answer["login"]["id"]), (200, False, first))
        self.assertEqual(self.count("signin_jobs"), 1)

    def test_grok_has_no_sign_in_path(self):
        code, answer = self.start(runtime="grok")
        self.assertEqual(code, 409, answer)
        self.assertIn("xAI's terms", answer["error"])
        self.assertEqual(self.count("signin_jobs"), 0)

    def test_only_claude_and_codex(self):
        self.assertEqual(hub.LOGIN_RUNTIMES, ("claude", "codex"))
        for runtime in ("gemini", "", "CLAUDE", "llama"):
            code, answer = self.start(runtime=runtime)
            self.assertEqual(code, 400, answer)
        self.assertEqual(self.count("signin_jobs"), 0)

    def test_a_runtime_that_is_signed_in_already_is_refused(self):
        self.reports("solo", claude=True)
        code, answer = self.start()
        self.assertEqual(code, 409, answer)
        self.assertIn("signed in", answer["error"])

    def test_a_machine_whose_helper_is_silent_is_refused(self):
        self.reports("solo", seen=hub.MACHINE_STALE + 60)
        code, answer = self.start()
        self.assertEqual(code, 409, answer)
        self.assertEqual("Solo is not answering. Check that its server is on.", answer["error"])

    def test_a_sign_in_reading_from_an_hour_ago_does_not_refuse_the_sign_in(self):
        """A machine whose last reading said "signed in" and whose credential has gone since must not be refused
        on that reading. Its helper is still reporting here, so there is nothing wrong with this machine but the
        age of the one thing the route read, and the owner was told "its own sign-out comes first" — a dead end
        with the wrong reason. A reading older than MACHINE_STALE says nothing, as it does everywhere else."""
        self.reports("solo", claude=True)
        hub.q("UPDATE machine_status SET reported=? WHERE agent=?", (hub.now() - hub.MACHINE_STALE - 60, "solo"))
        self.assertIsNone(hub.signed_in_now("solo", "claude"))
        code, answer = self.start()
        self.assertEqual(code, 200, answer)

    def test_an_unknown_agent_is_refused(self):
        self.assertEqual(self.start(agent="nobody")[0], 404)

    def test_the_machine_reports_the_link_and_the_owner_sees_it(self):
        lid = self.open_one()
        self.assertEqual(self.row(lid)["state"], "needs_owner")
        seen = self.view()
        self.assertEqual((seen["state"], seen["url"], seen["wants_code"], seen["shows_code"]),
                         ("needs_owner", CLAUDE_URL, True, None))

    def test_codex_shows_its_own_code_and_asks_for_none_back(self):
        """Codex's device sign-in is the other direction: its code goes into the provider's page, not into the
        machine. One mechanism carries both."""
        self.reports("solo", codex=False)
        lid = self.open_one(runtime="codex", url=CODEX_URL, wants=False, shown="WXYZ-1234")
        seen = self.view()
        self.assertEqual((seen["url"], seen["shows_code"], seen["wants_code"]), (CODEX_URL, "WXYZ-1234", False))
        code, answer = self.send_code()
        self.assertEqual(code, 409, answer)
        self.assertIn("not waiting for a code", answer["error"])

    def test_the_code_goes_to_the_machine_once(self):
        lid = self.open_one()
        self.assertEqual(self.send_code()[0], 200)
        self.assertEqual(self.row(lid)["state"], "signing_in")
        code, first = self.machine_asks(lid)
        self.assertEqual((code, first["code"], first["stop"]), (200, CODE, False))
        code, again = self.machine_asks(lid)
        self.assertEqual((code, again.get("code")), (200, None), "the code was given a second time")

    def test_a_code_without_a_sign_in_waiting_is_refused(self):
        code, answer = self.send_code()
        self.assertEqual(code, 409, answer)
        self.start()                        # starting, not needs_owner yet
        code, answer = self.send_code()
        self.assertEqual(code, 409, answer)
        self.assertIn("not waiting for a code", answer["error"])

    def test_the_shape_of_a_code_is_checked(self):
        self.open_one()
        # A provider's own code can be long and carry a hash (Claude's is `code#state`); a terminal key cannot.
        for bad in ("ab", "x" * 220, "code with spaces", "code;rm -rf /", "e\\nEnter", "../etc"):
            code, answer = self.send_code(code=bad)
            self.assertEqual(code, 400, (bad, answer))

    def test_a_machine_cannot_send_the_owner_anywhere_else(self):
        """The link comes from the machine, so the hub pins it to the provider's own address: otherwise a machine
        could put a page of its own in front of the owner."""
        code, answer = self.start()
        lid = answer["login"]["id"]
        for bad in ("https://claude.ai.example.com/login", "https://evil.example/claude.ai", "http://claude.ai/login",
                    "https://auth.openai.com/activate", "javascript:alert(1)", "https://console.anthropic.com\\n"):
            code, said = self.machine_report(lid, state="needs_owner", url=bad, wants_code=True)
            self.assertEqual(code, 400, (bad, said))
        self.assertIsNone(self.view()["url"])
        self.assertEqual(self.row(lid)["state"], "starting")

    # ---- the screen follows the machine, not a clock
    #
    # The owner, 19 October 2026: "I entered the code, signed in but the app still said waiting for sign in?" He had
    # signed Codex in on the provider's own page, the credential was on the machine and its helper was saying so —
    # and both the sign-in and the install job that waited for it were still on the screen, with the code.

    def test_a_sign_in_the_machine_made_is_over(self):
        lid = self.open_one()
        self.assertEqual(self.machine_says(claude=True)[0], 200)
        row = self.row(lid)
        self.assertEqual((row["state"], row["detail"]), ("done", None))
        self.assertEqual(hub.LIVE_LOGINS, {}, "the link and any code must go with the sign-in")
        seen = self.view()
        self.assertEqual((seen["state"], seen["url"], seen["shows_code"]), ("done", None, None))

    def test_a_job_that_waits_at_its_sign_in_ends_with_it(self):
        """The sign-in is the last step of an install and of a preparation, so a job parked there is finished. Its
        words go with its prompt: a done job says what a done job of its kind did, not "Sign in with this code"."""
        self.reports("solo", codex=False)
        jid = self.waiting_job(runtime="codex")
        self.assertEqual(self.machine_says(codex=True)[0], 200)
        row = self.job(jid)
        self.assertEqual((row["state"], row["step"], row["detail"], row["prompt"]), ("done", "sign_in", None, None))

    def test_a_machine_that_is_not_signed_in_ends_nothing(self):
        lid, jid = self.open_one(), self.waiting_job()
        for says in (False, None):
            self.assertEqual(self.machine_says(claude=says)[0], 200)
            self.assertEqual(self.row(lid)["state"], "needs_owner")
            self.assertEqual(self.job(jid)["state"], "needs_owner")
        self.assertEqual(self.view()["url"], CLAUDE_URL, "a sign-in still waiting keeps its link")

    def test_only_what_that_runtime_was_waiting_for_ends(self):
        self.reports("solo", codex=False)
        lid = self.open_one(runtime="codex", url=CODEX_URL, wants=False, shown="WXYZ-1234")
        jid = self.waiting_job(runtime="codex")
        self.assertEqual(self.machine_says(claude=True, codex=False)[0], 200)
        self.assertEqual(self.row(lid)["state"], "needs_owner")
        self.assertEqual(self.job(jid)["state"], "needs_owner")

    def test_a_job_that_waits_somewhere_else_is_left_alone(self):
        self.reports("solo", codex=False)
        jid = self.waiting_job(runtime="codex")
        hub.q("UPDATE server_jobs SET step='runtime', prompt=NULL, detail='Installing Codex.' WHERE id=?", (jid,))
        self.assertEqual(self.machine_says(codex=True)[0], 200)
        self.assertEqual(self.job(jid)["state"], "needs_owner", "only the step that waits for a sign-in ends here")

    def test_the_machine_saying_it_too_is_not_a_conflict(self):
        """The machine's own report closed it here first; the machine says the same thing a few seconds later."""
        lid = self.open_one()
        self.assertEqual(self.machine_says(claude=True)[0], 200)
        code, said = self.machine_report(lid, state="done", detail=None)
        self.assertEqual((code, said.get("state")), (200, "done"), said)
        code, said = self.machine_report(lid, state="failed", detail="Claude Code did not report itself signed in.")
        self.assertEqual(code, 409, "a sign-in that is done does not become failed")
        self.assertEqual(self.row(lid)["state"], "done")

    def test_the_helper_watches_as_long_as_the_hub_keeps_it_open(self):
        """Three minutes was the measure of a person in a browser, and it called a real sign-in failed."""
        self.assertGreaterEqual(fleet.LOGIN_DONE_WAIT, hub.LOGIN_LIFE)

    def test_each_runtime_keeps_to_its_own_provider(self):
        self.reports("solo", codex=False)
        lid = self.open_one(runtime="codex", url=CODEX_URL, wants=False)
        self.assertEqual(self.row(lid)["state"], "needs_owner")
        code, answer = self.start()                 # the codex one is still open
        self.assertEqual(answer["login"]["runtime"], "codex")
        self.assertEqual(self.machine_report(lid, state="needs_owner", url=CLAUDE_URL, wants_code=True)[0], 400)

    def test_done_and_failed_end_it(self):
        lid = self.open_one()
        self.assertEqual(self.machine_report(lid, state="done", detail="Claude Code is signed in.")[0], 200)
        self.assertEqual(self.row(lid)["state"], "done")
        # A finished sign-in cannot be CHANGED. The machine saying the same thing again changes nothing and is no
        # conflict: the hub may have ended it first, from that machine's own status report.
        self.assertEqual(self.machine_report(lid, state="done")[0], 200)
        self.assertEqual(self.row(lid)["detail"], "Claude Code is signed in.")
        self.assertEqual(self.machine_report(lid, state="failed", detail="it did not")[0], 409)
        self.assertEqual(self.row(lid)["state"], "done")
        self.assertEqual(self.machine_asks(lid)[1], {"stop": True, "why": "done"})
        self.reports("solo", claude=True)
        self.assertEqual(self.start()[0], 409)                                   # and now it is signed in

    def test_a_sign_in_nobody_finishes_is_given_up(self):
        lid = self.open_one()
        hub.q("UPDATE signin_jobs SET updated=? WHERE id=?", (hub.now() - hub.LOGIN_LIFE - 1, lid))
        self.assertEqual((self.view()["state"], self.view()["timed_out"]), ("failed", True))   # it waited for him
        self.assertEqual(hub.LIVE_LOGINS, {})
        self.assertEqual(self.start()[1]["changed"], True)      # and the owner can start a new one

    def test_a_sign_in_that_only_waited_too_long_for_the_owner_says_so(self):
        """The owner, 6 November 2026, of "No code came back in 14 minutes." in orange under his provider cards: "that
        orange message does not make sense for the user! what is that?!" A sign-in that waited for him and got
        nothing is no fault, so the hub says which failure it was (`timed_out`), and the app shows no line for it."""
        lid = self.open_one()
        self.assertIs(self.view()["timed_out"], False)
        for bad in ({"state": "needs_owner", "url": CLAUDE_URL, "wants_code": True, "timed_out": True},
                    {"state": "failed", "detail": "x", "timed_out": "yes"}):
            self.assertEqual(self.machine_report(lid, **bad)[0], 400, bad)
        self.assertEqual(self.machine_report(lid, state="failed", timed_out=True,
                                             detail="No code came back in 14 minutes. Start the sign-in again.")[0], 200)
        self.assertEqual((self.view()["state"], self.view()["timed_out"]), ("failed", True))
        # Every other end is a failure he hears of: the machine's own error, and a code that went and did not sign in.
        lid = self.open_one()
        self.assertEqual(self.machine_report(lid, state="failed",
                                             detail="The machine hit an error during the sign-in. Try again.")[0], 200)
        self.assertEqual((self.view()["state"], self.view()["timed_out"]), ("failed", False))
        lid = self.open_one()
        self.assertEqual(self.send_code()[0], 200)
        hub.q("UPDATE signin_jobs SET updated=? WHERE id=?", (hub.now() - hub.LOGIN_LIFE - 1, lid))
        self.assertEqual((self.view()["state"], self.view()["timed_out"]), ("failed", False))

    def test_a_real_providers_link_is_not_too_long_for_the_hub(self):
        """The link Claude Code printed on 21 October 2026 ran to 465 characters — its scopes, its challenge and the
        page it comes back to — and the pattern allowed 400, so the hub refused the machine's report of the only
        link the owner could have opened."""
        link = ("https://claude.com/cai/oauth/authorize?code=true&client_id=" + "a" * 36 +
                "&response_type=code&redirect_uri=https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback"
                "&scope=org%3Acreate_api_key+user%3Aprofile+user%3Ainference+user%3Asessions%3Aclaude_code"
                "+user%3Afile_upload+user%3Aplugins&code_challenge=" + "b" * 43 +
                "&code_challenge_method=S256&state=" + "c" * 43)
        self.assertGreater(len(link), 400, "longer than the pattern used to allow")
        self.assertRegex(link, fleet.LOGIN_URLS["claude"])
        lid = self.open_one(url=link)
        self.assertEqual(self.view()["url"], link, "the whole of it reaches the app")
        self.assertEqual(self.view()["state"], "needs_owner")
        self.assertEqual(lid, self.view()["id"])

    def test_the_code_a_provider_gives_is_the_shape_that_provider_gives(self):
        """**Claude's own code is `code#state`** — two random parts and a hash, about ninety characters. The hub's
        rule took forty-one and no hash, so the one code the owner had was refused before it was ever sent (21
        October 2026). The machine types it with `send-keys -l`, and what that allows is what this takes."""
        real = "Xq7Lm2Np9Rs4Tv6Wy8Za1Bc3De5Fg0Hj#mK3bQ9wR2tV5yH8jL4nC6dF0gS1aZ7eX"
        lid = self.open_one()
        for bad in ("abc", "has space 1234", "semi;colon1234", "x" * 220):
            self.assertEqual(self.send_code(code=bad)[0], 400, bad[:20])
        self.assertEqual(self.send_code(code=real)[0], 200)
        self.assertEqual(hub.LIVE_LOGINS[lid]["code"], real)

    def test_a_sign_in_whose_link_the_hub_lost_is_over(self):
        """**A hub that restarted kept no link.** The live part is in memory on purpose, so after a restart the
        owner has nothing to open and nothing can finish the sign-in — and the row would stand for a quarter of an
        hour refusing the next one, which is what the owner met on 21 October 2026."""
        lid = self.open_one()
        self.assertEqual(self.view()["state"], "needs_owner")
        hub.LIVE_LOGINS.clear()                                  # the hub restarted
        got = self.view()
        self.assertEqual((got["state"], got["url"], got["timed_out"]), ("failed", None, False))
        self.assertIn("restarted", got["detail"])
        self.assertEqual(self.start()[1]["changed"], True)       # and the owner can start a new one at once

    def test_a_sign_in_whose_machine_restarted_is_over(self):
        """A helper leaves `starting` within its own ninety seconds, one way or the other. One that stood there far
        longer went with its machine — an update of it, most often — and the window it left behind reads to nobody."""
        code, answer = self.start()
        lid = answer["login"]["id"]
        self.assertEqual((code, self.view()["state"]), (200, "starting"))
        hub.q("UPDATE signin_jobs SET updated=? WHERE id=?", (hub.now() - hub.LOGIN_START_LIFE - 1, lid))
        self.assertEqual((self.view()["state"], self.view()["timed_out"]), ("failed", False))    # a link never came
        self.assertIn("Start the sign-in again", self.view()["detail"])
        self.assertEqual(self.start()[1]["changed"], True)       # and the owner can start a new one at once

    def test_the_machines_page_shows_the_last_sign_in(self):
        self.assertIsNone(self.view())
        lid = self.open_one()
        self.assertEqual(self.view()["id"], lid)
        self.assertIn("machine_signin", self.request("/ui/state")[1]["ui_features"])


class AnotherAccount(Machines):
    """**Using a DIFFERENT account of the same provider** (`replace`), which is the whole reason a sign-out exists.

    No provider starts a second sign-in while one is live, so without this half the hub answered "its own sign-out
    comes first" — a step Founderizer had nowhere, which made the app's own button inert. The owner, 20 October
    2026, had a manager at 92% of its weekly allowance and an idle account of his own beside it.

    A sign-out stops the agent, so it is refused while the agent has work open, and the machine's own report of the
    account he is LEAVING must never be read as the sign-in he is waiting for.
    """

    def signed_in(self, agent="solo"):
        self.reports(agent, claude=True)

    def test_a_signed_in_runtime_is_refused_until_the_owner_asks_for_another_account(self):
        self.signed_in()
        code, answer = self.start()
        self.assertEqual(code, 409, answer)
        self.assertIn("Use another account signs it out first", answer["error"])
        self.assertEqual(self.count("signin_jobs"), 0)

    def test_another_account_signs_out_first_in_the_same_job(self):
        self.signed_in()
        code, answer = self.start(replace=True)
        self.assertEqual(code, 200, answer)
        self.assertEqual(answer["login"]["state"], "signing_out")
        event = hub.q1("SELECT * FROM events WHERE agent='solo' AND kind='login' ORDER BY id DESC")
        self.assertEqual(json.loads(event["extra"]),
                         {"login": answer["login"]["id"], "runtime": "claude", "replace": True})
        self.assertEqual(self.count("signin_jobs"), 1, "one job, not a sign-out job and a sign-in job")

    def test_asking_for_another_account_when_it_is_already_signed_out_is_an_ordinary_sign_in(self):
        """Nothing to sign out of, so no first half and nothing for the machine to do twice."""
        self.reports("solo", claude=False)
        code, answer = self.start(replace=True)
        self.assertEqual((code, answer["login"]["state"]), (200, "starting"), answer)
        event = hub.q1("SELECT * FROM events WHERE agent='solo' AND kind='login' ORDER BY id DESC")
        self.assertIs(json.loads(event["extra"])["replace"], False)

    def test_the_machine_still_saying_signed_in_does_not_finish_a_sign_out(self):
        """The reading is about the account he is LEAVING. Before this, the first report after the owner pressed
        the button closed the whole thing as done, and no link ever reached him."""
        self.signed_in()
        lid = self.start(replace=True)[1]["login"]["id"]
        self.assertEqual(self.machine_says(claude=True)[0], 200)
        self.assertEqual(self.row(lid)["state"], "signing_out")

    def test_a_reading_older_than_the_sign_out_finishes_nothing_either(self):
        """The machine's own status loop can post a reading it took before the sign-out. It says "signed in" about
        the old account, and it must not end the sign-in that is waiting for the new one."""
        self.signed_in()
        lid = self.start(replace=True)[1]["login"]["id"]
        code, said = self.machine_report(lid, state="starting", detail="Claude Code is signed out.")
        self.assertEqual(code, 200, said)
        hub.q("INSERT OR REPLACE INTO machine_status(agent,data,reported) VALUES(?,?,?)",
              ("solo", json.dumps({"runtimes": {"claude": {"signed_in": True}}}),
               self.row(lid)["updated"] - 5))
        hub.end_signed_in_waits("solo")
        self.assertEqual(self.row(lid)["state"], "starting")

    def test_the_sign_in_that_follows_the_sign_out_ends_as_any_other_does(self):
        self.signed_in()
        lid = self.start(replace=True)[1]["login"]["id"]
        self.assertEqual(self.machine_report(lid, state="starting", detail="Claude Code is signed out.")[0], 200)
        code, said = self.machine_report(lid, state="needs_owner", url=CLAUDE_URL, wants_code=True, shows_code=None)
        self.assertEqual(code, 200, said)
        self.assertEqual(self.view()["url"], CLAUDE_URL)
        self.assertEqual(self.machine_says(claude=True)[0], 200)
        self.assertEqual(self.row(lid)["state"], "done")
        self.assertEqual(hub.LIVE_LOGINS, {}, "the link goes with the sign-in, as on any other end")

    def test_a_machine_cannot_send_a_waiting_sign_in_back_to_the_beginning(self):
        """`starting` is the end of a replace's first half and nothing else: a machine that could send a sign-in
        waiting for the owner back there would drop the link he is about to use."""
        lid = self.open_one()
        code, answer = self.machine_report(lid, state="starting", detail="again")
        self.assertEqual(code, 409, answer)
        self.assertEqual(self.view()["url"], CLAUDE_URL)

    def test_a_sign_out_is_refused_while_the_agent_has_work_open(self):
        """It stops the agent, so nothing is signed out from under a running task. The same facts a switch reads."""
        self.signed_in()
        hub.q("INSERT INTO tasks(id,owner,requester,title,done_when,state,created) "
              "VALUES(7,'solo','manager','A task','It is done','working',?)", (hub.now(),))
        code, answer = self.start(replace=True)
        self.assertEqual(code, 409, answer)
        self.assertIn("T-7", answer["error"])
        self.assertIn("stops it", answer["error"])
        self.assertEqual(self.count("signin_jobs"), 0)

    def test_a_runtime_fleet_drives_no_sign_out_for_says_so(self):
        self.reports("solo", codex=True)
        with patch.object(hub, "LOGIN_OUT_RUNTIMES", ()):
            code, answer = self.start(runtime="codex", replace=True)
        self.assertEqual(code, 409, answer)
        self.assertIn("sign out there yourself", answer["error"].lower())

    def test_replace_is_part_of_the_command_body(self):
        """So a repeat of one request_id is the same request, and a change of mind is a new one."""
        self.signed_in()
        rid = str(uuid.uuid4())
        first = self.request("/ui/machines/solo/signin", self.command(runtime="claude", replace=True, request_id=rid))
        self.assertEqual(first[0], 200, first)
        again = self.request("/ui/machines/solo/signin", self.command(runtime="claude", request_id=rid))
        self.assertEqual(again[0], 409, again)

    def test_the_sign_out_leaves_the_old_credential_nowhere(self):
        """The same line the sign-in keeps: Fleet never reads, holds or passes on a credential, and a sign-out is
        the runtime's own command in its own window. Nothing of it is written down here either."""
        self.signed_in()
        lid = self.start(replace=True)[1]["login"]["id"]
        self.machine_report(lid, state="starting", detail="Claude Code is signed out.")
        written = json.dumps([dict(r) for r in hub.q("SELECT * FROM signin_jobs")]) + \
            json.dumps([dict(r) for r in hub.q("SELECT * FROM events WHERE kind='login'")]) + \
            json.dumps([dict(r) for r in hub.q("SELECT * FROM ui_controls")])
        for secret in ("token", "credential", "password", "oauth", "api_key"):
            self.assertNotIn(secret, written.lower(), secret)
        self.assertEqual(hub.LIVE_LOGINS, {})
        self.assertNotIn("logout", json.loads(hub.q1(
            "SELECT extra FROM events WHERE kind='login' ORDER BY id DESC")["extra"]).get("runtime", ""))


class NoCredentialKept(Machines):
    """The absences: nothing of a sign-in is written down. This is the class to read if the terms are ever argued."""

    def everything_written(self):
        """Every byte this hub kept: its whole records file, and the files beside it."""
        rows = []
        for (table,) in hub.DB.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
            for row in hub.DB.execute(f"SELECT * FROM {table}").fetchall():
                rows.append(json.dumps({k: row[k] for k in row.keys()}, default=str))
        return "\n".join(rows) + "\n" + Path(self.path).read_bytes().decode("utf-8", "replace")

    def test_the_whole_flow_leaves_the_code_nowhere(self):
        lid = self.open_one()
        self.assertEqual(self.send_code()[0], 200)
        self.assertEqual(self.machine_asks(lid)[1]["code"], CODE)
        self.assertEqual(self.machine_report(lid, state="done")[0], 200)
        written = self.everything_written()
        self.assertNotIn(CODE, written, "the code the owner pasted was written down")
        self.assertNotIn(CLAUDE_URL, written, "the provider's link was written down")
        self.assertEqual(hub.LIVE_LOGINS, {}, "the live part of a finished sign-in was kept")

    def test_the_records_table_holds_the_codes_fingerprint_and_not_the_code(self):
        """The owner-command record must still recognise a repeat of the same request_id, so it keeps the SHA-256."""
        import hashlib
        self.open_one()
        body = self.command(code=CODE)
        self.assertEqual(self.request("/ui/machines/solo/signin/code", body)[0], 200)
        kept = hub.q1("SELECT * FROM ui_controls WHERE route='machines/solo/signin/code'")
        self.assertNotIn(CODE, kept["body"])
        self.assertIn(hashlib.sha256(CODE.encode()).hexdigest(), kept["body"])
        self.assertNotIn(CODE, kept["result"])
        answer = self.request("/ui/machines/solo/signin/code", body)        # the same request_id, the same answer
        self.assertEqual((answer[0], answer[1]["replayed"]), (200, True))

    def test_no_log_line_carries_a_code_or_a_link(self):
        lid = self.open_one()
        self.send_code()
        self.machine_asks(lid)
        lines = " ".join(r["what"] for r in hub.q("SELECT what FROM log"))
        self.assertNotIn(CODE, lines)
        self.assertNotIn(CLAUDE_URL, lines)
        self.assertIn(f"L-{lid}", lines)        # that it happened is recorded; what it carried is not

    def test_the_event_to_the_machine_carries_no_code(self):
        lid = self.open_one()
        self.send_code()
        extras = " ".join(r["extra"] or "" for r in hub.q("SELECT extra FROM events WHERE agent='solo'"))
        self.assertNotIn(CODE, extras)

    def test_a_code_the_machine_never_came_for_is_forgotten(self):
        lid = self.open_one()
        self.send_code()
        hub.LIVE_LOGINS[lid]["code_at"] = hub.now() - hub.LOGIN_CODE_LIFE - 1
        hub.expire_logins()
        self.assertIsNone(hub.LIVE_LOGINS[lid].get("code"))
        self.assertIsNone(self.machine_asks(lid)[1]["code"])

    def test_a_restart_of_the_hub_drops_every_open_sign_in(self):
        """Nothing of a sign-in outlives the hub's memory: the link and the code go with a restart (HubRestart says
        how the sign-in itself goes on)."""
        lid = self.open_one()
        self.send_code()
        hub.LIVE_LOGINS.clear()             # what a restart does: the rows stay, the live part does not
        seen = self.view()
        self.assertEqual((seen["url"], seen["wants_code"]), (None, False))
        self.assertIsNone(self.machine_asks(lid)[1]["code"])


class HubRestart(Machines):
    """**A sign-in that waits for the owner outlives a restart of the hub** (helper feature signin_relink). The hub
    restarts each time it takes a release, and on 6 November 2026 the owner's fleet took four in about an hour: two
    sign-ins of Iris that waited for his code ended with "The machine hit an error during the sign-in." (a URLError,
    then a ConnectionResetError), and he had to start again. The provider's window stays open on the machine, so a
    restart takes only what the hub keeps in memory (LIVE_LOGINS), and the machine gives the link back (`send_link`).
    An older helper's sign-in ends with the restart as before: Signin.test_a_sign_in_whose_link_the_hub_lost_is_over."""

    def setUp(self):
        super().setUp()
        self.helper_has("signin_relink")

    def helper_has(self, *features):
        """solo's helper reports these features, and that neither runtime is signed in."""
        helper_reports("solo", *features, runtimes={"claude": {"version": "2.1.287", "signed_in": False},
                                                   "codex": {"version": "0.160.0", "signed_in": False}})

    def until(self, done, what, seconds=30):
        """Wait for done(). what: the words of a failure, or a call that gives them then."""
        end = time.monotonic() + seconds
        while not done():
            if time.monotonic() > end:
                self.fail(f"not in {seconds} seconds: {what() if callable(what) else what}")
            REAL_SLEEP(0.02)

    def restart_hub(self, met):
        """The hub goes away and comes back on the same port, as a release restarts it: its port closes, and what it
        keeps in memory is gone (LIVE_LOGINS). Its rows are in the database, which a restart keeps. It comes back
        once `met` says that the machine met it away."""
        port = self.server.server_port
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        hub.LIVE_LOGINS.clear()
        self.until(met, "the machine met the hub away")
        self.server = ThreadingHTTPServer(("127.0.0.1", port), SourceHandler)
        self.server.busy, self.server.idle, self.server.machines = 0, threading.Condition(), True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def test_a_sign_in_survives_a_restart_of_the_hub_in_the_middle_of_the_code_wait(self):
        """The whole path, with the helper's own code and real sockets: the machine waits for the owner's code, the
        hub goes away and comes back, the machine gives it the link back, the owner's code reaches the machine and
        the sign-in ends done. The provider's window is taken down only at its end."""
        self.server.machines = True             # a call of solo's helper comes from solo's machine (SourceHandler)
        code, answer = self.start()
        self.assertEqual(code, 200, answer)
        lid = answer["login"]["id"]
        steps, said, typed = [], [], []
        helper = fleet.Helper.__new__(fleet.Helper)
        helper.agent, helper.conf, helper.say = "solo", {"role": "worker"}, said.append
        helper.lifecycle = type("Lifecycle", (), {"report": lambda _self, **_: True,
                                                  "read_models": lambda _self, **_: None,
                                                  "report_soon": lambda _self: None})()
        helper.signed_in = lambda _runtime: bool(typed)             # the runtime signs in with the owner's code

        def type_code(_session, code):
            typed.append(code)
            steps.append("typed")

        over, real_http = threading.Event(), fleet.http

        def to_this_hub(*args, **kwargs):
            if over.is_set():           # a test that failed half way: its helper never calls a hub outside it
                raise RuntimeError("the test is over")
            return real_http(*args, **kwargs)

        patches = [patch.object(fleet, "HUB", self.base), patch.object(fleet, "AGENT", None),
                   patch.object(fleet, "http", to_this_hub), patch.object(fleet, "HUB_RETRY", 0.05),
                   patch.object(fleet, "exe", lambda *a, **k: "/home/solo/.local/bin/claude"),
                   patch.object(fleet, "tmux", lambda *a, **k: steps.append(a[0]) or
                                type("R", (), {"returncode": 0})()),
                   patch.object(fleet, "ensure_session", lambda *a, **k: None),
                   patch.object(fleet, "ready_runtime_config", lambda *a, **k: False),
                   patch.object(fleet, "start_window", lambda *a, **k: steps.append("window")),
                   patch.object(fleet, "login_screen",
                                lambda *a, **k: f"Use the url below to sign in:\n  {CLAUDE_URL}\n"),
                   patch.object(fleet, "type_login_code", type_code),
                   patch.object(fleet.time, "sleep", lambda seconds: REAL_SLEEP(min(seconds, 0.02)))]
        for one in patches:
            one.start()
            self.addCleanup(one.stop)
        signing = threading.Thread(target=helper.runtime_login, args=({"login": lid, "runtime": "claude"},),
                                   daemon=True)
        signing.start()
        self.addCleanup(lambda: (over.set(), signing.join(10)))     # before the stand-ins end (cleanups run LIFO)
        self.until(lambda: self.view()["url"] == CLAUDE_URL, "the link reached the app")

        heard = len(said)
        self.restart_hub(lambda: len(said) > heard)                 # the machine says what it met
        self.until(lambda: self.view()["state"] != "needs_owner" or self.view()["url"] == CLAUDE_URL,
                   lambda: f"the machine gave the link back; it said {said}")
        self.assertEqual((self.view()["state"], self.view()["url"]), ("needs_owner", CLAUDE_URL), said)
        self.assertEqual(self.send_code()[0], 200)                  # the owner's code, after the restart
        signing.join(30)

        self.assertFalse(signing.is_alive(), "the sign-in did not end")
        self.assertEqual((self.row(lid)["state"], self.row(lid)["timed_out"]), ("done", None))
        self.assertEqual(typed, [CODE])
        self.assertEqual(steps, ["kill-session", "window", "typed", "kill-session"])    # the window stayed open
        self.assertNotIn(lid, hub.LIVE_LOGINS)
        self.assertFalse([line for line in said if "error" in line], said)
        for words in ("the hub is away", "the hub answers again", "the hub restarted, so its link went to the hub"):
            self.assertTrue([line for line in said if words in line], f"{words!r} not in {said}")

    def test_the_sign_in_keeps_its_row_and_the_machine_gives_the_link_back(self):
        lid = self.open_one()
        hub.LIVE_LOGINS.clear()                     # what a restart takes: the rows stay, the live part does not
        seen = self.view()
        self.assertEqual((seen["state"], seen["url"], seen["timed_out"]), ("needs_owner", None, False))
        code, asked = self.machine_asks(lid)
        self.assertEqual((code, asked["stop"], asked["send_link"], asked["code"]), (200, False, True, None))
        self.assertEqual(self.machine_report(lid, state="needs_owner", url=CLAUDE_URL, wants_code=True)[0], 200)
        seen = self.view()
        self.assertEqual((seen["state"], seen["url"], seen["wants_code"]), ("needs_owner", CLAUDE_URL, True))
        self.assertIs(self.machine_asks(lid)[1]["send_link"], False)
        self.assertEqual(self.send_code()[0], 200)
        self.assertEqual(self.machine_asks(lid)[1]["code"], CODE)
        self.assertEqual(self.machine_report(lid, state="done")[0], 200)
        self.assertEqual(self.row(lid)["state"], "done")

    def test_a_code_the_owner_sends_after_the_restart_reaches_the_machine(self):
        """Also in the seconds before the machine gave the link back: whether the sign-in waits for a code is the
        runtime's own, and Codex takes none back."""
        lid = self.open_one()
        hub.LIVE_LOGINS.clear()
        self.assertEqual(self.send_code()[0], 200)
        asked = self.machine_asks(lid)[1]
        self.assertEqual((asked["code"], asked["send_link"], self.row(lid)["state"]), (CODE, False, "signing_in"))
        self.assertEqual(self.machine_report(lid, state="done")[0], 200)
        lid = self.open_one(runtime="codex", url=CODEX_URL, wants=False, shown="WXYZ-1234")
        hub.LIVE_LOGINS.clear()
        self.assertEqual(self.send_code()[0], 409)
        self.assertIs(self.machine_asks(lid)[1]["send_link"], True)

    def test_a_code_that_went_with_the_restart_is_asked_for_again(self):
        """The owner's code was in memory when the hub restarted, or went in an answer that never reached the machine:
        the machine asks for a code it never got, so the sign-in waits for him again."""
        lid = self.open_one()
        self.assertEqual(self.send_code()[0], 200)
        hub.LIVE_LOGINS.clear()
        asked = self.machine_asks(lid)[1]
        self.assertEqual((asked["stop"], asked["code"], asked["state"], asked["send_link"]),
                         (False, None, "needs_owner", True))
        self.assertEqual((self.row(lid)["state"], self.row(lid)["detail"]), ("needs_owner", None))
        self.assertEqual(self.machine_report(lid, state="needs_owner", url=CLAUDE_URL, wants_code=True)[0], 200)
        self.assertEqual(self.send_code()[0], 200)                  # he sends it again
        self.assertEqual(self.machine_asks(lid)[1]["code"], CODE)
        self.assertEqual(self.machine_report(lid, state="done")[0], 200)
        self.assertEqual(self.row(lid)["state"], "done")
        lines = " ".join(r["what"] for r in hub.q("SELECT what FROM log"))
        self.assertIn(f"L-{lid} waits for the owner's code again", lines)
        self.assertNotIn(CODE, lines)

    def test_the_restart_takes_nothing_from_its_time(self):
        """It ends at the hub's own time for a sign-in, as one that waited for the owner, and not before."""
        lid = self.open_one()
        hub.LIVE_LOGINS.clear()
        hub.q("UPDATE signin_jobs SET updated=? WHERE id=?", (hub.now() - hub.LOGIN_LIFE + 60, lid))
        hub.expire_logins()
        self.assertEqual(self.row(lid)["state"], "needs_owner")
        hub.q("UPDATE signin_jobs SET updated=? WHERE id=?", (hub.now() - hub.LOGIN_LIFE - 1, lid))
        self.assertEqual((self.view()["state"], self.view()["timed_out"]), ("failed", True))

    def test_a_report_goes_again_for_as_long_as_the_hub_keeps_the_sign_in(self):
        self.assertEqual(fleet.LOGIN_LIFE, hub.LOGIN_LIFE)


class HelperSide(unittest.TestCase):
    """The machine's own half, against stand-ins: what it would run, and what it would type."""

    def test_grok_is_refused_on_the_machine_too(self):
        with self.assertRaises(fleet.Refused) as refused:
            fleet.runtime_login_command("grok", "/usr/bin/grok")
        self.assertIn("xAI's terms", str(refused.exception))

    def test_the_commands_are_the_providers_own_flows(self):
        self.assertEqual(fleet.runtime_login_command("claude", "/home/fleet/.local/bin/claude"),
                         "exec /home/fleet/.local/bin/claude /login")
        self.assertEqual(fleet.runtime_login_command("codex", "/home/fleet/.local/bin/codex"),
                         "exec /home/fleet/.local/bin/codex login --device-auth")
        for unknown in ("gemini", "", "llama"):
            with self.assertRaises(fleet.Refused):
                fleet.runtime_login_command(unknown, "/bin/true")

    def test_no_command_asks_a_provider_for_a_lasting_token(self):
        """`claude setup-token` makes a long-lived token, which is exactly what Fleet may never hold."""
        for runtime in ("claude", "codex"):
            command = fleet.runtime_login_command(runtime, "/bin/" + runtime)
            for forbidden in ("setup-token", "--api-key", "token", "ANTHROPIC_API_KEY", "export"):
                self.assertNotIn(forbidden, command, runtime)

    def test_the_link_is_read_from_the_screen_the_provider_drew(self):
        screen = ("  Browser didn't open? Use the url below to sign in:\n"
                  f"  {CLAUDE_URL}\n\n  Paste code here if prompted > ")
        self.assertEqual(fleet.LOGIN_URLS["claude"].search(screen).group(0), CLAUDE_URL)
        self.assertEqual(fleet.LOGIN_URLS["codex"].search(f"open {CODEX_URL} and enter").group(0), CODEX_URL)
        self.assertIsNone(fleet.LOGIN_URLS["claude"].search("https://claude.ai.example.com/login"))

    def test_codexs_own_code_is_read_from_its_screen(self):
        self.assertEqual(fleet.LOGIN_SHOWN_CODE["codex"].search("your code is WXYZ-1234 ok").group(0), "WXYZ-1234")

    def test_only_a_code_is_ever_typed_into_the_window(self):
        """A terminal takes control characters as keys, so anything but letters, digits and dashes is refused before
        it reaches send-keys."""
        typed = []
        with patch.object(fleet, "tmux", lambda *a, **k: typed.append(a) or type("R", (), {"returncode": 0})()):
            fleet.type_login_code("fleet-login-solo", CODE)
        self.assertIn(("send-keys", "-t", "=fleet-login-solo:=login", "-l", "--", CODE), typed)
        for bad in ("a b", "code\nEnter", "C-c", "x;id", "", "a" * 260, "..", "$(id)"):
            with self.assertRaises(fleet.Refused, msg=bad):
                fleet.type_login_code("fleet-login-solo", bad)

    def test_the_helper_takes_a_sign_in_to_the_owner_without_hitting_an_error(self):
        """The whole helper half, driven once with stand-ins: it finds the runtime, starts the provider's flow and
        reports the link the provider printed. Nothing here mocks `runtime_login` itself, so a name that does not
        exist in that path — the first owner's very first step — fails this check instead of the fleet."""
        posts, screen = [], f"Use the url below to sign in:\n  {CLAUDE_URL}\n"
        helper = fleet.Helper.__new__(fleet.Helper)
        helper.agent, helper.lifecycle = "solo", object()
        helper.await_login_code = lambda *_: False          # the owner has not pasted the code yet

        def post(method, path, data=None, timeout=40):
            posts.append((method, path, data))
            return 200, {}

        with patch.object(fleet, "http", post), \
             patch.object(fleet, "exe", lambda *a, **k: "/home/solo/.local/bin/claude"), \
             patch.object(fleet, "tmux", lambda *a, **k: type("R", (), {"returncode": 0})()), \
             patch.object(fleet, "ensure_session", lambda *a, **k: None), \
             patch.object(fleet, "start_window", lambda *a, **k: None), \
             patch.object(fleet, "login_screen", lambda *a, **k: screen), \
             patch.object(fleet.time, "sleep", lambda *_: None):
            helper.runtime_login({"login": 7, "runtime": "claude"})

        self.assertEqual([data["state"] for _m, _p, data in posts], ["needs_owner"])
        self.assertEqual(posts[0][1], "/helper/login/solo/7")
        self.assertEqual(posts[0][2]["url"], CLAUDE_URL)

    def test_a_sign_in_that_worked_sends_the_machines_status_before_it_ends(self):
        """The status is what says that it worked, for the hub and the app: sent at once and before the end of the
        sign-in, and not at the next round of the five-minute report clock (the owner, 25 October 2026)."""
        order = []
        helper = fleet.Helper.__new__(fleet.Helper)
        helper.agent, helper.conf = "solo", {"role": "worker"}
        helper.lifecycle = type("Lifecycle", (), {"report": lambda _self, **_: order.append("status") or True,
                                                  "read_models": lambda _self, **_: None,
                                                  "report_soon": lambda _self: order.append("soon")})()
        helper.say = lambda *_: None
        helper.await_login_code = lambda *_: True           # the owner pasted the code
        helper.signed_in = lambda _runtime: True            # and the runtime says it is signed in

        def post(method, path, data=None, timeout=40):
            order.append(data["state"])
            return 200, {}

        with patch.object(fleet, "http", post), \
             patch.object(fleet, "exe", lambda *a, **k: "/home/solo/.local/bin/claude"), \
             patch.object(fleet, "tmux", lambda *a, **k: type("R", (), {"returncode": 0})()), \
             patch.object(fleet, "ensure_session", lambda *a, **k: None), \
             patch.object(fleet, "ready_runtime_config", lambda *a, **k: False), \
             patch.object(fleet, "start_window", lambda *a, **k: None), \
             patch.object(fleet, "login_screen", lambda *a, **k: f"Use the url below to sign in:\n  {CLAUDE_URL}\n"), \
             patch.object(fleet.time, "sleep", lambda *_: None):
            helper.runtime_login({"login": 7, "runtime": "claude"})

        self.assertEqual(order, ["needs_owner", "status", "done", "soon"])     # the model options, after it

    def run_login(self, extra, signed_in, typed, done_wait=None, posts=None,
                  screen=f"Use the url below to sign in:\n  {CLAUDE_URL}\n", look=None):
        """The helper's sign-in against stand-ins, recording the order of its status reports and its sign-in posts.
        posts: a list that gets the body of each sign-in post. look: what the hub says of the sign-in (login_look)."""
        order, seq = [], list(signed_in)
        helper = fleet.Helper.__new__(fleet.Helper)
        helper.agent, helper.conf = "solo", {"role": "worker"}
        helper.lifecycle = type("Lifecycle", (), {"report": lambda _self, **_: order.append("status") or True,
                                                  "read_models": lambda _self, **_: None,
                                                  "report_soon": lambda _self: order.append("soon")})()
        helper.say = lambda *_: None
        helper.await_login_code = lambda *_: typed
        helper.signed_in = lambda _runtime: seq.pop(0) if seq else False
        if look is not None:
            helper.login_look = look

        def post(method, path, data=None, timeout=40):
            order.append(data["state"])
            if posts is not None:
                posts.append(data)
            return 200, {}

        patches = [patch.object(fleet, "http", post),
                   patch.object(fleet, "exe", lambda *a, **k: "/home/solo/.local/bin/claude"),
                   patch.object(fleet, "tmux", lambda *a, **k: type("R", (), {"returncode": 0})()),
                   patch.object(fleet, "ensure_session", lambda *a, **k: None),
                   patch.object(fleet, "ready_runtime_config", lambda *a, **k: False),
                   patch.object(fleet, "start_window", lambda *a, **k: None),
                   patch.object(fleet, "login_screen", lambda *a, **k: screen),
                   patch.object(fleet.time, "sleep", lambda *_: None)]
        if done_wait is not None:
            patches.append(patch.object(fleet, "LOGIN_DONE_WAIT", done_wait))
        for one in patches:
            one.start()
        try:
            helper.runtime_login(extra)
        finally:
            for one in patches:
                one.stop()
        return order

    def test_another_account_reports_the_sign_out_before_its_sign_in_starts(self):
        """A reading taken during the sign-out, still signed in, must not arrive after `starting` and close the new
        sign-in: the reading that says signed out goes first."""
        order = self.run_login({"login": 7, "runtime": "claude", "replace": True}, [True, True, False], typed=False)
        self.assertEqual(order[:3], ["status", "starting", "needs_owner"])

    def test_every_end_that_is_not_done_reports_the_machine_then_says_so(self):
        order = self.run_login({"login": 7, "runtime": "claude"}, [], typed=None)           # no code came back
        self.assertEqual(order, ["needs_owner", "status", "failed"])
        order = self.run_login({"login": 7, "runtime": "claude"}, [], typed=False)          # the hub ended it
        self.assertEqual(order, ["needs_owner", "status"])
        order = self.run_login({"login": 7, "runtime": "claude"}, [], typed=True, done_wait=0)     # never signed in
        self.assertEqual(order, ["needs_owner", "status", "failed"])

    def test_only_an_end_that_waited_for_the_owner_says_it_timed_out(self):
        """`timed_out` goes with the ends that waited for the owner and got nothing: no code came back, or a provider
        that takes no code back (Codex) was not signed in on its own page. A code that went and did not sign the
        runtime in is a failure he hears of."""
        def ends(runtime, typed, screen=f"Use the url below to sign in:\n  {CLAUDE_URL}\n"):
            posts = []
            self.run_login({"login": 7, "runtime": runtime}, [], typed=typed, done_wait=0, posts=posts, screen=screen)
            return [(p["state"], p.get("timed_out")) for p in posts if p["state"] != "needs_owner"]
        self.assertEqual(ends("claude", None), [("failed", True)])            # no code came back in 14 minutes
        self.assertEqual(ends("claude", True), [("failed", False)])           # his code did not sign it in
        self.assertEqual(ends("codex", True, f"Open {CODEX_URL}\nEnter WXYZ-1234\n"), [("failed", True)])

    def test_a_codex_sign_in_ends_when_the_hub_stops_it(self):
        """A runtime that takes no code back (Codex) waits on the provider's page for the owner, and its helper looks
        at the hub at each round. Nothing read that look's answer, so a sign-in that the hub ended kept its window and
        its wait for up to 15 minutes. It ends at the hub's stop now, as the wait for a code does: the machine's status,
        and no report of its own."""
        looks = []

        def look(lid, link, until):
            looks.append(lid)
            if len(looks) > 2:                      # a look after the stop: it waited on
                raise RuntimeError("it looked again after the hub stopped the sign-in")
            return (200, {"stop": False, "state": "needs_owner"}) if len(looks) == 1 else \
                (200, {"stop": True, "why": "canceled"})
        order = self.run_login({"login": 7, "runtime": "codex"}, [], typed=True, look=look,
                               screen=f"Open {CODEX_URL}\nEnter WXYZ-1234\n")
        self.assertEqual((looks, order), ([7, 7], ["needs_owner", "status"]))

    def test_a_sign_in_starts_during_a_runtime_round_waits_out_a_fleet_update_and_runs_once(self):
        helper = fleet.Helper.__new__(fleet.Helper)
        helper.outside, helper.outside_lock, helper.logins = 0, threading.Lock(), set()
        helper.lifecycle = type("Lifecycle", (), {"lock": threading.Lock(), "state": None})()
        self.assertTrue(helper.begin_signin(7))         # no session gate: a runtime-update round may hold it
        self.assertEqual(helper.outside, 1)             # and no Fleet update starts until it ends
        self.assertFalse(helper.begin_signin(7))        # the same sign-in handed out again: no second thread
        helper.lifecycle.state = "updating"
        with self.assertRaises(fleet.Updating):         # the event stays pending for the restarted helper
            helper.begin_signin(8)
        self.assertEqual(helper.outside, 1)

    def test_status_now_wakes_the_status_thread_and_is_acknowledged(self):
        calls = []
        helper = fleet.Helper.__new__(fleet.Helper)
        helper.agent = "solo"
        helper.lifecycle = type("Lifecycle", (), {"report_soon": lambda _self: calls.append("soon")})()
        with patch.object(fleet, "http", lambda method, path, data=None, timeout=40: calls.append(path) or (200, {})):
            helper.handle({"id": 5, "kind": "status_now", "extra": {}})
        self.assertEqual(calls, ["soon", "/helper/ack/solo"])

    def test_the_sign_out_commands_are_the_providers_own_too(self):
        """One half each, and both the provider's own command: nothing of Fleet touches the credential."""
        self.assertEqual(fleet.runtime_logout_command("claude", "/home/fleet/.local/bin/claude"),
                         "exec /home/fleet/.local/bin/claude /logout")
        self.assertEqual(fleet.runtime_logout_command("codex", "/home/fleet/.local/bin/codex"),
                         "exec /home/fleet/.local/bin/codex logout")
        for unknown in ("grok", "gemini", "", "llama"):
            with self.assertRaises(fleet.Refused, msg=unknown):
                fleet.runtime_logout_command(unknown, "/bin/true")
        for runtime in ("claude", "codex"):
            command = fleet.runtime_logout_command(runtime, "/bin/" + runtime)
            for forbidden in ("setup-token", "--api-key", "token", "ANTHROPIC_API_KEY", "export", "rm "):
                self.assertNotIn(forbidden, command, runtime)

    def test_another_account_signs_out_and_then_in_from_one_job(self):
        """The machine's half of a replace: the runtime's own sign-out first, the hub told when it took, then the
        ordinary sign-in in the same window session. Nothing mocks `runtime_login`, so the whole path runs."""
        posts, windows, screen = [], [], f"Use the url below to sign in:\n  {CLAUDE_URL}\n"
        signed_in = [True, True, False]          # it says signed in until its own sign-out has run
        helper = fleet.Helper.__new__(fleet.Helper)
        helper.agent, helper.lifecycle = "solo", object()
        helper.signed_in = lambda _runtime: signed_in.pop(0) if signed_in else False
        helper.await_login_code = lambda *_: False

        def post(method, path, data=None, timeout=40):
            posts.append(data)
            return 200, {}

        with patch.object(fleet, "http", post), \
             patch.object(fleet, "exe", lambda *a, **k: "/home/solo/.local/bin/claude"), \
             patch.object(fleet, "tmux", lambda *a, **k: type("R", (), {"returncode": 0})()), \
             patch.object(fleet, "ensure_session", lambda *a, **k: None), \
             patch.object(fleet, "start_window", lambda *a, w=windows, **k: w.append(k or a)), \
             patch.object(fleet, "login_screen", lambda *a, **k: screen), \
             patch.object(fleet.time, "sleep", lambda *_: None):
            helper.runtime_login({"login": 7, "runtime": "claude", "replace": True})

        self.assertEqual([d["state"] for d in posts], ["starting", "needs_owner"])
        self.assertIn("signed out", posts[0]["detail"])
        self.assertEqual([w[1] for w in windows], ["logout", "login"], "the sign-out first, then the sign-in")
        self.assertEqual(windows[0][2], "exec /home/solo/.local/bin/claude /logout")
        self.assertEqual(posts[1]["url"], CLAUDE_URL)

    # ---- the runtime's own first run, which a sign-out puts back
    #
    # Signing Claude Code out does not leave it signed out and ready: it resets it to a fresh install. Driven live
    # on the owner's own manager, 20 October 2026, the sign-in that followed opened behind a theme picker and a
    # "Select login method", saw no link for ninety seconds and gave up — with his manager signed out.

    def test_the_first_run_answers_are_written_after_the_sign_out_and_not_before_it(self):
        """The order is the whole fix: answers written before the sign-out go with the account."""
        order, signed_in = [], [True, True, False]
        helper = fleet.Helper.__new__(fleet.Helper)
        helper.agent, helper.lifecycle = "solo", object()
        helper.say = lambda *_: None
        helper.signed_in = lambda _r: signed_in.pop(0) if signed_in else False
        helper.await_login_code = lambda *_: False

        with patch.object(fleet, "http", lambda *a, **k: (200, {})), \
             patch.object(fleet, "exe", lambda *a, **k: "/home/solo/.local/bin/claude"), \
             patch.object(fleet, "tmux", lambda *a, **k: type("R", (), {"returncode": 0})()), \
             patch.object(fleet, "ensure_session", lambda *a, **k: None), \
             patch.object(fleet, "ready_runtime_config", lambda *a, **k: order.append("first-run") or True), \
             patch.object(fleet, "start_window", lambda _s, name, *a, **k: order.append(name)), \
             patch.object(fleet, "login_screen", lambda *a, **k: f"sign in:\n  {CLAUDE_URL}\n"), \
             patch.object(fleet.time, "sleep", lambda *_: None):
            helper.runtime_login({"login": 7, "runtime": "claude", "replace": True})

        self.assertEqual(order, ["logout", "first-run", "login"])

    def test_a_first_run_question_standing_in_front_of_the_link_is_answered(self):
        """Its own questions, not the provider's. Fleet takes the option the runtime itself has selected, which is
        what a person pressing through its first run would get, and only while one is really waiting."""
        theme = ("Let's get started.\n\nChoose the text style that looks best with your terminal:\n"
                 "\u276f 1. Dark mode\n  2. Light mode\n")
        method = "Select login method:\n\u276f 1. Claude account with subscription\n  2. Anthropic Console account\n"
        screens = [theme, theme, method, f"Use the url below to sign in:\n  {CLAUDE_URL}\n"]
        posts, keys = [], []
        helper = fleet.Helper.__new__(fleet.Helper)
        helper.agent, helper.lifecycle = "solo", object()
        helper.say = lambda *_: None
        helper.await_login_code = lambda *_: False

        def tmux(*args, **_):
            keys.append(args)
            return type("R", (), {"returncode": 0})()

        with patch.object(fleet, "http", lambda m, p, d=None, timeout=40: posts.append(d) or (200, {})), \
             patch.object(fleet, "exe", lambda *a, **k: "/home/solo/.local/bin/claude"), \
             patch.object(fleet, "tmux", tmux), \
             patch.object(fleet, "ensure_session", lambda *a, **k: None), \
             patch.object(fleet, "ready_runtime_config", lambda *a, **k: False), \
             patch.object(fleet, "start_window", lambda *a, **k: None), \
             patch.object(fleet, "login_screen", lambda *a, **k: screens.pop(0) if screens else ""), \
             patch.object(fleet.time, "sleep", lambda *_: None):
            helper.runtime_login({"login": 7, "runtime": "claude"})

        enters = [a for a in keys if a[:1] == ("send-keys",) and a[-1] == "Enter"]
        self.assertEqual(len(enters), 2, "one for each question, and one for the screen that repeated")
        self.assertEqual([d["state"] for d in posts], ["needs_owner"])
        self.assertEqual(posts[0]["url"], CLAUDE_URL)

    def test_a_screen_that_never_moves_stops_instead_of_being_pressed_for_ninety_seconds(self):
        """A key that changes nothing is not sent again, and the failure says which screen it is stuck on."""
        stuck = "Select login method:\n\u276f 1. Claude account with subscription\n"
        posts, keys, clock = [], [], iter(range(0, 10_000, 30))
        helper = fleet.Helper.__new__(fleet.Helper)
        helper.agent, helper.lifecycle = "solo", object()
        helper.say = lambda *_: None

        with patch.object(fleet, "http", lambda m, p, d=None, timeout=40: posts.append(d) or (200, {})), \
             patch.object(fleet, "exe", lambda *a, **k: "/home/solo/.local/bin/claude"), \
             patch.object(fleet, "tmux", lambda *a, **k: keys.append(a) or type("R", (), {"returncode": 0})()), \
             patch.object(fleet, "ensure_session", lambda *a, **k: None), \
             patch.object(fleet, "ready_runtime_config", lambda *a, **k: False), \
             patch.object(fleet, "start_window", lambda *a, **k: None), \
             patch.object(fleet, "login_screen", lambda *a, **k: stuck), \
             patch.object(fleet.time, "monotonic", lambda c=clock: next(c)), \
             patch.object(fleet.time, "sleep", lambda *_: None):
            helper.runtime_login({"login": 7, "runtime": "claude"})

        self.assertEqual(len([a for a in keys if a[-1] == "Enter"]), 1, "pressed once, then left alone")
        self.assertEqual([d["state"] for d in posts], ["failed"])
        self.assertIn("Select login method:", posts[0]["detail"])
        self.assertIn("answered 1", posts[0]["detail"])

    def test_a_link_the_runtime_drew_across_lines_is_taken_whole(self):
        """**The owner opened a link that stopped after eighty characters** and the provider answered "Missing
        redirect_uri parameter" (21 October 2026). Claude Code prints its link at the full width of its window and
        breaks it itself, so no line of the capture holds the whole of it and tmux joins nothing: the line that
        runs to the edge is continued by the line under it."""
        link = ("https://claude.com/cai/oauth/authorize?code=true&client_id=" + "a" * 28 +
                "&response_type=code&redirect_uri=https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback"
                "&scope=user%3Aprofile+user%3Ainference&code_challenge=" + "b" * 43 +
                "&code_challenge_method=S256&state=" + "c" * 20)
        drawn = [link[at:at + 80] for at in range(0, len(link), 80)]
        screen = "\n".join(["", "  Browser didn't open? Use the url below to sign in (c to copy)", ""] +
                           drawn + ["", "  Paste code here if prompted:"])
        self.assertGreater(len(drawn), 3)
        self.assertEqual(fleet.whole_link(screen, fleet.LOGIN_URLS["claude"]), link)
        self.assertEqual(len(fleet.LOGIN_URLS["claude"].search(screen).group(0)), 80, "one line holds this much")
        # A window too narrow for any line to reach an edge glues nothing to a link that simply ends.
        self.assertEqual(fleet.whole_link("sign in:\n  https://claude.ai/oauth/x\nEsc\n", fleet.LOGIN_URLS["claude"]),
                         "https://claude.ai/oauth/x")
        self.assertIsNone(fleet.whole_link("Select login method:\n  1. Claude account\n", fleet.LOGIN_URLS["claude"]))

    def test_the_sign_in_window_is_read_as_lines_and_not_as_one(self):
        """**Every sign-in failed on this.** The screen is read for a question and for the cursor standing on one,
        and both are lines; the helper stripped the newlines out with the other control characters, so the window
        came back as one line, no question was ever answered and the link never came. The owner saw the ninety
        seconds and the banner, which was the start of that one line."""
        pane = ("\x1b[2J ▐▛███▛█   Claude Code v2.1.285\r\n"
                "  Select login method:\n"
                "  ❯ 1. Claude account with subscription · Pro, Max, Team, or Enterprise\n"
                "    2. Anthropic Console account · API usage billing\n")
        with patch.object(fleet, "tmux", lambda *a, **k: type("R", (), {"returncode": 0, "stdout": pane})()):
            screen = fleet.login_screen("fleet-login-solo")
        self.assertEqual(len(screen.splitlines()), 4, "the window keeps its lines")
        self.assertRegex(screen, fleet.LOGIN_SETUP_CURSOR["claude"], "the cursor stands at the start of a line")
        self.assertEqual(fleet.login_prompt_line(screen), "Select login method:")
        self.assertNotIn("\x1b", screen)                    # and every other control character is still gone
        self.assertNotIn("\r", screen)

    def test_the_words_of_a_stuck_screen_carry_no_link_and_no_code(self):
        """The failure says which screen, and the screen itself never leaves the machine."""
        said = fleet.login_prompt_line(f"Paste code here if prompted:\n  {CLAUDE_URL}\n  {CODE}\n")
        self.assertEqual(said, "Paste code here if prompted:")
        for secret in (CLAUDE_URL, CODEX_URL, CODE, "WXYZ-1234"):
            self.assertNotIn(secret, said)
        self.assertNotIn("claude.ai", fleet.login_prompt_line(f"Open {CLAUDE_URL} now"))
        self.assertEqual(fleet.login_prompt_line(""), "")

    def test_the_link_is_taken_on_every_host_that_provider_signs_in_on(self):
        """Its own `/login` printed `claude.com` on 20 October 2026, and the pattern did not know that host."""
        for host in ("claude.ai", "claude.com", "console.anthropic.com"):
            link = f"https://{host}/cai/oauth/authorize?code=1&state=abc"
            self.assertEqual(fleet.LOGIN_URLS["claude"].search(f"  {link}\n").group(0), link, host)
        self.assertIsNone(fleet.LOGIN_URLS["claude"].search("https://claude.ai.example.com/login"))

    def test_a_runtime_that_asks_nothing_is_never_pressed(self):
        """Codex prints its link and its code straight away. Nothing may send a key into that window."""
        self.assertNotIn("codex", fleet.LOGIN_SETUP_CURSOR)
        keys, posts = [], []
        helper = fleet.Helper.__new__(fleet.Helper)
        helper.agent, helper.lifecycle = "solo", object()
        helper.say = lambda *_: None
        helper.await_login_code = lambda *_: False
        screens = ["Starting…\n\u276f 1. Something\n", f"open {CODEX_URL} and enter WXYZ-1234"]

        with patch.object(fleet, "http", lambda m, p, d=None, timeout=40: posts.append(d) or (200, {})), \
             patch.object(fleet, "exe", lambda *a, **k: "/home/solo/.local/bin/codex"), \
             patch.object(fleet, "tmux", lambda *a, **k: keys.append(a) or type("R", (), {"returncode": 0})()), \
             patch.object(fleet, "ensure_session", lambda *a, **k: None), \
             patch.object(fleet, "ready_runtime_config", lambda *a, **k: False), \
             patch.object(fleet, "start_window", lambda *a, **k: None), \
             patch.object(fleet, "login_screen", lambda *a, **k: screens.pop(0) if screens else ""), \
             patch.object(fleet.time, "sleep", lambda *_: None):
            helper.runtime_login({"login": 7, "runtime": "codex"})

        self.assertEqual([a for a in keys if a[-1] == "Enter"], [])
        self.assertEqual(posts[0]["shows_code"], "WXYZ-1234")

    def test_a_finished_sign_in_has_this_machine_read_its_account_again(self):
        """**The owner reads the account off the card, and the card is a reading.** A machine card names the
        account of that machine's own last usage reading, which its collector takes every five minutes — so a
        sign-in that worked sat there under the address of the account he had just left, with nothing on the card
        to say which of the two it was showing (the owner, 23 October 2026, on his manager). The sign-in is what
        knows the account changed, so it is what brings that reading forward."""
        posts, again = [], []
        helper = fleet.Helper.__new__(fleet.Helper)
        helper.agent, helper.conf = "solo", {"role": "worker"}
        helper.lifecycle = type("Lifecycle", (), {"report": lambda _self, **_: True, "read_models": lambda _self, **_: None,
                                                  "report_soon": lambda _self: None})()
        helper.say = lambda *_: None
        helper.signed_in = lambda _runtime: True
        helper.await_login_code = lambda *_: True           # the owner pasted the code
        helper.collector = type("Stand", (), {"account_again": lambda _self: again.append(True)})()

        with patch.object(fleet, "http", lambda m, p, d=None, timeout=40: posts.append(d) or (200, {})), \
             patch.object(fleet, "exe", lambda *a, **k: "/home/solo/.local/bin/claude"), \
             patch.object(fleet, "tmux", lambda *a, **k: type("R", (), {"returncode": 0})()), \
             patch.object(fleet, "ensure_session", lambda *a, **k: None), \
             patch.object(fleet, "ready_runtime_config", lambda *a, **k: False), \
             patch.object(fleet, "start_window", lambda *a, **k: None), \
             patch.object(fleet, "login_screen", lambda *a, **k: f"sign in:\n  {CLAUDE_URL}\n"), \
             patch.object(fleet.time, "sleep", lambda *_: None):
            helper.runtime_login({"login": 7, "runtime": "claude"})

        self.assertEqual([d["state"] for d in posts], ["needs_owner", "done"])
        self.assertEqual(len(again), 1, "the account is read again at the collector's next scan")

    def test_a_sign_out_that_does_not_take_stops_before_the_sign_in(self):
        """The runtime still says it is signed in, so the old account is still there and no second sign-in can
        start. It says so and ends, rather than opening a window that cannot work."""
        posts, windows = [], []
        helper = fleet.Helper.__new__(fleet.Helper)
        helper.agent, helper.lifecycle = "solo", object()
        helper.signed_in = lambda _runtime: True

        with patch.object(fleet, "http", lambda m, p, d=None, timeout=40: posts.append(d) or (200, {})), \
             patch.object(fleet, "exe", lambda *a, **k: "/home/solo/.local/bin/claude"), \
             patch.object(fleet, "tmux", lambda *a, **k: type("R", (), {"returncode": 0})()), \
             patch.object(fleet, "ensure_session", lambda *a, **k: None), \
             patch.object(fleet, "start_window", lambda *a, w=windows, **k: w.append(a)), \
             patch.object(fleet.time, "monotonic", lambda c=iter(range(0, 10_000, 200)): next(c)), \
             patch.object(fleet.time, "sleep", lambda *_: None):
            helper.runtime_login({"login": 7, "runtime": "claude", "replace": True})

        self.assertEqual([d["state"] for d in posts], ["failed"])
        self.assertIn("did not sign out", posts[0]["detail"])
        self.assertEqual([w[1] for w in windows], ["logout"], "no sign-in window was ever opened")

    def test_claudes_own_code_carries_its_state_and_is_still_typed(self):
        """What Claude gives the owner is `<code>#<state>`, about 94 characters. The guard used to allow 41 and no
        `#`, so the one code the owner pasted was refused as "not a sign-in code" (18 October 2026)."""
        real = "VxtFT9Oo890dA8gBxf4CHfcyon3vHUOiMrTMEFWEbqWUhbgT#vq7vbuuIdwu-85gAv8YPcnITodu8Lr734NARYouexJg"
        typed = []
        with patch.object(fleet, "tmux", lambda *a, **k: typed.append(a) or type("R", (), {"returncode": 0})()):
            fleet.type_login_code("fleet-login-solo", real)
        self.assertIn(("send-keys", "-t", "=fleet-login-solo:=login", "-l", "--", real), typed)

    def test_the_runtimes_own_first_screen_is_answered_before_anybody_waits_at_it(self):
        """Claude Code runs a wizard the first time — a theme, a sign-in method, and the folder it is started in —
        in front of the session and of the sign-in. The manager of a new fleet sat at it for eight hours while the
        app showed the agent online (18 October 2026), and a customer's closed conversation sat at the folder question
        of its own empty folder (28 October 2026)."""
        with tempfile.TemporaryDirectory() as made:
            home = os.path.realpath(made)        # the runtime keeps a folder by its real path
            chats = os.path.join(home, "fleet-chats")       # Claude Code 2.1.308 asks nothing in a subfolder of it
            self.assertTrue(fleet.ready_runtime_config(home, kit=home))
            kept = json.loads(Path(home, ".claude.json").read_text())
            self.assertTrue(kept["hasCompletedOnboarding"])          # the key the wizard really reads
            self.assertTrue(kept["hasCompletedClaudeInChromeOnboarding"])   # the notice of a first `--chrome` session
            self.assertTrue(kept["projects"][home]["hasTrustDialogAccepted"])   # and the folder it is started in
            self.assertTrue(kept["projects"][chats]["hasTrustDialogAccepted"])  # and the one of its conversations
            self.assertGreaterEqual(kept["fullscreenUpsellSeenCount"], 3)       # and the offer that blocks the window
            self.assertTrue(kept["theme"])
            self.assertFalse(fleet.ready_runtime_config(home, kit=home))     # written once, and never again

            answered = {"userID": "abc", "hasCompletedOnboarding": True, "theme": "light",
                        "hasCompletedClaudeInChromeOnboarding": True,
                        "projects": {home: {"hasTrustDialogAccepted": True, "history": ["x"]},
                                     chats: {"hasTrustDialogAccepted": True}}}
            Path(home, ".claude.json").write_text(json.dumps(answered))
            self.assertFalse(fleet.ready_runtime_config(home, kit=home))
            self.assertEqual(json.loads(Path(home, ".claude.json").read_text()), answered)   # its own keys stay

            before = dict(answered, projects={home: answered["projects"][home]})    # a machine answered before 28 Oct
            Path(home, ".claude.json").write_text(json.dumps(before))
            self.assertTrue(fleet.ready_runtime_config(home, kit=home))
            after = json.loads(Path(home, ".claude.json").read_text())
            self.assertEqual(after, dict(answered, fullscreenUpsellSeenCount=3))   # only the conversations' folder

            Path(home, ".claude.json").write_text(json.dumps({"userID": "abc", "theme": "light"}))
            self.assertTrue(fleet.ready_runtime_config(home, kit=home))      # a theme alone is not the answer
            after = json.loads(Path(home, ".claude.json").read_text())
            self.assertEqual((after["userID"], after["theme"], after["hasCompletedOnboarding"]), ("abc", "light", True))
            self.assertTrue(after["projects"][home]["hasTrustDialogAccepted"])

    def test_codex_s_own_folder_question_is_answered_once_and_never_over_the_owner_s_answer(self):
        """Codex 0.158 asked "Trust this folder?" in a Codex agent's checkout, with its parent trusted, and the owner
        chat and the conversation waited at it (live check, 28 October 2026)."""
        import tomllib
        with tempfile.TemporaryDirectory() as made:
            made = os.path.realpath(made)
            home, kit = os.path.join(made, "codex"), os.path.join(made, "fleet-ivy")
            config = Path(home, "config.toml")
            self.assertFalse(fleet.ready_codex_trust("claude", home, kit=kit))     # another runtime's helper:
            self.assertFalse(os.path.exists(home))                                  # nothing in Codex's files
            self.assertTrue(fleet.ready_codex_trust("codex", home, kit=kit))       # no file yet: Codex's own form
            self.assertEqual(tomllib.loads(config.read_text())["projects"][kit], {"trust_level": "trusted"})
            self.assertFalse(fleet.ready_codex_trust("codex", home, kit=kit))      # written once, and never again

            owners = f'model = "gpt-5.6-sol"\n\n[projects."{made}"]\ntrust_level = "trusted"'     # no final line end
            config.write_text(owners)
            self.assertTrue(fleet.ready_codex_trust("codex", home, kit=kit))
            kept = config.read_text()
            self.assertTrue(kept.startswith(owners + "\n"))                 # his own lines stay as they were
            self.assertEqual(tomllib.loads(kept)["projects"],
                             {made: {"trust_level": "trusted"}, kit: {"trust_level": "trusted"}})

            for his in (f'[projects."{kit}"]\ntrust_level = "untrusted"\n'.encode(),     # his answer, whatever it says
                        b'model = "unclosed\n',                                         # a file Codex cannot read
                        b'# caf\xe9\nmodel = "gpt-6"\n',          # nor one that is not UTF-8: the helper starts
                        b'projects = { "/srv/a" = { trust_level = "trusted" } }\n'):     # the block would break it
                with self.subTest(his):
                    config.write_bytes(his)
                    self.assertFalse(fleet.ready_codex_trust("codex", home, kit=kit))
                    self.assertEqual(config.read_bytes(), his)

            robot = os.path.join(made, "fleet-\U0001f916")             # beyond the BMP: no surrogate escapes in TOML
            config.write_text('model = "gpt-6"\n')
            self.assertTrue(fleet.ready_codex_trust("codex", home, kit=robot))
            self.assertEqual(tomllib.loads(config.read_text(encoding="utf-8"))["projects"][robot],
                             {"trust_level": "trusted"})

            odd = os.path.join(made, "fleet-caf\udce9")     # a byte that is not UTF-8: no block, and no crash
            config.write_text('model = "gpt-6"\n')
            self.assertFalse(fleet.ready_codex_trust("codex", home, kit=odd))
            self.assertEqual(config.read_text(), 'model = "gpt-6"\n')

            with patch.dict(sys.modules, {"tomllib": None}):        # a Python before 3.11 reads no TOML
                old = f'[projects."{kit}-old"]\ntrust_level = "trusted"\n'    # another folder's: not this one's
                config.write_text(old)
                self.assertTrue(fleet.ready_codex_trust("codex", home, kit=kit))
                self.assertFalse(fleet.ready_codex_trust("codex", home, kit=kit))      # its own key now: his
                for his in ('projects = { "/srv/a" = { trust_level = "trusted" } }\n',      # no block would parse
                            f"[projects.'{kit}']\ntrust_level = \"untrusted\"\n"):         # his, in single quotes
                    config.write_text(his)
                    self.assertFalse(fleet.ready_codex_trust("codex", home, kit=kit))
                    self.assertEqual(config.read_text(), his)
                config.write_text(old)
                self.assertTrue(fleet.ready_codex_trust("codex", home, kit=kit))
            self.assertEqual(tomllib.loads(config.read_text())["projects"],
                             {f"{kit}-old": {"trust_level": "trusted"}, kit: {"trust_level": "trusted"}})

    def test_the_sign_in_runs_in_a_session_of_its_own(self):
        """Not in the agent's own tmux session: nothing there is disturbed, and the window dies with the sign-in."""
        self.assertEqual(fleet.LOGIN_SESSION % "solo", "fleet-login-solo")
        self.assertNotEqual(fleet.LOGIN_SESSION % "solo", "fleet-solo")

    def against_a_hub(self, answer, runtime="claude", screen=f"Use the url below to sign in:\n  {CLAUDE_URL}\n",
                      signed_in=None, clock=None):
        """The helper's sign-in against a hub whose answer to each call is `answer(method, body)`: a (status, body)
        pair, or an exception that the call raises. signed_in: what the runtime says at each look, else signed in
        once a code was typed. clock: a one-item list that time.monotonic reads and time.sleep moves on, else
        time.sleep only records. Returns (steps, said, typed): the calls, windows, sleeps and typing in order, what
        the helper said, and the codes it typed."""
        steps, said, typed = [], [], []
        looks = list(signed_in) if signed_in is not None else None
        helper = fleet.Helper.__new__(fleet.Helper)
        helper.agent, helper.conf, helper.say = "solo", {"role": "worker"}, said.append
        helper.lifecycle = type("Lifecycle", (), {"report": lambda _self, **_: True,
                                                  "read_models": lambda _self, **_: None,
                                                  "report_soon": lambda _self: None})()
        helper.signed_in = (lambda _runtime: looks.pop(0) if looks else False) if looks is not None else \
            (lambda _runtime: bool(typed))

        def call(method, path, data=None, timeout=40):
            self.assertEqual(path, "/helper/login/solo/7")
            steps.append((method, data))
            got = answer(method, data)
            if isinstance(got, BaseException):
                raise got
            return got

        def sleep(seconds):
            steps.append(("sleep", seconds))
            if clock is not None:
                clock[0] += seconds

        def type_code(_session, code):
            typed.append(code)
            steps.append(("typed", None))

        patches = [patch.object(fleet, "http", call),
                   patch.object(fleet, "exe", lambda *a, **k: "/home/solo/.local/bin/" + runtime),
                   patch.object(fleet, "tmux", lambda *a, **k: steps.append(("tmux", a[0])) or
                                type("R", (), {"returncode": 0})()),
                   patch.object(fleet, "ensure_session", lambda *a, **k: None),
                   patch.object(fleet, "ready_runtime_config", lambda *a, **k: False),
                   patch.object(fleet, "start_window", lambda *a, **k: steps.append(("window", None))),
                   patch.object(fleet, "login_screen", lambda *a, **k: screen),
                   patch.object(fleet, "type_login_code", type_code),
                   patch.object(fleet.time, "sleep", sleep)]
        if clock is not None:
            patches.append(patch.object(fleet.time, "monotonic", lambda: clock[0]))
        for one in patches:
            one.start()
        try:
            helper.runtime_login({"login": 7, "runtime": runtime})
        finally:
            for one in patches:
                one.stop()
        return steps, said, typed

    def test_a_hub_that_is_away_is_waited_for_and_the_sign_in_still_ends_done(self):
        """Each way a call meets a hub that restarts is a wait: no connection, a reset, a closed connection, a
        timeout, an answer cut short and a 5xx. 6 November 2026, Iris on worker-1: a URLError at 08:08:49 UTC and a
        ConnectionResetError at 08:36:35 UTC each ended her sign-in while it waited for the owner's code. Now the
        provider's window stays open, the link goes back to the hub that lost it, the owner's code signs the runtime
        in, and the report of the end waits out the hub too."""
        waiting = (200, {"stop": False, "state": "needs_owner", "code": None, "send_link": False})
        script = iter([(200, {"ok": True}),                     # needs_owner: the link
                       waiting,
                       urllib.error.URLError(ConnectionRefusedError(61, "Connection refused")),   # the hub stops
                       ConnectionResetError(54, "Connection reset by peer"),
                       http.client.RemoteDisconnected("Remote end closed connection without response"),
                       TimeoutError("timed out"),
                       http.client.IncompleteRead(b""),
                       (503, {"error": "the hub is starting"}),
                       (200, {"stop": False, "state": "needs_owner", "code": None, "send_link": True}),  # back
                       (200, {"ok": True}),                     # needs_owner again: the link it lost
                       (200, {"stop": False, "state": "signing_in", "code": CODE, "send_link": False}),
                       ConnectionResetError(54, "Connection reset by peer"),   # and away at the report of the end
                       (200, {"ok": True})])                    # done
        steps, said, typed = self.against_a_hub(lambda _method, _body: next(script))

        self.assertIsNone(next(script, None), "every answer was asked for")
        self.assertEqual(typed, [CODE])
        posts = [body for method, body in steps if method == "POST"]
        self.assertEqual([body["state"] for body in posts], ["needs_owner", "needs_owner", "done", "done"])
        self.assertEqual(posts[1], posts[0], "the same link, as the machine read it")
        self.assertEqual((posts[1]["url"], posts[1]["wants_code"]), (CLAUDE_URL, True))
        windows = [i for i, (kind, what) in enumerate(steps) if kind == "tmux"]
        self.assertEqual(len(windows), 2)                       # taken down before it starts and at the end only
        self.assertEqual(windows[-1], len(steps) - 1)
        self.assertEqual(steps.count(("sleep", fleet.HUB_RETRY)), 7)   # six waits for the code, one for the end
        self.assertEqual(len([line for line in said if "the hub is away" in line]), 2, said)
        self.assertFalse([line for line in said if "error" in line], said)

    def test_only_the_sign_ins_own_deadline_ends_a_wait_for_a_hub_that_stays_away(self):
        """The hub does not come back while the owner's fourteen minutes run: the machine waits for it to the end
        of them, then reports the end as one that waited for him, once the hub answers again."""
        clock = [1000.0]

        def answer(method, body):
            if method == "GET":
                return urllib.error.URLError(ConnectionRefusedError(61, "Connection refused"))
            return 200, {"ok": True}

        steps, said, typed = self.against_a_hub(answer, clock=clock)
        posts = [body for method, body in steps if method == "POST"]
        self.assertEqual([(body["state"], body.get("timed_out")) for body in posts],
                         [("needs_owner", None), ("failed", True)])
        self.assertIn("No code came back in 14 minutes", posts[1]["detail"])
        looks = [method for method, _body in steps if method == "GET"]
        self.assertGreaterEqual(clock[0] - 1000.0, fleet.LOGIN_CODE_WAIT)
        self.assertEqual(len(looks), fleet.LOGIN_CODE_WAIT // fleet.HUB_RETRY + 1)
        self.assertEqual(typed, [])
        self.assertEqual(len([line for line in said if "the hub is away" in line]), 1, said)

    def test_codex_waiting_on_its_own_page_gives_a_restarted_hub_its_link_and_code_back(self):
        """Codex takes no code back, so the owner reads its own code from the app while the machine waits for the
        runtime: a hub that restarted gets that link and that code again."""
        script = iter([(200, {"ok": True}),                     # needs_owner
                       (200, {"stop": False, "state": "needs_owner", "code": None, "send_link": True}),
                       (200, {"ok": True}),                     # needs_owner again
                       (200, {"ok": True})])                    # done
        steps, said, _typed = self.against_a_hub(lambda _method, _body: next(script), runtime="codex",
                                                 screen=f"Open {CODEX_URL}\nEnter WXYZ-1234\n",
                                                 signed_in=[False, True])
        posts = [body for method, body in steps if method == "POST"]
        self.assertEqual([body["state"] for body in posts], ["needs_owner", "needs_owner", "done"])
        self.assertEqual(posts[1], {"state": "needs_owner", "url": CODEX_URL, "shows_code": "WXYZ-1234",
                                    "wants_code": False})
        self.assertIsNone(next(script, None))

    def test_a_codex_sign_in_made_while_the_hub_was_away_still_ends_done(self):
        """The owner signed Codex in on its page while the hub was away, to the end of the wait: the look waited the
        hub out until then, and the runtime is asked once more before the end is reported."""
        clock = [1000.0]

        def answer(method, body):
            if method == "GET":
                return urllib.error.URLError(ConnectionRefusedError(61, "Connection refused"))
            return 200, {"ok": True}

        steps, _said, _typed = self.against_a_hub(answer, runtime="codex", signed_in=[False, True], clock=clock,
                                                  screen=f"Open {CODEX_URL}\nEnter WXYZ-1234\n")
        posts = [body for method, body in steps if method == "POST"]
        self.assertEqual([body["state"] for body in posts], ["needs_owner", "done"])
        self.assertGreaterEqual(clock[0] - 1000.0, fleet.LOGIN_DONE_WAIT)


class NoTokenPath(unittest.TestCase):
    """The feature's own source, read as text: the shortcut that would break the terms is not in it."""

    TEXT = {name: (KIT / name).read_text() for name in ("hub.py", "fleet.py", "lifecycle.py")}

    def code_of(self, name, first, last):
        """The lines of one region, without its comments: what the program does, not what it says about itself."""
        text = self.TEXT[name]
        start = text.index(first)
        return "\n".join(line for line in text[start:text.index(last, start)].splitlines()
                         if not line.lstrip().startswith("#"))

    def test_the_hub_never_asks_for_a_lasting_token(self):
        region = self.code_of("hub.py", "LOGIN_RUNTIMES = ", "def machine_rows():")
        for forbidden in ("setup-token", "ANTHROPIC_API_KEY", "refresh_token", "access_token", "CLAUDE_CODE_OAUTH"):
            self.assertNotIn(forbidden, region)

    def test_the_hub_keeps_no_column_for_a_code_or_a_link(self):
        table = self.code_of("hub.py", "CREATE TABLE IF NOT EXISTS signin_jobs", "CREATE TABLE IF NOT EXISTS owner_devices")
        for forbidden in ("code", "url", "token", "secret"):
            self.assertNotIn(forbidden, table, f"the records keep a {forbidden} of a sign-in")

    def test_grok_is_refused_from_its_own_entry_of_the_runtime_table(self):
        """Neither program names Grok any more: its entry carries the fact (no sign_in) and the reason the owner
        reads, and both the hub and the machine refuse by reading that one entry. So a fourth provider whose terms
        forbid this is an entry too, and not a fifteenth place to name a runtime."""
        entry = lifecycle.RUNTIMES["grok"]
        self.assertIsNone(entry["sign_in"])
        self.assertIn("xAI's terms", entry["no_sign_in"])
        self.assertIn('"grok"', self.TEXT["lifecycle.py"])
        for name in ("hub.py", "fleet.py"):     # no second home for the fact, in either half
            self.assertNotIn('"grok"', self.TEXT[name])
            self.assertNotIn("'grok'", self.TEXT[name])

    def test_the_machines_half_writes_the_code_to_nothing(self):
        region = self.code_of("fleet.py", "def runtime_login_command", "def do_signin")
        for forbidden in ("open(", "write(", "print(", "self.say(code", "json.dump"):
            self.assertNotIn(forbidden, region, f"the sign-in half uses {forbidden}")


if __name__ == "__main__":
    unittest.main()
