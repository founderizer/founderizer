"""Authenticator codes at sign-in. Dummy data only: no vault, Chrome or network."""
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

import fleet

SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"                 # RFC 6238 test key "12345678901234567890"
SEED256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA"   # "12345678901234567890123456789012"
LOGIN = {"username": "pilot-a", "password": "DummyOnlyPassword123456789", "url": "https://example.com/login",
         "label": "practice"}


class Codes(unittest.TestCase):
    def setUp(self):        # the helper's own steps after a login is in hand, which only file mode had; it is gone,
        # and test_vault.py checks broker mode
        p = patch.object(fleet, "vault_mode", return_value="file")
        p.start()
        self.addCleanup(p.stop)

    def test_rfc_6238_vectors(self):
        for at, code in ((59, "94287082"), (1111111109, "07081804"), (1234567890, "89005924"), (2000000000, "69279037")):
            self.assertEqual(fleet.totp_code(f"otpauth://totp/x?secret={SEED}&digits=8", at), code)
        self.assertEqual(fleet.totp_code(SEED, 59), "287082")
        self.assertEqual(fleet.totp_code(f"otpauth://totp/x?secret={SEED256}&digits=8&algorithm=SHA256", 59), "46119246")
        for bad in ("not base32!", "", f"otpauth://totp/x?secret={SEED}&algorithm=MD5"):
            with self.assertRaises(Exception):
                fleet.totp_code(bad, 59)

    def test_the_vault_value_may_hold_a_seed_and_a_bad_one_is_refused(self):
        def read(value):
            item = {"id": "11111111-1111-4111-8111-111111111111", "key": "practice", "value": json.dumps(value)}
            return fleet.login_from_item(item, "11111111-1111-4111-8111-111111111111")
        base = {k: LOGIN[k] for k in ("username", "password", "url")}
        self.assertEqual(read(dict(base, totp=SEED))["totp"], SEED)
        self.assertNotIn("totp", read(base))
        with self.assertRaises(fleet.Refused) as refused:
            read(dict(base, totp="not base32!"))
        self.assertNotIn("not base32", str(refused.exception))

    def test_sign_in_types_the_authenticator_code_only_when_asked(self):
        with patch.object(fleet.sys, "platform", "darwin"), patch.object(fleet.time, "sleep"), \
             patch.object(fleet, "read_login", return_value=dict(LOGIN, totp=SEED)), \
             patch.object(fleet, "totp_code", return_value="135790"), \
             patch.object(fleet, "chrome_tab", side_effect=[42, 0, 42, 42, 42]) as chrome:
            result = fleet.do_signin("bws://x", "studio", "T-5")
        self.assertIn("authenticator code", result)
        self.assertNotIn("135790", result)
        self.assertIn('"135790"', chrome.call_args_list[3].args[1])
        self.assertEqual([c.args[2] for c in chrome.call_args_list], ["filled", "none", "otp", "filled", "none"])
        with patch.object(fleet.sys, "platform", "darwin"), patch.object(fleet.time, "sleep"), \
             patch.object(fleet, "read_login", return_value=dict(LOGIN, totp=SEED)), \
             patch.object(fleet, "chrome_tab", side_effect=[42, 0, 0]):
            with self.assertRaises(fleet.Refused):
                fleet.do_signin("bws://x", "studio", "T-5")
        with patch.object(fleet.sys, "platform", "darwin"), patch.object(fleet.time, "sleep"), \
             patch.object(fleet, "read_login", return_value=dict(LOGIN, totp=SEED)), \
             patch.object(fleet, "chrome_tab", side_effect=[42, 42]) as chrome:
            self.assertNotIn("authenticator", fleet.do_signin("bws://x", "studio"))    # no code asked, none typed

    @unittest.skipUnless(sys.platform == "darwin", "the check runs in the JavaScript of macOS (osascript)")
    def test_a_page_that_still_loads_is_not_signed_in(self):
        """The generated check itself, in JavaScriptCore, with a small stand-in for the document. The fields come
        first. Without a field, a page that still loads is 'loading', which do_signin takes for no outcome."""
        # The stand-in goes in as a parameter, not to eval(): osascript on macOS 27 runs eval() in the global scope.
        script = """
            var CHECK = %s, OTP = %s;
            function check(state, password, code) {
                var document = {readyState: state, querySelector: function (selector) {
                    return (selector === 'input[type=password]' ? password : selector === OTP && code) ? {} : null; }};
                return new Function('document', 'return ' + CHECK)(document);
            }
            JSON.stringify([check('loading', true, false), check('loading', false, true),
                            check('loading', false, false), check('interactive', false, false),
                            check('complete', false, false), check('complete', true, true),
                            check('complete', false, true)]);
        """ % (json.dumps(fleet.CHECK_JS), json.dumps(fleet.OTP_FIELD))
        answer = subprocess.run(["osascript", "-l", "JavaScript", "-e", script], capture_output=True, text=True,
                                timeout=30)
        self.assertEqual(json.loads(answer.stdout or "null"),
                         ["form", "otp", "loading", "none", "none", "form", "otp"], answer.stderr)

    def test_a_handover_carries_the_seed(self):
        with patch.object(fleet.shutil, "which", return_value="/dummy/age"), \
             patch.object(fleet, "read_login", return_value=dict(LOGIN, totp=SEED)), \
             patch.object(fleet.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "armored", "")) as run, \
             patch.object(fleet, "http", side_effect=[(200, {"pubkey": "age1dummy"}), (200, {"ref": "sealed:9"})]):
            fleet.do_handover("bws://x", "vps", "studio", "T-9")
        self.assertEqual(json.loads(run.call_args.kwargs["input"])["totp"], SEED)


if __name__ == "__main__":
    unittest.main()
