"""The central vault (Release 2): one store on the hub's server that holds every secret of the fleet, answers only the
hub's user, never calls the hub, and seals a copy only to a machine key that the owner signed -- so a hub that is
broken into cannot add a machine of its own and pull every secret in one call. And the other half on a machine's own
broker: a withdrawal, which gives back a delivered secret that no agent of that machine holds any more.

The age program and every age key are the stand-ins of test_vault.py: no real key, no real value, no hub and no
network. The owner's P-256 keys and signatures are real. They were made with openssl 3.5.0 (`openssl ecparam
-name prime256v1 -genkey`, `openssl dgst -sha256 -sign`), and openssl itself checked each one (`openssl dgst -sha256
-verify`) before it was put here, so this test needs no openssl. They were made again in the same way on 11
November 2026, when the fleet id of these statements became an example one, and no private half was kept.
"""
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import vault
from test_vault import FAKE_AGE, LOGIN

# ---- the owner's keys: base64 of 65 bytes, 04 || X || Y (CryptoKit's x963Representation)
OWNER_A = "BEDhRbV+2lgCRXOSwH4LtMxxFYsIJwg/LXmahfO7XBJeF+8XNgnOQ0HB/kS35cQu9WhvCYpWaTLZjFV3CyrOlJI="
OWNER_B = "BNu1XuaIffgPV05K+Pg0iYuEe+/A7Ks+jn2787j0JvsQJdrdmsnIeQhIQ3vf2dFROogFQ8QrjrULWbi+iHDT4T0="
STRANGER = "BGQB8A/m07gv3g4LqFJ4vyHjY1y6QhL8tmSvA9KBj3Mdss1+ilWryoBSh3kCZAORqlQ+HGfjXN2qhBRX5nL6iFI="    # no owner's

FLEET, OTHER_FLEET = "0f1e2d3c4b5a6978", "0123456789abcdef"
CENTRAL_KEY, STORE_KEY, VPS_STORE = ("age1" + c * 58 for c in "cku")     # the vault's key, its store's, a machine's
R1, R2, RR, RR2 = ("age1" + c * 58 for c in "mnrs")      # two keys of the machine vps, and two recovery keys
T0, T1, T2, T3 = 1761200000, 1761300000, 1761300600, 1761301200


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def pin(recipient, at, fleet=FLEET):
    return canon({"v": 1, "kind": "pin", "fleet": fleet, "machine": "vps", "recipient": recipient, "at": at})


# ---- the statements that were signed, byte for byte, and their signatures (base64 of DER: derRepresentation)
PIN_1, PIN_2, PIN_STALE, PIN_OTHER_FLEET = pin(R1, T1), pin(R2, T2), pin(R2, T0), pin(R1, T1, OTHER_FLEET)
UNPIN_3 = canon({"v": 1, "kind": "unpin", "fleet": FLEET, "machine": "vps", "at": T3})
RECOVERY_1 = canon({"v": 1, "kind": "recovery", "fleet": FLEET, "recipient": RR, "at": T1})
RECOVERY_STALE = canon({"v": 1, "kind": "recovery", "fleet": FLEET, "recipient": RR2, "at": T0})
PIN_NOT_CANONICAL = json.dumps({"v": 1, "kind": "pin", "fleet": FLEET, "machine": "vps", "recipient": R1, "at": T1})
SIG_PIN_1 = "MEUCIGebAVugRuu5dcMRqMFZDRvkSQorOOSfsum7uPX9uvB3AiEA3GQFIVdnQ5p7Z0aoBgO7orfCgfD1R19IBXvyIjN5SJc="     # A
SIG_PIN_1_STRANGER = "MEUCIDgkp9/eXknV0HCveEt7kKa3HuEUDR55Z/9MxmrzxgSkAiEAoJO6D9l3Aft+h5IyR+4UxueFwP7TRg6sRU/yn850uew="
SIG_PIN_2 = "MEQCIGw8tPdsYT8+sdaeb6UqQGRkLQnEk5gIB9jS25gbYkajAiALMBUm0bDUASdu8rnWgwp3EmJSB213VRjmkFRX2NJNUw=="     # B
SIG_UNPIN_3 = "MEUCIQCd95FEajbiNSevF50TwgtA0g8UecLc2WAqFYysuacS2gIgDj2clgI1ekFnA7FzKtcowzG8J+84zRQLuBPb87NhG60="   # A
SIG_PIN_STALE = "MEUCIQCp8lYJhnyfa+VT3W4hy64iz48eriLdOfvUWBC1xvCpLwIgaPisWIhAORUNROl91/7KShkvF9k+JDRVha4gYQQDgt8="  # A
SIG_RECOVERY_1 = "MEUCIBHRPaewwFdUYo4sLi9gZxN8zcD8R4L75F1UJNfbnkovAiEArzw9e7Zb++ar0V3w3hBlKkpAQvmGpjNYx9AXUtM4gZ0="
SIG_RECOVERY_STALE = "MEYCIQCGlEt7v/70AKpLopt1e6s6HOBx8QE9lGlLdz4m7jcKMwIhANNcqieDK/h/76DTzCCn090TJvJD5zUusaLLsuaQJgf+"
SIG_PIN_OTHER_FLEET = "MEYCIQDS2k3wibvpOtDdpZAcrma7oyagq530+heul627WYcgcwIhAJz60KXjpxuiP5NL/myWCBqmnTWdL7R+sH3Yd5ZlnpX7"
SIG_NOT_CANONICAL = "MEUCIGaY+YI+n9p0EM5KBEFtCtzYMd01jcUNMVAFiYBVbUXbAiEA5FBYh33D8+eXJXN5gGj2hkpaTkdr5A9eKIub6feSmaU="

# RFC 6979 A.2.5 (P-256 with SHA-256): a key and two signatures that nothing of ours made, for the curve constants.
RFC_KEY = (0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6,
           0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299)
RFC_SIGNED = ((b"sample", 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716,
               0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8),
              (b"test", 0xF1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367,
               0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083))

# ---- the values: fake, and only in this test
SID, KEY_SID, OTHER_SID = ("6f1c2a4e-8b3d-4e5f-9a7b-1c2d3e4f5a6b", "7a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d",
                           "8b3c4d5e-6f7a-4b2c-9d3e-4f5a6b7c8d9e")
REF, KEY_REF, OTHER_REF = ("bws://" + s for s in (SID, KEY_SID, OTHER_SID))
API_KEY = "sk-fake-only-central-20261024"
SALTS = {"password": "0f" * 16, "totp": "a5" * 16}
AKEY = "vps-central-agent-key-".ljust(43, "k")          # the agent key that a machine broker's caller fields carry
HUB_UID = os.getuid() + 1                               # the hub's user; this process is the vault's own user
EMPTY = json.dumps({"v": vault.STORE, "items": {}}, sort_keys=True)
FAKE_KEYGEN = """#!{python}
# Fake age-keygen: "-o FILE" makes a new key file with its public key line, and never writes over one.
import secrets, sys
public = "age1" + "".join(secrets.choice("023456789acdefghjklmnpqrstuvwxyz") for _ in range(58))
with open(sys.argv[2], "x") as f:
    f.write("# created: 2026-10-24T00:00:00Z\\n# public key: " + public + "\\nAGE-SECRET-KEY-1FAKECENTRAL\\n")
"""


def der(r, s):
    """The DER form of a signature, in base64, as CryptoKit writes it: each number in its shortest form, with a zero
    byte in front only when its high bit is set."""
    def integer(n):
        body = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big")
        return b"\x02" + bytes([len(body)]) + body
    numbers = integer(r) + integer(s)
    return base64.b64encode(b"\x30" + bytes([len(numbers)]) + numbers).decode()


# A third owner key whose private half this test holds, for the statements of the signed grants (DevOps plan V1):
# signed here with the curve of vault.py itself (owner_sign), so a new kind of statement needs no openssl. The
# verifier is proved above against openssl's own signatures and the vectors of RFC 6979.
OWNER_C_SECRET = 0x5A17C0FFEE5EED0F7E57B1A5ED0D1E7C0A2B3C4D5E6F708192A3B4C5D6E7F801


def owner_point(secret):
    """The base64 of 04 || X || Y of a private scalar's public point, as the app hands an owner key over."""
    x, y = vault.point_times(secret, vault.P256_G)
    return base64.b64encode(b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")).decode()


OWNER_C = owner_point(OWNER_C_SECRET)


def owner_sign(statement, secret=OWNER_C_SECRET):
    """ECDSA P-256 over SHA-256 of the statement's UTF-8, in DER and base64, as CryptoKit signs it."""
    e = int.from_bytes(hashlib.sha256(statement.encode("utf-8")).digest(), "big")
    while True:
        k = secrets.randbelow(vault.P256_N - 1) + 1
        r = vault.point_times(k, vault.P256_G)[0] % vault.P256_N
        s = pow(k, -1, vault.P256_N) * (e + r * secret) % vault.P256_N
        if r and s:
            return der(r, s)


def grant(ref, agent, machine, at, kind="grant", fleet=FLEET):
    """A grant statement (machine None for an ungrant), canonical."""
    return canon(dict({"v": 1, "kind": kind, "fleet": fleet, "login": ref, "agent": agent, "at": at},
                      **({"machine": machine} if machine else {})))


def pooled(ref, at, kind="pool"):
    return canon({"v": 1, "kind": kind, "fleet": FLEET, "login": ref, "at": at})


def halves(signature):
    return vault.der_signature(base64.b64decode(signature))


def registered(value, salts=SALTS):
    """The fingerprints that the owner's app registers for a value: SHA-256 of salt + secret, for each secret of 8
    characters or more. Written out here rather than taken from vault.py, so the two are compared."""
    found = [("password", value["password"])] + ([("totp", value["totp"])] if "totp" in value else [])
    return [{"kind": kind, "hash": hashlib.sha256((salts[kind] + secret).encode()).hexdigest(), "len": len(secret)}
            for kind, secret in found if len(secret) >= 8]


def call(path, request):
    """One request on a broker's socket, as the hub's central_call makes it: one line out, one line in."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(10)
        conn.connect(path)
        conn.sendall((json.dumps(request) + "\n").encode())
        data = b""
        while not data.endswith(b"\n"):
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
    return json.loads(data)


def leaky_age(real):
    """An age that gives what it should lock back in plain."""
    def run(argv, data, env=None):
        if argv[1:3] == ["-a", "-r"]:
            armored = vault.ARMOR + "\n" + data + "\n-----END AGE ENCRYPTED FILE-----\n"
            return subprocess.CompletedProcess(argv, 0, armored, "")
        return real(argv, data, env)
    return run


class Signatures(unittest.TestCase):
    """The owner's signature, verified in plain Python: P-256, DER read strictly, and any one of the owner's keys."""

    owners = {"owner_keys": [OWNER_A, OWNER_B]}

    def test_the_curve_is_p256_and_a_signature_that_nothing_of_ours_made_verifies(self):
        self.assertTrue(vault.on_curve(vault.P256_G))
        self.assertIsNone(vault.point_times(vault.P256_N, vault.P256_G))        # G has the order n
        self.assertTrue(vault.on_curve(RFC_KEY))
        n = vault.P256_N
        for message, r, s in RFC_SIGNED:
            digest = hashlib.sha256(message).digest()
            self.assertTrue(vault.ecdsa_verified(RFC_KEY, digest, r, s))
            self.assertFalse(vault.ecdsa_verified(RFC_KEY, hashlib.sha256(message + b".").digest(), r, s))
            self.assertFalse(vault.ecdsa_verified(RFC_KEY, digest, s, r))
            # r and s are in 1..n-1: s + n would be the same signature to a verifier that did not check it
            for halves_out_of_range in ((r, 0), (0, s), (n, s), (r, n), (r + n, s), (r, s + n)):
                self.assertFalse(vault.ecdsa_verified(RFC_KEY, digest, *halves_out_of_range))

    def test_a_signature_of_either_owner_key_verifies_and_no_other(self):
        self.assertTrue(vault.owner_signed(self.owners, PIN_1, SIG_PIN_1))          # key A
        self.assertTrue(vault.owner_signed(self.owners, PIN_2, SIG_PIN_2))          # key B: any owner key may sign
        self.assertFalse(vault.owner_signed(self.owners, PIN_2, SIG_PIN_1))         # a signature of another statement
        self.assertFalse(vault.owner_signed({"owner_keys": [OWNER_B]}, PIN_1, SIG_PIN_1))
        self.assertFalse(vault.owner_signed(self.owners, PIN_1, SIG_PIN_1_STRANGER))
        # The stranger's signature is a real one, of a key that is not the owner's.
        self.assertTrue(vault.owner_signed({"owner_keys": [STRANGER]}, PIN_1, SIG_PIN_1_STRANGER))

    def test_a_damaged_signature_is_refused(self):
        r, s = halves(SIG_PIN_1)
        n = vault.P256_N
        self.assertEqual(der(r, s), SIG_PIN_1)          # the test's own DER is CryptoKit's
        unpadded = SIG_UNPIN_3[:-2] + "1="              # other unused bits: the same bytes to a loose reader
        self.assertEqual(base64.b64decode(unpadded), base64.b64decode(SIG_UNPIN_3))
        for bad in (der(r ^ 1, s), der(r, s ^ (1 << 77)),                       # a flipped bit in r, in s
                    der(r, 0), der(0, s), der(n, s), der(r, n), der(r + n, s), der(r, s + n),     # out of 1..n-1
                    base64.b64encode(base64.b64decode(SIG_PIN_1) + b"\x00").decode(),         # a byte after the DER
                    SIG_PIN_1 + "\n", " " + SIG_PIN_1, SIG_UNPIN_3.rstrip("="), "", "not base64"):
            self.assertFalse(vault.owner_signed(self.owners, PIN_1, bad), bad)
        self.assertFalse(vault.owner_signed(self.owners, UNPIN_3, unpadded))
        self.assertTrue(vault.owner_signed(self.owners, UNPIN_3, SIG_UNPIN_3))
        # There is no low-s rule: CryptoKit can make either s, and (r, n - s) is the same signature.
        self.assertTrue(vault.owner_signed(self.owners, PIN_1, der(r, n - s)))

    def test_der_is_read_strictly(self):
        self.assertEqual(vault.der_signature(bytes.fromhex("3006020101020101")), (1, 1))
        self.assertEqual(vault.der_signature(bytes.fromhex("300702020080020101")), (128, 1))     # a needed zero byte
        for bad in ("3006020101020101" + "00",          # a byte after the sequence
                    "3106020101020101",                 # not a SEQUENCE
                    "308106020101020101",               # the long form of a short length
                    "3007020101020101", "3005020101020101",      # a length that is not the content's
                    "3009020101020101020101",           # three numbers
                    "3003020101",                       # one number
                    "3006020180020101",                 # a negative r
                    "300702020001020101",               # r with a zero byte that it does not need
                    "3006020100020101", "3006020101020100",      # r = 0, s = 0
                    "30050200020101",                   # a number of no bytes
                    "3006040101020101",                 # an OCTET STRING where a number belongs
                    "", "30", "3000"):
            self.assertIsNone(vault.der_signature(bytes.fromhex(bad)), bad)

    def test_an_owner_key_must_be_a_point_of_the_curve(self):
        self.assertTrue(vault.on_curve(vault.owner_key(OWNER_A)))
        raw, p = base64.b64decode(OWNER_A), vault.P256_P
        x, y = raw[1:33], int.from_bytes(raw[33:], "big")

        def b64(data):
            return base64.b64encode(data).decode()
        for bad in (b64(b"\x04" + x + ((y + 1) % p).to_bytes(32, "big")),     # a key not on the curve
                    b64(b"\x02" + x), b64(b"\x03" + raw[1:]),                 # a compressed key, another prefix
                    b64(raw[:-1]), b64(raw + b"\x00"),                        # 64 and 66 bytes
                    b64(b"\x04" + p.to_bytes(32, "big") + raw[33:]),          # x outside the field
                    b64(b"\x04" + bytes(64)),                                 # (0, 0)
                    OWNER_A.rstrip("="), OWNER_A + "\n", "", None, 7):
            with self.assertRaises(ValueError):
                vault.owner_key(bad)


class Configuration(unittest.TestCase):
    """The central vault's configuration, and a machine's broker's, which loads as it did."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="fcc-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.dir.chmod(0o755)
        for name in ("age", "curl"):
            (self.dir / name).write_text("#!/bin/sh\nexit 0\n")
            (self.dir / name).chmod(0o755)
        self.good = {"central": True, "hub_uid": HUB_UID, "fleet": FLEET, "owner_keys": [OWNER_A, OWNER_B],
                     "age": str(self.dir / "age"), "age_key": "/var/lib/fleet-vault-central/age.key",
                     "store": "/var/lib/fleet-vault-central/store.age",
                     "store_key": "/var/lib/fleet-vault-central/store.key",
                     "socket": "/run/fleet-vault-central/vault.sock",
                     "state": "/var/lib/fleet-vault-central/central.json"}

    def written(self, conf):
        path = self.dir / "vault.json"
        path.write_text(json.dumps(conf) + "\n")
        path.chmod(0o644)
        return str(path)

    def refused(self, conf):
        with self.assertRaises(SystemExit) as refused:
            vault.load_config(self.written(conf))
        return str(refused.exception)

    def test_a_central_configuration_loads_and_admits_only_the_hubs_user(self):
        conf = vault.load_config(self.written(self.good))
        self.assertEqual(conf, self.good)
        self.assertTrue(vault.admitted(conf, HUB_UID))
        for uid in (os.getuid(), HUB_UID + 1, 0):
            self.assertFalse(vault.admitted(conf, uid))

    def test_a_central_configuration_of_any_other_shape_is_refused(self):
        for key in sorted(vault.CENTRAL_KEYS):                                    # one missing
            self.assertIn("needs exactly", self.refused({k: v for k, v in self.good.items() if k != key}), key)
        for extra in ({"hub": "http://100.80.1.2:8765"}, {"worker_uid": 1001}, {"worker_group": "fleet-agents"},
                      {"agent": "vps"}, {"region": "eu"}, {"token_file": "/var/lib/fleet-vault/bws-token"},
                      {"bws": "/usr/local/bin/bws"}, {"bws_config": "/etc/fleet-vault/bws.toml"},
                      {"curl": "/usr/bin/curl"}, {"ssh": "/usr/bin/ssh"}, {"sdk": "/usr/local/lib/x.so"},
                      {"sdk_sha256": "a" * 64}, {"write_project": "c0ffee00-0000-4000-8000-0000000000ea"}):
            self.assertIn("needs exactly", self.refused(dict(self.good, **extra)), extra)
        for central in (False, "true", 1, None):
            self.assertIn("needs exactly", self.refused(dict(self.good, central=central)), central)
        for uid in (os.getuid(), -1, True, "998", None):
            self.assertIn("hub_uid", self.refused(dict(self.good, hub_uid=uid)), uid)
        for fleet in (FLEET.upper(), FLEET[:-1], FLEET + "0", "g" * 16, 7):
            self.assertIn("fleet must be", self.refused(dict(self.good, fleet=fleet)), fleet)
        raw = base64.b64decode(OWNER_A)
        off_curve = base64.b64encode(raw[:-1] + bytes([raw[-1] ^ 1])).decode()       # Y one bit off: no point
        for keys in ([], [OWNER_A] * 9, OWNER_A, None):
            self.assertIn("owner_keys must list", self.refused(dict(self.good, owner_keys=keys)), keys)
        for keys in ([off_curve], [OWNER_A, off_curve], [OWNER_A.rstrip("=")], [OWNER_A, 7],
                     [base64.b64encode(b"\x02" + raw[1:33]).decode()]):
            self.assertIn("point of the curve", self.refused(dict(self.good, owner_keys=keys)), keys)
        for key in ("age", "age_key", "store", "store_key", "socket", "state"):
            self.assertIn(f"{key} must be an absolute path", self.refused(dict(self.good, **{key: "vault.file"})))
        loose = self.dir / "loose-age"                          # an age that another user could replace
        loose.write_text("#!/bin/sh\nexit 0\n")
        loose.chmod(0o777)
        self.assertIn("The age program", self.refused(dict(self.good, age=str(loose))))

    def test_a_machines_live_configuration_still_loads_as_it_did(self):
        """The shape of /etc/fleet-vault/vault.json on a machine today: its own store, its agents' group, curl and
        ssh. Nothing of the central vault changes it."""
        live = {"hub": "http://100.80.1.2:8765", "age_key": "/var/lib/fleet-vault/age.key",
                "socket": "/run/fleet-vault/vault.sock", "age": str(self.dir / "age"), "worker_group": "fleet-agents",
                "store": "/var/lib/fleet-vault/store.age", "store_key": "/var/lib/fleet-vault/store.key",
                "curl": str(self.dir / "curl"), "ssh": "/usr/bin/ssh"}
        me = pwd.getpwuid(os.getuid())
        agents = type("Group", (), {"gr_mem": ["fleet-vps"], "gr_gid": me.pw_gid + 9000})()
        with patch.object(vault.grp, "getgrnam", return_value=agents):
            conf = vault.load_config(self.written(live))
            self.assertEqual(conf, live)
            self.assertFalse(vault.admitted(conf, HUB_UID))
            with patch.object(vault.pwd, "getpwuid", return_value=type("User", (), {"pw_name": "fleet-vps",
                                                                                    "pw_gid": 5})()):
                self.assertTrue(vault.admitted(conf, 4242))
            # but never with a Bitwarden project: Founderizer has no Bitwarden backend any more, and the broker does
            # not start on one
            bitwarden = {k: v for k, v in live.items() if k not in ("store", "store_key")}
            bitwarden.update(region="eu", token_file="/var/lib/fleet-vault/bws-token", bws="/usr/local/bin/bws",
                             bws_config="/etc/fleet-vault/bws.toml")
            with self.assertRaises(SystemExit) as refused:
                vault.load_config(self.written(bitwarden))
            self.assertIn("Founderizer has no Bitwarden backend any more", str(refused.exception))


class CentralVault(unittest.TestCase):
    """The central vault's operations, as the hub's user asks them, with a stand-in age and its own store."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="fc-"))         # short: a Unix socket path has at most 104 bytes
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.dir.chmod(0o700)
        state = self.dir / "state"
        state.mkdir(mode=0o700)
        self.age = self.dir / "age"
        self.age.write_text(FAKE_AGE.format(python=sys.executable))
        self.age.chmod(0o755)
        self.keys = {}
        # The vault's two keys, in its state folder, and the keys that open its copies, which are not the vault's.
        for public in (CENTRAL_KEY, STORE_KEY, R1, R2, RR):
            path = (state if public in (CENTRAL_KEY, STORE_KEY) else self.dir) / f"{public[4]}.key"
            path.write_text(f"# created: 2026-10-24T00:00:00Z\n# public key: {public}\n"
                            f"AGE-SECRET-KEY-1FAKE{public[4].upper()}\n")
            path.chmod(0o600)
            self.keys[public] = path
        store = state / "store.age"
        store.write_text(self.lock(STORE_KEY, EMPTY))
        store.chmod(0o600)
        self.conf = {"central": True, "hub_uid": HUB_UID, "fleet": FLEET, "owner_keys": [OWNER_A, OWNER_B, OWNER_C],
                     "age": str(self.age), "age_key": str(self.keys[CENTRAL_KEY]), "store": str(store),
                     "store_key": str(self.keys[STORE_KEY]), "socket": str(self.dir / "c.sock"),
                     "state": str(state / "central.json")}
        self.logged = []
        for p in (patch.object(vault, "log", self.logged.append),
                  patch.object(vault, "hub", side_effect=AssertionError("the central vault called the hub"))):
            p.start()
            self.addCleanup(p.stop)

    # ---- helpers
    def lock(self, recipient, text):
        """A copy locked with the stand-in age: what the owner's app seals, or what the vault keeps."""
        return subprocess.run([str(self.age), "-a", "-r", recipient], input=text, capture_output=True, text=True,
                              check=True).stdout

    def opened(self, ciphertext, recipient):
        """What a copy holds for the holder of this key; None when that key does not open it."""
        r = subprocess.run([str(self.age), "-d", "-i", str(self.keys[recipient])], input=ciphertext,
                           capture_output=True, text=True)
        return r.stdout if r.returncode == 0 else None

    def ask(self, op, uid=HUB_UID, **fields):
        return vault.handle(self.conf, json.dumps(dict({"v": vault.PROTOCOL, "op": op}, **fields)), uid)

    def refused(self, op, **fields):
        with self.assertRaises(vault.Refused) as refused:
            self.ask(op, **fields)
        return str(refused.exception)

    def intake_fields(self, value=LOGIN, ref=REF, title="example.org · pilot-b", item="login", prints=None,
                      to=CENTRAL_KEY):
        return {"login": ref, "title": title, "item": item, "ciphertext": self.lock(to, json.dumps(value)),
                "salts": SALTS, "fingerprints": registered(value) if prints is None else prints}

    def intake(self, **given):
        return self.ask("intake", **self.intake_fields(**given))

    def items(self):
        return vault.LocalStore(self.conf).opened()

    def signed(self, op, statement, signature):
        return self.ask(op, statement=statement, signature=signature)

    def granted(self, statement, op=None):
        """One statement of the signed grants, signed with the third owner key here."""
        return self.ask(op or json.loads(statement)["kind"], statement=statement, signature=owner_sign(statement))

    def state(self):
        return json.loads(Path(self.conf["state"]).read_text())

    # ---- who may ask, and what
    def test_only_the_hubs_user_may_ask(self):
        for uid in (os.getuid(), HUB_UID + 1, 0):           # the vault's own user, another user, root
            with self.assertRaises(vault.Refused) as refused:
                self.ask("status", uid=uid)
            self.assertEqual(str(refused.exception), "only the hub's user may ask the central vault")
        self.assertIs(self.ask("status")["central"], True)

    def test_a_central_vault_serves_nothing_of_a_machines_broker(self):
        for op in ("handover", "deposit", "withdraw", "read", "probe", "create", "request", "cancel", "place", "signin",
                   "nonsense", None, ["pin"]):
            self.assertEqual(self.refused(op, job=1, agent="vps", agent_key=AKEY), "unknown operation")

    def test_the_status_says_what_the_hub_needs_and_no_value(self):
        self.intake()
        self.assertEqual(self.ask("status"), {"ok": True, "v": 2, "central": True, "recipient": CENTRAL_KEY,
                                              "store_recipient": STORE_KEY, "fleet": FLEET, "owner_keys": 3,
                                              "pins": {}, "recovery": None, "grants": [], "pool": [], "items": 1,
                                              "removes": True, "replaces": True, "values": {}, "source": None})
        self.signed("pin", PIN_1, SIG_PIN_1)
        self.signed("recovery", RECOVERY_1, SIG_RECOVERY_1)
        status = self.ask("status")
        self.assertEqual((status["pins"], status["recovery"]), ({"vps": {"recipient": R1, "at": T1}}, RR))
        self.assertNotIn(LOGIN["password"], json.dumps(status))
        self.assertNotIn("example.org", json.dumps(status))             # no title either

    # ---- intake
    def test_intake_saves_the_owners_value_under_its_reference(self):
        # the answer names the fingerprints of the value that the store holds now: no secret, the hub has them
        prints = sorted(registered(LOGIN), key=lambda x: (x["kind"], x["hash"], x["len"]))
        self.assertEqual(self.intake(), {"ok": True, "login": REF, "saved": "new", "fingerprints": prints})
        item = self.items()[SID]
        self.assertEqual((item["key"], item["note"]), ("example.org · pilot-b", "taken from the owner"))
        self.assertEqual(item["value"], canon(LOGIN))                   # the canonical JSON of the value
        self.assertEqual(self.intake(), {"ok": True, "login": REF, "saved": "same", "fingerprints": prints})   # a retry
        self.assertEqual(self.intake(ref=REF.upper().replace("BWS://", "bws://"))["login"], REF)
        other = dict(LOGIN, password="AnotherFakePassword-123456")      # another value under the same reference
        with self.assertRaises(vault.Refused) as refused:
            self.intake(value=other)
        self.assertIn("holds another value under this reference", str(refused.exception))
        self.assertEqual(self.items()[SID]["value"], canon(LOGIN))
        key = {"password": API_KEY}                                     # an API key needs no address
        self.assertEqual(self.intake(value=key, ref=KEY_REF, title="OPENAI_API_KEY", item="api_key")["saved"], "new")
        self.assertEqual(self.items()[KEY_SID]["value"], canon(key))
        on_disk = Path(self.conf["store"]).read_text()
        for secret in (LOGIN["password"], LOGIN["totp"], API_KEY):
            self.assertNotIn(secret, on_disk)

    def test_intake_refuses_a_value_that_is_not_the_one_the_owner_registered(self):
        mine = registered(LOGIN)
        self.assertEqual(len(mine), 2)                                  # the password and the authenticator seed
        other = registered(dict(LOGIN, password="AnotherFakePassword-123456"))
        for prints in (other, mine[:1], mine[1:], [],                   # another value's; the seed's or the password's
                       registered(LOGIN, {"password": "11" * 16, "totp": "22" * 16}),    # missing; none; other salts
                       [dict(mine[0], len=mine[0]["len"] + 1), mine[1]]):
            with self.assertRaises(vault.Refused) as refused:
                self.intake(prints=prints)
            self.assertEqual(str(refused.exception), "the value does not match what the owner registered")
        self.assertEqual(self.items(), {})
        # The rule of a deposit: each of the value's own fingerprints is registered, so the rows of a reference that
        # the owner registered more than once, or one row twice, still take the value that one of them describes.
        self.assertEqual(self.intake(prints=other + mine + [mine[0]])["saved"], "new")

    def test_intake_refuses_a_copy_that_it_cannot_open_or_read(self):
        def refusal(**changes):
            fields = dict(self.intake_fields(), **changes)
            with self.assertRaises(vault.Refused) as refused:
                self.ask("intake", **fields)
            return str(refused.exception)
        self.assertIn("cannot be opened with the central vault's key",
                      refusal(ciphertext=self.lock(R1, json.dumps(LOGIN))))           # sealed to another key
        self.assertIn("cannot be opened", refusal(ciphertext=vault.ARMOR + "\nbm90IGEgY29weQ==\n"))
        self.assertIn("holds no item", refusal(ciphertext=self.lock(CENTRAL_KEY, "not json")))
        self.assertIn("the login is invalid",                                          # a login with no address
                      refusal(ciphertext=self.lock(CENTRAL_KEY, json.dumps({"password": "x" * 9}))))
        for bad in ({"ciphertext": json.dumps(LOGIN)}, {"ciphertext": vault.ARMOR + "x" * vault.COPY_MAX},
                    {"ciphertext": None}, {"login": "sealed:4"}, {"login": "bws://not-a-uuid"}, {"title": ""},
                    {"title": "two\nlines"}, {"title": "x" * 201}, {"item": "card"}, {"salts": {"password": "0f" * 16}},
                    {"salts": None}, {"fingerprints": None}, {"fingerprints": [{"kind": "password"}]},
                    {"fingerprints": [dict(registered(LOGIN)[0], kind="pin")]}, {"fingerprints": registered(LOGIN) * 17},
                    {"fingerprints": [dict(registered(LOGIN)[0], len="26")]}):
            self.assertEqual(refusal(**bad), "the intake request is not valid", bad)
        self.assertEqual(self.items(), {})

    # ---- the owner's statements
    def test_a_pin_is_kept_until_a_newer_statement_of_the_owner(self):
        self.assertEqual(self.signed("pin", PIN_1, SIG_PIN_1),
                         {"ok": True, "kind": "pin", "machine": "vps", "recipient": R1, "saved": "new"})
        self.assertEqual(self.signed("pin", PIN_1, SIG_PIN_1)["saved"], "same")             # a retry
        self.assertIn("as new or newer", self.refused("pin", statement=PIN_STALE, signature=SIG_PIN_STALE))
        self.assertEqual(self.signed("pin", PIN_2, SIG_PIN_2),                              # by the other owner key
                         {"ok": True, "kind": "pin", "machine": "vps", "recipient": R2, "saved": "replaced"})
        self.assertEqual(self.ask("status")["pins"], {"vps": {"recipient": R2, "at": T2}})
        self.assertEqual(self.signed("unpin", UNPIN_3, SIG_UNPIN_3),
                         {"ok": True, "kind": "unpin", "machine": "vps", "saved": "removed"})
        self.assertEqual(self.signed("unpin", UNPIN_3, SIG_UNPIN_3)["saved"], "same")
        self.assertEqual(self.ask("status")["pins"], {})
        # The unpin keeps its time, so the owner's older pins, which a hub could send again, stay old.
        for statement, signature in ((PIN_1, SIG_PIN_1), (PIN_2, SIG_PIN_2)):
            self.assertIn("as new or newer", self.refused("pin", statement=statement, signature=signature))
        self.assertEqual(self.state(), {"v": 1, "pins": {"vps": {"recipient": None, "at": T3}}, "recovery": None,
                                        "grants": {}, "pool": {}, "removed": {}})
        self.assertEqual(stat.S_IMODE(os.stat(self.conf["state"]).st_mode), 0o600)
        self.assertFalse(os.path.exists(self.conf["state"] + ".new"))

    def test_the_recovery_key_is_the_owners_too(self):
        self.assertEqual(self.signed("recovery", RECOVERY_1, SIG_RECOVERY_1),
                         {"ok": True, "kind": "recovery", "recipient": RR, "saved": "new"})
        self.assertEqual(self.signed("recovery", RECOVERY_1, SIG_RECOVERY_1)["saved"], "same")
        self.assertIn("as new or newer",
                      self.refused("recovery", statement=RECOVERY_STALE, signature=SIG_RECOVERY_STALE))
        self.assertEqual(self.ask("status")["recovery"], RR)

    def test_a_statement_that_is_not_exactly_the_owners_is_refused(self):
        r, s = halves(SIG_PIN_1)
        cases = [
            ("pin", PIN_1, SIG_PIN_1_STRANGER, "valid signature of the owner"),        # a signature by another key
            ("pin", PIN_1, der(r ^ 1, s), "valid signature of the owner"),             # a flipped bit in r
            ("pin", PIN_1, der(r, 0), "valid signature of the owner"),                 # s = 0
            ("pin", PIN_1, der(r + vault.P256_N, s), "valid signature of the owner"),  # r >= n
            ("pin", PIN_1, base64.b64encode(base64.b64decode(SIG_PIN_1) + b"\x00").decode(),
             "valid signature of the owner"),                                         # a byte after the DER
            ("pin", pin(R2, T1), SIG_PIN_1, "valid signature of the owner"),          # another key than was signed
            ("pin", PIN_OTHER_FLEET, SIG_PIN_OTHER_FLEET, "for another fleet"),       # signed, for another fleet
            ("pin", PIN_NOT_CANONICAL, SIG_NOT_CANONICAL, "canonical form"),          # signed, not canonical
            ("pin", PIN_1 + " ", SIG_PIN_1, "canonical form"),
            ("unpin", PIN_1, SIG_PIN_1, "not a valid unpin statement"),               # a statement of another kind
            ("recovery", PIN_1, SIG_PIN_1, "not a valid recovery statement"),
            ("pin", UNPIN_3, SIG_UNPIN_3, "not a valid pin statement"),
            ("pin", canon(dict(json.loads(PIN_1), kind="unpin")), SIG_PIN_1, "not a valid pin statement"),
            ("pin", canon(dict(json.loads(PIN_1), v=True)), SIG_PIN_1, "not a valid pin statement"),
            ("pin", canon(dict(json.loads(PIN_1), at=float(T1))), SIG_PIN_1, "not a valid pin statement"),
            ("pin", canon(dict(json.loads(PIN_1), machine="VPS")), SIG_PIN_1, "not a valid pin statement"),
            ("pin", canon(dict(json.loads(PIN_1), recipient="age1short")), SIG_PIN_1, "not a valid pin statement"),
            ("pin", canon(dict(json.loads(PIN_1), note="x")), SIG_PIN_1, "not a valid pin statement"),
            ("pin", "[1]", SIG_PIN_1, "canonical form"),
            ("pin", None, SIG_PIN_1, "needs its statement and its signature"),
            ("pin", PIN_1, None, "needs its statement and its signature"),
        ]
        for op, statement, signature, said in cases:
            text = self.refused(op, statement=statement, signature=signature)
            self.assertIn(said, text, (op, statement, signature))
            for content in (R1, R2, FLEET, OTHER_FLEET, SIG_PIN_1, "vps", str(T1)):  # no error repeats the statement
                self.assertNotIn(content, text)
        self.assertFalse(os.path.exists(self.conf["state"]))             # nothing was kept
        self.assertEqual(self.signed("pin", PIN_1, der(r, vault.P256_N - s))["saved"], "new")    # no low-s rule

    def test_a_state_that_another_user_can_read_or_that_is_damaged_is_refused(self):
        self.signed("pin", PIN_1, SIG_PIN_1)
        state = Path(self.conf["state"])
        state.chmod(0o640)
        self.assertIn("mode 600", self.refused("status"))
        state.chmod(0o600)
        for damaged in ("{}", "not json", json.dumps({"v": 1, "pins": {"vps": {"recipient": "age1x", "at": T1}},
                                                       "recovery": None}),
                        json.dumps({"v": 1, "pins": {}, "recovery": None, "removed": {REF.upper(): T1}}),
                        json.dumps({"v": 1, "pins": {}, "recovery": None, "removed": {REF: "today"}}),
                        json.dumps({"v": 1, "pins": {}, "recovery": None, "values": {REF: {"sha256": "0" * 64}}}),
                        json.dumps({"v": 1, "pins": {}, "recovery": None, "values": {REF: {"sha256": "0" * 63, "at": T1}}}),
                        json.dumps({"v": 1, "pins": {}, "recovery": None,
                                    "values": {REF.upper(): {"sha256": "0" * 64, "at": T1}}}),
                        json.dumps({"v": 1, "pins": {}, "recovery": None, "values": {REF: {"sha256": "0" * 64, "at": "now"}}}),
                        json.dumps({"v": 1, "pins": {}, "recovery": None, "values": [REF]})):
            state.write_text(damaged)
            self.assertEqual(self.refused("seal", login=REF, machine="vps"), "the central vault's state cannot be read")

    # ---- seal
    def test_seal_locks_a_value_only_to_the_key_the_owner_pinned_for_that_machine(self):
        self.intake()
        self.granted(grant(REF, "vps", "vps", T1))
        self.assertIn("has not pinned a key for this machine", self.refused("seal", login=REF, machine="vps"))
        self.signed("pin", PIN_1, SIG_PIN_1)
        sealed = self.ask("seal", login=REF, machine="vps")
        self.assertEqual(set(sealed), {"ok", "login", "machine", "recipient", "title", "ciphertext", "sha256"})
        self.assertEqual((sealed["login"], sealed["machine"], sealed["recipient"], sealed["title"]),
                         (REF, "vps", R1, "example.org · pilot-b"))
        self.assertEqual(sealed["sha256"], hashlib.sha256(sealed["ciphertext"].encode()).hexdigest())
        self.assertEqual(self.opened(sealed["ciphertext"], R1), canon(LOGIN))   # the stored text, unchanged
        for other in (R2, CENTRAL_KEY, STORE_KEY):
            self.assertIsNone(self.opened(sealed["ciphertext"], other))
        self.assertNotIn(LOGIN["password"], json.dumps(sealed))
        # what a machine's broker does with it: deposit reads it as a delivered login
        self.assertEqual(vault.delivered(self.opened(sealed["ciphertext"], R1), "login"), LOGIN)
        self.granted(grant(OTHER_REF, "vps", "vps", T1))       # a grant of this machine's opens no other secret
        self.assertIn("has not pinned", self.refused("seal", login=REF, machine="studio"))
        self.assertEqual(self.refused("seal", login=OTHER_REF, machine="vps"), "the central vault has no such login")
        for bad in ({"login": "sealed:4", "machine": "vps"}, {"login": REF, "machine": "VPS"}, {"login": REF},
                    {"machine": "vps"}, {"login": REF, "machine": "vps\n"}, {"login": REF, "machine": 7}):
            self.assertEqual(self.refused("seal", **bad), "a seal request needs a login and a machine", bad)
        self.signed("pin", PIN_2, SIG_PIN_2)                    # a new key of the machine: the next copy is for it
        self.assertEqual(self.ask("seal", login=REF, machine="vps")["recipient"], R2)
        self.signed("unpin", UNPIN_3, SIG_UNPIN_3)
        self.assertIn("has not pinned", self.refused("seal", login=REF, machine="vps"))

    def test_seal_needs_the_owners_signed_grant_to_an_agent_of_that_machine_or_the_pool(self):
        """DevOps plan V1: a hub that is broken into can no longer have any value sealed to any pinned machine. The
        vault seals a secret only to a machine where the owner signed its grant to an agent, or when he signed it
        into the grantable pool, which the manager may hand to an agent on any machine."""
        self.intake()
        self.signed("pin", PIN_1, SIG_PIN_1)
        self.assertIn("has signed no grant of this secret", self.refused("seal", login=REF, machine="vps"))
        self.assertEqual(self.granted(grant(REF, "studio", "studio", T1)),      # another machine's agent
                         {"ok": True, "kind": "grant", "login": REF, "agent": "studio", "machine": "studio",
                          "saved": "new"})
        self.assertIn("has signed no grant of this secret", self.refused("seal", login=REF, machine="vps"))
        self.granted(grant(REF, "vps", "vps", T1))
        self.assertEqual(self.ask("seal", login=REF, machine="vps")["recipient"], R1)
        self.assertEqual(self.granted(grant(REF, "vps", None, T2, kind="ungrant")),
                         {"ok": True, "kind": "ungrant", "login": REF, "agent": "vps", "saved": "removed"})
        self.assertIn("has signed no grant of this secret", self.refused("seal", login=REF, machine="vps"))
        # an agent that moved: its grant names its old machine until the owner signs the new one
        self.granted(grant(REF, "vps", "vps-2", T3))
        self.assertIn("has signed no grant of this secret", self.refused("seal", login=REF, machine="vps"))
        self.assertEqual(self.granted(pooled(REF, T1)),
                         {"ok": True, "kind": "pool", "login": REF, "saved": "new"})
        self.assertEqual(self.ask("seal", login=REF, machine="vps")["recipient"], R1)
        self.granted(pooled(REF, T2, kind="unpool"))
        self.assertIn("has signed no grant of this secret", self.refused("seal", login=REF, machine="vps"))
        status = self.ask("status")
        self.assertEqual((status["grants"], status["pool"]),
                         ([{"login": REF, "agent": "studio", "machine": "studio"},
                           {"login": REF, "agent": "vps", "machine": "vps-2"}], []))

    def test_a_signed_grant_is_kept_until_a_newer_statement_and_never_taken_from_the_hub_alone(self):
        statement = grant(REF, "vps", "vps", T2)
        self.assertEqual(self.granted(statement)["saved"], "new")
        self.assertEqual(self.granted(statement)["saved"], "same")                  # a retry
        self.assertIn("as new or newer", self.refused("grant", statement=grant(REF, "vps", "studio", T1),
                                                       signature=owner_sign(grant(REF, "vps", "studio", T1))))
        self.granted(grant(REF, "vps", None, T3, kind="ungrant"))
        old = grant(REF, "vps", "vps", T2)                                          # the hub sends the old one again
        self.assertIn("as new or newer", self.refused("grant", statement=old, signature=owner_sign(old)))
        self.assertEqual(self.state()["grants"], {REF: {"vps": {"machine": None, "at": T3}}})
        # Only the owner's key signs: the hub's own statement, or one of another fleet, is refused
        stranger = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
        newer = grant(REF, "vps", "vps", T3 + 60)
        self.assertIn("valid signature of the owner",
                      self.refused("grant", statement=newer, signature=owner_sign(newer, stranger)))
        other = grant(REF, "vps", "vps", T3 + 60, fleet=OTHER_FLEET)
        self.assertIn("for another fleet", self.refused("grant", statement=other, signature=owner_sign(other)))
        for bad in (grant(REF.upper().replace("BWS", "bws"), "vps", "vps", T3 + 60),
                    grant(REF, "VPS", "vps", T3 + 60), grant("sealed:4", "vps", "vps", T3 + 60),
                    canon({"v": 1, "kind": "grant", "fleet": FLEET, "login": REF, "agent": "vps", "at": T3 + 60}),
                    canon({"v": 1, "kind": "pool", "fleet": FLEET, "login": REF, "machine": "vps", "at": T3 + 60})):
            kind = json.loads(bad)["kind"]
            self.assertIn(f"not a valid {kind} statement", self.refused(kind, statement=bad,
                                                                           signature=owner_sign(bad)), bad)

    def test_a_sealed_copy_that_holds_a_value_in_plain_is_not_given(self):
        self.intake()
        self.signed("pin", PIN_1, SIG_PIN_1)
        self.granted(pooled(REF, T1))
        with patch.object(vault, "run", leaky_age(vault.run)):
            self.assertEqual(self.refused("seal", login=REF, machine="vps"),
                             "the sealed copy was not locked, so it is not given")

    # ---- inventory and export
    def test_the_inventory_names_the_references_and_nothing_else(self):
        self.assertEqual(self.ask("inventory"), {"ok": True, "logins": []})
        self.intake(value={"password": API_KEY}, ref=KEY_REF, title="OPENAI_API_KEY", item="api_key")
        self.intake()
        self.assertEqual(self.ask("inventory"), {"ok": True, "logins": sorted([REF, KEY_REF])})

    # ---- remove (Remove from Founderizer, 6 November 2026)
    def test_remove_takes_out_only_a_value_that_no_grant_or_pool_of_the_owner_names(self):
        """A removal needs no statement of the owner's, because it gives no value to anybody. But while his signed
        grant or pool names a secret, a hub that is broken into cannot take it away."""
        self.intake()
        self.intake(value={"password": API_KEY}, ref=KEY_REF, title="OPENAI_API_KEY", item="api_key")
        self.granted(grant(REF, "vps", "vps", T1))
        self.assertEqual(self.refused("remove", login=REF),
                         "a grant or the pool that the owner signed still names this login, so it is not removed")
        self.granted(grant(REF, "vps", None, T2, kind="ungrant"))
        self.granted(pooled(REF, T2))
        self.assertIn("still names this login", self.refused("remove", login=REF))
        self.assertEqual(sorted(self.items()), sorted([SID, KEY_SID]))         # a refusal removes nothing
        self.granted(pooled(REF, T3, kind="unpool"))
        self.assertEqual(self.ask("remove", login="bws://" + SID.upper()),
                         {"ok": True, "login": REF, "removed": "removed"})
        self.assertEqual(self.ask("inventory"), {"ok": True, "logins": [KEY_REF]})
        self.assertEqual(self.ask("status")["items"], 1)
        self.assertEqual(self.ask("remove", login=REF), {"ok": True, "login": REF, "removed": "absent"})   # asked again
        self.assertEqual(self.items()[KEY_SID]["value"], canon({"password": API_KEY}))     # the other value stays
        # A removed name takes no value again, not even the same one: else a hub that is broken into could remove a
        # value that nobody holds yet and put its own under the owner's name, for his next grant to send.
        for value in (LOGIN, dict(LOGIN, password="TheHubsOwnFakePassword-1")):
            self.assertEqual(self.refused("intake", **self.intake_fields(value=value)),
                             "this login was removed from the fleet, so no value is taken under its name again")
        self.assertEqual(set(self.state()["removed"]), {REF})
        self.assertEqual(self.intake(value={"password": API_KEY}, ref=KEY_REF, title="OPENAI_API_KEY",
                                     item="api_key")["saved"], "same")                    # another name: as before
        for bad in ({}, {"login": "sealed:4"}, {"login": 7}, {"login": REF + "\n"}, {"login": [REF]}):
            self.assertEqual(self.refused("remove", **bad), "a remove request needs a login", bad)
        self.assertEqual([line for line in self.logged if line.startswith("remove:")],
                         [f"remove: {REF} removed", f"remove: {REF} absent"])

    def test_a_removal_that_stops_halfway_still_keeps_the_name(self):
        """The name is kept before the value goes, so a store that cannot be written leaves the value and the name,
        and the next removal ends it."""
        self.intake()
        with patch.object(vault.LocalStore, "keep", side_effect=vault.Refused("the vault store could not be saved")):
            self.assertEqual(self.refused("remove", login=REF), "the vault store could not be saved")
        self.assertIn(SID, self.items())
        self.assertEqual(set(self.state()["removed"]), {REF})
        self.assertIn("removed from the fleet", self.refused("intake", **self.intake_fields()))
        self.assertEqual(self.ask("remove", login=REF)["removed"], "removed")
        self.assertEqual(self.ask("inventory"), {"ok": True, "logins": []})

    # ---- replace: a new value under a reference that the vault holds, only with the owner's signed statement
    def replace_fields(self, value, at, ref=REF, sign=owner_sign, said=None, **given):
        """An intake with the owner's replace statement about its own sealed copy, signed with the third owner key.
        said: fields of the statement that are other than the right ones."""
        fields = self.intake_fields(value=value, ref=ref, **given)
        statement = canon(dict({"v": 1, "kind": "replace", "fleet": FLEET, "login": ref, "at": at,
                                "sha256": hashlib.sha256(fields["ciphertext"].encode()).hexdigest()}, **(said or {})))
        return dict(fields, statement=statement, signature=sign(statement))

    def test_a_signed_replace_puts_the_new_value_in_the_place_of_the_old_one(self):
        self.intake()
        self.signed("pin", PIN_1, SIG_PIN_1)
        self.assertNotIn("values", self.state())        # until the first replace, a file that the old program reads
        new = dict(LOGIN, password="TheNewFakePassword-20261113")
        fields = self.replace_fields(new, T2)
        self.assertEqual(self.ask("intake", **fields),
                         {"ok": True, "login": REF, "saved": "replaced",
                          "fingerprints": sorted(registered(new), key=lambda x: (x["kind"], x["hash"], x["len"]))})
        item = self.items()[SID]
        self.assertEqual((item["value"], item["note"]), (canon(new), "taken from the owner"))
        self.assertEqual(len(self.items()), 1)                          # the same reference: no second item
        self.assertNotIn(LOGIN["password"], json.dumps(self.items()))   # the old value left the store
        self.assertNotIn(LOGIN["password"], Path(self.conf["store"]).read_text())
        self.assertEqual(self.state()["values"], {REF: {"sha256": json.loads(fields["statement"])["sha256"], "at": T2}})
        self.assertEqual(self.ask("intake", **fields)["saved"], "same")     # the same statement again: a retry
        # what the owner signed before stays: the pin, and a seal gives the new value
        self.granted(grant(REF, "vps", "vps", T2))
        sealed = self.ask("seal", login=REF, machine="vps")
        self.assertEqual(json.loads(self.opened(sealed["ciphertext"], R1)), new)
        # with a statement, a login that the store does not hold is saved as new
        key = {"password": API_KEY}
        self.assertEqual(self.ask("intake", **self.replace_fields(key, T2, ref=KEY_REF, title="OPENAI_API_KEY",
                                                                  item="api_key"))["saved"], "new")
        self.assertEqual([line for line in self.logged if line.startswith("intake:")][1:3],
                         [f"intake: {REF} replaced, with the owner's replace statement",
                          f"intake: {REF} same, with the owner's replace statement"])

    def test_a_replace_keeps_the_address_of_the_key_when_the_new_value_names_none(self):
        """The owner saved a key with the address of its service, and an agent's vault sends the key there for it
        (call_api). In Add secret the address is optional, so the new value of a replace often names none. The key
        changes; its address stays, or the agent that uses the key would have no place to send it to. The user name
        comes from the new value only (C11), so a replace by Add secret repairs a key that held a login's user name."""
        key = {"password": API_KEY, "url": "https://api.example.org", "username": "api-user"}
        self.intake(value=key, ref=KEY_REF, title="OPENAI_API_KEY", item="api_key")
        # only a replace keeps an address: the same key with no address and no statement is another value, refused
        self.assertIn("holds another value under this reference",
                      self.refused("intake", **self.intake_fields(value={"password": API_KEY}, ref=KEY_REF,
                                                                  title="OPENAI_API_KEY", item="api_key")))
        new = {"password": "sk-fake-only-the-new-20261113"}             # the form's address field was empty
        fields = self.replace_fields(new, T2, ref=KEY_REF, title="OPENAI_API_KEY", item="api_key")
        self.assertEqual(self.ask("intake", **fields)["saved"], "replaced")
        kept = {"password": new["password"], "url": "https://api.example.org", "username": ""}
        self.assertEqual(json.loads(self.items()[KEY_SID]["value"]), kept)
        self.assertFalse(vault.login_shaped(self.items()[KEY_SID]["value"]))   # a session can read this key again
        self.assertEqual(vault.check_login(self.items()[KEY_SID]["value"])["url"], "https://api.example.org")
        self.assertEqual(self.ask("intake", **fields)["saved"], "same")     # the same statement again: the same save
        self.assertEqual(json.loads(self.items()[KEY_SID]["value"]), kept)
        # the status names the checksum of the copy of the newest replace, and nothing of a value
        status = self.ask("status")
        self.assertEqual(status["values"], {KEY_REF: json.loads(fields["statement"])["sha256"]})
        self.assertNotIn(new["password"], json.dumps(status))
        # an address in the new value takes the place of the old one
        moved = {"password": "sk-fake-only-a-third-20261113", "url": "https://api2.example.org", "username": ""}
        self.assertEqual(self.ask("intake", **self.replace_fields(moved, T3, ref=KEY_REF, title="OPENAI_API_KEY",
                                                                  item="api_key"))["saved"], "replaced")
        self.assertEqual(json.loads(self.items()[KEY_SID]["value"]), moved)
        # a key that had no address gets none
        self.intake(value={"password": "sk-fake-only-no-address-1"}, ref=OTHER_REF, title="OTHER_API_KEY", item="api_key")
        self.ask("intake", **self.replace_fields({"password": "sk-fake-only-no-address-2"}, T2, ref=OTHER_REF,
                                                 title="OTHER_API_KEY", item="api_key"))
        self.assertEqual(json.loads(self.items()[OTHER_SID]["value"]), {"password": "sk-fake-only-no-address-2"})

    def test_a_replace_needs_the_owners_signature_about_this_login_and_this_very_copy(self):
        """Without the owner's own statement no value changes: the rule that keeps a hub that is broken into from
        putting its own value under a name that the owner gave."""
        self.intake()
        new = dict(LOGIN, password="TheNewFakePassword-20261113")
        good = self.replace_fields(new, T2)
        stranger = 0x1D0C0FFEE5EED0F7E57B1A5ED0D1E7C0A2B3C4D5E6F708192A3B4C5D6E7F8099       # no owner's key
        other_copy = self.replace_fields(new, T2, said={"sha256": hashlib.sha256(b"another copy").hexdigest()})
        cases = (
            (self.intake_fields(value=new), "holds another value under this reference"),          # no statement
            (self.replace_fields(new, T2, sign=lambda text: owner_sign(text, stranger)), "valid signature of the owner"),
            (dict(good, signature=owner_sign(good["statement"] + " ")), "valid signature of the owner"),
            (self.replace_fields(new, T2, said={"login": KEY_REF}), "the statement is about another login"),
            (other_copy, "the statement is about another copy than this one"),
            (dict(good, ciphertext=self.lock(CENTRAL_KEY, json.dumps(dict(new, password="TheHubsOwnValue-000001")))),
             "the statement is about another copy than this one"),         # the hub puts its own copy under his statement
            (self.replace_fields(new, T2, said={"fleet": OTHER_FLEET}), "the statement is for another fleet"),
            (self.replace_fields(new, T2, said={"kind": "pool"}), "not a valid replace statement"),
            (self.replace_fields(new, T2, said={"sha256": "0" * 63}), "not a valid replace statement"),
            (self.replace_fields(new, T2, said={"sha256": 5}), "not a valid replace statement"),
            (self.replace_fields(new, T2, said={"at": True}), "not a valid replace statement"),
            (self.replace_fields(new, T2, said={"machine": "vps"}), "not a valid replace statement"),
            ({k: v for k, v in good.items() if k != "signature"}, "needs its statement and its signature"),
            ({k: v for k, v in good.items() if k != "statement"}, "needs its statement and its signature"),
            (dict(good, statement=json.dumps(json.loads(good["statement"]))), "not in its canonical form"),
            (self.replace_fields(new, T2, prints=registered(LOGIN)), "does not match what the owner registered"))
        for fields, said in cases:
            with self.subTest(said=said):
                self.assertIn(said, self.refused("intake", **fields))
                self.assertEqual(self.items()[SID]["value"], canon(LOGIN))      # the old value is whole
                self.assertNotIn("values", self.state() if Path(self.conf["state"]).exists() else {})
        # a statement of another kind opens no other operation with a copy, and a grant is no replace
        self.assertIn("not a valid replace statement",
                      self.refused("intake", **dict(self.intake_fields(value=new), statement=grant(REF, "vps", "vps", T2),
                                                    signature=owner_sign(grant(REF, "vps", "vps", T2)))))
        self.assertIn("unknown operation", self.refused("replace", **good))
        # a name that remove took out takes no value, also with the owner's statement
        self.ask("remove", login=REF)
        self.assertIn("removed from the fleet", self.refused("intake", **self.replace_fields(new, T3)))

    def test_an_older_replace_cannot_come_back(self):
        """A hub can keep each copy and statement that passed it. The newest statement of a login wins: an older
        one, and another copy at the same time, change nothing."""
        self.intake()
        second, third = dict(LOGIN, password="SecondFakePassword-20261113"), dict(LOGIN, password="ThirdFakePassword-20261113")
        prints = registered(LOGIN) + registered(second) + registered(third)     # the hub gives each one registered
        early = self.replace_fields(second, T1, prints=prints)
        late = self.replace_fields(third, T2, prints=prints)
        self.assertEqual(self.ask("intake", **late)["saved"], "replaced")
        for fields in (early, self.replace_fields(second, T2, prints=prints)):   # older, and as old with another copy
            self.assertIn("as new or newer", self.refused("intake", **fields))
            self.assertEqual(self.items()[SID]["value"], canon(third))
        self.assertEqual(self.state()["values"][REF]["at"], T2)
        self.assertIn("holds another value", self.refused("intake", **self.intake_fields(prints=prints)))   # the first copy
        self.assertEqual(self.ask("intake", **self.replace_fields(second, T3, prints=prints))["saved"], "replaced")
        self.assertEqual(self.items()[SID]["value"], canon(second))

    def test_a_replace_that_stops_halfway_leaves_the_old_value_whole_and_the_same_statement_ends_it(self):
        self.intake()
        new = dict(LOGIN, password="TheNewFakePassword-20261113")
        prints = registered(LOGIN) + registered(new)
        fields = self.replace_fields(new, T2, prints=prints)
        # the state cannot be written: nothing changed at all
        with patch.object(vault, "keep_state", side_effect=vault.Refused("the central vault's state could not be saved, "
                                                                         "so nothing changed")):
            self.assertIn("state could not be saved", self.refused("intake", **fields))
        self.assertEqual(self.items()[SID]["value"], canon(LOGIN))
        self.assertFalse(Path(self.conf["state"]).exists())
        # the record is kept and then the store cannot be written: the old value is whole, and no older statement
        # is taken from here on
        with patch.object(vault.LocalStore, "keep", side_effect=vault.Refused("the vault store could not be saved")):
            self.assertEqual(self.refused("intake", **fields), "the vault store could not be saved")
        self.assertEqual(self.items()[SID]["value"], canon(LOGIN))
        self.assertNotIn(new["password"], json.dumps(self.items()))
        self.assertEqual(self.state()["values"][REF]["at"], T2)
        self.assertIn("as new or newer", self.refused("intake", **self.replace_fields(new, T1, prints=prints)))
        self.assertEqual(self.ask("intake", **fields)["saved"], "replaced")      # the same statement ends it
        self.assertEqual(self.items()[SID]["value"], canon(new))
        # a store that is not locked is not written: the old value stays
        newer = dict(LOGIN, password="NewerFakePassword-20261113")
        with patch.object(vault, "run", leaky_age(vault.run)):
            self.assertIn("was not locked", self.refused("intake", **self.replace_fields(
                newer, T3, prints=prints + registered(newer))))
        self.assertEqual(self.items()[SID]["value"], canon(new))

    def test_export_locks_the_stores_key_only_to_the_owners_recovery_key(self):
        self.intake()
        self.assertEqual(self.refused("export"), "the owner has not signed a recovery key, so nothing is exported")
        self.signed("recovery", RECOVERY_1, SIG_RECOVERY_1)
        backup = self.ask("export")
        self.assertEqual(set(backup), {"ok", "v", "made_at", "items", "store_recipient", "recovery", "store", "key"})
        self.assertEqual((backup["ok"], backup["v"], backup["items"], backup["store_recipient"], backup["recovery"]),
                         (True, 1, 1, STORE_KEY, RR))
        self.assertIsInstance(backup["made_at"], float)
        self.assertEqual(backup["store"], Path(self.conf["store"]).read_text())        # the file as it is on disk
        key = self.opened(backup["key"], RR)
        self.assertEqual(key, Path(self.conf["store_key"]).read_text())                # only the recovery key opens it
        for other in (R1, CENTRAL_KEY, STORE_KEY):
            self.assertIsNone(self.opened(backup["key"], other))
        text = json.dumps(backup)
        for secret in ("AGE-SECRET-KEY", LOGIN["password"], LOGIN["totp"]):
            self.assertNotIn(secret, text)
        # With that key the store opens: the backup needs nothing else of this machine.
        restored = self.dir / "restored.key"
        restored.write_text(key)
        r = subprocess.run([str(self.age), "-d", "-i", str(restored)], input=backup["store"], capture_output=True,
                           text=True, check=True)
        self.assertEqual(json.loads(r.stdout)["items"][SID]["value"], canon(LOGIN))

    def test_an_export_whose_key_is_not_locked_is_refused(self):
        self.signed("recovery", RECOVERY_1, SIG_RECOVERY_1)
        with patch.object(vault, "run", leaky_age(vault.run)):
            self.assertEqual(self.refused("export"), "the store's key was not locked, so nothing is exported")

    # ---- the socket, and what the log keeps
    def test_over_its_socket_the_vault_answers_the_hubs_user_and_takes_a_long_line(self):
        conf = dict(self.conf, hub_uid=os.getuid())             # here this process is the hub's user
        broker = vault.Broker(conf).open()
        threading.Thread(target=broker.serve, daemon=True).start()
        self.addCleanup(broker.close)
        status = call(conf["socket"], {"v": 2, "op": "status"})
        with open(vault.__file__, "rb") as f:
            self.assertEqual(status["source"], hashlib.sha256(f.read()).hexdigest())     # the running program
        self.assertEqual(status["store_recipient"], STORE_KEY)
        big = {"password": "sk-" + "x" * 7000}                  # a long key: its line is longer than a broker's 8192
        request = dict({"v": 2, "op": "intake"}, **self.intake_fields(value=big, ref=KEY_REF, title="BIG_API_KEY",
                                                                      item="api_key"))
        self.assertGreater(len(json.dumps(request)), 8192)
        self.assertEqual(call(conf["socket"], request), {"ok": True, "login": KEY_REF, "saved": "new",
                                                         "fingerprints": registered(big)})
        self.assertEqual(self.items()[KEY_SID]["value"], canon(big))
        other = vault.Broker(dict(self.conf, socket=str(self.dir / "o.sock"))).open()   # of another hub user
        threading.Thread(target=other.serve, daemon=True).start()
        self.addCleanup(other.close)
        self.assertEqual(call(str(self.dir / "o.sock"), {"v": 2, "op": "status"}),
                         {"ok": False, "v": 2, "error": "only the hub's user may ask the central vault"})

    def test_no_log_line_holds_a_value_a_key_or_a_statement(self):
        self.intake()
        self.signed("pin", PIN_1, SIG_PIN_1)
        self.granted(grant(REF, "vps", "vps", T1))
        self.signed("recovery", RECOVERY_1, SIG_RECOVERY_1)
        self.ask("seal", login=REF, machine="vps")
        self.ask("export")
        self.refused("pin", statement=PIN_STALE, signature=SIG_PIN_STALE)
        self.assertTrue(self.logged)
        for line in self.logged:
            for secret in (LOGIN["password"], LOGIN["totp"], "AGE-SECRET-KEY", R1, RR, FLEET, PIN_1, SIG_PIN_1):
                self.assertNotIn(secret, line)


class Withdrawals(unittest.TestCase):
    """withdraw on a machine's own broker (helper feature secret_withdrawals): the hub confirms one job and names the
    reference, and only an item that a deposit saved is removed."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="fw-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.dir.chmod(0o700)
        state = self.dir / "state"
        state.mkdir(mode=0o700)
        age = self.dir / "age"
        age.write_text(FAKE_AGE.format(python=sys.executable))
        age.chmod(0o755)
        for name, public in (("age.key", VPS_STORE), ("store.key", STORE_KEY)):
            (state / name).write_text(f"# public key: {public}\nAGE-SECRET-KEY-1FAKE\n")
            (state / name).chmod(0o600)
        store = state / "store.age"
        store.write_text(subprocess.run([str(age), "-a", "-r", STORE_KEY], input=EMPTY, capture_output=True,
                                        text=True, check=True).stdout)
        store.chmod(0o600)
        self.conf = {"hub": "http://100.80.1.2:8765", "worker_uid": os.getuid(), "age_key": str(state / "age.key"),
                     "socket": str(self.dir / "w.sock"), "age": str(age), "store": str(store),
                     "store_key": str(state / "store.key")}
        self.asked, self.answer = [], None

        def hub(conf, method, path, body=None):     # the hub's helper route, as the other half of Release 2 answers
            self.asked.append((conf.get("agent"), conf.get("agent_key"), method, path, body))
            return self.answer
        for p in (patch.object(vault, "hub", hub), patch.object(vault, "log", lambda text: None)):
            p.start()
            self.addCleanup(p.stop)

    def saved(self, sid, note):
        return vault.LocalStore(self.conf).put(sid, "OPENAI_API_KEY", canon({"password": API_KEY}), note)

    def confirms(self, ref, job=7):
        self.answer = (200, {"ok": True, "job": job, "kind": "withdraw", "login": ref})

    def withdraw(self, conf=None, **fields):
        request = dict({"v": 2, "op": "withdraw", "job": 7, "agent": "vps", "agent_key": AKEY}, **fields)
        return vault.handle(conf or self.conf, json.dumps(request), os.getuid())

    def refused(self, conf=None, **fields):
        with self.assertRaises(vault.Refused) as refused:
            self.withdraw(conf, **fields)
        return str(refused.exception)

    def test_a_machines_broker_says_that_it_takes_secrets_and_gives_them_back(self):
        status = vault.handle(self.conf, json.dumps({"v": 2, "op": "status"}), os.getuid())
        self.assertEqual((status["backend"], status["deposits"], status["withdrawals"]), ("store", True, True))
        self.assertNotIn("central", status)

    def test_a_delivered_secret_is_removed_and_then_is_absent(self):
        self.assertEqual(self.saved(KEY_SID, vault.DELIVERED), "new")
        self.saved(SID, vault.DELIVERED)                        # another delivered secret, which stays
        self.confirms(KEY_REF)
        self.assertEqual(self.withdraw(), {"ok": True, "v": 2, "withdrawal": 7, "login": KEY_REF, "removed": "removed"})
        self.assertEqual(self.asked, [("vps", AKEY, "POST", "/helper/vault/vps", {"job": 7, "kind": "withdraw"})])
        self.assertEqual(sorted(vault.LocalStore(self.conf).opened()), [SID])
        self.assertEqual(self.withdraw()["removed"], "absent")  # asked again, it ends the same way
        self.assertNotIn(API_KEY, Path(self.conf["store"]).read_text())

    def test_a_login_that_was_not_delivered_here_is_not_removed(self):
        for note in ("", "fleet-create:vps:5c2f9a10-7d41-4c88-9b55-0e3a1f6c2d90", "taken from the owner",
                     vault.DELIVERED + " "):
            sid = vault.LocalStore(self.conf).add("the owner's own", canon({"password": API_KEY}), note)
            self.confirms("bws://" + sid)
            self.assertEqual(self.refused(), "this login was not delivered here, so it is not removed")
            self.assertIn(sid, vault.LocalStore(self.conf).opened())

    def test_the_hub_must_confirm_this_withdrawal_and_name_a_valid_login(self):
        self.saved(KEY_SID, vault.DELIVERED)
        for answer, said in (((409, {"error": "no such withdrawal waits for this agent"}),
                              "the hub did not confirm this withdrawal: no such withdrawal waits for this agent"),
                             ((200, {"ok": True, "job": 8, "kind": "withdraw", "login": KEY_REF}),
                              "the hub did not confirm this withdrawal"),
                             ((200, {"ok": True, "job": 7, "kind": "deposit", "login": KEY_REF}),
                              "the hub did not confirm this withdrawal"),
                             ((200, {"ok": True, "job": 7, "kind": "withdraw", "login": "sealed:3"}),
                              "the hub named no valid login for this withdrawal")):
            self.answer = answer
            self.assertEqual(self.refused(), said)
        self.assertIn(KEY_SID, vault.LocalStore(self.conf).opened())

    def test_a_withdrawal_needs_its_caller_and_its_job(self):
        self.confirms(KEY_REF)
        line = json.dumps({"v": 2, "op": "withdraw", "job": 7})
        with self.assertRaises(vault.Refused) as refused:
            vault.handle(dict(self.conf, agent="vps"), line, os.getuid())
        self.assertEqual(str(refused.exception), "a withdrawal needs the caller fields")
        for job in (0, -1, True, "7", None):
            self.assertEqual(self.refused(job=job), "a withdrawal needs the number of its job")
        self.assertEqual(self.asked, [])

    def test_a_machines_broker_refuses_the_central_vaults_operations_as_unknown(self):
        for op in vault.CENTRAL_OPERATIONS:
            for caller in ({}, {"agent": "vps", "agent_key": AKEY}):
                line = json.dumps(dict({"v": 2, "op": op, "login": KEY_REF, "machine": "vps"}, **caller))
                with self.assertRaises(vault.Refused) as refused:
                    vault.handle(self.conf, line, os.getuid())
                self.assertEqual(str(refused.exception), "unknown operation", op)
        self.assertEqual(self.asked, [])


class Replacing(unittest.TestCase):
    """deposit on a machine's own broker, for a value that the owner replaced: the hub's answer for the delivery says
    `replaces`, and the broker puts the new value in the place of the one that an earlier delivery saved. Nothing in
    the helper's request can say it."""

    def setUp(self):
        Withdrawals.setUp(self)
        self.replaces, self.value, self.confirmed = True, {"password": "sk-fake-only-the-new-20261113"}, True

        def hub(conf, method, path, body=None):     # the hub's two helper routes of a delivery
            self.asked.append((path, body))
            if path.endswith("/fingerprints"):
                return (200, {"ok": True, "deposit": body["deposit"]}) if self.confirmed else \
                    (409, {"error": "this copy holds another value than the one the owner saved under this reference, "
                                    "so it is not kept"})
            copy = subprocess.run([self.conf["age"], "-a", "-r", VPS_STORE], input=json.dumps(self.value),
                                  capture_output=True, text=True, check=True).stdout
            return 200, dict({"ok": True, "job": body["job"], "kind": "deposit", "login": KEY_REF,
                              "title": "OPENAI_API_KEY", "item": "api_key", "ciphertext": copy, "fingerprint_salts": SALTS},
                             **({"replaces": True} if self.replaces else {}))
        p = patch.object(vault, "hub", hub)
        p.start()
        self.addCleanup(p.stop)

    saved = Withdrawals.saved

    def deposit(self, **fields):
        request = dict({"v": 2, "op": "deposit", "job": 9, "agent": "vps", "agent_key": AKEY}, **fields)
        return vault.handle(self.conf, json.dumps(request), os.getuid())

    def held(self):
        return json.loads(vault.LocalStore(self.conf).opened()[KEY_SID]["value"])

    def test_a_machines_broker_says_that_it_replaces(self):
        self.assertIs(vault.handle(self.conf, json.dumps({"v": 2, "op": "status"}), os.getuid())["replaces"], True)

    def test_a_delivery_that_the_hub_marks_so_replaces_the_delivered_value(self):
        self.assertEqual(self.saved(KEY_SID, vault.DELIVERED), "new")       # the old value, from an earlier delivery
        self.assertEqual(self.deposit(), {"ok": True, "v": 2, "deposit": 9, "login": KEY_REF, "saved": "replaced"})
        self.assertEqual(self.held(), self.value)
        self.assertEqual(len(vault.LocalStore(self.conf).opened()), 1)
        self.assertNotIn(API_KEY, json.dumps(vault.LocalStore(self.conf).opened()))     # the old value left the store
        self.assertEqual(self.deposit()["saved"], "same")                   # asked again, it ends the same way
        self.assertEqual(vault.LocalStore(self.conf).opened()[KEY_SID]["note"], vault.DELIVERED)

    def test_without_the_hubs_word_another_value_is_refused_as_before(self):
        self.saved(KEY_SID, vault.DELIVERED)
        self.replaces = False
        for request in ({}, {"replaces": True}, {"replace": True}):         # the helper's request cannot say it
            with self.assertRaises(vault.Refused) as refused:
                self.deposit(**request)
            self.assertIn("holds another value under this reference", str(refused.exception))
            self.assertEqual(self.held(), {"password": API_KEY})

    def test_a_delivery_replaces_only_what_a_delivery_saved(self):
        """A login that this vault made, or that the owner saved here himself, is not the hub's to change."""
        for note in ("", "fleet-create:vps:5c2f9a10-7d41-4c88-9b55-0e3a1f6c2d90", "taken from the owner"):
            vault.LocalStore(self.conf).remove(KEY_SID, note) if KEY_SID in vault.LocalStore(self.conf).opened() else None
            self.saved(KEY_SID, note)
            with self.assertRaises(vault.Refused) as refused:
                self.deposit()
            self.assertIn("did not come here from the owner's vault, so it is not replaced", str(refused.exception))
            self.assertEqual(self.held(), {"password": API_KEY})
            vault.LocalStore(self.conf).remove(KEY_SID, note)

    def test_a_replace_that_fails_leaves_the_old_value_whole(self):
        self.saved(KEY_SID, vault.DELIVERED)
        self.confirmed = False                      # the hub does not confirm the value: nothing is saved
        with self.assertRaises(vault.Refused):
            self.deposit()
        self.assertEqual(self.held(), {"password": API_KEY})
        self.confirmed = True
        with patch.object(vault.LocalStore, "keep", side_effect=vault.Refused("the vault store could not be saved")), \
                self.assertRaises(vault.Refused):
            self.deposit()
        self.assertEqual(self.held(), {"password": API_KEY})        # a store that cannot be written: the old one, whole
        with patch.object(vault, "run", leaky_age(vault.run)), self.assertRaises(vault.Refused):
            self.deposit()                                          # a store that is not locked is not written
        self.assertEqual(self.held(), {"password": API_KEY})
        self.assertEqual(self.deposit()["saved"], "replaced")
        self.assertEqual(self.held(), self.value)


class CentralSetup(unittest.TestCase):
    """What root runs to set the central vault up: store-init, the unit, and serve."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="fcs-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.dir.chmod(0o755)
        for name, text in (("age", FAKE_AGE), ("age-keygen", FAKE_KEYGEN)):
            (self.dir / name).write_text(text.format(python=sys.executable))
            (self.dir / name).chmod(0o755)
        self.state = self.dir / "state"                         # store-init makes it
        self.user = pwd.getpwuid(os.getuid()).pw_name

    def config(self, **changes):
        conf = dict({"central": True, "hub_uid": HUB_UID, "fleet": FLEET, "owner_keys": [OWNER_A],
                     "age": str(self.dir / "age"), "age_key": str(self.state / "age.key"),
                     "store": str(self.state / "store.age"), "store_key": str(self.state / "store.key"),
                     "socket": "/run/fleet-vault-central/vault.sock", "state": str(self.state / "central.json")},
                    **changes)
        path = self.dir / "vault.json"
        path.write_text(json.dumps(conf) + "\n")
        path.chmod(0o644)
        return str(path)

    def test_store_init_makes_the_vaults_key_its_store_key_and_an_empty_store_and_keeps_them(self):
        config = self.config()
        made = vault.store_init(config, self.user, keygen=str(self.dir / "age-keygen"))
        self.assertEqual(made["made"], ["folder", "key", "age_key", "store"])
        self.assertRegex(made["recipient"], vault.RECIPIENT)
        self.assertNotEqual(made["recipient"], made["public_key"])         # two keys, not one
        self.assertEqual(made["age_key"], str(self.state / "age.key"))
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        for name in ("age.key", "store.key", "store.age"):
            self.assertEqual(stat.S_IMODE((self.state / name).stat().st_mode), 0o600, name)
        status = vault.handle(vault.load_config(config), json.dumps({"v": 2, "op": "status"}), HUB_UID)
        self.assertEqual((status["recipient"], status["store_recipient"], status["items"], status["pins"]),
                         (made["recipient"], made["public_key"], 0, {}))
        before = [(self.state / name).read_text() for name in ("age.key", "store.key", "store.age")]
        again = vault.store_init(config, self.user, keygen="/nonexistent/age-keygen")
        self.assertEqual(again["made"], [])                     # nothing is replaced: a new key would lose every value
        self.assertEqual([(self.state / name).read_text() for name in ("age.key", "store.key", "store.age")], before)
        (self.state / "age.key").unlink()
        with self.assertRaises(SystemExit) as refused:
            vault.store_init(config, self.user, keygen="/nonexistent/age-keygen")
        self.assertIn("The central vault's key could not be made", str(refused.exception))

    def test_store_init_gives_a_central_store_to_the_central_vaults_user_when_none_is_named(self):
        """The unit runs the central vault as founderizer-vault, so a store-init that left out --user and gave the
        files to fleet-vault would leave a vault that reads none of them."""
        with patch.object(vault.pwd, "getpwnam", side_effect=KeyError) as asked, self.assertRaises(SystemExit):
            vault.store_init(self.config(), keygen=str(self.dir / "age-keygen"))
        self.assertEqual(asked.call_args[0][0], "founderizer-vault")
        machine = dict(json.loads(Path(self.config()).read_text()), hub="http://100.80.1.2:8765",
                       worker_uid=HUB_UID)
        for key in ("central", "hub_uid", "fleet", "owner_keys", "state"):
            machine.pop(key)
        (self.dir / "machine.json").write_text(json.dumps(machine))
        (self.dir / "machine.json").chmod(0o644)
        with patch.object(vault.pwd, "getpwnam", side_effect=KeyError) as asked, self.assertRaises(SystemExit):
            vault.store_init(str(self.dir / "machine.json"), keygen=str(self.dir / "age-keygen"))
        self.assertEqual(asked.call_args[0][0], "fleet-vault")          # a machine's broker: as before

    def test_store_init_keeps_every_key_of_the_central_vault_in_its_state_folder(self):
        for key in ("age_key", "state"):
            with self.assertRaises(SystemExit) as refused:
                vault.store_init(self.config(**{key: str(self.dir / "elsewhere")}), self.user,
                                 keygen=str(self.dir / "age-keygen"))
            self.assertIn("age_key and state must be in the central vault's state folder", str(refused.exception))
        self.assertFalse(self.state.exists())                   # refused before anything was made

    def test_the_unit_of_the_central_vault_has_every_hardening_line(self):
        config = self.config()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(vault.main(["unit", "--central", "--config", config, "--group", "fleet"]), 0)
        lines = out.getvalue().splitlines()
        for line in ("User=founderizer-vault", "Group=fleet",
                     f"ExecStart=/usr/bin/python3 /usr/local/lib/fleet-vault-central/vault.py serve --config {config}",
                     "RuntimeDirectory=fleet-vault-central", "RuntimeDirectoryMode=0750",
                     "StateDirectory=fleet-vault-central", "StateDirectoryMode=0700", "UMask=0077",
                     "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
                     "PrivateDevices=yes", "LimitCORE=0", "ProtectProc=invisible", "ProcSubset=pid",
                     "RestrictAddressFamilies=AF_UNIX", "IPAddressDeny=any", "Restart=on-failure",
                     "WantedBy=multi-user.target"):
            self.assertIn(line, lines)
        self.assertFalse([line for line in lines if "network" in line])          # it needs no network
        with contextlib.redirect_stdout(io.StringIO()):
            vault.main(["unit", "--central", "--config", config, "--group", "fleet", "--user", "founderizer-vault"])
            for wrong in (["unit", "--config", config, "--group", "fleet"],            # a central one needs --central
                          ["unit", "--central", "--config", config, "--group", "fleet", "--user", "fleet-vault"]):
                with self.assertRaises(SystemExit):
                    vault.main(wrong)
            machine = self.dir / "machine.json"
            machine.write_text(json.dumps({"hub": "http://100.80.1.2:8765"}))
            with self.assertRaises(SystemExit):                 # and a machine's broker gets no central unit
                vault.main(["unit", "--central", "--config", str(machine), "--group", "fleet"])

    def test_serve_runs_a_central_configuration(self):
        said, served = [], []

        class Stub:
            def __init__(self, conf):
                self.conf = conf

            def open(self):
                return self

            def serve(self):
                served.append(self.conf)
        program = self.dir / "vault.py"         # as root installs it: serve refuses a checkout in /tmp
        program.write_text("x")
        program.chmod(0o644)
        with patch.object(vault, "Broker", Stub), patch.object(vault, "log", said.append), \
                patch.object(vault, "__file__", str(program)):
            self.assertEqual(vault.main(["serve", "--config", self.config()]), 0)
        self.assertIs(served[0]["central"], True)
        self.assertEqual(said, ["central vault on /run/fleet-vault-central/vault.sock"])


if __name__ == "__main__":
    unittest.main()
