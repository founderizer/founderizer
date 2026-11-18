"""The cipher that seals the hub's Google file at rest (atrest.py): AEAD_CHACHA20_POLY1305 of RFC 8439.

The vectors below are the RFC's own (sections 2.3.2, 2.4.2, 2.5.2, 2.6.2, 2.8.2 and appendix A.5), taken from its text
by a program and not typed, so a wrong byte here is a wrong byte there. Where the `cryptography` package is installed,
a second implementation of the same cipher must give the same bytes for many lengths. No file, no network, no hub."""
import os
import struct
import unittest

import atrest

# RFC 8439, the hex of each dump, in its order
BLOCK_OUT = ("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2"
             "b5129cd1de164eb9cbd083e8a2503c4e")
SUNSCREEN = ("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a20496620492063"
             "6f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
             "637265656e20776f756c642062652069742e")
SUNSCREEN_CIPHER = ("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b357"
                    "1639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
                    "5af90bbf74a35be6b40b8eedf2785e42874d")
POLY_KEY = "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
POLY_MESSAGE = "43727970746f6772617068696320466f72756d2052657365617263682047726f7570"
POLY_TAG = "a8061dc1305136c6c22b8baf0c0127a9"
KEYGEN_OUT = "8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646"
AEAD_PLAIN = ("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a20496620492063"
              "6f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
              "637265656e20776f756c642062652069742e")
AEAD_AAD = "50515253c0c1c2c3c4c5c6c7"
AEAD_CIPHER = ("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b"
               "1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
               "3ff4def08e4b7a9de576d26586cec64b6116")
AEAD_TAG = "1ae10b594f09e26a7e902ecbd0600691"
A5_KEY = "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"
A5_CIPHER = ("64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0"
             "bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855"
             "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e9"
             "9040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a"
             "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130"
             "305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b")
A5_NONCE = "000000000102030405060708"
A5_AAD = "f33388860000000000004e91"
A5_TAG = "eead9d67890cbb22392336fea1851f38"
A5_PLAIN = ("496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f72206120"
            "6d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c6163"
            "65642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e"
            "20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d4472616674732061732072"
            "65666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e20617320"
            "2fe2809c776f726b20696e2070726f67726573732e2fe2809d")
RFC_KEY = bytes(range(32))                                   # 00:01:...:1f, of sections 2.3.2 and 2.4.2
AEAD_KEY = bytes(range(0x80, 0xA0))                          # 80:81:...:9f, of sections 2.6.2 and 2.8.2
AEAD_NONCE = bytes.fromhex("07000000") + bytes.fromhex("4041424344454647")     # the fixed part and the IV of 2.8.2

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError:          # a machine without the package runs the RFC's vectors only
    ChaCha20Poly1305 = None


class RFC8439(unittest.TestCase):
    def test_the_block_function(self):                                      # 2.3.2
        words = struct.unpack("<8I", RFC_KEY), struct.unpack("<3I", bytes.fromhex("000000090000004a00000000"))
        self.assertEqual(atrest._block(words[0], 1, words[1]).hex(), BLOCK_OUT)

    def test_the_cipher(self):                                              # 2.4.2
        nonce = bytes.fromhex("000000000000004a00000000")
        self.assertEqual(atrest.chacha20(RFC_KEY, 1, nonce, bytes.fromhex(SUNSCREEN)).hex(), SUNSCREEN_CIPHER)
        self.assertEqual(atrest.chacha20(RFC_KEY, 1, nonce, bytes.fromhex(SUNSCREEN_CIPHER)).hex(), SUNSCREEN)

    def test_poly1305(self):                                                # 2.5.2
        self.assertEqual(atrest.poly1305(bytes.fromhex(POLY_KEY), bytes.fromhex(POLY_MESSAGE)).hex(), POLY_TAG)

    def test_the_one_time_key(self):                                        # 2.6.2
        words = struct.unpack("<8I", AEAD_KEY), struct.unpack("<3I", bytes.fromhex("000000000001020304050607"))
        self.assertEqual(atrest._block(words[0], 0, words[1])[:32].hex(), KEYGEN_OUT)

    def test_the_aead(self):                                                # 2.8.2
        sealed = atrest.encrypt(AEAD_KEY, bytes.fromhex(AEAD_PLAIN), bytes.fromhex(AEAD_AAD), nonce=AEAD_NONCE)
        self.assertEqual(sealed.hex(), AEAD_NONCE.hex() + AEAD_CIPHER + AEAD_TAG)
        self.assertEqual(atrest.decrypt(AEAD_KEY, sealed, bytes.fromhex(AEAD_AAD)).hex(), AEAD_PLAIN)

    def test_the_decryption_of_appendix_a5(self):                           # A.5
        sealed = bytes.fromhex(A5_NONCE + A5_CIPHER + A5_TAG)
        self.assertEqual(atrest.decrypt(bytes.fromhex(A5_KEY), sealed, bytes.fromhex(A5_AAD)).hex(), A5_PLAIN)


class Sealing(unittest.TestCase):
    def test_a_changed_byte_another_key_or_other_associated_bytes_do_not_open(self):
        key, aad = atrest.new_key(), b"the file's header"
        sealed = atrest.encrypt(key, b'{"accounts": {}}', aad)
        for at in range(len(sealed)):                       # the nonce, the ciphertext and the tag, each byte
            changed = bytearray(sealed)
            changed[at] ^= 0x01
            with self.assertRaises(atrest.Unopened, msg=at):
                atrest.decrypt(key, bytes(changed), aad)
        for other in (atrest.new_key(), key[:-1] + bytes([key[-1] ^ 1])):
            with self.assertRaises(atrest.Unopened):
                atrest.decrypt(other, sealed, aad)
        for wrong in (b"", aad + b"!", aad[:-1]):
            with self.assertRaises(atrest.Unopened):
                atrest.decrypt(key, sealed, wrong)
        for short in (sealed[:-1], sealed[:atrest.NONCE_BYTES + atrest.TAG_BYTES - 1], b""):
            with self.assertRaises(atrest.Unopened):
                atrest.decrypt(key, short, aad)
        self.assertEqual(atrest.decrypt(key, sealed, aad), b'{"accounts": {}}')

    def test_each_sealing_draws_a_new_nonce_and_hides_the_text(self):
        key, plain = atrest.new_key(), b"1//refresh-token-of-an-example-account"
        first, second = atrest.encrypt(key, plain), atrest.encrypt(key, plain)
        self.assertNotEqual(first[:atrest.NONCE_BYTES], second[:atrest.NONCE_BYTES])
        self.assertNotEqual(first, second)
        for sealed in (first, second):
            self.assertNotIn(b"refresh", sealed)
            self.assertEqual(len(sealed), atrest.NONCE_BYTES + len(plain) + atrest.TAG_BYTES)
            self.assertEqual(atrest.decrypt(key, sealed), plain)

    def test_an_empty_text_and_texts_at_each_block_edge(self):
        key = atrest.new_key()
        for n in (0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 1000):
            plain = os.urandom(n)
            self.assertEqual(atrest.decrypt(key, atrest.encrypt(key, plain, b"x" * (n % 33)), b"x" * (n % 33)), plain)

    def test_a_key_and_a_nonce_have_their_lengths(self):
        for key in (b"", b"k" * 31, b"k" * 33, "k" * 32):
            with self.assertRaises(ValueError):
                atrest.encrypt(key, b"text")
        with self.assertRaises(ValueError):
            atrest.encrypt(atrest.new_key(), b"text", nonce=b"n" * 11)

    def test_a_key_id_names_a_key_and_opens_nothing(self):
        one, two = atrest.new_key(), atrest.new_key()
        self.assertNotEqual(one, two)
        self.assertEqual(len(one), atrest.KEY_BYTES)
        self.assertRegex(atrest.key_id(one), r"^[0-9a-f]{16}$")
        self.assertEqual(atrest.key_id(one), atrest.key_id(bytes(one)))
        self.assertNotEqual(atrest.key_id(one), atrest.key_id(two))
        self.assertNotIn(atrest.key_id(one), one.hex())


@unittest.skipIf(ChaCha20Poly1305 is None, "the cryptography package is not installed here")
class SecondImplementation(unittest.TestCase):
    def test_the_cryptography_package_gives_the_same_bytes(self):
        for n in (0, 1, 15, 16, 17, 63, 64, 65, 255, 256, 257, 4096, 10000):
            key, nonce, aad, plain = os.urandom(32), os.urandom(12), os.urandom(n % 50), os.urandom(n)
            theirs = ChaCha20Poly1305(key).encrypt(nonce, plain, aad)
            self.assertEqual(atrest.encrypt(key, plain, aad, nonce=nonce), nonce + theirs, n)
            self.assertEqual(atrest.decrypt(key, nonce + theirs, aad), plain, n)
            mine = atrest.encrypt(key, plain, aad)          # a nonce of its own: theirs opens it too
            self.assertEqual(ChaCha20Poly1305(key).decrypt(mine[:12], mine[12:], aad), plain, n)


if __name__ == "__main__":
    unittest.main()
