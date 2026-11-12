"""pins.py makes the pin of a program that the fleet downloads by itself (onboard.PINNED, the AI providers build spec,
section 3.9). These tests hold it to the rules of a pin, against a stand-in for npm's registry and for a vendor's store
on a local address: no outside call, no real program and no `brotli` (a stand-in opens the packed copy).
"""
import base64
import datetime
import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import threading
import unittest
import urllib.parse
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import fleet
import lifecycle
import onboard
import pins

NOW = datetime.datetime(2026, 11, 12, 8, 0, tzinfo=datetime.timezone.utc)
OLD, YOUNG = "2026-11-01T08:00:00.000Z", "2026-11-05T08:00:01.000Z"        # 11 days, and one second less than 7
UNPACK = [sys.executable, "-c", "import sys, zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))"]


def program(machine=183, text=b"a program"):
    """A file with the header of a Linux program for one processor (183: arm64, 62: x64)."""
    return b"\x7fELF\x02\x01\x01" + bytes(9) + (2).to_bytes(2, "little") + machine.to_bytes(2, "little") + text


def tgz(files):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for name, data in files.items():
            item = tarfile.TarInfo(name)
            item.size = len(data)
            tar.addfile(item, io.BytesIO(data))
    return out.getvalue()


class Store(ThreadingHTTPServer):
    """npm's registry and a vendor's store on one local address. files: {path: bytes}; calls: (path, client name)."""
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Answer)
        self.files, self.calls, self.short = {}, [], set()
        threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"

    def package(self, name, versions, latest):
        """npm's record of a package: {version: (its time, its file or None)}. The file's address."""
        record = {"name": name, "dist-tags": {"latest": latest}, "time": {}, "versions": {}}
        for version, (when, data) in versions.items():
            path = f"/{name}/-/{name.split('/')[-1]}-{version}.tgz"
            record["time"][version] = when
            record["versions"][version] = {"dist": {
                "tarball": self.url + path,
                "integrity": "sha512-" + base64.b64encode(hashlib.sha512(data or b"").digest()).decode()}}
            if data is not None:
                self.files[path] = data
        self.files["/" + urllib.parse.quote(name, safe="@")] = json.dumps(record).encode()
        return record


class Answer(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.calls.append((self.path, self.headers.get("User-Agent")))
        data = self.server.files.get(self.path)
        self.send_response(200 if data is not None else 404)
        self.send_header("Content-Length", str(len(data or b"") + (10 if self.path in self.server.short else 0)))
        self.end_headers()
        self.wfile.write(data or b"")


class Pins(unittest.TestCase):
    def setUp(self):
        self.store = Store()
        self.addCleanup(self.store.server_close)
        self.addCleanup(self.store.shutdown)
        self.folder = Path(tempfile.mkdtemp(prefix="fleet-pins-"))
        self.addCleanup(shutil.rmtree, str(self.folder), True)
        programs = {
            "tool": {"npm": "@maker/tool", "bin": "tool", "files": {
                "linux-arm64": {"npm": "@maker/tool-linux-arm64", "member": "package/bin/tool"}}},
            "craft": {"npm": "@maker/craft", "bin": "craft", "files": {
                "linux-x64": {"npm": "@maker/craft-linux-x64", "packed": "package/bin/craft.br", "urls": [
                    self.store.url + "/store/craft-{version}-linux-x86_64",
                    self.store.url + "/mirror/craft-{version}-linux-x86_64"]}}}}
        for one in (patch.object(pins, "NPM", self.store.url), patch.object(pins, "PROGRAMS", programs),
                    patch.object(pins, "BROTLI", UNPACK)):
            one.start()
            self.addCleanup(one.stop)
        # tool 2.0.0, as npm holds it: the program is a member of the platform package's file
        self.tool = program(183, b"the tool")
        self.tool_file = tgz({"package/package.json": b"{}", "package/bin/tool": self.tool})
        self.store.package("@maker/tool", {"2.0.0": (OLD, None)}, "2.0.0")
        self.store.package("@maker/tool-linux-arm64", {"2.0.0": (OLD, self.tool_file)}, "2.0.0")
        # craft 1.0.77, as its vendor's store holds it at two addresses, and npm's packed copy of it
        self.craft = program(62, b"the craft" * 1000)
        self.packed = tgz({"package/bin/craft.br": zlib.compress(self.craft)})
        self.store.package("@maker/craft", {"1.0.77": (OLD, None)}, "1.0.77")
        self.store.package("@maker/craft-linux-x64", {"1.0.77": (OLD, self.packed)}, "1.0.77")
        for place in ("store", "mirror"):
            self.store.files[f"/{place}/craft-1.0.77-linux-x86_64"] = self.craft

    def refused(self, *args, **kwargs):
        with self.assertRaises(pins.Refused) as refused:
            pins.pin(*args, now=NOW, **kwargs)
        return str(refused.exception)

    def downloads(self):
        return [path for path, _ in self.store.calls if path.endswith(".tgz") or "/craft-" in path]

    def test_a_file_of_npm_is_pinned_by_npms_own_digest_and_its_program_is_the_member(self):
        kept = self.folder / "tool"
        entry, report = pins.pin("tool", "2.0.0", {"linux-arm64": str(kept)}, now=NOW)
        address = f"{self.store.url}/@maker/tool-linux-arm64/-/tool-linux-arm64-2.0.0.tgz"
        self.assertEqual(entry, {"version": "2.0.0", "published": "2026-11-01", "bin": "tool", "files": {
            "linux-arm64": {"urls": [address], "sha512": hashlib.sha512(self.tool_file).hexdigest(),
                            "member": "package/bin/tool"}}})
        self.assertEqual(kept.read_bytes(), self.tool)                  # the member, not the .tgz
        self.assertEqual(kept.stat().st_mode & 0o777, 0o755)
        self.assertEqual(os.listdir(self.folder), ["tool"])             # and no .part file beside it
        said = report["files"]["linux-arm64"]
        self.assertEqual(said["program"], {"bytes": len(self.tool), "sha512": hashlib.sha512(self.tool).hexdigest(),
                                           "member": "package/bin/tool", "kept": str(kept)})
        self.assertEqual(said["downloads"], [{"url": address, "status": 200, "bytes": len(self.tool_file),
                                              "sha512": hashlib.sha512(self.tool_file).hexdigest()}])
        self.assertEqual(report["npm"]["age_days"], 11.0)
        self.assertEqual(report["entry"], entry)

    def test_a_file_of_the_vendors_store_is_pinned_by_its_own_digest_and_must_be_npms_program(self):
        entry, report = pins.pin("craft", "1.0.77", now=NOW)
        urls = [f"{self.store.url}/{place}/craft-1.0.77-linux-x86_64" for place in ("store", "mirror")]
        npm = f"{self.store.url}/@maker/craft-linux-x64/-/craft-linux-x64-1.0.77.tgz"
        # the digest of the file that the helper downloads: never the digest of npm's packed copy of it, which the
        # entry keeps beside it, as npm's own record gives it
        self.assertEqual(entry["files"], {"linux-x64": {
            "urls": urls, "member": None, "sha512": hashlib.sha512(self.craft).hexdigest(),
            "packed": {"url": npm, "sha512": hashlib.sha512(self.packed).hexdigest(),
                       "member": "package/bin/craft.br"}}})
        said = report["files"]["linux-x64"]
        self.assertIs(said["same_as_npm"], True)
        self.assertEqual([d["url"] for d in said["downloads"]], urls + [npm])
        self.assertEqual({d["sha512"] for d in said["downloads"][:2]}, {hashlib.sha512(self.craft).hexdigest()})
        self.assertEqual(said["downloads"][2]["sha512"], said["npm"]["integrity_sha512"])
        self.assertEqual(entry["files"]["linux-x64"]["packed"]["sha512"], said["npm"]["integrity_sha512"])

    def test_two_addresses_with_different_files_are_refused(self):
        self.store.files["/mirror/craft-1.0.77-linux-x86_64"] = self.craft + b"!"
        self.assertIn("/mirror/craft-1.0.77-linux-x86_64 gives another file", self.refused("craft", "1.0.77"))

    def test_a_store_file_that_is_not_npms_program_is_refused_and_nothing_is_kept(self):
        other = program(62, b"another build")
        for place in ("store", "mirror"):
            self.store.files[f"/{place}/craft-1.0.77-linux-x86_64"] = other
        kept = self.folder / "craft"
        self.assertIn("is not the program that npm holds as package/bin/craft.br of @maker/craft-linux-x64 1.0.77",
                      self.refused("craft", "1.0.77", {"linux-x64": str(kept)}))
        self.assertEqual(os.listdir(self.folder), [])

    def test_a_machine_without_brotli_makes_no_pin_of_a_store_file_and_calls_no_address(self):
        """Two addresses of one store are one source. Without npm's packed copy the file's age is not proved, so
        such a pin is not made at all: it would be the file that the store gave on the day of the pin."""
        with patch.object(pins, "BROTLI", ["no-such-program-of-the-fleet-tests", "-d"]):
            said = self.refused("craft", "1.0.77", {"linux-x64": str(self.folder / "craft")})
            self.assertEqual(self.store.calls, [])
            # a file of npm needs no such program: npm's own digest holds it
            self.assertEqual(pins.pin("tool", "2.0.0", now=NOW)[0]["version"], "2.0.0")
        self.assertIn("this machine has no `no-such-program-of-the-fleet-tests` program", said)
        self.assertIn("its age is not proved", said)
        self.assertEqual(os.listdir(self.folder), [])

    def test_a_packed_copy_that_differs_from_npms_digest_is_refused_and_nothing_is_kept(self):
        path = "/@maker/craft-linux-x64/-/craft-linux-x64-1.0.77.tgz"
        self.store.files[path] = tgz({"package/bin/craft.br": zlib.compress(self.craft), "package/more": b"added"})
        self.assertIn(f"the download of {self.store.url}{path} does not match npm's own digest of it",
                      self.refused("craft", "1.0.77", {"linux-x64": str(self.folder / "craft")}))
        self.assertEqual(os.listdir(self.folder), [])

    def test_a_brotli_that_ends_with_an_error_is_refused_also_when_its_bytes_are_right(self):
        failing = [sys.executable, "-c", "import sys, zlib; "
                   "sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read())); sys.exit(1)"]
        with patch.object(pins, "BROTLI", failing):
            self.assertIn(f"{sys.executable} could not open npm's packed copy",
                          self.refused("craft", "1.0.77", {"linux-x64": str(self.folder / "craft")}))
        self.assertEqual(os.listdir(self.folder), [])

    def test_a_file_that_holds_its_member_two_times_is_refused(self):
        """This reads the item of the member's name, and a program that unpacks the file keeps the last item of a
        place: with a later one, the pin and an install from npm would hold two different programs. npm unpacks an
        item without the first part of its path, whatever that part is."""
        def packed(*items):
            out = io.BytesIO()
            with tarfile.open(fileobj=out, mode="w:gz") as tar:
                for name, data in items:
                    item = tarfile.TarInfo(name)
                    item.size = len(data)
                    tar.addfile(item, io.BytesIO(data))
            return out.getvalue()
        other = program(183, b"another")
        for name in ("./package/bin/tool", "other/bin/tool", "/package/bin/tool", "package/./bin/tool"):
            with self.subTest(name):
                file = packed(("package/bin/tool", self.tool), (name, other))
                self.store.package("@maker/tool-linux-arm64", {"2.0.0": (OLD, file)}, "2.0.0")
                self.assertIn("npm's file holds package/bin/tool two times",
                              self.refused("tool", "2.0.0", {"linux-arm64": str(self.folder / "tool")}))
                self.assertEqual(os.listdir(self.folder), [])
        # an item of another first part alone is not the member, and one that comes before the member changes nothing:
        # the last one of the place is the member itself
        self.store.package("@maker/tool-linux-arm64", {"2.0.0": (OLD, packed(("other/bin/tool", self.tool)))}, "2.0.0")
        self.assertIn("npm's file has no package/bin/tool", self.refused("tool", "2.0.0"))
        file = packed(("other/bin/tool", other), ("package/bin/tool", self.tool))
        self.store.package("@maker/tool-linux-arm64", {"2.0.0": (OLD, file)}, "2.0.0")
        kept = self.folder / "tool"
        pins.pin("tool", "2.0.0", {"linux-arm64": str(kept)}, now=NOW)
        self.assertEqual(kept.read_bytes(), self.tool)

    def test_an_address_of_npms_record_with_a_character_that_no_address_has_is_refused(self):
        for odd in ("\U0001f600", " ", "\n"):
            with self.subTest(repr(odd)):
                record = self.store.package("@maker/tool-linux-arm64", {"2.0.0": (OLD, self.tool_file)}, "2.0.0")
                record["versions"]["2.0.0"]["dist"]["tarball"] += odd
                self.store.files["/" + urllib.parse.quote(record["name"], safe="@")] = json.dumps(record).encode()
                self.assertIn("names a file with a character that no address has", self.refused("tool", "2.0.0"))
                self.assertEqual(self.downloads(), [])

    def test_a_packed_copy_without_its_member_is_refused(self):
        other = tgz({"package/bin/other.br": zlib.compress(self.craft)})
        self.store.package("@maker/craft-linux-x64", {"1.0.77": (OLD, other)}, "1.0.77")
        self.assertIn("npm's file has no package/bin/craft.br", self.refused("craft", "1.0.77"))

    def test_a_version_younger_than_the_npm_rule_is_refused_before_any_download(self):
        self.store.package("@maker/tool", {"2.0.0": (OLD, None), "2.0.1": (YOUNG, None)}, "2.0.1")
        self.store.package("@maker/tool-linux-arm64", {"2.0.0": (OLD, self.tool_file), "2.0.1": (OLD, self.tool_file)},
                           "2.0.1")
        said = self.refused("tool", "2.0.1")
        self.assertEqual(said, f"npm published @maker/tool 2.0.1 7.0 days ago, and a pin is at least "
                               f"{lifecycle.NPM_DAYS} days old (lifecycle.NPM_DAYS)")
        self.assertEqual(self.downloads(), [])

    def test_the_rule_holds_for_the_package_of_each_file_and_takes_a_version_of_exactly_that_age(self):
        self.store.package("@maker/tool-linux-arm64", {"2.0.0": (YOUNG, self.tool_file)}, "2.0.0")
        self.assertIn("npm published @maker/tool-linux-arm64 2.0.0 7.0 days ago", self.refused("tool", "2.0.0"))
        self.assertEqual(self.downloads(), [])
        exactly = (NOW - datetime.timedelta(days=lifecycle.NPM_DAYS)).isoformat().replace("+00:00", "Z")
        self.store.package("@maker/tool-linux-arm64", {"2.0.0": (exactly, self.tool_file)}, "2.0.0")
        self.assertEqual(pins.pin("tool", "2.0.0", now=NOW)[0]["version"], "2.0.0")

    def test_a_build_of_another_channel_or_with_another_kind_of_name_is_no_pin(self):
        self.store.package("@maker/tool", {"2.0.0": (OLD, None), "2.0.3": (OLD, None)}, "2.0.0")
        self.assertEqual(self.refused("tool", "2.0.3"),
                         "npm's latest @maker/tool is 2.0.0: 2.0.3 is a build of another channel")
        self.assertEqual(self.refused("tool", "0.0.0-dev-1229"), "0.0.0-dev-1229 is no released version")
        self.assertEqual(self.refused("tool", "1.9.9"), "npm has no version 1.9.9 of @maker/tool")
        self.assertEqual(self.downloads(), [])

    def test_the_newest_pin_is_old_enough_and_not_above_latest(self):
        record = self.store.package("@maker/tool", {"1.9.0": (OLD, None), "2.0.0": (OLD, None), "2.0.1": (YOUNG, None),
                                                    "2.0.10": (OLD, None), "0.0.0-dev-7": (OLD, None)}, "2.0.1")
        self.assertEqual(pins.newest(record, NOW), "2.0.0")     # 2.0.1 is young, 2.0.10 is of another channel
        record["dist-tags"]["latest"] = "2.0.10"
        self.assertEqual(pins.newest(record, NOW), "2.0.10")    # by the numbers, not by the letters
        self.assertIsNone(pins.newest(self.store.package("@maker/tool", {"3.0.0": (YOUNG, None)}, "3.0.0"), NOW))

    def test_a_file_that_differs_from_npms_digest_is_refused_and_nothing_is_kept(self):
        path = "/@maker/tool-linux-arm64/-/tool-linux-arm64-2.0.0.tgz"
        self.store.files[path] = tgz({"package/bin/tool": program(183, b"not the tool that npm published")})
        self.assertIn("does not match npm's own digest of it", self.refused("tool", "2.0.0",
                                                                           {"linux-arm64": str(self.folder / "tool")}))
        self.assertEqual(os.listdir(self.folder), [])

    def test_a_file_without_its_member_or_for_another_processor_is_refused(self):
        for files, why in (({"package/bin/other": self.tool}, "npm's file has no package/bin/tool"),
                           ({"package/bin/tool": program(62)}, "is no Linux program for that processor"),
                           ({"package/bin/tool": b"#!/bin/sh\necho a script\n"}, "is no Linux program for that")):
            with self.subTest(why):
                self.store.package("@maker/tool-linux-arm64", {"2.0.0": (OLD, tgz(files))}, "2.0.0")
                self.assertIn(why, self.refused("tool", "2.0.0", {"linux-arm64": str(self.folder / "tool")}))
                self.assertEqual(os.listdir(self.folder), [])

    def test_a_download_that_ends_early_is_refused(self):
        self.store.short.add("/store/craft-1.0.77-linux-x86_64")
        self.assertIn("/store/craft-1.0.77-linux-x86_64 ended after", self.refused("craft", "1.0.77"))

    def test_an_address_that_does_not_answer_200_is_refused_with_its_code(self):
        del self.store.files["/mirror/craft-1.0.77-linux-x86_64"]
        self.assertEqual(self.refused("craft", "1.0.77"),
                         f"{self.store.url}/mirror/craft-1.0.77-linux-x86_64 answered 404")

    def test_each_call_carries_the_helpers_own_client_name(self):
        pins.pin("tool", "2.0.0", now=NOW)
        pins.pin("craft", "1.0.77", now=NOW)
        self.assertEqual({client for _, client in self.store.calls}, {fleet.OUTSIDE_AGENT})
        self.assertEqual(len(self.store.calls), 3 + 5)        # two records and a file; two records and three files

    def test_the_command_prints_the_entry_or_the_reason_and_lists_what_can_be_a_pin(self):
        out, err = io.StringIO(), io.StringIO()
        with patch("sys.stdout", out), patch("sys.stderr", err):
            self.assertEqual(pins.main(["tool", "2.0.0"]), 0)
            self.assertEqual(pins.main(["tool", "1.9.9"]), 1)
            self.assertEqual(pins.main(["tool"]), 0)
            self.assertEqual(pins.main(["tool", "2.0.0", "--keep", "nowhere"]), 1)
        entry = pins.pin("tool", "2.0.0", now=NOW)[0]
        self.assertEqual(out.getvalue(), pins.entry_text("tool", entry) + "\n" +
                         "tool: npm's latest @maker/tool is 2.0.0; the newest version that can be a pin is 2.0.0, "
                         "published 2026-11-01 08:00 UTC\n")
        self.assertIn("pins.py: npm has no version 1.9.9 of @maker/tool\n", err.getvalue())
        self.assertIn("pins.py: --keep takes PLATFORM=PATH\n", err.getvalue())
        # what it prints is the entry itself, as Python reads it: also the one with npm's packed copy in it
        self.assertEqual(eval("{" + pins.entry_text("tool", entry) + "}"), {"tool": entry})     # noqa: S307
        craft = pins.pin("craft", "1.0.77", now=NOW)[0]
        self.assertIn("packed", craft["files"]["linux-x64"])
        self.assertEqual(eval("{" + pins.entry_text("craft", craft) + "}"), {"craft": craft})   # noqa: S307


class Pinned(unittest.TestCase):
    """onboard.PINNED holds what this tool prints, for the programs and the platforms that the tool knows."""

    def test_each_entry_is_of_the_shape_that_the_tool_prints_and_onboard_holds_its_own_lines(self):
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "onboard.py"), encoding="utf-8") as f:
            source = f.read()
        self.assertEqual(set(onboard.PINNED), set(pins.PROGRAMS))
        for name, entry in onboard.PINNED.items():
            with self.subTest(name):
                made = pins.PROGRAMS[name]
                self.assertEqual(set(entry), {"version", "published", "bin", "files"})
                self.assertTrue(pins.RELEASED.fullmatch(entry["version"]), entry["version"])
                datetime.date.fromisoformat(entry["published"])
                self.assertEqual(entry["bin"], made["bin"])
                self.assertEqual(set(entry["files"]), set(made["files"]))
                self.assertLessEqual({"linux-x64", "linux-arm64"}, set(entry["files"]))
                for platform, file in entry["files"].items():
                    maker = made["files"][platform]
                    self.assertEqual(set(file), {"urls", "sha512", "member"} | ({"packed"} if "packed" in maker
                                                                                else set()))
                    self.assertRegex(file["sha512"], r"\A[0-9a-f]{128}\Z")
                    package = maker["npm"]
                    npm = f"{pins.NPM}/{package}/-/{package.split('/')[-1]}-{entry['version']}.tgz"
                    self.assertEqual(file["member"], maker.get("member"))
                    self.assertEqual(file["urls"], [url.format(version=entry["version"])
                                                    for url in maker.get("urls", [])] or [npm])
                    self.assertTrue(all(url.startswith("https://") for url in file["urls"]))
                    if "packed" in maker:
                        # a file of a vendor's store names npm's own file of that version, with npm's digest of it
                        self.assertEqual(set(file["packed"]), {"url", "sha512", "member"})
                        self.assertEqual((file["packed"]["url"], file["packed"]["member"]), (npm, maker["packed"]))
                        self.assertRegex(file["packed"]["sha512"], r"\A[0-9a-f]{128}\Z")
                        self.assertNotEqual(file["packed"]["sha512"], file["sha512"])
                self.assertIn(pins.entry_text(name, entry), source)
                self.assertNotIn(name, onboard.RUNTIME_PINS)        # one kind of pin for one program


if __name__ == "__main__":
    unittest.main()
