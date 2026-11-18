#!/usr/bin/env python3
"""The GitHub CLI of the task sessions (fleet.ensure_gh, 10 November 2026): the helper puts the pinned gh in
~/.local/bin of its own OS user, from GitHub's release archive, held to the archive's SHA-256 and to its program's,
with no root. Temporary folders, archives and stand-in programs made here only: no download, no real ~/.local/bin,
no hub."""
import hashlib
import inspect
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import types
import unittest
import zipfile
from unittest.mock import patch

import fleet

PROGRAM = b"#!/bin/sh\necho 'gh version test'\n"
PINNED = dict(fleet.GH_BUILDS)          # the real pins, before a test puts its own archive's in their place


def sha(data):
    return hashlib.sha256(data).hexdigest()


def tar_gz(members):
    """A .tar.gz of (name, bytes) members; bytes None makes a link to /bin/true in its place."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as t:
        for name, data in members:
            info = tarfile.TarInfo(name)
            if data is None:
                info.type, info.linkname = tarfile.SYMTYPE, "/bin/true"
                t.addfile(info)
            else:
                info.size, info.mode = len(data), 0o755
                t.addfile(info, io.BytesIO(data))
    return out.getvalue()


def zipped(members):
    """A .zip of (name, bytes) members, each with the mode of a program, as GitHub's macOS archives are."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for name, data in members:
            info = zipfile.ZipInfo(name)
            info.external_attr = 0o100755 << 16
            z.writestr(info, data)
    return out.getvalue()


def a_gh(folder, version):
    """A stand-in gh in folder, marked with that version, so that a test can see that it was not changed."""
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, "gh")
    with open(path, "w") as f:
        f.write(f"#!/bin/sh\necho 'gh version {version} (2026-10-26)'\necho 'https://github.com/cli/cli/releases'\n")
    os.chmod(path, 0o755)
    return path


class GitHubCLI(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="fleet-gh-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.home, self.empty = os.path.join(self.root, "home"), os.path.join(self.root, "empty")
        os.makedirs(self.home)
        os.makedirs(self.empty)
        self.bin = os.path.join(self.home, ".local", "bin")
        self.target = os.path.join(self.bin, "gh")
        self.system("Linux", "x86_64")
        self.name = f"gh_{fleet.GH_VERSION}_linux_amd64"
        self.archive = tar_gz([(f"{self.name}/LICENSE", b"MIT"), (f"{self.name}/bin/gh", PROGRAM)])
        self.pin(self.archive)
        for one in (patch.dict(os.environ, {"HOME": self.home, "PATH": f"{self.bin}:{self.empty}"}),
                    patch.object(fleet, "HOME", os.path.join(self.home, ".fleet"))):
            one.start()
            self.addCleanup(one.stop)
        self.fetched = []

    def system(self, sysname, machine):
        uname = patch.object(fleet.os, "uname", lambda: types.SimpleNamespace(sysname=sysname, machine=machine))
        uname.start()
        self.addCleanup(uname.stop)

    def pin(self, archive, program=PROGRAM, kind="tar.gz", platform="linux_amd64"):
        builds = patch.dict(fleet.GH_BUILDS, {platform: (kind, sha(archive), sha(program))})
        builds.start()
        self.addCleanup(builds.stop)

    def fetch(self, data, pause=0.0):
        def opener(request, timeout=None):
            self.fetched.append((request.full_url, request.get_header("User-agent"), timeout))
            time.sleep(pause)
            return io.BytesIO(data)
        return opener

    def leftovers(self):
        return sorted(n for n in os.listdir(self.bin) if n.startswith(".gh.")) if os.path.isdir(self.bin) else []

    def installed(self):
        with open(self.target, "rb") as f:
            return f.read() == PROGRAM

    def test_the_pinned_gh_is_put_in_local_bin_once_with_no_root(self):
        mask = os.umask(0o077)                  # a strict umask still leaves the program runnable by its own user
        try:
            self.assertEqual(fleet.ensure_gh(self.fetch(self.archive)), "installed")
        finally:
            os.umask(mask)
        self.assertTrue(self.installed())
        self.assertEqual(os.stat(self.target).st_mode & 0o777, 0o755)
        self.assertEqual(self.fetched, [(f"https://github.com/cli/cli/releases/download/v{fleet.GH_VERSION}/"
                                         f"{self.name}.tar.gz", fleet.OUTSIDE_AGENT, 60)])
        self.assertEqual(sorted(os.listdir(self.bin)), ["gh"])  # nothing of the download, nothing else of the archive
        self.assertEqual(fleet.ensure_gh(self.fetch(self.archive)), "there")
        self.assertEqual(len(self.fetched), 1)                  # the second start downloads nothing

    def test_the_pin_goes_first_on_every_machine_whatever_other_gh_it_has(self):
        """The owner, 11 November 2026: a Mac of the fleet uses the fleet's gh too, for consistency. So a gh elsewhere
        on the PATH (a distribution's package, Homebrew's), older, the same or newer, does not stop the pin, and it
        stays as it is for its other uses. A gh in ~/.local/bin that is not the pin, newer or older, is replaced."""
        other = os.path.join(self.root, "homebrew")
        for system in (("Darwin", "arm64"), ("Linux", "x86_64")):
            self.system(*system)
            platform = fleet.gh_platform()
            name = f"gh_{fleet.GH_VERSION}_{platform}"
            kind = fleet.GH_BUILDS[platform][0]
            archive = (zipped if kind == "zip" else tar_gz)([(f"{name}/bin/gh", PROGRAM)])
            self.pin(archive, kind=kind, platform=platform)
            with patch.dict(os.environ, {"PATH": f"{self.bin}:{other}"}):
                for version in ("9.0.0", fleet.GH_VERSION, "2.4.0"):
                    with self.subTest(system=system, version=version):
                        shutil.rmtree(self.bin, ignore_errors=True)
                        a_gh(other, version)
                        self.assertEqual(fleet.ensure_gh(self.fetch(archive)), "installed")
                        self.assertTrue(self.installed())
                        with open(os.path.join(other, "gh")) as f:
                            self.assertIn(version, f.read())        # the machine's own gh is never changed
                        self.assertEqual(fleet.ensure_gh(self.fetch(archive)), "there")
                for version in ("9.0.0", "2.4.0"):
                    with self.subTest(system=system, local=version):
                        shutil.rmtree(self.bin, ignore_errors=True)
                        a_gh(self.bin, version)
                        self.assertEqual(fleet.ensure_gh(self.fetch(archive)), "installed")
                        self.assertTrue(self.installed())

    def test_a_file_in_local_bin_that_is_not_a_program_is_replaced(self):
        os.makedirs(self.bin)
        with open(self.target, "wb") as f:
            f.write(b"not a program")
        self.assertEqual(fleet.ensure_gh(self.fetch(self.archive)), "installed")
        self.assertTrue(self.installed())

    def test_a_download_that_is_not_the_pinned_archive_installs_nothing(self):
        with self.assertRaisesRegex(fleet.Refused, "does not match the SHA-256 that GitHub publishes"):
            fleet.ensure_gh(self.fetch(self.archive + b"!"))
        self.assertEqual((os.path.lexists(self.target), self.leftovers()), (False, []))

    def test_an_archive_whose_program_is_not_the_pinned_one_installs_nothing(self):
        archive = tar_gz([(f"{self.name}/bin/gh", PROGRAM + b"# changed\n")])
        self.pin(archive)                       # the archive matches its pin, and the program in it does not
        with self.assertRaisesRegex(fleet.Refused, "is not the pinned one"):
            fleet.ensure_gh(self.fetch(archive))
        self.assertEqual((os.path.lexists(self.target), self.leftovers()), (False, []))

    def test_only_the_program_itself_is_taken_from_the_archive(self):
        """A link in its place, an archive without it and a file that is not an archive are each refused, and
        nothing is written."""
        for archive, words in ((tar_gz([(f"{self.name}/bin/gh", None)]), "is not a program"),
                               (tar_gz([(f"{self.name}/gh", PROGRAM)]), f"has no {self.name}/bin/gh"),
                               (tar_gz([(f"../{self.name}/bin/gh", PROGRAM)]), f"has no {self.name}/bin/gh"),
                               (b"no archive at all", "cannot be read")):
            with self.subTest(words=words, archive=archive[:12]):
                self.pin(archive)
                with self.assertRaisesRegex(fleet.Refused, words):
                    fleet.ensure_gh(self.fetch(archive))
                self.assertEqual((os.path.lexists(self.target), self.leftovers()), (False, []))

    def test_an_archive_or_a_program_larger_than_the_limit_is_refused(self):
        big = b"\0" * 5000                      # a program that the archive compresses to a few bytes
        archive = tar_gz([(f"{self.name}/bin/gh", big)])
        self.pin(archive, program=big)
        self.assertLess(len(archive) + 10, len(big))
        with patch.object(fleet, "GH_MOST", len(archive) + 10):        # the archive fits, its program does not
            with self.assertRaisesRegex(fleet.Refused, "is not a program of at most"):
                fleet.ensure_gh(self.fetch(archive))
        with patch.object(fleet, "GH_MOST", len(archive) - 1):         # and here the download itself does not
            with self.assertRaisesRegex(fleet.Refused, "larger than"):
                fleet.ensure_gh(self.fetch(archive))
        self.assertEqual((os.path.lexists(self.target), self.leftovers()), (False, []))
        with patch.object(fleet, "GH_MOST", len(big)):                 # at the limit, both fit
            self.assertEqual(fleet.ensure_gh(self.fetch(archive)), "installed")

    def test_a_disk_that_is_nearly_full_gets_no_try(self):
        with patch.object(fleet.shutil, "disk_usage", lambda path: types.SimpleNamespace(free=fleet.GH_ROOM - 1)):
            with self.assertRaisesRegex(fleet.Refused, "MB free"):
                fleet.ensure_gh(self.fetch(self.archive))
        self.assertEqual((self.fetched, os.path.lexists(self.target)), ([], False))

    def test_a_mac_takes_its_own_zip(self):
        self.system("Darwin", "arm64")
        name = f"gh_{fleet.GH_VERSION}_macOS_arm64"
        archive = zipped([(f"{name}/LICENSE", b"MIT"), (f"{name}/bin/gh", PROGRAM)])
        self.pin(archive, kind="zip", platform="macOS_arm64")
        self.assertEqual(fleet.ensure_gh(self.fetch(archive)), "installed")
        self.assertTrue(self.fetched[0][0].endswith(f"/{name}.zip"))
        self.assertTrue(self.installed())
        self.assertEqual(os.stat(self.target).st_mode & 0o777, 0o755)

    def test_each_pinned_build_is_one_that_github_makes(self):
        """The four systems of the fleet's machines: Linux and macOS, on x86-64 and Arm, and on an Apple silicon Mac a
        Python under Rosetta takes the arm64 build. Each pin is a whole SHA-256. Whether a pin is GitHub's own file is
        not a test's to say: the author checks it against the release's checksums file before a pin moves."""
        def sysctl(says):
            def run(argv, **_kw):
                if isinstance(says, Exception):
                    raise says
                return subprocess.CompletedProcess(argv, 0, says, "")
            return run
        for (sysname, machine, run), platform in (
                (("Linux", "x86_64", None), "linux_amd64"), (("Linux", "aarch64", None), "linux_arm64"),
                (("Darwin", "arm64", None), "macOS_arm64"), (("Darwin", "x86_64", sysctl("0\n")), "macOS_amd64"),
                (("Darwin", "x86_64", sysctl("1\n")), "macOS_arm64"),
                (("Darwin", "x86_64", sysctl(OSError("no sysctl"))), "macOS_amd64"),
                (("Linux", "riscv64", None), None), (("FreeBSD", "amd64", None), None)):
            with self.subTest(sysname=sysname, machine=machine), \
                    patch.object(fleet.os, "uname", lambda: types.SimpleNamespace(sysname=sysname, machine=machine)):
                self.assertEqual(fleet.gh_platform(run or (lambda *a, **kw: self.fail("no sysctl here"))), platform)
        self.assertEqual(sorted(PINNED), ["linux_amd64", "linux_arm64", "macOS_amd64", "macOS_arm64"])
        for platform, (kind, archive_sum, program_sum) in PINNED.items():
            self.assertEqual(kind, "zip" if platform.startswith("macOS") else "tar.gz")
            for one in (archive_sum, program_sum):
                self.assertRegex(one, r"\A[0-9a-f]{64}\Z")

    def test_a_system_that_github_builds_no_gh_for_gets_none(self):
        self.system("Linux", "riscv64")
        self.assertEqual(fleet.ensure_gh(self.fetch(self.archive)), "none")
        self.assertEqual(self.fetched, [])

    def test_two_helpers_of_one_user_download_it_once(self):
        """Where helpers still run as one OS user, the helpers that start together share its ~/.local/bin."""
        done, opener = [], self.fetch(self.archive, pause=0.3)
        threads = [threading.Thread(target=lambda: done.append(fleet.ensure_gh(opener))) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        self.assertEqual((sorted(done), len(self.fetched)), (["installed", "there"], 1))

    def test_what_a_helper_that_ended_left_behind_goes_and_a_live_ones_stays(self):
        os.makedirs(self.bin)
        gone, live = os.path.join(self.bin, ".gh.999999.new"), os.path.join(self.bin, ".gh.424242.new")
        for path in (gone, live):
            with open(path, "w") as f:
                f.write("half")
        with patch.object(fleet, "process_gone", lambda pid: pid == 999999):
            self.assertEqual(fleet.ensure_gh(self.fetch(self.archive)), "installed")
        self.assertEqual((os.path.exists(gone), os.path.exists(live)), (False, True))

    def test_the_helpers_thread_tries_again_after_a_network_error_and_never_after_a_refusal(self):
        said, waits = [], []
        answers = iter([OSError("no network"), OSError("no network"), "installed"])

        def ensure():
            answer = next(answers)
            if isinstance(answer, Exception):
                raise answer
            return answer
        with patch.object(fleet, "ensure_gh", ensure), patch.object(fleet, "gh_quiet", return_value=False):
            self.assertEqual(fleet.gh_thread(tries=4, wait=20, sleep=waits.append, say=said.append), "installed")
        self.assertEqual(waits, [20, 20])
        self.assertIn("(try 1 of 4): OSError: no network", said[0])
        self.assertEqual(said[-1], f"the GitHub CLI gh {fleet.GH_VERSION} is installed in ~/.local/bin for this "
                                   f"agent's sessions")
        said.clear()
        waits.clear()
        with patch.object(fleet, "ensure_gh", side_effect=OSError("no network")) as tried:
            self.assertIsNone(fleet.gh_thread(tries=3, wait=5, sleep=waits.append, say=said.append))
        self.assertEqual((tried.call_count, waits, len(said)), (3, [5, 5], 3))     # no wait after the last try
        said.clear()
        waits.clear()
        with patch.object(fleet, "ensure_gh", side_effect=fleet.Refused("not the pinned one")) as tried:
            self.assertIsNone(fleet.gh_thread(tries=3, wait=5, sleep=waits.append, say=said.append))
        self.assertEqual((tried.call_count, waits), (1, []))       # the same files would be refused again
        self.assertEqual(said, [f"the GitHub CLI gh {fleet.GH_VERSION} is not installed: not the pinned one"])
        with patch.object(fleet, "ensure_gh", return_value="there"), patch.object(fleet, "gh_quiet", return_value=False):
            said.clear()
            self.assertEqual(fleet.gh_thread(say=said.append), "there")
            self.assertEqual(said, [])              # a start that changes nothing writes nothing

    def test_the_agents_own_gh_setting_sends_no_telemetry_on_every_machine(self):
        """gh 2.103.3 sends telemetry unless told not to. A session with repositories gets GH_TELEMETRY=0
        (integration_env), and gh's own setting of the agent's OS user says it for every session, on Linux and on a Mac,
        where the user is the desktop account, which is the agent's."""
        calls, setting = [], {"value": "enabled"}

        def run(argv, **kw):
            calls.append((argv[1:], kw["env"]["GH_TELEMETRY"]))
            if argv[1:3] == ["config", "get"]:
                return subprocess.CompletedProcess(argv, 0, setting["value"] + "\n", "")
            setting["value"] = argv[4]
            return subprocess.CompletedProcess(argv, 0, "", "")
        self.assertTrue(fleet.gh_quiet("/home/a/.local/bin/gh", run))
        self.assertFalse(fleet.gh_quiet("/home/a/.local/bin/gh", run))        # the next start finds it set
        self.assertEqual(calls, [(["config", "get", "telemetry"], "0"), (["config", "set", "telemetry", "disabled"], "0"),
                                 (["config", "get", "telemetry"], "0")])
        with self.assertRaisesRegex(fleet.Refused, "gh did not take the setting: no such key"):
            fleet.gh_quiet("gh", lambda argv, **kw: subprocess.CompletedProcess(
                argv, 1 if argv[2] == "set" else 0, "", "no such key"))
        self.system("Darwin", "arm64")
        setting["value"], calls[:] = "enabled", []
        self.assertTrue(fleet.gh_quiet("/Users/a/.local/bin/gh", run))         # a Mac's own setting too
        self.assertEqual([c[0][:2] for c in calls], [["config", "get"], ["config", "set"]])
        said = []
        for system in (("Linux", "x86_64"), ("Darwin", "arm64")):
            self.system(*system)
            with self.subTest(system=system), patch.object(fleet, "ensure_gh", return_value="there"), \
                    patch.object(fleet, "gh_quiet", side_effect=[True, False, OSError("read-only")]) as quiet:
                said.clear()
                for _ in range(3):
                    fleet.gh_thread(say=said.append)
                self.assertEqual([c.args[0] for c in quiet.call_args_list], [self.target] * 3)    # the pinned copy
                self.assertEqual(said, ["gh sends no telemetry for this agent's user now (gh config: telemetry "
                                        "disabled)", "gh's telemetry setting is not changed: OSError: read-only"])
        with patch.object(fleet, "ensure_gh", return_value="none"), \
                patch.object(fleet, "gh_quiet", side_effect=AssertionError("no gh, no setting")):
            said.clear()
            self.assertEqual(fleet.gh_thread(say=said.append), "none")

    def test_helpers_of_one_user_change_gh_s_setting_one_at_a_time(self):
        """gh writes its whole config file again: a helper that read it while another helper of the same user wrote it
        would save it without the user's other settings (five helpers of the Mac Studio set it in one second on
        11 November 2026). So gh_quiet runs under the user's gh lock."""
        inside, most, lock = [0], [0], threading.Lock()

        def quiet(program, run=None):
            with lock:
                inside[0] += 1
                most[0] = max(most[0], inside[0])
            time.sleep(0.2)
            with lock:
                inside[0] -= 1
            return False
        with patch.object(fleet, "ensure_gh", return_value="there"), patch.object(fleet, "gh_quiet", quiet):
            threads = [threading.Thread(target=fleet.gh_thread, kwargs={"say": lambda text: None}) for _ in range(3)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(10)
        self.assertEqual(most[0], 1)
        self.assertTrue(os.path.exists(os.path.join(self.home, ".fleet", "gh.lock")))

    def test_a_worker_or_a_lead_starts_it_and_a_manager_does_not(self):
        """The roles whose task sessions get GitHub repositories (integration_env). The thread starts at the helper's
        start, beside the door's ops, and the helper's loop does not wait for it."""
        started = []

        class Thread:
            def __init__(self, target, name, daemon):
                started.append((target, name, daemon))

            def start(self):
                started.append("start")
        with patch.object(fleet.threading, "Thread", Thread):
            for conf, starts in (({"role": "worker"}, True), ({"role": "lead"}, True), ({"role": "manager"}, False),
                                 ({}, False)):
                with self.subTest(conf=conf):
                    started.clear()
                    self.assertEqual(fleet.start_gh(conf), starts)
                    self.assertEqual(started, [(fleet.gh_thread, "github-cli", True), "start"] if starts else [])
        source = inspect.getsource(fleet.cmd_run)
        self.assertLess(source.index("ensure_ops()"), source.index("start_gh(conf)"))


if __name__ == "__main__":
    unittest.main()
