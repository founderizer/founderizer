#!/usr/bin/env python3
"""The pin of a program that the fleet downloads by itself (onboard.PINNED): one version of it, and the SHA-512 of the
file of each Linux platform. A person runs this when a pin moves. No helper and no hub runs it. It is published with
the fleet's code, so that a person outside can make a pin and check one.

    python3 pins.py                                   each program's newest version that can be a pin
    python3 pins.py grok 1.0.77                       npm's record, one download of each file, then the entry
    python3 pins.py opencode 2.2.5 --keep linux-arm64=/scratch/opencode
                                                      the same, and that platform's program stays at the path

The rules of a pin:

- A pin is a released version that npm published at least lifecycle.NPM_DAYS days before, and not one above npm's
  `latest`: that is the fleet's own rule for npm packages (hubsetup.NPM_RULE), and a direct download must not go
  around it. The rule holds for the package of the program and for the package of each platform's file.
- Each file is downloaded here once, with the helper's own client name (fleet.OUTSIDE_AGENT), because the pin must be a
  file that the helper itself gets. Its SHA-512 is the digest of the file as it is downloaded.
- A file that npm holds (OpenCode) must have the digest that npm's own record gives it (dist.integrity).
- A file of a vendor's own store (Grok Build, whose npm file is packed with Brotli, which Python cannot open) must be
  the same at each of its addresses, and it must be the program that npm published on that day: npm's packed copy is
  opened with the `brotli` program, and it must hold the same bytes. The addresses of one vendor are one source, so
  without npm's copy the file is only what the store gave today, and its age is not proved. A machine with no
  `brotli` program makes no such pin. The entry keeps npm's file, its member and npm's own digest of the file
  (`packed`), so that a reader can hold the pin to npm's record again.
- Each program must be a Linux program of its platform's processor.

No install script runs and no `npm` runs: this reads records and files, and it starts none of them.
"""
import argparse
import base64
import binascii
import contextlib
import datetime
import hashlib
import http.client
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import urllib.error
import urllib.parse
import urllib.request

import fleet
import lifecycle

NPM = "https://registry.npmjs.org"
RELEASED = re.compile(r"\d{1,4}\.\d{1,4}\.\d{1,6}")     # a released version: a build with another name is no pin
RECORD_BYTES = 1 << 28      # npm's record of a package that has a build each hour is tens of MiB
BLOCK = 1 << 20
BROTLI = ["brotli", "-d", "-c"]     # opens npm's packed copy of a program from standard input; needed for such a pin
MACHINES = {"x64": 62, "arm64": 183}        # the processor in a Linux program's own header (ELF e_machine)

# What a pin is made from. `npm` is the package whose record gives a version its time. A file with `member` is npm's
# own file of that platform's package, and the program is that member of it. A file with `urls` comes from the
# vendor's own store, the same file at each address, and `packed` is the copy of it in npm's package of the platform.
PROGRAMS = {
    "grok": {"npm": "@xai-official/grok", "bin": "grok", "files": {
        "linux-x64": {"npm": "@xai-official/grok-linux-x64", "packed": "package/bin/grok.br", "urls": [
            "https://x.ai/cli/grok-{version}-linux-x86_64",
            "https://storage.googleapis.com/grok-build-public-artifacts/cli/grok-{version}-linux-x86_64"]},
        "linux-arm64": {"npm": "@xai-official/grok-linux-arm64", "packed": "package/bin/grok.br", "urls": [
            "https://x.ai/cli/grok-{version}-linux-aarch64",
            "https://storage.googleapis.com/grok-build-public-artifacts/cli/grok-{version}-linux-aarch64"]}}},
    "opencode": {"npm": "@opencode/cli", "bin": "opencode", "files": {
        "linux-x64": {"npm": "@opencode/cli-linux-x64", "member": "package/bin/opencode"},
        "linux-x64-baseline": {"npm": "@opencode/cli-linux-x64-baseline", "member": "package/bin/opencode"},
        "linux-arm64": {"npm": "@opencode/cli-linux-arm64", "member": "package/bin/opencode"}}},
}


class Refused(Exception):
    """This version, or one of its files, is no pin: the reason."""


def opened(url):
    """One call of an outside address with the helper's own client name: an edge can refuse Python's default one."""
    try:
        return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": fleet.OUTSIDE_AGENT}),
                                      timeout=60)
    except urllib.error.HTTPError as e:
        e.close()
        raise Refused(f"{url} answered {e.code}") from None
    except OSError as e:
        raise Refused(f"{url} did not answer: {str(getattr(e, 'reason', e))[:120]}") from None


def record(package):
    """npm's own record of a package: the time of each version, its file, and that file's digest."""
    with opened(f"{NPM}/{urllib.parse.quote(package, safe='@')}") as r:
        try:
            doc = json.loads(r.read(RECORD_BYTES))
        except ValueError:
            doc = None
    if not isinstance(doc, dict) or doc.get("name") != package or not isinstance(doc.get("time"), dict) or \
            not isinstance(doc.get("versions"), dict):
        raise Refused(f"npm gave no record of {package}")
    return doc


def order(version):
    return tuple(int(part) for part in version.split("."))


def published(doc, version):
    """When npm published one version of a package."""
    stamp = doc["time"].get(version) if version in doc["versions"] else None
    try:
        when = datetime.datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except ValueError:
        raise Refused(f"npm has no version {version} of {doc['name']}") from None
    return when if when.tzinfo else when.replace(tzinfo=datetime.timezone.utc)


def aged(doc, version, now):
    """When npm published the version, for one that is old enough to be a pin."""
    when = published(doc, version)
    if now - when < datetime.timedelta(days=lifecycle.NPM_DAYS):
        raise Refused(f"npm published {doc['name']} {version} {(now - when) / datetime.timedelta(days=1):.1f} days "
                      f"ago, and a pin is at least {lifecycle.NPM_DAYS} days old (lifecycle.NPM_DAYS)")
    return when


def latest(doc):
    """The version that npm installs when nobody names one. A version above it is a build of another channel, whatever
    its number looks like."""
    version = (doc.get("dist-tags") or {}).get("latest")
    if not isinstance(version, str) or not RELEASED.fullmatch(version):
        raise Refused(f"npm names no released version of {doc['name']} as its latest")
    return version


def newest(doc, now):
    """The newest version of a package that can be a pin, or None."""
    top, limit = order(latest(doc)), datetime.timedelta(days=lifecycle.NPM_DAYS)
    fit = [v for v in doc["versions"] if RELEASED.fullmatch(v) and order(v) <= top and now - published(doc, v) >= limit]
    return max(fit, key=order) if fit else None


def integrity(doc, version):
    """(the address of npm's file of one version, its SHA-512 as npm's record gives it)."""
    dist = doc["versions"][version].get("dist") or {}
    address, said = dist.get("tarball"), str(dist.get("integrity") or "")
    try:
        digest = base64.b64decode(said[len("sha512-"):], validate=True).hex() if said.startswith("sha512-") else ""
    except (binascii.Error, ValueError):
        digest = ""
    if not isinstance(address, str) or not address.startswith(NPM + "/") or len(digest) != 128:
        raise Refused(f"npm's record of {doc['name']} {version} gives no file with a SHA-512")
    if not address.isascii() or not address.isprintable() or " " in address:
        raise Refused(f"npm's record of {doc['name']} {version} names a file with a character that no address has")
    return address, digest


class Counted:
    """A download as a file to read, which keeps the SHA-512 and the size of what went through it."""

    def __init__(self, response):
        self.response, self.digest, self.size = response, hashlib.sha512(), 0

    def read(self, size):
        block = self.response.read(size)
        self.digest.update(block)
        self.size += len(block)
        return block


def download(url, take=None):
    """One download of one address: {url, status, bytes, sha512}. `take` reads what it needs of the file. The rest is
    then read to its end, because the digest is that of the whole file."""
    with opened(url) as response:
        counted, length = Counted(response), response.headers.get("Content-Length")
        try:
            if take:
                take(counted)
            while counted.read(BLOCK):
                pass
        except (http.client.HTTPException, tarfile.TarError, EOFError, OSError) as e:
            raise Refused(f"the download of {url} ended after {counted.size} bytes: {type(e).__name__}") from None
        if length is not None and length.strip() != str(counted.size):
            raise Refused(f"the download of {url} ended after {counted.size} of {length.strip()} bytes")
        return {"url": url, "status": response.status, "bytes": counted.size, "sha512": counted.digest.hexdigest()}


class Program:
    """Where the bytes of one program go: its SHA-512, its size and its first bytes always; a file of mode 755 when
    the person keeps it, which appears whole or not at all (kept)."""

    def __init__(self, path=None):
        self.path, self.part = path, f"{path}.{os.getpid()}.part" if path else None
        self.file = open(os.open(self.part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o755), "wb") if path else None
        self.digest, self.size, self.head = hashlib.sha512(), 0, b""

    def write(self, block):
        self.head = self.head if len(self.head) >= 20 else (self.head + block)[:20]
        self.digest.update(block)
        self.size += len(block)
        if self.file:
            self.file.write(block)

    def read_from(self, source):
        for block in iter(lambda: source.read(BLOCK), b""):
            self.write(block)

    def machine(self):
        """The processor that a Linux program names in its own header, or None for a file that is no such program."""
        if len(self.head) < 20 or self.head[:4] != b"\x7fELF":
            return None
        return int.from_bytes(self.head[18:20], "little" if self.head[5] == 1 else "big")

    def said(self):
        return {"bytes": self.size, "sha512": self.digest.hexdigest()}

    def kept(self):
        if self.file:
            self.file.close()
            os.chmod(self.part, 0o755)
            os.replace(self.part, self.path)
            self.file = None

    def dropped(self):
        if self.file:
            self.file.close()
            self.file = None
        if self.part:
            with contextlib.suppress(FileNotFoundError):
                os.remove(self.part)


class Unpacked:
    """What npm's packed copy of a program holds: its bytes go through BROTLI, and what comes out is counted."""

    def __init__(self):
        self.proc = subprocess.Popen(BROTLI, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.out, self.broken = Program(), False
        self.thread = threading.Thread(target=self.out.read_from, args=(self.proc.stdout,), daemon=True)
        self.thread.start()

    def read_from(self, source):
        try:
            for block in iter(lambda: source.read(BLOCK), b""):
                self.proc.stdin.write(block)
            self.proc.stdin.close()
        except OSError:
            self.broken = True

    def said(self):
        self.thread.join()
        if self.proc.wait() != 0 or self.broken:
            raise Refused(f"{BROTLI[0]} could not open npm's packed copy")
        return self.out.said()

    def ended(self):
        """After a download that failed: the program does not wait for more."""
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        for pipe in (self.proc.stdin, self.proc.stdout):
            with contextlib.suppress(OSError):
                pipe.close()


def unpacked_at(path):
    """Where npm puts an item of its file: the path without its first part, whatever the name of that part is."""
    return posixpath.normpath(path).lstrip("/").partition("/")[2]


def member(name, into):
    """A reader of a .tgz download that gives one regular file of it to `into`: the item of exactly that name. An item
    that npm would unpack to the same place and that comes after it is refused, because a program that unpacks the
    file keeps the last one: the pin and an install from npm would then hold two different programs."""
    def take(counted):
        found = False
        with tarfile.open(fileobj=counted, mode="r|gz", bufsize=BLOCK) as tar:
            for item in tar:
                if unpacked_at(item.name) != unpacked_at(name):
                    continue
                if found:
                    raise Refused(f"npm's file holds {name} two times")
                if item.isfile() and posixpath.normpath(item.name) == name:
                    into.read_from(tar.extractfile(item))
                    found = True
        if not found:
            raise Refused(f"npm's file has no {name}")
    return take


def whole(into):
    def take(counted):
        into.read_from(counted)
    return take


def pin(name, version, keep=None, now=None, say=lambda line: None):
    """(the onboard.PINNED entry of one program at one version, the report of how it was made). Raises Refused.

    keep: {platform: path} of the programs to keep. now: the time that the age rule measures from."""
    program, keep = PROGRAMS[name], dict(keep or {})
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if not RELEASED.fullmatch(version):
        raise Refused(f"{version} is no released version")
    if set(keep) - set(program["files"]):
        raise Refused(f"{name} has no file for {', '.join(sorted(set(keep) - set(program['files'])))}")
    if any(source.get("packed") for source in program["files"].values()) and not shutil.which(BROTLI[0]):
        raise Refused(f"this machine has no `{BROTLI[0]}` program, which opens npm's packed copy of {name}: without "
                      f"that copy the vendor's store alone says what the file is, and its age is not proved")
    doc = record(program["npm"])
    if order(version) > order(latest(doc)):
        raise Refused(f"npm's latest {program['npm']} is {latest(doc)}: {version} is a build of another channel")
    when = aged(doc, version, now)
    days = lambda at: round((now - at) / datetime.timedelta(days=1), 1)
    say(f"npm published {program['npm']} {version} at {when:%Y-%m-%d %H:%M} UTC, {days(when)} days ago")
    entry = {"version": version, "published": when.date().isoformat(), "bin": program["bin"], "files": {}}
    report = {"name": name, "version": version, "client": fleet.OUTSIDE_AGENT, "at": now.isoformat(timespec="seconds"),
              "npm": {"package": program["npm"], "published": when.isoformat(timespec="seconds"),
                      "age_days": days(when), "latest": latest(doc)}, "files": {}}
    for platform, source in program["files"].items():
        own = record(source["npm"])
        own_when = aged(own, version, now)
        address, wanted = integrity(own, version)
        said = {"npm": {"package": source["npm"], "published": own_when.isoformat(timespec="seconds"),
                        "age_days": days(own_when), "file": address, "integrity_sha512": wanted}, "downloads": []}
        out = Program(keep.get(platform))
        try:
            if source.get("member"):
                file = download(address, member(source["member"], out))
                said["downloads"].append(file)
                if file["sha512"] != wanted:
                    raise Refused(f"the download of {address} does not match npm's own digest of it")
                urls = [address]
            else:
                urls = [url.format(version=version) for url in source["urls"]]
                file = download(urls[0], whole(out))
                said["downloads"].append(file)
                for url in urls[1:]:
                    other = download(url)
                    said["downloads"].append(other)
                    if (other["sha512"], other["bytes"]) != (file["sha512"], file["bytes"]):
                        raise Refused(f"{url} gives another file than {urls[0]}")
                unpacked = Unpacked()
                try:
                    packed = download(address, member(source["packed"], unpacked))
                    said["downloads"].append(packed)
                    if packed["sha512"] != wanted:
                        raise Refused(f"the download of {address} does not match npm's own digest of it")
                    if unpacked.said() != out.said():
                        raise Refused(f"{urls[0]} is not the program that npm holds as {source['packed']} of "
                                      f"{source['npm']} {version}")
                finally:
                    unpacked.ended()
                said["same_as_npm"] = True
            if out.machine() != MACHINES[platform.split("-")[1]]:
                raise Refused(f"the {platform} file of {name} {version} is no Linux program for that processor")
            out.kept()
        finally:
            out.dropped()
        said["program"] = dict(out.said(), member=source.get("member"), kept=keep.get(platform))
        for one in said["downloads"]:
            say(f"{platform}: {one['url']} answered {one['status']} with {one['bytes']} bytes")
        say(f"{platform}: the program has {out.size} bytes" + (
            ", and npm's packed copy opens to the same bytes" if said.get("same_as_npm") else
            ", held to the digest of npm's own record"))
        # the digest of the file as the helper downloads it: the first address's, never that of npm's packed copy
        entry["files"][platform] = {"urls": urls, "sha512": file["sha512"], "member": source.get("member")}
        if source.get("packed"):
            # npm's own file of this platform, as its record names it, and the member that opened to the same bytes
            entry["files"][platform]["packed"] = {"url": address, "sha512": wanted, "member": source["packed"]}
        report["files"][platform] = said
    report["entry"] = entry
    return entry, report


def entry_text(name, entry):
    """One entry as the lines of onboard.PINNED."""
    lines = [f'    "{name}": {{"version": "{entry["version"]}", "published": "{entry["published"]}", '
             f'"bin": "{entry["bin"]}", "files": {{']
    for platform, file in entry["files"].items():
        urls = ",\n".join(f"                {json.dumps(url)}" for url in file["urls"])
        packed = file.get("packed")
        lines += [f'        "{platform}": {{', '            "urls": [', f"{urls}],",
                  f'            "sha512": ("{file["sha512"][:64]}"',
                  f'                       "{file["sha512"][64:]}"),',
                  f'            "member": {json.dumps(file["member"]) if file["member"] else None}'
                  + ("," if packed else "},")]
        if packed:
            lines += ['            "packed": {',
                      f'                "url": {json.dumps(packed["url"])},',
                      f'                "sha512": ("{packed["sha512"][:64]}"',
                      f'                           "{packed["sha512"][64:]}"),',
                      f'                "member": {json.dumps(packed["member"])}}}}},']
    return "\n".join(lines)[:-1] + "}},"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Make the pin of a program that the fleet downloads by itself "
                                             "(onboard.PINNED)")
    ap.add_argument("name", nargs="?", choices=sorted(PROGRAMS))
    ap.add_argument("version", nargs="?")
    ap.add_argument("--keep", action="append", default=[], metavar="PLATFORM=PATH",
                    help="keep that platform's program at this path, with mode 755")
    ap.add_argument("--json", action="store_true", help="print the report of the run as JSON, with the entry in it")
    args = ap.parse_args(argv)
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        if not args.version:
            for name in [args.name] if args.name else sorted(PROGRAMS):
                doc = record(PROGRAMS[name]["npm"])
                fit = newest(doc, now)
                print(f"{name}: npm's latest {PROGRAMS[name]['npm']} is {latest(doc)}; the newest version that can be "
                      f"a pin is " + (f"{fit}, published {published(doc, fit):%Y-%m-%d %H:%M} UTC" if fit else "none"))
            return 0
        keep = dict(pair.split("=", 1) for pair in args.keep if "=" in pair)
        if len(keep) != len(args.keep):
            raise Refused("--keep takes PLATFORM=PATH")
        entry, report = pin(args.name, args.version, keep, now, say=lambda line: print(line, file=sys.stderr))
    except (Refused, OSError) as e:
        print(f"pins.py: {e}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=1) if args.json else entry_text(args.name, entry))
    return 0


if __name__ == "__main__":
    sys.exit(main())
