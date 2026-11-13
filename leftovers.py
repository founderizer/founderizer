"""No process, tmux socket file or folder that a test starts or makes outlives the test process, however it ends.

A test stops what it started and removes what it made in a cleanup of its own, which a test process that is killed
never runs: at a caller's time-out, or when its terminal closes. On 11 November 2026 ten hubs of ended runs of
selftest.py still served on the owner's Mac with parent PID 1, the oldest for eight days; killed unit tests left
their hubs, tmux servers and git daemons the same way; and the temporary folders held the folders of killed tests and
a socket file of every tmux server that a test had started, which tmux never removes.

So each hub that a test starts reads LIFE, whose write end only the test process holds, and stops itself when that
process is gone (hub.py --parent-pipe, as in selftest.py). A server that cannot read LIFE runs under a keeper, its
parent, which reads LIFE for it (git daemon). And a guard reads GONE, whose write ends the test process and each of its
hubs hold: when all of them have ended, it runs the commands that it was given, which stop the servers that leave the
process that starts them at once (a tmux server), and then removes the folders and files that it was given. The guard
runs in a session of its own, so that a Ctrl-C or a kill of the test's process group does not reach it, and as the
child of a process that ends at once, so that the test process leaves no child of its own running when it ends.

It imports nothing of the fleet's own, so a test that takes it pays for no import of hub.py (scratch_home loads
fleet.py when a test file calls it). test_ui_api.HubProcesses checks all of it.

And no test reads or writes the helper's folder of the machine that runs it (scratch_home)."""
import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

GUARD = """import json, os, shutil, subprocess, sys
if os.fork():
    os._exit(0)
told = b""
while True:
    got = os.read(int(sys.argv[1]), 65536)
    if not got:
        break
    told += got
told = [json.loads(line) for line in told.splitlines()]
for argv in [what for kind, what in told if kind == "run"]:
    try:
        subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=60)
    except (OSError, subprocess.SubprocessError):
        pass
for path in [what for kind, what in told if kind == "remove"]:
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path, ignore_errors=True)
        else:
            os.remove(path)
    except OSError:
        pass
"""
KEEPER = """import os, signal, subprocess, sys, threading
server = subprocess.Popen(sys.argv[2:])
signal.signal(signal.SIGTERM, lambda *_: server.terminate())
def watch(life):
    while os.read(life, 4096):
        pass
    server.terminate()
threading.Thread(target=watch, args=(int(sys.argv[1]),), daemon=True).start()
sys.exit(server.wait())
"""
LIFE, GONE = [], []     # LIFE's read and write ends, from their first use; GONE's write end, once the guard runs


def life():
    """LIFE's read end. Only this process holds its write end, so a read of it ends when this process has ended."""
    if not LIFE:
        LIFE.extend(os.pipe())
    return LIFE[0]


def guard(kind, what):
    """GONE's write end, once the guard knows what to do when this process and its hubs have ended: a command to run,
    or a folder or a file to remove (kind). The first call starts the guard."""
    if not GONE:
        gone, gone_w = os.pipe()
        subprocess.run([sys.executable, "-I", "-c", GUARD, str(gone)], pass_fds=(gone,),
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       start_new_session=True)
        os.close(gone)
        GONE.append(gone_w)
    with contextlib.suppress(BrokenPipeError):         # no guard: a hub still stops, and only what it was told stays
        os.write(GONE[0], json.dumps([kind, what]).encode() + b"\n")
    return GONE[0]


def parent_pipe(folder):
    """What a hub.py process that a test starts takes, so that neither it nor `folder`, where it keeps its records,
    outlives this test process, however that ends: the descriptor to give it as `--parent-pipe`, and the descriptors
    to pass it (pass_fds). The guard removes `folder` once this process and its hubs have ended, which the test's own
    cleanup has usually done already."""
    gone_w = guard("remove", os.path.abspath(folder))
    return life(), (life(), gone_w)


def while_this_test_runs(argv):
    """A server that cannot read a pipe itself (git daemon), so that it does not outlive this test process, however
    that ends: argv under a keeper, its parent, which stops it when this process is gone, and the descriptors to pass
    the keeper (pass_fds). The keeper passes a SIGTERM on to the server and ends with it, so the test stops the server
    and reads its output as before."""
    return [sys.executable, "-I", "-c", KEEPER, str(life()), *argv], (life(),)


def when_gone(argv):
    """The command that stops a server which leaves the process that starts it at once, so that no keeper can hold
    it: the guard runs it when this process and its hubs have ended, however that happened, before it removes what it
    was given. It also runs when the test's own cleanup has stopped that server already, so it must name the server
    by a name of this run alone."""
    guard("run", list(argv))


def removed_when_gone(path):
    """`path`, a folder or a file that a test makes, which the guard removes when this process and its hubs have
    ended: a test that is killed runs no cleanup of its own. The test still removes it itself, and the guard then
    finds nothing."""
    guard("remove", os.path.abspath(path))
    return path


def tmux_socket(name):
    """The socket of a tmux server that a test starts, for `tmux -S`: a path of this run alone in /tmp, because the
    path of a socket has at most 104 bytes on a Mac and a test can run with a longer TMPDIR. The server leaves the
    process that starts it at once, and tmux leaves its socket file when the server ends, so the guard stops the
    server and then removes the file. `-S` reaches the server whatever environment it started with (`env -i` too),
    which `-L` does not: its folder follows TMUX_TMPDIR."""
    path = f"/tmp/{name}-{uuid.uuid4().hex[:8]}"
    when_gone(["tmux", "-S", path, "kill-server"])
    return removed_when_gone(path)


def scratch_home():
    """In a test file's setUpModule: the helper's folder (fleet.HOME, with fleet.SESSIONS and fleet.KEPT_RUNTIMES,
    which fleet.py makes from it at its import) is a folder of this run for every test of the file, and it is removed
    at the module's end. A class that gives the helper a folder of its own still does, inside this one. Returns the
    folder.

    Each test file that builds a fleet.Helper calls it (test_helper_session.OwnFolder checks that). On 13 November
    2026 a test class built a Helper with stand-in tmux answers and no folder of its own, because its tests reached
    no code that writes there. Then a mutation run took one guard out of the code, the real start of a chat ran, and
    it wrote a chat record and a session file into ~/.fleet of the owner's Mac; a later run read that record and
    failed for it. A test must not depend on which code it reaches for that."""
    import fleet
    folder = removed_when_gone(tempfile.mkdtemp(prefix="fleet-test-home-"))
    unittest.addModuleCleanup(shutil.rmtree, folder, True)
    home = os.path.join(folder, ".fleet")
    for name, path in (("HOME", home), ("SESSIONS", os.path.join(home, "sessions")),
                       ("KEPT_RUNTIMES", os.path.join(home, "runtimes"))):
        patcher = patch.object(fleet, name, path)
        patcher.start()
        unittest.addModuleCleanup(patcher.stop)
    return folder
