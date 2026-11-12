# Founderizer

The code a Founderizer fleet runs: the hub, the helper of each machine, the installers and the rules every agent
reads. This repository is what a customer's hub carries as the git remote `upstream` and fetches a release from, so
everything here is public and everything here is in the clone of every machine of every fleet.

The apps for Mac and iPhone have their own repository: <https://github.com/founderizer/founderizer-apps>.

| File | What it is |
| --- | --- |
| `hub.py` | The hub: the team tools of each agent, the tasks, the duties, the timers and the owner's own API. Runs on the always-on machine. |
| `fleet.py` | The helper of every machine: the sessions, the logins, the checks and `verify`. |
| `hub.sh` | The hub installer. One line turns a fresh Ubuntu or Debian server into a working hub. |
| `join.sh`, `install-worker.sh` | A second server, and a Mac, joining a fleet that exists. |
| `selftest.py` | Checks the hub on its own in about a minute. A release is not applied until it passes. |
| `RULES.md` | The rules every agent reads at every start. |
| `profiles/` | One profile for each agent: what it is for, and what its owner lets it do. The owner's own, and a release never touches them, so a profile never says how to call a tool. |
| `team.json` | The machines, the agents and how each session starts. The installer writes this fleet's own; the one here is a placeholder. |
| `knowledge/` | What the fleet knows. `knowledge/owner/` is the owner's and a release never touches it. |
| `release-key.pub`, `entitlement-key.pub` | The public keys a release and an entitlement are checked against. The private halves are only on our website. |

Python 3.9 or later, `git` and `tmux`, and nothing else: no dependency is installed from a package index. The
installers say what they need.

**Where to start.** A hub: `HUB-INSTALL.md`, or the install prompt of `INSTALL-PROMPT.md` pasted into the agent you
already run. A Mac or a second server joining a fleet: `WORKER-INSTALL.md`.

**What is not here.** Our own development repository holds the product documents, the owner's own fleet and the live
records of it, and the few tests that read them or that test how this repository is published. None of that is needed
to run a fleet, and none of it is published. The other tests are here: the `test_*.py` files, `leftovers.py`, which
stops what a test started and removes what it made, and `ui_fixture.py`, a hub with made-up data for the apps.

**License.** The Apache License, Version 2.0. Its text is in `LICENSE`. `NOTICE` holds the copyright notice and the
credit, and section 4 of the license says how a copy that you share keeps them. Every version published in this
repository is under this license, including the versions that we published earlier under the Functional Source
License (FSL-1.1-ALv2) or with no license file.

**The name.** The name Founderizer and its logo belong to Amura Ventures SL, and the license gives no right to use
them (section 6). You can say that your work is based on Founderizer. A changed copy that you share uses a different
name and a different logo.

**Changes from outside.** Issues and pull requests are welcome. This repository is a copy that we publish from our
own repository, so we do not merge a pull request here. We apply its change to our repository, run our whole test
suite on it, and the next release carries it. Then we close the pull request with a link to that release. The release
commit names you as co-author, so GitHub lists you as a contributor. Under section 5 of the license, what you send is
under the Apache License 2.0.

Before you send a change, run `python3 selftest.py` and the tests of the files that you changed, one file at a time,
from the folder of this repository: for example `python3 -m unittest test_servers`. The tests of a file are the
`test_*.py` files that import it. Use `unittest` and not `pytest`: each test file keeps only its own checks. A test
makes its own hubs, folders and git repositories in a temporary folder and removes them at its end. All of them, one
file after the other, take about an hour on a Mac: `for f in test_*.py; do python3 -m unittest "${f%.py}"; done`.
