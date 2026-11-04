# Founderizer

The code a Founderizer fleet runs: the hub, the helper of each machine, the installers and the rules every agent
reads. This repository is what a customer's hub carries as the git remote `upstream` and fetches a release from, so
everything here is public and everything here is in the clone of every machine of every fleet.

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

**What is not here.** Our own development repository holds the product documents, the test suite, the owner's own
fleet and the live records of it. None of that is needed to run a fleet, and none of it is published.

**License.** The Functional Source License, Version 1.1, ALv2 Future License (FSL-1.1-ALv2), in `LICENSE.md`. You
may use, change and share this code for any purpose except a Competing Use, which `LICENSE.md` defines. Two years
after we make a version available, that version is also under the Apache License, Version 2.0.
