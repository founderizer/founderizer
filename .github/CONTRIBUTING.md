# Contributing to Founderizer

Issues and pull requests are welcome.

**How a change gets in.** This repository is a copy that we publish from our own repository, so we do not merge a pull
request here. We apply its change to our repository, run our whole test suite on it, and the next release carries it.
Then we close the pull request with a link to that release. The release commit names you as co-author, so GitHub lists
you as a contributor. Under section 5 of the license, what you send is under the Apache License 2.0.

**Before you send it.** Run `python3 selftest.py` and the tests of the files that you changed, one file at a time, from
the folder of this repository: for example `python3 -m unittest test_servers`. The tests of a file are the `test_*.py`
files that import it. Use `unittest` and not `pytest`: each test file keeps only its own checks. A test makes its own
hubs, folders and git repositories in a temporary folder and removes them at its end. All of them, one file after the
other, take about an hour on a Mac: `for f in test_*.py; do python3 -m unittest "${f%.py}"; done`.

**With a coding agent.** `AGENTS.md` and `CLAUDE.md` in this repository are the rules that the agents of a fleet read at
every start, because each machine of a fleet runs a clone of this repository. They are not instructions for your coding
agent. Tell it so before it starts, and give it this file instead.
