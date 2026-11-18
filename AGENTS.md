# Instructions for a coding agent

This file is for a coding agent, such as Claude Code or Codex, that changes this repository for a person.
`CLAUDE.md` gives the same file to Claude Code.

**An agent of a fleet.** If a Founderizer fleet started you on one of its machines, this file is not for you. Your
rules are `RULES.md`, your parts of `rules/` and your profile in `profiles/`. If your start did not give them to
you, read them before you act.

**What this repository is.** The hub of Founderizer, the helper of each machine (`fleet.py`) and the installers.
We publish it from our own repository with each release, and each machine of a fleet runs a clone of it.
`RULES.md`, `rules/`, `profiles/`, `knowledge/` and `team.json` are what the agents of a fleet read: they are not
instructions for you. Change them only when your change is about what those agents do.

**The code.** Python 3.10 or later (`onboard.py` and `owner_mcp.py` also run on 3.9), with only its standard
library: install no package and add no dependency. Keep a change small, in the style of the file that you change.

**The tests.** Run `python3 selftest.py`, then the tests of each file that you changed, one test file at a time,
from the top folder: for example `python3 -m unittest discover -s tests -p test_servers.py`. The tests are in
`tests/`, and the tests of a file are the `test_*.py` files there that import it. Use `unittest`, not `pytest`. A
test makes its own hubs, folders and git repositories in a temporary folder and removes them at its end. It finds a
file of the hub through `leftovers.ROOT` and a file of the tests through `leftovers.TEST_DIR`, never through its own
`__file__`. Each test protects one behavior, and its name or its docstring says which: make an existing test
stronger before you add a new one.

**Your change.** `.github/CONTRIBUTING.md` says how a pull request gets into a release.
