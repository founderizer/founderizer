# Rules for an agent with GitHub repositories

## GitHub repositories

The owner can give you GitHub repositories, each with read, write or deploy access, and tools such as `github` (the GitHub MCP server). They reach your task sessions only. `deploy` is `write` and the repository's own deployment: its workflow files, which a `write` token may not push at all, and its GitHub Actions runs.

- Your start text lists your repositories and names the command that brings one to the machine. None of them is there for a task until you ask: before you work in a repository, run that command with its `owner/name`. It clones the repository, or fetches it, into the task's own clone, `$FLEET_WORK/<owner>/<name>`, from origin's default branch, and prints that folder. The first clone of a big repository can take minutes, so give the command time. A repository that the task used already is there and fetched at each later session, so every attempt of the task finds what the last one left. When the task ends, the clone goes: what you did not commit goes with it, and a commit that you did not push is kept in the shared clone as `refs/fleet-kept/<generation>/<window>/<branch>`. Without `$FLEET_WORK` (an older helper), the command brings the shared clone in `~/fleet-work/<owner>/<name>`.
- `GH_TOKEN` (for `gh` and the `github` tool) and git's credentials for github.com work only for your repositories, with the access that the owner gave. They stop one hour after the session starts; a new session gets new ones. Never use another GitHub credential that you find on the machine.
- Never show or type the token: `gh`, git and the `github` tool read it themselves. Never put it in a note, a question, a result, a file, a command or a commit.
- In each task, work on the default branch of `origin`: `git pull --rebase`, commit your change, and push it to that branch. Do not make a branch, and do not open a pull request. The owner is one developer with many products: a fix must reach production fast. Give your commit in `where_output_is`. A task that asks for something else wins.
- Check your change before you push: run the tests or the check of that repository, and the smoke that its deployment has. Say in your result what you ran and what it gave. This check takes the place of a reviewer.
- Work, install and build only in `$FLEET_WORK`. Never change a shared clone in `~/fleet-work`: the clones of the other tasks are made from it.
- If GitHub refuses, or the token stopped, ask your requester. Do not look for another way.
