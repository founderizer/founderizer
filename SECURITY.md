# Security

Founderizer keeps the logins and the API keys of your agents. A security problem in it can let another person use
them. If you find one, please tell us privately first, so that we can fix it before other people know about it.

## Report a problem privately

Do not open a public issue, pull request or discussion about a security problem.

Report it with GitHub's private vulnerability reporting:

1. Open the **Security** tab of this repository.
2. Select **Report a vulnerability**.
3. Complete the form, and send it.

The form is also at <https://github.com/founderizer/founderizer/security/advisories/new>. Only you and the
maintainers of this repository can see the report.

Put this information in the report:

- The release or the commit of this repository that you tested.
- The steps that show the problem.
- What an attacker can do with the problem.
- A proof of concept, if you have one.

Do not put a real password, key or token in a report, also not one of your own. Use an example value.

## What happens after a report

1. We read the report, and we answer you in the report.
2. We examine the problem. If we need more information, we ask you in the report.
3. If it is a security problem, we make the fix in our own repository, we test it, and we publish it in a new
   release. This repository is a copy of our own repository (`README.md`, "Changes from outside").
4. After the release, we publish a security advisory in this repository. The advisory tells what the problem was,
   which releases have it, and which release fixes it. If you agree, the advisory gives your name.
5. If it is not a security problem, we tell you why in the report.

Please keep the problem private until we publish the advisory.

## Which versions get fixes

We fix only the newest release. A hub takes a new release from this repository, and only a release whose manifest
has a valid signature (`releases.py`). A fleet gets a fix when it takes the release that has it. [VAULT.md](VAULT.md),
"How the vault's code is updated", tells how a release reaches the vault on each server.

## What this policy covers

- The code in this repository: the hub, the helper on each machine, the vault brokers and the central vault, the
  door, the installers and the owner's MCP server.
- The Mac and iPhone apps, and Fleet Vault for Mac, are in <https://github.com/founderizer/founderizer-apps>. Report
  a problem in them there.
- If you do not know which repository a problem belongs to, report it in either one.
- A problem in a service that a fleet uses, for example an AI provider, Tailscale or GitHub, goes to that service. A
  problem in how Founderizer uses the service goes to us.

## How the vault keeps secrets

[VAULT.md](VAULT.md) tells what the vault protects, how it protects it, what it does not protect, and what the owner
of a fleet must do.
