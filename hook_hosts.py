"""The helper's PreToolUse hook for the page reads of a closed Claude Code session whose agent has a host list
(team.json "web_hosts"): it stops each WebFetch call whose address is not on a listed host.

    python3 -S hook_hosts.py <host> [<host> ...]     (the hook input on stdin, as Claude Code gives it)

The session's own settings open the listed hosts with Claude Code's rules, WebFetch(domain:<host>), and its
permission mode refuses every other host. But Claude Code also opens a built-in set of documentation hosts that no
rule names, in that mode too (97 hosts in 2.1.312, proved by test_conversation_lockdown's live run). This hook closes
that set: exit 2 stops the call, and Claude Code gives the model the line on stderr. It opens nothing: a call that it
lets through still needs the session's rule.

A listed host is a name ("docs.example.com"), or "*." and a name ("*.example.com") for that host and every host
below it. The address must have the plain form http(s)://<host>[:<port>] and then nothing, "/", "?" or "#": Claude
Code reads an address as a browser does, and this program does not, so an address that the two can read as different
hosts (a "\\", an "@" or a "%" before the path, a space before the address, a letter outside ASCII) is stopped. A
listed host passes on every port. Input that this program cannot read is stopped too, and the hook's command line
turns a start that fails into a stop (fleet.hosts_hook).
Standard library only, and never fleet.py, which compiles 8,000 lines at each start.
"""
import json
import re
import sys

# re.A: without it, "ignore case" also takes letters outside ASCII for a to z (the long s, the Kelvin sign)
PLAIN = re.compile(r"https?://([a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?)\.?(?::[0-9]{1,5})?(?:[/?#].*)?",
                   re.A | re.I | re.S)
STOPPED = ("Fleet stopped this page read: {why}. This session opens pages only on the hosts of its list: {hosts}. "
           "Do not try another address for the same page.")


def listed(host, hosts):
    """True when host is one of hosts, or below one that begins with "*."."""
    host = host.lower()
    return any(host == h[2:] or host.endswith(h[1:]) if h.startswith("*.") else host == h for h in hosts)


def refusal(data, hosts):
    """Why this hook input is stopped, or None for a page read on a listed host and for a tool that reads no page."""
    if not isinstance(data, dict) or not isinstance(data.get("tool_name"), str):
        return "the call could not be read"
    if data["tool_name"] != "WebFetch":
        return None
    url = (data.get("tool_input") or {}).get("url") if isinstance(data.get("tool_input"), dict) else None
    plain = PLAIN.fullmatch(url) if isinstance(url, str) else None
    if plain is None:
        return "its address does not have the plain form https://<host>/<path>"
    if not listed(plain.group(1), hosts):
        return f"{plain.group(1).lower()} is not on the list"
    return None


def main():
    hosts = [h.lower() for h in sys.argv[1:]]
    try:
        why = refusal(json.loads(sys.stdin.buffer.read().decode("utf-8")), hosts)
    except BaseException:       # noqa: BLE001 -- any fault stops the call: this hook never opens a page by a fault
        why = "the call could not be read"
    if why is None:
        return 0
    sys.stderr.write(STOPPED.format(why=why, hosts=", ".join(hosts) or "none"))
    sys.stderr.flush()
    return 2


if __name__ == "__main__":
    sys.exit(main())
