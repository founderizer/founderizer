#!/usr/bin/env python3
"""ops: an agent's one step through the door (DevOps plan, section 2). Standard library only.

    ops <target> <action> [argument ...] [--content FILE | --content -]
    ops status

A target is a host (`ops web-1 restart nginx`, `ops web-1 journal unit=nginx lines=200`, `ops web-1 help`), a provider
account (`ops cloudflare:main purge <zone> app.example.com`), a repository (`ops commit:acme/ops push --content
change.json`, `ops deploy:acme/shop run`) or the GitOps repository (`ops gitops:acme/cluster read apps/shop.yaml`). The
door answers what ran, or why it refused: a refusal is the end of that call, and a case that needs it goes to the
owner with the exact command. The door knows this box by its address on the private network, so this command sends
no credential.

The door's address comes from team.json's "door" ({address, port}) in this checkout, or FLEET_DOOR=<address>:<port>.
Exit status: 0 done, 3 refused, 1 failed, 2 the door does not answer (one line, which a check can print as it is).
"""
import base64
import json
import os
import sys
import urllib.error
import urllib.request

KIT = os.path.dirname(os.path.abspath(__file__))
PORT = 8766
TIMEOUT = 3700              # a long upgrade runs while the call waits


def door_address():
    given = os.environ.get("FLEET_DOOR", "")
    if given:
        host, _, port = given.rpartition(":")
        return host or given, int(port) if port.isdigit() else PORT
    try:
        with open(os.path.join(KIT, "team.json"), encoding="utf-8") as f:
            door = json.load(f).get("door") or {}
    except (OSError, ValueError):
        door = {}
    return door.get("address"), int(door.get("port") or PORT)


def ask(method, path, body=None, timeout=TIMEOUT):
    """(status, answer); status None when the door does not answer."""
    host, port = door_address()
    if not host:
        return None, {"why": "this fleet has no door: team.json names none"}
    url = f"http://{host}:{port}{path}"
    req = urllib.request.Request(url, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {"why": f"the door answered {e.code}"}
    except (urllib.error.URLError, OSError, ValueError):
        return None, {"why": f"the door does not answer at {host}:{port}"}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["status"]:
        status, answer = ask("GET", "/ping", timeout=15)
        if status is None:
            print(answer["why"])
            return 2
        print(f"the door answers, and knows this box as {answer.get('agent')}" if status == 200 else
              "the door answers, and this box is not in its access file")
        return 0 if status == 200 else 3
    if len(argv) < 2 or argv[0].startswith("-"):
        print(__doc__.strip().split("\n\n")[1])
        return 64
    content = None
    if "--content" in argv:
        i = argv.index("--content")
        if i + 1 >= len(argv):
            print("--content takes a file, or - for stdin")
            return 64
        source = argv[i + 1]
        del argv[i:i + 2]
        if source == "-":
            content = sys.stdin.buffer.read()
        else:
            with open(source, "rb") as f:
                content = f.read()
    target, action, args = argv[0], argv[1], argv[2:]
    body = {"target": target, "action": action, "args": args}
    if content is not None:
        body["content"] = base64.b64encode(content).decode()
    status, answer = ask("POST", "/call", body)
    if status is None:
        print(answer["why"])
        return 2
    if answer.get("ok"):
        out = answer.get("out") or "done"
        print(out if out.endswith("\n") else out + "\n", end="")
        return 0
    print(("refused: " if answer.get("kind") == "refused" else "failed: ") + str(answer.get("why") or status))
    return 3 if answer.get("kind") == "refused" else 1


if __name__ == "__main__":
    sys.exit(main())
