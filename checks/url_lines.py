"""Fleet check (support plan F5): one GET of an address with one of the agent's own keys, and each line of the answer
printed as it came, so that each line that the last run did not print wakes the agent; a duty's watch makes each one
a case of its own. args: url, an https address (http only on 127.0.0.1), and key, the name of the variable that holds
the key, which goes as a bearer token. The answer is data: plain text of at most 64 KiB, each line one line of at most
400 characters with no control character, or the check fails. It follows no redirect, so the key goes to that address
only, and it uses no file and no AI."""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

ANSWER_MAX, LINE_MAX = 65536, 400
# A name of its own: an edge that refuses Python's default one stops the check (Cloudflare, 6 November 2026)
USER_AGENT = "Founderizer-Fleet/1 (check)"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None             # a redirect fails the check: the key never goes to another address


args = json.loads(sys.argv[1]).get("args") or {}
url, key = args.get("url"), args.get("key")
try:
    parts = urllib.parse.urlsplit(url) if isinstance(url, str) else None
except ValueError:
    parts = None
if not parts or not parts.hostname or parts.username or parts.password or parts.fragment or not (
        parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost"))):
    sys.exit("args.url must be an https address (http only on 127.0.0.1), with no user part and no #fragment")
token = os.environ.get(key) if isinstance(key, str) and key else None
if not token:
    sys.exit(f"this agent has no key {key!r} for its checks: args.key names the variable of a key it reads")
request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "text/plain",
                                                 "User-Agent": USER_AGENT})
try:
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as answer:
        body = answer.read(ANSWER_MAX + 1)
except urllib.error.HTTPError as e:
    sys.exit(f"the address answered HTTP {e.code}")
except (urllib.error.URLError, OSError) as e:
    sys.exit(f"the address did not answer: {type(e).__name__}")
if len(body) > ANSWER_MAX:
    sys.exit(f"the answer is larger than {ANSWER_MAX} bytes")
try:
    text = body.decode("utf-8")
except UnicodeDecodeError:
    sys.exit("the answer is not UTF-8 text")
lines = [line.strip() for line in text.splitlines() if line.strip()]
if any(len(line) > LINE_MAX or any(ord(c) < 32 or 127 <= ord(c) < 160 for c in line) for line in lines):
    sys.exit(f"a line of the answer is not one plain line of at most {LINE_MAX} characters")
print("\n".join(lines))
