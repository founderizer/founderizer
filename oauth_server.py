"""The hub's own OAuth authorization server for the remote MCP address (connected apps): its pure parts.

Python standard library only, and no import of hub. The hub's ConnectHandler calls these functions; they keep no
state, open no database and read no clock, except fetch_cimd, which is the one network call and has a deadline of its
own. The caller gives the hub's DNS name (<name>, for example hub-1.tail0000.ts.net) and the time.

What each part follows:

- the two metadata documents: RFC 9728 (protected resource) and RFC 8414 (authorization server);
- the redirect list and its match: exact, one ChatGPT pattern, and loopback with the port ignored (RFC 8252 7.3);
- the client: a Client ID Metadata Document (draft-ietf-oauth-client-id-metadata-document) on a short host list, or a
  dynamic registration (RFC 7591);
- PKCE S256 (RFC 7636), the resource indicator (RFC 8707) and the iss parameter of the authorization response (RFC
  9207);
- the opaque tokens and the one-time code, of which the hub keeps only the SHA-256;
- the handle of a sign-in page: the request's own fields with an HMAC-SHA256 of the hub's key, so that the hub keeps
  no row for an open page.

A connected app is a public client: it has no secret, and PKCE and the owner's one-time code are the lock. Every
error text here is safe to show: it never holds a token, a code, a verifier or a request body.

Tests: test_oauth_server.py, with stand-ins for the resolver and the connection, so that no test reaches the network.
"""

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import socket
import ssl
import threading
import time
import urllib.parse

SCOPES = ("fleet.read", "fleet.act")
LEVELS = ("read", "act")
GRANTS = ("authorization_code", "refresh_token")
ACCESS_LIFE = 3600              # seconds an access token works (the MCP specification wants short ones)
GRANT_LIFE = 60                 # seconds an authorization code works (RFC 6749 4.1.2: a short life)
CODE_LIFE = 600                 # seconds the owner's one-time code works, as hub.DEVICE_CODE_LIFE
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"     # hub.LINK_ALPHABET: 32 letters, 5 bits each
CODE_LENGTH = 12                # 60 bits, shown as ABCD-EFGH-JKLM: no count of wrong tries, so nobody can end it
CLIENTS_MAX = 50                # dynamic clients with no connection; the 51st deletes the oldest
HANDLE_LIFE = 600               # seconds a sign-in page's handle works, as the one-time code
HANDLE_MAX = 7680               # characters of a handle: with the code it fits a form body of 8 KiB (gate.BODY_MAX)
REDIRECTS_MAX = 5               # redirect_uris of one dynamic registration
CIMD_REDIRECTS_MAX = 50         # redirect_uris of one metadata document
NAME_MAX = 40                   # characters of a client's own name, after clean_name
STATE_MAX = 1000                # characters of a client's state, which the hub keeps and sends back
URI_MAX = 400                   # characters of a redirect URI or a client_id
FIELDS_MAX = 30                 # fields of one form or query
CIMD_TIMEOUT = 5                # seconds for one whole metadata fetch: the name lookup, the connection, the answer
CIMD_MAX = 64 * 1024            # bytes of a metadata document
CIMD_HEAD_MAX = 16 * 1024       # bytes of the status line and the headers of its answer
AGENT = "founderizer-hub"       # the User-Agent of the fetch: some edges refuse the one of a library
UNRESERVED = re.compile(r"[A-Za-z0-9._~-]{43,128}")  # a PKCE verifier or challenge (RFC 7636 4.1 and 4.2)
DCR_CLIENT = re.compile(r"[A-Za-z0-9_-]{43}")        # a client_id of POST /register: 32 random bytes, base64url
NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")

# The redirect list, the same for every fleet: an exact URI, or a pattern, and the name that the sign-in page shows.
EXACT_REDIRECTS = {
    "https://claude.ai/api/mcp/auth_callback": "Claude",
    "https://claude.com/api/mcp/auth_callback": "Claude",
    "https://chatgpt.com/connector_platform_oauth_redirect": "ChatGPT",
}
PATTERN_REDIRECTS = ((re.compile(r"https://chatgpt\.com/connector/oauth/[A-Za-z0-9_-]{1,128}"), "ChatGPT"),)
# http on a loopback host, any port or none, and a plain path: no query, no fragment, no user part, no dot segment.
LOOPBACK = re.compile(r"http://(127\.0\.0\.1|localhost)(?::([1-9][0-9]{0,4}))?"
                      r"(/(?:[A-Za-z0-9_~-][A-Za-z0-9._~-]*(?:/[A-Za-z0-9_~-][A-Za-z0-9._~-]*)*)?)")

# The CIMD list: a client_id that is an https address is a metadata document only on these hosts, under /oauth/.
CIMD_HOSTS = ("claude.ai", "claude.com", "chatgpt.com")
CIMD = re.compile(r"https://(claude\.ai|claude\.com|chatgpt\.com)/oauth/"
                  r"[A-Za-z0-9_~-][A-Za-z0-9._~-]*(?:/[A-Za-z0-9_~-][A-Za-z0-9._~-]*)*")
CLAUDE_CODE = "https://claude.ai/oauth/claude-code-client-metadata"
SHARED_SECRET_METHODS = ("client_secret_basic", "client_secret_post", "client_secret_jwt")
# A name that a client claims for itself is never one of these: the shown name of Claude and ChatGPT comes from the
# redirect, and that of Claude Code from its own metadata document.
CLAIMED_NAMES = re.compile(r"claude|chatgpt", re.I)
# Nor a whole name, in any case and with any spaces, that the owner's apps or the agents read as another channel or as
# part of the fleet: a device, a chat app, the owner, the hub, an agent's role, the product. Such a name shows as App.
RESERVED_NAMES = frozenset(("iphone", "ipad", "mac", "whatsapp", "discord", "owner", "hub", "manager", "founderizer",
                            "fleet", "app"))
TAILNET = ipaddress.ip_network("100.64.0.0/10")
NAT64 = ipaddress.ip_network("64:ff9b::/96")
SITE_LOCAL = ipaddress.ip_network("fec0::/10")


class Refused(Exception):
    """A request that the authorization server refuses. status: the HTTP status; error: the OAuth error code
    (invalid_request, invalid_grant, ...); the text is safe to show."""
    def __init__(self, status, error, text=""):
        super().__init__(text or error)
        self.status, self.error, self.text = status, error, text


class CimdRefused(Exception):
    """A Client ID Metadata Document that cannot be used. The text is safe to show and to log; it never holds the
    document."""


# ---------------------------------------------------------------- names, the two documents, the answers' headers


def check_name(name):
    """The hub's DNS name as the caller gives it (TAILNET_NAMES["names"][0]): lowercase, two labels or more, at most
    253 characters. Returns it; ValueError for anything else."""
    if not isinstance(name, str) or len(name) > 253 or not NAME.fullmatch(name):
        raise ValueError("the hub's DNS name must be a full lowercase name, for example hub-1.tail0000.ts.net")
    return name


def issuer(name):
    """https://<name>: the issuer, and the origin of every endpoint."""
    return "https://" + check_name(name)


def resource(name):
    """https://<name>/mcp: the protected resource, which every token is for."""
    return issuer(name) + "/mcp"


def resource_metadata_url(name):
    """The address of the protected resource metadata, with the resource's path (RFC 9728 3.1)."""
    return issuer(name) + "/.well-known/oauth-protected-resource/mcp"


def protected_resource_metadata(name):
    """GET /.well-known/oauth-protected-resource[/mcp] (RFC 9728): the same document on both paths."""
    return {"resource": resource(name), "authorization_servers": [issuer(name)],
            "scopes_supported": list(SCOPES), "bearer_methods_supported": ["header"], "resource_name": "Founderizer"}


def authorization_server_metadata(name):
    """GET /.well-known/oauth-authorization-server (RFC 8414). No offline_access: each code exchange gives a refresh
    token."""
    base = issuer(name)
    return {"issuer": base, "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token",
            "registration_endpoint": base + "/register", "revocation_endpoint": base + "/revoke",
            "response_types_supported": ["code"], "grant_types_supported": list(GRANTS),
            "code_challenge_methods_supported": ["S256"], "token_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"], "scopes_supported": list(SCOPES),
            "client_id_metadata_document_supported": True, "authorization_response_iss_parameter_supported": True}


def www_authenticate(name, insufficient=False):
    """The WWW-Authenticate value of a 401 of /mcp (no token, or one that does not work), or with insufficient of a 403
    for a tool above the connection's level (RFC 6750 3, MCP authorization "Scope Challenge Handling")."""
    where = resource_metadata_url(name)
    if insufficient:
        return f'Bearer error="insufficient_scope", scope="{" ".join(SCOPES)}", resource_metadata="{where}"'
    return f'Bearer resource_metadata="{where}", scope="{" ".join(SCOPES)}"'


def host_allowed(host, name):
    """True for a Host header that is the hub's full DNS name, bare or with :443, in any case."""
    return isinstance(host, str) and host.lower() in (check_name(name), name + ":443")


ORIGIN_NONE = ("/mcp", "/token", "/register", "/revoke")


def origin_allowed(path, method, origin, name):
    """Section 1 rule 8: /mcp, /token, /register and /revoke take no Origin at all (no browser page may call them);
    POST /authorize takes https://<name> or none. Other requests: any. origin: the header's value, or None."""
    if path in ORIGIN_NONE:
        return origin is None
    if path == "/authorize" and method == "POST":
        return origin is None or origin == issuer(name)
    return True


def json_headers():
    """The headers of every JSON answer."""
    return {"Content-Type": "application/json", "Cache-Control": "no-store"}


def html_headers(redirect_uri=None):
    """The headers of every HTML page. redirect_uri: the redirect of this request once it is proved, whose origin the
    form may go to (Chrome applies form-action to the redirect after a POST); None for an error page."""
    to = " " + redirect_origin(redirect_uri) if redirect_uri else ""
    return {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                                       f"form-action 'self'{to}; frame-ancestors 'none'"}


def error_body(error, text=""):
    """The JSON body of an OAuth error answer."""
    return dict({"error": error}, **({"error_description": text} if text else {}))


# ---------------------------------------------------------------- the redirect list


def redirect_match(uri):
    """The redirect list's entry of one URI: {"kind": "exact"|"pattern"|"loopback", "name", "host"}, or None when the
    URI is not on the list. name: "Claude", "ChatGPT", or None for loopback, whose shown name comes from the client
    (shown_name). host: what the sign-in page shows as where the app returns to."""
    if not isinstance(uri, str) or not 1 <= len(uri) <= URI_MAX:
        return None
    if uri in EXACT_REDIRECTS:
        return {"kind": "exact", "name": EXACT_REDIRECTS[uri], "host": urllib.parse.urlsplit(uri).hostname}
    for pattern, shown in PATTERN_REDIRECTS:
        if pattern.fullmatch(uri):
            return {"kind": "pattern", "name": shown, "host": urllib.parse.urlsplit(uri).hostname}
    m = LOOPBACK.fullmatch(uri)
    if m and (m.group(2) is None or int(m.group(2)) <= 65535):
        return {"kind": "loopback", "name": None, "host": m.group(1)}
    return None


def _loopback_parts(uri):
    m = LOOPBACK.fullmatch(uri) if isinstance(uri, str) else None
    return (m.group(1), m.group(3)) if m and (m.group(2) is None or int(m.group(2)) <= 65535) else None


def redirect_allowed(uri, registered):
    """The entry of registered (a client's redirect_uris) that a request's redirect_uri matches, or None. Exact
    string equality, or for loopback the same host and path with the port ignored (RFC 8252 7.3), because a native
    app takes a free port at each sign-in. The URI must also be on the redirect list itself."""
    if not redirect_match(uri) or not isinstance(registered, (list, tuple)):
        return None
    for entry in registered:
        if isinstance(entry, str) and entry == uri:
            return entry
    mine = _loopback_parts(uri)
    if mine:
        for entry in registered:
            if _loopback_parts(entry) == mine:
                return entry
    return None


def redirect_origin(uri):
    """scheme://host[:port] of a redirect on the list, for the page's form-action. ValueError for one not on it."""
    if not redirect_match(uri):
        raise ValueError("the redirect is not on the list")
    parts = urllib.parse.urlsplit(uri)
    return f"{parts.scheme}://{parts.netloc}"


def clean_name(value):
    """A client's own name as the page may show it: ASCII letters, digits and single spaces, at most 40 characters.
    "" for none, for a name that claims to be Claude or ChatGPT, whose names come from elsewhere, and for a reserved
    name (RESERVED_NAMES, as a whole name in any case and with any spaces)."""
    if not isinstance(value, str):
        return ""
    kept = " ".join("".join(c if (c.isascii() and c.isalnum()) or c == " " else " " for c in value).split())
    kept = kept[:NAME_MAX].strip()
    return "" if CLAIMED_NAMES.search(kept) or kept.replace(" ", "").lower() in RESERVED_NAMES else kept


def shown_name(redirect_uri, client_id, client_name=None):
    """The name of a connection, which the sign-in page, the owner's app and the agent's [owner via <name>] use.
    Claude or ChatGPT from the redirect; for a loopback redirect "Claude Code" with Claude Code's own metadata
    document, else the client's cleaned name, else "App". Never a client's claim to be Claude or ChatGPT, and never a
    reserved name (clean_name)."""
    found = redirect_match(redirect_uri)
    if not found:
        raise ValueError("the redirect is not on the list")
    if found["name"]:
        return found["name"]
    if client_id == CLAUDE_CODE:
        return "Claude Code"
    return clean_name(client_name) or "App"


# ---------------------------------------------------------------- clients: the CIMD list and dynamic registration


def client_kind(client_id):
    """"cimd" for a client_id on the CIMD list, "dcr" for one of the shape that POST /register makes, else None: a
    client_id of no known shape needs no database read."""
    if is_cimd(client_id):
        return "cimd"
    if isinstance(client_id, str) and DCR_CLIENT.fullmatch(client_id):
        return "dcr"
    return None


def is_cimd(client_id):
    """True for a client_id that is a metadata document on the CIMD list: https, a host of the list with no port and
    no user part, a path under /oauth/ of plain segments (no dot segment, no percent sign), no query, no fragment."""
    return isinstance(client_id, str) and len(client_id) <= URI_MAX and bool(CIMD.fullmatch(client_id))


def new_client_id():
    """A client_id for POST /register: 32 random bytes, base64url without padding (43 characters)."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()


def media_type(value):
    """The media type of a Content-Type value, lowercase, without its parameters; "" for none."""
    return value.split(";", 1)[0].strip().lower() if isinstance(value, str) else ""


def _no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("a key is there two times")
        out[key] = value
    return out


def _no_constant(text):
    raise ValueError("not JSON: " + text)


def load_json(raw):
    """A JSON object from bytes: UTF-8, no key two times, no NaN or Infinity. ValueError for anything else."""
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode("utf-8")
    value = json.loads(raw, object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    if not isinstance(value, dict):
        raise ValueError("not a JSON object")
    return value


def check_registration(content_type, body):
    """POST /register (RFC 7591), in the specification's order: application/json (415), a JSON object (400
    invalid_client_metadata), redirect_uris a list of 1 to 5 entries each on the redirect list (400
    invalid_redirect_uri), grant_types absent or within the two grants (400 invalid_client_metadata). Returns
    {"client_name", "redirect_uris", "grant_types"}, which the hub keeps; a token_endpoint_auth_method of the
    request is ignored, because the answer is always none. Raises Refused."""
    if media_type(content_type) != "application/json":
        raise Refused(415, "invalid_client_metadata", "the body must be application/json")
    try:
        meta = load_json(body)
    except (ValueError, UnicodeDecodeError):
        raise Refused(400, "invalid_client_metadata", "the body is not one JSON object") from None
    uris = meta.get("redirect_uris")
    if not isinstance(uris, list) or not 1 <= len(uris) <= REDIRECTS_MAX or \
            not all(isinstance(u, str) and redirect_match(u) for u in uris):
        raise Refused(400, "invalid_redirect_uri",
                      f"redirect_uris must be 1 to {REDIRECTS_MAX} addresses of Claude, ChatGPT or this computer")
    grants = meta.get("grant_types")
    if grants is not None and (not isinstance(grants, list) or not grants or
                               not all(isinstance(g, str) and g in GRANTS for g in grants)):
        raise Refused(400, "invalid_client_metadata", "grant_types may hold only authorization_code and refresh_token")
    return {"client_name": clean_name(meta.get("client_name")), "redirect_uris": list(dict.fromkeys(uris)),
            "grant_types": list(dict.fromkeys(grants)) if grants else list(GRANTS)}


def registration_answer(client_id, meta):
    """The 201 body of POST /register for a client that check_registration took."""
    return {"client_id": client_id, "client_name": meta["client_name"], "redirect_uris": meta["redirect_uris"],
            "grant_types": meta["grant_types"], "response_types": ["code"], "token_endpoint_auth_method": "none"}


def check_cimd_document(client_id, doc):
    """A fetched metadata document, checked: client_id equal to the address it came from, no client secret and no
    method of a shared secret, a way to use no client authentication, every redirect_uris entry on the redirect list,
    the authorization_code grant and the code response type. Returns {"client_id", "client_name", "redirect_uris",
    "grant_types"} (the grants of this server that the document names). Raises CimdRefused."""
    if not isinstance(doc, dict):
        raise CimdRefused("the metadata document is not a JSON object")
    if doc.get("client_id") != client_id:
        raise CimdRefused("the client_id of the metadata document is not its own address")
    if "client_secret" in doc or "client_secret_expires_at" in doc:
        raise CimdRefused("the metadata document holds a client secret")
    method, methods = doc.get("token_endpoint_auth_method"), doc.get("token_endpoint_auth_methods_supported")
    if methods is not None and (not isinstance(methods, list) or not all(isinstance(m, str) for m in methods)):
        raise CimdRefused("token_endpoint_auth_methods_supported is not a list of names")
    if method is not None and not isinstance(method, str):
        raise CimdRefused("token_endpoint_auth_method is not a name")
    if method in SHARED_SECRET_METHODS or any(m in SHARED_SECRET_METHODS for m in methods or ()):
        raise CimdRefused("the metadata document names a client secret method")
    if not (method in (None, "none") and methods is None or method == "none" or "none" in (methods or ())):
        raise CimdRefused("the client cannot connect without client authentication, which is all that this hub has")
    uris = doc.get("redirect_uris")
    if not isinstance(uris, list) or not 1 <= len(uris) <= CIMD_REDIRECTS_MAX or \
            not all(isinstance(u, str) and redirect_match(u) for u in uris):
        raise CimdRefused("a redirect of the metadata document is not on this hub's redirect list")
    grants = doc.get("grant_types")
    if grants is not None and (not isinstance(grants, list) or "authorization_code" not in grants):
        raise CimdRefused("the metadata document does not take an authorization code")
    kinds = doc.get("response_types")
    if kinds is not None and (not isinstance(kinds, list) or "code" not in kinds):
        raise CimdRefused("the metadata document does not take the code response type")
    return {"client_id": client_id, "client_name": clean_name(doc.get("client_name")),
            "redirect_uris": list(dict.fromkeys(uris)),
            "grant_types": [g for g in GRANTS if grants is None or g in grants]}


def address_refused(text):
    """Why a resolved address may not be fetched, or None for a public one. Refused: loopback, private (RFC 1918,
    fc00::/7), link-local, site-local (fec0::/10, which RFC 3879 deprecated and some networks still route inside),
    the tailnet's 100.64.0.0/10, multicast, unspecified, reserved, and every other address that is not global; an IPv6
    address that carries an IPv4 one (mapped, 6to4, NAT64) is judged by that one, and Teredo is refused."""
    try:
        ip = ipaddress.ip_address(text)
    except (ValueError, TypeError):
        return "not an address"
    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            return address_refused(str(ip.ipv4_mapped))
        if ip.teredo is not None:
            return "a Teredo address"
        if ip.sixtofour is not None:
            return address_refused(str(ip.sixtofour))
        if ip in NAT64:
            return address_refused(str(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)))
        if ip in SITE_LOCAL:
            return "a site-local address"
    if ip.version == 4 and ip in TAILNET:
        return "an address of the private network (100.64.0.0/10)"
    for test, why in (("is_loopback", "a loopback address"), ("is_unspecified", "an unspecified address"),
                      ("is_link_local", "a link-local address"), ("is_multicast", "a multicast address"),
                      ("is_private", "a private address"), ("is_reserved", "a reserved address")):
        if getattr(ip, test):
            return why
    if not ip.is_global:
        return "an address that is not public"
    return None


def resolve(host, port, timeout):
    """The addresses of a host name, by the system's resolver, at most timeout seconds: a list of address texts.
    OSError when there is no answer in time."""
    box = {}

    def ask():
        try:
            box["found"] = [i[4][0] for i in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]
        except OSError as e:
            box["error"] = e
    one = threading.Thread(target=ask, daemon=True)
    one.start()
    one.join(max(timeout, 0))
    if "found" not in box:
        raise OSError("the name has no answer")
    return box["found"]


def tls_connect(address, port, host, timeout):
    """A TLS connection to one checked address, with host as the SNI name and as the name the certificate must hold
    (the system's trust store, TLS 1.2 or newer). No proxy: a plain socket."""
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    raw = socket.socket(family, socket.SOCK_STREAM)
    try:
        raw.settimeout(timeout)
        raw.connect((address, port))
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context.wrap_socket(raw, server_hostname=host)
    except BaseException:
        raw.close()
        raise


def _dechunk(data, limit):
    """The body of a chunked answer (RFC 9112 7.1); trailers are dropped. CimdRefused for a body over limit or a
    broken one."""
    out, at = bytearray(), 0
    while True:
        end = data.find(b"\r\n", at)
        if end < 0 or end - at > 64:
            raise CimdRefused("the answer's chunks are broken")
        size_text = data[at:end].split(b";", 1)[0].strip()
        if not re.fullmatch(rb"[0-9A-Fa-f]{1,8}", size_text):
            raise CimdRefused("the answer's chunks are broken")
        size, at = int(size_text, 16), end + 2
        if size == 0:
            return bytes(out)
        if len(out) + size > limit:
            raise CimdRefused("the metadata document is too large")
        if len(data) < at + size + 2 or data[at + size:at + size + 2] != b"\r\n":
            raise CimdRefused("the answer's chunks are broken")
        out += data[at:at + size]
        at += size + 2


def read_answer(raw, limit=CIMD_MAX):
    """(status, {lowercase header: value}, body) of one HTTP/1.x answer read to its end. CimdRefused for a head over
    16 KiB, a header two times that frames the body, a coding other than identity, or a body over limit."""
    end = raw.find(b"\r\n\r\n")
    if end < 0 or end > CIMD_HEAD_MAX:
        raise CimdRefused("the answer has no complete head")
    lines = raw[:end].decode("latin-1").split("\r\n")
    m = re.fullmatch(r"HTTP/1\.[01] ([0-9]{3})(?: .*)?", lines[0])
    if not m:
        raise CimdRefused("the answer is not HTTP")
    head = {}
    for line in lines[1:]:
        key, colon, value = line.partition(":")
        if not colon or not key or key != key.strip():
            raise CimdRefused("the answer has a broken header")
        key = key.lower()
        if key in head and key in ("content-length", "transfer-encoding", "content-type", "content-encoding"):
            raise CimdRefused("the answer has a framing header two times")
        head[key] = value.strip()
    rest = raw[end + 4:]
    coding = head.get("content-encoding", "identity").lower()
    if coding != "identity":
        raise CimdRefused("the answer is compressed")
    if "transfer-encoding" in head:
        if head["transfer-encoding"].lower() != "chunked" or "content-length" in head:
            raise CimdRefused("the answer's framing is not plain")
        body = _dechunk(rest, limit)
    elif "content-length" in head:
        if not re.fullmatch(r"[0-9]{1,10}", head["content-length"]):
            raise CimdRefused("the answer's length is broken")
        size = int(head["content-length"])
        if size > limit:
            raise CimdRefused("the metadata document is too large")
        if len(rest) < size:
            raise CimdRefused("the answer ended early")
        body = rest[:size]
    else:
        body = rest
    if len(body) > limit:
        raise CimdRefused("the metadata document is too large")
    return int(m.group(1)), head, body


def fetch_cimd(client_id, resolver=resolve, connect=tls_connect, clock=time.monotonic, timeout=CIMD_TIMEOUT,
               limit=CIMD_MAX):
    """One Client ID Metadata Document, fetched and checked (check_cimd_document). The rules: a client_id on the CIMD
    list only; its name resolved once, and every address it gives checked (address_refused) before any connection;
    the connection to a checked address, with the host name for SNI and the certificate; no redirect followed (a 3xx
    is a refusal); no proxy; timeout seconds for the whole fetch; limit bytes; a 200 answer of JSON whose client_id
    is the address itself.

    resolver(host, port, seconds) -> [address text]; connect(address, port, host, seconds) -> a stream with
    sendall, recv, settimeout and close; clock() -> seconds. A test gives stand-ins, so that nothing reaches the
    network. Raises CimdRefused, whose text is safe to show."""
    if not is_cimd(client_id):
        raise CimdRefused("this client_id is not a metadata document of Claude or ChatGPT")
    parts = urllib.parse.urlsplit(client_id)
    host, path = parts.hostname, parts.path
    deadline = clock() + timeout

    def left():
        rest = deadline - clock()
        if rest <= 0:
            raise CimdRefused(f"the metadata document did not come in {timeout} seconds")
        return rest
    try:
        found = resolver(host, 443, left())
    except OSError:
        raise CimdRefused("the name of the metadata document has no address") from None
    if not isinstance(found, (list, tuple)) or not found:
        raise CimdRefused("the name of the metadata document has no address")
    addresses = list(dict.fromkeys(str(a) for a in found))
    for one in addresses:
        why = address_refused(one)
        if why:
            raise CimdRefused(f"the name of the metadata document gives {why}")
    stream = None
    for one in addresses:
        try:
            stream = connect(one, 443, host, left())
            break
        except (OSError, ssl.SSLError, ValueError):
            continue
    if stream is None:
        raise CimdRefused("the metadata document cannot be reached")
    data = bytearray()
    try:
        request = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {AGENT}\r\nAccept: application/json\r\n"
                   "Accept-Encoding: identity\r\nConnection: close\r\n\r\n").encode("ascii")
        stream.settimeout(left())
        stream.sendall(request)
        while True:
            stream.settimeout(left())
            chunk = stream.recv(16384)
            if not chunk:
                break
            data += chunk
            if len(data) > CIMD_HEAD_MAX + limit + 4096:
                raise CimdRefused("the metadata document is too large")
    except (OSError, ssl.SSLError, ValueError):
        raise CimdRefused("the metadata document could not be read") from None
    finally:
        try:
            stream.close()
        except OSError:
            pass
    status, head, body = read_answer(bytes(data), limit)
    if 300 <= status < 400:
        raise CimdRefused(f"the metadata document answered with a redirect ({status}), which is not followed")
    if status != 200:
        raise CimdRefused(f"the metadata document answered {status}")
    kind = media_type(head.get("content-type"))
    if kind != "application/json" and not (kind.startswith("application/") and kind.endswith("+json")):
        raise CimdRefused("the metadata document is not JSON")
    try:
        doc = load_json(body)
    except (ValueError, UnicodeDecodeError):
        raise CimdRefused("the metadata document is not one JSON object") from None
    return check_cimd_document(client_id, doc)


# ---------------------------------------------------------------- the authorization request, PKCE, the resource


def parse_query(query):
    """The fields of a query string or a form body as a dict. Refused (400 invalid_request) for a field that comes two
    times (OAuth 2.1: a parameter is never sent more than once), more than 30 fields, or text that is not UTF-8."""
    if isinstance(query, (bytes, bytearray)):
        try:
            query = bytes(query).decode("utf-8")
        except UnicodeDecodeError:
            raise Refused(400, "invalid_request", "the fields are not UTF-8") from None
    try:
        pairs = urllib.parse.parse_qsl(query or "", keep_blank_values=True, max_num_fields=FIELDS_MAX,
                                       errors="strict")
    except (ValueError, UnicodeDecodeError):
        raise Refused(400, "invalid_request", "the request has too many fields or a broken one") from None
    try:
        return _no_duplicates(pairs)
    except ValueError:
        raise Refused(400, "invalid_request", "a field of the request is there two times") from None


def parse_form(content_type, body):
    """The fields of POST /authorize, /token and /revoke: application/x-www-form-urlencoded (else 415), then
    parse_query. Raises Refused."""
    if media_type(content_type) != "application/x-www-form-urlencoded":
        raise Refused(415, "invalid_request", "the body must be application/x-www-form-urlencoded")
    return parse_query(body)


def check_challenge(challenge, method):
    """True for a PKCE challenge that this server takes: method S256, 43 to 128 characters of the unreserved set."""
    return method == "S256" and isinstance(challenge, str) and bool(UNRESERVED.fullmatch(challenge))


def s256(verifier):
    """BASE64URL(SHA256(ASCII(verifier))) without padding (RFC 7636 4.2)."""
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()


def verifier_matches(verifier, challenge):
    """True when a code_verifier of 43 to 128 unreserved characters gives the grant's S256 challenge. The comparison
    takes the same time for every wrong verifier."""
    if not isinstance(verifier, str) or not UNRESERVED.fullmatch(verifier) or not isinstance(challenge, str):
        return False
    return hmac.compare_digest(s256(verifier), challenge)


def resource_matches(value, name):
    """True for a resource parameter that is https://<name>/mcp, with the scheme and the host in any case (MCP
    authorization, "Canonical Server URI"). Refused: another path, a trailing slash, a port (also :443), a user part,
    a query, a fragment, and none."""
    if not isinstance(value, str) or not value or len(value) > URI_MAX or "?" in value or "#" in value or \
            any(c.isspace() for c in value):
        return False
    try:
        parts = urllib.parse.urlsplit(value)
    except ValueError:
        return False
    return parts.scheme.lower() == "https" and parts.netloc.lower() == check_name(name) and parts.path == "/mcp"


def check_authorize(params, name):
    """GET /authorize after the client and its redirect are proved, in the specification's order: response_type=code
    (unsupported_response_type), an S256 challenge (invalid_request), the resource (invalid_target, also when it is
    missing: RFC 8707 2), a state of at most 1000 characters (invalid_request). scope is free: unknown values are
    ignored, and the level comes from the owner's code. Returns {"state", "code_challenge", "resource"}. Raises
    Refused, whose error goes to the redirect (error_redirect)."""
    if params.get("response_type") != "code":
        raise Refused(400, "unsupported_response_type", "response_type must be code")
    if not check_challenge(params.get("code_challenge"), params.get("code_challenge_method")):
        raise Refused(400, "invalid_request", "a PKCE challenge with the method S256 is needed")
    if not resource_matches(params.get("resource"), name):
        raise Refused(400, "invalid_target", "resource must be " + resource(name))
    state = params.get("state")
    if state is not None and len(state) > STATE_MAX:
        raise Refused(400, "invalid_request", "state is too long")
    return {"state": state, "code_challenge": params["code_challenge"], "resource": resource(name)}


def _with_query(uri, fields):
    return uri + ("&" if "?" in uri else "?") + urllib.parse.urlencode(fields)


def error_redirect(redirect_uri, error, state, name):
    """The redirect of an authorization error: redirect_uri?error=...&state=...&iss=... (RFC 6749 4.1.2.1, RFC 9207).
    state is left out when the request had none. Only for a redirect that redirect_allowed took."""
    if not redirect_match(redirect_uri):
        raise ValueError("the redirect is not on the list")
    fields = [("error", error)] + ([("state", state)] if state is not None else []) + [("iss", issuer(name))]
    return _with_query(redirect_uri, fields)


def code_redirect(redirect_uri, code, state, name):
    """The 303 target of an approval: redirect_uri?code=...&state=...&iss=https%3A%2F%2F<name>."""
    if not redirect_match(redirect_uri):
        raise ValueError("the redirect is not on the list")
    fields = [("code", code)] + ([("state", state)] if state is not None else []) + [("iss", issuer(name))]
    return _with_query(redirect_uri, fields)


# ---------------------------------------------------------------- tokens and the one-time code


def sha256_hex(text):
    """The SHA-256 of a raw value, as the hub keeps a token, a code, a grant or a page handle."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def new_secret():
    """(raw, sha256): one opaque value of 32 random bytes, base64url: an access token, a refresh token, an
    authorization code or a page handle. Only the SHA-256 is kept; the raw value goes out once."""
    raw = secrets.token_urlsafe(32)
    return raw, sha256_hex(raw)


def scope_of(level):
    """The scope of a level: "fleet.read" for read, "fleet.read fleet.act" for act. ValueError for another level."""
    if level not in LEVELS:
        raise ValueError("the level is read or act")
    return "fleet.read" if level == "read" else "fleet.read fleet.act"


def token_answer(access, refresh, level):
    """The 200 body of POST /token."""
    return {"access_token": access, "token_type": "Bearer", "expires_in": ACCESS_LIFE, "refresh_token": refresh,
            "scope": scope_of(level)}


def new_code():
    """The owner's one-time code: {"code": "ABCD-EFGH-JKLM", "sha256"}. 12 letters of CODE_ALPHABET (60 bits), so a
    guess has no real chance in the code's ten minutes and the hub keeps no count of wrong tries: no stranger can end
    the owner's code. The SHA-256 is of the normal form (normal_code), which is all that the hub keeps."""
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))
    return {"code": "-".join(raw[i:i + 4] for i in range(0, CODE_LENGTH, 4)), "sha256": sha256_hex(raw)}


def normal_code(text):
    """The normal form of a typed code: uppercase, with every character that is not a letter or a digit left out (case
    and dashes ignored, as hub.enroll_device). "" when the rest is not 12 letters of CODE_ALPHABET, so a wrong shape
    can never match."""
    if not isinstance(text, str) or len(text) > 64:
        return ""
    raw = re.sub(r"[^A-Z0-9]", "", text.upper())
    return raw if len(raw) == CODE_LENGTH and all(c in CODE_ALPHABET for c in raw) else ""


def code_sha256(text):
    """The SHA-256 of a typed code's normal form, or None for a code of no valid shape."""
    raw = normal_code(text)
    return sha256_hex(raw) if raw else None


# ---------------------------------------------------------------- the handle of a sign-in page

HANDLE_FIELDS = ("client", "redirect_uri", "state", "code_challenge", "resource", "name", "redirect_uris", "made")


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _handle_mac(key, payload):
    return hmac.new(key, b"founderizer connected apps handle 1\n" + payload, hashlib.sha256).digest()


def make_handle(key, fields, t0):
    """The handle of one sign-in page: the request's fields (HANDLE_FIELDS: the client, its proved redirect, state,
    the PKCE challenge, the resource, the shown name, the client's redirect list or None, and made, which is t0) as
    base64url JSON, a dot, and the HMAC-SHA256 of that JSON with key (bytes, the hub's own, which never goes out). No
    row: a flood of pages pushes nothing out. None when the handle would be longer than HANDLE_MAX."""
    body = {k: fields.get(k) for k in HANDLE_FIELDS if k != "made"}
    body["made"] = t0
    payload = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    handle = _b64(payload) + "." + _b64(_handle_mac(key, payload))
    return handle if len(handle) <= HANDLE_MAX else None


def read_handle(key, handle, t0):
    """The fields of a handle that make_handle made with key at most HANDLE_LIFE seconds before t0, or None: a
    handle of another shape, another key or changed fields (the HMAC is compared in constant time), or one too old."""
    if not isinstance(handle, str) or not 3 <= len(handle) <= HANDLE_MAX or handle.count(".") != 1:
        return None
    text, _, mac = handle.partition(".")
    try:
        payload, given = _unb64(text), _unb64(mac)
    except (ValueError, TypeError):
        return None
    if not hmac.compare_digest(_handle_mac(key, payload), given):
        return None
    try:
        body = load_json(payload)
    except (ValueError, UnicodeDecodeError):
        return None
    made = body.get("made")
    if set(body) != set(HANDLE_FIELDS) or isinstance(made, bool) or not isinstance(made, (int, float)) or \
            not t0 - HANDLE_LIFE <= made <= t0 + 5:
        return None
    return body
