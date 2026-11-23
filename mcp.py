"""The hub's client for the owner's own MCP servers (UI-API.md, "Custom MCP servers (owner feature mcp)").

Only hub.py imports it. Python standard library only. It does three things for a remote server: it finds the server's
OAuth endpoints (RFC 9728 and RFC 8414), it registers the hub as a client (RFC 7591) and it gets and refreshes the
owner's tokens (OAuth 2.1 with PKCE). It also asks a server for its tools, so that the owner sees what a connected
server gives. No redirect is followed, every address must be https (http only on 127.0.0.1), and each endpoint must be
on the host of its own authorization server: a token goes to no other host. Tests: test_mcp_api.py, against a stand-in
MCP server.
"""

import base64
import hashlib
import http.client
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 20                        # seconds for one call
AGENT = "founderizer-hub"
VERSION = "2025-06-18"              # the MCP protocol version that the hub asks for
PAGE_MAX = 256 * 1024               # the largest answer that the hub reads
TOOLS_MAX = 200                     # the most tool names that the hub keeps
LIFE = 400 * 24 * 3600              # the longest access-token life that the hub takes from a server (400 days)
LOST = "the answer of the MCP server was lost: the request can have reached it"
GRANTS = ("authorization_code", "refresh_token")
NO_OAUTH = "this MCP server has no OAuth metadata"      # a server that needs no Connect (hub: why "no_oauth")


class McpError(Exception):
    """An MCP or OAuth call without its result. The text is safe to show: it never holds a token, a secret, a code or
    a request body. status: the HTTP status, or None. reason: the server's short reason (invalid_grant, ...), or None.
    unknown: True only when the request can have arrived and its answer was lost. why: Fleet's own code of what it
    found, which the hub passes on in its refusal's `why` (no_oauth), or None."""
    def __init__(self, message, status=None, reason=None, unknown=False, why=None):
        super().__init__(message)
        self.status, self.reason, self.unknown, self.why = status, reason, unknown, why


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an answer (an McpError), never a second request: no token goes to another host."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))


def address(value, host=None):
    """One checked address, or None: https anywhere, http on 127.0.0.1 only, with a host, no user part and no
    fragment. host: the only host that this address may have."""
    if not isinstance(value, str) or not 1 <= len(value) <= 400 or any(c.isspace() for c in value):
        return None
    try:
        parts = urllib.parse.urlsplit(value)
    except ValueError:
        return None
    if parts.scheme == "http" and parts.hostname not in ("127.0.0.1", "localhost"):
        return None
    if parts.scheme not in ("https", "http") or not parts.hostname or parts.username or parts.password or parts.fragment:
        return None
    return value if host is None or parts.hostname == host else None


def _host(url):
    return urllib.parse.urlsplit(url).hostname


def _refused(e):
    """The McpError of an answer that is not 2xx, with the server's own reason when it gives one."""
    try:
        raw = e.read(8192) or b"{}"
    except (OSError, http.client.HTTPException):
        raw = b"{}"
    finally:
        e.close()
    reason, text = None, None
    try:
        answer = json.loads(raw)
    except ValueError:
        answer = None
    if isinstance(answer, dict):
        for key in ("error", "error_description", "message"):
            value = answer.get(key)
            if isinstance(value, str) and value:
                reason, text = (value, text or value) if key == "error" else (reason, value)
            elif isinstance(value, dict) and isinstance(value.get("message"), str):
                text = text or value["message"]
    words = " ".join((text or reason or "").split())[:200]
    return McpError(f"the MCP server refused the request ({e.code})" + (f": {words}" if words else ""),
                    status=e.code, reason=reason)


def _open(method, url, access=None, data=None, headers=None):
    """The open answer to one request. A failure before the whole request went out is not unknown; one after it is."""
    head = {"User-Agent": AGENT}
    if access is not None:
        head["Authorization"] = "Bearer " + access
    head.update(headers or {})
    try:
        return OPENER.open(urllib.request.Request(url, data=data, method=method, headers=head), timeout=TIMEOUT)
    except urllib.error.HTTPError as e:
        raise _refused(e) from None
    except urllib.error.URLError:
        raise McpError("the MCP server cannot be reached now") from None
    except (http.client.HTTPException, OSError):
        raise McpError(LOST, unknown=True) from None


def _json(method, url, access=None, body=None, form=None, headers=None):
    """(the JSON answer, the answer's headers). body: a JSON request body; form: form fields, in which a client secret
    goes and nowhere else. The headers come as the message object of the answer, whose get() does not look at the case
    of a name: a server may send Mcp-Session-Id in any case."""
    data, head = None, dict(headers or {})
    if body is not None:
        data, head["Content-Type"] = json.dumps(body).encode(), "application/json"
    elif form is not None:
        data = urllib.parse.urlencode(form).encode()
        head["Content-Type"] = "application/x-www-form-urlencoded"
    with _open(method, url, access, data, head) as r:
        try:
            raw, kind = r.read(PAGE_MAX + 1), (r.headers.get("Content-Type") or "").lower()
        except (OSError, http.client.HTTPException):
            raise McpError(LOST, unknown=True) from None
        got = r.headers
    if len(raw) > PAGE_MAX:
        raise McpError("the answer of the MCP server is too large")
    if "text/event-stream" in kind:         # streamable HTTP: the answer of one request comes as one event
        raw = b"".join(line.split(b":", 1)[1].strip() for line in raw.splitlines() if line.startswith(b"data:"))
    try:
        answer = json.loads(raw) if raw.strip() else {}
    except ValueError:
        answer = None
    if not isinstance(answer, dict):
        raise McpError("the MCP server gave no JSON answer")
    return answer, got


# OAuth: where the server sends the owner, and the hub's own client


def _metadata(url, path, unsure=None):
    """The metadata document at one well-known path of url's host, or None. Both forms are tried: the path of RFC 8414
    (the well-known part first) and the plain one, which many servers use. unsure: a list that gets each failure that
    is not a plain absence (no 404 or 410: an outage, a refusal, a timeout), so that a caller can tell "this server
    has none" from "this server did not answer now"."""
    parts = urllib.parse.urlsplit(url)
    base = f"{parts.scheme}://{parts.netloc}"
    folder = parts.path.rstrip("/")
    for place in ([f"{base}/.well-known/{path}{folder}"] if folder else []) + [f"{base}/.well-known/{path}"]:
        try:
            answer, _ = _json("GET", place, headers={"Accept": "application/json"})
        except McpError as e:
            if unsure is not None and e.status not in (404, 410):
                unsure.append(e)
            continue
        if answer:
            return answer
    return None


def discover(url):
    """The OAuth endpoints of one MCP server: {issuer, authorization_endpoint, token_endpoint, registration_endpoint,
    scopes, resource}. The server names its authorization servers (RFC 9728); without that document the server's own
    host is the authorization server, as a server that protects itself. Every endpoint must be on the host of its
    authorization server, so the hub sends a secret or a token to no other host."""
    if not address(url):
        raise McpError("the address of the MCP server must be https (http only on 127.0.0.1)")
    unsure = []         # an outage of the resource's document too: it may name an authorization server elsewhere
    resource = _metadata(url, "oauth-protected-resource", unsure) or {}
    servers = [s for s in resource.get("authorization_servers") or [] if address(s)]
    issuer = servers[0] if servers else f"{urllib.parse.urlsplit(url).scheme}://{urllib.parse.urlsplit(url).netloc}"
    found = _metadata(issuer, "oauth-authorization-server", unsure) or _metadata(issuer, "openid-configuration", unsure)
    if not found and unsure:            # no plain absence: the server did not answer now, which says nothing of OAuth
        raise McpError(f"the OAuth metadata of this MCP server cannot be read now: {unsure[0]}")
    if not found:
        raise McpError(NO_OAUTH + ": it needs no Connect, or it is not an OAuth server", why="no_oauth")
    host = _host(issuer)
    ends = {}
    for key in ("authorization_endpoint", "token_endpoint", "registration_endpoint"):
        value = found.get(key)
        ends[key] = address(value, host=host) if isinstance(value, str) else None
    if not ends["authorization_endpoint"] or not ends["token_endpoint"]:
        raise McpError(f"this MCP server gives no authorization and token endpoint on {host}")
    grants = found.get("grant_types_supported")
    if isinstance(grants, list) and "authorization_code" not in grants:
        raise McpError("this MCP server does not take an authorization code")
    scopes = [s for s in resource.get("scopes_supported") or found.get("scopes_supported") or []
              if isinstance(s, str) and s and not any(c.isspace() for c in s)][:20]
    return dict(ends, issuer=issuer, scopes=scopes,
                grants=[g for g in grants if isinstance(g, str)] if isinstance(grants, list) else [],
                resource=resource.get("resource") if address(str(resource.get("resource") or "")) else None)


def register(endpoint, redirect_uri, name="Founderizer", scopes=(), grants=()):
    """The hub as a new client of one authorization server (RFC 7591): {client_id, client_secret}. A server that gives
    no secret makes a public client, which PKCE protects. A server without this endpoint needs a client that the owner
    registers himself. grants: the grant types that this server has, so that a strict server takes the registration."""
    asked = [g for g in GRANTS if not grants or g in grants] or ["authorization_code"]
    answer, _ = _json("POST", endpoint, body={
        "client_name": name, "redirect_uris": [redirect_uri], "grant_types": asked,
        "response_types": ["code"], "token_endpoint_auth_method": "none",
        "application_type": "native", **({"scope": " ".join(scopes)} if scopes else {})})
    client_id = answer.get("client_id")
    if not isinstance(client_id, str) or not client_id or len(client_id) > 400:
        raise McpError("this MCP server gave no client_id")
    secret = answer.get("client_secret")
    return {"client_id": client_id,
            "client_secret": secret if isinstance(secret, str) and 0 < len(secret) <= 400 else None}


def pkce():
    """(verifier, challenge): a verifier of URL-safe characters and its S256 challenge."""
    verifier = secrets.token_urlsafe(48)
    return verifier, base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def consent_url(endpoint, client_id, redirect_uri, state, challenge, scopes=(), resource=None):
    """The address where the owner gives the hub access. resource: what the token is for (RFC 8707), so that a server
    that follows it gives a token for itself only."""
    query = {"client_id": client_id, "redirect_uri": redirect_uri, "response_type": "code", "state": state,
             "code_challenge": challenge, "code_challenge_method": "S256"}
    if scopes:
        query["scope"] = " ".join(scopes)
    if resource:
        query["resource"] = resource
    glue = "&" if urllib.parse.urlsplit(endpoint).query else "?"
    return endpoint + glue + urllib.parse.urlencode(query, quote_via=urllib.parse.quote)


# The text that a session's MCP file would replace (lifecycle.MCP_EXPANDS, which this file does not import), and each
# $, which Grok and OpenCode may take for a variable (lifecycle.MCP_LOOSE_RUNTIMES). Not RFC 6750's form alone: a
# token of a known service holds "!" (Salesforce's).
REPLACED = ("$", "{env:", "{file:")
# The words of such a token, and of one with a character that no header takes: the hub refused it, and a new sign-in
# gets the same kind of token
TOKEN_FORM_SAYS = ("the server gave an access token that holds $, {env: or {file:, or a character that no header "
                   "takes, so Fleet sends it to no session. A new sign-in gets the same kind of token: the server's "
                   "maker must change it")


def _tokens(answer, had=None):
    """The token fields of one OAuth answer. A server that gives no new refresh token keeps the one that it had; a
    server that gives none at all (an authorization_code server) gives its access token a long life instead, and the
    hub keeps that token until it ends."""
    access = answer.get("access_token")
    if not isinstance(access, str) or not access:
        raise McpError("this MCP server gave no access token")
    # A token is sent in a header: one that a session's file would replace would send a variable of the session with it
    # (the T6 of the F6 validation), and a character that no header takes makes the request fail
    if any(text in access for text in REPLACED) or any(c < " " or c > "~" for c in access):
        raise McpError(TOKEN_FORM_SAYS, why="token_form")
    seconds = answer.get("expires_in")
    seconds = seconds if isinstance(seconds, int) and not isinstance(seconds, bool) and 0 < seconds <= LIFE else 3600
    token = answer.get("refresh_token")
    return {"access_token": access, "expires_at": int(time.time()) + seconds,
            "refresh_token": token if isinstance(token, str) and token else had,
            "scopes": str(answer.get("scope") or "").split()}


def exchange(endpoint, client_id, client_secret, code, verifier, redirect_uri, resource=None):
    """The owner's tokens for the code of a finished Connect. refresh_token is None for a server that gives none: then
    its access token is the whole connection, and expires_at says when the owner must connect again."""
    fields = {"grant_type": "authorization_code", "client_id": client_id, "code": code, "code_verifier": verifier,
              "redirect_uri": redirect_uri}
    if client_secret:
        fields["client_secret"] = client_secret
    if resource:
        fields["resource"] = resource
    answer, _ = _json("POST", endpoint, form=fields)
    return _tokens(answer)


def refresh(endpoint, client_id, client_secret, refresh_token, resource=None, scopes=()):
    """A new access token from the saved refresh token. A refusal is an McpError with the server's reason."""
    fields = {"grant_type": "refresh_token", "client_id": client_id, "refresh_token": refresh_token}
    if client_secret:
        fields["client_secret"] = client_secret
    if resource:
        fields["resource"] = resource
    if scopes:
        fields["scope"] = " ".join(scopes)
    answer, _ = _json("POST", endpoint, form=fields)
    return _tokens(answer, had=refresh_token)


# The server itself: what it is and which tools it gives


def _rpc(url, access, method, params=None, number=None, session=None, version=VERSION):
    """One JSON-RPC call to the MCP server. A notification (no number) has no answer."""
    body = {"jsonrpc": "2.0", "method": method, "params": params or {}}
    if number is not None:
        body["id"] = number
    headers = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": version}
    if session:
        headers["Mcp-Session-Id"] = session
    answer, got = _json("POST", url, access=access, body=body, headers=headers)
    error = answer.get("error")
    if isinstance(error, dict):
        words = " ".join(str(error.get("message") or "").split())[:200]
        raise McpError(f"the MCP server refused {method}" + (f": {words}" if words else ""),
                       reason=str(error.get("code")) if error.get("code") is not None else None)
    result = answer.get("result")
    return (result if isinstance(result, dict) else {}), got.get("Mcp-Session-Id")


def check(url, access=None):
    """What one server says about itself: {"server", "version", "tools", "note"}. It is one initialize call, the
    notification that follows it, and one tools/list; note says why a tool list did not come. 401 means that the
    server wants a Connect."""
    first, session = _rpc(url, access, "initialize", number=1, params={
        "protocolVersion": VERSION, "capabilities": {},
        "clientInfo": {"name": "founderizer", "title": "Founderizer", "version": "1"}})
    version = first.get("protocolVersion") if isinstance(first.get("protocolVersion"), str) else VERSION
    info = first.get("serverInfo") if isinstance(first.get("serverInfo"), dict) else {}
    name = info.get("name") if isinstance(info.get("name"), str) else None
    tools, note = [], None
    try:
        _rpc(url, access, "notifications/initialized", session=session, version=version)
        listed, _ = _rpc(url, access, "tools/list", number=2, session=session, version=version)
        tools = [t["name"] for t in listed.get("tools") or []
                 if isinstance(t, dict) and isinstance(t.get("name"), str)][:TOOLS_MAX]
    except McpError as e:   # a server that gives no tool list is still connected; the session itself will list them
        note = str(e)
    if session:             # end the session: the hub keeps none
        try:
            _open("DELETE", url, access, headers={"Mcp-Session-Id": session, "MCP-Protocol-Version": version}).close()
        except McpError:
            pass
    return {"server": " ".join(str(name).split())[:60] if name else None,
            "version": " ".join(str(info.get("version") or "").split())[:40] or None, "tools": sorted(tools),
            "note": note}
