"""The hub's Google client: OAuth, Drive, Sheets and Gmail (UI-API.md, "Google Drive and Gmail (owner feature google)").

Only hub.py imports it. Python standard library only. Every URL starts with a value of HOSTS and no redirect is
followed, so the access token goes only to Google's hosts. Tests: test_google_api.py, against a stand-in Google server.
"""

import base64
import csv
import email.message
import email.policy
import hashlib
import html
import html.parser
import http.client
import io
import json
import mimetypes
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

HOSTS = {"auth": "https://accounts.google.com", "token": "https://oauth2.googleapis.com",
         "drive": "https://www.googleapis.com", "gmail": "https://gmail.googleapis.com",
         "sheets": "https://sheets.googleapis.com", "founderizer": "https://founderizer.com"}
SCOPES = ("https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/gmail.modify")
# Founderizer's own Google app (UI-API.md, "Founderizer's Google app"; the owner's yes of 15 November 2026): one Desktop
# client of the project "Founderizer" for every hub, so that a customer connects with no client file. The release
# brings its client ID. Google's token address wants its secret too (it answered 400 invalid_request and 401
# invalid_client without one, 15 November 2026), and GitHub reports a secret of that shape in public code to Google, so
# the secret is in no public repository: a hub asks founderizer.com for it (client_secret) and keeps it in its own
# Google file (the owner's choice of the same day). Google's own words for such a secret: desktop apps "are public
# clients and cannot keep secrets confidential", and the secret of an installed app "is obviously not treated as a
# secret".
CLIENT = {"client_id": "686555588972-bci1m25uqoil3qs9ks3pqscr4iarno6o.apps.googleusercontent.com",
          "client_secret": None}
CLIENT_PATH = "/google-client.json"     # on HOSTS["founderizer"]: {"client_id", "client_secret"} of CLIENT's app
VERIFIED = False                    # True once Google has verified the app: Google then shows no warning page
TIMEOUT = 30                        # seconds for one call
AGENT = "founderizer-hub"
SMALL = 5 * 1024 * 1024             # the largest multipart upload; a larger one is resumable
TEXT_MAX = 10 * 1024 * 1024         # the largest text file that drive_text reads

FOLDER = "application/vnd.google-apps.folder"
DOC = "application/vnd.google-apps.document"
SHEET = "application/vnd.google-apps.spreadsheet"
SLIDES = "application/vnd.google-apps.presentation"
DRAWING = "application/vnd.google-apps.drawing"
GOOGLE_TYPE = "application/vnd.google-apps."
TEXT_TYPES = ("application/json", "application/xml", "application/javascript", "application/x-yaml", "application/x-sh")
EXPORTS = {DOC: ("text/markdown", ".md"), SHEET: ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
           ".xlsx"), SLIDES: ("application/pdf", ".pdf"), DRAWING: ("image/png", ".png")}
FIELDS = "id,name,mimeType,modifiedTime,size,owners(emailAddress),shared,driveId,parents,webViewLink,trashed"
HEADERS = ("From", "To", "Cc", "Subject", "Date")
REASON = re.compile(r"[A-Za-z_]{1,64}")     # Google's reasons are words; a token, a secret or a code never fits
LOST = "Google's answer was lost: the request can have reached Google"


class GoogleError(Exception):
    """A Google call without its result. The text is safe to show: it never holds a token, a secret, a code or a
    request body. status: Google's HTTP status, or None. reason: Google's short reason (invalid_grant, notFound, ...),
    or None. unknown: True only when the request can have reached Google and its answer was lost."""
    def __init__(self, message, status=None, reason=None, unknown=False):
        super().__init__(message)
        self.status, self.reason, self.unknown = status, reason, unknown


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an answer (a GoogleError), never a second request: the token never goes to another host."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))


def _refused(e):
    """The GoogleError of an answer that is not 2xx, with Google's reason: the OAuth error field, else
    error.errors[0].reason, else error.status."""
    try:
        answer = json.loads(e.read(65536) or b"{}")
    except (ValueError, OSError, http.client.HTTPException):
        answer = {}
    finally:
        e.close()
    error = answer.get("error") if isinstance(answer, dict) else None
    if isinstance(error, dict):
        found = error.get("errors")
        first = found[0] if isinstance(found, list) and found and isinstance(found[0], dict) else {}
        candidates = [first.get("reason"), error.get("status")]
    else:
        candidates = [error]
    reason = next((c for c in candidates if isinstance(c, str) and REASON.fullmatch(c)), None)
    if 300 <= e.code < 400:
        return GoogleError(f"Google answered {e.code}, a redirect, which the hub does not follow", e.code, reason)
    return GoogleError(f"Google answered {e.code}" + (f": {reason}" if reason else ""), e.code, reason)


def _open(method, url, access=None, data=None, headers=None):
    """The open answer to one request. urllib gives a failure before the whole request went out (DNS, a refused
    connection, a connect timeout) as URLError: not unknown. A failure after it is unknown."""
    head = {"User-Agent": AGENT}
    if access is not None:
        head["Authorization"] = "Bearer " + access
    head.update(headers or {})
    try:
        return OPENER.open(urllib.request.Request(url, data=data, method=method, headers=head), timeout=TIMEOUT)
    except urllib.error.HTTPError as e:
        raise _refused(e) from None
    except urllib.error.URLError:
        raise GoogleError("Google cannot be reached now") from None
    except (http.client.HTTPException, OSError):
        raise GoogleError(LOST, unknown=True) from None


def _read(r):
    try:
        return r.read()
    except (http.client.HTTPException, OSError):
        raise GoogleError(LOST, unknown=True) from None


def _call(method, url, access=None, body=None, data=None, ctype=None):
    """Google's JSON answer ({} for an empty one). body: a JSON request body; data: bytes of the type ctype."""
    if body is not None:
        data, ctype = json.dumps(body).encode(), "application/json; charset=UTF-8"
    with _open(method, url, access, data, {"Content-Type": ctype} if ctype else None) as r:
        raw = _read(r)
    try:
        answer = json.loads(raw) if raw.strip() else {}
    except ValueError:
        answer = None
    if not isinstance(answer, dict):
        raise GoogleError(LOST, unknown=True)       # a 2xx that cannot be read: the call can have had its effect
    return answer


def _url(host, path, query=None):
    query = {k: v for k, v in (query or {}).items() if v is not None}
    return HOSTS[host] + path + ("?" + urllib.parse.urlencode(query, doseq=True, quote_via=urllib.parse.quote)
                                 if query else "")


def _q(part):
    return urllib.parse.quote(str(part), safe="")


# OAuth

def _token(path, fields):
    """A form POST to HOSTS["token"]: the client secret goes only in this body, and a field that is None (a client
    with no secret) is left out."""
    fields = {k: v for k, v in fields.items() if v is not None}
    return _call("POST", HOSTS["token"] + path, data=urllib.parse.urlencode(fields).encode(),
                 ctype="application/x-www-form-urlencoded")


def _tokens(answer):
    access = answer.get("access_token")
    if not isinstance(access, str) or not access:
        raise GoogleError("Google gave no access token")
    seconds = answer.get("expires_in")
    seconds = seconds if isinstance(seconds, int) and not isinstance(seconds, bool) else 3600
    return access, int(time.time()) + seconds, str(answer.get("scope") or "").split()


def pkce():
    """(verifier, challenge): a verifier of 64 URL-safe characters and its S256 challenge."""
    verifier = secrets.token_urlsafe(48)
    return verifier, base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def consent_url(client_id, redirect_uri, state, challenge, login_hint=None, scopes=SCOPES):
    """login_hint: the email of the account that Google offers first. scopes: the permissions that this Connect asks
    for (one service, or both). Google adds the ones that the account granted before (include_granted_scopes), so the
    account's one refresh token keeps every service that it has."""
    query = {"client_id": client_id, "redirect_uri": redirect_uri, "response_type": "code", "scope": " ".join(scopes),
             "include_granted_scopes": "true", "access_type": "offline", "prompt": "consent", "state": state,
             "code_challenge": challenge, "code_challenge_method": "S256"}
    if login_hint:
        query["login_hint"] = login_hint
    return HOSTS["auth"] + "/o/oauth2/v2/auth?" + urllib.parse.urlencode(query, quote_via=urllib.parse.quote)


def exchange(client_id, client_secret, code, verifier, redirect_uri):
    """client_secret: None for a client whose token address takes the client ID and the PKCE verifier alone."""
    answer = _token("/token", {"grant_type": "authorization_code", "client_id": client_id,
                               "client_secret": client_secret, "code": code, "code_verifier": verifier,
                               "redirect_uri": redirect_uri})
    access, expires_at, scopes = _tokens(answer)
    refresh_token = answer.get("refresh_token")
    if not isinstance(refresh_token, str) or not refresh_token:
        raise GoogleError("Google gave no refresh token")
    return {"refresh_token": refresh_token, "access_token": access, "expires_at": expires_at, "scopes": scopes}


def refresh(client_id, client_secret, refresh_token):
    """(access_token, expires_at, scopes). A refusal is a GoogleError with Google's reason (invalid_grant)."""
    return _tokens(_token("/token", {"grant_type": "refresh_token", "client_id": client_id,
                                     "client_secret": client_secret, "refresh_token": refresh_token}))


def revoke(token):
    _token("/revoke", {"token": token})


def client_secret():
    """The secret of CLIENT's app, from founderizer.com (HOSTS["founderizer"] + CLIENT_PATH), which keeps it in no
    public repository. The answer counts only when it names CLIENT's own client ID, so the site can give a hub no other
    app. A GoogleError when founderizer.com cannot be reached or answers anything else, whose text names
    founderizer.com (not Google) and never holds the answer."""
    try:
        answer = _call("GET", HOSTS["founderizer"] + CLIENT_PATH)
    except GoogleError as e:
        words = (f"founderizer.com answered {e.status}" if e.status else
                 "founderizer.com gave no readable answer" if e.unknown else "founderizer.com cannot be reached now")
        raise GoogleError(words, e.status) from None
    secret = answer.get("client_secret")
    if answer.get("client_id") != CLIENT.get("client_id") or not (
            isinstance(secret, str) and re.fullmatch(r"[!-~]{8,200}", secret)):
        raise GoogleError("founderizer.com gave no client secret of Founderizer's Google app")
    return secret


def account_email(access):
    """The account's email from Gmail; without the Gmail scope (403), from Drive."""
    try:
        found = _gmail(access, "GET", "/profile").get("emailAddress")
    except GoogleError as e:
        if e.status != 403:
            raise
        user = _call("GET", _url("drive", "/drive/v3/about", {"fields": "user(emailAddress)"}), access).get("user")
        found = user.get("emailAddress") if isinstance(user, dict) else None
    if not isinstance(found, str) or not found:
        raise GoogleError("Google gave no email address for the account")
    return found


# Drive

def _drive(access, method, path, query=None, body=None):
    return _call(method, _url("drive", "/drive/v3/files" + path, query), access, body)


def _file(d):
    """The dict FILE of a Drive file resource."""
    owners = d.get("owners") or []
    size = d.get("size")
    return {"id": d.get("id"), "name": d.get("name"), "mime": d.get("mimeType"), "modified": d.get("modifiedTime"),
            "size": int(size) if str(size).isdigit() else None,
            "owner": owners[0].get("emailAddress") if owners and isinstance(owners[0], dict) else None,
            "shared": bool(d.get("shared")), "drive_id": d.get("driveId"), "parents": list(d.get("parents") or []),
            "link": d.get("webViewLink"), "trashed": bool(d.get("trashed"))}


def _quoted(text):
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"


def drive_search(access, words=None, folder=None, page=None):
    q = ([f"fullText contains {_quoted(words)}"] if words else []) + \
        ([f"{_quoted(folder)} in parents"] if folder else []) + ["trashed = false"]
    found = _drive(access, "GET", "", {
        "q": " and ".join(q), "pageSize": 20, "pageToken": page, "corpora": "allDrives",
        "includeItemsFromAllDrives": "true", "supportsAllDrives": "true", "fields": f"nextPageToken,files({FIELDS})",
        "orderBy": None if words else "folder,name"})
    return {"files": [_file(f) for f in found.get("files") or []], "next": found.get("nextPageToken") or None}


def drive_file(access, file_id):
    return _file(_drive(access, "GET", "/" + _q(file_id), {"fields": FIELDS, "supportsAllDrives": "true"}))


def _media_url(file):
    return _url("drive", "/drive/v3/files/" + _q(file["id"]), {"alt": "media", "supportsAllDrives": "true"})


def _export_url(file, mime):
    return _url("drive", f"/drive/v3/files/{_q(file['id'])}/export", {"mimeType": mime})


def _csv(rows):
    out = io.StringIO()
    csv.writer(out, lineterminator="\n").writerows(rows)
    return out.getvalue()


def drive_text(access, file, range=None):
    """The text of a Doc (Markdown), a Sheet (CSV of its first sheet, or of range), Slides or a text file of at most
    TEXT_MAX bytes; None for every other file and for a folder."""
    mime = file.get("mime") or ""
    if mime == SHEET and range:
        return _csv(sheet_read(access, file["id"], range))
    export = {DOC: "text/markdown", SHEET: "text/csv", SLIDES: "text/plain"}.get(mime)
    if export:
        url = _export_url(file, export)
    elif (mime.startswith("text/") or mime in TEXT_TYPES) and file.get("size") is not None \
            and file["size"] <= TEXT_MAX:
        url = _media_url(file)
    else:
        return None
    with _open("GET", url, access) as r:
        return _read(r).decode("utf-8", "replace")


def drive_download(access, file):
    """(response, content_type, filename): the open response, which the caller reads in parts and closes."""
    mime, name = file.get("mime") or "", file.get("name") or file["id"]
    if mime in EXPORTS:
        ctype, ext = EXPORTS[mime]
        url, name = _export_url(file, ctype), name if name.lower().endswith(ext) else name + ext
    elif mime.startswith(GOOGLE_TYPE):
        raise GoogleError(f"Drive cannot download a file of the type {mime}")
    else:
        ctype, url = mime or "application/octet-stream", _media_url(file)
    return _open("GET", url, access), ctype, name


def _upload(access, method, path, meta, data, media):
    """A multipart upload up to SMALL bytes. Above it a resumable one: Google gives an address, which must be on
    HOSTS["drive"], and one PUT sends the bytes there."""
    if "\r" in media or "\n" in media:
        raise ValueError("the media type has a line break")
    path, query = "/upload/drive/v3/files" + path, {"fields": FIELDS, "supportsAllDrives": "true"}
    if len(data) <= SMALL:
        b = "fleet-" + uuid.uuid4().hex
        body = (f"--{b}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{json.dumps(meta)}\r\n"
                f"--{b}\r\nContent-Type: {media}\r\n\r\n").encode() + data + f"\r\n--{b}--\r\n".encode()
        return _file(_call(method, _url("drive", path, dict(query, uploadType="multipart")), access, data=body,
                           ctype=f"multipart/related; boundary={b}"))
    with _open(method, _url("drive", path, dict(query, uploadType="resumable")), access, json.dumps(meta).encode(),
               {"Content-Type": "application/json; charset=UTF-8", "X-Upload-Content-Type": media,
                "X-Upload-Content-Length": str(len(data))}) as r:
        _read(r)
        place = r.headers.get("Location") or ""
    if urllib.parse.urlsplit(place)[:2] != urllib.parse.urlsplit(HOSTS["drive"])[:2]:
        raise GoogleError("Google gave an upload address that is not on its Drive host")
    return _file(_call("PUT", place, access, data=data, ctype=media))


def drive_create(access, kind, name, folder=None, data=None, mime=None):
    """kind: folder (no data), doc (Markdown bytes), sheet (CSV bytes) or file (the bytes as they are)."""
    meta = {"name": name}
    if folder:
        meta["parents"] = [folder]
    if kind == "folder":
        meta["mimeType"] = FOLDER
        return _file(_drive(access, "POST", "", {"fields": FIELDS, "supportsAllDrives": "true"}, meta))
    if kind == "doc":
        meta["mimeType"], media = DOC, "text/markdown"
    elif kind == "sheet":
        meta["mimeType"], media = SHEET, "text/csv"
    elif kind == "file":
        media = mime or mimetypes.guess_type(name)[0] or "application/octet-stream"
    else:
        raise ValueError(f"unknown kind {kind!r}")
    return _upload(access, "POST", "", meta, data or b"", media)


def drive_update(access, file, data, mime):
    """New content for a file. For a Doc, data is Markdown (text/markdown) and Google converts it."""
    return _upload(access, "PATCH", "/" + _q(file["id"]), {}, data, mime)


def drive_patch(access, file, name=None, folder=None, trashed=None):
    """A new name; a move to folder (out of the file's other parents); trashed true or false."""
    body, query = {}, {"fields": FIELDS, "supportsAllDrives": "true"}
    if name is not None:
        body["name"] = name
    if trashed is not None:
        body["trashed"] = bool(trashed)
    if folder:
        query["addParents"] = folder
        old = [p for p in file.get("parents") or [] if p != folder]
        query["removeParents"] = ",".join(old) if old else None
    return _file(_drive(access, "PATCH", "/" + _q(file["id"]), query, body))


# Sheets

def _sheets(access, method, path, query=None, body=None):
    return _call(method, _url("sheets", "/v4/spreadsheets/" + path, query), access, body)


def sheet_read(access, file_id, range):
    found = _sheets(access, "GET", f"{_q(file_id)}/values/{_q(range)}")
    return [[str(v) for v in row] for row in found.get("values") or []]


def sheet_write(access, file_id, range, rows, append=False):
    body, path = {"majorDimension": "ROWS", "values": rows}, f"{_q(file_id)}/values/{_q(range)}"
    if append:
        found = _sheets(access, "POST", path + ":append", {"valueInputOption": "USER_ENTERED",
                                                            "insertDataOption": "INSERT_ROWS"}, body).get("updates")
        found = found if isinstance(found, dict) else {}
    else:
        found = _sheets(access, "PUT", path, {"valueInputOption": "USER_ENTERED"}, body)
    return {"range": found.get("updatedRange"), "rows": found.get("updatedRows") or 0,
            "cells": found.get("updatedCells") or 0}


# Gmail

def _gmail(access, method, path, query=None, body=None):
    return _call(method, _url("gmail", "/gmail/v1/users/me" + path, query), access, body)


def _labels(access):
    return [x for x in _gmail(access, "GET", "/labels").get("labels") or [] if isinstance(x, dict)]


def _headers(part):
    """The headers of a message part by their lower-case names; the first one of a name wins."""
    found = {}
    for x in (part or {}).get("headers") or []:
        found.setdefault(str(x.get("name") or "").lower(), str(x.get("value") or ""))
    return found


def _head(msg, names):
    h = _headers(msg.get("payload"))
    return {"id": msg.get("id"), "thread": msg.get("threadId"), "from": h.get("from", ""), "to": h.get("to", ""),
            "cc": h.get("cc", ""), "subject": h.get("subject", ""), "date": h.get("date", ""),
            "snippet": html.unescape(msg.get("snippet") or ""),
            "labels": [names.get(x, x) for x in msg.get("labelIds") or []]}


def _b64(data):
    try:
        return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    except ValueError:
        raise GoogleError("Google gave data that is not base64url") from None


def _decode(part):
    """The text of a part, in the charset of its Content-Type (UTF-8 without one), bad bytes replaced."""
    head = email.message.Message()
    head["Content-Type"] = _headers(part).get("content-type", "text/plain")
    data = _b64(str(part["body"]["data"]))
    try:
        text = data.decode(head.get_content_charset() or "utf-8", "replace")
    except LookupError:
        text = data.decode("utf-8", "replace")
    return text.replace("\r\n", "\n")


def _walk(part, plain, rich, files):
    body, mime = part.get("body") or {}, str(part.get("mimeType") or "").lower()
    if part.get("filename"):
        if body.get("attachmentId"):
            files.append({"id": body["attachmentId"], "name": part["filename"], "mime": mime,
                          "size": body.get("size") or 0})
        return
    if mime == "text/plain" and body.get("data"):
        plain.append(_decode(part))
    elif mime == "text/html" and body.get("data"):
        rich.append(_decode(part))
    for sub in part.get("parts") or []:
        _walk(sub, plain, rich, files)


class _Text(html.parser.HTMLParser):
    """HTML as text: a line break for br, p, div, li, tr and h1 to h6, a space for a table cell; no script or
    style."""
    BREAKS = {"br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6"}

    def __init__(self):
        super().__init__(convert_charrefs=True)     # entities are unescaped in the data
        self.parts, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.skip += 1
        elif tag in self.BREAKS:
            self.parts.append("\n")
        elif tag in ("td", "th"):
            self.parts.append(" ")

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.skip = max(0, self.skip - 1)
        elif tag in self.BREAKS and tag != "br":
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(re.sub(r"\s+", " ", data))


def _html_text(markup):
    parser = _Text()
    parser.feed(markup)
    parser.close()
    kept = []
    for line in (" ".join(x.split()) for x in "".join(parser.parts).split("\n")):
        if line or (kept and kept[-1]):         # at most one blank line in a row
            kept.append(line)
    return "\n".join(kept).strip()


def gmail_search(access, query, page=None):
    found = _gmail(access, "GET", "/messages", {"q": query, "maxResults": 20, "pageToken": page})
    ids = [m["id"] for m in found.get("messages") or [] if isinstance(m, dict) and m.get("id")]
    names = {x.get("id"): x.get("name") for x in _labels(access)} if ids else {}
    return {"messages": [_head(_gmail(access, "GET", "/messages/" + _q(i), {"format": "metadata",
                                                                            "metadataHeaders": HEADERS}), names)
                         for i in ids],
            "next": found.get("nextPageToken") or None}


def gmail_message(access, message_id):
    """HEAD, message_id, references, text (the text/plain parts; without one, the text/html part as text) and
    attachments ([{id, name, mime, size}])."""
    msg = _gmail(access, "GET", "/messages/" + _q(message_id), {"format": "full"})
    found = _head(msg, {x.get("id"): x.get("name") for x in _labels(access)})
    h, plain, rich, files = _headers(msg.get("payload")), [], [], []
    _walk(msg.get("payload") or {}, plain, rich, files)
    found.update({"message_id": h.get("message-id", ""), "references": h.get("references", ""),
                  "text": "\n\n".join(plain) if plain else "\n\n".join(_html_text(x) for x in rich),
                  "attachments": files})
    return found


def gmail_attachment(access, message_id, attachment_id):
    found = _gmail(access, "GET", f"/messages/{_q(message_id)}/attachments/{_q(attachment_id)}")
    return _b64(str(found.get("data") or ""))


# A read check of a Gmail label (the wake-on-events design, step 1): ids only, for the hub's read of a wake-up rule.
# No message is read, so no sender, subject or text of a mail comes back from these two.

def gmail_labels_by_name(access):
    """{name: id} of every label of the account, a system label under its id (INBOX) and a user label under its
    name: users.messages.list takes ids, and an id belongs to one mailbox."""
    return {str(x.get("name")): str(x.get("id")) for x in _labels(access) if x.get("id") and x.get("name")}


def gmail_ids(access, label_ids, after, before=None, limit=500):
    """([(thread id, message id)], whole): the messages that have all of label_ids and that are newer than the
    second `after` (and older than `before`), at most `limit` of them. whole is False when Gmail has more, so that
    the caller can refuse the answer: a cut answer is never used. One call of 5 quota units for each page of 500. A
    list that does not end in 20 pages is a GoogleError."""
    query = f"after:{int(after)}" + (f" before:{int(before)}" if before is not None else "")
    found, page = [], None
    for _ in range(20):         # a bound on the pages, also for short ones: a list that never ends is an error
        answer = _gmail(access, "GET", "/messages", {"labelIds": list(label_ids), "q": query,
                                                    "maxResults": min(500, limit + 1 - len(found)), "pageToken": page})
        for m in answer.get("messages") or []:
            if isinstance(m, dict) and m.get("id") and m.get("threadId"):
                found.append((str(m["threadId"]), str(m["id"])))
        page = answer.get("nextPageToken")
        if len(found) > limit or (page and len(found) >= limit):
            return found[:limit], False
        if not page:
            return found, True
    raise GoogleError("Gmail's list of messages did not end")      # no answer to use: not "more than the limit"


def mime_message(to, cc, bcc, subject, body, reply=None):
    """The base64url raw of a plain-text UTF-8 email without From (Gmail sets the owner's address). reply: a dict of
    gmail_message, which the email answers in its thread. A header value with a line break is a ValueError."""
    msg = email.message.EmailMessage(policy=email.policy.SMTP)
    if reply and not (subject or "").strip():
        old = " ".join(str(reply.get("subject") or "").split())
        subject = old if old.lower().startswith("re:") else "Re: " + old
    for key, value in (("To", to), ("Cc", cc), ("Bcc", bcc), ("Subject", subject)):
        value = ", ".join(value) if isinstance(value, (list, tuple)) else (value or "")
        if "\r" in value or "\n" in value:
            raise ValueError(f"the {key} header has a line break")
        if value:
            msg[key] = value
    if reply and reply.get("message_id"):
        first = " ".join(str(reply["message_id"]).split())
        msg["In-Reply-To"] = first
        msg["References"] = " ".join((str(reply.get("references") or "") + " " + first).split())
    msg.set_content(body)
    return base64.urlsafe_b64encode(msg.as_bytes()).decode()


def _message(raw, thread):
    return dict({"raw": raw}, **({"threadId": thread} if thread else {}))


def gmail_draft(access, raw, thread=None, draft_id=None):
    """A new draft, or with draft_id new content for that draft."""
    message = _message(raw, thread)
    if draft_id is None:
        found = _gmail(access, "POST", "/drafts", body={"message": message})
    else:
        found = _gmail(access, "PUT", "/drafts/" + _q(draft_id), body={"id": draft_id, "message": message})
    sent = found.get("message") if isinstance(found.get("message"), dict) else {}
    return {"draft_id": found.get("id"), "message_id": sent.get("id"), "thread": sent.get("threadId")}


def gmail_send(access, raw, thread=None):
    found = _gmail(access, "POST", "/messages/send", body=_message(raw, thread))
    return {"id": found.get("id"), "thread": found.get("threadId")}


def gmail_label_ids(access, names, create=False):
    """{name: id}: a system name as it is (INBOX, UNREAD, STARRED, IMPORTANT); a user label by its name, without
    regard to case. With create, a missing user label is made; without it, a missing name is not in the answer."""
    labels = _labels(access)
    system = {x.get("id") for x in labels if x.get("type") == "system"}
    user = {}
    for x in labels:
        if x.get("type") != "system":
            user.setdefault(str(x.get("name") or "").casefold(), x.get("id"))
    found = {}
    for name in names:
        if name in system:
            found[name] = name
        elif name.casefold() in user:
            found[name] = user[name.casefold()]
        elif create:
            made = _gmail(access, "POST", "/labels", body={"name": name, "labelListVisibility": "labelShow",
                                                           "messageListVisibility": "show"}).get("id")
            if not isinstance(made, str) or not made:
                raise GoogleError("Google gave no label ID")
            found[name] = user[name.casefold()] = made
    return found


def gmail_modify(access, ids, add=(), remove=()):
    _gmail(access, "POST", "/messages/batchModify",
           body={"ids": list(ids), "addLabelIds": list(add), "removeLabelIds": list(remove)})


def gmail_trash(access, message_id, trash=True):
    _gmail(access, "POST", f"/messages/{_q(message_id)}/{'trash' if trash else 'untrash'}")
