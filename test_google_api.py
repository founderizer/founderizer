"""Tests of google.py against a stand-in Google server on 127.0.0.1 (UI-API.md, "Google Drive and Gmail").

python3 -m unittest -v test_google_api
"""

import base64
import email
import email.policy
import hashlib
import http.server
import json
import socket
import threading
import time
import unittest
import urllib.parse

import google

ACCESS, REFRESH, SECRET, CODE = "ya29.ACCESS-TOKEN", "1//0gREFRESH-TOKEN", "GOCSPX-CLIENT-SECRET", "4/0AbAUTH-CODE"
SECRETS = (ACCESS, REFRESH, SECRET, CODE)
NOT_FOUND = {"error": {"code": 404, "message": "Not found", "errors": [{"reason": "notFound"}], "status": "NOT_FOUND"}}

DOC_ITEM = {"id": "d1", "name": "Plan", "mimeType": google.DOC, "modifiedTime": "2026-10-16T10:00:00.000Z",
            "owners": [{"emailAddress": "owner@example.com"}], "shared": False, "parents": ["root1"],
            "webViewLink": "https://docs.google.com/document/d/d1/edit", "trashed": False}
PDF_ITEM = {"id": "p1", "name": "Costs.pdf", "mimeType": "application/pdf", "modifiedTime": "2026-10-15T09:00:00.000Z",
            "size": "2048", "shared": True, "driveId": "sd1", "parents": ["f1"],
            "webViewLink": "https://drive.google.com/file/d/p1/view", "trashed": False}
DOC_FILE = {"id": "d1", "name": "Plan", "mime": google.DOC, "modified": "2026-10-16T10:00:00.000Z", "size": None,
            "owner": "owner@example.com", "shared": False, "drive_id": None, "parents": ["root1"],
            "link": "https://docs.google.com/document/d/d1/edit", "trashed": False}
PDF_FILE = {"id": "p1", "name": "Costs.pdf", "mime": "application/pdf", "modified": "2026-10-15T09:00:00.000Z",
            "size": 2048, "owner": None, "shared": True, "drive_id": "sd1", "parents": ["f1"],
            "link": "https://drive.google.com/file/d/p1/view", "trashed": False}
LABELS = {"labels": [{"id": "INBOX", "name": "INBOX", "type": "system"},
                     {"id": "UNREAD", "name": "UNREAD", "type": "system"},
                     {"id": "STARRED", "name": "STARRED", "type": "system"},
                     {"id": "IMPORTANT", "name": "IMPORTANT", "type": "system"},
                     {"id": "Label_1", "name": "Clients", "type": "user"},
                     {"id": "Label_2", "name": "Projects/Fleet", "type": "user"}]}


def item(file_id, mime, name="x", size=None, parents=()):
    """A FILE dict as google.drive_file gives it."""
    return {"id": file_id, "name": name, "mime": mime, "modified": None, "size": size, "owner": None, "shared": False,
            "drive_id": None, "parents": list(parents), "link": None, "trashed": False}


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def args(req):
    """The query of a request: one value as it is, several as a list."""
    return {k: v[0] if len(v) == 1 else v for k, v in req["query"].items()}


def form(req):
    return dict(urllib.parse.parse_qsl(req["body"].decode(), strict_parsing=True))


def body(req):
    return json.loads(req["body"])


def multipart(req):
    """[(Content-Type, bytes)] of the parts of a multipart/related request."""
    boundary = req["headers"]["Content-Type"].split("boundary=", 1)[1].encode()
    chunks = req["body"].split(b"--" + boundary)
    assert chunks[0] == b"" and chunks[-1] == b"--\r\n", chunks[-1]
    parts = []
    for chunk in chunks[1:-1]:
        head, _, content = chunk[2:].partition(b"\r\n\r\n")
        assert content.endswith(b"\r\n")
        parts.append((head.decode().split(": ", 1)[1], content[:-2]))
    return parts


def close(handler, req):
    """Read the request and close the connection without an answer."""


def slow(handler, req):
    time.sleep(1.5)


def short(handler, req):
    handler.send_response(200)
    handler.send_header("Content-Length", "100")
    handler.end_headers()
    handler.wfile.write(b'{"id": "m1"')


class StandIn:
    """A stand-in Google server: it records each request and answers it with what a test set for its method and
    path (JSON for a dict, bytes as they are, or a function that answers itself); else 404."""
    def __init__(self):
        self.routes, self.requests = {}, []
        stand_in = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def answer(self):
                parts = urllib.parse.urlsplit(self.path)
                req = {"method": self.command, "path": parts.path, "headers": self.headers,
                       "query": urllib.parse.parse_qs(parts.query, keep_blank_values=True),
                       "body": self.rfile.read(int(self.headers.get("Content-Length") or 0))}
                stand_in.requests.append(req)
                self.close_connection = True
                route = stand_in.routes.get((self.command, parts.path), (404, {}, NOT_FOUND))
                if callable(route):
                    return route(self, req)
                status, headers, answer = route
                data = answer if isinstance(answer, bytes) else b"" if answer is None else json.dumps(answer).encode()
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                if not isinstance(answer, bytes):
                    self.send_header("Content-Type", "application/json; charset=UTF-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = answer

            def log_message(self, *a):
                pass

        class Server(http.server.ThreadingHTTPServer):
            def handle_error(self, request, client_address):
                pass

        self.server = Server(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:%d" % self.server.server_port
        threading.Thread(target=self.server.serve_forever, args=(0.05,), daemon=True).start()

    def on(self, method, path, answer=None, status=200, headers=None):
        self.routes[(method, path)] = answer if callable(answer) else (status, headers or {}, answer)

    def find(self, method, path):
        return [r for r in self.requests if r["method"] == method and r["path"] == path]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class GoogleApiTest(unittest.TestCase):
    def setUp(self):
        self.g = StandIn()
        self.saved = dict(google.HOSTS), google.TIMEOUT
        google.HOSTS.update({k: self.g.url for k in google.HOSTS})
        google.TIMEOUT = 5

    def tearDown(self):
        google.HOSTS.update(self.saved[0])
        google.TIMEOUT = self.saved[1]
        self.g.close()
        for req in self.g.requests:
            self.assertEqual(req["headers"]["User-Agent"], "founderizer-hub")
            if req["path"] in ("/token", "/revoke"):
                self.assertIsNone(req["headers"].get("Authorization"))
            else:
                self.assertEqual(req["headers"]["Authorization"], "Bearer " + ACCESS)
            for secret in (SECRET, REFRESH, CODE):
                self.assertNotIn(secret, req["path"] + str(req["query"]) + str(dict(req["headers"])))

    def assertSafe(self, error):
        for text in (str(error), repr(error), str(error.args), str(error.reason)):
            for secret in SECRETS:
                self.assertNotIn(secret, text)

    def refused(self, call, *a, **kw):
        with self.assertRaises(google.GoogleError) as caught:
            call(*a, **kw)
        self.assertSafe(caught.exception)
        return caught.exception

    # OAuth

    def test_pkce(self):
        verifier, challenge = google.pkce()
        self.assertRegex(verifier, r"^[A-Za-z0-9_-]{64}$")
        self.assertEqual(challenge, b64(hashlib.sha256(verifier.encode()).digest()))
        self.assertNotEqual(google.pkce()[0], verifier)

    def test_consent_url(self):
        url = google.consent_url("123-abc.apps.googleusercontent.com", "http://127.0.0.1:53682/", "STATE-1", "CH-1")
        self.assertTrue(url.startswith(self.g.url + "/o/oauth2/v2/auth?"), url)
        self.assertEqual(dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query, strict_parsing=True)), {
            "client_id": "123-abc.apps.googleusercontent.com", "redirect_uri": "http://127.0.0.1:53682/",
            "response_type": "code",
            "scope": "https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/gmail.modify",
            "include_granted_scopes": "true", "access_type": "offline", "prompt": "consent", "state": "STATE-1",
            "code_challenge": "CH-1", "code_challenge_method": "S256"})
        self.assertNotIn("login_hint", url)
        url = google.consent_url("cid", "http://127.0.0.1:53682/", "STATE-2", "CH-2", login_hint="ana+work@example.com")
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query, strict_parsing=True))
        self.assertEqual((query["login_hint"], query["state"], query["prompt"]), ("ana+work@example.com", "STATE-2",
                                                                                  "consent"))
        self.assertEqual(len(query), 11)
        # One service: Google asks for that permission only, and keeps what the account granted before.
        url = google.consent_url("cid", "http://127.0.0.1:53682/", "STATE-3", "CH-3",
                                 scopes=["https://www.googleapis.com/auth/gmail.modify"])
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query, strict_parsing=True))
        self.assertEqual((query["scope"], query["include_granted_scopes"]),
                         ("https://www.googleapis.com/auth/gmail.modify", "true"))
        self.assertEqual(self.g.requests, [])

    def test_exchange(self):
        self.g.on("POST", "/token", {"access_token": ACCESS, "expires_in": 3599, "refresh_token": REFRESH,
                                     "scope": " ".join(google.SCOPES), "token_type": "Bearer"})
        t0 = time.time()
        got = google.exchange("cid", SECRET, CODE, "VERIFIER", "http://127.0.0.1:53682/")
        self.assertEqual({k: got[k] for k in ("refresh_token", "access_token", "scopes")},
                         {"refresh_token": REFRESH, "access_token": ACCESS, "scopes": list(google.SCOPES)})
        self.assertAlmostEqual(got["expires_at"], t0 + 3599, delta=2)
        req = self.g.requests[-1]
        self.assertEqual(req["query"], {})
        self.assertEqual(req["headers"]["Content-Type"], "application/x-www-form-urlencoded")
        self.assertEqual(form(req), {"grant_type": "authorization_code", "client_id": "cid", "client_secret": SECRET,
                                     "code": CODE, "code_verifier": "VERIFIER",
                                     "redirect_uri": "http://127.0.0.1:53682/"})
        self.g.on("POST", "/token", {"access_token": ACCESS, "expires_in": 3599, "scope": google.SCOPES[0]})
        error = self.refused(google.exchange, "cid", SECRET, CODE, "VERIFIER", "http://127.0.0.1:53682/")
        self.assertFalse(error.unknown)

    def test_refresh(self):
        self.g.on("POST", "/token", {"access_token": ACCESS, "expires_in": 3599, "scope": google.SCOPES[1]})
        access, expires_at, scopes = google.refresh("cid", SECRET, REFRESH)
        self.assertEqual((access, scopes), (ACCESS, [google.SCOPES[1]]))
        self.assertAlmostEqual(expires_at, time.time() + 3599, delta=2)
        self.assertEqual(form(self.g.requests[-1]), {"grant_type": "refresh_token", "client_id": "cid",
                                                     "client_secret": SECRET, "refresh_token": REFRESH})
        self.g.on("POST", "/token", {"error": "invalid_grant", "error_description": "Token has been expired or revoked."},
                  400)
        error = self.refused(google.refresh, "cid", SECRET, REFRESH)
        self.assertEqual((error.status, error.reason, error.unknown), (400, "invalid_grant", False))

    def test_revoke(self):
        self.g.on("POST", "/revoke", {})
        self.assertIsNone(google.revoke(REFRESH))
        req = self.g.requests[-1]
        self.assertEqual((form(req), req["query"]), ({"token": REFRESH}, {}))
        self.g.on("POST", "/revoke", {"error": "invalid_token", "error_description": "Bad Request"}, 400)
        self.assertEqual(self.refused(google.revoke, REFRESH).reason, "invalid_token")

    def test_account_email(self):
        self.g.on("GET", "/gmail/v1/users/me/profile", {"emailAddress": "owner@example.com", "messagesTotal": 3})
        self.assertEqual(google.account_email(ACCESS), "owner@example.com")
        self.assertEqual(self.g.find("GET", "/drive/v3/about"), [])
        self.g.on("GET", "/gmail/v1/users/me/profile", {"error": {"code": 403, "errors": [
            {"reason": "insufficientPermissions"}], "status": "PERMISSION_DENIED"}}, 403)
        self.g.on("GET", "/drive/v3/about", {"user": {"emailAddress": "drive@example.com"}})
        self.assertEqual(google.account_email(ACCESS), "drive@example.com")
        self.assertEqual(args(self.g.find("GET", "/drive/v3/about")[0]), {"fields": "user(emailAddress)"})
        self.g.on("GET", "/gmail/v1/users/me/profile", {"error": {"code": 401, "status": "UNAUTHENTICATED"}}, 401)
        self.assertEqual(self.refused(google.account_email, ACCESS).status, 401)
        self.assertEqual(len(self.g.find("GET", "/drive/v3/about")), 1)

    # Drive

    def test_drive_search(self):
        self.g.on("GET", "/drive/v3/files", {"files": [DOC_ITEM, PDF_ITEM], "nextPageToken": "NEXT"})
        got = google.drive_search(ACCESS, words=r"it's a\b", folder="f1", page="P2")
        self.assertEqual(got, {"files": [DOC_FILE, PDF_FILE], "next": "NEXT"})
        self.assertEqual(args(self.g.requests[-1]), {
            "q": r"fullText contains 'it\'s a\\b' and 'f1' in parents and trashed = false", "pageSize": "20",
            "pageToken": "P2", "corpora": "allDrives", "includeItemsFromAllDrives": "true",
            "supportsAllDrives": "true", "fields": "nextPageToken,files(id,name,mimeType,modifiedTime,size,"
                                                   "owners(emailAddress),shared,driveId,parents,webViewLink,trashed)"})
        self.g.on("GET", "/drive/v3/files", {"files": []})
        self.assertEqual(google.drive_search(ACCESS, folder="f1"), {"files": [], "next": None})
        query = args(self.g.requests[-1])
        self.assertEqual((query["q"], query["orderBy"]), ("'f1' in parents and trashed = false", "folder,name"))
        self.assertNotIn("pageToken", query)
        google.drive_search(ACCESS, words="costs")
        query = args(self.g.requests[-1])
        self.assertEqual(query["q"], "fullText contains 'costs' and trashed = false")
        self.assertNotIn("orderBy", query)

    def test_drive_file(self):
        self.g.on("GET", "/drive/v3/files/p1", PDF_ITEM)
        self.assertEqual(google.drive_file(ACCESS, "p1"), PDF_FILE)
        self.assertEqual(args(self.g.requests[-1]), {"fields": google.FIELDS, "supportsAllDrives": "true"})
        self.assertEqual(self.refused(google.drive_file, ACCESS, "gone").reason, "notFound")

    def test_drive_text(self):
        def text(file, range=None):
            return google.drive_text(ACCESS, file, range)
        self.g.on("GET", "/drive/v3/files/d1/export", b"# Plan\n\nRead me.\n", headers={"Content-Type": "text/markdown"})
        self.assertEqual(text(item("d1", google.DOC)), "# Plan\n\nRead me.\n")
        self.assertEqual(args(self.g.requests[-1]), {"mimeType": "text/markdown"})
        self.g.on("GET", "/drive/v3/files/s1/export", b"a,b\r\n1,2\r\n", headers={"Content-Type": "text/csv"})
        self.assertEqual(text(item("s1", google.SHEET)), "a,b\r\n1,2\r\n")
        self.assertEqual(args(self.g.requests[-1]), {"mimeType": "text/csv"})
        self.g.on("GET", "/v4/spreadsheets/s1/values/Costs%21A1%3AB2",
                  {"range": "Costs!A1:B2", "majorDimension": "ROWS", "values": [["Item", "Cost, EUR"], ["Taxi", "12"]]})
        self.assertEqual(text(item("s1", google.SHEET), "Costs!A1:B2"), 'Item,"Cost, EUR"\nTaxi,12\n')
        self.g.on("GET", "/drive/v3/files/k1/export", b"Slide one\n", headers={"Content-Type": "text/plain"})
        self.assertEqual(text(item("k1", google.SLIDES)), "Slide one\n")
        self.assertEqual(args(self.g.requests[-1]), {"mimeType": "text/plain"})
        self.g.on("GET", "/drive/v3/files/t1", b"ok \xff\n", headers={"Content-Type": "text/plain"})
        self.assertEqual(text(item("t1", "text/plain", size=5)), "ok �\n")
        self.assertEqual(args(self.g.requests[-1]), {"alt": "media", "supportsAllDrives": "true"})
        self.g.on("GET", "/drive/v3/files/j1", b'{"a": 1}', headers={"Content-Type": "application/json"})
        self.assertEqual(text(item("j1", "application/json", size=8)), '{"a": 1}')
        before = len(self.g.requests)
        self.assertIsNone(text(item("i1", "image/png", size=10)))
        self.assertIsNone(text(item("f1", google.FOLDER)))
        self.assertIsNone(text(item("o1", "application/vnd.google-apps.form")))
        self.assertIsNone(text(item("t2", "text/plain", size=google.TEXT_MAX + 1)))
        self.assertEqual(len(self.g.requests), before)

    def test_drive_download(self):
        for file_id, mime, name, ctype, filename in (
                ("d1", google.DOC, "Plan", "text/markdown", "Plan.md"),
                ("s1", google.SHEET, "Costs", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                 "Costs.xlsx"),
                ("k1", google.SLIDES, "Deck", "application/pdf", "Deck.pdf"),
                ("w1", google.DRAWING, "Map", "image/png", "Map.png")):
            self.g.on("GET", f"/drive/v3/files/{file_id}/export", b"BYTES-" + file_id.encode(),
                      headers={"Content-Type": ctype})
            response, got_type, got_name = google.drive_download(ACCESS, item(file_id, mime, name))
            with response:
                self.assertEqual(response.read(3) + response.read(), b"BYTES-" + file_id.encode())
            self.assertEqual((got_type, got_name), (ctype, filename))
            self.assertEqual(args(self.g.requests[-1]), {"mimeType": ctype})
        self.g.on("GET", "/drive/v3/files/p1", b"%PDF-1.7 \x00\xff", headers={"Content-Type": "application/pdf"})
        response, got_type, got_name = google.drive_download(ACCESS, PDF_FILE)
        with response:
            self.assertEqual(response.read(), b"%PDF-1.7 \x00\xff")
        self.assertEqual((got_type, got_name), ("application/pdf", "Costs.pdf"))
        self.assertEqual(args(self.g.requests[-1]), {"alt": "media", "supportsAllDrives": "true"})
        before = len(self.g.requests)
        error = self.refused(google.drive_download, ACCESS, item("o1", "application/vnd.google-apps.form", "Poll"))
        self.assertEqual((error.status, error.unknown, len(self.g.requests)), (None, False, before))

    def test_drive_create(self):
        self.g.on("POST", "/drive/v3/files", dict(DOC_ITEM, id="f9", name="Reports", mimeType=google.FOLDER))
        self.assertEqual(google.drive_create(ACCESS, "folder", "Reports", folder="f1")["id"], "f9")
        req = self.g.requests[-1]
        self.assertEqual(body(req), {"name": "Reports", "parents": ["f1"], "mimeType": google.FOLDER})
        self.assertTrue(req["headers"]["Content-Type"].startswith("application/json"))
        self.assertEqual(args(req), {"fields": google.FIELDS, "supportsAllDrives": "true"})

        self.g.on("POST", "/upload/drive/v3/files", DOC_ITEM)
        for kind, name, folder, data, mime, meta, media in (
                ("doc", "Notes", None, b"# Notes\n", None, {"name": "Notes", "mimeType": google.DOC}, "text/markdown"),
                ("sheet", "Costs", "f1", b"a,b\n1,2\n", None,
                 {"name": "Costs", "parents": ["f1"], "mimeType": google.SHEET}, "text/csv"),
                ("file", "blob.bin", None, b"\x00\xff\r\n--x", "application/x-thing", {"name": "blob.bin"},
                 "application/x-thing"),
                ("file", "report.pdf", None, b"%PDF", None, {"name": "report.pdf"}, "application/pdf"),
                ("file", "README", None, b"hi", None, {"name": "README"}, "application/octet-stream")):
            self.assertEqual(google.drive_create(ACCESS, kind, name, folder, data, mime), DOC_FILE)
            req = self.g.requests[-1]
            self.assertEqual(args(req), {"uploadType": "multipart", "fields": google.FIELDS, "supportsAllDrives": "true"})
            self.assertTrue(req["headers"]["Content-Type"].startswith("multipart/related; boundary="))
            (meta_type, meta_data), (media_type, media_data) = multipart(req)
            self.assertEqual((meta_type, json.loads(meta_data)), ("application/json; charset=UTF-8", meta))
            self.assertEqual((media_type, media_data), (media, data))

        exactly = b"m" * google.SMALL
        google.drive_create(ACCESS, "file", "five.txt", data=exactly)
        self.assertEqual(multipart(self.g.requests[-1])[1], ("text/plain", exactly))

    def test_drive_create_resumable(self):
        data = bytes(range(256)) * (6 * 1024 * 4)               # 6 MB
        self.g.on("POST", "/upload/drive/v3/files", b"", headers={
            "Location": self.g.url + "/upload/drive/v3/files?uploadType=resumable&upload_id=U1"})
        self.g.on("PUT", "/upload/drive/v3/files", PDF_ITEM)
        self.assertEqual(google.drive_create(ACCESS, "file", "big.bin", "f1", data), PDF_FILE)
        start, put = self.g.requests
        self.assertEqual(args(start), {"uploadType": "resumable", "fields": google.FIELDS, "supportsAllDrives": "true"})
        self.assertEqual(body(start), {"name": "big.bin", "parents": ["f1"]})
        self.assertEqual((start["headers"]["X-Upload-Content-Type"], start["headers"]["X-Upload-Content-Length"]),
                         ("application/octet-stream", str(len(data))))
        self.assertEqual((args(put), put["body"], put["headers"]["Content-Type"]),
                         ({"uploadType": "resumable", "upload_id": "U1"}, data, "application/octet-stream"))

        other = StandIn()
        self.addCleanup(other.close)
        self.g.on("POST", "/upload/drive/v3/files", b"", headers={"Location": other.url + "/upload/drive/v3/files"})
        self.refused(google.drive_create, ACCESS, "file", "big.bin", None, data)
        self.assertEqual(other.requests, [])
        self.assertEqual(len(self.g.find("PUT", "/upload/drive/v3/files")), 1)

    def test_drive_update(self):
        self.g.on("PATCH", "/upload/drive/v3/files/t1", PDF_ITEM)
        self.assertEqual(google.drive_update(ACCESS, item("t1", "text/plain"), b"new text\n", "text/plain"), PDF_FILE)
        req = self.g.requests[-1]
        self.assertEqual(args(req), {"uploadType": "multipart", "fields": google.FIELDS, "supportsAllDrives": "true"})
        self.assertEqual(multipart(req), [("application/json; charset=UTF-8", b"{}"), ("text/plain", b"new text\n")])
        self.g.on("PATCH", "/upload/drive/v3/files/d1", DOC_ITEM)
        self.assertEqual(google.drive_update(ACCESS, item("d1", google.DOC), b"# New\n", "text/markdown"), DOC_FILE)
        self.assertEqual(multipart(self.g.requests[-1])[1], ("text/markdown", b"# New\n"))

    def test_drive_patch(self):
        self.g.on("PATCH", "/drive/v3/files/p1", PDF_ITEM)
        file = item("p1", "application/pdf", "Costs.pdf", parents=["f1", "f3"])
        for kw, sent, extra in (({"name": "New.pdf"}, {"name": "New.pdf"}, {}),
                                ({"folder": "f2"}, {}, {"addParents": "f2", "removeParents": "f1,f3"}),
                                ({"trashed": True}, {"trashed": True}, {}),
                                ({"trashed": False}, {"trashed": False}, {})):
            self.assertEqual(google.drive_patch(ACCESS, file, **kw), PDF_FILE)
            req = self.g.requests[-1]
            self.assertEqual(body(req), sent)
            self.assertEqual(args(req), dict({"fields": google.FIELDS, "supportsAllDrives": "true"}, **extra))

    def test_sheets(self):
        path = "/v4/spreadsheets/s1/values/Costs%21A1%3AB2"
        self.g.on("GET", path, {"range": "Costs!A1:B2", "values": [["Item", "Cost"], ["Taxi", "12"]]})
        self.assertEqual(google.sheet_read(ACCESS, "s1", "Costs!A1:B2"), [["Item", "Cost"], ["Taxi", "12"]])
        self.g.on("GET", path, {"range": "Costs!A1:B2"})
        self.assertEqual(google.sheet_read(ACCESS, "s1", "Costs!A1:B2"), [])

        rows = [["Item", 12], ["Paid", True], ["=SUM(B1:B2)", ""]]
        self.g.on("PUT", path, {"updatedRange": "Costs!A1:B3", "updatedRows": 3, "updatedColumns": 2, "updatedCells": 6})
        self.assertEqual(google.sheet_write(ACCESS, "s1", "Costs!A1:B2", rows),
                         {"range": "Costs!A1:B3", "rows": 3, "cells": 6})
        req = self.g.requests[-1]
        self.assertEqual((args(req), body(req)), ({"valueInputOption": "USER_ENTERED"},
                                                  {"majorDimension": "ROWS", "values": rows}))
        self.g.on("POST", path + ":append", {"tableRange": "Costs!A1:B3", "updates": {
            "updatedRange": "Costs!A4:B4", "updatedRows": 1, "updatedColumns": 2, "updatedCells": 2}})
        self.assertEqual(google.sheet_write(ACCESS, "s1", "Costs!A1:B2", [["Bus", 3]], append=True),
                         {"range": "Costs!A4:B4", "rows": 1, "cells": 2})
        req = self.g.requests[-1]
        self.assertEqual((args(req), body(req)), ({"valueInputOption": "USER_ENTERED", "insertDataOption": "INSERT_ROWS"},
                                                  {"majorDimension": "ROWS", "values": [["Bus", 3]]}))

    # Gmail

    def test_gmail_search(self):
        self.g.on("GET", "/gmail/v1/users/me/messages", {"messages": [{"id": "m1", "threadId": "t1"},
                                                                      {"id": "m2", "threadId": "t2"}],
                                                         "nextPageToken": "N2", "resultSizeEstimate": 2})
        self.g.on("GET", "/gmail/v1/users/me/messages/m1", {
            "id": "m1", "threadId": "t1", "labelIds": ["INBOX", "UNREAD", "Label_1"],
            "snippet": "Tom &amp; Ana&#39;s plan", "payload": {"headers": [
                {"name": "From", "value": "Ana <ana@example.com>"}, {"name": "to", "value": "owner@example.com"},
                {"name": "CC", "value": "tom@example.com"}, {"name": "Subject", "value": "Plan"},
                {"name": "Date", "value": "Thu, 15 Oct 2026 10:00:00 +0000"}]}})
        self.g.on("GET", "/gmail/v1/users/me/messages/m2", {"id": "m2", "threadId": "t2", "labelIds": ["Label_9"],
                                                            "snippet": "", "payload": {"headers": []}})
        self.g.on("GET", "/gmail/v1/users/me/labels", LABELS)
        got = google.gmail_search(ACCESS, "from:ana newer_than:7d", page="P1")
        self.assertEqual(got, {"next": "N2", "messages": [
            {"id": "m1", "thread": "t1", "from": "Ana <ana@example.com>", "to": "owner@example.com",
             "cc": "tom@example.com", "subject": "Plan", "date": "Thu, 15 Oct 2026 10:00:00 +0000",
             "snippet": "Tom & Ana's plan", "labels": ["INBOX", "UNREAD", "Clients"]},
            {"id": "m2", "thread": "t2", "from": "", "to": "", "cc": "", "subject": "", "date": "", "snippet": "",
             "labels": ["Label_9"]}]})
        self.assertEqual(args(self.g.find("GET", "/gmail/v1/users/me/messages")[0]),
                         {"q": "from:ana newer_than:7d", "maxResults": "20", "pageToken": "P1"})
        for message_id in ("m1", "m2"):
            self.assertEqual(args(self.g.find("GET", "/gmail/v1/users/me/messages/" + message_id)[0]),
                             {"format": "metadata", "metadataHeaders": ["From", "To", "Cc", "Subject", "Date"]})
        self.assertEqual(len(self.g.find("GET", "/gmail/v1/users/me/labels")), 1)

        self.g.on("GET", "/gmail/v1/users/me/messages", {"resultSizeEstimate": 0})
        self.assertEqual(google.gmail_search(ACCESS, "nothing"), {"messages": [], "next": None})
        self.assertNotIn("pageToken", args(self.g.requests[-1]))
        self.assertEqual(len(self.g.find("GET", "/gmail/v1/users/me/labels")), 1)

    def test_gmail_message(self):
        plain = "Hello Ana,\r\nthe plan is ready??? ✓\r\n".encode()
        self.assertTrue("-" in b64(plain) or "_" in b64(plain))      # a base64url body, not base64
        self.g.on("GET", "/gmail/v1/users/me/labels", LABELS)
        self.g.on("GET", "/gmail/v1/users/me/messages/m1", {
            "id": "m1", "threadId": "t1", "labelIds": ["INBOX", "Label_2"], "snippet": "Hello Ana",
            "payload": {"mimeType": "multipart/mixed", "filename": "", "body": {"size": 0}, "headers": [
                {"name": "From", "value": "Ana <ana@example.com>"}, {"name": "To", "value": "owner@example.com"},
                {"name": "Subject", "value": "Plan"}, {"name": "Date", "value": "Thu, 15 Oct 2026 10:00:00 +0000"},
                {"name": "Message-ID", "value": "<a1@mail.example.com>"},
                {"name": "References", "value": "<r0@mail.example.com>"}],
                "parts": [
                    {"mimeType": "multipart/alternative", "filename": "", "body": {"size": 0}, "parts": [
                        {"mimeType": "text/plain", "filename": "", "body": {"size": len(plain), "data": b64(plain)},
                         "headers": [{"name": "Content-Type", "value": 'text/plain; charset="UTF-8"'}]},
                        {"mimeType": "text/html", "filename": "", "body": {"data": b64(b"<p>Hello <b>Ana</b></p>")}}]},
                    {"mimeType": "application/pdf", "filename": "plan.pdf", "body": {"attachmentId": "ATT1", "size": 2048}},
                    {"mimeType": "text/plain", "filename": "notes.txt", "body": {"attachmentId": "ATT2", "size": 5}}]}})
        got = google.gmail_message(ACCESS, "m1")
        self.assertEqual(got, {
            "id": "m1", "thread": "t1", "from": "Ana <ana@example.com>", "to": "owner@example.com", "cc": "",
            "subject": "Plan", "date": "Thu, 15 Oct 2026 10:00:00 +0000", "snippet": "Hello Ana",
            "labels": ["INBOX", "Projects/Fleet"], "message_id": "<a1@mail.example.com>",
            "references": "<r0@mail.example.com>", "text": "Hello Ana,\nthe plan is ready??? ✓\n",
            "attachments": [{"id": "ATT1", "name": "plan.pdf", "mime": "application/pdf", "size": 2048},
                            {"id": "ATT2", "name": "notes.txt", "mime": "text/plain", "size": 5}]})
        self.assertEqual(args(self.g.find("GET", "/gmail/v1/users/me/messages/m1")[0]), {"format": "full"})

        page = ("<html><head><style>p {color: red}</style><script>alert('x')</script></head><body>"
                "<h1>Report</h1><p>Caf\xe9 &amp; more&nbsp;text</p><br><div>Line   two\n continues</div>"
                "<p></p><p></p><ul><li>One</li><li>Two<br/>three</li></ul><table><tr><td>A</td><td>B</td></tr>"
                "</table></body></html>")
        self.g.on("GET", "/gmail/v1/users/me/messages/m2", {
            "id": "m2", "threadId": "t2", "labelIds": [], "payload": {
                "mimeType": "multipart/related", "body": {"size": 0}, "headers": [], "parts": [
                    {"mimeType": "text/html", "filename": "", "body": {"data": b64(page.encode("latin-1"))},
                     "headers": [{"name": "Content-Type", "value": "text/html; charset=iso-8859-1"}]},
                    {"mimeType": "image/png", "filename": "logo.png", "body": {"attachmentId": "ATT3", "size": 9}}]}})
        got = google.gmail_message(ACCESS, "m2")
        self.assertEqual(got["text"], "Report\n\nCafé & more text\n\nLine two continues\n\nOne\n\nTwo\nthree\n\nA B")
        self.assertEqual((got["message_id"], got["references"], got["attachments"]),
                         ("", "", [{"id": "ATT3", "name": "logo.png", "mime": "image/png", "size": 9}]))

    def test_gmail_attachment(self):
        data = b"\xfb\xff\x00binary?>"
        self.g.on("GET", "/gmail/v1/users/me/messages/m1/attachments/ATT1", {"size": len(data), "data": b64(data)})
        self.assertEqual(google.gmail_attachment(ACCESS, "m1", "ATT1"), data)

    def test_mime_message(self):
        def parse(raw):
            self.assertRegex(raw, r"^[A-Za-z0-9_-]+=*$")
            return email.message_from_bytes(base64.urlsafe_b64decode(raw), policy=email.policy.default)

        text = "Hallo Ana,\nthe plan für Q4 is ready. ✓\n"
        for to in ("Ana <ana@example.com>, bob@example.com", ["Ana <ana@example.com>", "bob@example.com"]):
            msg = parse(google.mime_message(to, "cc@example.com", "hidden@example.com", "Plan für Q4", text))
            self.assertEqual((msg["To"], msg["Cc"], msg["Bcc"], msg["Subject"], msg["From"]),
                             ("Ana <ana@example.com>, bob@example.com", "cc@example.com", "hidden@example.com",
                              "Plan für Q4", None))
            self.assertEqual((msg.get_content_type(), msg.get_content_charset()), ("text/plain", "utf-8"))
            self.assertEqual(msg.get_content().replace("\r\n", "\n"), text)
            self.assertIsNone(msg["In-Reply-To"])
        msg = parse(google.mime_message("ana@example.com", "", None, "Hi", "Short."))
        self.assertEqual((msg["Cc"], msg["Bcc"]), (None, None))

        reply = {"message_id": "<a1@mail.example.com>", "references": "<r0@mail.example.com>", "subject": "Plan",
                 "thread": "t1"}
        msg = parse(google.mime_message("ana@example.com", "", "", "", "Yes.", reply))
        self.assertEqual((msg["Subject"], msg["In-Reply-To"], msg["References"]),
                         ("Re: Plan", "<a1@mail.example.com>", "<r0@mail.example.com> <a1@mail.example.com>"))
        self.assertEqual(parse(google.mime_message("ana@example.com", "", "", "Other", "Yes.", reply))["Subject"],
                         "Other")
        msg = parse(google.mime_message("ana@example.com", "", "", " ", "Yes.", dict(reply, subject="RE: Plan",
                                                                                     references="")))
        self.assertEqual((msg["Subject"], msg["References"]), ("RE: Plan", "<a1@mail.example.com>"))

        for to, cc, bcc, subject in (("a@b.c\nBcc: x@y.z", "", "", "Hi"), ("a@b.c", "c@d.e\r", "", "Hi"),
                                     ("a@b.c", "", ["x@y.z\n"], "Hi"), ("a@b.c", "", "", "Hi\r\nBcc: x@y.z")):
            with self.assertRaises(ValueError):
                google.mime_message(to, cc, bcc, subject, "Body")

    def test_gmail_draft(self):
        self.g.on("POST", "/gmail/v1/users/me/drafts", {"id": "r1", "message": {"id": "m9", "threadId": "t1",
                                                                                 "labelIds": ["DRAFT"]}})
        self.assertEqual(google.gmail_draft(ACCESS, "RAW", thread="t1"),
                         {"draft_id": "r1", "message_id": "m9", "thread": "t1"})
        self.assertEqual(body(self.g.requests[-1]), {"message": {"raw": "RAW", "threadId": "t1"}})
        google.gmail_draft(ACCESS, "RAW")
        self.assertEqual(body(self.g.requests[-1]), {"message": {"raw": "RAW"}})
        self.g.on("PUT", "/gmail/v1/users/me/drafts/r1", {"id": "r1", "message": {"id": "m10", "threadId": "t1"}})
        self.assertEqual(google.gmail_draft(ACCESS, "RAW2", draft_id="r1"),
                         {"draft_id": "r1", "message_id": "m10", "thread": "t1"})
        self.assertEqual(body(self.g.requests[-1]), {"id": "r1", "message": {"raw": "RAW2"}})

    def test_gmail_send(self):
        self.g.on("POST", "/gmail/v1/users/me/messages/send", {"id": "m11", "threadId": "t1", "labelIds": ["SENT"]})
        self.assertEqual(google.gmail_send(ACCESS, "RAW", "t1"), {"id": "m11", "thread": "t1"})
        self.assertEqual(body(self.g.requests[-1]), {"raw": "RAW", "threadId": "t1"})
        google.gmail_send(ACCESS, "RAW")
        self.assertEqual(body(self.g.requests[-1]), {"raw": "RAW"})

    def test_gmail_label_ids(self):
        self.g.on("GET", "/gmail/v1/users/me/labels", LABELS)
        self.g.on("POST", "/gmail/v1/users/me/labels", {"id": "Label_9", "name": "New", "type": "user"})
        names = ["INBOX", "STARRED", "clients", "PROJECTS/fleet", "New"]
        self.assertEqual(google.gmail_label_ids(ACCESS, names), {"INBOX": "INBOX", "STARRED": "STARRED",
                                                                 "clients": "Label_1", "PROJECTS/fleet": "Label_2"})
        self.assertEqual(self.g.find("POST", "/gmail/v1/users/me/labels"), [])
        self.assertEqual(google.gmail_label_ids(ACCESS, names, create=True)["New"], "Label_9")
        made = self.g.find("POST", "/gmail/v1/users/me/labels")
        self.assertEqual([body(r)["name"] for r in made], ["New"])

    def test_gmail_modify(self):
        self.g.on("POST", "/gmail/v1/users/me/messages/batchModify", None, 204)
        self.assertIsNone(google.gmail_modify(ACCESS, ["m1", "m2"], add=["Label_1"], remove=("INBOX", "UNREAD")))
        self.assertEqual(body(self.g.requests[-1]), {"ids": ["m1", "m2"], "addLabelIds": ["Label_1"],
                                                     "removeLabelIds": ["INBOX", "UNREAD"]})

    def test_gmail_trash(self):
        self.g.on("POST", "/gmail/v1/users/me/messages/m1/trash", {"id": "m1", "labelIds": ["TRASH"]})
        self.g.on("POST", "/gmail/v1/users/me/messages/m1/untrash", {"id": "m1", "labelIds": ["INBOX"]})
        self.assertIsNone(google.gmail_trash(ACCESS, "m1"))
        self.assertIsNone(google.gmail_trash(ACCESS, "m1", trash=False))
        self.assertEqual([r["path"] for r in self.g.requests], ["/gmail/v1/users/me/messages/m1/trash",
                                                               "/gmail/v1/users/me/messages/m1/untrash"])

    # Transport

    def test_redirect_is_not_followed(self):
        other = StandIn()
        self.addCleanup(other.close)
        other.on("GET", "/drive/v3/files/p1", PDF_ITEM)
        other.on("POST", "/gmail/v1/users/me/messages/send", {"id": "m1"})
        self.g.on("GET", "/drive/v3/files/p1", None, 302, {"Location": other.url + "/drive/v3/files/p1"})
        self.g.on("POST", "/gmail/v1/users/me/messages/send", None, 307,
                  {"Location": other.url + "/gmail/v1/users/me/messages/send"})
        error = self.refused(google.drive_file, ACCESS, "p1")
        self.assertEqual((error.status, error.unknown), (302, False))
        error = self.refused(google.gmail_send, ACCESS, "RAW")
        self.assertEqual((error.status, error.unknown), (307, False))
        self.assertEqual(other.requests, [])
        self.assertEqual(len(self.g.requests), 2)

    def test_unknown(self):
        send = "/gmail/v1/users/me/messages/send"
        self.g.on("POST", send, close)
        error = self.refused(google.gmail_send, ACCESS, "RAW")
        self.assertEqual((error.unknown, error.status), (True, None))
        self.assertEqual(body(self.g.requests[-1]), {"raw": "RAW"})        # Google read the whole request
        self.g.on("POST", send, short)
        self.assertTrue(self.refused(google.gmail_send, ACCESS, "RAW").unknown)
        self.g.on("POST", send, slow)
        google.TIMEOUT = 0.3
        self.assertTrue(self.refused(google.gmail_send, ACCESS, "RAW").unknown)
        google.TIMEOUT = 5
        self.g.on("POST", send, {"error": {"code": 500, "errors": [{"reason": "backendError"}]}}, 500)
        error = self.refused(google.gmail_send, ACCESS, "RAW")
        self.assertEqual((error.unknown, error.status, error.reason), (False, 500, "backendError"))
        self.g.on("POST", send, b"<html>not json</html>", headers={"Content-Type": "text/html"})
        self.assertTrue(self.refused(google.gmail_send, ACCESS, "RAW").unknown)

        free = socket.socket()
        free.bind(("127.0.0.1", 0))
        port = free.getsockname()[1]
        free.close()
        google.HOSTS["gmail"] = "http://127.0.0.1:%d" % port
        error = self.refused(google.gmail_send, ACCESS, "RAW")
        self.assertEqual((error.unknown, error.status), (False, None))

    def test_errors_hold_no_secret(self):
        self.g.on("POST", "/token", {"error": "invalid_grant",
                                     "error_description": f"Bad code {CODE} for {SECRET} and {REFRESH}"}, 400)
        self.assertEqual(self.refused(google.exchange, "cid", SECRET, CODE, "V", "http://127.0.0.1:5000/").reason,
                         "invalid_grant")
        self.assertEqual(self.refused(google.refresh, "cid", SECRET, REFRESH).reason, "invalid_grant")
        self.g.on("POST", "/token", {"error": CODE}, 400)
        self.assertIsNone(self.refused(google.refresh, "cid", SECRET, REFRESH).reason)
        self.g.on("GET", "/drive/v3/files/p1", {"error": {"code": 401, "message": f"Bad token {ACCESS}",
                                                          "errors": [{"reason": ACCESS, "message": ACCESS}],
                                                          "status": "UNAUTHENTICATED"}}, 401)
        error = self.refused(google.drive_file, ACCESS, "p1")
        self.assertEqual((error.status, error.reason), (401, "UNAUTHENTICATED"))
        self.g.on("POST", "/token", {"access_token": ACCESS, "expires_in": 3599, "id_token": SECRET})
        self.refused(google.exchange, "cid", SECRET, CODE, "V", "http://127.0.0.1:5000/")


if __name__ == "__main__":
    unittest.main()
