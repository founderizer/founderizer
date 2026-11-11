"""The door for threads: the repository calls of a narrowed conversation (person access plan, section 3). Standard
library only.

A person who may use only some of an agent's repositories talks to a locked thread: no shell, no file tool, no token.
Each repository action is one typed call that the hub makes for it. The hub owns the token, the check against the
person's list, the records and the tools; this module owns the GitHub requests and the rules, as pure functions of the
hub's request function:

    req(method, path, body=None, accept=None) -> (status, data)

It is bound to one token for one repository, so nothing here ever sees a token. Three things hold for every call:
an input is checked by pattern before it enters a URL, an answer carries only fields that this file names (never a
download_url, which holds a token), and a GitHub failure reaches the thread as a fixed sentence, never as GitHub's
own text, which the caller of the repository could have written.
"""
import base64
import re
import unicodedata
import urllib.parse

import door_targets

# The thread's own commit rules beside door_targets.NEVER_PATHS: the files that steer another agent's session, an
# editor, a shell or git itself.
EXTRA_NEVER = (".gemini/**", ".cursor/**", ".cursorrules", "CLAUDE.local.md", "GEMINI.md", ".devcontainer/**",
               ".envrc", ".gitmodules", ".gitattributes", ".git/**",
               # other tools' instruction files and the config that runs by itself (the security review of phase B)
               ".windsurf/**", ".windsurfrules", ".clinerules", ".clinerules/**", ".roo*", ".continue/**", ".aider*",
               ".zed/**", ".idea/**", "mise.toml", ".mise.toml", ".pre-commit-config.yaml", "lefthook*", ".lefthook*",
               ".npmrc", "CODEOWNERS")
FILE_MAX = 1024 * 1024           # a file that a read or an edit takes
READ_LINES, READ_BYTES = 400, 32 * 1024
CHANGES_MAX, EDITS_MAX = 200, 20
MATCHES_MAX, FRAGMENT_MAX = 20, 300
FOOTER = "Opened by a narrowed conversation (C-{cid}) of a Fleet agent: its words and code are untrusted."
NO_OTHER_CHECK = "These are the GitHub Actions runs only: this call sees no other check."

REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
NAME = re.compile(r"[A-Za-z0-9._/-]+")
SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
SENTENCES = {404: "GitHub did not find it: the repository, the path or the ref is not there for this access.",
             403: "GitHub does not allow this call for this access.",
             409: "GitHub refused the change.", 422: "GitHub refused the change.",
             429: "GitHub's rate limit is reached: try again later, not at once."}


class Refused(Exception):
    """One fixed sentence for the thread. Never GitHub's own text."""


def failed(status, own=None):
    """The refusal for a status: the call's own sentence for it when it has one, else the general one."""
    return Refused((own or {}).get(status) or SENTENCES.get(status) or "GitHub refused the call.")


def quote(text, safe="/"):
    return urllib.parse.quote(text, safe=safe)


def clean(text, limit=200):
    """Text from GitHub that an answer shows: no control character, and clipped."""
    text = "".join(c if c.isprintable() else "?" for c in str(text))
    return text if len(text) <= limit else text[:limit] + "…"


# ---------------------------------------------------------------- inputs

def repo_url(repo):
    """"/repos/<owner>/<name>", after the form check. The hub compared `repo` with the list already; this keeps a
    mistake there from becoming a path into another route."""
    if not isinstance(repo, str) or not REPO.fullmatch(repo) or set(repo.split("/")) & {".", ".."}:
        raise Refused("The repository is <owner>/<name>.")
    return "/repos/" + quote(repo)


def clean_path(path, what="The path"):
    if isinstance(path, str):
        path = unicodedata.normalize("NFC", path)
    if not isinstance(path, str) or len(path) > 1000 or not NAME.fullmatch(path) or ".." in path or \
            "//" in path or path.startswith("/") or path.endswith("/") or "." in path.split("/"):
        raise Refused(f"{what} takes only letters, digits, '.', '_', '-' and '/', with no '..', no '//' and no '/' "
                      "at its start or its end.")
    return path


def clean_ref(ref, what="The ref"):
    ref = clean_path(ref, what)
    if len(ref) > 200 or any(s.startswith(".") or s.endswith(".lock") for s in ref.split("/")):
        raise Refused(f"{what} has no part that starts with '.' or ends with '.lock'.")
    return ref


def branch_prefix(cid):
    """Where one conversation writes. A conversation's id never comes back, so no thread writes on another's
    branch."""
    if not isinstance(cid, int) or isinstance(cid, bool) or cid <= 0:
        raise Refused("This call has no conversation.")
    return f"fleet/c{cid}/"


def own_branch(branch, cid):
    prefix = branch_prefix(cid)
    if isinstance(branch, str) and ":" in branch:
        raise Refused("A branch name takes no ':'.")
    branch = clean_ref(branch, "The branch")
    if not branch.startswith(prefix) or len(branch) == len(prefix):
        raise Refused(f"This conversation writes only on a branch that starts with {prefix} and has a name after it.")
    return branch


def path_refused(path):
    """The commit rule that refuses a path, or None. Compared after NFC and case folding, because .CLAUDE/ and
    claude.md are the same files as .claude/ and CLAUDE.md on a Mac's file system."""
    folded = unicodedata.normalize("NFC", path).casefold()
    return next((p for p in door_targets.NEVER_PATHS + EXTRA_NEVER
                 if door_targets.glob_match(folded, p.casefold())), None)


# ---------------------------------------------------------------- reads

def get(req, path, own=None, accept=None):
    status, data = req("GET", path, None, accept)
    if status != 200:
        raise failed(status, own)
    return data


def default_branch(req, base):
    data = get(req, base)
    name = data.get("default_branch") if isinstance(data, dict) else None
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise Refused("GitHub refused the call.")
    return name


def sha_of(value):
    """A commit or tree id from GitHub, checked before it enters a URL or an answer."""
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise Refused("GitHub refused the call.")
    return value


def contents(req, base, path, ref):
    url = f"{base}/contents/{quote(path)}".rstrip("/") + (f"?ref={quote(ref, safe='')}" if ref else "")
    return get(req, url, {404: f"{path or 'The folder'} is not there at this ref."})


def file_text(req, base, path, ref):
    """One UTF-8 text file. A symlink and a submodule are refused: a symlink's text is a path that somebody else
    chose, and GitHub answers one that points inside the repository with its target's content."""
    data = contents(req, base, path, ref)
    if isinstance(data, list):
        raise Refused(f"{path} is a folder: list it with repo_files.")
    if not isinstance(data, dict) or data.get("type") != "file" or data.get("path") not in (None, path):
        raise Refused(f"{path} is a symlink, a submodule or no plain file: this call takes text files only.")
    size = data.get("size")
    if not isinstance(size, int) or size > FILE_MAX:
        raise Refused(f"{path} is over 1 MiB: this call does not take it.")
    try:
        if data.get("encoding") != "base64":
            raise ValueError
        raw = base64.b64decode(data.get("content") or "")
        if len(raw) > FILE_MAX:
            raise ValueError
        return raw.decode("utf-8")
    except (ValueError, TypeError):
        raise Refused(f"{path} is not UTF-8 text: this call does not take it.") from None


def repo_files(req, repo, path="", ref=None):
    """One folder: a line for each entry with its type, its name and a file's size."""
    base = repo_url(repo)
    path = clean_path(path.rstrip("/") if isinstance(path, str) else path, "The folder") if path else ""
    ref = clean_ref(ref) if ref is not None else None
    data = contents(req, base, path, ref)
    if not isinstance(data, list):
        raise Refused(f"{path} is a file: read it with repo_read.")
    lines = []
    for e in data[:1000]:
        if not isinstance(e, dict) or e.get("type") not in ("file", "dir", "symlink", "submodule"):
            continue
        size = f" {e['size']}" if e["type"] == "file" and isinstance(e.get("size"), int) else ""
        lines.append(f"{e['type']} {clean(e.get('name'))}{size}")
    out = "\n".join(sorted(lines)) or "The folder is empty."
    return out if len(out) <= READ_BYTES else out[:READ_BYTES] + "\n[the list is cut at 32 KiB]"


def repo_read(req, repo, path, ref=None, lines=None):
    """One text file, or a range of its lines. With no range it gives the first 400 lines, at most 32 KiB, and says
    how to ask for the next ones, so that a thread never pays for a whole file it did not need."""
    base, path = repo_url(repo), clean_path(path)
    ref = clean_ref(ref) if ref is not None else None
    first, last = 1, READ_LINES
    if lines is not None:
        m = re.fullmatch(r"(\d{1,7})-(\d{1,7})", lines) if isinstance(lines, str) else None
        first, last = (int(m.group(1)), int(m.group(2))) if m else (0, 0)
        if not 1 <= first <= last:
            raise Refused('lines is a range such as "401-800": the first and the last line, from 1.')
    rows = file_text(req, base, path, ref).split("\n")
    if rows[-1] == "":
        rows.pop()
    total = len(rows)
    if not total:
        return "[the file is empty]"
    if first > total:
        raise Refused(f"{path} has {total} lines.")
    want, shown, used = rows[first - 1:last], [], 0
    for row in want:
        used += len(row.encode()) + 1
        if used > READ_BYTES:
            break
        shown.append(row)
    if not shown:
        start = want[0].encode()[:READ_BYTES].decode("utf-8", "ignore")
        return f"{start}\n[line {first} of {total} is longer than 32 KiB: this is its start]"
    end = first + len(shown) - 1
    out = "\n".join(shown)
    if end < total and (lines is None or len(shown) < len(want)):
        out += f'\n[lines {first}-{end} of {total}; ask for more with lines="{end + 1}-{min(end + READ_LINES, total)}"]'
    return out


def repo_search(req, repo, query):
    """A code search of this one repository: each match's path and its matching fragments, so that the thread reads
    a file only where it must. The hub's `repo:` is the only one: a query with its own would search elsewhere."""
    repo_url(repo)
    if not isinstance(query, str) or not query.strip() or len(query) > 256 or not query.isprintable():
        raise Refused("The query is one line of at most 256 characters.")
    # a qualifier as GitHub reads one (repo:x, user:x), and not "f(user: str)" in the code that the thread looks for
    if re.search(r"(?i)(?:^|[\s(])(repo|org|user):(?=\S)", query):
        raise Refused("The query takes no repo:, org: or user: of its own: it searches this repository only.")
    busy = "GitHub refused the search: its search rate is reached, or this access cannot search. Do not retry at once."
    data = get(req, "/search/code?q=" + quote(f"{query.strip()} repo:{repo}", safe="") + f"&per_page={MATCHES_MAX}",
               {403: busy, 429: busy, 422: "GitHub refused the query."}, "application/vnd.github.text-match+json")
    items = data.get("items") if isinstance(data, dict) else None
    out, matches = [], 0
    for item in (items if isinstance(items, list) else []):
        if matches == MATCHES_MAX:
            break
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            continue
        inside = (item.get("repository") or {}).get("full_name")
        if inside is not None and str(inside).lower() != repo.lower():
            continue                              # never a match of another repository, whatever GitHub answered
        matches += 1
        out.append(clean(item["path"], 400))
        for match in (item.get("text_matches") or [])[:3]:
            if isinstance(match, dict) and isinstance(match.get("fragment"), str):
                piece = match["fragment"].strip("\n")
                piece = piece if len(piece) <= FRAGMENT_MAX else piece[:FRAGMENT_MAX] + "…"
                out.extend("    " + clean(row, FRAGMENT_MAX) for row in piece.split("\n"))
    return "\n".join(out) if out else "No match."


def repo_checks(req, repo, ref):
    """The GitHub Actions runs of a branch or a commit. It says that it sees no other check, so that no thread reads
    an empty answer as a green one."""
    base, ref = repo_url(repo), clean_ref(ref)
    key = "head_sha" if re.fullmatch(r"[0-9a-f]{40}", ref) else "branch"
    blind = "This repository's access cannot read its CI runs."
    data = get(req, f"{base}/actions/runs?{key}={quote(ref, safe='')}&per_page=10", {403: blind, 404: blind})
    runs = data.get("workflow_runs") if isinstance(data, dict) else None
    word = lambda v: v if isinstance(v, str) and re.fullmatch(r"[a-z_]{1,30}", v) else "none"
    lines = [f"{clean(r.get('name'))}: {word(r.get('status'))}, conclusion {word(r.get('conclusion'))}"
             for r in (runs if isinstance(runs, list) else [])[:10] if isinstance(r, dict)]
    return "\n".join(lines + [NO_OTHER_CHECK]) if lines else f"No GitHub Actions run for {ref}. {NO_OTHER_CHECK}"


# ---------------------------------------------------------------- writes

def planned(changes):
    """[(path, kind, value)] of a call's changes, with every rule that needs no request checked first, so that a
    refused call costs GitHub nothing. kind is edit (value: old, new), content (value: text) or delete."""
    form = "Each change is {path, edit: {old, new}}, {path, content} or {path, delete: true}."
    if not isinstance(changes, list) or not 0 < len(changes) <= CHANGES_MAX:
        raise Refused(f"A call takes 1 to {CHANGES_MAX} changes.")
    out, size, kinds = [], 0, {}
    for c in changes:
        if not isinstance(c, dict) or len(c) != 2 or "path" not in c:
            raise Refused(form)
        path = clean_path(c["path"])
        rule = path_refused(path)
        if rule:
            raise Refused(f"{path} is under the commit rules ({rule}), which no change passes.")
        edit, content = c.get("edit"), c.get("content")
        if isinstance(edit, dict) and set(edit) == {"old", "new"} and all(isinstance(v, str) for v in edit.values()):
            if not edit["old"] or edit["old"] == edit["new"]:
                raise Refused(f"The edit of {path} needs an old text, and a new text that differs from it.")
            kind, value, new = "edit", (edit["old"], edit["new"]), edit["new"]
        elif isinstance(content, str):
            kind, value, new = "content", content, content
        elif c.get("delete") is True:
            kind, value, new = "delete", None, ""
        else:
            raise Refused(form)
        if path in kinds and (kinds[path], kind) != ("edit", "edit"):
            raise Refused(f"{path} comes twice: only edits of one file may share a call.")
        kinds[path] = kind
        try:
            size += len(new.encode("utf-8"))
        except UnicodeError:
            raise Refused(f"The new text of {path} is not UTF-8.") from None
        out.append((path, kind, value))
    if sum(1 for _, kind, _ in out if kind == "edit") > EDITS_MAX:
        raise Refused(f"A call takes at most {EDITS_MAX} edits.")
    if size > door_targets.CONTENT_MAX:
        raise Refused(f"The new content is over {door_targets.CONTENT_MAX // 1024} KiB: it is refused, never cut.")
    return out


# A closing keyword and, close after it on its line, an issue in any form that GitHub reads: #5, owner/repo#5, GH-5,
# or the issue's URL. GitHub reads it in a pull request's words and in a commit message that reaches the default
# branch, so neither of the two may hold one.
CLOSING = re.compile(r"(?i)\b(close[sd]?|fix(e[sd])?|resolve[sd]?)\b[^\n]{0,40}?(#\d|GH-\d|/issues/\d)")


def repo_change(req, repo, branch, changes, message, cid, recheck):
    """One commit on the conversation's own branch, which starts at the default branch's head when it is new: one
    tree, one commit and one ref write without force. The default branch and a protected branch are refused by
    GitHub's own answer and not only by the prefix. When the tree did not change, nothing is committed, so a retry
    after a lost answer is safe. `recheck` runs right before the ref write: the list can change during the reads."""
    base, branch, plan = repo_url(repo), own_branch(branch, cid), planned(changes)
    if not isinstance(message, str) or not message.strip() or len(message) > 2000 or "\0" in message:
        raise Refused("The message is 1 to 2000 characters.")
    if CLOSING.search(message):
        raise Refused("A commit of this conversation closes no issue by itself: name the issue without close, fix or "
                      "resolve before it.")
    default = default_branch(req, base)
    if branch == default:
        raise Refused("This conversation never writes the default branch: its change goes there by a pull request.")
    status, ref = req("GET", f"{base}/git/ref/heads/{quote(branch)}")
    new = status == 404 or (status == 200 and not isinstance(ref, dict))
    if new:
        ref = get(req, f"{base}/git/ref/heads/{quote(default)}")
    elif status != 200:
        raise failed(status)
    else:
        about = get(req, f"{base}/branches/{quote(branch)}")
        if not isinstance(about, dict) or about.get("protected") is not False:
            raise Refused("This conversation never writes a protected branch.")
    head = sha_of(((ref if isinstance(ref, dict) else {}).get("object") or {}).get("sha"))
    commit = get(req, f"{base}/git/commits/{head}")
    base_tree = sha_of(((commit if isinstance(commit, dict) else {}).get("tree") or {}).get("sha"))
    texts, entries = {}, {}
    for path, kind, value in plan:
        entry = {"path": path, "mode": "100644", "type": "blob"}
        if kind == "delete":
            entry["sha"] = None
        elif kind == "content":
            entry["content"] = value
        else:
            if path not in texts:
                texts[path] = file_text(req, base, path, head)
            found = texts[path].count(value[0])
            if found != 1:
                raise Refused(f"The old text of the edit of {path} is there {found} times at the branch's head: "
                              "it must be there exactly once. Nothing changed.")
            entry["content"] = texts[path] = texts[path].replace(value[0], value[1])
        entries[path] = entry
    status, tree = req("POST", f"{base}/git/trees", {"base_tree": base_tree, "tree": list(entries.values())})
    if status != 201:
        raise failed(status, {422: "GitHub refused the change: a delete names a file that is not there, or a path "
                                   "is no file path. Nothing changed."})
    tree = sha_of(tree.get("sha") if isinstance(tree, dict) else None)
    if tree == base_tree:
        return "Nothing changed."
    status, made = req("POST", f"{base}/git/commits", {
        "message": f"{message.strip()}\n\nNarrowed-conversation: C-{cid}", "tree": tree, "parents": [head]})
    if status != 201:
        raise failed(status)
    made = sha_of(made.get("sha") if isinstance(made, dict) else None)
    recheck()
    moved = {422: f"{branch} moved meanwhile, or GitHub refused the write: nothing changed. Call again.",
             409: f"{branch} moved meanwhile, or GitHub refused the write: nothing changed. Call again."}
    if new:
        status, _ = req("POST", f"{base}/git/refs", {"ref": "refs/heads/" + branch, "sha": made})
    else:
        status, _ = req("PATCH", f"{base}/git/refs/heads/{quote(branch)}", {"sha": made, "force": False})
    if status not in (200, 201):
        raise failed(status, moved)
    return f"{repo} {branch} is at {made}: {len(entries)} file{'s' if len(entries) != 1 else ''} in one commit" + \
        (", on a new branch." if new else ".")


def repo_pull_request(req, repo, branch, title, body, cid, recheck=None):
    """The branch's pull request into the default branch: the open one gets the title and the body, else a new one
    opens. The caller gives words only. The head and the base are the hub's, and no state, merge or auto-merge is
    ever sent. The body begins with a line that tells a reader its words and code are untrusted, so no comment of the
    thread can hide it; it may not close an issue by itself, and its mentions notify nobody. recheck(), when given,
    runs right before the write, as in repo_change."""
    base, branch = repo_url(repo), own_branch(branch, cid)
    if not isinstance(title, str) or not title.strip() or len(title) > 256 or not title.isprintable():
        raise Refused("The title is one line of at most 256 characters.")
    if not isinstance(body, str) or len(body) > 60000 or "\0" in body:
        raise Refused("The body is text of at most 60000 characters.")
    if "<!--" in body or "<!--" in title:
        raise Refused("A pull request of this conversation holds no HTML comment.")
    if CLOSING.search(body) or CLOSING.search(title):
        raise Refused("A pull request of this conversation closes no issue by itself: name the issue without close, "
                      "fix or resolve before it.")
    footer = FOOTER.format(cid=cid)
    words = "\n".join(line for line in body.splitlines() if line.strip() != footer).strip()   # one line, the hub's
    words = re.sub(r"@(?=[A-Za-z0-9])", "@​", words)      # a mention that notifies nobody
    sent = {"title": re.sub(r"@(?=[A-Za-z0-9])", "@​", title.strip()),
            "body": footer + ("\n\n" + words if words else "")}
    default = default_branch(req, base)
    if branch == default:
        raise Refused("A pull request goes from the conversation's branch into the default branch.")
    head = f"{repo.split('/')[0]}:{branch}"
    pulls = get(req, f"{base}/pulls?head={quote(head, safe='')}&state=open&per_page=30")
    for pull in pulls if isinstance(pulls, list) else []:
        # GitHub gives every open pull request when it cannot read `head`: so each one is compared here.
        if not isinstance(pull, dict) or (pull.get("head") or {}).get("ref") != branch or \
                (pull.get("base") or {}).get("ref") != default or pull.get("state") != "open" or \
                str(((pull.get("head") or {}).get("repo") or {}).get("full_name", repo)).lower() != repo.lower():
            continue
        number = pull.get("number")
        if not isinstance(number, int) or isinstance(number, bool):
            continue
        if recheck:
            recheck()
        status, _ = req("PATCH", f"{base}/pulls/{number}", sent)
        if status != 200:
            raise failed(status)
        return f"Pull request #{number} of {repo}, from {branch} into {default}, has the new title and body."
    if recheck:
        recheck()
    status, made = req("POST", f"{base}/pulls", dict(sent, head=head, base=default))
    if status != 201:
        raise failed(status, {422: "GitHub refused the pull request: the branch is not there, or it has no commit "
                                   "that the default branch lacks."})
    number = made.get("number") if isinstance(made, dict) else None
    if not isinstance(number, int) or isinstance(number, bool):
        raise Refused("GitHub refused the call.")
    return f"Pull request #{number} of {repo} is open, from {branch} into {default}. A person merges it."
