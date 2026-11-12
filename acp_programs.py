"""What each Agent Client Protocol (ACP) program does in its own way: one adapter for each program.

The runtime table (lifecycle.RUNTIMES) holds what a program IS, as data: its command, its sign-in methods, the
variables that keep it quiet, the name of its key's variable. This module holds what a program DOES that standard
ACP does not say, which is code: the folder of a session with its files and its variables, the road of the system
text, the sign that its tools are there, the tokens of a turn, its limit and each other failure, and a tool call's own
name. The entry of a runtime names its adapter with the fact `acp_adapter`, and acp_runner.py, fleet.session_command
and lifecycle.Lifecycle call the adapter. No file but this one holds code for one program, and none compares a
runtime to a name for it (test_runtime_table): a fifth program is a row of the table, an adapter here and a pin.

Each fact below was read from the program at its pin, Grok Build 1.0.77 and OpenCode 2.2.5, against a stand-in model
with no account (step 0 of the AI providers build, 12 November 2026). A pin that moves runs those probes again.

The thread record of a failed prompt, as the hub's intake takes it (hub.clean_record):
    {"type": "error", "code", "message", "retryable", "resets_at"}
with one of these codes:
    usage_limit     a window of the provider that opens again by itself: the hub holds the agent (start_limit)
    no_credit       a person must act at the provider before a call works again
    refused         the provider refused the key or the call
    no_answer       the model's address gave no answer that the program could use
    error           each other error of a prompt, as before
"""
import datetime
import json
import os
import shutil

FLEET_DIR = ".fleet"
LIMIT = "usage_limit"
NO_CREDIT, REFUSED, NO_ANSWER, ERROR = "no_credit", "refused", "no_answer", "error"
# A program that tries a limited call again by itself tells its client of each wait. A wait of more than this many
# seconds is the limit, and the runner ends the turn; a shorter one is the provider's own throttle, and the program's
# next try is right (the AI providers spec, section 3.11 item 2).
LIMIT_WAIT = 60
SESSION = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"      # a Fleet session's id, a folder's name


def record(code, message, resets_at=None):
    """The thread record of a failed prompt. Only a limit is tried again by the fleet."""
    return {"type": "error", "code": code, "message": str(message or "The program gave no reason.")[:500],
            "retryable": code == LIMIT, "resets_at": resets_at if code == LIMIT else None}


def whole(value):
    """A count of tokens or of calls as the usage file takes it: a whole number, and one below 0 as 0."""
    return max(0, int(value)) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0


def words_of(error):
    """The program's own words of a JSON-RPC error: what its data says, else its message."""
    data = error.get("data")
    if isinstance(data, str) and data.strip():
        return data
    if isinstance(data, dict) and isinstance(data.get("message"), str) and data["message"].strip():
        return data["message"]
    return error.get("message")


class Program:
    """A program that does nothing in a way of its own: standard ACP. It is the adapter of a runtime that names none,
    and each other adapter changes only what its program does differently."""
    folder_name = None              # the folder of its sessions' folders in ~/.fleet; None for a program with none
    first_prompt_waits = False      # the first prompt goes at the helper's first signal, not at once (tools_ready)
    settle = 0                      # seconds between that signal and the first prompt
    needs_account = False           # no session of it starts for an agent with no model account

    def __init__(self, home=None):
        self.home = home or os.path.expanduser("~")

    # ---- the folder of one session: made new before the program starts, removed when its window ends
    def folder(self, session):
        """The session's own folder, ~/.fleet/<program>/<session>, or None for a program with none. Nothing that the
        program stored outside it reaches the session, so no stored credential can win over the account's key."""
        return os.path.join(self.home, FLEET_DIR, self.folder_name, session) if self.folder_name else None

    def session_env(self, session):
        """{NAME: value} of the variables that hold a path of this session. They are not in the table's acp_quiet,
        because each session has its own."""
        return {}

    def files(self, system, account):
        """{name: text} of the files of a new session's folder. system: the session's stable text; account: what the
        helper knows of the agent's model account (fleet.acp_account), or None for an agent with none."""
        return {}

    def carries_system(self):
        """True when the runner gives the program its system text (new_session). False when a file of the session's
        folder is the text's road, and the runner then gets none."""
        return True

    def prepare(self, session, system=None, account=None):
        """Make the session's folder new, of mode 700, with its files. Raises FileExistsError for a folder that is
        there: a folder of an earlier session is never taken, whatever it holds."""
        folder = self.folder(session)
        if not folder:
            return None
        os.makedirs(os.path.dirname(folder), mode=0o700, exist_ok=True)
        os.mkdir(folder, 0o700)
        for name, text in self.files(system, account).items():
            with open(os.open(os.path.join(folder, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w",
                      encoding="utf-8") as f:
                f.write(text)
        return folder

    def remove(self, session):
        folder = self.folder(session)
        if folder:
            shutil.rmtree(folder, ignore_errors=True)

    # ---- the start of a session
    def new_session(self, params, system, capabilities):
        """Put the system text into the params of session/new, on this program's own road to its system message.
        Returns the text that has no such road and goes at the head of the first prompt, or None. Standard ACP:
        `systemPrompt`, where the program says that it takes it."""
        if not system:
            return None
        if "systemPrompt" in ((capabilities or {}).get("sessionCapabilities") or {}):
            params["systemPrompt"] = {"mode": "append", "content": [{"type": "text", "text": system}]}
            return None
        return system

    def notified(self, method, params):
        """A notification of the program that is no session/update."""

    def tools_ready(self, session_id):
        """True when the tools of the session's MCP servers are there for the model. The runner waits for it before
        the first prompt: for this event, never for a time."""
        return True

    def model_options(self, initialize, session):
        """[(model, [effort, ...], default effort or None, is the current model)] from the answer of initialize, or
        from the answer of session/new, whichever the table's acp_models names: the other one is None."""
        if session is None:
            return []
        options = session.get("configOptions") if isinstance(session.get("configOptions"), list) else []
        model = next((o for o in options if isinstance(o, dict) and o.get("category") == "model"), None)
        effort = next((o for o in options if isinstance(o, dict) and o.get("category") == "thought_level"), None)
        values = lambda o: [x.get("value") for x in (o or {}).get("options") or [] if isinstance(x, dict)]
        current = (model or {}).get("currentValue")
        # the session gives the efforts of its current model only
        return [(name, values(effort) if name == current else [],
                 (effort or {}).get("currentValue") if name == current else None, name == current)
                for name in values(model)]

    # ---- one turn
    def usage(self, result, model):
        """What the answer of one prompt says the turn spent: {"models": {model: [input, cache_read, cache_write,
        output, calls]}, "context": {"used", "size"} or None}, the order of usage.MODEL_FIELDS; None for an answer
        with no token kinds. Standard ACP names none, so a program without an adapter of its own leaves no usage
        file, and its sessions' tokens stay unknown."""
        return None

    def update(self, update, now):
        """A session/update that is the program's own word for a limit: (the limit's record, True to end the turn),
        else None."""
        return None

    def failure(self, error):
        """The thread record of a prompt that the program answered with a JSON-RPC error."""
        return record(ERROR, words_of(error))

    def tool(self, update, entry):
        """Give a tool call's record the fleet's own name for it, where the program calls the tools of an MCP server
        through a tool of its own. Returns the records of the calls that this one update names beside its own."""
        return []


class Grok(Program):
    """Grok Build (`grok agent stdio`)."""
    folder_name = "grok"
    TOOLS_READY = "_x.ai/mcp_initialized"

    def __init__(self, home=None):
        super().__init__(home)
        self.ready = set()          # the sessions whose MCP tools the program said are there
        self.contexts = {}          # {model: its context size}, from the model list of initialize

    def session_env(self, session):
        # With GROK_HOME at a new folder the program reads nothing of ~/.grok: no stored sign-in, no key of its
        # configuration, no rule, no skill and no MCP server of it. It writes about 55 files there at each start.
        return {"GROK_HOME": self.folder(session)}

    def new_session(self, params, system, capabilities):
        # It ignores `systemPrompt` in silence. `_meta.rules` reaches the end of its system message, and stays with
        # the session; a text at the head of the first prompt is conversation, which a compaction can shorten.
        if system:
            params.setdefault("_meta", {})["rules"] = system
        return None

    def notified(self, method, params):
        if method == self.TOOLS_READY and isinstance(params, dict) and isinstance(params.get("sessionId"), str):
            self.ready.add(params["sessionId"])

    def tools_ready(self, session_id):
        return session_id in self.ready

    def model_options(self, initialize, session):
        if initialize is None:
            return super().model_options(initialize, session)
        state = (initialize.get("_meta") or {}).get("modelState") or {}
        options = []
        for row in state.get("availableModels") if isinstance(state.get("availableModels"), list) else []:
            meta = row.get("_meta") if isinstance(row, dict) and isinstance(row.get("_meta"), dict) else {}
            name = row.get("modelId") if isinstance(row, dict) else None
            if isinstance(meta.get("totalContextTokens"), int):
                self.contexts[name] = meta["totalContextTokens"]
            efforts = [e.get("value") for e in meta.get("reasoningEfforts") or [] if isinstance(e, dict)]
            options.append((name, efforts, meta.get("reasoningEffort"), name == state.get("currentModelId")))
        return options

    def usage(self, result, model):
        """`_meta.usage` of the answer: the turn's sums, and `modelUsage` with the same fields for each model. Its
        inputTokens has the cached tokens in it, and its outputTokens the reasoning tokens."""
        meta = result.get("_meta") if isinstance(result.get("_meta"), dict) else {}
        usage = meta.get("usage") if isinstance(meta.get("usage"), dict) else None
        if usage is None:
            return None

        def row(u):
            return [whole(whole(u.get("inputTokens")) - whole(u.get("cachedReadTokens"))),
                    whole(u.get("cachedReadTokens")), whole(u.get("cacheCreationTokens")),
                    whole(u.get("outputTokens")), whole(u.get("modelCalls"))]
        by_model = usage.get("modelUsage") if isinstance(usage.get("modelUsage"), dict) else {}
        models = {name: row(u) for name, u in by_model.items() if isinstance(name, str) and isinstance(u, dict)}
        if not models:              # no row of a model: the turn's own sums, for the session's model
            models = {meta.get("modelId") if isinstance(meta.get("modelId"), str) else model: row(usage)}
        last = meta.get("modelId") if isinstance(meta.get("modelId"), str) else model
        size = self.contexts.get(last)
        context = {"used": whole(meta.get("totalTokens")), "size": size} \
            if isinstance(meta.get("totalTokens"), int) and size else None
        return {"models": models, "context": context}

    def failure(self, error):
        """A 429 is the JSON-RPC error -32003 with the provider's words as a string, after one more try of the program,
        and with no reset time; "no credit" as a 429 has the same code. Each other refusal is -32603 with the HTTP
        status in its data."""
        code, data = error.get("code"), error.get("data")
        status = data.get("http_status") if isinstance(data, dict) else None
        if code == -32003:
            return record(NO_CREDIT if "insufficient_quota" in str(data) else LIMIT, words_of(error))
        if code == -32603 and status == 402:
            return record(NO_CREDIT, words_of(error))
        if code == -32603 and status in (401, 403):
            return record(REFUSED, words_of(error))
        if code == -32603 and isinstance(status, int) and status >= 500:
            return record(NO_ANSWER, words_of(error))
        return record(ERROR, words_of(error))

    def tool(self, update, entry):
        """The model calls the tool of an MCP server through `use_tool`, with the name <server>__<tool>."""
        raw = update.get("rawInput") if isinstance(update.get("rawInput"), dict) else {}
        own = ((update.get("_meta") or {}).get("x.ai/tool") or {}).get("name") if isinstance(update.get("_meta"), dict) \
            else None
        name = raw.get("tool_name")
        if entry.get("type") == "tool_call" and "use_tool" in (own, update.get("title")) and isinstance(name, str):
            server, found, tool = name.partition("__")
            if found and tool:
                entry.update(title=tool[:300], server=server[:60])
            else:
                entry.update(title=name[:300])
        return []


class OpenCode(Program):
    """OpenCode (`opencode acp`)."""
    folder_name = "opencode"
    # A prompt that comes at once after session/new does not have the tools of its MCP servers yet, and the program
    # gives its client no sign when they are there. The hub knows when the session listed the fleet's tools on its own
    # route, and the helper's first signal follows that (fleet.Helper.first_line_due): the first prompt goes then.
    first_prompt_waits = True
    # Measured at 2.2.5 on 12 November 2026, with the real program against a stand-in MCP server: 0.04 seconds after
    # the server got the program's tools/list call the model's tool list did not have the server's tools, and 0.1
    # seconds after it had them. And a session keeps the tool list of its first prompt: one whose first prompt came
    # too early did not get the fleet's tools at a prompt 8 seconds later either. The program gives no sign of that
    # last step, so the first prompt waits this long after the signal. It is the one wait here that is a time: an
    # event of the program in its place is the better rule, when a later version gives one.
    settle = 2.0
    # Without the configuration of an account the program offers hosted models that need no key, so no session of it
    # starts without one.
    needs_account = True
    RETRY = "opencode/retry"
    LIMITS = ("provider.rate-limit", "provider.free-limit", "provider.go-limit")
    NO_CREDITS = ("provider.quota", "provider.budget-limit", "provider.model-budget-limit")
    CONTEXT, OUTPUT = 64000, 8000       # a model of the owner's own server, where the server names no size

    def session_env(self, session):
        # Its configuration folder is a source of its own (its AGENTS.md, its skills and its plugins load, and a plugin
        # is code), so it is this new folder. Its database holds its saved accounts, and one of them wins over the key
        # of the configuration: in a new folder there is none.
        folder = self.folder(session)
        return {"OPENCODE_CONFIG_DIR": folder, "OPENCODE_DB": os.path.join(folder, "db.sqlite")}

    def carries_system(self):
        return False                # AGENTS.md of its configuration folder is in its system message

    def files(self, system, account):
        files = {"AGENTS.md": system} if system else {}
        if account:
            files["opencode.json"] = json.dumps(self.config(account), indent=1) + "\n"
        return files

    def config(self, account):
        """The session's configuration, with the exact keys of OpenCode 2.2.5. account: {provider, the provider's
        name in the program; model, "<provider>/<model>" or None; key_env, the variable that holds the key, or None
        for a server with no key; address, title and models (the names of its own models), of the owner's own model
        server only}.

        The policy is what keeps each other provider out: without it the program offers hosted models that need no
        key, and each provider whose key is in the environment under the program's own name. The last line that
        matches decides, so the order of the two lines matters."""
        provider, model = account["provider"], account.get("model")
        settings = {"apiKey": "{env:%s}" % account["key_env"]} if account.get("key_env") else {}
        entry = {"settings": settings}
        if account.get("address"):
            # A provider that the program does not know: without `package` its model is listed and each prompt fails,
            # and without `limit.context` the program takes 200,000 tokens as the model's context
            names = [n.partition("/")[2] if n.startswith(provider + "/") else n
                     for n in ([model] if model else []) + list(account.get("models") or [])]
            entry = {"name": account.get("title") or provider, "package": "@ai-sdk/openai-compatible",
                     "settings": dict({"baseURL": account["address"]}, **settings),
                     "models": {name: {"name": name, "limit": {"context": account.get("context") or self.CONTEXT,
                                                               "output": self.OUTPUT}}
                                for name in dict.fromkeys(names) if name}}
        config = {"update": "disable", "providers": {provider: entry},
                  "policies": [{"action": "provider.use", "resource": "*", "effect": "deny"},
                               {"action": "provider.use", "resource": provider, "effect": "allow"}]}
        return dict({"model": model}, **config) if model else config

    def usage(self, result, model):
        """`usage` of the answer. Its inputTokens and outputTokens have neither the cached nor the reasoning tokens in
        them, and it gives no count of model calls: one for each answer with usage."""
        usage = result.get("usage") if isinstance(result.get("usage"), dict) else None
        if usage is None:
            return None
        return {"models": {model: [whole(usage.get("inputTokens")), whole(usage.get("cachedReadTokens")),
                                   whole(usage.get("cachedWriteTokens")),
                                   whole(usage.get("outputTokens")) + whole(usage.get("thoughtTokens")), 1]},
                "context": None}    # its usage_update gives the context, which the runner keeps

    def update(self, update, now):
        """The program tries a limited call again by itself, for up to 15 minutes before each try, and tells of each
        wait in a session_info_update. A wait of more than LIMIT_WAIT seconds for a limit of the provider is the
        limit: the turn ends there, with the reset time that the provider's Retry-After header gave, if any."""
        if update.get("sessionUpdate") != "session_info_update" or not isinstance(update.get("_meta"), dict):
            return None
        retry = update["_meta"].get(self.RETRY)
        error = retry.get("error") if isinstance(retry, dict) and isinstance(retry.get("error"), dict) else None
        if not error or error.get("type") != "provider.rate-limit":
            return None
        try:
            at = datetime.datetime.fromisoformat(str(retry.get("nextRetryAt")).replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
        if at - now <= LIMIT_WAIT:
            return None
        after = error.get("retryAfterMs")
        resets = now + after / 1000 if isinstance(after, (int, float)) and not isinstance(after, bool) and after > 0 \
            else None
        return record(LIMIT, error.get("message") or "The provider's limit was reached.", resets), True

    def failure(self, error):
        """The error after its last try, -32603 with the kind in data.errorName; a refused key is -32000."""
        data = error.get("data") if isinstance(error.get("data"), dict) else {}
        kind = data.get("errorName")
        if error.get("code") == -32000:
            return record(REFUSED, error.get("message"))
        if kind in self.LIMITS:
            return record(LIMIT, error.get("message"))
        if kind in self.NO_CREDITS:
            return record(NO_CREDIT, error.get("message"))
        if kind == "provider.internal":
            return record(NO_ANSWER, error.get("message"))
        return record(ERROR, error.get("message"))

    def tool(self, update, entry):
        """The model calls the tool of an MCP server with code in the tool `execute`, as tools.<server>.<tool>(...).
        The update that ends the call names each tool that the code called: each one is a record of its own."""
        output = update.get("rawOutput") if isinstance(update.get("rawOutput"), dict) else {}
        calls = (output.get("metadata") or {}).get("toolCalls") if isinstance(output.get("metadata"), dict) else None
        records = []
        for number, call in enumerate(calls[:20] if isinstance(calls, list) else [], 1):
            name = call.get("tool") if isinstance(call, dict) else None
            if not isinstance(name, str) or not name.strip():
                continue
            server, found, tool = name.partition(".")
            records.append({"type": "tool_call", "tool_call_id": f"{entry['tool_call_id']}/{number}"[:300],
                            "title": (tool if found and tool else name)[:300], "kind": "other",
                            "status": "failed" if call.get("status") in ("failed", "error") else "completed",
                            **({"server": server[:60]} if found and tool else {})})
        return records


ADAPTERS = {"grok": Grok, "opencode": OpenCode}


def adapter(name, home=None):
    """The adapter that an entry of the runtime table names with `acp_adapter`; the standard one for None. Raises
    KeyError for a name with no adapter here."""
    return (ADAPTERS[name] if name else Program)(home)
