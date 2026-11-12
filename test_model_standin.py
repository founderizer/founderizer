"""A stand-in model server for tests (the AI providers build spec, step 0, probe B), and the tests of the stand-in.

`Models()` listens on a local address and speaks the OpenAI shapes: GET /v1/models, POST /v1/chat/completions and POST
/v1/responses, each as one answer or as a stream of events. No test calls a real model through it, and it needs no
key, no account and no network but the loopback address. Other tests import it:

    import test_model_standin as standin
    models = standin.Models(key="a-test-key")
    self.addCleanup(models.close)
    models.script += [standin.tool("ping", {"value": 7}), standin.text("Done.")]

**What it answers** is a script. `script` holds one answer for each model call, in the order of the calls, and
`otherwise` answers each call after them: an answer, or a function of the call's body. An answer is `text(...)`,
`tool(name, arguments)`, `several(tool, tool, ...)`, or a refusal: `LIMIT` (429), `limit(seconds)` (429 with
Retry-After), `NO_CREDIT`, `WRONG_KEY` (401) or `error(status, ...)`. With no script, the model follows one
instruction: "Call the tool <name> with the value <n>." gives that tool call when the call offers that tool, and each
other call gives the text "Done.".

**Tokens.** A token is a word. The input of a call is the words of its messages, and a `context` cuts it there, as a
server does that cuts a long prompt without an error (`cuts` False refuses such a prompt with 400 instead). An answer
can name its own counts with `usage=`: input, cached (a part of the input), output, reasoning (a part of the output).

**Keys.** With `key`, a call with another bearer gets 401. `records` holds each call: its kind (models, chat,
responses, other), its path, its key, its body and its headers.

**The model list.** `models` holds each model's name, or the whole row that the list gives for it (a dict with its
`id`), for a client that reads more of a row than its name.

**One more route.** A test that needs another route makes a subclass of `Answer` with it, and a subclass of `Models`
whose `answers` names that class.

Grok Build 1.0.77 and OpenCode 2.2.5 ended whole turns with tool calls against it, each from its own program
(`ai-providers-facts.md` of the build's plans, 12 November 2026). A test that makes one calls `close()` at its end.
"""
import json
import re
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ASKS = re.compile(r"Call the tool ([A-Za-z0-9_.-]{1,64}) with the value (-?\d{1,9})\.")


def text(words, **more):
    return dict({"text": words}, **more)


def tool(name, arguments, **more):
    return dict({"tools": [{"name": name, "arguments": arguments}]}, **more)


def several(*tools, **more):
    return dict({"tools": [call for one in tools for call in one["tools"]]}, **more)


def error(status, message, kind, code, retry_after=None):
    return {"status": status, "message": message, "type": kind, "code": code, "retry_after": retry_after}


# What a provider answers when a key has no allowance left for now, and when its account has no credit.
LIMIT = error(429, "Rate limit reached for requests", "rate_limit_error", "rate_limit_exceeded")
NO_CREDIT = error(429, "You exceeded your current quota, please check your plan and billing details.",
                  "insufficient_quota", "insufficient_quota")
WRONG_KEY = error(401, "Incorrect API key provided.", "invalid_request_error", "invalid_api_key")


def limit(retry_after):
    """LIMIT with the provider's own word on when to call again, in seconds (the Retry-After header)."""
    return dict(LIMIT, retry_after=retry_after)


def said(content):
    """The text of a message's content, or of a Responses input item: a string, or a list of parts."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(said(part.get("text") if "text" in part else part.get("content"))
                        for part in content if isinstance(part, dict))
    return ""


def turns(body):
    """The messages of a call as [(role, text)], for both shapes: Chat Completions `messages`, and Responses
    `instructions` and `input`. A tool's result has the role "tool"."""
    out = []
    if isinstance(body.get("instructions"), str):
        out.append(("system", body["instructions"]))
    items = body.get("messages") if "messages" in body else body.get("input")
    for item in [{"role": "user", "content": items}] if isinstance(items, str) else items or []:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "function_call_output":
            out.append(("tool", said(item.get("output"))))
        elif item.get("type") in (None, "message"):
            out.append((str(item.get("role")), said(item.get("content"))))
    return out


def offered(body):
    """The names of the tools that a call offers, in both shapes."""
    return [name for name in ((t.get("function") or t).get("name") for t in body.get("tools") or []
                              if isinstance(t, dict)) if name]


class Models(ThreadingHTTPServer):
    daemon_threads = True
    answers = None          # the class that answers a call: Answer, or a test's own subclass of it with one more route

    def __init__(self, key=None, models=("stand-in",), context=None, cuts=True):
        super().__init__(("127.0.0.1", 0), self.answers or Answer)
        self.key, self.models, self.context, self.cuts = key, list(models), context, cuts
        self.script, self.otherwise, self.records = [], self.follows, []
        self.plain = set()              # the models that answer with text where a tool call was asked for
        self.lock, self.made = threading.Lock(), 0
        threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    @property
    def url(self):
        """The base address that a client takes: its routes are <url>/models, <url>/chat/completions, ..."""
        return f"http://127.0.0.1:{self.server_address[1]}/v1"

    def close(self):
        self.shutdown()
        self.server_close()

    def handle_error(self, request, client_address):
        """A client that went away in the middle of an answer is no fault of this server: nothing is printed."""
        if not isinstance(sys.exc_info()[1], ConnectionError):
            super().handle_error(request, client_address)

    def of(self, *kinds):
        with self.lock:
            return [r for r in self.records if r["kind"] in kinds]

    def calls(self):
        """The bodies of the model calls, in their order."""
        return [r["body"] for r in self.of("chat", "responses")]

    def follows(self, body):
        """The answer of a model with no script: it calls the tool that the last user message asks for by name, when
        the call offers that tool and no result of it is there yet."""
        spoken = turns(body)
        asked = next((ASKS.search(words) for role, words in reversed(spoken) if role == "user"), None)
        calls_tools = body.get("model") not in self.plain
        if asked and asked.group(1) in offered(body) and spoken[-1][0] != "tool" and calls_tools:
            return tool(asked.group(1), {"value": int(asked.group(2))})
        return text("Done.")

    def next_answer(self, body):
        with self.lock:
            answer = self.script.pop(0) if self.script else None
        if answer is None:
            answer = self.otherwise(body) if callable(self.otherwise) else self.otherwise
        return answer

    def call_id(self):
        with self.lock:
            self.made += 1
            return f"call_standin{self.made}"

    def counts(self, body, answer):
        """The token counts of one answer: (input, cached, output, reasoning). None for a prompt that this server
        refuses as longer than its context."""
        words = sum(len(spoken.split()) for _, spoken in turns(body))
        if self.context is not None and words > self.context:
            if not self.cuts:
                return None
            words = self.context
        wrote = answer.get("text") or " ".join(json.dumps(t["arguments"]) for t in answer.get("tools") or [])
        usage = dict({"input": words, "cached": 0, "output": max(1, len(wrote.split())), "reasoning": 0},
                     **answer.get("usage") or {})
        return usage["input"], usage["cached"], usage["output"], usage["reasoning"]


class Answer(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def send(self, status, body, kind="application/json", headers=()):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(data)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def refuse(self, answer):
        after = answer.get("retry_after")
        self.send(answer["status"], {"error": {"message": answer["message"], "type": answer["type"], "param": None,
                                               "code": answer["code"]}},
                  headers=[("Retry-After", str(after))] if after is not None else ())

    def route(self):
        """(the kind of this call, its bearer or None) after its record is kept; the body is read first."""
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"null") if length else None
        except ValueError:
            body = None
        path = self.path.split("?")[0]
        path = path[len("/v1"):] if path.startswith("/v1/") else path
        kind = {("GET", "/models"): "models", ("POST", "/chat/completions"): "chat",
                ("POST", "/responses"): "responses"}.get((self.command, path), "other")
        bearer = self.headers.get("Authorization", "")
        key = bearer[len("Bearer "):] if bearer.startswith("Bearer ") else None
        with self.server.lock:
            self.server.records.append({"kind": kind, "method": self.command, "path": self.path, "key": key,
                                        "body": body, "headers": dict(self.headers.items())})
        return kind, key, body if isinstance(body, dict) else {}

    def do_GET(self):
        kind, key, _ = self.route()
        if kind == "other":
            return self.send(404, {"error": {"message": "not found", "type": "invalid_request_error", "code": None}})
        if self.server.key is not None and key != self.server.key:
            return self.refuse(WRONG_KEY)
        row = {"object": "model", "created": 0, "owned_by": "stand-in"}
        self.send(200, {"object": "list", "data": [dict(row, **(one if isinstance(one, dict) else {"id": one}))
                                                   for one in self.server.models]})

    def do_POST(self):
        kind, key, body = self.route()
        if kind == "other":
            return self.send(404, {"error": {"message": "not found", "type": "invalid_request_error", "code": None}})
        if self.server.key is not None and key != self.server.key:
            return self.refuse(WRONG_KEY)
        answer = self.server.next_answer(body)
        if "status" in answer:
            return self.refuse(answer)
        counts = self.server.counts(body, answer)
        if counts is None:
            return self.refuse(error(400, f"This model's maximum context length is {self.server.context} tokens.",
                                     "invalid_request_error", "context_length_exceeded"))
        calls = [dict(call, id=self.server.call_id()) for call in answer.get("tools") or []]
        (self.as_chat if kind == "chat" else self.as_responses)(body, answer.get("text"), calls, counts)

    # ------------------------------------------------------------ Chat Completions

    def as_chat(self, body, words, calls, counts):
        took, cached, wrote, reasoned = counts
        usage = {"prompt_tokens": took, "completion_tokens": wrote, "total_tokens": took + wrote,
                 "prompt_tokens_details": {"cached_tokens": cached},
                 "completion_tokens_details": {"reasoning_tokens": reasoned}}
        head = {"id": "chatcmpl-standin", "created": 0, "model": body.get("model") or "stand-in"}
        finish = "tool_calls" if calls else "stop"
        made = [{"id": c["id"], "type": "function",
                 "function": {"name": c["name"], "arguments": json.dumps(c["arguments"])}} for c in calls]
        if not body.get("stream"):
            message = {"role": "assistant", "content": words, **({"tool_calls": made} if made else {})}
            return self.send(200, dict(head, object="chat.completion", usage=usage, choices=[
                {"index": 0, "message": message, "finish_reason": finish}]))
        part = lambda delta, end=None: dict(head, object="chat.completion.chunk",
                                            choices=[{"index": 0, "delta": delta, "finish_reason": end}])
        events = [part({"role": "assistant", "content": ""})]
        if words:
            events.append(part({"content": words}))
        for at, call in enumerate(made):
            events.append(part({"tool_calls": [{"index": at, "id": call["id"], "type": "function",
                                                "function": {"name": call["function"]["name"], "arguments": ""}}]}))
            written = call["function"]["arguments"]
            events.append(part({"tool_calls": [{"index": at, "function": {"arguments": written}}]}))
        events += [part({}, finish), dict(head, object="chat.completion.chunk", choices=[], usage=usage)]
        self.send(200, "".join(f"data: {json.dumps(e)}\n\n" for e in events).encode() + b"data: [DONE]\n\n",
                  "text/event-stream")

    # ------------------------------------------------------------ Responses

    def as_responses(self, body, words, calls, counts):
        took, cached, wrote, reasoned = counts
        usage = {"input_tokens": took, "input_tokens_details": {"cached_tokens": cached}, "output_tokens": wrote,
                 "output_tokens_details": {"reasoning_tokens": reasoned}, "total_tokens": took + wrote}
        output = []
        if words:
            output.append({"type": "message", "id": "msg_standin", "status": "completed", "role": "assistant",
                           "content": [{"type": "output_text", "text": words, "annotations": []}]})
        output += [{"type": "function_call", "id": "fc_" + c["id"], "call_id": c["id"], "status": "completed",
                    "name": c["name"], "arguments": json.dumps(c["arguments"])} for c in calls]
        response = {"id": "resp_standin", "object": "response", "created_at": 0, "status": "completed",
                    "model": body.get("model") or "stand-in", "output": output, "usage": usage}
        if not body.get("stream"):
            return self.send(200, response)
        opening = dict(response, status="in_progress", output=[], usage=None)
        events = [{"type": "response.created", "response": opening},
                  {"type": "response.in_progress", "response": opening}]
        for at, item in enumerate(output):
            if item["type"] == "message":
                part, where = item["content"][0], {"output_index": at, "item_id": item["id"], "content_index": 0}
                events += [
                    {"type": "response.output_item.added", "output_index": at,
                     "item": dict(item, status="in_progress", content=[])},
                    dict(where, type="response.content_part.added", part=dict(part, text="")),
                    dict(where, type="response.output_text.delta", delta=words),
                    dict(where, type="response.output_text.done", text=words),
                    dict(where, type="response.content_part.done", part=part)]
            else:
                events += [
                    {"type": "response.output_item.added", "output_index": at,
                     "item": dict(item, status="in_progress", arguments="")},
                    {"type": "response.function_call_arguments.delta", "output_index": at, "item_id": item["id"],
                     "delta": item["arguments"]},
                    {"type": "response.function_call_arguments.done", "output_index": at, "item_id": item["id"],
                     "arguments": item["arguments"]}]
            events.append({"type": "response.output_item.done", "output_index": at, "item": item})
        events.append({"type": "response.completed", "response": response})
        self.send(200, "".join(f"event: {e['type']}\ndata: {json.dumps(dict(e, sequence_number=n))}\n\n"
                               for n, e in enumerate(events)).encode(), "text/event-stream")


# ---------------------------------------------------------------- the tests of the stand-in itself

PING = {"type": "function", "function": {"name": "ping", "description": "Ping.", "parameters": {
    "type": "object", "properties": {"value": {"type": "integer"}}, "required": ["value"]}}}
ASK = "Call the tool ping with the value 7."


def call(url, body=None, key=None):
    """One call as a client makes it: (status, the answer as JSON or as its stream's events, the headers)."""
    request = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), headers={
        "Content-Type": "application/json", **({"Authorization": f"Bearer {key}"} if key else {})})
    try:
        with urllib.request.urlopen(request, timeout=10) as r:
            status, raw, headers = r.status, r.read().decode(), r.headers
    except urllib.error.HTTPError as e:
        with e:
            status, raw, headers = e.code, e.read().decode(), e.headers
    if headers.get("Content-Type") == "text/event-stream":
        return status, [json.loads(line[len("data: "):]) for line in raw.splitlines()
                        if line.startswith("data: ") and line != "data: [DONE]"], headers
    return status, json.loads(raw), headers


class StandIn(unittest.TestCase):
    def setUp(self):
        self.models = Models()
        self.addCleanup(self.models.close)

    def chat(self, content=ASK, key=None, **more):
        return call(self.models.url + "/chat/completions", dict(
            {"model": "stand-in", "messages": [{"role": "user", "content": content}], "tools": [PING]}, **more), key)

    def test_the_model_list_and_a_key(self):
        self.models.models = ["small", {"id": "large", "context_length": 64000}]
        listed = call(self.models.url + "/models")[1]["data"]
        self.assertEqual([m["id"] for m in listed], ["small", "large"])
        self.assertEqual(listed[1], {"id": "large", "object": "model", "created": 0, "owned_by": "stand-in",
                                     "context_length": 64000})
        self.models.key = "the-test-key"
        for key in (None, "another-key"):
            status, answer, _ = call(self.models.url + "/models", key=key)
            self.assertEqual((status, answer["error"]["code"]), (401, "invalid_api_key"))
        self.models.script.append(text("With the key."))
        self.assertEqual(self.chat(key="another-key")[0], 401)
        self.assertEqual(len(self.models.script), 1)                # a refused call takes no answer of the script
        self.assertEqual(self.chat(key="the-test-key")[1]["choices"][0]["message"]["content"], "With the key.")
        self.assertEqual(call(self.models.url + "/models", key="the-test-key")[0], 200)
        self.assertEqual([r["key"] for r in self.models.of("models")], [None, None, "another-key", "the-test-key"])
        self.assertEqual([r["key"] for r in self.models.of("chat")], ["another-key", "the-test-key"])
        self.assertEqual(call(self.models.url.replace("/v1", "") + "/models", key="the-test-key")[0], 200)
        self.assertEqual(call(self.models.url + "/elsewhere", key="the-test-key")[0], 404)

    def test_a_chat_call_gives_the_tool_call_that_its_message_asks_for_and_then_text(self):
        status, answer, _ = self.chat()
        choice = answer["choices"][0]
        self.assertEqual((status, choice["finish_reason"], choice["message"]["content"]), (200, "tool_calls", None))
        made = choice["message"]["tool_calls"]
        self.assertEqual([(c["function"]["name"], json.loads(c["function"]["arguments"])) for c in made],
                         [("ping", {"value": 7})])
        self.assertEqual(answer["usage"]["prompt_tokens"], 8)        # a token is a word
        after = [{"role": "user", "content": ASK}, dict(choice["message"]),
                 {"role": "tool", "tool_call_id": made[0]["id"], "content": "7"}]
        answer = self.chat(messages=after)[1]
        self.assertEqual((answer["choices"][0]["finish_reason"], answer["choices"][0]["message"]["content"]),
                         ("stop", "Done."))
        # a call that does not offer the tool, and a model that calls no tools, answer with text
        self.assertEqual(self.chat(tools=[])[1]["choices"][0]["finish_reason"], "stop")
        self.models.plain.add("stand-in")
        self.assertEqual(self.chat()[1]["choices"][0]["message"]["content"], "Done.")

    def test_a_chat_stream_carries_the_same_answer_in_events_with_the_usage_last(self):
        self.models.script += [several(tool("ping", {"value": 7}), tool("ping", {"value": 8}),
                                       usage={"input": 1000, "cached": 600, "output": 50, "reasoning": 20})]
        status, events, _ = self.chat(stream=True, stream_options={"include_usage": True})
        self.assertEqual(status, 200)
        calls = {}
        for event in events:
            for choice in event["choices"]:
                for part in choice["delta"].get("tool_calls") or []:
                    one = calls.setdefault(part["index"], {"name": "", "arguments": ""})
                    one["name"] += part["function"].get("name", "")
                    one["arguments"] += part["function"]["arguments"]
        self.assertEqual(calls, {0: {"name": "ping", "arguments": '{"value": 7}'},
                                 1: {"name": "ping", "arguments": '{"value": 8}'}})
        self.assertEqual(events[-2]["choices"][0]["finish_reason"], "tool_calls")
        self.assertEqual(events[-1], dict(events[-1], choices=[], usage={
            "prompt_tokens": 1000, "completion_tokens": 50, "total_tokens": 1050,
            "prompt_tokens_details": {"cached_tokens": 600}, "completion_tokens_details": {"reasoning_tokens": 20}}))
        text_events = self.chat("Say something.", stream=True)[1]
        self.assertEqual("".join(e["choices"][0]["delta"].get("content") or "" for e in text_events if e["choices"]),
                         "Done.")

    def test_the_responses_shape_gives_the_same_answers_as_one_object_and_as_a_stream(self):
        tools = [{"type": "function", "name": "ping", "parameters": PING["function"]["parameters"]}]
        body = {"model": "stand-in", "instructions": "You are a test.", "tools": tools,
                "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": ASK}]}]}
        status, answer, _ = call(self.models.url + "/responses", body)
        item = answer["output"][0]
        self.assertEqual((status, item["type"], item["name"], json.loads(item["arguments"])),
                         (200, "function_call", "ping", {"value": 7}))
        self.assertEqual(answer["usage"], {"input_tokens": 12, "input_tokens_details": {"cached_tokens": 0},
                                           "output_tokens": 2, "output_tokens_details": {"reasoning_tokens": 0},
                                           "total_tokens": 14})
        body["input"] += [item, {"type": "function_call_output", "call_id": item["call_id"], "output": "7"}]
        status, events, _ = call(self.models.url + "/responses", dict(body, stream=True))
        self.assertEqual([e["type"] for e in events], [
            "response.created", "response.in_progress", "response.output_item.added", "response.content_part.added",
            "response.output_text.delta", "response.output_text.done", "response.content_part.done",
            "response.output_item.done", "response.completed"])
        self.assertEqual(events[-1]["response"]["output"][0]["content"][0]["text"], "Done.")
        self.assertEqual([e["sequence_number"] for e in events], list(range(9)))
        self.models.script.append(tool("ping", {"value": 9}))
        events = call(self.models.url + "/responses", dict(body, stream=True))[1]
        self.assertEqual([e["type"] for e in events][2:5], [
            "response.output_item.added", "response.function_call_arguments.delta",
            "response.function_call_arguments.done"])
        self.assertEqual(events[-1]["response"]["output"][0]["arguments"], '{"value": 9}')

    def test_the_script_answers_first_and_then_the_answer_for_each_other_call(self):
        self.models.script += [text("One."), tool("ping", {"value": 1})]
        self.models.otherwise = text("The rest.")
        said_ = [self.chat("Hello.")[1]["choices"][0]["message"] for _ in range(4)]
        self.assertEqual([m["content"] for m in said_], ["One.", None, "The rest.", "The rest."])
        self.models.otherwise = lambda body: text(f"{len(body['messages'])} message")
        self.assertEqual(self.chat("Hello.")[1]["choices"][0]["message"]["content"], "1 message")
        self.assertEqual(len(self.models.calls()), 5)
        self.assertEqual(self.models.calls()[0]["messages"], [{"role": "user", "content": "Hello."}])

    def test_a_limit_a_missing_credit_and_a_wrong_key_are_answers_of_the_script(self):
        self.models.script += [limit(30), LIMIT, NO_CREDIT, WRONG_KEY]
        status, answer, headers = self.chat()
        self.assertEqual((status, headers["Retry-After"], answer["error"]["code"]), (429, "30", "rate_limit_exceeded"))
        status, answer, headers = self.chat(stream=True)
        self.assertEqual((status, headers["Retry-After"], answer["error"]["type"]), (429, None, "rate_limit_error"))
        self.assertEqual(self.chat()[1]["error"]["code"], "insufficient_quota")
        self.assertEqual(self.chat()[0], 401)
        self.assertEqual(self.chat()[0], 200)

    def test_a_context_cuts_a_long_prompt_or_refuses_it(self):
        self.models.context = 100
        self.assertEqual(self.chat("seven " * 60)[1]["usage"]["prompt_tokens"], 60)
        self.assertEqual(self.chat("seven " * 600)[1]["usage"]["prompt_tokens"], 100)        # cut, with no error
        self.models.cuts = False
        status, answer, _ = self.chat("seven " * 600)
        self.assertEqual((status, answer["error"]["code"]), (400, "context_length_exceeded"))


if __name__ == "__main__":
    unittest.main()
